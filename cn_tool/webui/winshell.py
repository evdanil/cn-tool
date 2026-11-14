"""The Windows shell calls behind ``--create-shortcut``: a known folder's path, and a ``.lnk`` written through COM.

Windows only, standard library only. The DLLs are reached through the seams ``_ole32()`` and ``_shell32()``, so a
Linux test replaces them with fakes, and ``ctypes`` is imported inside the functions: importing this module costs
nothing. It stays out of ``oscompat``, which every module imports.

The COM methods are called through the object's vtable by index. The indices follow the Windows SDK declaration
order (ShObjIdl_core.h for IShellLinkW, ObjIdl.h for IPersist and IPersistFile), after IUnknown's three methods.
``tests/test_webui_winshell.py`` pins them, and its real-Windows test reads a written link back through an
independent reader (Windows Script Host's shortcut object, from PowerShell).
"""
from __future__ import annotations

import uuid
from typing import Optional

CLSID_SHELL_LINK = "{00021401-0000-0000-C000-000000000046}"
IID_ISHELLLINKW = "{000214F9-0000-0000-C000-000000000046}"
IID_IPERSISTFILE = "{0000010B-0000-0000-C000-000000000046}"
FOLDERID_PROGRAMS = "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}"  # the user's Start Menu\Programs
FOLDERID_DESKTOP = "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"  # the user's Desktop, where it was redirected to

_COINIT_APARTMENTTHREADED = 0x2
_CLSCTX_INPROC_SERVER = 0x1
_S_FALSE = 1
_RPC_E_CHANGED_MODE = 0x80010106  # COM is already initialised on this thread with another threading model

# IUnknown
_QUERY_INTERFACE = 0
_RELEASE = 2
# IShellLinkW: GetPath 3, GetIDList 4, SetIDList 5, GetDescription 6, SetDescription 7, GetWorkingDirectory 8,
# SetWorkingDirectory 9, GetArguments 10, SetArguments 11, GetHotkey 12, SetHotkey 13, GetShowCmd 14,
# SetShowCmd 15, GetIconLocation 16, SetIconLocation 17, SetRelativePath 18, Resolve 19, SetPath 20.
_SET_DESCRIPTION = 7
_SET_WORKING_DIRECTORY = 9
_SET_ARGUMENTS = 11
_SET_ICON_LOCATION = 17
_SET_PATH = 20
# IPersistFile: IPersist::GetClassID 3, IsDirty 4, Load 5, Save 6, SaveCompleted 7, GetCurFile 8.
_SAVE = 6


def known_folder(folder_id: str) -> str:
    """The path of a known folder (``FOLDERID_PROGRAMS``, ``FOLDERID_DESKTOP``), as ``SHGetKnownFolderPath`` says.

    The shell allocates the string; it is freed with ``CoTaskMemFree`` (ole32), whether the call succeeded or not.
    A failing HRESULT raises ``OSError``.
    """
    import ctypes

    shell32 = _shell32()
    buffer = ctypes.c_void_p()
    hr = shell32.SHGetKnownFolderPath(_guid(folder_id), 0, None, ctypes.pointer(buffer))
    try:
        _check(hr, "SHGetKnownFolderPath")
        return ctypes.wstring_at(buffer.value)
    finally:
        if buffer.value:
            _ole32().CoTaskMemFree(buffer.value)


def write_link(path: str, target: str, arguments: str, workdir: str, description: str,
               icon: Optional[str] = None) -> None:
    """Write the shortcut ``path`` (a ``.lnk``) that starts ``target`` with ``arguments`` in ``workdir``.

    ``icon`` is the path of a ``.ico`` the shortcut shows (its first image); without one no icon is set and
    Explorer shows the target's own. An icon is decoration: a failing ``SetIconLocation`` is ignored and the
    shortcut is still written. Every interface obtained is released and COM is
    uninitialised again when this call initialised it (``S_OK`` or ``S_FALSE``; not ``RPC_E_CHANGED_MODE``), also
    after a failure. A failing HRESULT raises ``OSError`` naming the call and the HRESULT in hex.
    """
    import ctypes

    ole32 = _ole32()
    hr = ole32.CoInitializeEx(None, _COINIT_APARTMENTTHREADED)
    initialised = _unsigned(hr) != _RPC_E_CHANGED_MODE
    if initialised:
        _check(hr, "CoInitializeEx")
    try:
        link = ctypes.c_void_p()
        _check(ole32.CoCreateInstance(_guid(CLSID_SHELL_LINK), None, _CLSCTX_INPROC_SERVER,
                                      _guid(IID_ISHELLLINKW), ctypes.pointer(link)), "CoCreateInstance")
        try:
            for index, name, value in (
                (_SET_PATH, "SetPath", target),
                (_SET_ARGUMENTS, "SetArguments", arguments),
                (_SET_WORKING_DIRECTORY, "SetWorkingDirectory", workdir),
                (_SET_DESCRIPTION, "SetDescription", description),
            ):
                _check(_method(link, index, ctypes.c_wchar_p)(link, value), "IShellLinkW::" + name)
            if icon:
                _method(link, _SET_ICON_LOCATION, ctypes.c_wchar_p, ctypes.c_int)(link, icon, 0)
            persist = ctypes.c_void_p()
            query = _method(link, _QUERY_INTERFACE, ctypes.c_void_p, ctypes.c_void_p)
            _check(query(link, _guid(IID_IPERSISTFILE), ctypes.pointer(persist)), "IShellLinkW::QueryInterface")
            try:
                save = _method(persist, _SAVE, ctypes.c_wchar_p, ctypes.c_int)
                _check(save(persist, path, True), "IPersistFile::Save")
            finally:
                _release(persist)
        finally:
            _release(link)
    finally:
        if initialised:
            ole32.CoUninitialize()


def _method(interface, index: int, *argtypes, restype=None):
    """Slot ``index`` of the vtable of the COM object ``interface`` (a ``c_void_p``), as a callable prototype.

    The first argument of the call is the object itself. The result is a plain ``c_long`` (an HRESULT), never
    ``ctypes.HRESULT``, which would raise by itself. ``WINFUNCTYPE`` exists on Windows only; on x64, the one
    supported Windows, it is the same calling convention as ``CFUNCTYPE``, which a Linux test's fake uses.
    """
    import ctypes

    prototype = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
    vtable = ctypes.cast(interface, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    return prototype(restype or ctypes.c_long, ctypes.c_void_p, *argtypes)(vtable[index])


def _release(interface) -> None:
    import ctypes

    _method(interface, _RELEASE, restype=ctypes.c_ulong)(interface)


def _guid(text: str):
    """A ``GUID`` struct for ``{...}``: Data1, Data2 and Data3 little-endian, then Data4, i.e. ``bytes_le``."""
    import ctypes

    return (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID(text).bytes_le)


def _unsigned(hr: int) -> int:
    return hr & 0xFFFFFFFF


def _check(hr: int, call: str) -> None:
    """Raise ``OSError`` for a failing HRESULT (the high bit set), whether ctypes read it signed or not."""
    code = _unsigned(hr)
    if code & 0x80000000:
        raise OSError(f"{call} failed with HRESULT 0x{code:08X}")


def _ole32():
    """``ole32`` with the prototypes this module needs declared. Tests replace this with a fake.

    ``WinDLL``, not ``OleDLL``: an HRESULT comes back as a plain ``c_long``, so ``RPC_E_CHANGED_MODE`` reaches
    ``write_link`` instead of raising. Pointers are ``c_void_p``, which is pointer-sized.
    """
    import ctypes

    ole32 = ctypes.WinDLL("ole32")
    ole32.CoInitializeEx.restype = ctypes.c_long
    ole32.CoInitializeEx.argtypes = (ctypes.c_void_p, ctypes.c_ulong)
    ole32.CoUninitialize.restype = None
    ole32.CoUninitialize.argtypes = ()
    ole32.CoCreateInstance.restype = ctypes.c_long
    ole32.CoCreateInstance.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
                                       ctypes.c_void_p)
    ole32.CoTaskMemFree.restype = None
    ole32.CoTaskMemFree.argtypes = (ctypes.c_void_p,)
    return ole32


def _shell32():
    """``shell32`` with ``SHGetKnownFolderPath`` declared. Tests replace this with a fake."""
    import ctypes

    shell32 = ctypes.WinDLL("shell32")
    shell32.SHGetKnownFolderPath.restype = ctypes.c_long
    shell32.SHGetKnownFolderPath.argtypes = (ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p)
    return shell32
