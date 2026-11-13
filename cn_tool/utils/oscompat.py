"""One place that says which operating system cn runs on.

Code asks ``oscompat.is_windows()``, ``oscompat.is_macos()`` or ``oscompat.is_linux()`` at runtime through
this module, never through direct function imports. Tests use the ``windows_host``, ``macos_host`` and
``posix_host`` fixtures to change the answers for one test. All answers are read at every call, and neither
``os.name`` nor ``sys.platform`` is ever patched (pathlib reads ``os.name`` on every ``Path()``).

Standard library only, so any module may import it.
"""
from __future__ import annotations

import os
import sys


def is_windows() -> bool:
    """True on Windows (``os.name == "nt"``). Read at every call."""
    return os.name == "nt"


def is_macos() -> bool:
    """True on macOS (``sys.platform == "darwin"``). Read at every call."""
    return sys.platform == "darwin"


def is_linux() -> bool:
    """True on Linux, read at every call."""
    return sys.platform.startswith("linux")


# What the Windows branch of pid_exists reads (winnt.h, winerror.h): the access right it asks for, the error
# of a process that is alive but not ours (87, ERROR_INVALID_PARAMETER, is a process that is gone), and the
# exit code a running process reports.
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_ERROR_ACCESS_DENIED = 5
_STILL_ACTIVE = 259
_MAX_WINDOWS_PID = 0xFFFFFFFF  # a pid is a DWORD


def pid_exists(pid: int) -> bool:
    """Whether a process with this id is alive.

    POSIX: ``os.kill(pid, 0)`` as 0.6.0 did. Windows: ``OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)``. A null
    handle with ``ERROR_ACCESS_DENIED`` is a process that is alive but not ours, ``ERROR_INVALID_PARAMETER`` is a
    process that is gone, and any other error is read as gone, as POSIX reads an unexpected ``OSError``. With a
    handle, ``GetExitCodeProcess`` tells ``STILL_ACTIVE`` (259) from a process that has ended, and the handle is
    closed again. Windows never gets ``os.kill(pid, 0)``: signal 0 is ``CTRL_C_EVENT`` there, and CPython
    would call ``GenerateConsoleCtrlEvent`` instead of looking at the process.
    """
    if pid <= 0:
        return False
    if is_windows():
        return _windows_pid_exists(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but we may not have permission to signal it.
        return True
    except OSError:
        return False
    return True


def pid_definitely_dead(pid: int) -> bool:
    """True only when the operating system confirms that this PID has exited.

    Unknown errors and invalid IDs are not proof of death. This stricter check is for
    destructive history operations; ``pid_exists`` keeps its existing semantics.
    """
    if type(pid) is not int or pid <= 0:
        return False
    if is_windows():
        if pid > _MAX_WINDOWS_PID:
            return False
        import ctypes
        from ctypes import wintypes

        try:
            kernel32 = _kernel32()
            handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return _last_error() == 87  # ERROR_INVALID_PARAMETER: no process with that PID
            try:
                exit_code = wintypes.DWORD()
                return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))) and exit_code.value != _STILL_ACTIVE
            finally:
                kernel32.CloseHandle(handle)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except Exception:
        return False
    return False


def _windows_pid_exists(pid: int) -> bool:
    if pid > _MAX_WINDOWS_PID:
        return False  # it would wrap around to another process in the DWORD argument
    import ctypes
    from ctypes import wintypes

    kernel32 = _kernel32()
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return _last_error() == _ERROR_ACCESS_DENIED
    try:
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return False
        return exit_code.value == _STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


# winbase.h. subprocess.CREATE_NO_WINDOW exists only on Windows, so the literal is kept here.
CREATE_NO_WINDOW = 0x08000000


def no_console_window_flags() -> int:
    """The ``creationflags`` a console child (``ping.exe``, ``gpg.exe``) needs so that it opens no window.

    A Windows process without a console (``pythonw``, the windowless web UI shortcut) that starts a console
    program gives that child a new, visible console window of its own. ``CREATE_NO_WINDOW`` runs it without one.
    Only then: a process with a console (``GetConsoleWindow`` is not null) returns 0, so its children share that
    console, and Ctrl+C reaches them, as before. POSIX returns 0 without loading kernel32.
    """
    if not is_windows():
        return 0
    return 0 if _kernel32().GetConsoleWindow() else CREATE_NO_WINDOW


def child_process_kwargs() -> dict:
    """``{"creationflags": CREATE_NO_WINDOW}`` when ``no_console_window_flags`` asks for it, else ``{}``.

    Spread into every ``subprocess`` call (``Popen(cmd, ..., **oscompat.child_process_kwargs())``). An empty dict
    keeps a POSIX call, and a Windows start with a console, at exactly today's arguments: ``creationflags`` is a
    Windows-only argument.
    """
    flags = no_console_window_flags()
    return {"creationflags": flags} if flags else {}


def _kernel32():
    """``kernel32`` with the prototypes ``pid_exists`` and ``no_console_window_flags`` need declared. Tests replace this with a fake.

    The default ``restype`` of ctypes is a C int, which cuts a 64-bit handle to 32 bits, so ``OpenProcess`` is
    declared to return a pointer-sized ``HANDLE``, ``GetConsoleWindow`` a pointer-sized ``HWND``, and every function
    lists its argument types. ``use_last_error``
    makes ctypes keep the error of each call, which ``_last_error`` reads. ``ctypes`` is imported here, not at
    module level: no run that never asks about a Windows process pays for it.
    """
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, wintypes.LPDWORD)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.GetConsoleWindow.restype = wintypes.HWND
    kernel32.GetConsoleWindow.argtypes = ()
    return kernel32


def _last_error() -> int:
    """The error code of the last ``_kernel32()`` call on this thread (``ctypes.get_last_error``, Windows only)."""
    import ctypes

    return ctypes.get_last_error()
