"""One place that says which operating system cn runs on.

Code asks ``oscompat.is_windows()`` or ``oscompat.is_macos()`` when it runs, through this module and never
through ``from cn_tool.utils.oscompat import is_windows``: a test then flips the answer for one test with the
``windows_host``, ``macos_host`` and ``posix_host`` fixtures. Both answers are read at every call, and neither
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


def _kernel32():
    """``kernel32`` with the prototypes ``pid_exists`` needs declared. Tests replace this with a fake.

    The default ``restype`` of ctypes is a C int, which cuts a 64-bit handle to 32 bits, so ``OpenProcess`` is
    declared to return a pointer-sized ``HANDLE`` and every function lists its argument types. ``use_last_error``
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
    return kernel32


def _last_error() -> int:
    """The error code of the last ``_kernel32()`` call on this thread (``ctypes.get_last_error``, Windows only)."""
    import ctypes

    return ctypes.get_last_error()
