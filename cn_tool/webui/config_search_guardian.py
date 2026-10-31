"""Contain one killable search process behind independent owner lifelines.

The launcher owns the returned Guardian and passes ``worker`` to its worker,
then closes its own copy of that endpoint. Both endpoints use trusted private
multiprocessing connections. The worker sends (start, request), (data, bytes),
or (stop, None); it receives started, data, finished, stopped, or failed.
The child target accepts (request, connection) and exchanges bytes on that
connection using send_bytes/recv_bytes. Messages including their envelope are
limited to 8 MiB. Receivers must apply the same limit before unpickling. A
finished exit code other than zero, an EOF, or a missing valid final result is
a failed search. Data already in flight may precede a stopped response; the
worker must discard it once cancellation is requested. The launcher must keep
the Guardian alive until shutdown and call close().
"""

from __future__ import annotations

import multiprocessing
from multiprocessing.connection import wait
import os
import pickle
import signal
import sys
import threading

from cn_tool.utils import oscompat

_MAX_MESSAGE = 8 * 1024 * 1024
_TIMEOUT = 2.0


def _linux_parent_death(expected_parent):
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'parent-death signal unavailable')
    if os.getppid() != expected_parent:
        raise RuntimeError('parent already exited')


class _WindowsJob:
    """A non-inheritable job handle held solely by the launcher."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        class BasicLimit(ctypes.Structure):
            _fields_ = [('PerProcessUserTimeLimit', ctypes.c_longlong),
                        ('PerJobUserTimeLimit', ctypes.c_longlong),
                        ('LimitFlags', wintypes.DWORD),
                        ('MinimumWorkingSetSize', ctypes.c_size_t),
                        ('MaximumWorkingSetSize', ctypes.c_size_t),
                        ('ActiveProcessLimit', wintypes.DWORD),
                        ('Affinity', ctypes.c_size_t),
                        ('PriorityClass', wintypes.DWORD),
                        ('SchedulingClass', wintypes.DWORD)]

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                'ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
                'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]

        class ExtendedLimit(ctypes.Structure):
            _fields_ = [('BasicLimitInformation', BasicLimit),
                        ('IoInfo', IoCounters),
                        ('ProcessMemoryLimit', ctypes.c_size_t),
                        ('JobMemoryLimit', ctypes.c_size_t),
                        ('PeakProcessMemoryUsed', ctypes.c_size_t),
                        ('PeakJobMemoryUsed', ctypes.c_size_t)]

        self._kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        k = self._kernel
        k.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        k.CreateJobObjectW.restype = wintypes.HANDLE
        k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                               ctypes.c_void_p, wintypes.DWORD]
        k.SetInformationJobObject.restype = wintypes.BOOL
        k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k.OpenProcess.restype = wintypes.HANDLE
        k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k.AssignProcessToJobObject.restype = wintypes.BOOL
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CloseHandle.restype = wintypes.BOOL
        self._handle = k.CreateJobObjectW(None, None)
        if not self._handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedLimit()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
        if not k.SetInformationJobObject(self._handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise ctypes.WinError(ctypes.get_last_error())

    def assign(self, pid):
        import ctypes

        handle = self._kernel.OpenProcess(0x0100 | 0x0001, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not self._kernel.AssignProcessToJobObject(self._handle, handle):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self._kernel.CloseHandle(handle)

    def close(self):
        if self._handle:
            self._kernel.CloseHandle(self._handle)
            self._handle = None


def _send(connection, message):
    payload = pickle.dumps(message, protocol=4)
    if len(payload) > _MAX_MESSAGE:
        raise ValueError('guardian message exceeds limit')
    connection.send_bytes(payload)


def _receive(connection):
    return pickle.loads(connection.recv_bytes(_MAX_MESSAGE))


def _child(target, request, connection, expected_parent):
    if oscompat.is_linux():
        _linux_parent_death(expected_parent)
    try:
        target(request, connection)
    except BaseException:
        # Child exceptions can contain search text or paths.
        sys.exit(1)
    finally:
        connection.close()


def _terminate(process):
    if process is not None:
        if process.is_alive():
            process.terminate()
            process.join(_TIMEOUT)
        if process.is_alive():
            process.kill()
        process.join()
        process.close()


def _serve(target, launcher, worker, parent_pid):
    child = None
    child_pipe = None
    generation = 0
    sending = False
    reading = False
    writing = False
    outgoing = []
    events = []
    event_lock = threading.Lock()
    context = multiprocessing.get_context('spawn')
    wake_read, wake_write = context.Pipe(duplex=False)

    def retire(*, terminate=False, finish=False):
        nonlocal child, child_pipe, generation, reading, writing
        # Invalidate in-flight reads and writes before closing their endpoint.
        generation += 1
        reading = False
        writing = False
        if child_pipe is not None:
            child_pipe.close()
            child_pipe = None
        status = None
        if child is not None and terminate:
            _terminate(child)
            child = None
        elif child is not None and finish:
            child.join()
            status = child.exitcode
            child.close()
            child = None
        return status

    def notify(kind, token, value):
        with event_lock:
            events.append((kind, token, value))
            try:
                wake_write.send_bytes(b'x')
            except (OSError, ValueError, TypeError):
                pass

    def send_async(message):
        def send():
            try:
                _send(worker, message)
                notify('sent', 0, True)
            except (OSError, ValueError):
                notify('sent', 0, False)
        threading.Thread(target=send, daemon=True).start()

    def read_async(connection, token):
        def read():
            try:
                notify('read', token, ('data', connection.recv_bytes(_MAX_MESSAGE - 128)))
            except EOFError:
                notify('read', token, ('eof', None))
            except (OSError, ValueError, TypeError):
                notify('read', token, ('failed', None))
        threading.Thread(target=read, daemon=True).start()

    def write_async(connection, token, payload):
        def write():
            try:
                connection.send_bytes(payload)
                notify('wrote', token, True)
            except (OSError, ValueError, TypeError):
                notify('wrote', token, False)
        threading.Thread(target=write, daemon=True).start()

    try:
        if oscompat.is_linux():
            _linux_parent_death(parent_pid)
            os.setsid()
        _send(launcher, ('ready', None))
        if _receive(launcher) != ('go', None):
            return
        while True:
            if not sending and outgoing:
                sending = True
                send_async(outgoing.pop(0))
            if child is not None and child_pipe is not None and not reading and not sending and not outgoing:
                reading = True
                read_async(child_pipe, generation)
            watched = [launcher, worker, wake_read]
            if child is not None and child_pipe is None:
                watched.append(child.sentinel)
            ready = wait(watched)
            if launcher in ready:
                return
            if worker in ready:
                try:
                    command, value = _receive(worker)
                except (EOFError, OSError, ValueError, pickle.UnpicklingError):
                    return
                if command == 'start' and child is None:
                    parent, endpoint = context.Pipe(duplex=True)
                    try:
                        child = context.Process(target=_child, args=(target, value, endpoint, os.getpid()))
                        child.start()
                        child_pipe = parent
                        generation += 1
                        outgoing.append(('started', None))
                    except Exception:
                        parent.close()
                        if child is not None and child.pid is not None:
                            _terminate(child)
                        child = None
                        outgoing.append(('failed', None))
                    finally:
                        endpoint.close()
                elif command == 'stop' and child is not None:
                    retire(terminate=True)
                    outgoing.append(('stopped', None))
                elif command == 'data' and child is not None and child_pipe is not None and not writing and isinstance(value, bytes):
                    writing = True
                    write_async(child_pipe, generation, value)
                else:
                    outgoing.append(('failed', None))
                # A stalled receiver must not permit unbounded queued statuses.
                if len(outgoing) > 2:
                    return
            if wake_read in ready:
                wake_read.recv_bytes()
                with event_lock:
                    kind, token, value = events.pop(0)
                if kind == 'sent':
                    sending = False
                    if not value:
                        return
                elif kind == 'wrote' and token == generation:
                    writing = False
                    if not value:
                        retire(terminate=True)
                        outgoing.append(('failed', None))
                elif kind == 'read' and token == generation:
                    reading = False
                    tag, payload = value
                    if tag == 'data':
                        outgoing.append(('data', payload))
                    elif tag == 'eof':
                        retire()
                    else:
                        retire(terminate=True)
                        outgoing.append(('failed', None))
            if child is not None and child_pipe is None and child.sentinel in ready:
                outgoing.append(('finished', retire(finish=True)))
    except (EOFError, OSError, BrokenPipeError):
        pass
    finally:
        if child is not None:
            _terminate(child)
        if child_pipe is not None:
            child_pipe.close()
        worker.close()
        launcher.close()
        wake_read.close()
        wake_write.close()


class Guardian:
    def __init__(self, process, launcher, worker, job):
        self.process = process
        self._launcher = launcher
        self.worker = worker
        self._job = job
        self._watcher = threading.Thread(target=self._watch, daemon=True)
        self._watcher.start()

    def _watch(self):
        # Keep the exited guardian's PID reserved until its group is killed.
        wait([self.process.sentinel])
        if self._job is not None:
            self._job.close()
        elif oscompat.is_linux():
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.process.join()

    def close(self):
        self._launcher.close()
        self.worker.close()
        self._watcher.join(_TIMEOUT + 2)
        if self._watcher.is_alive():
            self.process.kill()
            self._watcher.join()
        self.process.close()


def start_guardian(target):
    """Start a contained guardian; fail closed if containment cannot be set up."""
    if not (oscompat.is_linux() or oscompat.is_windows()):
        raise RuntimeError('search process containment is unavailable')
    context = multiprocessing.get_context('spawn')
    launcher, launcher_child = context.Pipe(duplex=True)
    worker, worker_child = context.Pipe(duplex=True)
    job = None
    process = context.Process(target=_serve, args=(target, launcher_child, worker_child, os.getpid()))
    try:
        if oscompat.is_windows():
            job = _WindowsJob()
        process.start()
        launcher_child.close()
        worker_child.close()
        if not launcher.poll(10) or _receive(launcher) != ('ready', None):
            raise RuntimeError('search guardian failed to initialize')
        if job is not None:
            job.assign(process.pid)
        _send(launcher, ('go', None))
        return Guardian(process, launcher, worker, job)
    except BaseException:
        if job is not None:
            job.close()
        if process.pid is not None:
            _terminate(process)
        launcher.close()
        worker.close()
        launcher_child.close()
        worker_child.close()
        raise
