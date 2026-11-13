"""Lazy local launcher. No UI dependencies are paid by ordinary cn commands."""
import argparse
import asyncio
import io
import os
import socket
import sys
import threading
import webbrowser

from cn_tool.utils import oscompat
from . import session_file

_GRACEFUL_SHUTDOWN_TIMEOUT = 5
_ERROR_BOX_TIMEOUT = 60
_REOPEN_TIMEOUT = 5

TITLE = 'cn-tool Web'
START_FAILED = 'The web interface could not start. Check the installation and local network configuration.'
# MessageBoxW's MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST: a box that comes to the front even when an
# Explorer double-click started cn without a console.
_MESSAGE_BOX_FLAGS = 0x0 | 0x10 | 0x10000 | 0x40000


class _NullStream(io.TextIOWrapper):
    """Devnull that is never a terminal. Windows' NUL is a character device, so ``isatty()`` on it says True: a
    windowless start would then print its error to nowhere instead of showing the box, and nobody would see it."""

    def isatty(self):
        return False


def _replace_missing_streams():
    """Give a windowless start (``pythonw``) somewhere to write.

    There, ``sys.stdout`` and ``sys.stderr`` are None, and uvicorn's log formatter calls ``sys.stdout.isatty()``:
    the server could not even be configured ("Unable to configure formatter 'default'"). Only a missing stream is
    replaced, and never ``sys.stdin`` (``getpass`` echoes when ``sys.stdin is not sys.__stdin__``). The replacement
    is no terminal on any platform, so ``_show_error`` still shows its box.
    """
    for name in ('stdout', 'stderr'):
        if getattr(sys, name) is None:
            setattr(sys, name, _NullStream(open(os.devnull, 'wb'), encoding='utf-8'))


def _user32():
    """``user32`` with ``MessageBoxW`` declared. Tests replace this with a fake; ``ctypes`` is imported only here."""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL('user32', use_last_error=True)
    user32.MessageBoxW.argtypes = (wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT)
    user32.MessageBoxW.restype = ctypes.c_int
    return user32


def _show_error_box(message):
    try:
        if oscompat.is_windows():
            # Always there, needs no Tcl (managed installs often leave tkinter out), and comes to the front.
            _user32().MessageBoxW(None, message, TITLE, _MESSAGE_BOX_FLAGS)
            return
        from tkinter import Tk, messagebox
        root = Tk()
        root.withdraw()
        messagebox.showerror(TITLE, message)
        root.destroy()
    except Exception:
        # No display: the message already went to stderr, when there is one.
        pass


def _show_error(message):
    # Stderr first: a scripted start has nobody to click a box. The devnull that replaced a missing stderr is no
    # place to print, so a windowless start goes straight to the box, on macOS too.
    printed = False
    if sys.stderr is not None and not isinstance(sys.stderr, _NullStream):
        try:
            print(message, file=sys.stderr)
            printed = True
            if sys.stderr.isatty():
                return
        except (OSError, ValueError):
            pass
    if oscompat.is_macos():
        # Tk aborts the process off the main thread there, so a box cannot be bounded: the message on stderr is
        # enough, and with nowhere to print it the box runs on the main thread, as it always did.
        if not printed:
            _show_error_box(message)
        return
    # A desktop launcher still gets the box. A native message box may not run Tcl timers, so the box lives on a
    # daemon thread and the wait is bounded.
    box = threading.Thread(target=_show_error_box, args=(message,), daemon=True)
    box.start()
    box.join(_ERROR_BOX_TIMEOUT)


def _notice(message):
    if sys.stderr is not None:
        try:
            print(message, file=sys.stderr)
        except (OSError, ValueError):
            pass


def _refuse(message):
    _show_error(message)
    raise SystemExit(2)


def _one_line(error):
    text = ' '.join(str(error).split()) or type(error).__name__
    return text.rstrip('.')


def _check_web_stack():
    """Import NiceGUI for real: the only check that sees a ``.pyd`` that application control blocks."""
    try:
        import nicegui  # noqa: F401 -- optional dependency check only
    except ModuleNotFoundError as error:
        if error.name != 'nicegui':
            _refuse(_not_loaded(error))
        # The interpreter that lacks it, by path: on Windows a bare pip.exe is a blocked stub too.
        _refuse(f'Install the web interface: "{sys.executable}" -m pip install "cn-tool[webui]"')
    except Exception as error:
        _refuse(_not_loaded(error))


def _not_loaded(error):
    return (f'A part of the web interface could not be loaded: {_one_line(error)}. '
            "Your organisation's application control may block it; see the Windows guide.")


def _resolved(config_file):
    """``-c FILE`` as the start path reads it: ``~`` expanded, absolute against the working directory."""
    return os.path.abspath(os.path.expanduser(str(config_file))) if config_file else None


def _open_in_browser(url, no_browser):
    if no_browser:
        if sys.stdout is not None and sys.stdout.isatty():
            print(url, flush=True)
    else:
        webbrowser.open(url)


def _reopen(session):
    """Ask the running session for a fresh bootstrap token (``POST /reopen``): the token, or None when stale."""
    import json
    import urllib.request
    request = urllib.request.Request(
        f'http://127.0.0.1:{session.port}/reopen', method='POST',
        data=json.dumps({'secret': session.secret}).encode('utf-8'), headers={'Content-Type': 'application/json'})
    # Never through a proxy that the environment names: the session is on this machine.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=_REOPEN_TIMEOUT) as response:
            payload = json.loads(response.read().decode('utf-8'))
    except (OSError, ValueError):  # refused, 403 (a wrong secret), a timeout, not JSON
        return None
    token = payload.get('token') if isinstance(payload, dict) else None
    return token if isinstance(token, str) and token else None


def _publish(access, port, config_file):
    """The server has started: write the session file, then let a waiting second start find it."""
    try:
        session_file.write_session(session_file.Session(os.getpid(), port, access.reopen_secret,
                                                        _resolved(config_file)))
    except OSError:
        pass  # this session still works; a later start cannot find it and starts its own
    finally:
        session_file.release_lock()


def _reuse_running_session(args, config_file):
    """True when a running session was reopened; False when this start holds the lock (or none could be taken)."""
    found = session_file.claim(_reopen, wait=session_file.WAIT_SECONDS)
    if found is None:
        return False
    session, token = found
    if session.config_file != config_file:
        running = session.config_file or 'the default configuration'
        _refuse(f'cn-tool Web is already running with {running}. Quit it first to open another configuration.')
    if args.port is not None:
        _notice(f'cn-tool Web is already running on port {session.port}.')
    _open_in_browser(f'http://127.0.0.1:{session.port}/bootstrap#{token}', args.no_browser)
    return True


def _start_config_search_guardian():
    # Search availability must not prevent the rest of the interface starting.
    if not (oscompat.is_linux() or oscompat.is_windows()):
        return None
    try:
        from .config_search_guardian import start_guardian
        from .config_search_worker import run_search
        return start_guardian(run_search)
    except Exception:
        return None


async def serve(controller, *, config_file=None, no_browser=False, port=0, config_search_guardian=None):
    import uvicorn
    from .access import LocalAccess
    from .app import create_app
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', port))
    listener.listen(128)
    bound = listener.getsockname()[1]
    access = LocalAccess(f'127.0.0.1:{bound}')
    # A reset Windows Proactor connection may never detach from its asyncio
    # server. Bound Uvicorn's connection drain; normal Quit closes the worker first.
    server = uvicorn.Server(uvicorn.Config(
        create_app(controller, access), access_log=False, log_level='warning',
        timeout_graceful_shutdown=_GRACEFUL_SHUTDOWN_TIMEOUT,
    ))
    watcher = None
    startup_attempted = False
    interrupted = False
    try:
        startup_attempted = True
        if config_search_guardian is None:
            controller.start(config_file)
        else:
            try:
                controller.start(config_file, config_search_connection=config_search_guardian.worker)
            finally:
                # Only the worker retains this endpoint after process spawn.
                config_search_guardian.worker.close()

        async def supervise():
            while not server.started and not server.should_exit:
                await asyncio.sleep(.02)
            if server.started:
                _publish(access, bound, config_file)
                _open_in_browser(access.origin + '/bootstrap#' + access.bootstrap_token, no_browser)
            while not server.should_exit:
                if controller.current_phase() == 'closed':
                    server.should_exit = True
                await asyncio.sleep(.1)

        watcher = asyncio.create_task(supervise())
        await server.serve(sockets=[listener])
    except (KeyboardInterrupt, asyncio.CancelledError):
        interrupted = True
        raise
    finally:
        # First, so that a second start no longer reopens a session that is ending.
        session_file.remove_session(access.reopen_secret)
        try:
            if startup_attempted:
                try:
                    if interrupted:
                        controller.quit(interrupted=True)
                    else:
                        controller.quit()
                except (EOFError, OSError, RuntimeError):
                    pass
                else:
                    while controller.current_phase() not in {'closed', 'failed'}:
                        await asyncio.sleep(.05)
        finally:
            if watcher is not None:
                watcher.cancel()
                await asyncio.gather(watcher, return_exceptions=True)
            listener.close()


def _create_shortcut(args):
    """``--create-shortcut``: the checks, then ``shortcut.create_shortcuts``. No server, worker or socket."""
    if args.no_browser:
        _refuse('cn-web: --no-browser does not work with --create-shortcut')
    if args.port is not None:
        _refuse('cn-web: --port does not work with --create-shortcut')
    config_file = _resolved(args.config_file)
    if config_file is not None and not os.path.isfile(config_file):
        problem = 'is not a file' if os.path.exists(config_file) else 'does not exist'
        _refuse(f'cn-web: the configuration file "{config_file}" {problem}.')
    _check_web_stack()
    # The output names profile paths: UTF-8 even when redirected on Windows, reconfigured in place as cn's main() does.
    from cn_tool.main import _use_utf8_stdio
    _use_utf8_stdio()
    from .shortcut import create_shortcuts
    return create_shortcuts(console=args.console, config_file=config_file, out=sys.stdout, err=sys.stderr)


def main(argv=None):
    _replace_missing_streams()
    parser = argparse.ArgumentParser(description='Open the cn-tool web interface in the browser')
    parser.add_argument('-c', dest='config_file', metavar='FILE', help='use this configuration file, as cn -c does')
    parser.add_argument('--no-browser', action='store_true',
                        help='do not open the browser; print the address when run in a terminal')
    parser.add_argument('--port', type=int, default=None, metavar='PORT', help='listen on a specific local port')
    parser.add_argument('--create-shortcut', action='store_true',
                        help='write Start menu and Desktop shortcuts that start this interface with this Python, '
                             'then exit')
    parser.add_argument('--console', action='store_true',
                        help='with --create-shortcut: the shortcut opens a console window')
    args = parser.parse_args(argv)
    if args.console and not args.create_shortcut:
        _refuse('cn-web: --console works only with --create-shortcut')
    if args.create_shortcut:
        try:
            raise SystemExit(_create_shortcut(args))
        except KeyboardInterrupt:
            raise SystemExit(130) from None
    try:
        _check_web_stack()
        try:
            if _reuse_running_session(args, _resolved(args.config_file)):
                return
            from .controller import SessionController
            guardian = _start_config_search_guardian()
            try:
                options = dict(config_file=args.config_file, no_browser=args.no_browser,
                               port=args.port if args.port is not None else 0)
                if guardian is not None:
                    options['config_search_guardian'] = guardian
                asyncio.run(serve(SessionController(), **options))
            finally:
                if guardian is not None:
                    guardian.close()
        finally:
            session_file.release_lock()
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except Exception:
        _show_error(START_FAILED)
        raise SystemExit(3)
