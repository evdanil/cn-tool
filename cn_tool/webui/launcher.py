"""Lazy local launcher. No UI dependencies are paid by ordinary cn commands."""
import argparse
import asyncio
import socket
import sys
import webbrowser

from cn_tool.utils import oscompat

_GRACEFUL_SHUTDOWN_TIMEOUT = 5


def _show_error(message):
    if sys.stderr is not None and sys.stderr.isatty():
        print(message, file=sys.stderr)
        return
    try:
        from tkinter import Tk, messagebox
        root = Tk()
        root.withdraw()
        messagebox.showerror('cn Subnets', message)
        root.destroy()
    except Exception:
        if sys.stderr is not None:
            print(message, file=sys.stderr)


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
    access = LocalAccess(f'127.0.0.1:{listener.getsockname()[1]}')
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
                url = access.origin + '/bootstrap#' + access.bootstrap_token
                if no_browser:
                    if sys.stdout is not None and sys.stdout.isatty():
                        print(url, flush=True)
                else:
                    webbrowser.open(url)
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


def main(argv=None):
    parser = argparse.ArgumentParser(description='Open the local Subnets interface')
    parser.add_argument('-c', dest='config_file', metavar='FILE')
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--port', type=int, default=0, metavar='PORT', help='listen on a specific local port')
    args = parser.parse_args(argv)
    try:
        try:
            import nicegui  # noqa: F401 -- optional dependency check only
        except ImportError:
            _show_error('Install the graphical interface: pip install "cn-tool[webui]"')
            raise SystemExit(2)
        from .controller import SessionController
        guardian = _start_config_search_guardian()
        try:
            options = dict(config_file=args.config_file, no_browser=args.no_browser, port=args.port)
            if guardian is not None:
                options['config_search_guardian'] = guardian
            asyncio.run(serve(SessionController(), **options))
        finally:
            if guardian is not None:
                guardian.close()
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except Exception:
        _show_error('Subnets could not start. Check the installation and local network configuration.')
        raise SystemExit(3)
