"""Minimal spawned-worker entrypoint that owns console interrupt handling."""
import multiprocessing
import signal


def _ignore_parent_interrupts():
    if multiprocessing.current_process().name == 'MainProcess':
        return
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (AttributeError, ValueError):
        pass


_ignore_parent_interrupts()


def worker_main(connection, stop, interrupt=None, config_search_connection=None):
    """Load the application worker only after it ignores the launcher's Ctrl+C."""
    _ignore_parent_interrupts()
    from .worker import worker_main as run_worker
    if config_search_connection is None:
        run_worker(connection, stop, interrupt)
    else:
        run_worker(connection, stop, interrupt, config_search_connection)
