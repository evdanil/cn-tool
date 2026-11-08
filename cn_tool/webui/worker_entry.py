"""Minimal spawned-worker entrypoint that owns console interrupt handling."""
from .interrupts import ignore_console_interrupts as _ignore_parent_interrupts

_ignore_parent_interrupts()


def worker_main(connection, stop, interrupt=None, config_search_connection=None):
    """Load the application worker only after it ignores the launcher's Ctrl+C."""
    _ignore_parent_interrupts()
    from .worker import worker_main as run_worker
    if config_search_connection is None:
        run_worker(connection, stop, interrupt)
    else:
        run_worker(connection, stop, interrupt, config_search_connection)
