"""The launcher winds down every spawned process after a console Ctrl+C, which Windows sends to all of them."""
import multiprocessing
import signal


def ignore_console_interrupts():
    """Leave a console Ctrl+C to the launcher: a spawned process ignores it."""
    if multiprocessing.current_process().name == 'MainProcess':
        return
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (AttributeError, ValueError):
        pass
