"""The terminal side of the Ping Monitor's live view: keys, stop requests and the frame on stderr.

``cn_tool/modules/ping_monitor.py`` pings; this module holds what a run needs from the terminal
around it (plan sections 2.4 and 4.4):

* ``Keys`` reads single keys without Enter while a run goes on, and nothing at all when stdin is not
  a terminal (``cn monitor - < list.txt`` has read stdin to its end).
* ``StopSignals`` turns the first Ctrl+C, and SIGTERM and SIGHUP on POSIX, into a stop request that
  never raises; a second Ctrl+C hands over to the handler installed before.
* ``LiveScreen`` draws ``ping_grid``'s lines with a Rich ``Live`` on a console of its own on stderr,
  and only when stderr is a terminal: stdout carries results only.

On POSIX both stay off for a job in the background (``cn monitor ... &``): the terminal is the shell's.
A run sent there mid-run (Ctrl+Z, then ``bg``) is asked again at every poll and draw: it sleeps instead
of reading, skips its frames, and at its end leaves the terminal's settings and screen to the shell.

The platform is asked through ``oscompat`` at every call. The Windows key API is reached as
``user_input.msvcrt`` and the POSIX terminal API as ``user_input.termios`` (None on Windows), so a
Linux test drives every branch with fakes.
"""
from __future__ import annotations

import io
import os
import select  # exists on Windows too, but only the POSIX branch calls it
import signal
import sys
import threading
import time
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Sequence, TextIO, Tuple

from rich.console import Console
from rich.live import Live
from rich.text import Text

from cn_tool.utils import oscompat, user_input

if TYPE_CHECKING:
    from cn_tool.utils.ping_grid import Line

_KBHIT_INTERVAL = 0.05  # how often Windows looks for a key
_ESCAPE_WAIT = 0.05  # how long the rest of an escape sequence may take to follow its ESC
_ESCAPE_REST = 16  # more bytes than any key's escape sequence has
_WINDOWS_PREFIXES = ("\x00", "\xe0")  # an arrow, function or navigation key: a prefix and a second code
_REVERSE = " reverse"
_DISABLED_SIZE = (80, 24)


def _is_terminal(stream: Any) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):  # a replaced or already closed stream is not a terminal
        return False


def _in_foreground(stream: Any) -> bool:
    """False when the terminal belongs to another process group: a job sent to the background with ``&``, which
    SIGTTOU would stop at its first change of the terminal's settings, and whose frames would cover the shell. Windows
    has no job control; a stream whose group cannot be asked counts as the foreground's."""
    if oscompat.is_windows():
        return True
    try:
        return os.tcgetpgrp(stream.fileno()) == os.getpgrp()
    except (AttributeError, OSError, ValueError):
        return True


def _show_cursor(stream: Any) -> None:
    """From a job that ends in the background: show the cursor its Live hid, the six bytes of that alone, unless the
    terminal stops a background job that writes to it (``stty tostop``: then ``tput cnorm`` shows it)."""
    termios = user_input.termios
    try:
        if termios.tcgetattr(stream.fileno())[3] & termios.TOSTOP:
            return
        stream.write("\x1b[?25h")
        stream.flush()
    except (AttributeError, OSError, ValueError) + ((termios.error,) if termios is not None else ()):
        pass  # no terminal to ask, or one gone


def _escape_done(rest: bytes) -> bool:
    """Whether ``rest``, what came after an ESC, ends its sequence: CSI (``[``, parameters, then a final byte from ``@``
    to ``~``), SS3 (``O`` and one byte: F1 to F4, the arrows in application mode), or Alt and one key."""
    if rest[:1] == b"[":
        return any(0x40 <= byte <= 0x7E for byte in rest[1:])
    if rest[:1] == b"O":
        return len(rest) >= 2
    return bool(rest)


class Keys:
    """Single keys without Enter while a run goes on; nothing at all when stdin is not a terminal or refuses cbreak
    mode, and nothing while the terminal belongs to another process group (a background job): a job started in the
    background takes its keys at its first ``poll`` in the foreground (``fg``).

    POSIX: inside the ``with`` block the terminal is in cbreak mode (no echo, no line buffering,
    signals still on, so Ctrl+C stays SIGINT), and ``poll`` waits in ``select``. Windows: ``poll``
    looks with ``msvcrt.kbhit()`` every 50 ms, and there is no terminal state to change.

    ``poll`` returns a key lower-cased. An arrow or function key is read whole and ignored on both
    platforms (F2 is ESC O Q on POSIX and a prefix and Q on Windows, never a q). Ctrl+C read as a
    character on Windows comes back as ``"\\x03"``. Without keys ``poll`` only sleeps, so a wait loop
    built on it never spins. It may return None before its timeout at the end of input; a caller
    keeps its own deadline.
    """

    def __init__(self, stream: Optional[TextIO] = None) -> None:
        self._stream: Any = sys.stdin if stream is None else stream
        self.enabled: bool = _is_terminal(self._stream)
        self._inside = False
        self._fd: Optional[int] = None
        self._saved: Optional[List[Any]] = None

    def __enter__(self) -> Keys:
        self._inside = True
        self._cbreak()
        return self

    def _cbreak(self) -> None:
        """Inside the ``with`` block, put the terminal in cbreak mode once this job owns it (POSIX); from the
        background, a change of its settings would stop the job (SIGTTOU)."""
        if (not self.enabled or not self._inside or self._saved is not None or oscompat.is_windows()
                or not _in_foreground(self._stream)):
            return
        termios = user_input.termios
        fd = self._stream.fileno()
        try:
            saved = termios.tcgetattr(fd)
            cbreak = list(saved)
            cbreak[3] = saved[3] & ~(termios.ICANON | termios.ECHO)  # ISIG stays: Ctrl+C is still a signal
            cbreak[6] = list(saved[6])
            cbreak[6][termios.VMIN] = 1
            cbreak[6][termios.VTIME] = 0
            termios.tcsetattr(fd, termios.TCSANOW, cbreak)
        except (OSError, termios.error):  # a terminal that refuses: the run goes on without keys
            self.enabled = False
            return
        self._fd, self._saved = fd, saved

    def __exit__(self, *exc: object) -> None:
        self._inside = False
        if self._saved is None:
            return
        fd, saved = self._fd, self._saved
        self._fd = self._saved = None
        if not _in_foreground(self._stream):
            return  # the shell's terminal now, with its settings: writing ours would stop this job (SIGTTOU)
        termios = user_input.termios
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        except (OSError, termios.error):
            pass  # the terminal is gone (a hang-up): there is nothing left to restore

    def poll(self, timeout: float) -> Optional[str]:
        """Wait at most ``timeout`` seconds for one key and return it lower-cased, else None."""
        self._cbreak()  # a job started in the background, now in the foreground
        if not self.enabled or not _in_foreground(self._stream):  # a read from the background would stop the job
            time.sleep(timeout)
            return None
        deadline = time.monotonic() + timeout
        if oscompat.is_windows():
            return self._poll_windows(deadline)
        return self._poll_posix(deadline)

    def _poll_posix(self, deadline: float) -> Optional[str]:
        fd = self._stream.fileno()
        while True:
            if not select.select([fd], [], [], max(0.0, deadline - time.monotonic()))[0]:
                return None
            data = self._read(fd, 1)
            if not data:
                return None
            if data != b"\x1b":
                return data.decode("utf-8", errors="replace").lower()
            # An arrow or function key: the rest of its sequence follows the ESC, in one read or, over SSH, in more.
            rest = b""
            while not _escape_done(rest):
                if not select.select([fd], [], [], _ESCAPE_WAIT)[0]:
                    if not rest:
                        return "\x1b"  # a lone Esc
                    break  # a sequence cut short: what came of it is ignored
                more = self._read(fd, _ESCAPE_REST)
                if not more:
                    return None
                rest += more

    def _read(self, fd: int, size: int) -> bytes:
        """Up to ``size`` bytes. At the end of input, or with the terminal gone, b"" and no keys from now on."""
        try:
            data = os.read(fd, size)
        except OSError:
            data = b""
        if not data:
            self.enabled = False
        return data

    def _poll_windows(self, deadline: float) -> Optional[str]:
        msvcrt = user_input.msvcrt
        while True:
            if msvcrt.kbhit():
                char = msvcrt.getwch()
                if char not in _WINDOWS_PREFIXES:
                    return char.lower()
                msvcrt.getwch()  # the key's second code, ignored; the wait goes on
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            # time.sleep, not an Event wait: before Python 3.14 a lock wait on Windows ignores Ctrl+C.
            time.sleep(min(_KBHIT_INTERVAL, remaining))


class StopSignals:
    """While a run goes on, the stop requests: the first Ctrl+C, and on POSIX SIGTERM and SIGHUP, only set `reason`;
    they never raise. A second Ctrl+C hands over to the handler that was installed before.

    A ``KeyboardInterrupt`` on the first Ctrl+C would mark a menu run interrupted and escape the live
    view before its ``finally``. Windows has no SIGTERM or SIGHUP delivery to take. Outside the main
    thread nothing is installed (``signal.signal`` works only there); ``stop`` and ``interrupt`` still
    work, for ``q`` and for Ctrl+C read as a key.
    """

    def __init__(self) -> None:
        self.reason: Optional[str] = None  # None, or "interrupt" | "terminate" | "hangup" | "key"
        self._interrupts = 0
        self._replaced: Dict[int, Any] = {}

    def __enter__(self) -> StopSignals:
        if threading.current_thread() is not threading.main_thread():
            return self
        handlers = {signal.SIGINT: self._on_interrupt}
        if not oscompat.is_windows():
            handlers[signal.SIGTERM] = self._on_terminate
            handlers[signal.SIGHUP] = self._on_hangup
        for signum, handler in handlers.items():
            if signal.getsignal(signum) is signal.SIG_IGN:  # ignored on entry (nohup, a background job): it stays so
                self._replaced[signum] = signal.SIG_IGN
                continue
            self._replaced[signum] = signal.signal(signum, handler)
        return self

    def __exit__(self, *exc: object) -> None:
        replaced, self._replaced = self._replaced, {}
        for signum, previous in replaced.items():
            # None: a handler that was not installed from Python, which cannot be put back; the default can.
            signal.signal(signum, signal.SIG_DFL if previous is None else previous)

    @property
    def stopped(self) -> bool:
        return self.reason is not None

    def stop(self, reason: str = "key") -> None:
        """A stop request (``q``, SIGTERM, SIGHUP): the first reason stays."""
        if self.reason is None:
            self.reason = reason

    def interrupt(self) -> None:
        """A Ctrl+C. The first only asks to stop; a second goes to the SIGINT handler installed before.

        ``q`` does not count: after ``q`` the first Ctrl+C still only asks to stop, and a Ctrl+C, then
        ``q``, then a Ctrl+C is the second.
        """
        self._interrupts += 1
        if self._interrupts == 1:
            self.stop("interrupt")
            return
        previous = self._replaced.get(signal.SIGINT)
        if previous is signal.SIG_IGN:
            return
        if callable(previous) and previous is not signal.default_int_handler:
            previous(signal.SIGINT, None)
            return
        raise KeyboardInterrupt  # SIG_DFL, default_int_handler, or nothing known

    def _on_interrupt(self, signum: int, frame: Any) -> None:
        self.interrupt()

    def _on_terminate(self, signum: int, frame: Any) -> None:
        self.stop("terminate")

    def _on_hangup(self, signum: int, frame: Any) -> None:
        self.stop("hangup")


# ping_grid's style name -> the color scheme key (get_global_color_scheme) that draws it. "dim" is Rich's
# own style; "text" is drawn without one.
STYLE_COLORS: Dict[str, str] = {
    "ok": "success",
    "warning": "warning",
    "info": "info",
    "error": "error",
    "label": "description",
    "header": "header",
    "dim": "dim",
    "text": "",
}


def _rich_style(name: str, colors: Mapping[str, str]) -> str:
    reverse = name.endswith(_REVERSE)
    if reverse:
        name = name[: -len(_REVERSE)]
    key = STYLE_COLORS.get(name, "")  # an unknown style name is drawn without one
    style = colors.get(key, key)
    return f"{style}{_REVERSE}".strip() if reverse else style


def to_text(lines: Sequence[Line], colors: Mapping[str, str]) -> Text:
    """One Rich ``Text`` for ``lines``, one line each, every segment styled from ``colors`` (the color scheme)."""
    text = Text()
    for number, line in enumerate(lines):
        if number:
            text.append("\n")
        for chunk, style in line:
            text.append(chunk, style=_rich_style(style, colors))
    return text


class LiveScreen:
    """The live view: a Rich Live on a Console of its own on stderr, drawn only when stderr is a terminal.

    The console writes to ``stream`` and never to stdout, and the Live redirects neither stream, so
    the command line's stdout carries results only. Rich reads ``NO_COLOR`` itself: then the frame
    keeps bold, dim and reverse video, and no colour. When the terminal goes away (a hang-up), a
    write fails with ``OSError``; the screen then turns itself off and the run goes on without it.
    Nothing is written while the terminal belongs to another process group (a background job): a job
    started in the background starts its Live at its first frame in the foreground (``fg``).
    """

    def __init__(self, colors: Mapping[str, str], *, stream: Optional[TextIO] = None) -> None:
        self._colors = colors
        self._stream: Any = sys.stderr if stream is None else stream
        self.enabled: bool = _is_terminal(self._stream)
        self._console: Optional[Console] = None
        if self.enabled:
            self._console = Console(file=self._stream, force_terminal=True, highlight=False, markup=False, emoji=False)
        self._live: Optional[Live] = None
        self._inside = False

    @property
    def size(self) -> Tuple[int, int]:
        """(width, height) of the terminal, read at every call; (80, 24) without one."""
        if self._console is None:
            return _DISABLED_SIZE
        width, height = self._console.size
        return width, height

    def __enter__(self) -> LiveScreen:
        self._inside = True
        self._start()
        return self

    def _start(self) -> bool:
        """Inside the ``with`` block, start the Live once this job owns the terminal (from the background, even
        hiding the cursor would reach the shell's screen); True when it runs."""
        if self._live is None and self._inside and self.enabled and self._console is not None \
                and _in_foreground(self._stream):
            self._live = Live(
                console=self._console,
                auto_refresh=False,
                transient=False,
                redirect_stdout=False,
                redirect_stderr=False,
                vertical_overflow="crop",
            )
            self._live.start()
        return self._live is not None

    def __exit__(self, *exc: object) -> None:
        self._inside = False
        live, self._live = self._live, None
        if live is not None:
            background = self._console is not None and not _in_foreground(self._stream)
            if background:
                self._console.file = io.StringIO()  # the last frame would cover the shell's screen
            try:
                live.stop()
            except OSError:
                self.enabled = False
            if background:
                _show_cursor(self._stream)  # the Live hid it, and its "show" went into the swallowed frame

    def show(self, lines: Sequence[Line]) -> None:
        """Replace the frame with ``lines`` and draw it (not from the background)."""
        if not _in_foreground(self._stream):
            return
        try:
            if self._start():
                self._live.update(to_text(lines, self._colors), refresh=True)
        except OSError:
            self._turn_off()

    def note(self, line: Line) -> None:
        """Print one line (a change line) above the frame, where it stays (not from the background)."""
        if not _in_foreground(self._stream):
            return
        try:
            if self._start():
                self._console.print(to_text([line], self._colors))
        except OSError:
            self._turn_off()

    def _turn_off(self) -> None:
        """The terminal went away: stop the Live and never draw again."""
        self.enabled = False
        self.__exit__()
