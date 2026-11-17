"""One cn-web session per user: the session file and the start lock.

``~/.cn-web-session`` is UTF-8 JSON, ``{"pid", "port", "secret", "config_file"}``. The running launcher writes it,
atomically, once its server has started, and removes it on Quit. The secret is what ``POST /reopen`` asks for
(``access.py``); the profile's ACL (POSIX: mode 0600) protects it.

``~/.cn-web.lock`` holds the pid of a start that has not yet published its session, so a second start during a slow
first one waits for that session instead of starting another. It is created with ``O_EXCL``; a lock whose pid is
gone (``oscompat.pid_exists``) is stale and broken at once, and a live one is taken over after ``WAIT_SECONDS``.

Standard library and the file system only: the HTTP request that reopens a session is the launcher's.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Tuple

from cn_tool.utils import oscompat

SESSION_NAME = '.cn-web-session'
LOCK_NAME = '.cn-web.lock'
WAIT_SECONDS = 30
POLL_SECONDS = .2


@dataclass(frozen=True)
class Session:
    pid: int
    port: int
    secret: str
    config_file: Optional[str]


def session_path() -> Path:
    return Path.home() / SESSION_NAME


def lock_path() -> Path:
    return Path.home() / LOCK_NAME


def _is_int(value) -> bool:
    return type(value) is int


def read_session() -> Optional[Session]:
    """The session the file names, or None when there is none or it cannot be read."""
    try:
        data = json.loads(session_path().read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    pid, port, secret, config_file = (data.get(key) for key in ('pid', 'port', 'secret', 'config_file'))
    if not (_is_int(pid) and pid > 0 and _is_int(port) and 0 < port < 65536 and isinstance(secret, str) and secret
            and (config_file is None or isinstance(config_file, str))):
        return None
    return Session(pid, port, secret, config_file)


def _replace(source: Path, target: Path, tries: int = 50, pause: float = .02) -> None:
    # On Windows a file that another handle has open (a waiting start reads the session file every few milliseconds)
    # cannot be replaced: try again for a moment, as _remove_lock does, instead of leaving the session unpublished.
    for attempt in range(tries):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt + 1 == tries:
                raise
            time.sleep(pause)


def write_session(session: Session) -> None:
    """Write the file through a temporary file beside it and ``os.replace``, so a reader never sees half of it.

    The replace is tried again for a moment when the file system refuses it with ``PermissionError`` (Windows, while a
    reader has the old file open); any other error, or a refusal that lasts, raises ``OSError``.
    """
    target = session_path()
    temporary = target.with_name(f'{SESSION_NAME}.{os.getpid()}.tmp')
    content = json.dumps({'pid': session.pid, 'port': session.port, 'secret': session.secret,
                          'config_file': session.config_file})
    try:
        descriptor = os.open(str(temporary), os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            handle.write(content)
        _replace(temporary, target)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def remove_session(secret: str) -> None:
    """Remove the file if it is still the session with this secret: a successor's file stays."""
    session = read_session()
    if session is not None and session.secret == secret:
        try:
            session_path().unlink()
        except OSError:
            pass


def acquire_lock() -> bool:
    """Take the start lock: True when taken, False when another start holds it. Other errors raise ``OSError``."""
    try:
        descriptor = os.open(str(lock_path()), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return False
    try:
        os.write(descriptor, str(os.getpid()).encode('utf-8'))
    finally:
        os.close(descriptor)
    return True


def lock_holder() -> Optional[int]:
    """The pid in the lock file, or None when there is no lock or it names no pid (yet)."""
    try:
        text = lock_path().read_text(encoding='utf-8').strip()
    except (OSError, ValueError):
        return None
    return int(text) if text.isdigit() and int(text) > 0 else None


def _break_lock(holder: Optional[int]) -> None:
    # Only the lock that was judged: one another start took since is left alone.
    if lock_holder() == holder:
        _remove_lock()


def _remove_lock(tries: int = 50, pause: float = .02) -> None:
    # On Windows a file that another process has open cannot be removed, and a waiting start reads the lock every few
    # milliseconds: try again for a moment instead of leaving the lock behind.
    for attempt in range(tries):
        try:
            lock_path().unlink()
            return
        except FileNotFoundError:
            return
        except PermissionError:
            if attempt + 1 < tries:
                time.sleep(pause)
        except OSError:
            return


def release_lock() -> None:
    """Remove the lock if this process holds it."""
    if lock_holder() == os.getpid():
        _remove_lock()


def claim(reopen: Callable[[Session], Optional[str]], *, wait: float = WAIT_SECONDS,
          poll: float = POLL_SECONDS) -> Optional[Tuple[Session, str]]:
    """Find the running session, or take the lock to start one.

    Returns ``(session, token)`` when ``reopen(session)`` gave a running session's fresh bootstrap token, and None
    when this process may start a session: it then holds the lock (unless the home directory refused one), which
    the caller releases once the session file is written or the start fails. A session whose pid is gone, or that
    ``reopen`` cannot reach (refused, wrong secret), is stale: it is asked once and replaced by the new session.
    """
    stale = None

    def running():
        nonlocal stale
        session = read_session()
        if session is None or session == stale:
            return None
        if oscompat.pid_exists(session.pid):
            token = reopen(session)
            if token:
                return session, token
        stale = session
        return None

    deadline = time.monotonic() + wait
    while True:
        found = running()
        if found:
            return found
        try:
            taken = acquire_lock()
        except OSError:
            return None  # no lock can be taken here: start without one
        if taken:
            found = running()  # a session published between the read and the lock
            if found:
                release_lock()
            return found
        holder = lock_holder()
        if holder is not None and not oscompat.pid_exists(holder):
            _break_lock(holder)
            continue
        if time.monotonic() >= deadline:
            # A start that has not published in this time is not coming (or its pid now belongs to another
            # process): take its place, and give the next waiter a full wait of its own.
            _break_lock(holder)
            deadline = time.monotonic() + wait
            continue
        time.sleep(poll)
