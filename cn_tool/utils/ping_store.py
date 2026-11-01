"""The Ping Monitor's history store: SQLite through the standard library's ``sqlite3``.

One file per machine (WAL does not work over a network file system). A ``request`` is a canonical
set of targets and TCP ports with its host list; a ``run`` is one process recording it; a ``round``
holds one character per host of the request's host list (``observations``) and a ``result`` row for
every host it saw. ``PingStore.open`` gives a writer, which creates the schema in an empty file, or a
reader, which never creates, alters, prunes or writes anything (docs/plans/2026-10-ping-monitor-plan.md,
section 3.3).

``sqlite3`` is imported inside the functions that use it: the loader imports every module at start,
and ``cn --help`` must not pay for it. Times are UTC epoch seconds. Every failure is a ``StoreError``
whose text completes ``cn: monitor: history: <message>``.
"""
from __future__ import annotations

import json
import math
import re
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from cn_tool.utils.ping_history import GAP_FACTOR

if TYPE_CHECKING:  # only for the annotations: sqlite3 is imported where it is used
    import sqlite3
    from types import ModuleType

SCHEMA_VERSION = 1
RUN_STATUSES = ("running", "finished", "stopped", "failed")
_FINAL_STATUSES = RUN_STATUSES[1:]
_BUSY_TIMEOUT = 10  # seconds a connection waits for another one's write lock
_DELETE_LOCK_SECONDS = 3.0  # leave time for other monitors to acquire the writer lock
_DELETE_PROGRESS_OPCODES = 1000
_DAY = 86400
# sweep(): at most this many result rows in a batch, so that no write lock is held for long (22 batches, the longest
# 0.44 s, for 30 days of the README's /24: 43,200 rounds, 4.3 million result rows); the pause between two batches is
# over SQLite's longest busy-retry step (100 ms), so that a run waiting for the lock gets it.
_SWEEP_RESULTS = 200_000
_SWEEP_BATCH = 5000  # rounds looked at in one read
_SWEEP_PAUSE = 0.15  # seconds
_PREFIX = re.compile(r"[0-9a-fA-F]{4,}")
Cursor = Tuple[float, int]  # (started, id) of a round: where the next page of rounds starts
ID_MESSAGE = "'{prefix}' is not a request ID: give 4 or more hex digits"

# Positional over the request's host list, so the characters and the list are part of the schema:
# changing either's meaning bumps SCHEMA_VERSION. executescript() would commit the transaction the
# statements run in, so they are executed one by one.
_SCHEMA = (
    "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)",
    "CREATE TABLE request (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL,"
    " targets TEXT NOT NULL, tcp_ports TEXT NOT NULL, hosts TEXT NOT NULL)",
    "CREATE TABLE run (id TEXT PRIMARY KEY,"
    " request_id INTEGER NOT NULL REFERENCES request ON DELETE CASCADE,"
    " source TEXT, started REAL NOT NULL, interval REAL, until REAL,"
    " host TEXT NOT NULL, pid INTEGER NOT NULL, heartbeat REAL NOT NULL, round_seconds REAL,"
    " ended REAL, status TEXT NOT NULL)",
    "CREATE TABLE round (id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " run_id TEXT NOT NULL REFERENCES run ON DELETE CASCADE,"
    " started REAL NOT NULL, observations TEXT NOT NULL, answered INTEGER NOT NULL)",
    "CREATE TABLE result (round_id INTEGER NOT NULL REFERENCES round ON DELETE CASCADE,"
    " host TEXT NOT NULL, address TEXT NOT NULL, t REAL NOT NULL,"
    " result TEXT NOT NULL, tcp TEXT, PRIMARY KEY (round_id, host)) WITHOUT ROWID",
    "CREATE INDEX run_by_request ON run (request_id, started)",
    "CREATE INDEX round_by_run ON round (run_id, started)",
)

_RUN_COLUMNS = (
    "run.id, run.request_id, run.source, run.started, run.interval, run.until, run.host, run.pid,"
    " run.heartbeat, run.round_seconds, run.ended, run.status,"
    " (SELECT COUNT(*) FROM round WHERE round.run_id = run.id)"
)
_ROUNDS = "FROM round JOIN run ON run.id = round.run_id"
_UNOWNED = "NOT EXISTS (SELECT 1 FROM run WHERE run.id = round.run_id)"  # a round that delete() left without its run


class StoreError(Exception):
    """One line for ``cn: monitor: history: <message>``."""


@dataclass(frozen=True)
class RunInfo:
    """A ``run`` row, and the number of its rounds still stored."""

    id: str
    request_id: int
    source: Optional[str]
    started: float
    interval: Optional[float]
    until: Optional[float]
    host: str
    pid: int
    heartbeat: float
    round_seconds: Optional[float]
    ended: Optional[float]
    status: str
    rounds: int


class AlreadyRunning(Exception):
    """Admission was refused because this request already has a live run."""

    def __init__(self, run: RunInfo) -> None:
        self.run = run
        super().__init__(f"run {run.id} is already running")


class DeletionTimedOut(StoreError):
    """Atomic deletion exceeded its write-lock budget and was rolled back."""


class HistoryExpired(Exception):
    """A live history page's parent or cursor no longer exists."""


class HistoryTooLarge(Exception):
    """A saved request exceeds the bounded history template response."""


@dataclass(frozen=True)
class RequestInfo:
    """A ``request`` row with its counts: rounds of every run, the first and last round start, its newest run, and
    its runs whose row says ``running`` (live or lost: ``ping_history.run_state`` tells), newest first."""

    id: int
    key: str
    targets: Tuple[str, ...]
    tcp_ports: Tuple[int, ...]
    hosts: Tuple[str, ...]
    runs: int
    rounds: int
    first_round: Optional[float]
    last_round: Optional[float]
    newest_run: Optional[RunInfo]
    running: Tuple[RunInfo, ...] = ()


@dataclass(frozen=True)
class Deletion:
    """What ``PingStore.delete`` did: the requests it deleted, with their counts as read in its transaction; when a run
    of them was going on (``going_on``), nothing was deleted and ``requests`` are those it would have deleted."""

    requests: Tuple[RequestInfo, ...]
    going_on: Tuple[RunInfo, ...] = ()


@dataclass(frozen=True)
class ResultRow:
    """The details of one host seen in a round; ``tcp`` maps a port to its state."""

    host: str
    address: str
    t: float
    result: str
    tcp: Optional[Dict[int, str]] = None


@dataclass(frozen=True)
class StoredRound:
    """A stored round, its run's ``interval`` (``None`` for a one-round run) and its rows sorted by host."""

    id: int
    run_id: str
    started: float
    interval: Optional[float]
    observations: str
    answered: int
    rows: Tuple[ResultRow, ...]


def _request_id(
    connection: "sqlite3.Connection", key: str, targets: Sequence[str], tcp_ports: Sequence[int], hosts: Sequence[str]
) -> int:
    row = connection.execute("SELECT id FROM request WHERE key = ?", (key,)).fetchone()
    if row is not None:
        return int(row[0])
    cursor = connection.execute(
        "INSERT INTO request (key, targets, tcp_ports, hosts) VALUES (?, ?, ?, ?)",
        (key, _dump(list(targets)), _dump(sorted(int(port) for port in tcp_ports)), _dump(list(hosts))),
    )
    return int(cursor.lastrowid)


def _insert_run(
    connection: "sqlite3.Connection", run_id: str, request_id: int, *, source: Optional[str], started: float,
    interval: Optional[float], until: Optional[float], host: str, pid: int, heartbeat: Optional[float] = None,
) -> None:
    connection.execute(
        "INSERT INTO run (id, request_id, source, started, interval, until, host, pid, heartbeat, status)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'running')",
        (run_id, request_id, source, started, interval, until, host, pid, started if heartbeat is None else heartbeat),
    )


def _sqlite3() -> "ModuleType":
    """The ``sqlite3`` module; a Python built without SQLite headers has none."""
    try:
        import sqlite3
    except ImportError as error:
        raise StoreError("this Python has no sqlite3 module") from error
    return sqlite3


@contextmanager
def _reported(verb: str, path: Path) -> Iterator[None]:
    """Turn a ``sqlite3.Error`` into ``StoreError("cannot <verb> <path>: <reason>")``."""
    sqlite3 = _sqlite3()
    try:
        yield
    except sqlite3.Error as error:
        raise StoreError(f"cannot {verb} {path}: {error}") from error


def _exists(path: Path) -> bool:
    """Whether the history is there for a reader; a directory on the way it cannot search is a ``StoreError``, as
    ``Path.exists`` raises there instead of answering False."""
    try:
        return path.exists()
    except OSError as error:
        raise StoreError(f"cannot read {path}: {error.strerror or error}") from error


def _uri(path: Path, mode: str) -> str:
    """The ``file:`` URI of ``path`` that opens the file as it is and never creates it: ``mode`` is ``ro`` or ``rw``. A
    Windows UNC path (``\\\\server\\share\\...``) turns into a URI with a host, which SQLite refuses: its name goes
    after ``file:`` as it is, escaped, which SQLite reads as a path."""
    uri = path.absolute().as_uri()
    if not uri.startswith("file:///"):
        from urllib.parse import quote

        uri = "file:" + quote(str(path.absolute()), safe="\\/:")
    return f"{uri}?mode={mode}"


def _reader_uri(path: Path) -> str:
    """The read-only ``file:`` URI of ``path``."""
    return _uri(path, "ro")


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _dump_tcp(tcp: Optional[Dict[int, str]]) -> Optional[str]:
    return None if tcp is None else _dump({str(port): state for port, state in sorted(tcp.items())})


def _load_tcp(text: Optional[str]) -> Optional[Dict[int, str]]:
    return None if text is None else {int(port): state for port, state in json.loads(text).items()}


def _host_names(text: str) -> Iterator[str]:
    """Decode host names one at a time from the request's JSON array."""
    decoder = json.JSONDecoder()
    pos = 0

    def whitespace(index: int) -> int:
        while index < len(text) and text[index] in " \t\r\n":
            index += 1
        return index

    pos = whitespace(pos)
    if pos >= len(text) or text[pos] != "[":
        raise ValueError("invalid hosts array")
    pos = whitespace(pos + 1)
    while pos < len(text) and text[pos] != "]":
        host, pos = decoder.raw_decode(text, pos)
        if not isinstance(host, str):
            raise ValueError("invalid host")
        yield host
        pos = whitespace(pos)
        if pos < len(text) and text[pos] == ",":
            pos = whitespace(pos + 1)
            if pos >= len(text) or text[pos] == "]":
                raise ValueError("invalid hosts array")
        elif pos >= len(text) or text[pos] != "]":
            raise ValueError("invalid hosts array")
    if pos >= len(text) or whitespace(pos + 1) != len(text):
        raise ValueError("invalid hosts array")


# Cap work per array as well as output size. Very large arrays have an unknown
# count; the first few targets may still be useful to identify the request.
_HISTORY_ARRAY_CHARS = 8192
_HISTORY_PREVIEW_ITEMS = 3
_HISTORY_PREVIEW_CHARS = 80


def _request_array_summary(text: str, *, ports: bool = False, preview: bool = True) -> Tuple[list, Optional[int]]:
    if not isinstance(text, str):
        return [], None
    large = len(text) > _HISTORY_ARRAY_CHARS
    valid = (lambda value: type(value) is int and 1 <= value <= 65535) if ports else (
        lambda value: isinstance(value, str))
    try:
        if large:
            if not preview:
                return [], None
            decoder = json.JSONDecoder()
            remainder = text.lstrip()
            if not remainder.startswith("["):
                return [], None
            remainder = remainder[1:]
            values = []
            for index in range(_HISTORY_PREVIEW_ITEMS):
                remainder = remainder.lstrip()
                if index:
                    if not remainder.startswith(","):
                        return [], None
                    remainder = remainder[1:].lstrip()
                value, end = decoder.raw_decode(remainder)
                if not valid(value):
                    return [], None
                values.append(value)
                remainder = remainder[end:]
            if not remainder.lstrip(" \t\r\n").startswith((",", "]")):
                return [], None
            count = None
        else:
            values = json.loads(text)
            if not isinstance(values, list) or not all(valid(value) for value in values):
                return [], None
            count = len(values)
        if not preview:
            return [], count
        if ports:
            return values[:_HISTORY_PREVIEW_ITEMS], count
        return [value if len(value) <= _HISTORY_PREVIEW_CHARS else value[:_HISTORY_PREVIEW_CHARS - 1] + "…"
                for value in values[:_HISTORY_PREVIEW_ITEMS]], count
    except (ValueError, TypeError, RecursionError):
        return [], None


def _history_integer(value: Any, minimum: int = 1) -> bool:
    """An integer SQLite can bind, excluding booleans."""
    return type(value) is int and minimum <= value <= 2**63 - 1


def _history_timestamp(value: Any) -> bool:
    return (type(value) is int and -(2**63) <= value <= 2**63 - 1 or
            type(value) is float and math.isfinite(value))


class PingStore:
    """
    An open history file. ``open`` makes one; ``close`` (or leaving a ``with`` block) ends it.

    Every method is one short transaction, so nothing stays open between calls: a long read would keep
    the ``-wal`` file growing. A reader's writer methods raise ``StoreError("cannot write ...: opened
    read-only")``.
    """

    def __init__(self, path: Path, connection: "sqlite3.Connection", *, write: bool) -> None:
        self.path = path
        self._connection = connection
        self._write = write
        self._snapshot = False

    # --- opening and closing -----------------------------------------------------------------

    @classmethod
    def open(cls, path: Path, *, write: bool, create: bool = True) -> Optional["PingStore"]:
        """
        Open the history at ``path``, as a writer or a reader.

        A reader of a missing file gets ``None`` ("nothing recorded"): ``connect()`` would create it. So does a
        writer that passed ``create=False`` (``--delete``, ``--clear``: they never make a history), which opens the
        file read-write by a ``mode=rw`` URI, so one removed after the check is not created again, and which
        refuses an empty database instead of writing a schema into it. Otherwise a writer creates missing
        parent directories, and the schema in an empty database.

        @raise StoreError: the file cannot be opened, is not a cn ping history (a text file, another
            program's database), or was written by a newer cn; or this Python has no ``sqlite3``.
        """
        path = Path(path)
        existing_only = not write or not create
        if existing_only and not _exists(path):
            return None
        sqlite3 = _sqlite3()
        verb = "write" if write else "read"
        if write and create:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as error:
                raise StoreError(f"cannot write {path}: {error.strerror or error}") from error
        # Opened as it is, so a history removed since the check above is never created again.
        uri = None if write and create else _uri(path, "rw") if write else _reader_uri(path)
        try:
            with _reported(verb, path):
                connection = sqlite3.connect(uri or str(path), timeout=_BUSY_TIMEOUT, isolation_level=None,
                                             uri=uri is not None)
        except StoreError:
            if existing_only and not _exists(path):
                return None
            raise
        store = cls(path, connection, write=write)
        try:
            with _reported(verb, path):
                connection.execute("PRAGMA foreign_keys = ON")  # off by default: the cascades need it
            store._check_schema(create=create)
            if write:  # only once the file is known to be ours: the journal mode is stored in the file
                with _reported(verb, path):
                    connection.execute("PRAGMA journal_mode = WAL").fetchone()
        except BaseException:
            connection.close()
            raise
        return store

    def close(self) -> None:
        """Close the connection; closing twice is harmless."""
        self._connection.close()

    def __enter__(self) -> "PingStore":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @contextmanager
    def snapshot(self) -> Iterator[None]:
        """
        One read transaction around several reads (re-entrant): in WAL they all see the history as it was at the
        first of them, whatever another process commits or prunes meanwhile, so the starts the spacing is taken from
        and the rounds read with it are one history. Short: an open read holds the checkpoint back.
        """
        if self._snapshot:
            yield
            return
        with self._transaction(write=False):
            self._snapshot = True
            try:
                yield
            finally:
                self._snapshot = False

    @contextmanager
    def _transaction(self, *, write: bool) -> Iterator["sqlite3.Connection"]:
        """One explicit transaction: ``BEGIN IMMEDIATE`` for a write, ``BEGIN`` for a read; rolled back on error. A read
        inside a ``snapshot`` is part of it."""
        if write and not self._write:
            raise StoreError(f"cannot write {self.path}: opened read-only")
        connection = self._connection
        if self._snapshot and not write:
            with _reported("read", self.path):
                yield connection
            return
        with _reported("write" if write else "read", self.path):
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                connection.rollback()  # a no-op when SQLite has already rolled back
                raise

    def _check_schema(self, *, create: bool = True) -> None:
        """A writer creates the schema in an empty database (unless it must not create anything); anything but a cn
        store of this version is refused."""
        with self._transaction(write=self._write) as connection:
            tables = {name for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
            if not tables and self._write and create:
                for statement in _SCHEMA:
                    connection.execute(statement)
                connection.execute("INSERT INTO meta (key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
                return
            row = None
            if "meta" in tables:
                row = connection.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
            try:
                version = int(row[0]) if row is not None else None
            except (TypeError, ValueError):
                version = None
            if version is not None and version > SCHEMA_VERSION:
                raise StoreError(f"{self.path} was written by a newer cn (schema {version})")
            if version != SCHEMA_VERSION:
                raise StoreError(f"{self.path} is not a cn ping history")

    # --- writer --------------------------------------------------------------------------------

    def ensure_request(self, key: str, targets: Sequence[str], tcp_ports: Sequence[int], hosts: Sequence[str]) -> int:
        """The id of the request ``key``: inserted, or the existing row returned unchanged."""
        with self._transaction(write=True) as connection:
            return _request_id(connection, key, targets, tcp_ports, hosts)

    def start_run(
        self,
        run_id: str,
        request_id: int,
        *,
        source: Optional[str],
        started: float,
        interval: Optional[float],
        until: Optional[float],
        host: str,
        pid: int,
        heartbeat: Optional[float] = None,
    ) -> None:
        """Insert the run, ``running``, before its first round; its first heartbeat is ``heartbeat`` (the wall clock
        when the row is written, which a slow start can put well after ``started``), else ``started``."""
        with self._transaction(write=True) as connection:
            _insert_run(connection, run_id, request_id, source=source, started=started, interval=interval, until=until,
                        host=host, pid=pid, heartbeat=heartbeat)

    def begin_run(
        self,
        key: str,
        targets: Sequence[str],
        tcp_ports: Sequence[int],
        hosts: Sequence[str],
        run_id: str,
        **run: Any,
    ) -> int:
        """``ensure_request`` and ``start_run`` (``run`` is its keywords) in one transaction, and the request's id: a
        prune in another process never finds the request between the two, without a run, and deletes it."""
        with self._transaction(write=True) as connection:
            request_id = _request_id(connection, key, targets, tcp_ports, hosts)
            _insert_run(connection, run_id, request_id, **run)
            return request_id

    def admit_run(
        self, key: str, targets: Sequence[str], tcp_ports: Sequence[int], hosts: Sequence[str], run_id: str,
        *, going_on: Callable[[RunInfo], bool], **run: Any,
    ) -> int:
        """Atomically admit a run unless an existing running row is still live.

        The caller supplies the existing host/PID/heartbeat predicate; it is evaluated under the writer lock.
        Lost rows are preserved, and a refusal rolls back the whole transaction.
        """
        with self._transaction(write=True) as connection:
            request_id = _request_id(connection, key, targets, tcp_ports, hosts)
            for existing in _run_infos(connection, request_id, running=True):
                if going_on(existing):
                    raise AlreadyRunning(existing)
            _insert_run(connection, run_id, request_id, **run)
            return request_id

    def heartbeat(self, run_id: str, now: float, *, round_seconds: Optional[float] = None) -> None:
        """Refresh the run's heartbeat (after every batch), and its last round's length when one ended."""
        with self._transaction(write=True) as connection:
            if round_seconds is None:
                cursor = connection.execute("UPDATE run SET heartbeat = ? WHERE id = ?", (now, run_id))
            else:
                cursor = connection.execute(
                    "UPDATE run SET heartbeat = ?, round_seconds = ? WHERE id = ?", (now, round_seconds, run_id)
                )
            self._require_run(cursor, run_id)

    def record_round(self, run_id: str, started: float, observations: str, rows: Iterable[ResultRow]) -> int:
        """
        Store a finished round in one transaction: a follower never sees half of it. ``rows`` are the
        hosts it saw (``answered`` is their number). Returns the round's id, never reused.
        """
        rows = list(rows)
        with self._transaction(write=True) as connection:
            cursor = connection.execute(
                "INSERT INTO round (run_id, started, observations, answered) VALUES (?, ?, ?, ?)",
                (run_id, started, observations, len(rows)),
            )
            round_id = int(cursor.lastrowid)
            connection.executemany(
                "INSERT INTO result (round_id, host, address, t, result, tcp) VALUES (?, ?, ?, ?, ?, ?)",
                [(round_id, row.host, row.address, row.t, row.result, _dump_tcp(row.tcp)) for row in rows],
            )
        return round_id

    def end_run(self, run_id: str, *, ended: float, status: str) -> None:
        """
        Write the run's end and final status.

        @raise ValueError: ``status`` is not ``finished``, ``stopped`` or ``failed``.
        """
        if status not in _FINAL_STATUSES:
            raise ValueError(f"a run ends finished, stopped or failed, not {status!r}")
        with self._transaction(write=True) as connection:
            cursor = connection.execute("UPDATE run SET ended = ?, status = ? WHERE id = ?", (ended, status, run_id))
            self._require_run(cursor, run_id)

    def prune(self, now: float, days: int) -> int:
        """
        In one transaction, delete the rounds started more than ``days`` days before ``now`` (their
        result rows go by cascade), then the runs left without rounds, then the requests left without
        runs. Returns the number of rounds deleted.

        A run left without rounds goes when it is not ``running``, or when it still says ``running``
        but its heartbeat is older than the cut-off (at least one day) and than ``GAP_FACTOR`` of its
        intervals: a run that was killed never wrote its end, while a live one every two days writes
        no heartbeat between its rounds and keeps its row (and its request) for the next.
        """
        with self._transaction(write=True) as connection:
            deleted = connection.execute("DELETE FROM round WHERE started < ?", (now - days * _DAY,)).rowcount
            connection.execute(
                "DELETE FROM run WHERE (status != 'running' OR (heartbeat < ? AND heartbeat + ? * COALESCE(interval, 0) < ?))"
                " AND NOT EXISTS (SELECT 1 FROM round WHERE round.run_id = run.id)",
                (now - max(days, 1) * _DAY, GAP_FACTOR, now),
            )
            connection.execute(
                "DELETE FROM request WHERE NOT EXISTS (SELECT 1 FROM run WHERE run.request_id = request.id)"
            )
        return int(deleted)

    def delete(
        self, keys: Optional[Sequence[str]], *, going_on: Callable[[RunInfo], bool], guard_all: bool = False,
    ) -> Deletion:
        """
        Delete the requests whose keys are ``keys`` (``None``: every one) with their runs, in one short transaction.

        Only the ``run`` and ``request`` rows go: the rounds and their results stay, owned by no run, and every read
        reaches a round through its run, so the request is gone, whole, at the commit, for every reader (cn 0.8.0's
        too). ``sweep`` frees the rounds after. Deleting them here, under one lock, took 9 to 16 s for 4.3 million result
        rows, and another run waits 10 s for the lock at most. The cascades would delete them, so foreign keys are off
        for this transaction (SQLite ignores the pragma inside one), and on again after, whatever happens.

        ``going_on`` is asked about every row of the requests that says ``running``, inside the lock: when it accepts
        one, nothing is deleted and ``Deletion.going_on`` has those runs. With ``guard_all``, every
        selected run is checked and invalid or absent parent request keys are refused.
        """
        if not self._write:
            raise StoreError(f"cannot write {self.path}: opened read-only")
        sqlite3 = _sqlite3()
        connection = self._connection
        where, params = ("", ()) if keys is None else (f"WHERE key IN ({', '.join('?' * len(keys))})", tuple(keys))
        with _reported("write", self.path):
            connection.execute("PRAGMA foreign_keys = OFF")
        try:
            with self._transaction(write=True):
                infos = _request_infos(connection, where, params)
                if guard_all:
                    scoped_where = "" if keys is None else f"WHERE request.key IN ({', '.join('?' * len(keys))})"
                    rows = connection.execute(
                        f"SELECT {_RUN_COLUMNS}, request.key FROM run LEFT JOIN request ON request.id = run.request_id "
                        f"{scoped_where}", params,
                    )
                    guarded = []
                    for row in rows:
                        run, key = RunInfo(*row[:-1]), row[-1]
                        if not isinstance(key, str) or re.fullmatch(r"[0-9a-fA-F]{64}", key) is None:
                            raise StoreError(f"cannot write {self.path}: invalid or missing parent request key")
                        if going_on(run):
                            guarded.append(run)
                    running = tuple(guarded)
                else:
                    running = tuple(run for info in infos for run in info.running if going_on(run))
                if running:
                    return Deletion(tuple(infos), going_on=running)  # nothing was written: the commit is a no-op
                if keys is None:
                    connection.execute("DELETE FROM run")
                    connection.execute("DELETE FROM request")
                elif infos:
                    marks = ", ".join("?" * len(infos))
                    ids = [info.id for info in infos]
                    connection.execute(f"DELETE FROM run WHERE request_id IN ({marks})", ids)
                    connection.execute(f"DELETE FROM request WHERE id IN ({marks})", ids)
                return Deletion(tuple(infos))
        finally:
            with suppress(sqlite3.Error):  # a closed connection has nothing to restore
                connection.execute("PRAGMA foreign_keys = ON")

    def delete_run(self, run_id: str, request_id: int, *, going_on: Callable[[RunInfo], bool]) -> str:
        """Delete one inactive run, its rounds and results, and its empty request atomically.

        The identity and liveness checks and deletes share one writer lock. Other runs,
        including runs admitted while the caller was deciding, remain untouched.
        """
        if not self._write:
            raise StoreError(f"cannot write {self.path}: opened read-only")
        sqlite3 = _sqlite3()
        connection = self._connection
        with _reported("write", self.path):
            connection.execute("PRAGMA foreign_keys = OFF")
        timed_out = False
        try:
            with self._transaction(write=True):
                deadline = time.monotonic() + _DELETE_LOCK_SECONDS
                def check_deadline() -> int:
                    nonlocal timed_out
                    timed_out = time.monotonic() >= deadline
                    return int(timed_out)
                connection.set_progress_handler(check_deadline, _DELETE_PROGRESS_OPCODES)
                row = connection.execute(
                    f"SELECT {_RUN_COLUMNS}, request.key FROM run LEFT JOIN request ON request.id = run.request_id "
                    "WHERE run.id = ? AND run.request_id = ?",
                    (run_id, request_id),
                ).fetchone()
                if row is None:
                    return "missing"
                run, key = RunInfo(*row[:-1]), row[-1]
                if not isinstance(key, str) or re.fullmatch(r"[0-9a-fA-F]{64}", key) is None:
                    raise StoreError(f"cannot write {self.path}: invalid or missing parent request key")
                if going_on(run):
                    return "running"
                connection.execute(
                    "DELETE FROM result WHERE round_id IN (SELECT id FROM round WHERE run_id = ?)", (run_id,),
                )
                connection.execute("DELETE FROM round WHERE run_id = ?", (run_id,))
                connection.execute("DELETE FROM run WHERE id = ? AND request_id = ?", (run_id, request_id))
                connection.execute(
                    "DELETE FROM request WHERE id = ? AND NOT EXISTS "
                    "(SELECT 1 FROM run WHERE request_id = ?)", (request_id, request_id),
                )
                return "deleted"
        except StoreError as error:
            if timed_out:
                raise DeletionTimedOut(
                    "run deletion exceeded its safe database lock time; nothing was deleted"
                ) from error
            raise
        finally:
            connection.set_progress_handler(None, 0)
            with suppress(sqlite3.Error):
                connection.execute("PRAGMA foreign_keys = ON")

    def sweep(self, *, vacuum: bool = False) -> int:
        """
        Free the rounds no run owns (what ``delete`` leaves), with their results, in batches of at most
        ``_SWEEP_RESULTS`` result rows: each batch is one short transaction, and the sweep waits ``_SWEEP_PAUSE``
        between two of them, with nothing held, so a run that records meanwhile gets the lock. Returns the number of
        rounds freed.

        Ownership is read again under each batch's lock. Only ``delete`` makes such rounds, so a sweep that ends early
        (Ctrl+C, a crash) leaves rounds nobody sees, and the next one frees them. ``vacuum`` (after ``--clear``, which
        leaves the file empty) also rewrites the file, under the write lock: it never follows a ``--delete``, whose
        freed pages the next rounds reuse. The counters (``sqlite_sequence``) are kept, so a round id is never given
        twice.
        """
        if not self._write:
            raise StoreError(f"cannot write {self.path}: opened read-only")
        freed, last = 0, 0
        cut = self._orphans(last)
        while cut is not None:
            freed += self._free(last, cut)
            last, cut = cut, self._orphans(cut)
            if cut is not None:
                time.sleep(_SWEEP_PAUSE)
        if vacuum:
            with _reported("write", self.path):
                self._connection.execute("VACUUM")
        return freed

    def has_leftovers(self) -> bool:
        """Whether rounds no run owns are left: what a delete whose sweep was interrupted (Ctrl+C, a crash) leaves,
        which no reader sees. A read, for any connection."""
        return self._orphans(0) is not None

    def _orphans(self, last: int) -> Optional[int]:
        """The id that ends the next batch of rounds no run owns after ``last``, where their result rows reach
        ``_SWEEP_RESULTS`` (or the last one found), None when there are none. A read: it never blocks a WAL writer."""
        with self._transaction(write=False) as connection:
            found = connection.execute(
                f"SELECT id, answered FROM round WHERE id > ? AND {_UNOWNED} ORDER BY id LIMIT ?", (last, _SWEEP_BATCH)
            ).fetchall()
        cut, results = None, 0
        for round_id, answered in found:
            cut, results = round_id, results + answered
            if results >= _SWEEP_RESULTS:
                break
        return cut

    def _free(self, last: int, cut: int) -> int:
        """Delete the unowned rounds with an id in (``last``, ``cut``], their results first, in one transaction."""
        with self._transaction(write=True) as connection:
            connection.execute(
                f"DELETE FROM result WHERE round_id IN (SELECT id FROM round WHERE id > ? AND id <= ? AND {_UNOWNED})",
                (last, cut),
            )
            return int(connection.execute(
                f"DELETE FROM round WHERE id > ? AND id <= ? AND {_UNOWNED}", (last, cut)
            ).rowcount)

    def _require_run(self, cursor: "sqlite3.Cursor", run_id: str) -> None:
        if cursor.rowcount == 0:
            raise StoreError(f"cannot write {self.path}: no run {run_id}")

    # --- reader ----------------------------------------------------------------------------------

    def history_page(
        self, kind: str, parent: Any = None, *, after: Any = None, limit: int = 100,
    ) -> Tuple[List[Dict[str, Any]], Any]:
        """A bounded, changing view of requests, runs, rounds, or one round's hosts.

        ``after`` is the last key returned, scoped by the caller to its kind and parent. No transaction or
        snapshot survives the call. A removed parent or cursor raises ``HistoryExpired``.
        """
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("history limit must be between 1 and 100")
        if kind not in ("requests", "runs", "rounds", "hosts", "template"):
            raise ValueError("invalid history kind")
        if (kind == "requests" and parent is not None or
                kind in ("runs", "hosts") and not _history_integer(parent) or
                kind in ("rounds", "template") and (not isinstance(parent, str) or not parent) or
                kind == "template" and (after is not None or limit != 1)):
            raise ValueError("invalid history parent")
        if after is not None:
            valid = (_history_integer(after, 0 if kind == "hosts" else 1)
                     if kind in ("requests", "hosts") else
                     isinstance(after, (tuple, list)) and len(after) == 2
                     and _history_timestamp(after[0])
                     and ((isinstance(after[1], str) and bool(after[1])) if kind == "runs"
                          else _history_integer(after[1])))
            if not valid:
                raise ValueError("invalid history cursor")
        with self._transaction(write=False) as connection:
            if kind == "template":
                row = connection.execute(
                    "SELECT substr(request.targets, 1, 8193), substr(request.tcp_ports, 1, 8193),"
                    " run.interval, run.until, run.started FROM run JOIN request ON request.id = run.request_id"
                    " WHERE run.id = ?", (parent,),
                ).fetchone()
                if row is None:
                    raise HistoryExpired()
                targets_json, ports_json, interval, until, started = row
                try:
                    if not isinstance(targets_json, str) or not isinstance(ports_json, str):
                        raise ValueError("invalid template")
                    if len(targets_json) > 8192 or len(ports_json) > 8192:
                        raise HistoryTooLarge()
                    targets, ports = json.loads(targets_json), json.loads(ports_json)
                    if (not isinstance(targets, list) or not targets or not all(isinstance(t, str) and t.splitlines() == [t] for t in targets) or
                            not isinstance(ports, list) or len(ports) > 5 or
                            any(type(port) is not int or not 1 <= port <= 65535 for port in ports) or
                            len(set(ports)) != len(ports) or
                            (interval is not None and (type(interval) not in (int, float) or
                             not math.isfinite(interval) or
                             not -(2**63) <= interval <= 2**63 - 1))):
                        raise ValueError("invalid template")
                except (ValueError, TypeError, RecursionError) as error:
                    raise StoreError(f"cannot read {self.path}: invalid monitor template") from error
                whole_interval = int(interval) if interval is not None and int(interval) == interval else None
                return [dict(targets=targets, ports=ports, interval=whole_interval,
                             until=until, started=started)], None
            if kind == "requests":
                if after is not None and not connection.execute("SELECT 1 FROM request WHERE id = ?", (after,)).fetchone():
                    raise HistoryExpired()
                rows = connection.execute(
                    "SELECT id, substr(key, 1, 65), substr(targets, 1, ?), substr(tcp_ports, 1, ?), substr(hosts, 1, ?)"
                    " FROM request WHERE id > ? ORDER BY id LIMIT ?",
                    (_HISTORY_ARRAY_CHARS + 1,) * 3 + (after or 0, limit + 1),
                )
                items, keys = [], []
                for request_id, key, targets, ports, hosts in rows:
                    keys.append(request_id)
                    if len(keys) > limit:
                        break
                    targets_preview, target_count = _request_array_summary(targets)
                    ports_preview, port_count = _request_array_summary(ports, ports=True)
                    _, host_count = _request_array_summary(hosts, preview=False)
                    safe_key = key if isinstance(key, str) and len(key) <= 64 else ""
                    items.append(dict(id=request_id, key=safe_key, targets_preview=targets_preview,
                                      ports_preview=ports_preview, target_count=target_count,
                                      port_count=port_count, host_count=host_count))
                if len(keys) > limit:
                    return items, keys[limit - 1]
            elif kind == "runs":
                if not connection.execute("SELECT 1 FROM request WHERE id = ?", (parent,)).fetchone():
                    raise HistoryExpired()
                if after is not None and not connection.execute(
                    "SELECT 1 FROM run WHERE request_id = ? AND started = ? AND id = ?", (parent, *after)
                ).fetchone():
                    raise HistoryExpired()
                where = " AND (run.started > ? OR (run.started = ? AND run.id > ?))" if after else ""
                params = (parent, after[0], after[0], after[1], limit + 1) if after else (parent, limit + 1)
                rows = connection.execute(
                    f"SELECT {_RUN_COLUMNS} FROM run WHERE run.request_id = ?{where}"
                    " ORDER BY run.started, run.id LIMIT ?", params
                ).fetchall()
                items = [dict(zip(RunInfo.__dataclass_fields__, row)) for row in rows]
                keys = [(row[3], row[0]) for row in rows]
            elif kind == "rounds":
                if not connection.execute("SELECT 1 FROM run WHERE id = ?", (parent,)).fetchone():
                    raise HistoryExpired()
                if after is not None and not connection.execute(
                    "SELECT 1 FROM round WHERE run_id = ? AND started = ? AND id = ?", (parent, *after)
                ).fetchone():
                    raise HistoryExpired()
                where = " AND (started > ? OR (started = ? AND id > ?))" if after else ""
                params = (parent, after[0], after[0], after[1], limit + 1) if after else (parent, limit + 1)
                rows = connection.execute(
                    f"SELECT id, started, answered FROM round WHERE run_id = ?{where} ORDER BY started, id LIMIT ?",
                    params,
                ).fetchall()
                items = [dict(id=row[0], started=row[1], answered=row[2]) for row in rows]
                keys = [(row[1], row[0]) for row in rows]
            else:
                found = connection.execute(
                    "SELECT request.hosts, round.observations FROM round JOIN run ON run.id = round.run_id"
                    " JOIN request ON request.id = run.request_id WHERE round.id = ?", (parent,)
                ).fetchone()
                if found is None:
                    raise HistoryExpired()
                selected = []
                anchor_found = after is None
                try:
                    for index, host in enumerate(_host_names(found[0])):
                        if index == after:
                            anchor_found = True
                        if after is None or index > after:
                            selected.append((index, host))
                            if len(selected) == limit + 1:
                                break
                except ValueError as error:
                    raise StoreError(f"cannot read {self.path}: invalid hosts array") from error
                if not anchor_found:
                    raise HistoryExpired()
                details = {}
                if selected:
                    names = [host for _, host in selected]
                    rows = connection.execute(
                        "SELECT host, address, result FROM result WHERE round_id = ?"
                        f" AND host IN ({', '.join('?' * len(names))})", (parent, *names),
                    ).fetchall()
                    details = {host: (address, result) for host, address, result in rows}
                items = [dict(index=index, host=host, observation=found[1][index:index + 1],
                              address=details.get(host, (None, None))[0], result=details.get(host, (None, None))[1])
                         for index, host in selected]
                keys = [index for index, _ in selected]
        return items[:limit], keys[limit - 1] if len(items) > limit else None

    def requests(self) -> List[RequestInfo]:
        """Every request with its counts and newest run, newest activity (last round or newest run start) first."""
        with self._transaction(write=False) as connection:
            return _request_infos(connection, "", ())

    def find(self, prefix: str) -> List[RequestInfo]:
        """
        The requests whose key starts with ``prefix``, case-insensitively, newest activity first.

        @raise ValueError: ``prefix`` is not 4 or more hex digits.
        """
        problem = id_problem(prefix)
        if problem:
            raise ValueError(problem)
        with self._transaction(write=False) as connection:
            return _request_infos(connection, "WHERE lower(substr(key, 1, ?)) = ?", (len(prefix), prefix.lower()))

    def request(self, key: str) -> Optional[RequestInfo]:
        """The request whose key is ``key``, or ``None``."""
        with self._transaction(write=False) as connection:
            found = _request_infos(connection, "WHERE key = ?", (key,))
        return found[0] if found else None

    def other_ports(self, targets: Sequence[str], key: str) -> List[Tuple[int, ...]]:
        """The TCP ports of every other request (key differs) with exactly these ``targets``, oldest request first."""
        wanted = list(targets)
        with self._transaction(write=False) as connection:
            rows = connection.execute(
                "SELECT targets, tcp_ports FROM request WHERE key != ? ORDER BY id", (key,)
            ).fetchall()
        return [tuple(json.loads(ports)) for stored, ports in rows if json.loads(stored) == wanted]

    def request_brief(self, request_id: int) -> Optional[Dict[str, Any]]:
        """A bounded request description for a confirmation, without reading its host list."""
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT substr(key, 1, 65), substr(targets, 1, ?), substr(tcp_ports, 1, ?) "
                "FROM request WHERE id = ?", (_HISTORY_ARRAY_CHARS + 1, _HISTORY_ARRAY_CHARS + 1, request_id),
            ).fetchone()
        if row is None:
            return None
        key, targets, ports = row
        target_preview, target_count = _request_array_summary(targets)
        port_preview, port_count = _request_array_summary(ports, ports=True)
        return dict(key=key if isinstance(key, str) and len(key) <= 64 else "", targets_preview=target_preview,
                    target_count=target_count, ports_preview=port_preview, port_count=port_count)

    def run(self, run_id: str) -> Optional[RunInfo]:
        """The run with exactly this ID and its current round count, or None."""
        with self._transaction(write=False) as connection:
            row = connection.execute(f"SELECT {_RUN_COLUMNS} FROM run WHERE run.id = ?", (run_id,)).fetchone()
        return RunInfo(*row) if row is not None else None

    def runs(self, request_id: int) -> List[RunInfo]:
        """The request's runs, newest first (by ``started``)."""
        with self._transaction(write=False) as connection:
            return _run_infos(connection, request_id)

    def rounds(
        self,
        request_id: int,
        *,
        since: Optional[float] = None,
        before: Optional[float] = None,
        after: Optional[Cursor] = None,
        newer_than: int = 0,
        through: Optional[int] = None,
        limit: int = 500,
    ) -> List[StoredRound]:
        """
        One page: up to ``limit`` rounds of every run of the request, each with its rows, in start order (the
        id breaks a tie), never in commit order: two runs of one request can commit out of start order. The
        rounds start at or after ``since`` and before ``before``, come after ``after`` (the ``(started, id)``
        of the previous page's last round) and have an id above ``newer_than`` (those committed after a read)
        and up to ``through`` (``last_round_id`` when a read began: what another run commits during the read,
        behind its cursor or ahead of it, waits for the next one).

        @raise ValueError: ``limit`` is below 1 (SQLite reads ``LIMIT -1`` as no limit).
        """
        if limit < 1:
            raise ValueError(f"a page holds at least one round, not limit={limit}")
        match, params = _rounds_of(request_id, newer_than=newer_than, through=through, before=before, since=since,
                                   after=after)
        with self._transaction(write=False) as connection:
            found = connection.execute(
                "SELECT round.id, round.run_id, round.started, run.interval, round.observations, round.answered"
                f" {_ROUNDS} WHERE {match} ORDER BY round.started, round.id LIMIT ?",
                (*params, limit),
            ).fetchall()
            if not found:
                return []
            ids = [row[0] for row in found]
            details = connection.execute(
                "SELECT round_id, host, address, t, result, tcp FROM result"
                f" WHERE round_id IN ({', '.join('?' * len(ids))}) ORDER BY round_id, host",
                ids,
            ).fetchall()
        rows: Dict[int, List[ResultRow]] = {}
        for round_id, host, address, t, result, tcp in details:
            rows.setdefault(round_id, []).append(ResultRow(host, address, t, result, _load_tcp(tcp)))
        return [
            StoredRound(round_id, run_id, started, interval, observations, answered, tuple(rows.get(round_id, ())))
            for round_id, run_id, started, interval, observations, answered in found
        ]

    def last_round_id(self) -> int:
        """
        The id of the newest round recorded, 0 before the first. Ids follow commit order (one writer at a time)
        and AUTOINCREMENT never gives one twice, so no round at or below it can be committed later.
        """
        with self._transaction(write=False) as connection:
            return connection.execute("SELECT COALESCE(MAX(id), 0) FROM round").fetchone()[0]

    def round_starts(
        self, request_id: int, *, before: Optional[float] = None, since: Optional[float] = None,
        through: Optional[int] = None,
    ) -> List[Tuple[float, Optional[float]]]:
        """
        The start of each of the request's rounds and its run's interval, oldest first, without their rows: what the
        tracker needs (the median spacing of one-round runs) before it reads the rounds themselves, up to the same
        ``through`` mark (``last_round_id``) as the rounds.
        """
        match, params = _rounds_of(request_id, through=through, before=before, since=since)
        with self._transaction(write=False) as connection:
            return [
                (started, interval)
                for started, interval in connection.execute(
                    f"SELECT round.started, run.interval {_ROUNDS} WHERE {match} ORDER BY round.started, round.id",
                    params,
                )
            ]

    def oldest_round_start(self, request_id: int, *, since: Optional[float] = None) -> Optional[float]:
        """The start of the request's oldest round from ``since`` on, None without one: a follower whose first round is
        older than it lost rounds to another run's prune (the request keeps its id)."""
        match, params = _rounds_of(request_id, since=since)
        with self._transaction(write=False) as connection:
            (oldest,) = connection.execute(f"SELECT MIN(round.started) {_ROUNDS} WHERE {match}", params).fetchone()
        return None if oldest is None else float(oldest)


def id_problem(prefix: str) -> Optional[str]:
    """What is wrong with a request ID as ``--show`` and ``--follow`` take it (4 or more hex digits), or None."""
    return None if _PREFIX.fullmatch(prefix) else ID_MESSAGE.format(prefix=prefix)


def _rounds_of(
    request_id: int,
    *,
    newer_than: int = 0,
    through: Optional[int] = None,
    before: Optional[float] = None,
    since: Optional[float] = None,
    after: Optional[Cursor] = None,
) -> Tuple[str, List[Any]]:
    """The condition, over ``_ROUNDS``, for a request's rounds with an id above ``newer_than`` and up to
    ``through``, before ``before``, since ``since`` and after the ``(started, id)`` cursor ``after``."""
    conditions, params = ["run.request_id = ?", "round.id > ?"], [request_id, newer_than]
    if through is not None:
        conditions.append("round.id <= ?")
        params.append(through)
    if after is not None:
        conditions.append("(round.started > ? OR (round.started = ? AND round.id > ?))")
        params.extend([after[0], after[0], after[1]])
    if before is not None:
        conditions.append("round.started < ?")
        params.append(before)
    if since is not None:
        conditions.append("round.started >= ?")
        params.append(since)
    return " AND ".join(conditions), params


def _round_span(
    connection: "sqlite3.Connection", match: str, params: Sequence[Any]
) -> Tuple[int, Optional[float], Optional[float]]:
    """The number, first and last start of the rounds that ``match`` selects."""
    count, first, last = connection.execute(
        f"SELECT COUNT(round.id), MIN(round.started), MAX(round.started) {_ROUNDS} WHERE {match}", params
    ).fetchone()
    return int(count), first, last


def _run_infos(
    connection: "sqlite3.Connection", request_id: int, *, limit: int = -1, running: bool = False
) -> List[RunInfo]:
    """The request's runs (with ``running``, those whose row says so), newest first; ``limit`` -1 is every one."""
    only = " AND run.status = 'running'" if running else ""
    rows = connection.execute(
        f"SELECT {_RUN_COLUMNS} FROM run WHERE run.request_id = ?{only} ORDER BY run.started DESC, run.rowid DESC"
        " LIMIT ?",
        (request_id, limit),
    ).fetchall()
    return [RunInfo(*row) for row in rows]


def _request_infos(connection: "sqlite3.Connection", where: str, params: Tuple[Any, ...]) -> List[RequestInfo]:
    """The requests ``where`` selects, with their counts and newest run, newest activity first."""
    infos = []
    for request_id, key, targets, tcp_ports, hosts in connection.execute(
        f"SELECT id, key, targets, tcp_ports, hosts FROM request {where}", params
    ).fetchall():
        (runs,) = connection.execute("SELECT COUNT(*) FROM run WHERE request_id = ?", (request_id,)).fetchone()
        rounds, first, last = _round_span(connection, *_rounds_of(request_id))
        newest = _run_infos(connection, request_id, limit=1)
        infos.append(
            RequestInfo(
                id=request_id,
                key=key,
                targets=tuple(json.loads(targets)),
                tcp_ports=tuple(json.loads(tcp_ports)),
                hosts=tuple(json.loads(hosts)),
                runs=runs,
                rounds=rounds,
                first_round=first,
                last_round=last,
                newest_run=newest[0] if newest else None,
                running=tuple(_run_infos(connection, request_id, running=True)),
            )
        )
    infos.sort(key=_activity, reverse=True)
    return infos


def _activity(info: RequestInfo) -> Tuple[float, int]:
    """Newest activity: the later of the last round and the newest run's start; the newer request on a tie."""
    times = [info.last_round, info.newest_run.started if info.newest_run else None]
    return max((t for t in times if t is not None), default=float("-inf")), info.id
