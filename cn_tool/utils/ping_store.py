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
import re
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from cn_tool.utils.ping_history import GAP_FACTOR

if TYPE_CHECKING:  # only for the annotations: sqlite3 is imported where it is used
    import sqlite3
    from types import ModuleType

SCHEMA_VERSION = 1
RUN_STATUSES = ("running", "finished", "stopped", "failed")
_FINAL_STATUSES = RUN_STATUSES[1:]
_BUSY_TIMEOUT = 10  # seconds a connection waits for another one's write lock
_DAY = 86400
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


def _reader_uri(path: Path) -> str:
    """The read-only ``file:`` URI of ``path``. A Windows UNC path (``\\\\server\\share\\...``) turns into a URI
    with a host, which SQLite refuses: its name goes after ``file:`` as it is, escaped, which SQLite reads as a path."""
    uri = path.absolute().as_uri()
    if not uri.startswith("file:///"):
        from urllib.parse import quote

        uri = "file:" + quote(str(path.absolute()), safe="\\/:")
    return f"{uri}?mode=ro"


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _dump_tcp(tcp: Optional[Dict[int, str]]) -> Optional[str]:
    return None if tcp is None else _dump({str(port): state for port, state in sorted(tcp.items())})


def _load_tcp(text: Optional[str]) -> Optional[Dict[int, str]]:
    return None if text is None else {int(port): state for port, state in json.loads(text).items()}


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
    def open(cls, path: Path, *, write: bool) -> Optional["PingStore"]:
        """
        Open the history at ``path``, as a writer or a reader.

        A reader of a missing file gets ``None`` ("nothing recorded"): ``connect()`` would create it.
        A writer creates missing parent directories, and the schema in an empty database.

        @raise StoreError: the file cannot be opened, is not a cn ping history (a text file, another
            program's database), or was written by a newer cn; or this Python has no ``sqlite3``.
        """
        path = Path(path)
        if not write and not _exists(path):
            return None
        sqlite3 = _sqlite3()
        verb = "write" if write else "read"
        if write:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as error:
                raise StoreError(f"cannot write {path}: {error.strerror or error}") from error
        # A reader opens read-only, so a history removed since the check above is never created again.
        uri = None if write else _reader_uri(path)
        try:
            with _reported(verb, path):
                connection = sqlite3.connect(uri or str(path), timeout=_BUSY_TIMEOUT, isolation_level=None,
                                             uri=uri is not None)
        except StoreError:
            if not write and not _exists(path):
                return None
            raise
        store = cls(path, connection, write=write)
        try:
            with _reported(verb, path):
                connection.execute("PRAGMA foreign_keys = ON")  # off by default: the cascades need it
            store._check_schema()
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

    def _check_schema(self) -> None:
        """A writer creates the schema in an empty database; anything but a cn store of this version is refused."""
        with self._transaction(write=self._write) as connection:
            tables = {name for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
            if not tables and self._write:
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

    def _require_run(self, cursor: "sqlite3.Cursor", run_id: str) -> None:
        if cursor.rowcount == 0:
            raise StoreError(f"cannot write {self.path}: no run {run_id}")

    # --- reader ----------------------------------------------------------------------------------

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
