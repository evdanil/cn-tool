# modules/ping_monitor.py
"""
Menu item m and ``cn monitor``: ping a request round after round, record every round in the ping history, and
summarise what was seen; list, show and follow what was recorded (docs/plans/2026-10-ping-monitor-plan.md).

``PingMonitorModule`` is ``BulkPingModule`` with its own menu item and command: target parsing, name resolution and
the ping and TCP probes are inherited, and ``_sweep`` gives a round batch by batch. The model is
``utils/ping_history.py``, the store ``utils/ping_store.py``, the grid ``utils/ping_grid.py`` and the terminal
``utils/ping_live.py``.
"""
from __future__ import annotations

import argparse
import math
import os
import re
import shutil
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, Iterable, Iterator, List, Mapping, NamedTuple, Optional, Sequence, Set, Tuple

from rich.cells import cell_len, set_cell_size
from rich.markup import escape

from cn_tool.core.base import CliResult, ScriptContext, cli_exit_code
from cn_tool.modules import bulk_ping
from cn_tool.utils import oscompat, ping_grid, ping_live
from cn_tool.utils import ping_history as ph
from cn_tool.utils.cli_input import read_objects
from cn_tool.utils.config_history import format_time, since_time
from cn_tool.utils.display import console, get_global_color_scheme, print_table_data, table_columns
from cn_tool.utils.file_io import queue_save
from cn_tool.utils.ping_store import PingStore, RequestInfo, ResultRow, RunInfo, StoreError, StoredRound, id_problem
from cn_tool.utils.user_input import press_any_key, read_user_input

Row = Dict[str, Any]
UserInput = Tuple[str, str, List[str]]

MIN_INTERVAL = 10.0  # seconds: a sane floor, not a safety limit (an overrun skips slots instead)
DEFAULT_INTERVAL = 60.0  # --for without --every
RESOLVE_BEAT = 10.0  # seconds between heartbeats while a round's names resolve, well inside run_state's 60 s
RESOLVE_POLL = 0.5  # real seconds between looks at the keys and the clock while a batch of lookups runs
FOLLOW_POLL = 2.0  # seconds between two reads of the store while following another run
SLICE = 0.5  # the longest wait without looking at the keys and the stop request
SHEET = "Ping Monitor"
TABLE_PERIODS = 3  # online periods the table shows; JSON, CSV and the report get all
BATCH_ESTIMATE = 3.0  # seconds a batch takes, for the warning before the first round
MACOS_IPV6_BATCH_ESTIMATE = 9.0
_FRAME_LINES = 5  # the frame's lines around the grid but the legend: header, counters, two blank lines, footer
CHANGE_LINES = 3  # the change lines printed above the frame that the screen keeps in view (plan section 2.4)
LIST_SHOWN = 20  # requests the menu lists; cn monitor --list lists every one
RUNS_SHOWN = 5  # runs a summary's header names one by one; one-round runs are counted
DISPLAY_THRESHOLD = 32  # item 6's: a subnet with more hosts shows the seen ones and one line for the rest
_HISTORY = "cn: monitor: history: {}"
_NO_ROUND = "No round finished."


def usage_problem(args: argparse.Namespace) -> Optional[str]:
    """
    What is wrong with a ``cn monitor`` command line, or None: the modes (targets, ``--list``, ``--show``,
    ``--follow``) exclude each other, ``--every``/``--for``/``--tcp`` go with targets only, ``--since`` not with
    ``--list``, an ID has 4 or more hex digits, and the interval and the duration are at least ``MIN_INTERVAL``.
    ``main`` refuses with it before anything starts.
    """
    modes = [name for name in ("list", "show", "follow") if getattr(args, name, None) not in (None, False)]  # even ''"
    since = getattr(args, "since", None)
    if len(modes) > 1:
        return " and ".join(f"--{mode}" for mode in modes) + " cannot be combined"
    if modes:
        mode = modes[0]
        if getattr(args, "objects", None) or getattr(args, "file", None) is not None:
            return f"--{mode} takes no targets"
        for name, flag in (("tcp", "--tcp"), ("every", "--every"), ("run_for", "--for")):
            if getattr(args, name, None) is not None:
                return f"{flag} goes with targets, not with --{mode}"
        if mode == "list" and since is not None:
            return "--since does not go with --list"
        if mode != "list":
            return id_problem(getattr(args, mode))
    every, run_for = getattr(args, "every", None), getattr(args, "run_for", None)
    if every is not None and every.total_seconds() < MIN_INTERVAL:
        return f"--every must be at least {int(MIN_INTERVAL)}s"
    if run_for is not None and run_for.total_seconds() < MIN_INTERVAL:  # as the menu's question: 0s is no run
        return f"--for must be at least {int(MIN_INTERVAL)}s"
    if every is not None and run_for is not None and run_for < every:
        return "--for must be at least as long as --every"
    return None


def _when(stamp: Optional[float]) -> str:
    """A time as ``format_time`` prints it (``cn diff``'s form), or "" for none."""
    return "" if stamp is None else format_time(datetime.fromtimestamp(stamp, tz=timezone.utc))


def _day(stamp: float) -> str:
    return datetime.fromtimestamp(stamp, tz=timezone.utc).strftime("%Y-%m-%d")


def _clock(stamp: float, now: Optional[float] = None) -> str:
    """``09:14:00`` (UTC), with the date in front when ``now`` is given and falls on another day."""
    moment = datetime.fromtimestamp(stamp, tz=timezone.utc)
    if now is not None and _day(stamp) != _day(now):
        return moment.strftime("%Y-%m-%d %H:%M:%S")
    return moment.strftime("%H:%M:%S")


def _span(seconds: float) -> str:
    """``30s``, ``5m``, ``2h``, ``1d``: an interval as it was typed, when it is a whole number of a unit."""
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size and seconds % size == 0:
            return f"{int(seconds // size)}{unit}"
    return f"{int(seconds)}s"


def _slots(started: float, interval: float, until: float) -> int:
    """How many slots ``started + n x interval`` fall before ``until``: the "up to" of ``round 14 of up to 120``."""
    return math.ceil((until - started) / interval)


def _tcp_open(rows: Iterable[ResultRow]) -> bool:
    """A stored row with a port that was open."""
    return any(state == "open" for row in rows for state in (row.tcp or {}).values())


def _say(message: str) -> None:
    """One line on the console (stderr in command-line mode), as it is: no markup, no wrap."""
    console.print(message, markup=False, soft_wrap=True)


def _since(since: Any) -> Optional[float]:
    """``--since`` as a time (an age counts back from now), or None for every round kept."""
    if since is None:
        return None
    when = since_time(since, datetime.fromtimestamp(time.time(), tz=timezone.utc))
    return when.timestamp() if when is not None else None


# --- the request and what a run leaves -----------------------------------------------------------------

@dataclass(frozen=True)
class Request:
    """What is pinged: the canonical tokens, the ports, the host list (all three in the key) and the expanded
    targets the grid's blocks come from."""

    tokens: List[str]
    ports: Tuple[int, ...]
    hosts: List[str]
    inputs: List[UserInput]
    key: str

    @property
    def short_id(self) -> str:
        return ph.short_id(self.key)

    def index(self) -> Dict[str, int]:
        return {host: number for number, host in enumerate(self.hosts)}

    def blocks(self) -> List[ping_grid.Block]:
        subnets = [text for kind, text, _ in self.inputs if kind == "subnet"]
        singles = [host for kind, _, hosts in self.inputs if kind != "subnet" for host in hosts]
        return ping_grid.build_blocks(subnets, singles, self.index())


@dataclass
class RunPlan:
    """How a run goes: ``every`` seconds between round starts (None: one round), no round starts at or after
    ``until`` (None: until stopped), the summary takes the earlier rounds from ``since`` on (None: every one kept).
    ``source`` is the ``--file`` name the list shows."""

    every: Optional[float] = None
    until: Optional[float] = None
    since: Optional[float] = None
    source: Optional[str] = None
    icmp: bool = True


@dataclass
class RunOutcome:
    """What a run, or a read of the store, leaves for the summary."""

    request: Request
    tracker: ph.Tracker
    rounds: int = 0  # this run's (a read: every one read)
    earlier: int = 0  # read from the store before this run's first
    late: int = 0  # slots skipped by a round that overran
    first: Optional[float] = None  # the start of this run's first round
    interval: Optional[float] = None
    last_rows: List[Row] = field(default_factory=list)
    last_id: int = 0  # every stored round up to this id is read (PingStore.last_round_id when the read began)
    unresolved: Set[str] = field(default_factory=set)  # names a round could not resolve
    resolved: Set[str] = field(default_factory=set)  # names a round resolved: never in not_found
    probe_failed: bool = False
    tcp_open: bool = False
    store_error: Optional[str] = None
    stop_reason: Optional[str] = None
    running: bool = False
    live_runs: FrozenSet[str] = frozenset()  # a read: the runs of the request going on
    last_run: Optional[str] = None  # a read: the run of the last round folded in

    def online_now(self) -> bool:
        """Whether a period the last round saw goes on now: the run that recorded that round is still going on. Another
        run going on never saw the host (it may not have recorded a round yet), so the period ended there."""
        return self.last_run is not None and self.last_run in self.live_runs


def _stored_round(stored: StoredRound) -> ph.Round:
    rows = {
        row.host: {"Host": row.host, "Address": row.address, "Result": row.result,
                   **{f"TCP {port}": state for port, state in (row.tcp or {}).items()}}
        for row in stored.rows
    }
    return ph.Round(stored.started, stored.interval, stored.observations, rows, {row.host: row.t for row in stored.rows})


def _stored_rounds(store: PingStore, request_id: int, *, since: Optional[float], before: Optional[float] = None,
                   newer_than: int = 0, through: Optional[int] = None) -> Iterator[StoredRound]:
    """The request's stored rounds with an id above ``newer_than`` and up to ``through``, in start order, a page at
    a time (each page one short read)."""
    after: Optional[Tuple[float, int]] = None
    while True:
        page = store.rounds(request_id, since=since, before=before, after=after, newer_than=newer_than,
                            through=through)
        if not page:
            return
        yield from page
        after = (page[-1].started, page[-1].id)


def _latest(request: Request, observations: str, rows: Mapping[str, Row]) -> List[Row]:
    """The ``latest`` section: every host of the request in host order, its row when the round has one, else its
    character read back as a result, with no address (plan section 2.2). A run's own and a later --show agree."""
    latest: List[Row] = []
    for host, char in zip(request.hosts, observations):
        row = rows.get(host)
        if row is None:
            row = {"Host": host, "Address": "", "Result": ph.result_text(char)}
            row.update({f"TCP {port}": "" for port in request.ports})
        latest.append(row)
    return latest


def _latest_from(request: Request, stored: StoredRound) -> List[Row]:
    """The ``latest`` section from a stored round (``_latest``): only a seen host has a stored row."""
    rows: Dict[str, Row] = {}
    for found in stored.rows:
        row: Row = {"Host": found.host, "Address": found.address, "Result": found.result}
        row.update({f"TCP {port}": (found.tcp or {}).get(port, "") for port in request.ports})
        rows[found.host] = row
    return _latest(request, stored.observations, rows)


def _targets_label(info: RequestInfo, width: int = 44) -> str:
    """``sites.txt: 10.1.2.0/24, web01.example.net +10``: the newest run's file, then the targets cut to one line."""
    source = info.newest_run.source if info.newest_run is not None else None
    shown: List[str] = []
    for token in info.targets:
        if shown and len(", ".join(shown + [token])) > width:
            break
        shown.append(token)
    label = ", ".join(shown) + (f" +{len(info.targets) - len(shown)}" if len(shown) < len(info.targets) else "")
    return f"{source}: {label}" if source else label


def state_text(state: str, detail: str) -> str:
    """The list's ``State`` column: ``running: round 14 of up to 120, next at 09:15:00``, ``lost at 09:14:00``,
    ``stopped early``, ``finished``, ``failed``. JSON keeps the word and the detail apart."""
    if state == "stopped":
        return "stopped early"
    if state == "running" and detail:
        return f"running: {detail}"
    return f"{state} {detail}".strip()


class PingMonitorModule(bulk_ping.BulkPingModule):
    """
    Menu item m and ``cn monitor``: a bulk ping over a period, recorded round by round, with a live grid, and the
    recorded requests listed, shown or followed without pinging (plan section 2).
    """
    cli_name = "monitor"

    @property
    def menu_key(self) -> str:
        return "m"

    @property
    def menu_title(self) -> str:
        return "Ping Monitor"

    # --- reading ICMP errors (plan section 4.5) -------------------------------------------------------
    def _classify_ping_result(self, returncode: Optional[int], output: str, *, ipv6: bool = False) -> str:
        """``cn ping``'s reading, and for a ``NO RESPONSE`` the ICMP error the output holds: ``REJECTED`` (the target
        itself sent it) or ``UNREACHABLE`` (anyone else did). ``_classify_stopped_ping`` comes through here too."""
        result = super()._classify_ping_result(returncode, output, ipv6=ipv6)
        if result == "NO RESPONSE":
            return ph.icmp_error_result(output) or result
        return result

    def _look_up(self, names: List[str]) -> List[Optional[str]]:
        """``cn ping``'s lookups, a batch of names at a time, each on a daemon thread (``_Background``): a name that
        waits on the resolver never holds the process open after a stop, as a pool's worker would."""
        answers: List[Optional[str]] = []
        for start in range(0, len(names), bulk_ping.BATCH_SIZE):
            lookups = [_Background(bulk_ping._lookup_address, name) for name in names[start:start + bulk_ping.BATCH_SIZE]]
            answers += [lookup.result() for lookup in lookups]
        return answers

    # --- the request -----------------------------------------------------------------------------------
    def _request(self, lines: Iterable[str], ports: Sequence[int], reject: Callable[[str, str], None]) -> Optional[Request]:
        """The request of the typed lines: their canonical tokens expanded again, so that every spelling of the same
        targets is one host list and one key (plan section 3.2). None when no line is usable."""
        tokens, _ = self._tokens(lines, reject, bulk_ping.MAX_TCP_HOSTS if ports else None)
        return self._request_of(tokens, ports) if tokens else None

    def _tokens(
        self, lines: Iterable[str], reject: Callable[[str, str], None], host_limit: Optional[int] = None
    ) -> Tuple[List[str], int]:
        """The canonical tokens of every usable line and the number of hosts they name. A line whose hosts an earlier
        line already named is a target too, so the order of the lines never changes the request."""
        typed: List[str] = []
        refused: Set[str] = set()

        def kept() -> Iterator[str]:
            for text in lines:
                typed.append(text)
                yield text

        def refuse(text: str, reason: str) -> None:
            refused.add(text)
            reject(text, reason)

        _, hosts = self._expand_targets(kept(), refuse, host_limit)
        usable: List[UserInput] = []
        for text in typed:
            kind, line_hosts, reason = self._parse_target(text)
            if text not in refused and reason is None and line_hosts:
                usable.append((kind, text, line_hosts))
        return ph.canonical_tokens(usable), len(hosts)

    def _request_of(self, tokens: Sequence[str], ports: Sequence[int], stored: Optional[RequestInfo] = None) -> Request:
        """A request from canonical tokens; a ``stored`` request keeps its own host list and key."""
        inputs, expanded = self._expand_targets(tokens, lambda target, reason: None)
        ordered = tuple(sorted(set(ports)))
        if stored is not None:
            return Request(list(tokens), ordered, list(stored.hosts), inputs, stored.key)
        return Request(list(tokens), ordered, expanded, inputs, ph.request_key(tokens, ordered, expanded))

    # --- the store -----------------------------------------------------------------------------------
    def _open_store(self, ctx: ScriptContext, *, write: bool) -> Tuple[Optional[PingStore], Optional[str]]:
        """The store, or None with the reason. A reader of a missing file gets (None, None): nothing recorded."""
        configured = ctx.cfg.get("ping_history_file")
        # "history_file =" left empty is the default: the path type reads an empty value as "." (the working directory).
        path = Path(configured if configured and str(configured) != "." else "~/.cn-ping-history.db").expanduser()
        try:
            return PingStore.open(path, write=write), None
        except StoreError as error:
            return None, str(error)

    def _state(self, run: RunInfo, now: Optional[float] = None) -> Tuple[str, str]:
        """A run's state word and its detail: ``running`` with ``round 14 of up to 120, next at 09:15:00``, ``lost``
        with ``at 09:14:00``, or ``finished``, ``stopped``, ``failed`` with none (plan section 2.3)."""
        now = time.time() if now is None else now
        state = ph.run_state(
            run.status, heartbeat=run.heartbeat, interval=run.interval, host=run.host, pid=run.pid, now=now,
            this_host=socket.gethostname(), pid_alive=oscompat.pid_exists,
        )
        if state == "lost":
            return state, f"at {_clock(run.heartbeat, now)}"
        if state != "running":
            return state, ""
        if run.interval is None:
            return state, "one round, in progress"
        detail = f"round {run.rounds}"
        detail += f" of up to {_slots(run.started, run.interval, run.until)}" if run.until is not None else " until stopped"
        upcoming = run.started + math.ceil((now - run.started) / run.interval) * run.interval
        if run.until is None or upcoming < run.until:
            detail += f", next at {_clock(upcoming, now)}"
        return state, detail

    def _live(self, info: RequestInfo, now: Optional[float] = None) -> Optional[RunInfo]:
        """The newest run of the request that is going on, if any (a lost one is not)."""
        return next((run for run in info.running if self._state(run, now)[0] == "running"), None)

    def _live_runs(self, info: Optional[RequestInfo]) -> FrozenSet[str]:
        """The ids of the request's runs that are going on (``RunOutcome.live_runs``)."""
        return frozenset(run.id for run in (info.running if info else ()) if self._state(run)[0] == "running")

    # --- the command line ----------------------------------------------------------------------------
    def run_cli(self, ctx: ScriptContext, args: argparse.Namespace) -> CliResult:
        """
        ``cn monitor``: a run (targets), ``--list``, ``--show ID`` or ``--follow ID``; the sections and exit status
        of each are in plan section 2.2. ``main`` has refused every mix of modes before (``usage_problem``).
        """
        ctx.logger.info("Request Type - Ping Monitor (command line)")
        if args.list:
            return self._cli_list(ctx, args.format)
        if args.show or args.follow:
            return self._cli_show(ctx, args)
        return self._cli_run(ctx, args)

    def _cli_run(self, ctx: ScriptContext, args: argparse.Namespace) -> CliResult:
        empty: Dict[str, List[Row]] = {"seen": [], "latest": [], "summary": [], "not_found": []}
        try:
            objects = read_objects(args.objects, args.file)
        except (OSError, UnicodeDecodeError) as exc:  # a file that is missing, a directory or not UTF-8
            source = "standard input" if args.file in (None, "-") else args.file
            _say(f"cn: monitor: cannot read {source}: {getattr(exc, 'strerror', None) or exc}")
            return CliResult(2, empty)
        if not objects:
            _say("cn: monitor: no targets given; see cn monitor --help")
            return CliResult(2, empty)

        ports = tuple(args.tcp or ())
        icmp = shutil.which("ping") is not None
        missing = bulk_ping._PING_MISSING.replace("cn: ping:", "cn: monitor:")
        if not icmp:
            if not ports:
                _say(missing)
                return CliResult(2, empty)
            _say(f"{missing}; ICMP skipped")

        not_found: List[Dict[str, str]] = []
        request = self._request(objects, ports, lambda target, reason: not_found.append({"object": target, "reason": reason}))
        if request is None:
            _say("cn: monitor: no usable target; see cn monitor --help")
            return CliResult(2, {**empty, "not_found": not_found})
        invalid = bool(not_found)

        every = args.every.total_seconds() if args.every else (DEFAULT_INTERVAL if args.run_for else None)
        source = getattr(args, "source_file", None)
        plan = RunPlan(
            every=every,
            until=time.time() + args.run_for.total_seconds() if args.run_for else None,
            since=_since(args.since),
            source=Path(source).name if source else None,
            icmp=icmp,
        )
        outcome = self._track(ctx, request, plan)
        if outcome.store_error:
            _say(_HISTORY.format(outcome.store_error))
        if not outcome.rounds:
            _say(_NO_ROUND)
        missed = outcome.unresolved - outcome.resolved  # names are resolved every round: one answer finds the host
        not_found.extend({"object": name, "reason": bulk_ping._NO_SUCH_HOST} for name in sorted(missed))

        data = {**self._sections(outcome, args.format), "not_found": not_found}
        self._save_report_rows(ctx, self._seen_rows(outcome, "report"))
        found = bool(outcome.rounds) and (outcome.tcp_open if request.ports else bool(data["seen"]))
        failed = outcome.probe_failed or outcome.store_error is not None
        return CliResult(cli_exit_code(found, invalid, failed), data)

    def _cli_list(self, ctx: ScriptContext, fmt: str) -> CliResult:
        store, error = self._open_store(ctx, write=False)
        if error:
            _say(_HISTORY.format(error))
            return CliResult(3, {"requests": []})
        if store is None:
            return CliResult(1, {"requests": []})
        with store:
            try:
                infos = store.requests()
            except StoreError as exc:
                _say(_HISTORY.format(exc))
                return CliResult(3, {"requests": []})
        rows = [self._request_row(info, fmt) for info in infos]
        return CliResult(0 if rows else 1, {"requests": rows})

    def _request_row(self, info: RequestInfo, fmt: str, number: Optional[int] = None) -> Row:
        """One row of the list: ``State`` is the running run's, else the newest run's; JSON splits it into ``State``
        (one word) and ``Detail``. The ``#`` column is the menu's."""
        now = time.time()
        run = self._live(info, now) or info.newest_run
        state, detail = self._state(run, now) if run is not None else ("", "")
        row: Row = {} if number is None else {"#": number}
        row.update({
            "ID": ph.short_id(info.key),
            "Targets": _targets_label(info),
            "TCP": ",".join(str(port) for port in info.tcp_ports) or "-",
            "Runs": info.runs,
            "Rounds": info.rounds,
            "Last round": _when(info.last_round),
        })
        if fmt == "json":
            row.update({"State": state, "Detail": detail})
        else:
            row["State"] = state_text(state, detail)
        return row

    def _find(self, store: PingStore, prefix: str) -> Tuple[Optional[RequestInfo], Optional[str]]:
        """The one request whose ID starts with ``prefix``, or the reason there is none."""
        try:
            matches = store.find(prefix)
        except ValueError as exc:
            return None, str(exc)
        if not matches:
            return None, f"no recorded request has the ID '{prefix}'; see cn monitor --list"
        if len(matches) > 1:
            candidates = ", ".join(ph.short_id(info.key) for info in matches)
            return None, f"'{prefix}' is the start of {len(matches)} IDs ({candidates}); give more digits"
        return matches[0], None

    def _cli_show(self, ctx: ScriptContext, args: argparse.Namespace) -> CliResult:
        empty: Dict[str, List[Row]] = {"seen": [], "latest": [], "summary": []}
        prefix = args.follow or args.show
        if args.follow and not ping_live.LiveScreen(get_global_color_scheme(ctx.cfg)).enabled:
            _say("cn: monitor: --follow needs a terminal on stderr; --show prints the summary")
            return CliResult(2, empty)
        store, error = self._open_store(ctx, write=False)
        if error:
            _say(_HISTORY.format(error))
            return CliResult(3, empty)
        if store is None:
            _say(f"cn: monitor: no recorded request has the ID '{prefix}': nothing is recorded yet")
            return CliResult(2, empty)
        with store:
            try:
                info, problem = self._find(store, prefix)
                if info is None:
                    _say(f"cn: monitor: {problem}")
                    return CliResult(2, empty)
                since = _since(args.since)
                outcome = self._read(store, info, since=since)
                if args.follow and outcome.running:
                    outcome = _Follow(self, ctx, store, info, outcome, since).go()
                elif args.follow:
                    _say(f"cn: monitor: no run of {ph.short_id(info.key)} is going on; showing its summary")
            except StoreError as exc:
                _say(_HISTORY.format(exc))
                return CliResult(3, empty)
        data = self._sections(outcome, args.format)
        self._save_report_rows(ctx, self._seen_rows(outcome, "report"))
        found = outcome.tcp_open if outcome.request.ports else bool(data["seen"])
        return CliResult(0 if found else 1, data)

    # --- reading the store ---------------------------------------------------------------------------
    def _read(self, store: PingStore, info: RequestInfo, *, since: Optional[float],
              note: Optional[Callable[[ph.Change], None]] = None, note_after: int = 0) -> RunOutcome:
        """A recorded request's summary from the store alone: its rounds from ``since`` on (None: every one kept).
        ``note`` gets the changes of the rounds with an id above ``note_after`` (a follower's window read again)."""
        request = self._request_of(info.targets, info.tcp_ports, info)
        with store.snapshot():  # the state, the starts and the rounds of one history, whatever another run does
            current = store.request(info.key)
            # A request pruned and named again since it was found (by another run) has a new id: its rounds are there.
            request_id = current.id if current is not None else info.id
            through = store.last_round_id()
            starts = store.round_starts(request_id, since=since, through=through)
            spacing = ph.expected_spacing(start for start, interval in starts if interval is None)
            outcome = RunOutcome(request, ph.Tracker(request.hosts, request.ports, spacing))
            self._take_stored(outcome, store, request_id, since, through=through, note=note, note_after=note_after)
        outcome.live_runs = self._live_runs(current)
        outcome.running = bool(outcome.live_runs)
        return outcome

    def _take_stored(self, outcome: RunOutcome, store: PingStore, request_id: int, since: Optional[float],
                     note: Optional[Callable[[ph.Change], None]] = None, through: Optional[int] = None,
                     note_after: int = 0) -> bool:
        """Fold the rounds committed after the last read into the outcome, in start order; ``note`` gets each change
        of a round with an id above ``note_after``.
        False when the caller must read the window again: one of them started before a round already folded in
        (another run of the request committed it late; the tracker takes rounds in time order only), or, after the
        first read, one is a one-round run's (it moves the median spacing the window was read with). The read holds
        to the rounds recorded when it began (``through``, else now): one committed during it, behind its cursor or
        not, waits for the next."""
        last: Optional[StoredRound] = None
        through = store.last_round_id() if through is None else through
        for stored in _stored_rounds(store, request_id, since=since, newer_than=outcome.last_id, through=through):
            if outcome.tracker.last_round is not None and stored.started < outcome.tracker.last_round:
                return False
            if stored.interval is None and outcome.last_id:
                return False
            for change in outcome.tracker.add(_stored_round(stored)):
                if note is not None and stored.id > note_after:
                    note(change)
            outcome.rounds += 1
            outcome.interval = stored.interval
            outcome.tcp_open = outcome.tcp_open or _tcp_open(stored.rows)
            last = stored
        outcome.last_id = max(outcome.last_id, through)
        if last is not None:
            outcome.last_rows = _latest_from(outcome.request, last)
            outcome.last_run = last.run_id
        return True

    # --- the menu ------------------------------------------------------------------------------------
    def run(self, ctx: ScriptContext) -> None:
        """Menu item m: the recorded requests when there are any, a summary of one, or a new run (plan 2.1, 2.3)."""
        ctx.logger.info("Request Type - Ping Monitor")
        _Menu(self, ctx).go()

    # --- a run ---------------------------------------------------------------------------------------
    def _track(self, ctx: ScriptContext, request: Request, plan: RunPlan) -> RunOutcome:
        """Run the plan: the earlier rounds first, then a round per slot until the end, ``q`` or a stop request, each
        recorded in the store and drawn in the live view (plan section 4.1). The menu and ``cn monitor`` share it."""
        return _Run(self, ctx, request, plan).go()

    # --- output --------------------------------------------------------------------------------------
    def _sections(self, outcome: RunOutcome, fmt: str) -> Dict[str, List[Row]]:
        return {
            "seen": self._seen_rows(outcome, fmt),
            "latest": list(outcome.last_rows),
            "summary": [self._summary_row(outcome, fmt)] if outcome.tracker.rounds else [],
        }

    def _seen_rows(self, outcome: RunOutcome, fmt: str) -> List[Row]:
        """The ``seen`` section (plan section 3.5) in ``fmt``: JSON gets numbers and the periods as a list, the
        table at most ``TABLE_PERIODS`` periods, CSV, Markdown and the report every one as text."""
        tracker = outcome.tracker
        with_dates = tracker.first_round is not None and _day(tracker.first_round) != _day(tracker.last_round)
        rows: List[Row] = []
        online_now = outcome.online_now()
        for summary in tracker.summaries():
            row: Row = {"Host": summary.host, "Address": summary.address, "Latest": summary.latest}
            row.update({f"TCP {port}": summary.tcp.get(port, "") for port in outcome.request.ports})
            row.update({"First seen": _when(summary.first_seen), "Last seen": _when(summary.last_seen)})
            if fmt == "json":
                open_now = online_now and summary.ongoing
                row.update({
                    "Seen rounds": summary.seen_rounds,
                    "Rounds": summary.rounds,
                    "Online": [
                        {"from": _when(start), "to": None if open_now and number == len(summary.periods) else _when(end)}
                        for number, (start, end) in enumerate(summary.periods, 1)
                    ],
                })
            else:
                row["Seen"] = f"{summary.seen_rounds} of {summary.rounds} rounds"
                row["Online"] = ph.online_text(
                    summary.periods, ongoing=summary.ongoing, running=online_now, with_dates=with_dates,
                    limit=TABLE_PERIODS if fmt == "table" else None,
                )
            rows.append(row)
        return rows

    def _summary_row(self, outcome: RunOutcome, fmt: str) -> Row:
        tracker = outcome.tracker
        if fmt == "json":
            interval: Any = outcome.interval
        else:
            interval = _span(outcome.interval) if outcome.interval else "one round"
        return {
            "ID": outcome.request.short_id,
            "Started": _when(tracker.first_round),
            "Ended": _when(tracker.last_round),
            "Rounds": outcome.rounds,
            "Earlier rounds": outcome.earlier,
            "Interval": interval,
            "Hosts": len(outcome.request.hosts),
            "Seen": len(tracker.summaries()),
            "Answering": sum(1 for char in tracker.cells() if char in ph.SEEN),
        }

    def _display_rows(self, outcome: RunOutcome) -> List[Row]:
        """The menu's table: every host of a single target or a small subnet, seen or not; for a larger subnet the
        hosts seen and one line for the rest, as item 6 folds the silent ones (plan section 2.1)."""
        seen = {row["Host"]: row for row in self._seen_rows(outcome, "table")}
        cells, index, ports = outcome.tracker.cells(), outcome.request.index(), outcome.request.ports
        rows: List[Row] = []

        def add(hosts: List[str], fold: Optional[str]) -> None:
            if fold is None or len(hosts) <= DISPLAY_THRESHOLD:
                rows.extend(
                    seen[host] if host in seen else _blank_row(
                        host, ports, Latest=ph.result_text(cells[index[host]]), Seen=f"0 of {outcome.tracker.rounds} rounds"
                    )
                    for host in hosts
                )
                return
            found = [seen[host] for host in hosts if host in seen]
            rows.extend(found)
            if len(found) < len(hosts):
                if found:
                    label = f"(... and {len(hosts) - len(found):,} other hosts in {fold}: never answered)"
                else:
                    label = f"All {len(hosts):,} hosts in {fold}: never answered"
                rows.append(_blank_row(label, ports))

        listed: Set[str] = set()
        for kind, text, hosts in outcome.request.inputs:
            hosts = [host for host in hosts if host in index]
            listed.update(hosts)
            add(hosts, text if kind == "subnet" else None)
        # A stored request keeps the hosts it recorded (plan section 3.2), those today's expansion leaves out too.
        rest = [host for host in outcome.request.hosts if host not in listed]
        if rest:
            add(rest, "the recorded host list")
        return rows

    def _save_report_rows(self, ctx: ScriptContext, rows: List[Row]) -> None:
        """Queue the ``Ping Monitor`` sheet when ``report_auto_save`` is on: every seen host, every period."""
        if ctx.cfg.get("report_auto_save") and rows:
            columns = table_columns(rows)
            queue_save(ctx, columns, [[row.get(column, "") for column in columns] for row in rows],
                       sheet_name=SHEET, index=False, force_header=True)


# --- running rounds ----------------------------------------------------------------------------------------

class _Background:
    """
    ``call(*args)`` on a daemon thread, its answer (or its exception) handed over by ``result``. ``concurrent.futures``
    joins its workers when Python exits, so a lookup it ran that waits on the resolver would keep ``cn monitor`` alive
    after ``q``, a stop or the second Ctrl+C; a daemon thread is left behind instead.
    """

    def __init__(self, call: Callable[..., Any], *args: Any) -> None:
        self.done = threading.Event()
        self._answer: Any = None
        self._error: Optional[BaseException] = None
        threading.Thread(target=self._run, args=(call, args), daemon=True).start()

    def _run(self, call: Callable[..., Any], args: Tuple[Any, ...]) -> None:
        try:
            self._answer = call(*args)
        except BaseException as error:  # raised again in the caller's thread, as a pool's Future does
            self._error = error
        finally:
            self.done.set()

    def result(self) -> Any:
        """The answer, once the call is done; its exception is raised here."""
        self.done.wait()
        if self._error is not None:
            raise self._error
        return self._answer


class _RunClock:
    """A run's clock: the wall clock, except that it never runs backwards. A step back (an NTP step, ``date``) is
    absorbed, so the rounds of a run are stored in the order they ran; a step forward (a suspend) is kept, so the gap
    shows and a run carried past its end ends. The run's end is on it too; the heartbeat stays on the wall clock,
    which other processes compare."""

    def __init__(self) -> None:
        self.offset = 0.0
        self.last: Optional[Tuple[float, float]] = None  # (run time, monotonic time) of the last reading

    def now(self) -> float:
        reading, ticks = time.time() + self.offset, time.monotonic()
        if self.last is not None:
            expected = self.last[0] + (ticks - self.last[1])
            if reading < expected:
                self.offset += expected - reading
                reading = expected
        self.last = (reading, ticks)
        return reading


class _Run:
    """One run of a plan (plan section 4): the loop, its store writes and its live view. A store that fails is
    closed and the run goes on without it; the summary says so (exit 3)."""

    def __init__(self, module: PingMonitorModule, ctx: ScriptContext, request: Request, plan: RunPlan) -> None:
        self.module = module
        self.ctx = ctx
        self.request = request
        self.plan = plan
        self.index = request.index()
        self.blocks = request.blocks()
        self.colors = get_global_color_scheme(ctx.cfg)
        self.store: Optional[PingStore] = None
        self.run_id = uuid.uuid4().hex
        self.view = "grid"
        self.clock = _RunClock()
        self.started = 0.0
        self.without_own: Optional[ph.Tracker] = None  # a one-round run's earlier rounds without its start
        self.outcome = RunOutcome(request, ph.Tracker(request.hosts, request.ports), interval=plan.every, running=True)

    # -- the store ---------------------------------------------------------------------------------------
    def _store_call(self, call: Callable[[PingStore], Any]) -> Any:
        """A store operation, or None without a store; a failure closes the store and is kept for the summary."""
        if self.store is None:
            return None
        try:
            return call(self.store)
        except StoreError as error:
            self.outcome.store_error = self.outcome.store_error or str(error)
            self._close()
            return None

    def _close(self) -> None:
        store, self.store = self.store, None
        if store is not None:
            store.close()

    def _open(self) -> None:
        """Open the store, prune it, read the earlier rounds, then start the run's row (and the request's, when new)."""
        self.store, error = self.module._open_store(self.ctx, write=True)
        if error:
            self.outcome.store_error = error
            return
        days = self.ctx.cfg.get("ping_history_days")
        days = max(int(30 if days is None else days), 1)
        self._store_call(lambda store: store.prune(self.started, days))
        request = self.request
        # The earlier rounds first, under the request's id when the history holds it (a new request has none): the
        # run's row goes in after them with its first heartbeat, so however long they take to read it is never lost.
        known = self._store_call(lambda store: store.request(request.key))
        if known is not None:
            self._store_call(lambda store: self._earlier(store, known.id))
        # The request and the run in one transaction: another process's prune never finds the request without a run.
        self._store_call(lambda store: store.begin_run(
            request.key, request.tokens, request.ports, request.hosts, self.run_id, source=self.plan.source,
            started=self.started, interval=self.plan.every, until=self.plan.until, host=socket.gethostname(),
            pid=os.getpid(), heartbeat=time.time(),
        ))

    def _earlier(self, store: PingStore, request_id: int) -> None:
        """Fold the request's rounds from before this run (from ``since`` on) into a new tracker, from one snapshot (the
        starts and the rounds of one history, whatever another run commits or prunes meanwhile)."""
        with store.snapshot():
            self._fold_earlier(store, request_id)

    def _fold_earlier(self, store: PingStore, request_id: int) -> None:
        through = store.last_round_id()
        starts = store.round_starts(request_id, since=self.plan.since, before=self.started, through=through)
        if not starts:
            return
        outcome, hosts, ports = self.outcome, self.request.hosts, self.request.ports
        cron = [start for start, interval in starts if interval is None]
        trackers = [ph.Tracker(hosts, ports, ph.expected_spacing(cron))]
        if self.plan.every is None:
            # A one-round run counts its own start too (its round is stored there), so its summary reads the rounds as
            # --show will. One stopped before its round leaves no start to count: the same rounds go into a tracker
            # without it, which _without_own_start takes, so neither another run's commit nor a prune changes them.
            own = ph.expected_spacing(cron + [self.started])
            if own != trackers[0].one_round_spacing:
                trackers.insert(0, ph.Tracker(hosts, ports, own))
        earlier, tcp_open = 0, False
        last: Optional[StoredRound] = None
        for stored in _stored_rounds(store, request_id, since=self.plan.since, before=self.started, through=through):
            rnd = _stored_round(stored)
            for tracker in trackers:
                tracker.add(rnd)
            earlier += 1
            tcp_open = tcp_open or _tcp_open(stored.rows)
            last = stored
        # Only a read that ended: one that failed half way leaves the run without its earlier rounds, both ways.
        outcome.tracker, outcome.earlier, outcome.tcp_open = trackers[0], earlier, tcp_open
        self.without_own = trackers[1] if len(trackers) > 1 else None
        if last is not None:
            outcome.last_rows = _latest_from(self.request, last)

    def _without_own_start(self) -> None:
        """A one-round run that recorded no round (a stop came first) leaves no start for --show to count: its summary
        takes the earlier rounds as folded without it, from the start's own read."""
        if self.without_own is not None and not self.outcome.rounds:
            self.outcome.tracker = self.without_own

    # -- the loop ----------------------------------------------------------------------------------------
    def go(self) -> RunOutcome:
        outcome, logger = self.outcome, self.ctx.logger
        status = "failed"
        try:
            # The stop handlers come first: a Ctrl+C while the history opens (a lock wait, a long history) only asks
            # the run to stop. The keys and the live view come after the start's warnings.
            with ping_live.StopSignals() as stop:
                self.started = self.clock.now()
                self._open()
                every = self.plan.every
                logger.info(
                    "Ping Monitor - run %s of %s: %d hosts, %s, %d earlier rounds", self.run_id,
                    self.request.short_id, len(self.request.hosts), f"every {_span(every)}" if every else "one round",
                    outcome.earlier,
                )
                self._warn_overrun()
                with ping_live.Keys() as keys, ping_live.LiveScreen(self.colors) as screen:
                    self._loop(stop, keys, screen)
                self._without_own_start()
            outcome.stop_reason = stop.reason
            status = "stopped" if stop.reason else "finished"
        except (KeyboardInterrupt, SystemExit):  # the second Ctrl+C: main's handler exits; the run ends as stopped
            status = "stopped"
            raise
        finally:
            outcome.running = False
            try:
                try:
                    self._end(status)
                except (KeyboardInterrupt, SystemExit):  # a second Ctrl+C while the end is written: written still
                    self._end(status)
                    raise
            finally:
                self._close()
                logger.info("Ping Monitor - run %s %s after %d rounds", self.run_id, status, outcome.rounds)
        return outcome

    def _end(self, status: str) -> None:
        self._store_call(lambda store: store.end_run(self.run_id, ended=self.clock.now(), status=status))

    def _warn_overrun(self) -> None:
        """Before the first round: one warning when a round is likely to take longer than the interval (4.2)."""
        if not self.plan.every:
            return
        hosts = len(self.request.hosts)
        per_batch = BATCH_ESTIMATE
        if oscompat.is_macos() and any(":" in host for host in self.request.hosts):
            per_batch = MACOS_IPV6_BATCH_ESTIMATE
        estimate = math.ceil(hosts / bulk_ping.BATCH_SIZE) * per_batch
        if estimate > self.plan.every:
            _say(f"about {hosts:,} hosts: a round takes up to {estimate:.0f} s, longer than the "
                 f"{_span(self.plan.every)} interval; slots will be skipped.")

    def _loop(self, stop: Any, keys: Any, screen: Any) -> None:
        every, slot = self.plan.every, 0
        while not stop.stopped:
            if self.plan.until is not None and self.clock.now() >= self.plan.until:
                return  # past its end (a suspend, or a start that outlasted --for): it ends, no round more (4.2)
            if not self._round(slot, stop, keys, screen) or every is None:
                return
            following = max(slot + 1, math.ceil((self.clock.now() - self.started) / every))
            last = following if self.plan.until is None else min(following, _slots(self.started, every, self.plan.until))
            self.outcome.late += max(last - slot - 1, 0)  # the run's own slots it overran, never those past its end
            slot = following
            next_at = self.started + slot * every
            if self.plan.until is not None and next_at >= self.plan.until:
                return
            self._wait(next_at, stop, keys, screen)

    def _wait(self, until: float, stop: Any, keys: Any, screen: Any) -> None:
        """Wait for the next slot in slices, minding the keys and the stop request, with the countdown drawn. The
        wait is at most one interval of the monotonic clock, and ends early when the run's clock jumps past the slot
        (a suspend)."""
        deadline = time.monotonic() + min(until - self.clock.now(), self.plan.every or 0.0)
        while not stop.stopped:
            remaining = min(deadline - time.monotonic(), until - self.clock.now())
            if remaining <= 0:
                return
            self._key(keys.poll(min(SLICE, remaining)), stop)
            self._draw(screen, {}, next_in=deadline - time.monotonic())

    def _key(self, key: Optional[str], stop: Any) -> None:
        if key == "q":
            stop.stop("key")
        elif key == "\x03":  # Windows can hand a Ctrl+C over as a character
            stop.interrupt()
        elif key == "v":
            self.view = "table" if self.view == "grid" else "grid"

    def _address_targets(self, hosts: List[str], stop: Any, keys: Any,
                         screen: Any) -> Optional[Tuple[List[Tuple[str, str]], List[str]]]:
        """
        ``_address_targets`` a batch of hosts at a time (one wave of parallel lookups each), on a daemon thread
        (``_Background``). This thread meanwhile reads the keys every ``RESOLVE_POLL`` and writes a heartbeat once
        ``RESOLVE_BEAT`` has passed, however long a lookup waits on the resolver, so the run stays live (``run_state``)
        and the store is never touched from another thread. None when a stop came: the round is dropped before any
        ping, and a lookup still waiting is left behind (it never holds the process open).
        """
        targets: List[Tuple[str, str]] = []
        unresolvable: List[str] = []
        beat = time.monotonic()
        for start in range(0, len(hosts), bulk_ping.BATCH_SIZE):
            lookups = _Background(self.module._address_targets, hosts[start:start + bulk_ping.BATCH_SIZE])
            while True:
                done = lookups.done.wait(RESOLVE_POLL)
                key = keys.poll(0)
                self._key(key, stop)
                if stop.stopped:
                    return None
                if key == "v" or not done:  # the round's header, not the wait's, while a lookup waits; v at once
                    self._draw(screen, {}, done=0, total=len(hosts))
                now = time.monotonic()
                if now - beat >= RESOLVE_BEAT:
                    beat = now
                    self._store_call(lambda store: store.heartbeat(self.run_id, time.time()))
                if done:
                    break
            found, gone = lookups.result()
            targets += found
            unresolvable += gone
        return targets, unresolvable

    def _round(self, slot: int, stop: Any, keys: Any, screen: Any) -> bool:
        """One round: resolve the names, sweep batch by batch (drawing each), then record it. False when a stop came
        while it pinged: the round in flight is dropped, since its hosts not pinged yet would read as silent, and a
        signal reaches the pings of the batch in flight too, cutting their results short (plan section 4.4). Once
        every host is pinged (after the last batch) the round is complete: a stop then (``q``, read between batches,
        or a signal during ``process_data`` or the save) keeps it, and the loop ends."""
        outcome, ports, logger, hosts = self.outcome, self.request.ports, self.ctx.logger, self.request.hosts
        begun = self.clock.now()
        # A one-round run is one sample of the cron spacing, at its start (as _fold_earlier counted it): its round is
        # stored there, so a slow start reads the periods as --show will (each host keeps its own batch time).
        round_started = self.started if self.plan.every is None else begun
        resolved = self._address_targets(hosts, stop, keys, screen)
        if resolved is None:
            return False
        targets, unresolvable = resolved
        outcome.unresolved.update(unresolvable)
        outcome.resolved.update(host for host, address in targets if host != address)  # an address pairs with itself
        pending: Dict[int, str] = {self.index[name]: "?" for name in unresolvable}
        rows: Dict[str, Row] = {name: bulk_ping._row(name, "", ph.NO_SUCH_HOST, ports) for name in unresolvable}
        times: Dict[str, float] = {}
        sweep = self.module._sweep(targets, logger, ports, self.plan.icmp)
        self._draw(screen, pending, done=0, total=len(targets))
        while True:
            if stop.stopped and len(times) < len(targets):  # its hosts not pinged yet would read as silent
                sweep.close()
                return False
            batch_started = self.clock.now()
            batch = next(sweep, None)
            if batch is None:
                break
            if stop.stopped:  # a signal while this batch pinged (keys are read after it): its pings got it too
                sweep.close()
                return False
            for row in batch[1]:
                rows[row["Host"]], times[row["Host"]] = row, batch_started
                pending[self.index[row["Host"]]] = ph.observation(row, ports)
            self._store_call(lambda store: store.heartbeat(self.run_id, time.time()))
            self._key(keys.poll(0), stop)
            self._draw(screen, pending, done=len(times), total=len(targets), rows=rows, times=times)

        ordered = self.module.execute_hook("process_data", self.ctx, [rows[host] for host in hosts if host in rows])
        by_host = {row["Host"]: row for row in ordered}
        observations = "".join(ph.observation(by_host[host], ports) if host in by_host else "." for host in hosts)
        seen = {host: by_host[host] for host, char in zip(hosts, observations) if char in ph.SEEN}
        record = [
            ResultRow(host, str(row.get("Address", "")), times.get(host, round_started), str(row.get("Result", "")),
                      {port: str(row.get(f"TCP {port}", "")) for port in ports} if ports else None)
            for host, row in seen.items()
        ]
        self._store_call(lambda store: store.record_round(self.run_id, round_started, observations, record))
        ended = self.clock.now()
        self._store_call(lambda store: store.heartbeat(self.run_id, time.time(), round_seconds=ended - begun))

        rnd = ph.Round(round_started, self.plan.every, observations, seen,
                       {host: times.get(host, round_started) for host in seen})
        for change in outcome.tracker.add(rnd):
            screen.note(_change_line(change))
        outcome.rounds += 1
        outcome.first = round_started if outcome.first is None else outcome.first
        outcome.last_rows = _latest(self.request, observations, by_host)  # a host the hook dropped too
        outcome.probe_failed = outcome.probe_failed or any(bulk_ping._probe_failed(row, ports) for row in ordered)
        outcome.tcp_open = outcome.tcp_open or any(row.get(f"TCP {port}") == "open" for row in ordered for port in ports)
        logger.debug("Ping Monitor - round %d (slot %d) of run %s: %d of %d seen in %.1f s", outcome.rounds, slot,
                     self.run_id, len(seen), len(hosts), ended - begun)
        return True

    # -- the live view ---------------------------------------------------------------------------------
    def _draw(self, screen: Any, pending: Dict[int, str], *, next_in: Optional[float] = None,
              done: Optional[int] = None, total: Optional[int] = None, rows: Optional[Mapping[str, Row]] = None,
              times: Optional[Mapping[str, float]] = None) -> None:
        if not screen.enabled:
            return
        width, height = screen.size
        screen.show(frame(
            self.request, self.blocks, self.outcome.tracker, pending, width=width, height=height, view=self.view,
            header=self._header(next_in, done, total, width),
            footer="q: stop and show the summary · v: table · Ctrl+C: same as q", rows=rows, times=times,
        ))

    def _header(self, next_in: Optional[float], done: Optional[int], total: Optional[int], width: int) -> str:
        """``Ping Monitor · sites.txt · round 15 of up to 120 · 09:15:00 UTC · every 1m until 11:00:00 · next round
        in 42 s`` (``: 300 of 1,024 pinged`` while a round is going on), without its least useful parts when it is
        wider than the screen."""
        plan, outcome = self.plan, self.outcome
        rounds = f"round {outcome.rounds + (1 if done is not None else 0)}"
        if plan.every and plan.until is not None:
            rounds += f" of up to {_slots(self.started, plan.every, plan.until)}"
        if done is not None:
            rounds += f": {done:,} of {total:,} pinged"
        now = self.clock.now()
        parts = [(SHEET, 1), (plan.source or self.request.short_id, 5), (rounds, 7), (f"{_clock(now)} UTC", 2)]
        if plan.every:
            every = f"every {_span(plan.every)}" + (f" until {_clock(plan.until, now)}" if plan.until else "")
            parts.append((every, 3))
        if outcome.late:
            parts.append((f"{outcome.late} started late", 4))
        if next_in is not None:
            parts.append((f"next round in {max(0, math.ceil(next_in))} s", 6))
        return _fit_parts(parts, width)


def _blank_row(host: str, ports: Sequence[int], **values: str) -> Row:
    """A row of the menu's table with the ``seen`` section's columns, empty but for ``host`` and ``values``."""
    row: Row = {"Host": host, "Address": "", "Latest": ""}
    row.update({f"TCP {port}": "" for port in ports})
    row.update({"First seen": "", "Last seen": "", "Seen": "", "Online": ""})
    row.update(values)
    return row


def _period(start: float, end: float) -> str:
    """``2026-10-08 22:00–23:30``, with the end's date too when it falls on another day (UTC)."""
    first = datetime.fromtimestamp(start, tz=timezone.utc)
    last = datetime.fromtimestamp(end, tz=timezone.utc)
    return first.strftime("%Y-%m-%d %H:%M") + "–" + last.strftime("%H:%M" if _day(start) == _day(end) else "%Y-%m-%d %H:%M")


def _rounds(count: int) -> str:
    return f"{count:,} round{'' if count == 1 else 's'}"


def _ports_text(ports: Sequence[int]) -> str:
    return f"with TCP {','.join(str(port) for port in ports)}" if ports else "without TCP"


def _change_line(change: ph.Change) -> ping_grid.Line:
    """``09:14:02  10.1.2.7  went silent``: the line a change leaves above the frame."""
    style = ping_grid.STYLES.get(change.observation, "text") if change.seen else "warning"
    return [(f"{_clock(change.time)}  ", "dim"), (change.host, "label"), (f"  {change.text}", style)]


class _Follow:
    """``--follow``: the live view of the rounds another process records, read from the store every
    ``FOLLOW_POLL`` seconds, until that run ends, ``q`` or Ctrl+C; the followed run goes on (plan section 2.4)."""

    def __init__(self, module: PingMonitorModule, ctx: ScriptContext, store: PingStore, info: RequestInfo,
                 outcome: RunOutcome, since: Optional[float]) -> None:
        self.module, self.ctx, self.store, self.info, self.outcome = module, ctx, store, info, outcome
        self.since = since
        self.blocks = outcome.request.blocks()
        self.view = "grid"

    def go(self) -> RunOutcome:
        """Follow until the run ends, ``q`` or Ctrl+C; the outcome it ends with (read again when needed)."""
        colors = get_global_color_scheme(self.ctx.cfg)
        with ping_live.StopSignals() as stop, ping_live.Keys() as keys, ping_live.LiveScreen(colors) as screen:
            while True:
                self._draw(screen)
                polled_at = time.monotonic()  # a step of the wall clock never stalls the reads
                while not stop.stopped and time.monotonic() - polled_at < FOLLOW_POLL:
                    key = keys.poll(SLICE)
                    if key == "q":
                        stop.stop("key")
                    elif key == "\x03":
                        stop.interrupt()
                    elif key == "v":
                        self.view = "table" if self.view == "grid" else "grid"
                        self._draw(screen)
                if stop.stopped:
                    self._read_more(screen)  # what was recorded since the last read: the summary is the history now
                    return self.outcome
                if not self._read_more(screen):
                    self._draw(screen, ended=True)
                    return self.outcome

    def _read_more(self, screen: Any) -> bool:
        """The rounds committed since the last read, and whether a run of the request goes on. The state and the
        rounds come from one snapshot: a run that records its last round and ends, or one that starts and records its
        first, is seen as it was at one moment, its rounds with it."""
        changes: List[ph.Change] = []
        with self.store.snapshot():
            current = self.store.request(self.info.key)
            live_runs = self.module._live_runs(current)
            read_before = self.outcome.last_id
            named_again = current is not None and current.id != self.info.id  # pruned, then named again by a run
            if named_again:
                self.info = current
            if (named_again or self._pruned()
                    or not self.module._take_stored(self.outcome, self.store, self.info.id, self.since,
                                                    note=changes.append)):
                # The window read again: the changes of the rounds recorded since the last read, from that read, once.
                changes = []
                self.outcome = self.module._read(self.store, current or self.info, since=self.since,
                                                 note=changes.append, note_after=read_before)
        for change in changes:
            screen.note(_change_line(change))
        self.outcome.running, self.outcome.live_runs = bool(live_runs), live_runs
        return bool(live_runs)

    def _pruned(self) -> bool:
        """Whether another run's prune took rounds the follower folded in: the window's oldest round is younger than
        the first it holds (the request keeps its id, so no new round tells)."""
        first = self.outcome.tracker.first_round
        if first is None:
            return False
        oldest = self.store.oldest_round_start(self.info.id, since=self.since)
        return oldest is None or oldest > first

    def _draw(self, screen: Any, ended: bool = False) -> None:
        if not screen.enabled:
            return
        width, height = screen.size
        tracker = self.outcome.tracker
        parts = [SHEET, f"following {ph.short_id(self.info.key)}", f"round {tracker.rounds}"]
        parts.append(f"last round {_clock(tracker.last_round)} UTC" if tracker.last_round is not None else "no round yet")
        if ended:
            parts.append("the run has ended")
        screen.show(frame(
            self.outcome.request, self.blocks, tracker, {}, width=width, height=height, view=self.view,
            header=" · ".join(parts), footer="q: stop following (the run goes on) · v: table · Ctrl+C: same as q",
        ))


# --- the menu ----------------------------------------------------------------------------------------------

class _Menu:
    """Menu item m (plan sections 2.1 and 2.3): the list of recorded requests, the summary of one picked from it
    (a window, ``g``, ``f``, ``n``), and a new run with its questions and its summary."""

    def __init__(self, module: PingMonitorModule, ctx: ScriptContext) -> None:
        self.module = module
        self.ctx = ctx
        self.colors = get_global_color_scheme(ctx.cfg)

    # -- printing and asking ---------------------------------------------------------------------------
    def _say(self, text: str, color: str = "description") -> None:
        console.print(f"[{self.colors[color]}]{escape(text)}[/]")

    def _ask(self, prompt: str) -> str:
        return read_user_input(self.ctx, prompt).strip()

    def _yes(self, prompt: str) -> bool:
        while True:
            answer = self._ask(prompt).lower()
            if answer in ("", "y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
            self._say("Answer y or n.", "error")

    def _store(self) -> Optional[PingStore]:
        """The history for reading, or None (nothing recorded, or an error, which is printed)."""
        store, error = self.module._open_store(self.ctx, write=False)
        if error:
            self._say(f"Ping history: {error}", "error")
        return store

    # -- the list --------------------------------------------------------------------------------------
    def go(self) -> None:
        while True:
            store = self._store()
            infos: List[RequestInfo] = []
            if store is not None:
                with store:
                    try:
                        infos = store.requests()
                    except StoreError as error:
                        self._say(f"Ping history: {error}", "error")
            picked = self._pick(infos) if infos else None
            if picked is None:
                self.new_run(None)
                return
            if not self.summary(picked):
                return

    def _pick(self, infos: List[RequestInfo]) -> Optional[RequestInfo]:
        """The list, newest first, and the request whose number is typed; None for Enter (a new run)."""
        rows = [self.module._request_row(info, "table", number) for number, info in enumerate(infos[:LIST_SHOWN], 1)]
        print_table_data(self.ctx, {"Recorded pings, newest first": rows})
        if len(infos) > LIST_SHOWN:
            self._say(f"(+{len(infos) - LIST_SHOWN} older; cn monitor --list shows all)")
        while True:
            answer = self._ask("Number to see its summary, or Enter for a new run: ")
            if not answer:
                return None
            if answer.isdecimal() and 1 <= int(answer) <= len(rows):  # isdigit() takes "²", which int() refuses
                return infos[int(answer) - 1]
            self._say("Invalid choice", "error")

    # -- a recorded request ----------------------------------------------------------------------------
    def summary(self, picked: RequestInfo) -> bool:
        """A recorded request's summary, from the store alone, until Enter (True: back to the list) or ``n`` (False:
        the new run has ended the item)."""
        since: Optional[float] = None
        while True:
            store = self._store()
            if store is None:
                return True
            with store:
                try:
                    info = store.request(picked.key)
                    if info is None:
                        self._say("This request is no longer in the ping history.", "error")
                        return True
                    outcome = self.module._read(store, info, since=since)
                    runs = store.runs(info.id)
                except StoreError as error:
                    self._say(f"Ping history: {error}", "error")
                    return True
            self._show(info, runs, outcome)
            while True:
                answer = self._ask("Window, g, f, n or Enter: " if outcome.running else "Window, g, n or Enter: ")
                if not answer:
                    return True
                if answer.lower() == "n":
                    self.new_run(info)
                    return False
                if answer.lower() == "g":
                    self._grid(outcome)
                    break
                if answer.lower() == "f":
                    if not outcome.running:
                        self._say("No run of these targets is going on: f follows one.", "error")
                        continue
                    self._follow(info, outcome, since)
                    break
                try:
                    since = _since(ph.parse_window(answer))
                except ValueError as error:
                    self._say(str(error), "error")
                    continue
                break

    def _show(self, info: RequestInfo, runs: List[RunInfo], outcome: RunOutcome) -> None:
        tracker = outcome.tracker
        title = f"{ph.short_id(info.key)} · {_targets_label(info)}"
        if info.tcp_ports:
            title += f" · TCP {','.join(str(port) for port in info.tcp_ports)}"
        console.print()
        self._say(title, "header")
        self._say(self._runs_line(runs))
        if tracker.rounds:
            print_table_data(self.ctx, {SHEET: self.module._display_rows(outcome)})
            answering = sum(1 for char in tracker.cells() if char in ph.SEEN)
            self._say(
                f"{_rounds(outcome.rounds)} from {_when(tracker.first_round)} to {_when(tracker.last_round)} · "
                f"{len(tracker.summaries())} of {len(outcome.request.hosts)} hosts seen · "
                f"{answering} answering in the last round"
            )
        else:
            self._say("No round recorded in this window.")
        keys = ["Enter: back", "24h or 2026-10-08: narrow it", "g: grid"]
        keys += ["f: follow live"] if outcome.running else []
        keys += ["n: a new run of these targets"]
        self._say(" · ".join(keys))

    def _runs_line(self, runs: List[RunInfo]) -> str:
        """``Runs: running since 09:00:00 (14 rounds, every 1m, until 11:00:00); finished 2026-10-08 22:00–06:00
        (480 rounds, every 1m); 288 one-round runs, the last at 09:10:03``."""
        now = time.time()
        periodic = [run for run in runs if run.interval is not None]
        once = [run for run in runs if run.interval is None]
        parts = [self._run_text(run, now) for run in periodic[:RUNS_SHOWN]]
        if len(periodic) > RUNS_SHOWN:
            parts.append(f"{len(periodic) - RUNS_SHOWN} more")
        if once:
            parts.append(f"{len(once)} one-round run{'s' if len(once) > 1 else ''}, the last at {_clock(once[0].started, now)}")
        return "Runs: " + ("; ".join(parts) if parts else "none")

    def _run_text(self, run: RunInfo, now: float) -> str:
        state, _ = self.module._state(run, now)
        details = [_rounds(run.rounds), f"every {_span(run.interval or 0)}"]
        if state == "running":
            if run.until is not None:
                details.append(f"until {_clock(run.until, now)}")
            return f"running since {_clock(run.started, now)} ({', '.join(details)})"
        end = run.ended if run.ended is not None else run.heartbeat
        return f"{state_text(state, '')} {_period(run.started, end)} ({', '.join(details)})"

    def _grid(self, outcome: RunOutcome) -> None:
        """``g``: the grid of the last stored round, a still picture, with ``x`` for the hosts gone silent."""
        tracker = outcome.tracker
        if not tracker.rounds:
            self._say("No round recorded in this window.")
        else:
            request = outcome.request
            header = f"{SHEET} · {request.short_id} · round {tracker.rounds} · {_when(tracker.last_round)}"
            lines = frame(request, request.blocks(), tracker, {}, width=console.width, height=console.height,
                          view="grid", header=header, footer="")
            console.print(ping_live.to_text(lines[:-1], self.colors))
        press_any_key(self.ctx)

    def _follow(self, info: RequestInfo, outcome: RunOutcome, since: Optional[float]) -> None:
        """``f``: the live view of the run going on, until it ends or ``q``; the summary is then read again."""
        if not ping_live.LiveScreen(self.colors).enabled:
            self._say("Following needs a terminal on stderr.", "error")
            return
        store = self._store()
        if store is None:
            return
        with store:
            try:
                _Follow(self.module, self.ctx, store, info, outcome, since).go()
            except StoreError as error:
                self._say(f"Ping history: {error}", "error")

    # -- a new run -------------------------------------------------------------------------------------
    def new_run(self, stored: Optional[RequestInfo]) -> None:
        """Item 6's target prompt and TCP question (or a recorded request's targets and ports), the earlier rounds,
        the period and the interval; then the run, its summary and "Press any key" (plan section 2.1)."""
        logger = self.ctx.logger
        if shutil.which("ping") is None:
            logger.error("'ping' command not found. Aborting.")
            press_any_key(self.ctx)
            return
        if stored is None:
            colors = self.colors
            console.print(
                "\n"
                f"[{colors['description']}]Enter IPs/FQDNs/Subnets to watch, one per line.[/]\n"
                f"[{colors['header']} {colors['bold']}]Example formats[/]: 192.168.0.1, 2001:db8::1, example.com, "
                "192.168.0.0/24\n"
                f"[{colors['warning']}]Subnets will be expanded and every host IP will be pinged.[/]\n"
                f"[{colors['description']}]An empty line ends the list.[/]\n"
            )
            tokens, hosts = self.module._tokens(
                bulk_ping._typed_lines(self.ctx), lambda target, reason: bulk_ping._print_rejected(self.ctx, target, reason)
            )
            if not tokens:
                logger.info("Ping Monitor - No valid hosts to watch.")
                press_any_key(self.ctx)
                return
            ports = self.module._ask_tcp_ports(self.ctx, hosts)
            request = self.module._request_of(tokens, ports)
            source = None
        else:
            # Today's request of the stored targets: the same key while their expansion is the same; when it changed,
            # a new request, and the stored one is never written to (plan section 3.2).
            request = self.module._request_of(stored.targets, stored.tcp_ports)
            source = stored.newest_run.source if stored.newest_run is not None else None
        include = self._earlier(request)
        run_for, every = self._period()
        now = time.time()
        plan = RunPlan(every=every, until=now + run_for if run_for else None, since=None if include else now,
                       source=source)
        outcome = self.module._track(self.ctx, request, plan)
        self._report(outcome)

    def _earlier(self, request: Request) -> bool:
        """Whether to add the request's earlier rounds; asked only when the history holds some."""
        store, _ = self.module._open_store(self.ctx, write=False)  # an error shows in the run's summary
        if store is None:
            return False
        with store:
            try:
                info = store.request(request.key)
                others = [] if info is not None and info.rounds else store.other_ports(request.tokens, request.key)
            except StoreError:
                return False
        if info is not None and info.rounds:
            self._say(f"These targets were pinged before: {_rounds(info.rounds)}, {_when(info.first_round)} to "
                      f"{_when(info.last_round)}.")
            return self._yes("Include them in the summary? [Y/n] ")
        if others:
            self._say(f"These targets were pinged before {' and '.join(_ports_text(ports) for ports in others)}; "
                      "those rounds are not included.")
        return False

    def _period(self) -> Tuple[Optional[float], Optional[float]]:
        """(how long, every) in seconds; (None, None) for one round."""
        while True:
            text = self._ask("Run for how long, e.g. 30m, 2h, 1d (Enter: one round): ")
            if not text:
                return None, None
            try:
                run_for = ph.parse_duration(text).total_seconds()
            except ValueError as error:
                self._say(str(error), "error")
                continue
            if run_for >= MIN_INTERVAL:
                break
            self._say(f"Run for at least {int(MIN_INTERVAL)}s, or press Enter for one round.", "error")
        default = min(DEFAULT_INTERVAL, run_for)
        while True:
            text = self._ask(f"Ping every, e.g. 30s, 5m (Enter: {_span(default)}): ")
            try:
                every = ph.parse_duration(text).total_seconds() if text else default
            except ValueError as error:
                self._say(str(error), "error")
                continue
            if every < MIN_INTERVAL:
                self._say(f"Ping at most every {int(MIN_INTERVAL)}s.", "error")
            elif every > run_for:
                self._say(f"Ping at least once in the {_span(run_for)} of the run.", "error")
            else:
                return run_for, every

    def _report(self, outcome: RunOutcome) -> None:
        """The end of a run: its header line, the folded table, the report sheet, "Press any key"."""
        if outcome.store_error:
            self._say(f"Ping history: {outcome.store_error}", "error")
        tracker = outcome.tracker
        if not outcome.rounds:
            self._say(_NO_ROUND)
        else:
            first, last = outcome.first, tracker.last_round
            if outcome.rounds == 1:
                line = f"1 round at {_clock(first)} UTC"
            else:
                line = f"{_rounds(outcome.rounds)} from {_clock(first)} to {_clock(last, first)} UTC"
            if outcome.interval:
                line += f", every {_span(outcome.interval)}"
            if outcome.earlier:
                line += f" + {outcome.earlier:,} earlier round{'' if outcome.earlier == 1 else 's'}"
            answering = sum(1 for char in tracker.cells() if char in ph.SEEN)
            line += (f" · {len(tracker.summaries())} of {len(outcome.request.hosts)} hosts seen · {answering} answering "
                     "in the last round")
            if outcome.late:
                line += f" · {_rounds(outcome.late)} started late"
            self._say(line)
        if tracker.rounds:
            print_table_data(self.ctx, {SHEET: self.module._display_rows(outcome)})
        self.module._save_report_rows(self.ctx, self.module._seen_rows(outcome, "report"))
        press_any_key(self.ctx)


# --- the frame ---------------------------------------------------------------------------------------------

_COUNT_WORDS = (("!", "replying"), ("R", "rejecting"), ("T", "TCP only"), ("U", "unreachable"), ("x", "gone"))


def frame(request: Request, blocks: Sequence[ping_grid.Block], tracker: ph.Tracker, pending: Dict[int, str], *,
          width: int, height: int, view: str, header: str, footer: str, rows: Optional[Mapping[str, Row]] = None,
          times: Optional[Mapping[str, float]] = None) -> List[ping_grid.Line]:
    """The live frame (plan section 2.4): the header, the counters, the grid (the compact view when it does not
    fit, the table after ``v``), the legend and the footer. ``rows`` and ``times``: the round in flight's rows and
    batch times so far, by host, laid over the last finished round as ``pending`` is."""
    rows, times = rows or {}, times or {}
    answered_partly = {index for index, host in enumerate(request.hosts) if host in rows and ph.partial_reply(rows[host])}
    cells = tracker.cells(pending)
    counts = tracker.counts(pending)
    summaries = tracker.summaries()
    ever = {summary.index for summary in summaries}
    seen = len(ever) + sum(1 for index, char in pending.items() if char in ph.SEEN and index not in ever)
    numbers = [f"{counts[char]:,} {word}" for char, word in _COUNT_WORDS if counts.get(char)]
    numbers.append(f"{seen:,} seen of {len(request.hosts):,}")
    legend = _legend_lines(ping_grid.legend(set(cells) - {ph.UNPROBED}), width)
    room = max(height - _FRAME_LINES - len(legend) - CHANGE_LINES, 1)
    if view == "table":
        body = _table_lines(_table_rows(request, tracker, summaries, cells, pending, rows, times), room, width)
    else:
        body = ping_grid.grid_lines(
            blocks, cells, width=width, height=room, changed=tracker.changed(pending),
            partial=tracker.partial(pending, answered_partly),
        ) or _crop(ping_grid.compact_lines(blocks, cells), room, width)
    return [
        [(_fit(header, width), "header")],
        [(_fit(" · ".join(numbers), width), "text")],
        [],
        *body,
        [],
        *legend,
        [(_fit(footer, width), "dim")],
    ]


def _legend_lines(legend: ping_grid.Line, width: int) -> List[ping_grid.Line]:
    """The legend in lines of at most ``width``, filled word by word as Rich wraps a line (a word wider than the
    screen is cut): its height is known before the body takes the rest of the screen, where an estimate from its
    length could fall a line short and push the footer off."""
    if sum(len(chunk) for chunk, _ in legend) <= width:
        return [legend]
    lines: List[ping_grid.Line] = [[]]
    used, gap = 0, ""
    for chunk, style in legend:
        for word in re.findall(r"\s+|\S+", chunk):
            if word.isspace():
                gap += word
                continue
            if used and used + len(gap) + len(word) > width:
                lines.append([])
                used = 0
            if used:
                lines[-1].append((gap, "text"))
                used += len(gap)
            gap = ""
            lines[-1].append((word[:width], style))
            used += len(word[:width])
    return lines


def _fit_parts(parts: Sequence[Tuple[str, int]], width: int) -> str:
    """``parts`` joined with `` · ``, in their order, as many as fit ``width`` terminal cells: taken by rank, the
    highest first, each one kept when the line still fits with it. The highest is always there, cut when it alone is
    too wide."""
    ranked = sorted(range(len(parts)), key=lambda index: -parts[index][1])
    if cell_len(parts[ranked[0]][0]) > width:
        return _fit(parts[ranked[0]][0], width)
    kept: Set[int] = set()
    for number in ranked:
        if cell_len(" · ".join(text for index, (text, _) in enumerate(parts) if index in kept | {number})) <= width:
            kept.add(number)
    return " · ".join(text for index, (text, _) in enumerate(parts) if index in kept)


def _fit(text: str, width: int) -> str:
    """One line of the frame, cut to the screen's width with an ellipsis: a line that wrapped would push the grid
    down and off the screen. Measured in terminal cells (a wide character such as 主 takes two), and never cut in
    half: a space stands for the half that does not fit."""
    return text if cell_len(text) <= width else set_cell_size(text, max(width - 1, 0)) + "…"


class _TableRow(NamedTuple):
    host: str
    latest: str
    cell: str
    last_seen: Optional[float]
    seen: int
    rounds: int


def _table_rows(request: Request, tracker: ph.Tracker, summaries: Sequence[ph.HostSummary], cells: Sequence[str],
                pending: Mapping[int, str], rows: Mapping[str, Row], times: Mapping[str, float]) -> List[_TableRow]:
    """``v``'s rows: the hosts seen so far, with the round in flight laid over the last finished round for the hosts
    it has reached, as the grid does (a host's seen rounds then count of the rounds that reached it)."""
    finished = {summary.index: summary for summary in summaries}
    table: List[_TableRow] = []
    for index in sorted(set(finished) | {index for index, char in pending.items() if char in ph.SEEN}):
        host, summary, char = request.hosts[index], finished.get(index), pending.get(index)
        if char is None:
            table.append(_TableRow(host, summary.latest, cells[index], summary.last_seen, summary.seen_rounds,
                                   summary.rounds))
        elif char in ph.SEEN:
            when = times[host] if summary is None else max(times[host], summary.last_seen)  # as the tracker holds it
            table.append(_TableRow(host, str(rows.get(host, {}).get("Result", "")), cells[index], when,
                                   (summary.seen_rounds if summary else 0) + 1, tracker.rounds + 1))
        else:
            table.append(_TableRow(host, ph.result_text(char), cells[index], summary.last_seen, summary.seen_rounds,
                                   tracker.rounds + 1))
    return table


_TABLE_TAIL = 2 + 16 + 2 + 25 + 2 + 11  # Latest, Last seen and Seen ("12345 of 12345") after the host


def _table_lines(table: Sequence[_TableRow], room: int, width: int) -> List[ping_grid.Line]:
    """``v``: the hosts seen so far, one line each, as many as fit, then ``(+N more)``; a long name is cut so that no
    line is wider than the screen (a wrapped line would push the footer off it)."""
    if not table:
        return [_clip([("No host seen yet.", "dim")], width)]
    if room < 2:  # no room for the header and a row
        return _crop([[(row.host, "label")] for row in table], room, width)
    host_width = min(max(cell_len(row.host) for row in table), max(width - _TABLE_TAIL, 8))  # in cells, as shown
    lines: List[ping_grid.Line] = [[(f"{'Host':<{host_width}}  {'Latest':<16}  {'Last seen':<25}  Seen", "header")]]
    room = max(room - 1, 1)
    shown = table if len(table) <= room else table[:room - 1]
    for row in shown:
        lines.append([
            (set_cell_size(_fit(row.host, host_width), host_width) + "  ", "label"),
            (f"{row.latest:<16}", ping_grid.STYLES.get(row.cell, "text")),
            (f"  {_when(row.last_seen):<25}  {row.seen} of {row.rounds}", "text"),
        ])
    if len(shown) < len(table):
        lines.append([(f"(+{len(table) - len(shown)} more)", "dim")])
    return [_clip(line, width) for line in lines]


def _crop(lines: Sequence[ping_grid.Line], room: int, width: int) -> List[ping_grid.Line]:
    """As many of ``lines`` as fit ``room``, the last of them then ``(+N more)``, each cut to ``width``: a frame
    taller or wider than the screen would push the footer, with its keys, off it."""
    if len(lines) > room:
        kept = max(room - 1, 0)
        lines = [*lines[:kept], [(f"(+{len(lines) - kept} more)", "dim")]]
    return [_clip(line, width) for line in lines]


def _clip(line: ping_grid.Line, width: int) -> ping_grid.Line:
    """``line`` cut to ``width`` terminal cells, an ellipsis where it is cut."""
    clipped: ping_grid.Line = []
    for text, style in line:
        room = width - sum(cell_len(chunk) for chunk, _ in clipped)
        if cell_len(text) > room:
            if room > 0:
                clipped.append((_fit(text, room), style))
            break
        clipped.append((text, style))
    return clipped
