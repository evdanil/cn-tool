"""The Ping Monitor's model: pure functions and a tracker over rounds, with no I/O
(docs/plans/2026-10-ping-monitor-plan.md, section 3).

A round is one sweep of every host of a request. ``observation`` reads a host's ``cn ping`` row as one
character, ``Round`` holds a round's characters and the rows of the hosts it saw, and ``Tracker`` folds rounds
into per-host state: what the live grid shows (``cells``), the summary (``summaries``) and the seen/not-seen
transitions (``Change``). ``request_key`` names a request, ``parse_duration`` reads ``--every``/``--for``,
``online_text`` formats online periods, ``run_state`` tells a live run from a lost one, and ``icmp_error_result``
reads an ICMP error out of a ping output that its classifier read as ``NO RESPONSE``.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import AbstractSet, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

from cn_tool.utils import oscompat
from cn_tool.utils.config_history import Since, parse_since

Row = Dict[str, str]
Period = Tuple[float, float]
Address = Tuple[Union[ipaddress.IPv4Address, ipaddress.IPv6Address], str]  # (address, zone in lower case)

REJECTED = "REJECTED"  # the target itself sent the ICMP error: it is up, behind its own firewall
UNREACHABLE = "UNREACHABLE"  # another address sent it (a router, a firewall in the path, this machine)
NO_SUCH_HOST = "no such host"  # the result of a name that did not resolve in its round

OBSERVATIONS = "!RTU.E?"  # what a round records for each host
SEEN = frozenset("!RT")  # replied, rejected (up, firewalled), answered on a TCP port
UNPROBED = " "  # a host the run has not pinged yet
GONE = "x"  # not seen now, seen earlier in the window

_RESULT_TEXTS = {".": "NO RESPONSE", "U": UNREACHABLE, "E": "ERROR", "?": NO_SUCH_HOST, UNPROBED: ""}
_CHANGE_TEXTS = {"!": "replied", "R": "rejected", "T": "answered on TCP"}
_SILENT_DETAIL = {"U": " (unreachable)", "E": " (error)", "?": " (name did not resolve)"}

DURATION_MESSAGE = "'{text}' is not a duration: use 30s, 5m, 2h, 1d or 2w"
WINDOW_MESSAGE = "'{text}' is not a time: give an age (30m, 24h, 7d) or a date (2026-10-08, 2026-10-08T14:00 UTC)"
_DURATION = re.compile(r"(?P<count>[0-9]{1,4})(?P<unit>[smhdw])", re.IGNORECASE)
_DURATION_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}

GAP_FACTOR = 2.5  # rounds further apart than this many expected spacings leave a coverage gap
MIN_STALE_SECONDS = 60.0  # a running run silent for longer than this (or 2.5 intervals) is lost


def observation(row: Mapping[str, str], tcp_ports: Sequence[int]) -> str:
    """
    One character for a ``cn ping`` row: ``!`` replied (fully or partly), ``R`` rejected, ``T`` silent to ping but
    a TCP port answered (open or reset), ``E`` the probe failed, ``?`` the name did not resolve, ``U`` unreachable
    or IPv6 ``NO ROUTE``, ``.`` no answer. A host that answered in any way is seen, whatever else failed.
    """
    result = str(row.get("Result", ""))
    if result.startswith("OK"):
        return "!"
    if result == REJECTED:
        return "R"
    if any(row.get(f"TCP {port}") in ("open", "closed") for port in tcp_ports):
        return "T"
    if result.startswith("ERROR"):
        return "E"
    if result == NO_SUCH_HOST:
        return "?"
    if result in (UNREACHABLE, "NO ROUTE"):
        return "U"
    return "."


def partial_reply(row: Mapping[str, str]) -> bool:
    """True for a row whose host answered only some echo requests (``OK (1/2 replies)``)."""
    return str(row.get("Result", "")).startswith("OK (")


def result_text(char: str) -> str:
    """The result an unseen observation stands for, where no row was kept: ``U`` is ``UNREACHABLE``, and so on."""
    return _RESULT_TEXTS[char]


# --- the request -------------------------------------------------------------------------------------

def _canonical_address(text: str) -> str:
    """An address in its compressed form, a zone ID kept as typed."""
    address, percent, zone = text.partition("%")
    return str(ipaddress.ip_address(address)) + percent + zone


def _is_address(text: str) -> bool:
    try:
        _canonical_address(text)
    except ValueError:
        return False
    return True


def canonical_tokens(user_inputs: Iterable[Tuple[str, str, Sequence[str]]]) -> List[str]:
    """
    The request's targets as canonical tokens, sorted and without duplicates, from ``_expand_targets``' structured
    input ``(input type, line as typed, its hosts)``: a subnet is its network (``10.1.2.5/24`` is ``10.1.2.0/24``),
    an address its compressed form, a name in lower case (an absolute name keeps its trailing dot: without it, a
    resolver's search list could find another host first), and a list one token per address.
    """
    tokens = set()
    for input_type, text, hosts in user_inputs:
        if input_type == "subnet":
            tokens.add(str(ipaddress.ip_network(text, strict=False)))
            continue
        for host in hosts:
            tokens.add(_canonical_address(host) if _is_address(host) else host.lower())
    return sorted(tokens)


def request_key(tokens: Iterable[str], tcp_ports: Iterable[int], hosts: Sequence[str]) -> str:
    """
    The SHA-256 (hex) that names a request: its tokens and ports, each sorted and without duplicates, and its host
    list in order. The host list is in the key, so a later expansion of the same tokens that differs is a new request.
    """
    payload = [sorted(set(tokens)), sorted(set(tcp_ports)), list(hosts)]
    return hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode("utf-8")).hexdigest()


def short_id(key: str) -> str:
    """The ID the list shows and ``--show`` takes: the first 8 hex digits of the key."""
    return key[:8]


# --- durations and spacing ---------------------------------------------------------------------------

def parse_duration(text: str) -> timedelta:
    """
    Parse ``--every`` or ``--for``: up to four digits and a unit, ``s``, ``m``, ``h``, ``d`` or ``w``
    (``30s``, ``5m``, ``2h``). Unlike ``parse_since`` it takes seconds.

    @raise ValueError: ``DURATION_MESSAGE`` for anything else.
    """
    match = _DURATION.fullmatch(text.strip())
    if not match:
        raise ValueError(DURATION_MESSAGE.format(text=text))
    return timedelta(**{_DURATION_UNITS[match["unit"].lower()]: int(match["count"])})


def parse_window(text: str) -> Since:
    """
    Parse ``--since`` for the monitor, or a window typed in the menu: ``parse_since``'s ages and dates, without
    ``cn diff``'s snapshot names.

    @raise ValueError: ``WINDOW_MESSAGE``.
    """
    try:
        since = parse_since(text)
    except ValueError:
        since = None
    if since is None or since.snapshot is not None:
        raise ValueError(WINDOW_MESSAGE.format(text=text))
    return since


def expected_spacing(starts: Iterable[float]) -> Optional[float]:
    """
    The median gap between consecutive one-round runs (what cron's schedule looks like), None below three rounds: one
    gap is no sample of a schedule (two runs days apart would read as online all along). Of an even number of gaps
    the lower middle one stands, so one long hole never stretches the spacing to cover itself.
    """
    import statistics  # here, not at the top: main imports this module on every start, for parse_duration

    ordered = sorted(starts)
    gaps = [later - earlier for earlier, later in zip(ordered, ordered[1:])]
    return statistics.median_low(gaps) if len(gaps) >= 2 else None


# --- rounds and the tracker --------------------------------------------------------------------------

@dataclass(frozen=True)
class Round:
    """One sweep: when it started, its run's interval (None for a one-round run), one observation per host of the
    request in host order, the rows of the hosts it saw, and each such host's batch time (default ``started``)."""

    started: float
    interval: Optional[float]
    observations: str
    rows: Mapping[str, Row] = field(default_factory=dict)
    times: Mapping[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class Change:
    """A host going from seen to not seen, or back, in a round."""

    index: int
    host: str
    time: float
    seen: bool
    observation: str

    @property
    def text(self) -> str:
        """``replied``, ``rejected``, ``answered on TCP``, or ``went silent`` with what the round saw instead."""
        if self.seen:
            return _CHANGE_TEXTS[self.observation]
        return "went silent" + _SILENT_DETAIL.get(self.observation, "")


@dataclass(frozen=True)
class HostSummary:
    """What the window saw of one host that was seen at least once. ``periods`` run from the first to the last round
    of each stretch in which it was seen; ``ongoing`` is true when it was seen in the last round."""

    index: int
    host: str
    address: str
    latest: str
    tcp: Dict[int, str]
    first_seen: float
    last_seen: float
    seen_rounds: int
    rounds: int
    periods: List[Period]
    ongoing: bool
    partial: bool
    cell: str


def _derived(char: str, ever_seen: bool, unreachable: bool) -> str:
    """The grid's character: the observation when seen, else ``x`` if seen earlier, else a sticky ``U``, else the
    round's own ``E``, ``?``, ``.`` or ``" "``."""
    if char in SEEN:
        return char
    if ever_seen:
        return GONE
    if unreachable:
        return "U"
    return char


class Tracker:
    """
    Folds rounds, in time order, into per-host state. ``add`` takes a finished round; ``cells`` and ``changed`` also
    take the observations of the round in flight (``pending``: host index to character), batch by batch.

    Work per round is proportional to the hosts that are not plain ``.`` now or were seen or unreachable before, so a
    long run over a large subnet stays cheap. Rounds are never kept: a 7-day run holds per-host state only.
    """

    def __init__(self, hosts: Sequence[str], tcp_ports: Sequence[int] = (), one_round_spacing: Optional[float] = None):
        self.hosts = list(hosts)
        self.tcp_ports = tuple(tcp_ports)
        self.one_round_spacing = one_round_spacing
        self.rounds = 0
        self.first_round: Optional[float] = None
        self.last_round: Optional[float] = None
        self.had_error = False
        self._last: Dict[int, str] = {}  # the last observation of each host that was not "."
        self._seen_now: Set[int] = set()
        self._ever_seen: Set[int] = set()
        self._unreachable: Set[int] = set()
        self._partial: Set[int] = set()
        self._changed: Set[int] = set()
        self._first_seen: Dict[int, float] = {}
        self._last_seen: Dict[int, float] = {}
        self._seen_rounds: Dict[int, int] = {}
        self._rows: Dict[int, Row] = {}
        self._open: Dict[int, List[float]] = {}  # index -> [start, end] of the period still open
        self._closed: Dict[int, List[Period]] = {}
        self._previous: Optional[Round] = None

    # -- rounds ---------------------------------------------------------------------------------------
    def _spacing(self, rnd: Round) -> Optional[float]:
        return rnd.interval if rnd.interval else self.one_round_spacing

    def _gap_before(self, rnd: Round) -> bool:
        """True when ``rnd`` is further from the previous round than ``GAP_FACTOR`` expected spacings (the larger of
        the two rounds'), or when neither round has an expected spacing."""
        if self._previous is None:
            return False
        spacings = [s for s in (self._spacing(self._previous), self._spacing(rnd)) if s]
        if not spacings:
            return True
        return rnd.started - self._previous.started > GAP_FACTOR * max(spacings)

    def _close(self, index: int) -> None:
        start, end = self._open.pop(index)
        self._closed.setdefault(index, []).append((start, end))

    def add(self, rnd: Round) -> List[Change]:
        """Fold a finished round in and return its changes (none for the first round: nothing came before it)."""
        if len(rnd.observations) != len(self.hosts):
            raise ValueError(f"a round has {len(rnd.observations)} observations for {len(self.hosts)} hosts")
        if self._gap_before(rnd):
            for index in list(self._open):
                self._close(index)

        current = {match.start(): match.group() for match in re.finditer(r"[^.]", rnd.observations)}
        touched = set(current) | self._seen_now | set(self._last)
        changes: List[Change] = []
        seen_now: Set[int] = set()
        self._partial = set()
        for index in sorted(touched):
            char = current.get(index, ".")
            host = self.hosts[index]
            when = rnd.times.get(host, rnd.started)
            if index in self._last_seen:  # a slower round of another run, started earlier, saw the host later
                when = max(when, self._last_seen[index])
            seen = char in SEEN
            if self.rounds and seen != (index in self._seen_now):
                changes.append(Change(index, host, when, seen, char))
            if char == ".":
                self._last.pop(index, None)
            else:
                self._last[index] = char
            if char == "U":
                self._unreachable.add(index)
            if char == "E":
                self.had_error = True
            if seen:
                seen_now.add(index)
                self._seen(index, host, when, rnd)
            elif index in self._open:
                self._close(index)

        self._changed = {change.index for change in changes}
        self._seen_now = seen_now
        self.rounds += 1
        self.first_round = rnd.started if self.first_round is None else self.first_round
        self.last_round = rnd.started
        self._previous = rnd
        return changes

    def _seen(self, index: int, host: str, when: float, rnd: Round) -> None:
        self._ever_seen.add(index)
        self._first_seen.setdefault(index, when)
        self._last_seen[index] = when
        self._seen_rounds[index] = self._seen_rounds.get(index, 0) + 1
        row = rnd.rows.get(host)
        if row is not None:
            self._rows[index] = dict(row)
            if partial_reply(row):
                self._partial.add(index)
        if index in self._open:
            self._open[index][1] = when
        else:
            self._open[index] = [when, when]

    # -- what the grid shows ---------------------------------------------------------------------------
    def cells(self, pending: Optional[Mapping[int, str]] = None) -> List[str]:
        """One character per host: the last round's state, with the round in flight's observations over it."""
        pending = pending or {}
        default = "." if self.rounds else UNPROBED
        cells = [default] * len(self.hosts)
        for index in self._ever_seen | self._unreachable | set(self._last) | set(pending):
            char = pending.get(index, self._last.get(index, default))
            unreachable = index in self._unreachable or char == "U"
            cells[index] = _derived(char, index in self._ever_seen, unreachable)
        return cells

    def changed(self, pending: Optional[Mapping[int, str]] = None) -> Set[int]:
        """The hosts to highlight: those whose seen state the round in flight has changed so far, and those the last
        round changed that the round in flight has not reached yet."""
        pending = pending or {}
        flipped = {index for index, char in pending.items() if (char in SEEN) != (index in self._seen_now)}
        return flipped | (self._changed - set(pending))

    def partial(self, pending: Optional[Mapping[int, str]] = None, answered_partly: AbstractSet[int] = frozenset()
                ) -> Set[int]:
        """The hosts that answered only some echo requests: ``answered_partly`` among those the round in flight has
        reached (``pending``), the last round's among the others."""
        return set(answered_partly) | (self._partial - set(pending or {}))

    def counts(self, pending: Optional[Mapping[int, str]] = None) -> Dict[str, int]:
        """How many hosts show each character, with the round in flight's observations over the last round's."""
        counts: Dict[str, int] = {}
        for char in self.cells(pending):
            counts[char] = counts.get(char, 0) + 1
        return counts

    # -- the summary -----------------------------------------------------------------------------------
    def summaries(self) -> List[HostSummary]:
        """Every host seen at least once, in host order."""
        cells = self.cells()
        summaries = []
        for index in sorted(self._ever_seen):
            row = self._rows.get(index, {})
            seen_last = index in self._seen_now
            char = self._last.get(index, ".")
            periods = list(self._closed.get(index, []))
            if index in self._open:
                periods.append(tuple(self._open[index]))
            summaries.append(HostSummary(
                index=index,
                host=self.hosts[index],
                address=str(row.get("Address", "")),
                latest=str(row.get("Result", "")) if seen_last else result_text(char),
                tcp={port: row[f"TCP {port}"] for port in self.tcp_ports if f"TCP {port}" in row} if seen_last else {},
                first_seen=self._first_seen[index],
                last_seen=self._last_seen[index],
                seen_rounds=self._seen_rounds[index],
                rounds=self.rounds,
                periods=periods,
                ongoing=seen_last,
                partial=index in self._partial,
                cell=cells[index],
            ))
        return summaries


# --- online periods as text --------------------------------------------------------------------------

def _clock(when: float, with_date: bool) -> str:
    moment = datetime.fromtimestamp(when, tz=timezone.utc)
    return moment.strftime("%m-%d %H:%M" if with_date else "%H:%M")


def online_text(
    periods: Sequence[Period], *, ongoing: bool, running: bool, with_dates: bool = False, limit: Optional[int] = None
) -> str:
    """
    The ``Online`` column: ``09:00–09:41, 09:55–now`` in UTC, with ``MM-DD`` when the window spans days. The last
    period ends ``now`` when the host was seen in the last round of a run still going. With ``limit``, only the
    latest periods are shown, then ``(+N earlier)``.
    """
    shown = list(periods) if limit is None else list(periods)[-limit:]
    texts = []
    for number, (start, end) in enumerate(shown, 1):
        until = "now" if ongoing and running and number == len(shown) else _clock(end, with_dates)
        texts.append(f"{_clock(start, with_dates)}–{until}")
    hidden = len(periods) - len(shown)
    return ", ".join(texts) + (f" (+{hidden} earlier)" if hidden else "")


# --- runs: live or lost ------------------------------------------------------------------------------

def run_state(
    status: str, *, heartbeat: float, interval: Optional[float], host: str, pid: int, now: float, this_host: str,
    pid_alive: Callable[[int], bool],
) -> str:
    """
    The state the list shows. A run whose row says ``running`` is live while its heartbeat is younger than
    ``max(2.5 x interval, 60 s)`` and, when it runs on this machine, its process exists; otherwise it is ``lost``.
    Any other status (``finished``, ``stopped``, ``failed``) is shown as it is.
    """
    if status != "running":
        return status
    if now - heartbeat > max(GAP_FACTOR * (interval or 0.0), MIN_STALE_SECONDS):
        return "lost"
    if host == this_host and not pid_alive(pid):
        return "lost"
    return "running"


# --- ICMP errors in a ping output ---------------------------------------------------------------------

_TOKEN = re.compile(r"[0-9A-Za-z.:%_-]+")
_LINUX_ERROR = re.compile(r"^From (?P<sender>\S+) icmp_seq=\d+ ")
_MACOS_ERROR = re.compile(r"^\d+ bytes from (?P<sender>\S+?)[:,] (?P<rest>.*)$")
_MACOS_SEND_ERROR = re.compile(
    r"^ping6?: (?:sendto|UDP connect): (?:No route to host|Host is down|Network is unreachable)$"
)


def _address(token: str) -> Optional[Address]:
    """``(address, zone in lower case)`` for an address token (a trailing ``:``, ``.`` or ``,`` dropped), else None."""
    text, _, zone = token.rstrip(":.,").partition("%")
    try:
        return ipaddress.ip_address(text), zone.lower()
    except ValueError:
        return None


def _same(sender: Address, target: Address) -> bool:
    """The same address, and the same zone when both name one."""
    return sender[0] == target[0] and (not sender[1] or not target[1] or sender[1] == target[1])


def _windows_senders(output: str) -> Tuple[List[Address], bool]:
    """The addresses that the per-echo lines name (the lines after the header, up to the next blank line). The header
    and the statistics block are never read: both name the target."""
    lines = output.splitlines()
    start = next((number for number, line in enumerate(lines) if line.strip()), len(lines))
    senders = []
    for line in lines[start + 1:]:
        if not line.strip():
            break
        senders.extend(found for token in _TOKEN.findall(line) if (found := _address(token)))
    return senders, False


def _posix_senders(output: str) -> Tuple[List[Address], bool]:
    """The senders of the ICMP error lines (Linux ``From …``, macOS ``… bytes from …`` without ``icmp_seq=``), and
    whether macOS reported a send error of this machine (``ping: sendto: No route to host`` and the like)."""
    senders: List[Address] = []
    local = False
    macos = oscompat.is_macos()
    for line in output.splitlines():
        line = line.strip()
        match = (_MACOS_ERROR if macos else _LINUX_ERROR).match(line)
        if match and not (macos and "icmp_seq=" in match.group("rest")):
            found = _address(match.group("sender"))
            if found:
                senders.append(found)
        elif macos and _MACOS_SEND_ERROR.match(line):
            local = True
    return senders, local


def header_target(output: Optional[str]) -> Optional[str]:
    """
    The pinged address as the output's header names it, or None without a header: the last address of the line
    that starts with ``PING `` or ``PING6(`` (macOS's ``PING6(...) <source> --> <target>``), or on Windows the first
    line that is not blank, in any language.
    """
    lines = (output or "").splitlines()
    if oscompat.is_windows():
        header = next((line for line in lines if line.strip()), None)
    else:
        header = next((line for line in lines if line.lstrip().startswith(("PING ", "PING6("))), None)
    tokens = [token.rstrip(":.,") for token in _TOKEN.findall(header or "") if _address(token)]
    return tokens[-1] if tokens else None


def icmp_error_result(output: Optional[str], target: Optional[str] = None) -> Optional[str]:
    """
    Read an ICMP error out of a ping output that its classifier read as ``NO RESPONSE`` (no reply in it):
    ``REJECTED`` when the pinged address itself sent one, ``UNREACHABLE`` when any other address did or the platform
    reported a local send error, None when no error line can be placed. Only the sender decides, never the text,
    which Windows prints in the user's language (plan section 4.5; the fixtures in tests/fixtures/ping).

    The pinged address is ``target``, or else the one the output's header names (``header_target``). Without either,
    an error line from an address is not guessed at; only a local send error still counts.
    """
    text = output or ""
    pinged = _address(target if target is not None else header_target(text) or "")
    senders, local = (_windows_senders if oscompat.is_windows() else _posix_senders)(text)
    if pinged is not None:
        if any(_same(sender, pinged) for sender in senders):
            return REJECTED
        if senders:
            return UNREACHABLE
    return UNREACHABLE if local else None
