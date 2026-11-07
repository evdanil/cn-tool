"""The Ping Monitor's whole-history fold: which IPs of a target line ever replied
(docs/plans/2026-11-06-show-available-design.md, "Monitor").

``fold_coverage`` reads every round kept for one request, as ``(start, observations)`` pairs, and gives each host a
status: ``Seen`` (a reply in some round), ``Unseen`` (no reply in at least one round where the probe ran) or ``Not
tested`` (no round could test it). A failed probe (``E``) or a name that did not resolve (``?``) is not evidence of
silence, so such a round does not count for that host: ``tested`` leaves it out and ``failed`` says how many there
were. A subnet whose hosts never replied is *silent*: this machine may simply not reach it, so its ``Unseen`` rows
carry ``SILENT_NOTE``. ``read_coverage`` reads the rounds from a ``PingStore``; ``unseen_rows`` makes the section the
command line, the web table and the download share; ``coverage_page`` cuts the web table's sorted, filtered page.

Pure but for ``read_coverage``: ``sqlite3`` and the store are never imported here at module level.
"""
from __future__ import annotations

import contextlib
import ipaddress
import re
from bisect import bisect_left, bisect_right
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from cn_tool.utils import ping_history as ph

if TYPE_CHECKING:  # only for the annotations: the store is imported where it is used
    from cn_tool.utils.ping_store import PingStore, RequestInfo

SEEN, UNSEEN, NOT_TESTED = "Seen", "Unseen", "Not tested"
SILENT_NOTE = "no IP in this subnet ever replied"
# The web page's query (``coverage_page``): what a page sorts by, filters on and groups by. The history reader and the
# worker's protocol check both read these lists, so a query is refused by one list.
PAGE_SORTS = ("host", "status", "first_seen", "last_seen", "answered")
PAGE_FILTERS = ("host", "status", "note")
PAGE_GROUPS = ("all", "seen", "unseen", "not_tested")
PAGE_COUNTS = ("seen", "unseen", "not_tested")
PAGE_SILENT_SUBNETS = 64  # the names a page's summary carries
_GROUP_STATUS = {"seen": SEEN, "unseen": UNSEEN, "not_tested": NOT_TESTED}
_COUNT_NAME = {status: name for name, status in _GROUP_STATUS.items()}
_FAILED = frozenset("E?")  # the probe failed, or the name did not resolve: no evidence either way
_ANSWERS = re.compile(r"[^.]")  # a plain "." costs nothing, as in ``Tracker.add``


class CoverageStopped(Exception):
    """The ``stop`` signal ended a fold before it read every round."""


@dataclass(frozen=True)
class HostCoverage:
    """One host of the request: its status, the start of the first and the last round it replied in, the rounds it
    replied in (``answered``), the rounds that tested it (``tested``, the rounds less ``failed``) and ``note``."""

    index: int
    host: str
    status: str
    first_seen: Optional[float]
    last_seen: Optional[float]
    answered: int
    tested: int
    failed: int
    note: str


@dataclass(frozen=True)
class Coverage:
    """Every host of the request in host order, the rounds read, the start of the oldest one (``since``) and the
    subnets that never replied, in the order the subnets were given."""

    hosts: Tuple[HostCoverage, ...]
    rounds: int
    since: Optional[float]
    silent_subnets: Tuple[str, ...]


def subnets_of(targets: Sequence[str], hosts: Sequence[str]) -> Dict[str, List[int]]:
    """
    The indexes (in ``hosts``, ascending) of the hosts inside each network of ``targets``, keyed by the target as
    written and in its order. Only a target that contains ``/`` is a network: a name or a single address is not, and
    neither is a host that is not an address. A host inside two networks is listed under both.
    """
    networks = []
    for target in targets:
        if "/" not in target:
            continue
        try:
            networks.append((target, ipaddress.ip_network(target, strict=False)))
        except ValueError:
            continue
    if not networks:
        return {}
    keyed: List[Tuple[int, int, int]] = []
    for index, host in enumerate(hosts):
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            continue
        keyed.append((address.version, int(address), index))
    keyed.sort()  # one search of the sorted hosts for each network, not a pass over every host for each
    found: Dict[str, List[int]] = {}
    for target, network in networks:
        low = bisect_left(keyed, (network.version, int(network.network_address), -1))
        high = bisect_right(keyed, (network.version, int(network.broadcast_address), len(hosts)))
        found[target] = sorted(index for _, _, index in keyed[low:high])
    return found


def fold_coverage(
    hosts: Sequence[str],
    rounds: Iterable[Tuple[float, str]],
    subnets: Optional[Mapping[str, Sequence[int]]] = None,
    *,
    stop: Optional[Callable[[], bool]] = None,
) -> Coverage:
    """
    Fold ``(start, observations)`` rounds, in any order, into the coverage of ``hosts``. ``subnets`` maps a network to
    the indexes of its hosts (``subnets_of``); one with no ``Seen`` host and an ``Unseen`` one is silent, and its
    ``Unseen`` hosts get ``SILENT_NOTE``. ``stop`` is asked once for each round.

    @raise ValueError: a round whose length is not the number of hosts, or that holds a character a round never records.
    @raise CoverageStopped: ``stop()`` was true.
    """
    count = len(hosts)
    answered = [0] * count
    failed = [0] * count
    first: List[Optional[float]] = [None] * count
    last: List[Optional[float]] = [None] * count
    total = 0
    since: Optional[float] = None
    for started, observations in rounds:
        if stop is not None and stop():
            raise CoverageStopped()
        if len(observations) != count:
            raise ValueError(f"a round has {len(observations)} observations for {count} hosts")
        total += 1
        if since is None or started < since:
            since = started
        for match in _ANSWERS.finditer(observations):
            char, index = match.group(), match.start()
            if char in ph.SEEN:
                answered[index] += 1
                earliest, latest = first[index], last[index]
                if earliest is None or started < earliest:
                    first[index] = started
                if latest is None or started > latest:
                    last[index] = started
            elif char in _FAILED:
                failed[index] += 1
            elif char not in ph.OBSERVATIONS:
                raise ValueError(f"a round holds {char!r}, which is not an observation")

    statuses = [
        SEEN if answered[index] else UNSEEN if total - failed[index] else NOT_TESTED for index in range(count)
    ]
    silent: List[str] = []
    noted: Set[int] = set()
    for network, members in (subnets or {}).items():
        member_statuses = {statuses[index] for index in members}
        if SEEN not in member_statuses and UNSEEN in member_statuses:
            silent.append(network)
            noted.update(index for index in members if statuses[index] == UNSEEN)
    return Coverage(
        hosts=tuple(
            HostCoverage(index, hosts[index], statuses[index], first[index], last[index], answered[index],
                         total - failed[index], failed[index], SILENT_NOTE if index in noted else "")
            for index in range(count)
        ),
        rounds=total,
        since=since,
        silent_subnets=tuple(silent),
    )


def read_coverage(
    store: "PingStore", info: "RequestInfo", *, stop: Optional[Callable[[], bool]] = None
) -> Coverage:
    """
    The coverage of ``info``'s whole history, read in one snapshot of ``store``.

    @raise StoreError: a stored round does not fit the request's host list, or the store cannot be read.
    @raise CoverageStopped: ``stop()`` was true.
    """
    from cn_tool.utils.ping_store import StoreError

    with store.snapshot():
        try:
            # Closed on the way out: a failed fold leaves the generator suspended, and an exception keeps it (and the
            # WAL read mark of its cursor) alive for as long as its traceback lives.
            with contextlib.closing(store.round_observations(info.id)) as stream:
                return fold_coverage(info.hosts, stream, subnets_of(info.targets, info.hosts), stop=stop)
        except ValueError as error:
            raise StoreError(f"request {info.key[:8]}: a stored round does not fit its hosts: {error}") from error


def coverage_page(
    coverage: Coverage,
    *,
    sort: str,
    descending: bool,
    group: str,
    filter_field: str,
    filter_text: str,
    limit: int,
    offset: int,
) -> Dict[str, Any]:
    """
    One page of the web table: the hosts of ``group`` (``PAGE_GROUPS``) whose ``filter_field`` text holds
    ``filter_text`` (case-insensitively), ordered by ``sort`` (``PAGE_SORTS``; ``host`` and none are the host order,
    ``index``), from ``offset`` for ``limit``. A host with no ``first_seen`` or ``last_seen`` sorts last either way, and
    equal values keep the host order. Returns ``items`` (a dict for each host, the fields of ``HostCoverage``), ``total``
    (the matches of the group and the filter), ``next_offset`` (None on the last page), ``counts`` (the hosts of each
    status in the whole fold, whatever the group and the filter) and ``summary`` (``rounds``, ``since`` and at most
    ``PAGE_SILENT_SUBNETS`` silent subnets).
    """
    wanted = _GROUP_STATUS.get(group)
    pattern = filter_text.casefold()
    matches = [
        host
        for host in coverage.hosts
        if (wanted is None or host.status == wanted) and pattern in str(getattr(host, filter_field)).casefold()
    ]
    if sort == "status":
        matches.sort(key=lambda host: host.status.casefold(), reverse=descending)  # a reversed sort keeps equal keys' order
    elif sort in ("first_seen", "last_seen", "answered"):
        seen = sorted((host for host in matches if getattr(host, sort) is not None),
                      key=lambda host: getattr(host, sort), reverse=descending)
        matches = seen + [host for host in matches if getattr(host, sort) is None]
    elif descending:  # host order, which ``fold_coverage`` gives
        matches.reverse()
    counts = dict.fromkeys(PAGE_COUNTS, 0)
    for host in coverage.hosts:
        counts[_COUNT_NAME[host.status]] += 1
    following = offset + limit
    return {
        "items": [asdict(host) for host in matches[offset:following]],
        "total": len(matches),
        "next_offset": following if following < len(matches) else None,
        "counts": counts,
        "summary": {
            "rounds": coverage.rounds,
            "since": coverage.since,
            "silent_subnets": list(coverage.silent_subnets[:PAGE_SILENT_SUBNETS]),
        },
    }


def unseen_rows(coverage: Coverage, fmt: str, when: Callable[[Optional[float]], str]) -> List[Dict[str, Any]]:
    """
    The ``unseen`` section: a row for each ``Unseen`` and ``Not tested`` host, in host order. ``Seen`` reads ``0 of
    2,880 rounds`` (the rounds that tested the host); for JSON it is the numbers ``Seen rounds`` and ``Rounds``
    instead. ``Since`` is ``when`` of the oldest round kept, and ``Failed rounds`` is a number in every format.
    """
    since = when(coverage.since)
    rows: List[Dict[str, Any]] = []
    for host in coverage.hosts:
        if host.status == SEEN:
            continue
        row: Dict[str, Any] = {"Host": host.host, "Status": host.status}
        if fmt == "json":
            row.update({"Seen rounds": host.answered, "Rounds": host.tested})
        else:
            row["Seen"] = f"{host.answered:,} of {host.tested:,} rounds"
        row.update({"Failed rounds": host.failed, "Since": since, "Note": host.note})
        rows.append(row)
    return rows
