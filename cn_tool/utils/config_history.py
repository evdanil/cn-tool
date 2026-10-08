"""Configuration history helpers for ``cn diff``: pure functions over config snapshots.

``parse_since`` and ``since_time`` turn the ``--since`` value into a point in time.
``select_window`` picks the snapshots to compare, ``changed_lines`` lists the lines that differ
between its ends, each attributed to the snapshot that made the change.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

if TYPE_CHECKING:  # only for the annotations: cn must start without the optional config_analyzer
    from config_analyzer.parser import Snapshot

ConfigKey = Tuple[str, str]  # (parent, line)

SINCE_MESSAGE = (
    "'{text}' is not a time: use 30m, 24h, 7d, 2w, 2026-10-01, 2026-10-01T14:00 "
    "or a snapshot file name ending in .cfg"
)

# Four digits keep ``now - delta`` inside datetime's range (9999 weeks is under 192 years).
_RELATIVE = re.compile(r"(?P<count>[0-9]{1,4})(?P<unit>[mhdw])", re.IGNORECASE)
_UNIT_NAMES = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
_SNAPSHOT_SUFFIX = ".cfg"


@dataclass(frozen=True)
class Since:
    """A parsed ``--since`` value: exactly one field is set by ``parse_since``."""

    delta: Optional[timedelta] = None
    when: Optional[datetime] = None
    snapshot: Optional[str] = None


def parse_since(text: str) -> Since:
    """
    Parse a ``--since`` value: ``30m``/``24h``/``7d``/``2w`` (counted back from now), an ISO
    date or time, or a snapshot file name ending in ``.cfg``.

    A naive ISO value is UTC (the zone the TUI shows); ``Z`` or an offset is honoured and the
    result is converted to UTC.

    @raise ValueError: ``SINCE_MESSAGE`` for anything else.
    """
    value = text.strip()
    relative = _RELATIVE.fullmatch(value)
    if relative:
        unit = _UNIT_NAMES[relative["unit"].lower()]
        return Since(delta=timedelta(**{unit: int(relative["count"])}))
    if value.lower().endswith(_SNAPSHOT_SUFFIX) and len(value) > len(_SNAPSHOT_SUFFIX):
        return Since(snapshot=value)
    try:
        # fromisoformat only learned a trailing "Z" in Python 3.11.
        if value.endswith(("Z", "z")):
            value = value[:-1] + "+00:00"
        when = datetime.fromisoformat(value)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return Since(when=when.astimezone(timezone.utc))
    except (ValueError, OverflowError):
        raise ValueError(SINCE_MESSAGE.format(text=text)) from None


def since_time(since: Since, now: datetime) -> Optional[datetime]:
    """The point in time ``since`` names, or ``None`` for a snapshot name (it has no time yet)."""
    if since.delta is not None:
        return now - since.delta
    return since.when


def format_time(when: datetime) -> str:
    """``when`` in UTC, to the second: ``2026-10-01T14:00:00+00:00``."""
    return when.astimezone(timezone.utc).isoformat(timespec="seconds")


def since_label(since: Since, now: datetime) -> str:
    """What ``since`` stands for in a message: the snapshot name, or the time it names in UTC."""
    when = since_time(since, now)
    if when is not None:
        return format_time(when)
    return since.snapshot or ""


def config_keys(text: str) -> List[ConfigKey]:
    """
    The ``(parent, line)`` key of every line of a configuration, in order, repeats kept.

    The parent is the nearest preceding line without leading whitespace (``""`` for such a line
    itself). Trailing whitespace is dropped. Blank lines and lines that are only ``!`` (Cisco
    separators) are skipped: they are never a key and never a parent.
    """
    keys: List[ConfigKey] = []
    parent = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.strip() == "!":
            continue
        if line[0].isspace():
            keys.append((parent, line))
        else:
            parent = line
            keys.append(("", line))
    return keys


@dataclass(frozen=True)
class Window:
    """The snapshots a diff covers: ``steps`` runs from ``start`` to ``end`` (both included), oldest first."""

    start: "Snapshot"
    end: "Snapshot"
    steps: List["Snapshot"]
    warning: str = ""


def select_window(
    newest_first: List["Snapshot"], since: Optional[Since], now: datetime, *, whole_history: bool
) -> Window:
    """
    The window over ``newest_first`` (newest snapshot first, at least one). It ends at the newest
    snapshot and starts at:

    - ``since`` a time: the newest snapshot at or before it, else the oldest one (with a warning);
    - ``since`` a snapshot name: that snapshot;
    - no ``since``: the oldest snapshot when ``whole_history``, else the previous one.

    Over a single snapshot, or when ``since`` is newer than the newest snapshot, start is end.

    @raise ValueError: ``since`` names a snapshot that is not in the list.
    """
    warning = ""
    if since is None:
        index = len(newest_first) - 1 if whole_history else min(1, len(newest_first) - 1)
    elif since.snapshot is not None:
        found = next((i for i, snap in enumerate(newest_first) if snap.original_filename == since.snapshot), None)
        if found is None:
            raise ValueError(f"no snapshot named {since.snapshot}")
        index = found
    else:
        cutoff = since_time(since, now)
        found = next(
            (i for i, snap in enumerate(newest_first) if cutoff is not None and snap.timestamp <= cutoff), None
        )
        if found is None:
            index = len(newest_first) - 1
            oldest = newest_first[index]
            warning = (
                f"no snapshot before {since_label(since, now)}; "
                f"compared from the oldest, {oldest.original_filename} ({format_time(oldest.timestamp)})"
            )
        else:
            index = found
    return Window(start=newest_first[index], end=newest_first[0], steps=newest_first[index::-1], warning=warning)


def _last_occurrences(keys: List[ConfigKey], surplus: "Counter[ConfigKey]") -> Dict[ConfigKey, List[int]]:
    """Positions of the last ``surplus[key]`` occurrences of each key in ``keys``: a repeated line counts at its tail."""
    wanted = Counter(surplus)
    found: Dict[ConfigKey, List[int]] = {}
    for position in range(len(keys) - 1, -1, -1):
        key = keys[position]
        if wanted[key] > 0:
            wanted[key] -= 1
            found.setdefault(key, []).append(position)
    return found


def changed_lines(window: Window) -> List[Dict[str, str]]:
    """
    The lines that differ between the ends of ``window``, as rows ``change`` (added|removed),
    ``parent``, ``line``, ``snapshot``, ``author`` and ``time`` (UTC).

    Keys (see ``config_keys``) are counted, not compared as sets: a key whose count differs by *n*
    gives *n* rows, a pure reorder gives none. A row is attributed to the last step of the window
    where its key's count rose (added) or fell (removed), so a line added and removed again inside
    the window is not shown. Rows are sorted by time, then by position in the end snapshot (added)
    or the start snapshot (removed), removed before added on a tie.
    """
    start_keys = config_keys(window.start.content_body)
    end_keys = config_keys(window.end.content_body)
    start_count, end_count = Counter(start_keys), Counter(end_keys)
    added, removed = end_count - start_count, start_count - end_count
    if not added and not removed:
        return []  # nothing differs: the steps in between need not be read

    rose: Dict[ConfigKey, "Snapshot"] = {}
    fell: Dict[ConfigKey, "Snapshot"] = {}
    previous = start_count
    for step in window.steps[1:]:
        current = Counter(config_keys(step.content_body))
        rose.update({key: step for key in added if current[key] > previous[key]})
        fell.update({key: step for key in removed if current[key] < previous[key]})
        previous = current

    ordered = []
    for change, order, positions, culprits in (
        ("added", 1, _last_occurrences(end_keys, added), rose),
        ("removed", 0, _last_occurrences(start_keys, removed), fell),
    ):
        for key, places in positions.items():
            step = culprits[key]
            parent, line = key
            row = {
                "change": change,
                "parent": parent,
                "line": line,
                "snapshot": step.original_filename,
                "author": step.author,
                "time": format_time(step.timestamp),
            }
            ordered.extend(((step.timestamp, place, order), row) for place in places)
    ordered.sort(key=lambda item: item[0])
    return [row for _, row in ordered]
