"""
``cn_table``: the one table of the web pages (plan ``docs/plans/webui-ux-plan.md`` section 7.1 and "R2-02 design note").

A table is built once and then updated in place: a quick filter over all columns that acts while the user types, sort
buttons in a header that is never drawn again (the focus stays on them), columns as wide as their content, one footer
(rows per page, the range, First / Previous / Next / Last), Download table (CSV) and Copy table, Ping these / Monitor
these over the rows as filtered, status as chips. The rows come from a source: ``RowsSource`` (rows the page holds,
filtered and sorted here) or anything with the ``PagedSource`` methods (rows the worker pages).

Nothing here is a slot of a component: the sort buttons are ordinary elements and a row's button is markup inside the
one ``tbody``, which the browser keeps while its text is the same, so an update of any other element of the page
replaces neither (``tests/test_webui_foreign_job_browser.py``).

The top of the module is pure (the standard library and the pure ``table_export`` / ``texts``); NiceGUI is imported
inside ``cn_table``, ``cn_definition_list`` and ``apply_table_assets``.
"""
from __future__ import annotations

import asyncio
import inspect
import ipaddress
import json
import math
import re
from dataclasses import dataclass, field, replace
from datetime import datetime
from html import escape
from typing import Any, Callable, Literal, Mapping, Protocol, Sequence

from . import table_export
from .table_export import ALL, PAGE_SIZES, page_limit
from .texts import fmt_count

FILTER_MIN_ROWS = 8   # fewer rows than this: no filter field
MAX_QUERY = 256
DEFAULT_SIZE = 25
NO_MATCH = 'No rows match this filter.'
TOO_LONG = f'Filter text must be {MAX_QUERY} characters or fewer.'
SCROLL_HINT = 'Scroll the table sideways to see all columns.'
CANCELLED = {False: 'Cancelled. Nothing was downloaded.', True: 'Cancelled. Nothing was copied.'}
ROW_KEYS = ('id', '__row')  # a row's identity, never a column
TONES = ('ok', 'problem', 'attention', 'neutral')

# What a status says, by its text (casefolded; "OK (2 of 3)" is read as "ok"). A chip is never colour alone: its text
# is the status.
STATE_TONES = {
    'ok': 'ok', 'data found': 'ok', 'open': 'ok', 'seen': 'ok', 'active': 'ok',
    'no response': 'problem', 'no route': 'problem', 'error': 'problem', 'timeout': 'problem',
    'unreachable': 'problem', 'not tested': 'problem', 'failed': 'problem',
    'no match': 'attention', 'not found': 'attention', 'no data': 'attention', 'data with warnings': 'attention',
    'partial data': 'attention', 'partial data with warnings': 'attention', 'warnings only': 'attention',
    'unseen': 'attention', 'not run': 'attention', 'closed': 'attention',
    'used': 'neutral', 'unused': 'neutral', 'free': 'neutral',
}

# One map for headings: a raw key of a result row to what the table's heading says. A key that is not here goes
# through ``column_label``'s rule (sentence case, the usual abbreviations in capitals).
COLUMN_LABELS = {
    'network view': 'Network view', 'Network view': 'Network view', 'subnet': 'Subnet', 'Subnet': 'Subnet',
    'network': 'Network', 'A Record': 'A record', 'IP Address': 'IP address', 'IP address': 'IP address',
    'Resolved Subnet': 'Network', 'Original Input(s)': 'Inputs', 'Original Input': 'Input',
    'Lease State': 'Lease state', 'lease state': 'Lease state', 'Record Type': 'Record type',
    'record type': 'Record type', 'PTR name': 'PTR name', 'mac': 'MAC', 'MAC': 'MAC', 'DUID': 'DUID',
}
_CAPITALS = {'ip', 'mac', 'duid', 'dhcp', 'dns', 'ptr', 'ttl', 'vlan', 'fqdn', 'tcp', 'icmp', 'id', 'ea'}
_ADDRESS_FIELDS = {'ip', 'ip address', 'address', 'resolved subnet', 'network', 'subnet', 'container',
                   'child container', 'host', 'start address', 'end address'}
_NUMERIC_FIELDS = {'count', 'port', 'interval', 'line', 'line number', 'prefix length', 'utilization',
                   'utilization %', 'dhcp utilization %', 'leases', 'static', 'total'}
_MONO_FIELDS = _ADDRESS_FIELDS | {'mac', 'duid'}
_STATE_FIELDS = {'status'}


class TableUnavailable(Exception):
    """A source cannot give its rows now; the text is what the table's status line says."""


@dataclass(frozen=True)
class Column:
    key: str                # the row's key; also td[data-col] and the name a sort is known by
    label: str = ''         # '' means column_label(key)
    kind: Literal['text', 'mono', 'state', 'action'] = 'text'
    sticky: bool = False    # the identity column: stays in view while the table scrolls sideways
    sortable: bool = True   # a column of kind 'action' never sorts
    hide_if_empty: bool = True  # RowsSource only: not drawn when no row of the source has a value
    max_ch: int = 40        # the widest a cell of this column grows, in characters, before an ellipsis (its title has it all)
    html: Callable[[dict], str] | None = None   # the cell's inner markup for a row; the page escapes what it puts in it

    @property
    def heading(self) -> str:
        return self.label or column_label(self.key)


@dataclass
class TableState:
    """How one table is arranged. The page owns it (one per table) and it outlives a redraw of the table."""
    query: str = ''
    sort: str = ''
    descending: bool = False
    page: int = 0                     # 0-based
    size: Any = DEFAULT_SIZE          # one of table_export.PAGE_SIZES
    group: str = 'all'
    # What a source that is not seekable needs to return to ``page``: the ``Page.next`` of each page before it (None
    # for the first). The handle reads and writes it, so a handle built again from this state shows the same page.
    cursors: list = field(default_factory=lambda: [None], compare=False, repr=False)

    def first_page(self) -> None:
        """Back to page one, for a state a page keeps while the rows under it are read again or are another set's (a
        new round, a refreshed history): the cursors belong to the rows they were taken from."""
        self.page, self.cursors = 0, [None]


@dataclass(frozen=True)
class Group:
    """A toggle above the table that narrows it to one kind of row; "All" is always the first."""
    key: str
    label: str


@dataclass(frozen=True)
class RowGroup:
    """A header row before each run of rows that have the same value in ``key``, saying ``label(first row of the run)``
    (escaped here). ``when(state)`` None means always; a run is of rows next to each other, so a table sorted by
    another column says ``when`` is false."""
    key: str
    label: Callable[[dict], str]
    when: Callable[[Any], bool] | None = None


@dataclass
class Page:
    rows: list
    total: int | None = None          # rows that match the filter and the group; None when the source cannot say
    offset: int = 0                   # 0-based number of rows[0] among them
    next: Any = None                  # the cursor of the next page; None on the last
    counts: Mapping[str, int] = field(default_factory=dict)  # rows of each Group.key and of 'all', filter applied
    unfiltered: int | None = None     # rows before the filter and the group: decides the chrome


@dataclass(frozen=True)
class RowAction:
    """The button of the column of kind 'action' (View details)."""
    label: str
    on_click: Callable[[str], Any]                 # gets str(row[id_key]); may be async
    name: Callable[[dict], str] | None = None      # one row's accessible name; ``label`` when None
    id_key: str = 'id'                             # a row without it has no button


class PagedSource(Protocol):
    """Rows the worker holds. ``seekable`` (optional, default False): pages are addressed by ``state.page`` alone and
    ``cursor`` is always None; otherwise ``cursor`` is the ``Page.next`` of the page before (None for the first)."""

    async def fetch(self, state: TableState, cursor: Any = None) -> Page: ...

    async def all_rows(self, state: TableState) -> list: ...   # every row as filtered and sorted; TableUnavailable


def column_label(key: str, labels: Mapping[str, str] | None = None) -> str:
    """The heading of a raw key: the map's, else the key in sentence case with the usual abbreviations in capitals
    ("lease state" and "Lease State" are both "Lease state"; "mac" is "MAC")."""
    labels = COLUMN_LABELS if labels is None else labels
    if key in labels:
        return labels[key]
    words = str(key).split(' ')
    out = []
    for index, word in enumerate(words):
        if word.casefold() in _CAPITALS:
            out.append(word.upper())
        elif word.isupper() or not word.isalpha():
            out.append(word)  # an abbreviation or something with a sign: as written
        elif index == 0:
            out.append(word[:1].upper() + word[1:].lower())
        else:
            out.append(word.lower())
    return ' '.join(out)


def is_address_field(key) -> bool:
    """Whether a column of this name holds addresses or networks (they sort as such and are drawn mono)."""
    return str(key).casefold() in _ADDRESS_FIELDS


def cell_text(value) -> str:
    return '' if value is None else str(value)


def is_blank(value) -> bool:
    return value is None or not str(value).strip()


def state_chip(text, tone: str | None = None) -> str:
    """A status as a chip (escaped HTML). ``tone`` None looks the text up in ``STATE_TONES``; unknown is neutral."""
    text = cell_text(text)
    if not text.strip():
        return ''
    if tone is None:
        key = text.strip().casefold()
        tone = STATE_TONES.get(key) or STATE_TONES.get(key.split(' (')[0].split(':')[0].strip(), 'neutral')
    if tone not in TONES:
        tone = 'neutral'
    return f'<span class="cn-chip cn-chip-{tone}">{escape(text)}</span>'


_GROUPED = re.compile(r'^[+-]?\d{1,3}(,\d{3})+(\.\d+)?$')


def _number(value):
    """A count or a percentage as a float ("1,024" and "87.5%" included); None when it is not a finite number."""
    text = str(value).strip().removesuffix('%').strip()
    if _GROUPED.match(text):
        text = text.replace(',', '')
    try:
        number = float(text)
    except ValueError:
        return None
    return number if math.isfinite(number) else None


def order_rows(rows, key, descending=False):
    """Order a copy of a complete result; missing values stay last in both directions, and so do values that cannot
    be read as what the column holds (a name in an address column as text, other counts in the order they came). Addresses and networks sort as such, counts as numbers (thousands separators
    allowed), everything else as text without case."""
    field_name = key.casefold()

    def sort_key(row):
        text = str(row.get(key)).strip()
        if field_name in _ADDRESS_FIELDS:
            try:
                network = ipaddress.ip_network(text, strict=False)
            except ValueError:
                return None
            return (network.version, int(network.network_address), network.prefixlen)
        if field_name in _NUMERIC_FIELDS:
            number = _number(text)
            return None if number is None else (number,)
        return (text.casefold(),)

    ordered, unreadable, missing = [], [], []
    for row in rows:
        if is_blank(row.get(key)):
            missing.append(row)
            continue
        ordered_key = sort_key(row)
        if ordered_key is None:
            unreadable.append(row)
        else:
            ordered.append((ordered_key, row))
    ordered.sort(key=lambda item: item[0], reverse=descending)
    if field_name in _ADDRESS_FIELDS:  # a name in an address column (Ping's Host) is text, in the direction asked
        unreadable.sort(key=lambda row: str(row.get(key)).strip().casefold(), reverse=descending)
    return [row for _, row in ordered] + unreadable + missing


def filter_rows_any(rows, query, keys=None):
    """The rows with ``query`` in any column: literal, without case. ``keys`` are the columns read (every key of a
    row but its identity when None)."""
    if not isinstance(query, str) or len(query) > MAX_QUERY:
        raise ValueError(TOO_LONG)
    needle = query.strip().casefold()
    if not needle:
        return list(rows)

    def values(row):
        return (row.get(key) for key in keys) if keys is not None else (
            value for key, value in row.items() if key not in ROW_KEYS)
    return [row for row in rows if any(value is not None and needle in str(value).casefold() for value in values(row))]


def columns_of(rows, lead=(), *, labels: Mapping[str, str] | None = None, sticky: str = '', keep=(),
               kinds: Mapping[str, str] | None = None) -> list:
    """The columns of rows whose keys are only known when they arrive: ``lead`` first (those that occur), then the
    others as they first appear. An address is mono, a status a chip (``kinds`` overrides); ``sticky`` names the
    identity column, which is always drawn; a key in ``keep`` is drawn even when no row has a value; ``labels``
    overrides headings."""
    keys = table_export.table_columns(({key: None for key in row if key not in ROW_KEYS} for row in rows), lead)
    columns = []
    for key in keys:
        folded = key.casefold()
        kind = (kinds or {}).get(key) or ('state' if folded in _STATE_FIELDS else 'mono' if folded in _MONO_FIELDS else 'text')
        columns.append(Column(key, (labels or {}).get(key, ''), kind, sticky=key == sticky,
                              hide_if_empty=key not in keep and key != sticky))
    return columns


def visible_columns(columns: Sequence[Column], rows) -> list:
    """The columns to draw: one that may hide and has no value in any row is left out; an action column stays."""
    rows = list(rows)
    return [column for column in columns
            if column.kind == 'action' or not column.hide_if_empty
            or any(not is_blank(row.get(column.key)) for row in rows)]


def normalise(state: TableState, columns: Sequence[Column], groups: Sequence[Group] = ()) -> TableState:
    """Make a state from anywhere (a kept one, a URL) valid for these columns, in place."""
    state.query = state.query[:MAX_QUERY] if isinstance(state.query, str) else ''
    sortable = {column.key for column in columns if column.sortable and column.kind != 'action'}
    if state.sort not in sortable:
        state.sort, state.descending = '', False
    state.descending = bool(state.descending)
    if state.size not in PAGE_SIZES:
        try:
            state.size = int(state.size)
        except (TypeError, ValueError):
            state.size = DEFAULT_SIZE
        if state.size not in PAGE_SIZES:
            state.size = DEFAULT_SIZE
    state.page = state.page if isinstance(state.page, int) and not isinstance(state.page, bool) and state.page > 0 else 0
    if state.group != 'all' and state.group not in {group.key for group in groups}:
        state.group = 'all'
    return state


class RowsSource:
    """Rows the page holds: filtered, grouped and sorted in process. ``group_of(row)`` gives a row's ``Group.key``.

    The rows may change while the table is on the page: ``set_rows(rows)`` replaces them, and ``touch()`` says that
    rows were edited in place. An append, a removal or ``source.rows = [...]`` is seen by itself (the arrangement is
    kept for one revision, one list and one length), an edit of a row's value is not: call ``touch()``. Then call
    ``TableHandle.refresh()``: it draws the new rows, and the table again when the columns that hold a value changed
    or when the rows came or went."""
    seekable = True

    def __init__(self, rows, *, order=None, group_of=None):
        self.rows = list(rows)
        self.keys = None  # the columns the filter reads: set by cn_table to the columns it draws, then by the rows
        self.columns = None  # every Column of the table (cn_table sets it): the drawn ones follow the rows
        self._order = order or order_rows
        self._group_of = group_of
        self._kept = (None, None, None)
        self._revision = 0
        self._stamp = None

    def touch(self) -> None:
        """The rows were edited in place: forget what was arranged from them."""
        self._revision += 1
        self._sync()

    def set_rows(self, rows) -> None:
        """Replace the rows (any iterable); the arrangement, the filtered columns and ``drawn_columns`` follow."""
        self.rows = list(rows)
        self.touch()

    def drawn_columns(self):
        """The columns to draw for the rows now (``columns`` that have a value in some row); None before ``columns``."""
        return None if self.columns is None else visible_columns(self.columns, self.rows)

    def _sync(self):
        stamp = (self._revision, id(self.rows), len(self.rows))
        if stamp != self._stamp:
            self._stamp = stamp
            self._kept = (None, None, None)
            if self.columns is not None:
                self.keys = [column.key for column in self.drawn_columns() if column.kind != 'action']

    def _matching(self, state):
        return filter_rows_any(self.rows, state.query, self.keys)

    def _arranged(self, state):
        self._sync()
        key = (state.query, state.sort, state.descending, state.group, tuple(self.keys) if self.keys is not None else None)
        if self._kept[0] != key:
            matching = self._matching(state)
            rows = matching
            if self._group_of is not None and state.group != 'all':
                rows = [row for row in rows if self._group_of(row) == state.group]
            if state.sort:
                rows = self._order(rows, state.sort, state.descending)
            counts = {'all': len(matching)}
            if self._group_of is not None:
                for row in matching:
                    name = self._group_of(row)
                    counts[name] = counts.get(name, 0) + 1
            self._kept = (key, rows, counts)
        return self._kept[1], self._kept[2]

    def filtered(self, state) -> list:
        """Every row as filtered, grouped and sorted: all pages (the export, Ping these)."""
        return list(self._arranged(state)[0])

    def page(self, state) -> Page:
        rows, counts = self._arranged(state)
        limit = page_limit(state.size)
        pages = max(1, -(-len(rows) // limit))
        number = min(max(int(state.page), 0), pages - 1)
        offset = number * limit
        return Page(rows[offset:offset + limit], total=len(rows), offset=offset,
                    next=number + 1 if number + 1 < pages else None, counts=counts, unfiltered=len(self.rows))

    async def fetch(self, state, cursor=None) -> Page:
        return self.page(state)

    async def all_rows(self, state) -> list:
        return self.filtered(state)


def last_page(total, size) -> int:
    """The ordinal of the last page of ``total`` rows."""
    return max(0, -(-int(total) // page_limit(size)) - 1)


def range_text(page: Page) -> str:
    """The footer's range: "1–25 of 65,790", "26–50" when the total is unknown, "0 of 0"."""
    count = len(page.rows)
    first, last = (page.offset + 1, page.offset + count) if count else (0, 0)
    text = fmt_count(last) if not count else f'{fmt_count(first)}–{fmt_count(last)}'
    return text + (f' of {fmt_count(page.total)}' if page.total is not None else '')


def match_text(page: Page, state: TableState) -> str:
    """The line beside the filter: nothing without a filter or a group, else how many rows are left."""
    if not state.query.strip() and state.group == 'all':
        return ''
    if page.total == 0 or (page.total is None and not page.rows):
        return NO_MATCH
    if page.total is None or page.unfiltered is None:
        return ''
    return f'{fmt_count(page.total)} of {fmt_count(page.unfiltered)} rows'


def header_id(prefix: str, key: str) -> str:
    """The id of a column's ``th`` (a grouped body's cells name it in ``headers``)."""
    return f'{prefix or "cn-table"}-h-{re.sub(r"[^A-Za-z0-9_-]", "_", key)}'


def _cell_html(column: Column, row, row_action, headers: str = ''):
    classes = ' '.join(name for name in ('cn-td-' + column.kind, 'cn-td-sticky' if column.sticky else '') if name)
    named = f' headers="{escape(headers, quote=True)}"' if headers else ''
    lead = f'<td class="{classes}"{named} data-col="{escape(column.key, quote=True)}">'
    if column.kind == 'action':
        identity = row.get(row_action.id_key) if row_action is not None else None
        if is_blank(identity):
            return lead + '</td>'
        name = row_action.name(row) if row_action.name is not None else row_action.label
        return (f'{lead}<button type="button" class="cn-row-action" data-row-action="{escape(str(identity), quote=True)}" '
                f'aria-label="{escape(name, quote=True)}">{escape(row_action.label)}</button></td>')
    text = cell_text(row.get(column.key))
    if column.html is not None:
        return lead + column.html(row) + '</td>'
    if column.kind == 'state':
        return lead + state_chip(text) + '</td>'
    if not text:
        return lead + '</td>'
    style = f' style="max-width:{column.max_ch}ch"' if column.max_ch != Column.max_ch else ''
    return f'{lead}<div class="cn-cell"{style} title="{escape(text, quote=True)}">{escape(text)}</div></td>'


def body_html(columns: Sequence[Column], rows, row_action: RowAction | None = None, *, empty: str = '',
              grouping: RowGroup | None = None, prefix: str = '') -> str:
    """The markup of the ``tbody``, every text escaped: one element for the browser instead of one per cell. A row is
    ``tr[data-row=<its number on the page>]``, a cell ``td[data-col=<key>]``; with ``grouping`` a header row
    (``tr.cn-table-group``) comes before each run, and does not count as a row. All the runs share the one ``tbody``,
    so a header row's ``scope`` could not end with its run: the header ``th`` has an id (``<prefix>-g<n>``) and each cell
    of its run names it and its column's ``th`` (``header_id``) in ``headers``."""
    rows = list(rows)
    if not rows:
        return (f'<tr class="cn-table-empty"><td colspan="{max(1, len(columns))}">{escape(empty)}</td></tr>'
                if empty else '')
    out, previous, run = [], object(), -1
    for index, row in enumerate(rows):
        if grouping is not None and row.get(grouping.key) != previous:
            previous, run = row.get(grouping.key), run + 1
            out.append(f'<tr class="cn-table-group"><th id="{prefix or "cn-table"}-g{run}" colspan="{max(1, len(columns))}">'
                       f'<span>{escape(grouping.label(row))}</span></th></tr>')
        out.append(f'<tr data-row="{index}">' + ''.join(
            _cell_html(column, row, row_action,
                       f'{prefix or "cn-table"}-g{run} {header_id(prefix, column.key)}' if grouping is not None else '')
            for column in columns) + '</tr>')
    return ''.join(out)


def definition_html(row, labels: Mapping[str, str] | None = None) -> str:
    """The inside of a ``dl`` for one row: a term and a value for every value the row has (escaped)."""
    return ''.join(f'<dt>{escape(column_label(key, labels))}</dt><dd>{escape(cell_text(value))}</dd>'
                   for key, value in row.items() if key not in ROW_KEYS and not is_blank(value))


def export_records(columns: Sequence[Column], rows):
    """``(headings, rows keyed by heading)`` of an export: the columns drawn without the action column, as shown."""
    data = [column for column in columns if column.kind != 'action']
    labels = [column.heading for column in data]
    return labels, [{column.heading: cell_text(row.get(column.key)) for column in data} for row in rows]


TABLE_CSS = '''
.cn-table-host { display:contents; }
.cn-table-block { display:flex; flex-direction:column; gap:8px; width:100%; min-width:0; }
.cn-table-tools { display:flex; flex-wrap:wrap; align-items:center; gap:8px 20px; width:100%; min-width:0; }
.cn-table-filter { display:flex; flex-wrap:wrap; align-items:center; gap:8px 12px; min-width:0; max-width:100%; }
.cn-table-filter .q-field { width:260px; max-width:100%; }
.cn-table-match:empty { display:none; }
.cn-table-groups { display:flex; flex-wrap:wrap; align-items:center; gap:6px; }
.cn-table-scroll { width:100%; min-width:0; max-width:100%; overflow-x:auto;
  border:1px solid var(--cn-line); border-radius:4px; background:var(--cn-panel); }
/* No box of its own (results first, R2-05): the page scrolls. The toolbar sticks to the top of the window where there
   is room for it; the header row follows under it, moved by the table script (a box that scrolls sideways cannot hold
   a sticky header for the page). */
@media (min-width:600px) and (min-height:500px) {
  .cn-table-tools { position:sticky; top:0; z-index:5; background:var(--cn-page); padding:6px 0; }
  .cn-panel .cn-table-tools { background:var(--cn-panel); }
}
.cn-data-table thead th { transform:translateY(var(--cn-head-shift, 0px)); }
.cn-table-scroll[data-cn-head-stuck] thead th { box-shadow:0 1px 0 var(--cn-line); }
.cn-data-table { border-collapse:separate; border-spacing:0; width:max-content; min-width:100%; font-size:var(--cn-text-data); font-variant-numeric:tabular-nums; }
.cn-data-table th, .cn-data-table td { text-align:left; vertical-align:middle; padding:7px 10px;
  border-bottom:1px solid var(--cn-line); white-space:nowrap; background:var(--cn-panel); }
.cn-data-table th { position:sticky; top:0; z-index:2; background:var(--cn-table-head); color:var(--cn-ink); font-weight:650; }
.cn-data-table tbody tr:last-child td { border-bottom:0; }
.cn-data-table tbody tr:hover td { background:var(--cn-table-hover); }
.cn-cell { max-width:40ch; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.cn-td-mono { font-family:ui-monospace,monospace; }
td.cn-td-sticky { font-weight:600; }
@media(min-width:600px) {
  .cn-data-table .cn-td-sticky { position:sticky; left:0; border-right:1px solid var(--cn-line); }
  .cn-data-table td.cn-td-sticky { z-index:1; }
  .cn-data-table th.cn-td-sticky { z-index:3; }
}
@media(max-width:599px) {
  .cn-data-table th, .cn-data-table td { padding:7px; }
  .cn-td-sticky .cn-cell { white-space:normal; overflow-wrap:anywhere; max-width:185px; }
}
.cn-table-empty td { color:var(--cn-muted); }
.cn-data-table .cn-table-group th { background:var(--cn-table-head); font-weight:650; }
.cn-table-group th span { position:sticky; left:10px; }
.cn-table-intro:empty { display:none; }
.cn-data-table mark { background:var(--cn-mark-bg); color:var(--cn-mark-ink); border-radius:2px; padding:0 1px; }
.cn-chip { display:inline-block; padding:1px 8px; border-radius:10px; font-weight:600; white-space:nowrap;
  border:1px solid var(--cn-line); background:var(--cn-chip-bg); color:var(--cn-ink); }
.cn-chip-ok { color:var(--cn-ok-ink); border-color:var(--cn-ok-ink); background:var(--cn-ok-bg); }
.cn-chip-problem { color:var(--cn-error-ink); border-color:var(--cn-error-ink); background:var(--cn-problem-bg); }
.cn-chip-attention { color:var(--cn-attention-ink); border-color:var(--cn-attention-line); background:var(--cn-attention-bg); }
.cn-row-action, .cn-page-button { border:0; background:transparent; color:var(--cn-link); font:inherit; font-weight:600;
  cursor:pointer; min-height:28px; padding:2px 8px; border-radius:4px; }
.cn-row-action:hover, .cn-page-button:hover { background:var(--cn-action-hover); }
.cn-group-button { border:1px solid currentColor; background:transparent; color:var(--cn-link); font:inherit;
  font-weight:600; cursor:pointer; min-height:32px; padding:2px 10px; border-radius:4px; max-width:100%; text-align:left; }
.cn-group-button:hover { background:var(--cn-action-hover); }
.cn-group-button[aria-pressed=true] { background:var(--cn-action-hover); box-shadow:inset 0 -3px var(--cn-focus); }
.cn-page-button[aria-disabled=true] { color:var(--cn-muted); cursor:default; background:transparent; }
.cn-table-hint { display:none; }
[data-cn-overflow] > .cn-table-hint { display:block; }
.cn-table-footer { display:flex; flex-wrap:wrap; align-items:center; gap:4px 16px; width:100%; min-width:0; }
.cn-table-footer label { display:inline-flex; flex-wrap:wrap; align-items:center; gap:4px 8px; max-width:100%; min-width:0; }
.cn-table-footer select { font:inherit; color:inherit; background:var(--cn-panel); border:1px solid var(--cn-field-line);
  border-radius:4px; padding:3px 6px; max-width:100%; }
.cn-table-range { font-variant-numeric:tabular-nums; }
.cn-table-pages { display:flex; flex-wrap:wrap; gap:2px; }
dl.cn-definitions { display:grid; grid-template-columns:max-content minmax(0,1fr); gap:4px 16px; margin:0; width:100%; }
dl.cn-definitions dt { color:var(--cn-muted); }
dl.cn-definitions dd { margin:0; overflow-wrap:anywhere; }
@media(max-width:599px) { dl.cn-definitions { grid-template-columns:minmax(0,1fr); gap:0; } dl.cn-definitions dd { margin-bottom:8px; } }
@layer overrides { @media (forced-colors: active) { .cn-chip { border:1px solid; }
  .cn-group-button[aria-pressed=true] { forced-color-adjust:none; background:Highlight; color:HighlightText; } .cn-data-table mark { background:Mark; color:MarkText; } } }
'''

# The scroll hint is shown only while a table's box overflows sideways: the block gets data-cn-overflow.
TABLE_JS = '''(() => {
  if (window.cnTables) return;
  const watched = new Set();  // the boxes on the page that the size observer watches; a box that left is let go
  const check = (box) => {
    const block = box.closest('[data-cn-table]');
    if (block) block.toggleAttribute('data-cn-overflow', box.scrollWidth > box.clientWidth + 1);
  };
  // The header row follows only when something that moves it changed: a scroll, a resize of the window, a new table, or
  // a table or its box changing size (rows patched in or out, a page, a filter, a column's width). A poll that changes
  // nothing of a table, or anything outside every table, costs the tables nothing (``stats.follows`` counts the runs).
  const stats = {follows: 0, watched: 0};
  let frame = 0;
  const later = () => { if (!frame) frame = requestAnimationFrame(() => { frame = 0; follow(); }); };
  const sizes = new ResizeObserver((entries) => {
    for (const entry of entries) {
      const box = entry.target.closest('.cn-table-scroll');
      if (box) check(box);
    }
    later();
  });
  const scan = () => {
    for (const box of watched) {
      if (box.isConnected) continue;
      sizes.unobserve(box);
      if (box.cnWatchedTable) sizes.unobserve(box.cnWatchedTable);
      watched.delete(box);
    }
    for (const box of document.querySelectorAll('.cn-table-scroll')) {
      if (watched.has(box)) continue;
      watched.add(box);
      sizes.observe(box);
      const table = box.querySelector('table');
      if (table) { sizes.observe(table); box.cnWatchedTable = table; }
      check(box);
      later();
    }
    stats.watched = watched.size;
  };
  // The header row of a table whose top has left the window is drawn under the sticky toolbar (or at the top of the
  // window), never past the table's last row. It is the table's own row moved by a transform, so its cells keep the
  // columns of the rows whatever their widths. It goes one pixel under the toolbar (which is opaque and above it): a
  // gap of a fraction of a pixel would show the rows passing by.
  const follow = () => {
    stats.follows++;
    for (const box of document.querySelectorAll('.cn-table-scroll')) {
      const head = box.querySelector('thead');
      if (!head) continue;
      const tools = box.closest('[data-cn-table]')?.querySelector('.cn-table-tools');
      let line = 0;
      if (tools && getComputedStyle(tools).position === 'sticky') {
        const bar = tools.getBoundingClientRect();
        if (bar.top <= 1 && bar.bottom > 0) line = bar.bottom;
      }
      const area = box.getBoundingClientRect();
      const wanted = line - (area.top + box.clientTop);  // the header's own place is inside the box's border
      const room = Math.max(0, Math.floor(area.height - 2 * head.offsetHeight));
      const shift = wanted > 1 ? Math.min(Math.ceil(wanted) - 1, room) : 0;
      const value = shift + 'px';
      if (box.style.getPropertyValue('--cn-head-shift') !== value) {
        box.style.setProperty('--cn-head-shift', value);
        box.toggleAttribute('data-cn-head-stuck', shift > 0);
      }
    }
  };
  window.addEventListener('scroll', later, {passive: true, capture: true});
  window.addEventListener('resize', later, {passive: true});
  // Only a table arriving or leaving (a redraw, a tool left inside the root) is of interest to the observer: rows patched
  // inside a table are seen by the size observer.
  const holds = (node) => node.nodeType === 1 && (node.matches('.cn-table-scroll') || node.querySelector('.cn-table-scroll'));
  new MutationObserver((records) => {
    for (const record of records) {
      if (record.target.closest?.('.cn-table-scroll')) continue;
      for (const node of record.addedNodes) if (holds(node)) { scan(); return; }
      for (const node of record.removedNodes) if (holds(node)) { scan(); return; }
    }
  }).observe(document.documentElement, {childList: true, subtree: true});
  document.addEventListener('DOMContentLoaded', scan);
  scan();
  // A sort, the filter or a group: the page goes back to the table's header when it is above the window.
  const toHeader = (id) => {
    const box = document.getElementById(id);
    const tools = box?.closest('[data-cn-table]')?.querySelector('.cn-table-tools');
    if (!box) return;
    const stuck = tools && getComputedStyle(tools).position === 'sticky' ? tools.offsetHeight : 0;
    const top = box.getBoundingClientRect().top;
    if (top < stuck) window.scrollBy(0, top - stuck);
  };
  window.cnTables = {scan, follow, toHeader, stats};
})();'''

_ROW_CLICK = "(event) => { const button = event.target.closest('[data-row-action]'); if (button) emit(button.dataset.rowAction); }"
PAGE_BUTTONS = (('first', 'First', 'First page'), ('previous', 'Previous', 'Previous page'),
                ('next', 'Next', 'Next page'), ('last', 'Last', 'Last page'))


def apply_table_assets():
    """Add the tables' stylesheet and script to the page, once per page. A page calls it while it is built;
    ``cn_table`` calls it too, so a table drawn later (by a poll) still gets both: the script is then run in the
    connected page, because markup added to a loaded document's head does not run."""
    from nicegui import ui

    from .scope import add_once

    add_once(ui.context.client, 'tables', css=TABLE_CSS, script=TABLE_JS)


def cn_definition_list(row, *, label: str = '', labels: Mapping[str, str] | None = None):
    """A section of one row as a definition list: a term and a value for each value it has, no table chrome."""
    from nicegui import ui

    apply_table_assets()
    if not label:
        return ui.html(definition_html(row, labels), sanitize=False, tag='dl').classes('cn-definitions')
    # An aria-label on a dl is ignored by screen readers: the name is on a group around it.
    with ui.element('div').props('role=group') as group:
        group._props['aria-label'] = label
        element = ui.html(definition_html(row, labels), sanitize=False, tag='dl').classes('cn-definitions')
    return element


def filter_input(label: str, name: str, value: str, on_change):
    """The quick filter's field (inside ``[data-cn-filter]``): visible label "Filter", named "Filter <label>", the text
    sent 200 ms after the last key. Returns ``(box, field)``. ``cn_table`` draws one; a list that is not a ``cn_table``
    (the Monitor's History lists) draws the same field with it."""
    from nicegui import ui

    with ui.element('div').props('data-cn-filter').classes('cn-table-filter') as box:
        field_ = ui.input('Filter', value=value, on_change=on_change).props(
            f'outlined dense debounce=200 maxlength={MAX_QUERY}')
        field_._props['aria-label'] = f'Filter {label}'
        field_._props['data-table-filter'] = name
    return box, field_


class PageFooter:
    """The one footer: a ``nav`` named "<label> pages" with a native **Rows per page** select, the range and First /
    Previous / Next / Last (``aria-disabled`` when they cannot act). ``on_size(value)`` gets the chosen size and
    ``on_go(where)`` one of 'first', 'previous', 'next', 'last'. ``cn_table`` draws one; a list that is not a
    ``cn_table`` (the Monitor's History lists) draws the same footer and calls ``show``."""

    def __init__(self, label: str, *, on_size, on_go, sizes: Sequence = PAGE_SIZES):
        from nicegui import ui

        self.buttons = {}
        with ui.element('nav').classes('cn-table-footer') as self.element:
            self.element._props['aria-label'] = f'{label} pages'
            with ui.element('label'):
                ui.element('span')._text = 'Rows per page'
                with ui.element('select').props('aria-label="Rows per page" data-table-size') as self.select:
                    for value, text in table_export.page_size_options().items():
                        if value in sizes:
                            ui.element('option').props(f'value={value}')._text = text
                self.select.on('change', lambda event: _call(on_size, event.args),
                               js_handler='(event) => emit(event.target.value)')
            self.range = ui.label('').classes('cn-table-range')
            with ui.element('div').classes('cn-table-pages'):
                for key, text, name in PAGE_BUTTONS:
                    button = ui.element('button').props('type=button').classes('cn-page-button')
                    button._text = text
                    button._props['aria-label'] = name
                    button._props['data-table-page'] = key
                    button.on('click', lambda _, key=key: _call(on_go, key))
                    self.buttons[key] = button

    def show(self, page: Page, state: TableState, *, seekable: bool = False):
        """Say what ``page`` is: its range, the size chosen, and which buttons can act."""
        if str(self.select._props.get('value')) != str(state.size):
            self.select._props['value'] = str(state.size)
            self.select.update()
        self.range.set_text(range_text(page))
        can = {'first': state.page > 0, 'previous': state.page > 0, 'next': page.next is not None,
               'last': seekable and page.total is not None and state.page < last_page(page.total, state.size)}
        for key, button in self.buttons.items():
            disabled = 'false' if can[key] else 'true'
            if button._props.get('aria-disabled') != disabled:
                button._props['aria-disabled'] = disabled
                button.update()
        self.buttons['last'].set_visibility(seekable and page.total is not None)


def size_choice(value):
    """The rows per page a footer's select sent, or None for a value that is not one."""
    size = ALL if value == ALL else int(value) if str(value).isdigit() else None
    return size if size in PAGE_SIZES else None


_BODY = []


def _rows_body():
    """The ``tbody``: a ``ui.html`` whose component (``table_body.js``) replaces only the rows whose markup changed, so
    a row that stays keeps its element (a selection or the focus in it survives a redraw of the rows around it)."""
    if not _BODY:
        from nicegui import ui

        class RowsBody(ui.html, component='table_body.js'):
            pass
        _BODY.append(RowsBody)
    return _BODY[0]('', sanitize=False, tag='tbody')


async def _call(function, *arguments):
    result = function(*arguments)
    if inspect.isawaitable(result):
        await result


class TableHandle:
    """One table on the page. ``state`` is the page's own object; ``page`` is what is on screen; ``region`` is the
    scroll box (None for a ``RowsSource`` without rows, which is one line of text)."""

    def __init__(self, *, name, label, columns, source, state, on_change, groups, row_action, empty, note='',
                 grouping=None, intro=None, export_extra=()):
        self.name, self.label, self.source, self.state = name, label, source, state
        self.note, self.grouping, self.intro = note, grouping, intro
        self.export_extra = list(export_extra)   # columns only the file has (``cn_table(export_extra=)``)
        self.columns = list(columns)
        self.groups = list(groups)
        self.row_action = row_action
        self.empty = empty
        self.on_change = on_change
        self.page = None
        self.region = None
        self._host = None  # a RowsSource's table is drawn again inside it when its columns or its emptiness change
        self.export_controls = None
        self.send_group = None
        self._seekable = bool(getattr(source, 'seekable', False))
        self._requests = 0
        self._headers = {}
        self._group_buttons = {}
        self._moving = False  # a First / Previous / Next / Last is on its way
        self._client = None
        self._filter = self._match = None
        self._send, self._export_wanted, self._link = False, True, False

    @property
    def _cursors(self) -> list:
        return self.state.cursors

    @_cursors.setter
    def _cursors(self, value: list) -> None:
        self.state.cursors = value

    # --- reading -------------------------------------------------------------------------------------------------

    def row(self, index):
        """The row of ``tr[data-row=index]`` on the page shown, or None."""
        rows = self.page.rows if self.page is not None else []
        return rows[index] if isinstance(index, int) and 0 <= index < len(rows) else None

    async def refresh(self):
        """Read the source again and draw: after its rows or the state changed. The newest request wins. A
        ``RowsSource`` whose rows came, went or changed which columns have a value is drawn again as a whole."""
        await self._refresh()

    async def _refresh(self) -> bool:
        """``refresh``; False when the source could not give its rows (``TableUnavailable``) and nothing newer did."""
        if self._sync_source():
            return True
        self._requests += 1
        request = self._requests
        normalise(self.state, self.columns, self.groups)
        if not self._seekable:
            self.state.page = len(self._cursors) - 1
        try:
            page = await self.source.fetch(self.state, None if self._seekable else self._cursors[-1])
            if not self._seekable and self._cursors[-1] is not None and not page.rows and page.total:
                # A cursor the result no longer has (it changed since the state was kept): the first page.
                self._cursors, self.state.page = [None], 0
                page = await self.source.fetch(self.state, None)
        except TableUnavailable as problem:
            if request == self._requests and self._alive():
                self._match.set_text(str(problem))
                return False
            return True
        if request == self._requests and self._alive():
            self._draw(page)
        return True

    def _sync_source(self) -> bool:
        """A ``RowsSource`` with other rows: the table appears, goes, or is drawn again when the columns that hold a
        value are not the ones on the screen. True when it drew the table itself."""
        source = self.source
        if not isinstance(source, RowsSource) or source.columns is None or self._host is None or self._host.is_deleted:
            return False
        source._sync()
        columns = source.drawn_columns() if source.rows else []
        if not source.rows and self.region is None:
            return False
        if source.rows and self.region is not None and [c.key for c in columns] == [c.key for c in self.columns]:
            return False
        from nicegui import ui

        self.columns = columns
        self.page = self.region = self.export_controls = self.send_group = None
        self._headers, self._group_buttons, self._cursors = {}, {}, [None]
        normalise(self.state, self.columns, self.groups)
        self._host.clear()
        with self._host:
            if source.rows:
                self._build(source.page(self.state))
            else:
                ui.label(self.empty).classes('cn-muted')
        return True

    async def apply(self, **changes):
        """Set fields of the state from outside (the URL of R2-08), validated, and draw. ``on_change`` is not called."""
        for key, value in changes.items():
            if key in TableState.__dataclass_fields__:
                setattr(self.state, key, value)
        if not self._seekable:
            self._cursors = [None]
        normalise(self.state, self.columns, self.groups)
        if self._filter is not None and (self._filter.value or '') != self.state.query:
            self._filter.set_value(self.state.query)
        await self.refresh()

    def _alive(self):
        return self._client is not None and not self._client.is_deleted and self.region is not None and not self.region.is_deleted

    # --- the user's changes --------------------------------------------------------------------------------------

    async def _changed(self, *, first_page=True, to_header=False):
        if first_page:
            self.state.page = 0
            self._cursors = [None]
        if not await self._refresh():
            return False
        if self._alive() and to_header:
            # The page scrolls, not the table (R2-05): a sort, the filter or a group brings the header back into the
            # window; a move from the footer keeps the scroll, so the footer stays under the pointer and the focus.
            self._client.run_javascript(f'window.cnTables?.toHeader({json.dumps(self.region.html_id)})')
        if self.on_change is not None:
            await _call(self.on_change, self.state)
        return True

    async def _filter_changed(self, event):
        value = event.value if isinstance(event.value, str) else ''
        if len(value) > MAX_QUERY:  # the field's maxlength was bypassed: the table stays as it is
            self._match.set_text(TOO_LONG)
            return
        if value == self.state.query:
            return
        self.state.query = value
        await self._changed(to_header=True)

    async def _sort(self, key):
        self.state.descending = not self.state.descending if self.state.sort == key else False
        self.state.sort = key
        await self._changed(to_header=True)

    async def _group(self, key):
        if key == self.state.group:
            return
        self.state.group = key
        await self._changed(to_header=True)

    async def _size(self, value):
        size = size_choice(value)
        if size is None or size == self.state.size:
            return
        self.state.size = size
        await self._changed()

    async def _go(self, where):
        page, state = self.page, self.state
        if page is None or self._moving:  # a second click while a page comes would step from the page left behind
            return
        self._moving = True
        try:
            await self._move(where, page, state)
        finally:
            self._moving = False

    async def _move(self, where, page, state):
        before = (state.page, list(self._cursors))
        if where == 'first' and state.page > 0:
            state.page, self._cursors = 0, [None]
        elif where == 'previous' and state.page > 0:
            state.page -= 1
            self._cursors = self._cursors[:-1] or [None]
        elif where == 'next' and page.next is not None:
            state.page += 1
            self._cursors.append(page.next)
        elif where == 'last' and self._seekable and page.total is not None and state.page < last_page(page.total, state.size):
            state.page = last_page(page.total, state.size)
        else:
            return  # the button cannot act now (it is aria-disabled, not disabled: the focus stays on it)
        if not await self._changed(first_page=False):
            state.page, self._cursors = before  # the page could not be read: the state stays on the page that is shown

    async def _row_clicked(self, event):
        if self.row_action is not None and isinstance(event.args, str) and any(
                str(row.get(self.row_action.id_key)) == event.args for row in (self.page.rows if self.page else [])):
            await _call(self.row_action.on_click, event.args)

    # --- export and send -----------------------------------------------------------------------------------------

    async def _export(self, copy):
        """Download table (CSV) or Copy table: every row of the table as it is arranged at the click (a change made
        while the rows are read does not change the file). A source that can be stopped (``cancel_walk``) gets a
        Cancel button meanwhile, and one with ``on_progress`` is given the status line's writer for its progress."""
        from . import table_actions

        controls = self.export_controls
        if table_actions.is_busy(controls):
            return
        table_actions.set_busy(controls, True)
        status = controls['status'].set_text
        cancelled = (lambda: bool(getattr(self.source, 'walk_cancelled', False)))
        try:
            known = self.page.total if self.page is not None else None
            refusal = table_actions.copy_refusal(known) if copy and known is not None else ''
            if refusal:  # the table says how many rows it has: too many to copy is known before one is read
                status(refusal)
                return
            if hasattr(self.source, 'on_progress'):
                self.source.on_progress = status
            try:
                rows = await self.source.all_rows(replace(self.state))
            except TableUnavailable as problem:
                status(CANCELLED[copy] if cancelled() else str(problem))
                return
            refusal = table_actions.copy_refusal(len(rows)) if copy else ''
            if refusal:
                status(refusal)
                return
            # Built on a thread: a table of a million rows would hold every tab's poll for seconds.
            try:
                labels, data = await asyncio.to_thread(export_records, [*self.columns, *self.export_extra], rows)
                text = await asyncio.to_thread(table_export.tsv_text if copy else table_export.csv_bytes, labels, data)
            except Exception:
                status(table_actions.EXPORT_FAILED)  # the buttons are freed by the ``finally``
                return
            if cancelled() or self._client is None or self._client.is_deleted:
                status(CANCELLED[copy] if cancelled() else '')
                return
            if copy:
                copied, message = await table_actions.write_clipboard(self._client, text, len(data))
                if copied and self.note:
                    message = f'{message} {self.note}'
            else:
                with self._client:
                    table_actions.offer_csv(text, table_export.export_filename(self.name, datetime.now()))
                message = table_actions.done_text(len(data), note=self.note)
            status(message)
        finally:
            table_actions.set_busy(controls, False)

    async def _copy_link(self):
        """Copy view link (R2-08): the tab's address, which arranges this table; said in the export's status line."""
        from .view_state import copy_link
        if self._client is not None and self.export_controls is not None:
            await copy_link(self._client, self.export_controls['status'])

    # --- drawing -------------------------------------------------------------------------------------------------

    def _build(self, first):
        """Draw the table's elements once. ``first`` is the first page of a ``RowsSource`` (None: it is fetched)."""
        from nicegui import ui
        from . import send_targets, table_actions

        apply_table_assets()
        self._client = ui.context.client
        state = self.state
        with ui.element('div').classes('cn-table-block') as block:
            block._props['data-cn-table'] = self.name
            self._intro = ui.label('').classes('cn-muted cn-table-intro') if self.intro is not None else None
            with ui.element('div').classes('cn-table-tools') as self._tools:
                if self.groups:
                    with ui.element('div').props('role=group').classes('cn-table-groups') as box:
                        box._props['aria-label'] = f'{self.label} groups'
                        for group in (Group('all', 'All'), *self.groups):
                            # A native button, as the sort and page buttons: a Quasar button moves the focus to a
                            # helper span inside it after a mouse click, so the keyboard went on from the wrong place.
                            button = ui.element('button').props('type=button').classes('cn-group-button')
                            button._text = group.label
                            button._props['data-table-group'] = group.key
                            button.on('click', lambda _, key=group.key: self._group(key))
                            self._group_buttons[group.key] = (button, group.label)
                self._filter_box, self._filter = filter_input(self.label, self.name, state.query, self._filter_changed)
                # What the filter left ("12 of 340 rows"), or why the table cannot be read: beside the filter, and
                # there when the filter is not.
                self._match = ui.label('').props('role=status').classes('cn-muted cn-table-match')
                target = send_targets.target_column([column.key for column in self.columns]) if self._send else None
                if target and hasattr(self.source, 'filtered'):
                    self._target = target
                    self.send_group = send_targets.render_send_group(
                        [], target, name=self.name, source=self._send if isinstance(self._send, str) else None)
                if self._export_wanted:
                    cancel = getattr(self.source, 'cancel_walk', None)
                    self.export_controls = table_actions.render_export_group(
                        name=self.name, on_download=lambda: self._export(False), on_copy=lambda: self._export(True),
                        on_cancel=cancel, on_link=self._copy_link if self._link else None)
            with ui.element('div').classes('cn-table-scroll').props('role=region tabindex=0') as self.region:
                self.region._props['aria-label'] = self.label
                with ui.element('table').classes('cn-data-table'):
                    with ui.element('thead'), ui.element('tr'):
                        for column in self.columns:
                            with ui.element('th').props('scope=col').classes('cn-td-sticky' if column.sticky else '') as header:
                                header._props['data-col'] = column.key
                                header._props['id'] = header_id(self.name, column.key)
                                if column.kind == 'action' or not column.sortable:
                                    ui.element('span')._text = column.heading
                                    continue
                                with ui.element('button').props('type=button').classes('cn-sort-button') as button:
                                    button._props['data-sort-key'] = column.key
                                    ui.element('span')._text = column.heading
                                    arrow = ui.element('span').props('aria-hidden=true')
                                button.on('click', lambda _, key=column.key: self._sort(key))
                                self._headers[column.key] = (header, button, arrow, column.heading)
                    self._body = _rows_body()
            self.region.on('click', self._row_clicked, js_handler=_ROW_CLICK)
            ui.label(SCROLL_HINT).classes('cn-muted text-sm cn-table-hint')
            self._pager = PageFooter(self.label, on_size=self._size, on_go=self._go)
            self._footer = self._pager.element
        if first is not None:
            self._draw(first)
        else:
            self._chrome(None)
            ui.timer(0, self.refresh, once=True)

    def _chrome(self, page):
        """What the table's size decides: the filter from ``FILTER_MIN_ROWS`` rows, the footer when the rows do not fit
        the smallest page. Judged on the rows before the filter, so neither comes or goes while the user types."""
        size = None if page is None else page.unfiltered if page.unfiltered is not None else page.total
        many = size is None and page is not None  # a source that cannot count is taken to be long
        self._filter_box.set_visibility(bool(self.state.query) or many or (size or 0) >= FILTER_MIN_ROWS)
        self._footer.set_visibility(many or (size or 0) > min(value for value in PAGE_SIZES if value != ALL)
                                    or (page is not None and (page.next is not None or self.state.page > 0)))

    def _draw(self, page):
        from . import table_actions

        state = self.state
        self.page = page
        if self._seekable:  # the source clamped the page
            if page.rows:
                state.page = page.offset // page_limit(state.size)
            elif page.total is not None:
                state.page = min(state.page, last_page(page.total, state.size))
        self._chrome(page)
        filtered = bool(state.query.strip()) or state.group != 'all'
        grouping = self.grouping if self.grouping is not None and (
            self.grouping.when is None or self.grouping.when(state)) else None
        self._body.set_content(body_html(self.columns, page.rows, self.row_action,
                                         empty=NO_MATCH if filtered else self.empty, grouping=grouping,
                                         prefix=self.name))
        if self._intro is not None:
            self._intro.set_text(self.intro(page))
        self._match.set_text(match_text(page, state))
        for key, (header, button, arrow, heading) in self._headers.items():
            direction = ('descending' if state.descending else 'ascending') if state.sort == key else ''
            if header._props.get('aria-sort', '') != direction:
                if direction:
                    header._props['aria-sort'] = direction
                else:
                    header._props.pop('aria-sort', None)
                header.update()
                button._props['aria-label'] = heading + (f', sorted {direction}' if direction else '')
                button.update()
                arrow._text = '' if not direction else ' ▲' if direction == 'ascending' else ' ▼'
                arrow.update()
            elif 'aria-label' not in button._props:
                button._props['aria-label'] = heading
        for key, (button, label) in self._group_buttons.items():
            count = page.counts.get(key)
            text = label if count is None else f'{label} ({fmt_count(count)})'
            pressed = 'true' if state.group == key else 'false'
            if button._props.get('aria-pressed') != pressed or button._text != text:
                button._props['aria-pressed'] = pressed
                button._text = text
                button.update()
        self._pager.show(page, state, seekable=self._seekable)
        if self.export_controls is not None and page.total is not None:
            description = table_actions.scope_description(page.total)
            for key in ('download', 'copy'):
                button = self.export_controls[key]
                if button._props.get('aria-description') != description:
                    button._props['aria-description'] = description
                    button.update()
        if self.send_group is not None:
            self.send_group.update(self.source.filtered(state))
        from .view_state import table_drawn
        table_drawn(self._client)  # the URL says what is drawn: a page clamped, or one not reached (R2-08)


def cn_table(*, name: str, label: str, columns: Sequence[Column], source, state: TableState,
             on_change: Callable[[TableState], Any] | None = None, groups: Sequence[Group] = (),
             send: bool | str = False, export: bool = True, row_action: RowAction | None = None,
             empty: str = 'No rows.', note: str = '', grouping: RowGroup | None = None,
             intro: Callable[[Page], str] | None = None, export_extra: Sequence[Column] = (),
             link: bool = False) -> TableHandle:
    """
    Draw one table here and return its handle.

    ``name`` marks the table's controls and is unique on the page (``[data-cn-table=<name>]``; the export's file is
    ``cn-<name>-<stamp>.csv``); ``label`` names it to the user (the region, "Filter <label>", "<label> pages").
    ``state`` is the page's own ``TableState``: the table changes it and then calls ``on_change(state)``. ``send``
    draws Ping these / Monitor these over the rows as filtered when a column holds targets (True: the origin is
    ``lookup_inputs.SOURCES[name]``; a string: the origin itself); it needs a ``RowsSource``. ``row_action`` is the
    button of the column of kind 'action'. A ``RowsSource`` without rows is the one line ``empty``. ``note`` is
    appended to what an export says it did ("Downloaded 5 rows. Ping was stopped: ..."). ``grouping`` puts a header
    row before each run of rows (``RowGroup``); ``intro(page)`` is a line above the table, from the page on screen.
    ``export_extra`` are columns that only the downloaded and copied table have (after the drawn ones): a value the
    screen says once, as a line above the table, that the file keeps for each row. ``link`` adds Copy view link to
    the export group, for a table whose arrangement the URL carries (``view_state``, R2-08).
    """
    from nicegui import ui

    rows_source = isinstance(source, RowsSource)
    if row_action is None:
        columns = [column for column in columns if column.kind != 'action']
    if rows_source:
        source.columns = list(columns)
        columns = source.drawn_columns()
    handle = TableHandle(name=name, label=label, columns=columns, source=source, state=state, on_change=on_change,
                         groups=groups, row_action=row_action, empty=empty, note=note, grouping=grouping, intro=intro,
                         export_extra=export_extra)
    handle._send, handle._export_wanted, handle._link = send, export, link
    normalise(state, handle.columns, handle.groups)
    if rows_source:
        source._sync()  # the columns the filter reads
        # The host is where the table is drawn again when the rows come, go or change the columns (display: contents).
        with ui.element('div').classes('cn-table-host') as handle._host:
            handle._client = ui.context.client
            if source.rows:
                handle._build(source.page(state))
            else:
                ui.label(empty).classes('cn-muted')
        return handle
    handle._build(None)
    return handle
