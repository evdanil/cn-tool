"""The Monitor page's Map view: the command line's live grid as text in the page, one character per host.

Three parts, all without NiceGUI. The worker calls ``snapshot`` on the run thread after each complete round (plain
values copied out of the tracker), then ``map_payload`` and ``host_payload`` to answer the page. The page calls
``render`` to lay the payload out with ``cn_tool.utils.ping_grid`` (the layout the command line draws, so the two
cannot drift) and to turn each line into one HTML row, ``diff`` to find the rows a new round changed, and
``host_lines`` for the popup. ``CSS`` and ``SCRIPT`` are the browser's side: no element per cell, the cell under the
pointer is found from the character geometry, and there is one popup and one keyboard cursor for the whole map.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from html import escape
from typing import Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

from cn_tool.utils import ping_grid

CAP_CELLS = 65536  # one /16: the grid is drawn while the subnet blocks together hold no more cells
CAP_NAMES = 2048  # and the Hosts block no more names
MAX_COLS = 400
_UNBOUNDED = 10 ** 9
_PLAIN = {'text': '', 'label': 'm-lab', 'header': 'm-hd'}

# Every character of the grid in words, for the popup; the legend's own words where it has them.
STATE_WORDS: Dict[str, str] = {**ping_grid.LEGEND, ' ': 'not probed yet'}
NOT_A_HOST = 'not a host of this run (network, broadcast or skipped address)'


@dataclass(frozen=True)
class Snapshot:
    """One complete round as the map needs it: plain values, nothing that follows the tracker."""

    blocks: Tuple[ping_grid.Block, ...]
    cells: str  # one character per host
    changed: FrozenSet[int]
    partial: FrozenSet[int]
    hosts: Tuple[str, ...]
    seen: Mapping[int, Tuple[float, float, float, int]]  # host -> first seen, last seen, since, rounds answered
    rounds: int
    summary: str


def snapshot(blocks: Sequence[ping_grid.Block], tracker) -> Snapshot:
    """Copy what the map shows out of ``tracker``. Call it on the thread that feeds the tracker."""
    cells = ''.join(tracker.cells())
    summaries = tracker.summaries()
    seen = {item.index: (item.first_seen, item.last_seen,
                         item.periods[-1][0] if item.ongoing and item.periods else item.last_seen, item.seen_rounds)
            for item in summaries}
    counts = Counter(cells)
    numbers = [f'{counts[char]:,} {word}' for char, word in ping_grid.COUNT_WORDS if counts.get(char)]
    numbers.append(f'{len(summaries):,} seen of {len(cells):,}')
    return Snapshot(tuple(blocks), cells, frozenset(tracker.changed()), frozenset(tracker.partial()),
                    tuple(tracker.hosts), seen, tracker.rounds, ' · '.join(numbers))


def _size(block: ping_grid.Block) -> int:
    return len(block.cells) if block.network is not None else len(block.names)


def _drawable(block: ping_grid.Block) -> bool:
    return _size(block) <= (CAP_CELLS if block.network is not None else CAP_NAMES)


def map_payload(snap: Snapshot, show: int = -1) -> dict:
    """What the page draws: each block's characters and marks, or its counter line when the map is over the cap
    (then block ``show`` alone is drawn, if it is one that can be)."""
    everything = sum(len(block.cells) for block in snap.blocks if block.network is not None) <= CAP_CELLS
    blocks: List[dict] = []
    for number, block in enumerate(snap.blocks):
        if not _drawable(block) or not (everything or number == show):
            text = ''.join(part for part, _ in ping_grid.compact_lines([block], snap.cells)[0])
            blocks.append(dict(kind='compact', title=block.title, text=text, can_show=_drawable(block)))
            continue
        hosts = block.cells if block.network is not None else [host for _, host in block.names]
        marks = dict(chars=''.join(' ' if host is None else snap.cells[host] for host in hosts),
                     changed=[at for at, host in enumerate(hosts) if host in snap.changed],
                     partial=[at for at, host in enumerate(hosts) if host in snap.partial])
        if block.network is not None:
            blocks.append(dict(kind='subnet', title=block.title, network=str(block.network), **marks))
        else:
            blocks.append(dict(kind='hosts', title=block.title, names=[label for label, _ in block.names], **marks))
    return dict(summary=snap.summary, hosts=len(snap.hosts), blocks=blocks)


def host_payload(snap: Snapshot, rows: Mapping[str, tuple], block: int, cell: int) -> Optional[dict]:
    """What is known of the host at ``cell`` of ``block`` (``rows``: the round's row by host), or ``None`` when there
    is no such cell. An address that is no host of the run answers with ``host`` false."""
    if not 0 <= block < len(snap.blocks):
        return None
    drawn = snap.blocks[block]
    if not 0 <= cell < _size(drawn):
        return None
    if drawn.network is not None:
        index, target = drawn.cells[cell], str(drawn.network[cell])
    else:
        target, index = drawn.names[cell]
    answer = dict(host=index is not None, target=target, address='', char=' ', result='', tcp=[], first_seen=None,
                  last_seen=None, since=None, seen_rounds=0, rounds=snap.rounds, changed=False, partial=False)
    if index is None:
        return answer
    row = rows.get(snap.hosts[index])
    if row is not None:
        answer.update(address=row[1], result=row[2], tcp=[dict(port=port, result=text) for port, text in row[3]])
    answer.update(char=snap.cells[index], changed=index in snap.changed, partial=index in snap.partial)
    if index in snap.seen:
        first, last, since, answered = snap.seen[index]
        answer.update(first_seen=first, last_seen=last, since=since, seen_rounds=answered)
    return answer


def _time(value) -> str:
    from datetime import datetime, timezone
    if value is None:
        return 'never'
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (OverflowError, OSError, ValueError):
        return 'Unknown'


def host_lines(host: Mapping[str, object]) -> List[List[str]]:
    """The popup's ``[label, value]`` lines for one ``host_payload`` answer."""
    lines = [['Target', str(host['target'])]]
    if not host['host']:
        return lines + [['State', NOT_A_HOST]]
    if host['address'] and host['address'] != host['target']:
        lines.append(['Address', str(host['address'])])
    char = str(host['char'])
    state = (f'{char} ' if char.strip() else '') + STATE_WORDS.get(char, 'unknown')
    if host['partial'] and char == '!':
        state += ', partial reply'
    if host['changed']:
        state += ', changed in the last round'
    lines.append(['State', state])
    if host['result']:
        lines.append(['Latest round', str(host['result'])])
    if host['tcp']:
        lines.append(['TCP', ', '.join(f"{item['port']}: {item['result']}" for item in host['tcp'])])
    lines += [['Last seen', _time(host['last_seen'])], ['First seen', _time(host['first_seen'])],
              ['Answered', f"{host['seen_rounds']:,} of {host['rounds']:,} rounds"]]
    if host['since'] is not None:
        lines.append(['Gone since' if char == ping_grid.CHARS[3] else 'Seen since', _time(host['since'])])
    return lines


# --- the page's side: payload -> rows of HTML -------------------------------------------------------------

def _classes(style: str, text: str) -> str:
    names = ['m-' + style.split()[0]]
    if style.startswith('warning') and text == '!':
        names.append('m-part')
    if style.endswith(' reverse'):
        names.append('m-rev')
    return ' '.join(names)


def _cell_runs(text: str, style: str) -> List[str]:
    """A segment of cells as spans; a partial reply (``!`` in the warning colour) is its own span, underlined."""
    if not style.startswith('warning') or '!' not in text or set(text) == {'!'}:
        return [f'<span class="{_classes(style, text[0])}">{escape(text)}</span>']
    runs: List[str] = []
    for char in text:
        if runs and runs[-1][0] == (char == '!'):
            runs[-1][1] += char
        else:
            runs.append([char == '!', char])
    return [f'<span class="{_classes(style, part[0])}">{escape(part)}</span>' for _, part in runs]


def _row_html(line: ping_grid.Line) -> str:
    parts: List[str] = []
    for text, style in line:
        if style in _PLAIN:
            name = _PLAIN[style]
            parts.append(f'<span class="{name}">{escape(text)}</span>' if name else escape(text))
        else:
            parts += _cell_runs(text, style)
    return ''.join(parts)


def _hosts_row_html(line: ping_grid.Line, first: int) -> Tuple[str, int]:
    """A line of the Hosts block: every state character is its own span, numbered in the block's order."""
    parts: List[str] = []
    for text, style in line:
        if style in _PLAIN:
            name = _PLAIN[style]
            parts.append(f'<span class="{name}">{escape(text)}</span>' if name else escape(text))
        else:
            parts.append(f'<span class="c {_classes(style, text)}" data-i="{first}">{escape(text)}</span>')
            first += 1
    return ''.join(parts), first


def _address_data(network) -> str:
    """What the browser needs to spell the address of a cell without asking: the IPv4 base, or the shared stem of an
    IPv6 network whose addresses differ in the last hextet only (``ping_grid`` spells those the same way)."""
    first = int(network.network_address)
    if network.version == 4:
        return f' data-ip4="{first}"'
    if network.prefixlen < 112 or first >> 32 == 0xFFFF:
        return ''
    stem = str(type(network.network_address)((first & ~0xFFFF) | 1))[:-1]
    return f' data-ip6="{escape(stem)}" data-ip6first="{escape(str(network.network_address))}" data-ip6low="{first & 0xFFFF}"'


def render(payload: Mapping[str, object], cols: int) -> dict:
    """``payload`` laid out for a box ``cols`` characters wide: per block its opening tag, its rows as
    ``(id, attributes, inner HTML)`` and what follows them. A box too narrow for the smallest row, or for a name of
    the Hosts block, gets the narrowest layout that fits them (``width``): the box scrolls sideways."""
    from ipaddress import ip_network
    blocks, chars = [], []
    changed, partial = set(), set()
    for item in payload['blocks']:
        if item['kind'] == 'compact':
            blocks.append(None)
            continue
        offset, count = len(chars), len(item['chars'])
        chars.extend(item['chars'])
        changed.update(offset + at for at in item['changed'])
        partial.update(offset + at for at in item['partial'])
        if item['kind'] == 'subnet':
            blocks.append(ping_grid.Block(item['title'], ip_network(item['network']),
                                          cells=tuple(range(offset, offset + count))))
        else:
            blocks.append(ping_grid.Block(item['title'], None,
                                          names=tuple((name, offset + at) for at, name in enumerate(item['names']))))
    drawn = [block for block in blocks if block is not None]
    width = max(1, min(int(cols), MAX_COLS))
    pair = max((len(name) + 2 for block in drawn for name, _ in block.names), default=0)
    size, label_width = ping_grid.ROW_SIZES[0], 0
    for _ in range(len(ping_grid.ROW_SIZES) + 2):
        layout = ping_grid.row_layout(drawn, width)
        if layout is None:  # too narrow for the smallest row
            label_width = ping_grid.row_layout(drawn, _UNBOUNDED)[1]
            width = label_width + 1 + ping_grid.ROW_SIZES[-1] + ping_grid.ROW_SIZES[-1] // ping_grid.GROUP - 1
            continue
        size, label_width = layout
        if pair and label_width + 1 + pair > width:
            width = label_width + 1 + pair
            continue
        break
    lines = ping_grid.grid_lines(drawn, chars, width=width, height=_UNBOUNDED, changed=changed, partial=partial)
    if lines is None:
        raise ValueError('The map cannot be laid out')
    out, at = [], 0
    for number, (item, block) in enumerate(zip(payload['blocks'], blocks)):
        head = f'<div class="b" data-b="{number}" data-kind="{item["kind"]}"'
        if block is None:
            button = (f'<button type="button" class="cn-map-show" data-show="{number}">Show this block'
                      f'<span class="cn-map-sr"> {escape(str(item["title"]))}</span></button>' if item['can_show'] else '')
            out.append(dict(open=head + '>', rows=[(f'cnm-{number}-0', '', escape(str(item['text'])))], tail=button))
            continue
        if at and not lines[at]:
            at += 1  # the blank line between two blocks
        rows: List[Tuple[str, str, str]] = []
        if block.network is not None:
            count = len(block.cells)
            head += f' data-lw="{label_width}" data-size="{size}" data-n="{count}"' + _address_data(block.network)
            rows.append((f'cnm-{number}-h', '', _row_html(lines[at])))
            at += 1
            for row in range(-(-count // size)):
                attrs = f' data-f="{row * size}" data-n="{min(size, count - row * size)}"'
                rows.append((f'cnm-{number}-{row}', attrs, _row_html(lines[at])))
                at += 1
        else:
            head += f' data-n="{len(block.names)}"'
            first = 0
            while at < len(lines) and lines[at]:
                inner, first = _hosts_row_html(lines[at], first)
                rows.append((f'cnm-{number}-{len(rows)}', '', inner))
                at += 1
        out.append(dict(open=head + '>', rows=rows, tail=''))
    return dict(blocks=out, size=size, label_width=label_width, group=ping_grid.GROUP, width=width)


def full_html(drawn: Mapping[str, object]) -> str:
    """The whole map as one string of HTML."""
    parts: List[str] = []
    for block in drawn['blocks']:
        parts.append(block['open'])
        for identity, attrs, inner in block['rows']:
            parts.append(f'<div class="r{" hd" if identity.endswith("-h") else ""}" id="{identity}"{attrs}>{inner}</div>')
        parts.append(block['tail'] + '</div>')
    return ''.join(parts)


def _shape(drawn: Mapping[str, object]) -> list:
    return [(block['open'], block['tail'], [row[:2] for row in block['rows']]) for block in drawn['blocks']]


def diff(before: Optional[Mapping[str, object]], after: Mapping[str, object]) -> Optional[List[List[str]]]:
    """The ``[id, inner HTML]`` of every row that differs, or ``None`` when the two are not the same rows (another
    width, another block shown): then the whole map is drawn again."""
    if before is None or _shape(before) != _shape(after):
        return None
    return [[new[0], new[2]] for old_block, new_block in zip(before['blocks'], after['blocks'])
            for old, new in zip(old_block['rows'], new_block['rows']) if old[2] != new[2]]


def legend_html() -> str:
    """Every character of the map and the two marks, whether the round shows them or not."""
    entries = [f'<span class="{_classes(ping_grid.STYLES[char], "")}">{escape(char)}</span> {escape(meaning)}'
               for char, meaning in ping_grid.LEGEND.items()]
    entries += ['<span class="m-dim">blank</span> not probed yet, or not a host of this run',
                '<span class="m-ok m-rev">!</span> changed in the last round',
                '<span class="m-warning m-part">!</span> partial reply']
    return ''.join(f'<span class="cn-map-key">{entry}</span>' for entry in entries)


CSS = '''
.cn-live-view { --cn-map-ok:#205E3C; --cn-map-info:#145C87; --cn-map-warning:#775110; --cn-map-error:#922D2D; --cn-map-dim:#5B6B77; --cn-map-bg:#FFFFFF; --cn-map-ink:#1F2D38; }
.cn-live-view:not([data-cn-live-view=map]) .cn-live-map-area { display:none; }
.cn-live-view[data-cn-live-view=map] .cn-live-table-area { display:none; }
.cn-map-summary { font-variant-numeric:tabular-nums; }
.cn-map { position:relative; padding:8px 10px; background:var(--cn-map-bg); color:var(--cn-map-ink); font-family:ui-monospace, Menlo, Consolas, "Liberation Mono", monospace; font-size:13px; line-height:18px; white-space:pre; font-variant-ligatures:none; cursor:default; -webkit-text-size-adjust:100%; text-size-adjust:100%; }
/* The ruler (100 characters) is fixed, like the popup: an absolute one would be part of what the box scrolls,
   and a box narrower than it would scroll sideways over nothing. */
.cn-map .cn-map-probe { position:fixed; visibility:hidden; pointer-events:none; top:0; left:0; }
.cn-map .b { width:max-content; min-width:100%; margin-bottom:18px; }
.cn-map .b:last-child { margin-bottom:0; }
.cn-map .r { height:18px; }
.cn-map .hd { position:sticky; top:0; z-index:1; background:var(--cn-map-bg); }
.cn-map .m-lab { color:#334D60; }
.cn-map .m-hd { color:var(--cn-map-dim); }
.cn-map .m-ok { color:var(--cn-map-ok); font-weight:700; }
.cn-map .m-info { color:var(--cn-map-info); font-weight:700; }
.cn-map .m-warning { color:var(--cn-map-warning); font-weight:700; }
.cn-map .m-error { color:var(--cn-map-error); font-weight:700; }
.cn-map .m-dim { color:var(--cn-map-dim); }
.cn-map .m-part { text-decoration:underline; text-decoration-thickness:2px; text-underline-offset:2px; }
.cn-map .m-rev { color:var(--cn-map-bg); }
.cn-map .m-ok.m-rev { background:var(--cn-map-ok); }
.cn-map .m-info.m-rev { background:var(--cn-map-info); }
.cn-map .m-warning.m-rev { background:var(--cn-map-warning); }
.cn-map .m-error.m-rev { background:var(--cn-map-error); }
.cn-map .m-dim.m-rev { background:var(--cn-map-dim); }
.cn-map .cn-map-cursor { display:none; position:absolute; z-index:2; pointer-events:none; box-sizing:border-box; border:2px solid var(--cn-map-info); border-radius:2px; }
.cn-map .cn-map-cursor.on { display:block; }
.cn-map:focus-visible .cn-map-cursor.on { box-shadow:0 0 0 2px #FFFFFF, 0 0 0 4px var(--cn-map-info); }
.cn-map .cn-map-show { margin:2px 0 0 2ch; min-height:28px; padding:2px 10px; font:inherit; color:var(--cn-map-info); background:#FFFFFF; border:1px solid var(--cn-map-info); border-radius:4px; cursor:pointer; }
.cn-map [data-kind=compact] { display:flex; flex-wrap:wrap; align-items:center; }
.cn-map-sr { position:absolute; width:1px; height:1px; margin:-1px; overflow:hidden; clip:rect(0 0 0 0); white-space:nowrap; }
.cn-map-popup { position:fixed; z-index:6000; box-sizing:border-box; max-width:min(360px, calc(100vw - 16px)); padding:10px 12px; background:#FFFFFF; color:#1F2D38; border:1px solid #9FB2C0; border-radius:6px; box-shadow:0 4px 16px rgba(16,40,60,.22); font-family:Roboto, -apple-system, "Segoe UI", sans-serif; font-size:13px; line-height:1.45; white-space:normal; cursor:auto; }
.cn-map-popup[hidden] { display:none; }
.cn-map-popup[data-pinned=false] { pointer-events:none; }
.cn-map-popup dl { display:grid; grid-template-columns:auto minmax(0,1fr); gap:2px 10px; margin:0; }
.cn-map-popup dt { color:#5B6B77; white-space:nowrap; }
.cn-map-popup dd { margin:0; overflow-wrap:anywhere; font-variant-numeric:tabular-nums; }
.cn-map-popup .cn-map-note { margin-top:4px; color:#5B6B77; }
.cn-map-popup .cn-map-acts { display:flex; flex-wrap:wrap; gap:8px; margin-top:8px; }
.cn-map-popup button { min-width:44px; min-height:44px; padding:0 12px; font:inherit; color:#145C87; background:#FFFFFF; border:1px solid #145C87; border-radius:4px; cursor:pointer; }
.cn-map-popup button:focus-visible, .cn-map .cn-map-show:focus-visible { outline:2px solid #145C87; outline-offset:2px; }
.cn-map-legend { font-family:ui-monospace, Menlo, Consolas, "Liberation Mono", monospace; font-size:13px; line-height:20px; }
.cn-map-legend .cn-map-key { display:inline-block; max-width:100%; margin-right:2ch; overflow-wrap:anywhere; }
.cn-live-switch .q-btn[aria-pressed=true] { background:#E5F0F7 !important; box-shadow:inset 0 -3px #145C87; font-weight:700; }
.cn-map-legend .m-ok, .cn-map-legend .m-info, .cn-map-legend .m-warning, .cn-map-legend .m-error { font-weight:700; }
.cn-map-legend .m-ok { color:#205E3C; } .cn-map-legend .m-info { color:#145C87; } .cn-map-legend .m-warning { color:#775110; }
.cn-map-legend .m-error { color:#922D2D; } .cn-map-legend .m-dim { color:#5B6B77; }
.cn-map-legend .m-part { text-decoration:underline; text-decoration-thickness:2px; text-underline-offset:2px; }
.cn-map-legend .m-ok.m-rev { color:#FFFFFF; background:#205E3C; padding:0 2px; }
@media print { .cn-map.cn-monitor-scroll { max-height:none; overflow:visible; } .cn-map-popup, .cn-map .cn-map-cursor { display:none; } }
'''

SCRIPT = r'''<script>
window.cnMonitorMap = window.cnMonitorMap || (() => {
  const KEY = 'cn-tool-monitor-live-view';
  const S = {wrap: null, box: null, body: null, cursor: null, popup: null, live: null, probe: null, words: {},
             group: 8, rev: null, cur: null, shown: null, pinned: false, say: false, cache: new Map(), timer: 0,
             view: 'map', sent: '', note: ''};
  const stored = () => { try { return sessionStorage.getItem(KEY); } catch (error) { return null; } };
  const store = view => { try { sessionStorage.setItem(KEY, view); } catch (error) { /* a private tab */ } };
  const send = (name, data) => { if (window.emitEvent) window.emitEvent(name, data); };
  const charWidth = () => S.probe ? S.probe.getBoundingClientRect().width / 100 : 0;

  function columns() {
    const width = charWidth();
    if (!S.box || !S.box.clientWidth || !width) return 0;
    const style = getComputedStyle(S.box);
    return Math.max(1, Math.floor((S.box.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight)) / width));
  }
  // Tell the server which view the tab shows and how many characters fit: it lays the map out.
  function report(force, fresh) {
    const cols = S.view === 'map' ? columns() : 0;
    if (S.view === 'map' && !cols) return;  // not on screen (another tab panel): reported once it is
    const sent = S.view + ':' + cols;
    if (!force && sent === S.sent) return;
    S.sent = sent;
    send('cn_monitor_map_view', {view: S.view, cols: cols, fresh: !!fresh});
  }
  function apply(view) {
    S.view = view === 'table' ? 'table' : 'map';
    if (S.wrap) S.wrap.dataset.cnLiveView = S.view;
  }
  function setView(view) { apply(view); store(S.view); hide(); report(true, false); }

  const blockOf = b => S.body ? S.body.querySelector('.b[data-b="' + b + '"]') : null;
  const same = (a, b) => !!a && !!b && a.b === b.b && a.c === b.c;
  function rowOf(d) {
    const block = blockOf(d.b);
    if (!block) return null;
    if (block.dataset.kind === 'hosts') {
      const cell = block.querySelector('[data-i="' + d.c + '"]');
      return cell ? cell.parentElement : null;
    }
    if (block.dataset.kind !== 'subnet' || d.c < 0 || d.c >= +block.dataset.n) return null;
    return document.getElementById('cnm-' + d.b + '-' + Math.floor(d.c / +block.dataset.size));
  }
  // A Range over character `col` of a row: the browser's own box of that character.
  function charRange(row, col) {
    if (col < 0) return null;
    const walker = document.createTreeWalker(row, NodeFilter.SHOW_TEXT);
    let node, left = col;
    while ((node = walker.nextNode())) {
      if (left < node.length) {
        const range = document.createRange();
        range.setStart(node, left);
        range.setEnd(node, left + 1);
        return range;
      }
      left -= node.length;
    }
    return null;
  }
  function rangeOf(d) {
    const block = blockOf(d.b), row = rowOf(d);
    if (!row) return null;
    if (block.dataset.kind === 'hosts') {
      const range = document.createRange();
      range.selectNodeContents(block.querySelector('[data-i="' + d.c + '"]'));
      return range;
    }
    const at = d.c % +block.dataset.size;
    return charRange(row, +block.dataset.lw + 1 + at + Math.floor(at / S.group));
  }
  // The cell under the pointer: null for none, undefined over the popup (which stays as it is).
  function hit(event) {
    const target = event.target.nodeType === 1 ? event.target : event.target.parentElement;
    if (!target || target.closest('.cn-map-popup')) return undefined;
    const row = target.closest('.r'), block = row && row.closest('.b');
    if (!block) return null;
    const b = +block.dataset.b;
    if (block.dataset.kind === 'hosts') {
      const cell = target.closest('[data-i]');
      return cell ? {b: b, c: +cell.dataset.i} : null;
    }
    if (block.dataset.kind !== 'subnet' || row.dataset.f === undefined) return null;
    const first = charRange(row, 0), width = charWidth();
    if (!first || !width) return null;
    let col = Math.floor((event.clientX - first.getBoundingClientRect().left) / width);
    for (const near of [col, col - 1, col + 1]) {  // the width is measured: the character's own box decides
      const range = charRange(row, near);
      if (!range) continue;
      const box = range.getBoundingClientRect();
      if (event.clientX >= box.left && event.clientX < box.right) { col = near; break; }
    }
    const k = col - (+block.dataset.lw + 1);
    if (k < 0 || k % (S.group + 1) === S.group) return null;  // the label, or the gap between two groups
    const at = k - Math.floor(k / (S.group + 1));
    return at < +row.dataset.n ? {b: b, c: +row.dataset.f + at} : null;
  }
  function target(d) {
    const block = blockOf(d.b);
    if (!block) return '';
    const data = block.dataset;
    if (data.kind === 'hosts') {
      const cell = block.querySelector('[data-i="' + d.c + '"]');
      return cell && cell.previousElementSibling ? cell.previousElementSibling.textContent : '';
    }
    if (data.ip4 !== undefined) {
      const address = +data.ip4 + d.c;
      return [Math.floor(address / 16777216), address >> 16 & 255, address >> 8 & 255, address & 255].join('.');
    }
    if (data.ip6 !== undefined) return d.c === 0 ? data.ip6first : data.ip6 + (+data.ip6low + d.c).toString(16);
    return '';
  }

  // What the popup shows is said once: a new round repeats nothing, and says the cell again only when something other
  // than the two lines that tick with every round has changed. ``how``: 'user' (a key or a tap: always said),
  // 'update' (the server's answer, or a new round: said when it differs), 'quiet' (a new round's placeholder).
  const TICKING = ['Last seen', 'Answered'];
  function say(lines, how) {
    if (!S.live || !S.say || how === 'quiet') return;
    const text = line => line.join(': ');
    const key = lines.filter(line => !TICKING.includes(line[0])).map(text).join('; ');
    if (how !== 'user' && key === S.said) return;
    S.said = key;
    S.live.textContent = lines.map(text).join('; ');
  }
  function fill(d, char, details, how) {
    const lines = details ? details.lines
      : [['Target', target(d) || 'This address'], ['State', (char.trim() ? char + ' ' : '') + (S.words[char] || '')]];
    const popup = S.popup;
    popup.textContent = '';
    const list = document.createElement('dl');
    for (const line of lines) {
      const label = document.createElement('dt'), value = document.createElement('dd');
      label.textContent = line[0];
      value.textContent = line[1];
      list.append(label, value);
    }
    popup.append(list);
    const note = document.createElement('div');
    note.className = 'cn-map-note';
    note.textContent = details ? S.note : 'Loading last seen and rounds…';
    if (note.textContent) popup.append(note);
    if (S.pinned) {
      const acts = document.createElement('div');
      acts.className = 'cn-map-acts';
      const address = (lines.find(line => line[0] === 'Address') || lines[0])[1];
      for (const [act, label] of [['copy', 'Copy IP'], ['table', 'Show in table'], ['close', 'Close']]) {
        const button = document.createElement('button');
        button.type = 'button';
        button.dataset.act = act;
        button.dataset.value = act === 'table' ? lines[0][1] : address;
        button.textContent = label;
        acts.append(button);
      }
      popup.append(acts);
    }
    popup.dataset.cell = d.b + ':' + d.c;
    popup.dataset.pinned = S.pinned ? 'true' : 'false';
    popup.dataset.details = details ? 'true' : 'false';
    popup.setAttribute('role', S.pinned ? 'group' : 'tooltip');
    popup.setAttribute('aria-label', 'Host details');
    say(lines, how);
  }
  function position() {
    const range = S.shown && rangeOf(S.shown);
    if (!range) return;
    const cell = range.getBoundingClientRect(), popup = S.popup;
    popup.hidden = false;
    const width = popup.offsetWidth, height = popup.offsetHeight;
    const view = document.documentElement;
    let left = Math.min(Math.max(8, cell.left), Math.max(8, view.clientWidth - width - 8));
    let top = cell.bottom + 8;
    if (top + height > view.clientHeight - 8 && cell.top - 8 - height >= 8) top = cell.top - 8 - height;
    popup.style.left = left + 'px';
    popup.style.top = top + 'px';
  }
  // After a scroll the popup follows its character, and closes once the character has left the box.
  function follow() {
    const range = S.shown && rangeOf(S.shown);
    if (!range) return;
    const cell = range.getBoundingClientRect(), box = S.box.getBoundingClientRect();
    if (cell.bottom < box.top || cell.top > box.bottom || cell.right < box.left || cell.left > box.right) hide();
    else position();
  }
  function show(d, pin, again) {
    const range = rangeOf(d);
    if (!range) { hide(); return; }
    const key = d.b + ':' + d.c, details = S.cache.get(key);
    S.shown = d;
    S.pinned = !!pin;
    S.note = '';
    fill(d, range.toString(), details, again ? (details ? 'update' : 'quiet') : 'user');
    position();
    clearTimeout(S.timer);
    if (!details) S.timer = setTimeout(() => send('cn_monitor_map_host', {b: d.b, c: d.c, rev: S.rev}), 120);
  }
  function hide() {
    clearTimeout(S.timer);
    if (S.popup) { S.popup.hidden = true; delete S.popup.dataset.cell; }
    S.shown = null;
    S.pinned = false;
  }
  // The server's answer for one cell: last seen, first seen, rounds answered, since.
  function details(message) {
    if (message.rev !== S.rev) return;
    const key = message.b + ':' + message.c;
    if (S.cache.size >= 256) S.cache.delete(S.cache.keys().next().value);
    S.cache.set(key, message);
    if (S.shown && S.shown.b === message.b && S.shown.c === message.c) {
      const range = rangeOf(S.shown);
      if (range) { fill(S.shown, range.toString(), message, 'update'); position(); }
    }
  }

  function place(scroll) {
    const range = S.cur && rangeOf(S.cur);
    if (!range) { S.cursor.classList.remove('on'); return; }
    let cell = range.getBoundingClientRect();
    const box = S.box.getBoundingClientRect();
    if (scroll) {
      if (cell.top < box.top + 28) S.box.scrollTop -= box.top + 28 - cell.top;
      else if (cell.bottom > box.bottom - 10) S.box.scrollTop += cell.bottom - box.bottom + 10;
      if (cell.left < box.left + 10) S.box.scrollLeft -= box.left + 10 - cell.left;
      else if (cell.right > box.right - 10) S.box.scrollLeft += cell.right - box.right + 10;
      cell = range.getBoundingClientRect();
    }
    const style = S.cursor.style;
    style.left = (cell.left - box.left - S.box.clientLeft + S.box.scrollLeft - 2) + 'px';
    style.top = (cell.top - box.top - S.box.clientTop + S.box.scrollTop - 1) + 'px';
    style.width = (cell.width + 4) + 'px';
    style.height = (cell.height + 2) + 'px';
    S.cursor.classList.add('on');
    S.box.dataset.cursor = S.cur.b + ':' + S.cur.c;
  }
  const drawnBlocks = () => [...S.body.querySelectorAll('.b')].filter(block => block.dataset.kind !== 'compact');
  function firstCell() {
    const block = drawnBlocks()[0];
    return block ? {b: +block.dataset.b, c: 0} : null;
  }
  function neighbour(b, step) {
    const blocks = drawnBlocks();
    return blocks[blocks.findIndex(block => +block.dataset.b === b) + step] || null;
  }
  function nearest(row, d) {
    const from = rangeOf(d).getBoundingClientRect().left;
    let best = null, gap = Infinity;
    for (const cell of row.querySelectorAll('[data-i]')) {
      const distance = Math.abs(cell.getBoundingClientRect().left - from);
      if (distance < gap) { best = cell; gap = distance; }
    }
    return best ? {b: d.b, c: +best.dataset.i} : d;
  }
  function across(other, step, d, column) {
    if (!other) return d;
    const b = +other.dataset.b, n = +other.dataset.n;
    if (other.dataset.kind === 'hosts') return {b: b, c: step > 0 ? 0 : n - 1};
    const size = +other.dataset.size;
    return {b: b, c: Math.min(n - 1, (step > 0 ? 0 : Math.floor((n - 1) / size) * size) + column)};
  }
  function move(d, key) {
    const block = blockOf(d.b);
    if (!block || !rowOf(d)) return firstCell();
    const n = +block.dataset.n, hosts = block.dataset.kind === 'hosts', size = hosts ? 1 : +block.dataset.size;
    const edge = (other, last) => other ? {b: +other.dataset.b, c: last ? +other.dataset.n - 1 : 0} : d;
    if (key === 'ArrowLeft') return d.c > 0 ? {b: d.b, c: d.c - 1} : edge(neighbour(d.b, -1), true);
    if (key === 'ArrowRight') return d.c < n - 1 ? {b: d.b, c: d.c + 1} : edge(neighbour(d.b, 1), false);
    if (key === 'PageUp') return neighbour(d.b, -1) ? edge(neighbour(d.b, -1), false) : {b: d.b, c: 0};
    if (key === 'PageDown') return neighbour(d.b, 1) ? edge(neighbour(d.b, 1), false) : {b: d.b, c: n - 1};
    const row = rowOf(d);
    if (key === 'Home' || key === 'End') {
      if (hosts) {
        const cells = row.querySelectorAll('[data-i]');
        return {b: d.b, c: +cells[key === 'Home' ? 0 : cells.length - 1].dataset.i};
      }
      const start = Math.floor(d.c / size) * size;
      return {b: d.b, c: key === 'Home' ? start : Math.min(n - 1, start + size - 1)};
    }
    const step = key === 'ArrowUp' ? -1 : 1;
    if (hosts) {
      const next = step < 0 ? row.previousElementSibling : row.nextElementSibling;
      return next && next.querySelector('[data-i]') ? nearest(next, d) : across(neighbour(d.b, step), step, d, 0);
    }
    const c = d.c + step * size;
    if (c >= 0 && c < n) return {b: d.b, c: c};
    if (step > 0 && Math.floor(d.c / size) < Math.floor((n - 1) / size)) return {b: d.b, c: n - 1};
    return across(neighbour(d.b, step), step, d, d.c % size);
  }

  function draw(message) {
    if (!S.body) return;
    if (message.full !== undefined) S.body.innerHTML = message.full;
    else for (const [id, inner] of message.rows) {
      const row = document.getElementById(id);
      if (row) row.innerHTML = inner;
    }
    S.rev = message.rev;
    S.cache.clear();
    if (message.label) S.box.setAttribute('aria-label', message.label);
    if (S.cur && !rowOf(S.cur)) { S.cur = null; delete S.box.dataset.cursor; }
    place(false);
    if (S.shown) { if (rowOf(S.shown)) show(S.shown, S.pinned, true); else hide(); }
    S.box.dataset.rev = String(message.rev);
  }

  function onMove(event) {
    if (event.pointerType === 'touch' || S.pinned) return;
    const d = hit(event);
    if (d === undefined) return;
    if (!d) { if (S.shown) hide(); return; }
    if (!same(d, S.shown)) { S.say = false; show(d, false); }
  }
  function copy(button) {
    const done = ok => { S.note = ok ? 'Copied.' : 'Could not copy: select the text instead.';
      const note = S.popup.querySelector('.cn-map-note') || S.popup.insertBefore(document.createElement('div'), S.popup.querySelector('.cn-map-acts'));
      note.className = 'cn-map-note'; note.textContent = S.note;
      if (S.live) { S.live.textContent = S.note; S.said = null; } };
    try { navigator.clipboard.writeText(button.dataset.value).then(() => done(true), () => done(false)); }
    catch (error) { done(false); }
  }
  function onClick(event) {
    const element = event.target.nodeType === 1 ? event.target : event.target.parentElement;
    const act = element && element.closest('[data-act]');
    if (act) {
      if (act.dataset.act === 'copy') copy(act);
      else if (act.dataset.act === 'table') { const value = act.dataset.value; hide(); send('cn_monitor_map_table', {target: value}); }
      else { hide(); S.box.focus({preventScroll: true}); }
      return;
    }
    const more = element && element.closest('[data-show]');
    if (more) { send('cn_monitor_map_show', {b: +more.dataset.show}); return; }
    const d = hit(event);
    if (d === undefined) return;
    if (!d) { hide(); return; }
    S.cur = d;
    S.say = true;
    place(false);
    show(d, true);
  }
  function onKey(event) {
    if (event.target !== S.box) {  // a button of the map or of the popup
      if (event.key === 'Escape' && S.shown) { hide(); S.box.focus({preventScroll: true}); event.preventDefault(); }
      return;
    }
    if (event.altKey || event.ctrlKey || event.metaKey) return;
    const key = event.key;
    if (key === 'Escape') { if (S.shown) { hide(); event.preventDefault(); } return; }
    if (key === 'Enter' || key === ' ') {
      if (!S.cur) S.cur = firstCell();
      if (S.cur) { S.say = true; place(true); show(S.cur, true); }
      event.preventDefault();
      return;
    }
    if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End', 'PageUp', 'PageDown'].includes(key)) return;
    event.preventDefault();
    const next = S.cur ? move(S.cur, key) : firstCell();
    if (!next) return;
    S.cur = next;
    S.say = true;
    place(true);
    show(next, false);
  }

  function init(options) {
    const box = document.getElementById(options.box), wrap = document.getElementById(options.wrap);
    if (!box || !wrap) return false;
    S.words = options.words;
    S.group = options.group;
    S.live = document.getElementById(options.live);
    const fresh = S.box !== box || !box.querySelector('.cn-map-body');
    if (fresh) {
      S.box = box;
      S.wrap = wrap;
      S.cur = S.shown = null;
      S.rev = null;
      box.textContent = '';
      S.probe = document.createElement('span');
      S.probe.className = 'cn-map-probe';
      S.probe.setAttribute('aria-hidden', 'true');
      S.probe.textContent = '0'.repeat(100);
      S.body = document.createElement('div');
      S.body.className = 'cn-map-body';
      S.cursor = document.createElement('div');
      S.cursor.className = 'cn-map-cursor';
      S.cursor.setAttribute('aria-hidden', 'true');
      S.popup = document.createElement('div');
      S.popup.className = 'cn-map-popup';
      S.popup.hidden = true;
      box.append(S.probe, S.body, S.cursor, S.popup);
      box.addEventListener('pointermove', onMove);
      box.addEventListener('pointerleave', () => { if (!S.pinned) hide(); });
      box.addEventListener('click', onClick);
      box.addEventListener('keydown', onKey);
      box.addEventListener('focus', () => { if (!S.cur && S.body) { S.cur = firstCell(); place(false); } });
      box.addEventListener('scroll', follow, {passive: true});
      if (!window.cnMonitorMapGlobal) {
        window.cnMonitorMapGlobal = true;
        document.addEventListener('click', event => { if (S.pinned && S.box && !S.box.contains(event.target)) hide(); });
        window.addEventListener('scroll', follow, {passive: true});
      }
      if (window.ResizeObserver) new ResizeObserver(() => { report(false, false); place(false); if (S.shown) position(); }).observe(box);
      else window.addEventListener('resize', () => report(false, false));
      if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => report(false, false));
    }
    apply(stored() || 'map');
    S.sent = '';
    report(true, fresh);
    return true;
  }
  return {init: init, draw: draw, details: details, setView: setView};
})();
</script>'''
