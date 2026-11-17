"""Ping presentation helpers for the shared local session."""
import asyncio
import json
import re


def parse_ports(text):
    from cn_tool.utils.validation import parse_tcp_ports
    return parse_tcp_ports(text) if text.strip() else ()


def ping_group_of(row, icmp_available=True):
    """The outcome group of one completed row, from what was observed (an unprobed port is never inferred)."""
    status = str(row.get('Result') or '').strip().casefold()
    if icmp_available:
        if status == 'ok' or status.startswith('ok ('):
            return 'ICMP responded'
        if status == 'no response':
            return 'ICMP no response'
        if status == 'no route':
            return 'ICMP no route'
        if status.startswith('error'):
            return 'ICMP error'
        if status == 'not run':
            return 'ICMP not run'
        return 'Other'
    values = [str(value or '').strip().casefold() for key, value in row.items() if key.startswith('TCP ')]
    if any(value in {'open', 'closed'} for value in values):
        return 'TCP: at least one response'
    if 'error' in values:
        return 'TCP: error'
    if 'unreachable' in values:
        return 'TCP: unreachable'
    if values and all(value == 'timeout' for value in values):
        return 'TCP: no response'
    return 'Other'


def ping_groups(rows, icmp_available=True):
    """Partition completed rows by observed outcomes, without inferring unprobed ports."""
    groups = {}
    for row in rows:
        groups.setdefault(ping_group_of(row, icmp_available), []).append(row)
    return groups


def format_diagnostic(key, item):
    if key in {'input_errors', 'resolution_errors'}:
        return f"{item['object']}: {item['reason'].replace('with --tcp', 'with TCP ports')}"
    return str(item)


def _ping_message(message):
    from cn_tool.modules import bulk_ping
    if message == bulk_ping._PING_MISSING:
        return 'The system ping command is not installed. Install ping or enter TCP ports to run TCP checks.'
    return message


def ping_headline(outcome):
    """What the user got from a Ping, in one line: "322 hosts pinged · 1 probe error". Zero counts are not printed;
    an error is its reason."""
    from . import texts
    kind, details = outcome.get('kind'), outcome.get('details') or {}
    if kind == 'lookup_error':
        return str(_ping_message(outcome.get('message')) or '').strip().rstrip('.') or 'Ping could not run'
    counts = texts.counts_line([
        (outcome.get('matched_count') or 0, 'host pinged', 'hosts pinged'),
        (details.get('probe_errors') or 0, 'probe error', 'probe errors'),
        (outcome.get('invalid_count') or 0, 'line not understood', 'lines not understood'),
        (outcome.get('resolution_error_count') or 0, 'DNS error', 'DNS errors')])
    if kind == 'stopped':
        return ' · '.join(part for part in ('Ping stopped', counts) if part)
    if kind in ('matched', 'partial'):
        return counts or 'Ping completed'
    if kind == 'invalid':
        return counts or 'No valid targets to ping'
    return 'Ping outcome'


def ping_outcome_display(snapshot, attempt, *, format_entries=True):
    outcome = snapshot.latest_outcome
    if not outcome:
        return None
    result = (attempt or {}).get('result') or {}
    details = outcome.get('details') or {}
    def errors(key):
        entries = result.get(key, [])
        return [format_diagnostic(key, item) for item in entries] if format_entries else entries
    return dict(title=ping_headline(outcome), tone='error' if outcome.get('kind') == 'lookup_error' else '',
                input_errors=errors('input_errors'), resolution_errors=errors('resolution_errors'),
                incomplete=details.get('attempted_incomplete') or [],
                unattempted=details.get('unattempted') or [])


PING_CSS = """
.nicegui-content:has(.cn-ping-form) { gap:12px; }
.cn-ping-empty:empty { display:none; }
.cn-ping-outcome, .cn-ping-outcome > .nicegui-column { gap:8px; }
.cn-ping-outcome h2 { margin-top:0; }
.cn-ping-stopped { font-weight:700; }
.cn-ping-pager { gap:6px; }
.cn-ping-jump { display:inline-flex; flex-wrap:nowrap; align-items:center; gap:6px; max-width:100%; }
.cn-ping-page-input { width:84px; max-width:100%; }
.cn-ping-pager [role=alert]:empty, .cn-ping-form [role=alert]:empty { display:none; }
.cn-ping-form { gap:8px; }
.cn-ping-form textarea { min-height:calc(3 * 1.5em); max-height:calc(10 * 1.5em + 16px); }
.cn-ping-diagnostics { width:100%; }
@media(min-width:800px) {
  .cn-ping-form { display:grid; grid-template-columns:minmax(0,2fr) minmax(0,1fr); column-gap:20px; }
  .cn-ping-target-label { grid-column:1; grid-row:1; }
  .cn-ping-ports-label { grid-column:2; grid-row:1; }
  .cn-ping-targets { grid-column:1; grid-row:2 / 5; align-self:stretch; }
  .cn-ping-target-help { grid-column:1; grid-row:5; }
  .cn-ping-ports { grid-column:2; grid-row:2; }
  .cn-ping-port-help { grid-column:2; grid-row:3; }
  .cn-ping-port-error { grid-column:2; grid-row:4; }
  .cn-ping-run-controls { grid-column:2; grid-row:5; }
}
"""


def render_ping(controller, scope):
    from .subnets import render_subnets
    scope.head_once('ping', css=PING_CSS)
    render_subnets(controller, scope, lookup_type='ping')


def render_pager(key, title, page, pages, set_page, refresh, *, interaction_lock):
    """Render bounded page controls for a list of diagnostics (the results are a ``tables.cn_table``); all
    identifiers are local fixed strings."""
    from nicegui import ui
    from . import texts
    nav_label = f'{title} pages'
    input_label = f'{title} page'
    go_label = f'Go to {title} page'

    async def change_page(index, focus):
        client = ui.context.client
        async with interaction_lock:
            set_page(index)
            await refresh()
            selector = json.dumps(f'[data-cn-pager="{key}"]')
            role = json.dumps(focus)
            script = f'''(() => {{
const nav = document.querySelector({selector});
const wanted = {role} === 'jump' ? nav?.querySelector('input') : nav?.querySelector('[data-ping-page="' + {role} + '"]:not([disabled])');
(wanted || nav?.querySelector('button:not([disabled])') || nav?.querySelector('input'))?.focus();
}})()'''
            async def restore_focus():
                await client.run_javascript(script, timeout=1)
            try:
                await asyncio.wait_for(restore_focus(), timeout=2)
            except TimeoutError:
                pass


    with ui.element('nav').props(f'aria-label="{nav_label}"').classes('cn-ping-pager row items-center min-w-0 w-full') as nav:
        nav._props['data-cn-pager'] = key
        ui.label(f'Page {texts.fmt_count(page + 1)} of {texts.fmt_count(pages)}')
        names = [('First', 0, 'first', page > 0), ('Previous', page - 1, 'previous', page > 0),
                 ('Next', page + 1, 'next', page < pages - 1), ('Last', pages - 1, 'last', page < pages - 1)]
        for action, index, focus, enabled in names:
            label = f'{action} {title} page'
            button = ui.button(action, on_click=lambda _, target=index, name=focus: change_page(target, name)).props('outline dense')
            button._props['aria-label'] = label
            button._props['data-ping-page'] = focus
            button.set_enabled(enabled)
        with ui.element('div').classes('cn-ping-jump'):
            jump = ui.input('Page', value=str(page + 1)).props('outlined dense inputmode=numeric').classes('cn-ping-page-input')
            jump._props['aria-label'] = input_label
            async def go():
                value = (jump.value or '').strip()
                if not re.fullmatch(r'[0-9]{1,10}', value) or not 1 <= int(value) <= pages:
                    error.set_text(f'Enter a page between 1 and {pages}.')
                    return
                await change_page(int(value) - 1, 'jump')
            jump.on('keydown.enter', go)
            go_button = ui.button('Go', on_click=go).props('outline dense')
            go_button._props['aria-label'] = go_label
        error = ui.label('').props('role=alert').classes('text-negative')


PING_LABELS = {'Host': 'Target', 'Result': 'ICMP result'}
TABLE_LABEL = 'Ping hosts'
STOPPED_NOTE = 'Ping was stopped: only completed results are included.'


def ping_columns(keys):
    """The Ping table's columns in display order (Target, ICMP result, each TCP port, Address, then the rest)."""
    keys = list(keys)
    leading = [key for key in ['Host', 'Result', *(key for key in keys if key.startswith('TCP ')), 'Address'] if key in keys]
    return leading + [key for key in keys if key not in leading]


def display_rows(rows):
    """The rows of a Ping result for a table: a value a plugin made a list or a mapping is its text."""
    return [{key: str(value) if isinstance(value, (dict, list, tuple)) else value for key, value in row.items()
             if key not in ('id', '__row')} for row in rows]


def table_columns(rows):
    """The Target (the identity), the ICMP result and each TCP port as chips, the address, then what a plugin added."""
    from . import tables
    keys = ping_columns(dict.fromkeys(key for row in rows for key in row))
    kinds = {key: 'state' for key in keys if key == 'Result' or key.startswith('TCP ')}
    return tables.columns_of(rows, keys, labels=PING_LABELS, sticky='Host', kinds=kinds)


def render_ping_results(snapshot, states, on_change=None):
    """The result on screen: its notices and one ``cn_table`` of the hosts. ``states`` is the tab's ``TableState`` by
    table name, so the arrangement outlives a redraw of the panel; the URL carries it (``on_change``, R2-08)."""
    from nicegui import ui
    from . import tables
    result = snapshot.result
    icmp = result.get('icmp_available', True)
    if not icmp:
        ui.label('ICMP was not run; TCP results are shown below.').classes('cn-muted')
    if result.get('stopped'):
        ui.label('Stopped: only completed results are shown.').classes('cn-ping-stopped')
    rows = display_rows(result.get('rows', []))
    if not rows:
        return
    groups = [tables.Group(name, name) for name in ping_groups(rows, icmp)]
    # A result arrives once, when a run ends; while a new run goes on, the table holds the previous, complete one.
    return tables.cn_table(
        name='ping', label=TABLE_LABEL, columns=table_columns(rows),
        source=tables.RowsSource(rows, group_of=lambda row: ping_group_of(row, icmp)),
        state=states.setdefault('ping', tables.TableState()), groups=groups,
        note=STOPPED_NOTE if result.get('stopped') else '', on_change=on_change, link=True)
