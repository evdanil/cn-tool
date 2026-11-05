"""Ping presentation helpers for the shared local session."""
import asyncio
import json
import re


def parse_ports(text):
    from cn_tool.utils.validation import parse_tcp_ports
    return parse_tcp_ports(text) if text.strip() else ()


def ping_groups(rows, icmp_available=True):
    """Partition completed rows by observed outcomes, without inferring unprobed ports."""
    groups = {}
    for row in rows:
        status = str(row.get('Result') or '').strip().casefold()
        if icmp_available:
            if status == 'ok' or status.startswith('ok ('):
                group = 'ICMP responded'
            elif status == 'no response':
                group = 'ICMP no response'
            elif status == 'no route':
                group = 'ICMP no route'
            elif status.startswith('error'):
                group = 'ICMP error'
            elif status == 'not run':
                group = 'ICMP not run'
            else:
                group = 'Other'
        else:
            values = [str(value or '').strip().casefold() for key, value in row.items() if key.startswith('TCP ')]
            if any(value in {'open', 'closed'} for value in values):
                group = 'TCP: at least one response'
            elif 'error' in values:
                group = 'TCP: error'
            elif 'unreachable' in values:
                group = 'TCP: unreachable'
            elif values and all(value == 'timeout' for value in values):
                group = 'TCP: no response'
            else:
                group = 'Other'
        groups.setdefault(group, []).append(row)
    return groups


def format_diagnostic(key, item):
    if key in {'input_errors', 'resolution_errors'}:
        return f"{item['object']}: {item['reason'].replace('with --tcp', 'with TCP ports')}"
    return str(item)


def ping_outcome_display(snapshot, attempt, *, format_entries=True):
    from cn_tool.modules import bulk_ping
    outcome = snapshot.latest_outcome
    if not outcome:
        return None
    result = (attempt or {}).get('result') or {}
    details = outcome.get('details') or {}
    titles = {'matched': 'Ping completed', 'partial': 'Ping completed with diagnostics',
              'invalid': 'Invalid input', 'stopped': 'Ping stopped', 'lookup_error': 'Ping failed'}
    def errors(key):
        entries = result.get(key, [])
        return [format_diagnostic(key, item) for item in entries] if format_entries else entries
    message = outcome.get('message') or ''
    if message == bulk_ping._PING_MISSING:
        message = 'The system ping command is not installed. Install ping or enter TCP ports to run TCP checks.'
    return dict(title=titles.get(outcome.get('kind'), 'Ping outcome'),
                message=message,
                summary=f"{outcome.get('matched_count', 0)} completed, {outcome.get('invalid_count', 0)} invalid, {outcome.get('resolution_error_count', 0)} DNS errors",
                input_errors=errors('input_errors'), resolution_errors=errors('resolution_errors'),
                incomplete=details.get('attempted_incomplete') or [],
                unattempted=details.get('unattempted') or [])


PING_CSS = """
.nicegui-content:has(.cn-ping-form) { gap:12px; }
.cn-ping-empty:empty { display:none; }
.cn-ping-outcome, .cn-ping-outcome > .nicegui-column { gap:8px; }
.cn-ping-outcome h2 { margin-top:0; }
.cn-ping-results-toolbar { display:flex; flex-wrap:wrap; align-items:center; gap:8px 20px; width:100%; }
.cn-ping-result-filters, .cn-ping-groups { display:flex; flex-wrap:wrap; align-items:center; gap:6px; }
.cn-ping-result-filters { width:100%; }
.cn-ping-result-filters .cn-field-filter { width:auto; }
.cn-ping-groups .q-btn { max-width:100%; }
.cn-ping-groups .q-btn__content { white-space:normal; overflow-wrap:anywhere; }
.cn-ping-table { min-width:0; max-width:100%; max-height:min(60vh,620px); overflow:auto; --cn-ping-target-width:320px; --cn-ping-icmp-width:160px; }
.cn-ping-table .q-table { table-layout:fixed; min-width:calc(var(--cn-ping-target-width) + var(--cn-ping-icmp-width) + var(--cn-ping-extra-columns) * 150px); }
.cn-ping-table .q-table th { position:sticky; top:0; z-index:1; }
.cn-ping-table .q-table th, .cn-ping-table .q-table td { padding:7px 10px; height:auto; font-size:14px; vertical-align:middle; }
.cn-ping-table .q-table td { overflow-wrap:anywhere; font-variant-numeric:tabular-nums; }
.cn-ping-table .q-table td:nth-child(2) { font-weight:600; }
.cn-ping-pager { gap:6px; }
.cn-ping-jump { display:inline-flex; flex-wrap:nowrap; align-items:center; gap:6px; max-width:100%; }
.cn-ping-page-input { width:84px; max-width:100%; }
.cn-ping-pager [role=alert]:empty, .cn-ping-form [role=alert]:empty { display:none; }
.cn-ping-form { gap:8px; }
.cn-ping-diagnostics { width:100%; }
@media(min-width:800px) {
  .cn-ping-form { display:grid; grid-template-columns:minmax(0,2fr) minmax(0,1fr); column-gap:20px; }
  .cn-ping-target-label { grid-column:1; grid-row:1; }
  .cn-ping-targets { grid-column:1; grid-row:2 / 5; align-self:stretch; }
  .cn-ping-target-help { grid-column:1; grid-row:5; }
  .cn-ping-ports { grid-column:2; grid-row:2; }
  .cn-ping-port-help { grid-column:2; grid-row:3; }
  .cn-ping-port-error { grid-column:2; grid-row:4; }
  .cn-ping-run-controls { grid-column:2; grid-row:5; }
}
@media(max-width:600px) {
  .cn-ping-table { --cn-ping-target-width:185px; --cn-ping-icmp-width:140px; }
  .cn-ping-table .q-table th, .cn-ping-table .q-table td { padding:7px; }
}
"""


def render_ping(controller):
    from nicegui import ui
    from .subnets import render_subnets
    ui.add_css(PING_CSS)
    render_subnets(controller, lookup_type='ping')


def render_pager(key, title, page, pages, set_page, refresh, *, interaction_lock, results=False):
    """Render bounded page controls; all identifiers are local fixed strings."""
    from nicegui import ui
    nav_label = 'Ping result pages' if results else f'{title} pages'
    input_label = 'Result page' if results else f'{title} page'
    go_label = 'Go to result page' if results else f'Go to {title} page'

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


    with ui.element('nav').props(f'aria-label="{nav_label}"').classes('cn-ping-pager row items-center min-w-0 ' + ('grow' if results else 'w-full')) as nav:
        nav._props['data-cn-pager'] = key
        ui.label(f'Page {page + 1} of {pages}')
        names = [('First', 0, 'first', page > 0), ('Previous', page - 1, 'previous', page > 0),
                 ('Next', page + 1, 'next', page < pages - 1), ('Last', pages - 1, 'last', page < pages - 1)]
        for action, index, focus, enabled in names:
            label = f'{action} page' if results else f'{action} {title} page'
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


def render_ping_results(snapshot, table, view, refresh, interaction_lock, results_id, render_filter):
    from nicegui import ui
    if (snapshot.phase in {'running', 'stopping', 'saving'} or
            (snapshot.latest_attempt_id and snapshot.latest_attempt_id != snapshot.result_job_id)):
        ui.label('Previous Ping results').classes('text-weight-bold')
    result = snapshot.result
    if not result.get('icmp_available', True):
        ui.label('ICMP was not run; TCP results are shown below.').classes('cn-muted')
    if result.get('stopped'):
        ui.label('Stopped: only completed results are shown.').classes('text-weight-bold')
    rows = result.get('rows', [])
    if not rows:
        return
    groups = ping_groups(rows, result.get('icmp_available', True))

    async def select_group(name):
        client = ui.context.client
        async with interaction_lock:
            view.ping_group = name
            view.ping_page = 0
            await refresh()
            from .subnets import restore_result_focus
            await restore_result_focus(client, results_id, 'data-ping-group', name)

    with ui.element('div').classes('cn-ping-result-filters'):
        with ui.element('div').props('role=group aria-label="Filter Ping results by outcome"').classes('cn-ping-groups'):
            for name, count in [('All', len(rows)), *((name, len(group)) for name, group in groups.items())]:
                button = ui.button(f'{name} ({count})', on_click=lambda _, value=name: select_group(value)).props('outline dense')
                button._props['aria-pressed'] = 'true' if view.ping_group == name else 'false'
                button._props['aria-description'] = 'Count across all completed results.'
                button._props['data-ping-group'] = name
        field_filtered = render_filter(rows, 'ping')
    if view.ping_group == 'All':
        filtered = field_filtered
    else:
        from .subnets import filter_rows
        group = groups.get(view.ping_group, [])
        selected, text = view.filters.get('ping', ('', ''))
        filtered = filter_rows(group, selected, text)
    if not filtered:
        ui.label('No hosts match these filters. Select All or clear the field filter to see more results.').props('role=status')
        return
    from .subnets import order_rows
    sort = view.sorts.get('ping')
    if sort:
        filtered = order_rows(filtered, *sort)
    page_size = 50
    pages = (len(filtered) + page_size - 1) // page_size
    view.ping_page = min(view.ping_page, pages - 1)
    start = view.ping_page * page_size
    shown = filtered[start:start + page_size]
    with ui.element('div').classes('cn-ping-results-toolbar'):
        ui.label(f'Showing {start + 1}–{start + len(shown)} of {len(filtered)} results').props('role=status aria-live=polite')
        if pages > 1:
            render_pager('results', 'Results', view.ping_page, pages,
                         lambda value: setattr(view, 'ping_page', value), refresh, interaction_lock=interaction_lock, results=True)
    table(shown, table_id='ping', all_rows=rows)
