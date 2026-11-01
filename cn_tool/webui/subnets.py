"""Subnets presentation. Redraws and navigation never submit worker operations."""
from dataclasses import dataclass, field, replace
import asyncio
import json
from html import escape


@dataclass
class Presentation:
    selection: object = None
    result_identity: object = None
    summary_scroll: tuple = (0, 0, 0)
    return_selection: object = None
    ping_page: int = 0
    pagination: dict = field(default_factory=lambda: {"rowsPerPage": 25, "page": 1})

    def attach(self, result, operation_id=None):
        identity = tuple(group['id'] for group in result.get('detail_groups', []))
        result_identity = ("operation", operation_id) if operation_id is not None else identity
        changed = result_identity != self.result_identity if operation_id is not None else set(identity) != set(self.result_identity or ())
        if changed or self.result_identity is None:
            self.ping_page = 0
            self.pagination = {"rowsPerPage": 25, "page": 1}
            self.summary_scroll = (0, 0, 0)
            self.selection = identity[0] if len(identity) == 1 else None
        self.result_identity = result_identity

    def select(self, identity):
        self.selection = identity

    def new_lookup(self):
        if self.selection != 'input':
            self.return_selection = self.selection
        self.selection = 'input'

    def return_to_results(self):
        self.selection = self.return_selection

    def groups(self, result):
        return [group for group in result.get('detail_groups', [])
                if self.selection == 'all' or group['id'] == self.selection]


def outcome_display(snapshot):
    """Return escaped text for the worker's latest outcome, without classifying it."""
    outcome = snapshot.latest_outcome
    if not outcome:
        return None
    titles = {'matched': 'Networks matched', 'partial': 'Partial results',
              'no_match': 'No matching networks', 'invalid': 'Invalid input',
              'stopped': 'Lookup stopped', 'lookup_error': 'Lookup failed'}
    counts = [f"{outcome.get('matched_count', 0)} matched",
              f"{outcome.get('invalid_count', 0)} invalid",
              f"{outcome.get('resolution_error_count', 0)} lookup errors",
              f"{outcome.get('miss_count', 0)} unmatched",
              f"{outcome.get('warning_count', 0)} warnings"]
    detail = outcome.get('details') or {}
    container_count = detail.get('container_count', 0)
    if container_count:
        counts.append(f"{container_count} container{'s' if container_count != 1 else ''}")
        if outcome.get('kind') == 'matched' and not outcome.get('matched_count'):
            titles['matched'] = 'Containers found'
    lines = []
    input_aliases = detail.get('input_aliases') or {}
    def address_label(address):
        originals = list(dict.fromkeys(input_aliases.get(address) or []))
        if originals and any(original != address for original in originals):
            return f"{address} (inputs: {', '.join(originals)})"
        return address
    for key in ('invalid_inputs', 'resolution_errors', 'lookup_errors'):
        lines.extend(f'{item}: {problem}' for item, problem in (detail.get(key) or {}).items())
    misses = detail.get('misses') or []
    if isinstance(misses, dict):
        lines.extend(f'{item}: {reason}' for item, reason in misses.items())
    else:
        lines.extend(f'{item}: no matching network' for item in misses)
    lines.extend(f"{address_label(item.get('object', ''))}: {item.get('warning', '')}" if isinstance(item, dict) else str(item)
                 for item in (detail.get('warnings') or []))
    for key, label in [('cancelled_ips', 'incomplete'), ('unattempted_ips', 'not attempted'),
                       ('ptr_not_checked', 'PTR not checked')]:
        lines.extend(f'{address_label(item)}: {label}' for item in (detail.get(key) or []))
    return dict(title=escape(titles.get(outcome.get('kind'), 'Lookup outcome')),
                summary=escape(', '.join(counts)), message=escape(str(outcome.get('message') or '')),
                details=[escape(line) for line in lines])


def report_display(snapshot):
    """Render report state and its independent worker-owned availability."""
    state = snapshot.latest_report_state or {}
    status = state.get('state')
    label = {'off': 'Reporting off', 'idle': 'No report saved', 'failed': 'Report save failed',
             'saved': 'Report saved', 'saving': 'Saving report', 'pending': 'Report pending'}.get(status, '')
    message = state.get('message') or ''
    text = label + (f'. {message}' if message else '')
    available = (snapshot.report_state or state).get('available') is True
    if available and not state.get('saved_for_attempt'):
        text += ('. ' if text else '') + 'The accumulated report contains earlier data.'
    return dict(text=escape(text), available=available, failed=status == 'failed')


CSS = '''
body { background:#F5F7FA; color:#172B3A; font:15px system-ui,sans-serif; }
.nicegui-content { max-width:1440px; margin:auto; padding:24px 28px; gap:18px; }
h1 { font-size:30px; line-height:1.2; font-weight:650; margin:0; }
h2 { font-size:21px; line-height:1.35; font-weight:650; margin:14px 0 8px; }
h3 { font-size:17px; font-weight:600; margin:12px 0 6px; }
.cn-panel { background:white; border:1px solid #CBD5DF; border-radius:6px; padding:20px; width:100%; }
.cn-muted { color:#526675; max-width:78ch; }
.cn-table { width:100%; overflow-x:auto; border:1px solid #CBD5DF; border-radius:4px; }
.cn-table th { background:#EDF2F6; color:#172B3A; font-weight:650; }
.cn-table td { white-space:normal; min-width:100px; max-width:420px; overflow-wrap:anywhere; }
.cn-table .q-table { min-width:650px; }
.cn-table .q-table__middle { overflow:visible; }
.cn-network { font-family:ui-monospace,monospace; }
.cn-summary-network { font-weight:650; }
.cn-summary-status { background:#EDF2F6; color:#172B3A; font-weight:600; padding:2px 6px; border-radius:3px; }
:focus-visible { outline:3px solid #145C87; outline-offset:3px; }
.q-btn { text-transform:none; font-weight:600; }
/* Keep the icon ligature inside its box while the Material Icons font loads. */
.q-expansion-item__toggle-icon.material-icons { overflow:hidden; }
.cn-sr-only { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }
.cn-compact-summary { display:none; }
.cn-summary-row { min-width:0; width:100%; border:1px solid #CBD5DF; border-radius:4px; padding:12px; overflow-wrap:anywhere; }
@media(max-width:600px) { .nicegui-content {padding:16px 12px;} .cn-panel {padding:14px;}
.cn-desktop-summary {display:none !important;} .cn-compact-summary {display:flex;} }
'''


LOOKUP_CSS = '''
.nicegui-content:has(.cn-lookup-form) { gap:12px; }
.cn-lookup-empty:empty { display:none; }
.cn-lookup-form, .cn-lookup-outcome { gap:8px; }
.cn-lookup-outcome h2 { margin-top:0; }
.cn-lookup-table { min-width:0; max-width:100%; max-height:min(65vh,620px); overflow:auto; --cn-lookup-target-width:280px; --cn-lookup-status-width:140px; }
.cn-lookup-table .q-table th { position:sticky; top:0; z-index:1; }
.cn-lookup-table .q-table th, .cn-lookup-table .q-table td { padding:7px 10px; height:auto; font-size:14px; vertical-align:middle; }
.cn-lookup-table .q-table td { overflow-wrap:anywhere; font-variant-numeric:tabular-nums; }
.cn-lookup-table .q-table__bottom { position:sticky; bottom:0; left:0; background:white; z-index:1; }
.cn-lookup-table .q-table__control { flex-wrap:wrap; max-width:100%; }
.cn-lookup-table .q-table__bottom { flex-wrap:wrap; height:auto; min-height:48px; gap:4px; }
.cn-lookup-primary .q-table { table-layout:fixed; min-width:calc(var(--cn-lookup-target-width) + var(--cn-lookup-status-width) + var(--cn-lookup-extra-columns) * 160px); }
.cn-lookup-primary td:first-child { font-family:ui-monospace,monospace; font-weight:600; }
.cn-lookup-primary td:nth-child(2) { font-weight:600; }
@media(max-width:600px) {
  .cn-lookup-table { --cn-lookup-target-width:185px; --cn-lookup-status-width:125px; }
  .cn-lookup-table .q-table th, .cn-lookup-table .q-table td { padding:7px; }
}
'''


def render_subnets(controller, lookup_type='subnet'):
    from nicegui import ui
    from cn_tool.core.interaction import CredentialReply

    ui.add_css(CSS)
    if lookup_type != 'ping':
        ui.add_css(LOOKUP_CSS)
    empty_class = ' cn-ping-empty' if lookup_type == 'ping' else ' cn-lookup-empty'
    ui.colors(primary='#145C87')
    view = Presentation()
    prompt_lock = asyncio.Lock()
    poll_lock = asyncio.Lock()
    latest = {'snapshot': None, 'prompt': None, 'download': None, 'download_error': '', 'dialog': None}
    with ui.row().classes('w-full items-center justify-between'):
        ui.label({'ip': 'IP', 'ping': 'Ping'}.get(lookup_type, 'Subnets')).mark('title').classes('text-h4')
        quit_button = ui.button('Quit application', on_click=controller.quit).props('outline')
    with ui.element('nav').props('aria-label=Tools').classes('row items-center gap-4'):
        ui.link('Subnets', '/').props('aria-current=page' if lookup_type == 'subnet' else '')
        ui.link('IP', '/ip').props('aria-current=page' if lookup_type == 'ip' else '')
        ui.link('Ping', '/ping').props('aria-current=page' if lookup_type == 'ping' else '')
        ui.link('Monitor', '/monitor')
        ui.link('Configuration Search', '/config-search')
        ui.link('Site Demobilization', '/demobilization')
    scope_label = ui.label('Attaching to the application…').classes('cn-muted')
    with ui.row().classes('items-center') as credentials_row:
        forget = ui.button('Forget saved credentials', on_click=controller.forget_credentials).props('outline')
        store_status = ui.label('').props('role=status aria-live=polite').classes('cn-muted' + empty_class)
    recovery = ui.label('If saved credentials are refused, forget them and run the lookup again to enter a different login.').classes('cn-muted text-sm')
    recovery.set_visibility(False)
    exit_help = 'Closing this tab keeps the application running. Quit finishes active work and saves, then runs configured exit actions.'
    quit_button.tooltip(exit_help)
    quit_button._props['aria-description'] = exit_help
    status = ui.label('Attaching…').props('role=status aria-live=polite')
    report_warning = ui.label('').props('role=status').classes('text-warning' + empty_class)
    elapsed = ui.label('').classes('cn-muted' + empty_class)
    with ui.column().classes('cn-panel cn-ping-form' if lookup_type == 'ping' else 'cn-panel cn-lookup-form'):
        ui.label('Targets').classes('cn-ping-target-label')
        target_props = 'outlined rows=3 aria-label=Targets'
        targets = ui.textarea(placeholder='192.0.2.1\n2001:db8::1' if lookup_type == 'ip' else '192.0.2.1\n2001:db8::/64').props(target_props).classes('w-full cn-ping-targets')
        ui.label({'ip': 'One IP address per line', 'ping': 'One IP address, hostname or subnet per line. Hostnames use system DNS.'}.get(lookup_type, 'One IP address or subnet per line')).classes('cn-muted cn-ping-target-help')
        ports = ui.input('TCP ports', placeholder='22, 443').props('outlined dense aria-label="TCP ports"').classes('w-full cn-ping-ports') if lookup_type == 'ping' else None
        if ports:
            ui.label('Optional: up to five comma-separated ports. ICMP is used when available.').classes('cn-muted cn-ping-port-help')
        port_error = ui.label('').props('role=alert').classes('text-negative cn-ping-port-error' + empty_class)
        with ui.row().classes('cn-ping-run-controls'):
            async def submit():
                if lookup_type == 'ping':
                    from .ping import parse_ports
                    try:
                        parsed = parse_ports(ports.value or '')
                    except ValueError as exc:
                        port_error.set_text(str(exc))
                        return
                    port_error.set_text('')
                    controller.submit(targets.value.splitlines(), lookup_type=lookup_type, tcp_ports=parsed)
                else:
                    controller.submit(targets.value.splitlines(), lookup_type=lookup_type)
                await refresh_now()
            run = ui.button('Run Ping' if lookup_type == 'ping' else 'Look up', on_click=submit)
            stop = ui.button('Stop', on_click=controller.cancel_active).props('outline')
            async def jump_to_results():
                if lookup_type == 'subnet' and view.selection == 'input':
                    view.return_to_results()
                    await draw_results.refresh()
                ui.run_javascript(f'document.getElementById({json.dumps(results.html_id)})?.focus()')
            show_results = ui.button('View results', on_click=jump_to_results).props('outline')
            show_results.set_visibility(False)
    @ui.refreshable
    def draw_outcome():
        snapshot = latest.get('displayed_outcome_snapshot') if lookup_type == 'ping' else latest['snapshot']
        if lookup_type == 'ping':
            from .ping import format_diagnostic, ping_outcome_display, render_pager
            outcome = ping_outcome_display(snapshot, {'result': latest.get('displayed_outcome_result')},
                                           format_entries=False) if snapshot else None
            if outcome:
                with ui.element('h2').props('tabindex=-1') as heading:
                    ui.label(outcome['title'])
                latest['outcome_heading'] = heading.html_id
                message = outcome['message'].strip()
                if message.casefold().removeprefix('ping ').rstrip('. ') == outcome['title'].casefold().removeprefix('ping ').rstrip('. '):
                    message = ''
                if message and not message.endswith(('.', '!', '?')):
                    message += '.'
                ui.label(' '.join(part for part in (message, outcome['summary']) if part)).props('role=status aria-live=polite')
                for key, title in [('input_errors', 'Invalid inputs'), ('resolution_errors', 'DNS errors'), ('incomplete', 'Attempted but incomplete'), ('unattempted', 'Not attempted')]:
                    if outcome[key]:
                        entries = outcome[key]
                        pages = (len(entries) + 49) // 50
                        current = min(latest['diagnostic_pages'].get(key, 0), pages - 1)
                        start = current * 50
                        shown = entries[start:start + 50]
                        with ui.element('section').classes('w-full') as section:
                            section._props['aria-label'] = title
                            expanded = latest['diagnostic_expanded'].get(key,
                                not bool((snapshot.latest_outcome or {}).get('matched_count')))
                            with ui.expansion(f'{title} ({len(entries)})', value=expanded,
                                    on_value_change=lambda event, category=key: latest['diagnostic_expanded'].__setitem__(category, event.value)
                                    ).classes('cn-ping-diagnostics').props('dense header-class=text-weight-bold'):
                                ui.label(f'Showing {start + 1}–{start + len(shown)} of {len(entries)}')
                                if pages > 1:
                                    render_pager(key, title, current, pages,
                                                 lambda value, category=key: latest['diagnostic_pages'].__setitem__(category, value),
                                                 draw_outcome.refresh, interaction_lock=poll_lock)
                                with ui.element('ul'):
                                    for item in shown:
                                        with ui.element('li'):
                                            ui.label(format_diagnostic(key, item))
            return
        outcome = outcome_display(snapshot) if snapshot else None
        if outcome and lookup_type == 'ip':
            outcome['title'] = {'Networks matched': 'Addresses matched', 'No matching networks': 'No matching addresses'}.get(outcome['title'], outcome['title'])
        if outcome:
            with ui.element('h2').props('tabindex=-1') as heading:
                ui.html(outcome['title'])
            latest['outcome_heading'] = heading.html_id
            ui.html(outcome['message'] + (' ' if outcome['message'] else '') + outcome['summary']).props('role=status aria-live=polite')
            if outcome['details']:
                with ui.expansion('Latest attempt diagnostics').classes('w-full'):
                    for line in outcome['details']:
                        ui.html(line)

    with ui.column().classes('cn-panel cn-outcome-report' + (' cn-ping-outcome' if lookup_type == 'ping' else ' cn-lookup-outcome')):
        with ui.column().classes('w-full') as outcome_area:
            draw_outcome()
        announcement = ui.html('').props('role=status aria-live=polite').classes('cn-sr-only')
        report = ui.html('').props('role=status aria-live=polite').classes('cn-muted' + empty_class)
        download_help = 'Download copies the existing accumulated report after pending saves finish. A failed lookup save may leave only earlier data.'
        download = ui.button('Download accumulated report', on_click=lambda: request_download()).props('outline')
        download.tooltip(download_help)
        download._props['aria-description'] = download_help
    pending_results = ui.label('').classes('cn-muted' + empty_class)
    results = ui.column().classes('w-full')
    results.props('tabindex=-1')

    def request_download():
        if latest['download'] is None:
            latest['download_error'] = ''
            download.disable()
            try:
                latest['download'] = controller.request_report_snapshot()
            except (RuntimeError, OSError, EOFError):
                latest['download_error'] = 'Report download is unavailable.'
                report.set_content(latest['download_error'])
                return
            report.set_content('Preparing a consistent report download…')

    def table(rows, *, summary=False):
        if not rows:
            ui.label('No rows.').classes('cn-muted')
            return
        keys = list(dict.fromkeys(key for row in rows for key in row if key not in {'id', '__row'}))
        if lookup_type == 'ping':
            leading = [key for key in ['Host', 'Result', *(key for key in keys if key.startswith('TCP ')), 'Address'] if key in keys]
            keys = leading + [key for key in keys if key not in leading]
        elif lookup_type == 'ip' or summary:
            identity_key = 'IP' if lookup_type == 'ip' else 'Resolved Subnet'
            leading = [key for key in (identity_key, 'Status', 'Network view') if key in keys]
            keys = leading + [key for key in keys if key not in leading]
        columns = [dict(name=key, label={'Host': 'Target', 'Result': 'ICMP result'}.get(key, key) if lookup_type == 'ping' else key,
                        field=key, align='left', sortable=lookup_type != 'ping') for key in keys]
        if lookup_type == 'ping':
            for column in columns:
                width = {'Host': 'var(--cn-ping-target-width)', 'Result': 'var(--cn-ping-icmp-width)'}.get(column['name'], '150px')
                column['headerStyle'] = f'width:{width}'
        if summary:
            columns.insert(min(3, len(columns)), dict(name='action', label='Details', field='id', align='left'))
        if lookup_type == 'ip' or summary:
            for column in columns:
                width = {identity_key: 'var(--cn-lookup-target-width)', 'Status': 'var(--cn-lookup-status-width)'}.get(column['name'], '160px')
                column['headerStyle'] = f'width:{width}'
        display_rows = [{key: str(value) if isinstance(value, (dict, list, tuple)) else value for key, value in row.items()} for row in rows]
        if summary and 'Resolved Subnet' in keys:
            columns[0]['label'] = 'Network / target'
            for row in display_rows:
                row['Resolved Subnet'] = row.get('Resolved Subnet') or row.get('Original Input(s)') or row.get('Original Input') or ''
        with ui.column().classes('w-full'):
            desktop_table(display_rows, columns, summary)

    def desktop_table(display_rows, columns, summary):
        rows = display_rows
        ui.label('Scroll the table horizontally to see all columns' + (' and View details.' if summary else '.')).classes('cn-muted text-sm')
        widget = ui.table(columns=columns, rows=[dict(row, __row=row.get('__row', row.get('id', f'row-{index}'))) for index, row in enumerate(display_rows)], row_key='__row',
                          pagination=view.pagination if summary else (0 if lookup_type == 'ping' else 25),
                          on_pagination_change=(lambda event: setattr(view, 'pagination', event.value)) if summary else None).classes('cn-table').props('flat bordered wrap-cells')
        table_name = {'ip': 'IP', 'ping': 'Ping'}.get(lookup_type, 'Subnet')
        widget.props(f'role=region tabindex=0 aria-label="{table_name} result table"')
        if lookup_type == 'ping':
            widget.props('hide-bottom dense').classes('cn-ping-table').style(f'--cn-ping-extra-columns:{max(0, len(columns) - 2)}')
        else:
            widget.props('dense').classes('cn-lookup-table')
            if summary or lookup_type == 'ip':
                widget.classes('cn-lookup-primary').style(f'--cn-lookup-extra-columns:{max(0, len(columns) - 2)}')
        if lookup_type != 'ping':
            ui.label(f'{len(rows)} ' + ('row' if len(rows) == 1 else 'rows')).classes('cn-muted text-sm')
        if summary:
            latest['summary_table'] = widget.html_id
            widget.add_slot('body-cell-action', '''<q-td :props="props"><q-btn v-if="props.row.id" flat dense color="primary" label="View details" :data-detail-id="props.row.id" :aria-label="'View details for ' + [props.row['Resolved Subnet'] || props.row.Network || props.row['Original Input(s)'], props.row['Network view'] || props.row.View].filter(Boolean).join(', ')" @click="$parent.$emit('details', props.row.id)" /></q-td>''')
            widget.on('details', lambda event: navigate(event.args))

    async def navigate(identity):
        client = ui.context.client
        if view.selection is None and latest.get('summary_table'):
            table_id = json.dumps(latest['summary_table'])
            view.summary_scroll = await client.run_javascript(f'[window.scrollY, document.getElementById({table_id})?.scrollLeft || 0, document.getElementById({table_id})?.scrollTop || 0]')
            latest['summary_origin'] = identity
        view.select(identity)
        await draw_results.refresh()
        if identity is not None:
            heading_id = json.dumps(latest.get('detail_heading'))
            client.run_javascript(f'document.getElementById({heading_id})?.focus()')
        if identity is None and latest.get('summary_table'):
            table_id = json.dumps(latest['summary_table'])
            vertical, horizontal, table_vertical = view.summary_scroll
            origin = json.dumps(latest.get('summary_origin'))
            # NiceGUI can remount QTable's slotted buttons in a later update.
            # Preserve the requested focus through those mounts, until the user acts.
            client.run_javascript(f'''(() => {{
const root = document.getElementById({json.dumps(results.html_id)});
root?.cnRestoreFocus?.();
if (!root || (document.activeElement !== document.body && !root.contains(document.activeElement))) return;
let target = null;
const stop = () => {{ observer.disconnect(); for (const event of ['pointerdown', 'keydown', 'wheel']) document.removeEventListener(event, stop, true); document.removeEventListener('focusin', moved, true); delete root.cnRestoreFocus; }};
const moved = event => {{ if (event.target !== target) stop(); }};
const restore = () => {{
  const table = document.getElementById({table_id});
  if (!table) {{ stop(); return; }}
  if (target?.isConnected && document.activeElement === target) return;
  if (document.activeElement !== document.body && document.activeElement !== target) {{ stop(); return; }}
  target = [...root.querySelectorAll('[data-detail-id]')].find(el => el.dataset.detailId === {origin} && el.getClientRects().length);
  target?.focus({{preventScroll:true}});
  window.scrollTo(0, {int(vertical)});
  table.scrollLeft = {int(horizontal)};
  table.scrollTop = {int(table_vertical)};
}};
const observer = new MutationObserver(restore);
root.cnRestoreFocus = stop;
observer.observe(root, {{childList:true, subtree:true}});
for (const event of ['pointerdown', 'keydown', 'wheel']) document.addEventListener(event, stop, {{capture:true, passive:true}});
document.addEventListener('focusin', moved, true);
restore();
}})();''')

    async def new_lookup():
        latest['lookup_scroll'] = await ui.context.client.run_javascript('window.scrollY')
        if view.selection is None and latest.get('summary_table'):
            table_id = json.dumps(latest['summary_table'])
            view.summary_scroll = await ui.context.client.run_javascript(f'[window.scrollY, document.getElementById({table_id})?.scrollLeft || 0, document.getElementById({table_id})?.scrollTop || 0]')
        view.new_lookup()
        draw_results.refresh()
        targets.run_method('focus')

    async def return_results():
        view.return_to_results()
        await draw_results.refresh()
        button_id = json.dumps(latest.get('new_lookup_button'))
        vertical = int(latest.get('lookup_scroll', 0))
        if view.selection is None and latest.get('summary_table'):
            _, horizontal, table_vertical = view.summary_scroll
            table_id = json.dumps(latest['summary_table'])
            ui.run_javascript(f'requestAnimationFrame(() => {{ document.getElementById({button_id})?.focus({{preventScroll:true}}); window.scrollTo(0, {vertical}); const table = document.getElementById({table_id}); if(table) {{ table.scrollLeft = {int(horizontal)}; table.scrollTop = {int(table_vertical)}; }} }});')
        else:
            ui.run_javascript(f'document.getElementById({button_id})?.focus({{preventScroll:true}}); window.scrollTo(0, {vertical});')

    @ui.refreshable
    def draw_results():
        snapshot = latest.get('displayed_snapshot')
        if snapshot is None:
            return
        if snapshot.result is None:
            return
        result = snapshot.result
        if lookup_type == 'ping':
            from .ping import render_ping_results
            render_ping_results(snapshot, table, view, draw_results.refresh, poll_lock)
            return
        if lookup_type == 'ip':
            from .ip import render_ip_results
            render_ip_results(snapshot, table)
            return
        latest['detail_heading_set'] = False
        groups = result.get('detail_groups', [])
        if snapshot.phase in {'running', 'stopping', 'saving'} or (snapshot.latest_attempt_id and snapshot.latest_attempt_id != snapshot.result_job_id):
            ui.label('Previous lookup results').classes('text-weight-bold')
        if view.selection == 'input':
            ui.button('Return to results', on_click=return_results).props('outline')
            return
        with ui.row().classes('items-center'):
            if view.selection is not None and len(groups) > 1:
                ui.button('Back to summary', on_click=lambda: navigate(None)).props('outline')
            if len(groups) > 1 and view.selection is None:
                show_all = ui.button('Show all details', on_click=lambda: navigate('all'))
                show_all._props['data-detail-id'] = 'all'
            new_lookup_button = ui.button('New lookup', on_click=new_lookup).props('outline')
            latest['new_lookup_button'] = new_lookup_button.html_id
        if not groups:
            ui.label('No matching networks.').classes('text-weight-bold')
        if result.get('containers'):
            with ui.element('nav').props('aria-label="Additional result sections"'):
                ui.link(f"Child containers ({len(result['containers'])})", '#child-containers')
        if view.selection is None and len(groups) > 1:
            with ui.element('h2').props('tabindex=-1') as summary_heading:
                ui.label(f'{len(groups)} networks').classes('text-h6')
            latest['summary_heading'] = summary_heading.html_id
            table(result.get('summary', []), summary=True)
        else:
            for group in view.groups(result):
                with ui.column().classes('cn-panel'):
                    with ui.element('h2').props('tabindex=-1').classes('cn-network') as detail_heading:
                        identity = ', '.join(str(value) for value in (group['network'], group.get('network_view')) if value)
                        ui.label(identity)
                    if not latest['detail_heading_set']:
                        latest['detail_heading'] = detail_heading.html_id
                        latest['detail_heading_set'] = True
                    if group.get('network_view'):
                        ui.label('View: ' + str(group['network_view'])).classes('cn-muted')
                    ui.label('Inputs: ' + ', '.join(group.get('original_inputs', [])))
                    for warning in group.get('warnings', []):
                        ui.label(str(warning)).classes('text-negative')
                    sections = list(group.get('tables', {}).items())
                    section_ids = [f'section-{detail_heading.id}-{index}' for index in range(len(sections))]
                    with ui.element('nav').classes('w-full') as section_index:
                        section_index._props['aria-label'] = f'Detail sections for {identity}'
                        for (name, rows), section_id in zip(sections, section_ids):
                            ui.link(f'{name} ({len(rows)})', f'#{section_id}').classes('q-mr-md')
                    for (name, rows), section_id in zip(sections, section_ids):
                        with ui.element('section').props(f'id={section_id}').classes('w-full'):
                            if rows:
                                with ui.element('h3'):
                                    ui.label(f'{name} ({len(rows)})')
                                table(rows)
                            else:
                                with ui.expansion(f'{name} (0)').classes('w-full'):
                                    table(rows)
        if result.get('containers'):
            containers = result['containers']
            with ui.element('section').props('id=child-containers').classes('w-full'):
                with ui.element('h2'):
                    ui.label(f'Child containers ({len(containers)})')
                table(containers)

    with results:
        draw_results()

    def restore_credential_focus(client):
        retry_id, targets_id, forget_id = map(json.dumps, (retry.html_id, targets.html_id, forget.html_id))
        client.run_javascript(f'''(() => {{
const valid = el => el && el.isConnected && el.matches('button, input, textarea, select, a[href], [tabindex]:not([tabindex="-1"])') && !el.matches(':disabled') && !el.closest('[disabled], [aria-disabled="true"]') && el.getClientRects().length > 0;
const retry = document.getElementById({retry_id});
const targets = document.getElementById({targets_id})?.querySelector('textarea');
const forget = document.getElementById({forget_id});
const target = [window.cnCredentialInvoker, retry, targets, forget].find(valid);
target?.focus({{preventScroll:true}}); window.cnCredentialInvoker = null;
}})()''')

    def current_credential_request():
        return controller.current_credential_request()

    async def clear_credentials(*, restore=True):
        active = latest['dialog']
        latest['dialog'] = None
        latest['dialog_status'] = None
        if active is None:
            return
        dialog, username_id, password_id = active
        client = dialog.client
        try:
            # Await clearing before removing controls so detached DOM nodes do not
            # retain typed secrets when a different tab answers the same request.
            await dialog.client.run_javascript(
                'for (const id of ' + json.dumps([username_id, password_id]) + ') {'
                'const field = document.getElementById(id); if (field) field.value = ""; }')
        finally:
            dialog.close()
            dialog.delete()
            if restore:
                restore_credential_focus(client)

    async def credentials(request):
        await ui.context.client.run_javascript('(() => { window.cnCredentialInvoker = document.activeElement; return true; })()')
        current = current_credential_request()
        if not current or current['request_id'] != request['request_id']:
            return False
        with ui.dialog().props('persistent') as dialog, ui.card().classes('w-full max-w-md'):
            ui.label(f"Credentials: {request['account']}").classes('text-h6')
            ui.label(request.get('message', ''))
            latest['dialog_status'] = ui.label('').props('role=status aria-live=polite').classes('cn-muted')
            username_id = f"credential-username-{dialog.id}"
            password_id = f"credential-password-{dialog.id}"
            remember_id = f"credential-remember-{dialog.id}"
            latest["dialog"] = (dialog, username_id, password_id)
            username = escape(request.get('username', ''), quote=True)
            readonly = '' if request.get('need_username', False) else 'readonly'
            fields = (f'<label for="{username_id}">Username</label>'
                      f'<input id="{username_id}" aria-label="Username" autocomplete="off" '
                      f'class="w-full border rounded p-2" value="{username}" {readonly}>')
            if request.get('need_password', True):
                fields += (f'<label for="{password_id}">Password</label>'
                           f'<input id="{password_id}" aria-label="Password" type="password" '
                           'autocomplete="off" class="w-full border rounded p-2">')
            if request.get('need_password') and request.get('store_supported'):
                fields += (f'<label><input id="{remember_id}" type="checkbox"> '
                           'Remember credentials on this computer</label>')
            # Fixed local markup, with the configured username escaped above. Vue must
            # not bind these input values: unrelated status updates must not reset them.
            ui.html(fields, sanitize=False).classes('w-full flex flex-col gap-2')
            async def reply(event):
                values = event.args
                answer = None if values['cancel'] else CredentialReply(values['username'], values['password'])
                async with prompt_lock:
                    if latest['dialog'] and latest['dialog'][0] is dialog:
                        await clear_credentials(restore=False)
                        latest['prompt'] = None
                    current = current_credential_request()
                    if current and current['request_id'] == request['request_id']:
                        controller.reply_credentials(request['request_id'], answer, remember=values['remember'])
                await refresh_now()
                if latest['dialog'] is None:
                    restore_credential_focus(dialog.client)
            def handler(cancel):
                # Native input elements have no value binding or input history on the server.
                # Capture only on explicit Continue, and clear before emitting the reply.
                return """() => {
const u = document.getElementById(USERNAME_ID);
const p = document.getElementById(PASSWORD_ID);
const r = document.getElementById(REMEMBER_ID);
const reply = {cancel: CANCEL, username: CANCEL ? '' : u.value, password: CANCEL ? '' : (p?.value || ''), remember: !CANCEL && !!r?.checked};
u.value = ''; if (p) p.value = ''; emit(reply);
}""".replace('CANCEL', json.dumps(cancel)).replace('USERNAME_ID', json.dumps(username_id)).replace('PASSWORD_ID', json.dumps(password_id)).replace('REMEMBER_ID', json.dumps(remember_id))
            with ui.row():
                ui.button('Continue').on('click', reply, js_handler=handler(False))
                ui.button('Cancel').props('outline').on('click', reply, js_handler=handler(True))
                dialog.on('keydown.escape', reply, js_handler=handler(True))
                ui.button('Forget saved credentials', on_click=controller.forget_credentials).props('outline')
        dialog.open()
        focus_id = username_id if request.get('need_username', False) else password_id
        ui.run_javascript(f'requestAnimationFrame(() => document.getElementById({json.dumps(focus_id)})?.focus())')
        return True

    async def poll_once():
        page = controller.page_snapshot(lookup_type, result_revision=latest.get('result_revision'),
                                        attempt_revision=latest.get('attempt_revision'))
        if page.result_changed:
            latest['received_result'] = page.result
            latest['result_revision'] = page.result_revision
        if page.attempt_changed:
            latest['received_outcome'] = page.outcome
            latest['received_attempt_result'] = page.attempt_result
            latest['attempt_revision'] = page.attempt_revision
        attempt = {'result': latest.get('received_attempt_result')}
        snapshot = replace(page.state, result=latest.get('received_result'), result_job_id=page.result_job_id,
                           latest_attempt_id=page.attempt_job_id, latest_outcome=latest.get('received_outcome'),
                           latest_report_state=page.attempt_report_state)
        latest['snapshot'] = snapshot
        scope_label.set_text('Ping uses system DNS and does not require Infoblox.' if lookup_type == 'ping' else
                             f"{snapshot.scope or 'Configured scope pending'} | Account: {snapshot.username or 'pending'}")
        report_warning.set_text(snapshot.report_warning)
        busy = snapshot.phase in {'running', 'stopping', 'saving', 'closing'}
        run.set_enabled(snapshot.phase == 'ready' and not snapshot.active_job_id and bool((targets.value or '').strip()))
        stop.set_visibility(snapshot.phase in {'running', 'stopping', 'saving'})
        stop.set_enabled(snapshot.phase == 'running')
        quit_button.set_enabled(snapshot.phase not in {'closing', 'closed'})
        forget.set_enabled(snapshot.phase not in {'closing', 'closed', 'failed'})
        storage = snapshot.credential_store or {}
        store_status.set_text(storage.get('message', ''))
        if lookup_type == 'ping':
            credentials_row.set_visibility(bool(snapshot.saved_login_restored or storage.get('message')))
        show_results.set_visibility(bool((snapshot.result or {}).get('rows') or (snapshot.result or {}).get('detail_groups')))
        recovery.set_visibility(snapshot.saved_login_restored)
        if latest.get('dialog_status') is not None:
            latest['dialog_status'].set_text(storage.get('message', ''))
        phase_messages = {'starting': 'Checking configuration and credentials…', 'ready': 'Ready',
                   'setup_required': 'Setup required.',
                   'failed': 'Application failed. Quit and relaunch to start a new session.',
                   'closing': 'Finishing active work and configured exit actions…', 'closed': 'Application closed.',
                   'stopping': 'Stopping…', 'saving': 'Saving report…'}
        message = (snapshot.progress_stage or 'Working…') if snapshot.phase == 'running' else phase_messages.get(snapshot.phase, snapshot.phase)
        if snapshot.phase == 'running' and snapshot.progress_completed is not None:
            message += f' ({snapshot.progress_completed} of {snapshot.progress_total} completed)'
        if snapshot.phase == 'stopping' and snapshot.active_lookup_type == 'ping':
            message += ' Waiting for active DNS and probes to finish.'
        if snapshot.error:
            message = snapshot.error.get('message', str(snapshot.error)) if isinstance(snapshot.error, dict) else str(snapshot.error)
        if snapshot.active_job_id and snapshot.active_lookup_type:
            message = f"{ {'ip': 'IP lookup', 'ping': 'Ping', 'subnet': 'Subnets lookup'}.get(snapshot.active_lookup_type, 'Working') }: {message}"
        status.set_text(message)
        elapsed.set_text(f'Elapsed: {int(snapshot.elapsed_seconds)}s' if busy else '')
        retry.set_visibility(snapshot.phase == 'setup_required')
        recovery_help.set_visibility(snapshot.phase == 'setup_required')
        display = report_display(snapshot)
        report.classes(remove='text-negative')
        if display['failed']:
            report.classes(add='text-negative')
        report.set_content(display['text'])
        download.set_enabled(display['available'] and latest['download'] is None)
        if latest['download'] is not None:
            report.set_content('Preparing a consistent report download…')
        elif latest['download_error']:
            report.set_content(escape(latest['download_error']))
        prepared = controller.report_completion(latest['download']) or {} if latest['download'] else {}
        if prepared.get('request_id') == latest['download']:
            if prepared.get('status') == 'ready':
                ui.download('/download/' + latest['download'])
                latest['download'] = None
            elif prepared.get('status') == 'failed':
                latest['download_error'] = prepared.get('error', 'Report download failed.')
                report.set_content(escape(latest['download_error']))
                controller.acknowledge_report_completion(latest['download'])
                latest['download'] = None
        async with prompt_lock:
            request = current_credential_request()
            request_id = request['request_id'] if request else None
            if request_id != latest['prompt']:
                await clear_credentials()
                latest['prompt'] = None
                request = current_credential_request()
                if request and await credentials(request):
                    latest['prompt'] = request['request_id']
        async def focused_inside(container):
            client = ui.context.client
            if not client.has_socket_connection:
                return False
            try:
                return await client.run_javascript(f'''(() => {{
const active = document.activeElement;
const interactive = 'input, textarea, select, button, a[href], [contenteditable]:not([contenteditable="false"]), [tabindex]:not([tabindex="-1"]), [role="button"]';
return !!(active?.closest(interactive) && document.getElementById({json.dumps(container.html_id)})?.contains(active));
}})()''', timeout=1)
            except TimeoutError:
                return False

        outcome_fingerprint = page.attempt_revision
        if outcome_fingerprint != latest.get('outcome_fingerprint'):
            if latest.get('outcome_fingerprint') is not None and await focused_inside(outcome_area):
                if outcome_fingerprint != latest.get('announced_outcome'):
                    if lookup_type == 'ping':
                        from .ping import ping_outcome_display
                        display_outcome = ping_outcome_display(snapshot, attempt, format_entries=False)
                    else:
                        display_outcome = outcome_display(snapshot)
                    if display_outcome:
                        announced = display_outcome['title'] + '. ' + display_outcome['message'] + ' ' + display_outcome['summary']
                        announcement.set_content(escape(announced) if lookup_type == 'ping' else announced)
                    else:
                        announcement.set_content('')
                    latest['announced_outcome'] = outcome_fingerprint
            else:
                latest['outcome_fingerprint'] = outcome_fingerprint
                announcement.set_content('')
                if lookup_type == 'ping':
                    latest['displayed_outcome_snapshot'] = snapshot
                    latest['displayed_outcome_result'] = latest.get('received_attempt_result')
                    latest['diagnostic_pages'] = {}
                    latest['diagnostic_expanded'] = {}
                await draw_outcome.refresh()
                if snapshot.latest_outcome and snapshot.latest_attempt_id != latest.get('focused_attempt'):
                    latest['focused_attempt'] = snapshot.latest_attempt_id
                    heading_id = json.dumps(latest.get('outcome_heading'))
                    ui.run_javascript(f'''(() => {{
const active = document.activeElement;
const interactive = 'input, textarea, select, button, a[href], [contenteditable]:not([contenteditable="false"]), [tabindex]:not([tabindex="-1"]), [role="button"]';
if (!active?.closest(interactive)) document.getElementById({heading_id})?.focus();
}})()''')
        previous = bool(snapshot.result is not None and (
            (lookup_type in {'subnet', 'ping'} and snapshot.phase in {'running', 'stopping', 'saving'}) or
            (snapshot.latest_attempt_id and snapshot.latest_attempt_id != snapshot.result_job_id)))
        results_fingerprint = (page.result_revision, previous)
        if results_fingerprint != latest.get('results_fingerprint'):
            if latest.get('results_fingerprint') is not None and await focused_inside(results):
                pending_results.set_text('New results are available. Move focus away from the current results to update them.')
            else:
                latest['results_fingerprint'] = results_fingerprint
                pending_results.set_text('')
                latest['displayed_snapshot'] = snapshot
                if snapshot.result is not None:
                    view.attach(snapshot.result, snapshot.result_job_id)
                await draw_results.refresh()

    async def refresh_now():
        async with poll_lock:
            await poll_once()

    async def poll():
        if poll_lock.locked():
            return
        await refresh_now()

    recovery_help = ui.label('Retry setup retries credentials. If you edit .cn, quit and relaunch to load the changes.').classes('cn-muted text-sm')
    retry = ui.button('Retry setup', on_click=controller.retry_initialize).props('outline')
    targets.disable()
    targets.on_value_change(lambda _: poll())
    async def restore_draft():
        client = ui.context.client
        if client.is_deleted:
            return
        element_id = json.dumps(targets.html_id)
        key = json.dumps('cn-tool-draft-' + lookup_type)
        install = f'''const root = document.getElementById({element_id});
const input = root?.matches('textarea') ? root : root?.querySelector('textarea');
if (!input) return false;
if (!input.cnDraftListener) {{
    input.cnDraftListener = true;
    input.addEventListener('input', () => {{
        input.cnDraftEdited = true;
        sessionStorage.setItem({key}, input.value);
    }});
}}'''
        try:
            await asyncio.wait_for(client.connected(), timeout=5)
            installed = await client.run_javascript(f'(() => {{{install}\nreturn true;}})()', timeout=5)
            if not installed:
                raise TimeoutError
            targets.enable()
            restored = await client.run_javascript(f'''(() => {{
{install}
if (!input.cnDraftEdited) {{
    input.value = sessionStorage.getItem({key}) || '';
    input.dispatchEvent(new Event('input', {{bubbles: true}}));
}}
return true;
}})()''', timeout=5)
            if restored:
                targets.enable()
                return
        except TimeoutError:
            pass
        if not client.is_deleted:
            # Allow edits while waiting for reconnect; install the listener first so
            # a later restore cannot overwrite a value entered during recovery.
            client.run_javascript(f'(() => {{{install}}})()')
            await asyncio.sleep(0)
            targets.enable()
            ui.timer(1, restore_draft, once=True)
    ui.timer(0, restore_draft, once=True)
    if ports is not None:
        ports.disable()
        async def restore_ports():
            client = ui.context.client
            if client.is_deleted:
                return
            element_id = json.dumps(ports.html_id)
            install = f'''const root = document.getElementById({element_id});
const input = root?.matches('input') ? root : root?.querySelector('input');
if (!input) return false;
if (!input.cnDraftListener) {{
    input.cnDraftListener = true;
    input.addEventListener('input', () => {{
        input.cnDraftEdited = true;
        sessionStorage.setItem('cn-tool-draft-ping-ports', input.value);
    }});
}}'''
            try:
                await asyncio.wait_for(client.connected(), timeout=5)
                installed = await client.run_javascript(f'(() => {{{install}\nreturn true;}})()', timeout=5)
                if not installed:
                    raise TimeoutError
                ports.enable()
                restored = await client.run_javascript(f'''(() => {{
{install}
if (!input.cnDraftEdited) {{
    input.value = sessionStorage.getItem('cn-tool-draft-ping-ports') || '';
    input.dispatchEvent(new Event('input', {{bubbles: true}}));
}}
return true;
}})()''', timeout=5)
                if restored:
                    ports.enable()
                    return
            except TimeoutError:
                pass
            if not client.is_deleted:
                client.run_javascript(f'(() => {{{install}}})()')
                await asyncio.sleep(0)
                ports.enable()
                ui.timer(1, restore_ports, once=True)
        ui.timer(0, restore_ports, once=True)
    ui.timer(0, poll, once=True)
    ui.timer(.25, poll)
