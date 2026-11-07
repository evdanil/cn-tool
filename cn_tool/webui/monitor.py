"""Accessible, bounded presentation of the shared Ping Monitor session."""
import asyncio
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import json
import re

from .ping import parse_ports
from .subnets import CSS, report_display
from .report_actions import render_report_delete


HISTORY_EXPIRED = 'History changed or expired. Return to requests to browse available records.'
# Show Available's own words: the block has no requests list to return to, but a Refresh history that reads it again.
COVERAGE_EXPIRED = 'The history changed while you were reading it. Use Refresh history to read it again.'
COVERAGE_TITLE = 'Available IPs (whole history)'
COVERAGE_MEANING = 'Unseen means it never replied to this machine in the rounds kept. Not tested means no round could test it.'


def history_error_message(error):
    if error == 'too_large':
        return 'This history is too large to sort or filter safely. Reset this view or return to another record.'
    return str(error)


class MonitorFormError(ValueError):
    def __init__(self, field, message):
        self.field = field
        super().__init__(message)


def parse_monitor_form(ports, interval, duration):
    """Parse the seconds fields without accepting locale digits or fractions."""
    def seconds(value, label, optional=False):
        value = value.strip()
        if optional and not value:
            return None
        if not re.fullmatch(r'[0-9]{1,9}', value) or int(value) < 10:
            raise MonitorFormError(label.lower(), f'{label} must be a whole number of at least 10 seconds.')
        return int(value)
    try:
        parsed_ports = parse_ports(ports)
    except ValueError as error:
        raise MonitorFormError('ports', str(error)) from error
    every = seconds(interval, 'Interval')
    until = seconds(duration, 'Duration', optional=True)
    if until is not None and until < every:
        raise MonitorFormError('duration', 'Duration must be at least the interval.')
    return parsed_ports, every, until


@dataclass
class HistoryView:
    kind: str = 'requests'
    parent: object = None
    cursors: list = field(default_factory=lambda: [None])
    ancestors: list = field(default_factory=list)
    view_only: bool = False

    @property
    def cursor(self):
        return self.cursors[-1]

    def next(self, cursor):
        if cursor:
            self.cursors.append(cursor)

    def previous(self):
        if len(self.cursors) > 1:
            self.cursors.pop()

    def refresh(self):
        self.cursors = [None]

    def open(self, kind, parent, *, view_only=None):
        self.ancestors.append((self.kind, self.parent, self.cursors[:], self.view_only))
        self.kind, self.parent, self.cursors = kind, parent, [None]
        if view_only is not None:
            self.view_only = view_only

    def back(self):
        if self.ancestors:
            self.kind, self.parent, self.cursors, self.view_only = self.ancestors.pop()

    def breadcrumbs(self):
        names = {'runs': 'Request', 'rounds': 'Run', 'hosts': 'Round'}
        return ' / '.join(['Requests'] + [f"{names[kind]} {parent}" for kind, parent in
            [(item[0], item[1]) for item in self.ancestors[1:]] + ([(self.kind, self.parent)] if self.kind != 'requests' else [])])

    def reset(self):
        self.kind, self.parent, self.cursors, self.ancestors, self.view_only = 'requests', None, [None], [], False


def render_host_footer(*, scope, size, offset, count, total, previous_enabled,
                       next_enabled, on_previous, on_next, on_size):
    """Present bounded host pages; callers retain query and navigation state."""
    from nicegui import ui

    live = scope == 'live'
    marker = 'data-monitor-' + scope
    name = {'live': 'Latest round pages', 'coverage': 'Available IPs pages'}.get(scope, 'Round host pages')
    number = (lambda value: f'{value:,}') if scope == 'coverage' else str  # the other footers print as they always did
    buttons = []
    with ui.element('nav').props('aria-label=' + json.dumps(name)).classes('cn-monitor-footer'):
        with ui.row().classes('items-center gap-2 no-wrap'):
            ui.label('Rows per page:')
            # No transition: Quasar holds every focus() for the 300 ms of a menu's transition, so a menu opened again
            # inside that wait queued one that took the focus back from wherever the reader had moved on to.
            select = ui.select([5, 10, 15, 20, 25, 50], value=size, on_change=on_size).props(
                'dense borderless aria-label="Rows per page" transition-duration=0').classes('w-16')
            select._props[marker] = 'page-size'
            if live:
                select.props('popup-content-class=cn-monitor-live-popup')
        first, last = (offset + 1, offset + count) if count else (0, 0)
        ui.label(f'{number(first)}–{number(last)}' + (f' of {number(total)}' if total is not None else '')).classes('cn-monitor-range')
        with ui.row().classes('items-center gap-1 no-wrap'):
            for label, icon, callback, enabled, value in [
                    ('Previous hosts', 'chevron_left', on_previous, previous_enabled, 'previous' if live else 'previous-hosts'),
                    ('Next hosts', 'chevron_right', on_next, next_enabled, 'next' if live else 'next-hosts')]:
                button = ui.button(icon=icon, on_click=callback).props('flat round dense aria-label=' + json.dumps(label))
                button._props[marker] = value
                button.set_enabled(enabled)
                buttons.append(button)
    return buttons


def paged_handlers(latest, size, stacks, *, busy, request, following, first, names=('previous-hosts', 'next-hosts')):
    """The Previous, Next and rows-per-page handlers of a table that is read a page at a time (the live round, a saved
    round, Show Available). ``stacks`` are the lists in ``latest`` that gain an entry for each page opened and lose one
    on Previous, ``size`` is the key of the rows per page. ``busy()`` is true while an answer is awaited,
    ``following()`` gives what Next adds to each stack (None on the last page), ``first()`` puts the state back on
    page one, and ``request(name)`` asks for the page that the state now describes."""
    async def previous():
        if busy() or len(latest[stacks[0]]) < 2:
            return
        for key in stacks:
            latest[key].pop()
        await request(names[0])

    async def next_page():
        step = None if busy() else following()
        if step is None:
            return
        for key, value in zip(stacks, step):
            latest[key].append(value)
        await request(names[1])

    async def change_size(event):
        if event.value == latest[size]:
            return
        latest[size] = event.value
        first()
        await request('page-size')

    return previous, next_page, change_size


def render_monitor(controller):
    from nicegui import ui

    client = ui.context.client
    ui.add_css(CSS + '''
.cn-monitor-row { width:100%; min-width:0; overflow-wrap:anywhere; }
.cn-monitor-row .q-field { min-width:0; }
.cn-monitor-scroll { max-height: min(60vh, 620px); width:100%; min-width:0; overflow:auto; border:1px solid #CBD5DF; border-radius:4px; }
.cn-monitor-table { width:100%; border-collapse:collapse; font-variant-numeric:tabular-nums; }
.cn-monitor-table th, .cn-monitor-table td { text-align:left; vertical-align:middle; padding:7px 10px; border-bottom:1px solid #E2E8ED; }
.cn-monitor-history [role=status]:empty { display:none; }
.cn-monitor-table th { position:sticky; top:0; z-index:1; background:#EDF2F6; color:#334D60; font-weight:600; white-space:nowrap; }
.cn-monitor-table tbody tr:hover { background:#F4F8FB; }
.cn-monitor-table tr:last-child td { border-bottom:0; }
.cn-monitor-table .q-btn { text-transform:none; }
.cn-monitor-hosts { table-layout:fixed; min-width:680px; }
.cn-monitor-hosts th:first-child { width:320px; }
.cn-monitor-hosts th:nth-child(2) { width:170px; }
.cn-monitor-target { overflow-wrap:anywhere; white-space:normal; }
.cn-monitor-round-select { display:none; }
.cn-monitor-history { gap:8px; }
.cn-monitor-rounds-desktop { width:100%; }
.cn-monitor-state { display:inline-block; white-space:nowrap; font-size:13px; line-height:22px; padding:0 6px; border-radius:3px; background:#EDF2F6; color:#334D60; }
.cn-monitor-state.ok { background:#E8F4ED; color:#205E3C; }
.cn-monitor-state.problem { background:#FBEAEA; color:#922D2D; }
.cn-monitor-state.warning { background:#FFF3D8; color:#775110; }
.cn-monitor-inspector { display:grid; grid-template-columns:240px minmax(0,1fr); gap:20px; width:100%; }
.cn-monitor-rounds { min-width:0; }
.cn-monitor-round-list { max-height:480px; overflow:auto; border:1px solid #CBD5DF; border-radius:4px; }
.cn-monitor-round-choice { display:flex; justify-content:space-between; gap:8px; width:100%; padding:9px 10px; text-align:left; border:0; border-bottom:1px solid #E2E8ED; background:white; cursor:pointer; font:inherit; font-variant-numeric:tabular-nums; }
.cn-monitor-round-choice:hover { background:#F4F8FB; }
.cn-monitor-round-choice[aria-pressed=true] { background:#E5F0F7; box-shadow:inset 3px 0 #145C87; color:#10496B; font-weight:600; }
.cn-monitor-round-choice:focus-visible, .cn-monitor-scroll:focus-visible { outline:2px solid #145C87; outline-offset:-2px; }
.cn-monitor-detail { min-width:0; width:100%; }
.cn-monitor-toolbar { display:flex; flex-wrap:wrap; align-items:center; gap:8px; width:100%; }
.cn-monitor-context { min-width:0; overflow-wrap:anywhere; }
.cn-monitor-footer { display:flex; flex-wrap:wrap; justify-content:flex-end; align-items:center; gap:16px; width:100%; min-width:0; padding:8px 12px; border-top:1px solid #E2E8ED; font-size:12px; }
.cn-monitor-range { white-space:nowrap; font-variant-numeric:tabular-nums; }
.cn-monitor-pages { margin-left:auto; display:flex; flex-wrap:wrap; align-items:center; gap:8px; }
.cn-monitor-coverage-table { min-width:1000px; }
.cn-monitor-coverage-table td:nth-child(3), .cn-monitor-coverage-table td:nth-child(4) { white-space:nowrap; }
.cn-monitor-notice { width:100%; min-width:0; overflow-wrap:anywhere; padding:8px 10px; border-left:3px solid #775110; background:#FFF3D8; color:#5E400C; }
@media(max-width:900px) { .cn-monitor-inspector { grid-template-columns:1fr; } .cn-monitor-selected-title { display:none; } .cn-monitor-rounds-desktop { display:none; } .cn-monitor-round-select { display:block; width:100%; } }
@media(max-width:600px) { .cn-monitor-actions { flex-wrap:wrap; } .cn-monitor-hosts th:first-child { width:185px; } .cn-monitor-hosts th:nth-child(2) { width:140px; } .cn-monitor-table th, .cn-monitor-table td { padding:7px; } .cn-monitor-pages { margin-left:0; } }
''')
    ui.colors(primary='#145C87')
    latest = {'result': None, 'result_revision': None, 'attempt_revision': None,
              'outcome': None, 'live_query': None, 'live_key': None, 'live_page': None,
              'live_offset': 0, 'live_offsets': [0], 'live_size': 25, 'live_sort': '', 'live_descending': False, 'live_group': 'all', 'live_filter_field': 'host', 'live_filter_text': '', 'history_query': None, 'history_page': None,
              'history_dirty': True, 'download': None, 'template_query': None, 'delete_query': None,
              'round_query': None, 'round_hosts': None, 'selected_round': None,
              'host_cursors': [None], 'host_offsets': [0], 'host_size': 25, 'host_sort': '', 'host_descending': False, 'host_group': 'all',
              'host_filter_field': 'host', 'host_filter_text': '',
              'history_views': {'requests': dict(sort='', descending=False, field='targets', text=''),
                                'runs': dict(sort='', descending=False, field='started', text='')}, 'round_pick': 'first', 'request_context': None, 'run_context': None,
              # Show Available: the saved target the box belongs to (None: the page is not on one), the rows per page the
              # tab chose (it outlives a reset), and everything else the table reads or shows, off until ticked.
              'coverage_parent': None, 'coverage_size': 25, 'coverage_drawn': False, **coverage_defaults()}
    history = HistoryView()
    lock = asyncio.Lock()

    with ui.row().classes('w-full items-center justify-between cn-monitor-row'):
        ui.label('Ping Monitor').mark('title').classes('text-h4')
        quit_button = ui.button('Quit application', on_click=controller.quit).props('outline')
    with ui.element('nav').props('aria-label=Tools').classes('row items-center gap-4 cn-monitor-row'):
        ui.link('Subnets', '/')
        ui.link('IP', '/ip')
        ui.link('Ping', '/ping')
        ui.link('Monitor', '/monitor').props('aria-current=page')
        ui.link('Configuration Search', '/config-search')
        ui.link('Site Demobilization', '/demobilization')
    with ui.row().classes('cn-monitor-toolbar'):
        status = ui.label('Attaching…').props('role=status aria-live=polite').classes('text-weight-bold grow')
        def stop_owned():
            state = controller.snapshot()
            if state.active_lookup_type == 'monitor' and state.active_job_id and state.phase == 'running':
                controller.cancel(state.active_job_id)
        stop = ui.button('Stop this session’s monitor', on_click=stop_owned).props('outline')
    with ui.tabs().classes('w-full').props('align=left no-caps') as tabs:
        live_tab = ui.tab('Live monitor')
        history_tab = ui.tab('History')
    with ui.tab_panels(tabs, value=live_tab).classes('w-full').props('keep-alive'):
        live_panel = ui.tab_panel(live_tab).classes('p-0')
        history_panel = ui.tab_panel(history_tab).classes('p-0')
    with live_panel, ui.column().classes('cn-panel'):
        ui.label('Start a monitor').classes('text-h6')
        ui.label('Monitoring continues when you close this tab. Use Stop to end the active run.').classes('cn-muted').tooltip('Quit waits for DNS, probe cleanup and configured exit actions.')
        targets = ui.textarea('Targets', placeholder='192.0.2.1\nexample.com').props('outlined autogrow').classes('w-full')
        target_error = ui.label('').props('role=alert').classes('text-negative')
        ui.label('One IP address, hostname or subnet per line. Hostnames use system DNS.').classes('cn-muted')
        ports = ui.input('TCP ports', placeholder='22, 443').props('outlined').classes('w-full')
        port_error = ui.label('').props('role=alert').classes('text-negative')
        ui.label('Optional: up to five comma-separated ports. ICMP is used when available.').classes('cn-muted')
        with ui.row().classes('w-full cn-monitor-row'):
            interval = ui.input('Interval (seconds)', value='60').props('outlined inputmode=numeric').classes('grow')
            duration = ui.input('Duration (seconds)', value='').props('outlined inputmode=numeric').classes('grow')
        interval_error = ui.label('').props('role=alert').classes('text-negative')
        duration_error = ui.label('').props('role=alert').classes('text-negative')
        ui.label('Leave duration blank to run until stopped. Both values must be at least 10 seconds.').classes('cn-muted')
        form_error = ui.label('').props('role=alert').classes('text-negative')
        reuse_status = ui.label('').classes('cn-muted')
        fields = {'targets': (targets, target_error), 'ports': (ports, port_error),
                  'interval': (interval, interval_error), 'duration': (duration, duration_error)}
        for control, error_label in fields.values():
            control._props['aria-describedby'] = error_label.html_id
        async def submit():
            for control, error_label in fields.values():
                control._props.pop('aria-invalid', None)
                control.update()
                error_label.set_text('')
            form_error.set_text('')
            try:
                if not (targets.value or '').strip():
                    raise MonitorFormError('targets', 'Enter at least one target.')
                parsed_ports, every, until = parse_monitor_form(ports.value or '', interval.value or '', duration.value or '')
                controller.submit(targets.value.splitlines(), 'monitor', tcp_ports=parsed_ports,
                                  interval_seconds=every, duration_seconds=until)
            except MonitorFormError as error:
                control, error_label = fields[error.field]
                error_label.set_text(str(error))
                control._props['aria-invalid'] = 'true'
                control.update()
                root = json.dumps(control.html_id)
                client.run_javascript(f"(() => {{ const root = document.getElementById({root}); (root?.matches('input,textarea') ? root : root?.querySelector('input,textarea'))?.focus(); }})()")
                return
            except (ValueError, RuntimeError) as error:
                form_error.set_text(str(error))
                return
            await poll()
        with ui.row().classes('cn-monitor-actions'):
            run = ui.button('Run monitor', on_click=submit)
            run.disable()
    with live_panel, ui.column().classes('cn-panel'):
        ui.label('Latest complete round').classes('text-h6')
        summary = ui.label('No complete round yet.').props('role=status aria-live=polite')
        outcome_status = ui.label('').props('role=status').classes('text-negative')
        warning_status = ui.label('').props('role=status aria-live=polite').classes('text-negative')
        history_status = ui.label('').props('role=status').classes('text-negative')
        report = ui.html('').props('role=status aria-live=polite tabindex=-1 data-report-status').classes('cn-muted')
        def download_report():
            try:
                latest['download'] = controller.request_report_snapshot()
            except RuntimeError:
                report.set_content('Report download is unavailable.')
        with ui.row().classes('items-center'):
            download = ui.button('Download accumulated report', on_click=download_report).props('outline')
            report_delete = render_report_delete(controller)
        pending_live = ui.label('').props('role=status aria-live=polite').classes('cn-muted')
        live_area = ui.column().classes('w-full')
        @ui.refreshable
        def draw_live():
            latest['live_buttons'] = []
            page = latest['live_page']
            if not page:
                return
            state = page.get('status')
            ui.label(live_page_label(page)).classes('cn-muted')
            if state == 'not_ready':
                ui.label('Waiting for the first complete round. No result is inferred for an unfinished round.').classes('cn-muted')
                return
            if state != 'ready':
                ui.label('Latest round is unavailable.').classes('cn-muted')
                return
            rows = page.get('rows', [])
            counts = page.get('counts')
            if counts is not None:
                async def choose_group(group):
                    latest['live_group'] = group
                    latest['live_offset'], latest['live_offsets'] = 0, [0]
                    latest['live_user_request'] = 'group-' + group
                    latest['live_key'] = None
                    await poll()
                with ui.element('nav').props('aria-label="Filter latest round hosts"').classes('cn-monitor-toolbar'):
                    for group, label in (('all', 'All'), ('answered', 'Answered'), ('no_response', 'No response'),
                                         ('problem', 'Problems'), ('other', 'Other')):
                        count = sum(counts.values()) if group == 'all' else counts[group]
                        button = ui.button(f'{label} ({count})', on_click=lambda _, value=group: choose_group(value)).props('outline dense')
                        button._props['aria-pressed'] = str(group == latest['live_group']).lower()
                        button._props['data-monitor-live'] = 'group-' + group
                with ui.element('div').classes('cn-monitor-toolbar'):
                    field = ui.select({'host': 'Target', 'result': 'Result', 'address': 'Address', 'tcp': 'TCP'},
                                      value=latest['live_filter_field'], label='Filter field').props('outlined dense').classes('w-40')
                    pattern = ui.input('Contains', value=latest['live_filter_text']).props('outlined dense maxlength=256').classes('grow')
                    async def apply_filter():
                        latest['live_filter_field'], latest['live_filter_text'] = field.value, (pattern.value or '')[:256]
                        latest['live_offset'], latest['live_offsets'] = 0, [0]
                        latest['live_user_request'] = 'filter'
                        latest['live_key'] = None
                        await poll()
                    pattern.on('keydown.enter', apply_filter)
                    button = ui.button('Filter hosts', on_click=apply_filter).props('outline dense')
                    button._props['data-monitor-live'] = 'filter'
                    async def clear_filter():
                        latest['live_filter_text'] = ''
                        latest['live_offset'], latest['live_offsets'] = 0, [0]
                        latest['live_user_request'] = 'clear-filter'
                        latest['live_key'] = None
                        await poll()
                    clear = ui.button('Clear host filter', on_click=clear_filter).props('outline dense')
                    clear._props['data-monitor-live'] = 'clear-filter'
                ui.label('Counts describe the complete round; the table reflects the selected group and filter.').classes('cn-muted')
                if not rows:
                    ui.label('No hosts match the selected group and filter.').classes('cn-muted')
            with ui.element('div').classes('cn-monitor-scroll').props('tabindex=0 aria-label="Latest round results"'), ui.element('table').classes('cn-monitor-table cn-monitor-hosts').props('aria-label="Latest round host results"'):
                with ui.element('thead'), ui.element('tr'):
                    async def change_sort(column):
                        if latest['live_sort'] == column:
                            latest['live_descending'] = not latest['live_descending']
                        else:
                            latest['live_sort'], latest['live_descending'] = column, False
                        latest['live_offset'], latest['live_offsets'] = 0, [0]
                        latest['live_user_request'] = 'sort-' + column
                        latest['live_key'] = None
                        await poll()
                    for label, column in (('Target', 'host'), ('Result', 'result'), ('Address', 'address'), ('TCP', 'tcp')):
                        with ui.element('th').props('scope=col') as header:
                            if latest['live_sort'] == column:
                                header._props['aria-sort'] = 'descending' if latest['live_descending'] else 'ascending'
                            button = ui.button(label, on_click=lambda _, value=column: change_sort(value)).props('flat dense')
                            button._props['aria-label'] = f'Sort by {label}' + ((', descending' if latest['live_descending'] else ', ascending') if latest['live_sort'] == column else '')
                            button._props['data-monitor-live'] = 'sort-' + column
                with ui.element('tbody'):
                    for row in rows:
                        with ui.element('tr'):
                            values = dict(live_fields(row))
                            for key in ('Host', 'Result', 'Address', 'TCP'):
                                with ui.element('td'):
                                    ui.label(values[key]).classes('cn-monitor-target' if key == 'Host' else '').props('title=' + json.dumps(values[key]))
            async def request_live(name):
                latest['live_offset'] = latest['live_offsets'][-1]
                latest['live_user_request'] = name
                latest['live_key'] = None
                await poll()

            prev, next_page, change_size = paged_handlers(
                latest, 'live_size', ('live_offsets',), names=('previous', 'next'), request=request_live,
                busy=lambda: latest['live_query'] or latest.get('live_user_request'),
                following=lambda: None if page.get('next_offset') is None else (page['next_offset'],),
                first=lambda: latest.update(live_offsets=[0]))

            latest['live_buttons'] = render_host_footer(scope='live', size=latest['live_size'], offset=page['offset'],
                count=len(rows), total=page.get('total'), previous_enabled=len(latest['live_offsets']) > 1,
                next_enabled=page.get('next_offset') is not None, on_previous=prev,
                on_next=next_page, on_size=change_size)
        with live_area:
            draw_live()
    with history_panel, ui.column().classes('cn-panel cn-monitor-history gap-3'):
        history_reuse_status = ui.label('').props('role=status aria-live=polite').classes('cn-muted')
        history_delete_status = ui.label('').props('role=status aria-live=polite').classes('cn-muted')
        with ui.dialog().props('persistent') as delete_dialog, ui.card().classes('w-full max-w-lg'):
            delete_title = ui.label('').classes('text-h6')
            delete_description = ui.label('')
            delete_error = ui.label('').props('role=alert').classes('text-negative')
            with ui.row().classes('cn-monitor-actions'):
                def cancel_delete():
                    if latest['delete_query']:
                        return
                    delete_dialog.close()
                    client.run_javascript('window.cnMonitorDeleteInvoker?.focus()')
                delete_cancel = ui.button('Cancel', on_click=cancel_delete).props('outline autofocus')
                async def confirm_delete():
                    selection = latest['delete_selection']
                    try:
                        latest['delete_query'] = controller.request_monitor_delete(
                            selection['action'], selection.get('run_id'), selection.get('request_id'))
                    except (AttributeError, RuntimeError, ValueError):
                        delete_error.set_text('Could not start deletion. Try again when the session is ready.')
                        return
                    delete_error.set_text('Deleting history…')
                    delete_confirm.disable()
                    delete_cancel.disable()
                    await poll()
                delete_confirm = ui.button('Delete run', on_click=confirm_delete).props('color=negative')
        delete_dialog.props(f'aria-labelledby={delete_title.html_id}')
        delete_dialog.on('keydown.escape', lambda _: cancel_delete())
        def open_delete(action, item=None):
            if latest['delete_query']:
                return
            latest['delete_selection'] = {'action': action}
            if action == 'run':
                latest['delete_selection'].update(run_id=item['id'], request_id=item.get('request_id'))
                delete_title.set_text('Delete this run?')
                count = item.get('rounds', 0)
                description = (f"Started {history_value('started', item.get('started'))}; status {item.get('status', 'unknown')}; "
                               f"{count} complete {'round' if count == 1 else 'rounds'}. "
                               'This permanently deletes this run and its rounds. Other runs of this request remain.')
                if item.get('status') == 'lost':
                    description += ' A stale heartbeat can mean this run is still active on its host; check before deleting.'
                delete_description.set_text(description)
                delete_confirm.set_text('Delete run')
            else:
                delete_title.set_text('Delete all monitor history?')
                delete_description.set_text('This permanently deletes every saved request, run and round at confirmation. This cannot be undone. A stale heartbeat can make a remote run appear lost; check remote monitors before deleting.')
                delete_confirm.set_text('Delete all history')
            delete_error.set_text('')
            delete_confirm.enable()
            delete_cancel.enable()
            client.run_javascript('window.cnMonitorDeleteInvoker = document.activeElement')
            delete_dialog.open()
            client.run_javascript(f"setTimeout(() => document.getElementById({json.dumps(delete_cancel.html_id)})?.focus(), 100)")
        def set_reuse_notice(message):
            set_changed(reuse_status, message)
            set_changed(history_reuse_status, message)
        def cancel_round_query():
            if latest['round_query']:
                controller.release_monitor_history_page(latest['round_query'])
            latest['round_query'] = None
            latest['round_hosts'] = None

        async def request_round_hosts(focus=None, *, refresh='hosts'):
            cancel_round_query()
            latest['detail_focus'] = focus
            try:
                latest['round_query'] = controller.request_monitor_history(
                    'hosts', latest['selected_round']['id'], latest['host_cursors'][-1], latest['host_size'],
                    latest['host_sort'], latest['host_descending'], latest['host_group'],
                    latest['host_filter_field'], latest['host_filter_text'])
            except (AttributeError, RuntimeError, ValueError):
                latest['round_hosts'] = {'error': 'Round results are unavailable. Refresh history to try again.'}
            if refresh == 'all':
                await draw_history.refresh()
            elif refresh == 'hosts':
                await draw_round_hosts.refresh()
            if refresh == 'all' and focus:
                selector = '.cn-monitor-round-choice[aria-pressed=true]' if focus == 'round' else f'[data-monitor-detail="{focus}"]:not([disabled])'
                client.run_javascript(f'(() => {{ const control = document.querySelector({json.dumps(selector)}); (control?.querySelector("input") || control)?.focus({{preventScroll:true}}); }})()')

        async def select_round(item, focus='round', *, refresh='all'):
            latest['selected_round'] = item
            latest['host_cursors'], latest['host_offsets'] = [None], [0]
            await request_round_hosts(focus, refresh=refresh)

        async def step_round(direction):
            items = (latest['history_page'] or {}).get('items', [])
            selected = latest['selected_round']
            if not selected or selected not in items:
                return
            index = items.index(selected) + direction
            if 0 <= index < len(items):
                await select_round(items[index], 'earlier' if direction < 0 else 'later')
            elif direction < 0 and len(history.cursors) > 1:
                history.previous()
                await request_history('previous', round_pick='last')
            elif direction > 0 and latest['history_page'].get('next_cursor'):
                history.next(latest['history_page']['next_cursor'])
                await request_history('next')

        async def use_settings(run_id):
            if latest['template_query']:
                controller.release_monitor_history_page(latest['template_query'])
            latest['template_query'] = None
            latest['template_draft'] = tuple(control.value for control in (targets, ports, interval, duration))
            try:
                latest['template_query'] = controller.request_monitor_history('template', run_id, None, 1)
                set_reuse_notice('Loading saved settings…')
            except (AttributeError, RuntimeError, ValueError):
                set_reuse_notice(history_template_error(None))
            await poll()

        def table_head(labels):
            with ui.element('thead'), ui.element('tr'):
                for label in labels:
                    with ui.element('th').props('scope=col'):
                        ui.label(label)

        def cell(text, *, target=False):
            with ui.element('td'):
                ui.label(str(text)).classes('cn-monitor-target' if target else '').props('title=' + json.dumps(str(text)))

        def state_cell(text, observation=None, *, tone=None):
            if tone is None:
                tone = ('ok' if observation in {'!', 'T', 'R'} or text == 'finished' else
                        'problem' if observation in {'E', '?', 'U'} or text == 'failed' else
                        'warning' if text in {'running', 'lost'} else '')
            with ui.element('td'):
                label = {'DNS name did not resolve': 'DNS failed', 'Answered on TCP': 'TCP reply'}.get(text, text)
                ui.label(label).classes('cn-monitor-state ' + tone).props('title=' + json.dumps(text))

        @ui.refreshable
        def draw_round_hosts():
            hosts_page = latest['round_hosts']
            if hosts_page is None:
                ui.label('Loading round results…').props('role=status').classes('cn-muted')
            elif hosts_page.get('error'):
                message = ('This round changed or was deleted. Refresh history to select an available round.'
                           if hosts_page['error'] == 'expired' else
                           'This round is too large to display safely. Select another round.'
                           if hosts_page['error'] == 'too_large' else history_error_message(hosts_page['error']))
                ui.label(message).props('role=alert').classes('text-negative')
            else:
                rows = hosts_page.get('items', [])
                counts = hosts_page.get('counts')
                if counts is not None:
                    async def choose_host_group(group):
                        latest['host_group'], latest['host_cursors'], latest['host_offsets'] = group, [None], [0]
                        await request_round_hosts('group-' + group)
                    with ui.element('nav').props('aria-label="Filter saved round hosts"').classes('cn-monitor-toolbar'):
                        for group, label in (('all', 'All'), ('answered', 'Answered'), ('no_response', 'No response'),
                                             ('problem', 'Problems'), ('other', 'Other')):
                            count = sum(counts.values()) if group == 'all' else counts[group]
                            button = ui.button(f'{label} ({count})', on_click=lambda _, value=group: choose_host_group(value)).props('outline dense')
                            button._props['aria-pressed'] = str(group == latest['host_group']).lower()
                            button._props['data-monitor-detail'] = 'group-' + group
                    with ui.element('div').classes('cn-monitor-toolbar'):
                        field = ui.select({'host': 'Target', 'status': 'Status', 'address': 'Address', 'result': 'Probe result'},
                                          value=latest['host_filter_field'], label='Round host filter field').props('outlined dense').classes('w-40')
                        pattern = ui.input('Round host filter', value=latest['host_filter_text']).props('outlined dense maxlength=256').classes('grow')
                        async def apply_host_filter():
                            latest['host_filter_field'], latest['host_filter_text'] = field.value, (pattern.value or '')[:256]
                            latest['host_cursors'], latest['host_offsets'] = [None], [0]
                            await request_round_hosts('filter-hosts')
                        pattern.on('keydown.enter', apply_host_filter)
                        button = ui.button('Filter round hosts', on_click=apply_host_filter).props('outline dense')
                        button._props['data-monitor-detail'] = 'filter-hosts'
                        async def clear_host_filter():
                            latest['host_filter_text'], latest['host_cursors'], latest['host_offsets'] = '', [None], [0]
                            await request_round_hosts('clear-filter')
                        clear = ui.button('Clear round host filter', on_click=clear_host_filter).props('outline dense')
                        clear._props['data-monitor-detail'] = 'clear-filter'
                    ui.label(f"{hosts_page['total']} matching hosts; counts describe the complete round.").classes('cn-muted')
                    if not rows:
                        ui.label('No hosts match the selected group and filter.').classes('cn-muted')
                with ui.element('div').classes('cn-monitor-scroll').props('tabindex=0 aria-label="Round results"'), ui.element('table').classes('cn-monitor-table cn-monitor-hosts').props('aria-label="Round host results"'):
                    with ui.element('thead'), ui.element('tr'):
                        async def sort_hosts(column):
                            if latest['host_sort'] == column:
                                latest['host_descending'] = not latest['host_descending']
                            else:
                                latest['host_sort'], latest['host_descending'] = column, False
                            latest['host_cursors'], latest['host_offsets'] = [None], [0]
                            await request_round_hosts('sort-' + column)
                        for label, column in (('Target', 'host'), ('Status', 'status'), ('Address', 'address'), ('Probe result', 'result')):
                            with ui.element('th').props('scope=col') as header:
                                if latest['host_sort'] == column:
                                    header._props['aria-sort'] = 'descending' if latest['host_descending'] else 'ascending'
                                button = ui.button(label, on_click=lambda _, value=column: sort_hosts(value)).props('flat dense')
                                button._props['aria-label'] = f'Sort round hosts by {label}' + ((', descending' if latest['host_descending'] else ', ascending') if latest['host_sort'] == column else '')
                                button._props['data-monitor-detail'] = 'sort-' + column
                    with ui.element('tbody'):
                        for row in rows:
                            with ui.element('tr'):
                                cell(row.get('host') or 'Unknown host', target=True)
                                state_cell(history_value('observation', row.get('observation')), row.get('observation'))
                                cell(row.get('address') or '—', target=True)
                                cell(row.get('result') or '—')
                previous_hosts, next_hosts, change_host_size = paged_handlers(
                    latest, 'host_size', ('host_cursors', 'host_offsets'), request=request_round_hosts,
                    busy=lambda: latest['round_query'],
                    following=lambda: next_cursor_step(latest['host_offsets'], latest['round_hosts'], len(rows)),
                    first=lambda: latest.update(host_cursors=[None], host_offsets=[0]))

                render_host_footer(scope='detail', size=latest['host_size'], offset=latest['host_offsets'][-1],
                    count=len(rows), total=hosts_page.get('total'), previous_enabled=len(latest['host_cursors']) > 1,
                    next_enabled=bool(hosts_page.get('next_cursor')), on_previous=previous_hosts,
                    on_next=next_hosts, on_size=change_host_size)
                if not rows:
                    ui.label('No host results on this page.').classes('cn-muted')

        # --- Show Available: every IP of the saved target on screen, with whether it ever replied ---------------------
        def cancel_coverage_query():
            if latest['coverage_query']:
                controller.release_monitor_history_page(latest['coverage_query'])
            latest['coverage_query'] = None

        def release_coverage_download():
            """Give up the Unseen export in flight: the controller drops its late answer and removes its file."""
            if latest['coverage_download']:
                controller.release_report_request(latest['coverage_download'])
            latest['coverage_download'] = None

        def reset_coverage():
            """Box off, nothing read, nothing left to show: what a new target line, or leaving the line, leaves behind."""
            cancel_coverage_query()
            release_coverage_download()
            latest.update(coverage_defaults())

        def first_coverage_page():
            latest['coverage_cursors'], latest['coverage_offsets'] = [None], [0]

        async def request_coverage(focus=None):
            cancel_coverage_query()
            latest['coverage_page'] = None
            latest['coverage_focus'] = focus
            try:
                latest['coverage_query'] = controller.request_monitor_history(
                    'coverage', latest['coverage_parent'], latest['coverage_cursors'][-1], latest['coverage_size'],
                    latest['coverage_sort'], latest['coverage_descending'], latest['coverage_group'],
                    latest['coverage_filter_field'], latest['coverage_filter_text'])
            except (AttributeError, RuntimeError, ValueError):
                latest['coverage_page'] = {'error': 'History is unavailable. Try refreshing.'}
            await draw_coverage.refresh()

        async def toggle_coverage(event):
            if bool(event.value) == latest['coverage_on']:
                return
            if event.value:
                latest['coverage_on'] = True
                await request_coverage('toggle')
            else:
                reset_coverage()
                await draw_coverage.refresh()
            focus_coverage('toggle')

        def sync_coverage_download():
            """The download button, what its file holds and its error follow the state, without redrawing the table."""
            button, label = latest.get('coverage_download_button'), latest.get('coverage_download_label')
            if button is None:
                return
            page = latest['coverage_page'] or {}
            unseen = 0 if page.get('error') else (page.get('counts') or {}).get('unseen', 0)
            button.set_enabled(unseen > 0 and latest['coverage_download'] is None)
            note = coverage_download_note(page)
            latest['coverage_download_note'].set_text(note)
            latest['coverage_download_note'].set_visibility(bool(note))
            set_changed(label, latest['coverage_download_error'])

        def download_coverage():
            if latest['coverage_download'] or latest['coverage_parent'] is None:
                return
            latest['coverage_download_error'] = ''
            try:
                latest['coverage_download'] = controller.request_coverage_export(latest['coverage_parent'])
            except (AttributeError, RuntimeError, ValueError):
                latest['coverage_download_error'] = 'Download is unavailable. Refresh history and try again.'
            sync_coverage_download()

        async def choose_coverage_group(group):
            latest['coverage_group'] = group
            first_coverage_page()
            await request_coverage('group-' + group)

        async def apply_coverage_filter(field, pattern, *, clear=False):
            latest['coverage_filter_field'] = field.value
            latest['coverage_filter_text'] = '' if clear else (pattern.value or '')[:256]
            first_coverage_page()
            await request_coverage('clear-filter' if clear else 'filter')

        async def sort_coverage(column):
            if latest['coverage_sort'] == column:
                latest['coverage_descending'] = not latest['coverage_descending']
            else:
                latest['coverage_sort'], latest['coverage_descending'] = column, False
            first_coverage_page()
            await request_coverage('sort-' + column)

        previous_coverage, next_coverage, change_coverage_size = paged_handlers(
            latest, 'coverage_size', ('coverage_cursors', 'coverage_offsets'), request=request_coverage,
            busy=lambda: latest['coverage_query'],
            following=lambda: next_cursor_step(latest['coverage_offsets'], latest['coverage_page']),
            first=first_coverage_page)

        def draw_coverage_table(page):
            rows = page['items']
            counts = page['counts']
            notices = coverage_notices(page['summary'])
            if notices:  # one live region with a line for each subnet: a screen reader hears one update, not sixty-four
                with ui.element('div').props('role=status').classes('cn-monitor-notice'):
                    for line in notices:
                        ui.label(line)
            with ui.element('nav').props('aria-label="Available IPs by status"').classes('cn-monitor-toolbar'):
                for group, label in (('all', 'All'), ('seen', 'Seen'), ('unseen', 'Unseen'), ('not_tested', 'Not tested')):
                    count = sum(counts.values()) if group == 'all' else counts[group]
                    button = ui.button(f'{label} ({count:,})', on_click=lambda _, value=group: choose_coverage_group(value)).props('outline dense')
                    button._props['aria-pressed'] = str(group == latest['coverage_group']).lower()
                    button._props['data-monitor-coverage'] = 'group-' + group
            with ui.element('div').classes('cn-monitor-toolbar'):
                field = ui.select({'host': 'Target', 'status': 'Status', 'note': 'Note'}, value=latest['coverage_filter_field'],
                                  label='Available IPs filter field').props('outlined dense').classes('w-52')
                pattern = ui.input('Available IPs filter', value=latest['coverage_filter_text']).props('outlined dense maxlength=256').classes('grow')
                pattern.on('keydown.enter', lambda: apply_coverage_filter(field, pattern))
                button = ui.button('Filter available IPs', on_click=lambda: apply_coverage_filter(field, pattern)).props('outline dense')
                button._props['data-monitor-coverage'] = 'filter'
                button = ui.button('Clear available IPs filter', on_click=lambda: apply_coverage_filter(field, pattern, clear=True)).props('outline dense')
                button._props['data-monitor-coverage'] = 'clear-filter'
            total = page['total']
            ui.label(f"{total:,} matching {'host' if total == 1 else 'hosts'}; counts describe the whole history.").classes('cn-muted')
            if not rows:
                ui.label('No hosts match the selected group and filter.').classes('cn-muted')
            with ui.element('div').classes('cn-monitor-scroll').props('tabindex=0 role=region aria-label="Available IPs results"'), ui.element('table').classes('cn-monitor-table cn-monitor-coverage-table').props('aria-label="Available IPs table"'):
                with ui.element('thead'), ui.element('tr'):
                    for label, column in (('Target', 'host'), ('Status', 'status'), ('First seen', 'first_seen'),
                                          ('Last seen', 'last_seen'), ('Rounds answered', 'answered'), ('Failed rounds', None), ('Note', None)):
                        with ui.element('th').props('scope=col') as header:
                            if column is None:
                                ui.label(label)
                                continue
                            if latest['coverage_sort'] == column:
                                header._props['aria-sort'] = 'descending' if latest['coverage_descending'] else 'ascending'
                            button = ui.button(label, on_click=lambda _, value=column: sort_coverage(value)).props('flat dense')
                            button._props['aria-label'] = f'Sort available IPs by {label}' + ((', descending' if latest['coverage_descending'] else ', ascending') if latest['coverage_sort'] == column else '')
                            button._props['data-monitor-coverage'] = 'sort-' + column
                with ui.element('tbody'):
                    for row in rows:
                        with ui.element('tr'):
                            cell(row['host'], target=True)
                            state_cell(row['status'], tone=COVERAGE_TONES.get(row['status'], ''))
                            cell(coverage_time(row['first_seen']))
                            cell(coverage_time(row['last_seen']))
                            cell(coverage_answered(row))
                            cell(f"{row['failed']:,}")
                            cell(row['note'] or '—', target=True)
            render_host_footer(scope='coverage', size=latest['coverage_size'], offset=latest['coverage_offsets'][-1],
                count=len(rows), total=total, previous_enabled=len(latest['coverage_cursors']) > 1,
                next_enabled=bool(page.get('next_cursor')), on_previous=previous_coverage,
                on_next=next_coverage, on_size=change_coverage_size)

        @ui.refreshable
        def draw_coverage():
            latest['coverage_download_button'] = latest['coverage_download_label'] = latest['coverage_download_note'] = None
            # The block is drawn on the runs of a saved target only: not on the list of targets, and not on the rounds of
            # a run, where the box is remembered (``request_history``) but nothing is read or shown.
            latest['coverage_drawn'] = latest['coverage_parent'] is not None and history.kind == 'runs'
            if not latest['coverage_drawn']:
                return
            page = latest['coverage_page']
            with ui.column().classes('w-full gap-2').props('role=region aria-label="Available IPs"'):
                # The box is alone in the first row, ticked or not, so ticking it never moves it from under the pointer.
                with ui.row().classes('cn-monitor-toolbar'):
                    box = ui.checkbox('Show Available', value=latest['coverage_on'], on_change=toggle_coverage)
                    box._props['data-monitor-coverage'] = 'toggle'
                if not latest['coverage_on']:
                    return
                ui.label(COVERAGE_TITLE).props('role=heading aria-level=3').classes('text-subtitle1 text-weight-bold')
                ui.label(COVERAGE_MEANING).classes('cn-muted')
                with ui.row().classes('cn-monitor-toolbar'):
                    help_text = ('Downloads every IP of this target line that never replied (Unseen) as CSV, with its note. '
                                 'It is separate from the accumulated report and does not change it.')
                    button = ui.button('Download available IPs', on_click=download_coverage).props('outline dense no-caps')
                    button._props['data-monitor-coverage'] = 'download'
                    button._props['aria-description'] = help_text
                    button.tooltip(help_text)
                    note = ui.label('').classes('cn-muted')
                    label = ui.label('').props('role=alert').classes('text-negative')
                    latest['coverage_download_button'], latest['coverage_download_label'] = button, label
                    latest['coverage_download_note'] = note
                    sync_coverage_download()
                if page is None:
                    ui.label('Reading the whole history…').props('role=status').classes('cn-muted')
                elif page.get('error'):
                    ui.label(COVERAGE_EXPIRED if page['error'] == 'expired' else history_error_message(page['error'])).props('role=alert').classes('text-negative')
                else:
                    ui.label(coverage_summary_line(page['summary'])).props('role=status').classes('text-weight-bold')
                    draw_coverage_table(page)

        history_area = ui.column().classes('w-full')
        @ui.refreshable
        def draw_history_controls():
            page = latest['history_page']
            async def back():
                history.back()
                await request_history('back')
            async def root():
                history.reset()
                await request_history('refresh')
            async def previous():
                history.previous()
                await request_history('previous')
            async def next_page():
                history.next((latest['history_page'] or {}).get('next_cursor'))
                await request_history('next')
            async def refresh():
                history.refresh()
                await request_history('refresh', fresh_coverage=True)
            with ui.element('nav').props('aria-label="History location"').classes('cn-monitor-toolbar'):
                if history.kind == 'requests':
                    ui.label('Saved targets').classes('text-h6')
                else:
                    ui.button('Saved targets', on_click=root).props('flat dense no-caps')
                    ui.label('/').classes('cn-muted')
                    request = latest['request_context'] or {}
                    ui.label(request_summary(request)[0].removeprefix('Targets: ')).classes('cn-monitor-context text-weight-bold')
                    if history.kind == 'rounds':
                        ui.label('/').classes('cn-muted')
                        ui.label('Run started ' + history_value('started', (latest['run_context'] or {}).get('started'))).classes('cn-monitor-context')
                        if history.view_only:
                            ui.label('Saved run').classes('cn-monitor-state').tooltip('Viewing another run’s history only. Stop controls your session’s active monitor.')
            with ui.element('nav').props('aria-label="History pages"').classes('cn-monitor-toolbar'):
                if history.ancestors:
                    button = ui.button('Back to runs' if history.kind == 'rounds' else 'Back to targets', on_click=back).props('outline dense no-caps')
                    button._props['data-monitor-history'] = 'back'
                button = ui.button('Refresh history', on_click=refresh).props('flat dense no-caps')
                button._props['data-monitor-history'] = 'refresh'
                if history.kind == 'requests':
                    ui.button('Delete all history', on_click=lambda: open_delete('all')).props('flat dense no-caps color=negative')
                with ui.element('div').classes('cn-monitor-pages'):
                    noun = 'round page' if history.kind == 'rounds' else 'page'
                    button = ui.button('Previous ' + noun, on_click=previous).props('outline dense no-caps')
                    button._props['data-monitor-history'] = 'previous'
                    latest['history_previous_button'] = button
                    button.set_enabled(len(history.cursors) > 1 and page is not None)
                    ui.label(f'Page {len(history.cursors)}').classes('cn-muted')
                    button = ui.button('Next ' + noun, on_click=next_page).props('outline dense no-caps')
                    button._props['data-monitor-history'] = 'next'
                    latest['history_next_button'] = button
                    button.set_enabled(bool(page and page.get('next_cursor')))

        @ui.refreshable
        def draw_history():
            page = latest['history_page']
            if page is None:
                ui.label('Loading history…').props('role=status').classes('cn-muted')
                return
            if page.get('error'):
                ui.label(HISTORY_EXPIRED if page['error'] == 'expired' else history_error_message(page['error'])).props('role=alert').classes('text-negative')
                if page['error'] == 'too_large' and history.kind in ('requests', 'runs'):
                    async def reset_history_view():
                        default_field = 'targets' if history.kind == 'requests' else 'started'
                        latest['history_views'][history.kind] = dict(sort='', descending=False, field=default_field, text='')
                        history.refresh()
                        await request_history('refresh')
                    ui.button('Reset history view', on_click=reset_history_view).props('outline dense')
                if page['error'] == 'expired':
                    async def return_to_requests():
                        history.reset()
                        await request_history('refresh')
                    ui.button('Return to requests', on_click=return_to_requests).props('outline')
                return
            if history.kind in ('requests', 'runs'):
                current = latest['history_views'][history.kind]
                choices = ({'targets': 'Targets', 'ports': 'TCP ports', 'hosts': 'Hosts'} if history.kind == 'requests' else
                           {'started': 'Started (UTC)', 'status': 'Status', 'rounds': 'Rounds', 'interval': 'Interval'})
                with ui.element('div').classes('cn-monitor-toolbar'):
                    field = ui.select(choices, value=current['field'], label='History filter field').props('outlined dense').classes('w-40')
                    pattern = ui.input('History filter', value=current['text']).props('outlined dense maxlength=256').classes('grow')
                    async def filter_history(clear=False):
                        current['field'], current['text'] = field.value, '' if clear else (pattern.value or '')[:256]
                        history.refresh()
                        await request_history('clear-filter' if clear else 'filter')
                    pattern.on('keydown.enter', lambda: filter_history())
                    button = ui.button('Filter history', on_click=lambda: filter_history()).props('outline dense')
                    button._props['data-monitor-history'] = 'filter'
                    clear = ui.button('Clear history filter', on_click=lambda: filter_history(True)).props('outline dense')
                    clear._props['data-monitor-history'] = 'clear-filter'
                if 'total' in page:
                    ui.label(f"{page['total']} matching records.").classes('cn-muted')
            if not page.get('items'):
                ui.label('No saved monitor history. Start a monitor to record results.' if history.kind == 'requests' and not latest['history_views']['requests']['text'] else
                         'No complete rounds in this run.' if history.kind == 'rounds' else 'No records match this view.').classes('cn-muted')
                return
            items = page['items']
            if history.kind == 'rounds':
                with ui.element('div').classes('cn-monitor-inspector'):
                    with ui.column().classes('cn-monitor-rounds gap-2'):
                        choices = {item['id']: history_value('started', item.get('started')) for item in items}
                        async def choose_round(event):
                            chosen = next((item for item in items if item['id'] == event.value), None)
                            if chosen and chosen != latest['selected_round']:
                                await select_round(chosen, 'round-select')
                        picker = ui.select(choices, value=(latest['selected_round'] or {}).get('id'), label='Round (UTC)', on_change=choose_round).props('outlined dense').classes('cn-monitor-round-select')
                        picker._props['data-monitor-detail'] = 'round-select'
                        with ui.column().classes('cn-monitor-rounds-desktop gap-2'):
                            with ui.row().classes('w-full justify-between'):
                                ui.label('Rounds (oldest first)').classes('text-weight-bold')
                                ui.label('Answered').classes('text-weight-bold')
                            with ui.element('div').classes('cn-monitor-round-list w-full'):
                                for item in items:
                                    stamp = history_value('started', item.get('started'))
                                    chosen = latest['selected_round'] == item
                                    with ui.element('button').classes('cn-monitor-round-choice').props(
                                            'type=button aria-pressed=' + str(chosen).lower() + ' aria-label=' + json.dumps('Select round ' + stamp)) as choice:
                                        ui.label(stamp.removesuffix(' UTC')).classes('pointer-events-none')
                                        ui.label(str(item.get('answered', 0))).classes('pointer-events-none')
                                    choice.on('click', lambda _, row=dict(item): select_round(row))
                    with ui.column().classes('cn-monitor-detail gap-2'):
                        selected = latest['selected_round']
                        with ui.row().classes('cn-monitor-toolbar'):
                            if selected:
                                ui.label(history_value('started', selected.get('started'))).props('role=heading aria-level=3').classes('text-weight-bold grow cn-monitor-selected-title')
                            for label, direction, marker in [('Earlier round', -1, 'earlier'), ('Later round', 1, 'later')]:
                                button = ui.button(label, on_click=lambda _, step=direction: step_round(step)).props('outline dense no-caps')
                                button._props['data-monitor-detail'] = marker
                                index = items.index(selected) if selected in items else -1
                                button.set_enabled(index >= 0 and (index > 0 or len(history.cursors) > 1) if direction < 0 else
                                                   index >= 0 and (index < len(items) - 1 or bool(page.get('next_cursor'))))
                        draw_round_hosts()
                return
            name = 'Saved monitor targets' if history.kind == 'requests' else 'Monitor runs'
            with ui.element('div').classes('cn-monitor-scroll').props('tabindex=0 aria-label=' + json.dumps(name)), ui.element('table').classes('cn-monitor-table').style('min-width:680px' if history.kind == 'requests' else 'min-width:1000px').props('aria-label=' + json.dumps(name)):
                with ui.element('thead'), ui.element('tr'):
                    async def sort_history(column):
                        current = latest['history_views'][history.kind]
                        if current['sort'] == column:
                            current['descending'] = not current['descending']
                        else:
                            current['sort'], current['descending'] = column, False
                        history.refresh()
                        await request_history('sort-' + column)
                    columns = (('Targets', 'targets'), ('TCP ports', 'ports'), ('Hosts', 'hosts')) if history.kind == 'requests' else (
                        ('Started (UTC)', 'started'), ('Status', 'status'), ('Rounds', 'rounds'), ('Interval', 'interval'))
                    current = latest['history_views'][history.kind]
                    for label, column in columns:
                        with ui.element('th').props('scope=col') as header:
                            if current['sort'] == column:
                                header._props['aria-sort'] = 'descending' if current['descending'] else 'ascending'
                            button = ui.button(label, on_click=lambda _, value=column: sort_history(value)).props('flat dense')
                            button._props['aria-label'] = f"Sort {'saved targets' if history.kind == 'requests' else 'runs'} by {label}" + (
                                (', descending' if current['descending'] else ', ascending') if current['sort'] == column else '')
                            button._props['data-monitor-history'] = 'sort-' + column
                    with ui.element('th').props('scope=col'):
                        ui.label('Actions')
                with ui.element('tbody'):
                    for item in items:
                        with ui.element('tr'):
                            if history.kind == 'requests':
                                for line in request_summary(item):
                                    cell(line.split(': ', 1)[1])
                            else:
                                cell(history_value('started', item.get('started')).removesuffix(' UTC'))
                                state_cell(item.get('status') or 'unknown')
                                cell(item.get('rounds', 0))
                                every = item.get('interval')
                                cell('One round' if every is None else f'{every:g}s')
                            with ui.element('td'), ui.row().classes('items-center gap-1 no-wrap'):
                                async def open_item(_, row=dict(item), target='runs' if history.kind == 'requests' else 'rounds'):
                                    if target == 'rounds' and (latest['run_context'] or {}).get('id') != row['id']:
                                        latest.update(host_sort='', host_descending=False, host_group='all',
                                                      host_filter_field='host', host_filter_text='')
                                    latest['request_context' if target == 'runs' else 'run_context'] = row
                                    history.open(target, row['id'], view_only=(not row.get('owned') if target == 'rounds' else None))
                                    await request_history('back')
                                ui.button('View runs' if history.kind == 'requests' else 'View rounds', on_click=open_item).props('outline dense no-caps')
                                if history.kind == 'runs':
                                    ui.button('Use settings', on_click=lambda _, run_id=item['id']: use_settings(run_id)).props('flat dense no-caps')
                                    with ui.button('Details').props('flat dense no-caps'), ui.menu():
                                        ui.label('Owned by this session' if item.get('owned') else 'View only').classes('text-weight-bold')
                                        for line in history_run_summary(item):
                                            ui.label(line)
                                        for key in ('id', 'source', 'host', 'pid', 'heartbeat', 'round_seconds'):
                                            if item.get(key) is not None:
                                                ui.label(f"{key.replace('_', ' ').capitalize()}: {history_value(key, item[key])}")
                                    remove = ui.button('Delete run', on_click=lambda _, row=dict(item): open_delete('run', row)).props('flat dense no-caps color=negative')
                                    remove.set_enabled(item.get('status') != 'running' and bool(item.get('request_id')))
                                    if item.get('status') == 'running':
                                        remove.tooltip('A running monitor cannot be deleted.')
        with history_area:
            draw_history_controls()
            draw_coverage()
            draw_history()

    def focus_coverage(marker, *, only_if_lost=False):
        """Put focus back on the control that was used, or its opposite, or the box. With ``only_if_lost`` only when a
        redraw left it on the page, so that a slow answer never takes it from where the reader went."""
        opposite = {'next-hosts': 'previous-hosts', 'previous-hosts': 'next-hosts'}.get(marker)
        client.run_javascript(f'''(() => {{
if ({json.dumps(only_if_lost)} && document.activeElement !== document.body) return;
const find = name => name && document.querySelector(`[data-monitor-coverage="${{name}}"]:not([disabled])`);
const control = find({json.dumps(marker)}) || find({json.dumps(opposite)}) || find('toggle');
(control?.querySelector('input:not(.hidden)') || control)?.focus({{preventScroll:true}});  // not a checkbox's hidden input
}})()''')

    def focus_history(target):
        selector = json.dumps(f'[data-monitor-history="{target}"]:not([disabled])')
        client.run_javascript(f'''(() => {{
const requested = document.querySelector({selector});
const fallback = document.querySelector('[data-monitor-history=refresh]');
(requested || fallback)?.focus();
if (!requested && fallback) {{
  fallback.cnHistoryPendingFocus = {json.dumps(target)};
  const clearPending = () => {{ delete fallback.cnHistoryPendingFocus; }};
  for (const event of ['blur', 'pointerdown', 'keydown']) fallback.addEventListener(event, clearPending, {{once:true}});
}}
}})()''')

    async def request_history(focus=None, *, round_pick='first', fresh_coverage=False):
        latest['round_pick'] = round_pick
        cancel_round_query()
        latest['selected_round'] = None
        latest['host_cursors'], latest['host_offsets'] = [None], [0]
        if latest['history_query']:
            controller.release_monitor_history_page(latest['history_query'])
        latest['history_query'] = None
        latest['history_page'] = None
        # The box belongs to the saved target the runs table lists, and to the rounds of its runs. Another target, or the
        # list of targets, starts with it off and its query released, so that an answer for the old target can never draw
        # under the new one. The rounds of a run of the same target keep the box ticked but draw nothing and leave no query
        # open; the runs, back again, read the table again.
        target = (history.parent if history.kind == 'runs' else
                  history.ancestors[-1][1] if history.kind == 'rounds' and history.ancestors else None)
        if target != latest['coverage_parent']:
            reset_coverage()
            latest['coverage_parent'] = target
            await draw_coverage.refresh()
        elif history.kind == 'rounds':
            cancel_coverage_query()
            latest['coverage_page'] = None
            if latest['coverage_drawn']:
                await draw_coverage.refresh()
        elif latest['coverage_on'] and (fresh_coverage or (latest['coverage_page'] is None and not latest['coverage_query'])):
            first_coverage_page()
            await request_coverage()
        elif history.kind == 'runs' and not latest['coverage_drawn']:
            await draw_coverage.refresh()  # back from the rounds with the box off: the block comes back
        try:
            if history.kind in ('requests', 'runs'):
                current = latest['history_views'][history.kind]
                latest['history_query'] = controller.request_monitor_history(history.kind, history.parent, history.cursor, 50,
                    current['sort'], current['descending'], 'all', current['field'], current['text'])
            else:
                latest['history_query'] = controller.request_monitor_history(history.kind, history.parent, history.cursor, 50)
        except (AttributeError, RuntimeError, ValueError):
            latest['history_page'] = {'error': 'History is unavailable. Try refreshing.'}
        await draw_history_controls.refresh()
        await draw_history.refresh()
        if focus:
            focus_history(focus)

    async def live_has_focus():
        if not client.has_socket_connection:
            return False
        try:
            return bool(await client.run_javascript(f"""(() => {{
const area = document.getElementById({json.dumps(live_area.html_id)});
return area?.contains(document.activeElement) ||
  [...document.querySelectorAll('.cn-monitor-live-popup')].some(popup => popup.getClientRects().length > 0 && getComputedStyle(popup).visibility !== 'hidden');
}})()""", timeout=1))
        except TimeoutError:
            return False

    async def poll():
        if lock.locked():
            return
        async with lock:
            page = controller.page_snapshot('monitor', result_revision=latest['result_revision'], attempt_revision=latest['attempt_revision'])
            if page.result_changed:
                latest['result'], latest['result_revision'] = page.result, page.result_revision
            if page.attempt_changed:
                latest['outcome'], latest['attempt_result'], latest['attempt_revision'] = page.outcome, page.attempt_result, page.attempt_revision
            state = page.state
            await report_delete.update(state)
            deleting = state.report_delete_pending
            active = state.active_lookup_type == 'monitor' and bool(state.active_job_id)
            update = state.monitor_update
            data = ((update or {}) if active else (latest.get('attempt_result') or latest['result'] or update or {}))
            phase = state.phase
            message = {'ready': 'Ready', 'starting': 'Starting application…', 'stopping': 'Stopping… Waiting for DNS and probe cleanup.',
                       'saving': 'Saving report…', 'closing': 'Finishing active work and exit actions…', 'closed': 'Application closed.',
                       'failed': 'Application failed. Quit and relaunch.'}.get(phase, state.progress_stage or phase)
            if phase == 'running':
                message = operation_message(state, update, active=active)
            if state.error:
                message = state.error.get('message', str(state.error)) if isinstance(state.error, dict) else str(state.error)
            set_changed(status, message)
            run.set_enabled(not deleting and phase == 'ready' and not state.active_job_id and all(control.enabled for control, _ in fields.values()))
            stop.set_visibility(active and phase in {'running', 'stopping', 'saving'})
            stop.set_enabled(active and phase == 'running')
            quit_button.set_enabled(phase not in {'closing', 'closed'})
            if data:
                previous = bool(page.attempt_job_id and page.result_job_id and page.attempt_job_id != page.result_job_id)
                set_changed(summary, monitor_summary(data, active=active, previous=previous))
            else:
                set_changed(summary, 'No complete round yet. An unfinished round does not indicate an outage.')
            outcome = latest['outcome'] or {}
            set_changed(outcome_status, str(outcome.get('message') or '') if outcome.get('kind') in {'invalid', 'lookup_error', 'partial', 'stopped'} else '')
            set_changed(warning_status, ' '.join(monitor_warnings(data, outcome)))
            set_changed(history_status, f"History: {data['history_error']}" if data.get('history_error') else '')
            report_state = replace(state, latest_report_state=page.attempt_report_state)
            display = report_display(report_state)
            if report.content != display['text']:
                report.set_content(display['text'])
            download.set_enabled(not deleting and display['available'] and latest['download'] is None)
            if latest['download']:
                completion = controller.report_completion(latest['download']) or {}
                if completion.get('status') == 'ready':
                    with client:
                        ui.download('/download/' + latest['download'])
                    latest['download'] = None
                elif completion.get('status') == 'failed':
                    report.set_content('Report download failed.')
                    controller.acknowledge_report_completion(latest['download'])
                    latest['download'] = None
            job = state.active_job_id if active else page.attempt_job_id
            run_id = (update or {}).get('run_id')
            revision = (update or {}).get('revision')
            identity = (job, run_id, revision)
            if latest.get('live_identity') != identity:
                previous_identity = latest.get('live_identity')
                latest.pop('pending_live', None)
                if (previous_identity and previous_identity[:2] == identity[:2] and revision is not None
                        and not latest.get('live_user_request')):
                    set_changed(pending_live, f'Complete round revision {revision} is available; updating the displayed page.')
                if not previous_identity or previous_identity[:2] != identity[:2]:
                    latest['live_user_request'] = None
                    latest.update(live_offset=0, live_offsets=[0], live_sort='', live_descending=False, live_group='all',
                                  live_filter_field='host', live_filter_text='')
                    if previous_identity:
                        latest['live_page'] = None
                        await draw_live.refresh()
                latest['live_identity'] = identity
            key = (job, run_id, revision, latest['live_offset'], latest['live_size'], latest['live_sort'], latest['live_descending'], latest['live_group'], latest['live_filter_field'], latest['live_filter_text']) if job and run_id is not None and revision is not None else None
            if key != latest['live_key']:
                latest.pop('pending_live', None)
                if key is None:
                    latest['live_page'] = None
                    await draw_live.refresh()
                if latest['live_query']:
                    controller.release_monitor_live_page(latest['live_query'])
                latest['live_query'] = None
                latest['live_key'] = key
                if key:
                    if latest.get('live_user_request'):
                        for button in latest.get('live_buttons', []):
                            button.props('aria-disabled=true').classes(add='disabled')
                        set_changed(pending_live, 'Loading host results…')
                    try:
                        latest['live_query'] = controller.request_monitor_live_page(*key)
                    except (AttributeError, RuntimeError, ValueError):
                        latest['live_page'] = {'status': 'unavailable'}
                        set_changed(pending_live, '')
                        await draw_live.refresh()
            if latest['live_query']:
                result = controller.monitor_live_page(latest['live_query'])
                if result is not None:
                    controller.release_monitor_live_page(latest['live_query'])
                    latest['live_query'] = None
                    if result.get('status') == 'expired':
                        latest['live_key'] = None
                    elif result.get('status') == 'ready' and not result.get('rows') and latest['live_offset']:
                        total = result.get('total')
                        size = latest['live_size']
                        last_offset = max(0, ((total - 1) // size) * size) if type(total) is int and total >= 0 else None
                        latest['live_offset'] = (last_offset if last_offset is not None and last_offset < latest['live_offset']
                                                 else (latest['live_offsets'][-2] if len(latest['live_offsets']) > 1 else 0))
                        latest['live_offsets'] = [offset for offset in latest['live_offsets'] if offset < latest['live_offset']] + [latest['live_offset']]
                        latest['live_key'] = None
                    else:
                        latest['pending_live'] = result
            if latest.get('pending_live') is not None:
                pending_result = latest['pending_live']
                pending_key = latest['live_key']
                focus_target = latest.get('live_user_request')
                had_live_focus = await live_has_focus()
                if (focus_target and had_live_focus and latest['live_key'] == pending_key
                        and latest.get('pending_live') is pending_result):
                    try:
                        current_focus = await client.run_javascript("document.activeElement?.closest('[data-monitor-live]')?.dataset.monitorLive || null", timeout=1)
                        focus_target = current_focus or focus_target
                    except TimeoutError:
                        pass
                # UI callbacks can change the query while either browser focus check awaits.
                if latest['live_key'] == pending_key and latest.get('pending_live') is pending_result:
                    if focus_target or not had_live_focus:
                        latest['live_page'] = latest.pop('pending_live')
                        latest['live_user_request'] = None
                        set_changed(pending_live, '')
                        await draw_live.refresh()
                        if focus_target and had_live_focus:
                            selector = json.dumps(f'[data-monitor-live="{focus_target}"]:not([disabled])')
                            client.run_javascript(f"""(() => {{
if (document.activeElement !== document.body) return;
const opposite = {{next:'previous', previous:'next'}}[{json.dumps(focus_target)}];
const control = document.querySelector({selector}) ||
  (opposite && document.querySelector(`[data-monitor-live="${{opposite}}"]:not([disabled])`)) ||
  document.querySelector('[data-monitor-live]:not([disabled])');
(control?.querySelector('input') || control)?.focus({{preventScroll:true}});
}})()""")
                    else:
                        set_changed(pending_live, f"Complete round revision {latest['pending_live'].get('revision', revision)} is available. Move focus away from these controls to show it.")
            if latest['template_query']:
                template_page = controller.monitor_history_page(latest['template_query'])
                if template_page is not None:
                    controller.release_monitor_history_page(latest['template_query'])
                    latest['template_query'] = None
                    if template_page.get('error') or len(template_page.get('items', [])) != 1:
                        set_reuse_notice(history_template_error(template_page.get('error')))
                    elif tuple(control.value for control in (targets, ports, interval, duration)) != latest['template_draft']:
                        set_reuse_notice('Form changed while saved settings were loading. Your edits were kept; select Use settings again to replace them.')
                    else:
                        tabs.set_value(live_tab)
                        values, notice = history_template_form(template_page['items'][0])
                        for control, suffix, value in zip((targets, ports, interval, duration),
                                                          ('targets', 'ports', 'interval', 'duration'), values):
                            control.set_value(value)
                            key = json.dumps('cn-tool-draft-monitor-' + suffix)
                            root = json.dumps(control.html_id)
                            client.run_javascript(f"(() => {{ sessionStorage.setItem({key}, {json.dumps(value)}); const root = document.getElementById({root}); const input = root?.matches('input,textarea') ? root : root?.querySelector('input,textarea'); if (input) input.cnDraftEdited = true; }})()")
                        for control, error_label in fields.values():
                            control._props.pop('aria-invalid', None)
                            control.update()
                            error_label.set_text('')
                        form_error.set_text('')
                        set_reuse_notice(notice)
                        root = json.dumps(targets.html_id)
                        client.run_javascript(f"(() => {{ const root = document.getElementById({root}); (root?.matches('input,textarea') ? root : root?.querySelector('input,textarea'))?.focus(); }})()")
            if latest['delete_query']:
                deletion = controller.monitor_delete_result(latest['delete_query'])
                if deletion is not None:
                    controller.release_monitor_delete_result(latest['delete_query'])
                    latest['delete_query'] = None
                    deletion_status = deletion.get('status')
                    if deletion_status == 'deleted':
                        action = latest['delete_selection']['action']
                        notice = 'Run deleted.' if action == 'run' else 'Monitor history deleted.'
                        if deletion.get('warning'):
                            notice += ' ' + deletion['warning']
                        set_changed(history_delete_status, notice)
                        delete_dialog.close()
                        if latest['template_query']:
                            controller.release_monitor_history_page(latest['template_query'])
                            latest['template_query'] = None
                        history.reset()
                        await request_history('refresh')
                    else:
                        messages = {'running': 'A recorded monitor is active or its state cannot be verified. Wait for it to finish or check the process that owns it.',
                                    'missing': 'The selected history no longer exists. Refresh history and try again.',
                                    'failed': 'History could not be deleted. Check the history file and try again.'}
                        delete_error.set_text(deletion.get('warning') if deletion_status == 'failed' and deletion.get('warning')
                                              else messages.get(deletion_status, messages['failed']))
                        delete_confirm.enable()
                        delete_cancel.enable()
            if latest['history_dirty'] and phase in {'ready', 'running', 'stopping', 'saving'}:
                latest['history_dirty'] = False
                await request_history()
            if latest['history_query']:
                result = controller.monitor_history_page(latest['history_query'])
                if result is not None:
                    controller.release_monitor_history_page(latest['history_query'])
                    latest['history_query'] = None
                    latest['history_page'] = result
                    latest['history_previous_button'].set_enabled(len(history.cursors) > 1)
                    latest['history_next_button'].set_enabled(bool(result.get('next_cursor')))
                    if history.kind == 'rounds' and not result.get('error') and result.get('items'):
                        pick = -1 if latest['round_pick'] == 'last' else 0
                        latest['round_pick'] = 'first'
                        await select_round(result['items'][pick], 'round', refresh='none')
                    await draw_history.refresh()
                    # Restore a temporarily disabled pager only while its fallback
                    # still owns focus and the user has not interacted elsewhere.
                    client.run_javascript('''(() => {
const fallback = document.querySelector('[data-monitor-history=refresh]');
const marker = fallback?.cnHistoryPendingFocus;
if (marker && document.activeElement === fallback && fallback.offsetParent !== null) {
  document.querySelector(`[data-monitor-history="${marker}"]:not([disabled])`)?.focus();
}
if (fallback) delete fallback.cnHistoryPendingFocus;
})()''')

            if latest['round_query']:
                result = controller.monitor_history_page(latest['round_query'])
                if result is not None:
                    controller.release_monitor_history_page(latest['round_query'])
                    latest['round_query'] = None
                    latest['round_hosts'] = result
                    await draw_round_hosts.refresh()
                    marker = latest.pop('detail_focus', None)
                    if marker:
                        selector = '.cn-monitor-round-choice[aria-pressed=true]' if marker == 'round' else f'[data-monitor-detail="{marker}"]:not([disabled])'
                        client.run_javascript(f'''(() => {{
const selected = document.querySelector('.cn-monitor-round-choice[aria-pressed=true]');
const list = selected?.parentElement;
if (selected && selected.offsetParent !== null && list) list.scrollTop += selected.getBoundingClientRect().top - list.getBoundingClientRect().top - list.clientHeight / 2 + selected.offsetHeight / 2;
if (document.activeElement === document.body && document.querySelector('.cn-monitor-detail')?.offsetParent !== null) {{
  const opposite = {{'next-hosts':'previous-hosts', 'previous-hosts':'next-hosts', 'earlier':'later', 'later':'earlier'}}[{json.dumps(marker)}];
  const candidates = [document.querySelector({json.dumps(selector)}),
    opposite ? document.querySelector(`[data-monitor-detail="${{opposite}}"]:not([disabled])`) : null,
    selected, document.querySelector('[data-monitor-detail="round-select"]')];
  const control = candidates.find(element => element && element.offsetParent !== null && !element.matches('[disabled]'));
  (control?.querySelector('input') || control)?.focus({{preventScroll:true}});
}}
}})()''')

            query = latest['coverage_query']
            if query:
                result = controller.monitor_history_page(query)
                if result is not None:
                    controller.release_monitor_history_page(query)
                    latest['coverage_query'] = None
                    marker, latest['coverage_focus'] = latest['coverage_focus'], None
                    if result.get('error') == 'expired':
                        first_coverage_page()  # the next read starts from the first page
                    latest['coverage_page'] = result
                    await draw_coverage.refresh()
                    if marker:
                        focus_coverage(marker, only_if_lost=True)

            exported = latest['coverage_download']
            if exported:
                completion = controller.report_completion(exported) or {}
                if completion.get('status') == 'ready':
                    latest['coverage_download'] = None
                    with client:
                        ui.download('/download/' + exported)
                    sync_coverage_download()
                elif completion.get('status') == 'failed':
                    latest['coverage_download'] = None
                    latest['coverage_download_error'] = completion.get('error') or 'The download failed.'
                    controller.acknowledge_report_completion(exported)
                    sync_coverage_download()

    for control, suffix, default in [(targets, 'targets', ''), (ports, 'ports', ''),
                                     (interval, 'interval', '60'), (duration, 'duration', '')]:
        control.disable()
        async def restore(control=control, suffix=suffix, default=default):
            if client.is_deleted:
                return
            install = '''const root = document.getElementById(%s);
const input = root?.matches('input,textarea') ? root : root?.querySelector('input,textarea');
if (!input) return false;
const key = %s;
if (!input.cnDraftListener) {
  input.cnDraftListener = true;
  input.addEventListener('input', () => { input.cnDraftEdited = true; sessionStorage.setItem(key, input.value); });
}
''' % (json.dumps(control.html_id), json.dumps('cn-tool-draft-monitor-' + suffix))
            try:
                await asyncio.wait_for(client.connected(), timeout=5)
                installed = await client.run_javascript(f'(() => {{{install} return true;}})()', timeout=5)
                if not installed:
                    raise TimeoutError
                restored = await client.run_javascript(f'''(() => {{{install}
if (!input.cnDraftEdited) {{ input.value = sessionStorage.getItem(key) ?? {json.dumps(default)}; input.dispatchEvent(new Event('input', {{bubbles:true}})); }}
return true;
}})()''', timeout=5)
                if restored:
                    control.enable()
                    return
            except TimeoutError:
                pass
            if not client.is_deleted:
                client.run_javascript(f'(() => {{{install}}})()')
                await asyncio.sleep(0)
                control.enable()
                ui.timer(1, restore, once=True)
        ui.timer(0, restore, once=True)
    def release_queries():
        cancel_round_query()
        if latest['delete_query']:
            controller.release_monitor_delete_result(latest['delete_query'])
            latest['delete_query'] = None
        if latest['template_query']:
            controller.release_monitor_history_page(latest['template_query'])
            latest['template_query'] = None
        if latest['live_query']:
            controller.release_monitor_live_page(latest['live_query'])
            latest['live_query'] = None
        if latest['history_query']:
            controller.release_monitor_history_page(latest['history_query'])
            latest['history_query'] = None
        cancel_coverage_query()
        release_coverage_download()
        if latest['download']:
            controller.release_report_request(latest['download'])
            latest['download'] = None
    client.on_delete(release_queries)
    targets.on_value_change(lambda _: poll())
    ui.timer(0, poll, once=True)
    ui.timer(0.5, poll)


def live_fields(row):
    tcp = ', '.join(f"{entry['port']}: {entry['result']}" for entry in row.get('tcp', [])) or 'Not checked'
    return [('Host', str(row.get('host') or 'Unknown')), ('Address', str(row.get('address') or 'Unknown')),
            ('Result', str(row.get('result') or 'Unknown')), ('TCP', tcp)]


def next_cursor_step(offsets, page, count=None):
    """What Next adds to the stacks of a table paged by cursors: the page's next cursor and the number of the first
    row after it (``count`` rows were shown; the page's items by default). None when the page has no next one."""
    cursor = (page or {}).get('next_cursor')
    if not cursor:
        return None
    return cursor, offsets[-1] + (len(page['items']) if count is None else count)


COVERAGE_TONES = {'Seen': 'ok', 'Unseen': 'warning', 'Not tested': 'problem'}


def coverage_defaults():
    """Show Available's state with the box off and nothing read: also what a reset puts back (the target line and the
    rows per page are kept apart, in ``latest``)."""
    return dict(coverage_on=False, coverage_query=None, coverage_page=None, coverage_cursors=[None], coverage_offsets=[0],
                coverage_sort='', coverage_descending=False, coverage_group='all', coverage_filter_field='host',
                coverage_filter_text='', coverage_download=None, coverage_download_error='', coverage_focus=None)


def coverage_download_note(page):
    """What the Download available IPs file holds, beside its button: every Unseen IP of the line, whatever group, sort or
    filter the table shows (``page['counts']`` describe the whole history). Nothing before the history is read."""
    if not page or page.get('error') or 'counts' not in page:
        return ''
    unseen = page['counts']['unseen']
    if not unseen:
        return 'No Unseen IP to download.'
    return f"{unseen:,} Unseen {'IP' if unseen == 1 else 'IPs'}, whatever filter is showing."


def coverage_time(value):
    """A first or last seen time as the history tables show a time, and ``—`` for an IP that never replied."""
    return '—' if value is None else history_value('started', value)


def coverage_answered(item):
    return f"{item['answered']:,} of {item['tested']:,}"


def coverage_summary_line(summary):
    """What the table rests on: the rounds kept for the target line and the day of the oldest."""
    rounds = summary['rounds']
    if not rounds:
        return 'No rounds are kept for this target line.'
    return f"{rounds:,} {'round' if rounds == 1 else 'rounds'} since {coverage_time(summary['since']).split(' ', 1)[0]}"


def coverage_notices(summary):
    """One line for each subnet where no IP ever replied, and a last one when the page could not name them all."""
    from cn_tool.utils.ping_coverage import PAGE_SILENT_SUBNETS

    names = summary['silent_subnets']
    lines = [f'No IP in {name} has ever replied. This machine may not be able to reach it, '
             'so these IPs are untested rather than unused.' for name in names]
    if len(names) >= PAGE_SILENT_SUBNETS:
        lines.append('and possibly more.')
    return lines


def history_run_summary(item):
    status = f"Status: {item.get('status') or 'unknown'}"
    count = item.get('rounds', 0)
    lines = [status, f"Started: {history_value('started', item.get('started'))}",
             f"{count} complete {'round' if count == 1 else 'rounds'}"]
    every = item.get('interval')
    lines.append('One round' if every is None else f'Every {every:g} seconds')
    if item.get('until') is not None:
        lines.append(f"Planned end: {history_value('until', item['until'])}")
    elif every is not None:
        lines.append('No planned end')
    if item.get('ended') is not None:
        lines.append(f"Ended: {history_value('ended', item['ended'])}")
    return lines


def history_template_error(error):
    if error == 'too_large':
        return 'This saved request is too large to load into the form. Enter its targets and ports manually.'
    return 'Saved settings are unavailable. Refresh history and try again.'


def history_template_form(item):
    from math import ceil, isfinite

    every = item.get('interval')
    interval = (str(int(every)) if type(every) in (int, float) and isfinite(every)
                and 10 <= every <= 999999999 and int(every) == every else '')
    duration = ''
    notice = 'Saved settings loaded. Review them before starting.'
    if item.get('until') is not None:
        seconds = item['until'] - item['started']
        if isfinite(seconds) and 10 <= seconds <= 999999999 and interval:
            duration = str(max(int(interval), ceil(seconds)))
            notice = 'Duration is estimated from the saved schedule. Review it before starting.'
        else:
            notice = 'The saved duration could not be restored. Enter a duration or leave it blank to run until stopped.'
    if not interval:
        notice += ' Enter an interval of at least 10 seconds; this run used a different schedule.'
    return ('\n'.join(item['targets']), ', '.join(str(port) for port in item['ports']), interval, duration), notice


def history_value(key, value):
    if key in {'started', 'ended', 'until', 'heartbeat'} and isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except (OverflowError, OSError, ValueError):
            return 'Unknown'
    if key == 'observation':
        return {'!': 'Replied', 'R': 'Rejected', 'T': 'Answered on TCP', 'U': 'Unreachable',
                '.': 'No response', 'E': 'Probe error', '?': 'DNS name did not resolve',
                ' ': 'Unknown'}.get(value, 'Unknown')
    return str(value) if value is not None else 'Unknown'


def monitor_warnings(result, outcome):
    warnings = []
    if result.get('probe_failed'):
        warnings.append('Probe errors occurred during this monitor.')
    hook_error = (outcome.get('details') or {}).get('hook_error')
    if hook_error:
        warnings.append(str(hook_error))
    elif outcome.get('warning_count'):
        warnings.append(f"Monitor completed with {outcome['warning_count']} warning(s).")
    return warnings


def live_page_label(page):
    revision = page.get('revision', 0)
    return f'Showing complete round revision {revision}.' if revision else 'Waiting for the first complete round.'


def set_changed(label, value):
    if label.text != value:
        label.set_text(value)


def operation_message(state, update, *, active):
    stage = ((update or {}).get('stage') if active else None) or state.progress_stage or 'Working…'
    if active and update and stage in {'probing', 'resolving'} and update.get('total', 0) > 0:
        return f"Monitor: {stage} {update.get('completed', 0)} of {update['total']} targets"
    return f"{'Monitor' if active else 'Another operation'}: {stage}"


def monitor_summary(data, *, active, previous):
    label = 'Current monitor' if active else 'Previous monitor result' if previous else 'Most recent completed run'
    count = data.get('current_rounds', 0)
    rounds = f'{count} complete rounds this run' if count else 'No complete round this run'
    text = f"{label}: {rounds}; {data.get('earlier_rounds', 0)} earlier rounds."
    skipped = data.get('skipped_slots', 0)
    if skipped:
        text += f' {skipped} starts skipped because a round overran its interval.'
    return text


def request_summary(item):
    def preview(label, values, count):
        text = ', '.join(str(value) for value in values)
        if not text:
            text = 'unavailable' if count is None else 'None'
        if count is None and values:
            text += ' (total unavailable)'
        elif count is not None and count > len(values):
            text += f' (+{count - len(values)} more)'
        return f'{label}: {text}'
    hosts = item.get('host_count')
    return [preview('Targets', item.get('targets_preview') or [], item.get('target_count')),
            preview('TCP ports', item.get('ports_preview') or [], item.get('port_count')),
            f"Hosts: {hosts if hosts is not None else 'unavailable'}"]
