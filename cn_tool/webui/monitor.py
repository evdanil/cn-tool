"""Accessible, bounded presentation of the shared Ping Monitor session."""
import asyncio
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import json
import re

from .ping import parse_ports
from .subnets import CSS, report_display


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


def render_monitor(controller):
    from nicegui import ui

    client = ui.context.client
    ui.add_css(CSS + '''
.cn-monitor-row { width:100%; min-width:0; overflow-wrap:anywhere; }
.cn-monitor-row .q-field { min-width:0; }
.cn-monitor-table { width:100%; border-collapse:collapse; table-layout:fixed; }
.cn-monitor-table th, .cn-monitor-table td { text-align:left; vertical-align:top; padding:8px; border-bottom:1px solid #CBD5DF; overflow-wrap:anywhere; }
.cn-monitor-table th { background:#EDF2F6; }
@media(max-width:600px) { .cn-monitor-actions { flex-wrap:wrap; } }
''')
    ui.colors(primary='#145C87')
    latest = {'result': None, 'result_revision': None, 'attempt_revision': None,
              'outcome': None, 'live_query': None, 'live_key': None, 'live_page': None,
              'live_offset': 0, 'history_query': None, 'history_page': None,
              'history_dirty': True, 'download': None}
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
    ui.label('Monitoring continues when you navigate away or close this tab. Stop ends this session’s run; Quit stops it and waits for cleanup and configured exit actions. DNS and probe cleanup can take time.').classes('cn-muted')
    status = ui.label('Attaching…').props('role=status aria-live=polite').classes('text-weight-bold')
    with ui.column().classes('cn-panel'):
        ui.label('Start a monitor').classes('text-h6')
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
            def stop_owned():
                state = controller.snapshot()
                if state.active_lookup_type == 'monitor' and state.active_job_id and state.phase == 'running':
                    controller.cancel(state.active_job_id)
            stop = ui.button('Stop this session’s monitor', on_click=stop_owned).props('outline')
    with ui.column().classes('cn-panel'):
        ui.label('Latest complete round').classes('text-h6')
        summary = ui.label('No complete round yet.').props('role=status aria-live=polite')
        outcome_status = ui.label('').props('role=status').classes('text-negative')
        warning_status = ui.label('').props('role=status aria-live=polite').classes('text-negative')
        history_status = ui.label('').props('role=status').classes('text-negative')
        report = ui.html('').props('role=status').classes('cn-muted')
        def download_report():
            try:
                latest['download'] = controller.request_report_snapshot()
            except RuntimeError:
                report.set_content('Report download is unavailable.')
        download = ui.button('Download accumulated report', on_click=download_report).props('outline')
        pending_live = ui.label('').props('role=status aria-live=polite').classes('cn-muted')
        live_area = ui.column().classes('w-full')
        @ui.refreshable
        def draw_live():
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
            ui.label(f"Showing hosts {page['offset'] + 1}–{page['offset'] + len(rows)}" if rows else 'No host results in this round.')
            with ui.column().classes('cn-compact-summary w-full'):
                for row in rows:
                    with ui.column().classes('cn-summary-row'):
                        for label, value in live_fields(row):
                            ui.label(f'{label}: {value}')
            with ui.element('table').classes('cn-monitor-table cn-desktop-summary'):
                with ui.element('thead'), ui.element('tr'):
                    for label in ('Host', 'Address', 'Result', 'TCP'):
                        ui.element('th').props('scope=col').add_slot('default', label)
                with ui.element('tbody'):
                    for row in rows:
                        with ui.element('tr'):
                            for _, value in live_fields(row):
                                with ui.element('td'):
                                    ui.label(value)
            with ui.element('nav').props('aria-label="Latest round pages"').classes('row cn-monitor-actions'):
                async def prev():
                    latest['live_offset'] = max(0, latest['live_offset'] - 50)
                    latest['live_user_request'] = 'previous'
                    latest['live_key'] = None
                    await poll()
                async def next_page():
                    latest['live_offset'] = page['next_offset']
                    latest['live_user_request'] = 'next'
                    latest['live_key'] = None
                    await poll()
                previous = ui.button('Previous hosts', on_click=prev).props('outline')
                previous._props['data-monitor-live'] = 'previous'
                previous.set_enabled(page['offset'] > 0)
                following = ui.button('Next hosts', on_click=next_page).props('outline')
                following._props['data-monitor-live'] = 'next'
                following.set_enabled(page.get('next_offset') is not None)
        with live_area:
            draw_live()
    with ui.column().classes('cn-panel'):
        ui.label('History').classes('text-h6')
        ui.label('History can change while you browse. Refresh starts at the first page. Runs owned by another process are view-only.').classes('cn-muted')
        history_area = ui.column().classes('w-full')
        @ui.refreshable
        def draw_history():
            page = latest['history_page']
            ui.label(history.breadcrumbs()).classes('text-weight-bold')
            ui.label(history.kind.capitalize()).classes('text-weight-bold')
            if history.view_only:
                ui.label('Viewing another run’s history only. Stop this session’s monitor controls your session’s run.').classes('cn-muted')
            if page is None:
                ui.label('Loading history…').classes('cn-muted')
            elif page.get('error'):
                ui.label('History changed or expired. Return to requests to browse available records.' if page['error'] == 'expired' else str(page['error'])).props('role=alert').classes('text-negative')
                if page['error'] == 'expired':
                    async def return_to_requests():
                        history.reset()
                        await request_history('refresh')
                    ui.button('Return to requests', on_click=return_to_requests).props('outline')
            elif not page.get('items'):
                ui.label('No records on this page.').classes('cn-muted')
            else:
                for item in page['items']:
                    with ui.column().classes('cn-summary-row'):
                        if history.kind == 'requests' and 'targets_preview' in item:
                            for line in request_summary(item):
                                ui.label(line)
                        for key, value in item.items():
                            if key != 'owned' and not (history.kind == 'requests' and key in {'key', 'targets_preview', 'ports_preview', 'target_count', 'port_count', 'host_count'}):
                                ui.label(f"{key.replace('_', ' ').capitalize()}: {history_value(key, value)}")
                        if history.kind == 'runs':
                            ui.label('Owned by this session' if item.get('owned') else 'View only')
                        if history.kind != 'hosts':
                            kinds = {'requests': 'runs', 'runs': 'rounds', 'rounds': 'hosts'}
                            kind = kinds[history.kind]
                            async def open_item(_, target=kind, identity=item['id'], view_only=(not item.get('owned') if history.kind == 'runs' else None)):
                                history.open(target, identity, view_only=view_only)
                                await request_history('back')
                            ui.button(f'View {kind}', on_click=open_item).props('outline')
            with ui.element('nav').props('aria-label="History pages"').classes('row cn-monitor-actions'):
                async def back():
                    history.back()
                    await request_history('back')
                async def previous():
                    history.previous()
                    await request_history('previous')
                async def next_page():
                    history.next(page.get('next_cursor'))
                    await request_history('next')
                async def refresh():
                    history.refresh()
                    await request_history('refresh')
                button = ui.button('Back', on_click=back).props('outline')
                button._props['data-monitor-history'] = 'back'
                button.set_enabled(bool(history.ancestors))
                button = ui.button('Previous page', on_click=previous).props('outline')
                button._props['data-monitor-history'] = 'previous'
                button.set_enabled(len(history.cursors) > 1)
                button = ui.button('Next page', on_click=next_page).props('outline')
                button._props['data-monitor-history'] = 'next'
                button.set_enabled(bool(page and page.get('next_cursor')))
                button = ui.button('Refresh history', on_click=refresh).props('outline')
                button._props['data-monitor-history'] = 'refresh'
        with history_area:
            draw_history()

    def focus_history(target):
        selector = json.dumps(f'[data-monitor-history="{target}"]:not([disabled])')
        client.run_javascript(f"(document.querySelector({selector}) || document.querySelector('[data-monitor-history=refresh]'))?.focus()")

    async def request_history(focus=None):
        if latest['history_query']:
            controller.release_monitor_history_page(latest['history_query'])
        latest['history_query'] = None
        latest['history_page'] = None
        latest['history_focus'] = focus
        try:
            latest['history_query'] = controller.request_monitor_history(history.kind, history.parent, history.cursor, 50)
        except (AttributeError, RuntimeError, ValueError):
            latest['history_page'] = {'error': 'History is unavailable. Try refreshing.'}
        await draw_history.refresh()
        if focus:
            focus_history(focus)

    async def live_has_focus():
        if not client.has_socket_connection:
            return False
        try:
            return bool(await client.run_javascript(f"document.getElementById({json.dumps(live_area.html_id)})?.contains(document.activeElement)", timeout=1))
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
            run.set_enabled(phase == 'ready' and not state.active_job_id and all(control.enabled for control, _ in fields.values()))
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
            download.set_enabled(display['available'] and latest['download'] is None)
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
                if previous_identity and previous_identity[:2] == identity[:2] and revision is not None:
                    set_changed(pending_live, f'Complete round revision {revision} is available; updating the displayed page.')
                latest['live_user_request'] = None
                if previous_identity and previous_identity[:2] != identity[:2]:
                    latest['live_page'] = None
                    await draw_live.refresh()
                latest['live_identity'] = identity
                latest['live_offset'] = 0
            key = (job, run_id, revision, latest['live_offset']) if job and run_id is not None and revision is not None else None
            if key != latest['live_key']:
                if key is None:
                    latest['live_page'] = None
                    await draw_live.refresh()
                if latest['live_query']:
                    controller.release_monitor_live_page(latest['live_query'])
                latest['live_query'] = None
                latest['live_key'] = key
                if key:
                    try:
                        latest['live_query'] = controller.request_monitor_live_page(*key, 50)
                    except (AttributeError, RuntimeError, ValueError):
                        latest['live_page'] = {'status': 'unavailable'}
                        await draw_live.refresh()
            if latest['live_query']:
                result = controller.monitor_live_page(latest['live_query'])
                if result is not None:
                    controller.release_monitor_live_page(latest['live_query'])
                    latest['live_query'] = None
                    if result.get('status') == 'expired':
                        latest['live_offset'] = 0
                        latest['live_key'] = None
                    else:
                        latest['pending_live'] = result
            if latest.get('pending_live') is not None:
                focus_target = latest.get('live_user_request')
                if focus_target or not await live_has_focus():
                    latest['live_page'] = latest.pop('pending_live')
                    latest['live_user_request'] = None
                    set_changed(pending_live, '')
                    await draw_live.refresh()
                    if focus_target:
                        selector = json.dumps(f'[data-monitor-live="{focus_target}"]:not([disabled])')
                        client.run_javascript(f"(document.querySelector({selector}) || document.querySelector('[data-monitor-live]:not([disabled])'))?.focus()")
                else:
                    set_changed(pending_live, f"Complete round revision {latest['pending_live'].get('revision', revision)} is available. Move focus away from these controls to show it.")
            if latest['history_dirty'] and phase in {'ready', 'running', 'stopping', 'saving'}:
                latest['history_dirty'] = False
                await request_history()
            if latest['history_query']:
                result = controller.monitor_history_page(latest['history_query'])
                if result is not None:
                    controller.release_monitor_history_page(latest['history_query'])
                    latest['history_query'] = None
                    latest['history_page'] = result
                    focused = False
                    if client.has_socket_connection:
                        try:
                            focused = bool(await client.run_javascript(f"document.getElementById({json.dumps(history_area.html_id)})?.contains(document.activeElement)", timeout=1))
                        except TimeoutError:
                            pass
                    await draw_history.refresh()
                    if focused:
                        focus_history(latest.get('history_focus') or 'refresh')

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
        if latest['live_query']:
            controller.release_monitor_live_page(latest['live_query'])
            latest['live_query'] = None
        if latest['history_query']:
            controller.release_monitor_history_page(latest['history_query'])
            latest['history_query'] = None
    client.on_delete(release_queries)
    targets.on_value_change(lambda _: poll())
    ui.timer(0, poll, once=True)
    ui.timer(0.5, poll)


def live_fields(row):
    tcp = ', '.join(f"{entry['port']}: {entry['result']}" for entry in row.get('tcp', [])) or 'Not checked'
    return [('Host', str(row.get('host') or 'Unknown')), ('Address', str(row.get('address') or 'Unknown')),
            ('Result', str(row.get('result') or 'Unknown')), ('TCP', tcp)]


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
