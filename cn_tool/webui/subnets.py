"""Subnets presentation. Redraws and navigation never submit worker operations."""
from dataclasses import dataclass, field
import json
from html import escape


@dataclass
class Presentation:
    selection: object = None
    result_identity: object = None
    summary_scroll: tuple = (0, 0)
    pagination: dict = field(default_factory=lambda: {"rowsPerPage": 25, "page": 1})

    def attach(self, result, operation_id=None):
        identity = tuple(group['id'] for group in result.get('detail_groups', []))
        result_identity = ("operation", operation_id) if operation_id is not None else identity
        changed = result_identity != self.result_identity if operation_id is not None else set(identity) != set(self.result_identity or ())
        if changed or self.result_identity is None:
            self.pagination = {"rowsPerPage": 25, "page": 1}
            self.summary_scroll = (0, 0)
            self.selection = identity[0] if len(identity) == 1 else None
        self.result_identity = result_identity

    def select(self, identity):
        self.selection = identity

    def groups(self, result):
        return [group for group in result.get('detail_groups', [])
                if self.selection == 'all' or group['id'] == self.selection]


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
.cn-network { font-family:ui-monospace,monospace; }
:focus-visible { outline:3px solid #145C87; outline-offset:3px; }
.q-btn { text-transform:none; font-weight:600; }
@media(max-width:600px) { .nicegui-content {padding:16px 12px;} .cn-panel {padding:14px;} }
'''


def render_subnets(controller):
    from nicegui import ui
    from cn_tool.core.interaction import CredentialReply

    ui.add_css(CSS)
    ui.colors(primary='#145C87')
    view = Presentation()
    latest = {'snapshot': None, 'fingerprint': None, 'prompt': None, 'download': None, 'download_error': '', 'dialog': None}
    with ui.row().classes('w-full items-center justify-between'):
        ui.label('Subnets').mark('title').classes('text-h4')
        quit_button = ui.button('Quit application', on_click=controller.quit).props('outline')
    scope_label = ui.label('Attaching to the application…').classes('cn-muted')
    with ui.row().classes('items-center'):
        forget = ui.button('Forget saved credentials', on_click=controller.forget_credentials).props('outline')
        store_status = ui.label('').props('role=status aria-live=polite').classes('cn-muted')
    recovery = ui.label('If saved credentials are refused, select Forget saved credentials, then Quit and relaunch to enter a different login.').classes('cn-muted text-sm')
    recovery.set_visibility(False)
    ui.label('Closing this tab keeps the application running. Quit finishes active work and saves, then runs configured exit actions.').classes('cn-muted text-sm')
    status = ui.label('Attaching…').props('role=status aria-live=polite')
    report_location = ui.label('').classes('cn-muted text-sm')
    report_warning = ui.label('').props('role=status').classes('text-warning')
    elapsed = ui.label('').classes('cn-muted')
    with ui.column().classes('cn-panel'):
        ui.label('Targets')
        targets = ui.textarea(placeholder='192.0.2.1\n2001:db8::/64').props('outlined autogrow aria-label=Targets').classes('w-full')
        ui.label('One IP address or subnet per line').classes('cn-muted')
        with ui.row():
            async def submit():
                controller.submit(targets.value.splitlines())
                await poll()
            run = ui.button('Look up', on_click=submit)
            stop = ui.button('Stop', on_click=lambda: controller.cancel(controller.snapshot().active_job_id)).props('outline')
    results = ui.column().classes('w-full')
    report = ui.label('').props('role=status').classes('cn-muted')
    ui.label('Download copies the existing accumulated report after pending saves finish. A failed lookup save may leave only earlier data.').classes('cn-muted text-sm')
    download = ui.button('Download report', on_click=lambda: request_download()).props('outline')

    def request_download():
        if latest['download'] is None:
            latest['download_error'] = ''
            latest['download'] = controller.request_report_snapshot()
            download.disable()
            report.set_text('Preparing a consistent report download…')

    def table(rows, *, summary=False):
        if not rows:
            ui.label('No rows.').classes('cn-muted')
            return
        keys = list(dict.fromkeys(key for row in rows for key in row if key not in {'id', '__row'}))
        columns = [dict(name=key, label=key, field=key, align='left', sortable=True) for key in keys]
        if summary:
            columns.append(dict(name='action', label='Details', field='id', align='left'))
        display_rows = [{key: str(value) if isinstance(value, (dict, list, tuple)) else value for key, value in row.items()} for row in rows]
        ui.label('Scroll the table horizontally to see all columns' + (' and View details.' if summary else '.')).classes('cn-muted text-sm')
        widget = ui.table(columns=columns, rows=[dict(row, __row=row.get('__row', row.get('id', f'row-{index}'))) for index, row in enumerate(display_rows)], row_key='__row',
                          pagination=view.pagination if summary else 25,
                          on_pagination_change=(lambda event: setattr(view, 'pagination', event.value)) if summary else None).classes('cn-table').props('flat bordered wrap-cells')
        widget.props('role=region aria-label="Subnet result table"')
        ui.label(f'{len(rows)} ' + ('row' if len(rows) == 1 else 'rows')).classes('cn-muted text-sm')
        if summary:
            latest['summary_table'] = widget.html_id
            widget.add_slot('body-cell-action', '''<q-td :props="props"><q-btn v-if="props.row.id" flat color="primary" label="View details" @click="$parent.$emit('details', props.row.id)" /></q-td>''')
            widget.on('details', lambda event: navigate(event.args))

    async def navigate(identity):
        client = ui.context.client
        if view.selection is None and latest.get('summary_table'):
            table_id = json.dumps(latest['summary_table'])
            view.summary_scroll = await client.run_javascript(f'[window.scrollY, document.getElementById({table_id})?.querySelector(".q-table__middle")?.scrollLeft || 0]')
        view.select(identity)
        await draw_results.refresh()
        if identity is None and latest.get('summary_table'):
            table_id = json.dumps(latest['summary_table'])
            vertical, horizontal = view.summary_scroll
            client.run_javascript(f'window.scrollTo(0, {int(vertical)}); const table = document.getElementById({table_id})?.querySelector(".q-table__middle"); if(table) table.scrollLeft = {int(horizontal)};')

    def new_lookup():
        view.select('input')
        draw_results.refresh()
        targets.run_method('focus')

    @ui.refreshable
    def draw_results():
        snapshot = latest['snapshot']
        if snapshot is None or snapshot.result is None:
            return
        result = snapshot.result
        groups = result.get('detail_groups', [])
        if snapshot.phase in {'running', 'stopping', 'saving'}:
            ui.label('Previous lookup results').classes('text-weight-bold')
        if view.selection == 'input':
            return
        with ui.row().classes('items-center'):
            if view.selection is not None and len(groups) > 1:
                ui.button('Back to summary', on_click=lambda: navigate(None)).props('outline')
            if len(groups) > 1 and view.selection is None:
                ui.button('Show all details', on_click=lambda: navigate('all'))
            ui.button('New lookup', on_click=new_lookup).props('outline')
        if not result.get('stopped'):
            ui.label('Lookup completed with input issues.' if result.get('input_errors') or result.get('misses') else 'Lookup completed.').classes('text-weight-bold')
        if result.get('stopped'):
            ui.label('Stopped. Available partial results are shown.').props('role=status')
        for item, problem in result.get('input_errors', {}).items():
            ui.label(f'{item}: {problem}').classes('text-negative')
        for item in result.get('misses', []):
            ui.label(f'{item}: no matching network').classes('cn-muted')
        if not groups:
            ui.label('No matching networks.').classes('text-weight-bold')
        if view.selection is None and len(groups) > 1:
            ui.label(f'{len(groups)} networks').classes('text-h6')
            table(result.get('summary', []), summary=True)
        else:
            for group in view.groups(result):
                with ui.column().classes('cn-panel'):
                    ui.label(group['network']).classes('text-h5 cn-network')
                    ui.label('View: ' + str(group.get('network_view') or 'default')).classes('cn-muted')
                    ui.label('Inputs: ' + ', '.join(group.get('original_inputs', [])))
                    for warning in group.get('warnings', []):
                        ui.label(str(warning)).classes('text-negative')
                    for name, rows in group.get('tables', {}).items():
                        ui.label(name).classes('text-h6')
                        table(rows)
        if result.get('containers'):
            ui.label('Child containers').classes('text-h6')
            table(result['containers'])

    with results:
        draw_results()

    async def clear_credentials():
        active = latest['dialog']
        latest['dialog'] = None
        latest['dialog_status'] = None
        if active is None:
            return
        dialog, username_id, password_id = active
        try:
            # Await clearing before removing controls so detached DOM nodes do not
            # retain typed secrets when a different tab answers the same request.
            await dialog.client.run_javascript(
                'for (const id of ' + json.dumps([username_id, password_id]) + ') {'
                'const field = document.getElementById(id); if (field) field.value = ""; }')
        finally:
            dialog.close()
            dialog.delete()

    def credentials(request):
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
                if latest['dialog'] and latest['dialog'][0] is dialog:
                    await clear_credentials()
                current = controller.snapshot().credential_request
                if current and current['request_id'] == request['request_id']:
                    controller.reply_credentials(request['request_id'], answer, remember=values['remember'])
                await poll()
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
                ui.button('Forget saved credentials', on_click=controller.forget_credentials).props('outline')
        dialog.open()

    async def poll():
        snapshot = controller.snapshot()
        latest['snapshot'] = snapshot
        scope_label.set_text(f"{snapshot.scope or 'Configured scope pending'} | Account: {snapshot.username or 'pending'}")
        report_location.set_text(f'Report location: {snapshot.report_location}' if snapshot.report_location else '')
        report_warning.set_text(snapshot.report_warning)
        busy = snapshot.phase in {'running', 'stopping', 'saving', 'closing'}
        run.set_enabled(snapshot.phase == 'ready' and not snapshot.active_job_id and bool((targets.value or '').strip()))
        stop.set_visibility(snapshot.phase in {'running', 'stopping', 'saving'})
        stop.set_enabled(snapshot.phase == 'running')
        quit_button.set_enabled(snapshot.phase not in {'closing', 'closed'})
        forget.set_enabled(snapshot.phase not in {'closing', 'closed', 'failed'})
        storage = snapshot.credential_store or {}
        store_status.set_text(storage.get('message', ''))
        recovery.set_visibility(snapshot.saved_login_restored)
        if latest.get('dialog_status') is not None:
            latest['dialog_status'].set_text(storage.get('message', ''))
        phase_messages = {'starting': 'Checking configuration and credentials…', 'ready': 'Ready',
                   'setup_required': 'Setup required. Check configuration, then Retry setup.',
                   'failed': 'Application failed. Quit and relaunch to start a new session.',
                   'closing': 'Finishing active work and configured exit actions…', 'closed': 'Application closed.',
                   'stopping': 'Stopping…', 'saving': 'Saving report…'}
        message = (snapshot.progress_stage or 'Working…') if snapshot.phase == 'running' else phase_messages.get(snapshot.phase, snapshot.phase)
        if snapshot.error:
            message = snapshot.error.get('message', str(snapshot.error)) if isinstance(snapshot.error, dict) else str(snapshot.error)
        status.set_text(message)
        elapsed.set_text(f'Elapsed: {int(snapshot.elapsed_seconds)}s' if busy else '')
        retry.set_visibility(snapshot.phase == 'setup_required')
        state = snapshot.report_state or {}
        report.classes(remove='text-negative')
        if state.get('state', state.get('status')) == 'failed':
            report.classes(add='text-negative')
        report.set_text({'off': 'Reporting off. Downloads contain only the existing report.', 'saving': 'Saving report',
                         'saved': 'Report saved', 'failed': 'Report save failed', 'idle': state.get('message', 'No report saved')}.get(state.get('state', state.get('status')), '')
                        + (f" — {state['filename']}" if state.get('filename') else '')
                        + (f". {state['message']}" if state.get('message') and state.get('state', state.get('status')) != 'idle' else ''))
        download.set_enabled(snapshot.phase in {'ready', 'running', 'stopping', 'saving'} and latest['download'] is None)
        if latest['download'] is not None:
            report.set_text('Preparing a consistent report download…')
        elif latest['download_error']:
            report.set_text(latest['download_error'])
        prepared = controller.report_completion(latest['download']) or {} if latest['download'] else {}
        if prepared.get('request_id') == latest['download']:
            if prepared.get('status') == 'ready':
                ui.download('/download/' + latest['download'])
                latest['download'] = None
            elif prepared.get('status') == 'failed':
                latest['download_error'] = prepared.get('error', 'Report download failed.')
                report.set_text(latest['download_error'])
                controller.acknowledge_report_completion(latest['download'])
                latest['download'] = None
        request = snapshot.credential_request
        request_id = request['request_id'] if request and snapshot.phase not in {'closing', 'closed', 'failed'} else None
        if request_id != latest['prompt']:
            latest['prompt'] = request_id
            await clear_credentials()
            if request_id:
                credentials(request)
        if snapshot.result is not None:
            view.attach(snapshot.result, snapshot.result_job_id)
        fingerprint = repr((snapshot.result_job_id, snapshot.result, snapshot.phase, snapshot.error))
        if fingerprint != latest['fingerprint']:
            latest['fingerprint'] = fingerprint
            draw_results.refresh()

    retry = ui.button('Retry setup', on_click=controller.retry_initialize).props('outline')
    targets.on_value_change(lambda _: poll())
    ui.timer(0, poll, once=True)
    ui.timer(.25, poll)
