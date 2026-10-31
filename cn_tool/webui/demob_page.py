"""Consent-gated site demobilization presentation."""
import asyncio
import json
from dataclasses import replace
from html import escape

from cn_tool.utils import oscompat

from .subnets import CSS, report_display


def render_demob(controller):
    from nicegui import ui
    from cn_tool.core.interaction import CredentialReply

    client = ui.context.client
    ui.add_css(CSS + '''
.cn-demob { min-width:0; overflow-wrap:anywhere; }
.cn-demob .q-btn, .cn-demob .q-field { max-width:100%; min-width:0; }
.cn-demob-list { list-style:none; margin:0; padding:0; width:100%; }
.cn-demob-row { width:100%; border-bottom:1px solid #CBD5DF; padding:12px 0; gap:3px; }
.cn-demob-line { white-space:pre-wrap; overflow-wrap:anywhere; font-family:ui-monospace,monospace; }
''')
    ui.colors(primary='#145C87')
    latest = dict(preview=None, preview_page=None, preview_query=None, preview_offsets=[0],
                  result_job=None, result_page=None, result_query=None, result_offsets=[0],
                  result_revision=None, attempt_revision=None, outcome=None, attempt_result=None,
                  download=None, download_error='', prompt=None, dialog=None, note='', discovery=None,
                  preview_focus=None, result_focus=None)
    lock, prompt_lock = asyncio.Lock(), asyncio.Lock()
    with ui.row().classes('w-full items-center justify-between cn-demob'):
        ui.label('Site Demobilization').mark('title').classes('text-h4')
        quit_button = ui.button('Quit application', on_click=controller.quit).props('outline')
    with ui.element('nav').props('aria-label=Tools').classes('row items-center gap-4 cn-demob'):
        ui.link('Subnets', '/')
        ui.link('IP', '/ip')
        ui.link('Ping', '/ping')
        ui.link('Monitor', '/monitor')
        ui.link('Configuration Search', '/config-search')
        ui.link('Site Demobilization', '/demobilization').props('aria-current=page')
    ui.label('First look up this site’s networks in Infoblox. Review the networks, then choose whether to search the configured live configuration repository.').classes('cn-muted')
    if oscompat.is_macos():
        ui.label('The configuration scan is currently unavailable on macOS. You can still look up site networks.').props('role=status').classes('text-warning')
    ui.label('A search can include up to 200 distinct IPv4 networks. Cached configuration search is unavailable here.').classes('cn-muted')
    scope_label = ui.label('Configured scope pending').classes('cn-muted')
    with ui.row().classes('items-center'):
        forget = ui.button('Forget saved credentials', on_click=controller.forget_credentials).props('outline')
        store_status = ui.label('').props('role=status aria-live=polite').classes('cn-muted')
    status = ui.label('Attaching…').props('role=status aria-live=polite').classes('text-weight-bold')
    report_warning = ui.label('').props('role=status aria-live=polite').classes('text-warning')
    with ui.column().classes('cn-panel cn-demob'):
        site = ui.input('Site code', placeholder='SITE1').props('outlined maxlength=1024').classes('w-full')
        error = ui.label('').props('role=alert').classes('text-negative')
        async def lookup():
            value = (site.value or '').strip()
            if not value:
                try:
                    controller.discard_demob_for_replacement()
                except (RuntimeError, OSError, EOFError):
                    error.set_text('The previous preview could not be cleared. Try again.')
                else:
                    error.set_text('Enter a site code.')
                    latest['note'] = 'Previous preview cleared.'
                await poll()
                return
            try:
                controller.submit_demob_lookup(value)
            except RuntimeError:
                error.set_text('Another operation is running or the session is unavailable. Wait for it to finish or relaunch the application.')
                return
            except ValueError:
                error.set_text('The site code is too long or invalid. Check it and try again.')
                return
            except (OSError, EOFError):
                error.set_text('The session is unavailable. Quit and relaunch the application.')
                return
            error.set_text('')
            latest['note'] = ''
            await poll()
        def stop_work():
            state = controller.page_snapshot('demob').state
            if state.active_lookup_type == 'demob' and state.active_job_id and state.phase == 'running':
                controller.cancel(state.active_job_id)
        with ui.row().classes('flex-wrap'):
            run = ui.button('Look up site networks', on_click=lookup)
            run.disable()
            stop = ui.button('Stop', on_click=stop_work).props('outline')
            stop.set_visibility(False)
    discovery_announcement = ui.label('').props('role=status aria-live=polite aria-atomic=true').classes('text-warning')
    discovery_announcement._props['data-demob-announcement'] = 'true'
    preview_message = ui.label('').props('role=status aria-live=polite').classes('cn-muted')
    preview_area = ui.column().classes('w-full cn-demob')

    async def request_preview_page():
        if latest['preview_query']:
            controller.release_demob_page(latest['preview_query'])
            latest['preview_query'] = None
        preview = latest['preview'] or {}
        if not preview.get('token'):
            return
        try:
            latest['preview_query'] = controller.request_demob_page(preview['token'], latest['preview_offsets'][-1], 50)
            preview_message.set_text('Loading site networks…')
        except (ValueError, RuntimeError, OSError, EOFError):
            preview_message.set_text('Preview expired or is unavailable. Look up the site again.')

    async def preview_move(direction):
        if direction == 'previous' and len(latest['preview_offsets']) > 1:
            latest['preview_offsets'].pop()
        elif direction == 'next' and latest['preview_page'] and latest['preview_page'].get('next_offset') is not None:
            latest['preview_offsets'].append(latest['preview_page']['next_offset'])
        else:
            return
        latest['preview_page'] = None
        latest['preview_focus'] = direction
        await request_preview_page()
        await draw_preview.refresh()

    async def confirm(token):
        try:
            controller.confirm_demob_search(token)
        except (ValueError, RuntimeError, OSError, EOFError):
            latest['note'] = 'Preview expired or is unavailable. Look up the site again.'
        else:
            latest['note'] = ''
        await poll()

    async def decline(token):
        controller.decline_demob(token)
        latest['note'] = 'Search declined. Look up the site again to start a new check.'
        await poll()

    @ui.refreshable
    def draw_preview():
        preview = latest['preview']
        if not preview:
            return
        with ui.element('section').props('aria-label="Site network preview"').classes('cn-panel cn-demob'):
            ui.label('Review site networks').classes('text-h6')
            ui.label(f"Site: {preview['site']}")
            page = latest['preview_page']
            if page and page['status'] == 'ready':
                with ui.element('ul').props('aria-label="Site networks"').classes('cn-demob-list'):
                    for row in page['rows']:
                        with ui.element('li').classes('cn-demob-row'):
                            keys = list(row)
                            preferred = [key for key in keys if key.lower() in ('network', 'network view')]
                            for key in preferred + [key for key in keys if key not in preferred]:
                                label = ui.label(f'{key}: {row[key]}')
                                if key in preferred:
                                    label.classes('text-weight-bold')
                with ui.element('nav').props('aria-label="Site network pages"').classes('row flex-wrap'):
                    previous = ui.button('Previous network page', on_click=lambda: preview_move('previous')).props('outline')
                    previous._props['data-demob-network-page'] = 'previous'
                    previous.set_enabled(len(latest['preview_offsets']) > 1)
                    next_button = ui.button('Next network page', on_click=lambda: preview_move('next')).props('outline')
                    next_button._props['data-demob-network-page'] = 'next'
                    next_button.set_enabled(page['next_offset'] is not None)
            elif page:
                ui.label('Preview expired or is unavailable. Look up the site again.').props('role=alert')
            if preview.get('token'):
                ui.label('Continue only if these are the networks you want to check. Configuration files will be read after you choose Search configurations.').classes('cn-muted')
                if oscompat.is_macos():
                    ui.label('Configuration scans are unavailable on macOS.').classes('text-warning')
                with ui.row().classes('flex-wrap'):
                    search = ui.button('Search configurations', on_click=lambda: confirm(preview['token']))
                    search.set_enabled(not oscompat.is_macos() and bool(page and page.get('status') == 'ready'))
                    ui.button('Decline', on_click=lambda: decline(preview['token'])).props('outline')
    with preview_area:
        draw_preview()

    with ui.column().classes('cn-panel cn-demob'):
        ui.label('Latest check').classes('text-h6')
        outcome = ui.label('No check yet.').props('role=status aria-live=polite')
        discovery_area = ui.column().props('role=status aria-live=polite').classes('w-full cn-demob')
        diagnostics = ui.column().classes('w-full cn-demob')
        report = ui.html('').props('role=status aria-live=polite').classes('cn-muted')
        ui.label('The accumulated workbook can contain full device configurations, including sensitive information. Handle downloads accordingly.').classes('cn-muted')
        def download_report():
            try:
                latest['download'] = controller.request_report_snapshot()
                latest['download_error'] = ''
                download.disable()
            except (RuntimeError, OSError, EOFError):
                latest['download_error'] = 'Report download is unavailable.'
        download = ui.button('Download accumulated report', on_click=download_report).props('outline')
        download.disable()
    result_message = ui.label('').props('role=status aria-live=polite').classes('cn-muted')
    result_area = ui.column().classes('w-full cn-demob')

    async def request_result_page():
        if latest['result_query']:
            controller.release_config_search_page(latest['result_query'])
            latest['result_query'] = None
        if not latest['result_job']:
            result_message.set_text('')
            return
        try:
            latest['result_query'] = controller.request_config_search_page(latest['result_job'], latest['result_offsets'][-1], 50)
            result_message.set_text('Loading matches…')
        except (ValueError, RuntimeError, OSError, EOFError):
            latest['result_page'] = {'status': 'unavailable'}
            result_message.set_text('Results are unavailable. Run the check again.')

    async def result_move(direction):
        if direction == 'previous' and len(latest['result_offsets']) > 1:
            latest['result_offsets'].pop()
        elif direction == 'next' and latest['result_page'] and latest['result_page'].get('next_offset') is not None:
            latest['result_offsets'].append(latest['result_page']['next_offset'])
        else:
            return
        latest['result_page'] = None
        latest['result_focus'] = direction
        await request_result_page()
        await draw_results.refresh()

    @ui.refreshable
    def draw_results():
        page = latest['result_page']
        if not page:
            return
        with ui.element('section').props('aria-label="Configuration matches"').classes('cn-panel cn-demob'):
            ui.label('Configuration matches').classes('text-h6')
            ui.label('Line numbers start at 0.').classes('cn-muted')
            if page['status'] != 'ready':
                ui.label('Results are unavailable. Run the check again.').props('role=alert')
            else:
                for row in page['rows']:
                    with ui.column().classes('cn-demob-row'):
                        ui.label(f'{row[1]} · line {row[2]}').classes('text-weight-bold')
                        ui.label(f'Search: {row[0]}').classes('cn-muted')
                        ui.label(row[3]).classes('cn-demob-line')
                        ui.label(f'File: {row[4]}').classes('cn-muted')
                with ui.element('nav').props('aria-label="Configuration result pages"').classes('row flex-wrap'):
                    previous = ui.button('Previous result page', on_click=lambda: result_move('previous')).props('outline')
                    previous._props['data-demob-result-page'] = 'previous'
                    previous.set_enabled(len(latest['result_offsets']) > 1)
                    next_button = ui.button('Next result page', on_click=lambda: result_move('next')).props('outline')
                    next_button._props['data-demob-result-page'] = 'next'
                    next_button.set_enabled(page['next_offset'] is not None)
    with result_area:
        draw_results()

    async def clear_credentials():
        current = latest['dialog']
        latest['dialog'] = None
        if not current:
            return
        dialog, username_id, password_id = current
        try:
            await dialog.client.run_javascript(
                'for (const id of ' + json.dumps([username_id, password_id]) + ') {'
                'const field = document.getElementById(id); if (field) field.value = ""; }')
        finally:
            dialog.close()
            dialog.delete()
            dialog.client.run_javascript('window.cnCredentialInvoker?.focus(); window.cnCredentialInvoker = null;')

    async def credentials(request):
        await client.run_javascript('(() => { window.cnCredentialInvoker = document.activeElement; return true; })()')
        current = controller.current_credential_request()
        if not current or current['request_id'] != request['request_id']:
            return False
        with ui.dialog().props('persistent') as dialog, ui.card().classes('w-full max-w-md'):
            ui.label(f"Credentials: {request['account']}").classes('text-h6')
            ui.label(request.get('message', ''))
            username_id = f'credential-username-{dialog.id}'
            password_id = f'credential-password-{dialog.id}'
            remember_id = f'credential-remember-{dialog.id}'
            latest['dialog'] = (dialog, username_id, password_id)
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
            ui.html(fields, sanitize=False).classes('w-full flex flex-col gap-2')
            async def reply(event):
                values = event.args
                answer = None if values['cancel'] else CredentialReply(values['username'], values['password'])
                async with prompt_lock:
                    if latest['dialog'] and latest['dialog'][0] is dialog:
                        await clear_credentials()
                        latest['prompt'] = None
                    current = controller.current_credential_request()
                    if current and current['request_id'] == request['request_id']:
                        controller.reply_credentials(request['request_id'], answer, remember=values['remember'])
                await poll()
            def handler(cancel):
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

    async def poll():
        if lock.locked() or client.is_deleted:
            return
        async with lock:
            page_state = controller.page_snapshot('demob', result_revision=latest['result_revision'],
                                                  attempt_revision=latest['attempt_revision'])
            state = page_state.state
            phase = state.phase
            active = bool(state.active_job_id and state.active_lookup_type == 'demob')
            message = {'ready': 'Ready', 'starting': 'Starting application…', 'stopping': 'Stopping…',
                       'saving': 'Saving report…', 'closing': 'Finishing active work…',
                       'closed': 'Application closed.', 'failed': 'Application failed. Quit and relaunch.',
                       'setup_required': 'Application setup is required.'}.get(phase, phase)
            if phase == 'running':
                message = ('Site check in progress' if active else 'Another operation is running')
                if state.progress_stage:
                    message += ': ' + state.progress_stage
            if state.error:
                message = str(state.error.get('message', state.error) if isinstance(state.error, dict) else state.error)
            status.set_text(message)
            scope_label.set_text(f"{state.scope or 'Configured scope pending'} | Account: {state.username or 'pending'}")
            report_warning.set_text(state.report_warning or '')
            store_status.set_text((state.credential_store or {}).get('message', ''))
            run.set_enabled(phase == 'ready' and not state.active_job_id)
            stop.set_visibility(active and phase in {'running', 'stopping', 'saving'})
            stop.set_enabled(active and phase == 'running')
            forget.set_enabled(phase not in {'closing', 'closed', 'failed'})
            quit_button.set_enabled(phase not in {'closing', 'closed'})
            async with prompt_lock:
                request = controller.current_credential_request()
                request_id = request['request_id'] if request else None
                if request_id != latest['prompt']:
                    await clear_credentials()
                    latest['prompt'] = None
                    request = controller.current_credential_request()
                    if request and await credentials(request):
                        latest['prompt'] = request['request_id']
            preview = state.demob_preview
            if preview != latest['preview']:
                announcement = []
                if preview:
                    if preview['status'] == 'partial_error':
                        announcement.append('Network discovery is incomplete. Any search will be partial and will not be saved as a report.')
                    if preview['message']:
                        announcement.append(preview['message'])
                    announcement.extend(preview['notices'])
                discovery_announcement.set_text(' '.join(announcement))
                old = latest['preview']
                if old and old.get('token') and not preview and not active and not latest['note']:
                    latest['note'] = 'Preview expired or is unavailable. Look up the site again.'
                if latest['preview_query']:
                    controller.release_demob_page(latest['preview_query'])
                latest.update(preview=preview, preview_query=None, preview_page=None, preview_offsets=[0])
                if preview and preview.get('token'):
                    latest['note'] = ''
                    await request_preview_page()
                else:
                    preview_message.set_text(latest['note'])
                await draw_preview.refresh()
            elif latest['note'] and not preview:
                preview_message.set_text(latest['note'])
            if latest['preview_query']:
                page = controller.demob_page(latest['preview_query'])
                if page is not None:
                    controller.release_demob_page(latest['preview_query'])
                    latest['preview_query'] = None
                    latest['preview_page'] = page
                    rows = page['rows']
                    if page['status'] == 'ready':
                        preview_message.set_text(f"Showing {page['offset'] + 1}–{page['offset'] + len(rows)} of {page['total']} site networks." if rows else 'No site networks to show.')
                    else:
                        preview_message.set_text('Preview expired or is unavailable. Look up the site again.')
                    await draw_preview.refresh()
                    if latest['preview_focus']:
                        selector = json.dumps(f"[data-demob-network-page='{latest['preview_focus']}']:not([disabled])")
                        client.run_javascript(f"(document.querySelector({selector}) || document.querySelector('[data-demob-network-page]:not([disabled])'))?.focus()")
                        latest['preview_focus'] = None
            discovery = state.demob_discovery
            if discovery != latest['discovery']:
                latest['discovery'] = discovery
                discovery_area.clear()
                if discovery:
                    with discovery_area:
                        if discovery['status'] == 'partial_error':
                            ui.label('Network discovery was incomplete. This check is partial and will not be saved as a report.').classes('text-warning')
                        if discovery['message']:
                            ui.label(discovery['message']).classes('text-warning')
                        for notice in discovery['notices']:
                            ui.label(notice).classes('text-warning')
            if page_state.attempt_changed:
                latest['attempt_revision'] = page_state.attempt_revision
                latest['outcome'] = page_state.outcome
                latest['attempt_result'] = page_state.attempt_result
                diagnostics.clear()
                with diagnostics:
                    detail = (latest['outcome'] or {}).get('details') or {}
                    if not latest['discovery'] and detail.get('discovery_message'):
                        ui.label(detail['discovery_message']).classes('text-warning')
                    for notice in detail.get('notices', []) if not latest['discovery'] else []:
                        ui.label(notice).classes('text-warning')
                    missing = (latest['attempt_result'] or {}).get('missing_nets', [])
                    if missing:
                        ui.label('No configuration match for: ' + ', '.join(missing)).classes('cn-muted')
            if page_state.result_changed:
                latest['result_revision'] = page_state.result_revision
            previous = bool(page_state.result_job_id and page_state.attempt_job_id != page_state.result_job_id)
            title = str((latest['outcome'] or {}).get('message') or ('Check in progress.' if active else 'No check yet.'))
            if previous:
                title += ' Showing results from an earlier completed check.'
            outcome.set_text(title)
            display = report_display(replace(state, latest_report_state=page_state.attempt_report_state or state.latest_report_state))
            report.set_content(escape(latest['download_error']) if latest['download_error'] else display['text'])
            download.set_enabled(display['available'] and latest['download'] is None)
            if latest['download']:
                completion = controller.report_completion(latest['download']) or {}
                if completion.get('status') == 'ready':
                    with client:
                        ui.download('/download/' + latest['download'])
                    latest['download'] = None
                elif completion.get('status') == 'failed':
                    controller.acknowledge_report_completion(latest['download'])
                    latest['download'] = None
                    latest['download_error'] = 'Report download failed.'
            if page_state.result_job_id != latest['result_job']:
                latest.update(result_job=page_state.result_job_id, result_page=None, result_offsets=[0])
                await request_result_page()
                await draw_results.refresh()
            if latest['result_query']:
                page = controller.config_search_page(latest['result_query'])
                if page is not None:
                    controller.release_config_search_page(latest['result_query'])
                    latest['result_query'] = None
                    latest['result_page'] = page
                    rows = page['rows']
                    if page['status'] == 'ready':
                        result_message.set_text(f"Showing {page['offset'] + 1}–{page['offset'] + len(rows)} of {page['total']} matches." if rows else 'No configuration matches.')
                    else:
                        result_message.set_text('Results are unavailable. Run the check again.')
                    await draw_results.refresh()
                    if latest['result_focus']:
                        selector = json.dumps(f"[data-demob-result-page='{latest['result_focus']}']:not([disabled])")
                        client.run_javascript(f"(document.querySelector({selector}) || document.querySelector('[data-demob-result-page]:not([disabled])'))?.focus()")
                        latest['result_focus'] = None

    def release_queries():
        if latest['preview_query']:
            controller.release_demob_page(latest['preview_query'])
        if latest['result_query']:
            controller.release_config_search_page(latest['result_query'])
    client.on_delete(release_queries)
    ui.timer(0, poll, once=True)
    ui.timer(.5, poll)
