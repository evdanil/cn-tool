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
.nicegui-content:has(.cn-demob) { gap:12px; }
.cn-demob-empty:empty { display:none; }
.cn-demob h2 { margin:0; }
.cn-demob.cn-panel:not(.cn-demob-setup) { display:flex; flex-direction:column; gap:10px; }
.cn-demob-setup { display:flex; align-items:center; flex-wrap:wrap; gap:12px; padding:14px 18px; }
.cn-demob .cn-demob-site { flex:1 1 200px; max-width:420px; }
.cn-demob-help { font-size:14px; color:#526675; }
.cn-demob-help summary, .cn-demob-source summary { cursor:pointer; width:fit-content; color:#145C87; }
.cn-demob summary::before { content:"▸ "; }
.cn-demob details[open] > summary::before, details.cn-demob[open] > summary::before { content:"▾ "; }
.cn-demob-help > .cn-muted { margin-top:8px; }
.cn-demob-consent { width:100%; display:flex; align-items:center; flex-wrap:wrap; gap:10px; }
.cn-demob-consent .cn-muted { flex:1 1 280px; font-size:14px; }
.cn-demob-toolbar { width:100%; display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:8px; }
.cn-demob-pager { display:flex; flex-wrap:wrap; align-items:center; gap:8px; }
.cn-demob-filter { display:flex; flex-wrap:wrap; align-items:center; gap:8px; width:100%; }
.cn-demob-filter .q-field { flex:1 1 145px; min-width:0; }
.cn-demob-scroll { width:100%; max-height:390px; overflow:auto; border:1px solid #CBD5DF; border-radius:4px; }
.cn-demob-scroll.matches { max-height:460px; }
.cn-demob-table { width:100%; border-collapse:separate; border-spacing:0; text-align:left; font-size:14px; }
.cn-demob-table th { position:sticky; top:0; z-index:1; background:#EDF2F6; color:#172B3A; font-weight:650; }
.cn-demob-table th, .cn-demob-table td { padding:9px 12px; border-bottom:1px solid #CBD5DF; vertical-align:top; }
.cn-demob-sort .q-btn__content { white-space:normal; }
.cn-demob-table th[aria-sort=ascending] .cn-demob-sort::after { content:' ▲'; }
.cn-demob-table th[aria-sort=descending] .cn-demob-sort::after { content:' ▼'; }
.cn-demob-table tr:last-child td { border-bottom:0; }
.cn-demob-table tbody tr:nth-child(even) { background:#F5F7FA; }
.cn-demob-networks { min-width:640px; }
.cn-demob-networks td { min-width:130px; max-width:360px; overflow-wrap:anywhere; }
.cn-demob-matches { min-width:560px; table-layout:fixed; }
.cn-demob-matches th:nth-child(1) { width:150px; }
.cn-demob-matches th:nth-child(2) { width:65px; }
.cn-demob-matches td:nth-child(1) { font-weight:600; overflow-wrap:anywhere; }
.cn-demob-line { white-space:pre-wrap; overflow-wrap:anywhere; font:13px/1.5 ui-monospace,monospace; }
.cn-demob-source { margin-top:4px; font-size:12px; color:#526675; }
.cn-demob-source dl { display:grid; grid-template-columns:auto 1fr; gap:4px 10px; margin:8px 0 0; }
.cn-demob-source dt { font-weight:600; }
.cn-demob-source dd { margin:0; overflow-wrap:anywhere; }
.cn-demob-report { display:flex; width:100%; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px; }
.cn-demob-scroll-help { display:none; font-size:12px; }
@media(max-width:600px) {
  .cn-demob-setup { padding:12px; }
  .cn-demob .cn-demob-site { max-width:none; flex-basis:100%; }
  .cn-demob-scroll-help { display:block; }
  .cn-demob-table th, .cn-demob-table td { padding:8px; }
  .cn-demob-pager .q-btn { font-size:12px; }
}
@media(max-width:700px) {
  .cn-demob-matches { min-width:0; }
  .cn-demob-matches thead, .cn-demob-matches thead tr { display:block; }
  .cn-demob-matches thead tr { display:flex; flex-wrap:wrap; }
  .cn-demob-matches th { position:static; width:auto !important; max-width:100%; min-width:0; padding:3px; }
  .cn-demob-matches tbody, .cn-demob-matches tr { display:block; }
  .cn-demob-matches tbody tr { display:grid; grid-template-columns:minmax(0,1fr) auto; border-bottom:1px solid #CBD5DF; }
  .cn-demob-matches tbody tr:last-child { border:0; }
  .cn-demob-matches td { border:0; min-width:0; }
  .cn-demob-matches td:nth-child(1), .cn-demob-matches td:nth-child(2) { padding-bottom:0; }
  .cn-demob-matches td:nth-child(2) .cn-demob-line-number::before { content:"Line "; color:#526675; font:12px system-ui,sans-serif; }
  .cn-demob-matches td:nth-child(3) { grid-column:1 / -1; }
  .cn-demob-scroll-help.matches { display:none; }
}
''')
    ui.colors(primary='#145C87')
    latest = dict(preview=None, preview_page=None, preview_query=None, preview_offsets=[0],
                  result_job=None, result_page=None, result_query=None, result_offsets=[0],
                  result_revision=None, attempt_revision=None, outcome=None, attempt_result=None,
                  download=None, download_error='', prompt=None, dialog=None, note='', discovery=None,
                  preview_focus=None, result_focus=None, result_site=None, previous_results=False, result_heading=None,
                  preview_sort=None, preview_descending=False, preview_sort_focus=None,
                  result_sort=None, result_descending=False, result_sort_focus=None,
                  preview_filter_by=None, preview_filter_text='', preview_draft_by=None, preview_draft_text='',
                  result_filter_by=None, result_filter_text='', result_draft_by='device', result_draft_text='',
                  preview_filter_focus=None, result_filter_focus=None)
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
    with ui.element('details').classes('cn-demob-help cn-demob'):
        with ui.element('summary'):
            ui.label('How this check works').classes('inline')
        ui.label('Look up the site’s networks in Infoblox, review them, then choose whether to search the configured live configuration repository.').classes('cn-muted')
        ui.label('A search can include up to 200 distinct IPv4 networks. Cached configuration search is unavailable here.').classes('cn-muted')
    if oscompat.is_macos():
        ui.label('The configuration scan is currently unavailable on macOS. You can still look up site networks.').props('role=status').classes('text-warning')
    with ui.row().classes('w-full items-center cn-demob'):
        scope_label = ui.label('Configured scope pending').classes('cn-muted')
        forget = ui.button('Forget saved credentials', on_click=controller.forget_credentials).props('flat dense')
        store_status = ui.label('').props('role=status aria-live=polite').classes('cn-muted cn-demob-empty')
    status = ui.label('Attaching…').props('role=status aria-live=polite').classes('text-weight-bold')
    report_warning = ui.label('').props('role=status aria-live=polite').classes('text-warning cn-demob-empty')
    with ui.element('div').classes('cn-panel cn-demob cn-demob-setup'):
        site = ui.input('Site code', placeholder='SITE1').props('outlined dense maxlength=1024').classes('cn-demob-site')
        error = ui.label('').props('role=alert').classes('text-negative cn-demob-empty')
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
    discovery_announcement = ui.label('').props('role=status aria-live=polite aria-atomic=true').classes('text-warning cn-demob-empty')
    discovery_announcement._props['data-demob-announcement'] = 'true'
    preview_message = ui.label('').props('role=status aria-live=polite').classes('cn-muted cn-demob-empty')
    preview_area = ui.column().classes('w-full cn-demob')
    preview_area.set_visibility(False)

    async def request_preview_page():
        if latest['preview_query']:
            controller.release_demob_page(latest['preview_query'])
            latest['preview_query'] = None
        preview = latest['preview'] or {}
        if not preview.get('token'):
            return
        try:
            sort = dict(sort_by=latest['preview_sort'], descending=latest['preview_descending']) if latest['preview_sort'] else {}
            filtering = dict(filter_by=latest['preview_filter_by'], filter_text=latest['preview_filter_text']) if latest['preview_filter_by'] else {}
            latest['preview_query'] = controller.request_demob_page(preview['token'], latest['preview_offsets'][-1], 50, **sort, **filtering)
            preview_message.set_text('Loading site networks…')
        except (ValueError, RuntimeError, OSError, EOFError):
            preview_message.set_text('Preview expired or is unavailable. Look up the site again.')

    async def preview_move(direction, position='top'):
        if direction == 'previous' and len(latest['preview_offsets']) > 1:
            latest['preview_offsets'].pop()
        elif direction == 'next' and latest['preview_page'] and latest['preview_page'].get('next_offset') is not None:
            latest['preview_offsets'].append(latest['preview_page']['next_offset'])
        else:
            return
        latest['preview_page'] = None
        latest['preview_focus'] = (direction, position)
        await request_preview_page()
        await draw_preview.refresh()

    async def change_sort(kind, key):
        sort_key, descending = kind + '_sort', kind + '_descending'
        latest[descending] = not latest[descending] if latest[sort_key] == key else False
        latest[sort_key] = key
        latest[kind + '_sort_focus'] = key
        latest[kind + '_offsets'] = [0]
        latest[kind + '_page'] = None
        if kind == 'preview':
            await request_preview_page()
            await draw_preview.refresh()
        else:
            await request_result_page()
            await draw_results.refresh()

    def sort_header(kind, label, key):
        direction = ('descending' if latest[kind + '_descending'] else 'ascending') if latest[kind + '_sort'] == key else None
        with ui.element('th').props('scope=col' + (f' aria-sort={direction}' if direction else '')) as header:
            header._props['aria-label'] = label
            button = ui.button(label, on_click=lambda _, column=key: change_sort(kind, column)).props('flat dense no-caps').classes('cn-demob-sort')
            button._props['aria-label'] = f'Sort by {label}' + (f', {direction}' if direction else '')
            button._props['data-demob-sort-kind'] = kind
            button._props['data-demob-sort-key'] = key

    def restore_sort_focus(kind):
        key = latest[kind + '_sort_focus']
        if key is not None:
            client.run_javascript(
                "if (document.activeElement === document.body) {"
                "const buttons = document.querySelectorAll('[data-demob-sort-kind]');"
                f"Array.from(buttons).find(b => b.dataset.demobSortKind === {json.dumps(kind)} && b.dataset.demobSortKey === {json.dumps(key)})?.focus();"
                "}")
            latest[kind + '_sort_focus'] = None

    def filter_controls(kind, options):
        prefix = 'Network' if kind == 'preview' else 'Match'
        draft_by, draft_text = kind + '_draft_by', kind + '_draft_text'
        selected = latest[draft_by] if latest[draft_by] in options else next(iter(options), None)
        latest[draft_by] = selected
        async def apply(clear=False):
            if clear:
                latest[draft_text] = ''
            latest[kind + '_filter_text'] = latest[draft_text]
            latest[kind + '_filter_by'] = latest[draft_by] if latest[draft_text] else None
            latest[kind + '_filter_focus'] = 'clear' if clear else 'apply'
            latest[kind + '_offsets'] = [0]
            latest[kind + '_page'] = None
            if kind == 'preview':
                await request_preview_page()
                await draw_preview.refresh()
            else:
                await request_result_page()
                await draw_results.refresh()
        with ui.element('div').classes('cn-demob-filter'):
            ui.select(options, value=selected, label=f'{prefix} filter field',
                      on_change=lambda event: latest.__setitem__(draft_by, event.value)).props('outlined dense')
            ui.input(f'{prefix} filter value', value=latest[draft_text],
                     on_change=lambda event: latest.__setitem__(draft_text, event.value or '')).props('outlined dense maxlength=256')
            apply_button = ui.button(f'Apply {prefix.lower()} filter', on_click=lambda: apply()).props('outline dense')
            clear_button = ui.button(f'Clear {prefix.lower()} filter', on_click=lambda: apply(clear=True)).props('flat dense')
            for button, action in ((apply_button, 'apply'), (clear_button, 'clear')):
                button._props['data-demob-filter'] = kind + '-' + action

    def restore_filter_focus(kind):
        action = latest[kind + '_filter_focus']
        if action:
            selector = json.dumps(f'[data-demob-filter="{kind}-{action}"]')
            client.run_javascript(f'if (document.activeElement === document.body) document.querySelector({selector})?.focus();')
            latest[kind + '_filter_focus'] = None

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

    def draw_pager(kind, page, position='top'):
        network = kind == 'network'
        offsets = latest['preview_offsets' if network else 'result_offsets']
        move = preview_move if network else result_move
        title = 'Site network pages' if network else 'Configuration result pages'
        with ui.element('nav').props(f'aria-label="{title}{" (bottom)" if position == "bottom" else ""}"').classes('cn-demob-pager'):
            for direction, enabled in [('previous', len(offsets) > 1), ('next', page['next_offset'] is not None)]:
                button = ui.button(f'{direction.title()} {kind} page',
                                   on_click=lambda direction=direction: move(direction, position)).props('outline dense')
                button._props[f'data-demob-{kind}-page'] = direction
                button._props['data-demob-pager-position'] = position
                button.set_enabled(enabled)

    @ui.refreshable
    def draw_preview():
        preview = latest['preview']
        if not preview:
            return
        with ui.element('section').props('aria-label="Site network preview"').classes('cn-panel cn-demob'):
            with ui.element('h2'):
                ui.label(f"Review site networks for {preview['site']}")
            page = latest['preview_page']
            if preview.get('token'):
                with ui.element('div').classes('cn-demob-consent'):
                    ui.label('Review the networks below before allowing the configuration search.').classes('cn-muted')
                    if latest['preview_filter_by']:
                        ui.label('Filtering changes only the display. Search covers all discovered networks.').classes('cn-muted')
                    search = ui.button('Search configurations', on_click=lambda: confirm(preview['token']))
                    search.set_enabled(not oscompat.is_macos() and bool(page and page.get('status') == 'ready'))
                    ui.button('Decline', on_click=lambda: decline(preview['token'])).props('outline')
                if oscompat.is_macos():
                    ui.label('Configuration scans are unavailable on macOS.').classes('text-warning')
            if page and page['status'] == 'ready':
                with ui.element('div').classes('cn-demob-toolbar'):
                    ui.label('Site networks').classes('text-weight-bold')
                    draw_pager('network', page)
                ui.label('Scroll the table to see all columns.').classes('cn-muted cn-demob-scroll-help')
                columns = page.get('columns') or list(dict.fromkeys(key for row in page['rows'] for key in row))
                preferred = [key for key in columns if key.lower() in ('network', 'network view')]
                columns = preferred + [key for key in columns if key not in preferred]
                filter_controls('preview', {key: key for key in columns})
                with ui.element('div').props('role=region aria-label="Site networks table" tabindex=0').classes('cn-demob-scroll'):
                    with ui.element('table').props('aria-label="Site networks"').classes('cn-demob-table cn-demob-networks'):
                        with ui.element('thead'), ui.element('tr'):
                            for key in columns:
                                sort_header('preview', key, key)
                        with ui.element('tbody'):
                            for row in page['rows']:
                                with ui.element('tr'):
                                    for key in columns:
                                        with ui.element('td'):
                                            ui.label(str(row.get(key, '')))
                if len(page['rows']) > 10:
                    draw_pager('network', page, 'bottom')
            elif page:
                ui.label('Preview expired or is unavailable. Look up the site again.').props('role=alert')
    with preview_area:
        draw_preview()

    with ui.column().classes('cn-panel cn-demob') as check_panel:
        with ui.element('div').classes('cn-demob-toolbar'):
            with ui.element('h2'):
                ui.label('Latest check')
            outcome = ui.label('No check yet.').props('role=status aria-live=polite')
        discovery_area = ui.column().props('role=status aria-live=polite').classes('w-full cn-demob cn-demob-empty')
        diagnostics = ui.column().classes('w-full cn-demob cn-demob-empty')
        def download_report():
            try:
                latest['download'] = controller.request_report_snapshot()
                latest['download_error'] = ''
                download.disable()
            except (RuntimeError, OSError, EOFError):
                latest['download_error'] = 'Report download is unavailable.'
        with ui.element('div').classes('cn-demob-report'):
            report = ui.html('').props('role=status aria-live=polite').classes('cn-muted')
            download = ui.button('Download accumulated report', on_click=download_report).props('outline dense')
            download.disable()
        with ui.element('details').classes('cn-demob-help'):
            with ui.element('summary'):
                ui.label('About report contents').classes('inline')
            ui.label('The accumulated workbook can contain full device configurations, including sensitive information. Handle downloads accordingly.').classes('cn-muted')
    check_panel.set_visibility(False)
    result_message = ui.label('').props('role=status aria-live=polite').classes('cn-muted cn-demob-empty')
    result_area = ui.column().props('role=region aria-label="Configuration results" tabindex=-1').classes('w-full cn-demob')

    async def request_result_page():
        if latest['result_query']:
            controller.release_config_search_page(latest['result_query'])
            latest['result_query'] = None
        if not latest['result_job']:
            result_message.set_text('')
            return
        try:
            sort = dict(sort_by=latest['result_sort'], descending=latest['result_descending']) if latest['result_sort'] else {}
            filtering = dict(filter_by=latest['result_filter_by'], filter_text=latest['result_filter_text']) if latest['result_filter_by'] else {}
            latest['result_query'] = controller.request_config_search_page(latest['result_job'], latest['result_offsets'][-1], 50, **sort, **filtering)
            result_message.set_text('Loading matches…')
        except (ValueError, RuntimeError, OSError, EOFError):
            latest['result_page'] = {'status': 'unavailable'}
            result_message.set_text('Results are unavailable. Run the check again.')

    async def result_move(direction, position='top'):
        if direction == 'previous' and len(latest['result_offsets']) > 1:
            latest['result_offsets'].pop()
        elif direction == 'next' and latest['result_page'] and latest['result_page'].get('next_offset') is not None:
            latest['result_offsets'].append(latest['result_page']['next_offset'])
        else:
            return
        latest['result_page'] = None
        latest['result_focus'] = (direction, position)
        await request_result_page()
        await draw_results.refresh()

    def result_title():
        title = 'Previous configuration matches' if latest['previous_results'] else 'Configuration matches'
        return f"{title} for {latest['result_site']}" if latest['result_site'] else title

    @ui.refreshable
    def draw_results():
        latest['result_heading'] = None
        page = latest['result_page']
        if not page:
            return
        with ui.element('section').props('aria-label="Configuration matches"').classes('cn-panel cn-demob'):
            with ui.element('h2'):
                latest['result_heading'] = ui.label(result_title())
            if page['status'] != 'ready':
                ui.label('Results are unavailable. Run the check again.').props('role=alert')
            else:
                with ui.element('div').classes('cn-demob-toolbar'):
                    ui.label('Line numbers start at 0.').classes('cn-muted')
                    draw_pager('result', page)
                ui.label('Scroll the table to see all columns.').classes('cn-muted cn-demob-scroll-help matches')
                filter_controls('result', {'device': 'Device', 'line': 'Line', 'configuration': 'Matching configuration'})
                with ui.element('div').props('role=region aria-label="Configuration matches table" tabindex=0').classes('cn-demob-scroll matches'):
                    with ui.element('table').props('aria-label="Configuration matches"').classes('cn-demob-table cn-demob-matches'):
                        with ui.element('thead'), ui.element('tr'):
                            for name, key in (('Device', 'device'), ('Line', 'line'), ('Matching configuration', 'configuration')):
                                sort_header('result', name, key)
                        with ui.element('tbody'):
                            for row in page['rows']:
                                with ui.element('tr'):
                                    with ui.element('td'):
                                        ui.label(str(row[1]))
                                    with ui.element('td'):
                                        ui.label(str(row[2])).classes('cn-demob-line-number')
                                    with ui.element('td'):
                                        ui.label(str(row[3])).classes('cn-demob-line')
                                        with ui.element('details').classes('cn-demob-source'):
                                            with ui.element('summary') as source_summary:
                                                source_summary._props['aria-label'] = f'Source details for {row[1]}, line {row[2]}'
                                                ui.label('Details').classes('inline')
                                            with ui.element('dl'):
                                                for name, value in [('Search', row[0]), ('File', row[4])]:
                                                    with ui.element('dt'):
                                                        ui.label(name)
                                                    with ui.element('dd'):
                                                        ui.label(str(value))
                if len(page['rows']) > 10:
                    draw_pager('result', page, 'bottom')
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
            preview_area.set_visibility(bool(preview))
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
                latest.update(preview=preview, preview_query=None, preview_page=None, preview_offsets=[0], preview_focus=None,
                              preview_sort=None, preview_descending=False, preview_sort_focus=None,
                              preview_filter_by=None, preview_filter_text='', preview_draft_by=None, preview_draft_text='', preview_filter_focus=None)
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
                        if rows:
                            scope = f" (of {page['overall_total']} total)" if latest['preview_filter_by'] and 'overall_total' in page else ''
                            preview_message.set_text(f"Showing {page['offset'] + 1}–{page['offset'] + len(rows)} of {page['total']} site networks{scope}.")
                        else:
                            total = page.get('overall_total')
                            message = (f"No networks match this filter (of {total} total)." if total is not None else 'No networks match this filter.') + ' Clear filter to see all results.'
                            preview_message.set_text(message if latest['preview_filter_by'] else 'No site networks to show.')
                    else:
                        preview_message.set_text('Preview expired or is unavailable. Look up the site again.')
                    await draw_preview.refresh()
                    restore_sort_focus('preview')
                    restore_filter_focus('preview')
                    if latest['preview_focus']:
                        direction, position = latest['preview_focus']
                        selector = json.dumps(f"[data-demob-network-page='{direction}'][data-demob-pager-position='{position}']:not([disabled])")
                        fallback = json.dumps(f"[data-demob-network-page][data-demob-pager-position='{position}']:not([disabled])")
                        client.run_javascript(
                            "if (document.activeElement === document.body || document.activeElement?.matches('[data-demob-network-page]')) {"
                            f"(document.querySelector({selector}) || document.querySelector({fallback}) || document.querySelector('[data-demob-network-page]:not([disabled])'))?.focus();"
                            "}")
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
            previous_changed = previous != latest['previous_results']
            latest['previous_results'] = previous
            title = str((latest['outcome'] or {}).get('message') or ('Check in progress.' if active else 'No check yet.'))
            if previous:
                title += ' Showing results from an earlier completed check.'
            outcome.set_text(title)
            display = report_display(replace(state, latest_report_state=page_state.attempt_report_state or state.latest_report_state))
            report.set_content(escape(latest['download_error']) if latest['download_error'] else display['text'])
            download.set_enabled(display['available'] and latest['download'] is None)
            check_panel.set_visibility(bool(latest['outcome'] or discovery or page_state.result_job_id or display['available']))
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
                # Keep keyboard focus in a stable region when a newer result removes its source details.
                if latest['result_job']:
                    target = result_area.html_id if page_state.result_job_id else site.html_id
                    focus_target = 'target' if page_state.result_job_id else '(target?.querySelector("input") || target)'
                    try:
                        await client.run_javascript(
                            '(() => { const area = document.getElementById(' + json.dumps(result_area.html_id) + ');'
                            'if (area?.contains(document.activeElement)) {'
                            'const target = document.getElementById(' + json.dumps(target) + ');'
                            + focus_target + '?.focus(); } return true; })()', timeout=2)
                    except (TimeoutError, RuntimeError):
                        pass  # A disconnected browser cannot retain focus.
                latest.update(result_job=page_state.result_job_id, result_page=None, result_offsets=[0], result_focus=None,
                              result_sort=None, result_descending=False, result_sort_focus=None,
                              result_filter_by=None, result_filter_text='', result_draft_by='device', result_draft_text='', result_filter_focus=None,
                              result_site=(discovery or {}).get('site') if not previous else None)
                await request_result_page()
                await draw_results.refresh()
            elif previous_changed and latest['result_heading']:
                latest['result_heading'].set_text(result_title())
            if latest['result_query']:
                page = controller.config_search_page(latest['result_query'])
                if page is not None:
                    controller.release_config_search_page(latest['result_query'])
                    latest['result_query'] = None
                    latest['result_page'] = page
                    rows = page['rows']
                    if page['status'] == 'ready':
                        if rows:
                            scope = f" (of {page['overall_total']} total)" if latest['result_filter_by'] and 'overall_total' in page else ''
                            result_message.set_text(f"Showing {page['offset'] + 1}–{page['offset'] + len(rows)} of {page['total']} matches{scope}.")
                        else:
                            total = page.get('overall_total')
                            message = (f"No matches for this filter (of {total} total)." if total is not None else 'No matches for this filter.') + ' Clear filter to see all results.'
                            result_message.set_text(message if latest['result_filter_by'] else 'No configuration matches.')
                    else:
                        result_message.set_text('Results are unavailable. Run the check again.')
                    await draw_results.refresh()
                    restore_sort_focus('result')
                    restore_filter_focus('result')
                    if latest['result_focus']:
                        direction, position = latest['result_focus']
                        selector = json.dumps(f"[data-demob-result-page='{direction}'][data-demob-pager-position='{position}']:not([disabled])")
                        fallback = json.dumps(f"[data-demob-result-page][data-demob-pager-position='{position}']:not([disabled])")
                        client.run_javascript(
                            "if (document.activeElement === document.body || document.activeElement?.matches('[data-demob-result-page]')) {"
                            f"(document.querySelector({selector}) || document.querySelector({fallback}) || document.querySelector('[data-demob-result-page]:not([disabled])'))?.focus();"
                            "}")
                        latest['result_focus'] = None

    def release_queries():
        if latest['preview_query']:
            controller.release_demob_page(latest['preview_query'])
        if latest['result_query']:
            controller.release_config_search_page(latest['result_query'])
    client.on_delete(release_queries)
    ui.timer(0, poll, once=True)
    ui.timer(.5, poll)
