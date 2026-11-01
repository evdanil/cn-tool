"""Local, bounded presentation for live configuration search."""
import asyncio
from dataclasses import replace

from cn_tool.utils import oscompat

from .subnets import CSS, report_display


def render_config_search(controller):
    from nicegui import ui

    client = ui.context.client
    ui.add_css(CSS + '''
.cn-config { min-width:0; overflow-wrap:anywhere; }
.cn-config .q-field, .cn-config .q-btn { max-width:100%; min-width:0; }
.cn-config-form { display:grid; grid-template-columns:minmax(0,1fr) auto; align-items:start; gap:12px; }
.cn-config-input { width:100%; min-width:0; gap:6px; }
.cn-config textarea { resize:vertical; max-height:180px; }
.cn-config-panel { display:flex; flex-direction:column; gap:8px; }
.cn-config-scroll { width:100%; max-height:58vh; overflow:auto; border:1px solid #CBD5DF; border-radius:6px; }
.cn-config-table { width:100%; min-width:540px; border-collapse:separate; border-spacing:0; table-layout:fixed; }
.cn-config-table th { position:sticky; top:0; z-index:1; background:#EDF2F6; text-align:left; font-weight:600; }
.cn-config-table th, .cn-config-table td { padding:8px 12px; border-bottom:1px solid #CBD5DF; vertical-align:top; }
.cn-config-table th:first-child { width:160px; }
.cn-config-table th:nth-child(2) { width:64px; }
.cn-config-table tbody tr:last-child td { border-bottom:0; }
.cn-config-table tbody tr:nth-child(even) { background:#F5F7FA; }
.cn-config details { min-width:0; }
.cn-config summary { color:#145C87; cursor:pointer; width:fit-content; }
.cn-config summary::before { content:"▸ "; }
.cn-config details[open] > summary::before { content:"▾ "; }
.cn-config summary:focus-visible, .cn-config-scroll:focus-visible { outline:2px solid #145C87; outline-offset:2px; }
.cn-config-source { font-size:12px; margin-top:4px; }
.cn-config [aria-disabled=true] { opacity:.5; cursor:default; }
@media(max-width:700px) {
  .cn-config-form { grid-template-columns:minmax(0,1fr); }
  .cn-config-table { min-width:0; }
  .cn-config-table thead { position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0,0,0,0); }
  .cn-config-table tbody, .cn-config-table tr { display:block; }
  .cn-config-table tbody tr { display:grid; grid-template-columns:minmax(0,1fr) auto; border-bottom:1px solid #CBD5DF; }
  .cn-config-table tbody tr:last-child { border:0; }
  .cn-config-table td { border:0; min-width:0; }
  .cn-config-table td:nth-child(1), .cn-config-table td:nth-child(2) { padding-bottom:0; }
  .cn-config-table td:nth-child(2) .cn-config-line::before { content:"Line "; color:#526675; font:12px system-ui,sans-serif; }
  .cn-config-table td:nth-child(3) { grid-column:1 / -1; }
}

.cn-config-line { white-space:pre-wrap; overflow-wrap:anywhere; font-family:ui-monospace,monospace; }
.cn-config-actions { flex-wrap:wrap; min-width:0; gap:8px; }
''')
    ui.colors(primary='#145C87')
    latest = dict(job=None, result=None, page=None, query=None, offsets=[0], download=None, download_error='',
                  attempt=None, outcome=None, result_revision=None, attempt_revision=None,
                  attempt_result=None)
    lock = asyncio.Lock()
    with ui.row().classes('w-full items-center justify-between cn-config'):
        ui.label('Configuration Search').mark('title').classes('text-h4')
        quit_button = ui.button('Quit application', on_click=controller.quit).props('outline')
    with ui.element('nav').props('aria-label=Tools').classes('row items-center gap-4 cn-config'):
        ui.link('Subnets', '/')
        ui.link('IP', '/ip')
        ui.link('Ping', '/ping')
        ui.link('Monitor', '/monitor')
        ui.link('Configuration Search', '/config-search').props('aria-current=page')
        ui.link('Site Demobilization', '/demobilization')
    if oscompat.is_macos():
        ui.label('Configuration search is currently unavailable on macOS. Other tools remain available.').props('role=status').classes('text-warning')
    status = ui.label('Attaching…').props('role=status aria-live=polite').classes('text-weight-bold')
    report_warning = ui.label('').props('role=status aria-live=polite').classes('text-warning')
    with ui.element('section').classes('cn-panel cn-config cn-config-panel'):
        with ui.element('div').classes('cn-config-form'):
            with ui.column().classes('cn-config-input'):
                terms = ui.textarea('Search terms', placeholder='192.0.2.0/24\nrouter-name').props('outlined rows=3').classes('w-full')
                ui.label('One IPv4 network, address, site code or regular expression per line.').classes('cn-muted')
            actions = ui.row().classes('cn-config-actions')
        with ui.element('details'):
            with ui.element('summary'):
                ui.label('Search help').classes('inline')
            ui.label('Search the configured live configuration repository. Cached search is not supported here; use the menu or change the configuration to live search.').classes('cn-muted')
            ui.label('Keywords use regular expressions and need at least five characters unless recognized as site codes.').classes('cn-muted')
            ui.label('A site code searches configuration text as a regular expression; it does not run the Site Demobilization Check.').classes('cn-muted')
            ui.label('Up to 200 lines, 1,024 characters per line and 64 KiB in total.').classes('cn-muted')
        error = ui.label('').props('role=alert').classes('text-negative')
        error.set_visibility(False)
        def show_error(message):
            error.set_text(message)
            error.set_visibility(bool(message))
        async def submit():
            text = terms.value or ''
            lines = text.splitlines()
            if not text.strip():
                show_error('Enter at least one search term.')
                return
            if (len(lines) > 200 or any(len(line) > 1024 for line in lines) or
                    len(text.encode('utf-8')) > 65536):
                show_error('Search input exceeds the stated limits. Shorten it and try again.')
                return
            try:
                controller.submit(lines, lookup_type='config_search')
            except (ValueError, RuntimeError, OSError, EOFError) as exc:
                show_error(str(exc) or 'Search could not start. Try again.')
                return
            show_error('')
            await poll()
        def stop_search():
            state = controller.page_snapshot('config_search').state
            if state.active_lookup_type == 'config_search' and state.active_job_id and state.phase == 'running':
                controller.cancel(state.active_job_id)
        with actions:
            run = ui.button('Search configurations', on_click=submit)
            run.disable()
            stop = ui.button('Stop search', on_click=stop_search).props('outline')
            stop.set_visibility(False)
            view_matches = ui.button('View matches', on_click=lambda: client.run_javascript(
                "document.querySelector('[data-config-results]')?.focus()")).props('flat')
            view_matches.set_visibility(False)
    with ui.column().classes('cn-panel cn-config cn-config-panel'):
        ui.label('Latest search').classes('text-weight-bold')
        outcome = ui.label('No search yet.').props('role=status aria-live=polite tabindex=-1 data-config-outcome')
        diagnostics = ui.column().props('role=status aria-live=polite data-config-diagnostics').classes('w-full cn-config')
        report = ui.html('').props('role=status aria-live=polite').classes('cn-muted')
        def download_report():
            try:
                latest['download'] = controller.request_report_snapshot()
                latest['download_error'] = ''
                download.disable()
            except (RuntimeError, OSError, EOFError):
                latest['download_error'] = 'Report download is unavailable.'
        with ui.row().classes('cn-config-actions items-center'):
            download = ui.button('Download accumulated report', on_click=download_report).props('outline dense')
            download.disable()
            ui.label('May include earlier searches and whole configurations, including sensitive information.').classes('cn-muted')
    with ui.element('section').props('aria-label="Configuration results" tabindex=-1 data-config-results').classes('cn-panel cn-config cn-config-panel') as results_area:
        with ui.row().classes('w-full items-center justify-between cn-config-actions'):
            ui.label('Configuration matches').classes('text-h6')
            with ui.element('nav').props('aria-label="Configuration result pages"').classes('row cn-config-actions'):
                previous_button = ui.button('Previous page', on_click=lambda: change_page('previous')).props('outline dense aria-disabled=true')
                next_button = ui.button('Next page', on_click=lambda: change_page('next')).props('outline dense aria-disabled=true')
        results_message = ui.label('').props('role=status aria-live=polite').classes('cn-muted')
        ui.label('Line numbers start at 0.').classes('cn-muted text-xs')
        results_body = ui.column().props('data-config-results-body').classes('w-full cn-config')
    results_area.set_visibility(False)

    def update_navigation():
        page = latest['page'] or {}
        ready = page.get('status') == 'ready' and not latest['query']
        previous_button.props(f'aria-disabled={str(not (ready and len(latest["offsets"]) > 1)).lower()}')
        next_button.props(f'aria-disabled={str(not (ready and page.get("next_offset") is not None)).lower()}')
        results_area.set_visibility(bool(latest['job']))
        view_matches.set_visibility(bool(latest['job']))

    async def change_page(direction):
        if latest['query'] or not latest['page'] or latest['page'].get('status') != 'ready':
            return
        if direction == 'previous' and len(latest['offsets']) > 1:
            latest['offsets'].pop()
        elif direction == 'next' and latest['page'] and latest['page'].get('next_offset') is not None:
            latest['offsets'].append(latest['page']['next_offset'])
        else:
            return
        latest['page'] = None
        await request_page()
        await draw_results.refresh()

    @ui.refreshable
    def draw_results():
        page = latest['page']
        if not page:
            return
        if page.get('status') != 'ready':
            ui.label('Results are unavailable. Run the search again.').props('role=alert')
            return
        rows = page['rows']
        if not rows:
            return
        with ui.element('div').props('role=region aria-label="Scrollable configuration matches" tabindex=0').classes('cn-config-scroll'):
            with ui.element('table').props('aria-label="Configuration matches"').classes('cn-config-table'):
                with ui.element('thead'):
                    with ui.element('tr'):
                        for heading in ('Device', 'Line', 'Matching configuration'):
                            with ui.element('th').props('scope=col'):
                                ui.label(heading)
                with ui.element('tbody'):
                    for row in rows:
                        with ui.element('tr'):
                            with ui.element('td'):
                                ui.label(str(row[1])).classes('text-weight-medium')
                            with ui.element('td'):
                                ui.label(str(row[2])).classes('cn-config-line')
                            with ui.element('td'):
                                ui.label(str(row[3])).classes('cn-config-line')
                                with ui.element('details').classes('cn-config-source'):
                                    with ui.element('summary') as source_summary:
                                        source_summary._props['aria-label'] = f'Source details for {row[1]}, line {row[2]}'
                                        ui.label('Details').classes('inline')
                                    ui.label(f'Search: {row[0]}').classes('cn-muted')
                                    ui.label(f'File: {row[4]}').classes('cn-muted')
    with results_body:
        draw_results()

    async def request_page():
        if latest['query']:
            controller.release_config_search_page(latest['query'])
            latest['query'] = None
        if not latest['job']:
            results_message.set_text('')
            update_navigation()
            return
        try:
            latest['query'] = controller.request_config_search_page(latest['job'], latest['offsets'][-1], 50)
            results_message.set_text('Loading matches…')
        except (ValueError, RuntimeError, OSError, EOFError):
            latest['page'] = {'status': 'unavailable'}
            results_message.set_text('Results are unavailable. Run the search again.')
        update_navigation()

    async def preserve_replaced_focus(source, target):
        # Guard in the browser, so a delayed reply never steals focus from the form.
        try:
            await client.run_javascript(
                f"if (document.querySelector('[{source}]')?.contains(document.activeElement)) {{"
                f"{target}?.focus();" + "}", timeout=2)
        except (TimeoutError, RuntimeError):
            pass  # The browser may have disconnected while work completed.

    async def render_diagnostics(result):
        await preserve_replaced_focus('data-config-diagnostics', "document.querySelector('[data-config-outcome]')")
        diagnostics.clear()
        if not result:
            diagnostics.set_visibility(False)
            return
        with diagnostics:
            errors = result.get('errors', [])
            missing = result.get('missing_nets', [])
            for title, items in ((f'{len(errors)} invalid inputs', errors), (f'{len(missing)} unmatched networks', missing)):
                if not items:
                    continue
                with ui.element('details') as disclosure:
                    if not result.get('total'):
                        disclosure.props('open')
                    with ui.element('summary'):
                        ui.label(title).classes('inline')
                    if items is errors:
                        for item in errors:
                            ui.label(f"Input line {item.get('line', '')}: {item.get('reason', '')}").classes('text-negative')
                    else:
                        ui.label('No configuration match for: ' + ', '.join(missing)).classes('cn-muted')
        diagnostics.set_visibility(bool(result.get('errors') or result.get('missing_nets')))

    async def poll():
        if lock.locked() or client.is_deleted:
            return
        async with lock:
            page_state = controller.page_snapshot('config_search', result_revision=latest['result_revision'],
                                                  attempt_revision=latest['attempt_revision'])
            state = page_state.state
            if page_state.result_changed:
                latest['result_revision'] = page_state.result_revision
                latest['result'] = page_state.result
            if page_state.attempt_changed:
                latest['attempt_revision'] = page_state.attempt_revision
                latest['outcome'] = page_state.outcome
                latest['attempt_result'] = page_state.attempt_result
            phase = state.phase
            active = bool(state.active_job_id and state.active_lookup_type == 'config_search')
            message = {'ready': 'Ready', 'starting': 'Starting application…', 'stopping': 'Stopping search…',
                       'saving': 'Saving report…', 'closing': 'Finishing active work…',
                       'closed': 'Application closed.', 'failed': 'Application failed. Quit and relaunch.',
                       'setup_required': 'Application setup is required.'}.get(phase, phase)
            if phase == 'running':
                message = ('Searching configurations' if active else 'Another operation is running')
                if state.progress_stage:
                    message += ': ' + state.progress_stage
            if state.error:
                message = str(state.error.get('message', state.error) if isinstance(state.error, dict) else state.error)
            if status.text != message:
                status.set_text(message)
            if report_warning.text != (state.report_warning or ''):
                report_warning.set_text(state.report_warning or '')
            report_warning.set_visibility(bool(state.report_warning))
            run.set_enabled(not oscompat.is_macos() and phase == 'ready' and not state.active_job_id)
            stop.set_visibility(active and phase in {'running', 'stopping', 'saving'})
            stop.set_enabled(active and phase == 'running')
            quit_button.set_enabled(phase not in {'closing', 'closed'})
            attempt_value = latest['outcome'] or {}
            previous = bool(page_state.result_job_id and page_state.attempt_job_id != page_state.result_job_id)
            title = str(attempt_value.get('message') or ('Search in progress.' if active else 'No search yet.'))
            if previous:
                title += ' Showing results from an earlier completed search.'
            if outcome.text != title:
                outcome.set_text(title)
            diagnostic_result = latest['attempt_result'] or {}
            diagnostic_key = (page_state.attempt_job_id, latest['attempt_revision'])
            if latest['attempt'] != diagnostic_key:
                latest['attempt'] = diagnostic_key
                await render_diagnostics(diagnostic_result)
            display = report_display(replace(state, latest_report_state=page_state.attempt_report_state or state.latest_report_state))
            report_text = latest['download_error'] or display['text']
            if report.content != report_text:
                report.set_content(report_text)
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
            job = page_state.result_job_id
            if job != latest['job']:
                # A fresh result may replace a focused source-details disclosure.
                # Move only that focus, before removing its node, never focus in the form.
                focus_target = ("document.querySelector('[data-config-results]')" if job else
                                f"document.getElementById('{terms.html_id}')?.querySelector('textarea')")
                await preserve_replaced_focus('data-config-results-body', focus_target)
                latest.update(job=job, page=None, offsets=[0])
                await request_page()
                await draw_results.refresh()
            if latest['query']:
                page = controller.config_search_page(latest['query'])
                if page is not None:
                    controller.release_config_search_page(latest['query'])
                    latest['query'] = None
                    latest['page'] = page
                    if page.get('status') == 'ready':
                        rows = page['rows']
                        results_message.set_text(f"Showing {page['offset'] + 1}–{page['offset'] + len(rows)} of {page['total']} matches." if rows else 'No configuration matches.')
                    else:
                        results_message.set_text('Results are unavailable. Run the search again.')
                    await draw_results.refresh()
                    update_navigation()

    def release_query():
        if latest['query']:
            controller.release_config_search_page(latest['query'])
    client.on_delete(release_query)
    ui.timer(0, poll, once=True)
    ui.timer(.5, poll)
