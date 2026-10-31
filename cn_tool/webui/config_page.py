"""Local, bounded presentation for live configuration search."""
import asyncio
import json
from dataclasses import replace

from cn_tool.utils import oscompat

from .subnets import CSS, report_display


def render_config_search(controller):
    from nicegui import ui

    client = ui.context.client
    ui.add_css(CSS + '''
.cn-config { min-width:0; overflow-wrap:anywhere; }
.cn-config .q-field, .cn-config .q-btn { max-width:100%; min-width:0; }
.cn-config-row { width:100%; min-width:0; border-bottom:1px solid #CBD5DF; padding:12px 0; gap:4px; }
.cn-config-line { white-space:pre-wrap; overflow-wrap:anywhere; font-family:ui-monospace,monospace; }
.cn-config-actions { flex-wrap:wrap; min-width:0; }
''')
    ui.colors(primary='#145C87')
    latest = dict(job=None, result=None, page=None, query=None, offsets=[0], download=None, download_error='',
                  attempt=None, outcome=None, redraw=None, result_revision=None, attempt_revision=None,
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
    ui.label('Search the configured live configuration repository. Cached search is not supported here; use the menu or change the configuration to live search.').classes('cn-muted')
    if oscompat.is_macos():
        ui.label('Configuration search is currently unavailable on macOS. Other tools remain available.').props('role=status').classes('text-warning')
    status = ui.label('Attaching…').props('role=status aria-live=polite').classes('text-weight-bold')
    report_warning = ui.label('').props('role=status aria-live=polite').classes('text-warning')
    with ui.column().classes('cn-panel cn-config'):
        terms = ui.textarea('Search terms', placeholder='192.0.2.0/24\nrouter-name').props('outlined autogrow').classes('w-full')
        ui.label('Enter one IPv4 network, address, site code or keyword per line. Keywords use regular expressions and need at least five characters unless recognized as site codes. A site code searches configuration text as a regular expression; it does not run the Site Demobilization Check. Up to 200 lines, 1,024 characters per line and 64 KiB in total.').classes('cn-muted')
        error = ui.label('').props('role=alert').classes('text-negative')
        async def submit():
            text = terms.value or ''
            lines = text.splitlines()
            if not text.strip():
                error.set_text('Enter at least one search term.')
                return
            if (len(lines) > 200 or any(len(line) > 1024 for line in lines) or
                    len(text.encode('utf-8')) > 65536):
                error.set_text('Search input exceeds the stated limits. Shorten it and try again.')
                return
            try:
                controller.submit(lines, lookup_type='config_search')
            except (ValueError, RuntimeError, OSError, EOFError) as exc:
                error.set_text(str(exc) or 'Search could not start. Try again.')
                return
            error.set_text('')
            await poll()
        def stop_search():
            state = controller.page_snapshot('config_search').state
            if state.active_lookup_type == 'config_search' and state.active_job_id and state.phase == 'running':
                controller.cancel(state.active_job_id)
        with ui.row().classes('cn-config-actions'):
            run = ui.button('Search configurations', on_click=submit)
            run.disable()
            stop = ui.button('Stop search', on_click=stop_search).props('outline')
            stop.set_visibility(False)
    with ui.column().classes('cn-panel cn-config'):
        ui.label('Latest search').classes('text-h6')
        outcome = ui.label('No search yet.').props('role=status aria-live=polite')
        diagnostics = ui.column().props('role=status aria-live=polite').classes('w-full cn-config')
        report = ui.html('').props('role=status aria-live=polite').classes('cn-muted')
        ui.label('The accumulated workbook can contain earlier searches and whole configurations, including sensitive information. Handle downloads accordingly.').classes('cn-muted')
        def download_report():
            try:
                latest['download'] = controller.request_report_snapshot()
                latest['download_error'] = ''
                download.disable()
            except (RuntimeError, OSError, EOFError):
                latest['download_error'] = 'Report download is unavailable.'
        download = ui.button('Download accumulated report', on_click=download_report).props('outline')
        download.disable()
    results_message = ui.label('').props('role=status aria-live=polite').classes('cn-muted')
    results_area = ui.column().classes('w-full cn-config')

    async def change_page(direction):
        if direction == 'previous' and len(latest['offsets']) > 1:
            latest['offsets'].pop()
        elif direction == 'next' and latest['page'] and latest['page'].get('next_offset') is not None:
            latest['offsets'].append(latest['page']['next_offset'])
        else:
            return
        latest['page'] = None
        latest['redraw'] = direction
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
        with ui.element('section').props('aria-label="Configuration matches"').classes('cn-panel cn-config'):
            ui.label('Configuration matches').classes('text-h6')
            ui.label('Line numbers start at 0.').classes('cn-muted')
            for row in rows:
                with ui.column().classes('cn-config-row'):
                    ui.label(f'{row[1]} · line {row[2]}').classes('text-weight-bold')
                    ui.label(f'Search: {row[0]}').classes('cn-muted')
                    ui.label(row[3]).classes('cn-config-line')
                    ui.label(f'File: {row[4]}').classes('cn-muted')
            with ui.element('nav').props('aria-label="Configuration result pages"').classes('row cn-config-actions'):
                previous = ui.button('Previous page', on_click=lambda: change_page('previous')).props('outline')
                previous._props['data-config-page'] = 'previous'
                previous.set_enabled(len(latest['offsets']) > 1)
                next_button = ui.button('Next page', on_click=lambda: change_page('next')).props('outline')
                next_button._props['data-config-page'] = 'next'
                next_button.set_enabled(page.get('next_offset') is not None)
    with results_area:
        draw_results()

    async def request_page():
        if latest['query']:
            controller.release_config_search_page(latest['query'])
            latest['query'] = None
        if not latest['job']:
            results_message.set_text('')
            return
        try:
            latest['query'] = controller.request_config_search_page(latest['job'], latest['offsets'][-1], 50)
            results_message.set_text('Loading matches…')
        except (ValueError, RuntimeError, OSError, EOFError):
            latest['page'] = {'status': 'unavailable'}
            results_message.set_text('Results are unavailable. Run the search again.')

    def render_diagnostics(result):
        diagnostics.clear()
        if not result:
            return
        with diagnostics:
            for item in result.get('errors', []):
                ui.label(f"Input line {item.get('line', '')}: {item.get('reason', '')}").classes('text-negative')
            missing = result.get('missing_nets', [])
            if missing:
                ui.label('No configuration match for: ' + ', '.join(missing)).classes('cn-muted')

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
                render_diagnostics(diagnostic_result)
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
                latest.update(job=job, page=None, offsets=[0], redraw=None)
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
                    if latest['redraw']:
                        selector = json.dumps(f"[data-config-page='{latest['redraw']}']:not([disabled])")
                        client.run_javascript(f"(document.querySelector({selector}) || document.querySelector('[data-config-page]:not([disabled])'))?.focus()")
                        latest['redraw'] = None

    def release_query():
        if latest['query']:
            controller.release_config_search_page(latest['query'])
    client.on_delete(release_query)
    ui.timer(0, poll, once=True)
    ui.timer(.5, poll)
