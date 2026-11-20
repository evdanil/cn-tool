"""Local, bounded presentation for live configuration search."""
import asyncio

from cn_tool.utils import oscompat

from . import config_table
from . import outcome as outcome_banner
from . import search_text, texts, view_state
from .results_first import focus_field, form_field
from .shell import render_shell
from .tables import TableState, apply_table_assets, cn_table
from .theme import apply_theme


def render_config_search(controller, scope):
    from nicegui import ui
    from .scope import tab_state

    client = ui.context.client
    # The table's arrangement (page, filter, sort) of the result on screen, found again after a visit to another tool.
    kept = tab_state(client).setdefault('config_search', {})
    apply_theme()
    scope.head_once('config-search', css='''
.cn-config { min-width:0; overflow-wrap:anywhere; }
.cn-config .q-field, .cn-config .q-btn { max-width:100%; min-width:0; }
.cn-config-form { display:grid; grid-template-columns:minmax(0,1fr) auto; align-items:start; gap:12px; }
.cn-config-input { width:100%; min-width:0; gap:6px; }
.cn-config textarea { max-height:calc(10 * 1.5em + 16px); }  /* the handle is box_resize's, on a desktop only */
.cn-config-panel { display:flex; flex-direction:column; gap:8px; }
.cn-config details { min-width:0; }
.cn-config summary { color:var(--cn-link); cursor:pointer; width:fit-content; }
.cn-config summary::before { content:"▸ "; }
.cn-config details[open] > summary::before { content:"▾ "; }
[data-config-results]:focus-visible, .cn-config summary:focus-visible { outline:2px solid var(--cn-link); outline-offset:2px; }
@media(max-width:700px) {
  .cn-config-form { grid-template-columns:minmax(0,1fr); }
}
.cn-config-actions { flex-wrap:wrap; min-width:0; gap:8px; }
''')
    apply_table_assets()
    scope.head_once('config-matches', css=config_table.MATCH_CSS, script=config_table.COPY_SCRIPT)
    latest = dict(job=None, attempt_job=None, result=None, attempt=None, outcome=None, result_revision=None, attempt_revision=None,
                  attempt_result=None, table=TableState())
    lock = asyncio.Lock()
    shell = render_shell(controller, 'config_search')
    shell.set_help(search_text.CONFIG_HELP)
    if oscompat.is_macos():
        ui.label('Configuration search is currently unavailable on macOS. Other tools remain available.').props('role=status').classes('cn-notice')
    with ui.row().classes('w-full items-baseline gap-3'):
        shell.status = ui.label('Attaching…').props('role=status').classes('text-weight-bold')
        shell.add_elapsed()
    report_warning = ui.label('').props('role=status').classes('text-warning')
    # The matches table's arrangement is in the URL (R2-08): the tab state is the truth, the URL its projection.
    link = view_state.ViewState(scope, view_state.MATCHES_SCHEMA,
                                lambda: view_state.table_values(latest['table'] if latest['job'] else None))
    link.notice()
    with ui.element('section').classes('cn-panel cn-config cn-config-panel'):
        with ui.element('div').classes('cn-config-form'):
            with ui.column().classes('cn-config-input'):
                _, terms = form_field('textarea', 'Search terms', props='rows=4 autogrow')  # the one form style
                ui.label('One IPv4 network, address, site code or regular expression per line, for example 192.0.2.0/24 or router-name. '
                         'Ctrl+Enter searches.').classes('cn-muted')
            actions = ui.row().classes('cn-config-actions')
        error = ui.label('').props('role=alert').classes('text-negative')
        error.set_visibility(False)
        def show_error(message):
            error.set_text(message)
            error.set_visibility(bool(message))
        async def submit():
            if not scope.alive:
                return
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
            latest.pop('notice', None)
            await poll()
        async def retry():
            if not scope.alive:
                return
            try:
                request = outcome_banner.repeat(controller, 'config_search')
            except (ValueError, RuntimeError, OSError, EOFError) as exc:
                show_error(str(exc) or 'Search could not start. Try again.')
                return
            terms.set_value('\n'.join(request['inputs']))  # what is repeated is shown
            show_error('')
            latest.pop('notice', None)
            await poll()
        async def clear_results():
            """Clear results: the controller forgets the last search, the page is as on a first visit (the terms stay) and
            the focus goes to the terms box. Nothing is stopped and the report is not touched."""
            if not scope.alive:
                return
            try:
                # What the page drew, not what the controller holds now: another tab may have searched since.
                controller.clear_results('config_search', attempt_job_id=latest['attempt_job'], result_job_id=latest['job'])
            except RuntimeError:  # the results changed, or a search started (another tab): nothing is cleared
                latest['notice'] = texts.NOT_CLEARED
                await poll()
                return
            latest.pop('notice', None)
            latest['cleared'] = True  # said by the banner's polite region until the next search
            await poll()
            if scope.alive:
                focus_field(client, terms)
        handlers = dict(retry=retry, open_settings=outcome_banner.open_settings, show_lines=outcome_banner.show_lines,
                        clear_results=clear_results)
        def submit_from_keyboard():
            if run.enabled:
                return submit()
        terms.on('keydown.ctrl.enter', submit_from_keyboard)
        terms.on('keydown.meta.enter', submit_from_keyboard)
        with actions:
            run = shell.waits(ui.button('Search configurations', on_click=submit))
            run.disable()
            shell.add_stop()  # shown only while this page's search runs, and it ends only that one
            view_matches = ui.button('View matches', on_click=lambda: client.run_javascript(
                "document.querySelector('[data-config-results]')?.focus()")).props('flat')
            view_matches.set_visibility(False)
    with ui.column().classes('cn-panel cn-config cn-config-panel'):
        ui.label('Latest search').classes('text-weight-bold')
        banner = outcome_banner.Banner(heading=False, marker='data-config-outcome')
        banner.set(outcome_banner.INFORMATION, 'No search yet.')
        diagnostics = ui.column().props('role=status data-config-diagnostics').classes('w-full cn-config')
        # What this search did to the report, when a save was due. The workbook, its download and its deletion are
        # the header's Report menu.
        report = ui.label('').props('role=status').classes('cn-muted')
        ui.label('Saved searches go to the shared report. It may include whole configurations, including sensitive information.').classes('cn-muted')
    with ui.element('section').props('aria-label="Configuration results" tabindex=-1 data-config-results').classes('cn-panel cn-config cn-config-panel') as results_area:
        with ui.element('h2').classes('text-h6 q-my-none'):
            ui.label('Configuration matches')
        results_body = ui.column().props('data-config-results-body').classes('w-full cn-config')
    results_area.set_visibility(False)

    def update_navigation():
        results_area.set_visibility(bool(latest['job']))
        view_matches.set_visibility(bool(latest['job']))

    @ui.refreshable
    def draw_results():
        # The table is built once for a result and updates itself in place (filter, sort, pages); the worker holds the
        # rows. A new result is a new table with a new arrangement.
        if latest['job']:
            cn_table(name='config-matches', label='Configuration matches', columns=config_table.match_columns(),
                     source=config_table.match_pages(controller, latest['job']), state=latest['table'],
                     empty='No configuration matches.', grouping=config_table.GROUPING, intro=config_table.search_line,
                     export_extra=config_table.EXPORT_EXTRA, on_change=lambda _: link.replace(), link=True)
    with results_body:
        draw_results()

    async def popped(values):
        """Back or Forward to an entry of this tool: that entry's table arrangement (a field it omits is its default), as
        a click would set it; the entry is not rewritten."""
        if not scope.alive or not latest['job']:
            return
        view_state.set_table(latest['table'], values)
        await draw_results.refresh()
        if scope.alive:
            link.replace()
    link.on_pop(popped)

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
        if not scope.alive:
            return
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
                    if items is errors:
                        disclosure.props('data-lines-not-understood')
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
        # A poll that a click awaits is no timer tick: nothing cancels it when the tool is left (PageScope), so it asks
        # scope.alive at its start and after every await.
        if lock.locked() or client.is_deleted or not scope.alive:
            return
        async with lock:
            page_state = controller.page_snapshot('config_search', result_revision=latest['result_revision'],
                                                  attempt_revision=latest['attempt_revision'])
            state = page_state.state
            deleting = state.report_delete_pending
            if page_state.result_changed:
                latest['result_revision'] = page_state.result_revision
                latest['result'] = page_state.result
            if page_state.attempt_changed:
                latest['attempt_revision'] = page_state.attempt_revision
                latest['outcome'] = page_state.outcome
                latest['attempt_result'] = page_state.attempt_result
            latest['attempt_job'] = page_state.attempt_job_id
            phase = state.phase
            active = bool(state.active_job_id and state.active_lookup_type == 'config_search')
            shell.update(state)  # the status line, Stop, the banner of another tool's job and the end of the session
            if report_warning.text != (state.report_warning or ''):
                report_warning.set_text(state.report_warning or '')
            report_warning.set_visibility(bool(state.report_warning))
            run.set_enabled(not deleting and not oscompat.is_macos() and phase == 'ready' and not state.active_job_id)
            attempt_value = latest['outcome'] or {}
            previous = bool(page_state.result_job_id and page_state.attempt_job_id != page_state.result_job_id)
            if active or attempt_value:
                latest['cleared'] = False
            title = search_text.headline(attempt_value) or ('Search in progress.' if active else
                                                             texts.RESULTS_CLEARED if latest.get('cleared') else 'No search yet.')
            if previous:
                title = texts.sentence(title, 'Showing results from an earlier completed search')
            lines = len((latest['attempt_result'] or {}).get('errors', []))
            banner.set(outcome_banner.tone_for(attempt_value) if attempt_value else outcome_banner.INFORMATION, title,
                       actions=outcome_banner.actions_for('config_search', attempt_value, handlers, lines=lines,
                                                          can_repeat=bool(controller.last_request('config_search')),
                                                          can_clear=not active and bool(attempt_value or page_state.result_job_id)))
            diagnostic_result = latest['attempt_result'] or {}
            diagnostic_key = (page_state.attempt_job_id, latest['attempt_revision'])
            if latest['attempt'] != diagnostic_key:
                latest['attempt'] = diagnostic_key
                await render_diagnostics(diagnostic_result)
                if not scope.alive:
                    return
            note = latest.get('notice') or texts.attempt_report_note(page_state.attempt_report_state, state.report_state)  # a refusal first
            if report.text != note:
                report.set_text(note)
            job = page_state.result_job_id
            arrived = link.take()  # the URL's arrangement, at the first poll (None: the tab's stands)
            if arrived is not None and not job and view_state.table_named(arrived):
                link.gone()  # a link to matches that are not here
            if job != latest['job']:
                # A fresh result may replace a focused source-details disclosure.
                # Move only that focus, before removing its node, never focus in the form.
                focus_target = ("document.querySelector('[data-config-results]')" if job else
                                f"document.getElementById('{terms.html_id}')?.querySelector('textarea')")
                await preserve_replaced_focus('data-config-results-body', focus_target)
                if not scope.alive:
                    return
                table = kept['table'] if job and kept.get('job') == job else TableState()
                if arrived is not None and job:
                    view_state.set_table(table, arrived)
                kept.update(job=job, table=table)
                latest.update(job=job, table=table)
                update_navigation()
                await draw_results.refresh()
                if not scope.alive:
                    return
            link.replace()

    scope.timer(0, poll, once=True)
    scope.timer(.5, poll)
