"""Consent-gated site demobilization presentation."""
import asyncio
import json

from cn_tool.utils import oscompat

from . import config_table, dialogs, search_text, texts, view_state
from . import outcome as outcome_banner
from .dialogs import confirm_dialog
from .setup_card import needs_endpoint, render_setup
from .results_first import form_field
from .shell import render_shell
from .sign_in import SignInFlow
from .tables import DEFAULT_SIZE, TableState, apply_table_assets, cn_table
from .theme import apply_theme
from .controller import ReportDeletionInProgress


FIRST_PAGE = DEFAULT_SIZE  # the rows of the preview's first page: the table's own first page


def render_demob(controller, scope):
    from nicegui import ui

    client = ui.context.client
    apply_theme()
    scope.head_once('demob', css='''
.cn-demob { min-width:0; overflow-wrap:anywhere; }
.cn-demob .q-btn, .cn-demob .q-field { max-width:100%; min-width:0; }
.nicegui-content:has(.cn-demob) { gap:12px; }
.cn-demob-empty:empty { display:none; }
.cn-demob h2 { margin:0; }
.cn-demob.cn-panel:not(.cn-demob-setup) { display:flex; flex-direction:column; gap:10px; }
.cn-demob-setup { display:flex; align-items:center; flex-wrap:wrap; gap:12px; padding:14px 18px; }
.cn-demob .cn-demob-site { flex:1 1 200px; max-width:420px; }
.cn-demob-help { font-size:var(--cn-text-data); color:var(--cn-muted); }
.cn-demob-help summary, .cn-demob-source summary { cursor:pointer; width:fit-content; color:var(--cn-link); }
.cn-demob summary::before { content:"▸ "; }
.cn-demob details[open] > summary::before, details.cn-demob[open] > summary::before { content:"▾ "; }
.cn-demob-help > .cn-muted { margin-top:8px; }
.cn-demob-consent { width:100%; display:flex; align-items:center; flex-wrap:wrap; gap:10px; }
.cn-demob-consent .cn-muted { flex:1 1 280px; font-size:var(--cn-text-data); }
.cn-demob-toolbar { width:100%; display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:8px; }
@media(max-width:600px) {
  .cn-demob-setup { padding:12px; }
  .cn-demob .cn-demob-site { max-width:none; flex-basis:100%; }
}
''')
    apply_table_assets()
    scope.head_once('config-matches', css=config_table.MATCH_CSS, script=config_table.COPY_SCRIPT)
    latest = dict(preview=None, preview_page=None, preview_query=None, preview_table=TableState(),
                  result_job=None, result_table=TableState(),
                  result_revision=None, attempt_revision=None, outcome=None, attempt_result=None,
                  note='', discovery=None, previous_results=False, result_site=None, result_heading=None)
    lock = asyncio.Lock()
    shell = render_shell(controller, 'demob')
    shell.set_help(search_text.DEMOB_HELP)
    setup = render_setup(controller, 'demob')  # Setup required: the reason, Retry setup and the way to Settings
    if oscompat.is_macos():
        ui.label('The configuration scan is currently unavailable on macOS. You can still look up site networks.').props('role=status').classes('cn-notice')
    with ui.row().classes('w-full items-center cn-demob'):
        scope_label = ui.label('Configured scope pending').classes('cn-muted')
        # Offered only while the credential store says a login is saved (dialogs.saved_login).
        forget = ui.button(dialogs.FORGET, on_click=controller.forget_credentials).props('flat dense')
        forget.set_visibility(False)
        store_status = ui.label('').props('role=status').classes('cn-muted cn-demob-empty')
    with ui.row().classes('w-full items-baseline gap-3'):
        shell.status = ui.label('Attaching…').props('role=status tabindex=-1 data-demob-status').classes('text-weight-bold')
        shell.add_elapsed()
    report_warning = ui.label('').props('role=status').classes('text-warning cn-demob-empty')
    # The latest check's matches table: its arrangement is the tab's (found again after a visit to another tool) and
    # the URL's (R2-08). The site-networks preview is not: it belongs to a typed site code, and it expires.
    from .scope import tab_state
    kept = tab_state(client).setdefault('demob', {})
    link = view_state.ViewState(scope, view_state.MATCHES_SCHEMA,
                                lambda: view_state.table_values(latest['result_table'] if latest['result_job'] else None))
    link.notice()
    setup.add_card()  # in the form's place while the settings name no Infoblox endpoint
    with ui.element('div').classes('cn-panel cn-demob cn-demob-setup') as form:
        with ui.column().classes('cn-demob-site gap-1'):
            _, site = form_field('input', 'Site code', props='maxlength=1024')  # the one form style
            ui.label('For example SITE1. Ctrl+Enter looks up the site.').classes('cn-muted')
        error = ui.label('').props('role=alert').classes('text-negative cn-demob-empty')
        async def lookup():
            if not scope.alive:
                return
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
                job = controller.submit_demob_lookup(value)
            except ReportDeletionInProgress as refusal:
                error.set_text(str(refusal))
                return
            except RuntimeError:
                error.set_text('Another operation is running or the session is unavailable. Wait for it to finish or relaunch the application.')
                return
            except ValueError:
                error.set_text('The site code is too long or invalid. Check it and try again.')
                return
            except (OSError, EOFError):
                error.set_text('The session is unavailable. Quit and relaunch the application.')
                return
            sign_in.started(job)
            error.set_text('')
            latest['note'] = ''
            await poll()
        def lookup_from_keyboard():
            if run.enabled:
                return lookup()
        site.on('keydown.ctrl.enter', lookup_from_keyboard)
        site.on('keydown.meta.enter', lookup_from_keyboard)
        with ui.row().classes('flex-wrap'):
            run = shell.waits(ui.button('Look up site networks', on_click=lookup))
            setup.form.extend([form, scope_label])  # no scope and no account to name while Infoblox is not set up
            run.disable()
            shell.add_stop()  # shown only while this page's site check runs, and it ends only that one
    # The one live region besides the outcome: incomplete discovery is said before the outcome panel exists.
    discovery_announcement = ui.label('').props('role=status aria-live=polite aria-atomic=true').classes('text-warning cn-demob-empty')
    discovery_announcement._props['data-demob-announcement'] = 'true'
    preview_message = ui.label('').props('role=status').classes('cn-muted cn-demob-empty')
    preview_area = ui.column().classes('w-full cn-demob')
    preview_area.set_visibility(False)

    async def request_preview_page():
        # The first page tells the table's columns and that the preview is there; the table's first read takes it.
        if not scope.alive:
            return  # the tool was left: its queries are released and nobody would release a new one
        if latest['preview_query']:
            controller.release_demob_page(latest['preview_query'])
            latest['preview_query'] = None
        preview = latest['preview'] or {}
        if not preview.get('token'):
            return
        try:
            latest['preview_query'] = controller.request_demob_page(preview['token'], 0, FIRST_PAGE)
            preview_message.set_text('Loading site networks…')
        except (ValueError, RuntimeError, OSError, EOFError):
            preview_message.set_text('Preview expired or is unavailable. Look up the site again.')

    async def confirm(token):
        if not scope.alive:
            return
        try:
            sign_in.started(controller.confirm_demob_search(token))
        except RuntimeError as refusal:
            # A refusal (a running deletion, another tab's work) leaves the preview untouched, and a note would be
            # hidden behind it: say what is wrong, not that the preview expired.
            error.set_text(str(refusal) or 'Another operation is running. Try again when it finishes.')
        except (ValueError, OSError, EOFError):
            latest['note'] = 'Preview expired or is unavailable. Look up the site again.'
        else:
            error.set_text('')
            latest['note'] = ''
        await poll()

    async def ask_consent(preview):
        if not scope.alive:
            return
        count = preview.get('row_count')
        lines = [f"Search the configured live configuration repository for the networks found for {preview['site']}"
                 + (f' ({texts.plural(count, "network")}).' if isinstance(count, int) and count else '.'),
                 'Filtering the table above changes only the display: the search covers all discovered networks.']
        if preview.get('status') == 'partial_error':
            lines.append('Network discovery was incomplete, so this check is partial and will not be saved as a report.')
        if await confirm_dialog(f"Search configurations for {preview['site']}?", lines, confirm='Start search',
                                fallback='[data-demob-cancel]'):
            if not scope.alive:
                return  # the tool was left while the question was open: nothing is started from a page that is gone
            await confirm(preview['token'])
            # The dialog gave the focus back to Search configurations, which the redraw has now removed with Cancel:
            # the status line stays, and says what the search does.
            client.run_javascript('if (document.activeElement === document.body) '
                                  'document.querySelector("[data-demob-status]")?.focus({preventScroll: true});')

    async def cancel(token):
        controller.decline_demob(token)
        latest['note'] = 'Search cancelled. Look up the site again to start a new check.'
        await poll()

    def search_enabled():
        # A running deletion disables confirmation without discarding the preview it would use.
        page = latest['preview_page']
        return not latest.get('delete_pending') and not oscompat.is_macos() and bool(page and page.get('status') == 'ready')

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
                    ui.label('Review the networks below before allowing the configuration search. Filtering the table '
                             'changes only the display: the search covers all discovered networks.').classes('cn-muted')
                    search = ui.button('Search configurations', on_click=lambda: ask_consent(preview))
                    latest['search_button'] = search
                    search.set_enabled(search_enabled())
                    ui.button('Cancel', on_click=lambda: cancel(preview['token'])).props('outline data-demob-cancel')
                if oscompat.is_macos():
                    ui.label('Configuration scans are unavailable on macOS.').props('role=status').classes('cn-notice')
            if page and page['status'] == 'ready' and page['total']:
                ui.label('Site networks').classes('text-weight-bold')
                names = page.get('columns') or list(dict.fromkeys(key for row in page['rows'] for key in row))
                source = config_table.network_pages(controller, preview['token'])
                source.seed(page, FIRST_PAGE)
                cn_table(name='site-networks', label='Site networks', columns=config_table.network_columns(names),
                         source=source, state=latest['preview_table'],
                         empty='No site networks to show.')
            elif page and page['status'] != 'ready':
                ui.label('Preview expired or is unavailable. Look up the site again.').props('role=alert')
    with preview_area:
        draw_preview()

    with ui.column().classes('cn-panel cn-demob') as check_panel:
        with ui.element('div').classes('cn-demob-toolbar'):
            with ui.element('h2'):
                ui.label('Latest check')
        banner = outcome_banner.Banner(heading=False)
        banner.set(outcome_banner.INFORMATION, 'No check yet.')
        discovery_area = ui.column().props('role=status').classes('w-full cn-demob cn-demob-empty')
        diagnostics = ui.column().classes('w-full cn-demob cn-demob-empty')
        # What this check did to the report, when a save was due. The workbook, its download and its deletion are
        # the header's Report menu.
        report = ui.label('').props('role=status').classes('cn-muted')
        with ui.element('details').classes('cn-demob-help'):
            with ui.element('summary'):
                ui.label('About report contents').classes('inline')
            ui.label('The accumulated workbook can contain full device configurations, including sensitive information. Handle downloads accordingly.').classes('cn-muted')
    check_panel.set_visibility(False)
    result_area = ui.column().props('role=region aria-label="Configuration results" tabindex=-1').classes('w-full cn-demob')

    def result_title():
        title = 'Previous configuration matches' if latest['previous_results'] else 'Configuration matches'
        return f"{title} for {latest['result_site']}" if latest['result_site'] else title

    @ui.refreshable
    def draw_results():
        latest['result_heading'] = None
        if not latest['result_job']:
            return
        with ui.element('section').classes('cn-panel cn-demob'):
            with ui.element('h2'):
                latest['result_heading'] = ui.label(result_title())
            cn_table(name='config-matches', label='Configuration matches', columns=config_table.match_columns(),
                     source=config_table.match_pages(controller, latest['result_job']), state=latest['result_table'],
                     empty='No configuration matches.', grouping=config_table.GROUPING, intro=config_table.search_line,
                     export_extra=config_table.EXPORT_EXTRA, on_change=lambda _: link.replace(), link=True)
    with result_area:
        draw_results()

    async def popped(values):
        """Back or Forward to an entry of this tool: that entry's table arrangement (a field it omits is its default), as
        a click would set it; the entry is not rewritten."""
        if not scope.alive or not latest['result_job']:
            return
        view_state.set_table(latest['result_table'], values)
        await draw_results.refresh()
        if scope.alive:
            link.replace()
    link.on_pop(popped)

    # The sign-in dialog: opened for the worker's request, kept open while Infoblox checks the password and when a
    # refused one is asked for again, closed when the request is gone (sign_in.SignInFlow). After a cancelled
    # sign-in focus returns to Look up site networks, enabled again once the lookup has ended.
    sign_in = SignInFlow(controller, client=client, fallback=lambda: [f'#{setup.retry.html_id}', f'#{run.html_id}'],
                         store=lambda: latest.get('store') or {}, restored=lambda: latest.get('restored', False),
                         after_reply=lambda: poll(),
                         active_job=lambda: controller.page_snapshot('demob').state.active_job_id)

    async def repeat():
        # Sign in again and Retry: the site of the last check goes back on the form and is looked up again. A
        # password the lookup asks for is the poll's business (sign_in.follow), whichever button started it.
        request = controller.last_request('demob')
        if request and request.get('site'):
            site.set_value(request['site'])
        await lookup()

    handlers = dict(sign_in_again=repeat, retry=repeat, open_settings=outcome_banner.open_settings)

    async def poll():
        # A poll that a click awaits is no timer tick: nothing cancels it when the tool is left (PageScope), so it asks
        # scope.alive at its start and after every await, and never builds, requests or draws for a page that is gone.
        if lock.locked() or client.is_deleted or not scope.alive:
            return
        async with lock:
            page_state = controller.page_snapshot('demob', result_revision=latest['result_revision'],
                                                  attempt_revision=latest['attempt_revision'])
            state = page_state.state
            deleting = state.report_delete_pending
            latest['delete_pending'] = deleting
            phase = state.phase
            active = bool(state.active_job_id and state.active_lookup_type == 'demob')
            # The status line, Stop, the banner of another tool's job and the end of the session. While the setup card
            # or the Setup required block shows, it carries the reason and the status line only names the state.
            shell.update(state, own=setup.update(state))
            scope_label.set_text(f"{state.scope or 'Configured scope pending'} | Account: {state.username or 'pending'}")
            report_warning.set_text(state.report_warning or '')
            latest['store'], latest['restored'] = state.credential_store or {}, state.saved_login_restored
            store_status.set_text(latest['store'].get('message', ''))
            # Off while the setup card stands in for the form: Run is hidden then, and Ctrl+Enter asks Run.
            run.set_enabled(not deleting and phase == 'ready' and not state.active_job_id
                            and not needs_endpoint(state, 'demob'))
            forget.set_enabled(phase not in {'closing', 'closed', 'failed'})
            forget.set_visibility(dialogs.saved_login(latest['store'], latest['restored']))
            sign_in.refresh()
            await sign_in.follow()
            if not scope.alive:
                return
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
                latest.update(preview=preview, preview_query=None, preview_page=None, preview_table=TableState())
                if preview and preview.get('token'):
                    latest['note'] = ''
                    await request_preview_page()
                else:
                    preview_message.set_text(latest['note'])
                if not scope.alive:
                    return
                await draw_preview.refresh()
                if not scope.alive:
                    return
            elif latest['note'] and not preview:
                preview_message.set_text(latest['note'])
            if latest['preview_query']:
                page = controller.demob_page(latest['preview_query'])
                if page is not None:
                    controller.release_demob_page(latest['preview_query'])
                    latest['preview_query'] = None
                    latest['preview_page'] = page
                    if page['status'] != 'ready':
                        preview_message.set_text('Preview expired or is unavailable. Look up the site again.')
                    else:
                        preview_message.set_text('' if page['total'] else 'No site networks to show.')
                    await draw_preview.refresh()
                    if not scope.alive:
                        return
            search = latest.get('search_button')
            if search and not search.is_deleted:
                search.set_enabled(search_enabled())
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
            title = search_text.headline(latest['outcome']) or ('Check in progress.' if active else 'No check yet.')
            if previous:
                title = texts.sentence(title, 'Showing results from an earlier completed check')
            # A typed login that Infoblox refused was dropped: Sign in again starts the same lookup, which asks again.
            banner.set(outcome_banner.tone_for(latest['outcome']) if latest['outcome'] else outcome_banner.INFORMATION, title,
                       actions=outcome_banner.actions_for('demob', latest['outcome'], handlers,
                                                          can_repeat=bool(controller.last_request('demob'))))
            note = texts.attempt_report_note(page_state.attempt_report_state, state.report_state)
            if report.text != note:
                report.set_text(note)
            check_panel.set_visibility(bool(latest['outcome'] or discovery or page_state.result_job_id))
            arrived = link.take()  # the URL's arrangement, at the first poll (None: the tab's stands)
            if arrived is not None and not page_state.result_job_id and view_state.table_named(arrived):
                link.gone()  # a link to matches that are not here
                link.replace()
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
                    if not scope.alive:
                        return
                job = page_state.result_job_id
                table = kept['table'] if job and kept.get('job') == job else TableState()
                if arrived is not None and job:
                    view_state.set_table(table, arrived)
                kept.update(job=job, table=table)
                latest.update(result_job=job, result_table=table,
                              result_site=(discovery or {}).get('site') if not previous else None)
                await draw_results.refresh()
                if not scope.alive:
                    return
                link.replace()
            elif previous_changed and latest['result_heading']:
                latest['result_heading'].set_text(result_title())

    def release_queries():
        if latest['preview_query']:
            controller.release_demob_page(latest['preview_query'])
    scope.on_leave(release_queries)
    scope.on_leave(sign_in.leave)  # a request the open dialog answers is cancelled: nobody is left to answer it
    scope.timer(0, poll, once=True)
    scope.timer(.5, poll)
