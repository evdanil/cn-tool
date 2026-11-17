"""Accessible, bounded presentation of the shared Ping Monitor session."""
import asyncio
import json

from . import job_slots, lookup_inputs, monitor_map, monitor_style, monitor_tables, tab_aria, target_preview, texts, view_state
from . import outcome as outcome_banner
from .dialogs import confirm_dialog
from .monitor_feed import ChangesPanel
from .monitor_link import MonitorLink
from .monitor_live_map import NOT_RUNNING, WAITING, LiveMap, set_changed  # noqa: F401 (WAITING: re-exported)
from .monitor_state import MonitorTab
from .scope import tab_state
from .shell import render_shell, set_clock, until
from .results_first import FormFold, form_field, form_summary
from .tables import FILTER_MIN_ROWS, TableState, apply_table_assets, cn_table, filter_input
from .theme import apply_theme
# The page's words are monitor_text's; the names stay importable from here.
from .monitor_text import (  # noqa: F401
    export_too_many, HISTORY_EXPIRED, COVERAGE_EXPIRED, COVERAGE_TITLE, COVERAGE_MEANING, history_error_message,
    MonitorFormError, parse_monitor_form, HistoryView, live_fields, STATE_LABELS, state_tone, state_cell_parts,
    live_row, round_host_row, coverage_row, COVERAGE_TONES, coverage_defaults, coverage_download_note, coverage_time,
    coverage_answered, coverage_summary_line, coverage_notices, history_run_summary, history_template_error,
    history_template_form, history_value, RUN_DETAILS, history_run_details, delete_run_reason, monitor_warnings, moment,
    monitor_header, stopped_notice, request_form, live_page_label, monitor_summary, request_summary,
    EXPORT_TABLE_CHANGED, LIVE_CHANGED, LIVE_UNAVAILABLE, ROUND_CHANGED, ROUND_TOO_LARGE, COVERAGE_CHANGED,
)


# One line, in the attention tone, for a run with a probe error (the hosts are marked E in the Map).
PROBE_ERRORS = 'Some hosts could not be tested (marked E).'
HELP = (
    'Targets: one IP address, hostname or subnet per line. Hostnames use system DNS. TCP ports are optional; ICMP is '
    'used when available. Ctrl+Enter in the form starts the monitor, and on the folded line runs it again.',
    'A monitor pings its targets once every interval until you stop it or its duration ends. It keeps running when '
    'you open another page or close this tab, and other tools wait until it stops.',
    'The Map shows every host of the latest complete round; the Table filters, sorts and exports them. History keeps '
    'the rounds of earlier runs.',
)


def render_monitor(controller, scope):
    from nicegui import ui

    client = ui.context.client
    apply_theme()
    scope.head_once('monitor', css=monitor_style.CSS)
    # What the tab keeps while it visits another tool (monitor_state.py): the panel, the History position and the
    # round chosen, the tables' arrangements, Show Available; the live table's for its run. Taken back when it leaves.
    kept = tab_state(client).setdefault('monitor', MonitorTab())
    link = MonitorLink(scope, kept)  # the URL's view (R2-08): it wins on arrival, so it goes into `kept` first
    latest = {'result': None, 'result_revision': None, 'attempt_revision': None,
              'outcome': None, 'history_query': None, 'history_page': None,
              # The live table: the run it shows ((job, run id), None for none, () before the first poll), whether that run has a complete round,
              # the revision drawn, its arrangement (kept for the run) and its cn_table. 'idle': no monitor of this
              # session runs (None before the first poll). 'hosts': the size of the run on screen, as (job and run,
              # hosts), kept between its rounds.
              'live_identity': (), 'live_ready': False, 'live_revision': None, 'live_state': TableState(),
              'live_handle': None, 'idle': None, 'hosts': (None, None),
              'history_dirty': True, 'template_query': None, 'delete_query': None,
              # A saved round: the one chosen ('round_keep': the id of the one a return chooses again) and the
              # arrangement of its hosts' table (kept for the rounds of one run).
              'round_handle': None, 'round_keep': kept.round_id, 'round_pick': 'first',
              # Show Available: the saved target the box belongs to (None: the page is not on one), its table's
              # arrangement, and everything else it reads or shows, off until ticked.
              'coverage_drawn': False, **coverage_defaults(), **kept.restore()}
    history = kept.history
    lock = asyncio.Lock()
    apply_table_assets()
    scope.head_once('monitor-map', css=monitor_map.CSS, script=monitor_map.SCRIPT)

    def alive():
        return scope.alive and not client.is_deleted

    def place_round(first):
        """Results first: "Latest complete round" above "Start a monitor" while a run is active (the page's order is the
        reading and the focus order, so the panel is moved, not drawn elsewhere)."""
        if latest.get('round_first') != first:
            latest['round_first'] = first
            round_panel.move(live_panel, target_index=0 if first else -1)

    shell = render_shell(controller, 'monitor')
    shell.set_help(HELP)
    with ui.row().classes('cn-monitor-toolbar'):
        with ui.row().classes('items-baseline gap-3 grow'):
            shell.status = ui.label('Attaching…').props('role=status').classes('text-weight-bold')
            shell.add_elapsed()
        shell.add_stop()  # shown only while this session's monitor runs, and it ends only that one
    link.view.notice()
    with ui.tabs().classes('w-full').props('align=left no-caps') as tabs:
        live_tab = ui.tab('Live monitor')
        history_tab = ui.tab('History')
    with ui.tab_panels(tabs, value=history_tab if kept.panel == 'history' else live_tab,
                       animated=False).classes('w-full cn-monitor-panels').props('keep-alive'):
        live_panel = ui.tab_panel(live_tab).classes('p-0 cn-monitor-live')
        history_panel = ui.tab_panel(history_tab).classes('p-0')
    tab_aria.wire_tabs([(live_tab, live_panel), (history_tab, history_panel)])

    def panel():
        return 'history' if tabs.value in (history_tab, history_tab._props.get('name')) else 'live'

    # A page built on History (the tab left the Monitor there) draws the Live panel only when it is chosen: its form's
    # drafts are restored and its Map's box is set up then. Monitor these chooses it at once (handed_over below).
    pending = []

    def panel_changed(_):
        link.push()
        if panel() == 'live' and alive():
            live_map.restart()
            feed.restart()
            for args in pending:
                scope.timer(0, lambda args=args: restore(*args), once=True)
            pending.clear()
    tabs.on_value_change(panel_changed)
    with live_panel, ui.column().classes('cn-panel').props('data-monitor-form') as form_panel:
        with ui.element('h2').classes('text-h6 q-my-none'):
            ui.label('Start a monitor')
        # What Quit does to a monitor is said here, in text: a tooltip is not shown to a keyboard (tracker M9).
        ui.label('Monitoring continues when you close this tab. Use Stop to end the active run. '
                 'Quit waits for DNS, probe cleanup and configured exit actions.').classes('cn-muted')
        # The one form style (results_first.form_field): a label above an outlined, dense box; no placeholder.
        _, targets = form_field('textarea', 'Targets', props='autogrow')
        target_error = ui.label('').props('role=alert').classes('text-negative')
        lookup_inputs.helper_text(targets, lookup_inputs.TARGET_HELP['monitor'])
        preview = target_preview.attach(targets, 'monitor', scope)  # the live line (7.3)
        _, ports = form_field('input', 'TCP ports')
        port_error = ui.label('').props('role=alert').classes('text-negative')
        lookup_inputs.helper_text(ports, lookup_inputs.PORT_HELP)
        preview.use_ports(ports)  # the live line warns when the hosts are more than the tool tests with ports
        with ui.row().classes('w-full cn-monitor-row'):
            with ui.column().classes('grow gap-0'):
                _, interval = form_field('input', 'Interval (seconds)', value='60', props='inputmode=numeric')
            with ui.column().classes('grow gap-0'):
                _, duration = form_field('input', 'Duration (seconds)', props='inputmode=numeric')
        interval_error = ui.label('').props('role=alert').classes('text-negative')
        duration_error = ui.label('').props('role=alert').classes('text-negative')
        ui.label('Leave duration blank to run until stopped. Both values must be at least 10 seconds.').classes('cn-muted')
        form_error = ui.label('').props('role=alert').classes('text-negative')
        reuse_status = ui.label('').classes('cn-muted')
        fields = {'targets': (targets, target_error), 'ports': (ports, port_error),
                  'interval': (interval, interval_error), 'duration': (duration, duration_error)}
        for control, error_label in fields.values():
            control._props['aria-describedby'] = f"{error_label.html_id} {control._props.get('aria-describedby', '')}".strip()  # the error, then the helper line
        reading = []  # set while a Run reads the box: a second click or Ctrl+Enter meanwhile is the same Run

        async def submit():
            if not alive() or reading:
                return
            reading.append(True)
            try:
                return await read_and_start()
            finally:
                reading.clear()

        async def read_and_start():
            for control, error_label in fields.values():
                control._props.pop('aria-invalid', None)
                control.update()
                error_label.set_text('')
            form_error.set_text('')
            try:
                if not (targets.value or '').strip():
                    raise MonitorFormError('targets', 'Enter at least one target.')
                parsed_ports, every, until = parse_monitor_form(ports.value or '', interval.value or '', duration.value or '')
                typed = targets.value or ''
                lines = await target_preview.lines_for_submit(typed, 'monitor')  # off the event loop
                if not alive():
                    return
                if not lines:  # comments only
                    raise MonitorFormError('targets', target_preview.NO_TARGETS)
                controller.submit(lines, 'monitor', tcp_ports=parsed_ports, interval_seconds=every,
                                  duration_seconds=until, typed=typed)
            except MonitorFormError as error:
                control, error_label = fields[error.field]
                error_label.set_text(str(error))
                control._props['aria-invalid'] = 'true'
                control.update()
                root = json.dumps(control.html_id)
                client.run_javascript(f"(() => {{ const root = document.getElementById({root}); (root?.matches('input,textarea') ? root : root?.querySelector('input,textarea'))?.focus(); }})()")
                return control  # Run again opens the form at this field (the box above is hidden while the form is folded)
            except (ValueError, RuntimeError) as error:
                form_error.set_text(str(error))
                return
            fold.ran()  # results first: the form is its one line, under the round once the run is on
            reading.clear()  # started: a Run from here on is a new one, whatever the poll takes
            await poll()
        handoff_note = lookup_inputs.handoff_note()  # targets sent by "Monitor these" (said once; nothing runs)
        with ui.row().classes('cn-monitor-actions'):
            run = shell.waits(ui.button('Run monitor', on_click=submit))
            run.disable()

        async def submit_by_key():
            # Ctrl+Enter (Cmd+Enter on a Mac) in any field of the form is the Run button: nothing while it is off.
            if run.enabled:
                await submit()
        for control, _ in fields.values():
            for chord in ('ctrl', 'meta'):
                control.on(f'keydown.{chord}.enter', submit_by_key)
    fold = FormFold(form_panel, 'monitor', focus=targets, run=run, again=submit, alive=lambda: scope.alive)
    with live_panel, ui.column().classes('cn-panel') as round_panel:
        with ui.element('h2').classes('text-h6 q-my-none'):
            ui.label('Latest complete round')
        # One line: the round on screen and when it began, what the run does now, and the run's own facts. The
        # countdown is a clock that ticks in the browser, so a monitor that waits sends nothing to keep it.
        with ui.element('div').classes('cn-monitor-header') as header:
            header_round = ui.label('')
            with ui.element('span').classes('cn-monitor-header-next'):
                header_doing = ui.label('')
                header_clock = until()
            header_facts = ui.label('')
        header.set_visibility(False)
        # A run that has ended: when, after how many rounds, and that the view below is its last round.
        ended_notice = outcome_banner.Banner(heading=False)
        probe_notice = outcome_banner.Banner(heading=False)
        summary = ui.label('').props('role=status aria-live=polite')
        outcome_status = ui.label('').props('role=status').classes('text-negative')
        warning_status = ui.label('').props('role=status').classes('text-negative')
        history_status = ui.label('').props('role=status').classes('text-negative')
        # What this monitor's report save did, when one was due; the workbook is the header's Report menu.
        report = ui.label('').props('role=status').classes('cn-muted')
        feed = ChangesPanel(controller, scope)  # "Changes" (R3-08): drawn beside the Map / Table switch, below
        async def show_in_table(target):
            handle = latest['live_handle']
            if handle is None or not handle._alive():
                return
            # The one host of that name, not every host whose name contains it (10.20.30.1 is in 10.20.30.100 too);
            # once the table has drawn, the focus goes to its region: the popup that held it is gone.
            handle.source.exact = target
            live_map.choose('table')
            await handle.apply(query=handle.source.exact, page=0)
            if not alive():
                return
            show_exact()
            client.run_javascript(f"""(() => {{
const active = document.activeElement;
if (active && active !== document.body && active.getClientRects().length && !active.closest('.cn-map-popup')) return;
document.getElementById({json.dumps(handle.region.html_id)})?.focus();
}})()""")

        live_map = LiveMap(controller, scope, poll=lambda: poll(), show_in_table=show_in_table)
        feed.live_map = live_map
        link.bind(panel=panel, latest=latest, history=history, live_map=live_map, tabs=tabs, live_tab=live_tab,
                  history_tab=history_tab, request_history=lambda **kw: request_history(**kw),
                  live_handle=lambda: latest['live_handle'])
        with ui.element('div').classes('cn-live-bar'):  # the switch and the closed "Changes" share a line: the Map stays high
            live_map.switch()
            feed.build()
        # One wrapper, two areas: the tab shows the area of its view (monitor_map.CSS) and both stay in the page.
        live_view = ui.column().classes('w-full cn-live-view')
        live_map.area(live_view)
        live_map.start()

        with live_view, ui.column().classes('w-full cn-live-table-area'):
            live_area = ui.column().classes('w-full')

        def show_exact():
            """Show in table's notice: the table lists exactly one host, said above it with the way back."""
            handle, box = latest['live_handle'], latest.get('exact_box')
            exact = handle.source.exact if handle is not None else None
            if exact and handle.state.query != exact:  # the reader typed another filter: a plain one again
                handle.source.exact = exact = None
            if box is not None and not box.is_deleted:
                latest['exact_text'].set_text(f'Showing exactly {exact}' if exact else '')
                box.set_visibility(bool(exact))

        async def clear_exact():
            handle = latest['live_handle']
            if handle is None:
                return
            handle.source.exact = None
            await handle.apply(query='', page=0)
            if not alive():
                return
            show_exact()
            client.run_javascript("document.querySelector('input[data-table-filter=\"monitor-live\"]')?.focus()")

        @ui.refreshable
        def draw_live():
            latest['live_handle'] = None
            if not latest['live_ready']:
                if latest['idle']:
                    ui.label(NOT_RUNNING).classes('cn-muted')  # no round to show and none on its way
                elif latest['live_identity']:
                    ui.label(monitor_tables.WAITING_ROUND).classes('cn-muted')
                return
            # Show in table lists the one host of that name: said above the table, with the way back beside it.
            with ui.element('div').classes('cn-notice cn-monitor-exact') as box:
                latest['exact_text'] = ui.label('')
                ui.button('Clear', on_click=clear_exact).props('flat dense aria-label="Clear exact match"')
            latest['exact_box'] = box
            box.set_visibility(False)
            ui.label('Counts describe the complete round; the table shows the selected group and filter.').classes('cn-muted')
            job, run_id = latest['live_identity']
            identity = latest['live_identity']  # a walk of this run's table stops when another run is shown
            source = monitor_tables.LiveSource(controller, (job, run_id, latest['live_revision']),
                                               alive=lambda: alive() and latest['live_identity'] == identity,
                                               generation=latest['config_generation'])
            if latest.get('live_exact') and latest['live_state'].query == latest['live_exact']:
                source.exact = latest['live_exact']  # Show in table's one host, found again after a visit elsewhere
            latest['live_handle'] = cn_table(
                name='monitor-live', label='Latest round results', columns=monitor_tables.LIVE_COLUMNS, source=source,
                state=latest['live_state'], groups=monitor_tables.HOST_GROUPS,
                on_change=lambda _: (show_exact(), link.replace()), empty='No hosts in this round.')
            show_exact()
        with live_area:
            draw_live()
    with history_panel, ui.column().classes('cn-panel cn-monitor-history gap-3'):
        history_reuse_status = ui.label('').props('role=status').classes('cn-muted')
        history_delete_status = ui.label('').props('role=status').classes('cn-muted')
        history_delete_error = ui.label('').props('role=alert').classes('text-negative')

        async def open_delete(action, item=None):
            if latest['delete_query'] or not alive():
                return
            selection = {'action': action, 'generation': latest['config_generation']}
            if action == 'run':
                selection.update(run_id=item['id'], request_id=item.get('request_id'))
                count = item.get('rounds', 0)
                lines = [f"Started {history_value('started', item.get('started'))}; status {item.get('status', 'unknown')}; "
                         f"{count} complete {'round' if count == 1 else 'rounds'}.",
                         'This permanently deletes this run and its rounds. Other runs of this request remain.']
                if item.get('status') == 'lost':
                    lines.append('A stale heartbeat can mean this run is still active on its host; check before deleting.')
                title, confirm = 'Delete this run?', 'Delete run'
            else:
                lines = ['This permanently deletes every saved request, run and round at confirmation. This cannot be undone.',
                         'A stale heartbeat can make a remote run appear lost; check remote monitors before deleting.']
                title, confirm = 'Delete all monitor history?', 'Delete all history'
            with history_panel:  # not inside the redrawn history: a redraw while it is open must not take it away
                confirmed = await confirm_dialog(title, lines, confirm=confirm, danger=True,
                                                 fallback='[data-monitor-history=refresh]')
            if not confirmed or not alive():  # a question answered after the Monitor was left deletes nothing
                return
            history_delete_status.set_text('')
            if latest['delete_query']:
                return
            if selection['generation'] != latest['config_generation']:
                # Opened before the settings were reloaded: the history file may now be another one.
                history_delete_error.set_text('The settings were reloaded since this was opened. Nothing was deleted.')
                return
            try:
                latest['delete_query'] = controller.request_monitor_delete(
                    action, selection.get('run_id'), selection.get('request_id'), generation=selection['generation'])
            except (AttributeError, RuntimeError, ValueError):
                history_delete_error.set_text('Could not start deletion. Try again when the session is ready.')
                return
            latest['delete_selection'] = selection
            history_delete_error.set_text('')
            history_delete_status.set_text('Deleting history…')
            await poll()
        def set_reuse_notice(message):
            set_changed(reuse_status, message)
            set_changed(history_reuse_status, message)
        async def select_round(item, focus='round', *, refresh='all', kept_round=False, step=False):
            if not alive():
                return
            latest['selected_round'] = item
            if not kept_round:  # the round a return chooses again keeps its page: the same round is the same rows
                latest['round_state'].first_page()  # another round: the cursors of the last one do not fit
            link.push() if refresh == 'all' and not step else link.replace()  # a round chosen is a step Back undoes; Earlier and Later are not
            if refresh == 'all':
                await draw_history.refresh()
            elif refresh == 'hosts':
                await draw_round_hosts.refresh()
            if focus and refresh == 'all' and alive():
                focus_round(focus)

        def focus_round(focus):
            """The list was drawn again: the round chosen, or the button that stepped to it, takes the focus back."""
            if focus:
                client.run_javascript(monitor_style.focus_round_script(focus))

        async def step_round(direction):
            items = (latest['history_page'] or {}).get('items', [])
            selected = latest['selected_round']
            if not selected or selected not in items:
                return
            index = items.index(selected) + direction
            if 0 <= index < len(items):
                await select_round(items[index], 'earlier' if direction < 0 else 'later', step=True)
            elif direction < 0 and len(history.cursors) > 1:
                history.previous()
                latest['round_focus'] = 'earlier'  # the button stays the reader's across the list's pages
                await request_history(round_pick='last', step=True)
            elif direction > 0 and latest['history_page'].get('next_cursor'):
                history.next(latest['history_page']['next_cursor'])
                latest['round_focus'] = 'later'
                await request_history(step=True)

        async def use_settings(run_id):
            if not alive():
                return
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

        def cell(text, *, target=False):
            with ui.element('td'):
                ui.label(str(text)).classes('cn-monitor-target' if target else '').props('title=' + json.dumps(str(text)))

        def state_cell(text, observation=None, *, tone=None):
            label, classes, title = state_cell_parts(text, state_tone(text, observation) if tone is None else tone)
            with ui.element('td'):
                ui.label(label).classes(classes).props('title=' + json.dumps(title))

        @ui.refreshable
        def draw_round_hosts():
            latest['round_handle'] = None
            selected = latest['selected_round']
            if not selected:
                return
            ui.label('Counts describe the complete round; the table shows the selected group and filter.').classes('cn-muted')
            source = monitor_tables.HistorySource(controller, 'hosts', selected['id'],
                                                  alive=lambda: alive() and latest['selected_round'] is selected,
                                                  generation=latest['config_generation'])
            latest['round_handle'] = cn_table(
                name='monitor-round', label='Round results', columns=monitor_tables.ROUND_COLUMNS, source=source,
                state=latest['round_state'], groups=monitor_tables.HOST_GROUPS, empty='No host results in this round.',
                on_change=lambda _: link.replace())  # its view link is the run's, in the location bar

        # --- Show Available: every IP of the saved target on screen, with whether it ever replied ---------------------
        def release_coverage_download():
            """Give up the Unseen export in flight: the controller drops its late answer and removes its file."""
            if latest['coverage_download']:
                controller.release_report_request(latest['coverage_download'])
            latest['coverage_download'] = None

        def reset_coverage():
            """Box off, nothing read, nothing left to show: what a new target line, or leaving the line, leaves behind."""
            release_coverage_download()
            latest.update(coverage_defaults(), coverage_state=TableState())

        async def toggle_coverage(event):
            if bool(event.value) == latest['coverage_on']:
                return
            if event.value:
                latest['coverage_on'] = True
            else:
                reset_coverage()
            await draw_coverage_body.refresh()
            if alive():
                focus_coverage('toggle')

        def sync_coverage_download():
            """The download button, what its file holds and its error follow the state, without redrawing the table."""
            button, label = latest.get('coverage_download_button'), latest.get('coverage_download_label')
            if button is None or button.is_deleted:
                return
            page = latest['coverage_page'] or {}
            unseen = 0 if page.get('error') else (page.get('counts') or {}).get('unseen', 0)
            button.set_enabled(unseen > 0 and latest['coverage_download'] is None)
            note = coverage_download_note(page)
            latest['coverage_download_note'].set_text(note)
            latest['coverage_download_note'].set_visibility(bool(note))
            set_changed(label, latest['coverage_download_error'])

        def coverage_answered(result):
            """A page of the table came: its summary line, its silent subnets and the download follow it."""
            latest['coverage_page'] = result
            summary = latest.get('coverage_summary')
            if summary is None or summary.is_deleted:
                return
            if result.get('error'):
                set_changed(summary, '')
            else:
                set_changed(summary, coverage_summary_line(result['summary']))
                lines = coverage_notices(result['summary'])
                notices = latest['coverage_notices']
                if [child.text for child in notices] != lines:
                    notices.clear()
                    with notices:  # one live region with a line for each subnet: one update, not sixty-four
                        for line in lines:
                            ui.label(line)
                notices.set_visibility(bool(lines))
            sync_coverage_download()

        def download_coverage():
            if latest['coverage_download'] or latest['coverage_parent'] is None or not alive():
                return
            latest['coverage_download_error'] = ''
            if settings_moved():  # the request on screen may now name another history file's request
                latest['coverage_download_error'] = 'The settings were reloaded. Refresh history, then download again.'
                sync_coverage_download()
                return
            try:
                latest['coverage_download'] = controller.request_coverage_export(latest['coverage_parent'])
            except (AttributeError, RuntimeError, ValueError):
                latest['coverage_download_error'] = 'Download is unavailable. Refresh history and try again.'
            sync_coverage_download()

        @ui.refreshable
        def draw_coverage():
            # The block is drawn on the runs of a saved target only: not on the list of targets, and not on the rounds of
            # a run, where the box is remembered (``request_history``) but nothing is read or shown.
            latest['coverage_drawn'] = latest['coverage_parent'] is not None and history.kind == 'runs'
            if not latest['coverage_drawn']:
                latest['coverage_download_button'] = None
                return
            with ui.column().classes('w-full gap-2').props('role=region aria-label="Available IPs"'):
                # The box is alone in the first row, ticked or not, so ticking it never moves it from under the pointer.
                with ui.row().classes('cn-monitor-toolbar'):
                    box = ui.checkbox('Show Available', value=latest['coverage_on'], on_change=toggle_coverage)
                    box._props['data-monitor-coverage'] = 'toggle'
                draw_coverage_body()

        @ui.refreshable
        def draw_coverage_body():
            """Everything under the box. The box redraws only this, never itself: a redraw that replaced it would drop
            the focus of a reader on it and lose a Space pressed on it while the redraw was on its way."""
            latest['coverage_download_button'] = latest['coverage_summary'] = None
            if not latest['coverage_on']:
                return
            latest['coverage_page'] = None
            with ui.column().classes('w-full gap-2'):
                ui.label(COVERAGE_TITLE).props('role=heading aria-level=2').classes('text-subtitle1 text-weight-bold')
                ui.label(COVERAGE_MEANING).classes('cn-muted')
                with ui.row().classes('cn-monitor-toolbar'):
                    button = ui.button('Download available IPs', on_click=download_coverage).props('outline dense no-caps')
                    button._props['data-monitor-coverage'] = 'download'
                    note = ui.label('').classes('cn-muted')
                    label = ui.label('').props('role=alert').classes('text-negative')
                    latest['coverage_download_button'], latest['coverage_download_label'] = button, label
                    latest['coverage_download_note'] = note
                    sync_coverage_download()
                # What the download holds and that it leaves the report alone: text on the page, not a tooltip (M9).
                described = ui.label('Downloads every IP of this target line that never replied (Unseen) as CSV, with '
                                     'its note. It is separate from the accumulated report and does not change it. '
                                     'Download table (CSV) below holds this table as filtered.').classes('cn-muted text-sm')
                button._props['aria-describedby'] = described.html_id
                latest['coverage_summary'] = ui.label('Reading the whole history…').props('role=status').classes('text-weight-bold')
                latest['coverage_notices'] = ui.element('div').props('role=status').classes('cn-notice')
                latest['coverage_notices'].set_visibility(False)
                ui.label('Counts describe the whole history; the table shows the selected group and filter.').classes('cn-muted')
                parent = latest['coverage_parent']
                source = monitor_tables.HistorySource(
                    controller, 'coverage', parent, generation=latest['config_generation'], on_answer=coverage_answered,
                    alive=lambda: alive() and latest['coverage_on'] and latest['coverage_parent'] == parent)
                cn_table(name='monitor-available', label='Available IPs results', columns=monitor_tables.COVERAGE_COLUMNS,
                         source=source, state=latest['coverage_state'], groups=monitor_tables.COVERAGE_GROUPS,
                         empty='No hosts.')

        def settings_moved():
            """The controller is past the settings generation this page last saw: what the page shows may belong to
            another history file, so nothing is read for it."""
            known = latest['config_generation']
            return known is not None and controller.snapshot().config_generation != known

        history_area = ui.column().classes('w-full')
        @ui.refreshable
        def draw_history_controls():
            async def back():
                history.back()
                await request_history('back')
            async def root():
                history.reset()
                await request_history('refresh')
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
                            # What the chip means is beside it, not in a tooltip (M9).
                            ui.label('Saved run').classes('cn-monitor-state')
                            ui.label('History only: Stop controls this session’s monitor, not this run.').classes('cn-muted text-sm')
                        view_state.link_button()  # a link to this run and its round (S9)
            with ui.element('nav').props('aria-label="History pages"').classes('cn-monitor-toolbar'):
                if history.ancestors:
                    button = ui.button('Back to runs' if history.kind == 'rounds' else 'Back to targets', on_click=back).props('outline dense no-caps')
                    button._props['data-monitor-history'] = 'back'
                button = ui.button('Refresh history', on_click=refresh).props('flat dense no-caps')
                button._props['data-monitor-history'] = 'refresh'
                if history.kind == 'requests':  # the one button that cannot be undone: last, behind a rule
                    with ui.element('div').classes('cn-monitor-danger'):
                        ui.button('Delete all history', on_click=lambda: open_delete('all')).props('flat dense no-caps color=negative')

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
                        latest['history_views'][history.kind].update(sort='', descending=False, text='')
                        show_history_filter()
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
                if 'total' in page:
                    ui.label(f"{texts.plural(page['total'], 'matching record')}.").classes('cn-muted')
            if not page.get('items'):
                draw_history_footer(page)
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
                        draw_history_footer(page)
                    with ui.column().classes('cn-monitor-detail gap-2'):
                        selected = latest['selected_round']
                        with ui.row().classes('cn-monitor-toolbar'):
                            if selected:
                                ui.label(history_value('started', selected.get('started'))).props('role=heading aria-level=2').classes('text-weight-bold grow cn-monitor-selected-title')
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
                                        latest['round_state'] = TableState()  # another run: its rounds start plain
                                    latest['request_context' if target == 'runs' else 'run_context'] = row
                                    history.open(target, row['id'], view_only=(not row.get('owned') if target == 'rounds' else None))
                                    await request_history('back')
                                ui.button('View runs' if history.kind == 'requests' else 'View rounds', on_click=open_item).props('outline dense no-caps')
                                if history.kind == 'runs':
                                    ui.button('Use settings', on_click=lambda _, run_id=item['id']: use_settings(run_id)).props('flat dense no-caps')
                                    with ui.button('Details').props('flat dense no-caps'), ui.menu().classes('cn-monitor-details'):
                                        ui.label('Owned by this session' if item.get('owned') else 'View only').classes('text-weight-bold')
                                        for line in history_run_summary(item):
                                            ui.label(line)
                                        with ui.element('dl').classes('cn-monitor-facts'):
                                            for label, value in history_run_details(item):
                                                with ui.element('dt'):
                                                    ui.label(label)
                                                with ui.element('dd'):
                                                    ui.label(value)
                                    remove = ui.button('Delete run', on_click=lambda _, row=dict(item): open_delete('run', row)).props('flat dense no-caps color=negative')
                                    reason = delete_run_reason(item)
                                    remove.set_enabled(not reason)
                                    if reason:  # visible text, not a tooltip: a disabled button takes no focus and no hover
                                        reason_label = ui.label(reason).classes('cn-muted cn-monitor-reason')
                                        remove._props['aria-describedby'] = reason_label.html_id
            draw_history_footer(page)

        def draw_history_footer(page):
            """The footer of the list on screen: rows per page, the range, First, Previous and Next (the one footer)."""
            async def go(where):
                if where == 'first' and len(history.cursors) > 1:
                    history.refresh()
                elif where == 'previous' and len(history.cursors) > 1:
                    history.previous()
                elif where == 'next' and page.get('next_cursor'):
                    history.next(page['next_cursor'])
                else:
                    return
                await request_history(where)

            async def size(value):
                chosen = monitor_tables.history_size(value)
                view = latest['history_views'][history.kind]
                if chosen is None or chosen == view['size']:
                    return
                view['size'] = chosen
                history.refresh()
                await request_history('page-size')
            monitor_tables.history_footer(history.kind, latest['history_views'][history.kind], page, history.cursors,
                                          on_size=size, on_go=go)

        async def history_filter_changed(event):
            value = event.value if isinstance(event.value, str) else ''
            if history.kind not in ('requests', 'runs') or len(value) > 256:
                return
            current = latest['history_views'][history.kind]
            if value == current['text']:
                return
            current['text'] = value
            history.refresh()
            await request_history()

        def show_history_filter():
            """The list's quick filter (one field, over every column) is the same element for both lists: it keeps the
            focus and what is typed while the list under it is drawn again. It shows the text of the list on screen."""
            listed = history.kind in ('requests', 'runs')
            page = latest['history_page'] or {}
            # As on every table: no filter under FILTER_MIN_ROWS records, unless one is set (it must stay to clear).
            history_filter_box.set_visibility(listed and (
                bool(latest['history_views'][history.kind].get('text')) or page.get('next_cursor') is not None
                or page.get('total', FILTER_MIN_ROWS) >= FILTER_MIN_ROWS))
            if listed:
                name = 'Filter ' + monitor_tables.history_list_label(history.kind)
                if history_filter._props.get('aria-label') != name:
                    history_filter._props['aria-label'] = name
                    history_filter.update()
                text = latest['history_views'][history.kind]['text']
                if (history_filter.value or '') != text:
                    history_filter.set_value(text)
        with history_area:
            draw_history_controls()
            draw_coverage()
            history_filter_box, history_filter = filter_input(
                'Saved monitor targets', 'monitor-history', '', history_filter_changed)
            draw_history()

    def focus_coverage(marker):
        """Put the focus back on Show Available's box (or the control named) once the block under it is drawn again."""
        client.run_javascript(f'''(() => {{
const control = document.querySelector({json.dumps(f'[data-monitor-coverage="{marker}"]')});
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

    async def request_history(focus=None, *, round_pick='first', fresh_coverage=False, keep_round=False, step=False):
        # Also awaited by a click: nothing is asked of the worker for a page that was left (scope.alive, at the start
        # and after every await), since its queries were given up when it was left. A link's rows are read first.
        if not await link.locate(controller) or not alive():  # overtaken by a later Back or Forward: that one reads
            return
        latest['round_pick'] = round_pick
        if not keep_round:  # only the first read after a return chooses the kept round again
            latest['round_keep'] = None
        if focus:
            latest.pop('round_focus', None)
        latest['selected_round'] = None
        latest['coverage_state'].first_page()  # History is read again: Show Available starts at its first page
        if latest['history_query']:
            controller.release_monitor_history_page(latest['history_query'])
        latest['history_query'] = None
        latest['history_page'] = None
        # The box belongs to the saved target the runs table lists, and to the rounds of its runs. Another target, or the
        # list of targets, starts with it off, so that an answer for the old target can never draw under the new one.
        # The rounds of a run of the same target keep the box ticked but draw nothing and read nothing; the runs, back
        # again, read the table again, and so does Refresh history.
        target = (history.parent if history.kind == 'runs' else
                  history.ancestors[-1][1] if history.kind == 'rounds' and history.ancestors else None)
        if target != latest['coverage_parent']:
            reset_coverage()
            latest['coverage_parent'] = target
            await draw_coverage.refresh()
        elif history.kind != 'runs':
            if latest['coverage_drawn']:
                await draw_coverage.refresh()
        elif not latest['coverage_drawn']:
            await draw_coverage.refresh()
        elif fresh_coverage and latest['coverage_on']:
            await draw_coverage_body.refresh()  # the box stays, with the focus of a reader on it
        if not alive():
            return
        show_history_filter()
        try:
            size = latest['history_views'][history.kind]['size']
            if history.kind in ('requests', 'runs'):
                current = latest['history_views'][history.kind]
                latest['history_query'] = controller.request_monitor_history(history.kind, history.parent, history.cursor, size,
                    current['sort'], current['descending'], 'all', monitor_tables.ANY, current['text'])
            else:
                latest['history_query'] = controller.request_monitor_history(history.kind, history.parent, history.cursor, size)
        except (AttributeError, RuntimeError, ValueError):
            latest['history_page'] = {'error': 'History is unavailable. Try refreshing.'}
        await draw_history_controls.refresh()
        await draw_history.refresh()
        link.replace() if keep_round or step else link.push()  # another saved target or run is a step Back undoes
        if focus and alive():
            focus_history(focus)

    async def poll():
        # Also awaited by a click, which is not cancelled with the scope: it asks scope.alive (alive()) at its start and
        # after every await, so a page that was left neither reads nor asks anything more. Its job is never stopped.
        if lock.locked() or not alive():
            return
        async with lock:
            page = controller.page_snapshot('monitor', result_revision=latest['result_revision'], attempt_revision=latest['attempt_revision'])
            if page.result_changed:
                latest['result'], latest['result_revision'] = page.result, page.result_revision
            if page.attempt_changed:
                latest['outcome'], latest['attempt_result'], latest['attempt_revision'] = page.outcome, page.attempt_result, page.attempt_revision
            state = job_slots.monitor_view(page.state)  # the page's own slot is the Monitor's (R3-03): its phase, job and facts
            generation = state.config_generation
            if latest['config_generation'] is None:
                latest['config_generation'] = generation
            elif generation != latest['config_generation']:
                # Reloaded settings may name another [ping] history_file: a round or a fold chosen before may not exist
                # there, or be another one under the same id. History starts again from the saved targets.
                latest['config_generation'] = generation
                # A confirmation opened for the history file before the reload is answered after it: it sees the
                # generation has moved and deletes nothing (open_delete).
                # The chosen round goes now; History is read again once the session accepts queries (the reload is
                # still starting when the generation moves), by the history_dirty step below. A table's export walk
                # under the old settings stops by itself (its source's generation).
                latest['selected_round'] = latest['round_keep'] = None
                history.reset()
                latest['history_dirty'] = True
            deleting = state.report_delete_pending
            active = state.active_lookup_type == 'monitor' and bool(state.active_job_id)
            update = state.monitor_update
            data = ((update or {}) if active else (latest.get('attempt_result') or latest['result'] or update or {}))
            phase = state.phase
            shell.update(page.state)  # the status line, Stop, the pill, the toast and the end of the session
            run.set_enabled(not deleting and phase == 'ready' and not state.active_job_id and all(control.enabled for control, _ in fields.values()))
            place_round(active)
            fold.set_summary(form_summary(targets.value or '', ports=ports.value or '', interval=interval.value or '',
                                          duration=duration.value or '', tool='monitor'))
            outcome = latest['outcome'] or {}
            if data:
                previous = bool(page.attempt_job_id and page.result_job_id and page.attempt_job_id != page.result_job_id)
                summary_text = monitor_summary(data, active=active, previous=previous)
            else:  # a run before its first round, or one that ended without one; nothing at all says nothing here
                summary_text = ('No complete round yet. An unfinished round does not indicate an outage.'
                                if active or outcome else '')
            rounds = data.get('current_rounds', 0)
            # The run has ended and left something to say: a result, or rounds the session still holds.
            ended = not active and bool(outcome) and (latest.get('attempt_result') is not None or bool(rounds))
            probe_failed = bool(data.get('probe_failed'))
            message = str(outcome.get('message') or '') if outcome.get('kind') in {'invalid', 'lookup_error', 'partial', 'stopped'} else ''
            # Said once: a stop by the notice of the ended run, a probe error by its one line in the attention tone.
            if (outcome.get('kind') == 'stopped' and ended) or (
                    outcome.get('kind') == 'lookup_error' and (latest.get('attempt_result') or {}).get('probe_failed')):
                message = ''
            set_changed(outcome_status, message)
            probe_notice.set(outcome_banner.ATTENTION, PROBE_ERRORS) if probe_failed else probe_notice.hide()
            set_changed(warning_status, ' '.join(monitor_warnings(data, outcome)))
            set_changed(history_status, f"History: {data['history_error']}" if data.get('history_error') else '')
            set_changed(report, texts.attempt_report_note(page.attempt_report_state, state.report_state))
            job = state.active_job_id if active else page.attempt_job_id
            run_id = (update or {}).get('run_id')
            revision = (update or {}).get('revision')
            # The live table: built once for a run with a complete round, then read again for each new revision in
            # place (its header, filter, footer and the focus stay); a new run starts with a table of its own.
            identity = (job, run_id) if job and run_id is not None else None
            fold.show(active or identity is not None, running=active, attempt=page.attempt_job_id)
            ready = bool(identity and revision)
            if identity != latest['live_identity'] or ready != latest['live_ready'] or latest['idle'] != (not active):
                if identity != latest['live_identity']:
                    # Another run (or the first poll): the kept arrangement only for the run the tab left.
                    latest['live_state'] = kept.live_for(identity)
                    link.live(identity, latest['live_state'])
                    latest['live_exact'] = kept.live_exact
                    live_map.reset(active, kept.map_show)
                # A monitor of this session started or ended (or this is the first poll). An ended run's Map is
                # dimmed; a view with no round to show says that none is on its way, in place of "Waiting".
                latest['idle'] = not active
                live_view.classes(**{'remove' if active else 'add': 'cn-live-stopped'})
                if identity != latest['live_identity'] or ready != latest['live_ready'] or not ready:
                    latest.update(live_identity=identity, live_ready=ready, live_revision=revision)
                    await draw_live.refresh()
                    if not alive():
                        return
                    link.replace()
            elif ready and revision != latest['live_revision']:
                latest['live_revision'] = revision
                handle = latest['live_handle']
                if handle is not None:
                    handle.source.key = (job, run_id, revision)
                    scope.task(handle.refresh(), name='monitor-live-round')
            live_map.follow(job, run_id, revision, active)
            # The change list (R3-08): asked when the run's changes_seq moved. The round summary says the round's count (the
            # difference of changes_seq between two revisions: exact) once, and never a partial one.
            feed.follow((job, run_id) if update and job and run_id is not None else None, update, active=active)
            note = feed.note(revision)
            set_changed(summary, summary_text + (' ' + note if note else ''))
            # The line above the live view and the notice of an ended run. The run's size is in the snapshot only
            # while it probes: the round on screen gives it too (the Map's answer, the table's counts), and it is
            # kept for the run, so a tab opened between two rounds names the hosts as soon as it has drawn one.
            if latest['hosts'][0] != (job, run_id):
                latest['hosts'] = ((job, run_id), None)
            shown = latest['live_handle'].page if latest['live_handle'] is not None else None
            size = (live_map.hosts or (shown.counts.get('all') if shown else 0)
                    or (texts.job_size(state) if active else 0))
            if size:
                latest['hosts'] = ((job, run_id), size)
            # The session's update describes this run unless a later one replaced it (or a reload dropped it).
            same_run = bool(update) and (active or not data.get('run_id') or data['run_id'] == update.get('run_id'))
            head, doing, next_at, facts = monitor_header(
                update if same_run else None,
                state.active_request if active else (page.attempt_meta or {}).get('request'),
                active=active, rounds=rounds, hosts=latest['hosts'][1], started=state.active_started_at if active else None)
            set_changed(header_round, head)
            set_changed(header_doing, f' · {doing}' + (' ' if next_at else '') if doing else '')
            set_clock(header_clock, next_at)
            set_changed(header_facts, f' · {facts}' if facts else '')
            header.set_visibility(active or bool(rounds))
            notice = stopped_notice(outcome, page.attempt_meta, rounds, probe_failed=probe_failed,
                                    showing=same_run and (update.get('revision') or 0) > 0) if ended else ''
            ended_notice.set(outcome_banner.INFORMATION, notice) if notice else ended_notice.hide()
            live_map.enable()  # every line above the view switch has its place now
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
                        fold.edit(focus=False)  # the settings are put on the form, which opens to show them
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
                        history_delete_error.set_text('')
                        set_changed(history_delete_status, notice)
                        if latest['template_query']:
                            controller.release_monitor_history_page(latest['template_query'])
                            latest['template_query'] = None
                        history.reset()
                        await request_history('refresh')
                        if not alive():
                            return
                    else:
                        messages = {'running': 'A recorded monitor is active or its state cannot be verified. Wait for it to finish or check the process that owns it.',
                                    'missing': 'The selected history no longer exists. Refresh history and try again.',
                                    'failed': 'History could not be deleted. Check the history file and try again.'}
                        history_delete_status.set_text('')
                        history_delete_error.set_text(deletion.get('warning') if deletion_status == 'failed' and deletion.get('warning')
                                                      else messages.get(deletion_status, messages['failed']))
            if latest['history_dirty'] and phase in {'ready', 'running', 'stopping', 'saving'}:
                latest['history_dirty'] = False
                await request_history(keep_round=True)  # a return chooses the round it left again
                if not alive():
                    return
            if latest['history_query']:
                result = controller.monitor_history_page(latest['history_query'])
                if result is not None:
                    controller.release_monitor_history_page(latest['history_query'])
                    latest['history_query'] = None
                    latest['history_page'] = result
                    show_history_filter()
                    if link.answered(result):  # a link's saved target or run is gone: History from the start
                        await request_history(keep_round=True)
                        return
                    if history.kind == 'rounds' and not result.get('error') and result.get('items'):
                        items, pick = result['items'], -1 if latest['round_pick'] == 'last' else 0
                        again = next((item for item in items if item.get('id') == latest['round_keep']), None)
                        latest['round_pick'], latest['round_keep'] = 'first', None
                        await select_round(again or items[pick], 'round', refresh='none', kept_round=again is not None)
                    await draw_history.refresh()
                    if not alive():
                        return
                    focus_round(latest.pop('round_focus', None))
                    link.replace()
                    client.run_javascript(monitor_style.PAGER_FOCUS)

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

    # Built in the order the session is in now, so that the first poll moves nothing.
    place_round(bool(controller.snapshot().monitor_job_id))
    # A tab's form is its draft (sessionStorage). A tab with none of the four values, a new one, shows what this
    # session's Monitor was last asked; a tab that holds any, even an empty one, keeps its own. Decided once.
    drafts = [(targets, 'targets', ''), (ports, 'ports', ''), (interval, 'interval', '60'), (duration, 'duration', '')]
    draft_keys = json.dumps(['cn-tool-draft-monitor-' + suffix for _, suffix, _ in drafts])
    async def restore(control, suffix, default, index, again=False):  # the four fields; ``again``: subnets' restore_draft
        if not alive():
            return
        if panel() != 'live':  # the form is not drawn: restored when the Live panel is chosen (panel_changed)
            pending.append((control, suffix, default, index))
            return
        last = request_form(controller.last_request('monitor'))
        fresh = json.dumps(default if last is None else last[index])
        install = '''const root = document.getElementById(%s);
const input = root?.matches('input,textarea') ? root : root?.querySelector('input,textarea');
if (!input) return false;
const key = %s;
%s
if (!input.cnDraftListener) {
  input.cnDraftListener = true;
  input.addEventListener('input', () => { input.cnDraftEdited = true; sessionStorage.setItem(key, input.value); });
}
''' % (json.dumps(control.html_id), json.dumps('cn-tool-draft-monitor-' + suffix), preview.guard_js() if control is targets else '')
        try:
            await asyncio.wait_for(client.connected(), timeout=5)
            if not again:
                installed = alive() and await client.run_javascript(f'(() => {{{install} return true;}})()', timeout=5)
                if not alive():
                    return
                if not installed:
                    raise TimeoutError
                control.enable()  # first: the value the script restores is an event, and a disabled field's are ignored
            restored = await client.run_javascript(f'''(() => {{{install}{lookup_inputs.keep_typed('key', default)}
if (!input.cnDraftEdited) {{
  window.cnMonitorNewTab ??= {draft_keys}.every(name => sessionStorage.getItem(name) === null);
  input.value = sessionStorage.getItem(key) ?? (window.cnMonitorNewTab ? {fresh} : {json.dumps(default)});
  input.dispatchEvent(new Event('input', {{bubbles:true}}));
}}
return true;
}})()''', timeout=5)
            if not alive():
                return
            if restored:
                if index == 0:
                    await lookup_inputs.show_handoff(client, 'monitor', handoff_note, run, (targets, ports),
                                                     opened=lambda: fold.edit(focus=False))
                return
        except (TimeoutError, asyncio.TimeoutError):  # distinct classes on Python 3.10: a miss left a field disabled
            pass
        if alive():
            client.run_javascript(f'(() => {{{install}}})()')
            await asyncio.sleep(0)
            control.enable()
            scope.timer(1, lambda: restore(control, suffix, default, index, again=True), once=True)
    for index, (control, suffix, default) in enumerate(drafts):
        control.disable()
        scope.timer(0, lambda c=control, s=suffix, d=default, i=index: restore(c, s, d, i), once=True)

    async def handed_over():
        """Targets sent by Monitor these to a tab that left the Monitor on History: the form is what the user came for."""
        try:
            sent = await client.run_javascript("sessionStorage.getItem('cn-tool-handoff-monitor') !== null", timeout=5)
        except (TimeoutError, asyncio.TimeoutError):
            return
        if sent and alive():
            tabs.set_value(live_tab)
    if kept.panel == 'history':
        scope.when_connected(lambda: scope.task(handed_over(), name='monitor-handoff'))
    def release_queries():
        if latest['delete_query']:
            controller.release_monitor_delete_result(latest['delete_query'])
            latest['delete_query'] = None
        if latest['template_query']:
            controller.release_monitor_history_page(latest['template_query'])
            latest['template_query'] = None
        live_map.release()
        feed.release()
        if latest['history_query']:
            controller.release_monitor_history_page(latest['history_query'])
            latest['history_query'] = None
        release_coverage_download()

    def keep():
        """The Monitor is left (or the tab closes): the tab takes back what it finds again on its return."""
        kept.keep(latest, panel=panel())
        handle = latest['live_handle']
        if latest['live_identity'] != ():  # () : no poll has said which run is on screen; the kept one stays
            kept.keep_live(latest['live_identity'], latest['live_state'], show=live_map.show,
                           exact=handle.source.exact if handle is not None else latest.get('live_exact'))
    scope.on_leave(release_queries)
    scope.on_leave(keep)
    targets.on_value_change(lambda _: poll())
    scope.timer(0, poll, once=True)
    scope.timer(0.5, poll)

