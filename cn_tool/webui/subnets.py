"""Subnets presentation. Redraws and navigation never submit worker operations."""
from dataclasses import dataclass, field, replace
import asyncio
import json
import re
from html import escape

from cn_tool.utils.unused_addresses import CONTAINER, INCOMPLETE, UnusedList, unused_addresses, with_unconfirmed

from .tables import TableState, order_rows  # noqa: F401  (order_rows: its home is tables.py; the tests read it here)

UNUSED_TITLE = 'Unused addresses'


def table_name(*parts) -> str:
    """A table's name from what it shows (``detail-10-20-0-0-24-lab-dns-records``): the same on every draw of the page,
    and fit for a file name."""
    return '-'.join(slug for slug in (re.sub(r'[^a-z0-9]+', '-', str(part).casefold()).strip('-') for part in parts if part) if slug)
# The section of `cn subnet --available` (cn_tool.modules.subnet_request.UNUSED_SECTION).
UNUSED_SECTION = 'unused addresses'
# What a refusal row of `cn subnet --available` says (subnet_request.NO_LIST_NOTICE).
NO_LIST_NOTICE = 'no unused addresses listed: '
UNUSED_FILENAME = 'cn-unused-addresses.csv'
UNUSED_MEANING = 'Unused means no record of any type in Infoblox. It does not prove that nothing answers there.'


def available_result(result, *, cache=None):
    """
    The unused addresses of a Subnets result, from the sections it already holds (no request, no worker).

    Each group (one network in one network view) is judged on its own by ``unused_addresses`` (a group the lookup
    marked ``unconfirmed``, because a list request missed its network, is refused as incomplete); every child
    container is a refusal of its own, and so is every group of a result whose view list was not proved readable
    (``views_readable``) or of a stopped lookup (``stopped``: ``INCOMPLETE``); an input whose lookup failed
    (``resolution_errors``) is named last, with its message. Returns ``rows`` (the download: ``network view`` when
    any group has one, ``network``, ``IP address``, as ``cn subnet --available`` prints them), ``refusals``
    (``network``, ``network_view``, ``reason``) and ``by_group`` (a group's id to its table ``rows``, ``network view``
    when the group has one and then ``IP address``, or to its ``refusal``). ``cache``, one dict for one result, keeps
    the answer so that a poll does not compute it again.
    """
    if cache is not None and cache.get('result') is result:
        return cache['value']
    groups = result.get('detail_groups') or []
    views_readable = bool(result.get('views_readable', False))  # not proved is not readable
    stopped = bool(result.get('stopped'))
    show_view = shows_view(result)
    rows, refusals, by_group = [], [], {}
    for group in groups:
        network, network_view = str(group['network']), str(group.get('network_view') or '')
        # A stopped lookup cannot show that it left no half-read group, so none of its groups is listed.
        tables = group.get('tables') or {}
        found = UnusedList(refusal=INCOMPLETE) if stopped else unused_addresses(
            network, tables, with_unconfirmed(group.get('warnings') or [], tables, bool(group.get('unconfirmed'))),
            views_readable=views_readable)
        if found.refusal:
            refusals.append(dict(network=network, network_view=network_view, reason=found.refusal))
            by_group[group['id']] = dict(rows=[], refusal=found.refusal)
            continue
        lead = {'network view': network_view, 'network': network} if show_view else {'network': network}
        rows.extend(dict(lead, **{'IP address': address}) for address in found.addresses)
        shown = {'network view': network_view} if network_view else {}
        by_group[group['id']] = dict(rows=[dict(shown, **{'IP address': address}) for address in found.addresses],
                                     refusal='')
    for container in result.get('containers') or []:
        refusals.append(dict(network=str(container.get('child container') or container.get('container') or ''),
                             network_view=str(container.get('network view') or ''), reason=CONTAINER))
    # An input whose lookup failed (a name that did not resolve, a request that failed) has no group and no table, so
    # nothing stands for its addresses: it is named, like a container. A miss and an invalid input are not.
    for failed, message in (result.get('resolution_errors') or {}).items():
        refusals.append(dict(network=str(failed), network_view='', reason=str(message)))
    found = dict(rows=rows, refusals=refusals, by_group=by_group)
    if cache is not None:
        cache.clear()
        cache.update(result=result, value=found)
    return found


def shows_view(result):
    """Whether the rows of the download carry ``network view``: when any group of the result belongs to a view."""
    return any(group.get('network_view') for group in result.get('detail_groups') or [])


def available_download(result, found):
    """
    The bytes of ``cn-unused-addresses.csv`` for ``found`` (``available_result(result)``): the ``unused addresses``
    rows, then a ``warnings`` row (``network view`` when the result shows it, ``network``, ``warning``) for every
    input that could not be listed, as ``cn subnet --available --format csv`` writes them, so that a short file cannot
    pass for a complete one. No rows and no refusals give no bytes.
    """
    from cn_tool.utils.render import csv_bytes
    show_view = shows_view(result)
    refused = [{**({'network view': refusal['network_view']} if show_view else {}), 'network': refusal['network'],
                'warning': NO_LIST_NOTICE + refusal['reason']} for refusal in found['refusals']]
    return csv_bytes({UNUSED_SECTION: found['rows'], 'warnings': refused})


def refusal_line(refusal):
    """``<network or child container>[ in network view V]: <reason>``, as the page names a subnet it cannot list."""
    where = f" in network view {refusal['network_view']}" if refusal['network_view'] else ''
    return f"{refusal['network']}{where}: {refusal['reason']}"


async def restore_result_focus(client, root_id, attribute, value, table_identity=None):
    """Follow a control through the redraws of its panel (each mounts a new table), until the user acts."""
    root, attribute, value, identity = map(json.dumps, (root_id, attribute, value, table_identity))
    await client.run_javascript(f'''(() => {{
const root = document.getElementById({root});
if (!root) return;
root.cnSortRestore?.();
let target = null;
const stop = () => {{ observer.disconnect(); for (const e of ['pointerdown', 'keydown', 'wheel']) document.removeEventListener(e, stop, true); document.removeEventListener('focusin', moved, true); delete root.cnSortRestore; }};
const moved = event => {{ if (event.target !== target) stop(); }};
const restore = () => {{
 if (target?.isConnected && document.activeElement === target) return;
 const next = [...root.querySelectorAll('[' + {attribute} + ']')].find(el => el.getAttribute({attribute}) === {value} && ({identity} === null || el.dataset.sortTable === {identity}));
 if (document.activeElement !== document.body && document.activeElement !== target && document.activeElement !== next) {{ stop(); return; }}
 target = next;
 target?.focus({{preventScroll:true}});
}};
const observer = new MutationObserver(restore);
root.cnSortRestore = stop;
observer.observe(root, {{childList:true, subtree:true}});
for (const e of ['pointerdown', 'keydown', 'wheel']) document.addEventListener(e, stop, {{capture:true, passive:true}});
document.addEventListener('focusin', moved, true);
restore();
}})()''', timeout=1)


@dataclass
class Presentation:
    selection: object = None
    result_identity: object = None
    summary_scroll: tuple = (0, 0, 0)
    tables: dict = field(default_factory=dict)  # a table's id to its tables.TableState (filter, sort, page, size, group)
    show_available: bool = False  # the tab's choice: it survives a new lookup and a switch, a load starts with it off
    available_cache: dict = field(default_factory=dict)  # ``available_result`` of the result on screen only

    def attach(self, result, operation_id=None):
        identity = tuple(group['id'] for group in result.get('detail_groups', []))
        result_identity = ("operation", operation_id) if operation_id is not None else identity
        changed = result_identity != self.result_identity if operation_id is not None else set(identity) != set(self.result_identity or ())
        if changed or self.result_identity is None:
            ping = self.tables.get('ping')
            # The hosts probed so far belong to the running job, not to the result: their state stays (PingProgress
            # lets go of another job's), or its table would run on a state this dict no longer holds.
            partial = {key: value for key, value in self.tables.items() if isinstance(key, tuple) and key[0] == 'ping-partial'}
            self.tables.clear()
            self.tables.update(partial)
            if ping is not None:  # the tab's rows per page for Ping survives a new result; nothing else does
                self.tables['ping'] = TableState(size=ping.size)
            self.available_cache.clear()
            self.summary_scroll = (0, 0, 0)
            self.selection = identity[0] if len(identity) == 1 else None
        self.result_identity = result_identity

    def select(self, identity):
        self.selection = identity

    def groups(self, result):
        return [group for group in result.get('detail_groups', [])
                if self.selection == 'all' or group['id'] == self.selection]


# A list of lines the tool did not understand is shown open up to this many, collapsed above it.
NOT_UNDERSTOOD_OPEN = 5
NOT_UNDERSTOOD = 'Lines not understood'
_RUNNING = {'running', 'stopping', 'saving'}
EARLIER_RESULTS = 'Results of the earlier lookup'


def _reason(message, fallback):
    """An error's reason as a headline: the worker's sentence without its closing stop."""
    return str(message or '').strip().rstrip('.') or fallback


def lookup_headline(outcome, lookup_type='subnet'):
    """What the user got from a Subnets or IP lookup, in one line: "9 networks found", "3 addresses found · 2 lines not
    understood", "Nothing found for 2 inputs". Zero counts are not printed; an error is its reason."""
    from . import texts
    kind, details = outcome.get('kind'), outcome.get('details') or {}
    if kind == 'lookup_error':
        return _reason(outcome.get('message'), 'The lookup failed')
    noun = ('address', 'addresses') if lookup_type == 'ip' else ('network', 'networks')
    found = [texts.plural(n, *words) for n, words in ((outcome.get('matched_count') or 0, noun),
                                                       (details.get('container_count') or 0, ('container', 'containers')))
             if n]
    misses = outcome.get('miss_count') or 0
    rest = texts.counts_line([
        (outcome.get('invalid_count') or 0, 'line not understood', 'lines not understood'),
        (outcome.get('resolution_error_count') or 0, 'lookup error', 'lookup errors'),
        (0 if kind == 'no_match' else misses, 'input without a match', 'inputs without a match'),
        (outcome.get('warning_count') or 0, 'warning', 'warnings')])
    if kind == 'no_match':
        head = f"Nothing found for {texts.plural(misses, 'input')}" if misses else 'Nothing found'
    elif kind == 'stopped':
        head = ' · '.join(['Lookup stopped'] + ([' and '.join(found) + ' found'] if found else []))
    elif kind in ('matched', 'partial'):
        head = (' and '.join(found) + ' found') if found else ''
    elif kind == 'invalid':
        head = '' if rest else 'No line was understood'
    else:
        return 'Lookup outcome'
    return ' · '.join(part for part in (head, rest) if part) or 'Lookup completed'


def outcome_display(snapshot, lookup_type='subnet'):
    """Return escaped text for the worker's latest outcome, without classifying it: ``title`` (the headline), ``tone``
    ('error' for a failed lookup), ``not_understood`` (the lines the tool did not understand) and ``details`` (the
    rest of the diagnostics)."""
    outcome = snapshot.latest_outcome
    if not outcome:
        return None
    detail = outcome.get('details') or {}
    input_aliases = detail.get('input_aliases') or {}

    def address_label(address):
        originals = list(dict.fromkeys(input_aliases.get(address) or []))
        if originals and any(original != address for original in originals):
            return f"{address} (inputs: {', '.join(originals)})"
        return address
    not_understood = [f'{item}: {problem}' for item, problem in (detail.get('invalid_inputs') or {}).items()]
    lines = []
    for key in ('resolution_errors', 'lookup_errors'):
        lines.extend(f'{item}: {problem}' for item, problem in (detail.get(key) or {}).items())
    misses = detail.get('misses') or []
    if isinstance(misses, dict):
        lines.extend(f'{item}: {reason}' for item, reason in misses.items())
    else:
        lines.extend(f'{item}: no matching network' for item in misses)
    lines.extend(f"{address_label(item.get('object', ''))}: {item.get('warning', '')}" if isinstance(item, dict) else str(item)
                 for item in (detail.get('warnings') or []))
    for key, label in [('cancelled_ips', 'incomplete'), ('unattempted_ips', 'not attempted'),
                       ('ptr_not_checked', 'PTR not checked')]:
        lines.extend(f'{address_label(item)}: {label}' for item in (detail.get(key) or []))
    return dict(title=escape(lookup_headline(outcome, lookup_type)),
                tone='error' if outcome.get('kind') == 'lookup_error' else '',
                not_understood=[escape(line) for line in not_understood], details=[escape(line) for line in lines])


def scope_line(scope, username):
    """The line under the title once the session knows them: "Network views: all · Signed in as alice". Nothing
    before then."""
    scope = str(scope or '').strip().rstrip('.')
    if scope == 'All network views':
        scope = 'Network views: all'
    return ' · '.join(part for part in (scope, f'Signed in as {username}' if username else '') if part)


def earlier_results(snapshot, lookup_type):
    """Whether the results on screen are not the latest attempt's: this tool's own job is running (they are the earlier
    lookup's) or its latest attempt produced nothing to replace them. Another tool's job says nothing about them."""
    if snapshot.result is None:
        return False
    own = (bool(snapshot.active_job_id) and snapshot.active_lookup_type == lookup_type
           and snapshot.phase in _RUNNING)
    return own or bool(snapshot.latest_attempt_id and snapshot.latest_attempt_id != snapshot.result_job_id)


# The three lookup pages. The scope line keeps its place while it has no text (a lookup learns the scope and the login
# only when it starts, and the form below must not move then); an error's headline and the notice carry the error
# tone: the reason is its own words, the colour only supports it.
OUTCOME_CSS = '''
.cn-scope { min-height:1.5em; }
'''

LOOKUP_CSS = '''
.nicegui-content:has(.cn-lookup-form) { gap:12px; }
.cn-lookup-empty:empty { display:none; }
.cn-lookup-form textarea { min-height:calc(3 * 1.5em); max-height:calc(10 * 1.5em + 16px); }
.cn-lookup-form, .cn-lookup-outcome { gap:8px; }
.cn-lookup-outcome h2 { margin-top:0; }
'''

# The outcome is one row (results first, R2-05): the banner, then what the attempt did to the report, on one line where
# it fits; no panel around them. Lines not understood and diagnostics open under it.
OUTCOME_ROW_CSS = '''
.cn-outcome-row { display:flex; flex-wrap:wrap; align-items:center; gap:4px 16px; width:100%; min-width:0; }
.cn-outcome-row > .cn-outcome-area { flex:1 1 24em; min-width:0; gap:8px; }
'''


def render_subnets(controller, scope, lookup_type='subnet'):
    from nicegui import ui
    from . import dialogs, lookup_inputs, target_preview, texts
    from . import outcome as outcome_banner
    from .setup_card import needs_endpoint, render_setup
    from .shell import render_shell
    from .sign_in import SignInFlow
    from .results_first import FormFold, form_field, form_summary
    from .theme import apply_theme

    apply_theme()
    scope.head_once('lookup-outcome', css=OUTCOME_CSS + OUTCOME_ROW_CSS)
    from .tables import apply_table_assets
    apply_table_assets()
    if lookup_type != 'ping':
        scope.head_once('lookup', css=LOOKUP_CSS)
    empty_class = ' cn-ping-empty' if lookup_type == 'ping' else ' cn-lookup-empty'
    from .scope import tab_state
    # The tab's arrangement of the result (table states, the open details, Show Available), found again after a
    # visit to another tool; the result itself is read again from the controller (R2-10).
    view = tab_state(ui.context.client).setdefault(lookup_type, Presentation())
    from . import view_state
    main = {'subnet': 'summary', 'ip': 'ip', 'ping': 'ping'}[lookup_type]  # the table the URL arranges (R2-08)

    def link_values():
        values = view_state.table_values(view.tables.get(main))
        shown = latest.get('displayed_snapshot')
        if lookup_type == 'subnet' and len(((shown.result if shown else None) or {}).get('detail_groups') or []) > 1:
            values['net'] = view.selection  # one network is its own details: no net
        return values
    link = view_state.ViewState(scope, view_state.LOOKUP_SCHEMAS[lookup_type], link_values)
    poll_lock = asyncio.Lock()
    latest = {'snapshot': None}
    shell = render_shell(controller, lookup_type)
    shell.set_help(lookup_inputs.HELP[lookup_type])
    setup = render_setup(controller, lookup_type)  # Setup required: the reason, Retry setup and the way to Settings
    retry = setup.retry
    # Ping needs neither a scope nor a login; the others show them once the session knows them (scope_line).
    scope_label = ui.label('Ping uses system DNS and does not require Infoblox.' if lookup_type == 'ping' else '').classes('cn-muted cn-scope')
    with ui.row().classes('items-center'):
        # Offered only while the credential store says a login is saved (dialogs.saved_login).
        forget = ui.button(dialogs.FORGET, on_click=controller.forget_credentials).props('outline')
        forget.set_visibility(False)
        store_status = ui.label('').props('role=status').classes('cn-muted' + empty_class)
    recovery = ui.label('If saved credentials are refused, forget them and run the lookup again to enter a different login.').classes('cn-muted text-sm')
    recovery.set_visibility(False)
    with ui.row().classes('w-full items-baseline gap-3'):
        shell.status = ui.label('Attaching…').props('role=status')
        shell.add_elapsed()
    report_warning = ui.label('').props('role=status').classes('text-warning' + empty_class)
    link.notice()  # a link to a result that is no longer here says so
    handoff_note = lookup_inputs.handoff_note()  # targets sent by "Ping these" (said once; nothing runs)
    if lookup_type != 'ping':
        setup.add_card()  # in the form's place while the settings name no Infoblox endpoint
    with ui.column().classes('cn-panel cn-ping-form' if lookup_type == 'ping' else 'cn-panel cn-lookup-form') as form:
        # The one form style: a label above an outlined, dense box; no placeholder (the example is the helper text).
        _, targets = form_field('textarea', 'Targets', props='rows=3 autogrow aria-label=Targets', classes='w-full cn-ping-targets',
                                label_classes='cn-ping-target-label')
        lookup_inputs.helper_text(targets, lookup_inputs.TARGET_HELP[lookup_type], 'cn-muted cn-ping-target-help')
        preview = target_preview.attach(targets, lookup_type, scope, 'cn-ping-target-preview')  # the live line (7.3)
        ports = None
        if lookup_type == 'ping':
            _, ports = form_field('input', 'TCP ports', props='aria-label="TCP ports"', classes='w-full cn-ping-ports', label_classes='cn-ping-ports-label')
            lookup_inputs.helper_text(ports, lookup_inputs.PORT_HELP, 'cn-muted cn-ping-port-help')
            preview.use_ports(ports)  # the live line warns when the hosts are more than the tool tests with ports
        port_error = ui.label('').props('role=alert').classes('text-negative cn-ping-port-error' + empty_class)
        with ui.row().classes('cn-ping-run-controls cn-form-actions'):
            reading = []  # set while a Run reads the box: a second click or Ctrl+Enter meanwhile is the same Run

            async def submit():
                # A click handler is not cancelled with the scope (scope.py): it asks scope.alive at its start and
                # after every await, so a page that was left never starts a job, builds UI or polls.
                if not scope.alive or reading:
                    return None
                reading.append(True)
                try:
                    return await read_and_start()
                finally:
                    reading.clear()

            async def read_and_start():
                if lookup_type == 'ping':
                    from .ping import parse_ports
                    try:
                        parsed = parse_ports(ports.value or '')
                    except ValueError as exc:
                        port_error.set_text(str(exc))
                        return ports  # Run again opens the form at the field that is wrong
                    port_error.set_text('')
                else:
                    parsed = ()
                    port_error.set_text('')
                typed = targets.value or ''
                lines = await target_preview.lines_for_submit(typed, lookup_type)  # off the event loop
                if not scope.alive:
                    return None
                if not lines:  # blank, or comments only
                    port_error.set_text(target_preview.NO_TARGETS)
                    return targets
                if lookup_type == 'ping':
                    start = lambda: controller.submit(lines, lookup_type=lookup_type, tcp_ports=parsed, typed=typed)
                else:
                    start = lambda: controller.submit(lines, lookup_type=lookup_type, typed=typed)
                try:
                    start()
                except RuntimeError as refusal:
                    # A click on a button that the next poll was about to disable (another tab's work, a deletion):
                    # say why nothing started rather than let the error end the handler and look like a dead button.
                    port_error.set_text(str(refusal) or 'The lookup could not start. Try again.')
                    return
                started_here()
                fold.ran()  # results first: the form is its one line now
                reading.clear()  # started: a Run from here on is a new one (Run again), whatever refresh_now takes
                await refresh_now()
            run = shell.waits(ui.button('Run Ping' if lookup_type == 'ping' else 'Look up', on_click=submit))
            setup.form.append(form)
            shell.add_stop().classes('cn-form-keep')  # shown only for this page's own job, and it ends only that one
            def jump_to_results():
                ui.run_javascript(f'document.getElementById({json.dumps(results.html_id)})?.focus()')
            show_results = ui.button('View results', on_click=jump_to_results).props('outline').classes('cn-form-keep')
            show_results.set_visibility(False)
        def run_from_keyboard():
            if run.enabled:
                return submit()
        for field in (targets, ports):
            if field is not None:
                for modifier in ('ctrl', 'meta'):
                    field.on(f'keydown.{modifier}.enter.prevent', run_from_keyboard)
    # After Run the form is one line with Edit (results first); the tab keeps the choice across a reload.
    fold = FormFold(form, lookup_type, focus=targets, run=run, again=submit, alive=lambda: scope.alive)

    def started_here():
        """A job this page started: the sign-in flow's leave rule asks whether the tab started the job that asks."""
        sign_in.started(controller.page_snapshot(lookup_type).state.active_job_id)

    async def sign_in_again():
        if not scope.alive:
            return
        request = controller.last_request(lookup_type)
        try:
            if not request:
                raise RuntimeError('The lookup to repeat is no longer known. Enter the targets and look up again.')
            # What is repeated is shown: the request's inputs go back into Targets (and the tab's draft) first.
            text = lookup_inputs.typed_text(request)
            targets.set_value(text)
            ui.run_javascript(f"sessionStorage.setItem({json.dumps('cn-tool-draft-' + lookup_type)}, {json.dumps(text)});")
            controller.submit(request['inputs'], lookup_type=lookup_type, typed=text)
        except RuntimeError as refusal:
            port_error.set_text(str(refusal) or 'The lookup could not start. Try again.')
            fold.edit(focus=False)  # the message is in the form, which the fold hides
            return
        port_error.set_text('')
        started_here()
        fold.ran()
        # The outcome is not redrawn under the focus, and this button is part of the refused outcome: let go of it,
        # so that the outcome goes with the new attempt. The sign-in dialog, or the new outcome, takes the focus.
        ui.run_javascript('if (document.activeElement?.closest("[data-sign-in-again]")) document.activeElement.blur();')
        await refresh_now()

    async def retry_last():
        if not scope.alive:
            return
        try:
            request = outcome_banner.repeat(controller, lookup_type)
        except (RuntimeError, ValueError) as refusal:
            port_error.set_text(str(refusal) or 'The lookup could not start. Try again.')
            fold.edit(focus=False)  # the message is in the form, which the fold hides
            return
        form = lookup_inputs.request_form(request, lookup_type)  # what is repeated is shown: its inputs go back on the form
        if form:
            targets.set_value(form[0])
            ui.run_javascript(f"sessionStorage.setItem({json.dumps('cn-tool-draft-' + lookup_type)}, {json.dumps(form[0])});")
            if ports is not None:
                ports.set_value(form[1])
        port_error.set_text('')
        started_here()
        fold.ran()
        ui.run_javascript('if (document.activeElement?.closest("[data-outcome-action]")) document.activeElement.blur();')
        await refresh_now()

    def draw_headline(title, snapshot, *, escaped, lines=0):
        """The outcome banner: its title is the page's one polite region; its actions are what the outcome offers."""
        outcome_value = snapshot.latest_outcome
        handlers = dict(sign_in_again=sign_in_again, retry=retry_last, open_settings=outcome_banner.open_settings,
                        show_lines=outcome_banner.show_lines)
        actions = outcome_banner.actions_for(lookup_type, outcome_value, handlers, lines=lines,
                                             can_repeat=bool(controller.last_request(lookup_type)))
        # One banner for the page, drawn once above the panel's redrawn part: a redraw updates the text of the same
        # live region (a region that is new at each redraw is often not announced).
        banner.set(outcome_banner.tone_for(outcome_value), title, actions=actions)
        latest['outcome_heading'] = banner.title.html_id
        latest['headline_drawn'] = True

    @ui.refreshable
    def draw_outcome():
        latest['headline_drawn'] = False
        try:
            draw_outcome_parts()
        finally:
            if not latest['headline_drawn']:
                banner.hide()

    def draw_outcome_parts():
        snapshot = latest.get('displayed_outcome_snapshot') if lookup_type == 'ping' else latest['snapshot']
        if lookup_type == 'ping':
            from .ping import format_diagnostic, ping_outcome_display, render_pager
            outcome = ping_outcome_display(snapshot, {'result': latest.get('displayed_outcome_result')},
                                           format_entries=False) if snapshot else None
            if outcome:
                draw_headline(outcome['title'], snapshot, escaped=False, lines=len(outcome['input_errors']))
                for key, title in [('input_errors', NOT_UNDERSTOOD), ('resolution_errors', 'DNS errors'), ('incomplete', 'Attempted but incomplete'), ('unattempted', 'Not attempted')]:
                    if outcome[key]:
                        entries = outcome[key]
                        pages = (len(entries) + 49) // 50
                        current = min(latest['diagnostic_pages'].get(key, 0), pages - 1)
                        start = current * 50
                        shown = entries[start:start + 50]
                        with ui.element('section').classes('w-full') as section:
                            section._props['aria-label'] = title
                            # Lines the tool did not understand are the user's own: open when few. The rest opens
                            # when nothing else came of the run.
                            opened = (len(entries) <= NOT_UNDERSTOOD_OPEN if key == 'input_errors'
                                      else not bool((snapshot.latest_outcome or {}).get('matched_count')))
                            expanded = latest['diagnostic_expanded'].get(key, opened)
                            with ui.expansion(f'{title} ({texts.fmt_count(len(entries))})', value=expanded,
                                    on_value_change=lambda event, category=key: latest['diagnostic_expanded'].__setitem__(category, event.value)
                                    ).classes('cn-ping-diagnostics').props('dense header-class=text-weight-bold' + (' data-lines-not-understood' if key == 'input_errors' else '')):
                                ui.label(f'Showing {texts.fmt_count(start + 1)}–{texts.fmt_count(start + len(shown))} of {texts.fmt_count(len(entries))}')
                                if pages > 1:
                                    render_pager(key, title, current, pages,
                                                 lambda value, category=key: latest['diagnostic_pages'].__setitem__(category, value),
                                                 draw_outcome.refresh, interaction_lock=poll_lock)
                                with ui.element('ul'):
                                    for item in shown:
                                        with ui.element('li'):
                                            ui.label(format_diagnostic(key, item))
            return
        outcome = outcome_display(snapshot, lookup_type) if snapshot else None
        if outcome:
            # The refused login was dropped: Sign in again starts the same lookup, which asks again.
            draw_headline(outcome['title'], snapshot, escaped=True, lines=len(outcome['not_understood']))
            if outcome['not_understood']:
                count = len(outcome['not_understood'])
                with ui.expansion(f'{NOT_UNDERSTOOD} ({texts.fmt_count(count)})', value=count <= NOT_UNDERSTOOD_OPEN
                                  ).classes('w-full').props('data-lines-not-understood'):
                    for line in outcome['not_understood']:
                        ui.html(line)
            if outcome['details']:
                with ui.expansion('Latest attempt diagnostics').classes('w-full'):
                    for line in outcome['details']:
                        ui.html(line)

    with ui.element('div').classes('cn-outcome-row cn-outcome-report' + (' cn-ping-outcome' if lookup_type == 'ping' else ' cn-lookup-outcome')):
        with ui.column().classes('cn-outcome-area') as outcome_area:
            banner = outcome_banner.Banner(escaped=lookup_type != 'ping')
            draw_outcome()
        announcement = ui.html('').props('role=status aria-live=polite').classes('cn-sr-only')  # the outcome's voice while the user is in it
        # What this tool's own latest attempt did to the report, when a save was due; the workbook itself is the
        # header's Report menu.
        report_note = ui.label('').props('role=status').classes('cn-muted' + empty_class)
    pending_results = ui.label('').classes('cn-muted' + empty_class)
    results = ui.column().classes('w-full')
    results.props(f'tabindex=-1 role=region data-cn-results aria-label="{ {"ip": "IP", "ping": "Ping"}.get(lookup_type, "Subnet") } results"')  # the header's "Skip to results" lands here

    def data_table(rows, *, name, label, table_id, lead=(), sticky='', labels=None, keep=(), details=False, send=False):
        """A table of the Subnets and IP pages (``tables.cn_table``). Its arrangement (``view.tables[table_id]``) is the
        tab's and outlives a redraw of the panel; a new result starts it again."""
        from . import tables
        columns = tables.columns_of(rows, lead, sticky=sticky, labels=labels, keep=keep)
        action = None
        if details:
            def details_name(row):
                network = row.get('Resolved Subnet') or row.get('Network') or row.get('Original Input(s)')
                return 'View details for ' + ', '.join(str(value) for value in (network, row.get('Network view') or row.get('View')) if value)
            action = tables.RowAction('View details', navigate, name=details_name)
            columns.insert(sum(1 for column in columns if column.key in lead), tables.Column('action', 'Details', 'action'))
        url = table_id == main  # its arrangement is in the URL: changes are written there, and it offers the link
        return tables.cn_table(name=name, label=label, columns=columns, source=tables.RowsSource(rows),
                               state=view.tables.setdefault(table_id, tables.TableState()), send=send, row_action=action,
                               on_change=(lambda _: link.replace()) if url else None, link=url)

    def detail_table(rows, *, name, label, table_id):
        """One section of a network's details: its first column stays in view when it is an address."""
        from . import tables
        first = next((key for key in rows[0] if key not in tables.ROW_KEYS), '') if rows else ''
        return data_table(rows, name=name, label=label, table_id=table_id, send=lookup_inputs.SOURCES['detail'],
                          sticky=first if tables.is_address_field(first) else '')

    def summary_table(rows):
        """The networks of a result: a miss is named by its input, and each network's row opens its details."""
        rows = [dict(row, **{'Resolved Subnet': row.get('Resolved Subnet') or row.get('Original Input(s)') or row.get('Original Input') or ''})
                if 'Resolved Subnet' in row else row for row in rows]
        handle = data_table(rows, name='summary', label='Networks', table_id='summary', lead=('Resolved Subnet', 'Status', 'Network view'),
                            sticky='Resolved Subnet', labels={'Resolved Subnet': 'Network / target'}, details=True, send=True)
        latest['summary_table'] = handle.region.html_id if handle.region is not None else None

    pops = [0]  # the number of the latest Back or Forward: a details step it overtook changes nothing

    async def navigate(identity, *, pushed=True, pop=None):
        client = ui.context.client
        if view.selection is None and latest.get('summary_table'):
            table_id = json.dumps(latest['summary_table'])
            view.summary_scroll = await client.run_javascript(f'[window.scrollY, document.getElementById({table_id})?.scrollLeft || 0, document.getElementById({table_id})?.scrollTop || 0]')
            latest['summary_origin'] = identity
        if not scope.alive or pop is not None and pop != pops[0]:
            return
        view.select(identity)
        await draw_results.refresh()
        if not scope.alive:
            return
        link.push() if pushed else link.replace()  # a network's details are a step Back undoes (R2-08)
        shown = latest.get('displayed_snapshot')
        view_state.set_title(client, lookup_type, detail_title(shown.result if shown else None))
        if identity is not None:
            heading_id = json.dumps(latest.get('detail_heading'))
            client.run_javascript(f'document.getElementById({heading_id})?.focus()')
        if identity is None and latest.get('summary_table'):
            table_id = json.dumps(latest['summary_table'])
            vertical, horizontal, table_vertical = view.summary_scroll
            origin = json.dumps(latest.get('summary_origin'))
            # The panel, and with it the table and its buttons, can be drawn again after this (a poll's refresh).
            # Preserve the requested focus through those mounts, until the user acts.
            client.run_javascript(f'''(() => {{
const root = document.getElementById({json.dumps(results.html_id)});
root?.cnRestoreFocus?.();
if (!root || (document.activeElement !== document.body && !root.contains(document.activeElement))) return;
let target = null;
const stop = () => {{ observer.disconnect(); for (const event of ['pointerdown', 'keydown', 'wheel']) document.removeEventListener(event, stop, true); document.removeEventListener('focusin', moved, true); delete root.cnRestoreFocus; }};
const moved = event => {{ if (event.target !== target) stop(); }};
const restore = () => {{
  const table = document.getElementById({table_id});
  if (!table) {{ stop(); return; }}
  if (target?.isConnected && document.activeElement === target) return;
  if (document.activeElement !== document.body && document.activeElement !== target) {{ stop(); return; }}
  target = [...root.querySelectorAll('[data-row-action], [data-detail-id]')].find(el => (el.dataset.rowAction ?? el.dataset.detailId) === {origin} && el.getClientRects().length);
  target?.focus({{preventScroll:true}});
  window.scrollTo(0, {int(vertical)});
  table.scrollLeft = {int(horizontal)};
  table.scrollTop = {int(table_vertical)};
}};
const observer = new MutationObserver(restore);
root.cnRestoreFocus = stop;
observer.observe(root, {{childList:true, subtree:true}});
for (const event of ['pointerdown', 'keydown', 'wheel']) document.addEventListener(event, stop, {{capture:true, passive:true}});
document.addEventListener('focusin', moved, true);
restore();
}})();''')

    def detail_title(result):
        """The title follows a network's details: "192.0.2.0/24, default" ("All networks"); '' for the rest."""
        groups = (result or {}).get('detail_groups') or []
        if lookup_type != 'subnet' or view.selection is None or len(groups) < 2:
            return ''
        if view.selection == 'all':
            return 'All networks'
        group = next((group for group in groups if group['id'] == view.selection), None)
        return ', '.join(str(value) for value in (group['network'], group.get('network_view')) if value) if group else ''

    def arrive(values, result):
        """Put a view the URL asked for (``values``, None for none) into the tab's state, before the results draw. A
        network that this result does not have, or a view of a result that is not here, is gone: the default view."""
        if values is None:
            return
        groups = (result or {}).get('detail_groups') or []
        net = values.get('net')
        found = net is None or (net == 'all' and len(groups) > 1) or any(group['id'] == net for group in groups)
        state = view.tables.setdefault(main, TableState())
        if result is None or not found:
            if result is not None or net is not None or view_state.table_named(values):
                link.gone()
            view.selection = groups[0]['id'] if len(groups) == 1 else None
            view_state.set_table(state, {})
            return
        if lookup_type == 'subnet':
            view.selection = net if net is not None else (groups[0]['id'] if len(groups) == 1 else None)
        view_state.set_table(state, values)

    async def popped(values):
        """Back, Forward or this tool's own link: the view of that history entry, applied as a click would."""
        if not scope.alive:
            return
        pops[0] += 1
        pop = pops[0]
        shown = latest.get('displayed_snapshot')
        result = shown.result if shown is not None else None
        before = view.selection
        arrive(values, result)
        if lookup_type == 'subnet' and view.selection != before:
            target, view.selection = view.selection, before
            await navigate(target, pushed=False, pop=pop)
            return
        await draw_results.refresh()
        if scope.alive and pop == pops[0]:
            link.replace()
    link.on_pop(popped)

    async def own_link():
        """The navigation's Subnets link: from a network's details back to the summary (as it is arranged); any other
        view stays."""
        shown = latest.get('displayed_snapshot')
        groups = ((shown.result if shown is not None else None) or {}).get('detail_groups') or []
        if lookup_type == 'subnet' and view.selection is not None and len(groups) > 1:
            await navigate(None)
        else:
            link.replace()
    link.on_link(own_link)

    async def toggle_available(event):
        client = ui.context.client
        async with poll_lock:
            if not scope.alive:
                return
            view.show_available = bool(event.value)
            await draw_results.refresh()
            if not scope.alive:
                return
            await restore_result_focus(client, results.html_id, 'data-show-available', 'true')

    def send_available(result, found):
        """Offer the rows and refusals that were drawn, not whatever result has arrived since."""
        ui.download.content(available_download(result, found), UNUSED_FILENAME, 'text/csv')

    def render_available_panel(result, found):
        """The line above the summary or details: how many, what it means, what could not be listed and why, and the download."""
        listed = sum(1 for entry in found['by_group'].values() if not entry['refusal'])
        count = len(found['rows'])
        with ui.element('section').classes('w-full cn-available').props('aria-label="Unused addresses"'):
            text = (f"Unused addresses: {texts.fmt_count(count)} in {texts.plural(listed, 'network')}" if listed
                    else 'Unused addresses: no network could be listed')
            ui.label(text).props('role=status').classes('text-weight-bold')
            ui.label(UNUSED_MEANING).classes('cn-muted')
            help_text = ('Downloads the unused addresses of this result as CSV. It is separate from the '
                         'accumulated report and does not change it.')
            download_available = ui.button('Download available IPs', on_click=lambda: send_available(result, found)).props('outline')
            # What the download is and that it leaves the report alone: text on the page, not a tooltip (M9).
            described = ui.label(help_text).classes('cn-muted text-sm')
            download_available._props['aria-describedby'] = described.html_id
            if not count:
                download_available.disable()
            for refusal in found['refusals']:
                ui.label(refusal_line(refusal)).props('role=status').classes('cn-notice')

    def render_available_table(found):
        """The unused addresses of every listed network, in one paged table (the details of one network hold their own)."""
        rows = found['rows']
        with ui.element('section').props('id=unused-addresses').classes('w-full'):
            with ui.element('h2'):
                ui.label(f'{UNUSED_TITLE} ({len(rows)})')
            lead = tuple(key for key in ('network view', 'network', 'IP address') if key in rows[0])
            data_table(rows, name='unused-addresses', label=f'{UNUSED_TITLE}, all networks', table_id='unused-addresses', lead=lead,
                       sticky='IP address' if 'network view' not in lead else '')

    @ui.refreshable
    def draw_results():
        snapshot = latest.get('displayed_snapshot')
        if snapshot is None or latest.get('partial_active'):
            return  # a Ping that runs shows the hosts probed so far (ping_progress), not an earlier result
        if snapshot.result is None:
            return
        result = snapshot.result
        if earlier_results(snapshot, lookup_type):
            ui.label(EARLIER_RESULTS).classes('text-weight-bold')
        if lookup_type == 'ping':
            from .ping import render_ping_results
            render_ping_results(snapshot, view.tables, on_change=lambda _: link.replace())
            return
        if lookup_type == 'ip':
            from .ip import render_ip_results
            render_ip_results(snapshot, data_table)
            return
        latest['detail_heading_set'] = False
        groups = result.get('detail_groups', [])
        with ui.row().classes('items-center'):
            if view.selection is not None and len(groups) > 1:
                ui.button('Back to summary', on_click=lambda: navigate(None)).props('outline')
            if len(groups) > 1 and view.selection is None:
                show_all = ui.button('Show all details', on_click=lambda: navigate('all'))
                show_all._props['data-detail-id'] = 'all'
            if view.selection is not None:
                view_state.link_button()  # a link to these details (S9)
            listable = bool(groups or result.get('containers'))  # a result of misses and errors has nothing to list
            if listable:
                show_available = ui.checkbox('Show Available', value=view.show_available, on_change=toggle_available)
                show_available._props['data-show-available'] = 'true'
        available = available_result(result, cache=view.available_cache) if listable and view.show_available else None
        if available is not None:
            render_available_panel(result, available)
            if view.selection is None and len(groups) > 1 and available['rows']:
                render_available_table(available)  # the summary has no details to hold it: every listed address, paged
        if not groups:
            ui.label('No matching networks.').classes('text-weight-bold')
        if result.get('containers'):
            with ui.element('nav').props('aria-label="Additional result sections"'):
                ui.link(f"Child containers ({len(result['containers'])})", '#child-containers')
        if view.selection is None and len(groups) > 1:
            with ui.element('h2').props('tabindex=-1') as summary_heading:
                ui.label(texts.plural(len(groups), 'network')).classes('text-h6')
            latest['summary_heading'] = summary_heading.html_id
            summary_table(result.get('summary', []))
        else:
            for group in view.groups(result):
                with ui.column().classes('cn-panel'):
                    with ui.element('h2').props('tabindex=-1').classes('cn-network') as detail_heading:
                        identity = ', '.join(str(value) for value in (group['network'], group.get('network_view')) if value)
                        ui.label(identity)
                    if not latest['detail_heading_set']:
                        latest['detail_heading'] = detail_heading.html_id
                        latest['detail_heading_set'] = True
                    if group.get('network_view'):
                        ui.label('View: ' + str(group['network_view'])).classes('cn-muted')
                    ui.label('Inputs: ' + ', '.join(group.get('original_inputs', [])))
                    for warning in group.get('warnings', []):
                        ui.label(str(warning)).classes('text-negative')
                    sections = list(group.get('tables', {}).items())
                    unused = available['by_group'].get(group['id']) if available is not None else None
                    section_ids = [f'section-{detail_heading.id}-{index}' for index in range(len(sections) + (unused is not None))]
                    with ui.element('nav').classes('w-full') as section_index:
                        section_index._props['aria-label'] = f'Detail sections for {identity}'
                        for (name, rows), section_id in zip(sections, section_ids):
                            ui.link(f'{name} ({len(rows)})', f'#{section_id}').classes('q-mr-md')
                        if unused is not None:
                            count = 'not listed' if unused['refusal'] else len(unused['rows'])
                            ui.link(f'{UNUSED_TITLE} ({count})', f'#{section_ids[-1]}').classes('q-mr-md')
                    for (name, rows), section_id in zip(sections, section_ids):
                        with ui.element('section').props(f'id={section_id}').classes('w-full'):
                            if not rows:  # an empty section stays closed
                                with ui.expansion(f'{name} (0)').classes('w-full'):
                                    ui.label('No rows.').classes('cn-muted')
                                continue
                            with ui.element('h3'):
                                ui.label(f'{name} ({len(rows)})')
                            if name == 'general' and len(rows) == 1:
                                from .tables import cn_definition_list
                                cn_definition_list(rows[0], label=f'{name}, {identity}')  # one network's facts: no table
                            else:
                                detail_table(rows, name=table_name('detail', group['network'], group.get('network_view'), name), label=f'{name}, {identity}',
                                             table_id=(group['id'], name))
                    if unused is not None:
                        with ui.element('section').props(f'id={section_ids[-1]}').classes('w-full'):
                            with ui.element('h3'):
                                ui.label(UNUSED_TITLE if unused['refusal'] else f"{UNUSED_TITLE} ({len(unused['rows'])})")
                            if unused['refusal']:
                                ui.label(f"Not listed: {unused['refusal']}.")
                            elif unused['rows']:
                                detail_table(unused['rows'], name=table_name('detail', group['network'], group.get('network_view'), UNUSED_TITLE),
                                             label=f'{UNUSED_TITLE}, {identity}', table_id=(group['id'], UNUSED_TITLE))
                            else:
                                ui.label('No unused addresses.')
        if result.get('containers'):
            containers = result['containers']
            with ui.element('section').props('id=child-containers').classes('w-full'):
                with ui.element('h2'):
                    ui.label(f'Child containers ({len(containers)})')
                data_table(containers, name='containers', label='Child containers', table_id='containers')

    with results:
        partial = None
        if lookup_type == 'ping':
            from .ping_progress import PingProgress
            partial = PingProgress(controller, view.tables, results)  # the bar and the hosts probed so far
        draw_results()

    def credential_fallback():
        # Focus after the dialog when the element that had it is gone or disabled: Retry setup, else Run (a lookup that
        # ends with nothing to show gives the form back, open, with Run).
        return [f'#{retry.html_id}', f'#{run.html_id}']

    def store_state():
        snapshot = latest['snapshot']
        return (snapshot.credential_store or {}) if snapshot else {}

    # The sign-in dialog: opened for the worker's request, kept open while Infoblox checks the password and when a
    # refused one is asked for again, closed when the request is gone (sign_in.SignInFlow).
    sign_in = SignInFlow(controller, fallback=credential_fallback, store=store_state, client=ui.context.client,
                         restored=lambda: getattr(latest['snapshot'], 'saved_login_restored', False),
                         after_reply=lambda: refresh_now(),
                         active_job=lambda: controller.page_snapshot(lookup_type).state.active_job_id)
    scope.on_leave(sign_in.leave)  # the tool is left: its dialog goes (sign_in.SignInFlow.leave says what the request does)

    async def poll_once():
        # Also awaited by a click (submit, Run again, Retry, Sign in again): scope.alive at the start and after every
        # await, so a poll that resumes after the tool was left draws, asks and reads nothing more.
        if not scope.alive:
            return
        page = controller.page_snapshot(lookup_type, result_revision=latest.get('result_revision'),
                                        attempt_revision=latest.get('attempt_revision'))
        deleting = page.state.report_delete_pending
        if page.result_changed:
            latest['received_result'] = page.result
            latest['result_revision'] = page.result_revision
        if page.attempt_changed:
            latest['received_outcome'] = page.outcome
            latest['received_attempt_result'] = page.attempt_result
            latest['attempt_revision'] = page.attempt_revision
        attempt = {'result': latest.get('received_attempt_result')}
        snapshot = replace(page.state, result=latest.get('received_result'), result_job_id=page.result_job_id,
                           latest_attempt_id=page.attempt_job_id, latest_outcome=latest.get('received_outcome'),
                           latest_report_state=page.attempt_report_state)
        latest['snapshot'] = snapshot
        if lookup_type != 'ping':
            line = scope_line(snapshot.scope, snapshot.username)
            if scope_label.text != line:
                scope_label.set_text(line)
        report_warning.set_text(snapshot.report_warning)
        # Off while the setup card stands in for the form: Run is hidden then, and Ctrl+Enter asks Run (run_from_keyboard).
        run.set_enabled(not deleting and snapshot.phase == 'ready' and not snapshot.active_job_id
                        and bool((targets.value or '').strip()) and not needs_endpoint(snapshot, lookup_type))
        forget.set_enabled(snapshot.phase not in {'closing', 'closed', 'failed'})
        storage = snapshot.credential_store or {}
        store_status.set_text(storage.get('message', ''))
        saved = dialogs.saved_login(storage, snapshot.saved_login_restored)
        forget.set_visibility(saved)
        shown = snapshot.result or {}
        show_results.set_visibility(bool(shown.get('rows') or shown.get('detail_groups')))
        fold.set_summary(form_summary(targets.value or '', ports=(ports.value or '') if ports is not None else '', tool=lookup_type))
        # Folded only beside something to look at: rows, networks or containers, the hosts probed so far, or its own job.
        own_job = bool(snapshot.active_job_id) and snapshot.active_lookup_type == lookup_type
        fold.show(bool(shown.get('rows') or shown.get('detail_groups') or shown.get('containers'))
                  or bool(partial is not None and latest.get('partial_active')) or own_job,
                  running=own_job, attempt=page.attempt_job_id)
        recovery.set_visibility(saved and snapshot.saved_login_restored)
        sign_in.refresh()
        # The status line, Stop, the banner of another tool's job and the end of the session. While the setup card
        # or the Setup required block shows, it carries the reason and the status line only names the state.
        shell.update(snapshot, own=setup.update(snapshot))
        note = texts.attempt_report_note(page.attempt_report_state, page.state.report_state)
        if report_note.text != note:
            report_note.set_text(note)
        await sign_in.follow()
        if not scope.alive:
            return
        async def focused_inside(container):
            client = ui.context.client
            if not client.has_socket_connection:
                return False
            try:
                return await client.run_javascript(f'''(() => {{
const active = document.activeElement;
const interactive = 'input, textarea, select, button, a[href], [contenteditable]:not([contenteditable="false"]), [tabindex]:not([tabindex="-1"]), [role="button"]';
return !!(active?.closest(interactive) && document.getElementById({json.dumps(container.html_id)})?.contains(active));
}})()''', timeout=1)
            except TimeoutError:
                return False

        outcome_fingerprint = page.attempt_revision
        if outcome_fingerprint != latest.get('outcome_fingerprint'):
            focused = latest.get('outcome_fingerprint') is not None and await focused_inside(outcome_area)
            if not scope.alive:
                return
            if focused:
                if outcome_fingerprint != latest.get('announced_outcome'):
                    if lookup_type == 'ping':
                        from .ping import ping_outcome_display
                        display_outcome = ping_outcome_display(snapshot, attempt, format_entries=False)
                    else:
                        display_outcome = outcome_display(snapshot, lookup_type)
                    if display_outcome:
                        announced = display_outcome['title']
                        announcement.set_content(escape(announced) if lookup_type == 'ping' else announced)
                    else:
                        announcement.set_content('')
                    latest['announced_outcome'] = outcome_fingerprint
            else:
                latest['outcome_fingerprint'] = outcome_fingerprint
                announcement.set_content('')
                if lookup_type == 'ping':
                    latest['displayed_outcome_snapshot'] = snapshot
                    latest['displayed_outcome_result'] = latest.get('received_attempt_result')
                    latest['diagnostic_pages'] = {}
                    latest['diagnostic_expanded'] = {}
                await draw_outcome.refresh()
                if not scope.alive:
                    return
                if not latest.get('polled'):
                    # An outcome there when the page loaded is not news: focus stays where the load left it, so the
                    # first Tab starts at the top of the page, not at a heading in the middle.
                    if snapshot.latest_outcome:
                        latest['focused_attempt'] = snapshot.latest_attempt_id
                elif snapshot.latest_outcome and snapshot.latest_attempt_id != latest.get('focused_attempt'):
                    latest['focused_attempt'] = snapshot.latest_attempt_id
                    heading_id = json.dumps(latest.get('outcome_heading'))
                    ui.run_javascript(f'''(() => {{
const active = document.activeElement;
const interactive = 'input, textarea, select, button, a[href], [contenteditable]:not([contenteditable="false"]), [tabindex]:not([tabindex="-1"]), [role="button"]';
// The form opened by itself and Run takes the focus at the next frame (results_first._FOCUS_RUN): that wins.
if (window.cnFoldFocusing) return;
// Run put the focus on the folded form's Edit: the outcome the user waits for takes it from there, unless Edit was
// pressed since (the form is on its way, and its first box takes the focus).
if (!active?.closest(interactive) || active.matches('[data-form-edit]:not([data-form-edit-asked])')) document.getElementById({heading_id})?.focus();
}})()''')
        partial_active = await partial.follow(snapshot) if partial is not None else False
        if not scope.alive:
            return
        results_fingerprint = (page.result_revision, earlier_results(snapshot, lookup_type), partial_active)
        if results_fingerprint != latest.get('results_fingerprint'):
            # The hosts probed so far replace the earlier result at once, whatever has the focus (owner decision):
            # both on screen would show two answers; the focus that was in the removed table moves to the progress.
            arriving = partial_active and not latest.get('partial_active')
            focused = latest.get('results_fingerprint') is not None and not arriving and await focused_inside(results)
            if not scope.alive:
                return
            if focused:
                pending_results.set_text('New results are available. Move focus away from the current results to update them.')
            else:
                if arriving:
                    await partial.take_focus()
                    if not scope.alive:
                        return
                latest['results_fingerprint'] = results_fingerprint
                pending_results.set_text('')
                latest['displayed_snapshot'] = snapshot
                latest['partial_active'] = partial_active
                if snapshot.result is not None:
                    view.attach(snapshot.result, snapshot.result_job_id)
                arrive(link.take(), snapshot.result)  # the URL's view, once, when there is a result to put it on
                await draw_results.refresh()
                if not scope.alive:
                    return
                link.replace()
                view_state.set_title(ui.context.client, lookup_type, detail_title(snapshot.result))
        latest['polled'] = True  # from here on an outcome that arrives is news

    async def refresh_now():
        async with poll_lock:
            await poll_once()

    async def poll():
        if poll_lock.locked():
            return
        await refresh_now()

    targets.disable()
    targets.on_value_change(lambda _: poll())
    async def restore_draft(again=False):
        # ``again``: a try after one that had no answer in time. The box is enabled and its listener sent, so the script
        # that writes the box goes at once: it does its work when it arrives, answered in time or not (a slow server never
        # answered the question first in five seconds, and the box stayed empty: test_webui_send_targets_slow_restore_browser).
        client = ui.context.client
        if client.is_deleted or not scope.alive:
            return
        element_id = json.dumps(targets.html_id)
        key = json.dumps('cn-tool-draft-' + lookup_type)
        keys = lookup_inputs.draft_keys(lookup_type)
        fresh = lookup_inputs.request_form(controller.last_request(lookup_type), lookup_type) or ('', '')
        install = f'''const root = document.getElementById({element_id});
const input = root?.matches('textarea') ? root : root?.querySelector('textarea');
if (!input) return false;
{preview.guard_js()}
if (!input.cnDraftListener) {{
    input.cnDraftListener = true;
    input.addEventListener('input', () => {{
        input.cnDraftEdited = true;
        sessionStorage.setItem({key}, input.value);
    }});
}}'''
        try:
            await asyncio.wait_for(client.connected(), timeout=5)
            if not again:
                installed = await client.run_javascript(f'(() => {{{install}\nreturn true;}})()', timeout=5)
                if not scope.alive:
                    return
                if not installed:
                    raise TimeoutError
                targets.enable()
            restored = await client.run_javascript(f'''(() => {{
{install}
{lookup_inputs.keep_typed(key)}
if (!input.cnDraftEdited) {{
    input.value = sessionStorage.getItem({key}) ?? {lookup_inputs.new_tab_value(keys, fresh[0])};
    input.dispatchEvent(new Event('input', {{bubbles: true}}));
}}
return true;
}})()''', timeout=5)
            if not scope.alive:
                return
            if restored:
                targets.enable()
                await lookup_inputs.show_handoff(ui.context.client, lookup_type, handoff_note, run, [f for f in (targets, ports) if f],
                                                 opened=lambda: fold.edit(focus=False))
                return
        except TimeoutError:
            pass
        if not client.is_deleted and scope.alive:
            # Allow edits while waiting for reconnect; install the listener first so
            # a later restore cannot overwrite a value entered during recovery.
            client.run_javascript(f'(() => {{{install}}})()')
            await asyncio.sleep(0)
            targets.enable()
            scope.timer(1, lambda: restore_draft(again=True), once=True)
    scope.timer(0, restore_draft, once=True)
    if ports is not None:
        ports.disable()
        async def restore_ports(again=False):  # ``again``: as restore_draft's
            client = ui.context.client
            if client.is_deleted or not scope.alive:
                return
            element_id = json.dumps(ports.html_id)
            fresh = (lookup_inputs.request_form(controller.last_request(lookup_type), lookup_type) or ('', ''))[1]
            install = f'''const root = document.getElementById({element_id});
const input = root?.matches('input') ? root : root?.querySelector('input');
if (!input) return false;
if (!input.cnDraftListener) {{
    input.cnDraftListener = true;
    input.addEventListener('input', () => {{
        input.cnDraftEdited = true;
        sessionStorage.setItem('cn-tool-draft-ping-ports', input.value);
    }});
}}'''
            try:
                await asyncio.wait_for(client.connected(), timeout=5)
                if not again:
                    installed = await client.run_javascript(f'(() => {{{install}\nreturn true;}})()', timeout=5)
                    if not scope.alive:
                        return
                    if not installed:
                        raise TimeoutError
                    ports.enable()
                restored = await client.run_javascript(f'''(() => {{
{install}
{lookup_inputs.keep_typed("'cn-tool-draft-ping-ports'")}
if (!input.cnDraftEdited) {{
    input.value = sessionStorage.getItem('cn-tool-draft-ping-ports') ?? {lookup_inputs.new_tab_value(lookup_inputs.draft_keys(lookup_type), fresh)};
    input.dispatchEvent(new Event('input', {{bubbles: true}}));
}}
return true;
}})()''', timeout=5)
                if not scope.alive:
                    return
                if restored:
                    ports.enable()
                    return
            except TimeoutError:
                pass
            if not client.is_deleted and scope.alive:
                client.run_javascript(f'(() => {{{install}}})()')
                await asyncio.sleep(0)
                ports.enable()
                scope.timer(1, lambda: restore_ports(again=True), once=True)
        scope.timer(0, restore_ports, once=True)
    scope.timer(0, poll, once=True)
    scope.timer(.25, poll)
