"""The shell every web page draws: its name, the navigation, the running job, Quit and Help.

A page never draws its own navigation or Quit button: it calls ``render_shell(controller, key)`` where its title row
and navigation used to be, and builds the rest of its content below. The pages, their routes and their ``<title>``
are the one table ``PAGES`` (``app.py`` registers a route from each row). NiceGUI is imported inside the functions.

The shell also says what runs (``PageShell.update``, called from the page's poll with the session's snapshot): a pill
in the header while any job runs, a banner on every page that does not own the job, a toast when that job ends, and
the page's own status line (the sentences are ``texts.py``'s). Quit asks first when something would be lost
(``PageShell.request_quit``), and once the application has quit the page is one card that says so, in every tab.

The Report menu (``report_actions.ReportMenu``) sits in the header of every page and is updated here too: no page
draws a report button. Help ("?", always drawn, in the same place) lists the page's lines, the keys, what Stop and Quit
do and where the report lives; the skip link is the first thing the page draws (both are ``keys.py``'s). Plan:
``docs/plans/webui-ux-plan.md`` section 3.3.
"""
import json
from dataclasses import dataclass
from weakref import WeakKeyDictionary

from . import job_indicator, keys
from .keys import GO_LETTERS, SWITCH_LABEL

TITLE_SUFFIX = 'cn-tool'


@dataclass(frozen=True)
class Page:
    key: str
    route: str
    label: str  # the link text and the page's h1
    title: str  # the document title


def _page(key, route, label):
    return Page(key, route, label, f'{label} – {TITLE_SUFFIX}')


PAGES = (
    _page('subnet', '/', 'Subnets'),
    _page('ip', '/ip', 'IP'),
    _page('ping', '/ping', 'Ping'),
    _page('monitor', '/monitor', 'Monitor'),
    _page('config_search', '/config-search', 'Configuration Search'),
    _page('demob', '/demobilization', 'Site Demobilization'),
    _page('settings', '/settings', 'Settings'),
)
_BY_KEY = {page.key: page for page in PAGES}
NOT_FOUND = Page('', '', 'Page not found', f'Page not found – {TITLE_SUFFIX}')  # an in-app link to no tool


def page_of(path):
    """The page of ``path`` (a route, with or without a query or a fragment), or None."""
    route = (path or '/').split('?', 1)[0].split('#', 1)[0] or '/'
    if len(route) > 1 and route.endswith('/'):
        route = route[:-1]  # the router matches '/ip/' as '/ip' (SubPages strips a trailing slash)
    return next((page for page in PAGES if page.route == route), None)


# The shell of each tab: {NiceGUI client: its PageShell}. Under the root (router.py) a tool gets the root's shell back
# from render_shell instead of drawing a second one.
_SHELLS = WeakKeyDictionary()


def bind_client(shell, client):
    """Make ``shell`` the tab's shell until the client is deleted. The shell holds its client, so a weak key would never
    let the pair go: the entries are dropped when the client is."""
    shell._client = client
    _SHELLS[client] = shell
    client.on_delete(lambda: (_SHELLS.pop(client, None), _UNSAVED.get(shell.controller, {}).pop(client, None)))


def page_shell(client):
    """The shell drawn in the tab of ``client``, or None."""
    return _SHELLS.get(client)

# The pages that can hold unsaved changes (Settings), per session: {controller: {NiceGUI client: its check}}. Quit
# from any tab asks all of them, so it names unsaved settings that another tab holds.
_UNSAVED = WeakKeyDictionary()


def unsaved_changes(controller):
    """Whether a tab of this session that is still connected holds unsaved changes. A tab leaves the count when it
    saves or reverts (its check says so) and when it disconnects."""
    return any(client.has_socket_connection and check() for client, check in list(_UNSAVED.get(controller, {}).items()))

CLOSED_TITLE = 'cn-tool has quit'
CLOSED_ADVICE = 'You can close this tab. To start again, run cn-web or use the cn-tool Web shortcut.'
FAILED_TITLE = 'cn-tool stopped unexpectedly'
# A session that failed is still running until Quit: a second start would reopen it, so the advice begins with Quit.
FAILED_ADVICE = 'Select Quit application, then start again: run cn-web or use the cn-tool Web shortcut.'

# The colours are the theme's custom properties. Once the body carries data-cn-closed, everything a page drew is hidden
# and only the card of that kind shows; NiceGUI's "connection lost" popup is hidden from the moment the application
# is closing, so a tab that loses its server after Quit never offers to reconnect.
CSS = '''
.cn-help-section h3 { font-size:var(--cn-text-body); font-weight:600; }
.cn-job-notice { display:flex; flex-wrap:wrap; align-items:center; gap:4px 12px; }
.cn-job-notice a { font-weight:600; }
@media (max-width: 599px) { .cn-shell-tools { width:100%; } }
a.cn-job-pill { display:inline-flex; align-items:center; gap:0 6px; height:32px; max-width:100%; padding:2px 12px; border-radius:16px;
  border:1px solid var(--cn-attention-line); background:var(--cn-attention-bg); color:var(--cn-attention-ink);
  text-decoration:none; font-weight:600; min-width:0; white-space:nowrap; overflow:hidden; }
a.cn-job-pill > * { flex:none; }
a.cn-job-pill > .cn-pill-text { flex:0 1 auto; min-width:3.5rem; overflow:hidden; text-overflow:ellipsis; }
a.cn-job-pill .cn-clock:not(:empty)::before { content:'·'; margin-right:6px; }
.cn-pill-prefix { position:absolute; width:1px; height:1px; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; }
.cn-clock { font-variant-numeric:tabular-nums; }
.cn-clock:empty { display:none; }
.cn-elapsed:not(:empty)::before { content:'Elapsed: '; }
.cn-closed-card { display:none; max-width:640px; }
.cn-closed-card h1 { margin-top:0; }
.cn-closed-card h1:focus, .cn-page-title:focus { outline:none; }
body[data-cn-closed] .nicegui-content > :not(.cn-closed-card):not(footer) { display:none !important; }
body[data-cn-closed=quit] .cn-closed-card[data-kind=quit], body[data-cn-closed=failed] .cn-closed-card[data-kind=failed] { display:block; }
body[data-cn-closing] #popup, body[data-cn-closed] #popup { display:none !important; }
body[data-cn-closed] .q-dialog, body[data-cn-closed] .q-menu, body[data-cn-closed] .q-tooltip, body[data-cn-closed] .q-notifications { display:none !important; }
'''

# One script for every page. The clocks: an element with data-cn-since shows the time since that moment (seconds since
# the epoch), one with data-cn-until the time left to it, and both tick here, in the browser, so a running job pushes
# nothing from the server to keep its clock. A clock (data-cn-clock) whose moment is taken away shows nothing: the
# text is the browser's, so the browser clears it. The forms are texts.fmt_duration's ('59 s', '4 min 20 s', '1 h 1 min');
# data-cn-coarse drops the seconds ('under 1 min', '5 min'). The end: closing(true) marks the tab once the
# application is closing, and a marked tab that loses its socket shows the card instead of NiceGUI's reconnect popup;
# closed(kind) shows the card of that kind ('quit', 'failed'), whose heading is then the page's h1 and its title, and
# closed('') takes it away again. A tab that only lost its socket while the application was closing, and gets it
# back (the application is still saving), takes the card away too: the server says when it has really quit.
CLOCK_SCRIPT = '''<script>
(() => {
  if (window.cnShell) return;
  const span = (seconds, coarse) => {
    seconds = Math.max(0, Math.round(seconds));
    const d = Math.floor(seconds / 86400), h = Math.floor(seconds % 86400 / 3600);
    const m = Math.floor(seconds % 3600 / 60), s = seconds % 60;
    if (d) return d + ' d' + (h ? ' ' + h + ' h' : '');
    if (h) return h + ' h' + (m ? ' ' + m + ' min' : '');
    if (coarse) return m ? m + ' min' : 'under 1 min';
    return m ? m + ' min' + (s ? ' ' + s + ' s' : '') : s + ' s';
  };
  const tick = () => {
    const now = Date.now() / 1000;
    for (const item of document.querySelectorAll('[data-cn-clock]')) {
      const since = item.dataset.cnSince, moment = Number(since ?? item.dataset.cnUntil ?? 0);
      const text = moment > 0 ? span(since !== undefined ? now - moment : moment - now, item.dataset.cnCoarse !== undefined) : '';
      if (item.textContent !== text) item.textContent = text;
    }
  };
  let title = null;
  const closed = (kind) => {
    if (!kind) {
      delete document.body.dataset.cnClosed;
      if (title !== null) { document.title = title; title = null; }
      return;
    }
    if (document.body.dataset.cnClosed === kind) return;
    document.body.dataset.cnClosed = kind;
    const heading = document.querySelector('.cn-closed-card[data-kind="' + kind + '"] h1');
    if (title === null) title = document.title;
    if (heading) document.title = heading.textContent.trim();
    heading?.focus();
  };
  let hooked = false, lost = false;
  const closing = (on) => {
    window.cnClosing = Boolean(on);
    if (!on) { delete document.body.dataset.cnClosing; return; }
    document.body.dataset.cnClosing = '';
    if (hooked || !window.socket) return;
    hooked = true;
    window.socket.on('disconnect', () => {
      if (window.cnClosing && !document.body.dataset.cnClosed) { lost = true; closed('quit'); }
    });
    window.socket.on('connect', () => { if (lost) { lost = false; closed(''); } });
  };
  // The way to another tool: a full load here; the root's router script (router.py) replaces go and guard, so that
  // a tool of the root opens without a load and a tool with unsaved changes is asked about first.
  const go = (route) => location.assign(route);
  window.cnShell = {tick, closed, closing, go, guard: () => {}};
  const start = () => {
    tick();
    setInterval(tick, 1000);
    new MutationObserver(tick).observe(document.body, {subtree: true, childList: true, attributes: true,
                                                         attributeFilter: ['data-cn-since', 'data-cn-until']});
  };
  if (document.body) start(); else document.addEventListener('DOMContentLoaded', start);
})();
</script>'''


def _clock(attribute, epoch, coarse):
    from nicegui import ui

    element = ui.element('span').classes('cn-clock')
    element._props['data-cn-clock'] = attribute
    if coarse:
        element._props['data-cn-coarse'] = ''
    set_clock(element, epoch)
    return element


def since(epoch=None, *, coarse=False):
    """An element that shows the time since ``epoch`` (seconds since the epoch) and ticks in the browser.

    It shows nothing while it has no moment; ``set_clock`` gives it one later. ``coarse`` drops the seconds."""
    return _clock('data-cn-since', epoch, coarse)


def until(epoch=None, *, coarse=False):
    """An element that counts down to ``epoch`` in the browser; see ``since``."""
    return _clock('data-cn-until', epoch, coarse)


def set_clock(element, epoch):
    """Point a ``since`` or ``until`` element at another moment, or at none (None or 0: it shows nothing)."""
    attribute = element._props['data-cn-clock']
    value = repr(float(epoch)) if epoch else None
    if element._props.get(attribute) == value:
        return
    if value is None:
        element._props.pop(attribute, None)
    else:
        element._props[attribute] = value
    element.update()


class PageShell:
    """What a page keeps of its shell: the Quit button, the status line it adopts, the help lines and the job.

    Under the root (router.py) one shell serves every tool of the tab: ``set_active`` hands it to the tool that is
    being built, which adopts the status line, Stop, the clock, the waiting controls and the help lines again."""

    def __init__(self, controller, active):
        self.controller = controller
        self.active = active
        self.root = False  # drawn once for the tab by the root page, not by one tool's page
        self._title = None  # the h1's label
        self._links = {}  # the navigation: {page key: its link}
        self._failed_settings = None  # the failed card's link to Settings (not on Settings)
        self._polled = False  # the tool polls on its own and owns the status line
        self.quit_button = None
        self.status = None  # the page's status line: the page creates it and sets it here
        self.elapsed = None  # the since() element beside the status line (add_elapsed)
        self._stop = None  # the page's Stop button (add_stop)
        self._help_button = None
        self._help_content = None
        self._help_lines = ()
        self._help_switch = None
        self._single_keys = True  # the tab's own choice: the click that opens Help says it (_open_help)
        self._client = None
        self._state = None  # the snapshot of the latest update
        self._asking = False  # the Quit confirmation is open
        self._waiting = []  # the controls that cannot start while another job runs: the banner describes them
        self._size = {}  # job id -> hosts: the size of a running Ping or Monitor, kept between its rounds
        self._foreign = {}  # slot -> the job of another tool seen there at the latest update (R3-03: two slots)
        self._notice = None
        self._indicator = None  # the header's job_indicator.JobIndicator
        self._closing = False
        self._closed = ''
        self._banner = self._banner_text = self._banner_link = None
        self._watchers = []  # functions the page gave (watch): called with every snapshot, for what only it shows
        self._failed_reason = None
        self._revisions = (None, None)
        self.report = None  # the header's ReportMenu (render_shell)

    @property
    def banner_id(self):
        """The id of the job banner, for ``aria-describedby``."""
        return self._banner.html_id

    def waits(self, control):
        """``control`` (a Run button) cannot start while another tool's job runs: while the banner shows, it is the
        control's description, so that a disabled button says why."""
        self._waiting.append(control)
        return control

    def add_elapsed(self):
        """Draw, where the page calls it (beside its status line), how long the page's own job has run: a ``since``
        element, so it ticks in the browser."""
        self.elapsed = since().classes('cn-elapsed cn-muted')
        return self.elapsed

    def add_stop(self):
        """Draw the page's Stop button where the page calls it. It is shown only while the page's own job runs
        (``update``), so no page offers to stop another tool's job."""
        from nicegui import ui
        from . import texts

        self._stop = ui.button(texts.STOP_LABELS[self.active], on_click=self.stop_own).props('outline')
        self._stop.set_visibility(False)
        return self._stop

    def stop_own(self):
        """End this page's own job: the one its latest poll saw, and only while it is still the running job of this
        page's tool. A click can therefore never end another tool's job, nor a job that began after that poll."""
        from .job_slots import own_view

        from .job_slots import stoppable

        seen = own_view(self._state, self.active)
        if seen is None or not _owns(seen, self.active) or not stoppable(seen):
            return
        now = own_view(self.controller.page_snapshot(self.active).state, self.active)
        if now.active_job_id == seen.active_job_id and _owns(now, self.active) and stoppable(now):
            self.controller.cancel(seen.active_job_id)

    def watch(self, watcher):
        """Call ``watcher(state)`` with every snapshot the shell reads, until the tool is left (``set_active``): for what
        a page shows that follows the session's work (Settings' reason that Use the new settings now waits)."""
        self._watchers.append(watcher)

    def set_unsaved(self, check):
        """``check()`` says whether the page holds unsaved changes (Settings): Quit then asks about them too, from
        this tab and from every other tab of the session (``unsaved_changes``), until this tab is gone (``bind_client`` drops it) or the check is
        taken back (``set_unsaved(None)``: the tool was left)."""
        client = self._client
        registry = _UNSAVED.setdefault(self.controller, {})
        if check is None:
            registry.pop(client, None)
            return
        registry[client] = check

    def set_active(self, key):
        """Hand the shell to the page of ``key`` (None: an in-app link that names no tool): the h1, the document title,
        ``aria-current`` in the navigation and the failed card follow it, and the parts a page owns (the status line,
        Stop, the clock, the waiting controls, the unsaved check, the help lines) are given back, for the page that is
        being built to adopt again. A tool's ``render_shell`` call gets the root's shell back, so it runs once for every tool opened."""
        page = _BY_KEY.get(key, NOT_FOUND)
        self.active = key
        self.status = self.elapsed = self._stop = None
        self._waiting = []
        self._polled = False
        self._foreign = {}  # a job the left page called another tool's may be this page's own
        self._notice = False  # not a notice: the next update draws the banner for this page
        self.set_unsaved(None)
        if self._title.text != page.label:
            self._title.set_text(page.label)
        if self._client.title != page.title:
            self._client.title = page.title
            if self._client.has_socket_connection:
                self._client.run_javascript(f'document.title = {json.dumps(page.title)}')
        for link_key, link in self._links.items():
            current = link.props.get('aria-current')
            if link_key == key and current != 'page':
                link.props['aria-current'] = 'page'
                link.update()
            elif link_key != key and current is not None:
                link.props.pop('aria-current', None)
                link.update()
        self._failed_settings.set_visibility(key != 'settings')
        self._watchers = []
        self._help_lines = ()
        self._draw_help()

    def set_help(self, lines):
        """Give Help the page's own lines (the first section of its dialog); no lines leaves the common sections."""
        self._help_lines = [str(line) for line in lines]
        self._draw_help()

    def _draw_help(self):
        from nicegui import ui
        from .keys import help_lines

        self._help_content.clear()
        with self._help_content:
            for heading, lines in help_lines(self._help_lines, PAGES).items():
                if not lines:
                    continue
                with ui.element('section').classes('gap-1 cn-help-section').props(f'aria-label="{heading}"'):
                    with ui.element('h3').classes('text-subtitle1 q-my-none'):
                        ui.label(heading)
                    for line in lines:
                        ui.label(line)
                if heading == 'Keyboard':
                    self._help_switch = ui.switch(SWITCH_LABEL, value=self._single_keys,
                                                  on_change=self._set_single_keys)

    def _set_single_keys(self, event):
        self._single_keys = bool(event.value)
        self._client.run_javascript(f"window.cnKeys?.set({'true' if self._single_keys else 'false'});")

    def _hosts(self, state):
        """The size of the running Ping or Monitor: the snapshot's while it probes, else the one seen before."""
        from . import texts

        size = texts.job_size(state)
        if state is None or not state.active_job_id:
            return None
        if size:
            self._size[state.active_job_id] = size
        return self._size.get(state.active_job_id)

    def _read(self):
        """The session as it is now. A page snapshot carries it without the tools' results; naming the revisions
        this shell has seen keeps the one tool's result from being copied again."""
        page = self.controller.page_snapshot('subnet', result_revision=self._revisions[0],
                                             attempt_revision=self._revisions[1])
        self._revisions = (page.result_revision, page.attempt_revision)
        return page.state

    def follow(self):
        """The poll of a page that has none of its own (Settings), and the root's own poll:
        read the session and update the shell. The status line is left to a page that polls on its own."""
        self.update(self._read(), _page=False)

    def update(self, state, *, own=None, _page=True):
        """Called from the page's poll with the session's snapshot.

        ``own`` replaces the status line's text (``texts.own_status`` by default). Everything else follows from the
        snapshot: Quit is off once the application is closing, the pill, the banner and its description of the
        waiting controls, the toast for a job that ended elsewhere, and the closed card. An element is touched only
        when what it shows changes, so an idle page sends nothing."""
        from . import texts
        from .job_slots import monitor_view, own_view, stoppable

        self._state = state
        self._polled = self._polled or _page
        phase = state.phase
        self.quit_button.set_enabled(phase not in {'closing', 'closed'})
        # The page's own slot as the one job (R3-03): the Monitor's page reads the monitor slot, every other page the
        # one-shot slot, so its status line, Stop, clock and banner are about the slot its Run starts.
        view = own_view(state, self.active)
        if self.status is not None and (_page or not self._polled):
            text = texts.own_status(view, page=self.active) if own is None else own
            if self.status.text != text:
                self.status.set_text(text)
        mine = bool(view.active_job_id) and view.phase in {'running', 'stopping', 'saving'} and _owns(view, self.active)
        if self._stop is not None:
            self._stop.set_visibility(mine)
            self._stop.set_enabled(mine and stoppable(view))
        if self.elapsed is not None:
            set_clock(self.elapsed, view.active_started_at if mine else None)
        monitor = monitor_view(state)
        self._size = {job: known for job, known in self._size.items()  # an ended job's size is forgotten
                      if job in (state.active_job_id, state.monitor_job_id)}
        hosts = self._hosts(view)
        self._hosts(monitor if view is state else state)  # the other slot's size is kept too (Quit names it)
        # A Monitor makes no page wait (5.7): the banner is the one-shot job's, on a one-shot page.
        self._show_notice(self._failed_notice(state) or texts.job_notice(view, page=self.active, hosts=hosts))
        # The indicator lists both jobs, each with its own clock and its own Stop… (R3-04).
        live = {'running', 'stopping', 'saving'}
        self._indicator.update(
            {'oneshot': state, 'monitor': monitor}, self.active,
            {name: view.active_started_at if view.active_job_id and view.phase in live else None
             for name, view in (('oneshot', state), ('monitor', monitor))})
        self._toast(state, monitor)
        self._show_end(state)
        self.report.update(state)
        for watcher in list(self._watchers):
            watcher(state)

    def _failed_notice(self, state):
        """Settings stays usable in a failed session (it edits a file), so it gets a notice where the tools get the
        card."""
        from . import texts

        if state.phase != 'failed' or self.active != 'settings':
            return None
        return texts.JobNotice(texts.sentence(FAILED_TITLE, _reason(state), FAILED_ADVICE), '', '')

    def _show_notice(self, notice):
        if notice == self._notice:
            return
        self._notice = notice
        self._banner_text.set_text(notice.text if notice else '')
        self._banner_link.set_text(notice.link_label if notice else '')
        self._banner_link._props['href'] = notice.route if notice and notice.route else '/'
        self._banner_link.update()
        self._banner_link.set_visibility(bool(notice and notice.route))
        self._banner.set_visibility(notice is not None)
        for control in self._waiting:
            if notice is not None:
                control._props['aria-describedby'] = self.banner_id
            else:
                control._props.pop('aria-describedby', None)
            control.update()

    def _toast(self, state, monitor):
        """Say once that the job of another tool has ended, for each slot (``state`` is the one-shot slot's view,
        ``monitor`` the Monitor's); not while the application itself is ending."""
        from nicegui import ui
        from . import texts

        ending = state.phase in {'closing', 'closed', 'failed'}
        for slot, view in (('oneshot', state), ('monitor', monitor)):
            running = view.active_job_id is not None and view.active_lookup_type in texts.TOOL_NAMES and not ending
            job = view.active_job_id if running and view.active_lookup_type != self.active else None
            before = self._foreign.get(slot)
            if before is not None and before['job'] != job and not ending:
                with self._client:
                    ui.notify(texts.job_ended_notice(before['tool'], hosts=before['hosts'],
                                                     stopped=self._ended_stopped(before)))
            if job is None:
                self._foreign.pop(slot, None)
            else:
                same = before is not None and before['job'] == job
                # "Stopped" only for a job that was stopped before it began to save: a Stop that reaches a job inside the
                # report gate is ignored by the worker, and its lookup is complete and saved.
                saved = view.phase == 'saving' or (same and before['saving'])
                self._foreign[slot] = dict(job=job, tool=view.active_lookup_type, hosts=self._size.get(job), saving=saved,
                                           stopped=not saved and ((same and before['stopped']) or view.phase == 'stopping'))

    def _ended_stopped(self, before):
        """Whether the job that ended was stopped: what its attempt's outcome says (a Stop that reached a job inside the
        report gate is ignored and the job is saved; one that reached it while it waited ended it unsaved), and only
        when no outcome is known the phases seen before it ended."""
        page = self.controller.page_snapshot(before['tool'])
        outcome = page.outcome
        if page.attempt_job_id == before['job'] and isinstance(outcome, dict) and 'stopped' in outcome:
            return outcome['stopped'] is True
        return before['stopped']

    def _show_end(self, state):
        phase = state.phase
        closing = phase in {'closing', 'closed'}
        closed = 'quit' if phase == 'closed' else 'failed' if phase == 'failed' and self.active != 'settings' else ''
        if closed == 'failed':
            reason = _reason(state)
            if self._failed_reason.text != reason:
                self._failed_reason.set_text(reason)
        if (closing, closed) == (self._closing, self._closed) or not self._client.has_socket_connection:
            return  # nothing new to tell the tab, or no tab to tell yet: the next poll tries again
        self._closing, self._closed = closing, closed
        self._client.run_javascript(f"window.cnShell?.closing({'true' if closing else 'false'}); "
                                    f"window.cnShell?.closed('{closed}');")

    def _open_help(self, event):
        """Open Help with the switch on the tab's own choice (kept by the browser for the tab): the click that
        opens Help says it, so the switch never shows what a slow tab had not yet answered."""
        if isinstance(event.args, bool) and self._help_switch is not None:
            self._single_keys = event.args
            self._help_switch.set_value(event.args)
        self._help_dialog.open()

    async def request_quit(self):
        """The Quit click: quit at once when nothing would be lost, else ask first, naming what Quit will do.

        The session is read at the click, not taken from the page's latest poll, so a job that began a moment ago is
        named too; and the question is asked again when something new would be lost by the time it is answered (a
        job another tab started while the dialog was open)."""
        from nicegui import Client
        from . import texts
        from .dialogs import confirm_dialog

        if self._asking:
            return  # a second click while the question is open: one question, one answer
        asked = set()
        self._asking = True
        try:
            while True:
                state = self._read()
                from .job_slots import monitor_view
                self._hosts(state)
                warning = texts.quit_warning(state, unsaved=unsaved_changes(self.controller),
                                             hosts=self._hosts(monitor_view(state)))
                if warning is None or set(warning.facts) <= asked:
                    break
                asked |= set(warning.facts)
                if not await confirm_dialog(warning.title, warning.lines, confirm=warning.confirm_label, danger=True):
                    return
        finally:
            self._asking = False
        self.controller.quit()
        # Every open tab is told now that the application is closing: one that loses its server before its next
        # poll then shows the card, not NiceGUI's offer to reconnect.
        for client in list(Client.instances.values()):
            if client.has_socket_connection:
                client.run_javascript('window.cnShell?.closing(true);')


def _owns(state, key):
    """Whether the job in ``state`` belongs to the tool of page ``key``."""
    return bool(state.active_job_id) and state.active_lookup_type == key


def _reason(state):
    error = state.error
    return str(error.get('message', error) if isinstance(error, dict) else error or '')


def render_shell(controller, active, *, poll=False):
    """Draw the title row (h1, the job's pill, the Report menu, Help, Quit), the navigation and the job banner of page ``active``
    where the page calls it.

    A page calls ``shell.update(state)`` from its own poll; one that has no poll (Settings) passes ``poll=True`` and
    the shell reads the session itself (every 0.25 s; a number is another interval). Under the root (router.py),
    which draws the shell once for the tab with ``active`` None, a tool's call draws nothing: it gets the root's shell,
    handed to it by ``set_active``.
    """
    from nicegui import ui
    from .dialogs import trap_focus
    from .report_actions import ReportMenu
    from .scope import add_once
    from .theme import apply_theme

    client = ui.context.client
    existing = _SHELLS.get(client)
    if existing is not None and existing.root:
        existing.set_active(active)
        return existing
    apply_theme()
    add_once(client, 'shell', css=CSS + job_indicator.CSS + keys.CSS, script=CLOCK_SCRIPT)
    add_once(client, 'keys', script=keys.keys_script({letter: _BY_KEY[key].route for letter, key in GO_LETTERS.items()}))
    shell = PageShell(controller, active)
    bind_client(shell, client)
    shell.root = active is None
    keys.skip_link()
    with ui.row().classes('w-full items-center justify-between cn-shell cn-title-row'):
        # tabindex=-1: a tool opened without a load moves the focus here, so a screen reader says the page's name.
        with ui.element('h1').classes('text-h4 cn-page-title').props('tabindex=-1'):
            shell._title = ui.label('').mark('title')
        with ui.row().classes('items-center gap-2 cn-shell-tools'):
            shell._indicator = job_indicator.JobIndicator(shell)  # up to two entries, each with its own Stop…
            with ui.dialog() as help_dialog, ui.card() as help_card:
                with ui.element('h2').classes('text-h6 q-my-none') as help_title:
                    ui.label('Help')
                help_dialog.props(f'aria-labelledby={help_title.html_id}')
                shell._help_content = ui.column().classes('gap-3')
                ui.button('Close', on_click=help_dialog.close).props('outline')
            trap_focus(help_dialog, help_card)  # Tab and Shift+Tab wrap inside Help, as in a confirmation
            shell.report = ReportMenu(controller)
            shell._help_dialog = help_dialog
            shell._help_button = ui.button('?').props('flat dense aria-label=Help data-cn-help')
            shell._help_button.on('click', shell._open_help, js_handler='() => emit(window.cnKeys ? window.cnKeys.enabled() : null)')
            shell.quit_button = ui.button('Quit application', on_click=shell.request_quit).props('outline')
    with ui.element('nav').props('aria-label=Tools').classes('row items-center gap-4 cn-shell'):
        for page in PAGES:
            shell._links[page.key] = ui.link(page.label, page.route)
    with ui.element('div').classes('cn-notice cn-job-notice').props('role=status') as shell._banner:
        shell._banner_text = ui.label('')
        shell._banner_link = ui.link('', '/')
    shell._banner.set_visibility(False)
    with ui.element('section').classes('cn-panel cn-closed-card').props('data-kind=quit') as card:
        with ui.element('h1').classes('text-h5').props('tabindex=-1') as heading:
            ui.label(CLOSED_TITLE)
        ui.label(CLOSED_ADVICE)
    card.props(f'aria-labelledby={heading.html_id}')
    with ui.element('section').classes('cn-panel cn-closed-card').props('data-kind=failed') as card:
        with ui.element('h1').classes('text-h5').props('tabindex=-1') as heading:
            ui.label(FAILED_TITLE)
        shell._failed_reason = ui.label('').props('role=status')
        ui.label(FAILED_ADVICE)
        with ui.row().classes('items-center gap-4 q-mt-md'):
            ui.button('Quit application', on_click=shell.request_quit).props('outline')
            shell._failed_settings = ui.link('Open Settings', _BY_KEY['settings'].route)
    card.props(f'aria-labelledby={heading.html_id}')
    keys.main_anchor()
    shell.set_active(active)
    if poll:
        ui.timer(0.25 if poll is True else poll, shell.follow)
    return shell
