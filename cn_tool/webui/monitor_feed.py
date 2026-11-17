"""The Monitor page's change list, title count and desktop notification (plan 7.4, R3-08).

``FeedState`` and ``list_rows`` are pure: what the page holds of the run's feed (``monitor_changes.ChangeFeed`` on the
worker), what it asks next, how the list reads and what a new answer adds. ``ChangesPanel`` is the NiceGUI part: the
section "Changes" under the header line, filled by ``SCRIPT`` in the browser (one ``<ol>`` patched in place, so a
focused button and the scroll position stay), the opt-in switch for desktop notifications and the title's count. The
list is not a live region: the round summary says "3 changes" once per round, and the switch's own states are said by
``aria-pressed`` and one ``role=alert`` that is empty unless the browser refused.

A gap in the sequence numbers is what the feed let go of: it is listed as a gap and counted as unknown, never
invented. NiceGUI is imported inside the functions.
"""
import json
import secrets

from . import texts
from .protocol import CHANGES_KEPT, CHANGES_PAGE_MAX

SHOWN = 20  # the list's size until "Show all"


class FeedState:
    """The entries of one run the page holds, oldest first, at most ``CHANGES_KEPT``."""

    def __init__(self):
        self.reset(None)

    def reset(self, identity):
        """Another run (or the page's first look): nothing held."""
        self.identity = identity
        self.entries, self.have, self.last_seq, self.unavailable = [], 0, 0, False

    @property
    def more(self):
        return self.have < self.last_seq

    @property
    def earlier(self):
        """How many changes before the oldest one held are not available (let go by the feed, or past the 200)."""
        return self.entries[0]['seq'] - 1 if self.entries else self.have

    def ingest(self, answer):
        if answer.get('status') != 'ready':
            self.unavailable = True
            return
        self.unavailable = False
        for entry in sorted((e for e in answer['entries'] if e['seq'] > self.have), key=lambda e: e['seq']):
            self.have = entry['seq']
            self.entries.append(entry)
        last = answer['last_seq']
        if not answer['entries'] and last > self.have:  # nothing the feed can still give: it let those go
            self.have = last
        self.last_seq = max(self.last_seq, last)
        del self.entries[:-CHANGES_KEPT]

    def in_round(self, revision):
        return sum(1 for entry in self.entries if entry['round'] == revision)

    def latest_round(self, revision):
        """``(count, exact)`` of the entries of round ``revision`` held. Exact only when nothing can be missing: the
        round's entries are contiguous, and either start at number 1 or follow the entry of an earlier round directly
        (or, with none, the newest entry is an earlier round's and is the feed's last number). Reading all that the feed
        kept proves the kept entries were read, not that the round was whole: a round that made more than 200 changes
        has lost its first ones."""
        held = [e for e in self.entries if e['round'] == revision]
        if not held:
            newest = self.entries[-1]['seq'] if self.entries else 0
            return 0, not self.more and newest == self.last_seq
        first = self.entries.index(held[0])
        contiguous = all(b['seq'] == a['seq'] + 1 for a, b in zip(held, held[1:]))
        before = held[0]['seq'] == 1 or (first > 0 and self.entries[first - 1]['seq'] == held[0]['seq'] - 1)
        return len(held), contiguous and before and not self.more

    def between(self, start, end):
        """The entries held with ``start`` < seq <= ``end``."""
        return [entry for entry in self.entries if start < entry['seq'] <= end]


def list_rows(entries, limit, *, earlier=0):
    """The rows of the list for the browser, newest first: ``limit`` entries, a gap row where numbers are missing
    (and at the end when the window reaches the oldest entry held and older ones are not available)."""
    shown = entries[-limit:]
    rows = []
    for position in range(len(shown) - 1, -1, -1):
        entry = shown[position]
        row = dict(kind='entry', seq=entry['seq'], text=texts.change_line(entry), silent=texts.went_silent(entry))
        if entry['block'] is not None and entry['cell'] is not None:
            row.update(b=entry['block'], c=entry['cell'], label=f"Show {entry['host']} on the map")
        rows.append(row)
        before = shown[position - 1]['seq'] if position else None
        if before is not None and entry['seq'] - before > 1:
            count = entry['seq'] - before - 1
            rows.append(dict(kind='gap', count=count, text=texts.gap_line(count)))
    if len(shown) == len(entries) and earlier:
        rows.append(dict(kind='gap', count=earlier, text=texts.gap_line(earlier)))
    return rows


CSS = '''
.cn-live-bar { display:flex; flex-wrap:wrap; align-items:flex-start; gap:8px; width:100%; }
.cn-live-bar > .cn-live-switch { width:auto; }
.cn-changes[open] { flex:1 1 100%; }
.cn-changes { min-width:0; border:1px solid var(--cn-line); border-radius:6px; background:var(--cn-panel); }
.cn-changes > summary { display:flex; flex-wrap:wrap; align-items:baseline; gap:0 12px; padding:3px 12px; cursor:pointer; }
.cn-changes > summary:focus-visible { outline:2px solid var(--cn-focus); outline-offset:-2px; }
.cn-changes > summary h2 { display:inline; margin:0; font-size:var(--cn-text-body); line-height:1.4; }
.cn-changes > summary .cn-changes-count { color:var(--cn-muted); }
.cn-changes-body { display:flex; flex-direction:column; gap:8px; padding:0 14px 14px; }
.cn-changes-bar { display:flex; flex-wrap:wrap; align-items:center; gap:4px 12px; width:100%; }
.cn-changes-list-box { max-height:min(30vh, 300px); width:100%; min-width:0; overflow:auto; border:1px solid var(--cn-line); border-radius:4px; }
.cn-changes-list-box:focus-visible { outline:2px solid var(--cn-focus); outline-offset:-2px; }
.cn-changes-list { list-style:none; margin:0; padding:0; font-variant-numeric:tabular-nums; }
.cn-changes-list li { display:flex; flex-wrap:wrap; align-items:center; gap:2px 12px; padding:6px 10px; border-bottom:1px solid var(--cn-line-soft); overflow-wrap:anywhere; }
.cn-changes-list li:last-child { border-bottom:0; }
.cn-changes-list li.gap { color:var(--cn-muted); font-style:italic; }
.cn-changes-list button { min-height:32px; padding:2px 10px; font:inherit; color:var(--cn-link); background:var(--cn-panel); border:1px solid var(--cn-link); border-radius:4px; cursor:pointer; }
.cn-changes-list button:hover { background:var(--cn-action-hover); }
.cn-changes-list button:focus-visible { outline:2px solid var(--cn-focus); outline-offset:2px; }
.cn-changes [role=alert]:empty, .cn-changes [hidden] { display:none; }
.cn-changes-notify { min-height:32px; padding:2px 12px; font:inherit; color:var(--cn-link); background:var(--cn-panel); border:1px solid var(--cn-link); border-radius:4px; cursor:pointer; }
.cn-changes-notify[aria-pressed=true] { background:var(--cn-action-hover); box-shadow:inset 3px 0 var(--cn-focus); font-weight:600; }
.cn-changes-notify:focus-visible { outline:2px solid var(--cn-focus); outline-offset:2px; }
'''

SCRIPT = r'''<script>
window.cnMonitorFeed = window.cnMonitorFeed || (() => {
  const KEY = 'cn-tool-monitor-notify', OPEN = 'cn-tool-monitor-changes-open';
  const S = {token: null, section: null, tally: null, list: null, empty: null, button: null, help: null, alert: null, texts: null, count: 0, base: '',
             set: null, enabled: false, listening: false, bound: false, pending: null};
  const send = (name, data) => { if (window.emitEvent) window.emitEvent(name, Object.assign({token: S.token}, data)); };
  const supported = () => typeof window.Notification === 'function';
  const permission = () => { try { return supported() ? window.Notification.permission : 'denied'; } catch (error) { return 'denied'; } };
  const stored = () => { try { return localStorage.getItem(KEY) === '1'; } catch (error) { return false; } };
  const opened = () => { try { return sessionStorage.getItem(OPEN) === '1'; } catch (error) { return false; } };
  const onToggle = () => { try { sessionStorage.setItem(OPEN, S.section.open ? '1' : '0'); } catch (error) { /* a private tab */ } };
  const keep = on => { try { localStorage.setItem(KEY, on ? '1' : '0'); } catch (error) { /* private window: this tab only */ } };

  // The switch: on only when the reader chose it and the browser still allows it. The question to the browser is asked
  // only by the click that turns it on, never by loading the page.
  function paint() {
    const b = S.button;
    if (!b) return;
    b.hidden = !supported();
    b.setAttribute('aria-pressed', S.enabled ? 'true' : 'false');
    S.help.textContent = !supported() ? S.texts.unsupported : permission() === 'denied' ? S.texts.blocked
      : S.enabled ? S.texts.on : S.texts.off;
    b.dataset.state = !supported() ? 'unsupported' : permission() === 'denied' ? 'blocked' : S.enabled ? 'on' : 'off';
  }
  async function toggle() {
    if (!supported()) return;
    S.alert.textContent = '';
    if (S.enabled) { S.enabled = false; keep(false); paint(); return; }
    let answer = permission();
    if (answer === 'denied') { S.alert.textContent = S.texts.blocked; return; }
    if (answer === 'default') {
      try { answer = await window.Notification.requestPermission(); } catch (error) { answer = 'denied'; }
    }
    if (!S.button) return;  // the page was left while the browser asked
    if (answer === 'granted') { S.enabled = true; keep(true); }
    else { S.enabled = false; keep(false); S.alert.textContent = S.texts.declined; }
    paint();
  }

  // The title: "(3↓) Monitor – cn-tool" while the tab is in the background; the base is the title as the shell set it.
  function title() {
    if (!S.texts) return;
    if (document.title !== S.set) S.base = document.title;
    const count = S.count > S.texts.max ? S.texts.max + '+' : String(S.count);
    S.set = S.count > 0 ? S.texts.title.replace('{count}', count).replace('{title}', S.base) : null;
    document.title = S.set === null ? S.base : S.set;
  }
  function returned() {
    if (document.hidden || !S.count) return;
    S.count = 0;
    if (document.title === S.set) { document.title = S.base; S.set = null; }
  }
  const away = () => document.hidden || !document.hasFocus();
  function arrive(message) {
    if (!S.texts) return;
    if (message.silent > 0 && document.hidden) { S.count += message.silent; title(); }
    if (!S.enabled || permission() !== 'granted' || !away()) return;
    for (const text of message.notices || []) {
      try {
        // One tag, renotify: a later round replaces the earlier notification and alerts again; a click brings the tab back.
        const note = new window.Notification(S.texts.app, {body: text, tag: 'cn-tool-monitor-changes', renotify: true});
        note.onclick = () => { try { window.focus(); note.close(); } catch (error) { /* gone */ } };
      } catch (error) { /* refused */ }
    }
  }

  // The list: rebuilt from the server's rows, newest first; the button that holds the focus keeps it.
  function render(message) {
    S.pending = message;  // kept for a list that is drawn later (a page built on History)
    if (!S.list) return;
    const held = document.activeElement && S.list.contains(document.activeElement)
      ? document.activeElement.closest('li').dataset.seq : null;
    const items = [];
    for (const row of message.rows) {
      const item = document.createElement('li');
      if (row.kind === 'gap') item.className = 'gap';
      else item.dataset.seq = String(row.seq);
      const text = document.createElement('span');
      text.textContent = row.text;
      item.append(text);
      if (row.label) {
        item.append(' ');
        const button = document.createElement('button');
        button.type = 'button';
        button.textContent = 'Show on map';
        button.setAttribute('aria-label', row.label);
        button.dataset.b = String(row.b);
        button.dataset.c = String(row.c);
        item.append(button);
      }
      items.push(item);
    }
    S.list.replaceChildren(...items);
    if (S.tally) S.tally.textContent = message.count || '';
    S.empty.textContent = message.empty || '';
    S.empty.hidden = message.rows.length > 0;
    if (held !== null) S.list.querySelector('li[data-seq="' + held + '"] button')?.focus({preventScroll: true});
  }
  function onClick(event) {
    const button = event.target.closest && event.target.closest('button[data-b]');
    if (!button) return;
    const b = +button.dataset.b, c = +button.dataset.c;
    if (!(window.cnMonitorMap && window.cnMonitorMap.focusCell(b, c))) send('cn_monitor_feed_focus', {b: b, c: c});
  }
  // The elements (drawn with the Live panel) and the document's own listeners are two sets: a page built on History
  // counts the title and sends notifications from init on, and ``bind`` adds the list when the Live panel is chosen.
  // Only what was added is taken away (a page that counts listeners sees one add and one remove, never a remove alone).
  function unbind() {
    if (S.bound) {
      S.section.removeEventListener('toggle', onToggle);
      S.list.removeEventListener('click', onClick);
      S.button.removeEventListener('click', toggle);
    }
    Object.assign(S, {section: null, tally: null, list: null, empty: null, button: null, help: null, alert: null, bound: false});
  }
  function bind(options) {
    const list = document.getElementById(options.list);
    if (!list || !S.texts) return false;
    unbind();
    Object.assign(S, {section: document.getElementById(options.section), tally: document.getElementById(options.count),
                      list: list, empty: document.getElementById(options.empty), button: document.getElementById(options.button),
                      help: document.getElementById(options.help), alert: document.getElementById(options.alert)});
    list.addEventListener('click', onClick);
    S.section.open = opened();  // closed until the reader opens it: the Map stays on the first screen
    S.section.addEventListener('toggle', onToggle);
    S.button.addEventListener('click', toggle);
    S.bound = true;
    paint();
    if (S.pending) render(S.pending);
    return true;
  }
  function dispose() {
    unbind();
    if (S.listening) {
      document.removeEventListener('visibilitychange', returned);
      window.removeEventListener('focus', returned);
    }
    if (S.set !== null && document.title === S.set) document.title = S.base;
    Object.assign(S, {token: null, texts: null, count: 0, set: null, listening: false, pending: null});
  }
  function init(options) {
    dispose();
    S.token = options.token;
    S.texts = options.texts;
    S.enabled = stored() && permission() === 'granted';
    document.addEventListener('visibilitychange', returned);
    window.addEventListener('focus', returned);
    S.listening = true;
    bind(options);
    return true;
  }
  return {init: init, bind: bind, dispose: dispose, render: render, arrive: arrive};
})();
</script>'''


WAIT_POLLS = 20  # a round's notification waits this many polls for the feed to catch up, then goes with what it has
RETRY_POLLS = 6  # after a refused or unavailable ask: this many polls before the next


class ChangesPanel:
    """The section "Changes" of the Monitor page: a closed ``<details>`` beside the Map / Table switch, fed from the
    page's poll.

    How many hosts a round changed is the difference of ``monitor_update``'s ``changes_seq`` between two revisions: exact,
    whatever the feed kept. The page announces once per round (the title count and the notification) when the entries of
    that round have been read, or when it has waited ``WAIT_POLLS`` polls; the round summary uses the same number and is
    never written with a partial one."""

    def __init__(self, controller, scope):
        self.controller, self.scope, self.client = controller, scope, scope.client
        self.state = FeedState()
        self.query = None
        self.cooldown = 0
        self.limit = SHOWN
        self.running = False
        self.live_map = None  # set by the page once the Map exists
        self.shown_key = None
        self.version = 0  # moves when what the list shows may have changed
        self.drawn_version = None
        self.token = secrets.token_hex(8)  # in the script's init and in its event: another page's are ignored
        self.previous = None  # (revision, changes_seq) at the last poll of this run
        self.deltas = {}      # revision -> how many changes that round made, when the page saw the round begin
        self.owed = []        # [start, end, waited]: seq ranges of rounds to announce once their entries are read
        self.seq = 0

    # --- drawn by the page, in its order -----------------------------------------------------------------------------
    def build(self):
        from nicegui import ui
        self.scope.head_once('monitor-feed', css=CSS, script=SCRIPT)
        with ui.element('details').classes('cn-changes') as self.section:
            with ui.element('summary'):
                with ui.element('h2').classes('text-h6 q-my-none') as heading:
                    ui.label('Changes')
                self.count = ui.label('').classes('cn-changes-count')
            self.section.props(f'role=group aria-labelledby={heading.html_id}')
            body = ui.element('div').classes('cn-changes-body')
        with body:
            with ui.element('div').classes('cn-changes-bar'):
                self.button = ui.element('button').props('type=button').classes('cn-changes-notify').props('aria-pressed=false')
                with self.button:
                    ui.label(texts.NOTIFY_LABEL)
                self.more = ui.button('', on_click=self._toggle_all).props('flat dense no-caps')
                self.more.set_visibility(False)
            self.help = ui.label('').classes('cn-muted')
            self.button._props['aria-describedby'] = self.help.html_id
            self.alert = ui.label('').props('role=alert').classes('text-negative')
            box = ui.element('div').classes('cn-changes-list-box').props('tabindex=0 role=region aria-label="Changes list"')
            with box:
                self.empty = ui.label('').classes('cn-muted q-pa-sm')
                self.list = ui.element('ol').classes('cn-changes-list').props('aria-label="Changes, newest first"')
        self.section.set_visibility(False)
        self.scope.on_event('cn_monitor_feed_focus', self._focus)
        self.scope.js(self._call('init'), 'window.cnMonitorFeed && window.cnMonitorFeed.dispose()')

    def _call(self, name):
        options = dict(section=self.section.html_id, count=self.count.html_id, list=self.list.html_id,
                       empty=self.empty.html_id, button=self.button.html_id, help=self.help.html_id,
                       alert=self.alert.html_id, token=self.token, texts=self.texts_for_script())
        return f'window.cnMonitorFeed && window.cnMonitorFeed.{name}({json.dumps(options)})'

    def texts_for_script(self):
        return dict(title=texts.TITLE_COUNT, max=texts.TITLE_COUNT_MAX, app='cn-tool Monitor', **texts.NOTIFY_HELP)

    def restart(self):
        """The Live panel was chosen after the page was built on History: its elements exist now (the title count and
        the notification have worked since the page was built)."""
        if self.scope.alive:
            self.client.run_javascript(self._call('bind'))
            self.shown_key = None
            self._draw()

    # --- the page's poll ---------------------------------------------------------------------------------------------
    def follow(self, identity, update, *, active):
        """Ask for what ``update['changes_seq']`` says is new, announce finished rounds and draw. ``identity``: (job,
        run id) of the run the page shows, or None."""
        self.running = active
        seq = (update or {}).get('changes_seq', 0) if identity else 0
        revision = (update or {}).get('revision', 0) if identity else 0
        if identity != self.state.identity:
            self._release()
            self.state.reset(identity)
            self.cooldown, self.limit, self.shown_key = 0, SHOWN, None
            self.previous, self.deltas, self.owed = None, {}, []
            self.version += 1
        self.seq = seq
        if identity is None:
            self.section.set_visibility(False)
            return
        self._rounds(revision, seq)
        if self.cooldown:
            self.cooldown -= 1
        if self.query:
            try:
                answer = self.controller.monitor_live_changes(self.query)
            except AttributeError:  # a controller that has no feed (a test's fake): nothing to read
                answer = dict(status='unavailable', entries=[], last_seq=0)
            if answer is not None:
                self._release()
                self.state.ingest(answer)
                self.version += 1
                if self.state.unavailable:
                    self.cooldown = RETRY_POLLS
        if not self.query and not self.cooldown and (self.state.have < seq or self.state.more):
            try:
                self.query = self.controller.request_monitor_live_changes(identity[0], identity[1], self.state.have,
                                                                           CHANGES_PAGE_MAX)
            except (AttributeError, RuntimeError, ValueError):  # too many outstanding (all tabs share 8), or none now
                self.cooldown = RETRY_POLLS
        self._announce()
        self.section.set_visibility(True)
        self._draw()

    def _rounds(self, revision, seq):
        """The round that began since the last poll: its change count is the difference of ``changes_seq``."""
        if self.previous is None:
            self.previous = (revision, seq)
            return
        before, was = self.previous
        if revision != before:
            if revision == before + 1:
                self.deltas[revision] = max(0, seq - was)
                for old in [r for r in self.deltas if r < revision - 3]:
                    del self.deltas[old]
            if seq > was:  # rounds the page did not see one by one are announced as one
                self.owed.append([was, seq, 0])
        self.previous = (revision, seq)

    def round_count(self, revision):
        """How many changes the latest round made, or None while it is not known (never a partial count)."""
        if revision in self.deltas:
            return self.deltas[revision]
        if self.state.identity is not None and not self.state.more and self.state.have >= self.seq and not self.query:
            return self.state.latest_round(revision)  # a first look at a run: read from the feed, once it is all here
        return None

    def note(self, revision):
        found = self.round_count(revision) if revision else None
        if found is None:
            return ''
        count, exact = found if isinstance(found, tuple) else (found, True)
        return texts.round_changes(count, exact=exact) if count else ''

    def _announce(self):
        """Once per round, when its entries are read (or the wait is over): the title's count and the notification."""
        while self.owed:
            start, end, waited = self.owed[0]
            if self.state.have < end and waited < WAIT_POLLS and not self.state.unavailable:
                self.owed[0][2] += 1
                return
            self.owed.pop(0)
            entries = self.state.between(start, end)
            message = dict(silent=sum(1 for e in entries if texts.went_silent(e)),
                           notices=[texts.notification_text(entries, end - start)])
            self.client.run_javascript(f'window.cnMonitorFeed && window.cnMonitorFeed.arrive({json.dumps(message)})')

    def release(self):
        self._release()

    def _release(self):
        if self.query:
            getattr(self.controller, 'release_monitor_live_changes', lambda query: None)(self.query)
            self.query = None

    # --- drawing ----------------------------------------------------------------------------------------------------
    def _draw(self):
        state = self.state
        key = (self.version, self.limit, self.running)
        if key == self.drawn_version:
            return
        self.drawn_version = key
        rows = list_rows(state.entries, self.limit, earlier=state.earlier)
        empty = '' if rows else ('No changes yet. A host that changes state between two complete rounds is listed here, '
                                 'from the second round on.' if self.running else 'No changes in this run.')
        message = dict(rows=rows, empty=empty, count=texts.changes_count(state.have))
        self.client.run_javascript(f'window.cnMonitorFeed && window.cnMonitorFeed.render({json.dumps(message)})')
        held = len(state.entries)
        self.more.set_text(f'Show all {held}' if self.limit == SHOWN else f'Show the last {SHOWN}')
        self.more.set_visibility(held > SHOWN)

    def _toggle_all(self):
        self.limit = CHANGES_KEPT if self.limit == SHOWN else SHOWN
        self._draw()

    async def _focus(self, event):
        args = event.args if isinstance(event.args, dict) else {}
        if args.get('token') != self.token or not self.scope.alive or self.live_map is None:
            return
        b, c = args.get('b'), args.get('c')
        if type(b) is int and type(c) is int and b >= 0 and c >= 0:
            await self.live_map.focus_cell(b, c)
