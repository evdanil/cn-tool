"""Results first (plan `docs/plans/webui-ux-plan.md`, "R2-05 design note"; rows M1 and m14).

After Run a tool's form folds to one line, its summary with **Edit** (`FormFold`), so that the results are on the first
screen. `form_summary` is that line (pure); `form_field` draws a field in the one form style (a label above an
outlined, dense box). The top level imports the standard library and `texts` only: NiceGUI is imported inside the
functions that draw.
"""
import functools
import json

from . import texts

SHOWN = 2  # targets named in the summary before "…"
CUT = 40  # characters of one named target
FOLDED = '1'  # the tab's sessionStorage value for a folded form


def FOLD_KEY(tool: str) -> str:  # noqa: N802 (a key builder, named like the other storage keys)
    """The ``sessionStorage`` key that holds a tab's fold of ``tool``'s form."""
    return f'cn-tool-form-{tool}'


def _short(text: str) -> str:
    return text if len(text) <= CUT else text[:CUT] + '…'


def _seconds(value) -> str:
    value = str(value or '').strip()
    return texts.fmt_duration(int(value)) if value.isdigit() else value


@functools.lru_cache(maxsize=8)
def _read(targets: str, tool: str):
    """``(count, named, not_understood)`` of a Targets box as the tokenizer reads it (``target_text``), cached: the
    pages ask on every poll. A text over 64 KiB, which the live line does not read, is counted by its lines."""
    from cn_tool.utils.target_text import parse

    if len(targets.encode('utf-8', 'surrogatepass')) > 64 * 1024:
        lines = [line.strip() for line in targets.splitlines() if line.strip()]
        return len(lines), tuple(lines[:SHOWN + 1]), 0
    tokens = parse(targets, tool, expand=False).tokens
    understood = list({token.text: token for token in tokens if token.kind not in ('unknown', 'ignored')}.values())
    return (len(understood), tuple(token.text for token in understood[:SHOWN + 1]),
            sum(1 for token in tokens if token.kind == 'unknown'))


def form_summary(targets: str, *, ports: str = '', interval=None, duration=None, tool: str = '') -> str:
    """The folded form's line: "320 targets: 10.20.30.0/24, 10.20.31.0/24, … · TCP 22 · every 10 s · until stopped".

    With ``tool`` ('subnet', 'ip', 'ping' or 'monitor') the targets are counted as the tokenizer reads the box, the
    same as the live line under it (comments, commas and ranges included; an item that is not understood adds "· N not
    understood"). Without it a non-blank line is one target. ``ports`` are shown as typed. ``interval`` given (even
    blank) means a Monitor's form: its interval, then its duration ("for 1 h", or "until stopped" when blank). A value
    that is not a number is shown as typed."""
    if tool:
        count, names, refused = _read(str(targets or ''), tool)
        if count == 0 and refused == 0:
            parts = ['No targets']
        else:
            named = ', '.join(_short(name) for name in names[:SHOWN]) + (', …' if count > SHOWN else '')
            parts = [f"{texts.plural(count, 'target')}: {named}" if count else 'No targets']
            if refused:
                parts[0] += f' · {refused:,} not understood'
    else:
        lines = [line.strip() for line in str(targets or '').splitlines() if line.strip()]
        if lines:
            named = ', '.join(_short(line) for line in lines[:SHOWN]) + (', …' if len(lines) > SHOWN else '')
            parts = [f"{texts.plural(len(lines), 'target')}: {named}"]
        else:
            parts = ['No targets']
    if str(ports or '').strip():
        parts.append('TCP ' + str(ports).strip())
    if interval is not None:
        every = _seconds(interval)
        if every:
            parts.append(f'every {every}')
        length = _seconds(duration)
        parts.append(f'for {length}' if length else 'until stopped')
    return ' · '.join(parts)


CSS = '''
.cn-field-label { display:block; font-weight:600; font-size:var(--cn-text-body); line-height:1.4; margin:0 0 4px; color:var(--cn-ink); }
.cn-form-summary-row { display:none; }
.cn-panel.cn-form-folded { display:flex !important; flex-direction:row; flex-wrap:wrap; align-items:center; gap:8px 16px;
  padding:8px 12px; }
.cn-form-folded > * { display:none !important; }
.cn-form-folded > .cn-form-summary-row { display:flex !important; flex:1 1 20em; min-width:0; flex-wrap:wrap;
  align-items:center; gap:8px 16px; }
.cn-form-folded > .cn-form-actions { display:flex !important; flex:0 1 auto; margin:0; }
.cn-form-folded .cn-form-actions > :not(.cn-form-keep) { display:none !important; }
.cn-form-summary { flex:1 1 16em; min-width:0; overflow-wrap:anywhere; font-weight:600; }
'''

# Focus, once the browser has drawn the fold (a few frames at most): Edit after Run, when the focus was in the form or
# fell from the hidden Run button to nothing; the first box of the form after Edit. A focus the user has moved meanwhile
# is left alone.
_FOCUS = '''(() => {
  const want = () => { %(find)s };
  const start = document.activeElement;
  let tries = 0;
  const step = () => {
    const target = want();
    const active = document.activeElement;
    const free = !active || active === document.body || active === start || %(free)s;
    if (!free) return;
    if (target && target.getClientRects().length) { target.focus(); if (document.activeElement === target) return; }
    if (++tries < 30) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
})()'''
_FOCUS_EDIT = _FOCUS % {
    # A Run that moves the focus to Edit takes the mark of an earlier press away; an Edit that already has the focus
    # keeps it, since it was pressed after this Run (the script can arrive after the press).
    'find': ('const edit = document.getElementById(%(edit)s); '
             'if (edit && document.activeElement !== edit) edit.removeAttribute("data-form-edit-asked"); return edit;'),
    'free': '!!document.getElementById(%(panel)s)?.contains(active)'}
_FOCUS_FIELD = _FOCUS % {
    'find': 'const root = document.getElementById(%(field)s); return root?.matches("input,textarea") ? root : root?.querySelector("input,textarea");',
    'free': '!!document.getElementById(%(panel)s)?.contains(active)'}
# Run, when the form opened by itself: for a focus that was on Edit or in the folded line, and, for the tab that started
# the attempt, one that fell to nothing. A tab the user is only reading (the focus on the page) is not scrolled to it.
#
# The fold's focus, in one place (R2-09 step 2 and R2-10, merged):
# - window.cnFoldLost is the element whose focus went away because it stopped being displayed (the browser takes the
#   focus from it at its next rendering, which can come before _FOCUS_RUN: the form's opening and the script are two
#   messages, and on a loaded machine the open form is drawn first). _WATCH_FOCUS sets it and clears it as soon as the
#   focus is anywhere again. It is installed once per document by apply_assets (scope.add_once, guarded in the script
#   by 'cnFoldLost' in window as well), so a tool opened again by the router adds no listener.
# - window.cnFoldFocusing is set while _FOCUS_RUN waits for a frame to put the focus on Run (a token, so an older
#   move ending does not clear a newer one; 3 s at most). The outcome heading's own focus script (subnets.py) leaves
#   the focus alone while it is set: both arrive in the same frame on a loaded machine (after a cancelled sign-in,
#   "Lookup stopped" took the focus from Run), and the fold's move of the focus to Run wins.
_WATCH_FOCUS = '''<script>
(() => {
  if ('cnFoldLost' in window) return;
  window.cnFoldLost = null;
  window.cnFoldFocusing = null;
  document.addEventListener('focusout', (event) => {
    const target = event.target;
    if (target instanceof Element && !target.getClientRects().length) window.cnFoldLost = target;
  }, true);
  document.addEventListener('focusin', () => { window.cnFoldLost = null; }, true);
})();
</script>'''
_FOCUS_RUN = '''(() => {
  const edit = document.getElementById(%(edit)s), row = document.getElementById(%(row)s);
  const active = document.activeElement;
  const online = (element) => element === edit || !!(element && row?.contains(element));
  const lost = online(window.cnFoldLost);
  if (lost) window.cnFoldLost = null;
  if (!lost && !online(active) && !(%(mine)s && (!active || active === document.body))) return;
  let tries = 0;
  const token = {};
  window.cnFoldFocusing = token;
  const done = () => { if (window.cnFoldFocusing === token) window.cnFoldFocusing = null; };
  setTimeout(done, 3000);
  const step = () => {
    const now = document.activeElement, run = document.getElementById(%(run)s);
    if (now && now !== document.body && !online(now)) return done();
    if (run && !run.disabled && run.getClientRects().length) { run.focus(); return done(); }
    if (++tries < 120) requestAnimationFrame(step); else done();
  };
  requestAnimationFrame(step);
})()'''


def apply_assets():
    """The form style's and the fold's stylesheet and its lost-focus watcher (``_WATCH_FOCUS``), once per document."""
    from nicegui import ui

    from .scope import add_once

    add_once(ui.context.client, 'results-first', css=CSS, script=_WATCH_FOCUS)


def form_field(kind: str, label: str, *, value: str = '', props: str = '', classes: str = 'w-full',
               label_classes: str = ''):
    """A label above an outlined, dense box (the one form style). ``kind`` is 'textarea' or 'input'. The label is a
    ``<label for>`` of the box's own input, so a click on it focuses the box and it is the box's name. Returns
    ``(label, field)``."""
    from nicegui import ui

    apply_assets()
    caption = ui.label(label).classes(('cn-field-label ' + label_classes).strip())
    caption.tag = 'label'  # a text element (found by its text, as a label of NiceGUI is) drawn as a <label>
    make = ui.textarea if kind == 'textarea' else ui.input
    field = make(value=value).props(f'outlined dense {props}'.strip()).classes(classes)
    if kind == 'textarea':
        from .box_resize import mark
        mark(field)  # a desktop can drag it taller (box_resize)
    # Quasar gives the box's own input the id named by ``for``: the field's id, so the pages' scripts find the input
    # by it as before.
    field.props(f'for={field.html_id}')
    caption._props['for'] = field.html_id
    return caption, field


def focus_field(client, field) -> None:
    """Put the focus on a form field (its box, whatever the element ``field`` wraps): the first field of a form that has
    no fold to open (Clear results on Configuration Search and Site Demobilization)."""
    if client.is_deleted or not client.has_socket_connection:
        return
    client.run_javascript(f'(() => {{ const root = document.getElementById({json.dumps(field.html_id)}); '
                          '(root?.matches("input,textarea") ? root : root?.querySelector("input,textarea"))?.focus(); })()')


class FormFold:
    """The fold of one form: drawn as the first child of the form's ``panel`` (a ``cn-panel``), one line of summary
    and **Edit**. The panel's row of buttons, when it has the class ``cn-form-actions``, stays beside it with the
    buttons marked ``cn-form-keep`` (Stop, View results).

    ``again`` (the page's own ``submit``, a coroutine function) makes the line offer **Run again**: the request the
    summary shows, started by the same code as Run, so it has Run's checks and its sign-in, setup and confirmations.
    It is off whenever ``run`` is; Ctrl/Cmd+Enter on the line is a click on it (a key held down is not). A start that
    ``again`` did not make (it was refused) opens the form, where its message is.

    ``folded`` is the tab's choice (``sessionStorage``, kept by a reload, never by a new tab) while the page has
    something to show (``show``). ``alive`` (a callable) says whether the page is still the tab's: a Run again that
    begins or ends after it was left leaves the fold alone. ``ran()`` folds (a Run that was accepted); ``edit()`` opens and focuses ``focus``.
    R2-08 reads ``folded`` and ``editing`` and sets them with ``edit()`` and ``ran()``; ``on_change(callback)`` is
    called with ``folded`` whenever it changes."""

    def __init__(self, panel, tool: str, *, focus, run=None, again=None, alive=None):
        from nicegui import ui

        apply_assets()
        self.panel, self.tool, self._focus, self._run_button = panel, tool, focus, run
        self._tab_folded = False
        self._something = False
        self._decided = False  # the user chose (Run, Edit, a handoff) before the tab's stored choice was read
        self._pending = False  # a Run of this page was accepted and the poll has not seen its job or result yet
        self._attempt = self._baseline = None  # the page's latest attempt id as last seen, and as it was at ran()
        self._starting = False  # a Run again is being started
        self._mine = False  # this tab ran the attempt behind the fold (its user is waiting for it)
        self._settling = False  # a Run was accepted and the page has not polled since
        self._callbacks = []
        self._again, self._runs = again, 0
        self._alive = alive or (lambda: True)  # False once the page was left: its handlers change nothing then
        self.folded = False
        with panel:
            with ui.element('div').classes('cn-form-summary-row') as self.row:
                self.summary = ui.label('').classes('cn-form-summary').props('data-form-summary')
                self.again_button = None
                if again is not None:
                    # Enter on a focused button clicks it with the modifiers held: the key handler of the row is the
                    # one that answers Ctrl/Cmd+Enter, so the click ignores them (as Edit's does).
                    self.again_button = ui.button('Run again').props('data-form-run-again')
                    self.again_button.on('click', self._run_again,
                                         js_handler='(event) => { if (!(event?.ctrlKey || event?.metaKey)) emit(); }')
                self.edit_button = ui.button('Edit').props('outline data-form-edit')
                # Ctrl+Enter held in the form after Run reaches Edit, which has the focus by then: it opens nothing.
                # A press that opens the form marks Edit at once (data-form-edit-asked): an outcome that arrives
                # before the form has opened must not take the focus from it (subnets.py), as it does from the Edit
                # that a Run focused. The next Run that moves the focus to Edit takes the mark away (_FOCUS_EDIT).
                edit_id = json.dumps(self.edit_button.html_id)
                self.edit_button.on('click', lambda: self.edit(), js_handler=(
                    '(event) => { if (!(event?.ctrlKey || event?.metaKey)) { '
                    f'document.getElementById({edit_id})?.setAttribute("data-form-edit-asked", ""); emit(); }} }}'))
                self.edit_button._props['aria-describedby'] = self.summary.html_id
                if self.again_button is not None:
                    self.again_button._props['aria-describedby'] = self.summary.html_id
                    for chord in ('ctrl', 'meta'):
                        # Capture: a Quasar button (Edit, Run again) stops its own Enter keydown before it bubbles.
                        self.row.on(f'keydown.capture.{chord}.enter.prevent', self._run_again,
                                    js_handler='(event) => { if (!event.repeat) emit(); }')
        self.row.move(panel, target_index=0)
        ui.timer(0, self._restore, once=True)

    @property
    def editing(self) -> bool:
        return not self._tab_folded

    def on_change(self, callback) -> None:
        self._callbacks.append(callback)

    def set_summary(self, text: str) -> None:
        """The line's words, and Run again's state: on exactly when the page's Run is (the page sets Run's first)."""
        if self.summary.text != text:
            self.summary.set_text(text)
        if self.again_button is not None and self._run_button is not None:
            self.again_button.set_enabled(self._run_button.enabled)

    async def _run_again(self) -> None:
        # One start at a time: a second click (or Ctrl+Enter) while the first is being accepted, or after it was and
        # before the page's next poll, would be refused ("job running") and would open the form of a run that did
        # start. From that poll on, Run again is off while the job runs, as always.
        if (not self._alive() or self._again is None or self._starting or self._settling
                or (self._run_button is not None and not self._run_button.enabled)):
            return
        self._starting = True
        before = self._runs
        try:
            chosen = await self._again()
        finally:
            self._starting = False
        if not self._alive():  # the page was left meanwhile (or before the handler began): its fold is not touched
            return
        if self._runs == before:  # nothing started: the reason is on the form, so the form is given back
            self.edit(focus=True if chosen is None else chosen)  # at the field the page named, else the first box

    def show(self, something: bool, *, running: bool = False, attempt=None) -> None:
        """What the page has to show beside the form (a result, its own job, a run): no fold without. A Run whose
        attempt ends with nothing to show (a failure, a cancelled sign-in) gives the form back, open: ``attempt`` is
        the page's latest attempt (job) id and ``running`` whether its own job runs, so that an attempt that began and
        ended between two polls is seen to have ended."""
        self._settling = False  # the poll has run since the last start: Run's state (so Run again's) is its answer
        if something:
            self._pending = False
        elif self._pending and attempt is not None and attempt != self._baseline and not running:
            self._pending = False
        if attempt is not None:
            self._attempt = attempt
        self._something = bool(something) or self._pending
        self._apply()

    def ran(self) -> None:
        """A Run was accepted: fold, and move the focus from the hidden Run button to Edit."""
        self._decided = self._pending = self._mine = True
        self._starting = False  # accepted: what follows is guarded by ``_settling``, not by the call that is still on
        self._settling = True
        self._baseline = self._attempt
        self._runs += 1
        self._tab_folded = True
        self._something = True
        self._store(True)
        self._apply()
        self._run(_FOCUS_EDIT % {'panel': json.dumps(self.panel.html_id), 'edit': json.dumps(self.edit_button.html_id)})

    def edit(self, *, focus=True) -> None:
        """Open the form, its values as they were; ``focus`` True puts the focus on its first box, an element of the
        form on that one, False nowhere."""
        self._decided = True
        self._mine = False
        self._tab_folded = False
        self._store(False)
        self._apply()
        if focus:
            target = self._focus if focus is True else focus
            self._run(_FOCUS_FIELD % {'field': json.dumps(target.html_id), 'panel': json.dumps(self.panel.html_id)})

    # --- inside -------------------------------------------------------------------------------------------------

    def _apply(self) -> None:
        folded = self._tab_folded and self._something
        if folded == self.folded:
            return
        self.folded = folded
        self.panel.classes(**{'add' if folded else 'remove': 'cn-form-folded'})
        if not folded and self._tab_folded:
            # The form opens by itself (nothing is left to show): the tab's fold is given up, so that a result another
            # tab makes later does not fold the form under a user who types. Only ran() or a reload that restores the
            # stored fold folds again.
            self._tab_folded = False
            self._store(False)
            mine, self._mine = self._mine, False
            if self._run_button is not None:
                # A focus that was on Edit or in the folded line goes to Run, and so does the one of the tab that ran.
                self._run(_FOCUS_RUN % {'edit': json.dumps(self.edit_button.html_id), 'row': json.dumps(self.row.html_id),
                                        'run': json.dumps(self._run_button.html_id), 'mine': json.dumps(mine)})
        for callback in list(self._callbacks):
            callback(folded)

    def _run(self, script: str) -> None:
        client = self.panel.client
        if not client.is_deleted and client.has_socket_connection:
            client.run_javascript(script)

    def _store(self, folded: bool) -> None:
        key = json.dumps(FOLD_KEY(self.tool))
        self._run(f'try {{ sessionStorage.setItem({key}, {json.dumps(FOLDED)}); }} catch (e) {{}}' if folded
                  else f'try {{ sessionStorage.removeItem({key}); }} catch (e) {{}}')

    async def _restore(self) -> None:
        import asyncio
        client = self.panel.client
        try:
            await asyncio.wait_for(client.connected(), timeout=5)
            stored = await client.run_javascript(
                f'(() => {{ try {{ return sessionStorage.getItem({json.dumps(FOLD_KEY(self.tool))}); }} catch (e) {{ return null; }} }})()',
                timeout=5)
        except (TimeoutError, asyncio.TimeoutError):
            return
        if stored == FOLDED and not self._decided and not client.is_deleted:
            self._tab_folded = True
            self._apply()
