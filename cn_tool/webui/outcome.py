"""The outcome banner: what a tool's latest attempt did, in one place, in one shape, on every tool page.

Plan: `docs/plans/webui-ux-plan.md`, R2-01 (finding M4b) and its design note.

- ``outcome_banner(tone, title, detail, actions)`` draws it. The **tone** is information, attention or error. Each has
  its own icon shape, its own word ("Information", "Attention", "Error") and its own colour, so none depends on
  colour alone. The title is the page's one polite region and takes the focus (``tabindex=-1``) when a page moves
  it there; the actions sit beside the region, outside it, so a count in an action never speaks.
- ``Banner`` is the same thing for a page that updates from a poll: ``set(...)`` redraws only when what is shown
  changes, so focus and clicks on the actions survive the poll.
- The pure parts (`tone_for`, `action_keys`, `lines_label`, `actions_for`) decide the tone and which actions an outcome
  offers; the pages supply what the actions do. Retry submits `controller.last_request(tool)` again (`repeat`).

NiceGUI is imported inside the functions that draw, so the pure parts load without the web stack.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

INFORMATION, ATTENTION, ERROR = 'information', 'attention', 'error'
TONE_WORDS = {INFORMATION: 'Information', ATTENTION: 'Attention', ERROR: 'Error'}

RETRY, OPEN_SETTINGS, SIGN_IN_AGAIN = 'Retry', 'Open Settings', 'Sign in again'
NO_REQUEST = 'The request to repeat is no longer known. Enter it again.'
# The tools whose errors can come from their settings (the Infoblox endpoint, the configuration repository).
SETTINGS_TOOLS = ('subnet', 'ip', 'demob', 'config_search')
# The tools whose last request Retry can submit as it was. A Monitor run is long and has its own form: it is not
# repeated by one click.
RETRY_TOOLS = ('subnet', 'ip', 'ping', 'config_search', 'demob')
_KINDS_NEEDING_ATTENTION = ('partial', 'stopped', 'invalid')
_COUNTS_NEEDING_ATTENTION = ('invalid_count', 'resolution_error_count', 'warning_count')

# Key order is the order of the buttons.
ACTION_KEYS = ('sign_in_again', 'retry', 'open_settings', 'show_lines')

CSS = '''
/* One line where it fits (results first): the tone's mark, the title, then the actions at the end of the line. What
   does not fit wraps: the title under the mark, the actions under the title, the detail on a line of its own. */
.cn-outcome { width:100%; min-width:0; overflow-wrap:anywhere; display:flex; flex-wrap:wrap; align-items:center;
  gap:4px 16px; padding:4px 12px; border-left:4px solid var(--cn-outcome-ink); background:var(--cn-outcome-bg); color:var(--cn-ink); }
.cn-outcome-information { --cn-outcome-ink:var(--cn-link); --cn-outcome-bg:var(--cn-info-bg); }
.cn-outcome-attention { --cn-outcome-ink:var(--cn-attention-ink); --cn-outcome-bg:var(--cn-attention-bg); }
.cn-outcome-error { --cn-outcome-ink:var(--cn-error-ink); --cn-outcome-bg:var(--cn-error-bg); }
.cn-outcome-voice { display:flex; flex-wrap:wrap; align-items:baseline; gap:2px 10px; min-width:0; flex:1 1 20em; }
.cn-outcome-voice > .cn-outcome-title { flex:1 1 12em; min-width:0; }
.cn-outcome-voice > .cn-outcome-detail { flex:0 0 100%; }
.cn-outcome-mark { display:inline-flex; align-items:center; gap:6px; color:var(--cn-outcome-ink); font-size:var(--cn-text-small);
  font-weight:700; text-transform:uppercase; letter-spacing:.04em; }
.cn-outcome-mark { flex:none; }
.cn-outcome-mark svg { width:18px; height:18px; flex:none; align-self:center; }
.cn-outcome-title { margin:0; font-size:var(--cn-text-heading); line-height:1.35; font-weight:650; color:var(--cn-outcome-ink); }
p.cn-outcome-title, div.cn-outcome-title { font-size:var(--cn-text-body); }
.cn-outcome-error .cn-outcome-title { color:var(--cn-error-ink); }
.cn-outcome-detail { margin:0; max-width:78ch; color:var(--cn-ink); }
.cn-outcome-actions { display:flex; flex-wrap:wrap; align-items:center; gap:8px; flex:0 1 auto; }
.cn-outcome-actions:empty { display:none; }
@media (forced-colors: active) { .cn-outcome { border:2px solid CanvasText; } }
'''

# One shape per tone (circle with i, triangle with !, circle with a cross), stroked in the tone's colour.
_ICONS = {
    INFORMATION: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5v.01"/>',
    ATTENTION: '<path d="M12 3.5 22 20H2z"/><path d="M12 10v5M12 17.5v.01"/>',
    ERROR: '<circle cx="12" cy="12" r="9"/><path d="M8.5 8.5l7 7M15.5 8.5l-7 7"/>',
}


@dataclass(frozen=True)
class Action:
    """One button of the banner. ``key`` is one of `ACTION_KEYS`; the handler is not part of what is compared."""
    key: str
    label: str
    on_click: Callable = field(compare=False, default=lambda: None)
    primary: bool = False


# --- the pure part ---------------------------------------------------------------------------------------------------

def tone_for(outcome) -> str:
    """The tone of a worker outcome: an error is the error tone; a run that stopped, found only some of its inputs
    usable or ended with probe errors, warnings or lines not understood asks for attention; the rest informs."""
    if not isinstance(outcome, dict):
        return INFORMATION
    if outcome.get('kind') == 'lookup_error':
        return ERROR
    if outcome.get('kind') in _KINDS_NEEDING_ATTENTION or any(outcome.get(key) for key in _COUNTS_NEEDING_ATTENTION):
        return ATTENTION
    if (outcome.get('details') or {}).get('probe_errors'):
        return ATTENTION
    return INFORMATION


def lines_label(count) -> str:
    """"Show the 2 lines not understood", "Show the line not understood"."""
    from . import texts
    return 'Show the line not understood' if count == 1 else f'Show the {texts.fmt_count(count)} lines not understood'


def action_keys(tool, outcome, *, lines=0, can_repeat=True) -> list:
    """The actions an outcome of ``tool`` offers, in button order.

    - **Sign in again** when the worker said the typed password was refused (`texts.sign_in_again`), and then no Retry:
      it repeats the same request and asks for the password.
    - **Retry** and **Open Settings** for an error (the error tone) of a tool that can be repeated / whose errors can
      come from its settings; Retry only while the request is still known (``can_repeat``).
    - **Show the N lines not understood** when the page lists some (``lines`` of them).
    """
    from . import texts
    keys = []
    if texts.sign_in_again(outcome):
        keys.append('sign_in_again')
    elif tone_for(outcome) == ERROR:
        if tool in RETRY_TOOLS and can_repeat:
            keys.append('retry')
        if tool in SETTINGS_TOOLS:
            keys.append('open_settings')
    if lines:
        keys.append('show_lines')
    return keys


def actions_for(tool, outcome, handlers, *, lines=0, can_repeat=True) -> list:
    """`action_keys` as `Action` objects. ``handlers`` maps a key to what the button does; a key with no handler on
    this page is left out."""
    labels = {'sign_in_again': SIGN_IN_AGAIN, 'retry': RETRY, 'open_settings': OPEN_SETTINGS,
              'show_lines': lines_label(lines)}
    return [Action(key, labels[key], handlers[key], primary=key == 'sign_in_again')
            for key in action_keys(tool, outcome, lines=lines, can_repeat=can_repeat) if key in handlers]


def repeat(controller, tool):
    """Submit ``tool``'s last request again and return it (the page puts its inputs back on the form). Raises
    ``RuntimeError`` with the reason when there is none to repeat or the controller refuses it."""
    request = controller.last_request(tool)
    if not request:
        raise RuntimeError(NO_REQUEST)
    if tool == 'demob':
        controller.submit_demob_lookup(request['site'])
    else:
        extra = {key: request[key] for key in ('tcp_ports', 'interval_seconds', 'duration_seconds') if key in request}
        if isinstance(request.get('typed'), str):
            extra['typed'] = request['typed']
        controller.submit(request['inputs'], lookup_type=tool, **extra)
    return request


def open_settings():
    """What the Open Settings action does."""
    from nicegui import ui
    ui.navigate.to('/settings')


SHOW_LINES_SCRIPT = '''(() => {
  const root = document.querySelector('[data-lines-not-understood]');
  if (!root) return;
  let head;
  if (root.tagName === 'DETAILS') { root.open = true; head = root.querySelector('summary'); }
  else {
    head = root.querySelector('.q-item');
    if (root.classList.contains('q-expansion-item--collapsed')) head.click();
  }
  head?.focus();
  root.scrollIntoView({block: 'nearest'});
})()'''


def show_lines():
    """What the Show the N lines not understood action does: open the page's list of them (the element marked
    ``data-lines-not-understood``) and put the focus on its header."""
    from nicegui import ui
    ui.run_javascript(SHOW_LINES_SCRIPT)


# --- drawing ---------------------------------------------------------------------------------------------------------

def _css(client):
    from .scope import add_once
    add_once(client, 'outcome', css=CSS)


def outcome_banner(tone, title, detail='', actions=(), *, heading=True, escaped=False, marker=''):
    """Draw the banner where the page calls it and return its parts: ``.box``, ``.title`` (the element that takes the
    focus) and ``.html_id`` of the title; ``.update(...)`` shows another outcome in the same elements.

    @param tone: INFORMATION, ATTENTION or ERROR.
    @param title: what the user got, in one line. ``escaped`` True when it is already HTML-escaped.
    @param detail: an optional second line.
    @param actions: `Action` objects; the primary one is drawn filled.
    @param heading: the title is an h2 (the page has no heading of its own for it); False for a page whose own
        heading ("Latest check") already names the area.
    @param marker: a data attribute name put on the title, for a page that finds it to focus it.
    """
    from nicegui import ui
    tone = tone if tone in TONE_WORDS else INFORMATION
    _css(ui.context.client)
    with ui.element('div').classes(f'cn-outcome cn-outcome-{tone}').props(f'data-outcome-tone={tone}') as box:
        with ui.element('div').classes('cn-outcome-voice').props('role=status aria-live=polite'):
            with ui.element('span').classes('cn-outcome-mark'):
                icon = ui.html(_icon(tone))
                word = ui.label(TONE_WORDS[tone])
            with ui.element('h2' if heading else 'p').classes('cn-outcome-title').props(
                    'tabindex=-1' + (f' {marker}' if marker else '')) as title_element:
                text = (ui.html if escaped else ui.label)(title)
            detail_element = ui.label(detail).classes('cn-outcome-detail')
            detail_element.set_visibility(bool(detail))
        action_box = ui.element('div').classes('cn-outcome-actions')
        _draw_actions(action_box, actions)
    return _Parts(box, title_element, text, icon, word, detail_element, action_box, tone, escaped)


def _icon(tone):
    return (f'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
            f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">{_ICONS[tone]}</svg>')


def _draw_actions(container, actions):
    from nicegui import ui
    with container:
        for action in actions:
            ui.button(action.label, on_click=action.on_click).props(
                f'{"color=primary" if action.primary else "outline"} data-outcome-action={action.key}'
                + (' data-sign-in-again' if action.key == 'sign_in_again' else ''))


@dataclass
class _Parts:
    box: object
    title: object
    text: object
    icon: object
    word: object
    detail: object
    actions: object
    tone: str
    escaped: bool

    @property
    def html_id(self):
        return self.title.html_id

    def update(self, tone, title, detail='', actions=()):
        """Show another outcome in the elements that are there. The live region (``.cn-outcome-voice``) is never
        replaced: a screen reader announces a change of text in a region it already knows, and often misses one that
        arrives inside a new region."""
        tone = tone if tone in TONE_WORDS else INFORMATION
        if tone != self.tone:
            self.box.classes(remove=f'cn-outcome-{self.tone}', add=f'cn-outcome-{tone}')
            self.box._props['data-outcome-tone'] = tone
            self.box.update()
            self.icon.set_content(_icon(tone))
            self.word.set_text(TONE_WORDS[tone])
            self.tone = tone
        (self.text.set_content if self.escaped else self.text.set_text)(title)
        self.detail.set_text(detail)
        self.detail.set_visibility(bool(detail))
        self.actions.clear()
        _draw_actions(self.actions, actions)


class Banner:
    """A banner of a page that updates from a poll. Draw it with ``Banner()`` where the page wants it, then
    ``set(tone, title, ...)`` on each poll: nothing is touched while what is shown is the same, so the focus and a
    click in progress on an action are not lost. Its live region is drawn once and a change updates the text in it
    (`_Parts.update`). ``hide()`` removes it from the page's flow and empties it, and the next ``set`` fills the same
    elements."""

    def __init__(self, **options):
        from nicegui import ui
        self.options, self.shown, self.parts = options, None, None
        self.container = ui.element('div').classes('w-full')
        self.container.set_visibility(False)

    def set(self, tone, title, detail='', actions=()):
        """Show the banner. Returns True when it changed."""
        key = (tone, title, detail, tuple(actions))
        self.container.set_visibility(True)
        if key == self.shown:
            return False
        self.shown = key
        if self.parts is None:
            with self.container:
                self.parts = outcome_banner(tone, title, detail, actions, **self.options)
        else:
            self.parts.update(tone, title, detail, actions)
        return True

    def hide(self):
        if self.shown is not None:
            self.shown = None
            if self.parts is not None:
                self.parts.update(self.parts.tone, '', '', ())
        self.container.set_visibility(False)

    @property
    def title(self):
        return self.parts.title if self.parts else None
