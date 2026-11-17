"""One dialog helper for the web pages (`confirm_dialog`, `credentials_dialog`).

Plan: `docs/plans/webui-ux-plan.md` section 3.4. `report_actions.ReportDeleteAction` keeps its own dialog.

The sign-in dialog (`credentials_dialog`) handles a password. Its rules:

- the user name and the password are native inputs: no value is bound to the page's script or kept on the server
  while the user types;
- they are read once, in the browser, when the user submits, and the fields are emptied before the values are sent;
- a dialog that goes away for any other reason (another tab answered, the request was replaced, the session ended)
  has its fields emptied before its elements are removed;
- nothing here logs, prints or stores a value. The reply goes to ``on_reply`` and nowhere else;
- a dialog that stays open while Infoblox checks the password (`CredentialsDialog.wait`) holds an empty Password
  field, and so does the same dialog when it asks again after a refusal (`CredentialsDialog.refuse`).
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from html import escape

# Browser side. 'before-show' remembers the element that had focus (the opener) and installs a document-level keydown
# listener that wraps Tab and Shift+Tab inside the card (Quasar traps Tab forward only; the listener is ready before
# the show transition ends, so a key pressed at once is trapped too). 'hide' removes the listener, gives focus back to
# the opener, or to the caller's fallback when the opener is gone or disabled, and then tells the server to remove
# the dialog. Dialogs can stand on one another (the sign-in dialog over an open confirmation or Help): each has its
# own listener, and a listener acts only while its card is in the dialog on top (the last `.q-dialog` of the
# document: Quasar adds each dialog to the end of the body when it shows), so two never move the focus against
# each other and the one below has the trap again when the one on top has gone.
_TRAP = '''const trap = (event) => {
  const card = document.getElementById(%(card)s);
  if (event.key !== 'Tab' || !card) return;
  const layers = document.querySelectorAll('.q-dialog');
  if (card.closest('.q-dialog') !== layers[layers.length - 1]) return;
  const items = [...card.querySelectorAll('button, [href], input, select, textarea, [tabindex]')]
    .filter((item) => !item.disabled && item.tabIndex >= 0 && item.getClientRects().length);
  if (!items.length) { event.preventDefault(); return; }
  const first = items[0], last = items[items.length - 1], active = document.activeElement;
  if (event.shiftKey && (active === first || !card.contains(active))) { event.preventDefault(); last.focus(); }
  else if (!event.shiftKey && (active === last || !card.contains(active))) { event.preventDefault(); first.focus(); }
};
'''

_REMEMBER = '''() => { window.cnDialogOpeners = window.cnDialogOpeners || {};
window.cnDialogTraps = window.cnDialogTraps || {};
let opener = document.activeElement?.closest('button, a[href], [tabindex]:not([tabindex="-1"])') || document.activeElement;
if (!opener || opener === document.body || opener === document.documentElement) {
  // A click can leave no focus at all: the opener is then the focusable element under the pointer.
  const hovered = [...document.querySelectorAll('button:hover, a[href]:hover, [tabindex]:not([tabindex="-1"]):hover')].filter((item) => !item.disabled);
  opener = hovered.length ? hovered[hovered.length - 1] : null;
}
window.cnDialogOpeners[%(card)s] = opener;
''' + _TRAP + '''window.cnDialogTraps[%(card)s] = trap;
document.addEventListener('keydown', trap, true); }'''

_RETURN = '''() => { const opener = (window.cnDialogOpeners || {})[%(card)s];
const trap = (window.cnDialogTraps || {})[%(card)s];
if (trap) document.removeEventListener('keydown', trap, true);
if (window.cnDialogOpeners) delete window.cnDialogOpeners[%(card)s];
if (window.cnDialogTraps) delete window.cnDialogTraps[%(card)s];
const usable = (item) => item && item.isConnected && !item.disabled;
let target = usable(opener) ? opener : null;
if (!target && %(fallback)s) { const named = document.querySelector(%(fallback)s); if (usable(named)) target = named; }
if (target) target.focus({preventScroll: true});
emit(); }'''


# The trap alone, for a dialog that is opened and closed in place (Help): Quasar gives the focus back itself.
_TRAP_ON = '''() => { window.cnDialogTraps = window.cnDialogTraps || {};
if (window.cnDialogTraps[%(card)s]) document.removeEventListener('keydown', window.cnDialogTraps[%(card)s], true);
''' + _TRAP + '''window.cnDialogTraps[%(card)s] = trap;
document.addEventListener('keydown', trap, true); }'''

_TRAP_OFF = '''() => { const trap = (window.cnDialogTraps || {})[%(card)s];
if (trap) { document.removeEventListener('keydown', trap, true); delete window.cnDialogTraps[%(card)s]; } }'''


def trap_focus(dialog, card) -> None:
    """Wrap Tab and Shift+Tab inside ``card`` while ``dialog`` is open, as `confirm_dialog` does (see `_TRAP`)."""
    values = {'card': json.dumps(card.html_id)}
    dialog.on('before-show', js_handler=_TRAP_ON % values)
    dialog.on('hide', js_handler=_TRAP_OFF % values)


_ASKING = 'cn_confirm_open'  # set on the NiceGUI client while its confirmation is open


async def confirm_dialog(title: str, lines: Sequence[str], *, confirm: str, cancel: str = 'Cancel',
                         danger: bool = False, note: str = '', fallback: str | None = None) -> bool:
    """Ask the user to confirm; True only for the confirm button.

    Cancel comes first and holds the first focus; Escape, a click outside and Cancel all answer False. The dialog is
    named by its title, Tab and Shift+Tab wrap inside the card, and focus returns to the element that opened it, or
    to the first element matching the CSS selector `fallback` when that element is gone.

    One question at a time per tab: a call made while this tab's confirmation is open (Enter pressed twice on the
    opener, before the dialog takes the focus) answers False at once and opens nothing.
    """
    from nicegui import ui
    client = ui.context.client
    if getattr(client, _ASKING, False):
        return False
    setattr(client, _ASKING, True)
    try:
        return await _ask(title, lines, confirm, cancel, danger, note, fallback)
    finally:
        setattr(client, _ASKING, False)


async def _ask(title, lines, confirm, cancel, danger, note, fallback):
    from nicegui import ui
    with ui.dialog().props('no-refocus') as dialog:
        with ui.card().classes('w-full').style('max-width: 540px; overflow-wrap: anywhere') as card:
            heading = ui.label(title).classes('text-h6').props('role=heading aria-level=2')
            for line in lines:
                ui.label(line)
            if note:
                ui.label(note).classes('cn-muted')
            with ui.row().classes('w-full justify-end'):
                ui.button(cancel, on_click=lambda: dialog.submit(False)).props('outline autofocus data-dialog-cancel')
                ui.button(confirm, on_click=lambda: dialog.submit(True)).props(
                    ('color=negative' if danger else 'color=primary') + ' data-dialog-confirm')
        dialog.props(f'aria-labelledby={heading.html_id}')
    values = {'card': json.dumps(card.html_id), 'fallback': json.dumps(fallback or '')}
    dialog.on('before-show', js_handler=_REMEMBER % values)
    dialog.on('hide', js_handler=_RETURN % values, handler=dialog.delete)
    dialog.open()
    result = await dialog
    return result is True


# --- Sign in -------------------------------------------------------------------------------------------------------

SIGN_IN_NOTE = 'cn-tool uses this login for Infoblox lookups until you quit.'
SIGN_IN = 'Sign in'
SIGN_IN_AGAIN = 'Sign in again'
FORGET = 'Forget saved credentials'
REMEMBER = 'Remember credentials on this computer'
USERNAME_REQUIRED = 'Enter the user name.'
PASSWORD_REQUIRED = 'Enter the password.'
CHECKING = 'Checking the password…'
PASSWORD_REFUSED = 'Password not accepted.'
# cn-tool cannot know the grid's lockout rule or how often the account was refused before: it says only this.
LOCKOUT = 'A new password is a sign-in at Infoblox. Repeated refusals can lock the account.'


def tries_line(tries_left) -> str:
    """Under "Password not accepted.": how many passwords this lookup still takes (the one being asked for
    included), and why there is a limit. '' when the request names no count."""
    if type(tries_left) is not int or tries_left < 1:
        return ''
    return f'You can try {tries_left} more {"time" if tries_left == 1 else "times"} in this lookup. {LOCKOUT}'


def sign_in_title(request) -> str:
    """The dialog's title: which login is asked for and, when the name is known and fixed, for whom.

    "Sign in to Infoblox as alice" for Infoblox's own account, "Sign in with your network login as alice" for the
    device login. Without a known name, or while the name can still be typed, no "as …"."""
    account = str(request.get('account') or '').strip().lower()
    title = 'Sign in to Infoblox' if account == 'infoblox' else 'Sign in with your network login'
    name = str(request.get('username') or '').strip()
    return f'{title} as {name}' if name and not request.get('need_username') else title


def saved_login(store, restored=False) -> bool:
    """Whether to offer "Forget saved credentials": the credential store's latest answer says a login is saved.

    ``store`` is the snapshot's ``credential_store`` (or None), ``restored`` its ``saved_login_restored``. Found or
    just saved: yes. Not found or forgotten: no. A save or a deletion on its way, and a failure whose outcome is
    unknown: yes, so that Forget can be tried (again). An answer that says nothing about the login (a timeout, a
    cancelled operation, no answer yet) leaves it to whether this session signed in with a saved login."""
    status = (store or {}).get('status')
    if status in ('deleted', 'missing'):
        return False
    if status in ('loaded', 'saved', 'pending', 'error'):
        return True
    return bool(restored)


_SIGN_IN_CSS = '''
.cn-signin { max-width:28rem; overflow-wrap:anywhere; }
.cn-signin-fields { display:flex; flex-direction:column; gap:6px; width:100%; }
.cn-signin-fields label { font-weight:600; margin-top:6px; }
.cn-signin-fields input:not([type=checkbox]) { width:100%; min-height:40px; padding:8px 10px; border:1px solid var(--cn-field-line);
  border-radius:4px; background:var(--cn-panel); color:var(--cn-ink); font:inherit; }
.cn-signin-fields input[readonly] { background:var(--cn-page); }
.cn-signin-fields .cn-signin-remember { display:flex; align-items:center; gap:8px; font-weight:400; margin-top:4px; }
.cn-signin [role=status]:empty { display:none; }
.cn-signin-error { color:var(--cn-error-ink); }
.cn-signin-error:empty { display:none; }
.cn-signin-more { color:var(--cn-muted); }
.cn-signin-more:empty { display:none; }
'''

# Read the fields once, empty them, then send: nothing typed leaves the browser before this, and nothing typed is
# left in a field after it (the user name stays when a password goes with it: the dialog may stay open while
# Infoblox checks, and closing empties both). `cnAnswered` makes it once: a second Enter or click sends nothing,
# except Cancel or Escape while the dialog waits for Infoblox (`cnWaiting`), which is sent once. Enter counts only in
# the two text fields (not on the checkbox or a button, whose own key it is) and not while an input method composes.
# A field that is asked for is never sent empty: Enter in a filled Username moves on to an empty Password, and
# otherwise the empty field gets the focus and says so in its error line (its description, `aria-invalid`).
_ANSWER = '''(event) => {
const card = document.getElementById(%(card)s);
if (!card) return;
if (card.dataset.cnAnswered) {
  if (%(cancel)s && card.dataset.cnWaiting) { delete card.dataset.cnWaiting; emit({cancel: true, username: '', password: '', remember: false}); }
  return;
}
if (%(enter)s && (event?.isComposing || !event?.target?.matches?.('input:not([type=checkbox])'))) return;
const u = document.getElementById(%(username)s);
const p = document.getElementById(%(password)s);
const r = document.getElementById(%(remember)s);
if (!%(cancel)s) {
  const asked = [[u, %(need_username)s && !u?.value.trim(), %(username_required)s], [p, !!p && !p.value, %(password_required)s]];
  const forward = %(enter)s && event.target === u && !asked[0][1] && asked[1][1];
  let empty = null;
  for (const [field, missing, text] of asked) {
    const error = field && document.getElementById(field.id + '-error');
    if (!error) continue;
    const say = missing && !forward;
    error.textContent = say ? text : '';
    if (say) field.setAttribute('aria-invalid', 'true'); else field.removeAttribute('aria-invalid');
    if (missing && !empty) empty = field;
  }
  if (empty) { empty.focus(); return; }
}
const reply = {cancel: %(cancel)s, username: %(cancel)s ? '' : (u?.value || ''), password: %(cancel)s ? '' : (p?.value || ''), remember: !%(cancel)s && !!r?.checked};
card.dataset.cnAnswered = '1';
if (u && (%(cancel)s || !p)) u.value = ''; if (p) p.value = '';
emit(reply);
}'''

# A click leaves the focus on a helper inside a Quasar button: the opener is the control around it.
_CAPTURE = '''(() => { window.cnCredentialInvoker = document.activeElement;
window.cnCredentialInvoker = window.cnCredentialInvoker?.closest?.('button, a[href], input, textarea, select, [tabindex]:not([tabindex="-1"])') || window.cnCredentialInvoker;
return true; })()'''

_OPENED = '''(() => { window.cnDialogTraps = window.cnDialogTraps || {};
''' + _TRAP + '''window.cnDialogTraps[%(card)s] = trap;
document.addEventListener('keydown', trap, true);
requestAnimationFrame(() => document.getElementById(%(focus)s)?.focus()); })()'''

# The dialog that stays open: 'checking' while Infoblox has the password (fields read-only, Cancel live), 'refused'
# when it asks again (Password empty and in focus, the alert and the tries line), 'open' for a first request.
# The alert is emptied while checking, so that a second refusal is announced again.
_STATE = '''(() => { const card = document.getElementById(%(card)s); if (!card) return;
const u = document.getElementById(%(username)s), p = document.getElementById(%(password)s);
const state = %(state)s;
const say = (suffix, text) => { const line = p && document.getElementById(p.id + suffix); if (line) line.textContent = text; };
if (state === 'checking') card.dataset.cnWaiting = '1';
else { delete card.dataset.cnWaiting; if (%(again)s) delete card.dataset.cnAnswered; }
for (const field of [u, p]) {
  if (!field) continue;
  if (state === 'checking' || (field === u && !%(need_username)s)) field.setAttribute('readonly', ''); else field.removeAttribute('readonly');
}
const remember = card.querySelector('input[type=checkbox]');
if (remember) remember.disabled = state === 'checking';
say('-checking', state === 'checking' ? %(checking)s : '');
say('-refused', state === 'refused' ? %(refused)s : '');
say('-more', state === 'refused' ? %(more)s : '');
if (!p) return;
if (%(again)s) { if (u) u.value = %(name)s; p.value = ''; }
if (state === 'refused') p.setAttribute('aria-invalid', 'true');
if (%(focus)s) p.focus();
})()'''

_EMPTY = '''(() => { for (const id of %(fields)s) { const field = document.getElementById(id); if (field) field.value = ''; }
return true; })()'''

# After the dialog: the Tab trap goes, and focus goes to the element that had it when the dialog opened, else to the
# first of the caller's fallbacks that can take it. With `wait`, when none can yet (Run is disabled until the job the
# cancelled sign-in belonged to has ended), the first that becomes usable gets it, for as long as focus rests on
# nothing the user could have chosen; it never takes focus away from a control.
_RESTORE = '''(() => {
const trap = (window.cnDialogTraps || {})[%(card)s];
if (trap) { document.removeEventListener('keydown', trap, true); delete window.cnDialogTraps[%(card)s]; }
const control = 'button, input, textarea, select, a[href], [tabindex]:not([tabindex="-1"])';
const usable = (el) => el && el.isConnected && el.matches(control) && !el.matches(':disabled') && !el.closest('[disabled], [aria-disabled="true"]') && el.getClientRects().length > 0;
const opener = window.cnCredentialInvoker; window.cnCredentialInvoker = null;
const pick = () => [opener, ...%(fallback)s.map((selector) => document.querySelector(selector))].find(usable);
const unclaimed = () => { const active = document.activeElement; return !active || active === document.body || !active.matches(control + ', [contenteditable]:not([contenteditable="false"])'); };
const target = pick();
if (target) { target.focus({preventScroll: true}); return; }
if (!%(wait)s) return;
let timer = 0;
const observer = new MutationObserver(() => {
  const found = unclaimed() ? pick() : null;
  if (found || !unclaimed()) { observer.disconnect(); clearTimeout(timer); }
  if (found) found.focus({preventScroll: true});
});
timer = setTimeout(() => observer.disconnect(), 15000);
observer.observe(document.body, {subtree: true, childList: true, attributes: true, attributeFilter: ['disabled', 'aria-disabled', 'style', 'class']});
})()'''


# A dialog whose page was left: the fields are emptied (if they are still there) and the Tab trap goes.
_DISCARD = '''(() => { for (const id of %(fields)s) { const field = document.getElementById(id); if (field) field.value = ''; }
const trap = (window.cnDialogTraps || {})[%(card)s];
if (trap) { document.removeEventListener('keydown', trap, true); delete window.cnDialogTraps[%(card)s]; } })()'''


async def credentials_opener(client) -> None:
    """Remember, in the browser, which element has focus now: where focus returns after the sign-in dialog. Awaited
    before the dialog is built, so the caller can check afterwards that the request is still the current one."""
    await client.run_javascript(_CAPTURE)


class CredentialsDialog:
    """An open sign-in dialog (`credentials_dialog`). The page keeps it to close it and to refresh its store line."""

    def __init__(self, request, dialog, card_id, field_ids, fallback, store_status, saved, status, forget, submit):
        self.request_id = request['request_id']
        self.dialog = dialog
        self.client = dialog.client
        self.answered = False
        self.waiting = False  # a password was submitted and Infoblox has not answered (`wait`)
        self.stopping = False  # Cancel was chosen while waiting
        self._shape, self._submit = _shape(request), submit
        self._card_id, self._field_ids, self._fallback = card_id, field_ids, list(fallback)
        self._store_status, self._saved, self._status, self._forget = store_status, saved, status, forget
        self._closed = False

    def refresh(self) -> None:
        """Show the credential store's latest message, and Forget only while a login is saved."""
        text = str(self._store_status() or '')
        if self._status.text != text:
            self._status.set_text(text)
        if self._forget is not None:
            saved = bool(self._saved())
            if self._forget.visible != saved:
                self._forget.set_visibility(saved)

    def wait(self) -> None:
        """Stay open while Infoblox checks the submitted password: the fields are read-only (Password is empty
        already), Sign in is off, Cancel and Escape stay and are reported to ``on_reply`` once, as None."""
        self.waiting = True
        self._submit.disable()
        self._show('checking')

    def refuse(self, request) -> bool:
        """Ask again in this dialog: Infoblox refused the password, and ``request`` is the worker's next one.

        True when the dialog took the request (it then answers under the new request id). False when it cannot:
        it was not waiting, Cancel was chosen while it waited, ``request`` does not say ``refused``, or it asks for something else than this dialog
        was built for; the caller then closes it and opens a new one."""
        if self._closed or not self.waiting or self.stopping or not request.get('refused') or _shape(request) != self._shape:
            return False
        self.request_id = request['request_id']
        self.waiting = self.stopping = self.answered = False
        self._submit.enable()
        self._show('refused', request, again=True)
        return True

    def _show(self, state, request=None, *, again=False, focus=True) -> None:
        request = request or {}
        need_username = self._shape[1]
        self.client.run_javascript(_STATE % {
            'card': json.dumps(self._card_id), 'username': json.dumps(self._field_ids[0]),
            'password': json.dumps(self._field_ids[1]), 'state': json.dumps(state), 'again': json.dumps(again),
            'need_username': json.dumps(need_username), 'checking': json.dumps(CHECKING),
            'refused': json.dumps(PASSWORD_REFUSED), 'more': json.dumps(tries_line(request.get('tries_left'))),
            'name': json.dumps(str(request.get('username') or '')), 'focus': json.dumps(focus)})

    async def close(self, *, restore=True, wait=True) -> None:
        """Empty the fields in the browser, then remove the dialog; ``restore`` gives focus back (`restore_focus`).

        The emptying is awaited before the elements go, so that a detached field cannot keep what was typed when
        another tab answered the same request."""
        if self._closed:
            return
        self._closed = True
        try:
            await self.client.run_javascript(_EMPTY % {'fields': json.dumps(self._field_ids)})
        finally:
            self.dialog.close()
            self.dialog.delete()
            if restore:
                self.restore_focus(wait=wait)

    def discard(self) -> None:
        """Remove the dialog at once, its fields with it, without giving focus back: the page it was opened on has
        been left. Its Tab trap leaves the document with it."""
        if self._closed:
            return
        self._closed = True
        self.client.run_javascript(_DISCARD % {'card': json.dumps(self._card_id), 'fields': json.dumps(self._field_ids)})
        self.dialog.close()
        self.dialog.delete()

    def restore_focus(self, *, wait=True) -> None:
        """Give focus back to the opener, else to the first usable fallback (see `_RESTORE`)."""
        self.client.run_javascript(_RESTORE % {'card': json.dumps(self._card_id), 'fallback': json.dumps(self._fallback),
                                               'wait': json.dumps(bool(wait))})


def _shape(request):
    """What a sign-in dialog is built for: a request of another shape needs another dialog."""
    need_username = bool(request.get('need_username', False))
    return (str(request.get('account') or ''), need_username, bool(request.get('need_password', True)),
            bool(request.get('store_supported')), None if need_username else str(request.get('username') or ''))


def credentials_dialog(request: dict, *, on_reply, store_status, saved=None, on_forget=None,
                       fallback: Sequence[str] = ()) -> CredentialsDialog:
    """Open the sign-in dialog for the worker's credential ``request`` and return it.

    ``on_reply(dialog, reply, remember)`` is awaited once, when the user submits (a
    ``cn_tool.core.interaction.CredentialReply``) or cancels (None); after `CredentialsDialog.wait` a Cancel is
    reported once more, as None, and after `CredentialsDialog.refuse` the next answer is. A ``request`` that says
    ``refused`` opens with "Password not accepted." and the tries line (`tries_line`). ``store_status()`` is the credential store's
    message, ``saved()`` whether a login is saved (Forget is drawn only with ``on_forget`` and shown only while it
    is); both are read again by ``CredentialsDialog.refresh``. ``fallback`` are CSS selectors for focus after the
    dialog, tried in order when the element that had focus before is gone or disabled.

    Call ``credentials_opener`` first. The dialog is named by its title, Cancel comes before Sign in, Enter in a
    field submits (Enter in Username moves to an empty Password; a field that is asked for is never sent empty, and
    says so), Escape cancels, Tab and Shift+Tab wrap inside the card, and first focus is the field to fill in.
    The core's hint (``request['message']``) is for the command line and is not shown.
    """
    from nicegui import ui
    from cn_tool.core.interaction import CredentialReply

    from .scope import add_once

    add_once(ui.context.client, 'sign-in', css=_SIGN_IN_CSS)
    need_username = bool(request.get('need_username', False))
    need_password = bool(request.get('need_password', True))
    with ui.dialog().props('persistent no-refocus') as dialog, ui.card().classes('w-full cn-signin') as card:
        heading = ui.label(sign_in_title(request)).classes('text-h6').props('role=heading aria-level=2')
        ui.label(SIGN_IN_NOTE)
        status = ui.label('').props('role=status aria-live=polite').classes('cn-muted')
        username_id, password_id, remember_id = (f'credential-{name}-{dialog.id}' for name in ('username', 'password', 'remember'))
        # Fixed local markup; the configured user name is escaped. Vue must not bind these values: a status update
        # elsewhere on the page must not reset them, and the server must not see them before the user submits.
        fields = (f'<label for="{username_id}">Username</label>'
                  f'<input id="{username_id}" aria-label="Username" autocomplete="username" autocapitalize="none" '
                  f'spellcheck="false" value="{escape(str(request.get("username") or ""), quote=True)}"'
                  f' aria-describedby="{username_id}-error"{"" if need_username else " readonly"}>'
                  f'<span id="{username_id}-error" class="cn-signin-error" role="alert"></span>')
        if need_password:
            fields += (f'<label for="{password_id}">Password</label>'
                       f'<input id="{password_id}" aria-label="Password" type="password" autocomplete="current-password" '
                       f'aria-describedby="{password_id}-error {password_id}-refused {password_id}-more">'
                       f'<span id="{password_id}-error" class="cn-signin-error" role="alert"></span>'
                       f'<span id="{password_id}-refused" class="cn-signin-error" role="alert"></span>'
                       f'<span id="{password_id}-more" class="cn-signin-more"></span>'
                       f'<span id="{password_id}-checking" class="cn-signin-more" role="status"></span>')
        if need_password and request.get('store_supported'):
            fields += f'<label class="cn-signin-remember"><input id="{remember_id}" type="checkbox"> {REMEMBER}</label>'
        inputs = ui.html(fields, sanitize=False).classes('cn-signin-fields')
        forget = None
        with ui.row().classes('w-full items-center justify-between'):
            if on_forget is not None:
                forget = ui.button(FORGET, on_click=on_forget).props('flat dense data-signin-forget')
                forget.set_visibility(False)
            else:
                ui.element('span')
            with ui.row().classes('items-center'):
                cancel = ui.button('Cancel').props('outline data-dialog-cancel')
                submit = ui.button(SIGN_IN).props('color=primary data-dialog-confirm')
        dialog.props(f'aria-labelledby={heading.html_id}')
    opened = CredentialsDialog(request, dialog, card.html_id, [username_id, password_id], fallback, store_status,
                               saved or (lambda: False), status, forget, submit)

    async def reply(event):
        values = event.args
        if opened.waiting:
            if values['cancel'] and not opened.stopping:
                opened.stopping = True
                await on_reply(opened, None, False)
            return
        if opened.answered:
            return
        opened.answered = True
        answer = None if values['cancel'] else CredentialReply(values['username'], values['password'])
        await on_reply(opened, answer, bool(values['remember']))

    def handler(cancel, enter=False):
        return _ANSWER % {'card': json.dumps(card.html_id), 'username': json.dumps(username_id),
                          'password': json.dumps(password_id), 'remember': json.dumps(remember_id),
                          'cancel': json.dumps(cancel), 'enter': json.dumps(enter),
                          'need_username': json.dumps(need_username), 'username_required': json.dumps(USERNAME_REQUIRED),
                          'password_required': json.dumps(PASSWORD_REQUIRED)}

    submit.on('click', reply, js_handler=handler(False))
    cancel.on('click', reply, js_handler=handler(True))
    inputs.on('keydown.enter', reply, js_handler=handler(False, enter=True))
    dialog.on('keydown.escape', reply, js_handler=handler(True))
    opened.refresh()
    dialog.open()
    refused = need_password and request.get('refused') is True
    named = refused and bool(str(request.get('username') or '').strip())  # the name of the refused try is filled in
    focus_id = username_id if need_username and not named else password_id if need_password else username_id
    ui.run_javascript(_OPENED % {'card': json.dumps(card.html_id), 'focus': json.dumps(focus_id)})
    if refused:
        opened._show('refused', request, focus=False)
    return opened
