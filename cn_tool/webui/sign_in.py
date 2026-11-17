"""The sign-in dialog of a lookup page, from the worker's request to the answer (`SignInFlow`).

A page builds one flow and calls `SignInFlow.follow` from its poll. The flow opens `dialogs.credentials_dialog` for
the controller's current credential request, sends the answer, and closes the dialog when the request is gone.
After a password was sent the dialog stays open while Infoblox checks it (`SessionController.sign_in_checking`):
a refusal that asks again (`credentials_required` with ``refused``) is shown in the same dialog, and anything else
(the login was used, the lookup ended or is stopping) closes it. Cancel in the waiting dialog stops the lookup.

Nothing here keeps, logs or prints a typed value: the reply goes from the dialog to
`SessionController.reply_credentials` and the fields are emptied by `dialogs` (see its module text).
"""
from __future__ import annotations

import asyncio
from weakref import WeakKeyDictionary, WeakSet

from . import dialogs

# controller -> the flows of its tabs' pages (WeakSet): which connected tab shows a dialog for which request. A flow
# leaves it when its page is left; a closed tab's flows go with the page (weak), so a deleted client is never kept.
_FLOWS = WeakKeyDictionary()
# tab_state keys (scope.tab_state, dropped with the client): the job this tab started last (one job runs at a time in
# a session, so the latest is the only one that can be asking), and the requests this tab left a dialog for.
STARTED = 'sign-in-started'
LEFT = 'sign-in-left'


class SignInFlow:
    """One page's sign-in dialog.

    ``fallback()`` gives the CSS selectors for focus after the dialog, ``store()`` the snapshot's
    ``credential_store`` (a dict), ``restored()`` its ``saved_login_restored``; ``after_reply()`` is awaited after an
    answer was sent, so that the page shows the new state before focus goes back. ``client`` is the page's NiceGUI
    client (the one in context when the dialog opens, by default). ``active_job()`` gives the id of the session's
    running job and ``started(job)`` is told of each job a page starts (kept for the tab): together they say whether a
    request is this tab's (see ``leave``).
    """

    def __init__(self, controller, *, fallback, store, restored, after_reply, client=None, active_job=None):
        self.controller, self.client = controller, client
        self._fallback, self._store, self._restored, self._after_reply = fallback, store, restored, after_reply
        self._active_job = active_job
        self.lock = asyncio.Lock()
        self.dialog = None
        self.prompt = None  # the request id that the open dialog answers
        self.left = False  # the page was left: nothing is opened any more
        _FLOWS.setdefault(controller, WeakSet()).add(self)

    def started(self, job) -> None:
        """A page of this tab started the job ``job`` (a lookup or a confirmed search)."""
        if job:
            self._tab()[STARTED] = job

    def _tab(self):
        from .scope import tab_state
        client = self.client
        if client is None:
            from nicegui import ui
            client = ui.context.client
        return tab_state(client)

    def refresh(self) -> None:
        """The credential store's line and Forget in the open dialog."""
        if self.dialog is not None:
            self.dialog.refresh()

    async def follow(self) -> None:
        """Bring the dialog in line with the controller's credential request (from the page's poll)."""
        async with self.lock:
            if self.left:
                return
            request = self.controller.current_credential_request()
            request_id = request['request_id'] if request else None
            dialog = self.dialog
            if dialog is not None and dialog.waiting:
                if request is None and self.controller.sign_in_checking():
                    return  # Infoblox has the password: the dialog waits for the verdict
                if request is not None and dialog.stopping:
                    return  # Cancel was chosen: the request is answered with nothing, not asked again
                if request is not None and dialog.refuse(request):
                    self.prompt = request_id
                    return
            if request_id != self.prompt:
                # A dialog that waited goes because the login was used (focus as after any sign-in) or because
                # the lookup was stopped from it (focus returns to Run once Run is enabled again).
                await self._clear(wait=dialog is None or not dialog.waiting or dialog.stopping)
                self.prompt = None
                request = self.controller.current_credential_request()
                if request and not self._left(request['request_id']) and await self._open(request):
                    self.prompt = request['request_id']

    def leave(self) -> None:
        """The page is left for another tool of the tab (its ``PageScope`` ends while the tab is connected): the dialog
        goes with it, and with the dialog its Tab trap. The request belongs to the session, not to the tab, and every
        tab that shows a sign-in dialog shows this one, so one rule decides (R2-09 review and R2-10, merged):

        - it is answered as cancelled only when this tab started the job that asks (``started``) and no other
          connected tab shows a dialog for that request: nobody else is left to answer it;
        - otherwise it stands. While another connected tab shows the dialog for it, this tab does not ask for it
          again on any of its pages (``LEFT``; that tab answers). When none does, the next page that asks, in any
          tab and this one included, shows the dialog again, as when a tab is closed; the lookup waits for an
          answer or for Stop.

        A dialog that waits for Infoblox's verdict has no request to answer: the check goes on, and a request that
        follows is asked for on the page's next visit."""
        dialog, prompt = self.dialog, self.prompt
        self.dialog = self.prompt = None
        self.left = True
        flows = _FLOWS.get(self.controller)
        if flows is not None:
            flows.discard(self)
        if dialog is None or dialog.client.is_deleted or not dialog.client.has_socket_connection:
            return  # the tab is gone (closed or reloaded): another tab, or the reloaded one, may still answer
        dialog.discard()
        current = self.controller.current_credential_request()
        if dialog.waiting or not current or current['request_id'] != prompt:
            return
        from .scope import tab_state
        tab = tab_state(dialog.client)
        if self._started_the_job(tab) and not self._shown_elsewhere(prompt):
            self.controller.reply_credentials(prompt, None)
            return
        left = tab.setdefault(LEFT, set())
        left.intersection_update({prompt})  # an older request cannot come back: the set holds one id at most
        left.add(prompt)

    def _started_the_job(self, tab) -> bool:
        return self._active_job is not None and tab.get(STARTED) is not None and self._active_job() == tab[STARTED]

    def _shown_elsewhere(self, request_id) -> bool:
        """Whether another connected tab has a sign-in dialog open for ``request_id``."""
        for other in list(_FLOWS.get(self.controller, ())):
            dialog = other.dialog
            if (other is not self and dialog is not None and dialog.request_id == request_id
                    and dialog.client.has_socket_connection and not dialog.client.is_deleted):
                return True
        return False

    def _left(self, request_id) -> bool:
        """This tab left a dialog for ``request_id`` and another connected tab still shows one for it (``leave``)."""
        return request_id in self._tab().get(LEFT, ()) and self._shown_elsewhere(request_id)

    async def _clear(self, *, restore=True, wait=True) -> None:
        active, self.dialog = self.dialog, None
        if active is not None:
            await active.close(restore=restore, wait=wait)

    async def _open(self, request) -> bool:
        from nicegui import ui
        client = self.client or ui.context.client
        await dialogs.credentials_opener(client)
        current = self.controller.current_credential_request()
        if self.left or not current or current['request_id'] != request['request_id']:
            return False  # the request went, or the page was left while the opener was awaited
        # A child of the page itself, whoever called: a poll that runs for a click (Sign in again, a reply) is in
        # the context of that button, and a dialog built there would go with the outcome the button is part of.
        with client.content:
            self.dialog = dialogs.credentials_dialog(
                request, on_reply=self._reply, store_status=lambda: (self._store() or {}).get('message', ''),
                saved=lambda: dialogs.saved_login(self._store() or {}, self._restored()),
                on_forget=self.controller.forget_credentials, fallback=self._fallback())
        return True

    async def _reply(self, dialog, answer, remember) -> None:
        if dialog.waiting:
            # Cancel while Infoblox checks the password: there is no request to answer, the lookup is stopped.
            self.controller.cancel_sign_in()
            await self._after_reply()
            return
        async with self.lock:
            checking = False
            current = self.controller.current_credential_request()
            if current and current['request_id'] == dialog.request_id:
                checking = self.controller.reply_credentials(dialog.request_id, answer, remember=remember) is True
            if self.dialog is dialog:
                if checking:
                    dialog.wait()
                else:
                    await self._clear(restore=False)
                    self.prompt = None
        await self._after_reply()
        if self.dialog is None:
            # After a cancelled sign-in focus returns to Run, which is enabled again once the lookup has ended.
            dialog.restore_focus(wait=answer is None)
