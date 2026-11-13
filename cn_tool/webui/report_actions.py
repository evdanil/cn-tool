"""Shared, client-owned presentation for deleting the session workbook."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .controller import SessionSnapshot


class ReportDeleteAction:
    """Follow cheap page metadata; the controller owns the shared operation."""

    def __init__(self, controller, dense=False):
        from nicegui import ui

        self.controller = controller
        self.client = ui.context.client
        self.state = None
        self.request_id = None
        self.generation = None  # the settings generation the open confirmation belongs to
        self.closed = False
        self.message = ''
        self.refused = False  # the message is a refusal of a click: it goes when the cause has passed
        self.button = ui.button('Delete report', on_click=self._open).props(
            'outline color=negative data-report-delete' + (' dense' if dense else ''))
        description = ('Deletes the accumulated report shared by all tools, after confirmation. '
                       'Available when nothing is running or saving.')
        self.button._props['aria-description'] = description
        self.button.disable()
        self.status = ui.label('').props('role=status aria-live=polite tabindex=-1 data-report-delete-status').classes('cn-muted')
        with ui.dialog().props('no-refocus') as self.dialog:
            with ui.card().classes('w-full').style('max-width: 540px; overflow-wrap: anywhere') as self.card:
                title = ui.label('Delete accumulated report?').classes('text-h6')
                self.filename = ui.label('')
                ui.label('Delete the whole accumulated report shared by all tools? Displayed results, monitor history, and downloaded copies will stay. The next saved results will create a new report.')
                with ui.row().classes('w-full justify-end'):
                    self.cancel = ui.button('Cancel', on_click=self.dialog.close).props('outline autofocus')
                    self.confirm = ui.button('Delete report', on_click=self._submit).props('color=negative')
            self.dialog.props(f'aria-labelledby={title.html_id}')
        # QDialog's default refocus can override a user's new focus after submit. Take focus back when nothing holds
        # it (document.body: a click outside the dialog, whatever the before-hide check saw) or when it is still in
        # the card and the dialog owned it; leave focus that moved elsewhere alone. Use a stable status when the
        # trigger became disabled during an accepted deletion.
        card, button, status = map(json.dumps, (self.card.html_id, self.button.html_id, self.status.html_id))
        self.dialog.on('before-hide', js_handler=f'''() => {{
const status = document.getElementById({status});
if (status) status.cnDeleteOwnedFocus = !!document.getElementById({card})?.contains(document.activeElement);
}}''')
        self.dialog.on('hide', js_handler=f'''() => {{
const status = document.getElementById({status});
const active = document.activeElement;
if (active === document.body || (status?.cnDeleteOwnedFocus && document.getElementById({card})?.contains(active))) {{
  const button = document.getElementById({button});
  (button && !button.matches(':disabled') ? button : status)?.focus({{preventScroll:true}});
}}
if (status) delete status.cnDeleteOwnedFocus;
}}''')
        self.client.on_delete(self.close)

    def _available(self):
        state = self.state
        return bool(state and state.phase == 'ready' and not state.active_job_id
                    and (state.report_state or {}).get('available')
                    and not state.report_delete_pending and not state.report_snapshot_pending
                    and not self.request_id)

    def _open(self):
        if self.closed or not self._available():
            return
        # Report metadata is already path-free. Defend the presentation as well
        # so a future caller can never turn confirmation into a path disclosure.
        name = str((self.state.report_state or {}).get('filename') or '')
        self.filename.set_text('Report file: ' + name.replace('\\', '/').rsplit('/', 1)[-1])
        self.message, self.refused = '', False
        self.status.set_text('')
        self.generation = self.state.config_generation
        self.confirm.enable()
        self.dialog.open()

    def _submit(self):
        if self.closed or self.request_id:
            return
        self.confirm.disable()
        try:
            self.request_id = self.controller.request_report_delete(generation=self.generation)
        except (RuntimeError, OSError, EOFError) as refusal:
            # The tab's view can be seconds old, so the controller's own answer decides. Its texts are written for
            # the user and carry no path; anything else gets a generic line.
            self.message = (str(refusal) if isinstance(refusal, RuntimeError) and str(refusal) else
                            'Report deletion could not be started. Try again.')
            self.refused = True
            self.status.set_text(self.message)
            self.status.classes(add='text-negative')
        else:
            self.refused = False
            self.button.disable()
            self.status.set_text('Deleting report…')
            self.status.classes(remove='text-negative')
        self.dialog.close()

    async def update(self, state: SessionSnapshot) -> None:
        if self.closed or self.client.is_deleted:
            return
        self.state = state
        report = state.report_state or {}
        if self.dialog.value and self.generation is not None and state.config_generation != self.generation:
            # Reloaded settings may name another workbook than the one this confirmation names.
            self.dialog.close()
            self.message, self.refused = '', False
        if self.message:
            # Messages expire with their cause. A refusal says why a click did nothing, so it stays while that cause
            # lasts (the other work) and goes once deletion is offered again. Any other message (a failure, a dropped
            # request) is about an earlier moment: new work or a report download in progress makes it stale.
            busy = bool(state.active_job_id or state.report_snapshot_pending)
            if (self.refused and self._available()) or (busy and not self.refused):
                self.message, self.refused = '', False
        if self.request_id:
            result = self.controller.report_delete_result(self.request_id)
            if result is None and not state.report_delete_pending:
                # The controller dropped the request without a completion: the session closed or the pipe broke.
                self.controller.release_report_delete_result(self.request_id)
                self.request_id = None
                self.message, self.refused = 'The session ended before report deletion was confirmed.', False
            elif result is not None:
                self.controller.release_report_delete_result(self.request_id)
                self.request_id = None
                if result['status'] in {'deleted', 'missing'}:
                    self.message, self.refused = '', False  # The global workbook status announces success.
                    status, card = map(json.dumps, (self.status.html_id, self.card.html_id))
                    self.client.run_javascript(f'''(() => {{
const active = document.activeElement;
if (active === document.getElementById({status}) || document.getElementById({card})?.contains(active)) {{
  document.querySelector('[data-report-status]')?.focus({{preventScroll:true}});
}}
}})()''')
                else:
                    self.message = result.get('message') or 'Report could not be deleted. Try again.'
                    self.refused = False
        if report.get('state') == 'deleted' and not report.get('available'):
            self.message, self.refused = '', False  # The workbook is gone, so advice about retrying no longer applies.
        pending = state.report_delete_pending or bool(self.request_id)
        self.button.set_enabled(self._available())
        self.status.set_text('Deleting report…' if pending else self.message)
        self.status.classes(add='text-negative' if self.message and not pending else '',
                            remove='text-negative' if pending or not self.message else '')

    def close(self) -> None:
        """Abandon this page's completion without cancelling the shared deletion."""
        if self.closed:
            return
        self.closed = True
        if self.request_id:
            self.controller.release_report_delete_result(self.request_id)
            self.request_id = None
        if not self.client.is_deleted:
            self.dialog.close()


def render_report_delete(controller, dense=False) -> ReportDeleteAction:
    return ReportDeleteAction(controller, dense)
