"""The Report menu: what the shared workbook is, its download and its deletion.

The menu belongs to the header (``shell.render_shell`` draws it on every page, ``PageShell.update`` feeds it the
session's snapshot), so a page never draws a report button. It holds one line about the workbook
(``texts.report_menu_line``), the sentence that says what Download copies, **Download accumulated report**,
**Delete report…** and the one live status line (``data-report-status``) that the download and the deletion share.

``ReportMenu`` owns the download request, its completion and its release; ``ReportDeleteAction`` owns the deletion
(its confirmation, its request and its completion), and the controller owns the shared operation. NiceGUI is imported
inside the functions.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .controller import SessionSnapshot

PREPARING = 'Preparing a consistent report download…'
DOWNLOAD_UNAVAILABLE = 'Report download is unavailable.'
DOWNLOAD_FAILED = 'Report download failed.'
DELETING = 'Deleting report…'

CSS = '''
.cn-report-menu { padding:12px 16px; gap:8px; max-width:min(440px, 92vw); align-items:stretch; }
.cn-report-menu .cn-report-state { font-weight:600; overflow-wrap:anywhere; }
.cn-report-menu .cn-report-status:empty { display:none; }
.cn-report-menu .cn-report-status { overflow-wrap:anywhere; }
.cn-report-menu .cn-report-reason:empty { display:none; }
.cn-report-menu .cn-report-reason { overflow-wrap:anywhere; }
.cn-report-menu .cn-report-actions { gap:8px; }
'''


class ReportDeleteAction:
    """Follow cheap page metadata; the controller owns the shared operation.

    The dialog is created where the caller stands (outside the menu, which draws its content only while it is open) and
    the button where ``draw_button`` is called (inside the menu). ``changed`` is called whenever ``text`` changes."""

    def __init__(self, controller, trigger, menu, changed=lambda: None):
        from nicegui import ui

        self.controller = controller
        self.client = ui.context.client
        self.trigger = trigger  # the Report button: focus comes back to it
        self.menu = menu
        self.changed = changed
        self.state = None
        self.request_id = None
        self.generation = None  # the settings generation the open confirmation belongs to
        self.closed = False
        self.message = ''
        self.refused = False  # the message is a refusal of a click: it goes when the cause has passed
        self.text = ''  # what the status line says about the deletion: "Deleting report…", a refusal or a failure
        self.failed = False
        self.button = None
        self.reason = None  # the line that says why the button is off (draw_reason)
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
        # the card and the dialog owned it; leave focus that moved elsewhere alone. The place it returns to is the
        # Report button: the menu that held the Delete button is closed by then.
        card, trigger_id = json.dumps(self.card.html_id), json.dumps(self.trigger.html_id)
        self.dialog.on('before-hide', js_handler=f'''() => {{
const trigger = document.getElementById({trigger_id});
if (trigger) trigger.cnDeleteOwnedFocus = !!document.getElementById({card})?.contains(document.activeElement);
}}''')
        self.dialog.on('hide', js_handler=f'''() => {{
const trigger = document.getElementById({trigger_id});
const active = document.activeElement;
if (active === document.body || (trigger?.cnDeleteOwnedFocus && document.getElementById({card})?.contains(active))) {{
  trigger?.focus({{preventScroll:true}});
}}
if (trigger) delete trigger.cnDeleteOwnedFocus;
}}''')
        self.client.on_delete(self.close)

    def draw_button(self):
        """The Delete button, in the menu where the caller stands."""
        from nicegui import ui

        self.button = ui.button('Delete report…', on_click=self._open).props('outline color=negative data-report-delete')
        description = ('Deletes the accumulated report shared by all tools, after confirmation. '
                       'Available when nothing is running or saving.')
        self.button._props['aria-description'] = description
        self.button.disable()
        return self.button

    def draw_reason(self):
        """The line under the buttons that says why Delete report… is off while work runs (R3-04, plan 5.7: it names
        the Monitor); the button is described by it while it shows."""
        from nicegui import ui

        self.reason = ui.label('').classes('cn-report-reason cn-muted').props('data-report-delete-reason')
        return self.reason

    def _show_reason(self, state):
        from . import texts

        text = texts.delete_unavailable(state) if (state.report_state or {}).get('available') else ''
        if self.reason is None or self.reason.text == text:
            return
        self.reason.set_text(text)
        if self.button is not None:
            if text:
                self.button._props['aria-describedby'] = self.reason.html_id
            else:
                self.button._props.pop('aria-describedby', None)
            self.button.update()

    def _available(self):
        state = self.state
        return bool(state and state.quiet and (state.report_state or {}).get('available') and not self.request_id)

    def _show(self):
        pending = bool(self.state and self.state.report_delete_pending) or bool(self.request_id)
        text, failed = (DELETING, False) if pending else (self.message, bool(self.message))
        if (text, failed) != (self.text, self.failed):
            self.text, self.failed = text, failed
            self.changed()

    def _say(self, message, *, negative=False):
        """Tell the tab that asked, whose menu is closed by now: a toast, as the status line is out of sight."""
        from nicegui import ui

        if message and not self.client.is_deleted:
            with self.client:
                ui.notify(message, type='negative' if negative else 'info')

    def _open(self):
        if self.closed or not self._available():
            return
        # Report metadata is already path-free. Defend the presentation as well
        # so a future caller can never turn confirmation into a path disclosure.
        name = str((self.state.report_state or {}).get('filename') or '')
        self.filename.set_text('Report file: ' + name.replace('\\', '/').rsplit('/', 1)[-1])
        self.message, self.refused = '', False
        self._show()
        self.generation = self.state.config_generation
        self.confirm.enable()
        self.menu.close()
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
            self._show()
            self._say(self.message, negative=True)
        else:
            self.refused = False
            if self.button is not None:
                self.button.disable()
            self._show()
        self.dialog.close()

    def update(self, state: SessionSnapshot) -> None:
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
            busy = bool(state.active_job_id or state.monitor_job_id or state.report_snapshot_pending)  # either slot
            if (self.refused and self._available()) or (busy and not self.refused):
                self.message, self.refused = '', False
        if self.request_id:
            result = self.controller.report_delete_result(self.request_id)
            if result is None and not state.report_delete_pending:
                # The controller dropped the request without a completion: the session closed or the pipe broke.
                self.controller.release_report_delete_result(self.request_id)
                self.request_id = None
                self.message, self.refused = 'The session ended before report deletion was confirmed.', False
                self._say(self.message, negative=True)
            elif result is not None:
                self.controller.release_report_delete_result(self.request_id)
                self.request_id = None
                if result['status'] in {'deleted', 'missing'}:
                    self.message, self.refused = '', False  # The workbook's status line announces success.
                    self._say(result.get('message') or report.get('message') or 'Accumulated report deleted.')
                else:
                    self.message = result.get('message') or 'Report could not be deleted. Try again.'
                    self.refused = False
                    self._say(self.message, negative=True)
        if report.get('state') == 'deleted' and not report.get('available'):
            self.message, self.refused = '', False  # The workbook is gone, so advice about retrying no longer applies.
        if self.button is not None:
            self.button.set_enabled(self._available())
        self._show_reason(state)
        self._show()

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


class ReportMenu:
    """The header's Report button and its menu; one per page, updated by ``PageShell.update``.

    It owns this page's report download (the request, its completion and its release), and holds the deletion in
    ``delete``. Everything it shows follows the session's snapshot, so every tab says the same about the workbook."""

    def __init__(self, controller):
        from nicegui import ui
        from . import texts
        from .scope import add_once

        self.controller = controller
        self.client = ui.context.client
        add_once(self.client, 'report-menu', css=CSS)
        self.state = None
        self.request_id = None  # this page's download in flight
        self.error = ''  # why the last download did not start or finish
        self.closed = False
        with ui.button('Report').props('outline icon-right=expand_more aria-haspopup=dialog aria-expanded=false '
                                       'data-report-menu') as self.trigger:
            self.menu = ui.menu().props('no-refocus role=dialog aria-label=Report')
        # The dialog goes beside the button: the menu draws its content only while it is open.
        self.delete = ReportDeleteAction(controller, self.trigger, self.menu, changed=self._show)
        with self.menu, ui.column().classes('cn-report-menu'):
            self.line = ui.label('').classes('cn-report-state').props('data-report-state')
            self.status = ui.label('').classes('cn-report-status cn-muted').props(
                'role=status aria-live=polite tabindex=-1 data-report-status')
            help_text = ui.label(texts.REPORT_DOWNLOAD_HELP)
            with ui.row().classes('items-center cn-report-actions'):
                self.download = ui.button('Download accumulated report', on_click=self._download).props('outline')
                self.download._props['aria-describedby'] = help_text.html_id
                # Off until the first poll reports: nothing is known about the workbook before it.
                self.download.disable()
                self.delete.draw_button()
            self.delete.draw_reason()
        trigger = json.dumps(self.trigger.html_id)
        # Say whether the menu is open, and when it closes with focus nowhere (Escape, a click on the page's own
        # background) give it back to the button: what the menu's own refocus would do, without taking focus from the
        # confirmation dialog that Delete opens.
        self.menu.on('show', js_handler=f"() => document.getElementById({trigger})?.setAttribute('aria-expanded', 'true')")
        self.menu.on('hide', js_handler=f'''() => {{
const trigger = document.getElementById({trigger});
trigger?.setAttribute('aria-expanded', 'false');
if (!document.activeElement || document.activeElement === document.body) trigger?.focus({{preventScroll:true}});
}}''')
        self.client.on_delete(self.close)

    # -- the download ------------------------------------------------------------------------------------------------

    def _download(self):
        if self.closed or self.request_id is not None:
            return
        self.error = ''
        self.download.disable()
        try:
            self.request_id = self.controller.request_report_snapshot()
        except (RuntimeError, OSError, EOFError):
            self.error = DOWNLOAD_UNAVAILABLE  # at the click: the menu is open and its status line says it
        self._show()

    def _finish_download(self):
        """Start the browser's download when the worker has prepared the copy, or say that it could not."""
        from nicegui import ui

        if self.request_id is None:
            return
        prepared = self.controller.report_completion(self.request_id) or {}
        if prepared.get('request_id', self.request_id) != self.request_id:
            return
        if prepared.get('status') == 'ready':
            with self.client:
                ui.download('/download/' + self.request_id)
            self.request_id = None
        elif prepared.get('status') == 'failed':
            self.error = prepared.get('error') or DOWNLOAD_FAILED
            if not self.menu.value:
                # The menu is closed by now, and its status line is drawn only while it is open: a toast, as for
                # a deletion.
                self.delete._say(self.error, negative=True)
            self.controller.acknowledge_report_completion(self.request_id)
            self.request_id = None

    # -- what it shows -----------------------------------------------------------------------------------------------

    def _status(self):
        """The one live line: the deletion's words first, then the download's, then the outcome of a deletion that
        another tab made."""
        report = (self.state.report_state or {}) if self.state is not None else {}
        if self.delete.text:
            return self.delete.text, self.delete.failed
        if self.request_id is not None:
            return PREPARING, False
        if self.error:
            return self.error, True
        if report.get('state') == 'deleted' and not report.get('available'):
            return report.get('message') or 'No accumulated report exists.', False
        return '', False

    def _show(self):
        text, failed = self._status()
        if self.status.text != text:
            self.status.set_text(text)
        if failed != ('text-negative' in self.status.classes):
            if failed:
                self.status.classes(add='text-negative')
            else:
                self.status.classes(remove='text-negative')

    def update(self, state: SessionSnapshot) -> None:
        """Called from ``PageShell.update`` with the session's snapshot."""
        from . import texts

        if self.closed or self.client.is_deleted:
            return
        self.state = state
        self.trigger.set_enabled(state.phase not in {'closing', 'closed'})
        self.delete.update(state)
        self._finish_download()
        line = texts.report_menu_line(state)
        if self.line.text != line:
            self.line.set_text(line)
        available = (state.report_state or {}).get('available') is True
        self.download.set_enabled(not state.report_delete_pending and available and self.request_id is None)
        self._show()

    def close(self) -> None:
        """The page is gone: give up its download (the copy is released). The deletion's presentation closes itself."""
        if self.closed:
            return
        self.closed = True
        if self.request_id is not None:
            self.controller.release_report_request(self.request_id)
            self.request_id = None
