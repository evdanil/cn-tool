"""The header's indicator of the running jobs, with a Stop… for each (R3-04, plan 5.7; finding S4).

The session has two slots (``job_slots``): the one-shot slot and the Monitor's. The indicator draws one entry for
each, in that order, each only while its slot holds a job: a pill that links to the tool that owns the job ("Monitor ·
round 31 · 5 min") and, on every page but that tool's own, **Stop…**. The tool's own page has its Stop button, so the
header offers the second one only where the page has none (B2: a Stop outside the owning page asks first). Stop… opens
``dialogs.confirm_dialog`` with ``texts.stop_warning`` and then cancels the job id it was asked about, so a click can
never end a job that began after the question was asked; the controller's own rule (the one-shot job in ``running``, the
Monitor in ``running``) decides the rest. Each entry is drawn once and touched only when what it shows changes, so an
idle page sends nothing. NiceGUI is imported inside the functions.
"""
from __future__ import annotations

from dataclasses import dataclass

_LIVE = {'running', 'stopping', 'saving'}
SLOTS = ('oneshot', 'monitor')  # the order in the header: the one-shot job first, then the Monitor

CSS = '''
/* The tools row takes what the title leaves (never wrapping above a phone's width), and the indicator takes what the
   buttons leave, its pills against the buttons: a job that starts, or a second one, moves nothing in the header and
   nothing below it. What does not fit is cut with an ellipsis (``.cn-pill-text``, the clock stays). */
@media (min-width: 600px) {
  .cn-title-row { flex-wrap:nowrap; }
  .cn-title-row > .cn-page-title { flex:none; }
  .cn-shell-tools { flex:1 1 0; min-width:0; flex-wrap:nowrap; justify-content:flex-end; }
  .cn-shell-tools > * { flex:none; }
  .cn-shell-tools > .cn-job-slot { flex:1 1 auto; }
}
.cn-job-slot { display:flex; align-items:center; justify-content:flex-end; gap:8px; min-width:0; max-width:100%; height:32px; }
.cn-job-entry { display:flex; align-items:center; gap:4px; min-width:0; max-width:100%; }
.cn-job-slot[data-jobs="2"] .cn-job-entry { flex:0 1 auto; }
.cn-job-stop.q-btn { flex:none; min-height:32px; height:32px; padding:0 10px; white-space:nowrap; }
.cn-job-stop .q-btn__content { flex-wrap:nowrap; white-space:nowrap; }
@media (max-width: 599px) {
  .cn-job-slot { width:100%; justify-content:flex-start; }
  .cn-job-slot[data-jobs="2"] { flex-direction:column; align-items:stretch; height:auto; min-height:32px; }
  .cn-job-slot[data-jobs="2"] .cn-job-entry { flex:none; justify-content:flex-start; }
}
'''


@dataclass
class _Entry:
    box: object
    pill: object
    text: object
    clock: object
    stop: object
    shown: object = None  # the texts.JobNotice the pill shows, or None
    job: str | None = None  # the job id this entry names (what its Stop… asks about)
    tool: str | None = None
    stop_state: tuple = (False, False)  # (visible, enabled)
    label: str | None = None  # the Stop button's name for a screen reader


class JobIndicator:
    """Draw the entries where the caller stands (inside ``.cn-job-slot``), and follow the session's two slots."""

    def __init__(self, shell):
        from nicegui import ui
        from . import texts
        from .shell import since

        self.shell = shell
        self.shown_count = 0
        self._asking = None  # (slot, job id, dialog) while a Stop… question is open
        self.slot = ui.element('div').classes('cn-job-slot')
        self.slot._props['data-jobs'] = '0'
        self._entries = {}
        with self.slot:
            for name in SLOTS:
                with ui.element('div').classes('cn-job-entry').mark(f'job-entry-{name}') as box:
                    with ui.link(target='/').classes('cn-job-pill') as pill:
                        ui.label('Running:').classes('cn-pill-prefix')  # for a screen reader: what the pill is about
                        text = ui.label('').classes('cn-pill-text')
                        clock = since(coarse=True)
                    stop = ui.button(texts.INDICATOR_STOP, on_click=self._clicked(name)).props(
                        'outline dense no-caps data-job-stop').classes('cn-job-stop')
                stop.set_visibility(False)
                stop.disable()  # matches ``stop_state`` (False, False): an update turns it on when it can act
                box.set_visibility(False)
                self._entries[name] = _Entry(box, pill, text, clock, stop)

    def _clicked(self, name):
        async def clicked():
            await self.request_stop(name)
        return clicked

    def update(self, views, active, started):
        """``views``: slot -> the slot's snapshot view (the one-shot slot's is the snapshot, the Monitor's its copy);
        ``active``: the page's key; ``started``: slot -> the moment its clock counts from (None: no clock)."""
        from . import texts
        from .job_slots import stoppable
        from .shell import set_clock

        count = 0
        for name in SLOTS:
            entry, view = self._entries[name], views[name]
            indicator = texts.job_indicator(view)
            if indicator != entry.shown:
                entry.shown = indicator
                entry.text.set_text(indicator.text if indicator else '')
                entry.pill._props['href'] = indicator.route if indicator else '/'
                entry.pill._props['title'] = indicator.text if indicator else ''  # in full, where the pill is cut
                entry.pill.update()
                entry.box.set_visibility(indicator is not None)
            entry.job = view.active_job_id if indicator else None
            entry.tool = view.active_lookup_type if indicator else None
            set_clock(entry.clock, started[name] if indicator else None)
            count += indicator is not None
            # The tool's own page has its Stop; the header offers one only for a job that page does not own.
            offered = indicator is not None and view.active_lookup_type != active
            label = texts.indicator_stop_label(entry.tool) if offered else None
            if label != entry.label:  # always the job's own name, also when one job replaces another between two polls
                entry.label = label
                if label:
                    entry.stop._props['aria-label'] = label
                    entry.stop.update()
            stop_state = (offered, offered and stoppable(view))
            if stop_state != entry.stop_state:
                if stop_state[0] != entry.stop_state[0]:
                    entry.stop.set_visibility(stop_state[0])
                if stop_state[1] != entry.stop_state[1]:
                    entry.stop.set_enabled(stop_state[1])
                entry.stop_state = stop_state
            if self._asking is not None and self._asking[0] == name and entry.job != self._asking[1]:
                self._asking[2].submit(False)  # the job the question was about is gone: the question is stale
        if count != self.shown_count:
            self.shown_count = count
            self.slot._props['data-jobs'] = str(count)
            self.slot.update()

    async def request_stop(self, name):
        """The click on a Stop…: ask about the job the entry names, then stop that job if it is still the one running
        in its slot."""
        from . import texts
        from .dialogs import confirm_dialog
        from .job_slots import monitor_view, stoppable

        entry = self._entries[name]
        job = entry.job

        def view():
            state = self.shell._read()
            return monitor_view(state) if name == 'monitor' else state

        seen = view()
        if not job or seen.active_job_id != job:
            return
        warning = texts.stop_warning(seen, hosts=self.shell._size.get(job))
        if warning is None:
            return
        self._asking = None
        asked = []

        def opened(dialog):
            self._asking = (name, job, dialog)
            asked.append(dialog)

        try:
            answered = await confirm_dialog(warning.title, warning.lines, confirm=warning.confirm_label, danger=True,
                                            fallback='.cn-page-title', opened=opened)
        finally:
            self._asking = None
        if not answered:
            return
        now = view()
        if now.active_job_id != job:  # it ended while the question was open, and the confirm came before the poll
            from nicegui import ui
            with self.shell._client:
                ui.notify(texts.stop_too_late(entry.tool or seen.active_lookup_type))
            return
        entry.stop.disable()  # the question is answered: the focus goes to the page's title, not to a button that goes
        entry.stop_state = (entry.stop_state[0], False)  # the next update turns it on again if the job still runs
        if stoppable(now):
            self.shell.controller.cancel(job)
