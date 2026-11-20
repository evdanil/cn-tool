"""Clear results on the Monitor page (a stopped run, or one that failed before a round): the click, its refusal and the
words the page says about it. ``monitor.py`` wires it (one ``MonitorClear`` per page) and keeps nothing of it.

The controller forgets the run (``SessionController.clear_results``), asked for the ids of the attempt and the result the
page drew (``drew``): when it holds others (another tab ran a monitor since) nothing is cleared and the page says so
(``notice``, said in the round's polite line until a run starts or the next Clear). After a clear the line says
"Results cleared." until a run or an outcome comes back.
"""
from . import outcome as outcome_banner
from . import texts


class MonitorClear:
    def __init__(self, controller, *, alive, edit_form, poll):
        """``alive()`` says whether the page is still the tab's, ``edit_form()`` opens the form and focuses it (the
        fold's ``edit``) and ``poll()`` is the page's own poll (awaited after a click)."""
        self.controller, self._alive, self._edit_form, self._poll = controller, alive, edit_form, poll
        self.drawn = (None, None)  # the attempt and the result ids of the last poll: what the page shows
        self.notice, self.cleared = '', False

    async def clear(self) -> None:
        """The button: forget the stopped run's rounds, as on a first visit (the form unfolds with its values and takes
        the focus). History and the report are not touched."""
        if not self._alive():
            return
        attempt, result = self.drawn
        try:
            # What the page drew, not what the controller holds now: another tab may have run a monitor since.
            self.controller.clear_results('monitor', attempt_job_id=attempt, result_job_id=result)
        except RuntimeError:  # the results changed, or a run started (another tab): nothing is cleared
            self.notice = texts.NOT_CLEARED
            await self._poll()
            return
        self.notice, self.cleared = '', True
        self._edit_form()
        await self._poll()

    def say(self, text, page, *, active, outcome) -> str:
        """The round's polite line (``text``, or "Results cleared." when there is nothing else to say) with a refusal in
        front of it; a run or an outcome ends "Results cleared.". Also notes the ids of what ``page`` (this poll's
        snapshot) shows, for the next click."""
        self.drawn = (page.attempt_job_id, page.result_job_id)
        if not text and self.cleared and not (active or outcome):
            text = texts.RESULTS_CLEARED
        if active:
            self.notice = ''
        if self.notice:
            text = f'{self.notice} {text}'.strip()
        if active or outcome:
            self.cleared = False
        return text

    def show(self, banner, outcome, notice, failed, title) -> None:
        """The ended run's banner: its notice, or the failed run's title, each with Clear results; else none."""
        clear = outcome_banner.actions_for('monitor', outcome, dict(clear_results=self.clear), can_clear=True)
        if notice:
            banner.set(outcome_banner.INFORMATION, notice, actions=clear)
        elif failed:
            banner.set(outcome_banner.tone_for(outcome), title, actions=clear)
        else:
            banner.hide()
