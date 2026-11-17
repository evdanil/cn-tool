"""The Ping page while a Ping runs: a progress bar and the hosts probed so far (plan R2-06, finding m2).

The worker sends each batch of rows as it finishes (``partial_result``); the controller holds them for the running job
(``SessionController.ping_partial``) and the page reads only what it has not seen. The rows are a ``tables.cn_table``
that is built once and updated in place, so a filter the reader typed and a sort stay while the rows come. The final
result replaces them (``subnets.render_subnets`` then draws its own table); a Ping that ends any other way leaves no
partial row on the page, and none in the controller. No estimate of the time left: the plan waits for real timings (V-12).

NiceGUI is imported inside the functions: the pure half (``progress_text``) needs the standard library.
"""
from __future__ import annotations

from . import ping, tables
from .texts import fmt_count

NOTE = 'Hosts probed so far. The final result replaces these rows.'
TABLE_LABEL = 'Ping hosts so far'


def progress_text(completed, total) -> str:
    """"300 of 1,024"."""
    return f'{fmt_count(completed)} of {fmt_count(total)}'


class PingProgress:
    """The partial results on the Ping page: ``follow(snapshot)`` from the page's poll says whether they are shown."""

    def __init__(self, controller, states, results):
        from nicegui import ui

        self.controller, self.states, self.results = controller, states, results
        self.job = None
        self.rows, self.keys, self.source, self.handle = [], None, None, None
        self.active = False
        self._shown = (None, None)
        self.box = ui.column().classes('w-full cn-ping-partial').props('tabindex=-1')
        with self.box:
            ui.label(NOTE).classes('cn-muted')
            with ui.row().classes('items-center w-full no-wrap'):
                self.bar = ui.linear_progress(value=0, show_value=False).props('aria-label="Ping progress"').classes('grow')
                self.text = ui.label('').classes('text-no-wrap')
            self.area = ui.column().classes('w-full')
        self.box.set_visibility(False)

    def _reset(self, job):
        """Start again for ``job``: the table's arrangement is the tab's for that job (``states``), so a page built
        again while it runs (a return from another tool) keeps the reader's filter and sort; another job's goes."""
        self.job, self.rows, self.keys, self.source, self.handle = job, [], None, None, None
        for key in [key for key in self.states if isinstance(key, tuple) and key[0] == 'ping-partial' and key[1] != job]:
            del self.states[key]
        self.area.clear()

    async def _hide(self):
        """The run is over (its result, or nothing, takes the place): the rows go, and the focus that was in them
        goes to the results region."""
        from nicegui import ui

        client = ui.context.client
        try:
            await client.run_javascript(
                f'''(() => {{ const box = document.getElementById({self.box.html_id!r});
if (box?.contains(document.activeElement)) document.getElementById({self.results.html_id!r})?.focus(); }})()''',
                timeout=1)
        except (TimeoutError, RuntimeError):
            pass  # a tab that is gone keeps no focus
        self.box.set_visibility(False)
        self._reset(None)
        self.active, self._shown = False, (None, None)

    async def take_focus(self):
        """The earlier result is about to be removed: a focus inside it moves to this box (the progress region), which
        is shown first (a box that is not drawn yet cannot take the focus, so the script waits for it)."""
        from nicegui import ui

        try:
            await ui.context.client.run_javascript(
                f'''(() => {{ const results = document.getElementById({self.results.html_id!r});
if (!results?.contains(document.activeElement)) return;
let frames = 0;
const take = () => {{ const box = document.getElementById({self.box.html_id!r});
  if (box && box.offsetParent !== null) box.focus(); else if (frames++ < 60) requestAnimationFrame(take); }};
take(); }})()''', timeout=1)
        except (TimeoutError, RuntimeError):
            pass  # a tab that is gone keeps no focus

    async def follow(self, snapshot) -> bool:
        """Take the rows that came since the last call. True while the page shows partial rows: this tool's own job
        runs and has sent a batch. A snapshot that still says the job runs when the controller has already dropped its
        rows (the result is on its way) keeps what is shown for one more poll."""
        mine = bool(snapshot.active_job_id) and snapshot.active_lookup_type == 'ping'
        read = getattr(self.controller, 'ping_partial', None)
        held = read(self.job, len(self.rows)) if read is not None and mine else None
        if held is None and not (mine and self.rows and snapshot.active_job_id == self.job):
            if self.active:
                await self._hide()
            return False
        if held is not None:
            if held['job_id'] != self.job:
                self._reset(held['job_id'])
            fresh = ping.display_rows(held['rows'])
            self.rows.extend(fresh)
            keys = {key for row in fresh for key in row}
            if fresh and (self.handle is None or not keys <= set(self.keys)):
                self._build()
            elif fresh:  # the same table: its rows are replaced and drawn in place (filter, sort, page and focus stay)
                self.source.set_rows(self.rows)
                await self.handle.refresh()
            shown = (held['completed'], held['total'])
            if shown != self._shown:
                self._shown = shown
                self.bar.set_value(shown[0] / shown[1] if shown[1] else 0)
                self.text.set_text(progress_text(*shown))
        if not self.active and self.rows:
            self.active = True
            self.box.set_visibility(True)
        return self.active

    def _build(self):
        """A table for the rows so far; the columns are those the rows have (a batch with a column it did not have
        before, which Ping does not send, draws the table again)."""
        self.keys = list(dict.fromkeys(key for row in self.rows for key in row))
        self.source = tables.RowsSource(self.rows)
        self.area.clear()
        with self.area:
            self.handle = tables.cn_table(
                name='ping-partial', label=TABLE_LABEL, columns=ping.table_columns(self.rows), source=self.source,
                state=self.states.setdefault(('ping-partial', self.job), tables.TableState()), export=False)
