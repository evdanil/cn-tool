"""What a tab keeps of the Monitor while it visits another tool (R2-11): ``tab_state(client)['monitor']``.

Under the root page (``router.py``) the Monitor is built again each time the tab comes back to it, and everything it
shows is read again from the controller and the worker: the run, its round, the Map, the History lists. What is the
tab's own is kept here, so a return finds it as it was left:

- the panel (Live monitor or History);
- the History position (``HistoryView``: the list, its parents and the pages opened), the lists' sort, filter and size,
  the saved target and the run on screen, and the round chosen, by its id, which is chosen again when the rounds are
  read again (its hosts' table keeps its page: the same round is the same rows);
- the arrangement of the round's and Show Available's tables, and whether Show Available is ticked (its table starts
  at its first page, as every read of the history does: the whole history is read again);
- for the run on screen only, the live table's arrangement, an exact match chosen by the Map's Show in table and the
  block the Map was asked to show; another run starts plain.

Never a result and never an input: the drafts are the tab's ``sessionStorage``, as are the fold and the Map or Table
choice, which therefore also survive a reload; this state does not (a reload is a new client). Pure: no NiceGUI.
"""
from dataclasses import dataclass, field

from .monitor_tables import HISTORY_SIZE
from .monitor_text import HistoryView
from .tables import TableState


def _views():
    return {'requests': dict(sort='', descending=False, text='', size=HISTORY_SIZE),
            'runs': dict(sort='', descending=False, text='', size=HISTORY_SIZE),
            'rounds': dict(size=HISTORY_SIZE)}


@dataclass
class MonitorTab:
    panel: str = 'live'
    history: HistoryView = field(default_factory=HistoryView)
    history_views: dict = field(default_factory=_views)
    request_context: object = None
    run_context: object = None
    round_id: object = None
    round_state: TableState = field(default_factory=TableState)
    coverage_on: bool = False
    coverage_parent: object = None
    coverage_state: TableState = field(default_factory=TableState)
    generation: object = None  # the settings generation the History position was taken under
    live_identity: object = None
    live_state: TableState = field(default_factory=TableState)
    live_exact: object = None
    map_show: int = -1

    def restore(self):
        """The page's starting values for what it keeps (its ``latest``); ``history`` is this tab's object itself.

        Show Available's table starts at its first page, so the state it is handed is put there now, before the page
        builds the table: its first read must not ask for the cursors of a fold the worker may no longer hold (it
        would draw that page, or an error, until the first poll read the history again)."""
        self.coverage_state.first_page()
        return dict(history_views=self.history_views, request_context=self.request_context,
                    run_context=self.run_context, selected_round=None, round_state=self.round_state,
                    coverage_on=self.coverage_on, coverage_parent=self.coverage_parent,
                    coverage_state=self.coverage_state, config_generation=self.generation)

    def keep(self, latest, *, panel):
        """Take back what the page leaves (``latest`` as it is when the Monitor is left)."""
        selected = latest.get('selected_round')
        self.panel = 'history' if panel == 'history' else 'live'
        self.history_views = latest['history_views']
        self.request_context, self.run_context = latest['request_context'], latest['run_context']
        self.round_id = selected.get('id') if isinstance(selected, dict) else latest.get('round_keep')
        self.round_state = latest['round_state']
        self.coverage_on, self.coverage_parent = bool(latest['coverage_on']), latest['coverage_parent']
        self.coverage_state = latest['coverage_state']
        self.generation = latest['config_generation']

    def live_for(self, identity):
        """The live table's arrangement for the run ``identity`` ((job, run id), None for none): the kept one when it
        is the run kept, else a plain one (and the kept exact match and block go)."""
        if identity is not None and identity == self.live_identity:
            return self.live_state
        self.live_identity, self.live_state, self.live_exact, self.map_show = identity, TableState(), None, -1
        return self.live_state if identity is not None else TableState()

    def keep_live(self, identity, state, *, exact, show):
        if identity is None:
            self.live_identity, self.live_state, self.live_exact, self.map_show = None, TableState(), None, -1
            return
        self.live_identity, self.live_state, self.live_exact, self.map_show = identity, state, exact, show
