"""The Monitor's view in the URL (R2-08): ``/monitor?tab=history&req=<id>&run=<id>&round=<id>``, ``?view=table`` and
the table of the view (the live table on Live, the round's on History). Design: "R2-08 design note" in
``docs/plans/webui-ux-plan.md``; the mechanism is ``view_state.ViewState``.

The tab's ``monitor_state.MonitorTab`` stays the one source of truth: ``arrive`` puts a URL's view into it before the
page reads it (the URL wins on arrival), ``values`` reads the view back from the page, and ``popped`` applies a view
that Back or Forward brought, as the reader's own clicks would. What is not in the URL stays the tab's: the History
lists' sort, filter, size and pages, Show Available, Show in table's host, the Map's block, the fold, the drafts.

A history position or a round that the history no longer has is ``gone``: History starts again from the saved targets
(or the run's first round) and one line says so. Live table values with no run to show are gone too. NiceGUI is
imported by ``view_state`` inside its methods; this module draws nothing itself.
"""
import asyncio

from . import view_state
from .monitor_tables import ANY, BUSY_PAUSE, BUSY_RETRIES
from .tables import TableState

# A link's saved target and run are looked for in at most this many pages of the History lists (100 rows each), and
# its round in at most this many pages of its run's rounds (the page's own size, so that the cursors found are the
# ones Earlier and Later step by). A round further in than that is taken to be gone.
LIST_PAGES, ROUND_PAGES = 20, 200
WALK_POLL = .01  # how often a page of the walk is looked for


class _Unknown(Exception):
    """The history could not say (unavailable, busy, too slow): the link's own checks of each list still apply."""


def _context(request_id):
    """What a saved target is called while its row is read (a link): the History location bar names it by id."""
    return {'id': request_id, 'targets_preview': [f'Saved target {request_id}'], 'target_count': 1, 'link': True}


def _known_request(context, request):
    return isinstance(context, dict) and context.get('id') == request and not context.get('link')


def _known_run(context, request, run):
    return (isinstance(context, dict) and context.get('id') == run and not context.get('link')
            and context.get('request_id', request) == request)


def position(history, values):
    """Move ``history`` (a ``HistoryView``) to the position of ``values``; ``(request id, run id, round id)``. The
    lists it shares with the position it is at keep what was read of them (their pages, the run's view only)."""
    request, run, round_id = values.get('req'), values.get('run'), values.get('round')
    if values.get('tab') != 'history':
        history.reset()
        return None, None, None
    target = [('requests', None)] + ([('runs', request)] if request is not None else [])
    target += [('rounds', run)] if request is not None and run is not None else []
    chain = [(kind, parent) for kind, parent, *_ in history.ancestors] + [(history.kind, history.parent)]
    shared = 0
    while shared < min(len(chain), len(target)) and chain[shared] == target[shared]:
        shared += 1
    if shared == 0:
        history.reset()
        shared = 1
    while len(history.ancestors) >= shared:
        history.back()
    for kind, parent in target[shared:]:
        history.open(kind, parent, view_only=False if kind == 'rounds' else None)
    if request is None:
        return None, None, None
    return request, run, round_id if run is not None else None


class _Reader:
    """The walk of a link's lists: one page at a time, through the controller, as the History lists read them."""

    def __init__(self, controller, alive):
        self.controller, self.alive = controller, alive

    async def page(self, kind, parent, cursor, limit, ordered):
        for retries in range(BUSY_RETRIES + 1):
            try:
                options = ('', False, 'all', ANY, '') if ordered else ()
                query = self.controller.request_monitor_history(kind, parent, cursor, limit, *options)
            except (AttributeError, RuntimeError, ValueError):
                raise _Unknown() from None
            try:
                result = await self._answer(query)
            finally:
                self.controller.release_monitor_history_page(query)
            error = str(result.get('error') or '')
            if not error.startswith('History reader is busy'):
                if error and error != 'expired':
                    raise _Unknown()
                return result
            await asyncio.sleep(BUSY_PAUSE * (retries + 1))
        raise _Unknown()

    async def _answer(self, query):
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 60
        while self.alive() and loop.time() < deadline:
            result = self.controller.monitor_history_page(query)
            if result is not None:
                return result
            await asyncio.sleep(WALK_POLL)
        raise _Unknown()

    async def row(self, kind, parent, wanted):
        """The row of ``kind`` whose id is ``wanted`` (None: not there). Saved targets are listed by id, so the walk
        stops once it is passed."""
        cursor = None
        for _ in range(LIST_PAGES):
            result = await self.page(kind, parent, cursor, 100, True)
            items = result.get('items') or []
            found = next((item for item in items if item.get('id') == wanted), None)
            if found is not None or result.get('error'):
                return found
            passed = kind == 'requests' and any(type(item.get('id')) is int and item['id'] > wanted for item in items)
            cursor = result.get('next_cursor')
            if passed or not cursor:
                return None
        raise _Unknown()

    async def round_pages(self, run, wanted, size):
        """The cursors that reach the page of the run's rounds holding round ``wanted`` (None: not there). Rounds are
        listed in the order they were taken, so the walk stops once it is passed."""
        cursors = [None]
        for _ in range(ROUND_PAGES):
            result = await self.page('rounds', run, cursors[-1], size, False)
            items = result.get('items') or []
            if result.get('error') or any(item.get('id') == wanted for item in items):
                return None if result.get('error') else cursors
            cursor = result.get('next_cursor')
            if not cursor or any(type(item.get('id')) is int and item['id'] > wanted for item in items):
                return None
            cursors.append(cursor)
        return None


class MonitorLink:
    """One Monitor page's URL. Made first, so that its ``arrive`` reaches the tab's state before the page reads it;
    ``bind`` gives it the page's parts once they are drawn."""

    def __init__(self, scope, kept):
        self.kept = kept
        self.page = None
        self.linked = False       # the History position came from a link: an answer that it has expired is "gone"
        self.round_id = None      # the round a link named: not among the rounds read is "gone"
        self.live_values = None   # the live table of a link, for the first run the page shows
        self.forced_view = None   # the link's Map or Table, for this load only (the tab's stored choice stays)
        self.popping = False      # a view of Back or Forward is being applied: it is the URL already
        self.wanted = None        # what ``locate`` reads before History is drawn: (target, run, round, rows, round)
        self.moves = 0            # the number of the latest move of the History position: an overtaken lookup changes nothing
        self.view = view_state.ViewState(scope, view_state.MONITOR_SCHEMA, self.values)
        self.arrive(self.view.take())

    # --- arrival ------------------------------------------------------------------------------------------------
    def arrive(self, values):
        """The URL's view into the tab's state (None: the tab's own stands)."""
        if values is None:
            return
        kept = self.kept
        kept.panel = values['tab']
        kept.request_context, kept.run_context, kept.round_id, kept.round_state = self._move(
            values, kept.request_context, kept.run_context, kept.round_id, kept.round_state, None)
        self.forced_view = values.get('view') if values['tab'] == 'live' else None
        self.live_values = values if values['tab'] == 'live' and values.get('view') == 'table' else None

    def _move(self, values, request_context, run_context, round_id, round_state, items):
        """The History position of ``values``, from the one the tab is at (``items``: the rounds on screen, None when
        not read). What the tab has read of the same saved target, run and round stays: their rows, the pages of the
        lists and the round's table; what it has not is read by ``locate``. ``(target row, run row, round, table)``."""
        history = self.kept.history
        same_run = history.kind == 'rounds' and values.get('run') is not None and history.parent == values.get('run')
        request, run, wanted = position(history, values)
        if not _known_request(request_context, request):
            request_context = _context(request) if request is not None else None
        if not _known_run(run_context, request, run):
            run_context = {'id': run, 'link': True} if run is not None else None
        elif run is not None:
            history.view_only = not run_context.get('owned')
        ids = None if items is None else [item.get('id') for item in items]
        found = same_run and wanted is not None and (wanted in ids if ids is not None else wanted == round_id)
        state = round_state if found and wanted == round_id else TableState()
        if wanted is not None:
            view_state.set_table(state, values)
        rows = request is not None and (request_context.get('link') or bool(run_context and run_context.get('link')))
        self.wanted = (request, run, wanted, rows, wanted is not None and not found) if request is not None else None
        self.linked, self.round_id = request is not None, wanted
        self.moves += 1
        return request_context, run_context, wanted, state

    async def locate(self, controller):
        """Before History is read for a link or a pop: the rows of a saved target and a run that the tab has not read
        (so the location bar names them, and a run of another target is gone), and the page of its rounds that holds
        the round named (so that it is shown, and Earlier and Later step from it). Once. False when a later move of the
        position overtook it while it waited (checked after every read): it has changed nothing, and the caller stops,
        since the later move reads History itself."""
        wanted, self.wanted = self.wanted, None
        page, move = self.page, self.moves
        if wanted is None or page is None:
            return True
        request, run, round_id, rows, walk = wanted
        latest, history = page.latest, page.history
        reader = _Reader(controller, lambda: self.view.scope.alive)
        try:
            if rows:
                found = await reader.row('requests', None, request)
                run_row = None
                if found is not None and move == self.moves and run is not None:
                    run_row = await reader.row('runs', request, run)
                if move != self.moves:
                    return False
                if found is None or (run is not None and run_row is None):
                    self._gone()
                    return True
                latest['request_context'] = found
                if run_row is not None:
                    latest['run_context'] = run_row
                    history.view_only = not run_row.get('owned')
            if walk:
                # Not there: the run's first page, whose answer says it is gone (``answered``) and shows its first round.
                cursors = await reader.round_pages(run, round_id, latest['history_views']['rounds']['size'])
                if move != self.moves:
                    return False
                history.cursors = cursors or [None]
        except _Unknown:
            pass
        return move == self.moves

    def _gone(self):
        """A link's saved target or run is not in the history (or the run is another target's): History from the
        start, and the line says so."""
        self.page.history.reset()
        latest = self.page.latest
        latest['request_context'] = latest['run_context'] = latest['round_keep'] = None
        self.linked, self.round_id = False, None
        self.view.gone()

    def bind(self, **page):
        """The page's parts: ``panel()``, ``latest``, ``history``, ``live_map``, ``tabs``, ``live_tab``,
        ``history_tab``, ``request_history``, ``live_handle()``."""
        from types import SimpleNamespace
        self.page = SimpleNamespace(**page)
        live_map = self.page.live_map
        live_map.changed = self.view.replace
        if self.forced_view:
            live_map.view = live_map.forced = self.forced_view  # this load's view; the tab's stored choice stays
        self.view.on_pop(self.popped)

    # --- the URL from the page ----------------------------------------------------------------------------------
    def values(self):
        page = self.page
        if page is None:
            return {}
        latest, history = page.latest, page.history
        if page.panel() == 'history':
            values = {'tab': 'history'}
            if history.kind == 'runs':
                values['req'] = history.parent
            elif history.kind == 'rounds':
                values['req'] = history.ancestors[-1][1] if history.ancestors else None
                values['run'] = history.parent
                selected = latest.get('selected_round')
                values['round'] = selected.get('id') if isinstance(selected, dict) else latest.get('round_keep')
                if values['round'] is not None:
                    values.update(view_state.table_values(latest['round_state']))
            return values
        # A plain Table is the tab's own choice (sessionStorage): the URL names the view only with the arrangement of
        # its table (a filter, a sort, a page, a group), which needs it.
        table = view_state.table_values(latest['live_state']) if latest.get('live_identity') else {}
        if page.live_map.view != 'table' or not view_state.table_named(table):
            return {}
        return {'view': 'table', **table}

    def replace(self):
        if not self.popping:
            self.view.replace()

    def push(self):
        """A step Back undoes (the tab, a saved target, a run, a round)."""
        if not self.popping:
            self.view.push()

    # --- what the page found ------------------------------------------------------------------------------------
    def live(self, identity, state):
        """The poll has the run it shows (``identity``, None for none) and its table's ``state``: a link's table
        arranges it, once; with no run to show, the link's table is gone."""
        values, self.live_values = self.live_values, None
        if values is None:
            return
        if identity is None:
            if view_state.table_named(values):
                self.view.gone()
            return
        view_state.set_table(state, values)

    def answered(self, result):
        """A History list came. True when a link's position has expired: History starts again from the saved
        targets, and the line says so (the caller reads the history again). A round the link named that is not among
        the rounds read is gone too: the run's first round is shown."""
        linked, self.linked = self.linked, False
        round_id, self.round_id = self.round_id, None
        if linked and result.get('error') == 'expired':
            self.page.history.reset()
            self.page.latest['request_context'] = self.page.latest['run_context'] = None
            self.page.latest['round_keep'] = None
            self.view.gone()
            return True
        if (round_id is not None and self.page.history.kind == 'rounds' and not result.get('error')
                and not any(item.get('id') == round_id for item in result.get('items') or [])):
            self.view.gone()
        return False

    # --- Back and Forward ---------------------------------------------------------------------------------------
    async def popped(self, values):
        """Back or Forward: the view of that entry, applied as the reader's clicks would."""
        self.popping = True
        try:
            await self._apply(values)
        finally:
            self.popping = False

    async def _apply(self, values):
        page = self.page
        latest, history = page.latest, page.history
        moved = values['tab'] == 'history'
        if moved:
            shown = latest.get('selected_round')
            items = (latest.get('history_page') or {}).get('items') if history.kind == 'rounds' else None
            latest['request_context'], latest['run_context'], round_id, latest['round_state'] = self._move(
                values, latest['request_context'], latest['run_context'],
                shown.get('id') if isinstance(shown, dict) else latest.get('round_keep'), latest['round_state'], items)
            latest['round_keep'], latest['selected_round'] = round_id, None
        elif values.get('view') and values['view'] != page.live_map.view:
            # Only an entry that names Map or Table changes it, for this load: the tab's stored choice stays (D1).
            page.live_map.view = page.live_map.forced = values['view']
            page.live_map.set_buttons()
            page.live_map.restart()
        page.tabs.set_value(page.history_tab if moved else page.live_tab)
        handle = page.live_handle()
        if not moved:
            # The entry's query is its view: a table field it leaves out is at its default (no filter), whatever the
            # tab shows now; only Map or Table is the tab's own choice when the entry names none.
            fields = TableState()
            view_state.set_table(fields, values)
            if handle is not None:
                await handle.apply(query=fields.query, sort=fields.sort, descending=fields.descending,
                                   page=fields.page, size=fields.size, group=fields.group)
            else:
                view_state.set_table(latest['live_state'], values)
        if moved:
            await page.request_history(keep_round=True)
