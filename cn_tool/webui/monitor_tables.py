"""
The Monitor's tables (plan ``docs/plans/webui-ux-plan.md``, R2-04): the latest round, a saved round's hosts and Show
Available are ``cn_table``s whose rows the worker pages (``PagedSource``s here), and the History lists of saved
targets, runs and rounds draw the same filter field and footer (``tables.filter_input``, ``tables.PageFooter``).

A source asks the controller for one page and looks for the answer every ``POLL`` seconds; a newer request of the same
table gives up an older one. ``all_rows`` is the export's walk: every row as filtered and sorted, ``MAX_PAGE_ROWS`` a
page, following each answer's own offset or cursor, retrying a busy history reader, stopped by Cancel
(``cancel_walk``), by a newer round or by reloaded settings. The words are ``monitor_text``'s.
"""
import asyncio

from . import table_actions, table_export
from .monitor_text import (
    COVERAGE_CHANGED, COVERAGE_EXPIRED, EXPORT_PREPARING, EXPORT_TABLE_CHANGED, EXPORT_TIMEOUT, HISTORY_UNAVAILABLE,
    LIVE_CHANGED, LIVE_UNAVAILABLE, ROUND_CHANGED, ROUND_EXPIRED, ROUND_TOO_LARGE, coverage_row, export_too_many,
    history_error_message, live_row, round_host_row,
)
from .tables import STATE_TONES, Column, Group, Page, PageFooter, TableState, TableUnavailable, last_page, size_choice

ANY = 'any'                      # ping_history.ANY_FIELD: the quick filter reads every column
POLL = .05                       # how often an answer is looked for
ANSWER_SECONDS = 60              # a page that does not come in this time is given up
BUSY_RETRIES, BUSY_PAUSE = 5, .2  # "History reader is busy": asked again, after a pause that grows each time
PROGRESS_PAGES = 4               # an export says how far it got after every fourth page
HISTORY_SIZES = (5, 10, 15, 20, 25, 50, 100)  # the History lists' rows per page: the worker reads up to 100
HISTORY_SIZE = 50
WAITING_ROUND = 'Waiting for the first complete round. No result is inferred for an unfinished round.'

# The Monitor's statuses as chips: what a host did in a saved round (the latest round's results and Show Available's
# statuses are in the table already).
STATE_TONES.update({'replied': 'ok', 'rejected': 'ok', 'tcp reply': 'ok', 'probe error': 'problem',
                    'dns failed': 'problem', 'unknown': 'neutral'})

LIVE_COLUMNS = (Column('host', 'Target', 'mono', sticky=True), Column('result', 'Result', 'state'),
                Column('address', 'Address', 'mono'), Column('tcp', 'TCP'))
ROUND_COLUMNS = (Column('host', 'Target', 'mono', sticky=True), Column('status', 'Status', 'state'),
                 Column('address', 'Address', 'mono'), Column('result', 'Probe result'))
COVERAGE_COLUMNS = (Column('host', 'Target', 'mono', sticky=True), Column('status', 'Status', 'state'),
                    Column('first_seen', 'First seen'), Column('last_seen', 'Last seen'),
                    Column('answered', 'Rounds answered'), Column('failed', 'Failed rounds', sortable=False),
                    Column('note', 'Note', sortable=False))
HOST_GROUPS = (Group('answered', 'Answered'), Group('no_response', 'No response'), Group('problem', 'Problems'),
               Group('other', 'Other'))
COVERAGE_GROUPS = (Group('seen', 'Seen'), Group('unseen', 'Unseen'), Group('not_tested', 'Not tested'))

_STALE = object()


def counted(counts, total):
    """``Page.counts`` with 'all' (the counts describe the whole round or history, whatever the group and filter)."""
    counts = dict(counts or {})
    whole = sum(counts.values()) if counts else total
    return dict(counts, all=whole) if whole is not None else counts, whole


class WorkerPages:
    """What the Monitor's sources share. ``alive()`` is false once the page is gone; ``generation`` is the settings
    generation the table was drawn under (a walk under newer settings stops)."""

    def __init__(self, controller, *, alive=lambda: True, generation=None):
        self.controller, self.alive, self.generation = controller, alive, generation
        self.on_progress = None      # set by the table while it exports: writes the export's status line
        self.walk_cancelled = False
        self._newest = 0

    def cancel_walk(self):
        self.walk_cancelled = True

    def settings_moved(self):
        return self.generation is not None and self.controller.snapshot().config_generation != self.generation

    def _say(self, text):
        if self.on_progress is not None:
            self.on_progress(text)

    async def _answer(self, query, answer, release, stale, walking=False):
        loop = asyncio.get_running_loop()
        deadline = loop.time() + ANSWER_SECONDS
        try:
            while self.alive() and not (walking and self.walk_cancelled):
                result = answer(query)
                if result is not None:
                    return result
                if stale():
                    return _STALE
                if loop.time() > deadline:
                    raise TableUnavailable(EXPORT_TIMEOUT)
                await asyncio.sleep(POLL)
            raise TableUnavailable('')
        finally:
            release(query)

    async def _walk(self, start, request, answer, release, read, stale=lambda: False):
        """Every row from ``start``: ``request(position)`` asks for a page, ``read(result)`` says
        ``('rows', rows, next position, total)``, ``('busy', text)`` or ``('error', text)``."""
        self.walk_cancelled = False
        self._say(EXPORT_PREPARING)
        rows, position, pages, retries = [], start, 0, 0
        limit = table_export.MAX_EXPORT_ROWS
        while True:
            if self.walk_cancelled or not self.alive():
                raise TableUnavailable('')
            if self.settings_moved():
                raise TableUnavailable(EXPORT_TABLE_CHANGED)
            query = request(position)
            result = await self._answer(query, answer, release, stale, walking=True)
            if result is _STALE:
                raise TableUnavailable(self.refused())
            outcome, *value = read(result)
            if outcome == 'busy':
                retries += 1
                if retries > BUSY_RETRIES:
                    raise TableUnavailable(value[0])
                await asyncio.sleep(BUSY_PAUSE * retries)
                if not self.alive():  # the page was left during the pause: nothing more is asked of the worker
                    raise TableUnavailable('')
                continue
            if outcome == 'error':
                raise TableUnavailable(value[0])
            items, following, total = value
            retries, pages = 0, pages + 1
            rows.extend(items)
            if len(rows) > limit or (type(total) is int and total > limit):
                raise TableUnavailable(export_too_many(limit))
            if following is None:
                return rows
            if not items or (type(following) is int and following <= position):
                raise TableUnavailable(self.refused())  # an answer that does not move on would never end
            position = following
            if pages % PROGRESS_PAGES == 0:
                self._say(table_actions.progress_text(len(rows), total if type(total) is int else None))

    def refused(self):
        return HISTORY_UNAVAILABLE


class LiveSource(WorkerPages):
    """The latest complete round of the run ``key = (job, run id, revision)``, held by the worker. Pages are addressed
    by their number (``seekable``). The page moves ``key`` to each new revision and refreshes the table; a request for
    a revision that has gone asks again for the current one. ``exact`` is Show in table's one host: while the filter
    holds exactly that text, the table lists the host of that name only."""
    seekable = True

    def __init__(self, controller, key, **kwargs):
        super().__init__(controller, **kwargs)
        self.key = key
        self.exact = None

    def current(self):
        return (self.controller.snapshot().monitor_update or {}).get('revision')

    def options(self, state):
        exact = bool(self.exact) and state.query == self.exact
        return (state.sort, state.descending, state.group, 'host' if exact else ANY, state.query) + ((True,) if exact else ())

    def refused(self):
        return LIVE_CHANGED if self.current() not in (None, self.key[2]) else LIVE_UNAVAILABLE

    async def fetch(self, state, cursor=None):
        self._newest += 1
        token = self._newest
        limit = table_export.page_limit(state.size)
        offset, options = state.page * limit, self.options(state)
        for _ in range(4):
            job, run, revision = self.key
            try:
                query = self.controller.request_monitor_live_page(job, run, revision, offset, limit, *options)
            except (AttributeError, RuntimeError, ValueError):
                if self.current() not in (None, revision):
                    self.key = (job, run, self.current())
                    continue
                raise TableUnavailable(LIVE_UNAVAILABLE) from None
            result = await self._answer(
                query, self.controller.monitor_live_page, self.controller.release_monitor_live_page,
                lambda: token != self._newest or self.current() not in (None, revision))
            if result is _STALE:
                if token != self._newest:
                    raise TableUnavailable('')  # a newer request of this table answers instead
                self.key = (job, run, self.current())
                continue
            status, total, rows = result.get('status'), result.get('total'), result.get('rows') or []
            if status == 'expired':
                self.key = (job, run, result.get('current_revision', revision))
                continue
            if status == 'not_ready':
                raise TableUnavailable(WAITING_ROUND)
            if status != 'ready':
                raise TableUnavailable(LIVE_UNAVAILABLE)
            if not rows and offset:  # the new round has fewer rows: its last page (the first when it cannot say)
                offset = last_page(total, state.size) * limit if type(total) is int else 0
                continue
            counts, whole = counted(result.get('counts'), total)
            return Page([live_row(row) for row in rows], total=total, offset=offset, counts=counts, unfiltered=whole,
                        next=state.page + 1 if result.get('next_offset') is not None else None)
        raise TableUnavailable(LIVE_UNAVAILABLE)

    async def all_rows(self, state):
        job, run, revision = self.key
        options = self.options(state)

        def request(offset):
            try:
                return self.controller.request_monitor_live_page(job, run, revision, offset,
                                                                 table_export.MAX_PAGE_ROWS, *options)
            except (AttributeError, RuntimeError, ValueError):
                raise TableUnavailable(self.refused()) from None

        def read(result):
            if result.get('status') == 'expired' or result.get('revision', revision) != revision:
                return 'error', LIVE_CHANGED
            if result.get('status') != 'ready':
                return 'error', LIVE_UNAVAILABLE
            return 'rows', [live_row(row) for row in result.get('rows') or []], result.get('next_offset'), result.get('total')
        # The controller drops an answer whose revision is no longer current: never wait for it.
        return await self._walk(0, request, self.controller.monitor_live_page, self.controller.release_monitor_live_page,
                                read, stale=lambda: self.current() not in (None, revision))


class HistorySource(WorkerPages):
    """The hosts of a saved round (``kind='hosts'``, ``parent`` its id) or Show Available (``'coverage'``, the saved
    target's id), read from the history file a page at a time by cursors. ``on_answer(result)`` sees every page the
    table draws (Show Available's summary and download read it)."""

    def __init__(self, controller, kind, parent, *, on_answer=None, **kwargs):
        super().__init__(controller, **kwargs)
        self.kind, self.parent, self.on_answer = kind, parent, on_answer
        self.row = round_host_row if kind == 'hosts' else coverage_row
        self.messages = ({'expired': ROUND_EXPIRED, 'too_large': ROUND_TOO_LARGE} if kind == 'hosts'
                         else {'expired': COVERAGE_EXPIRED})
        self.fold = None  # Show Available: the rounds and counts of the fold the table shows

    def options(self, state):
        return state.sort, state.descending, state.group, ANY, state.query

    def _ask(self, cursor, limit, state):
        try:
            return self.controller.request_monitor_history(self.kind, self.parent, cursor, limit, *self.options(state))
        except (AttributeError, RuntimeError, ValueError):
            raise TableUnavailable(HISTORY_UNAVAILABLE) from None

    async def fetch(self, state, cursor=None):
        self._newest += 1
        token = self._newest
        worker_cursor, offset = cursor if cursor else (None, 0)
        retries = 0
        while True:
            query = self._ask(worker_cursor, table_export.page_limit(state.size), state)
            result = await self._answer(query, self.controller.monitor_history_page,
                                        self.controller.release_monitor_history_page, lambda: token != self._newest)
            if result is _STALE:
                raise TableUnavailable('')
            error = result.get('error')
            if error and str(error).startswith('History reader is busy') and retries < BUSY_RETRIES:
                retries += 1
                await asyncio.sleep(BUSY_PAUSE * retries)
                if not self.alive():  # the page was left during the pause: nothing more is asked of the worker
                    raise TableUnavailable('')
                continue
            if self.on_answer is not None:
                self.on_answer(result)
            if error:
                raise TableUnavailable(self.messages.get(error) or history_error_message(error))
            items = result.get('items') or []
            self.fold = ((result.get('summary') or {}).get('rounds'), tuple(sorted((result.get('counts') or {}).items())))
            counts, whole = counted(result.get('counts'), result.get('total'))
            following = result.get('next_cursor')
            return Page([self.row(item) for item in items], total=result.get('total'), offset=offset, counts=counts,
                        unfiltered=whole, next=(following, offset + len(items)) if following else None)

    async def all_rows(self, state):
        fold = self.fold
        changed = {'hosts': ROUND_CHANGED, 'coverage': COVERAGE_CHANGED}[self.kind]

        def read(result):
            error = result.get('error')
            if error and str(error).startswith('History reader is busy'):
                return 'busy', str(error)
            if error:
                return 'error', changed if error == 'expired' else self.messages.get(error) or history_error_message(error)
            if self.kind == 'coverage' and ((result.get('summary') or {}).get('rounds'),
                                            tuple(sorted((result.get('counts') or {}).items()))) != fold:
                # A round recorded since the table was drawn refolds the history: the file would not be this table.
                return 'error', COVERAGE_CHANGED
            return 'rows', [self.row(item) for item in result.get('items') or []], result.get('next_cursor') or None, result.get('total')
        return await self._walk(None, lambda cursor: self._ask(cursor, table_export.MAX_PAGE_ROWS, state),
                                self.controller.monitor_history_page, self.controller.release_monitor_history_page, read)


# --- the History lists: saved targets, runs and rounds ----------------------------------------------------------------

def history_list_label(kind):
    return {'requests': 'Saved monitor targets', 'runs': 'Monitor runs'}.get(kind, 'Rounds')


def history_footer(kind, view, page, cursors, *, on_size, on_go):
    """The footer of a History list (the one footer of every table): ``view`` is the list's own state (its ``size``),
    ``page`` the worker's answer and ``cursors`` the cursors of the pages opened, the first None. The controls carry
    ``data-monitor-history`` (``first``, ``previous``, ``next``, ``page-size``), by which the page puts the focus back
    after the list is drawn again."""
    size = view.get('size', HISTORY_SIZE)
    footer = PageFooter(history_list_label(kind), on_size=on_size, on_go=on_go, sizes=HISTORY_SIZES)
    for key, button in footer.buttons.items():
        button._props['data-monitor-history'] = key
    footer.select._props['data-monitor-history'] = 'page-size'
    number = len(cursors) - 1
    items = (page or {}).get('items') or []
    footer.show(Page(items, total=(page or {}).get('total'), offset=number * size,
                     next=(page or {}).get('next_cursor') or None), TableState(page=number, size=size))
    return footer


def history_size(value):
    """The rows per page a History list's footer sent, or None for one it does not offer."""
    size = size_choice(value)
    return size if size in HISTORY_SIZES else None
