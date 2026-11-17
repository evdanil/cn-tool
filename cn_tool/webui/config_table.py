"""The tables of Configuration Search and Site Demobilization: ``tables.cn_table`` over the pages the worker holds.

The rows of a configuration search and the networks of a site preview stay in the worker (a result can hold 10,000
rows). ``WorkerPages`` is the ``PagedSource`` of such a table: it asks the controller for one page (sorted and filtered
by the worker over every column, ``protocol`` ``filter_by`` None), waits for the answer and gives it to the table.
Pages are addressed by the worker's own offsets, because a page can be shorter than asked when it reaches its byte
limit. Pure apart from the ``tables`` import (NiceGUI is imported by ``cn_table``, not here).
"""
from __future__ import annotations

import asyncio
from time import monotonic

from html import escape

from . import config_marks
from .table_export import MAX_PAGE_ROWS, page_limit
from .tables import Column, Page, RowGroup, TableUnavailable, columns_of
from .texts import plural

ANSWER_SECONDS = 10      # how long a page may take before the table says it is unavailable
POLL_SECONDS = 0.02
EXPIRED = 'Results are unavailable. Run the search again.'

# The wire row of a match is [search term, device, line (from 0), the matching line, the file] and, when the search
# child found where the line matched, a sixth field: its spans, [[start, end], ...] (``config_marks``).
MATCH_KEYS = ('search', 'device', 'line', 'configuration', 'file', 'spans')


def match_rows(page) -> list:
    """The rows of one configuration page as the table's rows (keys of ``protocol.CONFIG_COLUMNS``), each with the
    matches its device has under the filter (``_matches``: the worker counts them, a page holds only some)."""
    counts = page.get('device_counts') or {}
    rows = [dict(zip(MATCH_KEYS, row)) for row in page['rows']]
    for row in rows:
        row['_matches'] = counts.get(row['device'])
    return rows


def _configuration(row) -> str:
    line = str(row.get('configuration') or '')
    return f'<div class="cn-cell" style="max-width:80ch" title="{escape(line, quote=True)}">' \
           f'{config_marks.mark_html(line, row.get("spans"))}</div>'


def _file(row) -> str:
    path = str(row.get('file') or '')
    if not path:
        return ''
    name = f"Copy path of {row.get('device')}, line {row.get('line')}"
    return (f'<div class="cn-file"><div class="cn-cell" title="{escape(path, quote=True)}">{escape(path)}</div>'
            f'<button type="button" class="cn-copy-path" data-copy-path="{escape(path, quote=True)}" '
            f'aria-label="{escape(name, quote=True)}">Copy path</button></div>')


def match_columns() -> list:
    """Device (the identity), the line (numbered from 0, as the workbook and the command line do), the matching line
    with its match marked, and the file with a button that copies its path. The search is one line above the table."""
    return [Column('device', 'Device', sticky=True), Column('line', 'Line (from 0)'),
            Column('configuration', 'Matching configuration', max_ch=80, html=_configuration),
            Column('file', 'File', html=_file)]


# The search is one line above the table on screen; the file keeps it for each row (which term or network found it).
EXPORT_EXTRA = [Column('search', 'Search')]


def device_header(row) -> str:
    count = row.get('_matches')
    return str(row.get('device')) + (f' · {plural(count, "match", "matches")}' if count else '')


def by_device(state) -> bool:
    """Header rows by device only where the rows of a device are next to each other: in the search's own order and
    sorted by device."""
    return state.sort in ('', 'device')


GROUPING = RowGroup('device', device_header, by_device)


def search_line(page) -> str:
    """"Search: 192.0.2.0/24, router-name": what was searched, once, above the table (the rows of a search all say it)."""
    seen = dict.fromkeys(part.strip() for row in page.rows for part in str(row.get('search') or '').splitlines() if part.strip())
    return 'Search: ' + ', '.join(seen) if seen else ''


MATCH_CSS = '''
.cn-file { display:flex; align-items:center; gap:8px; }
.cn-file .cn-cell { max-width:40ch; }
'''

# One click listener for the whole page: copy the path the button holds, and say so (or say that it could not).
COPY_SCRIPT = """<script>
(() => {
  if (window.cnCopyPath) return;
  window.cnCopyPath = true;
  const say = (text) => {
    let box = document.querySelector('[data-copy-status]');
    if (!box) {
      box = document.createElement('div');
      box.setAttribute('role', 'status');
      box.setAttribute('data-copy-status', '');
      box.className = 'cn-sr-only';
      document.body.appendChild(box);
    }
    box.textContent = text;
  };
  document.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-copy-path]');
    if (!button) return;
    const original = button.textContent;
    try {
      await navigator.clipboard.writeText(button.dataset.copyPath);
      button.textContent = 'Copied';
      say('Path copied.');
    } catch (error) {
      say('The path could not be copied. Select it in the table and copy it.');
    }
    setTimeout(() => { if (button.isConnected) button.textContent = original; }, 2000);
  });
})();
</script>"""


def network_columns(names) -> list:
    """The columns of a site's networks, from the names the worker reports: the network and its view first."""
    lead = [name for wanted in ('network', 'network view') for name in names if name.lower() == wanted]
    return columns_of([dict.fromkeys(names, '')], lead, sticky=lead[0] if lead else '')


class WorkerPages:
    """A ``PagedSource`` over a worker-held result.

    ``request(offset, limit, sort_by, descending, filter_text)`` returns a query id (or raises what the controller
    raises when the result is gone), ``read(query)`` the answer or None while it is on its way, ``release(query)``
    lets the controller forget it, ``rows(page)`` makes the table's rows of an answer.
    """
    seekable = False

    def __init__(self, request, read, release, rows, unavailable=EXPIRED):
        self._request, self._read, self._release, self._rows = request, read, release, rows
        self._unavailable = unavailable
        self._seed = None

    def seed(self, answer, limit):
        """An answer for the first page (no filter, no sort, ``limit`` rows) that the page already has: the table's own
        first read takes it instead of asking again."""
        self._seed = (answer, limit)

    async def _page(self, state, offset, limit):
        sort = state.sort or None
        try:
            query = self._request(offset, limit, sort, bool(state.descending) if sort else False, state.query.strip())
        except (ValueError, RuntimeError, OSError, EOFError):
            raise TableUnavailable(self._unavailable) from None
        try:
            deadline = monotonic() + ANSWER_SECONDS
            while True:
                answer = self._read(query)
                if answer is not None:
                    break
                if monotonic() > deadline:
                    raise TableUnavailable(self._unavailable)
                await asyncio.sleep(POLL_SECONDS)
        finally:
            self._release(query)
        if answer.get('status') != 'ready':
            raise TableUnavailable(self._unavailable)
        return answer

    async def fetch(self, state, cursor=None) -> Page:
        limit = page_limit(state.size)
        seed, self._seed = self._seed, None
        if seed and not cursor and not state.query.strip() and not state.sort and seed[1] == limit:
            answer = seed[0]
        else:
            answer = await self._page(state, cursor or 0, limit)
        total = answer['total']
        return Page(self._rows(answer), total=total, offset=answer['offset'], next=answer['next_offset'],
                    unfiltered=answer.get('overall_total', total))

    async def all_rows(self, state) -> list:
        """Every row as filtered and sorted: the pages are walked from the first."""
        rows, offset = [], 0
        while offset is not None:
            answer = await self._page(state, offset, MAX_PAGE_ROWS)
            rows.extend(self._rows(answer))
            offset = answer['next_offset']
        return rows


def match_pages(controller, job) -> WorkerPages:
    """The matches of one finished configuration search (``job`` is the result's job id)."""
    def request(offset, limit, sort, descending, text):
        return controller.request_config_search_page(job, offset, limit, sort_by=sort, descending=descending,
                                                     filter_by=None, filter_text=text)
    return WorkerPages(request, controller.config_search_page, controller.release_config_search_page, match_rows)


def network_pages(controller, token) -> WorkerPages:
    """The networks of a site's preview (``token`` is the preview's)."""
    def request(offset, limit, sort, descending, text):
        return controller.request_demob_page(token, offset, limit, sort_by=sort, descending=descending,
                                             filter_by=None, filter_text=text)
    return WorkerPages(request, controller.demob_page, controller.release_demob_page, lambda page: page['rows'],
                       'Preview expired or is unavailable. Look up the site again.')
