"""The view of a tool in the URL's query (R2-08): what is open and how its table is arranged, never what was typed.

Design: "R2-08 design note" in ``docs/plans/webui-ux-plan.md``. The tool's tab state (``subnets.Presentation``,
``monitor_state.MonitorTab``, the kept ``tables.TableState``s) is the one source of truth; the URL is its projection:

- after every change the page calls ``ViewState.replace()`` (an adjustment of the same view) or ``push()`` (a step
  that Back should undo), which encode the tab state's view (non-default values only, in the schema's order) and write
  the current history entry when it differs;
- on arrival (a load, a reload, an in-app switch, a Back to another tool's entry) a query that names at least one
  parameter of the schema is the whole view (a name it leaves out is its default), read into the tab state before the
  page draws (``take``): the URL wins on arrival. A query that names none keeps the tab state, and the URL is written
  from it, so an in-app switch finds each tool's own query again;
- Back and Forward between two views of one tool reach the router's ``on_path_changed``, which hands the path to the
  current scope's ``ViewState`` (``popped``): the page applies it as if the reader had clicked, without a rebuild.

Every value is input: ``parse_query`` drops unknown names, gives a bad value its default, bounds numbers, cuts text
and ignores a query that is too long; ids are looked up by the page and a miss is ``gone()`` (the default view and one
line that says so). Nothing typed into a form ever goes in (I6). The pure half imports the standard library only;
NiceGUI is imported inside the methods.
"""
from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, quote

from .table_export import PAGE_SIZES

# A longer query is not a view this page wrote: it is ignored whole. Sized for what the page itself can write: the
# longest view (the Monitor's, every text at its limit in four-byte characters, twelve characters each once percent
# encoded) is about 5,100 characters, so 6 KiB reads every generated URL back (a test builds the worst case of every
# schema). It is still a bound on a hostile URL: at most 6,144 characters are split and parsed, whatever the request
# line the server accepted, and each value is cut or refused after that (the filter text at ``MAX_TEXT``).
MAX_QUERY_STRING = 6144
MAX_TEXT = 256           # tables.MAX_QUERY
MAX_PAGE = 1_000_000
GONE = 'This link points to a result that is no longer here.'
LINK = 'Copy view link'
LINK_DESCRIPTION = 'Copies the address of this view: what is open and how its table is arranged. It holds nothing you typed.'
LINK_COPIED = 'Link copied. It opens this view in another tab of this session.'
LINK_NOT_FOCUSED = 'The browser did not allow the copy because this tab was not active. Return to this tab and select Copy view link again.'
LINK_NOT_ALLOWED = 'The browser did not allow the copy. Select Copy view link again.'
LINK_UNAVAILABLE = "This browser cannot copy here: copy the address from the browser's address bar."
_HEX_ID = re.compile(r'[0-9a-f]{32}')


@dataclass(frozen=True)
class Param:
    """One parameter: ``parse(text)`` gives its value or raises ValueError (then it is ``default``); ``text(value)``
    writes it."""
    parse: Callable[[str], Any]
    default: Any = None
    text: Callable[[Any], str] = str


def text_value(limit=MAX_TEXT):
    def parse(value):
        return value[:limit]
    return parse


def word(value):
    """A column or group key: printable, at most 64 characters (the table says whether it is one of its own)."""
    if not value or len(value) > 64 or not value.isprintable():
        raise ValueError(value)
    return value


def choice(*values):
    def parse(value):
        if value not in values:
            raise ValueError(value)
        return value
    return parse


def whole(low, high):
    def parse(value):
        if not re.fullmatch(r'[0-9]{1,19}', value):
            raise ValueError(value)
        number = int(value)
        if not low <= number <= high:
            raise ValueError(value)
        return number
    return parse


def group_id(value):
    """A Subnets network's group id (the worker's uuid4 hex) or ``all`` (Show all details)."""
    if value != 'all' and not _HEX_ID.fullmatch(value):
        raise ValueError(value)
    return value


def run_id(value):
    """A saved run's id as the history reader takes it: printable, at most 128 bytes."""
    if not value or not value.isprintable() or len(value.encode('utf-8')) > 128:
        raise ValueError(value)
    return value


def _size(value):
    for size in PAGE_SIZES:
        if value == str(size):
            return size
    raise ValueError(value)


def table_schema(*, group=False):
    """The fields of the view's table: ``q`` (its filter), ``sort``, ``dir``, ``page`` (1-based in the URL), ``size``,
    and ``group`` for a table with group buttons."""
    schema = {'q': Param(text_value(), ''), 'sort': Param(word, ''), 'dir': Param(choice('asc', 'desc'), 'asc'),
              'page': Param(whole(1, MAX_PAGE), 1), 'size': Param(_size, 25)}
    if group:
        schema['group'] = Param(word, 'all')
    return schema


LOOKUP_SCHEMAS = {
    'subnet': {'net': Param(group_id), **table_schema()},
    'ip': table_schema(),
    'ping': table_schema(group=True),
}
MONITOR_SCHEMA = {'tab': Param(choice('live', 'history'), 'live'), 'view': Param(choice('map', 'table')),
                  'req': Param(whole(1, 2**63 - 1)), 'run': Param(run_id), 'round': Param(whole(1, 2**63 - 1)),
                  **table_schema(group=True)}
MATCHES_SCHEMA = table_schema()
TABLE_KEYS = tuple(table_schema(group=True))


def split(path):
    """``(path, query)`` of a router path (``/ip?q=x#y``: ``('/ip', 'q=x')``)."""
    path = (path or '/').split('#', 1)[0]
    route, _, query = path.partition('?')
    return route or '/', query


def names_any(query, schema) -> bool:
    """Whether the query names a parameter of the schema (with any value): then it is the whole view."""
    if not query or len(query) > MAX_QUERY_STRING:
        return False
    return any(name in schema for name, _ in parse_qsl(query, keep_blank_values=True))


def parse_query(query, schema) -> dict:
    """The view a query asks for: every name of the schema, its value parsed and bounded, else its default. Unknown
    names are dropped, the first of a repeated name counts, and a query over ``MAX_QUERY_STRING`` is ignored whole."""
    values = {name: param.default for name, param in schema.items()}
    if not query or len(query) > MAX_QUERY_STRING:
        return values
    seen = set()
    for name, raw in parse_qsl(query, keep_blank_values=True):
        if name not in schema or name in seen:
            continue
        seen.add(name)
        try:
            values[name] = schema[name].parse(raw)
        except ValueError:
            pass
    return values


def encode(values: Mapping, schema) -> str:
    """``?a=1&b=2`` for the values that differ from their default, in the schema's order; '' for the default view."""
    parts = []
    for name, param in schema.items():
        value = values.get(name, param.default)
        if value is None or value == param.default:
            continue
        parts.append(f'{name}={quote(param.text(value), safe="")}')
    return '?' + '&'.join(parts) if parts else ''


def table_values(state) -> dict:
    """The URL's fields of a ``TableState`` (``page`` 1-based)."""
    if state is None:
        return {}
    return dict(q=state.query, sort=state.sort, dir='desc' if state.descending and state.sort else 'asc',
                page=state.page + 1, size=state.size, group=state.group)


def set_table(state, values) -> None:
    """Put the URL's table fields into ``state`` (a ``TableState``), as the table would after the reader's own
    changes; the table validates them against its columns and groups (``tables.normalise``) when it draws. A source
    that is not seekable reaches ``page`` by the cursors ``state`` kept when they still describe it (the same
    arrangement, and they reach that far: a Back within the tab); else it opens on its first page, since cursors are
    not in the URL, and the URL is written from what it shows (``table_drawn``)."""
    arrangement = (state.query, state.sort, state.descending, state.size, state.group)
    state.query = values.get('q') or ''
    state.sort = values.get('sort') or ''
    state.descending = bool(state.sort) and values.get('dir') == 'desc'
    state.page = max(0, (values.get('page') or 1) - 1)
    state.size = values.get('size') or 25
    state.group = values.get('group') or 'all'
    kept = arrangement == (state.query, state.sort, state.descending, state.size, state.group)
    state.cursors = state.cursors[:state.page + 1] if kept and state.page < len(state.cursors) else [None]


def table_named(values) -> bool:
    """Whether the values arrange a table (anything but its defaults)."""
    defaults = table_schema(group=True)
    return any(values.get(name, defaults[name].default) != defaults[name].default for name in defaults)


def clipboard_message(result) -> str:
    """What the line under Copy view link says for the browser's answer to the write."""
    result = str(result or '')
    if result == 'ok':
        return LINK_COPIED
    if result == 'unavailable':
        return LINK_UNAVAILABLE
    return LINK_NOT_FOCUSED if 'focus' in result.lower() else LINK_NOT_ALLOWED


# Written in the browser only while it is still on the tool's path: a write that races a switch to another tool must
# not rename that tool's entry. The router pushes a tool's path just after it draws the tool, so a write that finds
# the browser on another path tries once more a moment later, and is dropped if it is still not there. A pushed entry
# carries its path in the state, as the router's own entries do. A write also names the address of the entry it was
# computed for (``entry``, what the view last wrote or applied there) and is dropped if the browser is on another one:
# a Back or Forward that overtook it must not find that entry rewritten with a newer arrangement.
_WRITE = '''(() => {
  const write = (late) => {
    if (location.pathname !== %(route)s) { if (!late) setTimeout(() => write(true), 200); return; }
    const here = location.pathname + location.search;
    if (here === %(url)s) return;
    if (%(entry)s !== null && here !== %(entry)s) return;  // the browser has moved on: this is another entry's write
    history.%(method)s({page: %(url)s}, '', %(url)s);
  };
  write(false);
})()'''


def _home():
    """The element a page is being built in, or None outside a page (a unit test's client)."""
    from nicegui import ui
    try:
        return ui.context.slot.parent
    except RuntimeError:
        return None


class ViewState:
    """The URL of one tool's page in one tab (``scope``): ``values()`` reads the view from the tab state, in the
    names of ``schema``. Made when the page is built; it reads the arrival's query then."""

    def __init__(self, scope, schema, values):
        self.scope, self.schema, self.values = scope, schema, values
        self.client = scope.client
        self.route, query = split(self.client.sub_pages_router.current_path)  # the router's path, not the tab's request
        self.pending = parse_query(query, schema) if names_any(query, schema) else None
        self.written = None  # nothing written yet: the first replace() writes the URL whatever it holds
        self._pop = None
        self._notice = None
        self._gone_at = False  # False: no message; None: shown, before the write of the view it opened; else that query
        self._home = _home()  # the page's element: a pop is applied inside it (a task has no slot)
        self._link = None
        self._pops = 0  # the number of the latest pop: an apply that has been overtaken writes nothing
        self._busy = 0
        self._waiting = 0  # pops received and not yet applied: the page's own writes wait for them (its state is older)
        self.applying = False  # a pop is being applied: the URL is the entry's already, until it is done
        scope.view_state = self

    # --- arrival ------------------------------------------------------------------------------------------------
    def take(self):
        """The view the URL asked for, once (None when it asked for none: the tab state stands)."""
        values, self.pending = self.pending, None
        return values

    def gone(self):
        """The link's result is not here: the page has opened its default view; say so until the reader changes it."""
        self._gone_at = None
        if self._notice is not None and not self._notice.is_deleted:
            self._notice.set_text(GONE)

    def notice(self):
        """The line that says a link pointed to something gone (``role=status``), drawn where the page calls it."""
        from nicegui import ui
        from .scope import add_once
        add_once(self.client, 'view-state', css='.cn-view-gone:empty { display:none; }')  # no gap while it is silent
        self._notice = ui.label(GONE if self._gone_at is not False else '').props('role=status data-cn-view-gone')
        self._notice.classes('cn-muted cn-view-gone')
        return self._notice

    # --- writes -------------------------------------------------------------------------------------------------
    def replace(self):
        self._write('replaceState')

    def push(self):
        self._write('pushState')

    def query(self):
        return encode(self.values(), self.schema)

    def follow(self):
        """A table of the page has drawn (``table_drawn``): the URL says what it shows (a page it clamped, or a page
        it could not reach and opened on its first instead), at once. Only the table's fields: a step the page is
        taking (another view, to be pushed) is the page's to write, so it is not written over the entry it leaves."""
        if self.written is None or self.applying:
            return
        now = self.values()
        then = parse_query(self.written[1:], self.schema)
        if all(now.get(name, param.default) == then[name] for name, param in self.schema.items()
               if name not in TABLE_KEYS):
            self.replace()

    def _write(self, method):
        if not self.scope.alive or self.client.is_deleted or self._waiting:
            return
        query = self.query()
        if self._gone_at is None:
            self._gone_at = query
        elif self._gone_at is not False and query != self._gone_at:
            self._gone_at = False
            if self._notice is not None and not self._notice.is_deleted:
                self._notice.set_text('')
        if query == self.written:
            return
        before, self.written = self.written, query
        url = self.route + query
        entry = None if before is None else self.route + before  # the address this write replaces or follows
        self.client.sub_pages_router.current_path = url  # the router's idea of the path follows the URL
        if self.client.has_socket_connection:
            self.client.run_javascript(_WRITE % dict(route=json.dumps(self.route), url=json.dumps(url),
                                                     entry=json.dumps(entry), method=method))

    # --- Back and Forward ---------------------------------------------------------------------------------------
    def on_pop(self, handler):
        """``handler(values)`` (may be async) applies a view that Back or Forward brought."""
        self._pop = handler

    def on_link(self, handler):
        """``handler()`` (may be async): the navigation's link of this tool was followed while the tab is on it. Without
        one the view stays and the URL is written from it (an arrival with no view parameter keeps the tab's)."""
        self._link = handler

    def linked(self):
        """From the router: the link of the tool the tab is on (no query). Nothing is pushed or read from a URL."""
        if not self.scope.alive:
            return
        if self._link is None:
            self.replace()
            return
        self.scope.task(self._run(self._link), name='view-state-link')

    def popped(self, path):
        """From the router: the tab is on this tool with ``path``'s query. Applied as if the reader had clicked."""
        if not self.scope.alive:
            return
        _, query = split(path)
        values = parse_query(query, self.schema)
        self.written = encode(values, self.schema)
        self.route = split(path)[0]
        self._pops += 1
        if self._pop is None:
            return
        self._waiting += 1
        self.scope.task(self._apply(values, self._pops), name='view-state-pop')

    async def _apply(self, values, pop):
        self._busy += 1
        self.applying = True
        try:
            await self._run(lambda: self._pop(values))
        finally:
            self._busy -= 1
            self._waiting -= 1
            self.applying = self._busy > 0
        await self._after_apply()
        if pop == self._pops:  # a later Back or Forward has the URL now
            self.replace()  # what the entry asked for may not all be here (a page, an id): the URL says what is shown

    async def _after_apply(self):
        """The seam between an apply's work and its URL write (a test holds it)."""

    async def _run(self, call):
        from contextlib import nullcontext
        with self._home if self._home is not None else nullcontext():
            result = call()
            if hasattr(result, '__await__'):
                await result


def set_title(client, key, prefix=''):
    """The document title of tool ``key``, after ``prefix`` when the view names one ("192.0.2.0/24 – Subnets – cn-tool")."""
    from .shell import PAGES
    page = next((page for page in PAGES if page.key == key), None)
    if page is None or client.is_deleted:
        return
    title = f'{prefix} – {page.title}' if prefix else page.title
    if client.title != title:
        client.title = title
        if client.has_socket_connection:
            client.run_javascript(f'document.title = {json.dumps(title)}')


def popped(scope, path):
    """The router's hook for a path that stays on the current tool: its ``ViewState``, if it has one, applies it."""
    view = getattr(scope, 'view_state', None) if scope is not None else None
    if view is not None:
        view.popped(path)


def linked(scope):
    """The router's hook for the navigation's link of the tool the tab is on: its ``ViewState`` keeps the view."""
    view = getattr(scope, 'view_state', None) if scope is not None else None
    if view is not None:
        view.linked()


def table_drawn(client):
    """``tables``' hook after a table drew: the current tool's URL follows its tables (``ViewState.follow``)."""
    from .scope import current
    view = getattr(current(client), 'view_state', None)
    if view is not None:
        view.follow()


async def copy_link(client, status):
    """Copy view link: the tab's own address (``location.href``) to the clipboard; ``status`` is the line that says how
    that went. The address holds only view parameters."""
    from . import table_actions
    try:
        result = await client.run_javascript(table_actions.CLIPBOARD_SCRIPT % 'location.href', timeout=10)
    except TimeoutError:
        result = 'focus'  # no answer: the tab is not active
    except Exception:  # the tab went away
        return
    if not status.is_deleted:
        status.set_text(clipboard_message(result))


def link_button():
    """A Copy view link button with its own ``role=status`` line, for a view that has no table toolbar beside it (a
    network's details, a run's rounds)."""
    from nicegui import ui
    client = ui.context.client
    with ui.element('div').classes('row items-center gap-2 cn-view-link').props('role=group aria-label="View link"'):
        button = ui.button(LINK).props('outline dense no-caps data-cn-view-link')
        button._props['aria-description'] = LINK_DESCRIPTION
        status = ui.label('').props('role=status aria-live=polite').classes('cn-muted')
        button.on_click(lambda: copy_link(client, status))
    return button
