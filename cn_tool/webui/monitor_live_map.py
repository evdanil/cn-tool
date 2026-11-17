"""The Monitor's Map on the server (R2-11): the Map / Table switch, the map's area, its four events and the reads of
the worker's map of the latest round. ``monitor_map`` is the map itself (layout, CSS and the one script, which the
page adds once per document); this is what a Monitor page does with it, through the page's ``PageScope``:

- ``start()`` sends ``cnMonitorMap.init`` when the page is built (``scope.js``) and ``dispose`` when it is left, so the
  document holds one set of the Map's listeners, observer and timer however often the Monitor is opened inside the
  root; the Live panel's choice sends ``init`` again (``restart``), for a page built on its History panel, whose Map
  box is not drawn until then;
- its four events go through ``scope.on_event``, so an event of a page that was left reaches nothing, and every
  handler asks ``scope.alive`` at its start and after each await;
- ``follow(...)``, from the page's poll, asks for the map of the latest round while the tab shows the Map and has said
  how wide its box is, and draws the answer (a new round replaces only the rows that changed); ``release()`` gives up
  what it asked for when the page is left or another run is shown.

NiceGUI is imported inside the functions.
"""
import asyncio
import json
import secrets
from time import monotonic

from . import monitor_map

# What the live view says while it has no round to show: its first round is on its way, or no monitor runs.
WAITING = 'Waiting for the first complete round.'
NOT_RUNNING = 'No monitor is running. Start one above, or open History.'
WANT_SECONDS = 10  # how long a "Show on map" waits for the Map to have the cell
NOT_ON_MAP = 'That host has no place the Map can draw. It is in the Table.'
UNAVAILABLE = 'The map of the latest round is unavailable.'
NOT_READY = 'Waiting for the first complete round. No result is inferred for an unfinished round.'
DISPOSE = 'window.cnMonitorMap && window.cnMonitorMap.dispose()'


def set_changed(label, value):
    if label.text != value:
        label.set_text(value)


def _whole(value, low, high):
    return value if type(value) is int and low <= value <= high else None


def _args(event):
    return event.args if isinstance(event.args, dict) else {}


def _mine(self, event):
    """The event's arguments, or None for an event that is not this page's map's: the dispatch is by event name per tab,
    so one sent by a map that was left can arrive after the Monitor was opened again (its token is the old one)."""
    args = _args(event)
    return args if args.get('token') == self.token else None


class LiveMap:
    """The Map of one Monitor page. ``poll`` is the page's poll (awaited after a report of the view or a block);
    ``show_in_table(target)`` is the page's Show in table; ``view`` is the tab's choice ('map' until the tab says)."""

    def __init__(self, controller, scope, *, poll, show_in_table):
        self.controller, self.scope, self.client = controller, scope, scope.client
        self.poll, self.show_in_table = poll, show_in_table
        self.view, self.cols, self.show = 'map', 0, -1
        self.query = self.key = self.payload = self.revision = self.drawn = self.host_query = None
        self.buttons = {}
        self.changed = None  # called when the tab reports its view (the URL follows it, R2-08)
        self.forced = None   # a link's Map or Table for this load: shown, not stored (the tab's own choice stays)
        self.want = None     # (block, cell) the change list asked for: moved to once the Map shows it
        self.token = secrets.token_hex(8)  # in the map's init and in each of its events: another page's are ignored

    # --- drawn by the page, in its order ---------------------------------------------------------------------------
    def switch(self):
        """The Map / Table group. Off until the page's first poll has drawn what is above it (``enable``): that moves
        it down, and a click straddling the move lands on the panel and is lost."""
        from nicegui import ui
        with ui.element('div').props('role=group aria-label="Latest round view"').classes('cn-monitor-toolbar cn-live-switch'):
            for name, label in (('map', 'Map'), ('table', 'Table')):
                button = ui.button(label, on_click=lambda _, value=name: self.choose(value)).props('outline dense')
                button._props['data-monitor-view'] = name
                button.disable()
                self.buttons[name] = button
        self.set_buttons()

    def area(self, wrap):
        """The map's area inside ``wrap``, the element both views share (it carries the tab's choice)."""
        from nicegui import ui
        self.wrap = wrap
        with wrap, ui.column().classes('w-full cn-live-map-area'):
            # What the summary above says again with every round: text, not a second live region (the summary speaks it).
            self.status = ui.label('').classes('cn-muted')
            self.summary = ui.label('').classes('cn-map-summary')
            self.box = ui.element('div').classes('cn-monitor-scroll cn-map').props('tabindex=0 role=group aria-label="Host map"')
            ui.html(monitor_map.legend_html(), sanitize=False).classes('cn-map-legend').props('role=note aria-label="Map legend"')
            ui.label('The map shows every host of the complete round: one character per address, in address order. '
                     'Point at, tap or move to a character for its details. Filters and sorting belong to the Table view.').classes('cn-muted')
            self.live = ui.label('').props('role=status aria-live=polite').classes('cn-map-sr')

    def start(self):
        for name, handler in (('cn_monitor_map_view', self._view_reported), ('cn_monitor_map_show', self._show_block),
                              ('cn_monitor_map_table', self._show_in_table), ('cn_monitor_map_host', self._host_details)):
            self.scope.on_event(name, handler)
        self.scope.js(self._init(), DISPOSE)

    def restart(self):
        """Init again: the Live panel was chosen, and its Map box may be drawn only now (init keeps a box it holds)."""
        if self.scope.alive:
            self.client.run_javascript(self._init())

    def _init(self):
        options = dict(box=self.box.html_id, wrap=self.wrap.html_id, live=self.live.html_id,
                       words=monitor_map.STATE_WORDS, group=monitor_map.ping_grid.GROUP, token=self.token,
                       view=self.forced)
        return f'window.cnMonitorMap && window.cnMonitorMap.init({json.dumps(options)})'

    # --- the view ---------------------------------------------------------------------------------------------------
    def set_buttons(self):
        for name, button in self.buttons.items():
            pressed = str(name == self.view).lower()
            if button._props.get('aria-pressed') != pressed:
                button._props['aria-pressed'] = pressed
                button.update()

    def enable(self):
        for button in self.buttons.values():
            button.enable()

    def choose(self, view):
        # The tab keeps the choice (sessionStorage) and answers with the view and the width of its map box.
        self.want = None  # a "Show on map" still waiting is the reader's earlier wish
        self.view, self.forced = view, None  # the reader's own click ends a link's view for this load, and is stored
        self.set_buttons()
        self.client.run_javascript(f'window.cnMonitorMap && window.cnMonitorMap.setView({json.dumps(view)})')

    # --- drawing ------------------------------------------------------------------------------------------------------
    @property
    def hosts(self):
        return (self.payload or {}).get('hosts')

    def draw(self, force_full=False):
        """Draw the payload at the tab's width: the whole map, or only the rows that differ from what it shows."""
        if self.payload is None or not self.cols:
            return
        try:
            drawn = monitor_map.render(self.payload, self.cols)
        except ValueError:  # an answer the layout cannot draw: say so, and leave the rest of the page working
            self.clear(UNAVAILABLE)
            return
        changes = None if force_full else monitor_map.diff(self.drawn, drawn)
        self.drawn = drawn
        message = dict(rev=self.revision, used=drawn['used'], jumps=drawn['jumps'],
                       label=f"Host map, {self.payload['hosts']:,} hosts; arrow keys move, Enter for details")
        if changes is None:
            message['full'] = monitor_map.full_html(drawn)
        else:
            message['rows'] = changes
        set_changed(self.summary, self.payload['summary'])
        set_changed(self.status, f'Showing complete round revision {self.revision}.')
        self.client.run_javascript(f'window.cnMonitorMap && window.cnMonitorMap.draw({json.dumps(message)})')
        if self.want is not None:
            self.scope.task(self._reach(), name='monitor-map-focus')

    def clear(self, message):
        self.want = None
        if self.payload is not None or self.drawn is not None:
            self.client.run_javascript('window.cnMonitorMap && window.cnMonitorMap.draw({rev: null, full: ""})')
        self.payload = self.drawn = self.revision = None
        set_changed(self.summary, '')
        set_changed(self.status, message)

    def release(self):
        self.want = None
        for name, release in (('query', 'release_monitor_live_map'), ('host_query', 'release_monitor_live_host')):
            if getattr(self, name):
                getattr(self.controller, release, lambda query: None)(getattr(self, name))
                setattr(self, name, None)

    def reset(self, active, show=-1):
        """Another run (or none) is on screen: nothing of the last one's map is asked for or shown."""
        self.show = show
        self.release()
        self.key = None
        self.clear(WAITING if active else NOT_RUNNING)

    def follow(self, job, run_id, revision, active):
        """From the page's poll. The Map asks only while the tab shows it and has said how wide its box is. A new
        round replaces the rows that changed: nothing of the page is rebuilt, so focus, scroll and an open popup stay."""
        key = ((job, run_id, revision, self.show)
               if self.view == 'map' and self.cols and job and run_id is not None and revision is not None else None)
        if key != self.key:
            if self.query:
                self.controller.release_monitor_live_map(self.query)
                self.query = None
            self.key = key
            if key:
                try:
                    self.query = self.controller.request_monitor_live_map(*key)
                except (AttributeError, RuntimeError, ValueError):
                    self.clear(UNAVAILABLE)
        if self.query:
            answer = self.controller.monitor_live_map(self.query)
            if answer is not None:
                self.controller.release_monitor_live_map(self.query)
                self.query = None
                if answer.get('status') == 'expired':
                    self.key = None
                elif answer.get('status') == 'ready' and answer.get('map'):
                    self.payload, self.revision = answer['map'], answer['revision']
                    self.draw()
                elif answer.get('status') == 'not_ready':
                    self.clear(NOT_READY)
                else:
                    self.clear(UNAVAILABLE)
        if not active and self.status.text.startswith(WAITING):
            set_changed(self.status, NOT_RUNNING)  # the run ended before its first round: none is on its way

    # --- the change list's "Show on map" ------------------------------------------------------------------------------
    async def focus_cell(self, block, cell):
        """Move the Map's one cursor to ``cell`` of ``block``: the page's JavaScript does it when the cell is on screen;
        otherwise the Map view is chosen, and a block that is not drawn is shown, and the cursor goes there when the next
        draw has it. Nothing is hidden or filtered (D2)."""
        if not self.scope.alive:
            return
        if self.view != 'map':
            self.choose('map')  # the tab reports the view, the poll asks for the map, and its draw reaches the cell
            self.want = (block, cell, monotonic() + WANT_SECONDS)
            return
        self.want = (block, cell, monotonic() + WANT_SECONDS)
        if self.payload is not None:
            await self._reach()

    async def _reach(self):
        want = self.want
        if want is not None and monotonic() > want[2]:  # asked long ago: the reader has moved on, so nothing moves now
            self.want = want = None
        if want is None or not self.scope.alive or self.payload is None:
            return
        block, cell, _ = want
        blocks = self.payload.get('blocks') or []
        item = blocks[block] if block < len(blocks) else None
        if item is None or cell < 0:
            self.want = None
            self.live.set_text(NOT_ON_MAP)
            return
        if item['kind'] == 'compact':
            if not item.get('can_show'):
                self.want = None
                self.live.set_text(NOT_ON_MAP)
                return
            if self.show != block:
                self.show = block  # the next poll asks for the map with that block drawn; its draw comes back here
                await self.poll()
                return
        self.want = None
        self.client.run_javascript(f'window.cnMonitorMap && window.cnMonitorMap.focusCell({block}, {cell})')

    # --- the map's events (scope.on_event: none reaches a page that was left) ----------------------------------------
    async def _view_reported(self, event):
        if not self.scope.alive:
            return
        args = _mine(self, event)
        if args is None:
            return
        self.view = 'table' if args.get('view') == 'table' else 'map'  # a report, however often: a link's view stays
        if self.view == 'table':
            self.want = None
        self.set_buttons()
        if self.changed is not None:
            self.changed()
        cols = _whole(args.get('cols'), 1, 100000)
        if self.view == 'map' and cols:
            resized, self.cols = cols != self.cols, min(cols, monitor_map.MAX_COLS)
            if args.get('fresh'):
                self.drawn = None
            if resized or args.get('fresh'):
                self.draw()
        await self.poll()

    async def _show_block(self, event):
        args = _mine(self, event)
        block = _whole((args or {}).get('b'), 0, monitor_map.CAP_CELLS - 1)
        if block is not None and self.scope.alive:
            self.show = block
            await self.poll()

    async def _show_in_table(self, event):
        target = (_mine(self, event) or {}).get('target')
        if isinstance(target, str) and target and self.scope.alive:
            await self.show_in_table(target[:256])

    async def _host_details(self, event):
        """The popup's second half: what the worker's copy of the round knows of one cell."""
        args = _mine(self, event) or {}
        block, cell = (_whole(args.get(name), 0, monitor_map.CAP_CELLS - 1) for name in ('b', 'c'))
        key, revision = self.key, self.revision
        if (not self.scope.alive or block is None or cell is None or not key or revision is None
                or args.get('rev') != revision):
            return
        if self.host_query:
            self.controller.release_monitor_live_host(self.host_query)
            self.host_query = None
        try:
            query = self.controller.request_monitor_live_host(key[0], key[1], revision, block, cell)
        except (AttributeError, RuntimeError, ValueError):
            return
        self.host_query = query
        answer = None
        for _ in range(200):  # the worker answers from memory: a few milliseconds
            answer = self.controller.monitor_live_host(query)
            if answer is not None or self.host_query != query or not self.scope.alive:
                break
            await asyncio.sleep(.02)
        if self.host_query == query:  # not given up by a leave (release) or a newer cell
            self.host_query = None
            self.controller.release_monitor_live_host(query)
        if answer and answer.get('status') == 'ready' and answer.get('host') and self.scope.alive:
            message = dict(b=block, c=cell, rev=revision, lines=monitor_map.host_lines(answer['host']))
            self.client.run_javascript(f'window.cnMonitorMap && window.cnMonitorMap.details({json.dumps(message)})')
