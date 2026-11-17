"""The lifetime of one tool's page in one tab: ``PageScope``.

On a page of its own (an ``@ui.page``, which no tool is any more) a page lives as long as its NiceGUI client, so it
could tie its polls, its releases and its listeners to the client. Under ``ui.sub_pages`` (one root page per tab, every
tool routed inside it since R2-11) the client outlives every tool: a tool is left without its client going away. Everything a page starts that must stop
when the page is left therefore goes through its scope, and the scope ends at whichever comes first: the tool is left
(``leave``, from the router) or the tab's client is deleted. Design: "R2-09 design note" in
``docs/plans/webui-ux-plan.md``.

What replaces what, in a page module:

========================================  ==========================================================
today                                      through the scope
========================================  ==========================================================
``ui.timer(interval, poll)``               ``scope.timer(interval, poll)``
``background_tasks.create(coroutine)``     ``scope.task(coroutine, name=...)``
``client.on_delete(release)``              ``scope.on_leave(release)``
``ui.on('cn_event', handler)``             ``scope.on_event('cn_event', handler)``
``client.on_connect(start)``               ``scope.when_connected(start)`` (once)
``client.run_javascript(install)``         ``scope.js(install, dispose)`` (a listener the page adds)
``ui.add_head_html('<script>…')``          ``scope.head_once(key, script=...)`` (runs even after load)
``ui.add_css(css)`` per render             ``scope.head_once(key, css=...)``
Settings' unsaved-changes question         ``scope.can_leave(check)``, asked by ``may_leave(client)``
========================================  ==========================================================

NiceGUI is imported inside the functions (tests/test_startup_imports.py); the module itself imports nothing heavy.
"""
import logging
from weakref import WeakKeyDictionary

log = logging.getLogger(__name__)

_CURRENT = WeakKeyDictionary()   # client -> its current PageScope
_TABS = WeakKeyDictionary()      # client -> the tab's state (tab_state)
_DISPATCH = WeakKeyDictionary()  # client -> {event name: the current scope's handler, or None}
_HEAD = WeakKeyDictionary()      # client -> the head_once keys already added


def tab_state(client):
    """What a tool wants to find again in the same tab after a visit to another tool (table states, the open
    details, a History position): a dict per client, ``tab_state(client).setdefault(key, ...)``. It lasts as long as
    the tab's client: a reload starts a new one (a draft lives in ``sessionStorage`` instead, a view in the URL)."""
    _hook(client)
    return _TABS.setdefault(client, {})


def current(client):
    """The tab's current scope, or None."""
    return _CURRENT.get(client)


def enter(client, key):
    """End the tab's current scope, if any, and start the scope of tool ``key``: the first call of a tool's builder.

    Ending first means a quick there-and-back never leaves two polls of one tool. The scope also ends when the
    client is deleted (the tab closed, or a full load replaced it)."""
    previous = _CURRENT.get(client)
    if previous is not None:
        previous.end()
    scope = PageScope(client, key)
    _CURRENT[client] = scope
    _hook(client)
    return scope


def _hook(client):
    """Once per client: when it is deleted, end its scope and drop its entries (the values hold the client: a scope,
    a handler of the scope, so a weak key alone would never let it go)."""
    if not getattr(client, 'cn_scope_hooked', False):
        client.cn_scope_hooked = True
        client.on_delete(lambda: _forget(client))


def leave(client, key=None):
    """The router's hook (``sub_pages_router.on_path_changed``): the tab is going to tool ``key`` (None for a path
    that is no tool). The current scope ends here, before the router removes the old page's elements, unless the
    path stays on the same tool (a change of the query only)."""
    scope = _CURRENT.get(client)
    if scope is not None and scope.key != key:
        _end_current(client)


async def may_leave(client):
    """Whether the tab's current tool may be left now: every ``can_leave`` check of its scope answers True (each may
    ask the user). A tab with no scope may always be left."""
    scope = _CURRENT.get(client)
    if scope is None or not scope.alive:
        return True
    for check in list(scope._checks):
        if not await check():
            return False
    return True


def _end_current(client):
    scope = _CURRENT.pop(client, None)
    if scope is not None:
        scope.end()


def _forget(client):
    _end_current(client)
    for registry in (_TABS, _DISPATCH, _HEAD):
        registry.pop(client, None)


def _dispatch(client, name, event):
    handler = _DISPATCH.get(client, {}).get(name)
    if handler is not None:
        return handler(event)
    return None


def add_once(client, key, *, script='', css=''):
    """Add a stylesheet and/or a script to the tab of ``client`` once, whoever asks first: a page, the shell or a helper
    (the theme, the tables, the outcome banner). True when this call added it, False when the tab already has it.
    A script given while the page is being loaded goes into the head; one given later (a tool opened by the router)
    is run in the connected page, because markup added to a loaded document's head never runs. A script must
    therefore be safe to run once per document (``window.cnX = window.cnX || ...``)."""
    from nicegui import ui

    _hook(client)
    done = _HEAD.setdefault(client, set())
    if key in done:
        return False
    done.add(key)
    if css:
        ui.add_css(css)
    if script:
        if client.has_socket_connection:
            client.run_javascript(_script_body(script))
        else:
            ui.add_head_html(script if script.lstrip().startswith('<script') else f'<script>{script}</script>')
    return True


def _script_body(script):
    text = script.strip()
    if text.startswith('<script>') and text.endswith('</script>'):
        text = text[len('<script>'):-len('</script>')]
    return text


class PageScope:
    """The lifetime of one tool's page in one tab: it ends when the tab closes or when the tool is left."""

    def __init__(self, client, key):
        self.client = client
        self.key = key
        self.alive = True
        self._leave = []
        self._timers = []
        self._tasks = []
        self._events = []
        self._dispose = []
        self._checks = []
        self.view_state = None  # the page's view_state.ViewState: the router hands it Back and Forward on this tool

    def on_leave(self, callback):
        """Run ``callback()`` once, when the scope ends (a release of the page's queries or of a prepared download).
        Callbacks run in the order they were given, after the scope's timers and tasks have stopped and while the
        page's elements still exist; one that raises is logged and the others still run. A scope that has already
        ended runs it at once."""
        if self.alive:
            self._leave.append(callback)
        else:
            _run(callback)

    def timer(self, interval, callback, *, once=False, immediate=True):
        """A ``ui.timer`` in the current container that stops when the scope ends, and whose callback is never
        called once the scope has ended (not even by a tick already scheduled)."""
        from nicegui import ui

        def tick():
            if self.alive:
                return callback()
            return None

        timer = ui.timer(interval, tick, once=once, immediate=immediate)
        if self.alive:
            self._timers.append(timer)
        else:
            timer.cancel()
        return timer

    def task(self, coroutine, *, name):
        """Run ``coroutine`` as a background task that is cancelled when the scope ends. A scope that has ended
        starts nothing (the coroutine is closed) and returns None."""
        from nicegui import background_tasks

        if not self.alive:
            coroutine.close()
            return None
        task = background_tasks.create(coroutine, name=name)
        self._tasks.append(task)
        task.add_done_callback(self._forget)  # a finished task is not kept until the scope ends
        return task

    def _forget(self, task):
        try:
            self._tasks.remove(task)
        except ValueError:  # the scope has ended and cleared its list
            pass

    def on_event(self, name, handler):
        """``ui.on(name, handler)`` for this scope: the handler is dropped when the scope ends, so an event that
        arrives after the tool was left (a stale map event) reaches nothing. One listener per event name and tab
        is registered on the client, once; it calls the current scope's handler."""
        if not self.alive:
            return
        table = _DISPATCH.setdefault(self.client, {})
        if name not in table:
            client = self.client
            client.layout.on(name, lambda event, name=name: _dispatch(client, name, event))
        table[name] = handler
        self._events.append((name, handler))

    def when_connected(self, callback):
        """Call ``callback()`` once: now if the tab's socket is connected (a tool opened by the router), else when
        it connects (a page being loaded). Not after the scope has ended, and not again on a reconnect. NiceGUI has no
        way to remove a ``client.on_connect`` handler, so the one added here stays on the client, a closure that does
        nothing once it has run or the scope has ended."""
        if not self.alive:
            return
        if self.client.has_socket_connection:
            callback()
            return
        done = []

        def connected():
            if self.alive and not done:
                done.append(True)
                callback()
        self.client.on_connect(connected)

    def js(self, install, dispose=''):
        """Run the script ``install`` in the tab once connected, and ``dispose`` when the scope ends (while the tab is
        still connected): the page's document or window listeners, observers and intervals are added by
        ``install`` and taken away by ``dispose``, so a tool left and opened again holds one set, not two."""
        if not self.alive:
            return
        if install:
            self.when_connected(lambda: self.client.run_javascript(install))
        if dispose:
            self._dispose.append(dispose)

    def head_once(self, key, *, script='', css=''):
        """Add a stylesheet and/or a script to the tab once, whichever tool asks first (``add_once``)."""
        add_once(self.client, key, script=script, css=css)

    def can_leave(self, check):
        """``check`` is an async callable answering whether the tool may be left now (Settings asks about unsaved
        changes and says True when the user chooses to leave); ``may_leave`` asks every check of the scope."""
        if self.alive:
            self._checks.append(check)

    def end(self):
        """End the scope (idempotent): stop its timers and tasks, drop its event handlers, run its dispose scripts,
        then its ``on_leave`` callbacks."""
        if not self.alive:
            return
        self.alive = False
        if _CURRENT.get(self.client) is self:
            _CURRENT.pop(self.client, None)
        for timer in self._timers:
            try:
                timer.cancel(with_current_invocation=True)
            except Exception:  # a timer whose element is already gone
                log.debug('timer already gone', exc_info=True)
        for task in list(self._tasks):
            if not task.done():
                task.cancel()
        table = _DISPATCH.get(self.client, {})
        for name, handler in self._events:
            if table.get(name) is handler:
                table[name] = None
        if self._dispose and self.client.has_socket_connection:
            self.client.run_javascript(';\n'.join(f'try {{ {code} }} catch (error) {{}}' for code in self._dispose))
        callbacks, self._leave = self._leave, []
        for callback in callbacks:
            _run(callback)
        self._timers, self._tasks, self._events, self._dispose, self._checks = [], [], [], [], []
        self.view_state = None


def _run(callback):
    try:
        callback()
    except Exception:
        log.exception('a page scope callback failed')
