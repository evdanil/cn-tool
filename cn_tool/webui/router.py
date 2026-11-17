"""The root page: the shell once per tab, and the tools of ``ROUTED`` opened inside it without a load (``ui.sub_pages``).

``app.py`` passes ``render_root`` to ``ui.run_with(root=...)``. Since R2-11 every tool is in ``ROUTED`` and no tool
has an ``@ui.page`` of its own, so no link between tools is a load; a same-origin link to a path that is no tool (none
is drawn) is let through to the browser by the router script below. A direct load, a reload or a deep link to a tool
builds the root, which routes to it. Unknown paths stay the 404 card of
``app.UnknownPathGuard`` (which also keeps a request that is not a GET, and a miss under ``/_nicegui/``, from building
the root); an in-app link to one (only a bug can make it) says "Page not found" inside the shell.

Each tool lives in its own ``PageScope`` (``scope.py``): the router's ``on_path_changed`` ends the old one before the
old page's elements go, and the builder starts the new one. A tool switch moves the focus to the h1 and the title with
it (``PageShell.set_active``, which the tool's ``render_shell`` call reaches). Settings with unsaved changes holds the
leave guard (``cnShell.guard``): a link, a ``g`` key or Back to another tool then asks ``may_leave`` first (to the
tool you are on, nothing is asked and the guard stays; with the socket down the browser asks itself). Design: "R2-09 design note"
in ``docs/plans/webui-ux-plan.md``. NiceGUI is imported inside the functions.
"""
import json

from .shell import PAGES, page_of, page_shell, render_shell

# The tools inside the root: every tool since R2-11 (the Monitor was the last page of its own).
ROUTED = ('subnet', 'ip', 'ping', 'monitor', 'settings', 'config_search', 'demob')
POLL_SECONDS = 0.5  # the shell's own poll: the header follows the session whatever the tool does
FOCUS_TITLE = "document.querySelector('h1.cn-page-title')?.focus({preventScroll: true})"
# The tool that is being left is hidden from the click or go() that leaves it until the switch has an outcome: the
# next tool drawn, its build failed (the 500 card) or the path is no tool (the 404 card). The page's timer is a last
# resort only (it gives up after 10 s, or at once with the socket down): a key or a click in that moment would go to
# a field that is about to go (R2-10).
SHOWN = "window.cnShell?.shown?.()"
CSS = ('.cn-tool-pages { display:contents; }'  # a tool's content sits in the page's column as on a page of its own
       ' .cn-tool-pages[data-cn-leaving] > * { visibility:hidden; }')

# Installed once per tab by the root, after the shell's CLOCK_SCRIPT and before NiceGUI's sub_pages.js, so its
# listeners come first. A click on a same-origin link to a path that is not routed here (no tool since R2-11) is let
# through to the browser (a full load) instead of the router, and so is any link while the socket is down (nothing
# would answer the router). While the guard is set (Settings with unsaved changes), a link, a go() and Back to another tool are
# stopped (the URL is put back) and the root is asked (cn_leave_request); release() clears the guard and goes. A
# target that is the tool you are on (the same path) is no leave: nothing is asked and the guard stays, which is also
# what release() does for it. With the socket down the browser asks itself (confirm, in the words guard() was given)
# and a yes is a full load. A Back or Forward that is stopped is undone with history.go() by the distance travelled
# (the Navigation API's entry index), so the entries after it survive; without that API it is a pushState. The
# window's scroll is kept per tool for a tool that is left by a link or a go(), for restoreScroll(), and the tool being
# left for another one is hidden (data-cn-leaving) until the switch ends (shown(), sent with the focus to the h1 when
# the next tool is drawn, when its build failed and when the path is unknown; a timer that waits while the socket is up,
# for 10 s at most, is the last resort): a key or a click in that moment would reach a field that is about to go.
ROUTER_SCRIPT = '''<script>
(() => {
  const shell = window.cnShell;
  if (!shell || shell.routes) return;
  const routes = new Set(%(routes)s), scrolls = {};
  const nav = window.navigation, index = () => (nav && nav.currentEntry ? nav.currentEntry.index : null);
  let guard = null, words = 'Leave this page and lose your unsaved changes?', seen = index(), returning = null;
  if (nav) nav.addEventListener('currententrychange', (event) => { if (event.navigationType !== 'traverse') seen = index(); });
  const online = () => Boolean(window.socket && window.socket.connected);
  const inside = (url) => url.origin === location.origin && routes.has(url.pathname);
  const here = (url) => url.origin === location.origin && url.pathname === location.pathname;
  let shownTimer = 0;
  const pages = () => document.querySelector('.cn-tool-pages');
  const shown = () => { clearTimeout(shownTimer); pages()?.removeAttribute('data-cn-leaving'); };
  // Leaving for another tool (not the same one with another query): hide the one that goes until the next is drawn.
  const remember = (url) => {
    scrolls[location.pathname] = window.scrollY;
    if (here(url)) return;
    pages()?.setAttribute('data-cn-leaving', '');
    clearTimeout(shownTimer);
    const since = Date.now();  // the outcome of the switch ends the hide; this is the last resort for one that never comes
    const wait = () => { if (online() && Date.now() - since < 10000) shownTimer = setTimeout(wait, 500); else shown(); };
    shownTimer = setTimeout(wait, 500);
  };
  const leave = (href) => { guard = null; window.cnSettingsDirty = false; location.assign(href); };
  const ask = (href) => {
    if (online()) { window.emitEvent('cn_leave_request', href); return; }
    if (window.confirm(words)) leave(href);
  };
  // The navigation's link (or g key) of the tool the tab is on: no new entry and no path change; the tool keeps its view
  // (sent as a leave request for the tool it is on, which the root answers with the tool's view_state.linked).
  const own = (url) => here(url) && !url.search && !url.hash && inside(url) && online();
  const go = (route) => {
    const url = new URL(route, location.origin);
    if (own(url)) { window.emitEvent('cn_leave_request', url.pathname); return; }
    if (guard !== null) { if (!here(url)) ask(route); return; }
    if (!inside(url) || !online()) { location.assign(route); return; }
    remember(url);
    window.emitEvent('sub_pages_navigate', url.pathname + url.search + url.hash);
  };
  document.addEventListener('click', (event) => {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const link = event.target.closest && event.target.closest('a[href]');
    if (!link || link.target === '_blank' || link.hasAttribute('download')) return;
    const href = link.getAttribute('href');
    if (!href.startsWith('/')) return;
    const url = new URL(href, location.origin);
    if (own(url)) {
      event.preventDefault(); event.stopImmediatePropagation(); window.emitEvent('cn_leave_request', url.pathname); return;
    }
    if (guard !== null) {
      if (here(url)) return;
      event.preventDefault(); event.stopImmediatePropagation(); ask(href); return;
    }
    if (!inside(url) || !online()) { event.stopImmediatePropagation(); return; }
    remember(url);
  }, true);
  window.addEventListener('popstate', (event) => {
    const now = index();
    if (returning !== null && now === returning) {  // the undo of a stopped Back or Forward arrived
      returning = null; seen = now; event.stopImmediatePropagation(); return;
    }
    if (guard === null || here(new URL(guard, location.origin))) { seen = now; return; }
    event.stopImmediatePropagation();
    const wanted = location.pathname + location.search + location.hash;
    if (seen !== null && now !== null && seen !== now) { returning = seen; history.go(seen - now); }
    else history.pushState({page: guard}, '', guard);
    ask(wanted);
  });
  Object.assign(shell, {
    routes, go, shown,
    guard: (path, text) => { guard = path || null; if (text) words = text; },
    guarded: () => guard !== null,
    release: (href) => {
      if (here(new URL(href, location.origin))) return;  // the tool stays, and so does its guard
      guard = null; window.cnSettingsDirty = false; go(href);
    },
    restoreScroll: (path) => {
      const top = scrolls[path];
      if (top) requestAnimationFrame(() => requestAnimationFrame(() => window.scrollTo(0, top)));
    },
  });
})();
</script>'''


def router_script(routes):
    """The router script for the routes of the root (``ROUTER_SCRIPT``)."""
    return ROUTER_SCRIPT % dict(routes=json.dumps(list(routes)))


def routed_pages():
    """The rows of ``shell.PAGES`` that the root routes."""
    return [page for page in PAGES if page.key in ROUTED]


_TOOL_PAGES = []


def _tool_pages():
    """``ui.sub_pages`` whose in-app 404 is the words of the guard's card, in the shell (NiceGUI's own is a bare
    "404: sub page ... not found" label). ``_render_404`` is protected: tests/test_webui_router_browser.py pins it."""
    if _TOOL_PAGES:
        return _TOOL_PAGES[0]
    from nicegui import ui
    from nicegui.elements.sub_pages import SubPages
    from .access import NOT_FOUND_LINES
    from .scope import leave

    class ToolPages(SubPages):
        def _find_matching_path(self):
            # NiceGUI matches a path by its longest prefix that is a route, for nested sub_pages; there are none
            # here, so a prefix is no match. Without this, Subnets (route '/') was built for any unknown in-app path
            # (its poll and reads started) before the rest was found unmatched (R2-10).
            match = super()._find_matching_path()
            return None if match is not None and match.remaining_path else match

        def _handle_scrolling(self, match, *, behavior):
            # 'smooth' is the router's call for the same tool with another query (Back and Forward between two views
            # of one tool, a link to the tool you are on): the view changes in place, so the scroll stays (R2-08).
            if behavior == 'smooth' and not match.fragment:
                return
            super()._handle_scrolling(match, behavior=behavior)

        def _shown(self) -> None:
            # The switch has its outcome (a card, not a tool): the tool that was left is gone, nothing hides the card.
            if not self.client.is_deleted and self.client.has_socket_connection:
                self.client.run_javascript(f'{SHOWN}; {FOCUS_TITLE}')

        def _render_error(self, error) -> None:
            super()._render_error(error)  # the 500 card; the failed build's partial content is already cleared
            leave(self.client, None)  # its scope ends now: what the build had started (the Map's init) is taken away
            self._shown()

        def _render_404(self) -> None:
            shell = page_shell(self.client)
            if shell is not None:
                shell.set_active(None)
            self._shown()
            with ui.element('section').classes('cn-panel').props('data-cn-not-found'):
                for line in NOT_FOUND_LINES:
                    ui.label(line)

    _TOOL_PAGES.append(ToolPages)
    return ToolPages


def render_root(controller, renderers):
    """The root page of a tab: the shell (with its own poll), the routed tools, the footer. ``renderers`` maps a
    page key to its ``render_x(controller, scope)``."""
    from nicegui import ui
    from .footer import render_footer
    from .scope import add_once, current, enter, leave, may_leave
    from .view_state import linked, popped

    client = ui.context.client
    render_shell(controller, None, poll=POLL_SECONDS)
    pages = routed_pages()
    add_once(client, 'router', css=CSS, script=router_script(page.route for page in pages))

    def path_changed(path):
        page = page_of(path)
        leave(client, page.key if page else None)  # before the router removes the old page's elements
        here = current(client)
        if page is not None and here is not None and here.key == page.key:
            popped(here, path)  # the same tool with another query: its view, applied in place (view_state, R2-08)
    client.sub_pages_router.on_path_changed(path_changed)

    async def leave_request(event):
        href = event.args[0] if isinstance(event.args, list) and event.args else event.args
        if not isinstance(href, str) or not href.startswith('/'):
            return
        target, here = page_of(href), current(client)
        if target is not None and here is not None and target.key == here.key:
            # The tool you are on is no leave: nothing to ask, and the guard stays. Only its own link sends it (the
            # script's own()): the view stays and the URL is written from it (Subnets' goes back to the summary).
            linked(here)
            return
        if await may_leave(client):
            client.run_javascript(f'window.cnShell?.release({json.dumps(href)})')
    ui.on('cn_leave_request', leave_request)

    def builder(page):
        def build():  # no parameters: a change of the query never rebuilds the tool
            scope = enter(client, page.key)
            renderers[page.key](controller, scope)
            if not client.sub_pages_router.is_initial_request:
                scope.when_connected(lambda: client.run_javascript(f'{SHOWN}; {FOCUS_TITLE}'))
        return build

    _tool_pages()({page.route: builder(page) for page in pages}).classes('cn-tool-pages')
    render_footer()
