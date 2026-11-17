"""Mount the presentation behind the local access boundary."""
from .access import card_html

_EXCHANGE_SCRIPT = '''<script>
const token = location.hash.slice(1);
history.replaceState(null, '', '/bootstrap');
fetch('/exchange', {method:'POST', headers:{'Content-Type':'application/json'},
body:JSON.stringify({token})}).then(r => {
if (r.ok) location.replace('/'); else document.getElementById('status').textContent =
'This launch link has expired. Use the established browser session or relaunch the application.';
}).catch(() => {document.getElementById('status').textContent='Unable to open the local application.'});
</script>'''
# The same card as the refusals, titled "cn-tool": its one line is the status while the token is exchanged.
BOOTSTRAP = (card_html('cn-tool', ['Opening cn-tool…']).replace('<p>', '<p id="status" role="status">', 1)
             .replace('</body>', _EXCHANGE_SCRIPT + '</body>'))

# Paths answered by the application besides the pages of shell.PAGES; anything else is a 404 card.
_OWN_PATHS = frozenset({'/bootstrap', '/exchange', '/reopen'})
_OWN_PREFIXES = ('/_nicegui/', '/_nicegui_ws/')
_DOWNLOAD = '/download/'


class UnknownPathGuard:
    """Pure ASGI: a request that NiceGUI would answer by building the root page for nothing is answered before it.

    NiceGUI renders the app's root for *every* 404 (any method, any path), and the root opens a client. Without the
    router, an unknown path was an error page and a non-GET request to a page was a 405; with it, every one of them
    would build the whole root. So, as before the router:

    - a GET or HEAD for a path that is no route answers the 404 card. The routes are the pages, the three access
      paths, ``/download/<one segment>`` and what NiceGUI itself serves under ``/_nicegui/`` and ``/_nicegui_ws/``
      (its static files, components and socket). A miss under ``/_nicegui/`` is a 404 card as well, found by asking
      NiceGUI's own routes (only when NiceGUI is loaded: with none loaded there is no root to build);
    - a request other than GET to a path only the root serves (the tools of ``router.ROUTED``) answers 405 (``Allow:
      GET``), as NiceGUI answers a page route. Other methods on other unknown paths stay NiceGUI's to answer.

    NiceGUI is not imported here: the guard answers in a process that has not loaded it.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'http':
            method, path = scope.get('method'), scope['path']
            if method in ('GET', 'HEAD') and (not self._known(path) or self._nicegui_miss(scope)):
                from .access import NOT_FOUND_LINES, send_card
                return await send_card(send, 404, 'Page not found', NOT_FOUND_LINES)
            if method != 'GET' and self._root_only(path):
                await send({'type': 'http.response.start', 'status': 405,
                            'headers': [(b'content-type', b'application/json'), (b'allow', b'GET')]})
                return await send({'type': 'http.response.body', 'body': b'{"detail":"Method Not Allowed"}'})
        return await self.app(scope, receive, send)

    @staticmethod
    def _root_only(path):
        from .router import ROUTED
        from .shell import PAGES
        return any(path == page.route for page in PAGES if page.key in ROUTED)

    @staticmethod
    def _nicegui_miss(scope):
        """A path under ``/_nicegui/`` that none of NiceGUI's routes (or mounts) takes."""
        import sys
        if not scope['path'].startswith('/_nicegui/'):
            return False
        nicegui = sys.modules.get('nicegui')
        routes = getattr(getattr(nicegui, 'app', None), 'routes', None)
        if not routes:
            return False
        from starlette.routing import Match
        return all(route.matches(scope)[0] == Match.NONE for route in routes)

    @staticmethod
    def _known(path):
        import sys
        from .shell import PAGES
        if path in _OWN_PATHS or path.startswith(_OWN_PREFIXES) or any(path == page.route for page in PAGES):
            return True
        if path.startswith(_DOWNLOAD):
            name = path[len(_DOWNLOAD):]
            return bool(name) and '/' not in name
        # Any other page registered with NiceGUI (a page a test adds); none can be while NiceGUI is not loaded.
        client = sys.modules.get('nicegui.client')
        return client is not None and path in client.Client.page_routes.values()


def create_app(controller, access):
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
    from nicegui import app as nicegui_app, ui
    from .access import AccessMiddleware
    from .subnets import render_subnets
    from .ip import render_ip
    from .ping import render_ping
    from .monitor import render_monitor
    from .config_page import render_config_search
    from .demob_page import render_demob
    from .settings_page import render_settings
    from .router import render_root

    parent = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    # Added first, so it is inside the access check: a refused request is 403 whether or not the path exists.
    parent.add_middleware(UnknownPathGuard)
    parent.add_middleware(AccessMiddleware, access=access)

    @parent.get('/bootstrap')
    async def bootstrap():
        return HTMLResponse(BOOTSTRAP, headers={'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer'})

    @parent.post('/exchange')
    async def exchange(request: Request):
        try:
            payload = await request.json()
            cookie = access.exchange(payload.get('token'))
        except (ValueError, AttributeError):
            cookie = None
        response = JSONResponse({'ok': bool(cookie)}, status_code=200 if cookie else 403)
        if cookie:
            response.set_cookie(access.cookie_name, cookie, httponly=True, samesite='strict', path='/')
        response.headers['Cache-Control'] = 'no-store'
        return response

    @parent.get('/download/{request_id}')
    async def download(request_id: str):
        try:
            path = controller.resolve_snapshot(request_id)
        except KeyError:
            return JSONResponse({'error': 'Download unavailable.'}, status_code=404)
        snapshot = controller.report_completion(request_id) or {}
        # The Unseen download is a CSV file; every other snapshot is the report workbook, as it always was.
        csv = str(path).lower().endswith('.csv')
        fallback = 'report.csv' if csv else 'report.xlsx'
        filename = snapshot.get('filename', fallback) if snapshot.get('request_id') == request_id else fallback
        class SnapshotResponse(FileResponse):
            async def __call__(self, scope, receive, send):
                try:
                    await super().__call__(scope, receive, send)
                finally:
                    controller.release_snapshot(request_id)
        media_type = 'text/csv' if csv else 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        return SnapshotResponse(path, filename=filename, media_type=media_type, headers={'Cache-Control': 'no-store'})

    renderers = {'subnet': render_subnets, 'ip': render_ip, 'ping': render_ping, 'monitor': render_monitor,
                 'config_search': render_config_search, 'demob': render_demob, 'settings': render_settings}

    def root_page():
        # No tool has an @ui.page of its own (R2-11): NiceGUI answers every route of shell.PAGES with this root,
        # which routes to the tool.
        render_root(controller, renderers)

    # Quasar's loading bar draws a progressbar with no name outside every landmark while a request is in flight;
    # the pages say what is running in their own status lines.
    nicegui_app.config.quasar_config['loadingBar'] = {**nicegui_app.config.quasar_config.get('loadingBar', {}),
                                                       'skipHijack': True}
    # Gzip buffers headers until the first body chunk; a cancelled file
    # transfer can then look like a missing response to NiceGUI's middleware.
    ui.run_with(parent, root=root_page, title='cn-tool', language='en-US',
                show_welcome_message=False, reconnect_timeout=15, gzip_middleware_factory=None)
    return parent
