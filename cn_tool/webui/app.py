"""Mount the presentation behind the local access boundary."""

BOOTSTRAP = '''<!doctype html><html><head><meta charset="utf-8"><title>Subnets</title></head>
<body><p id="status">Opening Subnets…</p><script>
const token = location.hash.slice(1);
history.replaceState(null, '', '/bootstrap');
fetch('/exchange', {method:'POST', headers:{'Content-Type':'application/json'},
body:JSON.stringify({token})}).then(r => {
if (r.ok) location.replace('/'); else document.getElementById('status').textContent =
'This launch link has expired. Use the established browser session or relaunch the application.';
}).catch(() => {document.getElementById('status').textContent='Unable to open the local application.'});
</script></body></html>'''


def create_app(controller, access):
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
    from nicegui import ui
    from .access import AccessMiddleware
    from .subnets import render_subnets
    from .ip import render_ip
    from .ping import render_ping
    from .monitor import render_monitor
    from .config_page import render_config_search
    from .demob_page import render_demob

    parent = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
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
        filename = snapshot.get('filename', 'report.xlsx') if snapshot.get('request_id') == request_id else 'report.xlsx'
        class SnapshotResponse(FileResponse):
            async def __call__(self, scope, receive, send):
                try:
                    await super().__call__(scope, receive, send)
                finally:
                    controller.release_snapshot(request_id)
        return SnapshotResponse(path, filename=filename, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                                headers={'Cache-Control': 'no-store'})

    @ui.page('/config-search')
    def config_search_page():
        render_config_search(controller)

    @ui.page('/demobilization')
    def demobilization_page():
        render_demob(controller)

    @ui.page('/ping')
    def ping_page():
        render_ping(controller)

    @ui.page('/monitor')
    def monitor_page():
        render_monitor(controller)

    @ui.page('/ip')
    def ip_page():
        render_ip(controller)

    ui.run_with(parent, root=lambda: render_subnets(controller), title='CN Tool',
                show_welcome_message=False, reconnect_timeout=15)
    return parent
