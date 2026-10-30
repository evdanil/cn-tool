"""Per-launch loopback access boundary, including the Socket.IO transport.

The cookie deliberately lacks Secure: this application serves plain HTTP only on
127.0.0.1. It is not an authentication scheme for shared hosting.
"""
import hashlib
import hmac
from http.cookies import SimpleCookie
import secrets
from threading import Lock


class LocalAccess:

    def __init__(self, authority):
        if not authority.startswith('127.0.0.1:') or not authority[10:].isdigit():
            raise ValueError('Expected a numeric loopback authority')
        self.cookie_name = 'cn_session_' + secrets.token_hex(12)
        self.authority = authority
        self.origin = 'http://' + authority
        self.bootstrap_token = secrets.token_urlsafe(32)
        self._secret = secrets.token_bytes(32)
        self._consumed = False
        self._lock = Lock()

    def exchange(self, token):
        with self._lock:
            if self._consumed or not isinstance(token, str) or not secrets.compare_digest(token, self.bootstrap_token):
                return None
            self._consumed = True
            value = secrets.token_urlsafe(32)
            return value + '.' + hmac.new(self._secret, value.encode(), hashlib.sha256).hexdigest()

    def valid_cookie(self, cookie):
        if not cookie or not self._consumed:
            return False
        value, separator, signature = cookie.partition('.')
        expected = hmac.new(self._secret, value.encode(), hashlib.sha256).hexdigest()
        return bool(separator) and secrets.compare_digest(signature, expected)


class AccessMiddleware:
    """Pure ASGI: HTTP middleware alone cannot guard WebSocket upgrades."""
    def __init__(self, app, access):
        self.app, self.access = app, access

    async def __call__(self, scope, receive, send):
        if scope['type'] not in {'http', 'websocket'}:
            return await self.app(scope, receive, send)
        headers = {}
        duplicate = False
        for key, value in scope.get('headers', []):
            name = key.decode('latin1').lower()
            if name in {'host', 'origin', 'cookie'} and name in headers:
                duplicate = True
            headers[name] = value.decode('latin1')
        host, origin = headers.get('host'), headers.get('origin')
        action = scope['type'] == 'websocket' or scope.get('method', 'GET') not in {'GET', 'HEAD'}
        public = scope['type'] == 'http' and ((scope['path'] == '/bootstrap' and not action)
                                                   or (scope['path'] == '/exchange' and scope.get('method') == 'POST'))
        cookies = SimpleCookie()
        try:
            cookies.load(headers.get('cookie', ''))
            cookie = cookies.get(self.access.cookie_name)
            authenticated = self.access.valid_cookie(cookie.value if cookie else None)
        except Exception:
            authenticated = False
        allowed = (not duplicate and host == self.access.authority
                   and (origin == self.access.origin if action else origin in {None, self.access.origin})
                   and (public or authenticated))
        if allowed:
            return await self.app(scope, receive, send)
        if scope['type'] == 'websocket':
            await send({'type': 'websocket.close', 'code': 1008})
        else:
            await send({'type': 'http.response.start', 'status': 403, 'headers': [(b'content-type', b'text/plain')]})
            await send({'type': 'http.response.body', 'body': b'Local application access denied.'})
