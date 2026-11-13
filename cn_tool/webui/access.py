"""Per-launch loopback access boundary, including the Socket.IO transport.

The cookie deliberately lacks Secure: this application serves plain HTTP only on
127.0.0.1. It is not an authentication scheme for shared hosting.

A launch hands out one-use bootstrap tokens: the first with the launch itself, and a fresh one for each
``POST /reopen`` that carries the launch's reopen secret (a second ``cn-web`` start reads it from
``~/.cn-web-session``, ``session_file.py``). Each token still opens one browser session, once.
"""
import hashlib
import hmac
from http.cookies import SimpleCookie
import json
import secrets
from threading import Lock

_REOPEN_BODY_LIMIT = 4096
# Unused bootstrap tokens kept at once: each /reopen adds one, and the oldest lapses first.
MAX_PENDING_TOKENS = 16


def _same(given, expected):
    # Constant time; bytes, because compare_digest refuses a str that is not ASCII.
    return isinstance(given, str) and secrets.compare_digest(given.encode('utf-8'), expected.encode('utf-8'))


def _loopback(client):
    if not client:
        return False
    import ipaddress
    try:
        address = ipaddress.ip_address(client[0])
    except ValueError:
        return False
    mapped = getattr(address, 'ipv4_mapped', None)
    return address.is_loopback or (mapped is not None and mapped.is_loopback)


class LocalAccess:

    def __init__(self, authority):
        if not authority.startswith('127.0.0.1:') or not authority[10:].isdigit():
            raise ValueError('Expected a numeric loopback authority')
        self.cookie_name = 'cn_session_' + secrets.token_hex(12)
        self.authority = authority
        self.origin = 'http://' + authority
        self.bootstrap_token = secrets.token_urlsafe(32)
        self.reopen_secret = secrets.token_urlsafe(32)
        self._secret = secrets.token_bytes(32)
        self._pending = [self.bootstrap_token]
        self._consumed = False
        self._lock = Lock()

    def exchange(self, token):
        with self._lock:
            # Every pending token is compared, so the time taken does not say which one matched.
            matches = [pending for pending in self._pending if _same(token, pending)]
            if not matches:
                return None
            self._pending.remove(matches[0])
            self._consumed = True
            value = secrets.token_urlsafe(32)
            return value + '.' + hmac.new(self._secret, value.encode(), hashlib.sha256).hexdigest()

    def reopen(self, secret):
        """A fresh one-use bootstrap token for the holder of the reopen secret, or None."""
        if not _same(secret, self.reopen_secret):
            return None
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._pending.append(token)
            del self._pending[:-MAX_PENDING_TOKENS]
        return token

    def valid_cookie(self, cookie):
        if not cookie or not self._consumed:
            return False
        value, separator, signature = cookie.partition('.')
        expected = hmac.new(self._secret, value.encode(), hashlib.sha256).hexdigest()
        return bool(separator) and secrets.compare_digest(signature, expected)


async def _deny(send):
    await send({'type': 'http.response.start', 'status': 403, 'headers': [(b'content-type', b'text/plain')]})
    await send({'type': 'http.response.body', 'body': b'Local application access denied.'})


async def _read_body(receive, limit):
    body = b''
    while True:
        message = await receive()
        if message['type'] != 'http.request':
            return None
        body += message.get('body', b'')
        if len(body) > limit:
            return None
        if not message.get('more_body', False):
            return body


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
        if scope['type'] == 'http' and scope['path'] == '/reopen':
            return await self._reopen(scope, receive, send, duplicate=duplicate, host=host, origin=origin)
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
            await _deny(send)

    async def _reopen(self, scope, receive, send, *, duplicate, host, origin):
        """``POST /reopen {"secret": ...}`` from this machine: ``{"token": ...}``, a new one-use bootstrap token.

        It sits beside ``/exchange`` but is answered here, before the application. A second launcher sends no
        Origin; a browser always sends one, and only the page's own may ask.
        """
        if (duplicate or scope.get('method') != 'POST' or host != self.access.authority
                or origin not in {None, self.access.origin} or not _loopback(scope.get('client'))):
            return await _deny(send)
        body = await _read_body(receive, _REOPEN_BODY_LIMIT)
        try:
            payload = json.loads(body.decode('utf-8')) if body is not None else None
        except ValueError:
            payload = None
        token = self.access.reopen(payload.get('secret')) if isinstance(payload, dict) else None
        if token is None:
            return await _deny(send)
        await send({'type': 'http.response.start', 'status': 200,
                    'headers': [(b'content-type', b'application/json'), (b'cache-control', b'no-store')]})
        await send({'type': 'http.response.body', 'body': json.dumps({'token': token}).encode('utf-8')})
