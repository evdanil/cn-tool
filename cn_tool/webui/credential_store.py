"""Native credential storage, isolated in a disposable spawned process."""
from __future__ import annotations

import hashlib
import json
import multiprocessing
import sys
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class CredentialScope:
    endpoint: str = field(repr=False)
    account: str

    @property
    def service(self) -> str:
        try:
            parts = urlsplit(self.endpoint)
            port = parts.port
            host = parts.hostname
            if (self.account not in {'device', 'infoblox'} or parts.scheme.lower() not in {'http', 'https'}
                    or not host or parts.username is not None or parts.password is not None
                    or '?' in self.endpoint or '#' in self.endpoint
                    or any(c.isspace() or ord(c) < 32 for c in self.endpoint)):
                raise ValueError
            scheme = parts.scheme.lower()
            host = host.lower()
            if ':' in host:
                host = f'[{host}]'
            if port is not None and port != {'http': 80, 'https': 443}[scheme]:
                host += f':{port}'
            endpoint = urlunsplit((scheme, host, parts.path.rstrip('/'), '', ''))
            digest = hashlib.sha256(json.dumps([endpoint, self.account], ensure_ascii=True).encode()).hexdigest()
            return f'cn-tool:webui:v1:{digest}'
        except (TypeError, ValueError):
            raise ValueError('Invalid credential storage scope') from None


@dataclass(frozen=True)
class VaultResult:
    status: str
    username: str = ''
    password: str = field(default='', repr=False)
    message: str = ''

    def __post_init__(self):
        if self.status not in {'loaded', 'missing', 'saved', 'deleted', 'unavailable', 'error', 'canceled'}:
            raise ValueError('Invalid credential store status')
        if self.status != 'loaded' and self.password:
            raise ValueError('Password is only allowed for loaded credentials')


_POINTER = 'meta:last-username'


def _valid_username(username):
    return isinstance(username, str) and bool(username) and len(username) <= 1024 and not any(
        ord(c) < 32 or ord(c) == 127 for c in username
    )


def _native_backend():
    """Select an OS backend directly, bypassing keyring's configured provider."""
    try:
        if sys.platform == 'win32':
            from keyring.backends.Windows import WinVaultKeyring as Backend
        elif sys.platform == 'darwin':
            from keyring.backends.macOS import Keyring as Backend
        elif sys.platform.startswith('linux'):
            from keyring.backends.SecretService import Keyring as Backend
        else:
            return None
        backend = Backend()
        return backend if backend.priority > 0 else None
    except Exception:
        return None


def _execute(backend, action, service, username, password):
    if backend is None:
        return VaultResult('unavailable', message='Native credential storage is unavailable.')
    if action not in {'load', 'save', 'forget'} or (username and not _valid_username(username)):
        return VaultResult('error', message='Invalid credential storage request.')
    if action in {'save', 'forget'} and not _valid_username(username):
        return VaultResult('error', message='Invalid credential storage request.')
    try:
        if action == 'load':
            selected = username or backend.get_password(service, _POINTER)
            if not _valid_username(selected):
                return VaultResult('missing')
            value = backend.get_password(service, 'user:' + selected)
            if not isinstance(value, str) or not value:
                return VaultResult('missing', username=selected)
            return VaultResult('loaded', username=selected, password=value)
        key = 'user:' + username
        if action == 'save':
            if not isinstance(password, str) or not password:
                return VaultResult('error', message='Invalid credential storage request.')
            backend.set_password(service, key, password)
            try:
                backend.set_password(service, _POINTER, username)
            except Exception:
                return VaultResult('error', message='Password saved; the saved username update outcome is unknown.')
            return VaultResult('saved', username=username)
        existing = backend.get_password(service, key)
        if existing is not None:
            backend.delete_password(service, key)
        try:
            if backend.get_password(service, _POINTER) == username:
                backend.delete_password(service, _POINTER)
        except Exception:
            return VaultResult('error', message='Password deleted; the saved username update outcome is unknown.')
        return VaultResult('deleted', username=username)
    except Exception:
        message = 'Native credential storage operation failed.'
        if action != 'load':
            message += ' The operation outcome is unknown.'
        return VaultResult('error', message=message)


def _helper_main(conn):
    try:
        request = json.loads(conn.recv_bytes(65536).decode('utf-8'))
        result = _execute(_native_backend(), request['action'], request['service'], request['username'], request['password'])
        conn.send_bytes(json.dumps({'status': result.status, 'username': result.username,
                                    'password': result.password, 'message': result.message}).encode('utf-8'))
    except Exception:
        try:
            conn.send_bytes(b'{"status":"error","message":"Native credential storage operation failed."}')
        except Exception:
            pass
    finally:
        conn.close()


class NativeCredentialStore:
    def __init__(self, stop, timeout: float = 15.0, *, _helper=None):
        self._stop = stop
        self._timeout = min(max(timeout, 0), 15.0)
        self._helper = _helper or _helper_main

    def load(self, scope: CredentialScope, username: str = '') -> VaultResult:
        return self._run('load', scope, username, '')

    def save(self, scope: CredentialScope, username: str, password: str) -> VaultResult:
        return self._run('save', scope, username, password)

    def forget(self, scope: CredentialScope, username: str) -> VaultResult:
        return self._run('forget', scope, username, '')

    def _run(self, action, scope, username, password):
        if self._stop.is_set():
            return VaultResult('canceled', message='Credential storage operation canceled.')
        try:
            request = json.dumps({'action': action, 'service': scope.service, 'username': username,
                                  'password': password}, ensure_ascii=True).encode('utf-8')
            if len(request) > 4096:
                return VaultResult('error', message='Credential storage request is too large.')
        except (TypeError, ValueError):
            return VaultResult('error', message='Invalid credential storage request.')
        ctx = multiprocessing.get_context('spawn')
        parent, child = ctx.Pipe(duplex=True)
        process = ctx.Process(target=self._helper, args=(child,), daemon=True)
        started = False
        reader = None
        reader_started = False
        dispatched = False
        deadline = time.monotonic() + self._timeout
        try:
            process.start()
            started = True
            child.close()
            if self._stop.is_set():
                return VaultResult('canceled', message='Credential storage operation canceled.')
            if time.monotonic() >= deadline:
                return VaultResult('unavailable', message='Credential storage timed out.')
            dispatched = True
            parent.send_bytes(request)
            received = threading.Event()
            reply = []

            def receive_reply():
                try:
                    reply.append(parent.recv_bytes(65536))
                except Exception:
                    pass
                finally:
                    received.set()

            reader = threading.Thread(target=receive_reply, name='credential-store-reader', daemon=True)
            reader.start()
            reader_started = True
            while True:
                if self._stop.is_set() or time.monotonic() >= deadline:
                    canceled = self._stop.is_set()
                    message = 'Credential storage operation canceled.' if canceled else 'Credential storage timed out.'
                    if action != 'load' and dispatched:
                        message += ' The operation outcome is unknown.'
                    return VaultResult('canceled' if canceled else 'unavailable', message=message)
                if received.wait(min(0.1, max(0, deadline - time.monotonic()))):
                    if self._stop.is_set() or time.monotonic() >= deadline:
                        canceled = self._stop.is_set()
                        message = 'Credential storage operation canceled.' if canceled else 'Credential storage timed out.'
                        if action != 'load' and dispatched:
                            message += ' The operation outcome is unknown.'
                        return VaultResult('canceled' if canceled else 'unavailable', message=message)
                    if not reply:
                        raise EOFError
                    data = json.loads(reply[0].decode('utf-8'))
                    # The helper is private, but reject malformed responses and never expose exception text.
                    return VaultResult(status=data['status'], username=data.get('username', ''),
                                       password=data.get('password', ''), message=data.get('message', ''))
        except Exception:
            message = 'Native credential storage operation failed.'
            if action != 'load' and dispatched:
                message += ' The operation outcome is unknown.'
            return VaultResult('error', message=message)
        finally:
            child.close()
            if started:
                if process.is_alive():
                    process.terminate()
                process.join(timeout=1)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=1)
                process.close()
            if reader_started:
                reader.join(timeout=1)
            parent.close()
            if reader_started and reader.is_alive():
                reader.join(timeout=1)
