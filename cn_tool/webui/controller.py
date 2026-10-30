"""One reconnectable presentation state per application instance."""
from copy import deepcopy
from dataclasses import dataclass
import multiprocessing
from threading import RLock, Thread
from time import monotonic
from uuid import uuid4

from .protocol import decode, encode, envelope


@dataclass
class SessionSnapshot:
    session_id: str
    phase: str = 'starting'
    active_job_id: object = None
    progress_stage: str = ''
    elapsed_seconds: float = 0
    result: object = None
    result_job_id: object = None
    report_state: object = None
    credential_request: object = None
    credential_store: object = None
    saved_login_restored: bool = False
    error: object = None
    report_snapshot: object = None
    scope: str = ''
    username: str = ''
    report_warning: str = ''
    report_location: str = ''


class SessionController:
    def __init__(self):
        self.session_id = uuid4().hex
        self._state = SessionSnapshot(self.session_id)
        self._lock = RLock()
        self._connection = self._process = self._stop = self._interrupt = None
        self._reader = None
        self._started_at = None
        self._config_file = None
        self._disconnected = False
        self._reader_finished = False
        self._report_requests = set()
        self._report_paths = {}
        self._report_completions = {}

    def start(self, config_file=None):
        from .worker_entry import worker_main
        with self._lock:
            if self._process is not None:
                raise RuntimeError('Session already started')
            self._config_file = str(config_file) if config_file else None
            context = multiprocessing.get_context('spawn')
            parent, child = context.Pipe()
            self._stop = context.Event()
            self._interrupt = context.Event()
            self._connection = parent
            self._process = context.Process(target=worker_main, args=(child, self._stop, self._interrupt))
            try:
                self._process.start()
                child.close()
                self._reader = Thread(target=self._receive, daemon=True)
                self._reader.start()
                self._send('initialize', None, {'config_file': str(config_file) if config_file else None})
            except BaseException:
                # A Ctrl+C can interrupt any spawn boundary. Stop and join the child here because
                # its command loop cannot process a graceful shutdown before initialization.
                self._state.phase = 'closing'
                self._stop.set()
                try:
                    child.close()
                except OSError:
                    pass
                try:
                    self._connection.close()
                except OSError:
                    pass
                process = self._process
                if getattr(process, 'pid', None) is not None:
                    process.join(timeout=1)
                    if process.is_alive():
                        process.terminate()
                        process.join()
                if self._reader is None or not self._reader.is_alive():
                    self._reader_finished = True
                    self._disconnected = True
                    self._state.phase = 'closed'
                raise

    def retry_initialize(self):
        """Explicit retry after canceled credentials; retain this runtime and account."""
        with self._lock:
            if self._state.phase != 'setup_required':
                raise RuntimeError('Setup retry is unavailable')
            self._send('initialize', None, {'config_file': self._config_file})
            self._state.phase = 'starting'
            self._state.error = None

    def _send(self, kind, job_id, payload):
        if self._connection is None:
            raise RuntimeError('Session not started')
        self._connection.send_bytes(encode(envelope(self.session_id, job_id, kind, payload)))

    def submit(self, inputs):
        with self._lock:
            if self._state.phase != 'ready' or self._state.active_job_id:
                raise RuntimeError('A lookup is already active or session is unavailable')
            job = uuid4().hex
            self._send('lookup', job, {'inputs': inputs})
            self._state.active_job_id = job
            self._state.phase = 'running'
            self._state.error = None
            self._state.progress_stage = ''
            self._state.elapsed_seconds = 0
            self._started_at = monotonic()
            return job

    def cancel(self, job_id):
        with self._lock:
            if job_id == self._state.active_job_id and self._state.phase in {'running', 'stopping'}:
                self._send('cancel', job_id, {})
                self._state.phase = 'stopping'

    def reply_credentials(self, request_id, reply, *, remember=False):
        with self._lock:
            request = self._state.credential_request
            if not request or request['request_id'] != request_id:
                return
            self._send('credentials_reply', self._state.active_job_id, {
                'request_id': request_id,
                'reply': None if reply is None else {'username': reply.username, 'password': reply.password},
                'remember': remember,
            })
            self._state.credential_request = None

    def forget_credentials(self):
        with self._lock:
            if self._state.phase not in {'closing', 'closed', 'failed'}:
                self._send('forget_credentials', None, {})

    def snapshot(self):
        with self._lock:
            state = deepcopy(self._state)
            if self._started_at is not None:
                state.elapsed_seconds = monotonic() - self._started_at
            return state

    def request_report_snapshot(self):
        with self._lock:
            if self._state.phase not in {'ready', 'running', 'stopping', 'saving'}:
                raise RuntimeError('Session unavailable')
            request_id = uuid4().hex
            self._report_requests.add(request_id)
            self._send('snapshot_report', None, {'request_id': request_id})
            return request_id

    def report_completion(self, request_id):
        """Path-free completion retained independently for every requesting tab."""
        with self._lock:
            return deepcopy(self._report_completions.get(request_id))

    def acknowledge_report_completion(self, request_id):
        """Consume presentation metadata without deleting a streaming snapshot."""
        with self._lock:
            self._report_completions.pop(request_id, None)

    def resolve_snapshot(self, request_id):
        """Private server download accessor; paths never enter browser snapshots."""
        with self._lock:
            return self._report_paths[request_id]

    def release_snapshot(self, request_id):
        """Server calls after streaming finishes; the configured workbook is untouched."""
        from pathlib import Path
        with self._lock:
            path = self._report_paths.get(request_id)
            if path is not None:
                try:
                    Path(path).unlink(missing_ok=True)
                except OSError:
                    self._state.report_snapshot = dict(request_id=request_id, status='failed',
                                                       error='Could not remove temporary report download.')
                    return False
                self._report_paths.pop(request_id, None)
            self._report_completions.pop(request_id, None)
            return True

    def quit(self, *, interrupted=False):
        with self._lock:
            if self._state.phase == 'closed':
                return
            if interrupted and self._interrupt is not None:
                self._interrupt.set()
            if self._state.phase == 'closing':
                return
            self._state.phase = 'closing'
            self._state.credential_request = None
            if self._disconnected:
                self._state.error = None
                # The reader owns joining the dead child; never replay exit hooks.
                if self._reader_finished or self._process is None:
                    self._state.phase = 'closed'
                return
            self._send('shutdown', None, {'interrupted': interrupted})

    def _accept(self, event):
        with self._lock:
            if event['session_id'] != self.session_id:
                return
            kind, payload, job = event['kind'], event['payload'], event['job_id']
            if job is not None and job != self._state.active_job_id:
                return
            if self._state.phase in {'failed', 'closed'}:
                return
            if kind == 'ready':
                self._state.scope, self._state.username = payload['scope'], payload['username']
                self._state.report_warning = payload.get('report_warning', '')
                self._state.report_location = payload.get('report_location', '')
                if self._state.phase != 'closing':
                    self._state.phase = 'ready'
            elif kind == 'setup_required':
                if self._state.phase != 'closing':
                    self._state.phase = 'setup_required'
                self._state.error = payload['message']
                self._state.credential_request = None
            elif kind == 'credentials_required':
                if self._state.phase != 'closing':
                    self._state.credential_request = payload
            elif kind == 'credential_store_state':
                self._state.credential_store = payload
            elif kind == 'saved_login_restored':
                self._state.saved_login_restored = True
            elif kind == 'progress':
                self._state.progress_stage = payload['stage']
            elif kind in {'result', 'error'}:
                if kind == 'result':
                    self._state.result = payload['result']
                    self._state.result_job_id = job
                else:
                    self._state.error = payload['message']
                if self._started_at is not None:
                    self._state.elapsed_seconds = monotonic() - self._started_at
                    self._started_at = None
                self._state.active_job_id = None
                self._state.credential_request = None
                if self._state.phase != 'closing':
                    self._state.phase = 'ready' if job else 'failed'
            elif kind == 'report_state':
                self._state.report_state = payload['state']
                if payload['state'].get('state') == 'saving' and self._state.phase != 'closing':
                    self._state.phase = 'saving'
            elif kind == 'report_snapshot' and payload['request_id'] in self._report_requests:
                self._report_requests.remove(payload['request_id'])
                public = {'request_id': payload['request_id']}
                if 'path' in payload:
                    from pathlib import Path
                    self._report_paths[payload['request_id']] = payload['path']
                    public.update(status='ready', filename=payload.get('filename', Path(payload['path']).name))
                else:
                    public.update(status='failed', error=payload.get('error', 'Report snapshot failed'))
                self._state.report_snapshot = public
                self._report_completions[payload["request_id"]] = deepcopy(public)
            elif kind == 'closed':
                # IPC acknowledges resource cleanup, not process termination.
                # The reader publishes closed after its sole child join below.
                self._state.phase = 'closing'
                self._report_paths.clear()
                self._report_completions.clear()
                self._state.active_job_id = None

    def _receive(self):
        try:
            while True:
                event = decode(self._connection.recv_bytes())
                self._accept(event)
                if event['kind'] == 'closed':
                    break
        except (EOFError, OSError, ValueError):
            with self._lock:
                self._disconnected = True
                if self._state.phase != 'closed':
                    self._state.phase = 'failed'
                    self._state.error = 'Worker connection closed unexpectedly. Relaunch to start a new session.'
                    self._state.active_job_id = None
                    self._state.credential_request = None
        finally:
            with self._lock:
                self._disconnected = True
            self._connection.close()
            self._process.join()
            with self._lock:
                self._reader_finished = True
                if self._state.phase == 'closing':
                    self._state.phase = 'closed'
                    self._state.error = None
