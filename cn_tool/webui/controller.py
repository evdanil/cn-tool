"""One reconnectable presentation state per application instance."""
from copy import deepcopy
from dataclasses import dataclass, field, replace
import multiprocessing
from threading import RLock, Thread
from time import monotonic
from uuid import uuid4

from .protocol import decode, encode, envelope, validate, valid_monitor_history_item


def _remove_file(path):
    """Remove a temporary download the worker prepared; one that is already gone, or locked, is not an error here."""
    from pathlib import Path
    try:
        Path(path).unlink(missing_ok=True)
    except OSError:
        pass


STALE_CONFIRMATION = 'The settings were reloaded since this was opened. Nothing was deleted.'


class ReportDeletionInProgress(RuntimeError):
    """Work refused only because a report deletion is running; the text is written for the user."""

    def __init__(self):
        super().__init__('Report deletion is in progress. Try again when it finishes.')


@dataclass
class SessionSnapshot:
    session_id: str
    phase: str = 'starting'
    active_job_id: object = None
    active_lookup_type: object = None
    results_by_type: dict = field(default_factory=lambda: {'subnet': None, 'ip': None, 'ping': None, 'monitor': None, 'config_search': None, 'demob': None})
    attempts_by_type: dict = field(default_factory=lambda: {'subnet': None, 'ip': None, 'ping': None, 'monitor': None, 'config_search': None, 'demob': None})
    demob_preview: object = None
    demob_discovery: object = None
    monitor_update: object = None
    progress_stage: str = ''
    progress_completed: object = None
    progress_total: object = None
    elapsed_seconds: float = 0
    result: object = None
    result_job_id: object = None
    latest_attempt_id: object = None
    latest_outcome: object = None
    latest_report_state: object = None
    report_state: object = None
    credential_request: object = None
    credential_store: object = None
    saved_login_restored: bool = False
    error: object = None
    report_snapshot: object = None
    report_delete_pending: bool = False
    report_snapshot_pending: bool = False
    # How the latest reload_configuration ended: token, status ('pending', 'applied', 'refused', 'failed'), message.
    reload_result: object = None
    # One more for each reload or Retry setup sent: either can bring other settings. The History tab of every page
    # starts again (the history file may be another), and a deletion confirmed under an older generation is refused
    # (the workbook or history file may be another). No deletion can be confirmed until the session is ready again.
    config_generation: int = 0
    scope: str = ''
    username: str = ''
    report_warning: str = ''


@dataclass
class PageSnapshot:
    state: SessionSnapshot
    result_revision: int
    attempt_revision: int
    result_changed: bool
    attempt_changed: bool
    result_job_id: object
    result: object
    attempt_job_id: object
    outcome: object
    attempt_result: object
    attempt_report_state: object


class SessionController:
    def __init__(self):
        self.session_id = uuid4().hex
        self._state = SessionSnapshot(self.session_id)
        self._lock = RLock()
        self._connection = self._process = self._stop = self._interrupt = None
        self._reader = None
        self._started_at = None
        self._config_file = None
        self._reload_token = 0
        self._reload_mode = None
        self._disconnected = False
        self._reader_finished = False
        self._delete_pending = None
        self._delete_abandoned = False
        self._delete_results = {}
        self._history_requests = {}
        self._history_pages = {}
        self._monitor_requests = {}
        self._monitor_pages = {}
        self._config_requests = {}
        self._config_pages = {}
        self._demob_requests = {}
        self._demob_pages = {}
        self._demob_expires = 0
        self._report_delete_request = None
        self._report_delete_abandoned = False
        self._report_delete_results = {}
        self._report_requests = set()
        # The workbook's own preparations: the CSV of Show Available is a request too, but it never reads the workbook.
        self._workbook_snapshots = set()
        self._report_paths = {}
        self._report_completions = {}
        self._report_streams = set()
        self._result_revisions = dict.fromkeys(('subnet', 'ip', 'ping', 'monitor', 'config_search', 'demob'), 0)
        self._attempt_revisions = dict.fromkeys(('subnet', 'ip', 'ping', 'monitor', 'config_search', 'demob'), 0)

    def start(self, config_file=None, *, config_search_connection=None):
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
            self._process = context.Process(
                target=worker_main, args=(child, self._stop, self._interrupt, config_search_connection))
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

    @property
    def config_file(self):
        """The ``-c FILE`` this session was started with, or None: the Settings page edits it, else ``~/.cn``."""
        return self._config_file

    def reload_configuration(self):
        """
        Read the configuration files again (Settings' "Use the new settings now", and Retry setup).

        In ``setup_required`` there is no runtime: this is ``retry_initialize``. In ``ready`` the worker closes the
        runtime without exit actions and opens a new one from the session's own files; only while nothing runs.
        """
        with self._lock:
            if self._state.phase == 'setup_required':
                self.retry_initialize()
                return self._reload_started('retry')
            if self._state.phase != 'ready':
                raise RuntimeError('The settings can be reloaded once the application has started.')
            if (self._state.active_job_id is not None or self._state.report_delete_pending
                    or self._workbook_snapshots):
                raise RuntimeError('The settings can be reloaded when no work is running. '
                                   'Try again when it finishes.')
            self._send('reload_config', None, {'config_file': self._config_file})
            self._state.phase = 'starting'
            self._state.error = None
            self._state.config_generation += 1
            return self._reload_started('reload')

    def _reload_started(self, mode):
        """A token for the page that asked, and a pending result in the snapshot that every tab reads."""
        self._reload_token += 1
        self._reload_mode = mode
        self._state.reload_result = dict(token=self._reload_token, status='pending', message='')
        return self._reload_token

    def _reload_ended(self, status, message=''):
        if self._reload_mode is None:
            return
        self._reload_mode = None
        self._state.reload_result = dict(token=self._reload_token, status=status, message=message)
        if status == 'applied':  # a saved login is looked up again for the settings now in use
            self._state.saved_login_restored = False

    def retry_initialize(self):
        """Explicit retry after canceled credentials; retain this runtime and account."""
        with self._lock:
            if self._state.phase != 'setup_required':
                raise RuntimeError('Setup retry is unavailable')
            self._send('initialize', None, {'config_file': self._config_file})
            self._state.phase = 'starting'
            self._state.error = None
            self._state.config_generation += 1  # the files are read again: confirmations opened before are stale

    def _send(self, kind, job_id, payload):
        if self._connection is None:
            raise RuntimeError('Session not started')
        try:
            self._connection.send_bytes(encode(envelope(self.session_id, job_id, kind, payload)))
        except (OSError, EOFError):
            with self._lock:
                self._clear_report_requests()
            raise

    def submit(self, inputs, lookup_type='subnet', *, tcp_ports=(), interval_seconds=60, duration_seconds=None):
        if lookup_type not in ('subnet', 'ip', 'ping', 'monitor', 'config_search'):
            raise ValueError('Invalid lookup type')
        with self._lock:
            if self._state.phase != 'ready' or self._state.active_job_id or self._state.report_delete_pending:
                raise self._lookup_refusal()
            job = uuid4().hex
            payload = {'inputs': inputs, 'lookup_type': lookup_type}
            if lookup_type in ('ping', 'monitor'):
                payload['tcp_ports'] = list(tcp_ports)
                if lookup_type == 'monitor':
                    payload.update(interval_seconds=interval_seconds, duration_seconds=duration_seconds)
            elif tcp_ports:
                raise ValueError('Ports require Ping')
            if self._state.demob_preview and self._state.demob_preview['token']:
                self._send('demob_decline', None, {})
            self._clear_demob()
            self._state.demob_discovery = None
            self._send('lookup', job, payload)
            if lookup_type == 'monitor':
                self._state.results_by_type['monitor'] = None
                self._result_revisions['monitor'] += 1
                self._state.monitor_update = None
                self._monitor_requests.clear()
                self._monitor_pages.clear()
            self._state.active_job_id = job
            self._state.active_lookup_type = lookup_type
            self._state.attempts_by_type[lookup_type] = dict(job_id=job, outcome=None, report_state=None)
            self._attempt_revisions[lookup_type] += 1
            self._state.latest_attempt_id = job
            self._state.latest_outcome = None
            previous = self._state.latest_report_state or {}
            self._set_report_state(dict(state='pending', status='pending', filename=previous.get('filename', ''),
                                        message='Lookup in progress.', available=previous.get('available', False),
                                        saved_for_attempt=False))
            self._state.phase = 'running'
            self._state.error = None
            self._state.progress_stage = ''
            self._state.progress_completed = self._state.progress_total = None
            self._state.elapsed_seconds = 0
            self._started_at = monotonic()
            return job

    def _clear_demob(self):
        self._state.demob_preview = None
        self._demob_expires = 0
        self._demob_requests.clear()
        self._demob_pages.clear()

    def _lookup_refusal(self):
        """Why a lookup cannot start now; the caller holds the lock."""
        if self._state.phase == 'ready' and not self._state.active_job_id and self._state.report_delete_pending:
            return ReportDeletionInProgress()
        return RuntimeError('A lookup is already active or session is unavailable')

    def _start_demob(self, kind, payload):
        if self._state.phase != 'ready' or self._state.active_job_id or self._state.report_delete_pending:
            raise self._lookup_refusal()
        job = uuid4().hex
        self._send(kind, job, payload)
        self._state.active_job_id = job
        self._state.active_lookup_type = 'demob'
        self._state.attempts_by_type['demob'] = dict(job_id=job, outcome=None, report_state=None)
        self._attempt_revisions['demob'] += 1
        self._state.latest_attempt_id = job
        self._state.latest_outcome = None
        previous = self._state.latest_report_state or {}
        self._set_report_state(dict(state='pending', status='pending', filename=previous.get('filename', ''),
                                    message='Site check in progress.', available=previous.get('available', False),
                                    saved_for_attempt=False))
        self._state.phase = 'running'
        self._state.error = None
        self._state.progress_stage = ''
        self._started_at = monotonic()
        return job

    def submit_demob_lookup(self, site):
        with self._lock:
            if self._state.phase != 'ready' or self._state.active_job_id or self._state.report_delete_pending:
                raise self._lookup_refusal()
            # Invalidate the old preview even if the new input is invalid.
            if self._state.demob_preview and self._state.demob_preview['token']:
                self._send('demob_decline', None, {})
            self._clear_demob()
            self._state.demob_discovery = None
            return self._start_demob('demob_lookup', {'site': site})

    def confirm_demob_search(self, token):
        with self._lock:
            if self._state.report_delete_pending:
                raise ReportDeletionInProgress()
            preview = self._state.demob_preview
            if not preview or monotonic() >= self._demob_expires or preview['token'] != token:
                if preview and monotonic() >= self._demob_expires:
                    self._clear_demob()
                raise ValueError('Preview is unavailable or expired')
            job = self._start_demob('demob_confirm', {'token': token})
            self._state.demob_discovery = deepcopy({key: preview[key] for key in ('site', 'status', 'message', 'notices')})
            self._clear_demob()
            return job

    def discard_demob_for_replacement(self):
        """Invalidate the current preview for a replacement attempt, including blank input."""
        with self._lock:
            if self._state.phase != 'ready' or self._state.active_job_id or self._state.report_delete_pending:
                raise self._lookup_refusal()
            preview = self._state.demob_preview
            self._clear_demob()
            if preview and preview['token']:
                self._send('demob_decline', None, {})

    def decline_demob(self, token):
        with self._lock:
            preview = self._state.demob_preview
            if not preview or preview['token'] != token:
                return
            self._clear_demob()
            if self._state.phase not in {'closing', 'closed', 'failed'}:
                self._send('demob_decline', None, {})

    def request_demob_page(self, token, offset, limit=50, *, sort_by=None, descending=False, filter_by=None, filter_text=''):
        with self._lock:
            preview = self._state.demob_preview
            if not preview or monotonic() >= self._demob_expires or preview['token'] != token:
                if preview and monotonic() >= self._demob_expires:
                    self._clear_demob()
                raise ValueError('Preview is unavailable or expired')
            if len(self._demob_requests) + len(self._demob_pages) >= 8:
                raise RuntimeError('Too many outstanding preview pages')
            query_id = uuid4().hex
            payload = dict(token=token, offset=offset, limit=limit, query_id=query_id)
            if sort_by is not None or filter_by is not None or filter_text or descending:
                payload.update(sort_by=sort_by, descending=descending, filter_by=filter_by, filter_text=filter_text)
            self._send('demob_page', None, payload)
            self._demob_requests[query_id] = payload
            return query_id

    def demob_page(self, query_id):
        with self._lock:
            if monotonic() >= self._demob_expires:
                self._clear_demob()
            return deepcopy(self._demob_pages.get(query_id))

    def release_demob_page(self, query_id):
        with self._lock:
            self._demob_requests.pop(query_id, None)
            self._demob_pages.pop(query_id, None)

    def cancel(self, job_id):
        with self._lock:
            if job_id == self._state.active_job_id and self._state.phase == 'running':
                self._send('cancel', job_id, {})
                self._state.phase = 'stopping'

    def cancel_active(self):
        with self._lock:
            self.cancel(self._state.active_job_id)

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
            if (self._state.demob_preview and self._state.demob_preview['token'] is not None
                    and monotonic() >= self._demob_expires):
                self._clear_demob()
            state = deepcopy(self._state)
            if self._started_at is not None:
                state.elapsed_seconds = monotonic() - self._started_at
            return state

    def page_snapshot(self, lookup_type, *, result_revision=None, attempt_revision=None):
        """Return atomic metadata and detached changed payloads for one page."""
        with self._lock:
            if (self._state.demob_preview and self._state.demob_preview['token'] is not None
                    and monotonic() >= self._demob_expires):
                self._clear_demob()
            result_version = self._result_revisions[lookup_type]
            attempt_version = self._attempt_revisions[lookup_type]
            result_changed = result_revision != result_version
            attempt_changed = attempt_revision != attempt_version
            result = self._state.results_by_type.get(lookup_type) or {}
            attempt = self._state.attempts_by_type.get(lookup_type) or {}
            # These fields contain the large per-tool data; never copy them as
            # part of routine metadata or expose references into controller state.
            state = deepcopy(replace(self._state, results_by_type={}, attempts_by_type={},
                                     result=None, latest_outcome=None))
            if self._started_at is not None:
                state.elapsed_seconds = monotonic() - self._started_at
            diagnostic = attempt.get('result') or {}
            attempt_result = None
            if attempt_changed and lookup_type == 'ping':
                attempt_result = deepcopy({key: diagnostic.get(key, []) for key in
                                           ('input_errors', 'resolution_errors')})
            elif attempt_changed and lookup_type in ('config_search', 'demob') and attempt.get('result') is not None:
                attempt_result = deepcopy({key: diagnostic[key] for key in
                                           ('status', 'total', 'errors', 'missing_nets')})
            elif attempt_changed and lookup_type == 'monitor' and 'result' in attempt:
                # Monitor's validated result is compact and includes failures from finalization.
                attempt_result = deepcopy(attempt['result'])
            return PageSnapshot(state, result_version, attempt_version, result_changed, attempt_changed,
                result.get('job_id'), deepcopy(result.get('result')) if result_changed else None,
                attempt.get('job_id'), deepcopy(attempt.get('outcome')) if attempt_changed else None,
                attempt_result, deepcopy(attempt.get('report_state')))

    def current_credential_request(self):
        """Revalidate a prompt without traversing retained results."""
        with self._lock:
            if self._state.phase in {'closing', 'closed', 'failed'}:
                return None
            return deepcopy(self._state.credential_request)

    def current_phase(self):
        """Read the lifecycle phase without copying retained results."""
        with self._lock:
            return self._state.phase

    def request_monitor_delete(self, action, run_id=None, request_id=None, generation=None):
        with self._lock:
            if generation is not None and generation != self._state.config_generation:
                raise RuntimeError(STALE_CONFIRMATION)
            if self._state.phase not in {'ready', 'running', 'stopping', 'saving'}:
                raise RuntimeError('Session unavailable')
            if self._delete_pending is not None:
                raise RuntimeError('A history deletion is already in progress')
            if len(self._delete_results) >= 32:
                raise RuntimeError('Too many unclaimed history deletion results')
            query_id = uuid4().hex
            payload = dict(action=action, run_id=run_id, request_id=request_id, query_id=query_id)
            validate(envelope(self.session_id, None, 'monitor_delete', payload))
            self._send('monitor_delete', None, payload)
            self._delete_pending = query_id
            self._delete_abandoned = False
            return query_id

    def monitor_delete_result(self, query_id):
        with self._lock:
            return deepcopy(self._delete_results.get(query_id))

    def release_monitor_delete_result(self, query_id):
        with self._lock:
            if self._delete_pending == query_id:
                self._delete_abandoned = True
            self._delete_results.pop(query_id, None)

    def request_monitor_history(self, kind, parent=None, cursor=None, limit=100, sort=None, descending=False, group='all', filter_field='host', filter_text=''):
        with self._lock:
            if self._state.phase not in {'ready', 'running', 'stopping', 'saving'}:
                raise RuntimeError('Session unavailable')
            query_id = uuid4().hex
            payload = dict(kind=kind, parent=parent, cursor=cursor, limit=limit, query_id=query_id)
            if sort is not None:
                payload.update(sort=sort, descending=descending, group=group, filter_field=filter_field, filter_text=filter_text)
            self._send('monitor_history', None, payload)
            self._history_requests[query_id] = (kind, limit)
            return query_id

    def monitor_history_page(self, query_id):
        with self._lock:
            return deepcopy(self._history_pages.get(query_id))

    def release_monitor_history_page(self, query_id):
        with self._lock:
            self._history_requests.pop(query_id, None)
            self._history_pages.pop(query_id, None)

    def release_monitor_live_page(self, query_id):
        with self._lock:
            self._monitor_requests.pop(query_id, None)
            self._monitor_pages.pop(query_id, None)

    def request_monitor_live_page(self, job_id, run_id, revision, offset, limit=100, sort=None, descending=False, group='all', filter_field='host', filter_text=''):
        with self._lock:
            update = self._state.monitor_update
            selected = self._state.attempts_by_type['monitor'] or {}
            if (self._state.phase in {'closing', 'closed', 'failed'} or not update or
                    selected.get('job_id') != job_id or update['run_id'] != run_id or update['revision'] != revision):
                raise RuntimeError('Monitor snapshot is unavailable or expired')
            query_id = uuid4().hex
            payload = dict(job_id=job_id, run_id=run_id, revision=revision, offset=offset, limit=limit, query_id=query_id)
            if sort is not None:
                payload.update(sort=sort, descending=descending, group=group, filter_field=filter_field, filter_text=filter_text)
            self._send('monitor_live_page', None, payload)
            self._monitor_requests[query_id] = payload
            return query_id

    def monitor_live_page(self, query_id):
        with self._lock:
            return deepcopy(self._monitor_pages.get(query_id))

    def request_config_search_page(self, job_id, offset, limit=50, *, sort_by=None, descending=False, filter_by=None, filter_text=''):
        with self._lock:
            result = (self._state.results_by_type['config_search'] or {})
            demob = self._state.results_by_type['demob'] or {}
            if demob.get('job_id') == job_id:
                result = demob
            if (self._state.phase in {'closing', 'closed', 'failed'} or result.get('job_id') != job_id):
                raise RuntimeError('Configuration result is unavailable or expired')
            if len(self._config_requests) + len(self._config_pages) >= 8:
                raise RuntimeError('Too many outstanding configuration pages')
            query_id = uuid4().hex
            payload = dict(job_id=job_id, offset=offset, limit=limit, query_id=query_id)
            if sort_by is not None or filter_by is not None or filter_text or descending:
                payload.update(sort_by=sort_by, descending=descending, filter_by=filter_by, filter_text=filter_text)
            self._send('config_search_page', None, payload)
            self._config_requests[query_id] = payload
            return query_id

    def config_search_page(self, query_id):
        with self._lock:
            return deepcopy(self._config_pages.get(query_id))

    def release_config_search_page(self, query_id):
        with self._lock:
            self._config_requests.pop(query_id, None)
            self._config_pages.pop(query_id, None)

    def request_report_delete(self, generation=None) -> str:
        """Reserve the shared workbook before sending a path-free deletion request. ``generation`` is the
        ``config_generation`` the confirmation was opened under: one from before a reload is refused."""
        with self._lock:
            if generation is not None and generation != self._state.config_generation:
                raise RuntimeError(STALE_CONFIRMATION)
            if self._state.report_delete_pending:
                raise ReportDeletionInProgress()
            if (self._state.phase != 'ready' or self._state.active_job_id or self._state.report_snapshot_pending):
                raise RuntimeError('The report is busy or the session is unavailable. Try again when it is ready.')
            if not (self._state.report_state or {}).get('available'):
                raise RuntimeError('No accumulated report exists.')
            request_id = uuid4().hex
            self._report_delete_request = request_id
            self._report_delete_abandoned = False
            self._state.report_delete_pending = True
            try:
                self._send('delete_report', None, {'request_id': request_id})
            except BaseException:
                self._report_delete_request = None
                self._state.report_delete_pending = False
                raise
            return request_id

    def report_delete_result(self, request_id: str) -> dict | None:
        """Return a detached completion for the tab that requested deletion."""
        with self._lock:
            return deepcopy(self._report_delete_results.get(request_id))

    def release_report_delete_result(self, request_id: str) -> None:
        """Abandon local presentation without cancelling the shared operation."""
        with self._lock:
            self._report_delete_results.pop(request_id, None)
            if request_id == self._report_delete_request:
                self._report_delete_abandoned = True

    def _clear_report_requests(self):
        self._report_requests.clear()
        self._workbook_snapshots.clear()
        self._state.report_snapshot_pending = False
        self._report_delete_request = None
        self._state.report_delete_pending = False
        self._report_delete_abandoned = False
        self._report_delete_results.clear()

    def request_report_snapshot(self):
        with self._lock:
            if self._state.report_delete_pending:
                raise ReportDeletionInProgress()
            if self._state.phase not in {'ready', 'running', 'stopping', 'saving'}:
                raise RuntimeError('Session unavailable')
            request_id = uuid4().hex
            self._report_requests.add(request_id)
            self._workbook_snapshots.add(request_id)
            self._state.report_snapshot_pending = True
            try:
                self._send('snapshot_report', None, {'request_id': request_id})
            except BaseException:
                self._report_requests.discard(request_id)
                self._workbook_snapshots.discard(request_id)
                self._state.report_snapshot_pending = bool(self._workbook_snapshots)
                raise
            return request_id

    def request_coverage_export(self, parent):
        """Ask the worker for the CSV of every ``Unseen`` host of request ``parent`` (a history ``requests`` row id).
        The reply is a ``report_snapshot``, so it completes, downloads and is released as the workbook is."""
        with self._lock:
            if self._state.phase not in {'ready', 'running', 'stopping', 'saving'}:
                raise RuntimeError('Session unavailable')
            request_id = uuid4().hex
            payload = dict(request_id=request_id, parent=parent)
            validate(envelope(self.session_id, None, 'monitor_coverage_export', payload))
            self._send('monitor_coverage_export', None, payload)
            self._report_requests.add(request_id)
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
            path = self._report_paths[request_id]
            self._report_streams.add(request_id)
            return path

    def release_report_request(self, request_id):
        """A page that no longer wants a snapshot (a reset, or the page closing) gives it up. Its late completion is
        dropped and its file removed on arrival. A file the browser is streaming is left to that stream's
        ``release_snapshot``. The worker is still preparing a released workbook download, so
        ``report_snapshot_pending`` stays true: its late reply clears it, not this call."""
        with self._lock:
            self._report_requests.discard(request_id)
            if request_id not in self._report_streams:
                self._remove_snapshot(request_id)

    def _remove_snapshot(self, request_id):
        path = self._report_paths.pop(request_id, None)
        self._report_completions.pop(request_id, None)
        if path is not None:
            _remove_file(path)

    def release_snapshot(self, request_id):
        """Server calls after streaming finishes; the configured workbook is untouched."""
        from pathlib import Path
        with self._lock:
            self._report_streams.discard(request_id)
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
            self._clear_demob()
            self._state.demob_discovery = None
            self._clear_report_availability()
            self._state.credential_request = None
            if self._disconnected:
                self._state.error = None
                # The reader owns joining the dead child; never replay exit hooks.
                if self._reader_finished or self._process is None:
                    self._state.phase = 'closed'
                return
            self._send('shutdown', None, {'interrupted': interrupted})

    def _set_report_state(self, report):
        if self._state.phase in {'setup_required', 'closing', 'failed', 'closed'}:
            report = dict(report, available=False)
        self._state.latest_report_state = report
        # The current workbook and the latest attempt have independent lifetimes.
        # A no-write attempt must not revive an older tool's saved-workbook label.
        current = self._state.report_state or {}
        if current.get('state') != 'deleted' or report.get('available'):
            self._state.report_state = report
        lookup_type = self._state.active_lookup_type
        if lookup_type is not None:
            attempt = self._state.attempts_by_type[lookup_type]
            if attempt is not None and attempt['job_id'] == self._state.active_job_id:
                attempt['report_state'] = deepcopy(report)

    def _clear_report_availability(self):
        report = self._state.latest_report_state or self._state.report_state
        if report is not None:
            self._set_report_state(dict(report, available=False))

    def _accept(self, event):
        with self._lock:
            if event['session_id'] != self.session_id:
                return
            kind, payload, job = event['kind'], event['payload'], event['job_id']
            if job is not None and job != self._state.active_job_id:
                return
            if kind in {'progress', 'report_state', 'result', 'lookup_context', 'monitor_update'} or (kind == 'error' and job is not None):
                if not job or payload.get('lookup_type') != self._state.active_lookup_type:
                    return
            if self._state.phase in {'failed', 'closed'}:
                return
            if kind == 'reload_result':
                if self._reload_mode == 'reload':
                    self._reload_ended(payload['status'], payload['message'])
                return
            if kind == 'ready' and self._reload_mode == 'retry':
                self._reload_ended('applied')
            if kind == 'setup_required' or (kind == 'error' and job is None):
                self._reload_ended('failed', payload['message'])
            if kind == 'ready':
                self._state.scope, self._state.username = payload['scope'], payload['username']
                self._state.report_warning = payload.get('report_warning', '')
                if self._state.phase != 'closing':
                    self._state.phase = 'ready'
                if 'report_state' in payload:
                    self._set_report_state(payload['report_state'])
            elif kind == 'setup_required':
                if self._state.phase != 'closing':
                    self._state.phase = 'setup_required'
                self._clear_report_availability()
                self._state.error = payload['message']
                self._state.credential_request = None
            elif kind == 'credentials_required':
                if job and job == self._state.active_job_id and self._state.phase != 'closing':
                    self._state.credential_request = payload
            elif kind == 'credential_store_state':
                self._state.credential_store = payload
            elif kind == 'saved_login_restored':
                self._state.saved_login_restored = True
            elif kind == 'monitor_update':
                previous = self._state.monitor_update
                if previous and (payload['run_id'] != previous['run_id'] or payload['revision'] < previous['revision']):
                    return
                self._state.monitor_update = deepcopy(payload)
                self._state.progress_stage = payload['stage']
                self._state.progress_completed = payload['completed']
                self._state.progress_total = payload['total']
            elif kind == 'report_delete_result':
                try:
                    validate(event)
                except (ValueError, TypeError):
                    return
                if payload['request_id'] != self._report_delete_request:
                    return
                self._report_delete_request = None
                self._state.report_delete_pending = False
                self._set_report_state(deepcopy(payload['report_state']))
                if not self._report_delete_abandoned:
                    self._report_delete_results[payload['request_id']] = deepcopy(payload)
                self._report_delete_abandoned = False
            elif kind == 'monitor_delete_result':
                try:
                    validate(event)
                except (ValueError, TypeError):
                    return
                if payload['query_id'] != self._delete_pending:
                    return
                self._delete_pending = None
                if not self._delete_abandoned:
                    self._delete_results[payload['query_id']] = deepcopy(payload)
                self._delete_abandoned = False
            elif kind == 'monitor_history_result':
                request = self._history_requests.get(payload['query_id'])
                if (request is None or len(payload['items']) > request[1] or
                        (request[0] == 'template' and (payload['next_cursor'] is not None or
                         len(payload['items']) != (0 if payload['error'] else 1))) or
                        # A coverage page that is not an error carries its summary, and no other page does.
                        ('summary' in payload) != (request[0] == 'coverage' and payload['error'] is None) or
                        not all(valid_monitor_history_item(request[0], item) for item in payload['items'])):
                    return
                self._history_requests.pop(payload['query_id'], None)
                self._history_pages[payload['query_id']] = deepcopy(payload)
            elif kind == 'monitor_live_page_result':
                expected = self._monitor_requests.get(payload['query_id'])
                current = self._state.monitor_update
                if (not expected or any(payload[k] != expected[k] for k in ('job_id', 'run_id', 'revision', 'offset'))
                        or len(payload['rows']) > expected['limit']
                        or not current or current['run_id'] != payload['run_id'] or current['revision'] != payload['revision']):
                    return
                self._monitor_requests.pop(payload['query_id'], None)
                self._monitor_pages[payload['query_id']] = deepcopy(payload)
            elif kind == 'demob_preview':
                if self._state.active_lookup_type != 'demob' or self._state.phase == 'closing':
                    return
                if self._state.phase == 'stopping':
                    self._send('demob_decline', None, {})
                    self._clear_demob()
                    self._state.active_job_id = None
                    self._state.active_lookup_type = None
                    self._state.credential_request = None
                    self._started_at = None
                    self._state.phase = 'ready'
                    return
                self._state.demob_preview = deepcopy(payload)
                previous = self._state.latest_report_state or {}
                self._set_report_state(dict(state='idle', status='idle', filename=previous.get('filename', ''),
                                            message='The site lookup was not saved as a report.',
                                            available=previous.get('available', False), saved_for_attempt=False))
                self._demob_expires = monotonic() + 300 if payload['token'] else 0
                self._state.active_job_id = None
                self._state.active_lookup_type = None
                self._state.credential_request = None
                self._started_at = None
                self._state.phase = 'ready'
            elif kind == 'demob_page_result':
                expected = self._demob_requests.get(payload['query_id'])
                preview = self._state.demob_preview
                if (not expected or not preview or monotonic() >= self._demob_expires or
                        expected['token'] != preview['token'] or expected['offset'] != payload['offset'] or
                        len(payload['rows']) > expected['limit'] or
                        any((k in payload) != (k in expected) or k in expected and payload[k] != expected[k]
                            for k in ('sort_by', 'descending', 'filter_by', 'filter_text')) or
                        payload['status'] == 'ready' and payload.get('overall_total', payload['total']) != preview['row_count']):
                    return
                self._demob_requests.pop(payload['query_id'], None)
                self._demob_pages[payload['query_id']] = deepcopy(payload)
            elif kind == 'config_search_page_result':
                expected = self._config_requests.get(payload['query_id'])
                selected = self._state.results_by_type['config_search'] or {}
                demob = self._state.results_by_type['demob'] or {}
                if demob.get('job_id') == payload['job_id']:
                    selected = demob
                if (not expected or selected.get('job_id') != payload['job_id'] or
                        any(payload[k] != expected[k] for k in ('job_id', 'offset')) or
                        len(payload['rows']) > expected['limit'] or
                        any((k in payload) != (k in expected) or k in expected and payload[k] != expected[k]
                            for k in ('sort_by', 'descending', 'filter_by', 'filter_text')) or
                        (payload['status'] == 'ready' and payload.get('overall_total', payload['total']) != selected['result']['total'])):
                    return
                self._config_requests.pop(payload['query_id'], None)
                self._config_pages[payload['query_id']] = deepcopy(payload)
            elif kind == 'lookup_context':
                self._state.username, self._state.scope = payload['username'], payload['scope']
            elif kind == 'progress':
                self._state.progress_stage = payload['stage']
                self._state.progress_completed = payload.get('completed')
                self._state.progress_total = payload.get('total')
            elif kind in {'result', 'error'}:
                if kind == 'result':
                    lookup_type = self._state.active_lookup_type
                    result = payload['result']
                    useful = (result.get('status') == 'complete' if lookup_type in ('config_search', 'demob') else
                              bool(result.get('current_rounds')) if lookup_type == 'monitor' else
                              bool(result.get('rows')) if lookup_type in ('ip', 'ping') else
                              bool(result.get('detail_groups') or result.get('containers')))
                    if useful:
                        if lookup_type in ('config_search', 'demob'):
                            previous = self._state.results_by_type[lookup_type] or {}
                            previous_job = previous.get('job_id')
                            if previous_job:
                                for query, request in list(self._config_requests.items()):
                                    if request['job_id'] == previous_job:
                                        self._config_requests.pop(query, None)
                                for query, page in list(self._config_pages.items()):
                                    if page['job_id'] == previous_job:
                                        self._config_pages.pop(query, None)
                        self._state.results_by_type[lookup_type] = dict(job_id=job, result=deepcopy(result))
                        self._result_revisions[lookup_type] += 1
                        if lookup_type == 'subnet':
                            self._state.result = result
                            self._state.result_job_id = job
                    self._state.latest_attempt_id = job
                    self._state.latest_outcome = payload.get('outcome')
                    self._state.attempts_by_type[lookup_type]['outcome'] = deepcopy(payload.get('outcome'))
                    self._state.attempts_by_type[lookup_type]['result'] = deepcopy(result)
                    self._attempt_revisions[lookup_type] += 1
                else:
                    if not job:
                        self._state.error = payload['message']
                    if job:
                        self._state.latest_attempt_id = job
                        self._state.latest_outcome = dict(kind='lookup_error', message=payload['message'],
                            matched_count=0, invalid_count=0, resolution_error_count=0, miss_count=0,
                            warning_count=0, stopped=False, details={})
                        self._state.attempts_by_type[self._state.active_lookup_type]['outcome'] = deepcopy(self._state.latest_outcome)
                        self._attempt_revisions[self._state.active_lookup_type] += 1
                        previous = self._state.latest_report_state or {}
                        self._set_report_state(dict(state='failed', status='failed', filename=previous.get('filename', ''),
                            message=payload['message'], available=previous.get('available', False), saved_for_attempt=False))
                if self._started_at is not None:
                    self._state.elapsed_seconds = monotonic() - self._started_at
                    self._started_at = None
                self._state.active_job_id = None
                self._state.active_lookup_type = None
                self._state.credential_request = None
                if self._state.phase != 'closing':
                    self._state.phase = 'ready' if job else 'failed'
                    if not job:
                        self._clear_report_requests()
                        self._clear_report_availability()
            elif kind == 'report_state':
                self._set_report_state(payload['state'])
                if payload['state'].get('state') == 'saving' and self._state.phase not in {'closing', 'stopping'}:
                    self._state.phase = 'saving'
            elif kind == 'report_snapshot' and payload['request_id'] not in self._report_requests:
                # Released before it was ready: nobody will download it, so the file goes now. The worker has
                # finished preparing it, though, which is what report_snapshot_pending stands for.
                self._workbook_snapshots.discard(payload['request_id'])
                self._state.report_snapshot_pending = bool(self._workbook_snapshots)
                if 'path' in payload:
                    _remove_file(payload['path'])
            elif kind == 'report_snapshot':
                self._report_requests.remove(payload['request_id'])
                self._workbook_snapshots.discard(payload['request_id'])
                self._state.report_snapshot_pending = bool(self._workbook_snapshots)
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
                self._clear_report_requests()
                self._clear_demob()
                self._state.demob_discovery = None
                self._state.results_by_type['demob'] = None
                # IPC acknowledges resource cleanup, not process termination.
                # The reader publishes closed after its sole child join below.
                self._state.phase = 'closing'
                self._clear_report_availability()
                self._monitor_requests.clear()
                self._monitor_pages.clear()
                self._config_requests.clear()
                self._config_pages.clear()
                self._state.results_by_type['config_search'] = None
                self._delete_pending = None
                self._delete_results.clear()
                self._history_requests.clear()
                self._history_pages.clear()
                self._state.monitor_update = None
                self._report_paths.clear()
                self._report_completions.clear()
                self._report_streams.clear()
                self._state.active_job_id = None
                self._state.active_lookup_type = None

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
                self._clear_report_requests()
                self._clear_demob()
                self._state.demob_discovery = None
                self._state.results_by_type['demob'] = None
                self._config_requests.clear()
                self._config_pages.clear()
                self._state.results_by_type['config_search'] = None
                if self._state.phase != 'closed':
                    self._state.phase = 'failed'
                    self._clear_report_availability()
                    self._state.error = 'Worker connection closed unexpectedly. Relaunch to start a new session.'
                    self._state.active_job_id = None
                    self._state.active_lookup_type = None
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
