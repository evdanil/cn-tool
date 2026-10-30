"""Persistent cn runtime; its sole reader stays responsive during blocking work."""
from dataclasses import asdict
from pathlib import Path
import multiprocessing
from queue import Queue
import signal
from threading import Condition, Event, Lock, Thread
from uuid import uuid4

from cn_tool.core.interaction import AuthenticationRequired, CredentialReply
from cn_tool.core.operation import OperationControl
from cn_tool.core.runtime import RuntimeSession, SetupRequired, abort_initialization
from .protocol import COMMANDS, decode, encode, envelope


def _ignore_parent_interrupts():
    """Let the launcher coordinate child shutdown after a console Ctrl+C."""
    if multiprocessing.current_process().name == 'MainProcess':
        return
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (AttributeError, ValueError):
        pass


_ignore_parent_interrupts()


def finish_lookup_report(ctx, module, lookup):
    from .reports import finish_lookup_report as finish
    status = asdict(finish(ctx, module, lookup))
    return dict(status, status=status['state'])


def snapshot_report(ctx, destination):
    from .reports import snapshot_report as snapshot
    path = destination / (uuid4().hex + '.xlsx')
    snapshot(ctx, path)
    return path


class VaultCancellation:
    """Cancel the active helper without poisoning later queued vault actions."""
    def __init__(self):
        self.shutdown = Event()
        self.current = Event()
        self.action = None

    def is_set(self):
        return self.shutdown.is_set() or self.current.is_set()

    def begin(self, action):
        self.current = Event()
        self.action = action

    def cancel_active(self):
        if self.action in {'load', 'save'}:
            self.current.set()


class WorkerInteraction:
    def __init__(self, emit, stopping):
        self.emit, self.stopping = emit, stopping
        self.condition = Condition()
        self.request_id = None
        self.reply = None
        self.answered = False
        self.closing = False
        self.vault_stop = VaultCancellation()
        self.endpoint = None
        self.store = None
        self.store_queue = None
        self.store_thread = None
        self.identity = None
        self.generation = 0
        self.last_forget = None
        self.pending_save = None
        self.restored = False
        self.store_support = {}
        self.restore_attempts = set()

    def bind(self, endpoint, store):
        self.endpoint, self.store = endpoint, store
        self.store_queue = Queue()
        self.store_thread = Thread(target=self._store_loop, daemon=True)
        self.store_thread.start()

    def _status(self, account, username, status, message='', pending=False):
        self.emit('credential_store_state', dict(account=account, username=username,
                  status=status, message=message, pending=pending))

    def _store_loop(self):
        """Serialize helpers separately from prompts and the sole pipe reader."""
        while True:
            item = self.store_queue.get()
            if item is None:
                return
            action, scope, username, password, generation, done, result = item
            with self.condition:
                # A requested deletion survives a later prompt cancellation or
                # initialization failure; it must follow any dispatched save.
                stale = action != 'forget' and (generation != self.generation or self.closing)
                if not stale:
                    self.vault_stop.begin(action)
            if not stale:
                try:
                    if action == 'save':
                        value = self.store.save(scope, username, password)
                    else:
                        value = getattr(self.store, action)(scope, username)
                except Exception:
                    from .credential_store import VaultResult
                    message = 'Native credential storage operation failed.'
                    if action != 'load':
                        message += ' The operation outcome is unknown.'
                    value = VaultResult('error', message=message)
                with self.condition:
                    self.vault_stop.action = None
                    stale = self.closing or (generation != self.generation and
                                             (action != 'forget' or generation != self.last_forget))
                    if not stale:
                        result.append(value)
                        if action != 'load':
                            message = value.message
                            if value.status == 'deleted':
                                message = 'Saved credentials forgotten. The current session remains signed in.'
                            elif value.status == 'saved':
                                message = 'Credentials saved on this computer.'
                            self._status(scope.account, username, value.status, message)
            if done is not None:
                done.set()
            # Do not retain the last helper request or response while idle.
            item = password = result = value = None

    def _queue(self, action, scope, username='', password='', generation=None, done=None, result=None):
        self.store_queue.put((action, scope, username, password,
                              self.generation if generation is None else generation, done,
                              result if result is not None else []))

    def select(self, account, username):
        if self.store is not None:
            from .credential_store import CredentialScope
            with self.condition:
                self.identity = (CredentialScope(self.endpoint, account), username)

    def forget(self):
        with self.condition:
            self.generation += 1
            self.pending_save = None
            if self.closing:
                return
            if not self.identity or not self.identity[1]:
                self._status('', '', 'missing', 'No saved-login identity is selected yet.')
                return
            scope, username = self.identity
            self.last_forget = self.generation
            self._status(scope.account, username, 'pending', 'Forgetting saved credentials…', True)
            self._queue('forget', scope, username)

    def commit(self):
        with self.condition:
            if self.pending_save and not self.closing and not self.stopping.is_set():
                scope, username, password, generation = self.pending_save
                self._status(scope.account, username, 'pending', 'Saving credentials…', True)
                self._queue('save', scope, username, password, generation)
            self.pending_save = None

    def discard(self):
        with self.condition:
            self.generation += 1
            self.pending_save = None

    def close_store(self):
        if self.store_queue is not None:
            self.store_queue.put(None)
            self.store_thread.join()

    def prompt(self, request):
        from dataclasses import replace
        from .credential_store import CredentialScope
        scope = CredentialScope(self.endpoint, request.account) if self.store is not None else None
        supported = self.store_support.get(request.account, False)
        generation = self.generation
        if scope is not None and request.account not in self.restore_attempts:
            self.restore_attempts.add(request.account)
            self.select(request.account, request.username)
            done, result = Event(), []
            self._queue('load', scope, request.username, generation=generation, done=done, result=result)
            while not done.wait(.1):
                if self.closing or self.stopping.is_set():
                    return None
            with self.condition:
                if result and generation == self.generation and not self.closing and not self.stopping.is_set():
                    loaded = result[0]
                    supported = loaded.status in {'loaded', 'missing'}
                    self.store_support[request.account] = supported
                    selected = request.username or loaded.username
                    self.select(request.account, selected)
                    self._status(request.account, selected, loaded.status, loaded.message)
                    if loaded.status in {'loaded', 'missing'} and request.need_username and not request.need_password and selected:
                        return CredentialReply(selected, '')
                    if loaded.status == 'loaded' and (not request.username or request.username == loaded.username):
                        if request.need_password:
                            self.restored = True
                            self.emit('saved_login_restored', {})
                            return CredentialReply(selected, loaded.password)
                    if request.need_username and selected:
                        request = replace(request, username=selected)
        with self.condition:
            if self.closing or self.stopping.is_set():
                return None
            self.request_id = uuid4().hex
            self.answered = False
            self.request = request
            self.request_generation = generation
            self.request_supported = supported
            self.emit('credentials_required', dict(asdict(request), request_id=self.request_id,
                      store_supported=supported and request.need_password))
            while not self.answered and not self.closing and not self.stopping.is_set():
                self.condition.wait(.1)
            reply = self.reply if self.answered else None
            self.request_id = None
            self.reply = None
            return reply

    def answer(self, request_id, reply, remember=False):
        with self.condition:
            if self.closing or request_id != self.request_id or self.answered:
                return
            self.reply = None if reply is None else CredentialReply(**reply)
            if self.reply is not None and self.store is not None:
                username = self.reply.username.strip() if self.request.need_username else self.request.username
                from .credential_store import CredentialScope
                scope = CredentialScope(self.endpoint, self.request.account)
                self.identity = (scope, username)
                if (remember and self.request_supported and self.request.need_password and self.reply.password
                        and self.request_generation == self.generation):
                    self.pending_save = (scope, username, self.reply.password, self.generation)
            self.answered = True
            self.condition.notify_all()

    def cancel(self):
        with self.condition:
            self.vault_stop.cancel_active()
            self.reply = None
            self.answered = True
            self.condition.notify_all()

    def close(self):
        """Permanently reject new prompts while allowing ordinary work to drain."""
        with self.condition:
            self.closing = True
            self.vault_stop.shutdown.set()
            self.reply = None
            self.answered = True
            self.condition.notify_all()

    def fail(self, code, message):
        raise AuthenticationRequired(code, message)


def prepare_result(module, ctx, lookup, malformed, misses, scope):
    from cn_tool.modules.subnet_request import _cache_key, _view_of
    from dataclasses import replace
    groups = []
    summary = module.lookup_sections(ctx, lookup, misses=misses, fallback_view=scope.requested)['subnets']
    for network, originals in lookup.grouped.items():
        identity = uuid4().hex
        single = replace(lookup, grouped={network: originals}, containers=[])
        sections = module.lookup_sections(ctx, single)
        tables = {name: rows for name, rows in sections.items() if name not in {'subnets', 'child containers', 'warnings'}}
        groups.append(dict(id=identity, network=str(network), network_view=_view_of(network),
                           original_inputs=originals, tables=tables,
                           warnings=lookup.warnings.get(_cache_key(network), [])))
    for row, group in zip(summary, groups):
        row['id'] = group['id']
    for index, row in enumerate(summary):
        row['__row'] = row.get('id', f'miss-{index}')
    return dict(summary=summary, detail_groups=groups, containers=lookup.containers,
                input_errors=dict(malformed, **lookup.resolution_errors), misses=misses, stopped=lookup.stopped)


def perform_lookup(runtime, module, scope, inputs, control):
    inputs = list(dict.fromkeys(item.strip() for item in inputs if item.strip()))
    problems = {item: module._network_problem(item) for item in inputs}
    malformed = {item: problem for item, problem in problems.items() if problem}
    candidates = [item for item in inputs if item not in malformed]
    misses = []
    def resolved(targets, errors, containers):
        found = {target.original_input for target in targets} | {row['container'] for row in containers}
        misses.extend(item for item in candidates if item not in found and item not in errors)
    module.execute_hook('pre_run', runtime.ctx, None)
    try:
        lookup = module.collect_lookup(runtime.ctx, candidates, scope, control=control, _on_resolved=resolved)
        # Cancel may arrive between the last scheduling boundary and presentation.
        lookup.stopped = lookup.stopped or control.stop.is_set()
        result = prepare_result(module, runtime.ctx, lookup, malformed, misses, scope)
        lookup.stopped = lookup.stopped or control.stop.is_set()
        result['stopped'] = lookup.stopped
        report = {'status': 'idle', 'state': 'idle', 'filename': '', 'message': 'Stopped lookup was not saved.'}
        if not lookup.stopped:
            if runtime.ctx.cfg.get('report_auto_save'):
                control.progress('saving report')
            if control.stop.is_set():
                lookup.stopped = result['stopped'] = True
                return result, report
            report = finish_lookup_report(runtime.ctx, module, lookup)
            module._publish_stats(runtime.ctx, len(inputs), lookup.query_targets, list(lookup.grouped), lookup.subnet_data)
        return result, report
    finally:
        module.execute_hook('post_run', runtime.ctx, None)


def run_lookup(runtime, module, scope, inputs, control):
    """Use the terminal's shared statistics boundary exactly once per operation."""
    from cn_tool.main import _run_tracked
    def outcome(pair):
        result, report = pair
        if result['stopped']:
            return 'interrupted'
        return 'failed' if report.get('status') == 'failed' else 'completed'
    return _run_tracked(runtime.ctx, module,
                        lambda: perform_lookup(runtime, module, scope, inputs, control),
                        outcome=outcome)


def worker_main(connection, stop, interrupt=None, *, store_factory=None):
    """Importable Windows-spawn target. Only this thread reads from the pipe."""
    from cn_tool.modules.subnet_request import request_result
    from cn_tool.utils.auth import ensure_infoblox_auth, infoblox_account_configured
    from .credential_store import NativeCredentialStore
    from cn_tool.utils.network_views import view_scope
    import tempfile

    write_lock = Lock()
    operation_lock = Lock()
    operation_stop = Event()
    state = {'session': None, 'job': None, 'runtime': None, 'scope': None,
             'closing': False, 'initializing': False, 'initialization_failed': False, 'interrupted': False,
             'orphaned': False, 'thread': None, 'ready': False, 'saving': False}
    def emit(kind, payload, job_id=None):
        try:
            with write_lock:
                connection.send_bytes(encode(envelope(state['session'], job_id, kind, payload)))
        except (OSError, EOFError):
            state['orphaned'] = True
            operation_stop.set()
    interaction = WorkerInteraction(lambda kind, payload: emit(kind, payload, state['job']), operation_stop)
    if interrupt is not None:
        def watch_for_interrupt():
            interrupt.wait()
            state['interrupted'] = True
            state['orphaned'] = True
            operation_stop.set()
            interaction.close()
        Thread(target=watch_for_interrupt, daemon=True).start()

    def initialize(payload):
        try:
            if state['runtime'] is None:
                state['runtime'] = RuntimeSession.open(
                    config_file=Path(payload['config_file']) if payload['config_file'] else None,
                    interaction=interaction)
            runtime = state['runtime']
            if interaction.store is None:
                interaction.bind(str(runtime.ctx.cfg.get('api_endpoint') or ''),
                                 (store_factory or NativeCredentialStore)(interaction.vault_stop))
            username, _ = ensure_infoblox_auth(runtime.ctx)
            if interaction.identity is None:
                interaction.select('infoblox' if infoblox_account_configured(runtime.ctx) else 'device', username)
            scope = view_scope(runtime.ctx, None, request_result)
            problem = scope.problem()
            if problem:
                raise SetupRequired(problem.message)
            state['scope'], state['ready'] = scope, True
            state['initializing'] = False
            cfg = getattr(runtime.ctx, 'cfg', {})
            report_file = cfg.get('report_file')
            interaction.commit()
            emit('ready', {'scope': scope.banner() or '', 'username': username,
                           'report_warning': cfg.get('report_directory_warning', ''),
                           'report_location': str(Path(report_file).resolve().parent) if report_file else ''})
        except (SetupRequired, AuthenticationRequired) as exc:
            interaction.discard()
            state['initializing'] = False
            message = exc.message
            if interaction.restored:
                message += ' To use a different login, forget saved credentials, then quit and relaunch.'
            emit('setup_required', {'message': message, 'code': exc.code})
        except Exception:
            interaction.discard()
            state['initializing'] = False
            state['initialization_failed'] = True
            emit('error', {'message': 'Runtime initialization failed. Check the configured connection.'})

    def lookup(payload, job):
        try:
            runtime = state['runtime']
            module = next(m for m in runtime.modules.values() if m.cli_name == 'subnet')
            def progress(stage):
                if stage == 'saving report':
                    with operation_lock:
                        state['saving'] = True
                    emit('report_state', {'state': {'state': 'saving', 'status': 'saving', 'filename': '', 'message': 'Saving report.'}}, job)
                emit('progress', {'stage': stage}, job)
            control = OperationControl(operation_stop, progress)
            result, report = run_lookup(runtime, module, state['scope'], payload['inputs'], control)
            emit('report_state', {'state': report}, job)
            state['job'] = None
            emit('result', {'result': result}, job)
        except Exception:
            state['job'] = None
            emit('error', {'message': 'Subnet lookup failed. Check the configured connection.'}, job)
        finally:
            state['job'] = None
            state['saving'] = False

    def report_snapshot(payload):
        try:
            path = snapshot_report(state['runtime'].ctx, Path(report_directory.name))
            emit('report_snapshot', {'request_id': payload['request_id'], 'path': str(path), 'filename': Path(state['runtime'].ctx.cfg.get('report_file', path)).name})
        except Exception:
            emit('report_snapshot', {'request_id': payload['request_id'], 'error': 'Could not prepare report download.'})

    pending_snapshots = []
    report_directory = tempfile.TemporaryDirectory(prefix='cn-web-report-')
    try:
        while not state['closing']:
            if stop.is_set() or state['orphaned']:
                state['orphaned'] = True
                break
            if not connection.poll(.05):
                if pending_snapshots and (state['thread'] is None or not state['thread'].is_alive()):
                    payload = pending_snapshots.pop(0)
                    state['thread'] = Thread(target=report_snapshot, args=(payload,))
                    state['thread'].start()
                continue
            try:
                message = decode(connection.recv_bytes())
            except ValueError:
                continue
            if message['kind'] not in COMMANDS:
                continue
            if state['session'] is None:
                if message['kind'] != 'initialize':
                    continue
                state['session'] = message['session_id']
            if message['session_id'] != state['session']:
                continue
            kind, payload, job = message['kind'], message['payload'], message['job_id']
            busy = state['thread'] is not None and state['thread'].is_alive()
            if kind == 'shutdown':
                state['closing'] = True
                state['interrupted'] = state['interrupted'] or bool(payload.get('interrupted'))
                # Quit finishes an existing lookup, but releases blocked credentials.
                if state['interrupted'] or not state['ready']:
                    operation_stop.set()
                interaction.close()
            elif kind == 'cancel' and job == state['job']:
                with operation_lock:
                    if not state['saving']:
                        operation_stop.set()
                        interaction.discard()
                        interaction.cancel()
            elif kind == 'forget_credentials':
                interaction.forget()
            elif kind == 'credentials_reply':
                interaction.answer(payload['request_id'], payload['reply'], payload.get('remember', False))
            elif kind == 'snapshot_report' and state['runtime'] is not None:
                pending_snapshots.append(payload)
            elif kind == 'initialize' and not state['initializing'] and not state['ready']:
                if busy:
                    state['thread'].join()
                operation_stop.clear()
                state['initializing'] = True
                state['thread'] = Thread(target=initialize, args=(payload,))
                state['thread'].start()
            elif kind == 'lookup' and state['ready'] and state['job'] is None:
                if busy:
                    state['thread'].join()
                state['job'] = job
                operation_stop.clear()
                state['thread'] = Thread(target=lookup, args=(payload, job))
                state['thread'].start()
    except KeyboardInterrupt:
        state['interrupted'] = True
        state['orphaned'] = True
    except (EOFError, OSError):
        state['orphaned'] = True
    finally:
        if state['interrupted'] or (interrupt is not None and interrupt.is_set()):
            state['interrupted'] = True
            state['orphaned'] = True
        if state['orphaned']:
            operation_stop.set()
        interaction.close()
        if state['thread'] is not None:
            state['thread'].join()
        interaction.close_store()
        runtime = state['runtime']
        if runtime is not None:
            if state['interrupted'] or (interrupt is not None and interrupt.is_set()):
                abort_initialization(runtime.ctx, exit_code=130)
            elif state['orphaned'] or state['initialization_failed']:
                abort_initialization(runtime.ctx)
            else:
                runtime.close()
        if state['session'] is not None:
            emit('closed', {})
        connection.close()
        report_directory.cleanup()
