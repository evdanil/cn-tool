"""Persistent cn runtime; its sole reader stays responsive during blocking work."""
from dataclasses import asdict
from pathlib import Path
import multiprocessing
from queue import Empty, Full, Queue
import signal
from threading import Condition, Event, Lock, Thread
from uuid import uuid4

from cn_tool.core.interaction import AuthenticationFailed, AuthenticationRequired, CredentialReply
from cn_tool.core.operation import OperationCancelled, OperationControl
from cn_tool.core.runtime import RuntimeSession, SetupRequired, abort_initialization
from .protocol import COMMANDS, decode, encode, envelope, valid_monitor_history_item


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


def finish_ip_lookup_report(ctx, module, lookup):
    from .reports import finish_ip_lookup_report as finish
    status = asdict(finish(ctx, module, lookup))
    return dict(status, status=status['state'])


def finish_ping_report(ctx, module, rows):
    from .reports import finish_ping_report as finish
    status = asdict(finish(ctx, module, rows))
    return dict(status, status=status['state'])


def snapshot_report(ctx, destination, cancel=None):
    from .reports import snapshot_report as snapshot
    path = destination / (uuid4().hex + '.xlsx')
    snapshot(ctx, path, cancel)
    return path


def _refusal_key(runtime, account):
    """Keep session-local refusal fingerprints without retaining old passwords."""
    import hashlib
    import secrets
    if not hasattr(runtime, '_webui_refusal_key'):
        runtime._webui_refusal_key = secrets.token_bytes(32)
        runtime._webui_refusals = set()
        runtime._webui_refusal_lock = Lock()
    digest = hashlib.blake2b(key=runtime._webui_refusal_key, digest_size=32)
    for value in (account.username, account.password):
        encoded = value.encode('utf-8')
        digest.update(len(encoded).to_bytes(8, 'big'))
        digest.update(encoded)
    return digest.digest()


def _remember_refusal(runtime, account):
    fingerprint = _refusal_key(runtime, account)
    with runtime._webui_refusal_lock:
        runtime._webui_refusals.add(fingerprint)


def _was_refused(runtime, account):
    fingerprint = _refusal_key(runtime, account)
    with runtime._webui_refusal_lock:
        return fingerprint in runtime._webui_refusals


def ensure_lookup_scope(runtime, interaction, control, budget=None):
    """Resolve the view afresh for one lookup, checking the grid before trusting a login."""
    from cn_tool.modules.subnet_request import request_result
    from cn_tool.core.base import Credentials
    from cn_tool.utils import api, auth
    from cn_tool.utils.network_views import view_scope
    import os

    ctx = runtime.ctx
    cfg = ctx.cfg
    endpoint = str(cfg.get('api_endpoint') or '').strip()
    if not cfg.get('infoblox_enabled') or not endpoint or endpoint == 'API_URL':
        from cn_tool.utils.config import user_config_path
        paths = cfg.get('config_files') or []
        path = paths[-1] if paths else user_config_path()
        hint = 'Run cn init, then configure' if not paths else 'Configure'
        raise SetupRequired(f'Infoblox API endpoint is not configured or enabled. {hint} [api] endpoint in {path}.')
    control.checkpoint()
    previous = (ctx.username, ctx.password, ctx.infoblox_credentials, api.session.auth,
                getattr(ctx, '_webui_infoblox_account', None))
    refused_attempt = False
    try:
        account = ctx.infoblox_credentials
        own = auth.infoblox_account_configured(ctx)
        own_username = (auth._env_user(ctx) or auth._api_user(ctx)) if own else ''
        previous_own_username = getattr(runtime, '_webui_own_username', own_username)
        if account is not None and (not own or own_username != previous_own_username):
            ctx.infoblox_credentials = account = None
        needs_device_login = not own and not ctx.password
        prompt_count = getattr(interaction, 'prompt_count', 0)
        if not own:
            source = getattr(runtime, '_webui_device_source', None)
            if ctx.password and source == auth._name(ctx, 'auth_device_password_var'):
                if os.getenv(source) != ctx.password or (os.getenv(auth._name(ctx, 'auth_device_user_var')) or ctx.username) != ctx.username:
                    ctx.username = ctx.password = ''
            if not ctx.password:
                password_name = auth._name(ctx, 'auth_device_password_var')
                runtime._webui_device_source = password_name if os.getenv(password_name) else None
                needs_device_login = True
        if account is not None and account.source not in ('', 'prompt'):
            found = auth._infoblox_settings(ctx)
            if (found.conflict or found.password != account.password or found.password_from != account.source
                    or (found.username and found.username != account.username)):
                ctx.infoblox_credentials = None
        username, _ = auth.ensure_infoblox_auth(ctx)
        if (needs_device_login and runtime._webui_device_source is None
                and getattr(interaction, 'prompt_count', 0) != prompt_count):
            runtime._webui_device_source = 'prompt'
        control.checkpoint()
        refused = getattr(runtime, '_webui_refused', None)
        account = ctx.infoblox_credentials
        if not own:
            current = getattr(ctx, '_webui_infoblox_account', None)
            if current is None or (current.username, current.password) != (ctx.username, ctx.password):
                current = Credentials(ctx.username, ctx.password)
            ctx._webui_infoblox_account = current
            account = current
        if refused is not None and account is not None and (account.username, account.password) == (refused.username, refused.password):
            if own:
                ctx.infoblox_credentials = refused
            else:
                ctx._webui_infoblox_account = refused
        if account is not None and _was_refused(runtime, account):
            runtime._webui_refused = account
            refused_attempt = True
            raise SetupRequired('Infoblox previously refused this login. Enter different credentials.')
        responses = []
        def discover(*args, **kwargs):
            if budget is not None:
                result = request_result(*args, **kwargs, paged=True, budget=budget)
            else:
                result = request_result(*args, **kwargs)
            responses.append(result)
            return result
        scope = view_scope(ctx, None, discover)
        scope.grid()
        result = responses[-1]
        if result.status_code == 401 and account is not None:
            refused_attempt = True
            _remember_refusal(runtime, account)
            runtime._webui_refused = refused if refused is not None and (account.username, account.password) == (refused.username, refused.password) else account
            if own and account.source == 'prompt':
                ctx.infoblox_credentials = None
            elif not own and getattr(runtime, '_webui_device_source', None) == 'prompt':
                ctx.username = ctx.password = ''
        control.checkpoint()
        if budget is not None:
            if result.status == 'redirect_error':
                raise SetupRequired('Infoblox redirected the preview request; check the configured API endpoint.')
            if result.truncated:
                raise SetupRequired('Network view lookup is incomplete; narrow the lookup.')
            fallback_403 = result.status_code == 403 and not scope.requested
            if not fallback_403 and (not result.ok or scope.grid().error):
                raise SetupRequired('Network view lookup failed; check the Infoblox API endpoint and access.')
        if not result.ok and (result.status_code != 403 or scope.requested):
            if result.status == 'not_found':
                raise SetupRequired(f'Network view discovery failed (HTTP {result.status_code}). Check the Infoblox API endpoint.')
            raise SetupRequired(result.message)
        problem = scope.problem()
        if problem:
            raise SetupRequired(problem.message)
        interaction.select('infoblox' if auth.infoblox_account_configured(ctx) else 'device', username)
        scope._webui_verified = result.ok
        scope._webui_username = username
        scope._webui_fallback = bool(scope.grid().error)
        scope._webui_previous = previous
        scope._webui_previous_own_username = previous_own_username
        runtime._webui_own_username = own_username
        return scope
    except BaseException:
        ctx.username, ctx.password, ctx.infoblox_credentials, api.session.auth, ctx._webui_infoblox_account = previous
        refused = getattr(runtime, '_webui_refused', None)
        if refused_attempt and refused is not None:
            restored = ctx.infoblox_credentials
            if restored is refused and restored.source == 'prompt':
                ctx.infoblox_credentials = None
                api.session.auth = None
            elif (restored is None and getattr(runtime, '_webui_device_source', None) == 'prompt'
                  and (ctx.username, ctx.password) == (refused.username, refused.password)):
                ctx.username = ctx.password = ''
                ctx._webui_infoblox_account = None
                api.session.auth = None
        raise


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
        self.prompt_count = 0

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
                                message = 'Saved credentials forgotten.'
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
        self.prompt_count += 1
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
                input_errors=dict(malformed, **lookup.resolution_errors), invalid_inputs=dict(malformed),
                resolution_errors=dict(lookup.resolution_errors), misses=misses, stopped=lookup.stopped)


def classify_lookup_outcome(result: dict) -> dict:
    """Classify stopped, partial, matched, lookup error, invalid, then no match."""
    groups = result.get('detail_groups', [])
    containers = result.get('containers', [])
    invalid = result.get('invalid_inputs', {})
    errors = result.get('resolution_errors', {})
    misses = result.get('misses', [])
    warnings = [warning for group in groups for warning in group.get('warnings', [])]
    stopped = bool(result.get('stopped', False))
    if stopped:
        kind = 'stopped'
    elif groups or containers:
        kind = 'partial' if invalid or errors or misses or warnings else 'matched'
    elif errors:
        kind = 'lookup_error'
    elif invalid and not misses:
        kind = 'invalid'
    else:
        kind = 'no_match'
    messages = {'stopped': 'Lookup stopped.', 'partial': 'Lookup completed with diagnostics.',
                'matched': 'Lookup completed.', 'lookup_error': 'Lookup could not resolve inputs.',
                'invalid': 'Inputs are invalid.', 'no_match': 'No matching subnets.'}
    return dict(kind=kind, message=messages[kind], matched_count=len(groups),
                invalid_count=len(invalid), resolution_error_count=len(errors),
                miss_count=len(misses), warning_count=len(warnings), stopped=stopped,
                details=dict(invalid_inputs=invalid, resolution_errors=errors, misses=misses,
                             warnings=warnings, container_count=len(containers)))


def classify_ip_lookup_outcome(result: dict) -> dict:
    from ipaddress import ip_address
    def canonical(values):
        return {str(ip_address(value)) for value in values}
    rows = result['rows']
    invalid, errors, misses, warnings = (result[key] for key in
                                         ('invalid_inputs', 'lookup_errors', 'misses', 'warnings'))
    matched = canonical(result['matched_ips'])
    failed = canonical(errors) - matched
    missing = canonical(misses) - matched - failed
    warned = canonical(row['object'] for row in warnings)
    stopped = bool(result['stopped'])
    if stopped:
        kind = 'stopped'
    elif rows:
        kind = 'partial' if invalid or errors or misses or warnings else 'matched'
    elif errors:
        kind = 'lookup_error'
    elif invalid:
        kind = 'invalid'
    else:
        kind = 'no_match'
    messages = {'stopped': 'Lookup stopped.', 'partial': 'Lookup completed with diagnostics.',
                'matched': 'Lookup completed.', 'lookup_error': 'Lookup could not resolve inputs.',
                'invalid': 'Inputs are invalid.', 'no_match': 'No matching IP addresses.'}
    return dict(kind=kind, message=messages[kind], matched_count=len(matched), invalid_count=len(invalid),
                resolution_error_count=len(failed), miss_count=len(missing), warning_count=len(warned),
                stopped=stopped, details=dict(invalid_inputs=invalid, lookup_errors=errors, misses=misses,
                warnings=warnings, cancelled_ips=result['cancelled_ips'], unattempted_ips=result['unattempted_ips'],
                ptr_not_checked=result['ptr_not_checked'], input_aliases=result.get('input_aliases', {})))


def perform_ip_lookup(runtime, module, scope, inputs, control):
    from cn_tool.modules.ip_request import prepare_ip_inputs, _ptr_warnings, _publish_stats
    prepared = prepare_ip_inputs(runtime.ctx, inputs)
    module.execute_hook('pre_run', runtime.ctx, None)
    try:
        lookup = module.collect_lookup(runtime.ctx, prepared, scope, control=control)
        lookup.stopped = lookup.stopped or control.stop.is_set()
        result = dict(rows=lookup.rows, invalid_inputs=prepared.invalid,
                      lookup_errors={original: lookup.failed_ips[key] for original, key in prepared.keys.items()
                                     if key in lookup.failed_ips},
                      misses=lookup.misses, warnings=_ptr_warnings(lookup.ptr_failures),
                      matched_ips=[ip for ip in lookup.completed_ips if ip in lookup.processed_data_by_ip],
                      input_aliases={ip: [original for original, key in prepared.keys.items() if key == ip]
                                     for ip in prepared.ip_addresses},
                      cancelled_ips=lookup.cancelled_ips, unattempted_ips=lookup.unattempted_ips,
                      ptr_not_checked=lookup.ptr_not_checked, stopped=lookup.stopped)
        report = {'status': 'idle', 'state': 'idle', 'filename': '', 'message': 'Stopped lookup was not saved.'}
        if not lookup.stopped:
            if runtime.ctx.cfg.get('report_auto_save'):
                control.progress('saving report')
            if control.stop.is_set():
                lookup.stopped = result['stopped'] = True
                return result, report
            report = finish_ip_lookup_report(runtime.ctx, module, lookup)
            if prepared.ip_addresses:
                _publish_stats(runtime.ctx, len(prepared.keys), prepared.ip_addresses,
                               lookup.processed_data_by_ip, lookup.rows)
        return result, report
    finally:
        module.execute_hook('post_run', runtime.ctx, None)


def run_ip_lookup(runtime, module, scope, inputs, control):
    from cn_tool.main import _run_tracked
    def outcome(pair):
        result, report = pair
        if result['stopped']:
            return 'interrupted'
        return 'failed' if report.get('status') == 'failed' else 'completed'
    return _run_tracked(runtime.ctx, module,
                        lambda: perform_ip_lookup(runtime, module, scope, inputs, control), outcome=outcome)


def report_state_for_context(ctx, report):
    """Return path-free report metadata and current workbook availability."""
    report_file = ctx.cfg.get('report_file')
    state = report.get('state', report.get('status', 'idle'))
    return dict(state=state, status=report.get('status', state),
                filename=Path(report_file).name if report_file else '',
                message=report.get('message', ''),
                available=bool(report_file and Path(report_file).is_file()),
                saved_for_attempt=state == 'saved')


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


def classify_ping_outcome(result, report):
    rows, invalid, errors = result['rows'], result['input_errors'], result['resolution_errors']
    if report.get('operation_failed'):
        kind, message = 'lookup_error', report['operation_message']
    elif report.get('probe_failed'):
        kind, message = 'lookup_error', report['message']
    elif result['stopped']:
        kind, message = 'stopped', 'Ping stopped.'
    elif rows:
        kind, message = ('partial', 'Ping completed with diagnostics.') if invalid or errors else ('matched', 'Ping completed.')
    elif errors:
        kind, message = 'lookup_error', 'Ping could not resolve inputs.'
    else:
        kind, message = 'invalid', 'No valid targets to ping.'
    return dict(kind=kind, message=message, matched_count=len(rows), invalid_count=len(invalid),
                resolution_error_count=len(errors), miss_count=0, warning_count=0, stopped=result['stopped'],
                details=dict(unattempted=report.get('unattempted', []),
                             attempted_incomplete=report.get('attempted_incomplete', [])))


def perform_ping_lookup(runtime, module, inputs, tcp_ports, control):
    from cn_tool.modules import bulk_ping
    from cn_tool.utils.validation import parse_tcp_ports
    tcp_ports = parse_tcp_ports(','.join(str(port) for port in tcp_ports)) if tcp_ports else ()
    ctx = runtime.ctx
    rows, invalid, errors, hosts = [], [], [], []
    completed, attempted = set(), set()
    attempts_lock = Lock()
    def on_attempt(host):
        with attempts_lock:
            attempted.add(host)
    icmp = bulk_ping.shutil.which('ping') is not None
    report = dict(state='idle', status='idle', message='This ping was not saved.')
    result = dict(rows=rows, input_errors=invalid, resolution_errors=errors, stopped=False, icmp_available=icmp)
    module.execute_hook('pre_run', ctx, None)
    try:
        try:
            control.stage('validating')
            _, hosts = module._expand_targets((line.strip() for line in inputs if line.strip()),
                lambda target, reason: invalid.append(dict(object=target, reason=reason)),
                bulk_ping.MAX_TCP_HOSTS if tcp_ports else None)
            if not icmp and not tcp_ports:
                report.update(state='failed', status='failed', probe_failed=True, message=bulk_ping._PING_MISSING)
            else:
                control.stage('resolving')
                targets, unresolvable = module._address_targets(hosts, control=control)
                errors.extend(dict(object=name, reason=bulk_ping._NO_SUCH_HOST) for name in unresolvable)
                if not control.stop.is_set():
                    if targets:
                        control.stage('probing')
                    for finished, batch in module._sweep(targets, ctx.logger, tcp_ports, icmp, control=control, on_attempt=on_attempt):
                        completed.update(host for host, _ in finished)
                        rows.extend(batch)
                        control.counted_stage('probing', len(rows), len(targets))
                if any(bulk_ping._probe_failed(row, tcp_ports) for row in rows):
                    report.update(state='failed', status='failed', probe_failed=True,
                                  message='A Ping probe failed. Completed results remain available.')
                if not control.stop.is_set() and rows:
                    rows = module.execute_hook('process_data', ctx, rows)
                    result['rows'] = rows
        except OperationCancelled:
            pass
        except bulk_ping.PingUnavailableError:
            report.update(state='failed', status='failed', probe_failed=True, message=bulk_ping._PING_MISSING)
        except Exception:
            report.update(state='failed', status='failed', probe_failed=True,
                          message='Ping failed while probing targets. Completed results remain available.')
        if not report.get('probe_failed') and any(bulk_ping._probe_failed(row, tcp_ports) for row in rows):
            report.update(state='failed', status='failed', probe_failed=True,
                          message='A Ping probe failed. Completed results remain available.')
        result['stopped'] = control.stop.is_set()
        failed = {item['object'] for item in errors}
        report['attempted_incomplete'] = [host for host in hosts if host in attempted and host not in completed]
        report['unattempted'] = [host for host in hosts if host not in completed and host not in attempted and host not in failed]
        if not result['stopped'] and not report.get('probe_failed'):
            if rows and ctx.cfg.get('report_auto_save'):
                control.progress('saving report')
            if control.stop.is_set():
                result['stopped'] = True
            else:
                details = {key: report[key] for key in ('unattempted', 'attempted_incomplete')}
                report = finish_ping_report(ctx, module, rows)
                report.update(details)
        return result, report
    finally:
        try:
            module.execute_hook('post_run', ctx, None)
        except Exception:
            ctx.logger.exception('Ping post-run hook failed')
            report.update(operation_failed=True, operation_message='Ping post-run hook failed. Completed results remain available.')


def run_ping_lookup(runtime, module, inputs, tcp_ports, control):
    from cn_tool.main import _run_tracked
    def outcome(pair):
        result, report = pair
        return 'failed' if report.get('operation_failed') or report.get('status') == 'failed' else 'interrupted' if result['stopped'] else 'completed'
    return _run_tracked(runtime.ctx, module,
        lambda: perform_ping_lookup(runtime, module, inputs, tcp_ports, control), outcome=outcome)


def monitor_history_error(error):
    return 'Ping history is unavailable. Check its availability and permissions.' if error else ''


class MonitorLiveCache:
    """Latest complete round copied on the run thread and paged without SQLite."""
    def __init__(self, job_id, emit, logger=None):
        self.job_id, self.emit = job_id, emit
        self.logger, self.last_history_error = logger, None
        self.lock = Lock()
        self.run_id = None
        self.rows = ()
        self.update = dict(lookup_type='monitor', run_id='', revision=0, stage='starting', completed=0, total=0,
                           current_rounds=0, earlier_rounds=0, skipped_slots=0, history_error='')

    def on_started(self, run_id):
        with self.lock:
            self.run_id = run_id
            self.update['run_id'] = run_id
            update = dict(self.update)
        self.emit(update)

    def on_status(self, stage, completed, total):
        with self.lock:
            self.update.update(stage=stage, completed=completed, total=total)
            update = dict(self.update)
        self.emit(update)

    def on_round(self, run_id, revision, outcome):
        ports = tuple(outcome.request.ports)
        if outcome.store_error and outcome.store_error != self.last_history_error:
            if self.logger is not None:
                self.logger.error('Ping Monitor history: %s', outcome.store_error)
            self.last_history_error = outcome.store_error
        rows = tuple((str(row.get('Host', '')), str(row.get('Address', '')), str(row.get('Result') or 'unknown'),
                      tuple((port, str(row.get(f'TCP {port}') or 'unknown')) for port in ports))
                     for row in outcome.last_rows)
        with self.lock:
            if run_id != self.run_id or revision <= self.update['revision']:
                return
            self.rows = rows
            self.update.update(revision=revision, current_rounds=outcome.rounds, earlier_rounds=outcome.earlier,
                               skipped_slots=outcome.late, history_error=monitor_history_error(outcome.store_error))
            update = dict(self.update)
        self.emit(update)

    def page(self, query):
        with self.lock:
            revision = self.update['revision']
            result = {key: query[key] for key in ('job_id', 'run_id', 'revision', 'offset', 'query_id')}
            result.update(rows=[], next_offset=None, current_revision=revision)
            if query['job_id'] != self.job_id or query['run_id'] != self.run_id:
                result['status'] = 'unavailable'
            elif query['revision'] != revision:
                result['status'] = 'expired'
            elif revision == 0:
                result['status'] = 'not_ready'
            else:
                result['status'] = 'ready'
                start = query['offset']
                end = min(start + query['limit'], len(self.rows))
                result['rows'] = [dict(host=host, address=address, result=value,
                                       tcp=[dict(port=port, result=text) for port, text in tcp])
                                  for host, address, value, tcp in self.rows[start:end]]
                result['next_offset'] = end if end < len(self.rows) else None
            return result


class MonitorInputError(ValueError):
    """A safe, user-facing Monitor validation problem."""


def delete_monitor_history(ctx, action, run_id, request_id):
    """Delete history with a thread-owned connection; retain committed results on cleanup failure."""
    from cn_tool.modules.ping_monitor import PingMonitorModule
    from cn_tool.utils.ping_store import DeletionTimedOut, PingStore
    module = PingMonitorModule()
    committed = False
    try:
        store = PingStore.open(module._history_path(ctx), write=True, create=False)
        if store is None:
            return 'missing', ''
        with store:
            if action == 'run':
                status = store.delete_run(run_id, request_id, going_on=module._deletion_going_on)
                if status != 'deleted':
                    return status, ''
                committed = True
                store.sweep(vacuum=False)
            else:
                deletion = store.delete(None, going_on=module._deletion_going_on, guard_all=True)
                if deletion.going_on:
                    return 'running', ''
                committed = bool(deletion.requests)
                if not committed and not store.has_leftovers():
                    return 'missing', ''
                freed = store.sweep(vacuum=True)
                if not committed and not freed:
                    return 'missing', ''
            return 'deleted', ''
    except DeletionTimedOut:
        return 'failed', 'This run is too large to delete within the safe database lock time. Nothing was deleted.'
    except Exception:
        if committed:
            return 'deleted', 'History was deleted, but cleanup could not finish.'
        return 'failed', 'Could not delete monitor history.'


def run_monitor_lookup(runtime, module, payload, control, observer):
    """Run an admitted Monitor without terminal or Infoblox resources."""
    import time
    from cn_tool.main import _run_tracked
    from cn_tool.modules import bulk_ping
    from cn_tool.modules.ping_monitor import RunPlan
    from .reports import finish_monitor_report

    def run():
        ports = tuple(payload['tcp_ports'])
        icmp = bulk_ping.shutil.which('ping') is not None
        if not icmp and not ports:
            raise MonitorInputError('Ping is unavailable; configure TCP ports or install ping.')
        invalid = []
        request = module._request((line.strip() for line in payload['inputs'] if line.strip()), ports,
                                  lambda target, reason: invalid.append((target, reason)))
        if request is None or invalid:
            raise MonitorInputError('Check the Monitor targets and try again.')
        duration = payload['duration_seconds']
        plan = RunPlan(every=payload['interval_seconds'], until=time.time() + duration if duration is not None else None,
                       icmp=icmp)
        started = False
        class Observer:
            def on_started(self, run_id):
                nonlocal started
                started = True
                module.execute_hook('pre_run', runtime.ctx, None)
                observer.on_started(run_id)
            def on_status(self, stage, completed, total):
                observer.on_status(stage, completed, total)
            def on_round(self, run_id, revision, outcome):
                observer.on_round(run_id, revision, outcome)
        report = None
        try:
            outcome = module.track_controlled(runtime.ctx, request, plan, control, Observer())
            if runtime.ctx.cfg.get('report_auto_save'):
                control.progress('saving report')
            report = asdict(finish_monitor_report(runtime.ctx, module, outcome))
            report['status'] = report['state']
            return outcome, report
        finally:
            if started:
                try:
                    module.execute_hook('post_run', runtime.ctx, None)
                except Exception:
                    runtime.ctx.logger.exception('Ping Monitor post-run hook failed')
                    if report is not None:
                        report['hook_error'] = 'A Monitor post-run hook failed. Completed results remain available.'
    def status(pair):
        outcome, report = pair
        return ('failed' if outcome.probe_failed or outcome.store_error or report['status'] == 'failed' or report.get('hook_error')
                else 'interrupted' if outcome.stop_reason else 'completed')
    return _run_tracked(runtime.ctx, module, run, outcome=status)


def mark_monitor_history_ownership(page, kind, active_job, cache_job, run_id):
    if kind != 'runs':
        return page
    return dict(page, items=[dict(item, owned=bool(active_job and active_job == cache_job and run_id
                                                   and item.get('id') == run_id)) for item in page['items']])


def classify_monitor_history_runs(page, kind):
    """Derive the display state without changing stored run rows."""
    if kind != 'runs':
        return page
    import socket
    import time
    from cn_tool.utils import oscompat
    from cn_tool.utils.ping_history import run_state

    now, this_host = time.time(), socket.gethostname()
    return dict(page, items=[dict(item, status=run_state(
        item['status'], heartbeat=item['heartbeat'], interval=item['interval'], host=item['host'], pid=item['pid'],
        now=now, this_host=this_host, pid_alive=oscompat.pid_exists)) for item in page['items']])

def worker_main(connection, stop, interrupt=None, config_search_connection=None, *, store_factory=None):
    """Importable Windows-spawn target. Only this thread reads from the pipe."""
    from .credential_store import NativeCredentialStore
    import tempfile

    from .config_demob import DemobPreviewVault
    demob_vault = DemobPreviewVault()
    write_lock = Lock()
    operation_lock = Lock()
    operation_stop = Event()
    snapshot_stop = Event()
    state = {'session': None, 'job': None, 'runtime': None, 'scope': None,
             'closing': False, 'initializing': False, 'initialization_failed': False, 'interrupted': False,
             'orphaned': False, 'thread': None, 'ready': False, 'saving': False,
             'report': None, 'job_type': None, 'monitor_cache': None,
             # Each slot is one independently bounded (10,000 rows / 8 MiB) completed search.
             'config_cache': {'config_search': None, 'demob': None},
             'waiting_snapshot': False, 'demob_preview_job': None}
    def emit(kind, payload, job_id=None):
        try:
            with write_lock:
                connection.send_bytes(encode(envelope(state['session'], job_id, kind, payload)))
        except (OSError, EOFError):
            state['orphaned'] = True
            operation_stop.set()
            snapshot_stop.set()
    interaction = WorkerInteraction(lambda kind, payload: emit(kind, payload, state['job']), operation_stop)
    if interrupt is not None:
        def watch_for_interrupt():
            interrupt.wait()
            state['interrupted'] = True
            state['orphaned'] = True
            operation_stop.set()
            snapshot_stop.set()
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
            state['ready'] = True
            state['initializing'] = False
            cfg = getattr(runtime.ctx, 'cfg', {})
            state['report'] = report_state_for_context(runtime.ctx, {
                'state': 'idle' if cfg.get('report_auto_save') else 'off'})
            emit('ready', {'scope': '', 'username': '',
                           'report_warning': cfg.get('report_directory_warning', ''),
                           'report_state': state['report']})
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

    def lookup(payload, job, snapshot_thread=None):
        scope = None
        refused = Event()
        def rollback():
            if scope is not None:
                from cn_tool.utils import api
                ctx = state['runtime'].ctx
                ctx.username, ctx.password, ctx.infoblox_credentials, api.session.auth, ctx._webui_infoblox_account = scope._webui_previous
                if hasattr(scope, '_webui_previous_own_username'):
                    state['runtime']._webui_own_username = scope._webui_previous_own_username
                account = getattr(state['runtime'], '_webui_refused', None)
                if refused.is_set() and account is not None:
                    if ctx.infoblox_credentials is account and account.source == 'prompt':
                        ctx.infoblox_credentials = None
                        api.session.auth = None
                    elif (ctx.infoblox_credentials is None and
                          getattr(state['runtime'], '_webui_device_source', None) == 'prompt' and
                          (ctx.username, ctx.password) == (account.username, account.password)):
                        ctx.username = ctx.password = ''
                        ctx._webui_infoblox_account = None
                        api.session.auth = None
        def stopped():
            lookup_type = payload['lookup_type']
            if lookup_type in ('config_search', 'demob'):
                result = dict(status='stopped', total=0, errors=[], missing_nets=[])
                outcome = dict(kind='stopped', message='Search stopped before starting.', matched_count=0,
                               invalid_count=0, resolution_error_count=0, miss_count=0, warning_count=0,
                               stopped=True, details={})
            elif lookup_type == 'monitor':
                result = dict(run_id='', current_rounds=0, earlier_rounds=0, skipped_slots=0,
                              history_error='', probe_failed=False)
                outcome = dict(kind='stopped', message='Monitor stopped before starting.', matched_count=0,
                               invalid_count=0, resolution_error_count=0, miss_count=0, warning_count=0,
                               stopped=True, details={})
            elif lookup_type == 'ping':
                result = dict(rows=[], input_errors=[], resolution_errors=[], stopped=True, icmp_available=False)
                outcome = classify_ping_outcome(result, {})
            elif lookup_type == 'ip':
                result = dict(rows=[], invalid_inputs={}, lookup_errors={}, misses={}, warnings=[], matched_ips=[],
                              cancelled_ips=[], unattempted_ips=[], ptr_not_checked=[], stopped=True)
                outcome = classify_ip_lookup_outcome(result)
            else:
                result = dict(detail_groups=[], containers=[], stopped=True)
                outcome = classify_lookup_outcome(result)
            report = report_state_for_context(state['runtime'].ctx, {
                'state': 'idle', 'status': 'idle', 'message': 'Stopped lookup was not saved.'})
            state['report'] = report
            emit('report_state', {'state': report, 'lookup_type': lookup_type}, job)
            state['job'] = None
            emit('result', {'result': result, 'outcome': outcome, 'lookup_type': lookup_type}, job)
        try:
            while snapshot_thread is not None and snapshot_thread.is_alive():
                if operation_stop.wait(.05):
                    raise OperationCancelled()
            state['waiting_snapshot'] = False
            if operation_stop.is_set():
                raise OperationCancelled()
            runtime = state['runtime']
            lookup_type = payload['lookup_type']
            if lookup_type in ('config_search', 'demob'):
                from cn_tool.modules.config_search import ConfigSearchModule
                module = next(m for m in runtime.modules.values() if type(m) is ConfigSearchModule)
            else:
                module = next(m for m in runtime.modules.values() if m.cli_name == lookup_type)
            def progress(stage):
                if stage == 'saving report':
                    with operation_lock:
                        state['saving'] = True
                    report = dict(state['report'], state='saving', status='saving', message='Saving report.', saved_for_attempt=False)
                    emit('report_state', {'state': report, 'lookup_type': payload['lookup_type']}, job)
                emit('progress', {'stage': stage, 'lookup_type': payload['lookup_type']}, job)
            def counted(stage, completed, total):
                emit('progress', {'stage': stage, 'lookup_type': lookup_type,
                                  'completed': completed, 'total': total}, job)
            control = OperationControl(operation_stop, progress, counted if lookup_type == 'ping' else None)
            if lookup_type == 'config_search' or (lookup_type == 'demob' and 'demob_scope' in payload):
                from .config_search import SearchOutcome, perform_config_search, perform_demob_search
                from cn_tool.utils.process_data import remove_duplicate_rows_sorted_by_col
                demob_scope = payload.get('demob_scope')
                search = (perform_demob_search(runtime, module, demob_scope, control, config_search_connection)
                          if demob_scope else perform_config_search(runtime, module, payload['inputs'], control, config_search_connection))
                from .reports import finish_config_search_report
                def before_write():
                    with operation_lock:
                        if operation_stop.is_set():
                            return False
                        state['saving'] = True
                        current = dict(state['report'], state='saving', status='saving', message='Saving report.',
                                       saved_for_attempt=False)
                        emit('report_state', {'state': current, 'lookup_type': lookup_type}, job)
                        emit('progress', {'stage': 'saving report', 'lookup_type': lookup_type}, job)
                        return True
                report = asdict(finish_config_search_report(runtime.ctx, module, search, before_write=before_write,
                                                           site_search=bool(demob_scope), demob_scope=demob_scope)
                                if demob_scope else finish_config_search_report(runtime.ctx, module, search, before_write=before_write))
                with operation_lock:
                    if operation_stop.is_set() and not state['saving'] and search.status == 'complete':
                        search = SearchOutcome('stopped', 'Search stopped.', errors=search.errors)
                    rows = remove_duplicate_rows_sorted_by_col(search.rows, 2) if search.status == 'complete' else []
                    rows = [[str(row[0]), row[1], row[2], row[3], row[4]] for row in rows]
                    missing = [str(net)[:-3] if str(net).endswith('/32') else str(net)
                               for net in sorted(set(search.networks) - search.matched_nets)] if search.status == 'complete' else []
                    errors = [dict(line=error.line, reason=error.reason) for error in search.errors]
                    result = dict(status=search.status, total=len(rows), errors=errors, missing_nets=missing)
                    if search.status == 'complete':
                        state['config_cache'][lookup_type] = (job, rows)
                    kind = ('partial' if errors and rows else 'matched' if rows else 'no_match') if search.status == 'complete' else (
                        'invalid' if search.status == 'invalid' else 'stopped' if search.status == 'stopped' else 'lookup_error')
                    message = search.message or ('Search completed with invalid inputs.' if errors else
                                                  'Search completed.' if rows else 'No matches found.')
                    outcome = dict(kind=kind, message=message, matched_count=len(rows), invalid_count=len(errors),
                                   resolution_error_count=0, miss_count=len(missing), warning_count=0,
                                   stopped=search.status == 'stopped', details={})
                    if demob_scope:
                        outcome['details'] = dict(discovery_status=demob_scope.status,
                                                  discovery_message=demob_scope.message,
                                                  notices=list(demob_scope.notices))
                        outcome['warning_count'] = len(demob_scope.notices) + int(demob_scope.status == 'partial_error')
                        if search.status == 'complete' and outcome['warning_count']:
                            outcome['kind'] = 'partial'
                            outcome['message'] = 'Search completed with incomplete subnet discovery.'
                    report = report_state_for_context(runtime.ctx, report)
                    state['report'] = report
                    emit('report_state', {'state': report, 'lookup_type': lookup_type}, job)
                    state['job'] = None
                    emit('result', {'result': result, 'outcome': outcome, 'lookup_type': lookup_type}, job)
                    return
            if lookup_type == 'monitor':
                from cn_tool.modules.bulk_ping import PingCleanupError
                from cn_tool.utils.ping_store import AlreadyRunning, StoreError
                try:
                    outcome, report = run_monitor_lookup(runtime, module, payload, control, state['monitor_cache'])
                except PingCleanupError:
                    state['job'] = None
                    emit('error', {'lookup_type': 'monitor',
                                   'message': 'A Monitor probe could not be cleaned up. Check the application logs.'}, job)
                    return
                except AlreadyRunning:
                    state['job'] = None
                    emit('error', {'lookup_type': 'monitor', 'message': 'These targets are already being monitored. View their history to follow the run.'}, job)
                    return
                except StoreError:
                    state['job'] = None
                    emit('error', {'lookup_type': 'monitor', 'message': 'Could not open or update Ping history. Check its availability and permissions.'}, job)
                    return
                except MonitorInputError as exc:
                    state['job'] = None
                    emit('error', {'lookup_type': 'monitor', 'message': str(exc)}, job)
                    return
                if outcome.store_error and outcome.store_error != state['monitor_cache'].last_history_error:
                    runtime.ctx.logger.error('Ping Monitor history: %s', outcome.store_error)
                result = dict(run_id=state['monitor_cache'].run_id or '', current_rounds=outcome.rounds,
                              earlier_rounds=outcome.earlier, skipped_slots=outcome.late,
                              history_error=monitor_history_error(outcome.store_error), probe_failed=outcome.probe_failed)
                stopped = bool(outcome.stop_reason)
                summary = dict(kind='lookup_error' if outcome.probe_failed else 'stopped' if stopped else 'matched',
                               message=('A Monitor probe failed.' if outcome.probe_failed else
                                        'Monitor stopped.' if stopped else 'Monitor finished.'),
                               matched_count=outcome.rounds,
                               invalid_count=0, resolution_error_count=len(outcome.unresolved - outcome.resolved),
                               miss_count=0, warning_count=int(bool(report.get('hook_error'))), stopped=stopped,
                               details={'hook_error': report['hook_error']} if report.get('hook_error') else {})
                report = report_state_for_context(runtime.ctx, report)
                state['report'] = report
                emit('report_state', {'state': report, 'lookup_type': lookup_type}, job)
                state['job'] = None
                emit('result', {'result': result, 'outcome': summary, 'lookup_type': lookup_type}, job)
                return
            if lookup_type == 'ping':
                result, report = run_ping_lookup(runtime, module, payload['inputs'], payload['tcp_ports'], control)
                outcome = classify_ping_outcome(result, report)
                report = report_state_for_context(runtime.ctx, report)
                state['report'] = report
                emit('report_state', {'state': report, 'lookup_type': lookup_type}, job)
                state['job'] = None
                emit('result', {'result': result, 'outcome': outcome, 'lookup_type': lookup_type}, job)
                return
            budget = demob_vault.new_budget(control) if lookup_type == 'demob' else None
            if budget is None:
                scope = ensure_lookup_scope(runtime, interaction, control)
            else:
                scope = ensure_lookup_scope(runtime, interaction, control, budget)
            verified = Event()
            if scope._webui_verified:
                verified.set()
            def observe(result):
                if result.ok:
                    verified.set()
                if result.status_code == 401:
                    refused.set()
                    runtime._webui_refused = (runtime.ctx.infoblox_credentials or
                                               getattr(runtime.ctx, '_webui_infoblox_account', None))
                    if runtime._webui_refused is not None:
                        _remember_refusal(runtime, runtime._webui_refused)
            runtime.ctx._webui_request_observer = observe
            def publish_context():
                with operation_lock:
                    control.checkpoint()
                    emit('lookup_context', {'lookup_type': lookup_type, 'username': scope._webui_username,
                                            'scope': scope.banner() or ('All network views' if not getattr(scope, '_webui_fallback', False)
                                                       else ('Network views cannot be listed; results are limited to this account’s access'
                                                             if lookup_type == 'demob' else
                                                             'View list unavailable; some searches use the default view'))}, job)
            if verified.is_set():
                publish_context()
            if lookup_type == 'demob':
                preview = demob_vault.preview(runtime.ctx, payload['site'], control=control,
                                              scope=scope, budget=budget)
                control.checkpoint()
                authenticated = verified.is_set() and not refused.is_set() and preview.status in {'ok', 'partial_error'}
                if not authenticated:
                    interaction.discard()
                    rollback()
                    demob_vault.invalidate()
                    preview.token = None
                    if refused.is_set() or not verified.is_set():
                        preview.status = 'error'
                        preview.message = 'Subnet lookup could not be authenticated.'
                        preview.notices = []
                        preview.row_count = 0
                public = asdict(preview)
                public.pop('rows')
                # Bound metadata independently of the retained preview pages.
                try:
                    encode(envelope(state['session'], job, 'demob_preview', public))
                except (ValueError, UnicodeError):
                    demob_vault.invalidate()
                    interaction.discard()
                    rollback()
                    authenticated = False
                    public = dict(site='', status='limit', message='Subnet lookup exceeds the preview limit.',
                                  notices=[], row_count=0, token=None)
                if authenticated and not scope._webui_verified:
                    publish_context()
                with operation_lock:
                    if operation_stop.is_set():
                        demob_vault.invalidate()
                        raise OperationCancelled()
                    if authenticated and public['status'] in {'ok', 'partial_error'}:
                        interaction.commit()
                    else:
                        interaction.discard()
                    state['demob_preview_job'] = job if public['token'] else None
                    state['job'] = None
                    emit('demob_preview', public, job)
                return
            runner = run_ip_lookup if lookup_type == 'ip' else run_lookup
            classifier = classify_ip_lookup_outcome if lookup_type == 'ip' else classify_lookup_outcome
            result, report = runner(runtime, module, scope, payload['inputs'], control)
            outcome = classifier(result)
            if not scope._webui_verified and verified.is_set() and not refused.is_set() and not result.get('stopped'):
                publish_context()
            if (verified.is_set() and not refused.is_set() and outcome['kind'] in {'matched', 'partial', 'no_match'}
                    and report.get('status', report.get('state')) != 'failed'):
                with operation_lock:
                    if not operation_stop.is_set():
                        interaction.commit()
                    else:
                        interaction.discard()
                        rollback()
            else:
                interaction.discard()
                rollback()
            report = report_state_for_context(runtime.ctx, report)
            state['report'] = report
            emit('report_state', {'state': report, 'lookup_type': payload['lookup_type']}, job)
            state['job'] = None
            emit('result', {'result': result, 'outcome': outcome, 'lookup_type': lookup_type}, job)
        except OperationCancelled:
            interaction.discard()
            rollback()
            stopped()
        except (SetupRequired, AuthenticationRequired) as exc:
            interaction.discard()
            rollback()
            if operation_stop.is_set() or (isinstance(exc, AuthenticationRequired) and not isinstance(exc, AuthenticationFailed)):
                stopped()
            else:
                state['job'] = None
                emit('error', {'message': exc.message, 'lookup_type': payload['lookup_type']}, job)
        except Exception:
            interaction.discard()
            rollback()
            state['job'] = None
            label = {'ip': 'IP', 'subnet': 'Subnet', 'ping': 'Ping', 'monitor': 'Monitor', 'config_search': 'Configuration', 'demob': 'Demobilization'}[payload['lookup_type']]
            emit('error', {'message': f'{label} lookup failed. Check the configured connection.', 'lookup_type': payload['lookup_type']}, job)
        finally:
            if state['runtime'] is not None and hasattr(state['runtime'].ctx, '_webui_request_observer'):
                del state['runtime'].ctx._webui_request_observer
            state['job'] = None
            state['saving'] = False
            state['job_type'] = None
            state['waiting_snapshot'] = False

    def report_snapshot(payload):
        try:
            path = snapshot_report(state['runtime'].ctx, Path(report_directory.name), snapshot_stop)
            emit('report_snapshot', {'request_id': payload['request_id'], 'path': str(path), 'filename': Path(state['runtime'].ctx.cfg.get('report_file', path)).name})
        except Exception:
            emit('report_snapshot', {'request_id': payload['request_id'], 'error': 'Could not prepare report download.'})

    history_queue = Queue(maxsize=8)
    history_stopped = Event()
    history_thread = None
    delete_thread = None
    delete_ids = set()
    def read_history(history_ctx, session_id):
        from cn_tool.utils.ping_history import read_monitor_history
        while True:
            payload = history_queue.get()
            if payload is None or history_stopped.is_set():
                return
            try:
                query = {key: payload[key] for key in ('kind', 'parent', 'cursor', 'limit')}
                page = read_monitor_history(history_ctx, query)
                if history_stopped.is_set():
                    return
                cache = state['monitor_cache']
                page = mark_monitor_history_ownership(page, query['kind'], state['job'],
                                                      cache.job_id if cache else None, cache.run_id if cache else None)
                page = classify_monitor_history_runs(page, query['kind'])
                if (not isinstance(page.get('items'), list) or len(page['items']) > query['limit'] or
                        (query['kind'] == 'template' and (page.get('next_cursor') is not None or
                         len(page['items']) != (0 if page.get('error') else 1))) or
                        not all(valid_monitor_history_item(query['kind'], item) for item in page['items'])):
                    raise ValueError('Invalid history page')
            except Exception:
                page = dict(items=[], next_cursor=None, error='Could not read Ping history.')
            with write_lock:
                if history_stopped.is_set():
                    return
                try:
                    data = encode(envelope(session_id, None, 'monitor_history_result', dict(page, query_id=payload['query_id'])))
                except (ValueError, TypeError, OverflowError):
                    fallback = dict(items=[], next_cursor=None, error='Could not read Ping history.', query_id=payload['query_id'])
                    data = encode(envelope(session_id, None, 'monitor_history_result', fallback))
                try:
                    connection.send_bytes(data)
                except (OSError, EOFError):
                    state['orphaned'] = True
                    operation_stop.set()
                    return

    pending_snapshots = []
    snapshot_thread = None
    report_directory = tempfile.TemporaryDirectory(prefix='cn-web-report-')
    try:
        while not state['closing']:
            if stop.is_set() or state['orphaned']:
                state['orphaned'] = True
                break
            if not connection.poll(.05):
                if pending_snapshots and (snapshot_thread is None or not snapshot_thread.is_alive()):
                    if (state['job_type'] == 'monitor' or state['thread'] is None or
                            not state['thread'].is_alive()):
                        payload = pending_snapshots.pop(0)
                        snapshot_thread = Thread(target=report_snapshot, args=(payload,))
                        snapshot_thread.start()
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
                demob_vault.invalidate()
                state['closing'] = True
                snapshot_stop.set()
                state['interrupted'] = state['interrupted'] or bool(payload.get('interrupted'))
                # Quit finishes an existing lookup, but releases blocked credentials.
                if (state['interrupted'] or not state['ready'] or state['job_type'] in ('monitor', 'config_search', 'demob')
                        or state['waiting_snapshot']):
                    operation_stop.set()
                interaction.close()
            elif kind == 'cancel':
                with operation_lock:
                    if job == state['job']:
                        demob_vault.invalidate()
                        if not state['saving']:
                            operation_stop.set()
                            interaction.discard()
                            interaction.cancel()
                    elif job == state['demob_preview_job']:
                        demob_vault.invalidate()
                        state['demob_preview_job'] = None
            elif kind == 'demob_decline':
                demob_vault.invalidate()
                state['demob_preview_job'] = None
            elif kind == 'demob_page':
                page = demob_vault.page(payload['token'], offset=payload['offset'], limit=payload['limit'])
                result = dict(query_id=payload['query_id'], offset=payload['offset'], rows=[], total=0,
                              next_offset=None, status='unavailable')
                if page is not None:
                    result.update(rows=page.rows, total=page.total, next_offset=page.next_offset, status='ready')
                emit('demob_page_result', result)
            elif kind == 'monitor_delete' and state['ready']:
                if payload['query_id'] in delete_ids:
                    continue
                if len(delete_ids) >= 1024:
                    emit('monitor_delete_result', dict(query_id=payload['query_id'], status='failed',
                                                       warning='History deletion limit reached. Restart the application.'))
                    continue
                delete_ids.add(payload['query_id'])
                if delete_thread is not None and delete_thread.is_alive():
                    emit('monitor_delete_result', dict(query_id=payload['query_id'], status='failed',
                                                       warning='History deletion is busy. Try again.'))
                else:
                    def delete_history(request=payload):
                        try:
                            status, warning = delete_monitor_history(state['runtime'].ctx, request['action'],
                                                                      request['run_id'], request['request_id'])
                        except Exception:
                            status, warning = 'failed', 'Could not delete monitor history.'
                        emit('monitor_delete_result', dict(query_id=request['query_id'], status=status, warning=warning))
                    delete_thread = Thread(target=delete_history)
                    delete_thread.start()
            elif kind == 'monitor_history' and state['ready']:
                if history_thread is None:
                    from types import SimpleNamespace
                    history_ctx = SimpleNamespace(cfg={'ping_history_file': state['runtime'].ctx.cfg.get('ping_history_file')})
                    history_thread = Thread(target=read_history, args=(history_ctx, state['session']), daemon=True)
                    history_thread.start()
                try:
                    history_queue.put_nowait(payload)
                except Full:
                    emit('monitor_history_result', dict(query_id=payload['query_id'], items=[], next_cursor=None,
                                                        error='History reader is busy. Try again.'))
            elif kind == 'config_search_page':
                import json
                cache = next((item for item in state['config_cache'].values()
                              if item is not None and item[0] == payload['job_id']), None)
                page = dict(job_id=payload['job_id'], offset=payload['offset'], query_id=payload['query_id'],
                            rows=[], total=0, next_offset=None, status='unavailable')
                if cache is not None and cache[0] == payload['job_id']:
                    rows = cache[1]
                    page.update(total=len(rows), status='ready')
                    index = payload['offset']
                    while index < len(rows) and len(page['rows']) < payload['limit']:
                        page['rows'].append(rows[index])
                        if len(json.dumps(page, ensure_ascii=False).encode('utf-8')) > 1024 * 1024 - 1024:
                            page['rows'].pop()
                            break
                        index += 1
                    page['next_offset'] = index if index < len(rows) else None
                emit('config_search_page_result', page)
            elif kind == 'monitor_live_page':
                cache = state['monitor_cache']
                if cache is None:
                    page = {key: payload[key] for key in ('job_id', 'run_id', 'revision', 'offset', 'query_id')}
                    page.update(rows=[], next_offset=None, status='unavailable', current_revision=0)
                else:
                    page = cache.page(payload)
                emit('monitor_live_page_result', page)
            elif kind == 'forget_credentials':
                interaction.forget()
            elif kind == 'credentials_reply' and job is not None and job == state['job']:
                interaction.answer(payload['request_id'], payload['reply'], payload.get('remember', False))
            elif kind == 'snapshot_report' and state['runtime'] is not None:
                if len(pending_snapshots) < 8:
                    pending_snapshots.append(payload)
                else:
                    emit('report_snapshot', {'request_id': payload['request_id'],
                                             'error': 'Report downloads are busy. Try again.'})
            elif kind == 'initialize' and not state['initializing'] and not state['ready']:
                if busy:
                    state['thread'].join()
                operation_stop.clear()
                state['initializing'] = True
                state['thread'] = Thread(target=initialize, args=(payload,))
                state['thread'].start()
            elif kind in {'lookup', 'demob_lookup', 'demob_confirm'} and state['ready'] and state['job'] is None:
                if kind == 'demob_confirm':
                    demob_scope = demob_vault.consume(payload['token'])
                    if demob_scope is None:
                        emit('error', {'lookup_type': 'demob', 'message': 'Preview is unavailable or expired.'}, job)
                        continue
                    state['demob_preview_job'] = None
                    payload = dict(lookup_type='demob', demob_scope=demob_scope)
                elif kind == 'demob_lookup':
                    state['demob_preview_job'] = None
                    demob_vault.invalidate()
                    payload = dict(lookup_type='demob', site=payload['site'])
                else:
                    state['demob_preview_job'] = None
                    demob_vault.invalidate()
                if busy:
                    state['thread'].join()
                state['job'] = job
                state['job_type'] = payload['lookup_type']
                if state['job_type'] == 'monitor':
                    state['monitor_cache'] = MonitorLiveCache(job, lambda update, job_id=job: emit('monitor_update', update, job_id),
                                                               state['runtime'].ctx.logger)
                operation_stop.clear()
                state['waiting_snapshot'] = snapshot_thread is not None and snapshot_thread.is_alive()
                state['thread'] = Thread(target=lookup, args=(payload, job, snapshot_thread))
                state['thread'].start()
    except KeyboardInterrupt:
        state['interrupted'] = True
        state['orphaned'] = True
    except (EOFError, OSError):
        state['orphaned'] = True
    finally:
        demob_vault.invalidate()
        snapshot_stop.set()
        for payload in pending_snapshots:
            emit('report_snapshot', {'request_id': payload['request_id'],
                                     'error': 'Report download cancelled because the session is closing.'})
        if state['interrupted'] or (interrupt is not None and interrupt.is_set()):
            state['interrupted'] = True
            state['orphaned'] = True
        if state['orphaned']:
            operation_stop.set()
        with write_lock:
            history_stopped.set()
        interaction.close()
        if state['thread'] is not None:
            state['thread'].join()
        state['config_cache'].clear()
        if config_search_connection is not None:
            try:
                config_search_connection.close()
            except OSError:
                pass
        if snapshot_thread is not None:
            snapshot_thread.join()
        if delete_thread is not None:
            delete_thread.join()
        if history_thread is not None:
            while True:
                try:
                    history_queue.get_nowait()
                except Empty:
                    break
            history_queue.put_nowait(None)
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
