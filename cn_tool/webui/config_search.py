"""Private, bounded configuration search service.

Only server configuration supplies repository paths. Results stay in the worker;
callers must expose them through an authenticated, job-scoped page interface.
"""
from dataclasses import dataclass, field
import ipaddress
import json
import pickle
import time

from cn_tool.modules.config_search import (
    BoundedSearchResult, CONFIG_SEARCH_CACHE_UNAVAILABLE_MESSAGE,
    ParsedConfigSearch, config_search_mode, parse_search_inputs,
)
from cn_tool.plugins.sdwan_yaml_search import SDWANYamlSearchPlugin
from .config_search_worker import MAX_MESSAGE, SearchRequest, snapshot_yaml_plugin


@dataclass
class SearchOutcome:
    status: str
    message: str = ''
    rows: list = field(default_factory=list)
    matched_nets: set = field(default_factory=set)
    networks: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    source_identities: dict = field(default_factory=dict)
    demob_status: str = ''
    demob_message: str = ''
    demob_notices: list = field(default_factory=list)


def _hook_plugin(module):
    """Return the sole supported hook or reject anything that cannot be replayed."""
    if module.hooks.get('pre_run'):
        raise ValueError('unsupported hook')
    hooks = module.hooks.get('process_data', [])
    if not hooks:
        return None
    if len(hooks) != 1:
        raise ValueError('unsupported hook')
    hook = hooks[0]
    plugin = getattr(hook, '__self__', None)
    if type(plugin) is not SDWANYamlSearchPlugin or getattr(hook, '__func__', None) is not SDWANYamlSearchPlugin._search_yaml_repo:
        raise ValueError('unsupported hook')
    return plugin


def _valid_inputs(inputs):
    if type(inputs) is not list or len(inputs) > 200:
        return False
    if any(type(value) is not str or len(value) > 1024 or
           any(c in value for c in '\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029') for value in inputs):
        return False
    try:
        return sum(len(value.encode('utf-8')) for value in inputs) + max(0, len(inputs) - 1) <= 65536
    except UnicodeError:
        return False


def _valid_result(result, networks):
    if type(result) is not BoundedSearchResult or result.status not in ('complete', 'limit', 'incomplete'):
        return False
    if type(result.rows) is not list or len(result.rows) > 10000 or type(result.matched_nets) is not set:
        return False
    if type(result.source_identities) is not dict or len(result.source_identities) > 10000:
        return False
    if result.status != 'complete' and (result.rows or result.matched_nets or result.source_identities):
        return False
    if not result.matched_nets <= set(networks):
        return False
    size = 2
    for row in result.rows:
        if type(row) is not list or len(row) != 5 or type(row[2]) is not int or row[2] < 0:
            return False
        if not (type(row[0]) is str or type(row[0]) is ipaddress.IPv4Network):
            return False
        if any(type(row[i]) is not str for i in (1, 3, 4)):
            return False
        try:
            if len(row[3].encode('utf-8')) > 16384:
                return False
            size += len(json.dumps([str(row[0]), *row[1:]], ensure_ascii=False).encode('utf-8')) + 1
        except UnicodeError:
            return False
        if size > 8 * 1024 * 1024:
            return False
    row_paths = {row[4] for row in result.rows}
    for path, identity in result.source_identities.items():
        if (type(path) is not str or path not in row_paths or type(identity) is not tuple or len(identity) != 7 or
                type(identity[0]) is not str or identity[2] == 0 or
                any(type(value) is not int or not -(2**127) <= value <= 2**128 - 1 for value in identity[1:6]) or
                type(identity[6]) is not str or len(identity[6]) != 64 or
                any(c not in '0123456789abcdef' for c in identity[6])):
            return False
        try:
            size += len(json.dumps([path, *identity], ensure_ascii=False).encode('utf-8')) + 64
        except UnicodeError:
            return False
        if size > 8 * 1024 * 1024:
            return False
    return True


def _send(connection, value):
    payload = pickle.dumps(value, protocol=4)
    if len(payload) > 8 * 1024 * 1024:
        raise ValueError('message exceeds limit')
    connection.send_bytes(payload)


def _receive(connection):
    return pickle.loads(connection.recv_bytes(8 * 1024 * 1024))


def _repository_refusal(cfg):
    """Honor the normalized runtime gate without accessing the repository."""
    if cfg.get('config_repo_enabled') is True:
        return None
    if cfg.get('config_repo_enabled_explicit') is False:
        return SearchOutcome('repository_disabled',
                             'Configuration search is disabled in [config_repo]. Enable it in the configuration and relaunch.')
    return SearchOutcome('repository_unavailable',
                         'Configuration repository is not configured or accessible. Check [config_repo] directory and relaunch.')


def perform_config_search(runtime, module, inputs, control, connection):
    """Run one live search under the guardian; never publish partial rows."""
    if not _valid_inputs(inputs):
        return SearchOutcome('invalid', 'Search input exceeds the allowed limits.')
    refusal = _repository_refusal(runtime.ctx.cfg)
    if refusal is not None:
        return refusal
    mode = config_search_mode(runtime.ctx)
    if mode == 'cached_unavailable':
        return SearchOutcome(mode, CONFIG_SEARCH_CACHE_UNAVAILABLE_MESSAGE)
    if mode != 'live':
        return SearchOutcome('incomplete', 'Could not determine configuration search mode.')
    try:
        plugin = _hook_plugin(module)
    except ValueError:
        return SearchOutcome('unsupported_plugin', 'This plugin is not supported in the WebUI. Use the menu to search.')
    if runtime.ctx.cfg.get('sdwan_yaml_enabled') and (plugin is None or not plugin._is_ready.is_set()):
        return SearchOutcome('unsupported_plugin', 'SD-WAN YAML search is not supported in the WebUI. Use the menu to include YAML results.')
    parsed = parse_search_inputs(inputs, runtime.ctx.cfg.get('site_code_pattern'))
    if not parsed.networks and not parsed.terms:
        return SearchOutcome('invalid', 'Enter at least one valid search term.', errors=parsed.errors)
    return _perform_search(runtime, parsed, plugin, control, connection)


def perform_demob_search(runtime, module, scope, control, connection):
    """Search only the server-owned scope consumed from the demob preview vault."""
    from .config_demob import DemobSearchScope, demob_scope_within_limits
    if type(scope) is not DemobSearchScope:
        return SearchOutcome('invalid', 'Invalid demobilization search scope.')

    def with_discovery(result):
        result.demob_status = scope.status
        result.demob_message = scope.message
        result.demob_notices = list(scope.notices)
        return result

    refusal = _repository_refusal(runtime.ctx.cfg)
    if refusal is not None:
        return with_discovery(refusal)
    mode = config_search_mode(runtime.ctx)
    if mode == 'cached_unavailable':
        return with_discovery(SearchOutcome(mode, CONFIG_SEARCH_CACHE_UNAVAILABLE_MESSAGE))
    if mode != 'live':
        return with_discovery(SearchOutcome('incomplete', 'Could not determine configuration search mode.'))
    if not demob_scope_within_limits(scope):
        return with_discovery(SearchOutcome('limit', 'Demobilization search scope exceeds its limits.'))
    if not scope.networks and not scope.terms:
        return with_discovery(SearchOutcome('invalid', 'No demobilization search terms are available.'))
    parsed = ParsedConfigSearch(scope.networks, scope.terms, scope.site, [])
    return with_discovery(_perform_search(runtime, parsed, None, control, connection))


def _perform_search(runtime, parsed, plugin, control, connection):
    if control.stop.is_set():
        return SearchOutcome('stopped', 'Search stopped.', errors=parsed.errors)
    if connection is None:
        return SearchOutcome('incomplete', 'Configuration search process is unavailable.', errors=parsed.errors)
    cfg = runtime.ctx.cfg
    request = SearchRequest(str(cfg.get('config_repo_directory') or ''),
                            tuple(cfg.get('config_repo_vendors') or ()), tuple(cfg.get('config_repo_regions') or ()),
                            tuple(cfg.get('config_repo_excluded_dirs') or ()), str(cfg.get('config_repo_history_dir') or ''),
                            tuple(str(net) for net in parsed.networks), tuple(parsed.terms), parsed.search_input,
                            plugin is not None)
    candidate = None
    started = False
    stopping = False
    snapshot_seen = False
    finished = False
    stop_deadline = None
    try:
        _send(connection, ('start', request))
        while True:
            if control.stop.is_set() and not stopping:
                _send(connection, ('stop', None))
                stopping = True
                stop_deadline = time.monotonic() + 5
                candidate = None
            if stopping and time.monotonic() >= stop_deadline:
                connection.close()
                return SearchOutcome('incomplete', 'Could not confirm that configuration search stopped.', errors=parsed.errors)
            if not connection.poll(.05):
                continue
            event = _receive(connection)
            if type(event) is not tuple or len(event) != 2:
                raise ValueError('invalid guardian event')
            tag, value = event
            if tag == 'started' and value is None and not started:
                started = True
            elif tag == 'data' and started and type(value) is bytes and len(value) <= MAX_MESSAGE:
                if stopping:
                    continue
                message = pickle.loads(value)
                if type(message) is not dict:
                    raise ValueError('invalid child message')
                if message == {'type': 'snapshot'} and plugin is not None and not snapshot_seen and candidate is None:
                    snapshot_seen = True
                    snapshot = snapshot_yaml_plugin(plugin)
                    if snapshot is None and cfg.get('sdwan_yaml_enabled'):
                        raise ValueError('YAML search unavailable')
                    reply = pickle.dumps({'type': 'snapshot', 'snapshot': snapshot}, protocol=4)
                    if len(reply) > MAX_MESSAGE:
                        raise ValueError('snapshot exceeds limit')
                    _send(connection, ('data', reply))
                elif set(message) == {'type', 'result'} and message['type'] == 'result' and candidate is None:
                    candidate = message['result']
                    if not _valid_result(candidate, parsed.networks):
                        raise ValueError('invalid result')
                else:
                    raise ValueError('invalid child message')
            elif tag == 'finished':
                finished = True
                if stopping:
                    # Drain the acknowledgement of the stop sent after completion.
                    continue
                if control.stop.is_set():
                    return SearchOutcome('stopped', 'Search stopped.', errors=parsed.errors)
                if type(value) is not int or value != 0 or not started or candidate is None or (plugin is not None and candidate.status == 'complete' and not snapshot_seen):
                    raise ValueError('child failed')
                messages = {'complete': '', 'limit': 'Search exceeded its limits. Narrow the search.',
                            'incomplete': 'A configuration file or directory could not be read or changed during the search.'}
                return SearchOutcome(candidate.status, messages[candidate.status], candidate.rows, candidate.matched_nets,
                                     parsed.networks, parsed.errors, candidate.source_identities)
            elif tag == 'stopped' and stopping:
                return SearchOutcome('stopped', 'Search stopped.', errors=parsed.errors)
            elif tag == 'failed':
                return SearchOutcome('stopped' if stopping else 'incomplete',
                                     'Search stopped.' if stopping else 'Configuration search process failed.', errors=parsed.errors)
            else:
                raise ValueError('invalid guardian event')
    except (OSError, EOFError, ValueError, TypeError, pickle.UnpicklingError):
        if not finished:
            try:
                if not stopping:
                    _send(connection, ('stop', None))
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if connection.poll(.05):
                        event = _receive(connection)
                        if type(event) is tuple and len(event) == 2 and event[0] in ('stopped', 'failed'):
                            break
                else:
                    connection.close()
            except (OSError, EOFError, ValueError, TypeError, pickle.UnpicklingError):
                connection.close()
        return SearchOutcome('incomplete', 'Configuration search process failed.', errors=parsed.errors)
