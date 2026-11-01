"""Strict JSON envelopes on the private worker pipe."""
import json
import math
import re

FIELDS = {
    'initialize': {'config_file'}, 'credentials_reply': {'request_id', 'reply', 'remember'}, 'forget_credentials': set(),
    'lookup': {'inputs', 'lookup_type', 'tcp_ports', 'interval_seconds', 'duration_seconds'}, 'cancel': set(), 'snapshot_report': {'request_id'}, 'shutdown': {'interrupted'},
    'ready': {'scope', 'username', 'report_warning', 'report_state'}, 'setup_required': {'message', 'code'},
    'credentials_required': {'request_id', 'account', 'username', 'need_username', 'need_password', 'message', 'store_supported'},
    'credential_store_state': {'account', 'username', 'status', 'message', 'pending'},
    'saved_login_restored': set(),
    'demob_lookup': {'site'}, 'demob_confirm': {'token'}, 'demob_decline': set(),
    'demob_preview': {'site', 'status', 'message', 'notices', 'row_count', 'token'},
    'demob_page': {'token', 'offset', 'limit', 'query_id'},
    'demob_page_result': {'query_id', 'offset', 'rows', 'total', 'next_offset', 'status'},
    'config_search_page': {'job_id', 'offset', 'limit', 'query_id'},
    'config_search_page_result': {'job_id', 'offset', 'rows', 'total', 'next_offset', 'status', 'query_id'},
    'monitor_delete': {'action', 'run_id', 'request_id', 'query_id'},
    'monitor_delete_result': {'query_id', 'status', 'warning'},
    'monitor_history': {'kind', 'parent', 'cursor', 'limit', 'query_id'},
    'monitor_history_result': {'items', 'next_cursor', 'error', 'query_id'},
    'monitor_live_page': {'job_id', 'run_id', 'revision', 'offset', 'limit', 'query_id'},
    'monitor_live_page_result': {'job_id', 'run_id', 'revision', 'offset', 'rows', 'next_offset', 'status', 'current_revision', 'query_id'},
    'monitor_update': {'lookup_type', 'run_id', 'revision', 'stage', 'completed', 'total', 'current_rounds', 'earlier_rounds', 'skipped_slots', 'history_error'},
    'progress': {'stage', 'lookup_type', 'completed', 'total'}, 'result': {'result', 'outcome', 'lookup_type'}, 'report_state': {'state', 'lookup_type'},
    'lookup_context': {'lookup_type', 'username', 'scope'},
    'error': {'message', 'lookup_type'}, 'report_snapshot': {'request_id', 'path', 'error', 'filename'}, 'closed': set(),
}
COMMANDS = frozenset(('initialize', 'credentials_reply', 'lookup', 'cancel', 'snapshot_report', 'shutdown', 'forget_credentials', 'monitor_live_page', 'monitor_history', 'monitor_delete', 'config_search_page', 'demob_lookup', 'demob_confirm', 'demob_decline', 'demob_page'))


def envelope(session_id, job_id, kind, payload):
    return dict(version=1, session_id=session_id, job_id=job_id, kind=kind, payload=payload)



def valid_monitor_request_summary(item):
    fields = {'id', 'key', 'targets_preview', 'ports_preview', 'target_count', 'port_count', 'host_count'}
    if not isinstance(item, dict) or set(item) != fields:
        return False
    return (type(item['id']) is int and 1 <= item['id'] <= 2**63 - 1 and
            isinstance(item['key'], str) and len(item['key']) <= 64 and
            isinstance(item['targets_preview'], list) and len(item['targets_preview']) <= 3 and
            all(isinstance(target, str) and len(target) <= 80 for target in item['targets_preview']) and
            isinstance(item['ports_preview'], list) and len(item['ports_preview']) <= 3 and
            all(type(port) is int and 1 <= port <= 65535 for port in item['ports_preview']) and
            all(value is None or type(value) is int and 0 <= value <= 2**63 - 1
                for value in (item['target_count'], item['port_count'], item['host_count'])) and
            (item['target_count'] is None or item['target_count'] >= len(item['targets_preview'])) and
            (item['port_count'] is None or item['port_count'] >= len(item['ports_preview'])))


def valid_monitor_history_item(kind, item):
    """Validate one compact, kind-specific history DTO."""
    def integer(value, minimum=0):
        return type(value) is int and minimum <= value <= 2**63 - 1
    def number(value):
        return (type(value) is int and -(2**63) <= value <= 2**63 - 1 or
                type(value) is float and math.isfinite(value))
    def optional_number(value):
        return value is None or number(value)
    def text(value):
        return isinstance(value, str) and len(value) <= 8192
    if kind == 'requests':
        return valid_monitor_request_summary(item)
    if kind == 'template':
        if not isinstance(item, dict) or set(item) != {'targets', 'ports', 'interval', 'until', 'started'}:
            return False
        targets, ports = item['targets'], item['ports']
        if (not isinstance(targets, list) or not targets or not all(isinstance(t, str) and t.splitlines() == [t] for t in targets) or
                not isinstance(ports, list) or len(ports) > 5 or
                any(type(p) is not int or not 1 <= p <= 65535 for p in ports) or len(set(ports)) != len(ports)):
            return False
        return (len(json.dumps(targets, ensure_ascii=False, separators=(',', ':'))) <= 8192 and
                len(json.dumps(ports, ensure_ascii=False, separators=(',', ':'))) <= 8192 and
                (item['interval'] is None or integer(item['interval'], -(2**63))) and
                optional_number(item['until']) and number(item['started']))
    if not isinstance(item, dict):
        return False
    if kind == 'runs':
        fields = {'id', 'request_id', 'source', 'started', 'interval', 'until', 'host', 'pid', 'heartbeat',
                  'round_seconds', 'ended', 'status', 'rounds', 'owned'}
        if set(item) != fields:
            return False
        from cn_tool.utils.ping_history import _history_run_id
        run_id = item['id']
        return (_history_run_id(run_id) and
                integer(item['request_id'], 1) and (item['source'] is None or text(item['source'])) and
                number(item['started']) and optional_number(item['interval']) and optional_number(item['until']) and
                text(item['host']) and integer(item['pid']) and number(item['heartbeat']) and
                optional_number(item['round_seconds']) and optional_number(item['ended']) and
                item['status'] in ('running', 'lost', 'finished', 'stopped', 'failed') and integer(item['rounds']) and
                type(item['owned']) is bool)
    if kind == 'rounds':
        return (set(item) == {'id', 'started', 'answered'} and integer(item['id'], 1) and
                number(item['started']) and integer(item['answered']))
    if kind == 'hosts':
        return (set(item) == {'index', 'host', 'observation', 'address', 'result'} and integer(item['index']) and
                text(item['host']) and item['observation'] in ('!', 'R', 'T', 'U', '.', 'E', '?', ' ') and
                (item['address'] is None or text(item['address'])) and
                (item['result'] is None or text(item['result'])))
    return False

def validate(message):
    if not isinstance(message, dict) or set(message) != {'version', 'session_id', 'job_id', 'kind', 'payload'}:
        raise ValueError('Invalid envelope')
    if type(message['version']) is not int or message['version'] != 1:
        raise ValueError('Unsupported protocol version')
    if not isinstance(message['session_id'], str) or not message['session_id']:
        raise ValueError('Invalid session ID')
    if message['job_id'] is not None and not isinstance(message['job_id'], str):
        raise ValueError('Invalid job ID')
    kind, payload = message['kind'], message['payload']
    if not isinstance(kind, str) or kind not in FIELDS or not isinstance(payload, dict) or set(payload) - FIELDS[kind]:
        raise ValueError('Invalid message kind or payload fields')
    if kind in {'monitor_delete', 'monitor_delete_result'}:
        if message['job_id'] is not None or set(payload) != FIELDS[kind]:
            raise ValueError('Invalid deletion envelope')
        query_id = payload['query_id']
        if (not isinstance(query_id, str) or not 1 <= len(query_id) <= 128 or
                not query_id.isascii() or not query_id.isprintable()):
            raise ValueError('Invalid deletion query ID')
        if kind == 'monitor_delete':
            from cn_tool.utils.ping_history import _history_int, _history_run_id
            action, run_id, request_id = payload['action'], payload['run_id'], payload['request_id']
            if not ((action == 'run' and _history_run_id(run_id) and _history_int(request_id)) or
                    (action == 'all' and run_id is None and request_id is None)):
                raise ValueError('Invalid deletion scope')
        elif (payload['status'] not in ('deleted', 'missing', 'running', 'failed') or
              not isinstance(payload['warning'], str) or len(payload['warning']) > 512):
            raise ValueError('Invalid deletion result')
        return message
    if kind.startswith('demob_'):
        if set(payload) != FIELDS[kind]:
            raise ValueError('Invalid demobilization payload')
        if (kind in {'demob_lookup', 'demob_confirm', 'demob_preview'} and not message['job_id'] or
                kind in {'demob_decline', 'demob_page', 'demob_page_result'} and message['job_id'] is not None):
            raise ValueError('Invalid demobilization job')
        def identifier(value):
            return isinstance(value, str) and 0 < len(value) <= 128 and value.isascii() and value.isprintable()
        if kind == 'demob_lookup' and (type(payload['site']) is not str or len(payload['site']) > 1024):
            raise ValueError('Invalid site')
        if kind in {'demob_confirm', 'demob_page'} and not identifier(payload['token']):
            raise ValueError('Invalid token')
        if kind == 'demob_preview':
            if (type(payload['site']) is not str or len(payload['site']) > 1024 or
                    payload['status'] not in ('ok', 'partial_error', 'invalid', 'error', 'limit', 'cancelled') or
                    type(payload['message']) is not str or type(payload['notices']) is not list or
                    any(type(item) is not str for item in payload['notices']) or
                    type(payload['row_count']) is not int or not 0 <= payload['row_count'] <= 10000 or
                    (payload['token'] is not None and not identifier(payload['token']))):
                raise ValueError('Invalid preview')
        if kind in {'demob_page', 'demob_page_result'}:
            if not identifier(payload['query_id']) or type(payload['offset']) is not int or not 0 <= payload['offset'] <= 10000:
                raise ValueError('Invalid preview page')
            if kind == 'demob_page':
                if type(payload['limit']) is not int or not 1 <= payload['limit'] <= 100:
                    raise ValueError('Invalid preview page limit')
            elif (payload['status'] not in ('ready', 'unavailable') or type(payload['rows']) is not list or
                  len(payload['rows']) > 100 or any(type(row) is not dict for row in payload['rows']) or
                  type(payload['total']) is not int or not 0 <= payload['total'] <= 10000 or
                  (payload['next_offset'] is not None and (type(payload['next_offset']) is not int or
                   not 0 <= payload['next_offset'] <= payload['total'])) or
                  (payload['status'] == 'unavailable' and (payload['rows'] or payload['total'] or payload['next_offset'] is not None))):
                raise ValueError('Invalid preview page result')
        limit = 257 * 1024 if kind == 'demob_page_result' else 256 * 1024
        if len(json.dumps(payload, ensure_ascii=False, allow_nan=False).encode('utf-8')) > limit:
            raise ValueError('Demobilization message exceeds limit')
        return message
    if kind in {'config_search_page', 'config_search_page_result'}:
        if message['job_id'] is not None or set(payload) != FIELDS[kind]:
            raise ValueError('Invalid configuration page envelope')
        if any(not isinstance(payload[k], str) or not payload[k] or len(payload[k]) > 128 or
               not payload[k].isascii() or not payload[k].isprintable() for k in ('job_id', 'query_id')):
            raise ValueError('Invalid configuration page identifier')
        if type(payload['offset']) is not int or not 0 <= payload['offset'] <= 10000:
            raise ValueError('Invalid configuration page offset')
        if kind == 'config_search_page':
            if type(payload['limit']) is not int or not 1 <= payload['limit'] <= 50:
                raise ValueError('Invalid configuration page limit')
        else:
            rows, total, position = payload['rows'], payload['total'], payload['next_offset']
            if (payload['status'] not in ('ready', 'unavailable') or type(total) is not int or
                    not 0 <= total <= 10000 or type(rows) is not list or len(rows) > 50 or
                    (position is not None and (type(position) is not int or not 0 <= position <= total))):
                raise ValueError('Invalid configuration page result')
            for row in rows:
                if (type(row) is not list or len(row) != 5 or type(row[2]) is not int or row[2] < 0 or
                        any(type(row[index]) is not str for index in (0, 1, 3, 4)) or
                        len(row[3].encode('utf-8')) > 16384):
                    raise ValueError('Invalid configuration row')
            if len(json.dumps(payload, ensure_ascii=False).encode('utf-8')) > 1024 * 1024:
                raise ValueError('Configuration page exceeds limit')
            if payload['status'] == 'unavailable' and (rows or total or position is not None):
                raise ValueError('Unavailable page contains data')
        return message
    if kind in {'monitor_history', 'monitor_history_result'}:
        if message['job_id'] is not None or set(payload) != FIELDS[kind]:
            raise ValueError('Invalid history envelope')
        query_id = payload['query_id']
        if not isinstance(query_id, str) or not query_id or len(query_id) > 128 or not query_id.isascii() or not query_id.isprintable():
            raise ValueError('Invalid query ID')
        cursor = payload['cursor'] if kind == 'monitor_history' else payload['next_cursor']
        if cursor is not None and (not isinstance(cursor, str) or len(cursor) > 1024 or not re.fullmatch(r'[A-Za-z0-9_-]+', cursor)):
            raise ValueError('Invalid history cursor')
        if kind == 'monitor_history':
            from cn_tool.utils.ping_history import _history_decode_cursor, _history_int, _history_run_id
            page_kind, parent, limit = payload['kind'], payload['parent'], payload['limit']
            if (page_kind not in ('requests', 'runs', 'rounds', 'hosts', 'template') or not _history_int(limit) or limit > 100 or
                    (page_kind == 'requests' and parent is not None) or
                    (page_kind in ('runs', 'hosts') and not _history_int(parent)) or
                    (page_kind in ('rounds', 'template') and not _history_run_id(parent)) or
                    (page_kind == 'template' and (cursor is not None or limit != 1))):
                raise ValueError('Invalid history query')
            if cursor is not None:
                _history_decode_cursor(cursor, page_kind, parent)
        else:
            items, error = payload['items'], payload['error']
            if (not isinstance(items, list) or len(items) > 100 or
                    (error is not None and not isinstance(error, str))):
                raise ValueError('Invalid history result')
            for item in items:
                if not any(valid_monitor_history_item(item_kind, item)
                           for item_kind in ('requests', 'runs', 'rounds', 'hosts', 'template')):
                    raise ValueError('Invalid history item')
        return message
    if kind in {'monitor_live_page', 'monitor_live_page_result'}:
        if message['job_id'] is not None or set(payload) != FIELDS[kind]:
            raise ValueError('Invalid live page envelope')
        if any(not isinstance(payload[k], str) or not payload[k] or len(payload[k]) > 128 or
                   not payload[k].isascii() or not payload[k].isprintable()
               for k in ('job_id', 'run_id', 'query_id')):
            raise ValueError('Invalid live page identifier')
        if any(type(payload[k]) is not int or payload[k] < 0 for k in ('revision', 'offset')):
            raise ValueError('Invalid live page position')
        if kind == 'monitor_live_page':
            if type(payload['limit']) is not int or not 1 <= payload['limit'] <= 100:
                raise ValueError('Invalid live page limit')
        else:
            rows = payload['rows']
            if (payload['status'] not in ('ready', 'not_ready', 'expired', 'unavailable') or
                    type(payload['current_revision']) is not int or payload['current_revision'] < 0 or
                    (payload['next_offset'] is not None and
                     (type(payload['next_offset']) is not int or payload['next_offset'] < 0)) or
                    not isinstance(rows, list) or len(rows) > 100):
                raise ValueError('Invalid live page result')
            for row in rows:
                if (not isinstance(row, dict) or set(row) != {'host', 'address', 'result', 'tcp'} or
                        any(not isinstance(row[k], str) for k in ('host', 'address', 'result')) or
                        not isinstance(row['tcp'], list) or len(row['tcp']) > 5 or
                        any(not isinstance(t, dict) or set(t) != {'port', 'result'} or
                            type(t['port']) is not int or not 1 <= t['port'] <= 65535 or
                            not isinstance(t['result'], str) for t in row['tcp'])):
                    raise ValueError('Invalid live row')
            if payload['status'] != 'ready' and (rows or payload['next_offset'] is not None):
                raise ValueError('Non-ready pages cannot contain rows')
        return message
    required = FIELDS[kind] - ({'path', 'error', 'filename'} if kind == 'report_snapshot' else set())
    if kind == 'lookup':
        if payload.get('lookup_type') != 'monitor':
            required -= {'interval_seconds', 'duration_seconds'}
            if {'interval_seconds', 'duration_seconds'} & payload.keys():
                raise ValueError('Timing requires Monitor')
        if payload.get('lookup_type') not in ('ping', 'monitor'):
            required -= {'tcp_ports'}
            if 'tcp_ports' in payload:
                raise ValueError('Ports require Ping or Monitor')
    if kind == 'monitor_update':
        counts = ('revision', 'completed', 'total', 'current_rounds', 'earlier_rounds', 'skipped_slots')
        if (payload.get('lookup_type') != 'monitor' or not isinstance(payload.get('run_id'), str)
                or not payload['run_id'] or len(payload['run_id']) > 128 or not payload['run_id'].isascii()
                or not payload['run_id'].isprintable() or any(type(payload.get(k)) is not int or payload[k] < 0 for k in counts)
                or payload['completed'] > payload['total']):
            raise ValueError('Invalid Monitor update')
    if kind == 'progress':
        required -= {'completed', 'total'}
        if ('completed' in payload) != ('total' in payload):
            raise ValueError('Counts must be paired')
        if 'completed' in payload and (payload.get('lookup_type') != 'ping' or
                any(type(payload[k]) is not int or payload[k] < 0 for k in ('completed', 'total')) or
                payload['completed'] > payload['total']):
            raise ValueError('Invalid progress counts')
    if kind == 'error' and message['job_id'] is None:
        required -= {'lookup_type'}
        if 'lookup_type' in payload:
            raise ValueError('Session error must be untyped')
    if kind == 'credentials_reply':
        required -= {'remember'}
    if kind == 'shutdown':
        required -= {'interrupted'}
    if kind == 'credentials_required':
        required -= {'store_supported'}
    if kind == 'ready':
        required -= {'report_warning', 'report_state'}
    if not required <= set(payload):
        raise ValueError('Missing payload fields')
    for key, value in payload.items():
        if key in {'reply', 'result', 'state', 'outcome', 'report_state'}:
            continue
        if key == 'tcp_ports':
            if (not isinstance(value, list) or len(value) > 5 or
                    any(type(port) is not int or not 1 <= port <= 65535 for port in value) or
                    len(set(value)) != len(value)):
                raise ValueError('Invalid TCP ports')
        elif key in {'interval_seconds', 'duration_seconds'}:
            if key == 'duration_seconds' and value is None:
                continue
            if type(value) is not int or not 10 <= value <= 2**53 - 1:
                raise ValueError('Invalid Monitor timing')
        elif key in {'completed', 'total', 'revision', 'current_rounds', 'earlier_rounds', 'skipped_slots'}:
            continue
        elif key == 'inputs':
            if not isinstance(value, list) or not all(isinstance(i, str) for i in value):
                raise ValueError('Invalid inputs')
        elif key.startswith('need_') or key in {'interrupted', 'remember', 'pending', 'store_supported'}:
            if type(value) is not bool:
                raise ValueError('Invalid credential flag')
        elif key == 'code':
            if type(value) is not int:
                raise ValueError('Invalid code')
        elif key == 'config_file' and value is None:
            continue
        elif not isinstance(value, str):
            raise ValueError('Invalid payload value')
    if kind == 'lookup' and payload.get('lookup_type') == 'demob':
        raise ValueError('Demobilization requires a preview and consent')
    if kind == 'lookup' and payload.get('lookup_type') == 'config_search':
        inputs = payload['inputs']
        if (len(inputs) > 200 or any(len(value) > 1024 or any(c in value for c in '\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029') for value in inputs) or
                sum(len(value.encode('utf-8')) for value in inputs) + max(0, len(inputs) - 1) > 65536):
            raise ValueError('Configuration input exceeds limits')
    if kind == 'lookup' and payload.get('lookup_type') == 'monitor' and payload['duration_seconds'] is not None and payload['duration_seconds'] < payload['interval_seconds']:
        raise ValueError('Duration must be at least the interval')
    if 'lookup_type' in payload and payload['lookup_type'] not in ('subnet', 'ip', 'ping', 'monitor', 'config_search', 'demob'):
        raise ValueError('Invalid lookup type')
    if kind == 'lookup_context' and payload['lookup_type'] in ('ping', 'monitor', 'config_search'):
        raise ValueError('Ping and Monitor have no lookup context')
    if kind == 'credentials_reply' and payload['reply'] is not None:
        reply = payload['reply']
        if not isinstance(reply, dict) or set(reply) != {'username', 'password'} or not all(isinstance(v, str) for v in reply.values()):
            raise ValueError('Invalid credential reply')
    if kind == 'result':
        outcome = payload['outcome']
        counts = {'matched_count', 'invalid_count', 'resolution_error_count', 'miss_count', 'warning_count'}
        if (not isinstance(payload['result'], dict) or not isinstance(outcome, dict)
                or set(outcome) != counts | {'kind', 'message', 'stopped', 'details'}
                or not isinstance(outcome['kind'], str)
                or outcome['kind'] not in {'matched', 'partial', 'no_match', 'invalid', 'lookup_error', 'stopped'}
                or not isinstance(outcome['message'], str) or type(outcome['stopped']) is not bool
                or not isinstance(outcome['details'], dict)
                or any(type(outcome[key]) is not int or outcome[key] < 0 for key in counts)):
            raise ValueError('Invalid outcome')
        if payload['lookup_type'] in ('config_search', 'demob'):
            result = payload['result']
            if (set(result) != {'status', 'total', 'errors', 'missing_nets'} or
                    result['status'] not in ('complete', 'invalid', 'stopped', 'incomplete', 'limit',
                                             'unsupported_plugin', 'cached_unavailable', 'repository_disabled',
                                             'repository_unavailable') or
                    type(result['total']) is not int or not 0 <= result['total'] <= 10000 or
                    type(result['errors']) is not list or len(result['errors']) > 200 or
                    type(result['missing_nets']) is not list or len(result['missing_nets']) > 200 or
                    any(type(net) is not str or len(net) > 32 for net in result['missing_nets']) or
                    any(type(error) is not dict or set(error) != {'line', 'reason'} or
                        type(error['line']) is not int or not 1 <= error['line'] <= 200 or
                        type(error['reason']) is not str or len(error['reason']) > 2048
                        for error in result['errors']) or
                    (result['status'] != 'complete' and (result['total'] or result['missing_nets']))):
                raise ValueError('Invalid configuration result')
        if payload['lookup_type'] == 'monitor':
            result = payload['result']
            fields = {'run_id', 'current_rounds', 'earlier_rounds', 'skipped_slots', 'history_error', 'probe_failed'}
            run_id = result.get('run_id')
            before_start = (run_id == '' and outcome['stopped'] and outcome['kind'] == 'stopped' and
                            result.get('history_error') == '' and result.get('probe_failed') is False and
                            all(result.get(k) == 0 for k in ('current_rounds', 'earlier_rounds', 'skipped_slots')))
            if (set(result) != fields or not isinstance(run_id, str) or
                    (not before_start and (not run_id or not run_id.isascii() or not run_id.isprintable())) or len(run_id) > 128 or
                    any(type(result[k]) is not int or result[k] < 0 for k in ('current_rounds', 'earlier_rounds', 'skipped_slots')) or
                    not isinstance(result['history_error'], str) or type(result['probe_failed']) is not bool):
                raise ValueError('Invalid Monitor result')
        if payload['lookup_type'] == 'ping':
            result = payload['result']
            fields = {'rows', 'input_errors', 'resolution_errors', 'stopped', 'icmp_available'}
            if (set(result) != fields or type(result['stopped']) is not bool or
                    type(result['icmp_available']) is not bool or result['stopped'] != outcome['stopped'] or
                    not isinstance(result['rows'], list) or
                    any(not isinstance(row, dict) or not {'Host', 'Address', 'Result'} <= set(row) or
                        any(not isinstance(k, str) or not isinstance(v, str)
                            for k, v in row.items()) for row in result['rows']) or
                    any(not isinstance(result[key], list) or any(not isinstance(item, dict) or
                        set(item) != {'object', 'reason'} or any(not isinstance(v, str) for v in item.values())
                        for item in result[key]) for key in ('input_errors', 'resolution_errors'))):
                raise ValueError('Invalid Ping result')
            details = outcome['details']
            if (set(details) - {'unattempted', 'attempted_incomplete'} or
                    any(not isinstance(details.get(key, []), list) or
                        any(not isinstance(item, str) for item in details.get(key, []))
                        for key in ('unattempted', 'attempted_incomplete')) or
                    any(len(details.get(key, [])) != len(set(details.get(key, [])))
                        for key in ('unattempted', 'attempted_incomplete')) or
                    bool(set(details.get('unattempted', [])) & set(details.get('attempted_incomplete', []))) or
                    outcome['matched_count'] != len(result['rows']) or
                    outcome['invalid_count'] != len(result['input_errors']) or
                    outcome['resolution_error_count'] != len(result['resolution_errors']) or
                    outcome['miss_count'] != 0 or outcome['warning_count'] != 0 or
                    outcome['kind'] == 'no_match' or
                    (result['stopped'] and outcome['kind'] not in {'stopped', 'lookup_error'}) or
                    (not result['stopped'] and outcome['kind'] == 'stopped') or
                    (outcome['kind'] in {'matched', 'partial'} and not result['rows']) or
                    (outcome['kind'] == 'matched' and (result['input_errors'] or result['resolution_errors'])) or
                    (outcome['kind'] == 'partial' and not (result['input_errors'] or result['resolution_errors'])) or
                    (outcome['kind'] == 'invalid' and (result['rows'] or result['resolution_errors']))):
                raise ValueError('Invalid Ping outcome')
        try:
            json.dumps(outcome['details'], allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError('Invalid outcome details') from exc
    report = payload.get('report_state') if kind == 'ready' else payload.get('state') if kind == 'report_state' else None
    if kind == 'report_state' or (kind == 'ready' and 'report_state' in payload):
        fields = {'state', 'status', 'filename', 'message', 'available', 'saved_for_attempt'}
        if (not isinstance(report, dict) or set(report) != fields
                or any(not isinstance(report[key], str) for key in fields - {'available', 'saved_for_attempt'})
                or any(type(report[key]) is not bool for key in {'available', 'saved_for_attempt'})):
            raise ValueError('Invalid report state')
    if (kind in {'lookup', 'cancel', 'result', 'progress', 'report_state', 'lookup_context', 'credentials_required', 'monitor_update'}
            or (kind == 'error' and message['job_id'] is not None)) and not message['job_id']:
        raise ValueError('Job ID required')
    return message


def encode(message):
    return json.dumps(validate(message), ensure_ascii=False, allow_nan=False).encode('utf-8')


def decode(data):
    try:
        return validate(json.loads(data.decode('utf-8')))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('Invalid JSON message') from exc
