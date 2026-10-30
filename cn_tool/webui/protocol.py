"""Strict JSON envelopes on the private worker pipe."""
import json

FIELDS = {
    'initialize': {'config_file'}, 'credentials_reply': {'request_id', 'reply', 'remember'}, 'forget_credentials': set(),
    'lookup': {'inputs'}, 'cancel': set(), 'snapshot_report': {'request_id'}, 'shutdown': set(),
    'ready': {'scope', 'username', 'report_warning', 'report_location'}, 'setup_required': {'message', 'code'},
    'credentials_required': {'request_id', 'account', 'username', 'need_username', 'need_password', 'message', 'store_supported'},
    'credential_store_state': {'account', 'username', 'status', 'message', 'pending'},
    'saved_login_restored': set(),
    'progress': {'stage'}, 'result': {'result'}, 'report_state': {'state'},
    'error': {'message'}, 'report_snapshot': {'request_id', 'path', 'error', 'filename'}, 'closed': set(),
}
COMMANDS = frozenset(('initialize', 'credentials_reply', 'lookup', 'cancel', 'snapshot_report', 'shutdown', 'forget_credentials'))


def envelope(session_id, job_id, kind, payload):
    return dict(version=1, session_id=session_id, job_id=job_id, kind=kind, payload=payload)


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
    required = FIELDS[kind] - ({'path', 'error', 'filename'} if kind == 'report_snapshot' else set())
    if kind == 'credentials_reply':
        required -= {'remember'}
    if kind == 'credentials_required':
        required -= {'store_supported'}
    if kind == 'ready':
        required -= {'report_warning', 'report_location'}
    if not required <= set(payload):
        raise ValueError('Missing payload fields')
    for key, value in payload.items():
        if key in {'reply', 'result', 'state'}:
            continue
        if key == 'inputs':
            if not isinstance(value, list) or not all(isinstance(i, str) for i in value):
                raise ValueError('Invalid inputs')
        elif key.startswith('need_') or key in {'remember', 'pending', 'store_supported'}:
            if type(value) is not bool:
                raise ValueError('Invalid credential flag')
        elif key == 'code':
            if type(value) is not int:
                raise ValueError('Invalid code')
        elif key == 'config_file' and value is None:
            continue
        elif not isinstance(value, str):
            raise ValueError('Invalid payload value')
    if kind == 'credentials_reply' and payload['reply'] is not None:
        reply = payload['reply']
        if not isinstance(reply, dict) or set(reply) != {'username', 'password'} or not all(isinstance(v, str) for v in reply.values()):
            raise ValueError('Invalid credential reply')
    if kind in {'lookup', 'cancel', 'result', 'progress'} and not message['job_id']:
        raise ValueError('Job ID required')
    return message


def encode(message):
    return json.dumps(validate(message), ensure_ascii=False, allow_nan=False).encode('utf-8')


def decode(data):
    try:
        return validate(json.loads(data.decode('utf-8')))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('Invalid JSON message') from exc
