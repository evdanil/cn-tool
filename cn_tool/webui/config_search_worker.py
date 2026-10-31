"""Spawn-safe, bounded live configuration search and shipped YAML adapter.

Only pass server-derived repository settings and validated input.  The caller
must reject unsupported hooks and cache mode before starting this target.  The
private connection carries pickle messages; it is never exposed to a browser.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
import ipaddress
import json
import logging
import pickle
from pathlib import Path
import re
from types import SimpleNamespace

from cn_tool.modules.config_search import BoundedSearchResult, search_live_bounded
from cn_tool.plugins.sdwan_yaml_search import SDWANYamlSearchPlugin

MAX_MESSAGE = 8 * 1024 * 1024 - 256
MAX_ITEMS = 10000
MAX_LINE = 16 * 1024
MAX_INPUT = 64 * 1024


@dataclass(frozen=True)
class SearchRequest:
    repo_directory: str
    vendors: tuple[str, ...]
    regions: tuple[str, ...]
    excluded_dirs: tuple[str, ...]
    history_dir: str
    networks: tuple[str, ...]
    terms: tuple[str, ...]
    search_input: str
    yaml_hook: bool = False


def _size(value):
    return len(value.encode('utf-8'))


def _validate_request(request):
    if type(request) is not SearchRequest or type(request.yaml_hook) is not bool:
        raise ValueError('Invalid request')
    for value in (request.repo_directory, request.history_dir, request.search_input):
        if type(value) is not str or _size(value) > MAX_INPUT:
            raise ValueError('Invalid request')
    for values in (request.vendors, request.regions, request.excluded_dirs, request.networks, request.terms):
        if type(values) is not tuple or len(values) > 200:
            raise ValueError('Invalid request')
        if any(type(value) is not str or len(value) > 1024 for value in values):
            raise ValueError('Invalid request')
    if sum(_size(x) for x in (*request.terms, *request.networks)) > MAX_INPUT:
        raise ValueError('Invalid request')
    networks = [ipaddress.ip_network(x, strict=False) for x in request.networks]
    if any(not isinstance(x, ipaddress.IPv4Network) for x in networks):
        raise ValueError('Invalid request')
    for term in request.terms:
        re.compile(term, re.IGNORECASE)
    return networks


def _scalar_text(value):
    # Check integers before decimal conversion: on Python 3.10 an arbitrarily
    # large YAML integer would otherwise allocate and consume CPU under the
    # plugin lock. Four bits per allowed character bounds the conversion;
    # the exact encoded size is checked after conversion.
    if type(value) is int and value.bit_length() > MAX_LINE * 4:
        raise ValueError('YAML snapshot exceeds limits')
    if type(value) in (str, bytes) and len(value) > MAX_LINE:
        raise ValueError('YAML snapshot exceeds limits')
    return str(value)


class _SnapshotBudget:
    def __init__(self):
        self.items = 0
        self.bytes = 0
        self.active = set()

    def add(self, text):
        # Check characters before encoding so an oversized scalar never creates
        # an equally oversized temporary UTF-8 buffer.
        if len(text) > MAX_LINE:
            raise ValueError('YAML snapshot exceeds limits')
        size = _size(text)
        if size > MAX_LINE:
            raise ValueError('YAML snapshot exceeds limits')
        self.bytes += size + 16
        if self.bytes > MAX_MESSAGE:
            raise ValueError('YAML snapshot exceeds limits')

    def copy(self, value, depth=0):
        self.items += 1
        if self.items > MAX_ITEMS or depth > 64:
            raise ValueError('YAML snapshot exceeds limits')
        if type(value) in (dict, list):
            identity = id(value)
            if identity in self.active:
                raise ValueError('Cyclic YAML snapshot')
            self.active.add(identity)
            try:
                if type(value) is dict:
                    result = {}
                    for key, child in value.items():
                        if type(key) not in (str, int, float, bool, type(None), date, datetime, bytes):
                            raise ValueError('Unsupported YAML key')
                        self.add(_scalar_text(key))
                        result[key] = self.copy(child, depth + 1)
                    return result
                return [self.copy(child, depth + 1) for child in value]
            finally:
                self.active.remove(identity)
        if type(value) not in (str, int, float, bool, type(None), date, datetime, bytes):
            raise ValueError('Unsupported YAML value')
        self.add(_scalar_text(value))
        return value


def _copy_snapshot(data, lines):
    if type(data) is not dict or type(lines) is not dict:
        raise ValueError('Invalid YAML snapshot')
    budget = _SnapshotBudget()
    result_data = {}
    result_lines = {}
    for filename, content in data.items():
        if type(filename) is not str:
            raise ValueError('Invalid YAML filename')
        budget.add(filename)
        result_data[filename] = budget.copy(content)
        raw_lines = lines.get(filename, [])
        if type(raw_lines) is not list:
            raise ValueError('Invalid YAML lines')
        result_lines[filename] = budget.copy(raw_lines)
        if any(type(line) is not str for line in result_lines[filename]):
            raise ValueError('Invalid YAML lines')
    snapshot = (result_data, result_lines)
    if len(pickle.dumps({'type': 'snapshot', 'snapshot': snapshot}, protocol=4)) > MAX_MESSAGE:
        raise ValueError('YAML snapshot exceeds limits')
    return snapshot


def snapshot_yaml_plugin(plugin):
    """Take a bounded private snapshot at the hook point, or None if not ready.

    Raises ValueError on unsupported or oversized structures; callers must stop
    the child and mark the search incomplete instead of providing partial data.
    """
    if type(plugin) is not SDWANYamlSearchPlugin:
        raise ValueError('Unsupported YAML plugin')
    with plugin._lock:
        if not plugin._is_ready.is_set():
            return None
        snapshot = _copy_snapshot(plugin._yaml_data, plugin._yaml_lines)
        if not plugin._is_ready.is_set():
            raise ValueError('YAML readiness changed during snapshot')
        return snapshot


def _apply_yaml(result, snapshot, networks, terms):
    if snapshot is None:
        return result
    if type(snapshot) is not tuple or len(snapshot) != 2:
        raise ValueError('Invalid YAML snapshot')
    data, lines = _copy_snapshot(*snapshot)
    plugin = SDWANYamlSearchPlugin()
    patterns = {term: re.compile(term, re.IGNORECASE) for term in terms}
    network_objects = {net: ipaddress.ip_network(net, strict=False) for net in networks}
    rows = result.rows
    size = len(json.dumps(rows, ensure_ascii=False).encode('utf-8'))
    for filename, content in data.items():
        if not content:
            continue
        device = Path(filename).stem.upper()
        raw_lines = lines.get(filename, [])
        for criterion, path, value in plugin._traverse_and_match(content, patterns, network_objects):
            line = f'{path}: {str(value)}'
            if _size(line) > MAX_LINE:
                raise ValueError('YAML row exceeds limits')
            index = next((i for i, raw in enumerate(raw_lines) if raw.strip() == line), 0)
            row = [criterion, device, index, line, filename]
            # Network criteria retain the plugin's network object type.
            encoded = json.dumps([str(criterion), *row[1:]], ensure_ascii=False).encode('utf-8')
            size += len(encoded) + 1
            if len(rows) >= MAX_ITEMS or size > MAX_MESSAGE:
                raise ValueError('YAML results exceed limits')
            rows.append(row)
            if criterion in network_objects:
                result.matched_nets.add(criterion)
    return result


def _send(connection, value):
    payload = pickle.dumps(value, protocol=4)
    if len(payload) > MAX_MESSAGE:
        raise ValueError('Message exceeds limits')
    connection.send_bytes(payload)


def run_search(request, connection):
    """Guardian target; regex work and YAML matching execute only here."""
    try:
        networks = _validate_request(request)
        cfg = {'config_repo_directory': Path(request.repo_directory),
               'config_repo_vendors': list(request.vendors),
               'config_repo_regions': list(request.regions),
               'config_repo_excluded_dirs': list(request.excluded_dirs),
               'config_repo_history_dir': request.history_dir}
        ctx = SimpleNamespace(cfg=cfg, logger=logging.getLogger('cn_tool.webui.search_child'))
        result = search_live_bounded(ctx, networks, list(request.terms), request.search_input)
        if result.status == 'complete' and request.yaml_hook:
            _send(connection, {'type': 'snapshot'})
            message = pickle.loads(connection.recv_bytes(MAX_MESSAGE))
            if type(message) is not dict or set(message) != {'type', 'snapshot'} or message['type'] != 'snapshot':
                raise ValueError('Invalid YAML response')
            result = _apply_yaml(result, message['snapshot'], networks, request.terms)
        _send(connection, {'type': 'result', 'result': result})
    except Exception:
        try:
            _send(connection, {'type': 'result', 'result': BoundedSearchResult(
                [], set(), 'incomplete', 'Configuration search could not be completed within its limits.')})
        except (OSError, EOFError):
            pass
    finally:
        connection.close()
