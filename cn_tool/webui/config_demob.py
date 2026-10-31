"""Session-owned, consent-gated site demobilization lookup.

Authentication and cancellation ownership belong to the worker. Call invalidate
before authentication for every new attempt and on decline, cancel and shutdown.
A live session may keep this vault across navigation and transient reconnects.
"""
from dataclasses import dataclass, field
import hashlib
import hmac
import ipaddress
import json
import math
import secrets
from threading import Lock
from time import monotonic
from typing import Any, Callable, Optional

from cn_tool.utils.api import NetworkFetchBudget, fetch_network_data
from cn_tool.utils.infoblox_ux import format_no_match_message, format_partial_results_message
from cn_tool.utils.network_views import NETWORK_VIEW, present_rows, view_scope
from cn_tool.utils.validation import is_valid_site
from cn_tool.modules.config_search import prepare_demob_terms


@dataclass
class DemobSearchScope:
    site: str
    networks: list
    terms: list[str]
    status: str
    message: str
    notices: list[str]


@dataclass
class DemobPreview:
    site: str
    status: str
    message: str = ''
    notices: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    row_count: int = 0
    token: Optional[str] = field(default=None, repr=False)


@dataclass
class DemobPreviewPage:
    """Page byte limit counts JSON of these fields, UTF-8, with json.dumps defaults
    and ensure_ascii=False. Callers must enforce their own outer protocol limit.
    """
    rows: list[dict[str, Any]]
    total: int
    next_offset: Optional[int]


def demob_scope_within_limits(scope: DemobSearchScope) -> bool:
    """Apply the same admission limits before preview and before scanning."""
    from .config_search import _valid_inputs
    return (type(scope.networks) is list and type(scope.terms) is list and
            len(scope.networks) <= 200 and len(scope.terms) <= 200 and
            all(type(net) is ipaddress.IPv4Network for net in scope.networks) and
            _valid_inputs(scope.terms) and _valid_inputs([scope.site]) and
            sum(len(str(net).encode('utf-8')) for net in scope.networks) +
            sum(len(term.encode('utf-8')) for term in scope.terms) <= 65536)


class DemobPreviewVault:
    """One expiring, single-use lookup per session; tokens are never retained."""

    def __init__(self, *, clock: Callable[[], float] = monotonic,
                 max_rows: int = 10000, max_bytes: int = 8 * 1024 * 1024,
                 max_page_rows: int = 100, max_page_bytes: int = 256 * 1024):
        if min(max_rows, max_bytes, max_page_rows, max_page_bytes) < 1:
            raise ValueError('Preview limits must be positive')
        self._clock = clock
        self._max_page_rows = max_page_rows
        self._max_page_bytes = max_page_bytes
        self._max_rows = max_rows
        self._max_bytes = max_bytes
        self._lock = Lock()
        self._generation = 0
        self._entry = None

    def new_budget(self, control: Any = None) -> NetworkFetchBudget:
        """Share one lookup budget across view discovery and both network families."""
        return NetworkFetchBudget(max_rows=self._max_rows, max_bytes=self._max_bytes, control=control)

    def invalidate(self) -> None:
        with self._lock:
            self._generation += 1
            self._entry = None

    def _match(self, token: str):
        if not isinstance(token, str) or len(token) > 128:
            return None
        entry = self._entry
        if entry is None:
            return None
        digest, expires, _, _ = entry
        if self._clock() >= expires:
            self._entry = None
            return None
        try:
            candidate = hashlib.sha256(token.encode('ascii')).digest()
        except UnicodeEncodeError:
            return None
        return entry if hmac.compare_digest(candidate, digest) else None

    def page(self, token: str, *, offset: int, limit: int) -> Optional[DemobPreviewPage]:
        """Return a bounded copy without consuming it, including page-envelope bytes."""
        if type(offset) is not int or type(limit) is not int or offset < 0 or not 1 <= limit <= self._max_page_rows:
            return None
        with self._lock:
            entry = self._match(token)
            if entry is None:
                return None
            rows = entry[3]
            if offset > len(rows):
                return None
            page = []
            rows_size = 0
            for row in rows[offset:offset + limit]:
                row_size = len(json.dumps(row, ensure_ascii=False).encode('utf-8'))
                candidate_size = rows_size + row_size + (2 if page else 0)
                end = offset + len(page) + 1
                next_offset = end if end < len(rows) else None
                envelope = {'rows': [], 'total': len(rows), 'next_offset': next_offset}
                envelope_size = len(json.dumps(envelope, ensure_ascii=False).encode('utf-8'))
                if envelope_size + candidate_size > self._max_page_bytes:
                    break
                page.append(dict(row))
                rows_size = candidate_size
            end = offset + len(page)
            return DemobPreviewPage(page, len(rows), end if end < len(rows) else None)

    def consume(self, token: str) -> Optional[DemobSearchScope]:
        with self._lock:
            entry = self._match(token)
            if entry is None:
                return None
            self._entry = None
            return entry[2]

    def preview(self, ctx: Any, site: str, *, control: Any = None, scope: Any = None,
                budget: Optional[NetworkFetchBudget] = None) -> DemobPreview:
        """Fetch a bounded preview, never inspecting the configuration repository."""
        with self._lock:
            self._generation += 1
            generation = self._generation
            self._entry = None
        site = site.strip().upper() if isinstance(site, str) and len(site) <= 1024 else ''
        if len(site) > 1024 or not is_valid_site(site, ctx.cfg.get('site_code_pattern')):
            return DemobPreview(site, 'invalid', 'Invalid site code format.')
        if control is not None:
            control.checkpoint()
        budget = budget if budget is not None else self.new_budget(control)
        discovery = []
        if scope is None:
            def discover(*args, **kwargs):
                from cn_tool.utils.api import request_result
                result = request_result(*args, **kwargs, paged=True, budget=budget)
                discovery.append(result)
                return result
            scope = view_scope(ctx, None, discover)
        lookup = fetch_network_data(ctx, site, ensure_auth=False, budget=budget)
        if control is not None:
            control.checkpoint()
        if any(failure.status == 'redirect_error' for failure in lookup.failures):
            return DemobPreview(site, 'error',
                                'Infoblox redirected the preview request; check the configured API endpoint.')
        if lookup.truncated:
            return DemobPreview(site, 'limit', 'Subnet lookup is incomplete; narrow the lookup.')
        if lookup.status == 'error':
            return DemobPreview(site, 'error', 'Subnet lookup failed.')
        if lookup.status not in ('ok', 'partial_error'):
            return DemobPreview(site, 'invalid', 'Subnet lookup returned an invalid status.')
        raw_rows = lookup.data.get('location', []) if isinstance(lookup.data, dict) else None
        if not isinstance(raw_rows, list):
            return DemobPreview(site, 'invalid', 'Subnet lookup returned invalid records.')
        if len(raw_rows) > self._max_rows:
            return DemobPreview(site, 'limit', 'Subnet lookup exceeds the preview limit; narrow the lookup.')
        # Bound fields before JSON encoding. Fetching and parsing happen upstream.
        rows = []
        used = 2
        for row in raw_rows:
            if not isinstance(row, dict):
                return DemobPreview(site, 'invalid', 'Subnet lookup returned an invalid record.')
            if any(key in row and row[key] is not None and not isinstance(row[key], str)
                   for key in ('network', 'comment', NETWORK_VIEW)):
                return DemobPreview(site, 'invalid', 'Subnet lookup returned an invalid record.')
            size = 0
            for key, value in row.items():
                if not isinstance(key, str):
                    return DemobPreview(site, 'invalid', 'Subnet lookup returned an invalid record.')
                if isinstance(value, str):
                    size += len(value)
                elif value is None:
                    pass
                elif type(value) is int and value.bit_length() <= 63:
                    size += 20
                elif type(value) is float and math.isfinite(value):
                    size += 32
                else:
                    return DemobPreview(site, 'invalid', 'Subnet lookup returned an invalid record.')
                size += len(key)
                if size > self._max_bytes - used:
                    return DemobPreview(site, 'limit', 'Subnet lookup exceeds the preview limit; narrow the lookup.')
            row = {k: (v if v is not None else '') for k, v in row.items()}
            try:
                row_size = len(json.dumps(row, ensure_ascii=False).encode('utf-8'))
            except UnicodeEncodeError:
                return DemobPreview(site, 'invalid', 'Subnet lookup returned an invalid record.')
            used += row_size + (2 if rows else 0)
            if used > self._max_bytes:
                return DemobPreview(site, 'limit', 'Subnet lookup exceeds the preview limit; narrow the lookup.')
            rows.append(row)
        notices = list(lookup.notices)
        view_fallback = bool(getattr(scope, '_webui_fallback', False))
        fallback_notice = 'Network views could not be listed; results are limited to this account’s access.'
        if view_fallback:
            notices.append(fallback_notice)
        if not isinstance(lookup.message, str) or any(not isinstance(item, str) for item in notices):
            return DemobPreview(site, 'invalid', 'Subnet lookup returned invalid notices.')
        if len(lookup.message) + sum(map(len, notices)) > self._max_bytes - used:
            return DemobPreview(site, 'limit', 'Subnet lookup exceeds the preview limit; narrow the lookup.')
        message = format_partial_results_message(lookup.message) if lookup.status == 'partial_error' else ''
        try:
            notice_bytes = sum(len(s.encode('utf-8')) for s in [message, *notices])
        except UnicodeEncodeError:
            return DemobPreview(site, 'invalid', 'Subnet lookup returned invalid notices.')
        if notice_bytes + used > self._max_bytes:
            return DemobPreview(site, 'limit', 'Subnet lookup exceeds the preview limit; narrow the lookup.')
        if not rows:
            no_match = scope.scoped(format_no_match_message('subnet records', site))
            return DemobPreview(site, 'partial_error' if view_fallback else lookup.status, f'{message} {no_match}'.strip(), notices)
        valid_rows = []
        invalid = False
        ipv6 = False
        for row in rows:
            try:
                network = ipaddress.ip_network(row['network'])
            except (KeyError, ValueError, TypeError):
                invalid = True
                continue
            if not isinstance(network, ipaddress.IPv4Network):
                ipv6 = True
                continue
            valid_rows.append(row)
        if ipv6:
            notices.append('IPv6 networks are not searched in configurations.')
        if invalid:
            notices.append('Invalid network records were skipped.')
        notice_bytes = sum(len(s.encode('utf-8')) for s in [message, *notices])
        status = 'partial_error' if invalid or ipv6 or view_fallback or lookup.status == 'partial_error' else lookup.status
        if len(scope.requested) > min(self._max_bytes, self._max_page_bytes):
            return DemobPreview(site, 'limit', 'Subnet lookup exceeds the preview limit; narrow the lookup.')
        show_view = scope.column(row.get(NETWORK_VIEW) for row in rows)
        if discovery:
            view_result = discovery[-1]
            if view_result.status == 'redirect_error':
                return DemobPreview(site, 'error',
                                    'Infoblox redirected the preview request; check the configured API endpoint.')
            if view_result.truncated:
                return DemobPreview(site, 'limit', 'Network view lookup is incomplete; narrow the lookup.')
            if view_result.status_code == 403 and not scope.requested:
                if not view_fallback:
                    notices.append(fallback_notice)
                    view_fallback = True
                status = 'partial_error'
            elif not view_result.ok or scope.grid().error:
                return DemobPreview(site, 'error', 'Network view lookup failed.')
        if view_fallback:
            show_view = True
        notice_bytes = sum(len(s.encode('utf-8')) for s in [message, *notices])
        shown_rows = present_rows(rows, NETWORK_VIEW, show_view, fallback=scope.requested)
        try:
            shown_sizes = [len(json.dumps(row, ensure_ascii=False).encode('utf-8')) for row in shown_rows]
        except UnicodeEncodeError:
            return DemobPreview(site, 'invalid', 'Subnet lookup returned an invalid record.')
        total = len(shown_rows)
        page_sizes = [size + len(json.dumps({'rows': [], 'total': total,
                                            'next_offset': i + 1 if i + 1 < total else None},
                                           ensure_ascii=False).encode('utf-8'))
                      for i, size in enumerate(shown_sizes)]
        shown_bytes = 2 + sum(shown_sizes) + 2 * max(total - 1, 0)
        if any(size > self._max_page_bytes for size in page_sizes) or shown_bytes + notice_bytes > self._max_bytes:
            return DemobPreview(site, 'limit', 'Subnet lookup exceeds the preview limit; narrow the lookup.')
        if control is not None:
            control.checkpoint()
        networks, terms = prepare_demob_terms(ctx, site, valid_rows)
        search_scope = DemobSearchScope(site, networks, terms, status, message, list(notices))
        if not demob_scope_within_limits(search_scope):
            return DemobPreview(site, 'limit', 'Demobilization search scope exceeds its limits.')
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode('ascii')).digest()
        with self._lock:
            if self._generation != generation:
                return DemobPreview(site, 'cancelled', 'This lookup was replaced or cancelled.')
            self._entry = (digest, self._clock() + 300, search_scope, shown_rows)
        return DemobPreview(site, status, message, notices, row_count=len(shown_rows), token=token)
