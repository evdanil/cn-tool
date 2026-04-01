import json
import threading
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError as RequestsConnectionError, HTTPError, RequestException, SSLError, Timeout
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry

from core.base import ScriptContext
from utils.display import get_global_color_scheme
from utils.infoblox_safety import (
    infoblox_debug_payloads_enabled,
    redact_infoblox_uri,
)
from utils.process_data import process_data


retries = Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"],
    backoff_factor=2,
)

_DEFAULT_INFOBLOX_MAX_WORKERS = 8
_MAX_INFOBLOX_MAX_WORKERS = 32
_adapter_lock = threading.Lock()
_session_pool_size = _DEFAULT_INFOBLOX_MAX_WORKERS
_inheritance_support_by_endpoint: Dict[str, bool] = {}
_inheritance_support_lock = threading.Lock()
_inheritance_support_inflight: Dict[str, threading.Event] = {}


def _sanitize_infoblox_worker_limit(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = _DEFAULT_INFOBLOX_MAX_WORKERS
    return max(1, min(_MAX_INFOBLOX_MAX_WORKERS, number))


def get_infoblox_max_workers(ctx_or_cfg: Any) -> int:
    """Return the configured shared Infoblox worker ceiling."""
    cfg = getattr(ctx_or_cfg, "cfg", ctx_or_cfg)
    if isinstance(cfg, dict):
        return _sanitize_infoblox_worker_limit(cfg.get("api_max_workers", _DEFAULT_INFOBLOX_MAX_WORKERS))
    return _DEFAULT_INFOBLOX_MAX_WORKERS


def bound_infoblox_workers(ctx_or_cfg: Any, task_count: int) -> int:
    """Clamp a task count to the shared Infoblox worker ceiling."""
    if task_count <= 0:
        return 1
    return max(1, min(task_count, get_infoblox_max_workers(ctx_or_cfg)))


def _build_http_adapter(pool_size: int) -> HTTPAdapter:
    return HTTPAdapter(max_retries=retries, pool_connections=pool_size, pool_maxsize=pool_size)


def configure_infoblox_session(ctx_or_cfg: Any) -> int:
    """Resize the shared requests adapter to the configured Infoblox pool size."""
    global adapter, _session_pool_size
    pool_size = get_infoblox_max_workers(ctx_or_cfg)
    with _adapter_lock:
        if pool_size == _session_pool_size:
            return pool_size
        adapter = _build_http_adapter(pool_size)
        session.mount("https://", adapter)
        _session_pool_size = pool_size
    return pool_size


adapter = _build_http_adapter(_session_pool_size)
session = requests.Session()
session.mount("https://", adapter)
session.headers.update({"Content-Type": "application/json"})


@dataclass(frozen=True)
class InfobloxResult:
    """Normalized result for Infoblox requests."""

    status: str
    status_code: int
    response: requests.Response
    content: bytes = b""
    items: List[Dict[str, Any]] = field(default_factory=list)
    message: str = ""
    error_kind: str = ""
    uri: str = ""
    full_url: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def failed(self) -> bool:
        return self.status not in {"ok", "not_found"}

    @property
    def has_items(self) -> bool:
        return bool(self.items)


@dataclass(frozen=True)
class NetworkSearchResult:
    """Processed IPv4/IPv6 subnet search result."""

    data: Dict[str, List[Dict[str, str]]]
    status: str
    message: str = ""
    error_kind: str = ""
    failures: List[InfobloxResult] = field(default_factory=list)

    @property
    def has_data(self) -> bool:
        return any(bool(items) for items in self.data.values())


def _build_response(status_code: int, content: bytes = b"", url: str = "") -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response._content = content
    response.url = url
    return response


def _normalize_items(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


def describe_infoblox_failure(result: InfobloxResult) -> str:
    if result.status == "auth_error":
        return "Authentication failed against Infoblox."
    if result.status == "timeout":
        return "Infoblox request timed out."
    if result.status == "connection_lost":
        return "Infoblox did not respond in time. The request may have been too large or exceeded the server timeout."
    if result.status == "connection_error":
        return "Unable to reach the Infoblox API endpoint."
    if result.status == "tls_error":
        return "TLS verification failed while contacting Infoblox."
    if result.status == "server_error":
        return f"Infoblox server error ({result.status_code})."
    if result.status == "invalid_json":
        return "Infoblox returned an invalid JSON response."
    if result.status == "invalid_query":
        return f"Infoblox rejected the request ({result.status_code})."
    if result.status == "not_found":
        return "No matching Infoblox records were found."
    return "Infoblox request failed."


class InfobloxClient:
    """Thin shared client for live Infoblox requests."""

    def __init__(self, http_session: requests.Session):
        self._session = http_session

    def request(self, ctx: ScriptContext, uri: str, *, ensure_auth: bool = True) -> InfobloxResult:
        configure_infoblox_session(ctx)
        endpoint = str(ctx.cfg.get("api_endpoint") or "").strip()
        debug_payloads = infoblox_debug_payloads_enabled(ctx)
        redacted_uri = redact_infoblox_uri(uri)

        def build_result(
            *,
            status: str,
            status_code: int,
            response_obj: requests.Response,
            content: bytes,
            items: Optional[List[Dict[str, Any]]] = None,
            message: str = "",
            error_kind: str = "",
            full_url_value: str = "",
        ) -> InfobloxResult:
            result = InfobloxResult(
                status=status,
                status_code=status_code,
                response=response_obj,
                content=content,
                items=items or [],
                message=message,
                error_kind=error_kind,
                uri=uri,
                full_url=full_url_value,
            )
            if debug_payloads:
                ctx.logger.debug(
                    "Infoblox API request debug - uri=%s full_url=%s status=%s code=%s content=%r",
                    uri,
                    full_url_value,
                    status,
                    status_code,
                    content,
                )
            else:
                ctx.logger.debug(
                    "Infoblox API request - uri=%s status=%s code=%s bytes=%s",
                    redacted_uri,
                    status,
                    status_code,
                    len(content or b""),
                )
            return result

        if not endpoint or endpoint == "API_URL":
            response = _build_response(503)
            return build_result(
                status="connection_error",
                status_code=503,
                response_obj=response,
                content=response.content,
                message="Infoblox API endpoint is not configured.",
                error_kind="connection_error",
            )

        if ensure_auth:
            from utils.auth import ensure_infoblox_auth

            ensure_infoblox_auth(ctx)

        full_url = f"{endpoint}{uri}"
        verify_ssl = bool(ctx.cfg.get("api_verify_ssl", True))
        timeout = int(ctx.cfg.get("api_timeout", 10))
        response = _build_response(500, url=full_url)

        try:
            with warnings.catch_warnings():
                if not verify_ssl:
                    warnings.simplefilter("ignore", InsecureRequestWarning)
                response = self._session.get(full_url, verify=verify_ssl, timeout=timeout)

            if response.status_code in (400, 404):
                return build_result(
                    status="not_found",
                    status_code=response.status_code,
                    response_obj=response,
                    content=response.content,
                    message=describe_infoblox_failure(
                        InfobloxResult(
                            status="not_found",
                            status_code=response.status_code,
                            response=response,
                            uri=uri,
                            full_url=full_url,
                        )
                    ),
                    error_kind="not_found",
                    full_url_value=full_url,
                )

            if response.status_code in (401, 403):
                return build_result(
                    status="auth_error",
                    status_code=response.status_code,
                    response_obj=response,
                    content=response.content,
                    message="Authentication failed against Infoblox.",
                    error_kind="auth_error",
                    full_url_value=full_url,
                )

            response.raise_for_status()
        except Timeout:
            response = _build_response(504, url=full_url)
            return build_result(
                status="timeout",
                status_code=504,
                response_obj=response,
                content=response.content,
                message="Infoblox request timed out.",
                error_kind="timeout",
                full_url_value=full_url,
            )
        except SSLError:
            response = _build_response(495, url=full_url)
            return build_result(
                status="tls_error",
                status_code=495,
                response_obj=response,
                content=response.content,
                message="TLS verification failed while contacting Infoblox.",
                error_kind="tls_error",
                full_url_value=full_url,
            )
        except RequestsConnectionError as exc:
            exc_lower = str(exc).lower()
            if any(kw in exc_lower for kw in ("reset", "aborted", "disconnected", "broken pipe", "eof occurred", "timed out")):
                status = "connection_lost"
                message = "Infoblox did not respond in time. The request may have been too large or exceeded the server timeout."
            else:
                status = "connection_error"
                message = "Unable to reach the Infoblox API endpoint."
            response = _build_response(503, url=full_url)
            return build_result(
                status=status,
                status_code=503,
                response_obj=response,
                content=response.content,
                message=message,
                error_kind=status,
                full_url_value=full_url,
            )
        except HTTPError as exc:
            error_response = exc.response or response
            status_code = error_response.status_code or 500
            if status_code in (401, 403):
                status = "auth_error"
            elif 500 <= status_code < 600:
                status = "server_error"
            elif status_code in (400, 404):
                status = "not_found"
            else:
                status = "invalid_query"
            message = describe_infoblox_failure(
                InfobloxResult(status=status, status_code=status_code, response=error_response, uri=uri, full_url=full_url)
            )
            return build_result(
                status=status,
                status_code=status_code,
                response_obj=error_response,
                content=error_response.content,
                message=message,
                error_kind=status,
                full_url_value=full_url,
            )
        except RequestException as exc:
            error_response = getattr(exc, "response", None)
            if error_response is not None:
                status_code = error_response.status_code or response.status_code or 500
                if status_code in (401, 403):
                    status = "auth_error"
                elif 500 <= status_code < 600:
                    status = "server_error"
                elif status_code in (400, 404):
                    status = "not_found"
                else:
                    status = "invalid_query"
                message = describe_infoblox_failure(
                    InfobloxResult(status=status, status_code=status_code, response=error_response, uri=uri, full_url=full_url)
                )
                return build_result(
                    status=status,
                    status_code=status_code,
                    response_obj=error_response,
                    content=error_response.content,
                    message=message,
                    error_kind=status,
                    full_url_value=full_url,
                )
            return build_result(
                status="request_error",
                status_code=response.status_code or 500,
                response_obj=response,
                content=response.content,
                message="Infoblox request failed.",
                error_kind="request_error",
                full_url_value=full_url,
            )

        try:
            payload = response.json()
        except ValueError:
            return build_result(
                status="invalid_json",
                status_code=response.status_code,
                response_obj=response,
                content=response.content,
                message="Infoblox returned an invalid JSON response.",
                error_kind="invalid_json",
                full_url_value=full_url,
            )

        return build_result(
            status="ok",
            status_code=response.status_code,
            response_obj=response,
            content=response.content,
            items=_normalize_items(payload),
            message="",
            error_kind="",
            full_url_value=full_url,
        )


_INFOBLOX_CLIENT = InfobloxClient(session)


def get_infoblox_client() -> InfobloxClient:
    return _INFOBLOX_CLIENT


def request_result(ctx: ScriptContext, uri: str, *, ensure_auth: bool = True) -> InfobloxResult:
    return get_infoblox_client().request(ctx, uri, ensure_auth=ensure_auth)


def _append_query_arg(uri: str, key: str, value: str) -> str:
    if f"{key}=" in str(uri):
        return uri
    separator = "&" if "?" in str(uri) else "?"
    return f"{uri}{separator}{key}={value}"


def request_result_with_inheritance(ctx: ScriptContext, uri: str, *, ensure_auth: bool = True) -> InfobloxResult:
    """
    Request Infoblox data with `_inheritance=True` and automatically fall back
    once per endpoint when the grid rejects the option.
    """
    endpoint_key = str(ctx.cfg.get("api_endpoint") or "").strip()
    should_probe = False
    wait_event: Optional[threading.Event] = None
    use_plain_request = False

    with _inheritance_support_lock:
        cached_support = _inheritance_support_by_endpoint.get(endpoint_key)
        if cached_support is False:
            use_plain_request = True
        if endpoint_key and cached_support is None:
            wait_event = _inheritance_support_inflight.get(endpoint_key)
            if wait_event is None:
                wait_event = threading.Event()
                _inheritance_support_inflight[endpoint_key] = wait_event
                should_probe = True

    if use_plain_request:
        return request_result(ctx, uri, ensure_auth=ensure_auth)

    if endpoint_key and wait_event is not None and not should_probe:
        wait_event.wait()
        use_plain_request = False
        with _inheritance_support_lock:
            if _inheritance_support_by_endpoint.get(endpoint_key) is False:
                use_plain_request = True
        if use_plain_request:
            return request_result(ctx, uri, ensure_auth=ensure_auth)

    inherited_uri = _append_query_arg(uri, "_inheritance", "True")

    try:
        result = request_result(ctx, inherited_uri, ensure_auth=ensure_auth)

        if result.status_code == 400:
            fallback_result = request_result(ctx, uri, ensure_auth=ensure_auth)
            if fallback_result.status_code != 400:
                if endpoint_key:
                    with _inheritance_support_lock:
                        _inheritance_support_by_endpoint[endpoint_key] = False
                ctx.logger.info("Infoblox endpoint rejected _inheritance; falling back to plain subnet lookups for this session.")
                return fallback_result
            return result

        if endpoint_key and result.status_code and result.status_code != 400:
            with _inheritance_support_lock:
                _inheritance_support_by_endpoint[endpoint_key] = True
        return result
    finally:
        if should_probe and endpoint_key:
            with _inheritance_support_lock:
                event = _inheritance_support_inflight.pop(endpoint_key, None)
                if event is not None:
                    event.set()


def make_api_call(ctx: ScriptContext, uri: str) -> requests.Response:
    """
    Compatibility wrapper for older callers that still expect a Response.
    """
    return request_result(ctx, uri, ensure_auth=False).response


def do_fancy_request(
    ctx: ScriptContext,
    message: str,
    uri: str,
    spinner: Optional[str] = "dots12",
) -> Optional[bytes]:
    """
    Compatibility wrapper that preserves the previous content-or-None contract.
    """

    def execute_request() -> Optional[bytes]:
        result = request_result(ctx, uri)
        if result.ok:
            return result.content
        return None

    if spinner:
        with ctx.console.status(status=message, spinner=spinner):
            return execute_request()
    return execute_request()


# Function to selectively encode the regex pattern for Infoblox WAPI
def selective_url_encode(pattern: str) -> str:
    # Characters that need to be URL-encoded
    chars_to_encode = {"%", ";", "/", "?", ":", "@", "&", "=", "+", "$", ",", " "}
    encoded_pattern = ""
    for char in pattern:
        if char in chars_to_encode:
            encoded_pattern += f"%{ord(char):02X}"  # URL-encode the character
        else:
            encoded_pattern += char  # Leave the character as-is
    return encoded_pattern


def fetch_network_data(
    ctx: ScriptContext,
    search_term: str,
    keyword: bool = False,
    ensure_auth: bool = True,
) -> NetworkSearchResult:
    """
    Fetches and processes IPv4 and IPv6 network data based on a search term.
    Merges results, removes duplicates, and returns the processed data.
    """

    colors = get_global_color_scheme(ctx.cfg)
    search_type = ''

    if not keyword:
        # Build regex pattern for site code search
        padded_search_term = rf'^[^;]+;\s*{search_term}\s*(;|$)'
        encoded_pattern = selective_url_encode(padded_search_term)
        search_type = f"location_{search_term}"
    else:
        encoded_pattern = selective_url_encode(search_term)
        search_type = "location_keyword"

    fields = "_return_fields=network,comment"
    uri_ipv4 = f"network?comment:~={encoded_pattern}&_max_results=1000&{fields}"
    uri_ipv6 = f"ipv6network?comment:~={encoded_pattern}&_max_results=1000&{fields}"

    with ctx.console.status(
        status=f"[{colors['description']}]Fetching subnet data for [{colors['header']}]{search_term.upper()}[/]...[/]",
        spinner="dots12",
    ):
        with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, 2)) as executor:
            future_to_family = {
                executor.submit(request_result, ctx, uri_ipv4, ensure_auth=ensure_auth): "ipv4",
                executor.submit(request_result, ctx, uri_ipv6, ensure_auth=ensure_auth): "ipv6",
            }
            family_results = {future_to_family[future]: future.result() for future in future_to_family}

    result_ipv4 = family_results["ipv4"]
    result_ipv6 = family_results["ipv6"]

    # Process data
    processed_data_ipv4: Dict[str, Any] = process_data(ctx, type=search_type, content=result_ipv4.content) if result_ipv4.ok else {}
    processed_data_ipv6: Dict[str, Any] = process_data(ctx, type=search_type, content=result_ipv6.content) if result_ipv6.ok else {}

    # Merge and deduplicate
    united_locations = processed_data_ipv4.get('location', []) + processed_data_ipv6.get('location', [])
    unique_networks: Set[str] = set()
    merged_locations: List[Dict[str, str]] = []

    for item in united_locations:
        network = item['network']
        if network not in unique_networks:
            unique_networks.add(network)
            merged_locations.append(item)

    failures = [lookup_result for lookup_result in (result_ipv4, result_ipv6) if lookup_result.failed]

    if failures and not merged_locations:
        first_failure = failures[0]
        return NetworkSearchResult(
            data={"location": merged_locations},
            status="error",
            message=describe_infoblox_failure(first_failure),
            error_kind=first_failure.error_kind,
            failures=failures,
        )

    if failures:
        first_failure = failures[0]
        return NetworkSearchResult(
            data={"location": merged_locations},
            status="partial_error",
            message=describe_infoblox_failure(first_failure),
            error_kind=first_failure.error_kind,
            failures=failures,
        )

    return NetworkSearchResult(data={"location": merged_locations}, status="ok")
