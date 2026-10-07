from __future__ import annotations

import json
import threading
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import quote

from core.base import Credentials, ScriptContext
from utils.display import get_global_color_scheme
from utils.validation import site_comment_regex
from utils.infoblox_safety import (
    infoblox_debug_payloads_enabled,
    redact_infoblox_uri,
)
from utils.network_views import NETWORK_VIEW, configured_view, scope_network
from utils.process_data import process_data

# requests and urllib3 load on the first Infoblox request, not at start: every other command (ping, diff,
# doctor without Infoblox, the menu's start) never pays for them. See "Start-up Budget" in
# docs/ARCHITECTURE.md. The names below are for annotations only.
if TYPE_CHECKING:
    import requests
    from requests.adapters import HTTPAdapter

# WAPI paging: one page holds WAPI_PAGE_SIZE rows and a paged request follows at most
# WAPI_MAX_PAGES pages, so a paged result never exceeds WAPI_MAX_ROWS rows.
WAPI_PAGE_SIZE = 1000
WAPI_MAX_PAGES = 10
WAPI_MAX_ROWS = WAPI_PAGE_SIZE * WAPI_MAX_PAGES

_WAPI_TEXT_LIMIT = 120  # characters of a WAPI error text quoted back to the user
_DEFAULT_INFOBLOX_MAX_WORKERS = 8
_MAX_INFOBLOX_MAX_WORKERS = 32
# Guards the pool size, the https adapter and the building of the session. Re-entrant: the session proxy
# takes it to build, and configure_infoblox_session holds it while it asks the proxy to remount.
_adapter_lock = threading.RLock()
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
    """An https adapter with a connection pool of ``pool_size`` that retries idempotent requests on transient errors."""
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    retries = Retry(
        total=3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
        backoff_factor=2,
    )
    return HTTPAdapter(max_retries=retries, pool_connections=pool_size, pool_maxsize=pool_size)


def _session_is_built() -> bool:
    """False while the shared session is still the lazy stand-in that has not built the real one."""
    return not isinstance(session, _LazySession) or session.built


def configure_infoblox_session(ctx_or_cfg: Any) -> int:
    """
    Size the shared requests adapter to the configured Infoblox pool size.

    It imports nothing: until the first request builds the session, the size is only recorded and the
    builder uses it; afterwards the https adapter is replaced.
    """
    global adapter, _session_pool_size
    pool_size = get_infoblox_max_workers(ctx_or_cfg)
    with _adapter_lock:
        if pool_size == _session_pool_size:
            return pool_size
        if _session_is_built():
            adapter = _build_http_adapter(pool_size)
            session.mount("https://", adapter)
        _session_pool_size = pool_size
    return pool_size


def _build_session() -> requests.Session:
    """Create the shared HTTP session, with the https adapter sized for the Infoblox workers."""
    global adapter
    import requests

    adapter = _build_http_adapter(_session_pool_size)
    built = requests.Session()
    built.mount("https://", adapter)
    built.headers.update({"Content-Type": "application/json"})
    return built


class _LazySession:
    """
    Stands in for the shared ``requests.Session`` until something first touches it.

    Reading, setting or deleting any attribute (``get``, ``auth``, ``mount``, ``headers``) builds the
    real session once, under ``_adapter_lock``, and passes the access on to it. So ``utils.api.session``
    stays one patchable module attribute that ``utils.auth`` and the tests use as they always did, while
    ``requests`` and ``urllib3`` load only when a request, or the credentials for one, need them.
    """

    def __init__(self, factory: Callable[[], requests.Session]):
        object.__setattr__(self, "_factory", factory)
        object.__setattr__(self, "_real", None)

    @property
    def built(self) -> bool:
        """Whether the real session exists yet."""
        return self._real is not None

    def _resolve(self) -> requests.Session:
        real = self._real
        if real is None:
            with _adapter_lock:
                real = self._real  # another thread may have built it while this one waited
                if real is None:
                    real = self._factory()
                    object.__setattr__(self, "_real", real)
        return real

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__") and name.endswith("__"):
            # copy, pickle, inspect and the like ask for these: they must not load the library.
            raise AttributeError(name)
        return getattr(self._resolve(), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._resolve(), name, value)

    def __delattr__(self, name: str) -> None:
        delattr(self._resolve(), name)


# The https adapter of the session: None until the session is built.
adapter: Optional[HTTPAdapter] = None
session = _LazySession(_build_session)


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
    truncated: bool = False
    next_page_id: Optional[str] = None
    # Who sent the request, for the text of a refusal: "user 'svc-ipam' (password from INFOBLOX_PW)" when
    # Infoblox has an account of its own, "" for the shared login, whose text stays "Authentication failed
    # against Infoblox." (and for every result a caller builds without one).
    account: str = ""

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
    truncated: bool = False
    # Something the user should read although the search worked (menu and stderr only, not JSON):
    # the site code was found in subnet comments because no subnet carries the attribute ...
    note: str = ""
    # ... and an address family the attribute search could not cover (a grid capability, not a failure).
    skipped: str = ""

    @property
    def has_data(self) -> bool:
        return any(bool(items) for items in self.data.values())

    @property
    def notices(self) -> List[str]:
        """What a menu should print as warnings next to a working search: ``skipped``, then ``note``."""
        return [text for text in (self.skipped, self.note) if text]


def _build_response(status_code: int, content: bytes = b"", url: str = "") -> requests.Response:
    import requests

    response = requests.Response()
    response.status_code = status_code
    response._content = content
    response.url = url
    return response


def _normalize_items(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        result = payload.get("result")
        # a ``_return_as_object=1`` answer wraps the rows; any other object is one record
        return _normalize_items(result) if isinstance(result, list) else [payload]
    return []


def _wapi_error_text(content: bytes) -> str:
    """The ``text`` field of a WAPI error body on a single line ("" when there is none)."""
    try:
        payload = json.loads(content)
    except ValueError:
        return ""
    text = payload.get("text") if isinstance(payload, dict) else None
    return " ".join(text.split()) if isinstance(text, str) else ""


def _classify_http_status(status_code: int, body_text: str) -> str:
    """Map an HTTP error status (and the response body) to an ``InfobloxResult.status``."""
    if status_code in (401, 403):
        return "auth_error"
    if 500 <= status_code < 600:
        return "server_error"
    if status_code == 404:
        return "not_found"
    if status_code == 400 and "result set too large" in body_text.lower():
        return "too_many_results"
    return "invalid_query"


def describe_infoblox_failure(result: InfobloxResult) -> str:
    """
    The sentence that says why ``result`` failed (the same one that ``InfobloxResult.message`` holds).

    A refusal (``auth_error``: the grid answered 401 or 403) names the account when Infoblox has one of its
    own, ``Infoblox refused user 'svc-ipam' (password from INFOBLOX_PW).``, so the engineer knows which
    account to check. "Refused", not "rejected the credentials", because a 403 may also mean that the
    account has no permission. The shared login keeps ``Authentication failed against Infoblox.``
    """
    if result.status == "auth_error":
        if result.account:
            return f"Infoblox refused {result.account}."
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
    if result.status == "too_many_results":
        return "Infoblox: more than 1,000 records match. Narrow the search (longer prefix or smaller subnet)."
    if result.status == "invalid_query":
        message = f"Infoblox rejected the request ({result.status_code})"
        detail = _wapi_error_text(result.content)
        return f"{message}: {detail[:_WAPI_TEXT_LIMIT]}" if detail else f"{message}."
    if result.status == "not_found":
        return "No matching Infoblox records were found."
    return "Infoblox request failed."


def _infoblox_account(ctx: ScriptContext) -> Optional[Credentials]:
    """Infoblox's own account on ``ctx``, or None: a context without one, or a test double, uses the shared login."""
    account = getattr(ctx, "infoblox_credentials", None)
    return account if isinstance(account, Credentials) else None


def _account_label(account: Optional[Credentials]) -> str:
    """
    How a refusal names ``account``: ``user 'svc-ipam' (password from INFOBLOX_PW)``,
    ``... (password from GPG file <path>)`` or ``... (password typed at the prompt)``; "" for None.
    The password variable is printed as ``Credentials.source`` stores it (the one that gave the password).
    """
    if account is None:
        return ""
    label = f"user '{account.username}'"
    if not account.source:
        return label
    if account.source == "prompt":
        return f"{label} (password typed at the prompt)"
    return f"{label} (password from {account.source})"


class InfobloxClient:
    """
    Thin shared client for live Infoblox requests.

    When Infoblox has an account of its own (``ctx.infoblox_credentials``) the client guards it against
    lock-out, because a refused account may be locked for the whole team by a burst of refused logins.
    The first request of an account is sent alone: the requests behind it wait for its outcome (the gate).
    Any outcome but a 401 (an answer, a timeout, a connection failure) opens the gate and the rest run in
    parallel as usual; a 401 refuses the account, and from then on none of its requests is sent, each one
    returns the same ``auth_error`` result at once (the breaker). A wrong password therefore costs one
    refused login per run, whatever the number of objects and workers. A 401 that arrives later in the run
    trips the breaker too. The state belongs to one ``Credentials`` object, compared by identity, so a new
    object is tried again. The shared (TACACS) login, and a 403, never reach the gate or the breaker.
    """

    def __init__(self, http_session: requests.Session):
        self._session = http_session
        self._refused: Optional[Credentials] = None  # the grid answered 401 to this account in this process
        self._answered: Optional[Credentials] = None  # this account's first request ended in any other way
        self._first_login = threading.Lock()  # held only around the first request of an account

    def request(
        self,
        ctx: ScriptContext,
        uri: str,
        *,
        ensure_auth: bool = True,
        paged: bool = False,
        max_pages: int = WAPI_MAX_PAGES,
    ) -> InfobloxResult:
        """
        Run one WAPI GET. With ``paged=True`` the pages are followed (WAPI_PAGE_SIZE rows each,
        at most ``max_pages`` of them) and merged into one result; ``truncated`` says that more
        rows were left behind. A failing page is returned as it is.
        """
        if not paged:
            return self._request_once(ctx, uri, ensure_auth=ensure_auth)

        first_page_uri = uri
        for key, value in (("_paging", "1"), ("_return_as_object", "1"), ("_max_results", str(WAPI_PAGE_SIZE))):
            first_page_uri = _append_query_arg(first_page_uri, key, value)

        items: List[Dict[str, Any]] = []
        next_page_id: Optional[str] = None
        for _ in range(max(1, max_pages)):
            page_uri = first_page_uri if next_page_id is None else f"{first_page_uri}&_page_id={quote(next_page_id, safe='')}"
            page = self._request_once(ctx, page_uri, ensure_auth=ensure_auth)
            if not page.ok:
                return page
            items.extend(page.items)
            next_page_id = page.next_page_id
            if next_page_id is None:
                break
        return replace(page, items=items, content=json.dumps(items).encode(), truncated=next_page_id is not None)

    def _request_once(self, ctx: ScriptContext, uri: str, *, ensure_auth: bool = True) -> InfobloxResult:
        configure_infoblox_session(ctx)
        endpoint = str(ctx.cfg.get("api_endpoint") or "").strip()
        debug_payloads = infoblox_debug_payloads_enabled(ctx)
        redacted_uri = redact_infoblox_uri(uri)
        account: Optional[Credentials] = None  # Infoblox's own account: known once the login below has run

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
            next_page_id: Optional[str] = None,
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
                next_page_id=next_page_id,
                account=_account_label(account),
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

        account = _infoblox_account(ctx)
        full_url = f"{endpoint}{uri}"

        def build_http_failure(error_response: requests.Response, status_code: int) -> InfobloxResult:
            content = error_response.content or b""
            status = _classify_http_status(status_code, content.decode("utf-8", errors="replace"))
            # The account goes into this result too, so that ``message`` and describe_infoblox_failure(result) agree.
            message = describe_infoblox_failure(
                InfobloxResult(
                    status=status,
                    status_code=status_code,
                    response=error_response,
                    content=content,
                    uri=uri,
                    full_url=full_url,
                    account=_account_label(account),
                )
            )
            return build_result(
                status=status,
                status_code=status_code,
                response_obj=error_response,
                content=content,
                message=message,
                error_kind=status,
                full_url_value=full_url,
            )

        def not_sent(refused: Credentials) -> InfobloxResult:
            """The breaker's answer: the grid's 401 to this account, said again without asking it again."""
            ctx.logger.debug("Infoblox request not sent: the grid refused %s earlier in this run", refused.username)
            return build_http_failure(_build_response(401, url=full_url), 401)

        if account is not None and account is self._refused:
            return not_sent(account)

        # Resolved before the try block, so that its except clauses always have the classes. Nothing above
        # this line loads requests: a run that stops at the missing credentials never pays for it.
        from requests.exceptions import (
            ConnectionError as RequestsConnectionError,
            HTTPError,
            RequestException,
            SSLError,
            Timeout,
        )
        from urllib3.exceptions import InsecureRequestWarning

        verify_ssl = bool(ctx.cfg.get("api_verify_ssl", True))
        timeout = int(ctx.cfg.get("api_timeout", 10))

        def send() -> InfobloxResult:
            response = _build_response(500, url=full_url)

            try:
                with warnings.catch_warnings():
                    if not verify_ssl:
                        warnings.simplefilter("ignore", InsecureRequestWarning)
                    response = self._session.get(full_url, verify=verify_ssl, timeout=timeout)

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
                # requests.Response.__bool__ is ``.ok``, so every 4xx/5xx response is falsy: test for None
                error_response = exc.response if exc.response is not None else response
                return build_http_failure(error_response, error_response.status_code or 500)
            except RequestException as exc:
                error_response = getattr(exc, "response", None)
                if error_response is not None:
                    return build_http_failure(error_response, error_response.status_code or response.status_code or 500)
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
                next_page_id=(payload.get("next_page_id") or None) if isinstance(payload, dict) else None,
            )

        if account is not None and account is not self._answered:
            # The account's first request goes alone: the others wait for its outcome here (no prompt can be
            # open meanwhile, the login above has finished). A 401 refuses the account, anything else opens the gate.
            with self._first_login:
                if account is self._refused:
                    return not_sent(account)
                if account is not self._answered:
                    result = send()
                    if result.status_code == 401:
                        self._refused = account
                    else:
                        self._answered = account
                    return result
        result = send()
        if account is not None and result.status_code == 401:
            self._refused = account  # a 401 later in the run (the account was locked meanwhile) trips the breaker too
        return result


_INFOBLOX_CLIENT = InfobloxClient(session)


def get_infoblox_client() -> InfobloxClient:
    return _INFOBLOX_CLIENT


def request_result(
    ctx: ScriptContext,
    uri: str,
    *,
    ensure_auth: bool = True,
    paged: bool = False,
    max_pages: int = WAPI_MAX_PAGES,
) -> InfobloxResult:
    return get_infoblox_client().request(ctx, uri, ensure_auth=ensure_auth, paged=paged, max_pages=max_pages)


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

        # Only a 400 says anything about _inheritance (other codes are classified invalid_query too,
        # e.g. 429); and only a plain retry that succeeds proves the grid rejected the option.
        if result.status == "invalid_query" and result.status_code == 400:
            fallback_result = request_result(ctx, uri, ensure_auth=ensure_auth)
            if fallback_result.status_code == 400:
                return result  # the query itself is bad; inheritance is not the problem
            if fallback_result.ok:
                if endpoint_key:
                    with _inheritance_support_lock:
                        _inheritance_support_by_endpoint[endpoint_key] = False
                ctx.logger.info("Infoblox endpoint rejected _inheritance; falling back to plain subnet lookups for this session.")
            return fallback_result

        # Only an answer that accepted the option proves support: a 400 of either kind is ambiguous.
        if endpoint_key and (result.ok or result.status == "not_found"):
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


def site_ea_name(ctx: ScriptContext) -> str:
    """The extensible attribute that holds the site code (``[site] ea_name``); "" when none is configured."""
    return str(ctx.cfg.get("site_ea_name") or "").strip()


def site_attribute_filter(ea_name: str, code: str) -> str:
    """The WAPI search term matching the extensible attribute ``ea_name`` to ``code`` (``:=``: case-insensitive)."""
    return f"*{quote(ea_name, safe='')}:={quote(code, safe='')}"


# dhcp_utilization is an IPv4 ``network`` field: ``ipv6network`` answers 400 to it. Both ask for the
# ``network_view`` of each subnet, so one CIDR held by two network views comes back as two rows.
_NETWORK_FIELDS_IPV4 = "_return_fields=network,comment,dhcp_utilization,network_view"
_NETWORK_FIELDS_IPV6 = "_return_fields=network,comment,network_view"


def _query_families(
    ctx: ScriptContext, uri_ipv4: str, uri_ipv6: str, ensure_auth: bool
) -> Tuple[InfobloxResult, InfobloxResult]:
    """Run the paged IPv4 and IPv6 network queries in parallel; returns (IPv4 result, IPv6 result)."""
    with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, 2)) as executor:
        future_to_family = {
            executor.submit(request_result, ctx, uri_ipv4, ensure_auth=ensure_auth, paged=True): "ipv4",
            executor.submit(request_result, ctx, uri_ipv6, ensure_auth=ensure_auth, paged=True): "ipv6",
        }
        family_results = {future_to_family[future]: future.result() for future in future_to_family}
    return family_results["ipv4"], family_results["ipv6"]


def _network_result(
    ctx: ScriptContext,
    search_type: str,
    result_ipv4: InfobloxResult,
    result_ipv6: InfobloxResult,
) -> NetworkSearchResult:
    """
    Parse both families' answers as ``search_type``, merge them and judge the outcome.

    The merge drops (network, network view) duplicates and keeps the first row of each, in the
    order the grid returned them (IPv4, then IPv6): one CIDR in two network views stays two rows.
    """
    processed_data_ipv4: Dict[str, Any] = process_data(ctx, type=search_type, content=result_ipv4.content) if result_ipv4.ok else {}
    processed_data_ipv6: Dict[str, Any] = process_data(ctx, type=search_type, content=result_ipv6.content) if result_ipv6.ok else {}

    # Merge and deduplicate
    united_locations = processed_data_ipv4.get('location', []) + processed_data_ipv6.get('location', [])
    unique_networks: Set[Tuple[str, str]] = set()
    merged_locations: List[Dict[str, str]] = []

    for item in united_locations:
        key = (item['network'], item.get(NETWORK_VIEW, ""))
        if key not in unique_networks:
            unique_networks.add(key)
            merged_locations.append(item)

    failures = [lookup_result for lookup_result in (result_ipv4, result_ipv6) if lookup_result.failed]
    truncated = result_ipv4.truncated or result_ipv6.truncated

    if failures and not merged_locations:
        first_failure = failures[0]
        return NetworkSearchResult(
            data={"location": merged_locations},
            status="error",
            message=describe_infoblox_failure(first_failure),
            error_kind=first_failure.error_kind,
            failures=failures,
            truncated=truncated,
        )

    if failures:
        first_failure = failures[0]
        return NetworkSearchResult(
            data={"location": merged_locations},
            status="partial_error",
            message=describe_infoblox_failure(first_failure),
            error_kind=first_failure.error_kind,
            failures=failures,
            truncated=truncated,
        )

    return NetworkSearchResult(data={"location": merged_locations}, status="ok", truncated=truncated)


def _search_comments(
    ctx: ScriptContext, search_term: str, keyword: bool, ensure_auth: bool, network_view: str = ""
) -> NetworkSearchResult:
    """
    Subnets whose comment names the site code (``[site] comment_pattern``) or, for a keyword, contains it.
    A ``network_view`` limits the search to that view; "" searches every view.
    """
    if not keyword:
        # Match the site code in the subnet comment the way [site] comment_pattern defines it.
        comment_regex = site_comment_regex(search_term, ctx.cfg.get("site_comment_pattern"))
        encoded_pattern = selective_url_encode(comment_regex)
        search_type = f"location_{search_term}"
    else:
        encoded_pattern = selective_url_encode(search_term)
        search_type = "location_keyword"

    uri_ipv4 = scope_network(
        f"network?comment:~={encoded_pattern}&_max_results=1000&{_NETWORK_FIELDS_IPV4}", network_view
    )
    uri_ipv6 = scope_network(
        f"ipv6network?comment:~={encoded_pattern}&_max_results=1000&{_NETWORK_FIELDS_IPV6}", network_view
    )
    result_ipv4, result_ipv6 = _query_families(ctx, uri_ipv4, uri_ipv6, ensure_auth)
    return _network_result(ctx, search_type, result_ipv4, result_ipv6)


def _search_attribute_then_comments(
    ctx: ScriptContext, ea_name: str, code: str, ensure_auth: bool, network_view: str = ""
) -> NetworkSearchResult:
    """
    Subnets that carry the site code in the extensible attribute ``ea_name``; when none does, the
    subnets whose comment names it (the result then carries a ``note``). A failed attribute query
    never falls back: a mistyped ``[site] ea_name`` must not look like a site without subnets.
    A ``network_view`` limits both searches to that view; "" searches every view.
    """
    attribute_filter = site_attribute_filter(ea_name, code)
    result_ipv4, result_ipv6 = _query_families(
        ctx,
        scope_network(f"network?{attribute_filter}&{_NETWORK_FIELDS_IPV4}", network_view),
        scope_network(f"ipv6network?{attribute_filter}&{_NETWORK_FIELDS_IPV6}", network_view),
        ensure_auth,
    )

    skipped = ""
    if not result_ipv4.failed and result_ipv6.status == "invalid_query":
        # The attribute may be defined for IPv4 objects only: that is a grid capability, not a failure.
        skipped = f"IPv6 subnets not searched: {describe_infoblox_failure(result_ipv6)}"
        result_ipv6 = replace(result_ipv6, status="ok", items=[], content=b"[]")

    # The grid matched the attribute, and the comment need not name the site: no local comment filter.
    found = _network_result(ctx, "location_keyword", result_ipv4, result_ipv6)

    if found.status == "error":
        reason = found.message.rstrip(".")
        return replace(
            found,
            message=f"Site search by extensible attribute '{ea_name}' ([site] ea_name) failed: {reason}; check with: cn doctor",
        )

    if found.status == "ok" and not found.has_data:
        # Both answers came back empty. The comment search covers IPv6 as well, so nothing stays "skipped".
        by_comment = _search_comments(ctx, code, keyword=False, ensure_auth=ensure_auth, network_view=network_view)
        if by_comment.has_data:
            note = (
                f"No subnet has the extensible attribute {ea_name} = {code.upper()}; "
                f"matched {code.upper()} in subnet comments instead."
            )
            return replace(by_comment, note=note)
        return by_comment

    return replace(found, skipped=skipped)


def fetch_network_data(
    ctx: ScriptContext,
    search_term: str,
    keyword: bool = False,
    ensure_auth: bool = True,
    *,
    network_view: Optional[str] = None,
) -> NetworkSearchResult:
    """
    Fetches and processes IPv4 and IPv6 network data based on a search term.
    Merges results, removes (network, network view) duplicates keeping the first row, and returns
    the processed data.

    A site code is looked up in the extensible attribute ``[site] ea_name`` when one is configured
    (and in subnet comments when no subnet carries it), otherwise in subnet comments only; a keyword
    is always searched in subnet comments.

    ``network_view`` limits every query to one network view: None uses ``[api] network_view``,
    "" searches every view, a name searches that view.
    """

    colors = get_global_color_scheme(ctx.cfg)
    ea_name = "" if keyword else site_ea_name(ctx)
    view = configured_view(ctx) if network_view is None else network_view

    with ctx.console.status(
        status=f"[{colors['description']}]Fetching subnet data for [{colors['header']}]{search_term.upper()}[/]...[/]",
        spinner="dots12",
    ):
        if ea_name:
            return _search_attribute_then_comments(ctx, ea_name, search_term, ensure_auth, view)
        return _search_comments(ctx, search_term, keyword, ensure_auth, view)
