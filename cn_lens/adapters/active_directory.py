"""Active Directory adapter for cn-lens.

Wraps ``utils.ad_helper`` (and mirrors the connection lifecycle from
``plugins.activedirectory_support``) to provide pure-data lookup functions
that return frozen dataclasses and ``LensFinding``-compatible dicts.

Public surface:
    name          — adapter identifier ``"ad"``
    health(runtime)  → AdapterHealth
    lookup_site(runtime, site_code_or_subnet)  → (AdSiteResult, list[dict])
    lookup_device(runtime, hostname)           → (AdDeviceResult, list[dict])
    enrich_ip(runtime, ip)                     → (AdIpEnrichment, list[dict])

Design notes:
- No ``print``, ``console``, or ``press_any_key`` — logger only.
- Offline mode: all public functions short-circuit immediately; zero LDAP I/O.
- AD not configured (``ad_enabled`` False or missing uri): returns not_configured
  health and not-found results with no findings beyond the standard status.
- LDAP/connection failure: returns ``error`` finding; never raises.
- Connection reuse: checks ``runtime.context._ad_connection`` (the attribute
  the ADSubnetEnrichmentPlugin stores) before creating a new connection.
  A newly-created connection is also stored on the context for subsequent
  calls within the same runtime lifetime.
"""
from __future__ import annotations

import socket
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from utils.ad_helper import (
    DEFAULT_OPERATION_TIMEOUT,
    DEFAULT_SEARCH_BASE,
    get_ad_subnet_info,
    init_ad_link,
)
from cn_lens.adapters.types import AdapterHealth
from cn_lens.models import LensFinding

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

# Module-level lock guarding the connection read-check-write cycle in _get_connection.
_CONNECTION_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Adapter identity
# ---------------------------------------------------------------------------

name: str = "ad"

# ---------------------------------------------------------------------------
# Return-value dataclasses (frozen so callers cannot mutate them)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdSiteResult:
    """AD site metadata resolved from a subnet or site-code query.

    Attributes
    ----------
    site_code:
        The CN of the AD site object (e.g. ``"SYD01"``).
    location:
        Free-text location string from the AD ``location`` attribute.
    country_code:
        ISO-3166 alpha-2 country code extracted from ``location`` if the
        string ends with ``, XX`` (e.g. ``"AU"``); empty string otherwise.
    ou_path:
        The distinguished name of the site object or subnet object found.
    found:
        ``True`` if an AD entry was located; ``False`` otherwise.
    """

    site_code: str
    location: str
    country_code: str
    ou_path: str
    found: bool


@dataclass(frozen=True)
class AdDeviceResult:
    """AD computer-object metadata for a device hostname.

    Attributes
    ----------
    ou_path:
        OU portion of the computer's distinguished name.
    last_site_code:
        Site code extracted from the ``siteObject`` attribute.
    computer_dn:
        Full distinguished name of the computer object.
    found:
        ``True`` if the computer was found in AD; ``False`` otherwise.
    """

    ou_path: str
    last_site_code: str
    computer_dn: str
    found: bool


@dataclass(frozen=True)
class AdIpEnrichment:
    """Result of an IP-address AD enrichment (reverse-DNS → AD device lookup).

    Attributes
    ----------
    resolved_hostname:
        The FQDN obtained by reverse-DNS (``socket.gethostbyaddr``); empty
        string if resolution failed.
    device_result:
        The AD device lookup result.  ``device_result.found`` is ``False``
        when the hostname could not be resolved or was not in AD.
    """

    resolved_hostname: str
    device_result: AdDeviceResult


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_NOT_FOUND_SITE = AdSiteResult(
    site_code="", location="", country_code="", ou_path="", found=False
)
_NOT_FOUND_DEVICE = AdDeviceResult(
    ou_path="", last_site_code="", computer_dn="", found=False
)

# Sentinel returned by _find_computer when an LDAP error occurs (distinct from
# None which means "not found").  Callers check ``entry is _LDAP_ERROR`` to
# generate an error finding instead of a not-found finding.
_LDAP_ERROR = object()


def _not_found_finding() -> LensFinding:
    return LensFinding(severity="info", source="ad", message="not_found", detail={})


def _error_finding(detail: str) -> LensFinding:
    return LensFinding(severity="error", source="ad", message="ldap_error", detail={"error": detail})


def _is_configured(runtime: "LensRuntime") -> bool:
    """Return True when AD is enabled and an LDAP URI is present in config."""
    cfg = runtime.cfg
    return bool(cfg.get("ad_enabled")) and bool(cfg.get("ad_uri", ""))


def _get_connection(runtime: "LensRuntime"):
    """Return a healthy LDAP connection, reusing one stored on the context if present.

    Checks ``runtime.context._ad_connection`` (the attribute the
    ADSubnetEnrichmentPlugin stores) before creating a new one.  A freshly
    opened connection is stored back for reuse by subsequent calls.

    A module-level ``threading.Lock`` guards the read-check-write cycle so
    concurrent calls from multiple threads open at most one connection.

    Returns ``None`` if the connection cannot be established.
    """
    ctx = runtime.context
    cfg = runtime.cfg

    # --- Fast path: reuse cached connection without acquiring the lock ---
    existing = getattr(ctx, "_ad_connection", None)
    if existing is not None:
        bound = getattr(existing, "bound", False)
        closed = getattr(existing, "closed", False)
        if bound and not closed:
            return existing

    # --- Slow path: acquire lock before the full check-open-store cycle ---
    with _CONNECTION_LOCK:
        # Re-check under the lock in case another thread already opened one.
        existing = getattr(ctx, "_ad_connection", None)
        if existing is not None:
            bound = getattr(existing, "bound", False)
            closed = getattr(existing, "closed", False)
            if bound and not closed:
                return existing
            # Stale — discard and reconnect below.
            try:
                existing.unbind()
            except Exception:
                pass
            ctx._ad_connection = None

        # --- Ensure credentials (non-interactive: already on context from auth) ---
        try:
            runtime.ensure_credentials("ad")
        except RuntimeError:
            # Offline mode — should not reach here (callers guard first), but be safe.
            runtime.logger.warning("AD adapter: ensure_credentials raised in offline mode.")
            return None

        timeout = cfg.get("ad_operation_timeout", DEFAULT_OPERATION_TIMEOUT)
        conn = init_ad_link(
            logger=runtime.logger,
            user=cfg.get("ad_user", ""),
            password=ctx.password,
            ldap_uri=cfg.get("ad_uri", ""),
            operation_timeout=timeout,
        )

        if conn:
            ctx._ad_connection = conn

        return conn


def _lookup_subnet_in_ad(
    runtime: "LensRuntime",
    conn,
    subnet: str,
) -> Dict[str, str]:
    """Call ``get_ad_subnet_info`` and return its result dict (may be empty)."""
    cfg = runtime.cfg
    search_base = cfg.get("ad_search_base", DEFAULT_SEARCH_BASE)
    timeout = cfg.get("ad_operation_timeout", DEFAULT_OPERATION_TIMEOUT)
    return get_ad_subnet_info(
        logger=runtime.logger,
        ldap_link=conn,
        subnet=subnet,
        search_base=search_base,
        operation_timeout=timeout,
    )


def _extract_country_code(location: str) -> str:
    """Extract trailing 2-letter code from a location string like 'Sydney, AU'."""
    if not location:
        return ""
    parts = location.rsplit(",", 1)
    if len(parts) == 2:
        code = parts[1].strip()
        if len(code) == 2 and code.isalpha():
            return code.upper()
    return ""


def _extract_site_from_dn(dn: str) -> str:
    """Extract the CN value from a site DN like 'CN=SYD01,CN=Sites,...'."""
    if not dn:
        return ""
    for part in dn.split(","):
        p = part.strip()
        if p.upper().startswith("CN="):
            return p.split("=", 1)[1]
    return ""


def _find_computer(runtime: "LensRuntime", conn, hostname: str):
    """Search AD for a computer object by hostname (sAMAccountName or CN).

    Returns
    -------
    - The first ldap3 Entry if found.
    - ``None`` if the computer was not found (clean not-found).
    - ``_LDAP_ERROR`` sentinel if an LDAP error occurs.

    Never re-raises ``LDAPException`` — callers check the return value.
    """
    cfg = runtime.cfg
    # Use the configuration base but switch to the domain root for computer search.
    # We derive the domain base from ad_search_base by looking for DC= parts.
    search_base_cfg = cfg.get("ad_search_base", DEFAULT_SEARCH_BASE)
    dc_parts = [p for p in search_base_cfg.split(",") if p.strip().upper().startswith("DC=")]
    search_base = ",".join(dc_parts) if dc_parts else search_base_cfg

    timeout = cfg.get("ad_operation_timeout", DEFAULT_OPERATION_TIMEOUT)

    # Strip domain suffix for sAMAccountName search
    short_name = hostname.split(".")[0]
    safe_name = escape_filter_chars(short_name)
    search_filter = f"(&(objectClass=computer)(|(sAMAccountName={safe_name}$)(cn={safe_name})))"

    try:
        conn.search(
            search_base,
            search_filter,
            attributes=["distinguishedName", "siteObject", "cn"],
            time_limit=timeout,
        )
        if conn.entries:
            return conn.entries[0]
        return None
    except LDAPException as exc:
        runtime.logger.error("AD adapter: LDAP error during computer search: %s", exc)
        return _LDAP_ERROR


# ---------------------------------------------------------------------------
# Protocol surface: health()
# ---------------------------------------------------------------------------


def health(runtime: "LensRuntime") -> AdapterHealth:
    """Return the adapter's health/availability for the given runtime.

    Returns
    -------
    AdapterHealth
        ``disabled``       — offline mode
        ``not_configured`` — AD not enabled or URI missing
        ``ok``             — connection opened successfully
        ``error``          — AD configured but connection failed
    """
    if runtime.offline:
        return AdapterHealth(status="disabled", detail="offline mode")

    if not _is_configured(runtime):
        return AdapterHealth(status="not_configured", detail="ad_enabled=False or ad_uri missing")

    conn = _get_connection(runtime)
    if conn is None:
        return AdapterHealth(status="error", detail="LDAP connection failed")

    return AdapterHealth(status="ok")


# ---------------------------------------------------------------------------
# Public: lookup_site
# ---------------------------------------------------------------------------


def lookup_site(
    runtime: "LensRuntime",
    site_code: str,
) -> Tuple[AdSiteResult, List[Dict[str, Any]]]:
    """Resolve a subnet (or site code) to AD site metadata.

    Parameters
    ----------
    site_code:
        A subnet CIDR (``"10.0.0.0/24"``) or a bare site code.  The function
        queries AD subnets using ``get_ad_subnet_info``.

    Returns
    -------
    (AdSiteResult, list[dict])
        Result dataclass and a list of finding dicts.
    """
    if runtime.offline:
        return _NOT_FOUND_SITE, []

    if not _is_configured(runtime):
        return _NOT_FOUND_SITE, []

    conn = _get_connection(runtime)
    if conn is None:
        return _NOT_FOUND_SITE, [_error_finding("LDAP connection failed")]

    try:
        ad_data = _lookup_subnet_in_ad(runtime, conn, site_code)
    except Exception as exc:
        runtime.logger.error("AD adapter: lookup_site error: %s", exc)
        return _NOT_FOUND_SITE, [_error_finding(str(exc))]

    if not ad_data:
        return _NOT_FOUND_SITE, [_not_found_finding()]

    location = ad_data.get("AD Location", "")
    country_code = _extract_country_code(location)
    site_cn = ad_data.get("AD Site", "") or ad_data.get("AD Name", "")

    # Build a representative OU path from the site name and search base.
    search_base = runtime.cfg.get("ad_search_base", DEFAULT_SEARCH_BASE)
    ou_path = f"CN={site_cn},{search_base}" if site_cn else search_base

    result = AdSiteResult(
        site_code=site_cn,
        location=location,
        country_code=country_code,
        ou_path=ou_path,
        found=True,
    )
    return result, []


# ---------------------------------------------------------------------------
# Public: lookup_device
# ---------------------------------------------------------------------------


def lookup_device(
    runtime: "LensRuntime",
    hostname: str,
) -> Tuple[AdDeviceResult, List[Dict[str, Any]]]:
    """Look up an AD computer object by hostname.

    Parameters
    ----------
    hostname:
        FQDN or short hostname of the device.

    Returns
    -------
    (AdDeviceResult, list[dict])
        Result dataclass and a list of finding dicts.
    """
    if runtime.offline:
        return _NOT_FOUND_DEVICE, []

    if not _is_configured(runtime):
        return _NOT_FOUND_DEVICE, []

    conn = _get_connection(runtime)
    if conn is None:
        return _NOT_FOUND_DEVICE, [_error_finding("LDAP connection failed")]

    try:
        entry = _find_computer(runtime, conn, hostname)
    except Exception as exc:
        runtime.logger.error("AD adapter: lookup_device error: %s", exc)
        return _NOT_FOUND_DEVICE, [_error_finding(str(exc))]

    if entry is _LDAP_ERROR:
        return _NOT_FOUND_DEVICE, [_error_finding("LDAP error during computer search")]
    if entry is None:
        return _NOT_FOUND_DEVICE, [_not_found_finding()]

    # Extract fields from the ldap3 Entry object.
    dn = str(entry.distinguishedName) if entry.distinguishedName else ""
    site_obj = str(entry.siteObject) if entry.siteObject else ""

    # OU path = everything after the first CN= component in the DN.
    ou_path = ""
    if dn:
        parts = dn.split(",", 1)
        ou_path = parts[1] if len(parts) > 1 else dn

    last_site_code = _extract_site_from_dn(site_obj)

    result = AdDeviceResult(
        ou_path=ou_path,
        last_site_code=last_site_code,
        computer_dn=dn,
        found=True,
    )
    return result, []


# ---------------------------------------------------------------------------
# Public: enrich_ip
# ---------------------------------------------------------------------------


def enrich_ip(
    runtime: "LensRuntime",
    ip: str,
) -> Tuple[AdIpEnrichment, List[Dict[str, Any]]]:
    """Enrich an IP address via reverse-DNS then AD device lookup.

    Steps:
    1. ``socket.gethostbyaddr(ip)`` → hostname.
    2. ``lookup_device(runtime, hostname)`` → AdDeviceResult.

    If reverse-DNS fails, returns an empty hostname and a not-found device.

    Parameters
    ----------
    ip:
        IPv4 address string.

    Returns
    -------
    (AdIpEnrichment, list[dict])
        Enrichment result and findings.
    """
    if runtime.offline:
        return AdIpEnrichment(resolved_hostname="", device_result=_NOT_FOUND_DEVICE), []

    if not _is_configured(runtime):
        return AdIpEnrichment(resolved_hostname="", device_result=_NOT_FOUND_DEVICE), []

    # --- Step 1: Reverse-DNS ---
    resolved_hostname = ""
    try:
        fqdn, _aliases, _addrs = socket.gethostbyaddr(ip)
        resolved_hostname = fqdn
    except (socket.herror, socket.gaierror, socket.timeout, OSError) as exc:
        runtime.logger.debug("AD adapter: reverse-DNS for %s failed: %s", ip, exc)

    if not resolved_hostname:
        return (
            AdIpEnrichment(resolved_hostname="", device_result=_NOT_FOUND_DEVICE),
            [],
        )

    # --- Step 2: AD device lookup ---
    device_result, findings = lookup_device(runtime, resolved_hostname)
    return AdIpEnrichment(resolved_hostname=resolved_hostname, device_result=device_result), findings
