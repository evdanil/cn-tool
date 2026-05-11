"""cn-lens Infoblox adapter (Task 7).

Implements the ``LensAdapter`` Protocol against the existing Infoblox WAPI
helpers so that cn-lens workflows can query IP/prefix/FQDN/keyword data
without duplicating the request logic already in ``utils.api``.

Public surface
--------------
``lookup_ip(runtime, ip)``         → ``InfobloxIPResult``
``lookup_prefix(runtime, prefix)`` → ``InfobloxPrefixResult``
``lookup_fqdn(runtime, fqdn)``     → ``InfobloxFqdnResult``
``search_by_keyword(runtime, term)``→ ``list[InfobloxRow]``

The module-level singleton ``InfobloxAdapter`` satisfies the ``LensAdapter``
Protocol (``name = "infoblox"``, ``health(runtime) → AdapterHealth``).

Design notes
------------
- Auth is acquired once via ``runtime.ensure_credentials("infoblox")`` before
  any request.  In offline mode that raises ``RuntimeError``; the adapter
  catches it, logs a debug message, and returns a synthetic disabled result.
- No ``console``, ``print``, ``press_any_key``, or ``utils.user_input.*`` calls.
  All diagnostic output goes through ``runtime.logger``.
- Every public function is wrapped so it never raises; errors are surfaced as
  ``LensFinding`` entries on the result object.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from cn_lens.adapters.types import AdapterHealth, VALID_SOURCE_STATUSES
from cn_lens.models import LensFinding
from utils.api import (
    InfobloxResult,
    bound_infoblox_workers,
    describe_infoblox_failure,
    request_result,
    selective_url_encode,
)
from utils.infoblox_inheritance import normalize_record_fields

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


# ---------------------------------------------------------------------------
# Result dataclasses (frozen)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InfobloxIPResult:
    """Result of an IP address lookup against Infoblox."""

    found: bool
    ip: str
    network: str = ""
    name: str = ""
    status: str = ""
    lease_state: str = ""
    record_type: str = ""
    mac: str = ""
    findings: tuple[LensFinding, ...] = ()


@dataclass(frozen=True)
class InfobloxPrefixResult:
    """Result of a prefix (subnet) lookup against Infoblox."""

    found: bool
    prefix: str
    network: str = ""
    comment: str = ""
    extattrs: tuple[Dict[str, Any], ...] = ()
    dhcp_options: tuple[Dict[str, Any], ...] = ()
    inherited_comment: bool = False
    findings: tuple[LensFinding, ...] = ()


@dataclass(frozen=True)
class InfobloxFqdnResult:
    """Result of an FQDN lookup against Infoblox."""

    found: bool
    fqdn: str
    records: tuple[Dict[str, Any], ...] = ()
    findings: tuple[LensFinding, ...] = ()


@dataclass(frozen=True)
class InfobloxRow:
    """A single row from a keyword/location search."""

    network: str
    comment: str = ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _not_found_finding(source_target: str) -> LensFinding:
    return LensFinding(
        severity="info",
        source="infoblox",
        message="not_found",
        detail={"target": source_target},
    )


def _error_finding(message: str, detail: Optional[Dict[str, Any]] = None) -> LensFinding:
    return LensFinding(
        severity="error",
        source="infoblox",
        message=message,
        detail=detail or {},
    )


def _is_not_configured(runtime: "LensRuntime") -> bool:
    """Return True when the Infoblox endpoint is the default placeholder."""
    endpoint = str(runtime.cfg.get("api_endpoint") or "").strip()
    return not endpoint or endpoint == "API_URL"


def _ensure_auth(runtime: "LensRuntime") -> bool:
    """Call ensure_credentials; return False (and log) if it raises."""
    try:
        runtime.ensure_credentials("infoblox")
        return True
    except RuntimeError as exc:
        runtime.logger.debug("cn-lens infoblox adapter: credentials unavailable: %s", exc)
        return False


def _parse_ip_items(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract fields from the first item of an ipv4address result."""
    if not items:
        return {}
    data = items[0]
    return {
        "network": data.get("network", ""),
        "ip": str(data.get("_ref", "")).split(":")[-1],
        "name": ",".join(data.get("names", [])),
        "status": data.get("status", ""),
        "lease_state": data.get("lease_state", ""),
        "record_type": ",".join(data.get("types", [])),
        "mac": data.get("mac_address", ""),
    }


def _parse_prefix_items(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract fields from the first item of a network result.

    Applies ``normalize_record_fields`` to surface inherited field values
    (e.g. comment inherited from a parent network) before extraction.
    """
    if not items:
        return {}
    # Normalize the first item to unwrap Infoblox inheritance wrappers.
    # scalar_fields covers "comment" (may be inherited); extattrs_fields handles
    # extensible-attribute inheritance; list_struct_fields handles "options".
    data = normalize_record_fields(
        items[0],
        scalar_fields=("comment",),
        extattrs_fields=("extattrs",),
        list_struct_fields=("options",),
    )

    # Extensible attributes — already a normalized dict after normalize_record_fields
    extattrs_raw = data.get("extattrs", {})
    extattrs: List[Dict[str, Any]] = []
    if isinstance(extattrs_raw, dict):
        for key, rec in extattrs_raw.items():
            val = rec.get("value", "") if isinstance(rec, dict) else str(rec)
            extattrs.append({"attribute": key, "value": val})

    # DHCP options — already a list of dicts after normalize_record_fields
    options_raw = data.get("options", [])
    dhcp_options: List[Dict[str, Any]] = []
    if isinstance(options_raw, list):
        for opt in options_raw:
            if isinstance(opt, dict):
                dhcp_options.append({
                    "name": opt.get("name", ""),
                    "num": str(opt.get("num", "")),
                    "value": opt.get("value", ""),
                    "vendor_class": opt.get("vendor_class", ""),
                    "use_option": str(opt.get("use_option", "")),
                })

    # Detect inherited comment via _inheritance metadata set by normalize_record_fields
    inheritance = data.get("_inheritance", {})
    comment_meta = inheritance.get("comment", {}) if isinstance(inheritance, dict) else {}
    inherited_comment = bool(comment_meta.get("inherited") or comment_meta.get("multisource"))

    return {
        "network": data.get("network", ""),
        "comment": data.get("comment", ""),
        "extattrs": extattrs,
        "dhcp_options": dhcp_options,
        "inherited_comment": inherited_comment,
    }


def _parse_fqdn_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract ip/name pairs from an FQDN search result."""
    records = []
    for item in items:
        ip = item.get("ipv4addr") or item.get("ipv6addr", "")
        name = item.get("name", "")
        if ip or name:
            records.append({"ip": ip, "name": name})
    return records


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup_ip(runtime: "LensRuntime", ip: str) -> InfobloxIPResult:
    """Look up a single IP address in Infoblox.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.
    ip:
        IPv4 or IPv6 address string.

    Returns
    -------
    InfobloxIPResult
        Always returned (never raises).
    """
    _disabled_result = InfobloxIPResult(found=False, ip=ip)

    if runtime.offline or _is_not_configured(runtime):
        return _disabled_result

    if not _ensure_auth(runtime):
        return InfobloxIPResult(
            found=False,
            ip=ip,
            findings=(
                _error_finding(
                    "credentials unavailable — Infoblox lookup skipped",
                    {"ip": ip},
                ),
            ),
        )

    try:
        uri = (
            f"ipv4address?ip_address={ip}"
            "&_return_fields=network,names,status,types,lease_state,mac_address"
        )
        result: InfobloxResult = request_result(runtime.context, uri, ensure_auth=False)
    except Exception as exc:
        runtime.logger.error("cn-lens infoblox adapter: unexpected error in lookup_ip: %s", exc)
        return InfobloxIPResult(
            found=False,
            ip=ip,
            findings=(_error_finding(str(exc), {"ip": ip}),),
        )

    if result.status == "not_found" or not result.items:
        runtime.logger.debug("cn-lens infoblox adapter: lookup_ip %s → not found", ip)
        return InfobloxIPResult(
            found=False,
            ip=ip,
            findings=(_not_found_finding(ip),),
        )

    if result.failed:
        msg = describe_infoblox_failure(result)
        runtime.logger.warning("cn-lens infoblox adapter: lookup_ip %s → %s", ip, msg)
        return InfobloxIPResult(
            found=False,
            ip=ip,
            findings=(_error_finding(msg, {"ip": ip}),),
        )

    parsed = _parse_ip_items(result.items)
    runtime.logger.info("cn-lens infoblox adapter: lookup_ip %s → ok", ip)
    return InfobloxIPResult(
        found=True,
        ip=ip,
        network=parsed.get("network", ""),
        name=parsed.get("name", ""),
        status=parsed.get("status", ""),
        lease_state=parsed.get("lease_state", ""),
        record_type=parsed.get("record_type", ""),
        mac=parsed.get("mac", ""),
    )


def lookup_prefix(runtime: "LensRuntime", prefix: str) -> InfobloxPrefixResult:
    """Look up a subnet prefix in Infoblox.

    Retrieves general subnet info, extensible attributes, and DHCP options.
    Uses ``_inheritance=True`` where supported by the grid.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.
    prefix:
        CIDR notation string (e.g. ``"10.0.0.0/24"``).

    Returns
    -------
    InfobloxPrefixResult
        Always returned (never raises).
    """
    _disabled_result = InfobloxPrefixResult(found=False, prefix=prefix)

    if runtime.offline or _is_not_configured(runtime):
        return _disabled_result

    if not _ensure_auth(runtime):
        return InfobloxPrefixResult(
            found=False,
            prefix=prefix,
            findings=(
                _error_finding(
                    "credentials unavailable — Infoblox prefix lookup skipped",
                    {"prefix": prefix},
                ),
            ),
        )

    try:
        fields = (
            "_return_fields=network,comment,extattrs,options,members"
            "&_inheritance=True"
            "&_max_results=1"
        )
        uri = f"network?network={prefix}&{fields}"
        result: InfobloxResult = request_result(runtime.context, uri, ensure_auth=False)
    except Exception as exc:
        runtime.logger.error(
            "cn-lens infoblox adapter: unexpected error in lookup_prefix: %s", exc
        )
        return InfobloxPrefixResult(
            found=False,
            prefix=prefix,
            findings=(_error_finding(str(exc), {"prefix": prefix}),),
        )

    if result.status == "not_found" or not result.items:
        runtime.logger.debug(
            "cn-lens infoblox adapter: lookup_prefix %s → not found", prefix
        )
        return InfobloxPrefixResult(
            found=False,
            prefix=prefix,
            findings=(_not_found_finding(prefix),),
        )

    if result.failed:
        msg = describe_infoblox_failure(result)
        runtime.logger.warning(
            "cn-lens infoblox adapter: lookup_prefix %s → %s", prefix, msg
        )
        return InfobloxPrefixResult(
            found=False,
            prefix=prefix,
            findings=(_error_finding(msg, {"prefix": prefix}),),
        )

    parsed = _parse_prefix_items(result.items)
    runtime.logger.info("cn-lens infoblox adapter: lookup_prefix %s → ok", prefix)
    return InfobloxPrefixResult(
        found=True,
        prefix=prefix,
        network=parsed.get("network", ""),
        comment=parsed.get("comment", ""),
        extattrs=tuple(parsed.get("extattrs", [])),
        dhcp_options=tuple(parsed.get("dhcp_options", [])),
        inherited_comment=bool(parsed.get("inherited_comment", False)),
    )


def lookup_fqdn(runtime: "LensRuntime", fqdn: str) -> InfobloxFqdnResult:
    """Look up DNS records for a given FQDN in Infoblox.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.
    fqdn:
        Fully qualified domain name or prefix (≥ 1 character).

    Returns
    -------
    InfobloxFqdnResult
        Always returned (never raises).
    """
    _disabled_result = InfobloxFqdnResult(found=False, fqdn=fqdn)

    if runtime.offline or _is_not_configured(runtime):
        return _disabled_result

    if not _ensure_auth(runtime):
        return InfobloxFqdnResult(
            found=False,
            fqdn=fqdn,
            findings=(
                _error_finding(
                    "credentials unavailable — Infoblox FQDN lookup skipped",
                    {"fqdn": fqdn},
                ),
            ),
        )

    try:
        uri = (
            f"search?fqdn~={fqdn}"
            "&_return_fields=ipv4addr,ipv6addr,name"
            "&_max_results=1000"
        )
        result: InfobloxResult = request_result(runtime.context, uri, ensure_auth=False)
    except Exception as exc:
        runtime.logger.error(
            "cn-lens infoblox adapter: unexpected error in lookup_fqdn: %s", exc
        )
        return InfobloxFqdnResult(
            found=False,
            fqdn=fqdn,
            findings=(_error_finding(str(exc), {"fqdn": fqdn}),),
        )

    if result.status == "not_found" or not result.items:
        runtime.logger.debug(
            "cn-lens infoblox adapter: lookup_fqdn %s → not found", fqdn
        )
        return InfobloxFqdnResult(
            found=False,
            fqdn=fqdn,
            findings=(_not_found_finding(fqdn),),
        )

    if result.failed:
        msg = describe_infoblox_failure(result)
        runtime.logger.warning(
            "cn-lens infoblox adapter: lookup_fqdn %s → %s", fqdn, msg
        )
        return InfobloxFqdnResult(
            found=False,
            fqdn=fqdn,
            findings=(_error_finding(msg, {"fqdn": fqdn}),),
        )

    records = _parse_fqdn_items(result.items)
    runtime.logger.info("cn-lens infoblox adapter: lookup_fqdn %s → %d records", fqdn, len(records))
    return InfobloxFqdnResult(
        found=bool(records),
        fqdn=fqdn,
        records=tuple(records),
        findings=() if records else (_not_found_finding(fqdn),),
    )


def search_by_keyword(runtime: "LensRuntime", term: str) -> List[InfobloxRow]:
    """Search Infoblox for networks whose comment matches a keyword.

    Issues parallel IPv4 + IPv6 network queries and returns de-duplicated rows.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.
    term:
        Keyword string (plain text, regex-safe encoding is applied).

    Returns
    -------
    list[InfobloxRow]
        Possibly empty; never raises.
    """
    if runtime.offline or _is_not_configured(runtime):
        return []

    if not _ensure_auth(runtime):
        return []

    try:
        encoded = selective_url_encode(term)
        fields = "_return_fields=network,comment"
        uri_v4 = f"network?comment:~={encoded}&_max_results=1000&{fields}"
        uri_v6 = f"ipv6network?comment:~={encoded}&_max_results=1000&{fields}"

        workers = bound_infoblox_workers(runtime.context, 2)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(request_result, runtime.context, uri_v4, ensure_auth=False): "ipv4",
                executor.submit(request_result, runtime.context, uri_v6, ensure_auth=False): "ipv6",
            }
            family_results: Dict[str, InfobloxResult] = {
                family: future.result() for future, family in futures.items()
            }
    except Exception as exc:
        runtime.logger.error(
            "cn-lens infoblox adapter: unexpected error in search_by_keyword: %s", exc
        )
        return []

    rows: List[InfobloxRow] = []
    seen_networks: set[str] = set()

    for result in family_results.values():
        if not result.ok:
            continue
        for item in result.items:
            net = item.get("network", "")
            if net and net not in seen_networks:
                seen_networks.add(net)
                rows.append(InfobloxRow(
                    network=net,
                    comment=item.get("comment", ""),
                ))

    runtime.logger.info(
        "cn-lens infoblox adapter: search_by_keyword %r → %d rows", term, len(rows)
    )
    return rows


# ---------------------------------------------------------------------------
# Adapter class (satisfies LensAdapter Protocol)
# ---------------------------------------------------------------------------

class InfobloxAdapter:
    """cn-lens adapter for the Infoblox WAPI.

    Satisfies the ``LensAdapter`` Protocol: has a ``name`` class attribute and
    a ``health(runtime)`` method.  Does not inherit from any base class.

    Adapter ``name`` is ``"infoblox"``.
    """

    name: str = "infoblox"

    def health(self, runtime: "LensRuntime") -> AdapterHealth:
        """Return the adapter's availability for the given runtime.

        Status mapping
        --------------
        - ``disabled``       — runtime is in offline mode.
        - ``not_configured`` — ``api_endpoint`` is absent or still the default
                               placeholder ``"API_URL"``.
        - ``ok``             — endpoint is configured and a lightweight probe
                               (``/grid``) succeeds.
        - ``error``          — endpoint is configured but the probe fails.
        """
        if runtime.offline:
            return AdapterHealth(status="disabled", detail="offline mode")

        if _is_not_configured(runtime):
            return AdapterHealth(
                status="not_configured",
                detail="api_endpoint not set in config",
            )

        # Lightweight reachability probe: fetch /grid (tiny payload, always present).
        try:
            result = request_result(runtime.context, "grid", ensure_auth=False)
            if result.ok or result.status == "not_found":
                return AdapterHealth(status="ok", detail="")
            return AdapterHealth(
                status="error",
                detail=describe_infoblox_failure(result),
            )
        except Exception as exc:
            runtime.logger.warning(
                "cn-lens infoblox adapter: health probe failed: %s", exc
            )
            return AdapterHealth(status="error", detail=str(exc))
