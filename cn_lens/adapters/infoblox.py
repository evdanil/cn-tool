"""cn-lens Infoblox adapter (Task 7).

Implements the ``LensAdapter`` Protocol against the existing Infoblox WAPI
helpers so that cn-lens workflows can query IP/prefix/FQDN/keyword data
without duplicating the request logic already in ``utils.api``.

Public surface
--------------
``lookup_ip(runtime, ip)``         → ``InfobloxIPResult``
``lookup_prefix(runtime, prefix)`` → ``InfobloxPrefixResult``
``lookup_fqdn(runtime, fqdn)``     → ``InfobloxFqdnResult``
``search_by_keyword(runtime, term, mode="keyword"|"site")``→ ``list[InfobloxRow]``

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

import re
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
    request_result_with_inheritance,
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
# Deep-dive result dataclasses (lookup_prefix_deep)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InfobloxDhcpRange:
    """One DHCP range record within a subnet."""

    start_addr: str
    end_addr: str
    member: str = ""
    failover_association: str = ""


@dataclass(frozen=True)
class InfobloxFixedAddress:
    """One fixed-address record within a subnet."""

    ip: str
    mac: str = ""
    name: str = ""


@dataclass(frozen=True)
class InfobloxDnsRecord:
    """One in-subnet DNS host record (from ipv4address?network=&usage=DNS)."""

    ip: str
    name: str = ""


@dataclass(frozen=True)
class InfobloxMember:
    """One DHCP/DNS member assigned to the subnet."""

    name: str
    ip: str = ""


@dataclass(frozen=True)
class InfobloxPrefixDeepResult:
    """Deep-dive result of a prefix (subnet) lookup against Infoblox.

    Includes all data fetched by ``lookup_prefix_deep``:
    * The base prefix info (comment, extattrs, DHCP options)
    * DHCP ranges with failover associations
    * Fixed addresses
    * In-subnet DNS records (ipv4address?network=&usage=DNS)
    * DHCP/DNS member assignments
    * Flag indicating whether the prefix is a network container
    """

    found: bool
    prefix: str
    network: str = ""
    comment: str = ""
    extattrs: tuple[Dict[str, Any], ...] = ()
    dhcp_options: tuple[Dict[str, Any], ...] = ()
    dhcp_ranges: tuple[InfobloxDhcpRange, ...] = ()
    fixed_addresses: tuple[InfobloxFixedAddress, ...] = ()
    dns_records: tuple[InfobloxDnsRecord, ...] = ()
    members: tuple[InfobloxMember, ...] = ()
    inherited_comment: bool = False
    is_container: bool = False
    findings: tuple[LensFinding, ...] = ()


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
            "&_max_results=1"
        )
        uri = f"network?network={prefix}&{fields}"
        result: InfobloxResult = request_result_with_inheritance(runtime.context, uri, ensure_auth=False)
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
        encoded_fqdn = selective_url_encode(fqdn)
        uri = (
            f"search?fqdn~={encoded_fqdn}"
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


def search_by_keyword(
    runtime: "LensRuntime",
    term: str,
    mode: str = "keyword",
) -> List[InfobloxRow]:
    """Search Infoblox for networks whose comment matches a keyword or site code.

    Issues parallel IPv4 + IPv6 network queries and returns de-duplicated rows.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.
    term:
        Search term.  In ``keyword`` mode the raw term is used as a regex
        substring match.  In ``site`` mode an anchored regex is built that
        mirrors the cn-tool ground truth in ``utils.api.fetch_network_data``
        (``keyword=False`` branch): ``^[^;]+;\\s*TERM\\s*(;|$)``, which matches
        the Infoblox comment convention ``COUNTRY; SITE; description`` exactly at
        the second semicolon-delimited field.
    mode:
        ``"keyword"`` (default) — unanchored comment substring match, behaviour
        unchanged from prior releases.
        ``"site"`` — anchored regex that prevents embedded substring hits such as
        site code ``SYD`` matching comment ``"busyday"``.
        Any other value raises ``ValueError``.

    Returns
    -------
    list[InfobloxRow]
        Possibly empty; never raises.

    Raises
    ------
    ValueError
        If ``mode`` is not ``"keyword"`` or ``"site"``.
    """
    if mode not in ("keyword", "site"):
        raise ValueError(f"search_by_keyword: invalid mode {mode!r}; expected 'keyword' or 'site'")

    if runtime.offline or _is_not_configured(runtime):
        return []

    if not _ensure_auth(runtime):
        return []

    try:
        if mode == "site":
            # Mirror utils/api.py fetch_network_data keyword=False branch exactly:
            # padded_search_term = rf'^[^;]+;\s*{search_term}\s*(;|$)'
            # encoded_pattern = selective_url_encode(padded_search_term)
            # NOTE: unlike utils/api.py (which injects the raw term), lens is
            # deliberately stricter and applies re.escape() so that site codes
            # containing regex metacharacters (e.g. "SYD.01") are matched
            # literally rather than as regex patterns.
            padded = rf'^[^;]+;\s*{re.escape(term)}\s*(;|$)'
            encoded = selective_url_encode(padded)
        else:
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
        "cn-lens infoblox adapter: search_by_keyword %r (mode=%s) → %d rows",
        term, mode, len(rows),
    )
    return rows


# ---------------------------------------------------------------------------
# Adapter class (satisfies LensAdapter Protocol)
# ---------------------------------------------------------------------------

def _decode_dhcp_option_value(name: str, raw_value: str) -> str:
    """Return a human-readable decoded value for common DHCP option types.

    Mirrors the option-value decoding done in cn-tool's ``process_data``
    helper (``parser_type="DHCP options"``): option 3/routers and option 6/
    domain-name-servers values are already IP strings — returned as-is.
    Binary/hex values would need further decoding; for the current parity
    scope we return the raw value unchanged.

    Parameters
    ----------
    name:
        DHCP option name (e.g. ``"routers"``).
    raw_value:
        Raw string value from the Infoblox WAPI response.

    Returns
    -------
    str
        Decoded value (or the original ``raw_value`` when no decoding applies).
    """
    # For the common IP-bearing options the raw value is already the decoded
    # IP string; nothing further is needed.
    return raw_value


def _parse_ranges(items: List[Dict[str, Any]]) -> List[InfobloxDhcpRange]:
    """Parse a list of range WAPI items into ``InfobloxDhcpRange`` objects."""
    ranges: List[InfobloxDhcpRange] = []
    for item in items:
        member_raw = item.get("member") or {}
        member_name = (
            member_raw.get("name", "")
            if isinstance(member_raw, dict)
            else str(member_raw)
        )
        failover_raw = item.get("failover_association") or {}
        failover_name = (
            failover_raw.get("name", "")
            if isinstance(failover_raw, dict)
            else str(failover_raw)
        )
        ranges.append(InfobloxDhcpRange(
            start_addr=item.get("start_addr", ""),
            end_addr=item.get("end_addr", ""),
            member=member_name,
            failover_association=failover_name,
        ))
    return ranges


def _parse_fixed_addresses(items: List[Dict[str, Any]]) -> List[InfobloxFixedAddress]:
    """Parse a list of fixedaddress WAPI items."""
    return [
        InfobloxFixedAddress(
            ip=item.get("ipv4addr", ""),
            mac=item.get("mac", ""),
            name=item.get("name", ""),
        )
        for item in items
    ]


def _parse_dns_records(items: List[Dict[str, Any]]) -> List[InfobloxDnsRecord]:
    """Parse in-subnet DNS records (ipv4address?network=&usage=DNS)."""
    records: List[InfobloxDnsRecord] = []
    for item in items:
        ip = item.get("ip_address", "")
        names_raw = item.get("names", [])
        name = names_raw[0] if names_raw else ""
        if ip:
            records.append(InfobloxDnsRecord(ip=ip, name=name))
    return records


def _parse_members(items: List[Dict[str, Any]]) -> List[InfobloxMember]:
    """Parse network/member items into ``InfobloxMember`` objects."""
    members: List[InfobloxMember] = []
    for item in items:
        # Member items may be dicts with "name"+"ipv4addr" or plain strings.
        if isinstance(item, dict):
            name = item.get("name", "")
            ip = item.get("ipv4addr", "")
        else:
            name = str(item)
            ip = ""
        if name:
            members.append(InfobloxMember(name=name, ip=ip))
    return members


def _parse_deep_prefix(
    network_items: List[Dict[str, Any]],
    range_items: List[Dict[str, Any]],
    fixed_items: List[Dict[str, Any]],
    dns_items: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Parse all deep-dive query results into a structured dict.

    Parameters mirror the four parallel fan-out requests in
    ``lookup_prefix_deep``.
    """
    if not network_items:
        return {}

    data = normalize_record_fields(
        network_items[0],
        scalar_fields=("comment",),
        extattrs_fields=("extattrs",),
        list_struct_fields=("options", "members"),
    )

    extattrs_raw = data.get("extattrs", {})
    extattrs: List[Dict[str, Any]] = []
    if isinstance(extattrs_raw, dict):
        for key, rec in extattrs_raw.items():
            val = rec.get("value", "") if isinstance(rec, dict) else str(rec)
            extattrs.append({"attribute": key, "value": val})

    options_raw = data.get("options", [])
    dhcp_options: List[Dict[str, Any]] = []
    if isinstance(options_raw, list):
        for opt in options_raw:
            if isinstance(opt, dict):
                raw_val = opt.get("value", "")
                dhcp_options.append({
                    "name": opt.get("name", ""),
                    "num": str(opt.get("num", "")),
                    "value": raw_val,
                    "decoded_value": _decode_dhcp_option_value(
                        opt.get("name", ""), raw_val
                    ),
                    "vendor_class": opt.get("vendor_class", ""),
                    "use_option": str(opt.get("use_option", "")),
                })

    members_raw = data.get("members", [])
    members = _parse_members(members_raw if isinstance(members_raw, list) else [])

    inheritance = data.get("_inheritance", {})
    comment_meta = inheritance.get("comment", {}) if isinstance(inheritance, dict) else {}
    inherited_comment = bool(comment_meta.get("inherited") or comment_meta.get("multisource"))

    return {
        "network": data.get("network", ""),
        "comment": data.get("comment", ""),
        "extattrs": extattrs,
        "dhcp_options": dhcp_options,
        "members": members,
        "inherited_comment": inherited_comment,
        "dhcp_ranges": _parse_ranges(range_items),
        "fixed_addresses": _parse_fixed_addresses(fixed_items),
        "dns_records": _parse_dns_records(dns_items),
    }


# ---------------------------------------------------------------------------
# Deep lookup public functions
# ---------------------------------------------------------------------------


def contains_address(runtime: "LensRuntime", ip: str) -> "InfobloxPrefixResult":
    """Find the containing subnet for a bare IP address.

    Wraps ``network?contains_address=<ip>`` — the same query used by
    ``modules/subnet_request.py:_resolve_single_input_detailed`` for /32 inputs.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.
    ip:
        IPv4 address string (no CIDR suffix).

    Returns
    -------
    InfobloxPrefixResult
        ``found=True`` with the parent subnet when found; ``found=False`` otherwise.
        Never raises.
    """
    _disabled_result = InfobloxPrefixResult(found=False, prefix=ip)

    if runtime.offline or _is_not_configured(runtime):
        return _disabled_result

    if not _ensure_auth(runtime):
        return InfobloxPrefixResult(
            found=False,
            prefix=ip,
            findings=(
                _error_finding(
                    "credentials unavailable — Infoblox contains_address skipped",
                    {"ip": ip},
                ),
            ),
        )

    try:
        uri = f"network?contains_address={ip}&_return_fields=network,comment&_max_results=1"
        result: InfobloxResult = request_result(runtime.context, uri, ensure_auth=False)
    except Exception as exc:
        runtime.logger.error(
            "cn-lens infoblox adapter: unexpected error in contains_address: %s", exc
        )
        return InfobloxPrefixResult(
            found=False,
            prefix=ip,
            findings=(_error_finding(str(exc), {"ip": ip}),),
        )

    if result.status == "not_found" or not result.items:
        runtime.logger.debug(
            "cn-lens infoblox adapter: contains_address %s → no parent found", ip
        )
        return InfobloxPrefixResult(
            found=False,
            prefix=ip,
            findings=(_not_found_finding(ip),),
        )

    if result.failed:
        msg = describe_infoblox_failure(result)
        return InfobloxPrefixResult(
            found=False,
            prefix=ip,
            findings=(_error_finding(msg, {"ip": ip}),),
        )

    item = result.items[0]
    parent_network = item.get("network", "")
    runtime.logger.info(
        "cn-lens infoblox adapter: contains_address %s → %s", ip, parent_network
    )
    return InfobloxPrefixResult(
        found=True,
        prefix=ip,
        network=parent_network,
        comment=item.get("comment", ""),
    )


def network_container_children(runtime: "LensRuntime", prefix: str) -> List[str]:
    """Return child subnet prefixes of a network container.

    Wraps ``network?network_container=<prefix>`` — mirrors
    ``modules/subnet_request.py:_resolve_single_input_detailed`` for prefixlen<30.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.
    prefix:
        CIDR notation string (e.g. ``"10.0.0.0/16"``).

    Returns
    -------
    list[str]
        Child CIDR strings.  Empty on error or when none found.  Never raises.
    """
    if runtime.offline or _is_not_configured(runtime):
        return []

    if not _ensure_auth(runtime):
        return []

    try:
        uri = (
            f"network?network_container={prefix}"
            "&_return_fields=network&_max_results=500"
        )
        result: InfobloxResult = request_result(runtime.context, uri, ensure_auth=False)
    except Exception as exc:
        runtime.logger.error(
            "cn-lens infoblox adapter: unexpected error in network_container_children: %s",
            exc,
        )
        return []

    if not result.ok or not result.items:
        return []

    children = [item["network"] for item in result.items if item.get("network")]
    runtime.logger.info(
        "cn-lens infoblox adapter: network_container_children %s → %d children",
        prefix, len(children),
    )
    return children


def lookup_prefix_deep(runtime: "LensRuntime", prefix: str) -> "InfobloxPrefixDeepResult":
    """Deep-dive lookup for a subnet prefix: fan-out across all related WAPI objects.

    Issues four parallel WAPI requests:
    1. ``network?network=<prefix>`` with inheritance (base info, members, options)
    2. ``range?network=<prefix>`` (DHCP ranges with failover)
    3. ``fixedaddress?network=<prefix>`` (static IP assignments)
    4. ``ipv4address?network=<prefix>&usage=DNS`` (in-subnet DNS host records)

    This mirrors the four ``request_specs`` in
    ``modules/subnet_request.py:_fetch_all_data_for_subnet``.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.
    prefix:
        CIDR notation string (e.g. ``"10.0.0.0/24"``).

    Returns
    -------
    InfobloxPrefixDeepResult
        Always returned; never raises.
    """
    _disabled_result = InfobloxPrefixDeepResult(found=False, prefix=prefix)

    if runtime.offline or _is_not_configured(runtime):
        return _disabled_result

    if not _ensure_auth(runtime):
        return InfobloxPrefixDeepResult(
            found=False,
            prefix=prefix,
            findings=(
                _error_finding(
                    "credentials unavailable — Infoblox deep prefix lookup skipped",
                    {"prefix": prefix},
                ),
            ),
        )

    # Fan-out: four parallel requests mirroring the donor module's request_specs
    _request_map = {
        "network_bundle": (
            f"network?network={prefix}"
            "&_return_fields=network,comment,extattrs,options,members"
            "&_max_results=1",
            request_result_with_inheritance,
        ),
        "dns_records": (
            f"ipv4address?network={prefix}&usage=DNS&_return_fields=ip_address,names",
            request_result,
        ),
        "range_bundle": (
            f"range?network={prefix}"
            "&_return_fields=network,start_addr,end_addr,member,failover_association",
            request_result,
        ),
        "fixed_addresses": (
            f"fixedaddress?network={prefix}&_return_fields=ipv4addr,mac,name",
            request_result,
        ),
    }

    workers = bound_infoblox_workers(runtime.context, len(_request_map))
    results_map: Dict[str, InfobloxResult] = {}
    error_findings: List[LensFinding] = []

    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_key = {
                executor.submit(fn, runtime.context, uri, ensure_auth=False): key
                for key, (uri, fn) in _request_map.items()
            }
            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    results_map[key] = future.result()
                except Exception as exc:
                    runtime.logger.error(
                        "cn-lens infoblox adapter: lookup_prefix_deep[%s] failed: %s",
                        key, exc,
                    )
                    error_findings.append(
                        _error_finding(f"{key}: {exc}", {"prefix": prefix})
                    )
    except Exception as exc:
        runtime.logger.error(
            "cn-lens infoblox adapter: unexpected error in lookup_prefix_deep: %s", exc
        )
        return InfobloxPrefixDeepResult(
            found=False,
            prefix=prefix,
            findings=(_error_finding(str(exc), {"prefix": prefix}),),
        )

    net_result = results_map.get("network_bundle")
    if net_result is None or (net_result.status == "not_found") or not net_result.items:
        # Check if it might be a container (has children but no direct network record)
        children = network_container_children(runtime, prefix)
        if children:
            return InfobloxPrefixDeepResult(
                found=False,
                prefix=prefix,
                network=prefix,
                is_container=True,
                findings=tuple(error_findings),
            )
        runtime.logger.debug(
            "cn-lens infoblox adapter: lookup_prefix_deep %s → not found", prefix
        )
        return InfobloxPrefixDeepResult(
            found=False,
            prefix=prefix,
            findings=(_not_found_finding(prefix),) + tuple(error_findings),
        )

    if net_result.failed:
        msg = describe_infoblox_failure(net_result)
        return InfobloxPrefixDeepResult(
            found=False,
            prefix=prefix,
            findings=(_error_finding(msg, {"prefix": prefix}),) + tuple(error_findings),
        )

    # Normalize network bundle for inheritance
    normalized_net_items = [
        normalize_record_fields(
            item,
            scalar_fields=("comment",),
            extattrs_fields=("extattrs",),
            list_struct_fields=("options", "members"),
        )
        for item in net_result.items
    ]

    range_items = (
        results_map["range_bundle"].items
        if "range_bundle" in results_map and results_map["range_bundle"].ok
        else []
    )
    fixed_items = (
        results_map["fixed_addresses"].items
        if "fixed_addresses" in results_map and results_map["fixed_addresses"].ok
        else []
    )
    dns_items = (
        results_map["dns_records"].items
        if "dns_records" in results_map and results_map["dns_records"].ok
        else []
    )

    parsed = _parse_deep_prefix(normalized_net_items, range_items, fixed_items, dns_items)

    runtime.logger.info(
        "cn-lens infoblox adapter: lookup_prefix_deep %s → ok "
        "(ranges=%d fixed=%d dns=%d members=%d)",
        prefix,
        len(parsed.get("dhcp_ranges", [])),
        len(parsed.get("fixed_addresses", [])),
        len(parsed.get("dns_records", [])),
        len(parsed.get("members", [])),
    )

    return InfobloxPrefixDeepResult(
        found=True,
        prefix=prefix,
        network=parsed.get("network", ""),
        comment=parsed.get("comment", ""),
        extattrs=tuple(parsed.get("extattrs", [])),
        dhcp_options=tuple(parsed.get("dhcp_options", [])),
        dhcp_ranges=tuple(parsed.get("dhcp_ranges", [])),
        fixed_addresses=tuple(parsed.get("fixed_addresses", [])),
        dns_records=tuple(parsed.get("dns_records", [])),
        members=tuple(parsed.get("members", [])),
        inherited_comment=bool(parsed.get("inherited_comment", False)),
        findings=tuple(error_findings),
    )


def lookup_hop_site(runtime: "LensRuntime", ip: str) -> Dict[str, Optional[str]]:
    """Look up the Infoblox Site (and VLAN) extattr for a single IP address.

    This is the pure-logic port of ``plugins/trace_site_mapper.py``'s 2-step
    lookup logic:

    1. Resolve the IP to its containing network via
       ``ipv4address?ip_address=<ip>&_return_fields=network``.
    2. Fetch the network record and extract ``extattrs.Site`` (falling back to
       ``extattrs.Location`` when ``Site`` is absent) and ``extattrs.VLAN``.

    Unlike the donor plugin this function is standalone (no BasePlugin coupling)
    and is designed to be called per-hop in the trace site-verdict path.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.  Must be online and configured; the function
        returns ``{"site": None, "vlan": None}`` when offline or unconfigured.
    ip:
        An IPv4 address string (hop IP from a traceroute result).

    Returns
    -------
    dict with keys:
        ``"site"``  — site code string (uppercased) or ``None`` when unavailable.
        ``"vlan"``  — VLAN value string or ``None`` when unavailable.

    Notes
    -----
    - Never raises; on any error returns ``{"site": None, "vlan": None}``.
    - The donor's ``N/A_…`` sentinel strings are replaced by ``None`` so that
      the caller can use a simple truthiness check rather than string inspection.
    """
    _unknown: Dict[str, Optional[str]] = {"site": None, "vlan": None}

    if runtime.offline or _is_not_configured(runtime):
        return _unknown

    if not _ensure_auth(runtime):
        return _unknown

    try:
        # Step 1: resolve IP → containing network CIDR
        resolve_uri = f"ipv4address?ip_address={ip}&_return_fields=network"
        resp_resolve = request_result(runtime.context, resolve_uri, ensure_auth=False)
        if resp_resolve.failed or not resp_resolve.items:
            runtime.logger.debug(
                "cn-lens infoblox lookup_hop_site: no network for %s", ip
            )
            return _unknown
        network_cidr = str(resp_resolve.items[0].get("network", ""))
        if not network_cidr:
            return _unknown

        # Step 2: fetch network record → extract Site / VLAN extattrs
        details_uri = f"network?network={network_cidr}&_return_fields=extattrs"
        resp_details = request_result(runtime.context, details_uri, ensure_auth=False)
        if resp_details.failed or not resp_details.items:
            runtime.logger.debug(
                "cn-lens infoblox lookup_hop_site: no network record for %s", network_cidr
            )
            return _unknown

        record = resp_details.items[0]
        extattrs = record.get("extattrs", {})
        site_ea = extattrs.get("Site", {}).get("value")
        location_ea = extattrs.get("Location", {}).get("value")
        vlan_ea = extattrs.get("VLAN", {}).get("value")

        # Prefer Site, fall back to Location (mirrors donor plugin)
        if site_ea:
            site = str(site_ea).strip().upper()
        elif location_ea:
            site = str(location_ea).strip().upper()
        else:
            site = None

        return {
            "site": site,
            "vlan": str(vlan_ea) if vlan_ea is not None else None,
        }

    except Exception as exc:
        runtime.logger.debug(
            "cn-lens infoblox lookup_hop_site(%s) error: %s", ip, exc
        )
        return _unknown


def deep_health(runtime: "LensRuntime") -> AdapterHealth:
    """Perform a live reachability probe against the Infoblox grid endpoint.

    This function issues a real HTTP GET to ``/grid`` (a tiny, always-present
    Infoblox WAPI resource) **without credentials** and is intended for the
    doctor workflow (P2.2) only.  It must never be called from the normal
    workflow health-check path, which must remain config-only (see
    ``InfobloxAdapter.health``).

    The probe tests **reachability only** — it does NOT validate credentials.
    Authentication is validated lazily on the first real query.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.  Must be online and configured; callers should
        guard with ``_is_not_configured(runtime)`` before calling if needed.

    Returns
    -------
    AdapterHealth
        - ``ok``             — grid endpoint reachable (HTTP 200, 404, or 401).
          A 401 response proves the server is up and requires authentication;
          credentials are validated on the first real query, not here.
        - ``error``          — endpoint unreachable or returned an unexpected
          failure status (connection error, timeout, server error, etc.).
        - ``disabled``       — runtime is offline.
        - ``not_configured`` — endpoint placeholder / missing.

    Notes
    -----
    Wire this into the doctor workflow in P2.2 as::

        from cn_lens.adapters.infoblox import deep_health
        health = deep_health(runtime)
    """
    if runtime.offline:
        return AdapterHealth(status="disabled", detail="offline mode")

    if _is_not_configured(runtime):
        return AdapterHealth(
            status="not_configured",
            detail="api_endpoint not set in config",
        )

    # Lightweight reachability probe: fetch /grid (tiny payload, always present).
    # auth_error (HTTP 401) means the server replied — endpoint IS reachable.
    # Credentials are validated on the first real query, not by this probe.
    try:
        result = request_result(runtime.context, "grid", ensure_auth=False)
        if result.ok or result.status in ("not_found", "auth_error"):
            if result.status == "auth_error":
                return AdapterHealth(
                    status="ok",
                    detail=(
                        "endpoint reachable (HTTP 401 — authentication required; "
                        "credentials are validated on first real query)"
                    ),
                )
            return AdapterHealth(status="ok", detail="grid endpoint reachable")
        return AdapterHealth(
            status="error",
            detail=describe_infoblox_failure(result),
        )
    except Exception as exc:
        runtime.logger.warning(
            "cn-lens infoblox adapter: deep_health probe failed: %s", exc
        )
        return AdapterHealth(status="error", detail=str(exc))


class InfobloxAdapter:
    """cn-lens adapter for the Infoblox WAPI.

    Satisfies the ``LensAdapter`` Protocol: has a ``name`` class attribute and
    a ``health(runtime)`` method.  Does not inherit from any base class.

    Adapter ``name`` is ``"infoblox"``.
    """

    name: str = "infoblox"

    def health(self, runtime: "LensRuntime") -> AdapterHealth:
        """Return the adapter's availability for the given runtime.

        This method is **config-only** — it never issues HTTP requests.
        Expensive liveness probing belongs to the doctor workflow (P2.2);
        see ``deep_health(runtime)`` in this module for the probe function
        that doctor should call.

        Status mapping
        --------------
        - ``disabled``       — runtime is in offline mode.
        - ``not_configured`` — ``api_endpoint`` is absent or still the default
                               placeholder ``"API_URL"``.
        - ``ok``             — endpoint is configured (liveness probed by doctor).
        """
        if runtime.offline:
            return AdapterHealth(status="disabled", detail="offline mode")

        if _is_not_configured(runtime):
            return AdapterHealth(
                status="not_configured",
                detail="api_endpoint not set in config",
            )

        return AdapterHealth(
            status="ok",
            detail="endpoint configured (liveness probed by doctor)",
        )
