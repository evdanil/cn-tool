"""Inspect workflow — classifies objects and, in online mode, queries live adapters.

Offline / None runtime
-----------------------
Returns the MVP-shape LensRun with a single classifier info finding per object
and the `not_queried` source status for every adapter.  No adapter I/O occurs.

Online runtime
--------------
Runs the per-object-type adapter composition defined below, collects findings
and structured summary blocks, and derives LensResult.sources from
registry.source_statuses(runtime).

Per-type adapter mapping
------------------------
IP     : infoblox.lookup_ip, ad.enrich_ip, config_repo.search,
         sdwan_yaml.search_by_keyword, dns.resolve_reverse
PREFIX : infoblox.lookup_prefix, config_repo.search, sdwan_yaml.lookup_prefix
FQDN   : infoblox.lookup_fqdn, dns.resolve_forward,
         dns.expand_fqdn_prefix (only for prefix-shape, see _is_fqdn_prefix),
         config_repo.search
SITE   : ad.lookup_site, sdwan_yaml.lookup_site, config_repo.search
DEVICE : ad.lookup_device, infoblox.search_by_keyword, config_repo.search

FQDN-prefix rule
----------------
expand_fqdn_prefix is called when the FQDN value has fewer than 3 dot-separated
labels (e.g. "host", "device1.corp") — i.e. it looks like a short hostname
prefix rather than a fully qualified domain name.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from cn_lens.adapters.registry import get_registry
from cn_lens.models import LensFinding, LensObject, LensObjectType, LensRun, ObjectSet
from cn_lens.workflows._helpers import (
    OFFLINE_FINDING_MESSAGE,
    CLASSIFIED_FINDING_MESSAGE,
    call_adapter,
    is_short_hostname,
    make_run_id,
    run_workflow,
    synthesise_error_finding as _synthesise_error_finding,
)

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


__all__ = [
    "OFFLINE_FINDING_MESSAGE",
    "CLASSIFIED_FINDING_MESSAGE",
    "make_run_id",
    "inspect_objects",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_fqdn_prefix(value: str) -> bool:
    """Return True when value looks like a hostname prefix (< 3 dot-separated labels).

    Rule: fewer than 3 labels → treat as FQDN prefix and call expand_fqdn_prefix.
    Examples:
        "host"            → True  (1 label)
        "device1.corp"    → True  (2 labels)
        "host.example.com"→ False (3 labels — full FQDN)
        "sub.host.ex.com" → False (4 labels)
    """
    return is_short_hostname(value)


def _classifier_finding(message: str = CLASSIFIED_FINDING_MESSAGE) -> LensFinding:
    """Return the initial classifier info finding (always present).

    Pass ``OFFLINE_FINDING_MESSAGE`` on the offline / None-runtime path;
    the default (``CLASSIFIED_FINDING_MESSAGE``) is used on the online path.
    """
    return LensFinding(
        severity="info",
        source="classifier",
        message=message,
        detail={"workflow": "inspect"},
    )


# ---------------------------------------------------------------------------
# Per-type adapter runners (online path)
# ---------------------------------------------------------------------------

def _run_ip(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    *,
    deep: bool = False,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run IP-specific adapters in documented order and return (summary, findings).

    Parameters
    ----------
    deep:
        When ``True``, also call ``infoblox.contains_address`` to find the
        parent subnet, then surface the parent network CIDR in the summary.
    """
    from cn_lens.adapters import infoblox, active_directory, config_repo, sdwan_yaml, dns

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = [_classifier_finding()]
    ip = obj.value

    # 1. infoblox.lookup_ip (always run, deep or not)
    def _ip_to_row(r) -> Dict[str, Any]:
        row: Dict[str, Any] = {
            "found": r.found,
            "ip": r.ip,
            "network": r.network,
            "name": r.name,
            "status": r.status,
            "lease_state": r.lease_state,
            "record_type": r.record_type,
            "mac": r.mac,
        }
        if deep:
            # Also find the parent subnet via contains_address
            try:
                parent = infoblox.contains_address(runtime, ip)
                row["parent_network"] = parent.network if parent.found else ""
                findings.extend(parent.findings)
            except Exception as exc:
                runtime.logger.error(
                    "inspect: infoblox.contains_address raised: %s", exc
                )
                row["parent_network"] = ""
        return row

    call_adapter(
        summary, "infoblox",
        fn=lambda: infoblox.lookup_ip(runtime, ip),
        to_row=_ip_to_row,
        findings=findings,
        log_prefix="inspect: infoblox.lookup_ip",
        on_success=lambda r: findings.extend(r.findings),
        on_error_extra={"found": False},
    )

    # 2. ad.enrich_ip
    call_adapter(
        summary, "ad",
        fn=lambda: active_directory.enrich_ip(runtime, ip),
        to_row=lambda r: {
            "resolved_hostname": r[0].resolved_hostname,
            "ou_path": r[0].device_result.ou_path,
            "last_site_code": r[0].device_result.last_site_code,
            "computer_dn": r[0].device_result.computer_dn,
            "found": r[0].device_result.found,
        },
        findings=findings,
        log_prefix="inspect: ad.enrich_ip",
        on_success=lambda r: findings.extend(r[1]),
        on_error_extra={"found": False},
    )

    # 3. config_repo.search
    call_adapter(
        summary, "config_repo",
        fn=lambda: config_repo.search(runtime, ip),
        to_row=lambda r: {
            "total_files_scanned": r.total_files_scanned,
            "match_count": len(r.matches),
            "truncated": r.truncated,
        },
        findings=findings,
        log_prefix="inspect: config_repo.search",
    )

    # 4. sdwan_yaml.search_by_keyword
    call_adapter(
        summary, "sdwan_yaml",
        fn=lambda: sdwan_yaml.search_by_keyword(runtime, ip),
        to_row=lambda r: {
            "match_count": len(r),
            "sites": list({m.site_code for m in r}),
        },
        findings=findings,
        log_prefix="inspect: sdwan_yaml.search_by_keyword",
    )

    # 5. dns.resolve_reverse
    call_adapter(
        summary, "dns",
        fn=lambda: dns.resolve_reverse(runtime, ip),
        to_row=lambda r: {
            "ptr": r.ptr,
            "status": r.status,
            "error": r.error,
        },
        findings=findings,
        log_prefix="inspect: dns.resolve_reverse",
    )

    return summary, findings


def _run_prefix(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    *,
    deep: bool = False,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run PREFIX-specific adapters in documented order.

    Parameters
    ----------
    deep:
        When ``True``, call ``infoblox.lookup_prefix_deep`` (fan-out to DHCP
        ranges, fixed addresses, in-subnet DNS records, member assignments, and
        decoded DHCP options) instead of the shallow ``infoblox.lookup_prefix``.
        Also checks whether the prefix is a network container and expands its
        children via ``infoblox.network_container_children``.
    """
    from cn_lens.adapters import infoblox, config_repo, sdwan_yaml, active_directory

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = [_classifier_finding()]
    prefix = obj.value

    if deep:
        # Deep path: fan-out to all related WAPI objects
        def _deep_to_row(r):
            row: Dict[str, Any] = {
                "found": r.found,
                "prefix": r.prefix,
                "network": r.network,
                "comment": r.comment,
                "inherited_comment": r.inherited_comment,
                "extattrs_count": len(r.extattrs),
                "dhcp_options_count": len(r.dhcp_options),
                "dhcp_ranges_count": len(r.dhcp_ranges),
                "fixed_addresses_count": len(r.fixed_addresses),
                "dns_records_count": len(r.dns_records),
                "members_count": len(r.members),
                "deep": True,
                "dhcp_ranges": [
                    {
                        "start_addr": rng.start_addr,
                        "end_addr": rng.end_addr,
                        "member": rng.member,
                        "failover_association": rng.failover_association,
                    }
                    for rng in r.dhcp_ranges
                ],
                "fixed_addresses": [
                    {"ip": fa.ip, "mac": fa.mac, "name": fa.name}
                    for fa in r.fixed_addresses
                ],
                "dns_records": [
                    {"ip": rec.ip, "name": rec.name}
                    for rec in r.dns_records
                ],
                "members": [
                    {"name": m.name, "ip": m.ip}
                    for m in r.members
                ],
                "dhcp_options": list(r.dhcp_options),
            }
            # Container expansion: when is_container, add children list
            if r.is_container:
                try:
                    children = infoblox.network_container_children(runtime, prefix)
                    row["container_children"] = children
                    row["container_children_count"] = len(children)
                    row["is_container"] = True
                except Exception as exc:
                    runtime.logger.error(
                        "inspect: network_container_children raised: %s", exc
                    )
                    row["container_children"] = []
                    row["container_children_count"] = 0
                    row["is_container"] = True
            return row

        call_adapter(
            summary, "infoblox",
            fn=lambda: infoblox.lookup_prefix_deep(runtime, prefix),
            to_row=_deep_to_row,
            findings=findings,
            log_prefix="inspect: infoblox.lookup_prefix_deep",
            on_success=lambda r: findings.extend(r.findings),
            on_error_extra={"found": False},
        )
    else:
        # Shallow path (default)
        call_adapter(
            summary, "infoblox",
            fn=lambda: infoblox.lookup_prefix(runtime, prefix),
            to_row=lambda r: {
                "found": r.found,
                "prefix": r.prefix,
                "network": r.network,
                "comment": r.comment,
                "inherited_comment": r.inherited_comment,
                "extattrs_count": len(r.extattrs),
                "dhcp_options_count": len(r.dhcp_options),
            },
            findings=findings,
            log_prefix="inspect: infoblox.lookup_prefix",
            on_success=lambda r: findings.extend(r.findings),
            on_error_extra={"found": False},
        )

    # 2. config_repo.search
    call_adapter(
        summary, "config_repo",
        fn=lambda: config_repo.search(runtime, prefix),
        to_row=lambda r: {
            "total_files_scanned": r.total_files_scanned,
            "match_count": len(r.matches),
            "truncated": r.truncated,
        },
        findings=findings,
        log_prefix="inspect: config_repo.search",
    )

    # 3. sdwan_yaml.lookup_prefix
    call_adapter(
        summary, "sdwan_yaml",
        fn=lambda: sdwan_yaml.lookup_prefix(runtime, prefix),
        to_row=lambda r: {
            "status": r.status,
            "site_code": r.site_code,
            "match_type": r.match_type,
        },
        findings=findings,
        log_prefix="inspect: sdwan_yaml.lookup_prefix",
        on_success=lambda r: findings.extend(r.findings),
    )

    # 4. active_directory.lookup_subnet — AD enrichment (site/location/description)
    call_adapter(
        summary, "ad",
        fn=lambda: active_directory.lookup_subnet(runtime, prefix),
        to_row=lambda r: {
            "found": r[0].found,
            "site": r[0].site,
            "location": r[0].location,
            "description": r[0].description,
        },
        findings=findings,
        log_prefix="inspect: active_directory.lookup_subnet",
        on_success=lambda r: findings.extend(r[1]),
        on_error_extra={"found": False},
    )

    return summary, findings


def _run_fqdn(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run FQDN-specific adapters in documented order."""
    from cn_lens.adapters import infoblox, dns, config_repo

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = [_classifier_finding()]
    fqdn = obj.value

    # 1. infoblox.lookup_fqdn
    call_adapter(
        summary, "infoblox",
        fn=lambda: infoblox.lookup_fqdn(runtime, fqdn),
        to_row=lambda r: {
            "found": r.found,
            "fqdn": r.fqdn,
            "record_count": len(r.records),
        },
        findings=findings,
        log_prefix="inspect: infoblox.lookup_fqdn",
        on_success=lambda r: findings.extend(r.findings),
        on_error_extra={"found": False},
    )

    # 2. dns.resolve_forward
    call_adapter(
        summary, "dns",
        fn=lambda: dns.resolve_forward(runtime, fqdn),
        to_row=lambda r: {
            "a_records": list(r.a_records),
            "aaaa_records": list(r.aaaa_records),
            "status": r.status,
        },
        findings=findings,
        log_prefix="inspect: dns.resolve_forward",
    )

    # 3. dns.expand_fqdn_prefix (only for prefix-shape values) — augments the
    # dns sub-block in-place; not structurally identical to the top-level
    # adapter pattern so kept as an explicit try/except.
    if _is_fqdn_prefix(fqdn):
        try:
            expansion = dns.expand_fqdn_prefix(runtime, fqdn)
            summary["dns"]["expansion"] = {
                "names": list(expansion.names),
                "status": expansion.status,
            }
        except Exception as exc:
            runtime.logger.error("inspect: dns.expand_fqdn_prefix raised unexpectedly: %s", exc)
            findings.append(_synthesise_error_finding("dns", exc))
            summary["dns"]["expansion"] = {"error": str(exc)}

    # 4. config_repo.search
    call_adapter(
        summary, "config_repo",
        fn=lambda: config_repo.search(runtime, fqdn),
        to_row=lambda r: {
            "total_files_scanned": r.total_files_scanned,
            "match_count": len(r.matches),
            "truncated": r.truncated,
        },
        findings=findings,
        log_prefix="inspect: config_repo.search",
    )

    return summary, findings


def _run_site(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run SITE-specific adapters in documented order."""
    from cn_lens.adapters import active_directory, sdwan_yaml, config_repo

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = [_classifier_finding()]
    site = obj.value

    # 1. ad.lookup_site
    call_adapter(
        summary, "ad",
        fn=lambda: active_directory.lookup_site(runtime, site),
        to_row=lambda r: {
            "found": r[0].found,
            "site_code": r[0].site_code,
            "location": r[0].location,
            "country_code": r[0].country_code,
            "ou_path": r[0].ou_path,
        },
        findings=findings,
        log_prefix="inspect: ad.lookup_site",
        on_success=lambda r: findings.extend(r[1]),
        on_error_extra={"found": False},
    )

    # 2. sdwan_yaml.lookup_site
    call_adapter(
        summary, "sdwan_yaml",
        fn=lambda: sdwan_yaml.lookup_site(runtime, site),
        to_row=lambda r: {
            "status": r.status,
            "site_name": r.site_name,
            "prefix_count": len(r.prefixes),
            "device_count": len(r.devices),
        },
        findings=findings,
        log_prefix="inspect: sdwan_yaml.lookup_site",
        on_success=lambda r: findings.extend(r.findings),
    )

    # 3. config_repo.search
    call_adapter(
        summary, "config_repo",
        fn=lambda: config_repo.search(runtime, site),
        to_row=lambda r: {
            "total_files_scanned": r.total_files_scanned,
            "match_count": len(r.matches),
            "truncated": r.truncated,
        },
        findings=findings,
        log_prefix="inspect: config_repo.search",
    )

    return summary, findings


def _run_device(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run DEVICE-specific adapters in documented order."""
    from cn_lens.adapters import active_directory, infoblox, config_repo

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = [_classifier_finding()]
    device = obj.value

    # 1. ad.lookup_device
    call_adapter(
        summary, "ad",
        fn=lambda: active_directory.lookup_device(runtime, device),
        to_row=lambda r: {
            "found": r[0].found,
            "ou_path": r[0].ou_path,
            "last_site_code": r[0].last_site_code,
            "computer_dn": r[0].computer_dn,
        },
        findings=findings,
        log_prefix="inspect: ad.lookup_device",
        on_success=lambda r: findings.extend(r[1]),
        on_error_extra={"found": False},
    )

    # 2. infoblox.search_by_keyword
    call_adapter(
        summary, "infoblox",
        fn=lambda: infoblox.search_by_keyword(runtime, device),
        to_row=lambda r: {
            "match_count": len(r),
            "networks": [row.network for row in r],
        },
        findings=findings,
        log_prefix="inspect: infoblox.search_by_keyword",
    )

    # 3. config_repo.search
    call_adapter(
        summary, "config_repo",
        fn=lambda: config_repo.search(runtime, device),
        to_row=lambda r: {
            "total_files_scanned": r.total_files_scanned,
            "match_count": len(r.matches),
            "truncated": r.truncated,
        },
        findings=findings,
        log_prefix="inspect: config_repo.search",
    )

    return summary, findings


# ---------------------------------------------------------------------------
# Dispatch table builder — deep flag captured via closure
# ---------------------------------------------------------------------------

def _make_dispatch(deep: bool = False) -> Dict[Any, Any]:
    """Build the dispatch table, capturing the ``deep`` flag via closure.

    When ``deep=True`` the IP and PREFIX handlers receive ``deep=True`` so
    they call the fan-out Infoblox functions instead of the shallow ones.
    """
    return {
        LensObjectType.IP: lambda rt, obj, bs: _run_ip(rt, obj, bs, deep=deep),
        LensObjectType.PREFIX: lambda rt, obj, bs: _run_prefix(rt, obj, bs, deep=deep),
        LensObjectType.FQDN: _run_fqdn,
        LensObjectType.SITE: _run_site,
        LensObjectType.DEVICE: _run_device,
    }


# Default (non-deep) dispatch table — kept for backward compatibility
_DISPATCH = _make_dispatch(deep=False)


# ---------------------------------------------------------------------------
# Offline result builder
# ---------------------------------------------------------------------------

def _build_offline_result(obj: LensObject, sources: Dict[str, str]):
    from cn_lens.models import LensResult
    return LensResult(
        lens_object=obj,
        status="classified",
        summary={
            "original": obj.original,
            "normalized": obj.normalized,
            "type": obj.object_type.value,
        },
        sources=sources,
        findings=(_classifier_finding(OFFLINE_FINDING_MESSAGE),),
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def inspect_objects(
    objects: ObjectSet,
    *,
    runtime: Optional["LensRuntime"] = None,
    run_id: Optional[str] = None,
    deep: bool = False,
) -> LensRun:
    """Classify and inspect a batch of network objects.

    Parameters
    ----------
    objects:
        The ``ObjectSet`` produced by ``classify_many``.
    runtime:
        Optional ``LensRuntime``.  When ``None`` or ``runtime.offline`` is
        ``True`` the function returns the offline MVP-shape output without
        contacting any live adapters.  When online, all applicable adapters
        are queried and their results are included in each ``LensResult``.
    run_id:
        Explicit run identifier.  Precedence order:
        1. ``run_id`` kwarg (if not None)
        2. ``runtime.options.run_id`` (if runtime is not None and options.run_id is not None)
        3. Auto-generated UTC timestamp via ``make_run_id()``.
    deep:
        When ``True``, perform a deep-dive for PREFIX and IP objects:
        fan-out to DHCP ranges, fixed addresses, in-subnet DNS records,
        member assignments, and decoded DHCP options.  Mirrors the
        "Subnet Data Detail" sheet from ``modules/subnet_request.py``.
        For IP objects, also calls ``infoblox.contains_address`` to find the
        parent subnet.  Network containers are expanded via
        ``infoblox.network_container_children``.

    Returns
    -------
    LensRun
        Always returned; never raises.
    """
    dispatch = _make_dispatch(deep=deep) if deep else _DISPATCH
    return run_workflow(
        "inspect",
        objects,
        runtime,
        registry=get_registry(),
        run_id=run_id,
        dispatch=dispatch,
        offline_result_fn=_build_offline_result,
    )
