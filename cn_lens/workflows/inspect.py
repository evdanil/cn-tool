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

from typing import Any, Callable, Dict, List, Optional, Tuple, TYPE_CHECKING

from cn_lens.adapters.registry import get_registry
from cn_lens.models import LensFinding, LensObject, LensObjectType, LensResult, LensRun, ObjectSet
from cn_lens.workflows._helpers import (
    OFFLINE_FINDING_MESSAGE,
    CLASSIFIED_FINDING_MESSAGE,
    is_short_hostname,
    make_run_id,
    maybe_persist,
    synthesise_error_finding as _synthesise_error_finding,
)

# Re-export for backwards compatibility (e.g. tests that import MVP_FINDING_MESSAGE
# from cn_lens.workflows.inspect).  The value now equals OFFLINE_FINDING_MESSAGE.
MVP_FINDING_MESSAGE = OFFLINE_FINDING_MESSAGE

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


# MVP_FINDING_MESSAGE is kept as a backwards-compatible alias equal to
# OFFLINE_FINDING_MESSAGE so that existing importers are not broken.
# CLASSIFIED_FINDING_MESSAGE and OFFLINE_FINDING_MESSAGE are the preferred names.
__all__ = [
    "MVP_FINDING_MESSAGE",
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
# Offline path
# ---------------------------------------------------------------------------

_OFFLINE_SOURCES: Dict[str, str] = {
    "classifier": "ok",
    "infoblox": "not_queried",
    "config_repo": "not_queried",
    "ad": "not_queried",
}


def _build_offline_result(obj: LensObject) -> LensResult:
    """Build the offline-shape LensResult when offline or runtime is None."""
    return LensResult(
        lens_object=obj,
        status="classified",
        summary={
            "original": obj.original,
            "normalized": obj.normalized,
            "type": obj.object_type.value,
        },
        sources=_OFFLINE_SOURCES,
        findings=(_classifier_finding(OFFLINE_FINDING_MESSAGE),),
    )


# ---------------------------------------------------------------------------
# Per-type adapter dispatch (online path)
# ---------------------------------------------------------------------------

def _run_ip(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run IP-specific adapters in documented order and return (summary, findings)."""
    from cn_lens.adapters import infoblox, active_directory, config_repo, sdwan_yaml, dns

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = []
    ip = obj.value

    # 1. infoblox.lookup_ip
    try:
        ib_result = infoblox.lookup_ip(runtime, ip)
        summary["infoblox"] = {
            "found": ib_result.found,
            "ip": ib_result.ip,
            "network": ib_result.network,
            "name": ib_result.name,
            "status": ib_result.status,
            "lease_state": ib_result.lease_state,
            "record_type": ib_result.record_type,
            "mac": ib_result.mac,
        }
        findings.extend(ib_result.findings)
    except Exception as exc:
        runtime.logger.error("inspect: infoblox.lookup_ip raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("infoblox", exc))
        summary["infoblox"] = {"found": False, "error": str(exc)}

    # 2. ad.enrich_ip
    try:
        ad_enrichment, ad_findings = active_directory.enrich_ip(runtime, ip)
        summary["ad"] = {
            "resolved_hostname": ad_enrichment.resolved_hostname,
            "ou_path": ad_enrichment.device_result.ou_path,
            "last_site_code": ad_enrichment.device_result.last_site_code,
            "computer_dn": ad_enrichment.device_result.computer_dn,
            "found": ad_enrichment.device_result.found,
        }
        findings.extend(ad_findings)
    except Exception as exc:
        runtime.logger.error("inspect: ad.enrich_ip raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("ad", exc))
        summary["ad"] = {"found": False, "error": str(exc)}

    # 3. config_repo.search
    try:
        cr_result = config_repo.search(runtime, ip)
        summary["config_repo"] = {
            "total_files_scanned": cr_result.total_files_scanned,
            "match_count": len(cr_result.matches),
            "truncated": cr_result.truncated,
        }
    except Exception as exc:
        runtime.logger.error("inspect: config_repo.search raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("config_repo", exc))
        summary["config_repo"] = {"error": str(exc)}

    # 4. sdwan_yaml.search_by_keyword
    try:
        sdwan_matches = sdwan_yaml.search_by_keyword(runtime, ip)
        summary["sdwan_yaml"] = {
            "match_count": len(sdwan_matches),
            "sites": list({m.site_code for m in sdwan_matches}),
        }
    except Exception as exc:
        runtime.logger.error("inspect: sdwan_yaml.search_by_keyword raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("sdwan_yaml", exc))
        summary["sdwan_yaml"] = {"error": str(exc)}

    # 5. dns.resolve_reverse
    try:
        dns_result = dns.resolve_reverse(runtime, ip)
        summary["dns"] = {
            "ptr": dns_result.ptr,
            "status": dns_result.status,
            "error": dns_result.error,
        }
    except Exception as exc:
        runtime.logger.error("inspect: dns.resolve_reverse raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("dns", exc))
        summary["dns"] = {"error": str(exc)}

    return summary, findings


def _run_prefix(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run PREFIX-specific adapters in documented order."""
    from cn_lens.adapters import infoblox, config_repo, sdwan_yaml

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = []
    prefix = obj.value

    # 1. infoblox.lookup_prefix
    try:
        ib_result = infoblox.lookup_prefix(runtime, prefix)
        summary["infoblox"] = {
            "found": ib_result.found,
            "prefix": ib_result.prefix,
            "network": ib_result.network,
            "comment": ib_result.comment,
            "inherited_comment": ib_result.inherited_comment,
            "extattrs_count": len(ib_result.extattrs),
            "dhcp_options_count": len(ib_result.dhcp_options),
        }
        findings.extend(ib_result.findings)
    except Exception as exc:
        runtime.logger.error("inspect: infoblox.lookup_prefix raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("infoblox", exc))
        summary["infoblox"] = {"found": False, "error": str(exc)}

    # 2. config_repo.search
    try:
        cr_result = config_repo.search(runtime, prefix)
        summary["config_repo"] = {
            "total_files_scanned": cr_result.total_files_scanned,
            "match_count": len(cr_result.matches),
            "truncated": cr_result.truncated,
        }
    except Exception as exc:
        runtime.logger.error("inspect: config_repo.search raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("config_repo", exc))
        summary["config_repo"] = {"error": str(exc)}

    # 3. sdwan_yaml.lookup_prefix
    try:
        sdwan_result = sdwan_yaml.lookup_prefix(runtime, prefix)
        summary["sdwan_yaml"] = {
            "status": sdwan_result.status,
            "site_code": sdwan_result.site_code,
            "match_type": sdwan_result.match_type,
        }
        findings.extend(sdwan_result.findings)
    except Exception as exc:
        runtime.logger.error("inspect: sdwan_yaml.lookup_prefix raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("sdwan_yaml", exc))
        summary["sdwan_yaml"] = {"error": str(exc)}

    return summary, findings


def _run_fqdn(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run FQDN-specific adapters in documented order."""
    from cn_lens.adapters import infoblox, dns, config_repo

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = []
    fqdn = obj.value

    # 1. infoblox.lookup_fqdn
    try:
        ib_result = infoblox.lookup_fqdn(runtime, fqdn)
        summary["infoblox"] = {
            "found": ib_result.found,
            "fqdn": ib_result.fqdn,
            "record_count": len(ib_result.records),
        }
        findings.extend(ib_result.findings)
    except Exception as exc:
        runtime.logger.error("inspect: infoblox.lookup_fqdn raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("infoblox", exc))
        summary["infoblox"] = {"found": False, "error": str(exc)}

    # 2. dns.resolve_forward
    try:
        dns_fwd = dns.resolve_forward(runtime, fqdn)
        dns_summary: Dict[str, Any] = {
            "a_records": list(dns_fwd.a_records),
            "aaaa_records": list(dns_fwd.aaaa_records),
            "status": dns_fwd.status,
        }
    except Exception as exc:
        runtime.logger.error("inspect: dns.resolve_forward raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("dns", exc))
        dns_summary = {"error": str(exc)}

    # 3. dns.expand_fqdn_prefix (only for prefix-shape values)
    if _is_fqdn_prefix(fqdn):
        try:
            expansion = dns.expand_fqdn_prefix(runtime, fqdn)
            dns_summary["expansion"] = {
                "names": list(expansion.names),
                "status": expansion.status,
            }
        except Exception as exc:
            runtime.logger.error("inspect: dns.expand_fqdn_prefix raised unexpectedly: %s", exc)
            findings.append(_synthesise_error_finding("dns", exc))
            dns_summary["expansion"] = {"error": str(exc)}

    summary["dns"] = dns_summary

    # 4. config_repo.search
    try:
        cr_result = config_repo.search(runtime, fqdn)
        summary["config_repo"] = {
            "total_files_scanned": cr_result.total_files_scanned,
            "match_count": len(cr_result.matches),
            "truncated": cr_result.truncated,
        }
    except Exception as exc:
        runtime.logger.error("inspect: config_repo.search raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("config_repo", exc))
        summary["config_repo"] = {"error": str(exc)}

    return summary, findings


def _run_site(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run SITE-specific adapters in documented order."""
    from cn_lens.adapters import active_directory, sdwan_yaml, config_repo

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = []
    site = obj.value

    # 1. ad.lookup_site
    try:
        ad_result, ad_findings = active_directory.lookup_site(runtime, site)
        summary["ad"] = {
            "found": ad_result.found,
            "site_code": ad_result.site_code,
            "location": ad_result.location,
            "country_code": ad_result.country_code,
            "ou_path": ad_result.ou_path,
        }
        findings.extend(ad_findings)
    except Exception as exc:
        runtime.logger.error("inspect: ad.lookup_site raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("ad", exc))
        summary["ad"] = {"found": False, "error": str(exc)}

    # 2. sdwan_yaml.lookup_site
    try:
        sdwan_result = sdwan_yaml.lookup_site(runtime, site)
        summary["sdwan_yaml"] = {
            "status": sdwan_result.status,
            "site_name": sdwan_result.site_name,
            "prefix_count": len(sdwan_result.prefixes),
            "device_count": len(sdwan_result.devices),
        }
        findings.extend(sdwan_result.findings)
    except Exception as exc:
        runtime.logger.error("inspect: sdwan_yaml.lookup_site raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("sdwan_yaml", exc))
        summary["sdwan_yaml"] = {"error": str(exc)}

    # 3. config_repo.search
    try:
        cr_result = config_repo.search(runtime, site)
        summary["config_repo"] = {
            "total_files_scanned": cr_result.total_files_scanned,
            "match_count": len(cr_result.matches),
            "truncated": cr_result.truncated,
        }
    except Exception as exc:
        runtime.logger.error("inspect: config_repo.search raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("config_repo", exc))
        summary["config_repo"] = {"error": str(exc)}

    return summary, findings


def _run_device(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run DEVICE-specific adapters in documented order."""
    from cn_lens.adapters import active_directory, infoblox, config_repo

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = []
    device = obj.value

    # 1. ad.lookup_device
    try:
        ad_result, ad_findings = active_directory.lookup_device(runtime, device)
        summary["ad"] = {
            "found": ad_result.found,
            "ou_path": ad_result.ou_path,
            "last_site_code": ad_result.last_site_code,
            "computer_dn": ad_result.computer_dn,
        }
        findings.extend(ad_findings)
    except Exception as exc:
        runtime.logger.error("inspect: ad.lookup_device raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("ad", exc))
        summary["ad"] = {"found": False, "error": str(exc)}

    # 2. infoblox.search_by_keyword
    try:
        ib_rows = infoblox.search_by_keyword(runtime, device)
        summary["infoblox"] = {
            "match_count": len(ib_rows),
            "networks": [r.network for r in ib_rows],
        }
    except Exception as exc:
        runtime.logger.error("inspect: infoblox.search_by_keyword raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("infoblox", exc))
        summary["infoblox"] = {"error": str(exc)}

    # 3. config_repo.search
    try:
        cr_result = config_repo.search(runtime, device)
        summary["config_repo"] = {
            "total_files_scanned": cr_result.total_files_scanned,
            "match_count": len(cr_result.matches),
            "truncated": cr_result.truncated,
        }
    except Exception as exc:
        runtime.logger.error("inspect: config_repo.search raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("config_repo", exc))
        summary["config_repo"] = {"error": str(exc)}

    return summary, findings


# Dispatch table: maps LensObjectType → adapter runner
_AdapterRunner = Callable[
    ["LensRuntime", LensObject, Dict[str, Any]],
    Tuple[Dict[str, Any], List[LensFinding]],
]
_DISPATCH: Dict[LensObjectType, _AdapterRunner] = {
    LensObjectType.IP: _run_ip,
    LensObjectType.PREFIX: _run_prefix,
    LensObjectType.FQDN: _run_fqdn,
    LensObjectType.SITE: _run_site,
    LensObjectType.DEVICE: _run_device,
}


# ---------------------------------------------------------------------------
# Online per-object runner
# ---------------------------------------------------------------------------

def _build_online_result(
    obj: LensObject,
    runtime: "LensRuntime",
    sources: Dict[str, str],
) -> LensResult:
    """Build a LensResult for a single object using live adapters."""
    base_summary: Dict[str, Any] = {
        "original": obj.original,
        "normalized": obj.normalized,
        "type": obj.object_type.value,
    }

    # Always start with the classifier finding
    findings: List[LensFinding] = [_classifier_finding()]

    dispatcher = _DISPATCH.get(obj.object_type)
    if dispatcher is not None:
        try:
            summary, adapter_findings = dispatcher(runtime, obj, base_summary)
            findings.extend(adapter_findings)
        except Exception as exc:
            # Last-resort guard: should not happen since each dispatcher already wraps
            runtime.logger.error("inspect: unexpected error in adapter dispatcher: %s", exc)
            summary = dict(base_summary)
            findings.append(_synthesise_error_finding("inspect", exc))
    else:
        # KEYWORD, INVALID, or any future type without a dispatcher
        summary = dict(base_summary)

    return LensResult(
        lens_object=obj,
        status="classified",
        summary=summary,
        sources=sources,
        findings=tuple(findings),
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def inspect_objects(
    objects: ObjectSet,
    *,
    runtime: Optional["LensRuntime"] = None,
    run_id: Optional[str] = None,
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

    Returns
    -------
    LensRun
        Always returned; never raises.
    """
    # --- Resolve run_id ---
    effective_run_id: str
    if run_id is not None:
        effective_run_id = run_id
    elif runtime is not None and runtime.options.run_id is not None:
        effective_run_id = runtime.options.run_id
    else:
        effective_run_id = make_run_id()

    # --- Offline path ---
    if runtime is None or runtime.offline:
        results = tuple(
            _build_offline_result(obj) for obj in objects.objects
        )
        return LensRun(
            schema_version=1,
            tool="cn-lens",
            workflow="inspect",
            run_id=effective_run_id,
            inputs=objects,
            results=results,
            warnings=(),
            errors=(),
        )

    # --- Online path ---
    # Build sources map once from the registry; share across all results in this run.
    registry = get_registry()
    sources: Dict[str, str] = {"classifier": "ok"}
    sources.update(registry.source_statuses(runtime))

    results = tuple(
        _build_online_result(obj, runtime, sources)
        for obj in objects.objects
    )

    run = LensRun(
        schema_version=1,
        tool="cn-lens",
        workflow="inspect",
        run_id=effective_run_id,
        inputs=objects,
        results=results,
        warnings=(),
        errors=(),
    )
    maybe_persist(run, runtime)
    return run
