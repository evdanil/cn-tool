"""Impact workflow — "Where is this used?"

Given a prefix/site/device/IP/FQDN, return all references found across
config_repo, sdwan_yaml, Infoblox containers, and AD group memberships.

Offline / None runtime
-----------------------
Returns the MVP-shape LensRun with a single classifier info finding per object
and ``not_queried`` source status for every adapter.  No adapter I/O occurs.

Online runtime
--------------
Runs the per-object-type adapter composition defined below.  Collects adapter
findings and a structured ``summary["impact"]`` block that contains a flat
``matches`` list of normalised reference records (each record is a
``ImpactMatch`` TypedDict with keys ``source``, ``device_or_file``,
``location``, ``snippet``).

Per-type adapter mapping
------------------------
PREFIX : config_repo.search(query=prefix)
         sdwan_yaml.lookup_prefix(prefix)
         infoblox.search_by_keyword(term=prefix)

SITE   : config_repo.search(query=site)
         sdwan_yaml.lookup_site(site)
         ad.lookup_site(site)

DEVICE : config_repo.search(query=device)
         infoblox.search_by_keyword(term=device)
         ad.lookup_device(device)

IP     : config_repo.search(query=ip)
         sdwan_yaml.search_by_keyword(term=ip)
         infoblox.lookup_ip(ip)   (treat host record as a reference)

FQDN   : config_repo.search(query=fqdn)
         infoblox.lookup_fqdn(fqdn)
         dns.resolve_forward(fqdn)

Hard constraints
----------------
- No print / console.  Logger only via runtime.logger.
- Adapter exceptions → caught, logged, synthesised error finding appended;
  remaining adapters in the chain still run.  Never propagates.
- CLI / interactive wiring is out of scope for this module.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple, TypedDict, TYPE_CHECKING

from cn_lens.adapters.registry import get_registry
from cn_lens.models import LensFinding, LensObject, LensObjectType, LensResult, LensRun, ObjectSet
from cn_lens.workflows._helpers import (
    OFFLINE_FINDING_MESSAGE,
    CLASSIFIED_FINDING_MESSAGE,
    make_run_id as _make_run_id,
    maybe_persist,
    synthesise_error_finding as _synthesise_error_finding,
)

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

# Deprecated alias — kept for backwards compatibility with existing tests/callers.
# Value equals OFFLINE_FINDING_MESSAGE (the offline-path message).
IMPACT_MVP_FINDING_MESSAGE: str = OFFLINE_FINDING_MESSAGE


# ---------------------------------------------------------------------------
# ImpactMatch — normalised reference record (TypedDict, module-private shape)
# ---------------------------------------------------------------------------

class ImpactMatch(TypedDict):
    """A normalised reference record produced by the impact workflow.

    Fields
    ------
    source:
        Name of the adapter that produced this match
        (``"config_repo"``, ``"sdwan_yaml"``, ``"infoblox"``, ``"ad"``,
        ``"dns"``).
    device_or_file:
        Human-readable device name or file path where the reference was found.
    location:
        Adapter-specific location string: line number for config_repo, YAML
        path for sdwan_yaml, network string for IB, DN for AD, or an empty
        string when not applicable.
    snippet:
        Short excerpt of the matching text or an empty string when the adapter
        does not provide one.
    """

    source: str
    device_or_file: str
    location: str
    snippet: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _classifier_finding(message: str = CLASSIFIED_FINDING_MESSAGE) -> LensFinding:
    """Return the initial classifier info finding (always present on every result).

    Pass ``OFFLINE_FINDING_MESSAGE`` on the offline / None-runtime path;
    the default (``CLASSIFIED_FINDING_MESSAGE``) is used on the online path.
    """
    return LensFinding(
        severity="info",
        source="classifier",
        message=message,
        detail={"workflow": "impact"},
    )


# ---------------------------------------------------------------------------
# Offline path
# ---------------------------------------------------------------------------

_OFFLINE_SOURCES: Dict[str, str] = {
    "classifier": "ok",
    "infoblox": "not_queried",
    "config_repo": "not_queried",
    "ad": "not_queried",
    "sdwan_yaml": "not_queried",
    "dns": "not_queried",
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
# Match-normalisation helpers (translate adapter result types → ImpactMatch)
# ---------------------------------------------------------------------------

def _matches_from_config_repo(cr_result: Any) -> List[ImpactMatch]:
    """Translate a ConfigSearchResult into a list of ImpactMatch records."""
    out: List[ImpactMatch] = []
    for m in cr_result.matches:
        out.append(ImpactMatch(
            source="config_repo",
            device_or_file=m.device,
            location=str(m.line_number),
            snippet=m.snippet,
        ))
    return out


def _call_config_repo(
    runtime: "LensRuntime",
    query: str,
    *,
    summary: Dict[str, Any],
    findings: List[LensFinding],
    matches: List[ImpactMatch],
    source: str = "config_repo",
) -> None:
    """Call config_repo.search and update summary/findings/matches in-place.

    On success populates ``summary["config_repo"]`` with scan stats and extends
    ``matches`` with translated ImpactMatch entries.  On error appends an error
    finding and sets ``summary["config_repo"]`` to an error dict.
    """
    from cn_lens.adapters import config_repo

    try:
        cr_result = config_repo.search(runtime, query)
        summary["config_repo"] = {
            "total_files_scanned": cr_result.total_files_scanned,
            "match_count": len(cr_result.matches),
            "truncated": cr_result.truncated,
        }
        matches.extend(_matches_from_config_repo(cr_result))
    except Exception as exc:
        runtime.logger.error("impact: config_repo.search raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding(source, exc))
        summary["config_repo"] = {"error": str(exc)}


def _matches_from_sdwan_keyword(sdwan_matches: Any) -> List[ImpactMatch]:
    """Translate a list[SdwanMatch] into ImpactMatch records."""
    out: List[ImpactMatch] = []
    for m in sdwan_matches:
        out.append(ImpactMatch(
            source="sdwan_yaml",
            device_or_file=m.file_path,
            location=m.path,
            snippet=m.matched_value,
        ))
    return out


def _matches_from_sdwan_prefix(sdwan_result: Any) -> List[ImpactMatch]:
    """Translate a SdwanPrefixResult into an ImpactMatch list (0 or 1 entry)."""
    if sdwan_result.status == "found":
        return [ImpactMatch(
            source="sdwan_yaml",
            device_or_file=sdwan_result.file_path or sdwan_result.site_code,
            location=sdwan_result.match_type,
            snippet=sdwan_result.raw or sdwan_result.prefix,
        )]
    return []


def _matches_from_sdwan_site(sdwan_result: Any) -> List[ImpactMatch]:
    """Translate a SdwanSiteResult into an ImpactMatch list (0 or 1 entry)."""
    if sdwan_result.status == "found":
        return [ImpactMatch(
            source="sdwan_yaml",
            device_or_file=sdwan_result.site_code,
            location="",
            snippet=sdwan_result.site_name or sdwan_result.site_code,
        )]
    return []


def _matches_from_ib_keyword(ib_rows: Any) -> List[ImpactMatch]:
    """Translate a list[InfobloxRow] into ImpactMatch records."""
    out: List[ImpactMatch] = []
    for row in ib_rows:
        out.append(ImpactMatch(
            source="infoblox",
            device_or_file=row.network,
            location=row.network,
            snippet=row.comment or "",
        ))
    return out


def _matches_from_ib_ip(ib_result: Any) -> List[ImpactMatch]:
    """Translate an InfobloxIPResult into an ImpactMatch list (0 or 1 entry)."""
    if ib_result.found:
        return [ImpactMatch(
            source="infoblox",
            device_or_file=ib_result.network or ib_result.ip,
            location=ib_result.ip,
            snippet=ib_result.name or "",
        )]
    return []


def _matches_from_ib_fqdn(ib_result: Any) -> List[ImpactMatch]:
    """Translate an InfobloxFqdnResult into ImpactMatch records."""
    out: List[ImpactMatch] = []
    if ib_result.found:
        for rec in ib_result.records:
            ip_val = rec.get("ip", "") if isinstance(rec, dict) else str(rec)
            name_val = rec.get("name", ib_result.fqdn) if isinstance(rec, dict) else ib_result.fqdn
            out.append(ImpactMatch(
                source="infoblox",
                device_or_file=ib_result.fqdn,
                location=ip_val,
                snippet=name_val,
            ))
    return out


def _matches_from_ad_site(ad_result: Any) -> List[ImpactMatch]:
    """Translate an AdSiteResult into an ImpactMatch list (0 or 1 entry)."""
    if ad_result.found:
        return [ImpactMatch(
            source="ad",
            device_or_file=ad_result.site_code,
            location=ad_result.ou_path,
            snippet=ad_result.location or ad_result.site_code,
        )]
    return []


def _matches_from_ad_device(ad_result: Any) -> List[ImpactMatch]:
    """Translate an AdDeviceResult into an ImpactMatch list (0 or 1 entry)."""
    if ad_result.found:
        return [ImpactMatch(
            source="ad",
            device_or_file=ad_result.computer_dn or ad_result.ou_path,
            location=ad_result.ou_path,
            snippet=ad_result.last_site_code or "",
        )]
    return []


def _matches_from_dns_forward(dns_result: Any) -> List[ImpactMatch]:
    """Translate a DnsForwardResult into ImpactMatch records (one per A record)."""
    out: List[ImpactMatch] = []
    if dns_result.status == "ok":
        for ip in dns_result.a_records:
            out.append(ImpactMatch(
                source="dns",
                device_or_file=dns_result.name,
                location=ip,
                snippet=ip,
            ))
    return out


# ---------------------------------------------------------------------------
# Per-type adapter dispatch (online path)
# ---------------------------------------------------------------------------

def _run_prefix(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding], List[ImpactMatch]]:
    """Run PREFIX-specific adapters: config_repo → sdwan_prefix → ib_keyword."""
    from cn_lens.adapters import sdwan_yaml, infoblox

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = []
    matches: List[ImpactMatch] = []
    prefix = obj.value

    # 1. config_repo.search
    _call_config_repo(runtime, prefix, summary=summary, findings=findings, matches=matches)

    # 2. sdwan_yaml.lookup_prefix
    try:
        sdwan_result = sdwan_yaml.lookup_prefix(runtime, prefix)
        summary["sdwan_yaml"] = {
            "status": sdwan_result.status,
            "site_code": sdwan_result.site_code,
            "match_type": sdwan_result.match_type,
        }
        findings.extend(sdwan_result.findings)
        matches.extend(_matches_from_sdwan_prefix(sdwan_result))
    except Exception as exc:
        runtime.logger.error("impact: sdwan_yaml.lookup_prefix raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("sdwan_yaml", exc))
        summary["sdwan_yaml"] = {"error": str(exc)}

    # 3. infoblox.search_by_keyword
    try:
        ib_rows = infoblox.search_by_keyword(runtime, prefix)
        summary["infoblox"] = {
            "match_count": len(ib_rows),
            "networks": [r.network for r in ib_rows],
        }
        matches.extend(_matches_from_ib_keyword(ib_rows))
    except Exception as exc:
        runtime.logger.error("impact: infoblox.search_by_keyword raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("infoblox", exc))
        summary["infoblox"] = {"error": str(exc)}

    return summary, findings, matches


def _run_site(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding], List[ImpactMatch]]:
    """Run SITE-specific adapters: config_repo → sdwan_site → ad_site."""
    from cn_lens.adapters import sdwan_yaml, active_directory

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = []
    matches: List[ImpactMatch] = []
    site = obj.value

    # 1. config_repo.search
    _call_config_repo(runtime, site, summary=summary, findings=findings, matches=matches)

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
        matches.extend(_matches_from_sdwan_site(sdwan_result))
    except Exception as exc:
        runtime.logger.error("impact: sdwan_yaml.lookup_site raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("sdwan_yaml", exc))
        summary["sdwan_yaml"] = {"error": str(exc)}

    # 3. ad.lookup_site
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
        matches.extend(_matches_from_ad_site(ad_result))
    except Exception as exc:
        runtime.logger.error("impact: ad.lookup_site raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("ad", exc))
        summary["ad"] = {"found": False, "error": str(exc)}

    return summary, findings, matches


def _run_device(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding], List[ImpactMatch]]:
    """Run DEVICE-specific adapters: config_repo → ib_keyword → ad_device."""
    from cn_lens.adapters import infoblox, active_directory

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = []
    matches: List[ImpactMatch] = []
    device = obj.value

    # 1. config_repo.search
    _call_config_repo(runtime, device, summary=summary, findings=findings, matches=matches)

    # 2. infoblox.search_by_keyword
    try:
        ib_rows = infoblox.search_by_keyword(runtime, device)
        summary["infoblox"] = {
            "match_count": len(ib_rows),
            "networks": [r.network for r in ib_rows],
        }
        matches.extend(_matches_from_ib_keyword(ib_rows))
    except Exception as exc:
        runtime.logger.error("impact: infoblox.search_by_keyword raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("infoblox", exc))
        summary["infoblox"] = {"error": str(exc)}

    # 3. ad.lookup_device
    try:
        ad_result, ad_findings = active_directory.lookup_device(runtime, device)
        summary["ad"] = {
            "found": ad_result.found,
            "ou_path": ad_result.ou_path,
            "last_site_code": ad_result.last_site_code,
            "computer_dn": ad_result.computer_dn,
        }
        findings.extend(ad_findings)
        matches.extend(_matches_from_ad_device(ad_result))
    except Exception as exc:
        runtime.logger.error("impact: ad.lookup_device raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("ad", exc))
        summary["ad"] = {"found": False, "error": str(exc)}

    return summary, findings, matches


def _run_ip(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding], List[ImpactMatch]]:
    """Run IP-specific adapters: config_repo → sdwan_keyword → ib_lookup_ip."""
    from cn_lens.adapters import sdwan_yaml, infoblox

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = []
    matches: List[ImpactMatch] = []
    ip = obj.value

    # 1. config_repo.search
    _call_config_repo(runtime, ip, summary=summary, findings=findings, matches=matches)

    # 2. sdwan_yaml.search_by_keyword
    try:
        sdwan_matches = sdwan_yaml.search_by_keyword(runtime, ip)
        summary["sdwan_yaml"] = {
            "match_count": len(sdwan_matches),
            "sites": list({m.site_code for m in sdwan_matches}),
        }
        matches.extend(_matches_from_sdwan_keyword(sdwan_matches))
    except Exception as exc:
        runtime.logger.error("impact: sdwan_yaml.search_by_keyword raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("sdwan_yaml", exc))
        summary["sdwan_yaml"] = {"error": str(exc)}

    # 3. infoblox.lookup_ip  (treat the host record as a reference)
    try:
        ib_result = infoblox.lookup_ip(runtime, ip)
        summary["infoblox"] = {
            "found": ib_result.found,
            "ip": ib_result.ip,
            "network": ib_result.network,
            "name": ib_result.name,
            "status": ib_result.status,
        }
        findings.extend(ib_result.findings)
        matches.extend(_matches_from_ib_ip(ib_result))
    except Exception as exc:
        runtime.logger.error("impact: infoblox.lookup_ip raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("infoblox", exc))
        summary["infoblox"] = {"found": False, "error": str(exc)}

    return summary, findings, matches


def _run_fqdn(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding], List[ImpactMatch]]:
    """Run FQDN-specific adapters: config_repo → ib_lookup_fqdn → dns_resolve_forward."""
    from cn_lens.adapters import infoblox, dns

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = []
    matches: List[ImpactMatch] = []
    fqdn = obj.value

    # 1. config_repo.search
    _call_config_repo(runtime, fqdn, summary=summary, findings=findings, matches=matches)

    # 2. infoblox.lookup_fqdn
    try:
        ib_result = infoblox.lookup_fqdn(runtime, fqdn)
        summary["infoblox"] = {
            "found": ib_result.found,
            "fqdn": ib_result.fqdn,
            "record_count": len(ib_result.records),
        }
        findings.extend(ib_result.findings)
        matches.extend(_matches_from_ib_fqdn(ib_result))
    except Exception as exc:
        runtime.logger.error("impact: infoblox.lookup_fqdn raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("infoblox", exc))
        summary["infoblox"] = {"found": False, "error": str(exc)}

    # 3. dns.resolve_forward  (reverse-locate behind the name)
    try:
        dns_result = dns.resolve_forward(runtime, fqdn)
        summary["dns"] = {
            "a_records": list(dns_result.a_records),
            "aaaa_records": list(dns_result.aaaa_records),
            "status": dns_result.status,
        }
        matches.extend(_matches_from_dns_forward(dns_result))
    except Exception as exc:
        runtime.logger.error("impact: dns.resolve_forward raised unexpectedly: %s", exc)
        findings.append(_synthesise_error_finding("dns", exc))
        summary["dns"] = {"error": str(exc)}

    return summary, findings, matches


# Dispatch table: maps LensObjectType → adapter runner
_AdapterRunner = Callable[
    ["LensRuntime", LensObject, Dict[str, Any]],
    Tuple[Dict[str, Any], List[LensFinding], List[ImpactMatch]],
]
_DISPATCH: Dict[LensObjectType, _AdapterRunner] = {
    LensObjectType.PREFIX: _run_prefix,
    LensObjectType.SITE: _run_site,
    LensObjectType.DEVICE: _run_device,
    LensObjectType.IP: _run_ip,
    LensObjectType.FQDN: _run_fqdn,
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
    matches: List[ImpactMatch] = []

    dispatcher = _DISPATCH.get(obj.object_type)
    if dispatcher is not None:
        try:
            summary, adapter_findings, adapter_matches = dispatcher(runtime, obj, base_summary)
            findings.extend(adapter_findings)
            matches.extend(adapter_matches)
        except Exception as exc:
            # Last-resort guard: should not happen since each dispatcher already wraps
            runtime.logger.error("impact: unexpected error in adapter dispatcher: %s", exc)
            summary = dict(base_summary)
            findings.append(_synthesise_error_finding("impact", exc))
    else:
        # KEYWORD, INVALID, or any future type without a dispatcher
        summary = dict(base_summary)

    # Attach impact matches block to the summary
    summary["impact"] = {"matches": matches}

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

def impact_objects(
    object_set: ObjectSet,
    *,
    runtime: Optional["LensRuntime"] = None,
    run_id: Optional[str] = None,
) -> LensRun:
    """Find all references to the given objects across available sources.

    Parameters
    ----------
    object_set:
        The ``ObjectSet`` produced by ``classify_many``.
    runtime:
        Optional ``LensRuntime``.  When ``None`` or ``runtime.offline`` is
        ``True`` the function returns the offline MVP-shape output without
        contacting any live adapters.  When online, all applicable adapters
        are queried and results are aggregated into ``summary["impact"]``.
    run_id:
        Explicit run identifier.  Precedence order:

        1. ``run_id`` kwarg (if not None)
        2. ``runtime.options.run_id`` (if runtime is not None and options.run_id is not None)
        3. Auto-generated UTC timestamp via ``_make_run_id()``.

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
        effective_run_id = _make_run_id()

    # --- Offline path ---
    if runtime is None or runtime.offline:
        results = tuple(
            _build_offline_result(obj) for obj in object_set.objects
        )
        return LensRun(
            schema_version=1,
            tool="cn-lens",
            workflow="impact",
            run_id=effective_run_id,
            inputs=object_set,
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
        for obj in object_set.objects
    )

    run = LensRun(
        schema_version=1,
        tool="cn-lens",
        workflow="impact",
        run_id=effective_run_id,
        inputs=object_set,
        results=results,
        warnings=(),
        errors=(),
    )
    maybe_persist(run, runtime)
    return run
