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

from typing import Any, Dict, List, Optional, Tuple, TypedDict, TYPE_CHECKING

from cn_lens.adapters.registry import get_registry
from cn_lens.models import LensFinding, LensObject, LensObjectType, LensRun, ObjectSet
from cn_lens.workflows._helpers import (
    OFFLINE_FINDING_MESSAGE,
    CLASSIFIED_FINDING_MESSAGE,
    call_adapter,
    run_workflow,
)

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


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
) -> None:
    """Call config_repo.search and update summary/findings/matches in-place.

    Thin wrapper around ``call_adapter`` that also extends *matches* on the
    success path — kept as a named helper because every impact chain starts
    with this identical config_repo call + matches extension.
    """
    from cn_lens.adapters import config_repo

    call_adapter(
        summary, "config_repo",
        fn=lambda: config_repo.search(runtime, query),
        to_row=lambda r: {
            "total_files_scanned": r.total_files_scanned,
            "match_count": len(r.matches),
            "truncated": r.truncated,
        },
        findings=findings,
        log_prefix="impact: config_repo.search",
        on_success=lambda r: matches.extend(_matches_from_config_repo(r)),
    )


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
# Per-type adapter dispatch handlers (online path)
# ---------------------------------------------------------------------------

def _matches_from_sdwan_prefix_all(sdwan_results: List[Any]) -> List[ImpactMatch]:
    """Translate a list[SdwanPrefixResult] (from lookup_prefix_all) into ImpactMatch records."""
    out: List[ImpactMatch] = []
    for r in sdwan_results:
        if r.status in ("found", "partial"):
            out.append(ImpactMatch(
                source="sdwan_yaml",
                device_or_file=r.file_path or r.site_code,
                location=r.match_type,
                snippet=r.raw or r.prefix,
            ))
    return out


def _run_prefix(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    *,
    all_matches: bool = False,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run PREFIX-specific adapters: config_repo → sdwan_prefix → ib_keyword → ad_subnet.

    Parameters
    ----------
    all_matches:
        When ``True``, calls ``sdwan_yaml.lookup_prefix_all`` (exhaustive mode,
        plan D9 ``--all-matches`` flag) instead of ``sdwan_yaml.lookup_prefix``
        (best-match mode).
    """
    from cn_lens.adapters import sdwan_yaml, infoblox, active_directory

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = [_classifier_finding()]
    matches: List[ImpactMatch] = []
    prefix = obj.value

    # 1. config_repo.search
    _call_config_repo(runtime, prefix, summary=summary, findings=findings, matches=matches)

    # 2. sdwan_yaml lookup — exhaustive (all-matches) or best-match (default)
    if all_matches:
        call_adapter(
            summary, "sdwan_yaml",
            fn=lambda: sdwan_yaml.lookup_prefix_all(runtime, prefix),
            to_row=lambda r: {
                "match_count": len(r),
                "sites": [x.site_code for x in r if x.status in ("found", "partial")],
            },
            findings=findings,
            log_prefix="impact: sdwan_yaml.lookup_prefix_all",
            on_success=lambda r: (
                [findings.extend(x.findings) for x in r],
                matches.extend(_matches_from_sdwan_prefix_all(r)),
            ),
        )
    else:
        call_adapter(
            summary, "sdwan_yaml",
            fn=lambda: sdwan_yaml.lookup_prefix(runtime, prefix),
            to_row=lambda r: {
                "status": r.status,
                "site_code": r.site_code,
                "match_type": r.match_type,
            },
            findings=findings,
            log_prefix="impact: sdwan_yaml.lookup_prefix",
            on_success=lambda r: (
                findings.extend(r.findings),
                matches.extend(_matches_from_sdwan_prefix(r)),
            ),
        )

    # 3. infoblox.search_by_keyword
    call_adapter(
        summary, "infoblox",
        fn=lambda: infoblox.search_by_keyword(runtime, prefix),
        to_row=lambda r: {
            "match_count": len(r),
            "networks": [row.network for row in r],
        },
        findings=findings,
        log_prefix="impact: infoblox.search_by_keyword",
        on_success=lambda r: matches.extend(_matches_from_ib_keyword(r)),
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
        log_prefix="impact: active_directory.lookup_subnet",
        on_success=lambda r: findings.extend(r[1]),
        on_error_extra={"found": False},
    )

    summary["impact"] = {"matches": matches}
    return summary, findings


def _run_site(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run SITE-specific adapters: config_repo → sdwan_site → ad_site."""
    from cn_lens.adapters import sdwan_yaml, active_directory

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = [_classifier_finding()]
    matches: List[ImpactMatch] = []
    site = obj.value

    # 1. config_repo.search
    _call_config_repo(runtime, site, summary=summary, findings=findings, matches=matches)

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
        log_prefix="impact: sdwan_yaml.lookup_site",
        on_success=lambda r: (
            findings.extend(r.findings),
            matches.extend(_matches_from_sdwan_site(r)),
        ),
    )

    # 3. ad.lookup_site
    # Prefixes are not available in the impact SITE chain (no Infoblox call
    # precedes this point).  The site-object lookup path still runs.
    # P5 follow-up: wire Infoblox prefix list if the chain is extended.
    call_adapter(
        summary, "ad",
        fn=lambda: active_directory.lookup_site(runtime, site, prefixes=()),
        to_row=lambda r: {
            "found": r[0].found,
            "site_code": r[0].site_code,
            "location": r[0].location,
            "country_code": r[0].country_code,
            "ou_path": r[0].ou_path,
        },
        findings=findings,
        log_prefix="impact: ad.lookup_site",
        on_success=lambda r: (
            findings.extend(r[1]),
            matches.extend(_matches_from_ad_site(r[0])),
        ),
        on_error_extra={"found": False},
    )

    summary["impact"] = {"matches": matches}
    return summary, findings


def _run_device(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run DEVICE-specific adapters: config_repo → ib_keyword → ad_device."""
    from cn_lens.adapters import infoblox, active_directory

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = [_classifier_finding()]
    matches: List[ImpactMatch] = []
    device = obj.value

    # 1. config_repo.search
    _call_config_repo(runtime, device, summary=summary, findings=findings, matches=matches)

    # 2. infoblox.search_by_keyword
    call_adapter(
        summary, "infoblox",
        fn=lambda: infoblox.search_by_keyword(runtime, device),
        to_row=lambda r: {
            "match_count": len(r),
            "networks": [row.network for row in r],
        },
        findings=findings,
        log_prefix="impact: infoblox.search_by_keyword",
        on_success=lambda r: matches.extend(_matches_from_ib_keyword(r)),
    )

    # 3. ad.lookup_device
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
        log_prefix="impact: ad.lookup_device",
        on_success=lambda r: (
            findings.extend(r[1]),
            matches.extend(_matches_from_ad_device(r[0])),
        ),
        on_error_extra={"found": False},
    )

    summary["impact"] = {"matches": matches}
    return summary, findings


def _run_ip(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run IP-specific adapters: config_repo → sdwan_keyword → ib_lookup_ip."""
    from cn_lens.adapters import sdwan_yaml, infoblox

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = [_classifier_finding()]
    matches: List[ImpactMatch] = []
    ip = obj.value

    # 1. config_repo.search
    _call_config_repo(runtime, ip, summary=summary, findings=findings, matches=matches)

    # 2. sdwan_yaml.search_by_keyword
    call_adapter(
        summary, "sdwan_yaml",
        fn=lambda: sdwan_yaml.search_by_keyword(runtime, ip),
        to_row=lambda r: {
            "match_count": len(r),
            "sites": list({m.site_code for m in r}),
        },
        findings=findings,
        log_prefix="impact: sdwan_yaml.search_by_keyword",
        on_success=lambda r: matches.extend(_matches_from_sdwan_keyword(r)),
    )

    # 3. infoblox.lookup_ip  (treat the host record as a reference)
    call_adapter(
        summary, "infoblox",
        fn=lambda: infoblox.lookup_ip(runtime, ip),
        to_row=lambda r: {
            "found": r.found,
            "ip": r.ip,
            "network": r.network,
            "name": r.name,
            "status": r.status,
        },
        findings=findings,
        log_prefix="impact: infoblox.lookup_ip",
        on_success=lambda r: (
            findings.extend(r.findings),
            matches.extend(_matches_from_ib_ip(r)),
        ),
        on_error_extra={"found": False},
    )

    summary["impact"] = {"matches": matches}
    return summary, findings


def _run_fqdn(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run FQDN-specific adapters: config_repo → ib_lookup_fqdn → dns_resolve_forward."""
    from cn_lens.adapters import infoblox, dns

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = [_classifier_finding()]
    matches: List[ImpactMatch] = []
    fqdn = obj.value

    # 1. config_repo.search
    _call_config_repo(runtime, fqdn, summary=summary, findings=findings, matches=matches)

    # 2. infoblox.lookup_fqdn
    call_adapter(
        summary, "infoblox",
        fn=lambda: infoblox.lookup_fqdn(runtime, fqdn),
        to_row=lambda r: {
            "found": r.found,
            "fqdn": r.fqdn,
            "record_count": len(r.records),
        },
        findings=findings,
        log_prefix="impact: infoblox.lookup_fqdn",
        on_success=lambda r: (
            findings.extend(r.findings),
            matches.extend(_matches_from_ib_fqdn(r)),
        ),
        on_error_extra={"found": False},
    )

    # 3. dns.resolve_forward  (reverse-locate behind the name)
    call_adapter(
        summary, "dns",
        fn=lambda: dns.resolve_forward(runtime, fqdn),
        to_row=lambda r: {
            "a_records": list(r.a_records),
            "aaaa_records": list(r.aaaa_records),
            "status": r.status,
        },
        findings=findings,
        log_prefix="impact: dns.resolve_forward",
        on_success=lambda r: matches.extend(_matches_from_dns_forward(r)),
    )

    summary["impact"] = {"matches": matches}
    return summary, findings


# ---------------------------------------------------------------------------
# Dispatch table builder
# ---------------------------------------------------------------------------

def _build_dispatch(all_matches: bool = False) -> dict:
    """Build the per-type handler dispatch table, capturing *all_matches* via closure.

    When *all_matches* is ``True``, the PREFIX handler routes to
    ``sdwan_yaml.lookup_prefix_all`` instead of ``sdwan_yaml.lookup_prefix``.
    All other handlers are unaffected.
    """
    return {
        LensObjectType.PREFIX: lambda rt, obj, bs: _run_prefix(
            rt, obj, bs, all_matches=all_matches
        ),
        LensObjectType.SITE: _run_site,
        LensObjectType.DEVICE: _run_device,
        LensObjectType.IP: _run_ip,
        LensObjectType.FQDN: _run_fqdn,
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def impact_objects(
    object_set: ObjectSet,
    *,
    runtime: Optional["LensRuntime"] = None,
    run_id: Optional[str] = None,
    all_matches: bool = False,
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
        3. Auto-generated UTC timestamp via ``make_run_id()`` (in _helpers).
    all_matches:
        When ``True``, use exhaustive SD-WAN YAML prefix matching
        (``sdwan_yaml.lookup_prefix_all``) for PREFIX objects instead of the
        default best-match mode (``sdwan_yaml.lookup_prefix``).  Equivalent to
        the ``--all-matches`` CLI flag (plan D9).

    Returns
    -------
    LensRun
        Always returned; never raises.
    """
    return run_workflow(
        "impact",
        object_set,
        runtime,
        registry=get_registry(),
        run_id=run_id,
        dispatch=_build_dispatch(all_matches=all_matches),
        offline_result_fn=_build_offline_result,
    )
