"""validate_site workflow — per-site consistency check across AD, SD-WAN, Infoblox, config-repo, DNS.

Offline / None runtime
-----------------------
Returns MVP-shape LensRun with a single classifier info finding per object
and ``not_queried`` source status for every adapter.  No adapter I/O occurs.

SITE objects (primary type)
---------------------------
Runs five ordered checks per site code, emits a ``LensFinding`` for each
result, and populates ``summary["validate_site"]`` with a structured
``checks`` list plus an ``overall_status`` field.

Non-SITE objects (IP, PREFIX, FQDN, DEVICE)
---------------------------------------------
Classifier-only result with a single info finding:
    "validate_site requires a site code input"

Check order and severity rules
-------------------------------
1. ad_known             — ad.lookup_site(site).found → False → error
2. sdwan_known          — sdwan_yaml.lookup_site(site).status == "found" → False → warning
3. infoblox_subnets_present — infoblox.search_by_keyword(site) non-empty → empty → warning
4. config_references_present — config_repo.search(site) non-empty → empty → warning
5. dns_subdomain_resolvable — dns.resolve_forward(site_subdomain) ok; skipped if no suffix configured

Overall status
--------------
- "pass"  — all checks pass
- "fail"  — at least one check has severity="error"
- "warn"  — no errors, at least one warning
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from cn_lens.adapters.registry import get_registry
from cn_lens.models import LensFinding, LensObject, LensObjectType, LensResult, ObjectSet
from cn_lens.workflows._helpers import (
    OFFLINE_FINDING_MESSAGE,
    run_workflow,
)

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

_WRONG_TYPE_MESSAGE = "validate_site requires a site code input"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _offline_classifier_finding() -> LensFinding:
    """Return the offline classifier info finding."""
    return LensFinding(
        severity="info",
        source="classifier",
        message=OFFLINE_FINDING_MESSAGE,
        detail={"workflow": "validate_site"},
    )


def _offline_result(obj: LensObject, sources: Dict[str, str]) -> LensResult:
    """MVP-shape result for offline / no-runtime path (all object types)."""
    return LensResult(
        lens_object=obj,
        status="classified",
        summary={
            "original": obj.original,
            "normalized": obj.normalized,
            "type": obj.object_type.value,
        },
        sources=sources,
        findings=(_offline_classifier_finding(),),
    )


# ---------------------------------------------------------------------------
# CheckResult type alias (plain dict for JSON serializability)
# ---------------------------------------------------------------------------

def _check_result(
    name: str,
    status: str,
    severity: str,
    message: str,
) -> Dict[str, str]:
    """Build a single check result dict."""
    return {
        "name": name,
        "status": status,    # "pass" | "fail" | "skip"
        "severity": severity,
        "message": message,
    }


def _overall_status(checks: List[Dict[str, str]]) -> str:
    """Derive overall_status from the check list.

    pass  — all checks are pass/skip
    fail  — at least one check is fail AND its severity is error
    warn  — no error-fails, at least one fail with severity warning
    """
    has_error_fail = any(
        c["status"] == "fail" and c["severity"] == "error" for c in checks
    )
    if has_error_fail:
        return "fail"
    has_warn_fail = any(
        c["status"] == "fail" and c["severity"] == "warning" for c in checks
    )
    if has_warn_fail:
        return "warn"
    return "pass"


# ---------------------------------------------------------------------------
# Per-site check runners
# ---------------------------------------------------------------------------

def _check_ad_known(
    runtime: "LensRuntime",
    site: str,
    checks: List[Dict[str, str]],
    findings: List[LensFinding],
) -> bool:
    """Check 1: ad_known — site found in Active Directory.

    Called before the Infoblox check (check 3), so no prefix list is available
    at this point.  The lookup falls back to the site-object path only.  If a
    future refactor reorders the checks or runs Infoblox first, prefixes can be
    wired in here (P5 follow-up).
    """
    from cn_lens.adapters import active_directory as ad
    try:
        ad_result, _ad_findings = ad.lookup_site(runtime, site, prefixes=())
        if ad_result.found:
            checks.append(_check_result("ad_known", "pass", "info", "Site found in AD"))
            return True
        else:
            msg = "Site not found in AD"
            checks.append(_check_result("ad_known", "fail", "error", msg))
            findings.append(LensFinding(severity="error", source="ad", message=msg, detail={"site": site}))
            return False
    except Exception as exc:
        runtime.logger.error("validate_site: ad.lookup_site raised unexpectedly: %s", exc)
        msg = f"AD lookup error: {exc}"
        checks.append(_check_result("ad_known", "fail", "error", msg))
        findings.append(LensFinding(severity="error", source="ad", message=msg, detail={"exception": type(exc).__name__}))
        return False


def _check_sdwan_known(
    runtime: "LensRuntime",
    site: str,
    checks: List[Dict[str, str]],
    findings: List[LensFinding],
) -> None:
    """Check 2: sdwan_known — site found in SD-WAN YAML."""
    from cn_lens.adapters import sdwan_yaml
    try:
        sdwan_result = sdwan_yaml.lookup_site(runtime, site)
        if sdwan_result.status == "found":
            checks.append(_check_result("sdwan_known", "pass", "info", "SD-WAN config found for site"))
        else:
            msg = "No SD-WAN config for site"
            checks.append(_check_result("sdwan_known", "fail", "warning", msg))
            findings.append(LensFinding(severity="warning", source="sdwan_yaml", message=msg, detail={"site": site}))
    except Exception as exc:
        runtime.logger.error("validate_site: sdwan_yaml.lookup_site raised unexpectedly: %s", exc)
        msg = f"SD-WAN lookup error: {exc}"
        checks.append(_check_result("sdwan_known", "fail", "error", msg))
        findings.append(LensFinding(severity="error", source="sdwan_yaml", message=msg, detail={"exception": type(exc).__name__}))


def _check_infoblox_subnets(
    runtime: "LensRuntime",
    site: str,
    checks: List[Dict[str, str]],
    findings: List[LensFinding],
) -> None:
    """Check 3: infoblox_subnets_present — site has subnets in Infoblox."""
    from cn_lens.adapters import infoblox
    try:
        rows = infoblox.search_by_keyword(runtime, site, mode="site")
        if rows:
            checks.append(_check_result("infoblox_subnets_present", "pass", "info", "Infoblox subnets reference this site"))
        else:
            msg = "No Infoblox subnets reference this site"
            checks.append(_check_result("infoblox_subnets_present", "fail", "warning", msg))
            findings.append(LensFinding(severity="warning", source="infoblox", message=msg, detail={"site": site}))
    except Exception as exc:
        runtime.logger.error("validate_site: infoblox.search_by_keyword raised unexpectedly: %s", exc)
        msg = f"Infoblox lookup error: {exc}"
        checks.append(_check_result("infoblox_subnets_present", "fail", "error", msg))
        findings.append(LensFinding(severity="error", source="infoblox", message=msg, detail={"exception": type(exc).__name__}))


def _check_config_references(
    runtime: "LensRuntime",
    site: str,
    checks: List[Dict[str, str]],
    findings: List[LensFinding],
) -> None:
    """Check 4: config_references_present — site referenced in config repo."""
    from cn_lens.adapters import config_repo
    try:
        cr_result = config_repo.search(runtime, site)
        if cr_result.matches:
            checks.append(_check_result("config_references_present", "pass", "info", "Config files reference this site"))
        else:
            msg = "No config files reference this site"
            checks.append(_check_result("config_references_present", "fail", "warning", msg))
            findings.append(LensFinding(severity="warning", source="config_repo", message=msg, detail={"site": site}))
    except Exception as exc:
        runtime.logger.error("validate_site: config_repo.search raised unexpectedly: %s", exc)
        msg = f"Config repo lookup error: {exc}"
        checks.append(_check_result("config_references_present", "fail", "error", msg))
        findings.append(LensFinding(severity="error", source="config_repo", message=msg, detail={"exception": type(exc).__name__}))


def _check_dns_subdomain(
    runtime: "LensRuntime",
    site: str,
    checks: List[Dict[str, str]],
    findings: List[LensFinding],
) -> None:
    """Check 5: dns_subdomain_resolvable — site DNS subdomain resolves forward.

    Skipped with info finding when ``cfg.site_dns_suffix`` is not configured.
    """
    from cn_lens.adapters import dns

    dns_suffix = runtime.cfg.get("site_dns_suffix", "") if runtime.cfg else ""
    if not dns_suffix:
        msg = "DNS suffix not configured; skipping DNS subdomain check"
        checks.append(_check_result("dns_subdomain_resolvable", "skip", "info", msg))
        findings.append(LensFinding(severity="info", source="dns", message=msg, detail={"site": site}))
        return

    fqdn = f"{site}.{dns_suffix}"
    try:
        dns_result = dns.resolve_forward(runtime, fqdn)
        if dns_result.status == "ok" and (dns_result.a_records or dns_result.aaaa_records):
            checks.append(_check_result("dns_subdomain_resolvable", "pass", "info", f"{fqdn} resolves ok"))
        else:
            msg = f"DNS subdomain {fqdn!r} did not resolve"
            checks.append(_check_result("dns_subdomain_resolvable", "fail", "warning", msg))
            findings.append(LensFinding(severity="warning", source="dns", message=msg, detail={"fqdn": fqdn}))
    except Exception as exc:
        runtime.logger.error("validate_site: dns.resolve_forward raised unexpectedly: %s", exc)
        msg = f"DNS lookup error for {fqdn!r}: {exc}"
        checks.append(_check_result("dns_subdomain_resolvable", "fail", "error", msg))
        findings.append(LensFinding(severity="error", source="dns", message=msg, detail={"exception": type(exc).__name__}))


# ---------------------------------------------------------------------------
# Per-type online handlers (runtime, obj, base_summary) -> (summary, findings)
# ---------------------------------------------------------------------------

def _run_site(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run all validate_site checks for a SITE object."""
    site = obj.value
    checks: List[Dict[str, str]] = []
    findings: List[LensFinding] = []

    # Run checks in documented order; each function appends to checks and findings.
    _check_ad_known(runtime, site, checks, findings)
    _check_sdwan_known(runtime, site, checks, findings)
    _check_infoblox_subnets(runtime, site, checks, findings)
    _check_config_references(runtime, site, checks, findings)
    _check_dns_subdomain(runtime, site, checks, findings)

    overall = _overall_status(checks)

    summary: Dict[str, Any] = {
        **base_summary,
        "validate_site": {
            "checks": checks,
            "overall_status": overall,
        },
    }
    return summary, findings


def _run_wrong_type(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Return classifier-only result for non-SITE objects."""
    findings: List[LensFinding] = [
        LensFinding(
            severity="info",
            source="classifier",
            message=_WRONG_TYPE_MESSAGE,
            detail={"workflow": "validate_site"},
        )
    ]
    return dict(base_summary), findings


_DISPATCH = {
    LensObjectType.SITE: _run_site,
    LensObjectType.IP: _run_wrong_type,
    LensObjectType.PREFIX: _run_wrong_type,
    LensObjectType.FQDN: _run_wrong_type,
    LensObjectType.DEVICE: _run_wrong_type,
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def validate_site_objects(
    object_set: ObjectSet,
    *,
    runtime: Optional["LensRuntime"] = None,
    run_id: Optional[str] = None,
) -> LensRun:
    """Validate site objects across AD, SD-WAN YAML, Infoblox, config-repo, and DNS."""
    return run_workflow(
        "validate_site",
        object_set,
        runtime,
        registry=get_registry(),
        run_id=run_id,
        dispatch=_DISPATCH,
        offline_result_fn=_offline_result,
    )
