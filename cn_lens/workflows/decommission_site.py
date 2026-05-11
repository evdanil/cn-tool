"""Decommission-site workflow — checks whether a site is safe to decommission.

Offline / None runtime
-----------------------
Returns the MVP-shape LensRun with no blocker checks.  All sources are
``not_queried``.

Online runtime (SITE object type)
----------------------------------
Runs four blocker checks in order:

1. active_subnets   — infoblox.search_by_keyword(site) returns subnets
2. config_references — config_repo.search(query=site) returns matches
3. ad_account       — ad.lookup_site(site) returns found=True
4. dhcp_dns_records  — dns.resolve_forward(<site>.<site_dns_suffix>) returns records
                       (skipped with an info finding when site_dns_suffix not configured)

A check that throws an adapter exception is treated as a blocker (conservative
safety rule).

Online runtime (non-SITE object types)
---------------------------------------
Classifier-only: returns an info finding
"decommission_site requires a site code input" and no blocker checks.

Verdict
-------
``safe_to_decommission`` — no blockers present (all checks clear).
``blocked``              — at least one blocker present.

When verdict is ``safe_to_decommission`` a workflow-level ``info`` finding
"Site is safe to decommission" is also emitted.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from cn_lens.models import LensFinding, LensObject, LensObjectType, LensResult, LensRun, ObjectSet
from cn_lens.workflows._helpers import OFFLINE_FINDING_MESSAGE, make_run_id, maybe_persist

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Privatised — not part of the public API.  Tests that imported these by name
# from this module should import the private forms instead.
_CLASSIFIER_FINDING_MESSAGE: str = "decommission_site requires a site code input"
_SAFE_FINDING_MESSAGE: str = "Site is safe to decommission"

# Legacy public aliases kept for backwards compatibility with existing tests.
CLASSIFIER_FINDING_MESSAGE = _CLASSIFIER_FINDING_MESSAGE
SAFE_FINDING_MESSAGE = _SAFE_FINDING_MESSAGE

# Documented check order — preserved in summary["decommission_site"]["blockers"]
_BLOCKER_NAMES: Tuple[str, ...] = (
    "active_subnets",
    "config_references",
    "ad_account",
    "dhcp_dns_records",
)

# ---------------------------------------------------------------------------
# Offline sources map
# ---------------------------------------------------------------------------

_OFFLINE_SOURCES: Dict[str, str] = {
    "classifier": "ok",
    "infoblox": "not_queried",
    "config_repo": "not_queried",
    "ad": "not_queried",
    "dns": "not_queried",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _offline_classifier_finding() -> LensFinding:
    """Return the offline classifier info finding."""
    return LensFinding(
        severity="info",
        source="classifier",
        message=OFFLINE_FINDING_MESSAGE,
        detail={"workflow": "decommission_site"},
    )


def _classifier_finding() -> LensFinding:
    """Return the wrong-type classifier finding for non-SITE objects (online path)."""
    return LensFinding(
        severity="info",
        source="classifier",
        message=_CLASSIFIER_FINDING_MESSAGE,
        detail={"workflow": "decommission_site"},
    )


def _safe_finding() -> LensFinding:
    return LensFinding(
        severity="info",
        source="decommission_site",
        message=_SAFE_FINDING_MESSAGE,
        detail={"workflow": "decommission_site"},
    )


def _error_finding(source: str, message: str, detail: Optional[Dict[str, Any]] = None) -> LensFinding:
    return LensFinding(
        severity="error",
        source=source,
        message=message,
        detail=detail or {},
    )


def _info_finding(source: str, message: str, detail: Optional[Dict[str, Any]] = None) -> LensFinding:
    return LensFinding(
        severity="info",
        source=source,
        message=message,
        detail=detail or {},
    )


# ---------------------------------------------------------------------------
# Offline path
# ---------------------------------------------------------------------------

def _build_offline_result(obj: LensObject) -> LensResult:
    """Build offline MVP-shape result: no checks, single classifier finding.

    Mirrors the inspect offline path: every offline result carries exactly one
    classifier info finding with the standard MVP message.
    """
    return LensResult(
        lens_object=obj,
        status="classified",
        summary={
            "original": obj.original,
            "normalized": obj.normalized,
            "type": obj.object_type.value,
        },
        sources=_OFFLINE_SOURCES,
        findings=(_offline_classifier_finding(),),
    )


# ---------------------------------------------------------------------------
# Non-SITE classifier-only path
# ---------------------------------------------------------------------------

def _build_classifier_only_result(
    obj: LensObject,
    sources: Dict[str, str],
) -> LensResult:
    """Build a classifier-only result for non-SITE object types."""
    return LensResult(
        lens_object=obj,
        status="classified",
        summary={
            "original": obj.original,
            "normalized": obj.normalized,
            "type": obj.object_type.value,
        },
        sources=sources,
        findings=(_classifier_finding(),),
    )


# ---------------------------------------------------------------------------
# BlockerEntry helper
# ---------------------------------------------------------------------------

def _make_blocker_entry(name: str, present: bool, details: List[str]) -> Dict[str, Any]:
    return {"name": name, "present": present, "details": details}


# ---------------------------------------------------------------------------
# Individual blocker checks
# ---------------------------------------------------------------------------

def _check_active_subnets(
    runtime: "LensRuntime",
    site: str,
) -> Tuple[bool, List[str], List[LensFinding]]:
    """Check whether Infoblox still has active subnets for the site.

    Returns
    -------
    (present, details, findings)
    """
    from cn_lens.adapters import infoblox

    try:
        rows = infoblox.search_by_keyword(runtime, site)
    except Exception as exc:
        runtime.logger.error(
            "decommission_site: infoblox.search_by_keyword raised unexpectedly: %s", exc
        )
        finding = _error_finding(
            "infoblox",
            str(exc),
            {"exception": type(exc).__name__},
        )
        return True, [str(exc)], [finding]

    if not rows:
        return False, [], []

    networks = [r.network for r in rows]
    finding = _error_finding(
        "infoblox",
        "Active subnets still exist in Infoblox",
        {"subnets": networks},
    )
    return True, networks, [finding]


def _check_config_references(
    runtime: "LensRuntime",
    site: str,
) -> Tuple[bool, List[str], List[LensFinding]]:
    """Check whether config repo contains references to the site.

    Returns
    -------
    (present, details, findings)
    """
    from cn_lens.adapters import config_repo

    try:
        result = config_repo.search(runtime, query=site)
    except Exception as exc:
        runtime.logger.error(
            "decommission_site: config_repo.search raised unexpectedly: %s", exc
        )
        finding = _error_finding(
            "config_repo",
            str(exc),
            {"exception": type(exc).__name__},
        )
        return True, [str(exc)], [finding]

    if not result.matches:
        return False, [], []

    file_paths = sorted({m.file_path for m in result.matches})
    finding = _error_finding(
        "config_repo",
        "Site code still referenced in configuration files",
        {"file_paths": file_paths},
    )
    return True, file_paths, [finding]


def _check_ad_account(
    runtime: "LensRuntime",
    site: str,
) -> Tuple[bool, List[str], List[LensFinding]]:
    """Check whether the AD site object still exists.

    Returns
    -------
    (present, details, findings)
    """
    from cn_lens.adapters import active_directory as ad

    try:
        ad_result, _ad_findings = ad.lookup_site(runtime, site)
    except Exception as exc:
        runtime.logger.error(
            "decommission_site: ad.lookup_site raised unexpectedly: %s", exc
        )
        finding = _error_finding(
            "ad",
            str(exc),
            {"exception": type(exc).__name__},
        )
        return True, [str(exc)], [finding]

    if not ad_result.found:
        return False, [], []

    finding = _error_finding(
        "ad",
        "AD site account still exists",
        {"site_code": ad_result.site_code},
    )
    return True, ["AD site account still exists"], [finding]


def _check_dhcp_dns_records(
    runtime: "LensRuntime",
    site: str,
    cfg: Dict[str, Any],
) -> Tuple[bool, List[str], List[LensFinding]]:
    """Check whether DNS records still exist for the site.

    Requires ``site_dns_suffix`` in cfg.  When absent, skips the check with
    an info finding and returns ``(False, [], [info_finding])``.

    Returns
    -------
    (present, details, findings)
    """
    from cn_lens.adapters import dns

    suffix = cfg.get("site_dns_suffix", "")
    if not suffix:
        finding = _info_finding(
            "dns",
            "dhcp_dns_records check skipped: site_dns_suffix not configured",
            {"check": "dhcp_dns_records"},
        )
        return False, [], [finding]

    fqdn = f"{site}.{suffix}"
    try:
        dns_result = dns.resolve_forward(runtime, fqdn)
    except Exception as exc:
        runtime.logger.error(
            "decommission_site: dns.resolve_forward raised unexpectedly: %s", exc
        )
        finding = _error_finding(
            "dns",
            str(exc),
            {"exception": type(exc).__name__, "fqdn": fqdn},
        )
        return True, [str(exc)], [finding]

    has_records = bool(dns_result.a_records or dns_result.aaaa_records)
    if not has_records:
        return False, [], []

    records = list(dns_result.a_records) + list(dns_result.aaaa_records)
    finding = _error_finding(
        "dns",
        f"DNS records still exist for {fqdn}",
        {"fqdn": fqdn, "records": records},
    )
    return True, records, [finding]


# ---------------------------------------------------------------------------
# Online SITE path
# ---------------------------------------------------------------------------

def _build_site_result(
    obj: LensObject,
    runtime: "LensRuntime",
    sources: Dict[str, str],
) -> LensResult:
    """Run all four blocker checks and build a LensResult for a SITE object."""
    site = obj.value
    cfg = dict(runtime.cfg) if hasattr(runtime.cfg, "items") else {}

    findings: List[LensFinding] = []
    blockers: List[Dict[str, Any]] = []

    # --- 1. active_subnets ---
    present, details, check_findings = _check_active_subnets(runtime, site)
    findings.extend(check_findings)
    blockers.append(_make_blocker_entry("active_subnets", present, details))

    # --- 2. config_references ---
    present, details, check_findings = _check_config_references(runtime, site)
    findings.extend(check_findings)
    blockers.append(_make_blocker_entry("config_references", present, details))

    # --- 3. ad_account ---
    present, details, check_findings = _check_ad_account(runtime, site)
    findings.extend(check_findings)
    blockers.append(_make_blocker_entry("ad_account", present, details))

    # --- 4. dhcp_dns_records ---
    present, details, check_findings = _check_dhcp_dns_records(runtime, site, cfg)
    findings.extend(check_findings)
    blockers.append(_make_blocker_entry("dhcp_dns_records", present, details))

    # --- Verdict ---
    any_blocked = any(b["present"] for b in blockers)
    verdict = "blocked" if any_blocked else "safe_to_decommission"

    if not any_blocked:
        findings.append(_safe_finding())

    summary: Dict[str, Any] = {
        "original": obj.original,
        "normalized": obj.normalized,
        "type": obj.object_type.value,
        "decommission_site": {
            "blockers": blockers,
            "verdict": verdict,
        },
    }

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

def decommission_site_objects(
    object_set: ObjectSet,
    *,
    runtime: Optional["LensRuntime"] = None,
    run_id: Optional[str] = None,
) -> LensRun:
    """Run decommission-site checks for every object in *object_set*.

    Parameters
    ----------
    object_set:
        The ``ObjectSet`` produced by ``classify_many``.
    runtime:
        Optional ``LensRuntime``.  When ``None`` or ``runtime.offline`` is
        ``True`` the function returns the offline MVP-shape output without
        contacting any live adapters.  When online, all four blocker checks
        are run for SITE objects; non-SITE objects receive a classifier-only
        result with an info finding.
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
            _build_offline_result(obj) for obj in object_set.objects
        )
        return LensRun(
            schema_version=1,
            tool="cn-lens",
            workflow="decommission_site",
            run_id=effective_run_id,
            inputs=object_set,
            results=results,
            warnings=(),
            errors=(),
        )

    # --- Online path ---
    from cn_lens.adapters.registry import get_registry

    registry = get_registry()
    sources: Dict[str, str] = {"classifier": "ok"}
    sources.update(registry.source_statuses(runtime))

    results = tuple(
        _build_site_result(obj, runtime, sources)
        if obj.object_type == LensObjectType.SITE
        else _build_classifier_only_result(obj, sources)
        for obj in object_set.objects
    )

    run = LensRun(
        schema_version=1,
        tool="cn-lens",
        workflow="decommission_site",
        run_id=effective_run_id,
        inputs=object_set,
        results=results,
        warnings=(),
        errors=(),
    )
    maybe_persist(run, runtime)
    return run
