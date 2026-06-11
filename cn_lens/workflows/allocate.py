"""Allocate workflow — safety-checks a candidate prefix before allocation.

Offline / None runtime
-----------------------
Returns the MVP-shape LensRun with a single classifier info finding per object
and the ``not_queried`` source status for every adapter.  No adapter I/O occurs.

Online runtime
--------------
For PREFIX objects: runs all applicable checks (ipam_availability, overlap_check,
inheritance_acceptable, target_site_known, no_existing_config_reference) and
derives a verdict (safe_to_allocate, caution, unsafe).

For non-PREFIX objects: returns a classifier-only result with an info finding
"allocate requires a prefix input".

Per-check behaviour
-------------------
ipam_availability        : infoblox.lookup_prefix — if found → error
overlap_check            : infoblox.search_by_keyword (network portion) — any
                           overlap → error
inheritance_acceptable   : only when target_site given; lookup supernet extattrs,
                           compare with site; mismatch → warning
target_site_known        : only when target_site given; ad.lookup_site must
                           succeed; failure → error
no_existing_config_reference : config_repo.search — any hit → warning

Verdict calculation
-------------------
- any error  → "unsafe"
- warnings only → "caution"
- no findings of concern → "safe_to_allocate"
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from cn_lens.adapters.registry import get_registry
from cn_lens.models import (
    LensFinding,
    LensObject,
    LensObjectType,
    LensResult,
    LensRun,
    ObjectSet,
)
from cn_lens.workflows._helpers import run_workflow, synthesise_error_finding

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

CLASSIFIER_FINDING_MESSAGE: str = "allocate requires a prefix input"

# Documented check order (preserved in summary["allocate"]["checks"])
_CHECK_ORDER = (
    "ipam_availability",
    "overlap_check",
    "inheritance_acceptable",
    "target_site_known",
    "no_existing_config_reference",
)


# ---------------------------------------------------------------------------
# Internal types
# ---------------------------------------------------------------------------

CheckResult = Dict[str, str]  # name, status, severity, message


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _classifier_finding(obj: LensObject) -> LensFinding:
    """Info finding for non-PREFIX objects."""
    return LensFinding(
        severity="info",
        source="classifier",
        message=CLASSIFIER_FINDING_MESSAGE,
        detail={"workflow": "allocate", "type": obj.object_type.value},
    )


def _make_check_result(
    name: str,
    *,
    status: str,
    severity: str,
    message: str,
) -> CheckResult:
    return {"name": name, "status": status, "severity": severity, "message": message}


def _skip_check(name: str, reason: str) -> CheckResult:
    return _make_check_result(
        name,
        status="skipped",
        severity="info",
        message=f"skip — {reason}",
    )


def _derive_verdict(checks: List[CheckResult]) -> str:
    """Derive verdict from collected check results.

    - Any check with severity ``error``   → ``unsafe``
    - Any check with severity ``warning`` → ``caution``  (no errors)
    - Otherwise                           → ``safe_to_allocate``
    """
    has_error = any(c["severity"] == "error" for c in checks)
    has_warning = any(c["severity"] == "warning" for c in checks)
    if has_error:
        return "unsafe"
    if has_warning:
        return "caution"
    return "safe_to_allocate"


def _network_portion(prefix: str) -> str:
    """Return just the network address string from a CIDR prefix."""
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        return str(net.network_address)
    except ValueError:
        return prefix.split("/")[0]


def _networks_overlap(candidate: str, other: str) -> bool:
    """Return True if candidate and other networks overlap."""
    try:
        net_a = ipaddress.ip_network(candidate, strict=False)
        net_b = ipaddress.ip_network(other, strict=False)
        return net_a.overlaps(net_b)
    except ValueError:
        return False


def _supernet_of(prefix: str) -> Optional[str]:
    """Return the immediate supernet CIDR string, or None if already /0."""
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        supernet = net.supernet()
        if supernet == net:
            return None
        return str(supernet)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Offline path
# ---------------------------------------------------------------------------

def _build_offline_result(obj: LensObject, sources: Dict[str, str]) -> LensResult:
    """Build the MVP-shape LensResult when offline or runtime is None."""
    return LensResult(
        lens_object=obj,
        status="classified",
        summary={
            "original": obj.original,
            "normalized": obj.normalized,
            "type": obj.object_type.value,
        },
        sources=sources,
        findings=(_classifier_finding(obj),),
    )


# ---------------------------------------------------------------------------
# Per-check runners (online path)
# ---------------------------------------------------------------------------

def _check_ipam_availability(
    runtime: "LensRuntime",
    prefix: str,
) -> Tuple[CheckResult, List[LensFinding]]:
    """Check 1: is the prefix already in IPAM?"""
    from cn_lens.adapters import infoblox

    try:
        result = infoblox.lookup_prefix(runtime, prefix)
    except Exception as exc:
        runtime.logger.error("allocate: ipam_availability: unexpected error: %s", exc)
        finding = synthesise_error_finding("infoblox", exc)
        return (
            _make_check_result(
                "ipam_availability",
                status="error",
                severity="error",
                message=str(exc),
            ),
            [finding],
        )

    if result.found:
        msg = "Prefix already exists in IPAM"
        return (
            _make_check_result(
                "ipam_availability",
                status="error",
                severity="error",
                message=msg,
            ),
            [LensFinding(severity="error", source="infoblox", message=msg, detail={"prefix": prefix})],
        )

    return (
        _make_check_result(
            "ipam_availability",
            status="ok",
            severity="info",
            message="Prefix not found in IPAM — available",
        ),
        [],
    )


def _check_overlap(
    runtime: "LensRuntime",
    prefix: str,
) -> Tuple[CheckResult, List[LensFinding]]:
    """Check 2: does the candidate overlap any existing network?"""
    from cn_lens.adapters import infoblox

    network_addr = _network_portion(prefix)
    try:
        rows = infoblox.search_by_keyword(runtime, network_addr)
    except Exception as exc:
        runtime.logger.error("allocate: overlap_check: unexpected error: %s", exc)
        finding = synthesise_error_finding("infoblox", exc)
        return (
            _make_check_result(
                "overlap_check",
                status="error",
                severity="error",
                message=str(exc),
            ),
            [finding],
        )

    overlapping = [r.network for r in rows if _networks_overlap(prefix, r.network)]
    if overlapping:
        ref = overlapping[0]
        msg = f"Overlaps existing network {ref}"
        return (
            _make_check_result(
                "overlap_check",
                status="error",
                severity="error",
                message=msg,
            ),
            [LensFinding(
                severity="error",
                source="infoblox",
                message=msg,
                detail={"prefix": prefix, "overlapping_network": ref},
            )],
        )

    return (
        _make_check_result(
            "overlap_check",
            status="ok",
            severity="info",
            message="No overlapping networks found",
        ),
        [],
    )


def _check_inheritance_acceptable(
    runtime: "LensRuntime",
    prefix: str,
    target_site: str,
) -> Tuple[CheckResult, List[LensFinding]]:
    """Check 3: are inherited extattrs from the supernet compatible with target_site?

    Strategy: look up the supernet in IPAM via ``infoblox.lookup_prefix``.
    If the supernet exists, compare its extattrs keys against what we know
    about the site (we check whether any extattr value references a different
    site code than target_site).  A mismatch emits a warning.
    """
    from cn_lens.adapters import infoblox

    supernet = _supernet_of(prefix)
    if not supernet:
        return (
            _make_check_result(
                "inheritance_acceptable",
                status="ok",
                severity="info",
                message="No supernet to inherit from",
            ),
            [],
        )

    try:
        parent_result = infoblox.lookup_prefix(runtime, supernet)
    except Exception as exc:
        runtime.logger.error("allocate: inheritance_acceptable: unexpected error: %s", exc)
        finding = synthesise_error_finding("infoblox", exc)
        return (
            _make_check_result(
                "inheritance_acceptable",
                status="error",
                severity="error",
                message=str(exc),
            ),
            [finding],
        )

    if not parent_result.found:
        # No parent container — nothing to inherit; treat as acceptable.
        return (
            _make_check_result(
                "inheritance_acceptable",
                status="ok",
                severity="info",
                message="Supernet not found in IPAM — no inheritance to check",
            ),
            [],
        )

    # Check: does any extattr value mention a site code that differs from target_site?
    mismatch_attrs: List[str] = []
    for attr in parent_result.extattrs:
        val = str(attr.get("value", "")).upper()
        attr_name = str(attr.get("attribute", ""))
        # If an extattr value looks like a site code and differs from target_site
        if val and val != target_site.upper() and _looks_like_site_code(val):
            mismatch_attrs.append(attr_name)

    if mismatch_attrs:
        msg = "Inheritance differs from site default"
        return (
            _make_check_result(
                "inheritance_acceptable",
                status="warning",
                severity="warning",
                message=msg,
            ),
            [LensFinding(
                severity="warning",
                source="infoblox",
                message=msg,
                detail={
                    "supernet": supernet,
                    "target_site": target_site,
                    "mismatched_attrs": mismatch_attrs,
                },
            )],
        )

    return (
        _make_check_result(
            "inheritance_acceptable",
            status="ok",
            severity="info",
            message="Inherited extattrs are compatible with target site",
        ),
        [],
    )


def _looks_like_site_code(val: str) -> bool:
    """Heuristic: 3-8 alphanumeric characters — typical site code pattern."""
    return bool(val) and val.isalnum() and 3 <= len(val) <= 8


def _check_target_site_known(
    runtime: "LensRuntime",
    target_site: str,
) -> Tuple[CheckResult, List[LensFinding]]:
    """Check 4: is target_site resolvable in AD?

    No prefix list is available in the allocate flow (the candidate prefix
    has not yet been allocated, so no Infoblox-backed CIDR evidence exists).
    The site-object LDAP path covers this case.
    """
    from cn_lens.adapters import active_directory as ad

    try:
        site_result, ad_findings = ad.lookup_site(runtime, target_site, prefixes=())
    except Exception as exc:
        runtime.logger.error("allocate: target_site_known: unexpected error: %s", exc)
        finding = synthesise_error_finding("ad", exc)
        return (
            _make_check_result(
                "target_site_known",
                status="error",
                severity="error",
                message=str(exc),
            ),
            [finding],
        )

    if not site_result.found:
        msg = f"Target site '{target_site}' not found in AD"
        return (
            _make_check_result(
                "target_site_known",
                status="error",
                severity="error",
                message=msg,
            ),
            [LensFinding(severity="error", source="ad", message=msg, detail={"target_site": target_site})],
        )

    return (
        _make_check_result(
            "target_site_known",
            status="ok",
            severity="info",
            message=f"Target site '{target_site}' found in AD",
        ),
        [],
    )


def _check_no_config_reference(
    runtime: "LensRuntime",
    prefix: str,
) -> Tuple[CheckResult, List[LensFinding]]:
    """Check 5: is the prefix already referenced in config?"""
    from cn_lens.adapters import config_repo

    try:
        cr_result = config_repo.search(runtime, prefix)
    except Exception as exc:
        runtime.logger.error("allocate: no_existing_config_reference: unexpected error: %s", exc)
        finding = synthesise_error_finding("config_repo", exc)
        return (
            _make_check_result(
                "no_existing_config_reference",
                status="error",
                severity="error",
                message=str(exc),
            ),
            [finding],
        )

    if cr_result.matches:
        msg = "Prefix already referenced in config"
        return (
            _make_check_result(
                "no_existing_config_reference",
                status="warning",
                severity="warning",
                message=msg,
            ),
            [LensFinding(
                severity="warning",
                source="config_repo",
                message=msg,
                detail={
                    "prefix": prefix,
                    "match_count": len(cr_result.matches),
                },
            )],
        )

    return (
        _make_check_result(
            "no_existing_config_reference",
            status="ok",
            severity="info",
            message="Prefix not referenced in config",
        ),
        [],
    )


# ---------------------------------------------------------------------------
# Per-type online handlers — (runtime, obj, base_summary) -> (summary, findings)
# ---------------------------------------------------------------------------

def _run_prefix(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    target_site: Optional[str],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run all allocate checks for a PREFIX object."""
    prefix = obj.value
    findings: List[LensFinding] = []
    checks: List[CheckResult] = []

    # --- Check 1: ipam_availability ---
    check, check_findings = _check_ipam_availability(runtime, prefix)
    checks.append(check)
    findings.extend(check_findings)

    # --- Check 2: overlap_check ---
    check, check_findings = _check_overlap(runtime, prefix)
    checks.append(check)
    findings.extend(check_findings)

    # --- Check 3: inheritance_acceptable ---
    if target_site:
        check, check_findings = _check_inheritance_acceptable(runtime, prefix, target_site)
        checks.append(check)
        findings.extend(check_findings)
    else:
        checks.append(_skip_check("inheritance_acceptable", "no target_site"))
        findings.append(LensFinding(
            severity="info",
            source="allocate",
            message="skip — no target_site",
            detail={"check": "inheritance_acceptable"},
        ))

    # --- Check 4: target_site_known ---
    if target_site:
        check, check_findings = _check_target_site_known(runtime, target_site)
        checks.append(check)
        findings.extend(check_findings)
    else:
        checks.append(_skip_check("target_site_known", "no target_site"))
        findings.append(LensFinding(
            severity="info",
            source="allocate",
            message="skip — no target_site",
            detail={"check": "target_site_known"},
        ))

    # --- Check 5: no_existing_config_reference ---
    check, check_findings = _check_no_config_reference(runtime, prefix)
    checks.append(check)
    findings.extend(check_findings)

    verdict = _derive_verdict(checks)

    summary: Dict[str, Any] = {
        **base_summary,
        "allocate": {
            "checks": checks,
            "verdict": verdict,
        },
    }
    if target_site is not None:
        summary["allocate"]["target_site"] = target_site

    return summary, findings


def _run_wrong_type(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Return classifier-only result for non-PREFIX objects."""
    return dict(base_summary), [_classifier_finding(obj)]


def _make_dispatch(target_site: Optional[str]) -> Dict[LensObjectType, Any]:
    """Build dispatch table, capturing target_site in the PREFIX handler closure."""
    def _handle_prefix(runtime: "LensRuntime", obj: LensObject, base_summary: Dict[str, Any]):
        return _run_prefix(runtime, obj, base_summary, target_site)

    return {
        LensObjectType.PREFIX: _handle_prefix,
        LensObjectType.IP: _run_wrong_type,
        LensObjectType.FQDN: _run_wrong_type,
        LensObjectType.DEVICE: _run_wrong_type,
        LensObjectType.SITE: _run_wrong_type,
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def allocate_objects(
    object_set: ObjectSet,
    *,
    runtime: Optional["LensRuntime"] = None,
    run_id: Optional[str] = None,
    target_site: Optional[str] = None,
) -> LensRun:
    """Safety-check a candidate prefix before allocation."""
    return run_workflow(
        "allocate",
        object_set,
        runtime,
        registry=get_registry(),
        run_id=run_id,
        dispatch=_make_dispatch(target_site),
        offline_result_fn=_build_offline_result,
    )
