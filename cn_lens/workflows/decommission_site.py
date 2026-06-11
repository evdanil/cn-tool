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

import re
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from cn_lens.adapters.registry import get_registry
from cn_lens.models import LensFinding, LensObject, LensObjectType, LensResult, ObjectSet
from cn_lens.workflows._helpers import OFFLINE_FINDING_MESSAGE, run_workflow

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

def _build_offline_result(obj: LensObject, sources: Dict[str, str]) -> LensResult:
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
        sources=sources,
        findings=(_offline_classifier_finding(),),
    )


# ---------------------------------------------------------------------------
# Non-SITE classifier-only path
# ---------------------------------------------------------------------------

def _run_wrong_type(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Return classifier-only (summary, findings) for non-SITE objects."""
    return dict(base_summary), [_classifier_finding()]


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
) -> Tuple[bool, List[str], List[LensFinding], List[Any]]:
    """Check whether Infoblox still has active subnets for the site.

    Returns
    -------
    (present, details, findings, infoblox_rows)
        ``infoblox_rows`` are the raw ``InfobloxRow`` objects for downstream
        use (e.g. country-prefix extraction in the config check).
    """
    from cn_lens.adapters import infoblox

    try:
        rows = infoblox.search_by_keyword(runtime, site, mode="site")
    except Exception as exc:
        runtime.logger.error(
            "decommission_site: infoblox.search_by_keyword raised unexpectedly: %s", exc
        )
        finding = _error_finding(
            "infoblox",
            str(exc),
            {"exception": type(exc).__name__},
        )
        return True, [str(exc)], [finding], []

    if not rows:
        return False, [], [], []

    networks = [r.network for r in rows]
    finding = _error_finding(
        "infoblox",
        "Active subnets still exist in Infoblox",
        {"subnets": networks},
    )
    return True, networks, [finding], list(rows)


def _build_device_name_pattern(site: str, infoblox_rows: List[Any]) -> str:
    """Build the device-name regex pattern that mirrors cn-tool's demob flow.

    Ported from ``modules/config_search.py`` ``execute_demob_search``::

        if country:
            pattern = rf'\\b(?:{country}{re.escape(sitecode.replace("-", ""))}|
                           {re.escape(sitecode)}[_0-9]+[-\\w\\d]*)\\b'
        else:
            pattern = rf'\\b(?:[A-Z]{{2}}{re.escape(sitecode.replace("-", ""))}|
                           {re.escape(sitecode)}[_0-9]+[-\\w\\d]*)\\b'

    Country is the first 2 characters of the comment field from the first
    Infoblox row (e.g. comment "AU; SYD01; Sydney DC" → country "AU").

    Note: ``[-\\w\\d]*`` contains a redundancy (``\\d``⊂``\\w``) that is a
    faithful copy of the cn-tool pattern from ``config_search.py`` and is
    kept verbatim deliberately.
    """
    country: Optional[str] = None
    if infoblox_rows:
        comment = infoblox_rows[0].comment if hasattr(infoblox_rows[0], "comment") else ""
        candidate = str(comment or "")[:2].strip().upper()  # first two chars = country code (e.g. "AU")
        if candidate.isalpha() and len(candidate) == 2:
            country = candidate

    escaped_site = re.escape(site)
    escaped_no_dash = re.escape(site.replace("-", ""))

    if country:
        return rf'\b(?:{country}{escaped_no_dash}|{escaped_site}[_0-9]+[-\w\d]*)\b'
    else:
        return rf'\b(?:[A-Z]{{2}}{escaped_no_dash}|{escaped_site}[_0-9]+[-\w\d]*)\b'


def _check_config_references(
    runtime: "LensRuntime",
    site: str,
    infoblox_rows: Optional[List[Any]] = None,
) -> Tuple[bool, List[str], List[LensFinding]]:
    """Check whether config repo contains references to the site.

    Implements the cn-tool demob-parity evidence chain:

    1. If Infoblox returned subnets, search each CIDR individually (IP-in-subnet
       matching in the adapter) and build per-subnet evidence rows.
    2. Additionally search a device-name regex pattern built from the site code
       and country prefix extracted from the first Infoblox comment.
    3. If no subnets were found (Infoblox returned nothing), fall back to a bare
       site-string search and note the fallback in the details row.

    Returns
    -------
    (present, details, findings)
        ``details`` contains per-subnet rows of the form
        ``"<subnet> — Used (N matches)"`` / ``"<subnet> — No match"`` and a
        device-name row ``"device-name pattern — Used (N matches)"`` /
        ``"device-name pattern — No match"``.
    """
    from cn_lens.adapters import config_repo

    rows: List[Any] = infoblox_rows if infoblox_rows else []
    subnet_cidrs: List[str] = [r.network for r in rows if hasattr(r, "network")]

    details: List[str] = []
    any_match = False

    try:
        if not subnet_cidrs:
            # --- Fallback: no subnets from Infoblox → bare site-string search ---
            details.append(f"No subnets found in Infoblox — fallback: searching site code '{site}'")
            result = config_repo.search(runtime, query=site)
            if result.matches:
                any_match = True
                details.append(
                    f"site-string '{site}' — Used ({len(result.matches)} matches)"
                )
            else:
                details.append(f"site-string '{site}' — No match")
        else:
            # --- Per-subnet evidence ---
            for cidr in subnet_cidrs:
                result = config_repo.search(runtime, query=cidr)
                match_count = len(result.matches)
                if match_count:
                    any_match = True
                    details.append(f"{cidr} — Used ({match_count} matches)")
                else:
                    details.append(f"{cidr} — No match")

            # --- Device-name regex ---
            device_name_pattern = _build_device_name_pattern(site, rows)
            dn_result = config_repo.search(runtime, query=device_name_pattern)
            dn_count = len(dn_result.matches)
            if dn_count:
                any_match = True
                details.append(f"device-name pattern — Used ({dn_count} matches)")
            else:
                details.append("device-name pattern — No match")

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

    if not any_match:
        return False, details, []

    finding = _error_finding(
        "config_repo",
        "Site code still referenced in configuration files",
        {"details": details},
    )
    return True, details, [finding]


def _check_ad_account(
    runtime: "LensRuntime",
    site: str,
    prefixes: Optional[List[str]] = None,
) -> Tuple[bool, List[str], List[LensFinding]]:
    """Check whether the AD site object still exists.

    Parameters
    ----------
    prefixes:
        Optional list of CIDR strings found by the upstream Infoblox search
        (from ``_check_active_subnets``).  Passed to ``ad.lookup_site`` so
        that the per-subnet LDAP queries use actual CIDR names rather than the
        bare site code (B9 fix: AD subnet objects are named by CIDR, not site
        code).  When None or empty, the per-subnet path is skipped and only
        the direct site-object lookup runs.

    Returns
    -------
    (present, details, findings)
    """
    from cn_lens.adapters import active_directory as ad

    effective_prefixes = prefixes if prefixes is not None else []

    try:
        ad_result, _ad_findings = ad.lookup_site(runtime, site, prefixes=effective_prefixes)
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

def _run_site(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Run all four blocker checks for a SITE object; return (summary, findings)."""
    site = obj.value
    cfg = dict(runtime.cfg) if hasattr(runtime.cfg, "items") else {}

    findings: List[LensFinding] = []
    blockers: List[Dict[str, Any]] = []

    # --- 1. active_subnets ---
    present, details, check_findings, ib_rows = _check_active_subnets(runtime, site)
    findings.extend(check_findings)
    blockers.append(_make_blocker_entry("active_subnets", present, details))
    # Collect Infoblox-found prefixes to pass into the AD lookup (B9 fix):
    # AD subnet objects are named by CIDR, so the bare site code can never
    # match; we use the CIDRs found by Infoblox as the subnet query targets.
    # Derived from ib_rows (structured data) rather than display strings so
    # that error-string details (when Infoblox threw) are never mistaken for
    # prefixes; ib_rows is empty on both error and no-results paths.
    infoblox_prefixes: List[str] = [r.network for r in ib_rows]

    # --- 2. config_references ---
    # Pass the raw Infoblox rows so the config check can search per-subnet
    # (IP-in-subnet) and build the device-name regex (demob-parity, P1.10).
    present, details, check_findings = _check_config_references(
        runtime, site, infoblox_rows=ib_rows
    )
    findings.extend(check_findings)
    blockers.append(_make_blocker_entry("config_references", present, details))

    # --- 3. ad_account ---
    present, details, check_findings = _check_ad_account(
        runtime, site, prefixes=infoblox_prefixes
    )
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
        **base_summary,
        "decommission_site": {
            "blockers": blockers,
            "verdict": verdict,
        },
    }
    return summary, findings


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

def decommission_site_objects(
    object_set: ObjectSet,
    *,
    runtime: Optional["LensRuntime"] = None,
    run_id: Optional[str] = None,
) -> LensRun:
    """Run decommission-site checks for every object in *object_set*."""
    return run_workflow(
        "decommission_site",
        object_set,
        runtime,
        registry=get_registry(),
        run_id=run_id,
        dispatch=_DISPATCH,
        offline_result_fn=_build_offline_result,
    )
