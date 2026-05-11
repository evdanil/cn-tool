"""Device workflow — enriches device objects using AD, Infoblox, config_repo, and
optionally the reachability adapter (ping) when ``probe=True``.

Offline / None runtime
-----------------------
Returns the MVP-shape LensRun (classifier finding + not_queried sources) with no
adapter I/O.

Online runtime
--------------
Per-object-type adapter composition:

DEVICE
    1. ad.lookup_device(hostname)
    2. infoblox.search_by_keyword(hostname)
    3. infoblox.lookup_fqdn(hostname)  — only when hostname has >= 3 dot-separated
       labels (i.e. it looks like a real FQDN rather than a short device name)
    4. config_repo.search(hostname)
    5. [probe only] reachability.ping(ip) for each IP resolved in step 2/3

IP
    1. ad.enrich_ip(ip)              — resolves hostname via reverse-DNS + AD lookup
    2. infoblox.lookup_ip(ip)
    3. config_repo.search(ip)
    4. If enrich_ip returned a hostname: re-enter the DEVICE chain for that hostname
       (ad.lookup_device + ib_keyword + ib_fqdn if FQDN-shaped + config_repo)

FQDN
    If the value has < 3 dot-separated labels (hostname-pattern):
        → treat as DEVICE (run the full DEVICE chain)
    Otherwise:
        → classifier-only; emit info finding "Not a device hostname; use dns workflow"

SITE
    Classifier-only; emit info finding
    "Use validate site or decommission site for site-level workflows"

PREFIX
    Classifier-only; emit info finding
    "Prefix not a device input; use inspect or impact"

Hostname-FQDN distinction rule
-------------------------------
A hostname is considered FQDN-shaped (triggers infoblox.lookup_fqdn) when it has
3 or more dot-separated labels.  The same rule decides whether a FQDN object is
treated as a device:
    "device1"          → 1 label → short hostname (FQDN lookup skipped)
    "device1.corp"     → 2 labels → short hostname (FQDN lookup skipped)
    "device1.corp.com" → 3 labels → FQDN-shaped (FQDN lookup included)

Probe flag
----------
When ``probe=True`` the adapter calls ``reachability.ping`` for every IP address
extracted from the Infoblox search_by_keyword and lookup_fqdn results.  A single
info finding per IP is added to the result recording the outcome.  ping errors are
caught and recorded as info findings; they never propagate.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

from cn_lens.adapters.registry import get_registry
from cn_lens.models import LensFinding, LensObject, LensObjectType, LensResult, LensRun, ObjectSet
from cn_lens.workflows._helpers import (
    is_short_hostname,
    make_run_id,
    maybe_persist,
    synthesise_error_finding as _synthesise_error_finding,
)

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CLASSIFIER_SOURCE = "classifier"
_OFFLINE_SOURCES: Dict[str, str] = {
    "classifier": "ok",
    "infoblox": "not_queried",
    "config_repo": "not_queried",
    "ad": "not_queried",
}

# Message used in the initial classifier info finding (matches inspect pattern)
_CLASSIFIER_MESSAGE = "device workflow — enriches device objects across AD, Infoblox, and config"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_fqdn_shaped(hostname: str) -> bool:
    """Return True when the hostname has 3+ dot-separated labels (looks like a full FQDN).

    Rule (inverse of is_short_hostname):
        "device1"          → 1 label  → False (short; no IB FQDN lookup)
        "device1.corp"     → 2 labels → False (short; no IB FQDN lookup)
        "device1.corp.com" → 3 labels → True  (FQDN-shaped; include IB FQDN lookup)
    """
    return not is_short_hostname(hostname)


def _classifier_finding() -> LensFinding:
    return LensFinding(
        severity="info",
        source=_CLASSIFIER_SOURCE,
        message=_CLASSIFIER_MESSAGE,
        detail={"workflow": "device"},
    )


def _info_finding(source: str, message: str, detail: Dict[str, Any] | None = None) -> LensFinding:
    return LensFinding(severity="info", source=source, message=message, detail=detail or {})


def _error_finding(source: str, exc: Exception) -> LensFinding:
    return _synthesise_error_finding(source, exc)


# ---------------------------------------------------------------------------
# Offline path
# ---------------------------------------------------------------------------

def _build_offline_result(obj: LensObject) -> LensResult:
    return LensResult(
        lens_object=obj,
        status="classified",
        summary={
            "original": obj.original,
            "normalized": obj.normalized,
            "type": obj.object_type.value,
        },
        sources=_OFFLINE_SOURCES,
        findings=(_classifier_finding(),),
    )


# ---------------------------------------------------------------------------
# IB IP extraction helper
# ---------------------------------------------------------------------------

def _extract_ips_from_ib_rows(rows) -> List[str]:
    """Extract bare IP addresses from InfobloxRow list.

    A row is considered a bare IP when its ``network`` field looks like an IPv4
    address (no slash component).
    """
    ips = []
    for row in rows:
        net = getattr(row, "network", "") or ""
        if net and "/" not in net:
            # Very lightweight heuristic: 4 dot-separated numeric octets
            parts = net.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                ips.append(net)
    return ips


def _extract_ips_from_fqdn_result(fqdn_result) -> List[str]:
    """Extract IP addresses from InfobloxFqdnResult records."""
    if fqdn_result is None:
        return []
    ips = []
    for record in getattr(fqdn_result, "records", ()):
        ip = record.get("ip", "") if isinstance(record, dict) else ""
        if ip:
            ips.append(ip)
    return ips


# ---------------------------------------------------------------------------
# Probe helper
# ---------------------------------------------------------------------------

def _probe_ips(
    runtime: "LensRuntime",
    ips: List[str],
    findings: List[LensFinding],
    probe_summary: Dict[str, Any],
) -> None:
    """Ping each IP and record the outcome as an info finding.  Never raises."""
    from cn_lens.adapters import reachability

    seen: Set[str] = set()
    results = []
    for ip in ips:
        if ip in seen:
            continue
        seen.add(ip)
        try:
            ping_result = reachability.ping(runtime, ip)
            results.append({"ip": ip, "success": ping_result.success, "error": ping_result.error})
            findings.append(_info_finding(
                source="reachability",
                message="ping_ok" if ping_result.success else "ping_failed",
                detail={"ip": ip, "loss_pct": ping_result.loss_pct, "error": ping_result.error},
            ))
        except Exception as exc:
            runtime.logger.error("device: reachability.ping raised unexpectedly for %s: %s", ip, exc)
            findings.append(_info_finding(
                source="reachability",
                message="ping_error",
                detail={"ip": ip, "error": str(exc)},
            ))
            results.append({"ip": ip, "success": False, "error": str(exc)})

    probe_summary["results"] = results


# ---------------------------------------------------------------------------
# DEVICE chain (shared by DEVICE type and FQDN-as-device dispatch)
# ---------------------------------------------------------------------------

def _run_device_chain(
    runtime: "LensRuntime",
    hostname: str,
    base_summary: Dict[str, Any],
    findings: List[LensFinding],
    probe: bool,
) -> Dict[str, Any]:
    """Execute the full device enrichment chain for a given hostname.

    Populates and returns a copy of ``base_summary`` with "ad", "infoblox",
    "config_repo", and optionally "probe" keys.  All adapter exceptions are
    caught and recorded as error findings; the chain always continues.
    """
    from cn_lens.adapters import active_directory, infoblox, config_repo

    summary: Dict[str, Any] = dict(base_summary)
    resolved_ips: List[str] = []

    # 1. ad.lookup_device
    try:
        ad_result, ad_findings = active_directory.lookup_device(runtime, hostname)
        summary["ad"] = {
            "found": ad_result.found,
            "ou_path": ad_result.ou_path,
            "last_site_code": ad_result.last_site_code,
            "computer_dn": ad_result.computer_dn,
        }
        findings.extend(ad_findings)
    except Exception as exc:
        runtime.logger.error("device: ad.lookup_device raised unexpectedly: %s", exc)
        findings.append(_error_finding("ad", exc))
        summary["ad"] = {"found": False, "error": str(exc)}

    # 2. infoblox.search_by_keyword
    try:
        ib_rows = infoblox.search_by_keyword(runtime, hostname)
        resolved_ips.extend(_extract_ips_from_ib_rows(ib_rows))
        summary["infoblox"] = {
            "match_count": len(ib_rows),
            "networks": [r.network for r in ib_rows],
        }
    except Exception as exc:
        runtime.logger.error("device: infoblox.search_by_keyword raised unexpectedly: %s", exc)
        findings.append(_error_finding("infoblox", exc))
        summary["infoblox"] = {"error": str(exc)}
        ib_rows = []

    # 3. infoblox.lookup_fqdn — only when hostname looks FQDN-shaped (>= 3 labels)
    if _is_fqdn_shaped(hostname):
        try:
            fqdn_result = infoblox.lookup_fqdn(runtime, hostname)
            resolved_ips.extend(_extract_ips_from_fqdn_result(fqdn_result))
            existing_ib = summary.get("infoblox", {})
            if isinstance(existing_ib, dict) and "error" not in existing_ib:
                existing_ib["fqdn_found"] = fqdn_result.found
                existing_ib["fqdn_record_count"] = len(fqdn_result.records)
                summary["infoblox"] = existing_ib
        except Exception as exc:
            runtime.logger.error("device: infoblox.lookup_fqdn raised unexpectedly: %s", exc)
            findings.append(_error_finding("infoblox", exc))

    # 4. config_repo.search
    try:
        cr_result = config_repo.search(runtime, hostname)
        summary["config_repo"] = {
            "total_files_scanned": cr_result.total_files_scanned,
            "match_count": len(cr_result.matches),
            "truncated": cr_result.truncated,
        }
    except Exception as exc:
        runtime.logger.error("device: config_repo.search raised unexpectedly: %s", exc)
        findings.append(_error_finding("config_repo", exc))
        summary["config_repo"] = {"error": str(exc)}

    # 5. [probe] ping resolved IPs
    if probe and resolved_ips:
        probe_summary: Dict[str, Any] = {}
        _probe_ips(runtime, resolved_ips, findings, probe_summary)
        summary["probe"] = probe_summary

    return summary


# ---------------------------------------------------------------------------
# Per-type dispatchers
# ---------------------------------------------------------------------------

def _run_device(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    probe: bool,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    findings: List[LensFinding] = []
    summary = _run_device_chain(runtime, obj.value, base_summary, findings, probe)
    return summary, findings


def _run_ip(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    probe: bool,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """IP → enrich_ip + ib_lookup_ip + config_repo + optional secondary device chain."""
    from cn_lens.adapters import active_directory, infoblox, config_repo

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = []
    ip = obj.value
    resolved_hostname: str = ""

    # 1. ad.enrich_ip
    try:
        ad_enrichment, ad_findings = active_directory.enrich_ip(runtime, ip)
        resolved_hostname = ad_enrichment.resolved_hostname or ""
        summary["ad"] = {
            "resolved_hostname": resolved_hostname,
            "ou_path": ad_enrichment.device_result.ou_path,
            "last_site_code": ad_enrichment.device_result.last_site_code,
            "computer_dn": ad_enrichment.device_result.computer_dn,
            "found": ad_enrichment.device_result.found,
        }
        findings.extend(ad_findings)
    except Exception as exc:
        runtime.logger.error("device: ad.enrich_ip raised unexpectedly: %s", exc)
        findings.append(_error_finding("ad", exc))
        summary["ad"] = {"found": False, "error": str(exc)}

    # 2. infoblox.lookup_ip
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
    except Exception as exc:
        runtime.logger.error("device: infoblox.lookup_ip raised unexpectedly: %s", exc)
        findings.append(_error_finding("infoblox", exc))
        summary["infoblox"] = {"found": False, "error": str(exc)}

    # 3. config_repo.search
    try:
        cr_result = config_repo.search(runtime, ip)
        summary["config_repo"] = {
            "total_files_scanned": cr_result.total_files_scanned,
            "match_count": len(cr_result.matches),
            "truncated": cr_result.truncated,
        }
    except Exception as exc:
        runtime.logger.error("device: config_repo.search raised unexpectedly: %s", exc)
        findings.append(_error_finding("config_repo", exc))
        summary["config_repo"] = {"error": str(exc)}

    # 4. Secondary device chain when enrich_ip resolved a hostname
    if resolved_hostname:
        secondary_base = {"hostname": resolved_hostname}
        secondary_findings: List[LensFinding] = []
        secondary_summary = _run_device_chain(
            runtime, resolved_hostname, secondary_base, secondary_findings, probe
        )
        findings.extend(secondary_findings)
        # Merge secondary results under "device" key
        summary["device"] = {
            "hostname": resolved_hostname,
            "ad": secondary_summary.get("ad", {}),
            "infoblox": secondary_summary.get("infoblox", {}),
            "config_repo": secondary_summary.get("config_repo", {}),
        }

    return summary, findings


def _run_fqdn(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    probe: bool,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """FQDN → if looks like a hostname (< 3 labels) run device chain; else classifier-only."""
    findings: List[LensFinding] = []
    value = obj.value

    if not _is_fqdn_shaped(value):
        # Hostname-pattern: treat as DEVICE
        summary = _run_device_chain(runtime, value, base_summary, findings, probe)
        return summary, findings
    else:
        # Full FQDN — not a device hostname
        summary = dict(base_summary)
        findings.append(_info_finding(
            source="device",
            message="Not a device hostname; use dns workflow",
            detail={"value": value, "labels": len(value.split("."))},
        ))
        return summary, findings


def _run_site(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    probe: bool,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    summary = dict(base_summary)
    findings = [_info_finding(
        source="device",
        message="Use validate site or decommission site for site-level workflows",
        detail={"value": obj.value},
    )]
    return summary, findings


def _run_prefix(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    probe: bool,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    summary = dict(base_summary)
    findings = [_info_finding(
        source="device",
        message="Prefix not a device input; use inspect or impact",
        detail={"value": obj.value},
    )]
    return summary, findings


_Dispatcher = Callable[
    ["LensRuntime", LensObject, Dict[str, Any], bool],
    Tuple[Dict[str, Any], List[LensFinding]],
]
_DISPATCH: Dict[LensObjectType, _Dispatcher] = {
    LensObjectType.DEVICE: _run_device,
    LensObjectType.IP: _run_ip,
    LensObjectType.FQDN: _run_fqdn,
    LensObjectType.SITE: _run_site,
    LensObjectType.PREFIX: _run_prefix,
}


# ---------------------------------------------------------------------------
# Online per-object runner
# ---------------------------------------------------------------------------

def _build_online_result(
    obj: LensObject,
    runtime: "LensRuntime",
    sources: Dict[str, str],
    probe: bool,
) -> LensResult:
    base_summary: Dict[str, Any] = {
        "original": obj.original,
        "normalized": obj.normalized,
        "type": obj.object_type.value,
    }
    findings: List[LensFinding] = [_classifier_finding()]

    dispatcher = _DISPATCH.get(obj.object_type)
    if dispatcher is not None:
        try:
            summary, adapter_findings = dispatcher(runtime, obj, base_summary, probe)
            findings.extend(adapter_findings)
        except Exception as exc:
            runtime.logger.error("device: unexpected error in dispatcher: %s", exc)
            summary = dict(base_summary)
            findings.append(_error_finding("device", exc))
    else:
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

def device_objects(
    object_set: ObjectSet,
    *,
    runtime: Optional["LensRuntime"] = None,
    run_id: Optional[str] = None,
    probe: bool = False,
) -> LensRun:
    """Classify and enrich a batch of device-oriented network objects.

    Parameters
    ----------
    object_set:
        The ``ObjectSet`` produced by ``classify_many``.
    runtime:
        Optional ``LensRuntime``.  When ``None`` or ``runtime.offline`` is
        ``True`` the function returns the offline MVP-shape output without
        contacting any live adapters.
    run_id:
        Explicit run identifier.  Precedence order:
        1. ``run_id`` kwarg (if not None)
        2. ``runtime.options.run_id`` (if runtime is not None and not None)
        3. Auto-generated UTC timestamp via ``make_run_id()``.
    probe:
        When ``True`` ping each IP resolved from Infoblox results.

    Returns
    -------
    LensRun
        Always returned; never raises.  ``LensRun.workflow == "device"``.
    """
    # --- Resolve run_id ---
    if run_id is not None:
        effective_run_id = run_id
    elif runtime is not None and runtime.options.run_id is not None:
        effective_run_id = runtime.options.run_id
    else:
        effective_run_id = make_run_id()

    # --- Offline path ---
    if runtime is None or runtime.offline:
        results = tuple(_build_offline_result(obj) for obj in object_set.objects)
        return LensRun(
            schema_version=1,
            tool="cn-lens",
            workflow="device",
            run_id=effective_run_id,
            inputs=object_set,
            results=results,
            warnings=(),
            errors=(),
        )

    # --- Online path ---
    registry = get_registry()
    sources: Dict[str, str] = {"classifier": "ok"}
    sources.update(registry.source_statuses(runtime))

    results = tuple(
        _build_online_result(obj, runtime, sources, probe)
        for obj in object_set.objects
    )

    run = LensRun(
        schema_version=1,
        tool="cn-lens",
        workflow="device",
        run_id=effective_run_id,
        inputs=object_set,
        results=results,
        warnings=(),
        errors=(),
    )
    maybe_persist(run, runtime)
    return run
