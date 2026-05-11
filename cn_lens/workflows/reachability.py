"""Reachability workflow — ping / traceroute across all object types.

Offline / None runtime
-----------------------
Returns the MVP-shape LensRun with a single classifier info finding per object
and ``not_queried`` source status for every adapter.  No adapter I/O occurs.

Online runtime
--------------
Per-object-type adapter composition:

IP     : ping (always for mode "ping"/"both"); trace / trace_with_site_mapping
         (for mode "trace"/"both").  When the AD adapter health is "ok",
         trace_with_site_mapping is used with a lambda that calls ad.enrich_ip
         to map each hop IP to a site code.  When AD is not_configured/disabled,
         bare trace is used.

FQDN   : dns.resolve_forward → for each resolved IP, ping/trace as above.
         Capped to first 4 IPs.  If no IPs resolve, emits an info finding and
         skips all adapter calls.

PREFIX : ping_many on the network host range.  Capped at 32 hosts.  Emits a
         warning finding when the prefix has more than 32 host IPs.

SITE   : ad.lookup_site to obtain site metadata.  If found=True, pings the
         site_code as a hostname target.  If not found, emits an info finding
         and skips ping.

DEVICE : ad.lookup_device to resolve the device.  If found=True, pings the
         original hostname.  If not found, emits an info finding and skips ping.

Caps
----
FQDN     : first 4 resolved IPs
PREFIX   : first 32 host IPs (warning emitted when > 32)
SITE     : up to 16 targets (warning emitted when > 16 found)
DEVICE   : up to 16 targets (warning emitted when > 16 found)

Design constraints
------------------
- No print / console. Logger only.
- Adapter exceptions → caught, error finding; never propagates.
- Bounded concurrency lives inside the adapters — workflow does not parallelize.
- run_id precedence: kwarg > runtime.options.run_id > auto-generated timestamp.
"""
from __future__ import annotations

import dataclasses
import ipaddress
from typing import Any, Callable, Dict, List, Optional, Tuple, TYPE_CHECKING

from cn_lens.adapters.registry import get_registry
from cn_lens.models import LensFinding, LensObject, LensObjectType, LensResult, LensRun, ObjectSet
from cn_lens.workflows._helpers import (
    make_run_id,
    maybe_persist,
    synthesise_error_finding as _synthesise_error_finding,
)

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FQDN_IP_CAP: int = 4
_PREFIX_HOST_CAP: int = 32
_SITE_TARGET_CAP: int = 16
_DEVICE_TARGET_CAP: int = 16

# Valid modes
_VALID_MODES = frozenset({"ping", "trace", "both"})


def _info_finding(source: str, message: str, detail: Dict[str, Any] | None = None) -> LensFinding:
    return LensFinding(
        severity="info",
        source=source,
        message=message,
        detail=detail or {},
    )


def _warning_finding(source: str, message: str, detail: Dict[str, Any] | None = None) -> LensFinding:
    return LensFinding(
        severity="warning",
        source=source,
        message=message,
        detail=detail or {},
    )


# ---------------------------------------------------------------------------
# Offline path
# ---------------------------------------------------------------------------

_OFFLINE_SOURCES: Dict[str, str] = {
    "classifier": "ok",
    "reachability": "not_queried",
    "dns": "not_queried",
    "ad": "not_queried",
}


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
        findings=(_info_finding("classifier", "offline — no reachability checks performed"),),
    )


# ---------------------------------------------------------------------------
# Ping/trace helpers (shared by IP, FQDN, SITE, DEVICE)
# ---------------------------------------------------------------------------

def _do_ping(
    runtime: "LensRuntime",
    target: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[LensFinding]]:
    """Call ping adapter; return (result_dict, error_finding).  One of them is None."""
    from cn_lens.adapters import reachability as reach_adapter

    try:
        result = reach_adapter.ping(runtime, target)
        return dataclasses.asdict(result), None
    except Exception as exc:
        runtime.logger.error("reachability: ping(%s) raised: %s", target, exc)
        return None, _synthesise_error_finding("reachability.ping", exc)


def _do_trace(
    runtime: "LensRuntime",
    target: str,
    *,
    ad_lookup: Optional[Callable[[str], Optional[str]]] = None,
    use_site_mapping: bool = False,
) -> Tuple[Optional[Dict[str, Any]], Optional[LensFinding], Optional[Dict[str, Optional[str]]]]:
    """Call trace or trace_with_site_mapping; return (trace_dict, error_finding, hop_sites).

    hop_sites is None when trace_with_site_mapping was NOT used (bare trace or error).
    """
    from cn_lens.adapters import reachability as reach_adapter

    try:
        if use_site_mapping and ad_lookup is not None:
            enriched = reach_adapter.trace_with_site_mapping(
                runtime, target, ad_lookup=ad_lookup
            )
            trace_dict = dataclasses.asdict(enriched.trace)
            return trace_dict, None, dict(enriched.hop_sites)
        else:
            result = reach_adapter.trace(runtime, target)
            return dataclasses.asdict(result), None, None
    except Exception as exc:
        runtime.logger.error("reachability: trace(%s) raised: %s", target, exc)
        return None, _synthesise_error_finding("reachability.trace", exc), None


def _make_ad_lookup(
    runtime: "LensRuntime",
) -> Callable[[str], Optional[str]]:
    """Return a closure that maps an IP to its AD site code (or None on failure).

    Used at two call sites (``_build_reach_summary_for_targets`` and
    ``_run_prefix``) to avoid duplicating the same three-line closure.
    """
    from cn_lens.adapters import active_directory as ad

    def _ad_lookup(ip: str) -> Optional[str]:
        try:
            enrichment, _ = ad.enrich_ip(runtime, ip)
            return enrichment.device_result.last_site_code or None
        except Exception as exc:
            runtime.logger.debug("reachability: ad_lookup(%s) raised: %s", ip, exc)
            return None

    return _ad_lookup


def _build_reach_summary_for_targets(
    runtime: "LensRuntime",
    targets: List[str],
    mode: str,
    *,
    ad_health_status: str,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Build the reachability summary block for a list of targets.

    Returns (reach_summary, findings).
    """
    findings: List[LensFinding] = []
    ping_dicts: List[Dict[str, Any]] = []
    trace_dicts: List[Dict[str, Any]] = []
    enriched_hops_list: List[Dict[str, Optional[str]]] = []

    # Determine if we should use trace_with_site_mapping
    use_site_mapping = ad_health_status == "ok"

    # Build ad_lookup closure once (captures runtime via closure)
    ad_lookup = _make_ad_lookup(runtime)

    for target in targets:
        if mode in ("ping", "both"):
            ping_dict, ping_err = _do_ping(runtime, target)
            if ping_dict is not None:
                ping_dicts.append(ping_dict)
            if ping_err is not None:
                findings.append(ping_err)

        if mode in ("trace", "both"):
            trace_dict, trace_err, hop_sites = _do_trace(
                runtime,
                target,
                ad_lookup=ad_lookup if use_site_mapping else None,
                use_site_mapping=use_site_mapping,
            )
            if trace_dict is not None:
                trace_dicts.append(trace_dict)
            if hop_sites is not None:
                enriched_hops_list.append(hop_sites)
            if trace_err is not None:
                findings.append(trace_err)

    reach_summary: Dict[str, Any] = {"targets": targets}
    if mode in ("ping", "both"):
        reach_summary["ping"] = ping_dicts
    if mode in ("trace", "both"):
        reach_summary["trace"] = trace_dicts
    if enriched_hops_list:
        reach_summary["enriched_hops"] = enriched_hops_list

    return reach_summary, findings


# ---------------------------------------------------------------------------
# Per-type runners
# ---------------------------------------------------------------------------

def _run_ip(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    mode: str,
    ad_health_status: str,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Ping/trace a single IP address."""
    target = obj.value
    summary = dict(base_summary)
    findings: List[LensFinding] = []

    reach_summary, reach_findings = _build_reach_summary_for_targets(
        runtime, [target], mode, ad_health_status=ad_health_status
    )
    findings.extend(reach_findings)
    summary["reachability"] = reach_summary
    return summary, findings


def _run_fqdn(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    mode: str,
    ad_health_status: str,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Resolve FQDN then ping/trace each resulting IP (cap 4)."""
    from cn_lens.adapters import dns

    fqdn = obj.value
    summary = dict(base_summary)
    findings: List[LensFinding] = []

    # 1. DNS forward lookup
    try:
        dns_result = dns.resolve_forward(runtime, fqdn)
        all_ips = list(dns_result.a_records)
    except Exception as exc:
        runtime.logger.error("reachability: dns.resolve_forward(%s) raised: %s", fqdn, exc)
        findings.append(_synthesise_error_finding("dns", exc))
        summary["reachability"] = {"targets": [], "ping": [] if mode in ("ping", "both") else None}
        return summary, findings

    if not all_ips:
        findings.append(_info_finding(
            "reachability",
            "no targets resolvable for object",
            {"fqdn": fqdn, "dns_status": dns_result.status},
        ))
        summary["reachability"] = {"targets": []}
        return summary, findings

    # Cap to 4
    if len(all_ips) > _FQDN_IP_CAP:
        runtime.logger.debug(
            "reachability: FQDN %s resolved to %d IPs; capping to %d",
            fqdn, len(all_ips), _FQDN_IP_CAP,
        )
    targets = all_ips[:_FQDN_IP_CAP]

    # 2. Ping/trace each IP
    reach_summary, reach_findings = _build_reach_summary_for_targets(
        runtime, targets, mode, ad_health_status=ad_health_status
    )
    findings.extend(reach_findings)
    summary["reachability"] = reach_summary
    return summary, findings


def _run_prefix(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    mode: str,
    ad_health_status: str,
    *,
    run_warnings: List[str],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Ping host range of the prefix (cap 32 hosts).

    When the prefix has more than ``_PREFIX_HOST_CAP`` host IPs the cap warning
    is emitted as BOTH a warning-severity LensFinding on the result AND a string
    appended to ``run_warnings`` (which propagates to LensRun.warnings).
    """
    from cn_lens.adapters import reachability as reach_adapter

    prefix_str = obj.value
    summary = dict(base_summary)
    findings: List[LensFinding] = []

    try:
        network = ipaddress.ip_network(prefix_str, strict=False)
        all_hosts = [str(h) for h in network.hosts()]
    except ValueError as exc:
        runtime.logger.error("reachability: invalid prefix %s: %s", prefix_str, exc)
        findings.append(_synthesise_error_finding("reachability", exc))
        summary["reachability"] = {"targets": []}
        return summary, findings

    if not all_hosts:
        findings.append(_info_finding(
            "reachability",
            "no targets resolvable for object",
            {"prefix": prefix_str, "reason": "no host IPs in prefix"},
        ))
        summary["reachability"] = {"targets": []}
        return summary, findings

    if len(all_hosts) > _PREFIX_HOST_CAP:
        cap_msg = (
            f"prefix {prefix_str} has {len(all_hosts)} host IPs; capped to {_PREFIX_HOST_CAP}"
        )
        run_warnings.append(cap_msg)
        findings.append(_warning_finding(
            "reachability",
            cap_msg,
            {"prefix": prefix_str, "total_hosts": len(all_hosts), "cap": _PREFIX_HOST_CAP},
        ))

    targets = all_hosts[:_PREFIX_HOST_CAP]

    # Use ping_many for batch efficiency
    ping_dicts: List[Dict[str, Any]] = []
    trace_dicts: List[Dict[str, Any]] = []
    enriched_hops_list: List[Dict[str, Optional[str]]] = []

    if mode in ("ping", "both"):
        try:
            batch = reach_adapter.ping_many(runtime, targets)
            ping_dicts = [dataclasses.asdict(r) for r in batch.results]
        except Exception as exc:
            runtime.logger.error("reachability: ping_many raised: %s", exc)
            findings.append(_synthesise_error_finding("reachability.ping_many", exc))

    if mode in ("trace", "both"):
        # For PREFIX, fall back to individual traces if needed
        # (ping_many equivalent for trace not in scope — trace_many exists but
        # we keep it simple: one trace per target using the same enrichment logic)
        use_site_mapping = ad_health_status == "ok"
        ad_lookup = _make_ad_lookup(runtime)

        for target in targets:
            trace_dict, trace_err, hop_sites = _do_trace(
                runtime, target,
                ad_lookup=ad_lookup if use_site_mapping else None,
                use_site_mapping=use_site_mapping,
            )
            if trace_dict is not None:
                trace_dicts.append(trace_dict)
            if hop_sites is not None:
                enriched_hops_list.append(hop_sites)
            if trace_err is not None:
                findings.append(trace_err)

    reach_summary: Dict[str, Any] = {"targets": targets}
    if mode in ("ping", "both"):
        reach_summary["ping"] = ping_dicts
    if mode in ("trace", "both"):
        reach_summary["trace"] = trace_dicts
    if enriched_hops_list:
        reach_summary["enriched_hops"] = enriched_hops_list

    summary["reachability"] = reach_summary
    return summary, findings


def _run_site(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    mode: str,
    ad_health_status: str,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Resolve SITE via AD, then ping discovered targets (cap 16)."""
    from cn_lens.adapters import active_directory as ad

    site_code = obj.value
    summary = dict(base_summary)
    findings: List[LensFinding] = []

    try:
        site_result, ad_findings = ad.lookup_site(runtime, site_code)
        findings.extend(ad_findings)
    except Exception as exc:
        runtime.logger.error("reachability: ad.lookup_site(%s) raised: %s", site_code, exc)
        findings.append(_synthesise_error_finding("ad.lookup_site", exc))
        summary["reachability"] = {"targets": []}
        return summary, findings

    if not site_result.found:
        findings.append(_info_finding(
            "reachability",
            "no targets resolvable for object",
            {"site": site_code, "reason": "site not found in AD"},
        ))
        summary["reachability"] = {"targets": []}
        return summary, findings

    # The AdSiteResult has no device list; use site_code as a single hostname target.
    # Per spec: "ad.lookup_site / ad.lookup_device — extract device hostnames or known IPs"
    # Since the dataclass has no device list field, we use the resolved site_code
    # as the target hostname.  If it's empty (shouldn't happen when found=True)
    # fall back to the input site_code.
    raw_targets = [site_result.site_code or site_code]

    if len(raw_targets) > _SITE_TARGET_CAP:
        findings.append(_warning_finding(
            "reachability",
            f"site {site_code} has {len(raw_targets)} targets; capped to {_SITE_TARGET_CAP}",
            {"site": site_code, "total_targets": len(raw_targets), "cap": _SITE_TARGET_CAP},
        ))

    targets = raw_targets[:_SITE_TARGET_CAP]

    reach_summary, reach_findings = _build_reach_summary_for_targets(
        runtime, targets, mode, ad_health_status=ad_health_status
    )
    findings.extend(reach_findings)
    summary["reachability"] = reach_summary
    return summary, findings


def _run_device(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    mode: str,
    ad_health_status: str,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Resolve DEVICE via AD, then ping the hostname (cap 16)."""
    from cn_lens.adapters import active_directory as ad

    hostname = obj.value
    summary = dict(base_summary)
    findings: List[LensFinding] = []

    try:
        device_result, ad_findings = ad.lookup_device(runtime, hostname)
        findings.extend(ad_findings)
    except Exception as exc:
        runtime.logger.error("reachability: ad.lookup_device(%s) raised: %s", hostname, exc)
        findings.append(_synthesise_error_finding("ad.lookup_device", exc))
        summary["reachability"] = {"targets": []}
        return summary, findings

    if not device_result.found:
        findings.append(_info_finding(
            "reachability",
            "no targets resolvable for object",
            {"device": hostname, "reason": "device not found in AD"},
        ))
        summary["reachability"] = {"targets": []}
        return summary, findings

    # Use original hostname as the target (DNS will resolve it at ping time)
    raw_targets = [hostname]

    if len(raw_targets) > _DEVICE_TARGET_CAP:
        findings.append(_warning_finding(
            "reachability",
            f"device {hostname} has {len(raw_targets)} targets; capped to {_DEVICE_TARGET_CAP}",
            {"device": hostname, "total_targets": len(raw_targets), "cap": _DEVICE_TARGET_CAP},
        ))

    targets = raw_targets[:_DEVICE_TARGET_CAP]

    reach_summary, reach_findings = _build_reach_summary_for_targets(
        runtime, targets, mode, ad_health_status=ad_health_status
    )
    findings.extend(reach_findings)
    summary["reachability"] = reach_summary
    return summary, findings


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

_DISPATCH = {
    LensObjectType.IP: _run_ip,
    LensObjectType.FQDN: _run_fqdn,
    LensObjectType.PREFIX: _run_prefix,
    LensObjectType.SITE: _run_site,
    LensObjectType.DEVICE: _run_device,
}


# ---------------------------------------------------------------------------
# Online per-object builder
# ---------------------------------------------------------------------------

def _build_online_result(
    obj: LensObject,
    runtime: "LensRuntime",
    sources: Dict[str, str],
    mode: str,
    ad_health_status: str,
    run_warnings: List[str],
) -> LensResult:
    base_summary: Dict[str, Any] = {
        "original": obj.original,
        "normalized": obj.normalized,
        "type": obj.object_type.value,
    }

    findings: List[LensFinding] = []
    dispatcher = _DISPATCH.get(obj.object_type)

    if dispatcher is not None:
        try:
            if obj.object_type == LensObjectType.PREFIX:
                # _run_prefix accepts run_warnings to propagate cap warnings
                summary, adapter_findings = _run_prefix(
                    runtime, obj, base_summary, mode, ad_health_status,
                    run_warnings=run_warnings,
                )
            else:
                summary, adapter_findings = dispatcher(
                    runtime, obj, base_summary, mode, ad_health_status
                )
            findings.extend(adapter_findings)
        except Exception as exc:
            runtime.logger.error(
                "reachability: unexpected error in dispatcher for %s: %s",
                obj.value, exc,
            )
            summary = dict(base_summary)
            findings.append(_synthesise_error_finding("reachability", exc))
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

def reachability_objects(
    object_set: ObjectSet,
    *,
    runtime: Optional["LensRuntime"] = None,
    run_id: Optional[str] = None,
    mode: str = "ping",
) -> LensRun:
    """Perform reachability checks (ping / trace) across a batch of network objects.

    Parameters
    ----------
    object_set:
        The ``ObjectSet`` produced by ``classify_many``.
    runtime:
        Optional ``LensRuntime``.  When ``None`` or ``runtime.offline`` is
        ``True``, returns the offline MVP-shape output without contacting any
        live adapters.
    run_id:
        Explicit run identifier.  Precedence order:
        1. ``run_id`` kwarg (if not None)
        2. ``runtime.options.run_id`` (if runtime is not None and options.run_id is not None)
        3. Auto-generated UTC timestamp via ``make_run_id()``.
    mode:
        One of ``"ping"``, ``"trace"``, or ``"both"``; default ``"ping"``.

    Returns
    -------
    LensRun
        Always returned; never raises.
    """
    if mode not in _VALID_MODES:
        raise ValueError(f"mode must be one of {sorted(_VALID_MODES)!r}; got {mode!r}")

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
            workflow="reachability",
            run_id=effective_run_id,
            inputs=object_set,
            results=results,
            warnings=(),
            errors=(),
        )

    # --- Online path ---
    from cn_lens.adapters import active_directory as ad

    registry = get_registry()
    sources: Dict[str, str] = {"classifier": "ok"}
    sources.update(registry.source_statuses(runtime))

    # Check AD adapter health once for all objects in this run
    try:
        ad_health = ad.health(runtime)
        ad_health_status = ad_health.status
    except Exception as exc:
        runtime.logger.error("reachability: ad.health() raised: %s", exc)
        ad_health_status = "error"

    run_warnings: List[str] = []

    results = tuple(
        _build_online_result(obj, runtime, sources, mode, ad_health_status, run_warnings)
        for obj in object_set.objects
    )

    run = LensRun(
        schema_version=1,
        tool="cn-lens",
        workflow="reachability",
        run_id=effective_run_id,
        inputs=object_set,
        results=results,
        warnings=tuple(run_warnings),
        errors=(),
    )
    maybe_persist(run, runtime)
    return run
