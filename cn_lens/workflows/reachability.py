"""Reachability workflow — ping / traceroute across all object types.

Offline / None runtime
-----------------------
Returns the MVP-shape LensRun with a single classifier info finding per object
and ``not_queried`` source status for every adapter.  No adapter I/O occurs.

Online runtime
--------------
Per-object-type adapter composition:

IP     : ping (always for mode "ping"/"both"); trace / trace_with_site_mapping
         (for mode "trace"/"both").  When Infoblox is configured, each trace
         result is enriched with a ``site_verdict`` field (see below).  When the
         AD adapter health is "ok" and Infoblox site data is absent, AD hop
         mapping is used as a fallback.  When AD is not_configured/disabled and
         no Infoblox site data is available, bare trace is used.

FQDN   : dns.resolve_forward → for each resolved IP, ping/trace as above.
         Capped to first 4 IPs.  If no IPs resolve, emits an info finding and
         skips all adapter calls.  ``reached`` in trace results is corrected by
         comparing the last hop IP against the full set of resolved IPs (fixes
         the hostname-target reached bug where the raw hostname never matches a
         hop IP string).

PREFIX : ping_many on the network host range.  Capped at ``max_hosts`` host
         IPs (default 32; 0 = full expansion).  Emits a warning finding when
         the prefix has more host IPs than the effective cap.

SITE   : ad.lookup_site to obtain site metadata.  If found=True, pings the
         site_code as a hostname target.  If not found, emits an info finding
         and skips ping.

DEVICE : ad.lookup_device to resolve the device.  If found=True, pings the
         original hostname.  If not found, emits an info finding and skips ping.

Trace site verdict
------------------
When mode is "trace" or "both" and Infoblox is configured, each trace result
dict is enriched with:

    ``site_verdict``: one of:
        ``"valid"``          — target site matches the last (or pre-last) hop site.
        ``"site_mismatch"``  — target site differs from the last hop site.
        ``"site_unknown"``   — insufficient Infoblox extattr data to determine.

    ``target_site``         — site code for the target IP (or None).
    ``last_hop_site``       — site code for the last responding hop IP (or None).
    ``pre_last_hop_site``   — site code for the pre-last responding hop IP (or None).
    ``last_hop_vlan``       — VLAN extattr for the last responding hop (or None).

Verdict semantics (ported from ``plugins/trace_site_mapper.py``):
- If either target site or last-hop site is None → ``"site_unknown"``.
- If target site == last-hop site (case-insensitive) → ``"valid"``.
- Otherwise → ``"site_mismatch"``.
- AD hop mapping becomes the fallback only when Infoblox extattr lookup yields
  no site for any of the relevant IPs.

``--probe mtr``
---------------
When ``probe="mtr"`` and the ``mtr`` binary is present in PATH,
``utils.diagnostics.process_mtr_target`` is called instead of the regular
traceroute adapter.  When the binary is absent the probe degrades gracefully:
a ``not_configured`` finding is emitted and no trace/MTR is performed.

Caps
----
FQDN     : first 4 resolved IPs
PREFIX   : first ``max_hosts`` host IPs (default 32; 0 = full expansion;
             warning emitted when total hosts exceed the effective cap)
SITE     : single target (site_code as hostname)
DEVICE   : single target (hostname)

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
from cn_lens.models import LensFinding, LensObject, LensObjectType, LensRun, ObjectSet
from cn_lens.workflows._helpers import (
    run_workflow,
    synthesise_error_finding as _synthesise_error_finding,
)

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FQDN_IP_CAP: int = 4
_PREFIX_HOST_CAP: int = 32  # Default cap; overridden by max_hosts kwarg (0 = unlimited)

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
# Site-verdict helpers (ported pure logic from plugins/trace_site_mapper.py)
# ---------------------------------------------------------------------------

def _compute_site_verdict(
    target_site: Optional[str],
    last_hop_site: Optional[str],
) -> str:
    """Derive the path-validity verdict from site codes.

    Parameters
    ----------
    target_site:
        Infoblox ``Site`` (or ``Location``) extattr for the trace target IP,
        or ``None`` when unavailable.
    last_hop_site:
        Same for the last responding traceroute hop IP.

    Returns
    -------
    str
        One of ``"valid"``, ``"site_mismatch"``, or ``"site_unknown"``.

    Semantics (derived from donor ``plugins/trace_site_mapper.py``):
    - Either site is None → ``"site_unknown"`` (insufficient data).
    - Sites match (case-insensitive) → ``"valid"`` (path appears correct).
    - Sites differ → ``"site_mismatch"`` (last hop is in the wrong site).
    """
    if not target_site or not last_hop_site:
        return "site_unknown"
    if target_site.upper() == last_hop_site.upper():
        return "valid"
    return "site_mismatch"


def _enrich_trace_dict_with_site_verdict(
    runtime: "LensRuntime",
    trace_dict: Dict[str, Any],
    target_ip: str,
) -> Dict[str, Any]:
    """Add ``site_verdict`` and related site fields to a trace result dict.

    Looks up the Infoblox extattr Site for the target IP, last responding hop
    IP, and pre-last hop IP.  Injects the verdict and site fields in-place
    (returns the mutated dict for convenience).

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.
    trace_dict:
        ``dataclasses.asdict`` output from a ``TraceResult``.
    target_ip:
        The target IP address (or hostname — only used if it looks like an IP).

    Returns
    -------
    dict
        The same ``trace_dict`` reference, now augmented.
    """
    from cn_lens.adapters.infoblox import lookup_hop_site

    hops = trace_dict.get("hops", [])
    responding = [h for h in hops if h.get("ip")]

    # Donor semantics (plugins/trace_site_mapper.py:230-246, utils/diagnostics.py:88-93):
    # last_hop_ip = valid_hops[-1] — the last responding hop, which IS the target
    # when the trace reached it.  The verdict is computed against this hop.
    # pre_last_hop_ip is display-only and never feeds the verdict.
    import ipaddress as _ipaddress
    try:
        _ipaddress.ip_address(target_ip)
        target_is_ip = True
    except ValueError:
        target_is_ip = False

    # last_hop_ip: last responding hop (may be the target itself when reached)
    last_hop_ip = responding[-1]["ip"] if responding else None
    # pre_last_hop_ip: one before last — display-only, never feeds verdict
    pre_last_hop_ip = responding[-2]["ip"] if len(responding) >= 2 else None

    target_site_info = lookup_hop_site(runtime, target_ip) if target_is_ip else {"site": None, "vlan": None}
    last_hop_site_info = lookup_hop_site(runtime, last_hop_ip) if last_hop_ip else {"site": None, "vlan": None}
    pre_last_hop_site_info = lookup_hop_site(runtime, pre_last_hop_ip) if pre_last_hop_ip else {"site": None, "vlan": None}

    target_site = target_site_info.get("site")
    last_hop_site = last_hop_site_info.get("site")
    pre_last_hop_site = pre_last_hop_site_info.get("site")
    last_hop_vlan = last_hop_site_info.get("vlan")

    # When Infoblox has no data at all (all None), check if AD already provided
    # hop site data via the existing enriched_hops path.  AD mapping is the
    # fallback: if we have an ad-derived last_hop_site in the parent hop_sites
    # dict it was already used before this function was called; nothing extra to
    # do here — we only overwrite with the IB verdict.

    verdict = _compute_site_verdict(target_site, last_hop_site)

    trace_dict["site_verdict"] = verdict
    trace_dict["target_site"] = target_site
    trace_dict["last_hop_site"] = last_hop_site
    trace_dict["pre_last_hop_site"] = pre_last_hop_site
    trace_dict["last_hop_vlan"] = last_hop_vlan

    return trace_dict


def _fix_reached_for_resolved_ips(
    trace_dict: Dict[str, Any],
    resolved_ips: Optional[List[str]],
) -> Dict[str, Any]:
    """Correct ``reached`` in a trace dict for hostname targets.

    When ``trace()`` is called with a hostname target the traceroute binary
    resolves it internally, but ``_parse_trace_output`` compares the last
    hop's IP against the raw hostname string — which never matches.  This
    function re-derives ``reached`` by checking whether the last responding
    hop IP is in the set of known resolved IPs for the target.

    Parameters
    ----------
    trace_dict:
        ``dataclasses.asdict`` output from a ``TraceResult``.
    resolved_ips:
        The IPs that the hostname target resolves to (e.g. from a prior DNS
        lookup).  When ``None``, the dict is returned unchanged.

    Returns
    -------
    dict
        The same ``trace_dict`` reference, possibly with ``reached`` corrected.
    """
    if not resolved_ips or trace_dict.get("reached"):
        # Already reached=True, or no resolved IPs to compare against → no-op.
        return trace_dict

    hops = trace_dict.get("hops", [])
    responding = [h for h in hops if h.get("ip")]
    if not responding:
        return trace_dict

    last_hop_ip = responding[-1]["ip"]
    if last_hop_ip in resolved_ips:
        trace_dict = dict(trace_dict)  # shallow copy to avoid mutating frozen dicts
        trace_dict["reached"] = True

    return trace_dict


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


def _build_ad_hop_sites(
    ad_lookup: Callable[[str], Optional[str]],
    trace_dict: Dict[str, Any],
) -> Optional[Dict[str, Optional[str]]]:
    """Build a hop-to-site mapping from AD lookup for the hops in a trace dict.

    Called as an AD fallback when Infoblox is configured but returned no site
    data for any hop in this trace.  Mirrors the ``hop_sites`` dict produced
    by ``trace_with_site_mapping``.

    Returns ``None`` if no hops are present (nothing to map).
    """
    hops = trace_dict.get("hops", ())
    responding = [h for h in hops if h.get("ip")]
    if not responding:
        return None

    hop_sites: Dict[str, Optional[str]] = {}
    for hop in responding:
        ip = hop["ip"]
        try:
            site = ad_lookup(ip)
        except Exception:
            site = None
        hop_sites[ip] = site

    return hop_sites if hop_sites else None


def _ib_enrichment_has_no_data(trace_dict: Dict[str, Any]) -> bool:
    """Return True when the IB site-verdict enrichment produced no useful site data.

    This is the "empty IB" predicate used by the AD fallback logic: if both
    ``target_site`` and ``last_hop_site`` are None (IB had no extattr data for
    any of the relevant IPs), the AD hop mapping is eligible as a fallback.
    """
    target_site = trace_dict.get("target_site")
    last_hop_site = trace_dict.get("last_hop_site")
    # site_verdict key presence confirms IB enrichment was attempted
    ib_was_attempted = "site_verdict" in trace_dict
    return ib_was_attempted and target_site is None and last_hop_site is None


def _do_trace(
    runtime: "LensRuntime",
    target: str,
    *,
    ad_lookup: Optional[Callable[[str], Optional[str]]] = None,
    use_site_mapping: bool = False,
    use_infoblox_site_verdict: bool = False,
    ad_lookup_fallback: Optional[Callable[[str], Optional[str]]] = None,
    resolved_ips: Optional[List[str]] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[LensFinding], Optional[Dict[str, Optional[str]]]]:
    """Call trace or trace_with_site_mapping; return (trace_dict, error_finding, hop_sites).

    Parameters
    ----------
    use_infoblox_site_verdict:
        When ``True``, enrich the trace dict with Infoblox extattr site data
        and a ``site_verdict`` field.  This is the primary site-mapping path;
        ``use_site_mapping`` (AD-based) becomes the fallback.
    ad_lookup_fallback:
        AD lookup callable used as a per-trace fallback when IB is configured
        but returned no site data for this trace (target_site and last_hop_site
        both None after IB enrichment).  When provided and IB has no data,
        ``hop_sites`` is populated from AD without overriding the IB verdict.
    resolved_ips:
        When supplied, ``reached`` in the trace dict is corrected by checking
        whether the last hop IP is in this set.  Fixes the hostname-target
        reached bug for FQDN objects.
    """
    from cn_lens.adapters import reachability as reach_adapter

    try:
        if use_site_mapping and ad_lookup is not None:
            enriched = reach_adapter.trace_with_site_mapping(
                runtime, target, ad_lookup=ad_lookup
            )
            trace_dict = dataclasses.asdict(enriched.trace)
            hop_sites: Optional[Dict[str, Optional[str]]] = dict(enriched.hop_sites)
        else:
            result = reach_adapter.trace(runtime, target)
            trace_dict = dataclasses.asdict(result)
            hop_sites = None

        # Fix reached for hostname targets (resolves the IP-vs-hostname mismatch)
        if resolved_ips:
            trace_dict = _fix_reached_for_resolved_ips(trace_dict, resolved_ips)

        # Infoblox extattr site verdict (primary path, replaces AD-only site info)
        if use_infoblox_site_verdict:
            trace_dict = _enrich_trace_dict_with_site_verdict(runtime, trace_dict, target)
            # AD fallback: when IB enrichment produced no site data for this trace,
            # use AD hop mapping to populate enriched_hops.  AD never overrides the
            # IB-derived site_verdict field — it only supplements hop annotation.
            if hop_sites is None and _ib_enrichment_has_no_data(trace_dict) and ad_lookup_fallback is not None:
                hop_sites = _build_ad_hop_sites(ad_lookup_fallback, trace_dict)

        return trace_dict, None, hop_sites
    except Exception as exc:
        runtime.logger.error("reachability: trace(%s) raised: %s", target, exc)
        return None, _synthesise_error_finding("reachability.trace", exc), None


def _make_ad_lookup(
    runtime: "LensRuntime",
) -> Callable[[str], Optional[str]]:
    """Return a closure that maps an IP to its AD site code (or None on failure)."""
    from cn_lens.adapters import active_directory as ad

    def _ad_lookup(ip: str) -> Optional[str]:
        try:
            enrichment, _ = ad.enrich_ip(runtime, ip)
            return enrichment.device_result.last_site_code or None
        except Exception as exc:
            runtime.logger.debug("reachability: ad_lookup(%s) raised: %s", ip, exc)
            return None

    return _ad_lookup


def _is_infoblox_configured(runtime: "LensRuntime") -> bool:
    """Return True when the Infoblox adapter is configured (not offline, not default URL)."""
    from cn_lens.adapters.infoblox import _is_not_configured as _ib_not_configured
    if runtime.offline:
        return False
    return not _ib_not_configured(runtime)


def _do_mtr_trace(
    runtime: "LensRuntime",
    target: str,
    *,
    use_infoblox_site_verdict: bool = False,
    resolved_ips: Optional[List[str]] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[LensFinding]]:
    """Run mtr via utils.diagnostics.process_mtr_target; return (trace_dict, error_finding).

    Falls back gracefully when the mtr binary is absent.  The returned trace_dict
    mirrors TraceResult's asdict schema (target, hops, reached, error) plus any
    site verdict fields when ``use_infoblox_site_verdict`` is True.

    Parameters
    ----------
    resolved_ips:
        When supplied, ``reached`` is corrected by checking whether the last hop
        IP is in this set (hostname-target reached fix).
    """
    import shutil
    from utils.diagnostics import process_mtr_target

    if shutil.which("mtr") is None:
        return None, _warning_finding(
            "reachability",
            "mtr binary not found in PATH — probe=mtr skipped",
            {"target": target},
        )

    try:
        mtr_raw = process_mtr_target(runtime.context, target)
    except Exception as exc:
        runtime.logger.error("reachability: mtr(%s) raised: %s", target, exc)
        return None, _synthesise_error_finding("reachability.mtr", exc)

    # Translate mtr result dict into a trace_dict that mirrors TraceResult.asdict
    last_hop_ip = mtr_raw.get("last_hop_ip", "") or ""
    pre_last_hop_ip = mtr_raw.get("pre_last_hop_ip", "") or ""

    # Build a minimal hops list (mtr gives us only last + pre-last hop IPs)
    hops_list = []
    hop_count = int(mtr_raw.get("hop_count", 0) or 0)
    if pre_last_hop_ip and pre_last_hop_ip not in ("Unreachable", "N/A"):
        hops_list.append({
            "index": max(1, hop_count - 1),
            "ip": pre_last_hop_ip,
            "hostname": "",
            "rtt_ms": 0.0,
        })
    if last_hop_ip and last_hop_ip not in ("Unreachable", "MTR_TIMEOUT", "MTR_NOT_FOUND", "MTR_EXEC_ERROR"):
        hops_list.append({
            "index": hop_count,
            "ip": last_hop_ip,
            "hostname": mtr_raw.get("last_hop_hostname", "") or "",
            "rtt_ms": 0.0,
        })

    # reached: last hop is the target IP (or in the resolved IPs for hostname targets)
    import ipaddress as _ipaddress
    try:
        _ipaddress.ip_address(target)
        target_ips = [target]
    except ValueError:
        target_ips = list(resolved_ips or [])

    reached = bool(last_hop_ip and last_hop_ip in target_ips)

    # Also fix for resolved_ips if not yet reached
    if not reached and resolved_ips and last_hop_ip in resolved_ips:
        reached = True

    error_str = ""
    mtr_status = mtr_raw.get("status", "OK")
    if mtr_status not in ("OK",):
        error_str = mtr_status

    trace_dict: Dict[str, Any] = {
        "target": target,
        "hops": tuple(hops_list),
        "reached": reached,
        "error": error_str,
        "probe": "mtr",
    }

    if use_infoblox_site_verdict:
        trace_dict = _enrich_trace_dict_with_site_verdict(runtime, trace_dict, target)

    return trace_dict, None


def _build_reach_summary_for_targets(
    runtime: "LensRuntime",
    targets: List[str],
    mode: str,
    *,
    ad_health_status: str,
    probe: str = "traceroute",
    resolved_ips: Optional[List[str]] = None,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Build the reachability summary block for a list of targets.

    Parameters
    ----------
    probe:
        Probe type for trace mode.  ``"traceroute"`` (default) uses the
        standard traceroute adapter.  ``"mtr"`` uses
        ``utils.diagnostics.process_mtr_target`` when the mtr binary is
        present; degrades to a warning finding when absent.
    resolved_ips:
        IPs that hostname targets resolve to.  When supplied, ``reached`` in
        trace results is corrected by checking the last hop against this set
        (hostname-target reached fix).
    """
    findings: List[LensFinding] = []
    ping_dicts: List[Dict[str, Any]] = []
    trace_dicts: List[Dict[str, Any]] = []
    enriched_hops_list: List[Dict[str, Optional[str]]] = []

    # Infoblox site verdict: primary path (replaces AD-based mapping when IB is configured)
    ib_configured = _is_infoblox_configured(runtime)
    use_infoblox_site_verdict = ib_configured and mode in ("trace", "both")

    # AD site mapping: primary path when IB absent; fallback (per-trace) when IB has no data.
    # Build ad_lookup whenever AD is healthy — it may be needed even when IB is configured
    # (as a per-trace fallback for traces where IB yields no extattr data).
    ad_healthy = ad_health_status == "ok"
    use_site_mapping = ad_healthy and not use_infoblox_site_verdict
    ad_lookup = _make_ad_lookup(runtime) if ad_healthy else None

    for target in targets:
        if mode in ("ping", "both"):
            ping_dict, ping_err = _do_ping(runtime, target)
            if ping_dict is not None:
                ping_dicts.append(ping_dict)
            if ping_err is not None:
                findings.append(ping_err)

        if mode in ("trace", "both"):
            if probe == "mtr":
                trace_dict, trace_err = _do_mtr_trace(
                    runtime,
                    target,
                    use_infoblox_site_verdict=use_infoblox_site_verdict,
                    resolved_ips=resolved_ips,
                )
                hop_sites = None
            else:
                trace_dict, trace_err, hop_sites = _do_trace(
                    runtime,
                    target,
                    ad_lookup=ad_lookup if use_site_mapping else None,
                    use_site_mapping=use_site_mapping,
                    use_infoblox_site_verdict=use_infoblox_site_verdict,
                    ad_lookup_fallback=ad_lookup if use_infoblox_site_verdict else None,
                    resolved_ips=resolved_ips,
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
# Per-type runners (take mode, ad_health_status; run_warnings via closure)
# ---------------------------------------------------------------------------

def _run_ip(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    mode: str,
    ad_health_status: str,
    probe: str = "traceroute",
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Ping/trace a single IP address."""
    target = obj.value
    summary = dict(base_summary)
    findings: List[LensFinding] = []

    reach_summary, reach_findings = _build_reach_summary_for_targets(
        runtime, [target], mode, ad_health_status=ad_health_status, probe=probe
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
    probe: str = "traceroute",
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

    if len(all_ips) > _FQDN_IP_CAP:
        runtime.logger.debug(
            "reachability: FQDN %s resolved to %d IPs; capping to %d",
            fqdn, len(all_ips), _FQDN_IP_CAP,
        )
    targets = all_ips[:_FQDN_IP_CAP]

    # 2. Ping/trace each IP.  Pass resolved_ips so that trace ``reached`` is
    #    corrected when the last hop IP matches a resolved IP of the FQDN
    #    (hostname-target reached fix: the raw traceroute target is the IP,
    #    but if the mock/binary returned reached=False because it compared the
    #    hop IP against the original hostname, we correct it here).
    reach_summary, reach_findings = _build_reach_summary_for_targets(
        runtime, targets, mode,
        ad_health_status=ad_health_status,
        probe=probe,
        resolved_ips=list(all_ips),
    )
    findings.extend(reach_findings)
    summary["reachability"] = reach_summary
    return summary, findings


def _compute_batch_status(ping_dicts: List[Dict[str, Any]]) -> Tuple[str, int]:
    """Derive batch_status and reachable_count from a list of ping result dicts.

    A host is considered *reachable* when ``received > 0`` (partial or full reply).
    A host is *ok* when ``received == sent`` (zero loss).

    Returns
    -------
    (batch_status, reachable_count) where batch_status is one of:
        ``"ok"``      — every polled host replied fully (all received == sent)
        ``"partial"`` — at least one host replied (received > 0) but not all ok
        ``"failed"``  — no host replied at all (all received == 0)
    """
    if not ping_dicts:
        return "failed", 0

    reachable_count = sum(
        1 for r in ping_dicts if r.get("received", 0) > 0
    )
    all_ok = all(
        r.get("received", 0) == r.get("sent", 0) and r.get("sent", 0) > 0
        for r in ping_dicts
    )

    if all_ok:
        batch_status = "ok"
    elif reachable_count > 0:
        batch_status = "partial"
    else:
        batch_status = "failed"

    return batch_status, reachable_count


def _run_prefix(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    mode: str,
    ad_health_status: str,
    run_warnings: List[str],
    max_hosts: int = _PREFIX_HOST_CAP,
    probe: str = "traceroute",
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Ping host range of the prefix.

    Parameters
    ----------
    max_hosts:
        Maximum number of host IPs to probe.  ``0`` means no cap (full
        expansion).  Defaults to ``_PREFIX_HOST_CAP`` (32) when not provided.
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

    # Determine effective cap: 0 means unlimited; otherwise use max_hosts.
    effective_cap = max_hosts if max_hosts > 0 else len(all_hosts)

    if len(all_hosts) > effective_cap:
        cap_msg = (
            f"prefix {prefix_str} has {len(all_hosts)} host IPs; capped to {effective_cap}"
        )
        run_warnings.append(cap_msg)
        findings.append(_warning_finding(
            "reachability",
            cap_msg,
            {"prefix": prefix_str, "total_hosts": len(all_hosts), "cap": effective_cap},
        ))

    targets = all_hosts[:effective_cap]

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
        ib_configured = _is_infoblox_configured(runtime)
        use_infoblox_site_verdict = ib_configured
        # AD site mapping: primary path when IB absent; fallback (per-trace) when IB has no data.
        ad_healthy = ad_health_status == "ok"
        use_site_mapping = ad_healthy and not use_infoblox_site_verdict
        ad_lookup = _make_ad_lookup(runtime) if ad_healthy else None

        for target in targets:
            if probe == "mtr":
                trace_dict, trace_err = _do_mtr_trace(
                    runtime, target,
                    use_infoblox_site_verdict=use_infoblox_site_verdict,
                )
                hop_sites = None
            else:
                trace_dict, trace_err, hop_sites = _do_trace(
                    runtime, target,
                    ad_lookup=ad_lookup if use_site_mapping else None,
                    use_site_mapping=use_site_mapping,
                    use_infoblox_site_verdict=use_infoblox_site_verdict,
                    ad_lookup_fallback=ad_lookup if use_infoblox_site_verdict else None,
                )
            if trace_dict is not None:
                trace_dicts.append(trace_dict)
            if hop_sites is not None:
                enriched_hops_list.append(hop_sites)
            if trace_err is not None:
                findings.append(trace_err)

    reach_summary: Dict[str, Any] = {"targets": targets}
    if mode in ("ping", "both"):
        batch_status, reachable_count = _compute_batch_status(ping_dicts)
        reach_summary["ping"] = ping_dicts
        reach_summary["batch_status"] = batch_status
        reach_summary["reachable_count"] = reachable_count
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
    probe: str = "traceroute",
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

    targets = [site_result.site_code or site_code]

    reach_summary, reach_findings = _build_reach_summary_for_targets(
        runtime, targets, mode, ad_health_status=ad_health_status, probe=probe
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
    probe: str = "traceroute",
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

    targets = [hostname]

    reach_summary, reach_findings = _build_reach_summary_for_targets(
        runtime, targets, mode, ad_health_status=ad_health_status, probe=probe
    )
    findings.extend(reach_findings)
    summary["reachability"] = reach_summary
    return summary, findings


# ---------------------------------------------------------------------------
# Dispatch table builder (closures capture mode, ad_health_status, run_warnings)
# ---------------------------------------------------------------------------

def _make_dispatch(
    mode: str,
    ad_health_status_ref: List[str],  # mutable 1-element list; [0] = current status
    run_warnings: List[str],
    max_hosts: int = _PREFIX_HOST_CAP,
    probe: str = "traceroute",
) -> Dict[LensObjectType, Any]:
    """Return dispatch table with closures capturing mode, ad_health_status, and probe."""
    def wrap_simple(fn):
        def handler(runtime, obj, base_summary):
            return fn(runtime, obj, base_summary, mode, ad_health_status_ref[0], probe)
        return handler

    def wrap_prefix(fn):
        def handler(runtime, obj, base_summary):
            return fn(runtime, obj, base_summary, mode, ad_health_status_ref[0],
                      run_warnings=run_warnings, max_hosts=max_hosts, probe=probe)
        return handler

    return {
        LensObjectType.IP: wrap_simple(_run_ip),
        LensObjectType.FQDN: wrap_simple(_run_fqdn),
        LensObjectType.PREFIX: wrap_prefix(_run_prefix),
        LensObjectType.SITE: wrap_simple(_run_site),
        LensObjectType.DEVICE: wrap_simple(_run_device),
    }


# ---------------------------------------------------------------------------
# Pre-online hook: AD deep health check
# ---------------------------------------------------------------------------

def _make_pre_online_fn(mode: str, ad_health_status_ref: List[str]):
    """Return the pre_online_fn that performs (or skips) the AD deep health probe."""
    def pre_online(runtime: "LensRuntime", sources: Dict[str, str]) -> None:
        if mode in ("trace", "both"):
            from cn_lens.adapters import active_directory as ad
            try:
                ad_health = ad.deep_health(runtime)
                ad_health_status_ref[0] = ad_health.status
            except Exception as exc:
                runtime.logger.error("reachability: ad.deep_health() raised: %s", exc)
                ad_health_status_ref[0] = "error"
            # Propagate the deep-probe result back into sources.
            sources["ad"] = ad_health_status_ref[0]
        else:
            # Ping-only mode: use the cheap config-only health from the registry.
            ad_health_status_ref[0] = sources.get("ad", "not_queried")
    return pre_online


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def reachability_objects(
    object_set: ObjectSet,
    *,
    runtime: Optional["LensRuntime"] = None,
    run_id: Optional[str] = None,
    mode: str = "ping",
    max_hosts: int = _PREFIX_HOST_CAP,
    probe: str = "traceroute",
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
    max_hosts:
        Maximum number of host IPs to probe for PREFIX objects.  ``<= 0``
        means no cap (full expansion of the entire host range).  Defaults to
        ``_PREFIX_HOST_CAP`` (32).  Overrides the per-run cap.
    probe:
        Probe tool for trace mode.  ``"traceroute"`` (default) uses the
        traceroute binary via the reachability adapter.  ``"mtr"`` passes the
        target through ``utils.diagnostics.process_mtr_target`` when the mtr
        binary is present in PATH; when absent, a warning finding is emitted
        and the trace is skipped (graceful degradation per the sources semantics
        — ``reachability`` source status is unaffected; the warning appears in
        the result's findings list).

    Returns
    -------
    LensRun
        Always returned; never raises.
    """
    if mode not in _VALID_MODES:
        raise ValueError(f"mode must be one of {sorted(_VALID_MODES)!r}; got {mode!r}")

    run_warnings: List[str] = []
    # Mutable 1-element list so closures can read updated value set by pre_online_fn
    ad_health_status_ref: List[str] = ["not_queried"]

    return run_workflow(
        "reachability",
        object_set,
        runtime,
        registry=get_registry(),
        run_id=run_id,
        dispatch=_make_dispatch(
            mode, ad_health_status_ref, run_warnings,
            max_hosts=max_hosts, probe=probe,
        ),
        offline_result_fn=_build_offline_result,
        pre_online_fn=_make_pre_online_fn(mode, ad_health_status_ref),
        run_warnings=run_warnings,
    )
