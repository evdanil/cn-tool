"""DNS workflow — resolves forward/reverse DNS and Infoblox DNS records for objects.

Offline / None runtime
-----------------------
Returns the MVP-shape LensRun (classifier finding + not_queried sources) without
contacting any adapters.

Online runtime
--------------
Per-type adapter mapping:

  IP      : dns.resolve_reverse (ip → PTR)  +  infoblox.lookup_ip (IB name field)
  FQDN    : dns.resolve_forward (name → IPs) +  infoblox.lookup_fqdn (IB records)
             +  dns.expand_fqdn_prefix when len(value.split('.')) < 3
  PREFIX  : dns.resolve_reverse for each host iff prefix size <= /28 (≤ 16 hosts),
             capped at 16 individual reverses;
             infoblox.lookup_prefix for IPAM context.
             When prefix > /28 (> 16 hosts) the per-host loop is skipped entirely
             and a warning is emitted — both in LensRun.warnings and as a
             warning-severity LensFinding on the result.
  SITE    : classifier-only; info finding "DNS workflow does not enrich site/device objects"
  DEVICE  : same as SITE

workflow-level summary["dns"] block
--------------------------------------
  forward:           dict[name, list[ip]]   — name-to-IPs from forward lookups
  reverse:           dict[ip, str|None]     — ip-to-PTR from reverse lookups
  infoblox_records:  dict[str, ...]         — IB cross-reference per name/IP

LensRun.warnings gets a string when prefix > /28 truncation occurs.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from cn_lens.adapters import dns as _dns
from cn_lens.adapters import infoblox as _ib
from cn_lens.adapters.registry import get_registry
from cn_lens.models import LensFinding, LensObject, LensObjectType, LensResult, LensRun, ObjectSet
from cn_lens.workflows._helpers import (
    OFFLINE_FINDING_MESSAGE as _OFFLINE_MESSAGE,
    CLASSIFIED_FINDING_MESSAGE as _CLASSIFIED_MESSAGE,
    is_short_hostname as _is_fqdn_prefix,
    make_run_id,
    maybe_persist,
)

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

# Maximum number of hosts for which per-host reverse lookups are performed.
# Prefixes with more than this many host addresses skip the reverse loop.
_PREFIX_REVERSE_CAP = 16

# Info message for types that DNS does not enrich
_NOT_ENRICHED_MESSAGE = "DNS workflow does not enrich site/device objects"


def _classifier_finding(
    workflow: str = "dns",
    message: str = _CLASSIFIED_MESSAGE,
) -> LensFinding:
    return LensFinding(
        severity="info",
        source="classifier",
        message=message,
        detail={"workflow": workflow},
    )


def _error_finding(source: str, exc: Exception) -> LensFinding:
    return LensFinding(
        severity="error",
        source=source,
        message=str(exc),
        detail={"exception": type(exc).__name__},
    )


def _warning_finding(source: str, message: str) -> LensFinding:
    return LensFinding(
        severity="warning",
        source=source,
        message=message,
        detail={},
    )


def _info_finding(source: str, message: str, detail: Dict[str, Any] | None = None) -> LensFinding:
    return LensFinding(
        severity="info",
        source=source,
        message=message,
        detail=detail or {},
    )


# ---------------------------------------------------------------------------
# Offline / None path
# ---------------------------------------------------------------------------

_OFFLINE_SOURCES: Dict[str, str] = {
    "classifier": "ok",
    "dns": "not_queried",
    "infoblox": "not_queried",
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
        findings=(_classifier_finding(message=_OFFLINE_MESSAGE),),
    )


# ---------------------------------------------------------------------------
# Per-type online runners
# ---------------------------------------------------------------------------

def _run_ip(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    run_warnings: List[str],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """IP: dns.resolve_reverse + infoblox.lookup_ip."""
    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = []
    ip = obj.value

    dns_reverse: Dict[str, Optional[str]] = {}

    # 1. dns.resolve_reverse
    try:
        rev = _dns.resolve_reverse(runtime, ip)
        dns_reverse[ip] = rev.ptr
        if rev.status != "ok" and rev.ptr is None:
            findings.append(_info_finding("dns", f"reverse lookup returned no PTR for {ip}", {"status": rev.status}))
    except Exception as exc:
        runtime.logger.error("dns: resolve_reverse raised unexpectedly: %s", exc)
        findings.append(_error_finding("dns", exc))
        dns_reverse[ip] = None

    # 2. infoblox.lookup_ip
    ib_records: Dict[str, Any] = {}
    try:
        ib_result = _ib.lookup_ip(runtime, ip)
        ib_records[ip] = {
            "found": ib_result.found,
            "name": ib_result.name,
            "network": ib_result.network,
            "status": ib_result.status,
        }
        findings.extend(ib_result.findings)
    except Exception as exc:
        runtime.logger.error("dns: infoblox.lookup_ip raised unexpectedly: %s", exc)
        findings.append(_error_finding("infoblox", exc))
        ib_records[ip] = {"found": False, "error": str(exc)}

    summary["dns"] = {
        "forward": {},
        "reverse": dns_reverse,
        "infoblox_records": ib_records,
    }
    return summary, findings


def _run_fqdn(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    run_warnings: List[str],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """FQDN: dns.resolve_forward + infoblox.lookup_fqdn + optional expand."""
    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = []
    fqdn = obj.value

    dns_forward: Dict[str, List[str]] = {}
    ib_records: Dict[str, Any] = {}

    # 1. dns.resolve_forward
    try:
        fwd = _dns.resolve_forward(runtime, fqdn)
        dns_forward[fqdn] = list(fwd.a_records) + list(fwd.aaaa_records)
    except Exception as exc:
        runtime.logger.error("dns: resolve_forward raised unexpectedly: %s", exc)
        findings.append(_error_finding("dns", exc))
        dns_forward[fqdn] = []

    # 2. infoblox.lookup_fqdn
    try:
        ib_result = _ib.lookup_fqdn(runtime, fqdn)
        ib_records[fqdn] = {
            "found": ib_result.found,
            "record_count": len(ib_result.records),
            "records": list(ib_result.records),
        }
        findings.extend(ib_result.findings)
    except Exception as exc:
        runtime.logger.error("dns: infoblox.lookup_fqdn raised unexpectedly: %s", exc)
        findings.append(_error_finding("infoblox", exc))
        ib_records[fqdn] = {"found": False, "error": str(exc)}

    # 3. dns.expand_fqdn_prefix (only for short labels)
    expansion: Dict[str, Any] = {}
    if _is_fqdn_prefix(fqdn):
        try:
            exp = _dns.expand_fqdn_prefix(runtime, fqdn)
            expansion = {"names": list(exp.names), "status": exp.status}
        except Exception as exc:
            runtime.logger.error("dns: expand_fqdn_prefix raised unexpectedly: %s", exc)
            findings.append(_error_finding("dns", exc))
            expansion = {"error": str(exc)}

    dns_block: Dict[str, Any] = {
        "forward": dns_forward,
        "reverse": {},
        "infoblox_records": ib_records,
    }
    if expansion:
        dns_block["expansion"] = expansion

    summary["dns"] = dns_block
    return summary, findings


def _run_prefix(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    run_warnings: List[str],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """PREFIX: per-host dns.resolve_reverse (if <=16 hosts) + infoblox.lookup_prefix.

    The per-host reverse loop is capped at _PREFIX_REVERSE_CAP (16) hosts.
    When the prefix size exceeds /28 (> 16 host addresses) the loop is skipped
    entirely and a warning is emitted.
    """
    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = []
    prefix_str = obj.value

    dns_reverse: Dict[str, Optional[str]] = {}
    ib_records: Dict[str, Any] = {}

    # Determine host count
    try:
        network = ipaddress.ip_network(prefix_str, strict=False)
        host_addrs = list(network.hosts())
    except ValueError:
        host_addrs = []

    host_count = len(host_addrs)

    if host_count > _PREFIX_REVERSE_CAP:
        msg = (
            f"Prefix {prefix_str} has {host_count} hosts (>{_PREFIX_REVERSE_CAP}); "
            f"per-host reverse DNS skipped"
        )
        run_warnings.append(msg)
        findings.append(_warning_finding("dns", msg))
    else:
        # Perform per-host reverse lookups (capped at _PREFIX_REVERSE_CAP)
        for host in host_addrs[:_PREFIX_REVERSE_CAP]:
            ip = str(host)
            try:
                rev = _dns.resolve_reverse(runtime, ip)
                dns_reverse[ip] = rev.ptr
            except Exception as exc:
                runtime.logger.error("dns: resolve_reverse raised for %s: %s", ip, exc)
                findings.append(_error_finding("dns", exc))
                dns_reverse[ip] = None

    # infoblox.lookup_prefix — always called regardless of size
    try:
        ib_result = _ib.lookup_prefix(runtime, prefix_str)
        ib_records[prefix_str] = {
            "found": ib_result.found,
            "network": ib_result.network,
            "comment": ib_result.comment,
        }
        findings.extend(ib_result.findings)
    except Exception as exc:
        runtime.logger.error("dns: infoblox.lookup_prefix raised unexpectedly: %s", exc)
        findings.append(_error_finding("infoblox", exc))
        ib_records[prefix_str] = {"found": False, "error": str(exc)}

    summary["dns"] = {
        "forward": {},
        "reverse": dns_reverse,
        "infoblox_records": ib_records,
    }
    return summary, findings


def _run_site_or_device(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    run_warnings: List[str],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """SITE / DEVICE: classifier-only; info finding; no adapter calls.

    ``run_warnings`` is accepted but intentionally unused here — the parameter
    is kept to maintain a uniform dispatch-table signature across all handlers.
    """
    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = [
        _info_finding("dns", _NOT_ENRICHED_MESSAGE, {"type": obj.object_type.value})
    ]
    return summary, findings


# ---------------------------------------------------------------------------
# Online per-object runner
# ---------------------------------------------------------------------------

_DISPATCH = {
    LensObjectType.IP: _run_ip,
    LensObjectType.FQDN: _run_fqdn,
    LensObjectType.PREFIX: _run_prefix,
    LensObjectType.SITE: _run_site_or_device,
    LensObjectType.DEVICE: _run_site_or_device,
}


def _build_online_result(
    obj: LensObject,
    runtime: "LensRuntime",
    sources: Dict[str, str],
    run_warnings: List[str],
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
            summary, adapter_findings = dispatcher(runtime, obj, base_summary, run_warnings)
            findings.extend(adapter_findings)
        except Exception as exc:
            runtime.logger.error("dns: unexpected error in dispatcher: %s", exc)
            summary = dict(base_summary)
            findings.append(_error_finding("dns", exc))
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

def dns_objects(
    object_set: ObjectSet,
    *,
    runtime: Optional["LensRuntime"] = None,
    run_id: Optional[str] = None,
) -> LensRun:
    """Resolve DNS and Infoblox DNS records for a batch of network objects.

    Parameters
    ----------
    object_set:
        The ``ObjectSet`` produced by ``classify_many``.
    runtime:
        Optional ``LensRuntime``.  When ``None`` or ``runtime.offline`` is
        ``True`` the function returns the offline MVP-shape output without
        contacting any live adapters.  When online, DNS and Infoblox adapters
        are queried per object type.
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
    # Resolve run_id
    if run_id is not None:
        effective_run_id = run_id
    elif runtime is not None and runtime.options.run_id is not None:
        effective_run_id = runtime.options.run_id
    else:
        effective_run_id = make_run_id()

    # Offline path
    if runtime is None or runtime.offline:
        results = tuple(_build_offline_result(obj) for obj in object_set.objects)
        return LensRun(
            schema_version=1,
            tool="cn-lens",
            workflow="dns",
            run_id=effective_run_id,
            inputs=object_set,
            results=results,
            warnings=(),
            errors=(),
        )

    # Online path
    registry = get_registry()
    sources: Dict[str, str] = {"classifier": "ok"}
    sources.update(registry.source_statuses(runtime))

    run_warnings: List[str] = []

    results = tuple(
        _build_online_result(obj, runtime, sources, run_warnings)
        for obj in object_set.objects
    )

    run = LensRun(
        schema_version=1,
        tool="cn-lens",
        workflow="dns",
        run_id=effective_run_id,
        inputs=object_set,
        results=results,
        warnings=tuple(run_warnings),
        errors=(),
    )
    maybe_persist(run, runtime)
    return run
