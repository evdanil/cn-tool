"""Device workflow — enriches device objects using AD, Infoblox, config_repo, and
optionally the reachability adapter (ping) when ``probe=True``, and optionally
SSH-based show-command collection when ``collect=True``.

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
    6. [collect only] device_ssh.collect_device(hostname) — serial/version/image/license
       (only when device_ssh_enabled is truthy in config; degrades gracefully otherwise)

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

Collect flag
------------
When ``collect=True`` the adapter calls ``device_ssh.collect_device`` with
per-platform command sets and parsers from ``utils/parsers.py``.  The result is
stored under ``summary["collect"]`` with fields ``serial``, ``version``, ``image``,
``license`` matching cn-tool "Device Data" column semantics.  When
``device_ssh_enabled`` is absent or falsy the collect block carries
``{"status": "not_configured"}`` and no SSH connection is attempted.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

from cn_lens.adapters.registry import get_registry
from cn_lens.models import LensFinding, LensObject, LensObjectType, LensRun, ObjectSet
from cn_lens.workflows._helpers import (
    call_adapter,
    is_short_hostname,
    run_workflow,
    synthesise_error_finding,
)

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CLASSIFIER_SOURCE = "classifier"

# Message used in the initial classifier info finding (matches inspect pattern)
_CLASSIFIER_MESSAGE = "device workflow — enriches device objects across AD, Infoblox, and config"


# ---------------------------------------------------------------------------
# Collect: platform command sets (mirrors device_query.py platform_commands)
# ---------------------------------------------------------------------------

def _build_collect_platform_commands() -> Dict[str, Dict[str, Any]]:
    """Build per-platform command→parser mapping for SSH collect step.

    Each value is a callable (parser) that accepts the raw command output (str)
    and returns a parsed structure.  The shape mirrors the ``platform_commands``
    dict in ``modules/device_query.py`` — same commands, same parsers from
    ``utils/parsers.py``.

    Returns a fresh dict on every call (callables are pure-function references).
    """
    from utils.parsers import (
        parse_show_version,
        parse_show_license_reservation,
        parse_show_license_summary,
        parse_show_license,
        parse_nexus_show_version,
        parse_nexus_show_license_all,
    )
    return {
        "iosxe": {
            "show version": parse_show_version,
            "show license reservation": parse_show_license_reservation,
            "show license summary": parse_show_license_summary,
            "show license": parse_show_license,
        },
        "nxos": {
            "show version": parse_nexus_show_version,
            "show license all": parse_nexus_show_license_all,
        },
    }


def _device_collect_summary(device_name: str, ssh_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract parity fields from SSH collect data matching cn-tool "Device Data" columns.

    Parameters
    ----------
    device_name:
        Hostname / IP used as the primary key (for error entries).
    ssh_data:
        The dict returned by ``collect_device`` — contains ``platform`` key
        and per-command parsed outputs.

    Returns
    -------
    dict with keys:
        ``serial``   — Serial Number (str)
        ``version``  — Software Version (str)
        ``image``    — Software Image (str)
        ``license``  — list of {name, status, type, count} dicts (may be empty)
        ``platform`` — platform family detected ("iosxe" / "nxos")
        ``uptime``   — Uptime string (str, may be empty)

    The field names are chosen to match the "Device Data" column semantics from
    ``utils/parsers.prepare_device_data`` / ``modules/device_query.process_device_data``:
        "Serial Number" → ``serial``
        "Software Version" → ``version``
        "Software Image" → ``image``
        "License Name" / "License Status" → entries in ``license``
    """
    # Error result from collect_device carries device_name as key
    if device_name in ssh_data and isinstance(ssh_data.get(device_name), str):
        return {
            "status": "error",
            "error": ssh_data[device_name],
        }

    platform = ssh_data.get("platform", "")
    version_data: Dict[str, Any] = ssh_data.get("show version", {}) or {}

    serial: str = version_data.get("Serial Number", "") or ""
    version: str = version_data.get("Software Version", "") or ""
    image: str = version_data.get("Software Image", "") or ""
    uptime: str = version_data.get("Uptime", "") or ""

    license_entries: List[Dict[str, str]] = []

    if platform == "iosxe":
        # Reservation data
        reservation_data: Dict[str, Any] = ssh_data.get("show license reservation", {}) or {}
        for sn, info in reservation_data.items():
            for lic in info.get("LICENSES", []):
                license_entries.append({
                    "name": lic.get("LICENSE_NAME", ""),
                    "type": lic.get("LICENSE_TYPE", ""),
                    "status": info.get("RESERVATION_STATUS", ""),
                    "count": "",
                })

        # Summary data
        for lic in ssh_data.get("show license summary", []) or []:
            license_entries.append({
                "name": lic.get("License", ""),
                "type": "",
                "status": lic.get("Status", ""),
                "count": lic.get("Count", ""),
            })

        # Detailed license data
        for lic in ssh_data.get("show license", []) or []:
            license_entries.append({
                "name": lic.get("Feature", ""),
                "type": lic.get("License Type", ""),
                "status": lic.get("License State", ""),
                "count": lic.get("License Count", ""),
            })

    elif platform == "nxos":
        for lic in ssh_data.get("show license all", []) or []:
            license_entries.append({
                "name": lic.get("License Name", ""),
                "type": lic.get("License Type", ""),
                "status": lic.get("License Status", ""),
                "count": lic.get("License Count", ""),
            })

    return {
        "platform": platform,
        "serial": serial,
        "version": version,
        "image": image,
        "uptime": uptime,
        "license": license_entries,
    }


def _run_collect_step(
    runtime: "LensRuntime",
    hostname: str,
    findings: List[LensFinding],
) -> Dict[str, Any]:
    """Run the SSH collect step for a device hostname.

    Returns a summary dict to be stored under ``summary["collect"]``.
    Never raises — all errors are captured and returned as an error-keyed dict
    that the caller stores in the summary; an info finding is appended.

    Graceful degradation:
    - ``device_ssh_enabled`` absent/falsy → ``{"status": "not_configured"}``
    - offline runtime → ``{"status": "offline"}`` (caller handles; this path
      is only reached from the online dispatch, but defensively handled)
    - SSH error → ``{"status": "error", "error": <message>}``
    """
    from cn_lens.adapters.device_ssh import collect_device, _is_ssh_enabled

    cfg = getattr(runtime, "cfg", {}) or {}

    if not _is_ssh_enabled(cfg):
        return {"status": "not_configured"}

    platform_commands = _build_collect_platform_commands()
    try:
        ssh_data = collect_device(runtime, hostname, platform_commands=platform_commands)
    except Exception as exc:
        runtime.logger.error("device: collect step raised unexpectedly for %s: %s", hostname, exc)
        findings.append(synthesise_error_finding("device_ssh", exc))
        return {"status": "error", "error": str(exc)}

    # collect_device returns error-keyed dict on failure
    if hostname in ssh_data and isinstance(ssh_data.get(hostname), str):
        error_msg = ssh_data[hostname]
        runtime.logger.info("device: collect step failed for %s: %s", hostname, error_msg)
        findings.append(_info_finding(
            source="device_ssh",
            message="collect_failed",
            detail={"hostname": hostname, "error": error_msg},
        ))
        return {"status": "error", "error": error_msg}

    return _device_collect_summary(hostname, ssh_data)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_fqdn_shaped(hostname: str) -> bool:
    """Return True when the hostname has 3+ dot-separated labels (looks like a full FQDN)."""
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
        findings=(_classifier_finding(),),
    )


# ---------------------------------------------------------------------------
# IB IP extraction helper
# ---------------------------------------------------------------------------

def _extract_ips_from_ib_rows(rows) -> List[str]:
    """Extract bare IP addresses from InfobloxRow list."""
    ips = []
    for row in rows:
        net = getattr(row, "network", "") or ""
        if net and "/" not in net:
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
    collect: bool = False,
) -> Dict[str, Any]:
    """Execute the full device enrichment chain for a given hostname."""
    from cn_lens.adapters import active_directory, infoblox, config_repo

    summary: Dict[str, Any] = dict(base_summary)
    resolved_ips: List[str] = []

    # 1. ad.lookup_device
    call_adapter(
        summary, "ad",
        fn=lambda: active_directory.lookup_device(runtime, hostname),
        to_row=lambda r: {
            "found": r[0].found,
            "ou_path": r[0].ou_path,
            "last_site_code": r[0].last_site_code,
            "computer_dn": r[0].computer_dn,
        },
        findings=findings,
        log_prefix="device: ad.lookup_device",
        on_success=lambda r: findings.extend(r[1]),
        on_error_extra={"found": False},
    )

    # 2. infoblox.search_by_keyword
    call_adapter(
        summary, "infoblox",
        fn=lambda: infoblox.search_by_keyword(runtime, hostname),
        to_row=lambda r: {
            "match_count": len(r),
            "networks": [row.network for row in r],
        },
        findings=findings,
        log_prefix="device: infoblox.search_by_keyword",
        on_success=lambda r: resolved_ips.extend(_extract_ips_from_ib_rows(r)),
    )

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
            findings.append(synthesise_error_finding("infoblox", exc))

    # 4. config_repo.search
    call_adapter(
        summary, "config_repo",
        fn=lambda: config_repo.search(runtime, hostname),
        to_row=lambda r: {
            "total_files_scanned": r.total_files_scanned,
            "match_count": len(r.matches),
            "truncated": r.truncated,
        },
        findings=findings,
        log_prefix="device: config_repo.search",
    )

    # 5. [probe] ping resolved IPs
    if probe and resolved_ips:
        probe_summary: Dict[str, Any] = {}
        _probe_ips(runtime, resolved_ips, findings, probe_summary)
        summary["probe"] = probe_summary

    # 6. [collect] SSH show-command collection
    if collect:
        summary["collect"] = _run_collect_step(runtime, hostname, findings)

    return summary


# ---------------------------------------------------------------------------
# Per-type dispatchers (probe captured via closure)
# ---------------------------------------------------------------------------

def _run_device(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    probe: bool,
    collect: bool,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    findings: List[LensFinding] = [_classifier_finding()]
    summary = _run_device_chain(runtime, obj.value, base_summary, findings, probe, collect=collect)
    return summary, findings


def _run_ip(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    probe: bool,
    collect: bool,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """IP → enrich_ip + ib_lookup_ip + config_repo + optional secondary device chain."""
    from cn_lens.adapters import active_directory, infoblox, config_repo

    summary: Dict[str, Any] = dict(base_summary)
    findings: List[LensFinding] = [_classifier_finding()]
    ip = obj.value
    resolved_hostname: str = ""

    # 1. ad.enrich_ip — resolved_hostname must be captured for step 4; kept as
    # explicit try/except because the side-effect variable capture does not fit
    # cleanly into call_adapter's on_success callback.
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
        findings.append(synthesise_error_finding("ad", exc))
        summary["ad"] = {"found": False, "error": str(exc)}

    # 2. infoblox.lookup_ip
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
        log_prefix="device: infoblox.lookup_ip",
        on_success=lambda r: findings.extend(r.findings),
        on_error_extra={"found": False},
    )

    # 3. config_repo.search
    call_adapter(
        summary, "config_repo",
        fn=lambda: config_repo.search(runtime, ip),
        to_row=lambda r: {
            "total_files_scanned": r.total_files_scanned,
            "match_count": len(r.matches),
            "truncated": r.truncated,
        },
        findings=findings,
        log_prefix="device: config_repo.search",
    )

    # 4. Secondary device chain when enrich_ip resolved a hostname
    if resolved_hostname:
        secondary_base = {"hostname": resolved_hostname}
        secondary_findings: List[LensFinding] = []
        secondary_summary = _run_device_chain(
            runtime, resolved_hostname, secondary_base, secondary_findings, probe,
            collect=collect,
        )
        findings.extend(secondary_findings)
        device_sub: Dict[str, Any] = {
            "hostname": resolved_hostname,
            "ad": secondary_summary.get("ad", {}),
            "infoblox": secondary_summary.get("infoblox", {}),
            "config_repo": secondary_summary.get("config_repo", {}),
        }
        if "collect" in secondary_summary:
            device_sub["collect"] = secondary_summary["collect"]
        summary["device"] = device_sub

    return summary, findings


def _run_fqdn(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    probe: bool,
    collect: bool,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """FQDN → if looks like a hostname (< 3 labels) run device chain; else classifier-only."""
    findings: List[LensFinding] = [_classifier_finding()]
    value = obj.value

    if not _is_fqdn_shaped(value):
        # Hostname-pattern: treat as DEVICE
        summary = _run_device_chain(runtime, value, base_summary, findings, probe, collect=collect)
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
    collect: bool,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    summary = dict(base_summary)
    findings = [_classifier_finding(), _info_finding(
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
    collect: bool,
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    summary = dict(base_summary)
    findings = [_classifier_finding(), _info_finding(
        source="device",
        message="Prefix not a device input; use inspect or impact",
        detail={"value": obj.value},
    )]
    return summary, findings


# ---------------------------------------------------------------------------
# Dispatch table builder (closures capture probe and collect)
# ---------------------------------------------------------------------------

def _make_dispatch(probe: bool, collect: bool = False) -> Dict[LensObjectType, Any]:
    """Return dispatch table with handlers capturing probe and collect via closure."""
    def wrap(fn):
        def handler(runtime, obj, base_summary):
            return fn(runtime, obj, base_summary, probe, collect)
        return handler

    return {
        LensObjectType.DEVICE: wrap(_run_device),
        LensObjectType.IP: wrap(_run_ip),
        LensObjectType.FQDN: wrap(_run_fqdn),
        LensObjectType.SITE: wrap(_run_site),
        LensObjectType.PREFIX: wrap(_run_prefix),
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def device_objects(
    object_set: ObjectSet,
    *,
    runtime: Optional["LensRuntime"] = None,
    run_id: Optional[str] = None,
    probe: bool = False,
    collect: bool = False,
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
    collect:
        When ``True`` run the SSH collect step via ``device_ssh.collect_device``
        for DEVICE and FQDN-as-device objects.  Adds a ``"collect"`` block to
        each result's summary with ``serial``, ``version``, ``image``, ``license``
        fields matching cn-tool "Device Data" column semantics.  When
        ``device_ssh_enabled`` is absent or falsy in config the collect block
        carries ``{"status": "not_configured"}`` and no SSH connection is made.

    Returns
    -------
    LensRun
        Always returned; never raises.  ``LensRun.workflow == "device"``.
    """
    return run_workflow(
        "device",
        object_set,
        runtime,
        registry=get_registry(),
        run_id=run_id,
        dispatch=_make_dispatch(probe, collect=collect),
        offline_result_fn=_build_offline_result,
    )
