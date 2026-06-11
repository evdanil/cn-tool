"""e911 workflow — collect E911 stack member MACs from network switches via SSH.

Requires SSH
------------
This workflow runs ``show switch`` on each target device via the device_ssh
adapter.  When ``device_ssh_enabled`` is absent or falsy the per-device
summary carries ``{"status": "not_configured"}`` and no SSH connection is
attempted.  This mirrors the ``device --collect`` degradation semantics.

Online
------
For each DEVICE / FQDN / IP object the handler:

1. Checks ``device_ssh_enabled``; if absent/falsy sets per-device
   ``summary["e911"] = {"status": "not_configured"}`` and skips SSH.
2. Calls ``collect_many`` with per-platform commands ``{"show switch": parse_show_switch}``
   (works for iosxe only — nxos does not use stacked architecture and the
   switch-stack concept does not apply; nxos targets produce an empty members
   list with ``is_valid=False`` from the parser, which is surfaced as an error
   result rather than a crash).
3. Parses the ``show switch`` output into per-member rows each carrying both
   MAC formats:
   - ``mac_colon``  e.g. ``"C4:AB:4D:EC:3B:60"``
   - ``mac_dot``    e.g. ``"C4AB.4DEC.3B60"``
4. Per-device error isolation: a failed SSH call on one device produces an
   error finding for that device and does not prevent other devices' results
   from being present in the run.

Offline / None runtime
-----------------------
Returns the MVP-shape LensRun (classifier finding + not_queried/disabled
sources) with no SSH I/O.

Output summary shape (per result)
----------------------------------
::

    {
        "original": "10.0.0.1",
        "normalized": "10.0.0.1",
        "type": "device",
        "e911": {
            "stack_mac": "C4:AB:4D:EC:3B:60",
            "members": [
                {
                    "switch_num": "1",
                    "role": "Active",
                    "mac_colon": "C4:AB:4D:EC:3B:60",
                    "mac_dot": "C4AB.4DEC.3B60",
                    "priority": "15",
                    "hw_version": "V02",
                    "state": "Ready",
                },
                ...
            ],
        },
    }

On SSH error the ``"e911"`` block carries::

    {"error": "<error message>"}

When SSH is not configured::

    {"status": "not_configured"}
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, TYPE_CHECKING

from cn_lens.adapters.registry import get_registry
from cn_lens.adapters.device_ssh import collect_many, _is_ssh_enabled
from cn_lens.models import LensFinding, LensObject, LensObjectType, LensResult, LensRun, ObjectSet
from cn_lens.workflows._helpers import (
    make_run_id,
    run_workflow,
    synthesise_error_finding,
    OFFLINE_FINDING_MESSAGE,
    CLASSIFIED_FINDING_MESSAGE,
)
from utils.parsers import parse_show_switch, normalize_mac_format

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CLASSIFIER_SOURCE = "classifier"
_SSH_SOURCE = "device_ssh"

_CLASSIFIER_MESSAGE = (
    "e911 workflow — collect stack member MAC addresses via SSH show switch"
)

# Per-platform SSH commands: only iosxe supports 'show switch'
# (nxos devices will return an error-pattern response which parse_show_switch
# converts to is_valid=False).
_PLATFORM_COMMANDS: Dict[str, Dict[str, Any]] = {
    "iosxe": {
        "show switch": parse_show_switch,
    },
    "nxos": {
        "show switch": parse_show_switch,
    },
}


# ---------------------------------------------------------------------------
# Helper: build per-device e911 summary from ssh collect result
# ---------------------------------------------------------------------------

def _build_e911_summary(device: str, ssh_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract per-stack-member rows from the SSH collect result.

    Parameters
    ----------
    device:
        Hostname / IP of the target device (used for error-keyed result detection).
    ssh_data:
        The dict returned by ``collect_many`` for this device.  Either:
        - Success: ``{"platform": "iosxe", "show switch": <parse_show_switch result>}``
        - Failure: ``{device: "<error message>"}``

    Returns
    -------
    dict
        ``{"stack_mac": "...", "members": [...]}`` on success,
        ``{"error": "<message>"}`` on SSH failure,
        ``{"is_valid": False, "error": "<message>"}`` when show switch parsed
        but found no valid members.
    """
    # Error result from collect_device / collect_many has device as key
    if device in ssh_data and isinstance(ssh_data.get(device), str):
        return {"error": ssh_data[device]}

    show_switch_result: Dict[str, Any] = ssh_data.get("show switch", {}) or {}

    if not show_switch_result.get("is_valid"):
        error_msg = show_switch_result.get("error") or "No valid switch stack members found"
        return {"error": error_msg}

    # Build per-member rows with both MAC formats
    stack_mac_raw: Optional[str] = show_switch_result.get("stack_mac")
    stack_mac_colon: Optional[str] = (
        normalize_mac_format(stack_mac_raw, "colon") if stack_mac_raw else None
    )

    members: List[Dict[str, Any]] = []
    for m in show_switch_result.get("members", []):
        raw_mac: str = m.get("mac_address", "")
        members.append({
            "switch_num": m.get("switch_num", ""),
            "role": m.get("role", ""),
            "mac_colon": normalize_mac_format(raw_mac, "colon") if raw_mac else "",
            "mac_dot": normalize_mac_format(raw_mac, "dot") if raw_mac else "",
            "priority": m.get("priority", ""),
            "hw_version": m.get("hw_version", ""),
            "state": m.get("state", ""),
        })

    return {
        "stack_mac": stack_mac_colon,
        "members": members,
    }


# ---------------------------------------------------------------------------
# Classifier finding factory
# ---------------------------------------------------------------------------

def _classifier_finding() -> LensFinding:
    return LensFinding(
        severity="info",
        source=_CLASSIFIER_SOURCE,
        message=_CLASSIFIER_MESSAGE,
        detail={"workflow": "e911"},
    )


def _info_finding(source: str, message: str, detail: Dict[str, Any] | None = None) -> LensFinding:
    return LensFinding(severity="info", source=source, message=message, detail=detail or {})


def _error_finding(source: str, message: str, detail: Dict[str, Any] | None = None) -> LensFinding:
    return LensFinding(severity="error", source=source, message=message, detail=detail or {})


# ---------------------------------------------------------------------------
# Offline result builder
# ---------------------------------------------------------------------------

def _build_offline_result(obj: LensObject, sources: Dict[str, str]) -> LensResult:
    return LensResult(
        lens_object=obj,
        status="classified",
        summary={
            "original": obj.original,
            "normalized": obj.normalized,
            "type": obj.object_type.value,
        },
        sources=sources,
        findings=(
            LensFinding(
                severity="info",
                source=_CLASSIFIER_SOURCE,
                message=OFFLINE_FINDING_MESSAGE,
                detail={"workflow": "e911"},
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Per-type handlers
# ---------------------------------------------------------------------------

def _run_device(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    ssh_results: Dict[str, Dict[str, Any]],
) -> tuple[Dict[str, Any], List[LensFinding]]:
    """Handler for DEVICE / FQDN / IP objects: extract e911 summary from ssh_results."""
    findings: List[LensFinding] = [_classifier_finding()]
    summary: Dict[str, Any] = dict(base_summary)

    device = obj.value
    ssh_data = ssh_results.get(device, {})

    # ssh_data absent (should not normally occur with collect_many)
    if not ssh_data:
        summary["e911"] = {"error": "no SSH result returned"}
        findings.append(_error_finding(
            _SSH_SOURCE, "collect_failed",
            {"device": device, "error": "no SSH result returned"},
        ))
        return summary, findings

    e911_summary = _build_e911_summary(device, ssh_data)
    summary["e911"] = e911_summary

    if "error" in e911_summary:
        # SSH failed or parse produced no valid members — record as info finding
        # (not a fatal error; the batch continues)
        findings.append(_info_finding(
            _SSH_SOURCE, "collect_failed",
            {"device": device, "error": e911_summary["error"]},
        ))

    return summary, findings


def _run_not_supported(
    runtime: "LensRuntime",
    obj: LensObject,
    base_summary: Dict[str, Any],
    _ssh_results: Dict[str, Dict[str, Any]],
) -> tuple[Dict[str, Any], List[LensFinding]]:
    """Handler for object types that are not valid e911 targets."""
    summary = dict(base_summary)
    findings = [
        _classifier_finding(),
        _info_finding(
            source="e911",
            message=(
                "e911 requires device hostnames or IPs; "
                "use a device hostname or IP address as input"
            ),
            detail={"value": obj.value, "type": obj.object_type.value},
        ),
    ]
    return summary, findings


# ---------------------------------------------------------------------------
# SSH collection step (online path)
# ---------------------------------------------------------------------------

def _run_ssh_collect(
    runtime: "LensRuntime",
    devices: List[str],
) -> Dict[str, Dict[str, Any]]:
    """Run collect_many and return raw SSH results keyed by device.

    Returns an empty dict when SSH is not configured (caller handles the
    not_configured summary shape).  All other errors are isolated per-device
    by collect_many itself.
    """
    cfg = getattr(runtime, "cfg", {}) or {}
    if not _is_ssh_enabled(cfg):
        return {}

    try:
        return collect_many(runtime, devices, platform_commands=_PLATFORM_COMMANDS)
    except Exception as exc:
        runtime.logger.error("e911: collect_many raised unexpectedly: %s", exc)
        # Return error-keyed entries for all devices
        return {d: {d: f"unexpected error: {exc}"} for d in devices}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def e911_objects(
    object_set: "ObjectSet",
    runtime: "Optional[LensRuntime]",
    *,
    run_id: Optional[str] = None,
) -> LensRun:
    """Collect E911 stack member MAC addresses from network switches.

    Parameters
    ----------
    object_set:
        The ObjectSet of classified inputs.  DEVICE, FQDN, and IP objects are
        dispatched to the SSH collection path.  Other types produce an info
        finding explaining they are not valid e911 targets.
    runtime:
        Active LensRuntime or ``None``.  When ``None`` or offline, returns the
        offline MVP-shape LensRun with no SSH I/O.
    run_id:
        Explicit run identifier.  When ``None``, resolved from
        ``runtime.options.run_id`` or auto-generated.

    Returns
    -------
    LensRun
        Always returned; never raises.
    """
    registry = get_registry()
    cfg = getattr(runtime, "cfg", {}) or {} if runtime is not None else {}
    ssh_enabled = _is_ssh_enabled(cfg)

    # Resolve run_id
    effective_run_id: str
    if run_id is not None:
        effective_run_id = run_id
    elif runtime is not None and runtime.options.run_id is not None:
        effective_run_id = runtime.options.run_id
    else:
        effective_run_id = make_run_id()

    # --- Offline path ---
    if runtime is None or runtime.offline:
        offline_sources: Dict[str, str] = {"classifier": "ok"}
        offline_sources.update(registry.source_statuses(runtime, offline=True))
        return LensRun(
            schema_version=1,
            tool="cn-lens",
            workflow="e911",
            run_id=effective_run_id,
            inputs=object_set,
            results=tuple(
                _build_offline_result(obj, offline_sources)
                for obj in object_set.objects
            ),
            warnings=(),
            errors=(),
        )

    # --- Online path ---
    sources: Dict[str, str] = {"classifier": "ok"}
    sources.update(registry.source_statuses(runtime))

    # Collect from all target devices in one batch (per-device error isolation)
    # Only DEVICE / FQDN / IP types are SSH targets; others pass through directly.
    _SSH_TARGET_TYPES = {LensObjectType.DEVICE, LensObjectType.FQDN, LensObjectType.IP}
    ssh_target_devices: List[str] = [
        obj.value
        for obj in object_set.objects
        if obj.object_type in _SSH_TARGET_TYPES
    ]

    if ssh_enabled and ssh_target_devices:
        ssh_results = _run_ssh_collect(runtime, ssh_target_devices)
    else:
        ssh_results = {}

    results: List[LensResult] = []
    for obj in object_set.objects:
        base_summary: Dict[str, Any] = {
            "original": obj.original,
            "normalized": obj.normalized,
            "type": obj.object_type.value,
        }
        try:
            if obj.object_type in _SSH_TARGET_TYPES:
                if not ssh_enabled:
                    # SSH not configured — produce not_configured summary
                    summary = dict(base_summary)
                    summary["e911"] = {"status": "not_configured"}
                    findings: List[LensFinding] = [
                        _classifier_finding(),
                        _info_finding(
                            _SSH_SOURCE,
                            "not_configured",
                            {"device": obj.value},
                        ),
                    ]
                else:
                    summary, findings = _run_device(runtime, obj, base_summary, ssh_results)
            else:
                summary, findings = _run_not_supported(runtime, obj, base_summary, ssh_results)
        except Exception as exc:
            runtime.logger.error(
                "e911: unexpected error in dispatcher for %s: %s", obj.value, exc
            )
            summary = dict(base_summary)
            findings = [
                _classifier_finding(),
                synthesise_error_finding("e911", exc),
            ]

        results.append(LensResult(
            lens_object=obj,
            status="classified",
            summary=summary,
            sources=sources,
            findings=tuple(findings),
        ))

    run = LensRun(
        schema_version=1,
        tool="cn-lens",
        workflow="e911",
        run_id=effective_run_id,
        inputs=object_set,
        results=tuple(results),
        warnings=(),
        errors=(),
    )

    # Persist on online path (mirrors other online workflows)
    from cn_lens.workflows._helpers import maybe_persist
    maybe_persist(run, runtime)

    return run
