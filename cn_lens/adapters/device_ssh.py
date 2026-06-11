"""SSH adapter for cn-lens (Phase 6, P6.1).

Connects to network devices via SSH using netmiko's ConnectHandler with
SSHDetect autodetect, ports the connection flow from
``modules/device_query.py`` / ``utils/parsers.py``.

Public surface
--------------
collect_device(runtime, device, *, platform_commands) -> dict
    Connect to a single device, run platform-specific commands, return results.
    Never raises — all failures are returned as error-keyed dicts.

collect_many(runtime, devices, *, platform_commands) -> dict[str, dict]
    Collect from multiple devices concurrently (ThreadPoolExecutor bounded by
    ``device_query_workers`` config key).  Per-device failure isolation: one
    device's exception never aborts the batch.

DeviceSshAdapter
    LensAdapter-conformant class (name="device_ssh", health(runtime)).
    health() returns ``not_configured`` when ``device_ssh_enabled`` is absent
    or falsy in config, ``disabled`` in offline mode, ``ok`` otherwise.

Design notes
------------
- No ``console``, ``print``, ``press_any_key``.  Logger only.
- Offline mode: collect_device / collect_many return immediately with error
  indicator; no SSH connection is attempted.
- Credentials: ``runtime.ensure_credentials("device")`` — same TACACS/GPG
  path as the "ad" scope.
- Concurrency: ThreadPoolExecutor max_workers = cfg["device_query_workers"]
  (default 10, same as cn-tool's device_query.py).
- Platform mapping: ``nxos`` in detected type → "nxos"; any ``cisco`` →
  "iosxe".  Unknown type → error result, no connection.
- Netmiko imports (SSHDetect, ConnLogOnly) are at module level so tests can
  patch them via patch.object without sys.modules injection.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from netmiko import ConnLogOnly, SSHDetect

from cn_lens.adapters.types import AdapterHealth
from utils.ssh import build_netmiko_device, describe_ssh_error, get_ssh_config_file

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Config key for the SSH enabled flag.
_CFG_ENABLED = "device_ssh_enabled"

#: Config key for the thread-pool size (shared with cn-tool's device_query.py).
_CFG_WORKERS = "device_query_workers"

#: Default pool size (mirrors device_query.py ThreadPoolExecutor argument).
_DEFAULT_WORKERS = 10

#: Sentinel value used as error marker in result dicts.
_ERROR_MARKER_PREFIX = "error:"


# ---------------------------------------------------------------------------
# Platform family mapping
# ---------------------------------------------------------------------------

def _detect_platform_family(detected_type: str) -> Optional[str]:
    """Map a netmiko device_type string to the cn-tool platform family name.

    Returns
    -------
    ``"nxos"``
        When ``detected_type`` contains ``"nxos"``.
    ``"iosxe"``
        When ``detected_type`` contains ``"cisco"`` (matches
        ``cisco_ios``, ``cisco_xe``, ``cisco_xr``).
    ``None``
        For any other detected type (unsupported platform).
    """
    if "nxos" in detected_type:
        return "nxos"
    if "cisco" in detected_type:
        return "iosxe"
    return None


# ---------------------------------------------------------------------------
# Core: collect_device
# ---------------------------------------------------------------------------

def collect_device(
    runtime: "LensRuntime",
    device: str,
    *,
    platform_commands: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Connect to *device*, run per-platform commands, return parsed results.

    Parameters
    ----------
    runtime:
        LensRuntime (or duck-type with .offline, .logger, .cfg,
        .ensure_credentials).
    device:
        IP address or hostname of the target device.
    platform_commands:
        Mapping of platform family → {command_name → parser_callable}.
        Parser callables receive the raw command output (str) and return
        Any (typically dict).

    Returns
    -------
    dict
        On success: ``{"platform": <family>, <cmd>: <parsed_output>, ...}``.
        On failure: ``{device: <error_string>}`` — never raises.
    """
    logger: logging.Logger = runtime.logger

    # Deliberate deviation from donor process_device_commands (device_query.py):
    # the donor applies a reverse-DNS device-name gate — only names matching
    # ``(es|mp|vi|bl|sp|lf)\d{3}`` are processed.  lens collect_device omits
    # that gate intentionally: cn-lens accepts any reachable target (IP, FQDN,
    # or arbitrary hostname).  This deviation is documented in docs/CN-LENS.md.

    # --- Offline short-circuit ---
    if runtime.offline:
        logger.debug("device_ssh.collect_device: offline, skipping %s", device)
        return {device: "offline mode — no SSH connections"}

    # --- Credentials ---
    try:
        username, password = runtime.ensure_credentials("device")
    except Exception as exc:
        logger.warning(
            "device_ssh.collect_device: credential error for %s: %s", device, exc
        )
        return {device: f"credential error: {exc}"}

    log_file = str(runtime.cfg.get("logging_file") or Path.home() / "netmiko.log")
    ssh_config_file = get_ssh_config_file(runtime.cfg, logger)

    dev = build_netmiko_device(
        host=device,
        device_type="autodetect",
        username=username,
        password=password,
        secret="",
        ssh_config_file=ssh_config_file,
    )

    conn = None
    output: Dict[str, Any] = {}
    try:
        # --- Autodetect phase ---
        guesser = SSHDetect(**dev)
        detected_type = guesser.autodetect()

        if not detected_type:
            logger.info(
                "device_ssh.collect_device: %s — unable to autodetect device type",
                device,
            )
            return {device: "unable to autodetect device type"}

        platform_family = _detect_platform_family(detected_type)
        if platform_family is None:
            logger.info(
                "device_ssh.collect_device: %s — unsupported platform family: %s",
                device,
                detected_type,
            )
            return {device: f"unsupported platform family: {detected_type}"}

        # --- Connect with detected type ---
        dev["device_type"] = detected_type
        conn = ConnLogOnly(log_file=log_file, **dev)

        cmd_list = platform_commands.get(platform_family, {})
        if not cmd_list:
            logger.warning(
                "device_ssh.collect_device: %s — no commands for platform %r",
                device,
                platform_family,
            )
            return {device: f"no commands defined for platform '{platform_family}'"}

        output["platform"] = platform_family

        for command, parser in cmd_list.items():
            raw = conn.send_command(f"{command}\n", auto_find_prompt=True)
            if isinstance(raw, str):
                output[command] = parser(raw) if callable(parser) else raw
            else:
                logger.warning(
                    "device_ssh.collect_device: %s — command %r did not return str",
                    device,
                    command,
                )
                output[command] = {}

    except Exception as exc:
        error_msg = describe_ssh_error(exc)
        logger.info(
            "device_ssh.collect_device: %s — connection/command error: %s",
            device,
            error_msg,
        )
        return {device: f"connection/command error: {error_msg}"}
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:
                pass  # best-effort disconnect

    return output


# ---------------------------------------------------------------------------
# Batch: collect_many
# ---------------------------------------------------------------------------

def collect_many(
    runtime: "LensRuntime",
    devices: List[str],
    *,
    platform_commands: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Collect from multiple devices concurrently.

    Uses ``ThreadPoolExecutor`` bounded by the ``device_query_workers`` config
    key (default 10).  Per-device failures are isolated: an exception from one
    device's future is caught and recorded as an error result; the remaining
    devices are unaffected.

    Parameters
    ----------
    runtime:
        LensRuntime.
    devices:
        Sequence of IP addresses or hostnames.  Duplicates are processed as
        given; deduplication is the caller's responsibility.
    platform_commands:
        Same shape as ``collect_device``.

    Returns
    -------
    dict[str, dict]
        Keys are the original device strings.  Values are either a successful
        result dict or an error dict ``{device: <error_string>}``.
        Every device in *devices* has exactly one entry in the returned dict.
    """
    results: Dict[str, Dict[str, Any]] = {}

    if runtime.offline:
        for device in devices:
            results[device] = {device: "offline mode — no SSH connections"}
        return results

    # Pre-acquire credentials on the calling (main) thread before launching
    # workers — prevents N pool threads from racing into ensure_credentials
    # simultaneously (donor-faithful pattern from device_query.py:111-114).
    try:
        runtime.ensure_credentials("device")
    except Exception as exc:
        runtime.logger.warning(
            "device_ssh.collect_many: credential acquisition failed: %s", exc
        )
        return {d: {d: f"credential error: {exc}"} for d in devices}

    try:
        max_workers = int(runtime.cfg.get(_CFG_WORKERS, _DEFAULT_WORKERS))
    except (TypeError, ValueError):
        max_workers = _DEFAULT_WORKERS
    if max_workers < 1:
        max_workers = _DEFAULT_WORKERS

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_device = {
            executor.submit(
                collect_device,
                runtime,
                device,
                platform_commands=platform_commands,
            ): device
            for device in devices
        }
        for future in as_completed(future_to_device):
            device = future_to_device[future]
            try:
                results[device] = future.result()
            except Exception as exc:
                runtime.logger.error(
                    "device_ssh.collect_many: unhandled exception for %s: %s",
                    device,
                    exc,
                )
                results[device] = {device: f"unexpected error: {exc}"}

    return results


# ---------------------------------------------------------------------------
# Enabled-flag helper
# ---------------------------------------------------------------------------

def _is_ssh_enabled(cfg: Dict[str, Any]) -> bool:
    """Return True iff ``device_ssh_enabled`` is truthy in *cfg*.

    Absent key (or any falsy value) → disabled.
    This mirrors the plugin-style enabled-flag semantics used by other adapters.
    """
    value = cfg.get(_CFG_ENABLED)
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "on", "t", "y"}
    return bool(value)


# ---------------------------------------------------------------------------
# Adapter class satisfying LensAdapter Protocol
# ---------------------------------------------------------------------------

class DeviceSshAdapter:
    """LensAdapter for SSH device collection (netmiko).

    Satisfies the ``LensAdapter`` Protocol: ``name`` class attribute and
    ``health(runtime)`` method.  All real SSH work is delegated to the
    module-level ``collect_device`` / ``collect_many`` functions.
    """

    name: str = "device_ssh"

    def health(self, runtime: "LensRuntime") -> AdapterHealth:
        """Return the adapter's availability for the given runtime.

        Status mapping
        --------------
        ``disabled``
            Runtime is in offline mode.
        ``not_configured``
            ``device_ssh_enabled`` is absent or falsy in the config.
            This is the default state — the adapter is opt-in.
        ``ok``
            ``device_ssh_enabled`` is truthy; credentials will be acquired
            on first use.
        """
        if runtime.offline:
            return AdapterHealth(status="disabled", detail="offline mode")

        if not _is_ssh_enabled(runtime.cfg):
            return AdapterHealth(
                status="not_configured",
                detail="device_ssh_enabled is false or absent in config",
            )

        return AdapterHealth(status="ok", detail="")
