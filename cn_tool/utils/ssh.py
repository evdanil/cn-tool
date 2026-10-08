from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional


def resolve_ssh_config_file(raw_value: Any) -> Optional[str]:
    """
    Resolve an SSH config path to an absolute string when it exists.

    Blank values disable SSH config support. Missing files are treated as absent.
    """
    text = str(raw_value or "").strip()
    if not text:
        return None
    path = Path(text).expanduser()
    if not path.is_file():
        return None
    return str(path.resolve())


def get_ssh_config_file(
    cfg: Dict[str, Any],
    logger: Optional[logging.Logger] = None,
    *,
    strict: bool = False,
) -> Optional[str]:
    """
    Resolve the configured SSH config file.

    When strict is False, missing files silently disable SSH config support.
    When strict is True, a configured-but-missing path raises ValueError.
    """
    raw_value = cfg.get("ssh_config_file", "")
    text = str(raw_value or "").strip()
    if not text:
        return None
    resolved = resolve_ssh_config_file(text)
    if resolved:
        return resolved
    if strict:
        raise ValueError(f"SSH config file not found: {Path(text).expanduser()}")
    if logger is not None:
        logger.debug("SSH config file not found, SSH config support disabled: %s", Path(text).expanduser())
    return None


def build_netmiko_device(
    *,
    host: str,
    device_type: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    secret: str = "",
    port: Optional[int] = None,
    timeout: Optional[int] = None,
    ssh_config_file: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build shared Netmiko kwargs with the current SSH-config and auth policy.
    """
    device: Dict[str, Any] = {
        "device_type": device_type,
        "host": host,
        "username": username or "",
        "password": password or "",
        "secret": secret or "",
        "use_keys": False,
        "allow_agent": False,
    }
    if port is not None:
        device["port"] = int(port)
    if timeout is not None:
        device["timeout"] = int(timeout)
    if ssh_config_file:
        device["ssh_config_file"] = ssh_config_file
    return device


def describe_ssh_error(exc: Exception) -> str:
    """
    Normalize known SSH-config failures into clearer user-facing messages.

    Sensitive credential values ('password' and 'secret' dict-repr fragments)
    are scrubbed from the message before it is returned so that exception
    text that inadvertently contains connection kwargs cannot leak credentials
    into per-device results, log files, or persisted run artefacts.
    """
    message = str(exc).strip() or exc.__class__.__name__
    if "ProxyJump with more than one proxy server is not supported" in message:
        return "SSH config error: multi-hop ProxyJump is not supported."
    # Scrub 'password': '<value>' and 'secret': '<value>' patterns that can
    # appear when netmiko exception messages embed the connection kwargs dict.
    message = re.sub(r"('password'\s*:\s*)'[^']*'", r"\1'***'", message)
    message = re.sub(r"('secret'\s*:\s*)'[^']*'", r"\1'***'", message)
    return message
