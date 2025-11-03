from typing import Any, Dict, Optional
from time import time
from datetime import datetime

from core.base import ScriptContext
from utils.display import get_global_color_scheme


def _yaml_device_count(ctx: ScriptContext) -> int:
    try:
        for plugin in ctx.plugins:
            # Prefer a dedicated property if available
            if hasattr(plugin, 'name') and getattr(plugin, 'name') == 'SD-WAN YAML Search':
                if hasattr(plugin, 'device_count'):
                    return int(getattr(plugin, 'device_count'))
                # Fallback to internal map if present
                data = getattr(plugin, '_yaml_data', None)
                if isinstance(data, dict):
                    return len(data)
    except Exception:
        pass
    return 0


def build_cache_status_line(ctx: ScriptContext) -> str:
    """
    Returns a single-line, Rich-markup string describing cache status.
    Safe to call even if cache is disabled or absent.
    """
    colors = get_global_color_scheme(ctx.cfg)

    # If exiting is in progress, surface a graceful shutdown status
    # Timestamp in local time, no seconds
    ts = datetime.now().astimezone().strftime("%d %b %Y %H:%M %Z")

    # Compute repo (file index) and YAML device counts up front
    repo_count = 0
    if ctx.cfg.get("cache_enabled", False) and getattr(ctx, "cache", None):
        try:
            repo_count = len(ctx.cache.dev_idx)
        except Exception:
            repo_count = 0
    yaml_count = _yaml_device_count(ctx)
    total_devices = repo_count + yaml_count

    if ctx.cfg.get("exiting", False):
        yaml_enabled = bool(ctx.cfg.get("sdwan_yaml_enabled", False)) if isinstance(ctx.cfg, dict) else False
        parts = [f"Repo [{colors['success']}]{repo_count}[/]"]
        if yaml_enabled:
            parts.append(f"YAML [{colors['success']}]{yaml_count}[/]")
        suffix = " (" + ", ".join(parts) + ")"
        return (
            f"[{colors['description']}]{ts} Configuration Cache Status: "
            f"[{colors['warning']}]Exiting Gracefully…[/] "
            f"Total Devices: [{colors['success']}]{total_devices}[/]" + suffix
        )
    if not ctx.cfg.get("cache_enabled", False) or not getattr(ctx, "cache", None):
        yaml_enabled = bool(ctx.cfg.get("sdwan_yaml_enabled", False)) if isinstance(ctx.cfg, dict) else False
        parts = [f"Repo [{colors['success']}]{repo_count}[/]"]
        if yaml_enabled:
            parts.append(f"YAML [{colors['success']}]{yaml_count}[/]")
        suffix = " (" + ", ".join(parts) + ")"
        return (
            f"[{colors['description']}]{ts} Configuration Cache Status: "
            f"[{colors['error']}]Disabled[/] "
            f"Total Devices: [{colors['success']}]{total_devices}[/]" + suffix
        )

    dc = ctx.cache.dc
    # If a fatal indexing error was recorded, show it immediately
    try:
        err_msg = dc.get("indexing_error", None)
    except Exception:
        err_msg = None
    if not err_msg:
        err_msg = ctx.cfg.get("indexing_error") if isinstance(ctx.cfg, dict) else None
    if err_msg:
        yaml_enabled = bool(ctx.cfg.get("sdwan_yaml_enabled", False)) if isinstance(ctx.cfg, dict) else False
        parts = [f"Repo [{colors['success']}]{repo_count}[/]"]
        if yaml_enabled:
            parts.append(f"YAML [{colors['success']}]{yaml_count}[/]")
        suffix = " (" + ", ".join(parts) + ")"
        return (
            f"[{colors['description']}]{ts} Configuration Cache Status: "
            f"[{colors['error']}]Error[/] - {err_msg} "
            f"Total Devices: [{colors['success']}]{total_devices}[/]" + suffix
        )
    try:
        indexing = bool(dc.get("indexing", False))
    except Exception:
        indexing = False

    if indexing:
        phase = dc.get("indexing_phase", "indexing") or "indexing"

        total = 0
        done = 0
        label = phase

        if phase == "checking":
            total = int(dc.get("checking_total", 0) or 0)
            done = int(dc.get("checking_done", 0) or 0)
        elif phase == "cleaning":
            total = int(dc.get("cleaning_total", 0) or 0)
            done = int(dc.get("cleaning_done", 0) or 0)
        else:  # indexing
            total = int(dc.get("indexing_total", 0) or 0)
            done = int(dc.get("indexing_done", 0) or 0)

        percent = int((done / total * 100)) if total else 0

        label_cap = str(label).capitalize()
        yaml_enabled = bool(ctx.cfg.get("sdwan_yaml_enabled", False)) if isinstance(ctx.cfg, dict) else False
        parts = [f"Repo [{colors['success']}]{repo_count}[/]"]
        if yaml_enabled:
            parts.append(f"YAML [{colors['success']}]{yaml_count}[/]")
        suffix = " (" + ", ".join(parts) + ")"
        return (
            f"[{colors['description']}]{ts} Configuration Cache Status: "
            f"[{colors['warning']}]{label_cap}[/] - "
            f"[{colors['value']}]{done}[/]/[{colors['value']}]{total}[/] "
            f"([{colors['success']}]{percent}%[/]) "
            f"Total Devices: [{colors['success']}]{total_devices}[/]" + suffix
        )

    # Not indexing: verify that the last successful update is not older than the last started indexing
    started = dc.get("indexing_started", 0)
    try:
        started_i = int(started or 0)
    except Exception:
        started_i = 0
    updated = ctx.cache.dc.get("updated", 0)
    try:
        updated_i = int(updated or 0)
    except Exception:
        updated_i = 0

    if started_i and updated_i < started_i:
        yaml_enabled = bool(ctx.cfg.get("sdwan_yaml_enabled", False)) if isinstance(ctx.cfg, dict) else False
        parts = [f"Repo [{colors['success']}]{repo_count}[/]"]
        if yaml_enabled:
            parts.append(f"YAML [{colors['success']}]{yaml_count}[/]")
        suffix = " (" + ", ".join(parts) + ")"
        return (
            f"[{colors['description']}]{ts} Configuration Cache Status: "
            f"[{colors['warning']}]Verifying[/] "
            f"Total Devices: [{colors['success']}]{total_devices}[/]" + suffix
        )
    # If nothing indexed yet, reflect 'Not Indexed' instead of 'Ready'
    if repo_count == 0 and int(updated_i) == 0:
        yaml_enabled = bool(ctx.cfg.get("sdwan_yaml_enabled", False)) if isinstance(ctx.cfg, dict) else False
        parts = [f"Repo [{colors['success']}]{repo_count}[/]"]
        if yaml_enabled:
            parts.append(f"YAML [{colors['success']}]{yaml_count}[/]")
        suffix = " (" + ", ".join(parts) + ")"
        return (
            f"[{colors['description']}]{ts} Configuration Cache Status: "
            f"[{colors['warning']}]Not Indexed[/] "
            f"Total Devices: [{colors['success']}]{total_devices}[/]" + suffix
        )
    yaml_enabled = bool(ctx.cfg.get("sdwan_yaml_enabled", False)) if isinstance(ctx.cfg, dict) else False
    parts = [f"Repo [{colors['success']}]{repo_count}[/]"]
    if yaml_enabled:
        parts.append(f"YAML [{colors['success']}]{yaml_count}[/]")
    suffix = " (" + ", ".join(parts) + ")"
    return (
        f"[{colors['description']}]{ts} Configuration Cache Status: "
        f"[{colors['success']}]Ready[/] "
        f"Total Devices: [{colors['success']}]{total_devices}[/]" + suffix
    )
    
