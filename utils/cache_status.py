from datetime import datetime

from core.base import ScriptContext
from utils.display import get_global_color_scheme


def _yaml_plugin(ctx: ScriptContext):
    try:
        for plugin in ctx.plugins:
            # Prefer a dedicated property if available
            if hasattr(plugin, 'name') and getattr(plugin, 'name') == 'SD-WAN YAML Search':
                return plugin
    except Exception:
        pass
    return None


def _yaml_state(ctx: ScriptContext) -> tuple[int, bool]:
    plugin = _yaml_plugin(ctx)
    if plugin is None:
        return 0, False

    try:
        if hasattr(plugin, 'device_count'):
            count = int(getattr(plugin, 'device_count'))
        else:
            data = getattr(plugin, '_yaml_data', None)
            count = len(data) if isinstance(data, dict) else 0
    except Exception:
        count = 0

    try:
        loading = bool(getattr(plugin, 'is_loading'))
    except Exception:
        loading = False

    return count, loading


def _device_suffix(
    ctx: ScriptContext,
    colors: dict[str, str],
    repo_count: int,
    yaml_count: int,
    yaml_loading: bool,
) -> str:
    parts = [f"Repo [{colors['success']}]{repo_count}[/]"]
    yaml_enabled = bool(ctx.cfg.get("sdwan_yaml_enabled", False)) if isinstance(ctx.cfg, dict) else False
    if yaml_enabled:
        if yaml_loading:
            parts.append(f"YAML [{colors['warning']}]Loading[/]")
        else:
            parts.append(f"YAML [{colors['success']}]{yaml_count}[/]")
    return " (" + ", ".join(parts) + ")"


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
    yaml_count, yaml_loading = _yaml_state(ctx)
    total_devices = repo_count + yaml_count

    if ctx.cfg.get("exiting", False):
        suffix = _device_suffix(ctx, colors, repo_count, yaml_count, yaml_loading)
        return (
            f"[{colors['description']}]{ts} Configuration Cache Status: "
            f"[{colors['warning']}]Exiting Gracefully…[/] "
            f"Total Devices: [{colors['success']}]{total_devices}[/]" + suffix
        )
    if not ctx.cfg.get("cache_enabled", False) or not getattr(ctx, "cache", None):
        suffix = _device_suffix(ctx, colors, repo_count, yaml_count, yaml_loading)
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
        suffix = _device_suffix(ctx, colors, repo_count, yaml_count, yaml_loading)
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
        suffix = _device_suffix(ctx, colors, repo_count, yaml_count, yaml_loading)
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
        suffix = _device_suffix(ctx, colors, repo_count, yaml_count, yaml_loading)
        return (
            f"[{colors['description']}]{ts} Configuration Cache Status: "
            f"[{colors['warning']}]Verifying[/] "
            f"Total Devices: [{colors['success']}]{total_devices}[/]" + suffix
        )
    # If nothing indexed yet, reflect 'Not Indexed' instead of 'Ready'
    if repo_count == 0 and int(updated_i) == 0:
        suffix = _device_suffix(ctx, colors, repo_count, yaml_count, yaml_loading)
        return (
            f"[{colors['description']}]{ts} Configuration Cache Status: "
            f"[{colors['warning']}]Not Indexed[/] "
            f"Total Devices: [{colors['success']}]{total_devices}[/]" + suffix
        )
    suffix = _device_suffix(ctx, colors, repo_count, yaml_count, yaml_loading)
    return (
        f"[{colors['description']}]{ts} Configuration Cache Status: "
        f"[{colors['success']}]Ready[/] "
        f"Total Devices: [{colors['success']}]{total_devices}[/]" + suffix
    )
