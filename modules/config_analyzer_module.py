import os
from pathlib import Path
from typing import Optional

from core.base import BaseModule, ScriptContext
from utils.display import get_global_color_scheme


class ConfigAnalyzerModule(BaseModule):
    """
    Integrates the external Config Analyzer TUI (in external/config-analyzer)
    to browse the configuration repository and diff device snapshots.

    Appears in the Info menu under key 'c'. Visibility is gated by
    'config_repo_enabled'.
    """

    @property
    def menu_key(self) -> str:
        # As requested: use 'c' under Info
        return "c"

    @property
    def menu_title(self) -> str:
        return "Config Repository Browser (TUI)"

    @property
    def visibility_config_key(self) -> Optional[str]:
        return "config_repo_enabled"

    def run(self, ctx: ScriptContext) -> None:
        colors = get_global_color_scheme(ctx.cfg)
        logger = ctx.logger

        # Pre-flight: ensure repository access
        # Use analyzer-specific override if present; otherwise fallback to global
        repo_path = ctx.cfg.get("config_analyzer_repo_directory") or ctx.cfg.get("config_repo_directory")
        if not repo_path or not Path(repo_path).exists():
            ctx.console.print(f"[{colors['error']}]Configuration repository directory is not accessible.[/]")
            return

        # Read optional settings
        history_dir = ctx.cfg.get("config_repo_history_dir", "history")
        layout_pref = ctx.cfg.get("config_analyzer_layout", "right")
        scroll_to_end = bool(ctx.cfg.get("config_analyzer_scroll_to_end", False))
        debug = bool(ctx.cfg.get("config_analyzer_debug", False))

        if debug:
            os.environ["CONFIG_ANALYZER_DEBUG"] = "1"

        try:
            # Lazy imports to keep this optional
            from config_analyzer.repo_browser import RepoBrowserApp
            from config_analyzer.tui import CommitSelectorApp
            from config_analyzer.utils import find_device_history, collect_snapshots
        except ImportError as e:
            ctx.console.print(
                f"[{colors['warning']}]Config Analyzer code or dependencies missing.[/]\n"
                f"[{colors['description']}]Install dependencies:[/] pip install textual python-dateutil\n"
                f"[{colors['error']}]Details:[/] {e}"
            )
            logger.exception("Config Analyzer import failed")
            return

        history_dir_l = str(history_dir).lower()

        # Main navigation loop: browse devices, then view snapshots/diff
        selected_cfg_path: Optional[str] = None
        device: Optional[str] = None
        try:
            while True:
                if not device:
                    try:
                        ctx.console.clear()
                    except Exception:
                        pass
                    browser = RepoBrowserApp(
                        str(repo_path),
                        scroll_to_end=scroll_to_end,
                        start_path=selected_cfg_path,
                        start_layout=layout_pref,
                        history_dir=str(history_dir),
                    )
                    browser.run()
                    if not getattr(browser, "selected_device_name", None):
                        return
                    device = browser.selected_device_name
                    selected_cfg_path = getattr(browser, "selected_device_cfg_path", None)
                    layout_pref = getattr(browser, "layout", layout_pref)

                device_history_path = find_device_history(str(repo_path), device, selected_cfg_path, str(history_dir))
                if not device_history_path:
                    ctx.console.print(
                        f"[{colors['warning']}]No history folder found for device '{device}'.[/]"
                    )

                # Find current config (outside history)
                current_config_path = selected_cfg_path
                if not current_config_path:
                    for root, dirs, files in os.walk(str(repo_path)):
                        dirs[:] = [d for d in dirs if d.lower() != history_dir_l]
                        if f"{device}.cfg" in files:
                            current_config_path = os.path.join(root, f"{device}.cfg")
                            break

                # Collect, parse, order snapshots (dedupes Current if identical to latest)
                snapshots = collect_snapshots(str(repo_path), device, selected_cfg_path, str(history_dir))

                if not snapshots:
                    ctx.console.print(
                        f"[{colors['warning']}]No snapshots or current config found for device '{device}'.[/]"
                    )
                    return

                try:
                    try:
                        ctx.console.clear()
                    except Exception:
                        pass
                    app = CommitSelectorApp(
                        snapshots_data=snapshots,
                        scroll_to_end=scroll_to_end,
                        layout=layout_pref,
                    )
                    app.run()
                except Exception as e:
                    ctx.console.print(f"[{colors['error']}]TUI error:[/] {e}")
                    return

                layout_pref = getattr(app, "layout", layout_pref)
                if getattr(app, "navigate_back", False):
                    device = None
                    selected_cfg_path = current_config_path
                    continue
                break
        except Exception:
            logger.exception("Config Analyzer module failed")
            ctx.console.print(f"[{colors['error']}]Unexpected error in Config Analyzer module.[/]")
