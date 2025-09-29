import os
from pathlib import Path
from typing import Optional, List

from core.base import BaseModule, ScriptContext
from utils.display import get_global_color_scheme
from utils.file_io import check_dir_accessibility


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

        # Pre-flight: gather repository paths (multi-root aware)
        def _coerce_repo_inputs(value) -> List[Path]:
            if not value:
                return []
            if isinstance(value, (list, tuple, set)):
                items = list(value)
            else:
                items = [value]

            paths: List[Path] = []
            for item in items:
                if item is None:
                    continue
                if isinstance(item, Path):
                    candidates = [item]
                else:
                    text = str(item)
                    if not text:
                        continue
                    fragments = [frag.strip() for frag in text.split(',')] if ',' in text else [text.strip()]
                    candidates = [Path(fragment).expanduser() for fragment in fragments if fragment]
                for candidate in candidates:
                    try:
                        resolved = candidate.expanduser().resolve(strict=False)
                    except Exception:
                        resolved = candidate.expanduser()
                    paths.append(resolved)
            return paths

        repo_candidates: List[Path] = []
        repo_candidates.extend(_coerce_repo_inputs(ctx.cfg.get("config_analyzer_repo_directories")))
        if not repo_candidates:
            repo_candidates.extend(_coerce_repo_inputs(ctx.cfg.get("config_analyzer_repo_directory")))
        if not repo_candidates:
            repo_candidates.extend(_coerce_repo_inputs(ctx.cfg.get("config_repo_directory")))

        seen: set[str] = set()
        repo_roots: List[Path] = []
        for candidate in repo_candidates:
            key = candidate.as_posix()
            if key in seen:
                continue
            if check_dir_accessibility(logger, candidate):
                repo_roots.append(candidate)
                seen.add(key)
            else:
                ctx.console.print(
                    f"[{colors['warning']}]Configuration repository directory is not accessible: {candidate}[/]"
                )

        if not repo_roots:
            ctx.console.print(f"[{colors['error']}]No accessible configuration repository directories found.[/]")
            return

        def _normalize_repo_names(value) -> List[str]:
            if isinstance(value, (list, tuple)):
                return [str(item).strip() for item in value]
            if isinstance(value, str):
                return [segment.strip() for segment in value.split(',')]
            return []

        repo_name_candidates = _normalize_repo_names(ctx.cfg.get("config_analyzer_repo_names"))
        repo_label_overrides: List[str] = []
        for idx, _root in enumerate(repo_roots):
            label = repo_name_candidates[idx] if idx < len(repo_name_candidates) else ""
            repo_label_overrides.append(label)

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

        history_dir = str(history_dir)
        history_dir_l = history_dir.lower()

        repo_root_strings = [str(path) for path in repo_roots]

        def _resolve_repo_root(path: Optional[str]) -> Optional[Path]:
            if not path:
                return None
            try:
                abs_path = Path(path).expanduser().resolve(strict=False)
            except Exception:
                return None
            for root in repo_roots:
                try:
                    abs_path.relative_to(root)
                    return root
                except ValueError:
                    continue
            return None

        def _locate_device_config(device_name: str) -> tuple[Optional[str], Optional[Path]]:
            target = f"{device_name}.cfg"
            for repo_root in repo_roots:
                for walk_root, dirs, files in os.walk(str(repo_root)):
                    dirs[:] = [d for d in dirs if d.lower() != history_dir_l]
                    if target in files:
                        return os.path.join(walk_root, target), repo_root
            return None, None

        # Main navigation loop: browse devices, then view snapshots/diff
        selected_cfg_path: Optional[str] = None
        device: Optional[str] = None
        selected_repo_root: Optional[Path] = None
        try:
            while True:
                if not device:
                    try:
                        ctx.console.clear()
                    except Exception:
                        pass
                    browser = RepoBrowserApp(
                        repo_root_strings,
                        scroll_to_end=scroll_to_end,
                        start_path=selected_cfg_path,
                        start_layout=layout_pref,
                        history_dir=history_dir,
                        repo_names=repo_label_overrides,
                    )
                    browser.run()
                    if not getattr(browser, "selected_device_name", None):
                        return
                    device = browser.selected_device_name
                    selected_cfg_path = getattr(browser, "selected_device_cfg_path", None)
                    repo_hint = getattr(browser, "selected_repo_root", None)
                    if repo_hint:
                        try:
                            selected_repo_root = Path(str(repo_hint)).expanduser().resolve(strict=False)
                        except Exception:
                            selected_repo_root = _resolve_repo_root(repo_hint)
                    else:
                        selected_repo_root = _resolve_repo_root(selected_cfg_path)
                    layout_pref = getattr(browser, "layout", layout_pref)

                repo_root_for_device = selected_repo_root or _resolve_repo_root(selected_cfg_path)
                if not repo_root_for_device:
                    selected_cfg_path, repo_root_for_device = _locate_device_config(device)
                    if selected_cfg_path:
                        selected_repo_root = repo_root_for_device
                if not repo_root_for_device:
                    ctx.console.print(
                        f"[{colors['error']}]Unable to locate configuration repository for device '{device}'.[/]"
                    )
                    return

                repo_root_str = str(repo_root_for_device)

                device_history_path = find_device_history(repo_root_str, device, selected_cfg_path, history_dir)
                if not device_history_path:
                    ctx.console.print(
                        f"[{colors['warning']}]No history folder found for device '{device}'.[/]"
                    )

                # Find current config (outside history)
                current_config_path = selected_cfg_path
                if not current_config_path:
                    for root, dirs, files in os.walk(repo_root_str):
                        dirs[:] = [d for d in dirs if d.lower() != history_dir_l]
                        if f"{device}.cfg" in files:
                            current_config_path = os.path.join(root, f"{device}.cfg")
                            break

                # Collect, parse, order snapshots (dedupes Current if identical to latest)
                snapshots = collect_snapshots(repo_root_str, device, selected_cfg_path, history_dir)

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
                    selected_repo_root = repo_root_for_device if current_config_path else selected_repo_root
                    continue
                break
        except Exception:
            logger.exception("Config Analyzer module failed")
            ctx.console.print(f"[{colors['error']}]Unexpected error in Config Analyzer module.[/]")
