import argparse
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.markup import escape

from cn_tool.core.base import BaseModule, CliResult, ScriptContext, cli_exit_code
from cn_tool.utils.cli_input import read_objects
from cn_tool.utils.config import RepoRoots, resolve_config_repo_roots
from cn_tool.utils.config_history import Since, Window, changed_lines, format_time, select_window, since_label
from cn_tool.utils.display import get_global_color_scheme


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def resolve_repo_roots(ctx: ScriptContext) -> RepoRoots:
    """The configuration repositories ``cn diff``, the repository browser and ``cn doctor`` use (see ``resolve_config_repo_roots``)."""
    return resolve_config_repo_roots(ctx.cfg, ctx.logger)


def configured_repo_roots(ctx: ScriptContext) -> Tuple[List[Tuple[Path, str]], List[Path]]:
    """``((root, label), ...)`` for the accessible configuration repositories and the inaccessible ones (see ``resolve_repo_roots``)."""
    roots = resolve_repo_roots(ctx)
    return roots.accessible, roots.inaccessible


def _report_missing_dependency(ctx: ScriptContext, exc: ImportError) -> None:
    """Tell (and log) that the optional config_analyzer package or one of its dependencies is missing."""
    colors = get_global_color_scheme(ctx.cfg)
    ctx.console.print(
        f"[{colors['warning']}]Config Analyzer code or dependencies missing.[/]\n"
        f"[{colors['description']}]Install dependencies:[/] pip install textual python-dateutil\n"
        f"[{colors['error']}]Details:[/] {escape(str(exc))}"
    )
    ctx.logger.exception("Config Analyzer import failed")


def _unreadable(cfg_path: str, history: Optional[str]) -> List[str]:
    """What of a device's current config, history folder and snapshots exists but cannot be read."""
    paths = [cfg_path]
    if history:
        try:
            names = sorted(os.listdir(history))
            paths.extend(os.path.join(history, name) for name in names if name.lower().endswith(".cfg"))
        except OSError:
            return [history]
    return [path for path in paths if not os.access(path, os.R_OK)]


def _mentions(window: Window, text: str) -> bool:
    """Whether any line of any snapshot in ``window`` contains ``text`` (any case)."""
    needle = text.lower()
    return any(needle in line.lower() for step in window.steps for line in step.content_body.splitlines())


def _unchanged_reason(window: Window, since: Optional[Since], text: Optional[str]) -> str:
    """Why a compared window has no rows to show."""
    name, when = window.start.original_filename, format_time(window.start.timestamp)
    if text is None:
        return f"no change since {name} ({when})"
    if not _mentions(window, text):
        return f"no line contains '{text}'"
    if since is not None:
        return f"'{text}' is unchanged since {name} ({when}); widen --since"
    return f"'{text}' is unchanged in the whole history (since {name}, {when})"


class ConfigAnalyzerModule(BaseModule):
    """
    Integrates the Config Analyzer TUI (the ``config_analyzer`` package, one ``ConfigAnalyzerApp``)
    to browse the configuration repository and diff device snapshots.

    Appears in the Info menu under key 'c'. Visibility is gated by
    'config_analyzer_enabled', which follows the directories the module reads (``resolve_repo_roots``),
    not ``[config_repo] directory`` alone. ``cn diff`` (``run_cli``) answers "what changed, and who changed it"
    from the same snapshots, without the TUI.
    """
    cli_name = "diff"

    @property
    def menu_key(self) -> str:
        # As requested: use 'c' under Info
        return "c"

    @property
    def menu_title(self) -> str:
        return "Config Repository Browser (TUI)"

    @property
    def visibility_config_key(self) -> Optional[str]:
        return "config_analyzer_enabled"

    def run(self, ctx: ScriptContext) -> None:
        colors = get_global_color_scheme(ctx.cfg)
        logger = ctx.logger

        # Pre-flight: gather repository paths (multi-root aware)
        roots, inaccessible = configured_repo_roots(ctx)
        for path in inaccessible:
            ctx.console.print(f"[{colors['warning']}]Configuration repository directory is not accessible: {path}[/]")
        if not roots:
            ctx.console.print(f"[{colors['error']}]No accessible configuration repository directories found.[/]")
            return

        # Read optional settings
        history_dir = str(ctx.cfg.get("config_repo_history_dir", "history"))
        layout = ctx.cfg.get("config_analyzer_layout", "right")
        scroll_to_end = bool(ctx.cfg.get("config_analyzer_scroll_to_end", False))
        debug = bool(ctx.cfg.get("config_analyzer_debug", False))

        if debug:
            os.environ["CONFIG_ANALYZER_DEBUG"] = "1"

        try:
            # Lazy import to keep this optional
            from config_analyzer.app import ConfigAnalyzerApp
        except ImportError as e:
            _report_missing_dependency(ctx, e)
            return

        # One App hosts the browser and the snapshot view; it returns when the user quits.
        try:
            ConfigAnalyzerApp(
                [str(root) for root, _label in roots],
                repo_names=[label for _root, label in roots],
                history_dir=history_dir,
                layout=layout,
                scroll_to_end=scroll_to_end,
            ).run()
        except Exception:
            logger.exception("Config Analyzer module failed")
            ctx.console.print(f"[{colors['error']}]Unexpected error in Config Analyzer module.[/]")

    def run_cli(self, ctx: ScriptContext, args: argparse.Namespace) -> CliResult:
        """
        ``cn diff DEVICE... [--since WHEN] [--line TEXT]``: the configuration lines added or removed
        on each device between two of its snapshots, each attributed to the snapshot that made the change.

        Without ``--since`` the window is the last change (the previous snapshot to the newest);
        with ``--since`` it starts at the newest snapshot at or before WHEN; with ``--line`` and no
        ``--since`` it starts at the oldest. See ``utils.config_history`` for the rules.

        Sections (every key is always present): ``compared`` (``device``, ``from_snapshot``,
        ``from_time``, ``to_snapshot``, ``to_time``, ``steps``), ``changes`` (``device``, ``change``,
        ``parent``, ``line``, ``snapshot``, ``author``, ``time``), ``not_found`` (``object``,
        ``reason``: a device without a cfg file, with nothing to compare or without a change) and
        ``warnings`` (``object``, ``warning``: a repository or file that could not be read, or a
        ``--since`` before the history). Never prompts.

        Exit status: 0 with at least one row in ``changes``, 1 without (see ``not_found``), 2 for
        unusable input or setup, 3 when a repository, history folder or snapshot could not be read.
        """
        ctx.logger.info("Request Type - Config Diff (command line)")
        since: Optional[Since] = args.since
        text: Optional[str] = args.line

        try:
            devices = read_objects(args.objects, args.file)
        except OSError as exc:
            ctx.console.print(f"Cannot read the list of devices: {exc}", markup=False)
            return CliResult(2, {})
        if not devices:
            ctx.console.print("Give at least one device name, or a --file listing them.", markup=False)
            return CliResult(2, {})

        try:
            from config_analyzer.utils import collect_snapshots, find_device_history, locate_device_config
        except ImportError as exc:
            _report_missing_dependency(ctx, exc)
            return CliResult(2, {})

        roots, inaccessible = configured_repo_roots(ctx)
        if not roots and not inaccessible:
            ctx.console.print(
                "No configuration repository directory is configured: "
                "set [config_analyzer] repo_directories or [config_repo] directory.",
                markup=False,
            )
            return CliResult(2, {})

        history_dir = str(ctx.cfg.get("config_repo_history_dir", "history"))
        root_paths = [root for root, _label in roots]
        now = _utcnow()
        compared: List[Dict[str, Any]] = []
        changes: List[Dict[str, Any]] = []
        not_found: List[Dict[str, str]] = []
        warnings = [
            {"object": str(path), "warning": f"{path}: configuration repository not accessible"}
            for path in inaccessible
        ]
        failed = bool(inaccessible)

        for device in sorted(devices):
            cfg_path, root = locate_device_config(root_paths, device, history_dir)
            if cfg_path is None:
                not_found.append({"object": device, "reason": f"no {device}.cfg in the configuration repositories"})
                continue

            # A snapshot that cannot be read is dropped by collect_snapshots and would shift the attribution.
            unreadable = _unreadable(cfg_path, find_device_history(root, device, cfg_path, history_dir))
            if unreadable:
                failed = True
                warnings.extend({"object": device, "warning": f"{path}: not readable"} for path in unreadable)
                continue

            snapshots = collect_snapshots(root, device, cfg_path, history_dir)
            if not snapshots:
                not_found.append({"object": device, "reason": f"no snapshots of {device}"})
                continue
            if len(snapshots) == 1:
                reason = f"only one snapshot ({snapshots[0].original_filename}); nothing to compare"
                not_found.append({"object": device, "reason": reason})
                continue

            try:
                window = select_window(snapshots, since, now, whole_history=since is None and text is not None)
            except ValueError as exc:
                not_found.append({"object": device, "reason": str(exc)})
                continue
            if window.warning:
                warnings.append({"object": device, "warning": window.warning})
            if since is not None and len(window.steps) == 1:  # WHEN is not before the newest snapshot
                newest = window.end
                reason = (
                    f"no change since {since_label(since, now)}: the newest snapshot is "
                    f"{newest.original_filename} ({format_time(newest.timestamp)})"
                )
                not_found.append({"object": device, "reason": reason})
                continue

            compared.append(
                {
                    "device": device,
                    "from_snapshot": window.start.original_filename,
                    "from_time": format_time(window.start.timestamp),
                    "to_snapshot": window.end.original_filename,
                    "to_time": format_time(window.end.timestamp),
                    "steps": len(window.steps) - 1,
                }
            )
            rows = changed_lines(window)
            if text is not None:
                rows = [row for row in rows if text.lower() in row["line"].lower()]
            if rows:
                changes.extend({"device": device, **row} for row in rows)
            else:
                not_found.append({"object": device, "reason": _unchanged_reason(window, since, text)})

        data = {"compared": compared, "changes": changes, "not_found": not_found, "warnings": warnings}
        return CliResult(cli_exit_code(found=bool(changes), invalid=False, failed=failed), data)
