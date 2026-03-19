import os
from typing import List, Optional, Tuple, Set

import click
from rich.console import Console

from .utils import find_device_history, collect_snapshots
from .debug import get_logger
from .tui import CommitSelectorApp
from .repo_browser import RepoBrowserApp

@click.command()
@click.option(
    '--repo-path',
    'repo_paths',
    required=True,
    multiple=True,
    type=click.Path(exists=True, file_okay=False, resolve_path=True),
    help="Path to a configuration repository. Repeat the option to aggregate multiple roots."
)
@click.option(
    '--repo-label',
    'repo_labels',
    multiple=True,
    help="Optional display name for a --repo-path entry (repeat in the same order)."
)
@click.option(
    '--device',
    required=False,
    default=None,
    help="Optional device name (without .cfg). If provided, opens its snapshot view."
)
@click.option(
    '--scroll-to-end',
    is_flag=True,
    default=False,
    help="Automatically scroll to the end of the diff view on load.",
    show_default=True,
)
@click.option(
    '--layout',
    type=click.Choice(['right', 'left', 'bottom', 'top'], case_sensitive=False),
    default='right',
    help="Position of the diff panel relative to the commit list.",
    show_default=True,
)
@click.option(
    '--history-dir',
    default='history',
    show_default=True,
    help="Folder name that contains device history (e.g. 'history').",
)
@click.option(
    '--debug',
    is_flag=True,
    default=False,
    help='Enable verbose debug logging to tui_debug.log',
    show_default=True,
)
def main(repo_paths, repo_labels, device, scroll_to_end, layout, history_dir, debug):
    """
    An interactive tool to analyze network device configuration changes.
    """
    console = Console()
    log = get_logger("main")

    raw_repo_labels = [str(label).strip() for label in repo_labels]
    repo_roots: List[str] = []
    repo_label_overrides: List[str] = []
    seen: Set[str] = set()
    for index, path in enumerate(repo_paths):
        abs_path = os.path.abspath(path)
        label = raw_repo_labels[index] if index < len(raw_repo_labels) else ""
        if abs_path in seen:
            continue
        repo_roots.append(abs_path)
        repo_label_overrides.append(label)
        seen.add(abs_path)
    if not repo_roots:
        raise click.UsageError("At least one --repo-path value is required")

    if debug:
        os.environ['CONFIG_ANALYZER_DEBUG'] = '1'
        console.print('[dim]Debug logging enabled -> tui_debug.log[/dim]')
    log.debug(
        "start: repos=%s labels=%s device=%s layout=%s history_dir=%s scroll_to_end=%s",
        repo_roots,
        repo_label_overrides,
        device,
        layout,
        history_dir,
        scroll_to_end,
    )
    # Helper: resolve device snapshots directory under history (prefer nearest to selected cfg path)
    history_dir_l = history_dir.lower()

    def _resolve_repo_root(path: Optional[str]) -> Optional[str]:
        if not path:
            return None
        abs_path = os.path.abspath(path)
        for root in repo_roots:
            if abs_path == root or abs_path.startswith(root + os.sep):
                return root
        return None

    def _locate_device_config(device_name: str) -> Tuple[Optional[str], Optional[str]]:
        target = f"{device_name}.cfg"
        for root in repo_roots:
            for walk_root, dirs, files in os.walk(root):
                dirs[:] = [d for d in dirs if d.lower() != history_dir_l]
                if target in files:
                    return os.path.join(walk_root, target), root
        return None, None

    # Persist layout preference across views
    layout_pref = layout

    # Loop to allow returning to the device browser from snapshot view
    selected_cfg_path = None
    selected_repo_root: Optional[str] = None
    while True:
        # If no device specified or user requested back, launch the browser
        if not device:
            try:
                console.clear()
            except Exception:
                pass
            browser = RepoBrowserApp(
                repo_roots,
                scroll_to_end=scroll_to_end,
                start_path=selected_cfg_path,
                start_layout=layout_pref,
                history_dir=history_dir,
                repo_names=repo_label_overrides,
            )
            browser.run()
            if not getattr(browser, 'selected_device_name', None):
                return
            device = browser.selected_device_name
            selected_cfg_path = getattr(browser, 'selected_device_cfg_path', None)
            selected_repo_root = getattr(browser, 'selected_repo_root', None) or _resolve_repo_root(selected_cfg_path)
            layout_pref = getattr(browser, 'layout', layout_pref)
            log.debug(
                "browser: selected device=%s cfg=%s repo=%s layout=%s",
                device,
                selected_cfg_path,
                selected_repo_root,
                layout_pref,
            )

        repo_root_for_device = selected_repo_root or _resolve_repo_root(selected_cfg_path)
        if not repo_root_for_device:
            selected_cfg_path, repo_root_for_device = _locate_device_config(device)
            if selected_cfg_path:
                selected_repo_root = repo_root_for_device
        if not repo_root_for_device:
            console.print(f"[bold red]Error:[/bold red] Unable to locate repository root for device '{device}'.")
            return

        selected_repo_root = repo_root_for_device

        device_history_path = find_device_history(repo_root_for_device, device, selected_cfg_path, history_dir)
        if not device_history_path:
            console.print(f"[bold yellow]Note:[/bold yellow] No history folder found for device '{device}'. Proceeding with current config only if present.")
        else:
            log.debug("history_dir=%s", device_history_path)

        # Find current device config outside of any 'history' folder
        current_config_path = None
        if selected_cfg_path:
            current_config_path = selected_cfg_path
        else:
            for root, dirs, files in os.walk(repo_root_for_device):
                # prune any history directories from traversal
                dirs[:] = [d for d in dirs if d.lower() != history_dir_l]
                if f"{device}.cfg" in files:
                    current_config_path = os.path.join(root, f"{device}.cfg")
                    break

        # Parse and collect snapshots (dedupes Current if identical to latest)
        with console.status("[cyan]Parsing configuration snapshots...[/cyan]"):
            snapshots = collect_snapshots(repo_root_for_device, device, selected_cfg_path, history_dir)

        if not snapshots:
            console.print(f"[bold yellow]Warning:[/bold yellow] No configuration snapshots or current config found for device '{device}'.")
            return

        # Warn if fewer than 2, but still launch the UI to allow preview
        if len(snapshots) < 2:
            console.print("[bold yellow]Note:[/bold yellow] Fewer than two items available; select two to see a diff when more are present.")

        try:
            try:
                console.clear()
            except Exception:
                pass
            app = CommitSelectorApp(
                snapshots_data=snapshots,
                scroll_to_end=scroll_to_end,
                layout=layout_pref,
            )
            app.run()

        except Exception as e:
            console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}")
            return

        # Save layout preference, then handle navigation
        layout_pref = getattr(app, 'layout', layout_pref)
        log.debug("snapshot_view_done: layout=%s navigate_back=%s", layout_pref, getattr(app, 'navigate_back', False))
        # If user requested to go back, reset device to reopen the browser
        if getattr(app, 'navigate_back', False):
            # Reopen browser at the directory of current config if available
            device = None
            selected_cfg_path = current_config_path
            selected_repo_root = repo_root_for_device if current_config_path else None
            continue
        break

if __name__ == "__main__":
    main()





