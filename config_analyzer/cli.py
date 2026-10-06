import os
from typing import List, Set

import click
from rich.console import Console
from rich.markup import escape

from .app import ConfigAnalyzerApp
from .debug import get_logger


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
    app = ConfigAnalyzerApp(
        repo_roots,
        repo_names=repo_label_overrides,
        history_dir=history_dir,
        layout=layout,
        scroll_to_end=scroll_to_end,
        device=device,
    )
    try:
        app.run()
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred:[/bold red] {escape(str(e))}")


if __name__ == "__main__":
    main()
