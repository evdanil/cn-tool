import os
from pathlib import Path
from typing import List, Optional, Sequence, Union

from textual.app import App
from textual.reactive import reactive

from .repo_browser import BrowserScreen
from .tui import SnapshotScreen
from .utils import collect_snapshots, locate_device_config
from .version import __version__


class ConfigAnalyzerApp(App):
    """The configuration analyzer: the repository browser, and the snapshots of a device on top of it.

    The App owns what the two screens share and what happens between them:

    - ``layout`` is the panel layout preference (``right``, ``bottom``, ``left`` or ``top``). Both
      screens read it when they are composed and when they are shown again, and Ctrl+L writes it
      back, so a layout chosen in one view is the layout of the other.
    - A device opened in the browser (``BrowserScreen.DeviceSelected``) has its snapshots pushed as a
      ``SnapshotScreen``. Esc there (``SnapshotScreen.Closed``) pops it and reveals the browser
      exactly as it was left: filter, cursor, preview and scroll. Quitting from either screen ends
      the app: Ctrl+Q does, and so do ``BrowserScreen.Closed`` (the browser is the root screen) and
      ``SnapshotScreen.Closed(back=False)``. The screens only ask; the app exits.
    - ``device`` opens that device's snapshots straight away, with the browser beneath (on the
      device's folder, for when Esc comes).
    - A device that cannot be opened is reported by a notification and the screen stays as it is.
    """

    TITLE = "ConfigAnalyzer"
    SUB_TITLE = f"v{__version__}"

    layout = reactive("right")

    def __init__(
        self,
        repo_roots: Sequence[Union[str, os.PathLike]],
        *,
        repo_names: Sequence[str] = (),
        history_dir: str = "history",
        layout: str = "right",
        scroll_to_end: bool = False,
        device: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.repo_roots: List[str] = [os.path.abspath(os.fspath(root)) for root in repo_roots]
        if not self.repo_roots:
            raise ValueError("At least one repository path must be provided to the config analyzer")
        self.repo_names: List[str] = list(repo_names)
        self.history_dir = history_dir
        self.scroll_to_end = scroll_to_end
        self.device = device
        self.layout = layout

    async def on_mount(self) -> None:
        cfg_path: Optional[str] = None
        repo_root: Optional[str] = None
        if self.device:
            # The browser starts in the device's folder, so Esc from its snapshots lands on the device.
            cfg_path, repo_root = locate_device_config(self.repo_roots, self.device, self.history_dir)
        await self.push_screen(
            BrowserScreen(
                self.repo_roots,
                scroll_to_end=self.scroll_to_end,
                start_path=cfg_path,
                history_dir=self.history_dir,
                repo_names=self.repo_names,
            )
        )
        if self.device:
            self._show_snapshots(self.device, cfg_path, repo_root)

    def open_device(
        self, name: str, cfg_path: Optional[str] = None, repo_root: Optional[str] = None
    ) -> bool:
        """Push the snapshots of device ``name`` on top of the browser; False when there is nothing to show.

        ``repo_root`` and ``cfg_path`` are what the browser knows about the device. Without a usable
        root (not given, and ``cfg_path`` is in none of the repositories) the device is looked up by name
        in every repository. A device that is not found, or has no readable snapshot, is reported by a
        notification. Only the browser opens devices: a second request while snapshots are shown (a
        double Enter queues two) is ignored.
        """
        if not isinstance(self.screen, BrowserScreen):
            return False
        repo_root = repo_root or self._repository_of(cfg_path)
        if repo_root is None:
            cfg_path, repo_root = locate_device_config(self.repo_roots, name, self.history_dir)
        return self._show_snapshots(name, cfg_path, repo_root)

    def _repository_of(self, path: Optional[str]) -> Optional[str]:
        """The repository root that contains ``path``, if any."""
        if not path:
            return None
        resolved = Path(os.path.abspath(path))
        return next((root for root in self.repo_roots if resolved.is_relative_to(root)), None)

    def _show_snapshots(self, name: str, cfg_path: Optional[str], repo_root: Optional[str]) -> bool:
        # Device names come from file names: shown as typed, never read as markup.
        if repo_root is None:
            self.notify(
                f"Unable to locate configuration repository for device '{name}'.", severity="error", markup=False
            )
            return False
        snapshots = collect_snapshots(repo_root, name, cfg_path, self.history_dir)
        if not snapshots:
            self.notify(
                f"No snapshots or current config found for device '{name}'.", severity="warning", markup=False
            )
            return False
        self.push_screen(SnapshotScreen(snapshots, scroll_to_end=self.scroll_to_end))
        return True

    def on_browser_screen_device_selected(self, message: BrowserScreen.DeviceSelected) -> None:
        message.stop()
        self.open_device(message.name, message.cfg_path, message.repo_root)

    def on_browser_screen_closed(self, message: BrowserScreen.Closed) -> None:
        message.stop()
        self.exit()  # the browser is the root screen: there is nothing under it to go back to

    async def on_snapshot_screen_closed(self, message: SnapshotScreen.Closed) -> None:
        message.stop()
        if not message.back:
            self.exit()
        elif isinstance(self.screen, SnapshotScreen):  # a double Esc queues two; the second finds the browser
            await self.pop_screen()
