import os
from typing import Dict, List, Optional, Tuple, Sequence, Union, Set

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static
from textual.containers import Horizontal, Vertical, Container
from textual.binding import Binding
from textual import events
import os
from textual.timer import Timer
from rich.console import Console, Group, RenderableType
from io import StringIO

from .parser import parse_snapshot, parse_snapshot_meta
from .formatting import format_timestamp
from .filter_mixin import FilterMixin
from .keymap import browser_bindings
from .tips import browser_tips
from .debug import get_logger
from .version import __version__
from .search import SearchController
from .widgets import SearchableTextPane

class BrowserDataTable(DataTable):
    BINDINGS = [
        Binding("home", "goto_first_row", "First", show=False),
        Binding("end", "goto_last_row", "Last", show=False),
        Binding("backspace", "filter_backspace", "", show=False),
        Binding("ctrl+h", "filter_backspace", "", show=False),
        Binding("left", "go_up", "Up", show=True),
        Binding("alt+up", "go_up", "Up", show=False),
        Binding("right", "enter_selected", "Open", show=True),
    ]
    
    def action_goto_first_row(self) -> None:
        try:
            if self.row_count:
                self.cursor_coordinate = (0, 0)
                self._notify_viewport_change()
        except Exception:
            pass
        
    def action_goto_last_row(self) -> None:
        try:
            rc = self.row_count
            if rc:
                self.cursor_coordinate = (rc - 1, 0)
                self._notify_viewport_change()
        except Exception:
            pass

    def _notify_viewport_change(self) -> None:
        try:
            hydrate = getattr(self.app, "_hydrate_viewport", None)
            if hydrate:
                center = getattr(self, "cursor_row", 0) or 0
                hydrate(center_row=center)
        except Exception:
            pass

    async def on_event(self, event: events.Event) -> Optional[bool]:  # type: ignore[override]
        try:
            handled = await super().on_event(event)
        except Exception:
            return None
        scroll_types = tuple(
            t
            for t in (
                getattr(events, "MouseScrollUp", None),
                getattr(events, "MouseScrollDown", None),
                getattr(events, "MouseScrollLeft", None),
                getattr(events, "MouseScrollRight", None),
            )
            if t is not None
        )
        if scroll_types and isinstance(event, scroll_types):
            self._notify_viewport_change()
        return handled

    def on_key(self, event: events.Key) -> None:  # type: ignore
        """Delegate filter keys to the App-level mixin; consume if handled.

        Handling at the widget level ensures Backspace works reliably
        since Textual delivers keys to the focused widget first.
        """
        try:
            handler = getattr(self.app, "process_filter_key", None)
            if handler and handler(event, require_table_focus=False):
                try:
                    event.stop()
                except Exception:
                    pass
                return
        except Exception:
            pass
        # Not handled by filter -> allow normal bindings/defaults to run
        try:
            super().on_key(event)
        except Exception:
            pass
        self._notify_viewport_change()

    def action_filter_backspace(self) -> None:
        try:
            fb = getattr(self.app, "filter_backspace", None)
            if fb:
                fb()
        except Exception:
            pass

    def action_go_up(self) -> None:
        try:
            self.app.action_go_up()  # type: ignore[attr-defined]
        except Exception:
            pass

    def action_enter_selected(self) -> None:
        try:
            self.app.action_enter_selected()  # type: ignore[attr-defined]
        except Exception:
            pass

class PreviewPane(SearchableTextPane):
    """Preview pane backed by :class:`SearchableTextPane` with key handling tweaks."""

    BINDINGS = [
        Binding("ctrl+f", "start_find", "Find"),
        Binding("up", "scroll_up", "Scroll Up", show=False),
        Binding("down", "scroll_down", "Scroll Down", show=False),
        Binding("pageup", "page_up", "Page Up", show=False),
        Binding("pagedown", "page_down", "Page Down", show=False),
        Binding("space", "page_down", "Page Down", show=False),
        Binding("home", "go_home", "Go Home", show=False),
        Binding("end", "go_end", "Go End", show=False),
    ]

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        wrap: bool = False,
        highlight: bool = False,
        auto_scroll: bool = False,
    ) -> None:
        # ``highlight`` is accepted for backward compatibility with the
        # previous RichLog implementation; SearchableTextPane doesn't use it.
        del highlight
        super().__init__(id=id, wrap=wrap)
        self._auto_scroll = auto_scroll

    def action_start_find(self) -> None:
        try:
            self.app.action_start_find_preview()  # type: ignore[attr-defined]
        except Exception:
            pass

    def _auto_scroll_if_needed(self) -> None:
        if not self._auto_scroll:
            return

        def _scroll() -> None:
            try:
                self.action_go_end()
            except Exception:
                pass

        try:
            self.call_after_refresh(_scroll)
        except Exception:
            _scroll()

    def set_renderable(self, renderable: RenderableType, *, base_text: Optional["Text"] = None, raw_text: Optional[str] = None) -> None:  # type: ignore[override]
        super().set_renderable(renderable, base_text=base_text, raw_text=raw_text)
        self._auto_scroll_if_needed()

    def set_text(self, text: str) -> None:  # type: ignore[override]
        super().set_text(text)
        self._auto_scroll_if_needed()

    def on_key(self, event: events.Key) -> None:  # type: ignore[override]
        # Handle search mode keys
        from .utils import handle_search_key

        app = getattr(self, "app", None)
        if app is not None and getattr(app, "_search_target", "") == "preview":
            if handle_search_key(app, event, "preview"):
                return

        super().on_key(event)

class RepoBrowserApp(FilterMixin, App):
    TITLE = "ConfigAnalyzer"
    SUB_TITLE = f"v{__version__} - Device Browser"
    FILTER_DEBOUNCE_SECONDS = 0.35
    CONFIG_EXTS: Tuple[str, ...] = (".cfg", ".yml", ".yaml")
    MAX_PREVIEW_BYTES: int = 2_000_000  # 2 MB cap to avoid TUI stall on huge files
    """Simple repository browser.

    - Lists folders (excluding any named 'history').
    - Lists .cfg files as devices in the current folder.
    - Shows user (author) and timestamp if available.
    - Previews device configuration on selection.
    - Enter to open; Left/Alt+Up to go up.
    """

    CSS = """
    /* Default split for horizontal layouts */
    #left { width: 48%; }
    #right { width: 52%; }

    /* Borders indicate split orientation */
    .layout-right #right { border-left: solid steelblue; }
    .layout-right #right:focus-within { border-left: thick yellow; }
    .layout-left #right { border-right: solid steelblue; }
    .layout-left #right:focus-within { border-right: thick yellow; }
    .layout-bottom #right { border-top: solid steelblue; }
    .layout-bottom #right:focus-within { border-top: thick yellow; }
    .layout-top #right { border-bottom: solid steelblue; }
    .layout-top #right:focus-within { border-bottom: thick yellow; }

    /* Ensure vertical layouts split available height and width evenly. Allow preview to scroll. */
    .layout-bottom #left { height: 1fr; width: 1fr; }
    .layout-bottom #right { height: 1fr; width: 1fr; overflow: auto; }
    .layout-top #left { height: 1fr; width: 1fr; }
    .layout-top #right { height: 1fr; width: 1fr; overflow: auto; }

    /* Ensure main panel expands to fill space so vertical split uses full height */
    #browser-main { height: 1fr; width: 1fr; }
    """

    BINDINGS = browser_bindings() + [
        Binding("up", "pane_up", "", show=False),
        Binding("down", "pane_down", "", show=False),
        Binding("pageup", "pane_page_up", "", show=False),
        Binding("pagedown", "pane_page_down", "", show=False),
        Binding("home", "pane_home", "", show=False),
        Binding("end", "pane_end", "", show=False),
        Binding("space", "pane_page_down", "", show=False),
        Binding("j", "pane_down", "", show=False),
        Binding("k", "pane_up", "", show=False),
        # Arrow key bindings for search navigation (handled in on_key when in search mode)
        # No explicit bindings needed as they're handled dynamically
    ]

    def __init__(self, repo_paths: Union[str, Sequence[str]], scroll_to_end: bool = False, start_path: Optional[str] = None, start_layout: Optional[str] = None, history_dir: str = 'history', repo_names: Optional[Sequence[str]] = None):
        super().__init__()
        self.logr = get_logger("browser")
        self._debug_keys = bool(os.environ.get("CN_TUI_DEBUG_KEYS"))

        if isinstance(repo_paths, (str, os.PathLike)):
            raw_paths = [str(repo_paths)]
        else:
            raw_paths = [str(p) for p in repo_paths]
        if not raw_paths:
            raise ValueError("At least one repository path must be provided to RepoBrowserApp")

        normalized: List[str] = []
        seen: Set[str] = set()
        for path in raw_paths:
            abs_path = os.path.abspath(path)
            if abs_path not in seen:
                normalized.append(abs_path)
                seen.add(abs_path)

        self.repo_roots = normalized
        self._is_multi_root = len(self.repo_roots) > 1
        self.repo_labels = self._build_repo_labels(self.repo_roots, repo_names)

        self.current_root: Optional[str] = None
        self.current_rel: str = ""
        self.current_path: Optional[str] = None
        self.selected_device_name: Optional[str] = None
        self.selected_device_cfg_path: Optional[str] = None
        self.selected_repo_root: Optional[str] = None
        self.scroll_to_end = scroll_to_end
        self.start_path = os.path.abspath(start_path) if start_path else None
        self.layout = start_layout or 'right'
        self.history_dir_l = history_dir.lower()
        self._start_highlight_file: Optional[str] = None
        if self.start_path and os.path.isfile(self.start_path):
            self._start_highlight_file = self.start_path
            self.start_path = os.path.dirname(self.start_path)
        # Track last directory to highlight when going up
        self._highlight_dir_name: Optional[str] = None
        # Metadata cache for files in current directory (path -> (author, ts_str))
        self._meta_cache: Dict[str, Tuple[str, str]] = {}
        self._pending_cursor_key: Optional[str] = None
        self._row_keys: List[str] = []
        self._entry_repo: Dict[str, str] = {}
        self._entry_types: Dict[str, str] = {}
        self._display_names: Dict[str, str] = {}
        self._filter_apply_timer: Optional[Timer] = None
        self.preview_fullscreen: bool = False
        self._last_preview_key: Optional[str] = None
        # Find-in-preview state
        self._search_target: str = ""  # 'preview' or ''
        self._preview_search: SearchController = SearchController()

    def _build_repo_labels(self, roots: Sequence[str], overrides: Optional[Sequence[str]] = None) -> Dict[str, str]:
        labels: Dict[str, str] = {}
        base_counts: Dict[str, int] = {}
        for root in roots:
            base = os.path.basename(root.rstrip(os.sep)) or root
            base_counts[base] = base_counts.get(base, 0) + 1

        for root in roots:
            base = os.path.basename(root.rstrip(os.sep)) or root
            if base_counts.get(base, 0) == 1:
                labels[root] = base
            else:
                parent = os.path.basename(os.path.dirname(root.rstrip(os.sep)))
                label = f"{parent}/{base}" if parent else base
                if label in labels.values():
                    label = root
                labels[root] = label

        if overrides:
            sanitized = [str(label).strip() for label in overrides]
            for idx, root in enumerate(roots):
                if idx >= len(sanitized):
                    break
                override = sanitized[idx]
                if override:
                    labels[root] = override

        return labels

    def _label_for_root(self, root: Optional[str]) -> str:
        if not root:
            return ""
        return self.repo_labels.get(root, os.path.basename(str(root).rstrip(os.sep)) or str(root))

    def compose(self) -> ComposeResult:
        yield Header()
        # Placeholders; actual widgets are built in _apply_layout
        self.table = BrowserDataTable(id="left")
        self.table.cursor_type = "row"
        self.preview = PreviewPane(id="right", wrap=False)
        self.preview.search = self._preview_search
        self.main_panel = Container(id="browser-main")
        yield self.main_panel
        # Tips/footer text is updated dynamically to show filter
        self.tips = Static("", id="tips")
        yield self.tips
        yield Footer()

    def on_descendant_focus(self, event: events.DescendantFocus) -> None:  # type: ignore
        """Update tips when focus changes between table and preview."""
        self._update_tips()

    def on_mount(self) -> None:
        self._setup_table()
        self._apply_layout()
        self._filter_text = ""
        self._all_entries: List[str] = []

        initial_root: Optional[str] = None
        initial_path: Optional[str] = None

        if self.start_path:
            candidate = self.start_path
            if os.path.isfile(candidate):
                candidate = os.path.dirname(candidate)
            if os.path.isdir(candidate):
                initial_root = self._determine_repo_root(candidate)
                if initial_root:
                    initial_path = candidate

        if initial_root is None:
            if self._is_multi_root:
                initial_root = None
                initial_path = None
            else:
                initial_root = self.repo_roots[0]
                initial_path = initial_root

        self._load_directory(initial_path, repo_root=initial_root)
        self.logr.debug(
            "mounted: root=%s path=%s multi=%s",
            self.current_root,
            self.current_path or "__multi__",
            self._is_multi_root,
        )

        def _focus_table() -> None:
            try:
                self.table.focus()
            except Exception:
                pass

        try:
            self.call_after_refresh(_focus_table)
        except Exception:
            _focus_table()

    def _determine_repo_root(self, path: Optional[str]) -> Optional[str]:
        if not path:
            return None
        try:
            abs_path = os.path.realpath(path)
        except Exception:
            return None
        for root in self.repo_roots:
            r = os.path.realpath(root)
            if abs_path == r or abs_path.startswith(r + os.sep):
                return root
        return None

    def _register_entry(self, path: str, display_name: str, entry_type: str, repo_root: str) -> None:
        if path in self._entry_types:
            self.logr.debug("register_entry: duplicate path=%s existing_type=%s new_type=%s", path, self._entry_types[path], entry_type)
            return
        self._all_entries.append(path)
        self._entry_types[path] = entry_type
        self._display_names[path] = display_name
        self._entry_repo[path] = repo_root

    def _populate_single_repo_entries(self, repo_root: str, directory: str) -> None:
        try:
            entries = sorted(os.listdir(directory), key=str.lower)
        except OSError as e:
            self.preview.set_text(f"Error reading directory: {e}")
            return

        dirs: List[Tuple[str, str]] = []
        files: List[Tuple[str, str]] = []
        for name in entries:
            full = os.path.join(directory, name)
            if os.path.isdir(full):
                if name.lower() == self.history_dir_l:
                    continue
                dirs.append((name, full))
            elif os.path.isfile(full) and name.lower().endswith(self.CONFIG_EXTS):
                files.append((name, full))

        for name, full in dirs:
            self._register_entry(full, name, "dir", repo_root)
        for name, full in files:
            self._register_entry(full, name, "dev", repo_root)

    def _populate_multi_root_entries(self) -> None:
        ordered_dirs: List[Tuple[str, str, str, str, str]] = []  # (label_l, name_l, name, full, root)
        ordered_files: List[Tuple[str, str, str, str, str]] = []
        # Sort primary by repo label (alphabetical), then by entry name
        seen_paths: Set[str] = set()

        for root in self.repo_roots:
            try:
                entries = sorted(os.listdir(root), key=str.lower)
            except OSError as e:
                self.logr.debug("listdir failed for %s: %s", root, e)
                continue
            label = self._label_for_root(root)
            label_l = (label or "").lower()
            self.logr.debug("populate_multi_root: root=%s label=%s entries=%s", root, label, len(entries))
            for name in entries:
                full = os.path.join(root, name)
                if full in seen_paths:
                    continue
                if os.path.isdir(full):
                    if name.lower() == self.history_dir_l:
                        continue
                    seen_paths.add(full)
                    ordered_dirs.append((label_l, name.lower(), name, full, root))
                elif os.path.isfile(full) and name.lower().endswith(self.CONFIG_EXTS):
                    seen_paths.add(full)
                    ordered_files.append((label_l, name.lower(), name, full, root))

        ordered_dirs.sort(key=lambda item: (item[0], item[1]))
        ordered_files.sort(key=lambda item: (item[0], item[1]))

        for _, _, name, full, root in ordered_dirs:
            self._register_entry(full, name, "dir", root)
        for _, _, name, full, root in ordered_files:
            self._register_entry(full, name, "dev", root)
        self.logr.debug("populate_multi_root: total entries=%s", len(self._all_entries))

    def _current_directory_label(self) -> str:
        if self.current_root is None and self._is_multi_root:
            return "All repositories"
        if self.current_root:
            label = self._label_for_root(self.current_root)
            if self.current_rel:
                return f"{label} / {self.current_rel}"
            return label
        if self.current_path:
            return self.current_path
        return ""

    def _apply_layout(self) -> None:
        """Rebuild widgets and mount according to current layout.

        Recreating widgets avoids Textual reparenting quirks that can drop
        content render state when switching containers immediately after start.
        """
        try:
            for child in list(self.main_panel.children):
                child.remove()
        except Exception:
            pass

        # Fresh widgets each time
        if getattr(self, "preview_fullscreen", False):
            self.preview = PreviewPane(id="preview_full", wrap=False, highlight=False, auto_scroll=self.scroll_to_end)
            # Ensure full width/height in fullscreen
            try:
                self.preview.styles.width = "100%"
                self.preview.styles.height = "1fr"
            except Exception:
                pass
        else:
            self.preview = PreviewPane(id="right", wrap=False, highlight=False, auto_scroll=self.scroll_to_end)
        self.preview.search = self._preview_search
        # Attach search controller to pane
        # RichLog doesn't attach search state; App manages it
        self.table = BrowserDataTable(id="left")
        self.table.cursor_type = "row"

        # Orientation or fullscreen preview
        if getattr(self, "preview_fullscreen", False):
            # Mount only the preview in fullscreen mode
            self.main_panel.mount(Container(self.preview))
        else:
            if self.layout in ("right", "left"):
                ordered = (self.preview, self.table) if self.layout == "left" else (self.table, self.preview)
                container = Horizontal(*ordered, classes=f"layout-{self.layout}")
            else:
                ordered = (self.preview, self.table) if self.layout == "top" else (self.table, self.preview)
                container = Vertical(*ordered, classes=f"layout-{self.layout}")
            self.main_panel.mount(container)

        # Columns for the fresh table
        self._setup_table()
        # Refresh tips line
        self._update_tips()
        if self._last_preview_key:
            try:
                self._update_preview(self._last_preview_key)
            except Exception:
                pass

    def _setup_table(self) -> None:
        t = self.table
        try:
            t.clear(columns=True)
        except TypeError:
            t.clear()
            try:
                t.columns.clear()  # type: ignore[attr-defined]
            except Exception:
                pass
        t.add_column("Type", key="type", width=6)
        t.add_column("Name", key="name")
        t.add_column("Repo", key="repo", width=18)
        t.add_column("User", key="user", width=16)
        t.add_column("Timestamp", key="timestamp")
        self._row_keys = []

    def _load_directory(self, path: Optional[str], repo_root: Optional[str] = None) -> None:
        if repo_root is None:
            repo_root = self._determine_repo_root(path)
        if repo_root is None and not self._is_multi_root:
            repo_root = self.repo_roots[0]

        resolved_path: Optional[str] = None
        if path:
            resolved_path = os.path.abspath(path)

        if repo_root:
            repo_root = os.path.abspath(repo_root)
            if resolved_path is None:
                resolved_path = repo_root
            elif not (resolved_path == repo_root or resolved_path.startswith(repo_root + os.sep)):
                resolved_path = repo_root
        else:
            resolved_path = None

        if repo_root is None:
            if self._is_multi_root:
                self.current_root = None
                self.current_rel = ""
                self.current_path = None
            else:
                root = self.repo_roots[0]
                self.current_root = root
                self.current_rel = ""
                self.current_path = root
        else:
            self.current_root = repo_root
            if resolved_path:
                rel = os.path.relpath(resolved_path, repo_root)
                self.current_rel = "" if rel == "." else rel
                self.current_path = resolved_path
            else:
                self.current_rel = ""
                self.current_path = repo_root

        self.logr.debug("load_directory: root=%s path=%s", self.current_root, self.current_path or "__multi__")

        self._filter_text = ""
        self._cancel_filter_timer()
        try:
            self.table.clear()
        except Exception:
            pass
        self.preview.clear()

        self._all_entries = []
        self._entry_repo = {}
        self._entry_types = {}
        self._display_names = {}

        if self.current_root is None:
            if self._is_multi_root:
                self._populate_multi_root_entries()
            else:
                root = self.repo_roots[0]
                self._populate_single_repo_entries(root, root)
        else:
            target_dir = self.current_path or self.current_root
            self._populate_single_repo_entries(self.current_root, target_dir)

        pending_key: Optional[str] = None
        if self._start_highlight_file and self._start_highlight_file in self._all_entries:
            pending_key = self._start_highlight_file
        elif self._highlight_dir_name:
            matches = [p for p in self._all_entries if os.path.basename(p) == self._highlight_dir_name]
            if len(matches) == 1:
                pending_key = matches[0]
            elif len(matches) > 1:
                for cand in matches:
                    if self._entry_repo.get(cand) == self.current_root:
                        pending_key = cand
                        break
                if not pending_key and matches:
                    pending_key = matches[0]

        self._pending_cursor_key = pending_key
        self._render_entries()

        self._start_highlight_file = None
        self._highlight_dir_name = None

    def _syntax_to_text(self, content: str, lang: str) -> "Text":
        from rich.syntax import Syntax
        from rich.text import Text
        # Render Syntax to ANSI, then parse to Text to keep styles
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, color_system="truecolor", width=10_000)
        console.print(Syntax(content, lang, word_wrap=False, line_numbers=False))
        return Text.from_ansi(buf.getvalue())

    def _update_preview(self, key: str) -> None:
        """Populate the right pane for a given key (file or directory)."""
        self._last_preview_key = key
        self.preview.clear()

        # Directory previews render informational text only
        if key == "..":
            self.preview.set_text(
                f"Path: {self._current_directory_label()}\nEnter to navigate. Press Q to quit."
            )
            self._update_tips()
            return

        if os.path.isdir(key):
            repo_label = self._label_for_root(self._entry_repo.get(key))
            if repo_label:
                msg = f"Path: {key}\nRepository: {repo_label}\nEnter to navigate. Press Q to quit."
            else:
                msg = f"Path: {key}\nEnter to navigate. Press Q to quit."
            self.preview.set_text(msg)
            self._update_tips()
            return

        try:
            fsize = os.path.getsize(key)
        except OSError:
            fsize = 0

        from rich.syntax import Syntax
        from rich.text import Text

        def _render_syntax(content: str, note: Optional[str] = None) -> None:
            base_lang = "yaml" if key.lower().endswith((".yml", ".yaml")) else "ini"
            renderable: RenderableType = Syntax(content, base_lang, word_wrap=False, line_numbers=False)

            # Clear the preview and set lines for search
            self.preview.clear()
            self.preview._lines = content.splitlines()
            if self.preview.search:
                self.preview.search.set_lines(self.preview._lines)

            if note:
                note_text = Text(note, style="italic dim")
                renderable = Group(renderable, note_text)
                # Note is not searchable

            # Set the renderable and apply search
            self.preview._renderable = renderable
            self.preview._base_text = None
            self.preview.apply_search()

        if fsize and fsize > self.MAX_PREVIEW_BYTES:
            try:
                with open(key, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read(self.MAX_PREVIEW_BYTES)
                more = max(fsize - len(content), 0)
                note = f"\n-- truncated preview ({more} more bytes) --" if more else None
                _render_syntax(content, note=note)
                self._update_tips()
            except Exception as exc:
                self.preview.set_text(f"Error reading file: {exc}")
                self._update_tips()
            return

        snap = parse_snapshot(key)
        if snap:
            _render_syntax(snap.content_body)
            self._update_tips()
            return

        try:
            with open(key, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            _render_syntax(content)
            self._update_tips()
        except OSError as exc:
            self.preview.set_text(f"Error reading file: {exc}")
            self._update_tips()

    def _selected_row_key(self) -> Optional[str]:
        row = self.table.cursor_row
        if row is None or row < 0 or row >= len(self._row_keys):
            return None
        return self._row_keys[row]

    # -------- Filtering / Quick Search --------
    def _update_tips(self) -> None:
        filter_hint = self.get_filter_hint() or " | Filter: _"
        if self._search_target == 'preview' and self._preview_search.has_query():
            cnt = self._preview_search.counter_text()
            q = self._preview_search.query
            search_hint = f" | Find: '{q}' {cnt} (↓/Enter=next, ↑=prev, Esc=exit)"
        elif self._search_target == 'preview':
            search_hint = " | Find: _ (type to search, Esc=cancel)"
        else:
            search_hint = ""
        preview_focused = bool(getattr(self.preview, "has_focus", False))
        self.tips.update(browser_tips(filter_hint, search_hint, preview_focused))

    # ---- Find in preview ----
    def action_start_find_preview(self) -> None:
        self._search_target = 'preview'
        self._preview_search.reset()
        try:
            self.preview.apply_search()
        except Exception:
            pass
        self._update_tips()

    def action_find_backspace(self) -> None:
        if self._search_target != 'preview':
            return
        self._preview_search.backspace()
        try:
            self.preview.apply_search()
        except Exception:
            pass
        self._update_tips()

    def action_find_append_char(self, ch: str) -> None:
        if self._search_target != 'preview' or not ch:
            return
        self._preview_search.append_char(ch)
        try:
            self.preview.apply_search()
        except Exception:
            pass
        self._update_tips()

    def action_cancel_find(self) -> None:
        if self._search_target != 'preview':
            return
        self._search_target = ''
        self._preview_search.reset()
        try:
            self.preview.apply_search()
        except Exception:
            pass
        self._update_tips()

    def action_find_next(self) -> None:
        if self._search_target != 'preview' or not self._preview_search.has_query():
            return
        if not self._preview_search.next():
            return
        try:
            self.preview.apply_search()
            self.preview.scroll_match_into_view(center=True)
        except Exception:
            pass
        self._update_tips()

    def action_find_prev(self) -> None:
        if self._search_target != 'preview' or not self._preview_search.has_query():
            return
        if not self._preview_search.prev():
            return
        try:
            self.preview.apply_search()
            self.preview.scroll_match_into_view(center=True)
        except Exception:
            pass
        self._update_tips()

    def _render_entries(self) -> None:
        """Render current directory entries honoring the active filter while minimizing metadata reads."""
        previous_key = self._selected_row_key()
        if self._pending_cursor_key:
            selection_candidate = self._pending_cursor_key
            self._pending_cursor_key = None
        else:
            selection_candidate = previous_key

        if self._is_multi_root and self.current_root is None:
            selection_candidate = None

        ft = (self._filter_text or "").lower()
        is_global_root = self._is_multi_root and self.current_root is None
        at_repo_root = bool(self.current_root) and self.current_rel == ""

        self._setup_table()

        if not ft:
            if self._is_multi_root:
                if not is_global_root:
                    self.table.add_row("..", "..", "", "", "", key="..")
                    self._row_keys.append("..")
            elif not at_repo_root:
                self.table.add_row("..", "..", "", "", "", key="..")
                self._row_keys.append("..")

        filtered: List[str] = []
        if ft:
            for full in self._all_entries:
                display = self._display_names.get(full, os.path.basename(full))
                repo_label = self._label_for_root(self._entry_repo.get(full))
                candidates = [display.lower()]
                if repo_label:
                    candidates.append(repo_label.lower())
                if any(ft in val for val in candidates):
                    filtered.append(full)
                    continue
                if os.path.isdir(full):
                    continue
                author, ts, _ = self._get_metadata(full, eager=True)
                if ft in author.lower() or ft in ts.lower():
                    filtered.append(full)
        else:
            filtered = list(self._all_entries)

        visible_limit = self._visible_limit()
        tail_start = max(0, len(filtered) - visible_limit)
        selection_index: Optional[int] = None
        if selection_candidate and selection_candidate in filtered:
            try:
                selection_index = filtered.index(selection_candidate)
            except ValueError:
                selection_index = None

        for idx, full in enumerate(filtered):
            display = self._display_names.get(full, os.path.basename(full))
            entry_type = self._entry_types.get(full)
            if not entry_type:
                entry_type = "dir" if os.path.isdir(full) else "dev"

            repo_label = self._label_for_root(self._entry_repo.get(full))

            if entry_type == "dir":
                self.table.add_row("dir", display, repo_label, "", "", key=full)
                self._row_keys.append(full)
                continue

            eager = (
                idx < visible_limit
                or idx >= tail_start
                or (selection_candidate and full == selection_candidate)
            )
            if selection_index is not None and abs(idx - selection_index) <= visible_limit:
                eager = True
            author, ts, ready = self._get_metadata(full, eager=eager)
            self.table.add_row("dev", display, repo_label, author, ts, key=full)
            if not ready and eager:
                self._pending_cursor_key = full
            self._row_keys.append(full)

        self._update_tips()

        row_index: Optional[int] = None
        if selection_candidate and selection_candidate in self._row_keys:
            target_key = selection_candidate
        elif self._row_keys:
            first_index = 0
            if self._row_keys[0] == ".." and len(self._row_keys) > 1:
                first_index = 1
            target_key = self._row_keys[first_index]
        else:
            target_key = None

        if target_key:
            try:
                row_index = self._row_keys.index(target_key)
                self.table.cursor_coordinate = (row_index, 0)
            except Exception:
                pass

        try:
            current_cursor = self.table.cursor_row or 0
        except Exception:
            current_cursor = 0
        center_row = row_index if row_index is not None else current_cursor
        self._hydrate_viewport(center_row=center_row, buffer=max(visible_limit // 2, 0))

        key = self._selected_row_key()
        if key:
            self._update_preview(key)

        self.logr.debug("render_entries: rows=%s filter='%s'", self.table.row_count, ft)

    def _get_metadata(self, path: str, eager: bool) -> Tuple[str, str, bool]:
        if path in ("..",):
            return "", "", True
        if os.path.isdir(path):
            return "", "", True
        cached = self._meta_cache.get(path)
        if cached:
            return cached[0], cached[1], True
        if not os.path.isfile(path):
            return "", "", True
        if not eager:
            return "...", "...", False
        author, ts = self._load_metadata(path)
        return author, ts, True

    def _load_metadata(self, path: str) -> Tuple[str, str]:
        try:
            snap = parse_snapshot_meta(path)
        except Exception as exc:
            self.logr.debug("parse_snapshot_meta failed for %s: %s", path, exc)
            snap = None
        author = snap.author if snap else ""
        ts_str = format_timestamp(snap.timestamp) if snap and getattr(snap, "timestamp", None) else ""
        meta = (author, ts_str)
        self._meta_cache[path] = meta
        return meta

    def _visible_limit(self) -> int:
        try:
            size = getattr(self.table, "size", None)
            height = getattr(size, "height", 0) if size else 0
            if height:
                return max(int(height), 50)
        except Exception:
            pass
        return 100
    def _viewport_range(self, center_row: Optional[int] = None, buffer: int = 0) -> range:
        total_rows = len(getattr(self, "_row_keys", []))
        if total_rows <= 0:
            return range(0)
        visible = self._visible_limit()
        window = max(visible, 1)
        if buffer:
            window += max(buffer, 0)
        if center_row is None or center_row < 0:
            try:
                center_row = self.table.cursor_row or 0
            except Exception:
                center_row = 0
        center_row = max(0, min(center_row, total_rows - 1))
        start = max(center_row - window, 0)
        end = min(center_row + window + 1, total_rows)
        return range(start, end)

    def _hydrate_viewport(self, center_row: Optional[int] = None, buffer: int = 0) -> None:
        if not getattr(self, "_row_keys", None):
            return
        indices = self._viewport_range(center_row=center_row, buffer=buffer)
        pending: List[Tuple[str, str, str]] = []
        for idx in indices:
            try:
                key = self._row_keys[idx]
            except IndexError:
                continue
            if key == ".." or os.path.isdir(key) or key in self._meta_cache:
                continue
            author, ts = self._load_metadata(key)
            pending.append((key, author, ts))
        if not pending:
            return
        for key, author, ts in pending:
            try:
                self.table.update_cell(key, "user", author)
                self.table.update_cell(key, "timestamp", ts)
            except Exception:
                self._pending_cursor_key = key
                self._render_entries()
                return

    def _ensure_metadata_for_key(self, key: str) -> bool:
        if key in ("..",):
            return False
        if os.path.isdir(key):
            return False
        if key in self._meta_cache:
            return False
        author, ts = self._load_metadata(key)
        try:
            self.table.update_cell(key, "user", author)
            self.table.update_cell(key, "timestamp", ts)
        except Exception:
            self._pending_cursor_key = key
            self._render_entries()
            return True
        return False

    def on_key(self, event: events.Key) -> None:  # type: ignore
        if self._debug_keys:
            try:
                self.logr.debug(
                    "app.on_key(repo): key=%s focus=%s pane_focus=%s table_focus=%s",
                    getattr(event, 'key', None),
                    getattr(self.screen.focused, 'id', None),
                    getattr(self.preview, 'has_focus', None),
                    getattr(self.table, 'has_focus', None),
                )
            except Exception:
                pass
        # When in preview fullscreen, Escape should exit fullscreen
        if getattr(self, "preview_fullscreen", False) and event.key == "escape":
            self.preview_fullscreen = False
            # Try to preserve selection to the last previewed path
            if getattr(self, "_last_preview_key", None):
                self._pending_cursor_key = self._last_preview_key
            self._apply_layout()
            self._render_entries()
            try:
                self.table.focus()
            except Exception:
                pass
            try:
                event.stop()
            except Exception:
                pass
            return

        # Delegate to mixin; consume if handled
        if self.process_filter_key(event, require_table_focus=True):
            try:
                event.stop()
            except Exception:
                pass
            return

        # Fallback: route navigation keys to preview pane if it has focus
        if event.key in ("up", "down", "pageup", "pagedown", "home", "end"):
            try:
                if getattr(self.preview, "has_focus", False):
                    if self._debug_keys:
                        self.logr.debug("app.route_nav_to_preview: key=%s", event.key)
                    {
                        "up": getattr(self.preview, "action_scroll_up", None),
                        "down": getattr(self.preview, "action_scroll_down", None),
                        "pageup": getattr(self.preview, "action_page_up", None),
                        "pagedown": getattr(self.preview, "action_page_down", None),
                        "home": getattr(self.preview, "action_go_home", None),
                        "end": getattr(self.preview, "action_go_end", None),
                    }.get(event.key, None)()  # type: ignore[misc]
                    try:
                        event.stop()
                    except Exception:
                        pass
                    return
            except Exception:
                pass

    def action_quit(self) -> None:
        """Clear filter first when active; otherwise quit."""
        if self.filter_active():
            self.clear_filter()
            return
        self.exit()

    # App-level pane navigation actions (guaranteed routing)
    def action_pane_up(self) -> None:
        try:
            self.preview.action_scroll_up()
        except Exception:
            pass

    def action_pane_down(self) -> None:
        try:
            self.preview.action_scroll_down()
        except Exception:
            pass

    def action_pane_page_up(self) -> None:
        try:
            self.preview.action_page_up()
        except Exception:
            pass

    def action_pane_page_down(self) -> None:
        try:
            self.preview.action_page_down()
        except Exception:
            pass

    def action_pane_home(self) -> None:
        try:
            self.preview.action_go_home()
        except Exception:
            pass

    def action_pane_end(self) -> None:
        try:
            self.preview.action_go_end()
        except Exception:
            pass

    def action_clear_filter(self) -> None:
        self.clear_filter()

    def _on_filter_changed(self) -> None:
        self._update_tips()
        current_filter = getattr(self, "_filter_text", "")
        if not current_filter:
            self._cancel_filter_timer()
            self._render_entries()
            return
        self._schedule_filter_render()

    def _schedule_filter_render(self) -> None:
        self._cancel_filter_timer()
        try:
            self._filter_apply_timer = self.set_timer(
                self.FILTER_DEBOUNCE_SECONDS,
                self._apply_filter_now,
                name="repo-browser-filter",
            )
        except Exception:
            self._apply_filter_now()

    def _cancel_filter_timer(self) -> None:
        timer = getattr(self, "_filter_apply_timer", None)
        if not timer:
            return
        try:
            timer.stop()
        except Exception:
            pass
        self._filter_apply_timer = None

    def _apply_filter_now(self) -> None:
        self._filter_apply_timer = None
        self._update_tips()
        self._render_entries()

    def on_unmount(self) -> None:
        self._cancel_filter_timer()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:  # type: ignore
        # Update preview when selection changes
        key = self._selected_row_key()
        self.logr.debug("row_highlighted: %s", key)
        if not key:
            return
        if self._ensure_metadata_for_key(key):
            return
        try:
            cursor_row = self.table.cursor_row or 0
        except Exception:
            cursor_row = 0
        self._hydrate_viewport(center_row=cursor_row, buffer=max(self._visible_limit() // 2, 0))
        self._update_preview(key)

    def action_enter_selected(self) -> None:
        key = self._selected_row_key()
        self.logr.debug("enter_selected: %s", key)
        if not key:
            return
        if key == "..":
            self.action_go_up()
            return
        if os.path.isdir(key):
            repo_root = self._entry_repo.get(key) or self._determine_repo_root(key) or self.current_root
            self._highlight_dir_name = os.path.basename(key)
            self._load_directory(key, repo_root=repo_root)
        else:
            # Device file selected -> open history directly
            base = os.path.basename(key)
            lower = base.lower()
            if lower.endswith(".cfg"):
                self.selected_device_name = os.path.splitext(base)[0]
                self.selected_device_cfg_path = key
                self.selected_repo_root = self._entry_repo.get(key) or self._determine_repo_root(key) or self.current_root
                self.exit()
            elif lower.endswith((".yml", ".yaml")):
                # Fullscreen preview for YAML files
                self.preview_fullscreen = True
                self._apply_layout()
                self._update_preview(key)
                try:
                    self.preview.focus()
                except Exception:
                    pass

    # Ensure Enter on the DataTable triggers navigation even if the widget handles the key
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:  # type: ignore
        self.action_enter_selected()

    def action_go_up(self) -> None:
        if self.current_root is None:
            return
        if not self.current_path:
            if self._is_multi_root:
                self._highlight_dir_name = None
                self._load_directory(None)
            return
        # If already at repo root, jump straight to union (when multi-root)
        if self.current_rel == "":
            if self._is_multi_root:
                self._highlight_dir_name = None
                self._load_directory(None)
            return

        parent = os.path.dirname(self.current_path)
        if not parent:
            return
        # If direct child of repo root and multi-root -> jump to union immediately
        try:
            is_direct_child_of_root = os.path.realpath(parent) == os.path.realpath(self.current_root)
        except Exception:
            is_direct_child_of_root = False
        if self._is_multi_root and is_direct_child_of_root:
            self._highlight_dir_name = None
            self._load_directory(None)
            return

        try:
            cr = os.path.realpath(self.current_root)
            pr = os.path.realpath(parent)
            if not (pr == cr or pr.startswith(cr + os.sep)):
                parent = self.current_root
        except Exception:
            parent = self.current_root
        self._highlight_dir_name = os.path.basename(self.current_path)
        self._load_directory(parent, repo_root=self.current_root)

    # Snap to first/last row actions
    def action_cursor_home(self) -> None:
        try:
            if self.table.row_count:
                self.table.cursor_coordinate = (0, 0)
        except Exception:
            pass

    def action_cursor_end(self) -> None:
        try:
            rc = self.table.row_count
            if rc:
                self.table.cursor_coordinate = (rc - 1, 0)
        except Exception:
            pass

    def action_toggle_layout(self) -> None:
        # Ignore layout changes while in fullscreen preview to avoid losing content
        if getattr(self, "preview_fullscreen", False):
            return
        order = ["right", "bottom", "left", "top"]
        try:
            idx = order.index(getattr(self, 'layout', 'right'))
        except ValueError:
            idx = 0
        self.layout = order[(idx + 1) % len(order)]

        # Remember current selection to restore after rebuild
        saved_key = self._selected_row_key()

        def _remount() -> None:
            # Rebuild widgets, then reload directory and restore selection
            target_path = self.current_path
            target_root = self.current_root
            self._apply_layout()
            self._load_directory(target_path, repo_root=target_root)
            if saved_key and saved_key in getattr(self, '_row_keys', []):
                try:
                    i = self._row_keys.index(saved_key)
                    self.table.cursor_coordinate = (i, 0)
                    self._update_preview(saved_key)
                except Exception:
                    pass
            try:
                self.table.focus()
            except Exception:
                pass

        try:
            self.call_after_refresh(_remount)
        except Exception:
            _remount()
