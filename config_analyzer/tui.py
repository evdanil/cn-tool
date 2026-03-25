from typing import Optional

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static
from textual.containers import Container, Horizontal, Vertical
from textual.binding import Binding
from textual.reactive import reactive
from textual import events

from .parser import Snapshot
from .filter_mixin import FilterMixin
from .debug import get_logger
from .version import __version__
from .differ import get_diff, get_diff_side_by_side
from .keymap import snapshot_bindings
from .tips import snapshot_tips
from rich.syntax import Syntax
from .formatting import format_timestamp
from rich.text import Text
from .search import SearchController
from .widgets import SearchableTextPane
import os


class DiffViewPane(SearchableTextPane):
    BINDINGS = [
        Binding("up", "scroll_up", "Scroll Up", show=False),
        Binding("down", "scroll_down", "Scroll Down", show=False),
        Binding("pageup", "page_up", "Page Up", show=False),
        Binding("pagedown", "page_down", "Page Down", show=False),
        Binding("space", "page_down", "Page Down", show=False),
        Binding("home", "go_home", "Go Home", show=False),
        Binding("end", "go_end", "Go End", show=False),
        Binding("d", "toggle_diff_mode", "Toggle Diff View"),
        Binding("h", "toggle_hide_unchanged", "Hide Unchanged"),
        Binding("tab", "focus_next_panel", "Switch Panel", show=False),
        Binding("ctrl+d", "dump_debug", "", show=False),
    ]

    _search_identity = "diff"

    def __init__(self, *, id: Optional[str] = None, wrap: bool = False) -> None:
        super().__init__(id=id, wrap=wrap)
        try:
            self.can_focus = True  # type: ignore[assignment]
        except Exception:
            pass

    def action_toggle_diff_mode(self) -> None:
        try:
            self.app.action_toggle_diff_mode()  # type: ignore[attr-defined]
        except Exception:
            pass

    def action_toggle_hide_unchanged(self) -> None:
        try:
            self.app.action_toggle_hide_unchanged()  # type: ignore[attr-defined]
        except Exception:
            pass

    def action_focus_next_panel(self) -> None:
        try:
            self.app.action_focus_next()  # type: ignore[attr-defined]
        except Exception:
            pass

    def on_key(self, event: events.Key) -> None:  # type: ignore[override]
        from .utils import handle_search_key

        # In-place search when active
        app = getattr(self, "app", None)
        if app is not None and bool(getattr(app, "_search_active", False)):
            if handle_search_key(app, event, "diff"):
                return
        # Tab switches panel when NOT in search mode
        elif event.key == "tab":
            self.action_focus_next_panel()
            event.stop()
            return

        super().on_key(event)

    def action_start_find(self) -> None:
        try:
            self.app.action_start_find()  # type: ignore[attr-defined]
        except Exception:
            pass

    def action_dump_debug(self) -> None:
        try:
            logr = get_logger("pane-dbg")
            size = getattr(self, "size", None)
            try:
                y = self.get_scroll_y()
            except Exception:
                y = None
            logr.debug(
                "diff.dump: id=%s size=%s scroll_y=%s lines=%s",
                getattr(self, 'id', None),
                size,
                y,
                len(getattr(self, '_lines', []) or []),
            )
        except Exception:
            pass

    # Fallbacks for older Textual
    def action_scroll_up(self) -> None:  # type: ignore[override]
        try:
            super().action_scroll_up()  # type: ignore[attr-defined]
        except Exception:
            try:
                self.action_page_up()
            except Exception:
                pass

    def action_scroll_down(self) -> None:  # type: ignore[override]
        try:
            super().action_scroll_down()  # type: ignore[attr-defined]
        except Exception:
            try:
                self.action_page_down()
            except Exception:
                pass

    def action_go_home(self) -> None:
        try:
            self.scroll_to_y(0)
        except Exception:
            pass

    def action_go_end(self) -> None:
        try:
            end_line = max(len(getattr(self, "_lines", []) or []), 0)
            self.scroll_to_y(end_line)
        except Exception:
            pass


class SelectionDataTable(DataTable):
    BINDINGS = [
        Binding("home", "goto_first_row", "First", show=False),
        Binding("end", "goto_last_row", "Last", show=False),
        Binding("enter", "select_row", "Select", show=False),
        Binding("backspace", "filter_backspace", "", show=False),
        Binding("ctrl+h", "filter_backspace", "", show=False),
        Binding("tab", "focus_next_panel", "Switch Panel", show=False),
    ]

    def action_goto_first_row(self) -> None:
        try:
            if self.row_count:
                self.cursor_coordinate = (0, 0)
        except Exception:
            pass

    def action_goto_last_row(self) -> None:
        try:
            rc = self.row_count
            if rc:
                self.cursor_coordinate = (rc - 1, 0)
        except Exception:
            pass

    def action_select_row(self) -> None:
        """Delegate row selection to the App's selection action."""
        try:
            # Toggle selection at the app level to keep logic DRY
            self.app.action_toggle_row()  # type: ignore[attr-defined]
        except Exception:
            pass

    def action_filter_backspace(self) -> None:
        try:
            fb = getattr(self.app, "filter_backspace", None)
            if fb:
                fb()
        except Exception:
            pass

    def action_focus_next_panel(self) -> None:
        try:
            self.app.action_focus_next()  # type: ignore[attr-defined]
        except Exception:
            pass

    def on_key(self, event: events.Key) -> None:  # type: ignore
        """Delegate filter keys to the App-level mixin; consume if handled.

        Handling at the widget level ensures Backspace/Enter work reliably
        since Textual delivers keys to the focused widget first.
        """
        # Force Tab to switch panel (DataTable may consume it otherwise)
        if event.key == "tab":
            self.action_focus_next_panel()
            try:
                event.stop()
            except Exception:
                pass
            return
        try:
            from .utils import handle_search_key

            if bool(getattr(self.app, "_search_active", False)) and handle_search_key(self.app, event, "diff"):
                try:
                    event.stop()
                except Exception:
                    pass
                return
        except Exception:
            pass
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


class CommitSelectorApp(FilterMixin, App):
    TITLE = "ConfigAnalyzer"
    SUB_TITLE = f"v{__version__} — Snapshot History"

    DEFAULT_CSS = """
    #table-container, #diff_view {
        background: $surface;
        width: 1fr;
    }

    #table-container {
        overflow: hidden;
    }

    #diff_view {
        visibility: hidden;
        padding: 0 1;
    }

    .layout-right #diff_view { border-left: solid steelblue; }
    .layout-right #diff_view:focus-within { border-left: thick yellow; }
    .layout-left #diff_view { border-right: solid steelblue; }
    .layout-left #diff_view:focus-within { border-right: thick yellow; }
    .layout-bottom #diff_view { border-top: solid steelblue; }
    .layout-bottom #diff_view:focus-within { border-top: thick yellow; }
    .layout-top #diff_view { border-bottom: solid steelblue; }
    .layout-top #diff_view:focus-within { border-bottom: thick yellow; }

    #main-panel { height: 1fr; width: 1fr; }
    """

    show_hide_diff_key = reactive(False, layout=True)
    # Dynamic footer hint visibility
    show_select_key = reactive(True)
    show_diff_controls_key = reactive(False)

    BINDINGS = snapshot_bindings(show_hide_diff_key, show_select_key, show_diff_controls_key)
    # Add App-level nav bindings to route to the diff pane when it has focus
    BINDINGS += [
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

    def __init__(self, snapshots_data: list[Snapshot], scroll_to_end: bool = False, layout: str = "right"):
        super().__init__()
        self.logr = get_logger("tui")
        self._debug_keys = bool(os.environ.get("CN_TUI_DEBUG_KEYS"))
        self.snapshots_data = snapshots_data
        self.scroll_to_end = scroll_to_end
        self.layout = layout
        self.selected_keys: list[str] = []
        self.ordered_keys: list[str] = []
        self.diff_mode: str = "unified"
        self.hide_unchanged_sbs: bool = False
        self.navigate_back: bool = False
        # Find-in-text state for diff/single preview
        self._search_active: bool = False
        self._search: SearchController = SearchController()
        self._diff_has_content: bool = False
        self._pending_diff_scroll: Optional[int] = None
        self._pending_diff_focus: bool = False
        self._diff_maximized: bool = False
        self._current_diff_document_id: str = ""

    def compose(self) -> ComposeResult:
        yield Header()
        # Placeholders; actual layout is mounted in _apply_layout
        self.diff_view = DiffViewPane(id="diff_view", wrap=False)
        self.diff_view.can_focus = False
        try:
            self.diff_view.search = self._search
        except Exception:
            pass
        self.table = SelectionDataTable(id="commit_table")
        self.table_container = Container(self.table, id="table-container")
        self.main_panel = Container(id="main-panel")
        yield self.main_panel
        self.tips = Static("", id="tips")
        yield self.tips
        yield Footer()

    def on_mount(self) -> None:
        self.logr.debug("on_mount: layout=%s", self.layout)
        self._apply_layout()
        self._filter_text: str = ""
        # Initialize footer hint flags
        self._update_focus_flags()

        def _focus_table() -> None:
            try:
                self.table.focus()
                self.logr.debug("on_mount: focused table; rows=%s", getattr(self.table, 'row_count', 'n/a'))
            except Exception as e:
                self.logr.exception("on_mount: table.focus failed: %s", e)

        try:
            self.call_after_refresh(_focus_table)
        except Exception:
            _focus_table()

    def _apply_layout(self) -> None:
        """Rebuild widgets to avoid reparent timing issues on Textual 0.61."""
        self.logr.debug("apply_layout: rebuild layout=%s", self.layout)
        # Clear container
        prev_scroll: Optional[int] = None
        prev_focus = False
        if hasattr(self, "diff_view") and getattr(self, "_diff_has_content", False):
            try:
                prev_scroll = self.diff_view.get_scroll_y()
            except Exception:
                prev_scroll = None
            prev_focus = bool(getattr(self.diff_view, "has_focus", False))
        self._pending_diff_scroll = prev_scroll
        self._pending_diff_focus = prev_focus and bool(self.show_hide_diff_key)
        try:
            for child in list(self.main_panel.children):
                child.remove()
        except Exception:
            pass

        # Fresh widgets each time
        self.diff_view = DiffViewPane(id="diff_view", wrap=False)
        try:
            self.diff_view.search = self._search
        except Exception:
            pass
        if not self.show_hide_diff_key:
            self.diff_view.styles.visibility = "hidden"
            self.diff_view.can_focus = False
        else:
            self.diff_view.styles.visibility = "visible"
            self.diff_view.can_focus = True

        self.table = SelectionDataTable(id="commit_table")
        self.table_container = Container(self.table, id="table-container")

        if self._diff_maximized and self.show_hide_diff_key:
            container = Container(self.diff_view, id="diff-maximized")
        else:
            if self.layout in ("right", "left"):
                ordered = (self.diff_view, self.table_container) if self.layout == "left" else (self.table_container, self.diff_view)
                container = Horizontal(*ordered, classes=f"layout-{self.layout}")
            else:
                ordered = (self.diff_view, self.table_container) if self.layout == "top" else (self.table_container, self.diff_view)
                container = Vertical(*ordered, classes=f"layout-{self.layout}")
        self.main_panel.mount(container)

        # Populate table and reapply state
        self.setup_table()
        self._update_tips()
        for key in self.selected_keys:
            try:
                self.table.update_cell(key, "selected_col", Text("x", style="green"))
            except Exception:
                pass

        if self.show_hide_diff_key and len(self.selected_keys) == 2:
            self.show_diff()
        elif self.show_hide_diff_key and len(self.selected_keys) == 1:
            self.show_single()
        else:
            self._pending_diff_scroll = None

        # Restore focus preference (diff pane if previously focused)
        focused_diff = False
        if self._pending_diff_focus and self.diff_view.styles.visibility == "visible":
            try:
                self.diff_view.focus()
                focused_diff = True
            except Exception:
                focused_diff = False
        if not focused_diff and not self._diff_maximized:
            try:
                self.table.focus()
            except Exception:
                pass
        self._pending_diff_focus = False
        self._update_focus_flags()

    def setup_table(self) -> None:
        self.logr.debug("setup_table: %d snapshots", len(self.snapshots_data))
        table = self.table
        # Clean model to avoid duplicate columns
        try:
            table.clear()
        except Exception:
            pass
        table.cursor_type = "row"
        table.add_column("Sel", key="selected_col", width=3)
        table.add_column("Name", key="name_col")
        table.add_column("Date", key="date_col")
        table.add_column("Author", key="author_col")
        # Render rows honoring any active filter
        self._render_rows()

    def _update_tips(self) -> None:
        filter_hint = self.get_filter_hint()
        show_diff_controls = bool(self.show_diff_controls_key)
        show_tab = True
        if self._search_active and self._search.has_query():
            search_hint = f" | Find: '{self._search.query}' {self._search.counter_text()} (↓/Enter=next, ↑=prev, Esc=exit)"
        elif self._search_active:
            search_hint = " | Find: _ (type to search, Esc=cancel)"
        else:
            search_hint = ""
        self.tips.update(snapshot_tips(filter_hint, show_diff_controls=show_diff_controls, show_tab=show_tab, search_hint=search_hint))

    def action_focus_next(self) -> None:
        """Ensure footer hint flags are updated after focus changes."""
        try:
            self.screen.focus_next()
        except Exception:
            pass
        self._update_focus_flags()
        self._update_tips()

    def _update_focus_flags(self) -> None:
        try:
            diff_visible = self.diff_view.styles.visibility == "visible"
        except Exception:
            diff_visible = False
        # Enter hint when table focused
        self.show_select_key = bool(getattr(self.table, "has_focus", False))
        # D/H hints when diff visible and focused
        self.show_diff_controls_key = bool(diff_visible and getattr(self.diff_view, "has_focus", False))

    def _activate_diff_document(self, document_id: str) -> str:
        if document_id != self._current_diff_document_id:
            self._search.reset()
            self._current_diff_document_id = document_id
        return document_id

    def _render_rows(self) -> None:
        table = self.table
        try:
            table.clear(columns=False)
        except Exception:
            # If clear with columns arg unsupported, rebuild columns
            table.clear()
            table.add_column("Sel", key="selected_col", width=3)
            table.add_column("Name", key="name_col")
            table.add_column("Date", key="date_col")
            table.add_column("Author", key="author_col")
        self.ordered_keys = []
        ft = (getattr(self, "_filter_text", "") or "").lower()
        for snapshot in self.snapshots_data:
            name = snapshot.original_filename
            author = snapshot.author or ""
            ts_str = str(snapshot.timestamp)
            if ft and not (ft in name.lower() or ft in author.lower() or ft in ts_str.lower()):
                continue
            key = snapshot.path
            self.ordered_keys.append(key)
            table.add_row(
                "x" if key in self.selected_keys else "",
                name,
                format_timestamp(snapshot.timestamp),
                snapshot.author,
                key=key,
            )
        # Reset cursor to first row
        try:
            if table.row_count:
                table.cursor_coordinate = (0, 0)
        except Exception:
            pass
        self._update_tips()

    def on_key(self, event: events.Key) -> None:  # type: ignore
        from .utils import handle_search_key

        # Delegate to mixin; consume if handled (only when table focused)
        if self._debug_keys:
            try:
                self.logr.debug(
                    "app.on_key(snapshot): key=%s focus=%s pane_focus=%s table_focus=%s",
                    getattr(event, 'key', None),
                    getattr(self.screen.focused, 'id', None),
                    getattr(self.diff_view, 'has_focus', None),
                    getattr(self.table, 'has_focus', None),
                )
            except Exception:
                pass
        if self._search_active and handle_search_key(self, event, "diff"):
            return
        if self._diff_maximized and not self._search_active and event.key == "escape":
            self.action_toggle_maximize_pane()
            try:
                event.stop()
            except Exception:
                pass
            return
        if self.process_filter_key(event, require_table_focus=True):
            try:
                event.stop()
            except Exception:
                pass
            return
        # Route navigation keys to diff pane when it has focus
        if event.key in ("up", "down", "pageup", "pagedown", "home", "end") and getattr(self.diff_view, "has_focus", False):
            # Let App-level Binding handle; no-op here
            return

    def show_diff(self) -> None:
        self.show_hide_diff_key = True

        restore_scroll = self._pending_diff_scroll
        self._pending_diff_scroll = None
        prev_scroll = 0
        if getattr(self, "_diff_has_content", False):
            try:
                prev_scroll = self.diff_view.get_scroll_y()
            except Exception:
                prev_scroll = 0

        path1, path2 = self.selected_keys
        snapshot1 = next(s for s in self.snapshots_data if s.path == path1)
        snapshot2 = next(s for s in self.snapshots_data if s.path == path2)
        if snapshot1.timestamp > snapshot2.timestamp:
            snapshot1, snapshot2 = snapshot2, snapshot1

        terminal_width = self.diff_view.size.width if self.diff_view.size.width > 0 else self.size.width

        if self.diff_mode == "side-by-side":
            renderable = get_diff_side_by_side(
                snapshot1,
                snapshot2,
                hide_unchanged=self.hide_unchanged_sbs,
                total_width=max(terminal_width, 80),
            )
            document_id = self._activate_diff_document(
                f"diff:side-by-side:{int(self.hide_unchanged_sbs)}:{snapshot1.path}:{snapshot2.path}"
            )
        else:
            renderable = get_diff(snapshot1, snapshot2)
            document_id = self._activate_diff_document(
                f"diff:unified:{snapshot1.path}:{snapshot2.path}"
            )

        self.diff_view.set_renderable(renderable, document_id=document_id)

        self._diff_has_content = True

        self.diff_view.styles.visibility = "visible"
        self.diff_view.can_focus = True  # allow Tab focus, but don't take focus now
        if self._search_active and self._search.has_query():
            try:
                self.diff_view.scroll_match_into_view(center=False)
            except Exception:
                pass
        else:
            target = restore_scroll if restore_scroll is not None else prev_scroll
            if target:
                try:
                    self.diff_view.scroll_to_y(target)
                except Exception:
                    pass
        self._update_focus_flags()
        self._update_tips()

    def hide_diff_panel(self) -> None:
        self.logr.debug("hide_diff_panel")
        self.diff_view.styles.visibility = "hidden"
        self.diff_view.can_focus = False
        self.show_hide_diff_key = False
        self._diff_maximized = False
        self._diff_has_content = False
        self._current_diff_document_id = ""
        if self._search_active:
            self._search_active = False
            self._search.reset()
            try:
                self.diff_view.apply_search()
            except Exception:
                pass
        try:
            self.table.focus()
        except Exception:
            pass
        self._update_focus_flags()
        self._update_tips()

    def action_hide_diff(self) -> None:
        # If diff visible, hide and clear selection; otherwise, go back to repo
        if self.diff_view.styles.visibility == "visible":
            self.hide_diff_panel()
            for key in list(self.selected_keys):
                try:
                    self.table.update_cell(key, "selected_col", "")
                except Exception:
                    # Table may have been filtered or rows rebuilt; ignore
                    pass
            self.selected_keys.clear()
        else:
            self.action_go_back()

    def action_go_back(self) -> None:
        # Clear filter on leaving the snapshot view
        self.clear_filter()
        self.navigate_back = True
        self.exit()

    def _on_filter_changed(self) -> None:
        self._render_rows()

    def action_quit(self) -> None:
        # Clear filter first when active; else quit
        if getattr(self, "_filter_text", ""):
            self._filter_text = ""
            self._render_rows()
            return
        self.exit()

    # App-level pane navigation actions (guaranteed routing)
    def action_pane_up(self) -> None:
        try:
            if getattr(self.diff_view, "has_focus", False):
                if self._debug_keys:
                    self.logr.debug("app.route_nav_to_diff: key=up")
                self.diff_view.action_scroll_up()
        except Exception:
            pass

    def action_pane_down(self) -> None:
        try:
            if getattr(self.diff_view, "has_focus", False):
                if self._debug_keys:
                    self.logr.debug("app.route_nav_to_diff: key=down")
                self.diff_view.action_scroll_down()
        except Exception:
            pass

    def action_pane_page_up(self) -> None:
        try:
            if getattr(self.diff_view, "has_focus", False):
                if self._debug_keys:
                    self.logr.debug("app.route_nav_to_diff: key=pageup")
                self.diff_view.action_page_up()
        except Exception:
            pass

    def action_pane_page_down(self) -> None:
        try:
            if getattr(self.diff_view, "has_focus", False):
                if self._debug_keys:
                    self.logr.debug("app.route_nav_to_diff: key=pagedown")
                self.diff_view.action_page_down()
        except Exception:
            pass

    def action_pane_home(self) -> None:
        try:
            if getattr(self.diff_view, "has_focus", False):
                if self._debug_keys:
                    self.logr.debug("app.route_nav_to_diff: key=home")
                self.diff_view.action_go_home()
        except Exception:
            pass

    def action_pane_end(self) -> None:
        try:
            if getattr(self.diff_view, "has_focus", False):
                if self._debug_keys:
                    self.logr.debug("app.route_nav_to_diff: key=end")
                self.diff_view.action_go_end()
        except Exception:
            pass

    def action_toggle_row(self) -> None:
        table = self.table
        if not table.has_focus:
            self.logr.debug("toggle_row: table not focused; ignoring")
            return
        try:
            row_key = self.ordered_keys[table.cursor_row]
        except IndexError:
            self.logr.debug("toggle_row: cursor out of range")
            return
        if row_key in self.selected_keys:
            self.selected_keys.remove(row_key)
            table.update_cell(row_key, "selected_col", "")
        else:
            if len(self.selected_keys) >= 2:
                oldest_key = self.selected_keys.pop(0)
                table.update_cell(oldest_key, "selected_col", "")
            self.selected_keys.append(row_key)
            table.update_cell(row_key, "selected_col", Text("x", style="green"))
        if len(self.selected_keys) == 2:
            self.show_diff()
        elif len(self.selected_keys) == 1:
            # Show single snapshot content with syntax highlighting
            self.show_single()
        else:
            self.hide_diff_panel()

    def show_single(self) -> None:
        try:
            path = self.selected_keys[-1]
        except IndexError:
            return
        try:
            snap = next(s for s in self.snapshots_data if s.path == path)
        except StopIteration:
            return
        self.show_hide_diff_key = True

        restore_scroll = self._pending_diff_scroll
        self._pending_diff_scroll = None
        prev_scroll = 0
        if getattr(self, "_diff_has_content", False):
            try:
                prev_scroll = self.diff_view.get_scroll_y()
            except Exception:
                prev_scroll = 0

        renderable = Syntax(snap.content_body, "ini", word_wrap=False, line_numbers=False)
        document_id = self._activate_diff_document(f"single:{snap.path}")
        self.diff_view.set_renderable(renderable, document_id=document_id)

        self._diff_has_content = True
        self.diff_view.styles.visibility = "visible"
        self.diff_view.can_focus = True
        if self._search_active and self._search.has_query():
            try:
                self.diff_view.scroll_match_into_view(center=False)
            except Exception:
                pass
        else:
            target = restore_scroll if restore_scroll is not None else prev_scroll
            if target:
                try:
                    self.diff_view.scroll_to_y(target)
                except Exception:
                    pass
        self._update_focus_flags()
        self._update_tips()
        
    def action_toggle_diff_mode(self) -> None:
        self.diff_mode = "side-by-side" if self.diff_mode == "unified" else "unified"
        if len(self.selected_keys) == 2 and self.diff_view.styles.visibility == "visible":
            if self._diff_has_content:
                try:
                    self._pending_diff_scroll = self.diff_view.get_scroll_y()
                except Exception:
                    self._pending_diff_scroll = None
            self.show_diff()

    def action_toggle_layout(self) -> None:
        order = ["right", "bottom", "left", "top"]
        try:
            idx = order.index(self.layout)
        except ValueError:
            idx = 0
        self.layout = order[(idx + 1) % len(order)]

        def _remount() -> None:
            self._apply_layout()

        try:
            self.call_after_refresh(_remount)
        except Exception:
            _remount()

    def action_toggle_maximize_pane(self) -> None:
        if not self._diff_has_content:
            return
        self._diff_maximized = not self._diff_maximized

        def _remount() -> None:
            self._apply_layout()

        try:
            self.call_after_refresh(_remount)
        except Exception:
            _remount()

    # ---- Find support ----
    def action_start_find(self) -> None:
        if not self._diff_has_content:
            return
        self._search_active = True
        self._search.reset()
        try:
            self.diff_view.apply_search()
        except Exception:
            pass
        self._update_tips()

    def action_cancel_find(self) -> None:
        if not self._search_active:
            return
        self._search_active = False
        self._search.reset()
        try:
            self.diff_view.apply_search()
        except Exception:
            pass
        self._update_tips()

    def action_find_backspace(self) -> None:
        if not self._search_active:
            return
        self._search.backspace()
        try:
            self.diff_view.apply_search()
            if self._search.has_matches():
                self.diff_view.scroll_match_into_view(center=False)
        except Exception:
            pass
        self._update_tips()

    def action_find_append_char(self, ch: str) -> None:
        if not self._search_active or not ch:
            return
        self._search.append_char(ch)
        try:
            self.diff_view.apply_search()
            if self._search.has_matches():
                self.diff_view.scroll_match_into_view(center=False)
        except Exception:
            pass
        self._update_tips()

    def action_find_next(self) -> None:
        if not self._search_active or not self._search.has_query():
            return
        if not self._search.next():
            return
        try:
            self.diff_view.apply_search()
            self.diff_view.scroll_match_into_view(center=True)
        except Exception:
            pass
        self._update_tips()

    def action_find_prev(self) -> None:
        if not self._search_active or not self._search.has_query():
            return
        if not self._search.prev():
            return
        try:
            self.diff_view.apply_search()
            self.diff_view.scroll_match_into_view(center=True)
        except Exception:
            pass
        self._update_tips()

    def action_toggle_hide_unchanged(self) -> None:
        self.hide_unchanged_sbs = not self.hide_unchanged_sbs
        if self.diff_mode == "side-by-side" and len(self.selected_keys) == 2 and self.diff_view.styles.visibility == "visible":
            if self._diff_has_content:
                try:
                    self._pending_diff_scroll = self.diff_view.get_scroll_y()
                except Exception:
                    self._pending_diff_scroll = None
            self.show_diff()

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
