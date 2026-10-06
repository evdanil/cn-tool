from typing import Optional

from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, DataTable, Input, Static
from textual.containers import Container
from textual.binding import Binding
from textual.message import Message
from textual.reactive import reactive
from textual import events

from .parser import Snapshot
from .filter_mixin import FilterMixin
from .debug import get_logger
from .version import __version__
from .differ import get_diff, get_diff_side_by_side
from .keymap import forward_printable, snapshot_bindings
from .tips import snapshot_tips
from rich.syntax import Syntax
from .formatting import format_timestamp
from rich.text import Text
from .search import SearchController
from .widgets import FilterInput, FindInput, SearchableTextPane
import os


# Panel layouts in Ctrl+L order. Each is a class on the main panel (``layout-<name>``): the
# widgets are composed once and only the class and the child order change.
_LAYOUTS = ("right", "bottom", "left", "top")


class DiffViewPane(SearchableTextPane):
    HELP = """
    ## Document

    Shows the selected snapshot, or the diff of two.

    - Up/Down, PageUp/PageDown, Space, `j`/`k`, Home/End scroll.
    - `d` switches unified and side-by-side; `h` hides unchanged lines (side-by-side).
    - Ctrl+F or Alt+F finds in the document: type, Enter/Down next, Up previous, Esc closes.
    - `z` maximises this pane; Esc restores it.
    - `/` goes to the filter; Tab goes back to the list.
    """

    BINDINGS = [
        Binding("up", "scroll_up", "Scroll Up", show=False),
        Binding("down", "scroll_down", "Scroll Down", show=False),
        Binding("pageup", "page_up", "Page Up", show=False),
        Binding("pagedown", "page_down", "Page Down", show=False),
        Binding("space", "page_down", "Page Down", show=False),
        # j, k and space are bound here, not on the screen: from the list they type into the filter
        Binding("j", "scroll_down", "Scroll Down", show=False),
        Binding("k", "scroll_up", "Scroll Up", show=False),
        Binding("home", "go_home", "Go Home", show=False),
        Binding("end", "go_end", "Go End", show=False),
        Binding("d", "toggle_diff_mode", "Toggle Diff View"),
        Binding("h", "toggle_hide_unchanged", "Hide Unchanged"),
        Binding("tab", "focus_next_panel", "Switch Panel", show=False),
        Binding("ctrl+d", "dump_debug", "Dump Pane Debug", show=False),
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
            self.screen.action_toggle_diff_mode()  # type: ignore[attr-defined]
        except Exception:
            pass

    def action_toggle_hide_unchanged(self) -> None:
        try:
            self.screen.action_toggle_hide_unchanged()  # type: ignore[attr-defined]
        except Exception:
            pass

    def action_focus_next_panel(self) -> None:
        try:
            self.screen.action_focus_next()  # type: ignore[attr-defined]
        except Exception:
            pass

    def on_key(self, event: events.Key) -> None:  # type: ignore[override]
        if event.key == "tab":
            self.action_focus_next_panel()
            event.stop()
            return

        super().on_key(event)

    def action_start_find(self) -> None:
        try:
            self.screen.action_start_find()  # type: ignore[attr-defined]
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
    HELP = """
    ## Snapshots

    Newest first. Select one snapshot to see it, two to see their diff.

    - Enter selects or deselects the row under the cursor.
    - Typing filters the list by name, author or time, in the filter line above. A filter
      that starts with z, / or ? needs / first.
    - `/` goes to the filter line; Up/Down move this list from there and Enter selects.
    - Esc clears the filter, then hides the document, then goes back to the repositories.
    - Tab switches to the document pane.
    """

    BINDINGS = [
        Binding("home", "goto_first_row", "First", show=False),
        Binding("end", "goto_last_row", "Last", show=False),
        # shown: this one shadows the screen's Enter binding while the list has the focus
        Binding("enter", "select_row", "Toggle Select"),
        Binding("tab", "focus_next_panel", "Switch Panel", show=False),
    ]

    # The filter line printable keys are forwarded to; the screen sets it, a bare list has none.
    filter_input: Optional[FilterInput] = None

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
        """Delegate row selection to the screen's selection action."""
        try:
            # Toggle selection at the screen level to keep logic DRY
            self.screen.action_toggle_row()  # type: ignore[attr-defined]
        except Exception:
            pass

    def action_focus_next_panel(self) -> None:
        try:
            self.screen.action_focus_next()  # type: ignore[attr-defined]
        except Exception:
            pass

    def on_key(self, event: events.Key) -> None:  # type: ignore
        """Tab switches panels; a printable key starts (or continues) the filter.

        Handling at the widget level ensures they work reliably since Textual delivers keys
        to the focused widget first. ``z``, ``/`` and ``?`` stay with the screen's bindings.
        """
        # Force Tab to switch panel (DataTable may consume it otherwise)
        if event.key == "tab":
            self.action_focus_next_panel()
            try:
                event.stop()
            except Exception:
                pass
            return
        if self.filter_input is not None:
            forward_printable(event, self.filter_input)


class SnapshotScreen(FilterMixin, Screen):
    """The snapshot list and its document pane: select one snapshot to read it, two to diff them.

    The host App provides ``layout`` (the panel layout preference, one of ``_LAYOUTS``): the screen
    reads ``app.layout`` when it is composed and when it resumes, and Ctrl+L writes it back. The
    screen's own ``layout`` attribute is ``Widget.layout``, Textual's child arrangement: not touched.

    The screen never exits the app. It posts ``Closed`` (back to the repository browser, or quit)
    and the host decides what happens to the screen stack.
    """

    TITLE = "ConfigAnalyzer"
    SUB_TITLE = f"v{__version__} — Snapshot History"

    # The list takes the first focus; the filter line is reached with / or by typing.
    AUTO_FOCUS = "#commit_table"

    DEFAULT_CSS = """
    #table-container, #diff_view {
        background: $surface;
        width: 1fr;
        height: 1fr;
    }

    #table-container {
        overflow: hidden;
    }

    #diff_view {
        visibility: hidden;
        padding: 0 1;
    }

    #input-row { height: auto; }
    #input-row FilterInput, #input-row FindInput { width: 1fr; }

    #main-panel { height: 1fr; width: 1fr; }
    #main-panel.layout-right, #main-panel.layout-left { layout: horizontal; }
    #main-panel.layout-bottom, #main-panel.layout-top { layout: vertical; }

    .layout-right #diff_view { border-left: solid steelblue; }
    .layout-right #diff_view:focus-within { border-left: thick yellow; }
    .layout-left #diff_view { border-right: solid steelblue; }
    .layout-left #diff_view:focus-within { border-right: thick yellow; }
    .layout-bottom #diff_view { border-top: solid steelblue; }
    .layout-bottom #diff_view:focus-within { border-top: thick yellow; }
    .layout-top #diff_view { border-bottom: solid steelblue; }
    .layout-top #diff_view:focus-within { border-bottom: thick yellow; }

    #main-panel.-maximized #table-container { display: none; }
    #main-panel.-maximized #diff_view { border: none; }
    """

    # Footer/help state. ``bindings=True`` refreshes the footer when a flag changes, and
    # ``check_action`` reads them to hide the bindings that do not apply right now.
    show_hide_diff_key = reactive(False, bindings=True)  # a document is shown
    show_select_key = reactive(True, bindings=True)  # the list has the focus
    show_diff_controls_key = reactive(False, bindings=True)  # the document pane has the focus

    BINDINGS = snapshot_bindings()
    # Shift+Tab is bound here because ``Screen`` binds it to ``app.focus_previous``, which would
    # cycle through the filter and find lines: with two panes it is the same toggle as Tab.
    BINDINGS += [
        Binding("shift+tab", "focus_previous", "Switch Panel", show=False),
    ]
    # Screen-level nav bindings route to the diff pane when it has focus
    BINDINGS += [
        Binding("up", "pane_up", "Scroll Up", show=False),
        Binding("down", "pane_down", "Scroll Down", show=False),
        Binding("pageup", "pane_page_up", "Page Up", show=False),
        Binding("pagedown", "pane_page_down", "Page Down", show=False),
        Binding("home", "pane_home", "Go Home", show=False),
        Binding("end", "pane_end", "Go End", show=False),
    ]

    class Closed(Message):
        """The user is done with the snapshots: ``back`` returns to the repository browser, else quit."""

        def __init__(self, back: bool) -> None:
            super().__init__()
            self.back = back

    def __init__(self, snapshots_data: list[Snapshot], scroll_to_end: bool = False) -> None:
        super().__init__()
        self.logr = get_logger("tui")
        self._debug_keys = bool(os.environ.get("CN_TUI_DEBUG_KEYS"))
        self.snapshots_data = snapshots_data
        self.scroll_to_end = scroll_to_end
        self.selected_keys: list[str] = []
        self.ordered_keys: list[str] = []
        self.diff_mode: str = "unified"
        self.hide_unchanged_sbs: bool = False
        # Find-in-text state for diff/single preview
        self._search_active: bool = False
        self._search: SearchController = SearchController()
        self._diff_has_content: bool = False
        self._pending_diff_scroll: Optional[int] = None
        self._current_diff_document_id: str = ""

    @property
    def _diff_maximized(self) -> bool:
        """Whether the document fills the panel; read-only view of the ``-maximized`` class."""
        panel = getattr(self, "main_panel", None)
        return panel is not None and panel.has_class("-maximized")

    def _shown_layout(self) -> str:
        """The layout on screen: an unknown name is shown as the vertical split (``bottom``)."""
        layout = self.app.layout  # type: ignore[attr-defined]
        return layout if layout in _LAYOUTS else "bottom"

    def compose(self) -> ComposeResult:
        yield Header()
        self.diff_view = DiffViewPane(id="diff_view", wrap=False)
        self.diff_view.can_focus = False
        self.diff_view.search = self._search
        self.table = SelectionDataTable(id="commit_table")
        self.table_container = Container(self.table, id="table-container")
        # One row above the panels: the filter, or the find line while find is open.
        self.filter_input = FilterInput(self.table, id="filter")
        self.find_input = FindInput("diff", id="find")
        self.find_input.display = False
        self.table.filter_input = self.filter_input
        yield Container(self.filter_input, self.find_input, id="input-row")
        # Composed once, in the order the starting layout needs; Ctrl+L and maximise only
        # change classes (and the child order) afterwards.
        shown = self._shown_layout()
        ordered = (self.diff_view, self.table_container) if shown in ("left", "top") else (self.table_container, self.diff_view)
        self.main_panel = Container(*ordered, id="main-panel", classes=f"layout-{shown}")
        yield self.main_panel
        self.tips = Static("", id="tips")
        yield self.tips
        yield Footer()

    def on_mount(self) -> None:
        self.logr.debug("on_mount: layout=%s", self.app.layout)  # type: ignore[attr-defined]
        self.setup_table()
        self._filter_text: str = ""
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

    def on_screen_resume(self) -> None:
        """Another screen was on top and may have changed the layout preference: show the current one."""
        self._apply_layout()

    def _apply_layout(self) -> None:
        """Point the main panel at the app's layout: one class, and the document before or after the list.

        Nothing is re-created, so focus, scroll offsets, the cursor and the selection stay as they are.
        """
        shown = self._shown_layout()
        for name in _LAYOUTS:
            self.main_panel.set_class(name == shown, f"layout-{name}")
        if shown in ("left", "top"):
            self.main_panel.move_child(self.diff_view, before=self.table_container)
        else:
            self.main_panel.move_child(self.table_container, before=self.diff_view)

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
        show_diff_controls = bool(self.show_diff_controls_key)
        show_tab = True
        if self._search_active and self._search.has_query():
            # the filter text is not repeated here: the filter line shows it
            search_hint = f" | Find: '{self._search.query}' {self._search.counter_text()}"
        else:
            search_hint = ""
        find_focused = self._search_active and self.focused is self.find_input
        filter_focused = self.focused is self.filter_input
        self.tips.update(
            snapshot_tips(
                show_diff_controls=show_diff_controls,
                show_tab=show_tab,
                find_focused=find_focused,
                search_hint=search_hint,
                filter_focused=filter_focused,
            )
        )

    def _sync_input_row(self) -> None:
        """Show the find line in place of the filter while find is open; no filter for a lone document.

        The row keeps its height, so the panels below do not move. The footer follows, because
        ``check_action`` hides Filter (/) while the row belongs to find or the list is hidden.
        """
        self.find_input.display = self._search_active
        self.filter_input.display = not self._search_active and not self._diff_maximized
        self.refresh_bindings()

    def _set_maximized(self, maximized: bool) -> None:
        """The document fills the panel (``-maximized`` on the main panel) or the split is back."""
        self.main_panel.set_class(maximized, "-maximized")
        self._sync_input_row()

    def _toggle_panes(self) -> None:
        """Tab and Shift+Tab: list and filter on one side, document and find line on the other.

        Explicit, not ``screen.focus_next()``: the inputs would become Tab stops and make it a
        three-stop cycle. Neither input is ever one; ``/`` and typing are the ways into the
        filter. With the document maximised the list is hidden, so the document keeps the focus.
        """
        focused = self.focused
        if self._diff_maximized:
            target = self.diff_view
        elif focused is self.diff_view or focused is self.find_input:
            target = self.table
        elif self.diff_view.can_focus:
            target = self.diff_view
        else:
            target = self.table
        try:
            target.focus()
        except Exception:
            pass
        self._update_tips()

    def action_focus_next(self) -> None:
        """Move focus on; the footer flags follow in ``on_descendant_focus``, once the focus has moved."""
        self._toggle_panes()

    def action_focus_previous(self) -> None:
        """Shift+Tab: with two panes it is the same toggle as Tab."""
        self._toggle_panes()

    def on_descendant_focus(self, event: events.DescendantFocus) -> None:
        """Refresh the focus-dependent flags (footer keys, tips) after any focus change.

        Reading ``has_focus`` right after ``focus_next()`` sees the old state, because Textual
        applies the change when the widget handles its Focus event; this message arrives after.
        """
        self._update_focus_flags()
        self._update_tips()

    def _update_focus_flags(self) -> None:
        try:
            diff_visible = self.diff_view.styles.visibility == "visible"
        except Exception:
            diff_visible = False
        focused = self.focused
        # Enter hint when the list is focused
        self.show_select_key = focused is self.table
        # d/h hints when the document is visible and focused
        self.show_diff_controls_key = bool(diff_visible and focused is self.diff_view)

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        """Hide the bindings that do not apply right now (``False`` removes them from the footer).

        - Maximize and Find need a document on screen.
        - Toggle Select (Enter) is for the list.
        - Filter (/) needs the filter on screen: not while find has its row or the list is hidden.
        """
        if action in ("toggle_maximize_pane", "start_find"):
            return bool(self.show_hide_diff_key)
        if action == "toggle_row":
            return bool(self.show_select_key)
        if action == "focus_filter":
            return not self._search_active and not self._diff_maximized
        return super().check_action(action, parameters)

    def action_toggle_help(self) -> None:
        """Show or hide Textual's help panel: the focused widget's help and the active keys."""
        if self.query("HelpPanel"):
            self.app.action_hide_help_panel()
        else:
            self.app.action_show_help_panel()

    def _activate_diff_document(self, document_id: str) -> str:
        if document_id != self._current_diff_document_id:
            self._search.reset()
            self.find_input.value = ""  # a different document starts a fresh search
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
        """Key tracing for ``CN_TUI_DEBUG_KEYS``; the keys themselves are bindings and ``Input`` widgets."""
        if self._debug_keys:
            try:
                self.logr.debug(
                    "app.on_key(snapshot): key=%s focus=%s pane_focus=%s table_focus=%s",
                    getattr(event, 'key', None),
                    getattr(self.focused, 'id', None),
                    getattr(self.diff_view, 'has_focus', None),
                    getattr(self.table, 'has_focus', None),
                )
            except Exception:
                pass

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
        self._set_maximized(False)
        self._diff_has_content = False
        self._current_diff_document_id = ""
        self._close_find()
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

    def action_back_out(self) -> None:
        """Esc, in one order: close find, restore a maximised document, clear the filter, hide the
        document and its selection, then go back to the repositories.

        A focused filter line has already cleared itself and handed the focus to the list
        (its own Esc binding), so that step never gets here.
        """
        if self._search_active:
            self.action_cancel_find()
        elif self._diff_maximized:
            self._set_maximized(False)
        elif not self.clear_filter():
            self.action_hide_diff()

    def action_go_back(self) -> None:
        # Clear filter on leaving the snapshot view
        self.clear_filter()
        self.post_message(self.Closed(back=True))

    def _on_filter_changed(self) -> None:
        self._render_rows()
        if self.filter_input.value != self._filter_text:
            # cleared from outside (Esc on the list, leaving the view): the line follows
            self.filter_input.value = self._filter_text

    def action_focus_filter(self) -> None:
        """/ : into the filter line, cursor at the end of what is there."""
        self.filter_input.cursor_position = len(self.filter_input.value)
        self.filter_input.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        """A character typed (or deleted) in the filter or the find line.

        The current value is read, not the event's: a burst of keys queues several events and
        an old one must not write an old value back.
        """
        event.stop()
        if event.input is self.filter_input:
            self.set_filter_text(self.filter_input.value)
        elif event.input is self.find_input:
            self._find_query_changed()

    def on_filter_input_accepted(self, event: FilterInput.Accepted) -> None:
        event.stop()
        self._toggle_highlighted_row()

    def on_find_input_next(self, event: FindInput.Next) -> None:
        event.stop()
        self.action_find_next()

    def on_find_input_previous(self, event: FindInput.Previous) -> None:
        event.stop()
        self.action_find_prev()

    def on_find_input_closed(self, event: FindInput.Closed) -> None:
        event.stop()
        self.action_cancel_find()

    def action_quit(self) -> None:
        self.post_message(self.Closed(back=False))

    # Screen-level pane navigation actions (guaranteed routing)
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
        if not self.table.has_focus:
            self.logr.debug("toggle_row: table not focused; ignoring")
            return
        self._toggle_highlighted_row()

    def _toggle_highlighted_row(self) -> None:
        """Select or deselect the row under the cursor (what Enter does on the list or in the filter)."""
        table = self.table
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
        try:
            idx = _LAYOUTS.index(self.app.layout)  # type: ignore[attr-defined]
        except ValueError:
            idx = 0
        self.app.layout = _LAYOUTS[(idx + 1) % len(_LAYOUTS)]  # type: ignore[attr-defined]
        self._apply_layout()

    def action_toggle_maximize_pane(self) -> None:
        if not self._diff_has_content:
            return
        self._set_maximized(not self._diff_maximized)
        if self._diff_maximized:
            # the list is hidden: the focus has to be on the document
            self.diff_view.focus()

    # ---- Find support ----
    def action_start_find(self) -> None:
        """Open the find line in the filter's row and focus it; starting again clears the query."""
        if not self._diff_has_content:
            return
        self._search_active = True
        self._search.reset()
        self.find_input.value = ""
        try:
            self.diff_view.apply_search()
        except Exception:
            pass
        self._sync_input_row()
        self.find_input.focus()
        self._update_tips()

    def _close_find(self) -> None:
        """Leave find: no query, no highlights, the filter row is back. The focus is the caller's."""
        if not self._search_active:
            return
        self._search_active = False
        self._search.reset()
        self.find_input.value = ""
        try:
            self.diff_view.apply_search()
        except Exception:
            pass
        self._sync_input_row()

    def action_cancel_find(self) -> None:
        """Esc in find: close it and give the focus back to the searched document."""
        if not self._search_active:
            return
        self._close_find()
        (self.diff_view if self.diff_view.can_focus else self.table).focus()
        self._update_tips()

    def _find_query_changed(self) -> None:
        """The find line was edited: search for what it holds and show the first hit."""
        query = self.find_input.value
        if not self._search_active or query == self._search.query:
            return
        self._search.set_query(query)
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


class CommitSelectorApp(App):
    """Single-screen App around ``SnapshotScreen``; the upstream public name and constructor survive.

    - ``view`` is the screen, pushed when the app mounts;
    - ``layout`` is the layout preference the screen reads and writes (``app.layout``);
    - ``navigate_back`` is set when the user asked to go back to the repository browser.
    """

    TITLE = "ConfigAnalyzer"
    SUB_TITLE = f"v{__version__} — Snapshot History"

    def __init__(self, snapshots_data: list[Snapshot], scroll_to_end: bool = False, layout: str = "right"):
        super().__init__()
        self.layout = layout
        self.navigate_back: bool = False
        self.view = SnapshotScreen(snapshots_data, scroll_to_end)

    async def on_mount(self) -> None:
        await self.push_screen(self.view)

    def on_snapshot_screen_closed(self, event: SnapshotScreen.Closed) -> None:
        event.stop()
        self.navigate_back = event.back
        self.exit()
