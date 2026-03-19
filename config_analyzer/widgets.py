from __future__ import annotations

from typing import List, Optional, Any
import os
import inspect
import asyncio

from textual.app import ComposeResult
from textual.widgets import RichLog
from textual.containers import Container
from textual import events
from .debug import get_logger

from .search import SearchController


class SearchableTextPane(RichLog):
    """A scrollable text pane that supports external search highlighting.

    Based on RichLog which properly handles scrolling. The parent App is expected
    to own the SearchController, handle query state, and call `apply_search()`
    after content/query changes.
    """

    DEFAULT_CSS = """
    SearchableTextPane {
        overflow-y: scroll;
        overflow-x: auto;
    }
    """

    def __init__(self, *, id: Optional[str] = None, wrap: bool = False, highlight: bool = False, auto_scroll: bool = False) -> None:
        # RichLog parameters: wrap, highlight, markup, auto_scroll, max_lines
        super().__init__(id=id, wrap=wrap, highlight=highlight, markup=False, auto_scroll=auto_scroll, max_lines=None)
        self._wrap = wrap
        # Ensure the widget is focusable
        try:
            self.can_focus = True  # type: ignore[assignment]
        except Exception:
            pass
        self._debug_keys = bool(os.environ.get("CN_TUI_DEBUG_KEYS"))
        self._logr = get_logger("pane")
        self._lines: List[str] = []
        self._base_text = None  # type: Optional["Text"]
        self._renderable: Optional[Any] = None
        # The app will attach a SearchController instance
        self.search: Optional[SearchController] = None

    # Mouse focus & scroll helpers
    def on_mouse_down(self, event: events.MouseDown) -> None:  # type: ignore[override]
        from .utils import safe_call
        safe_call(self.focus)
        safe_call(event.stop)

    def on_click(self, event: events.Click) -> None:  # type: ignore[override]
        # Some Textual versions dispatch Click; handle both
        from .utils import safe_call
        safe_call(self.focus)
        safe_call(event.stop)

    def on_mouse_scroll_up(self, event: events.MouseScrollUp) -> None:  # type: ignore[override]
        from .utils import safe_call
        safe_call(self.action_page_up)
        safe_call(event.stop)

    def on_mouse_scroll_down(self, event: events.MouseScrollDown) -> None:  # type: ignore[override]
        from .utils import safe_call
        safe_call(self.action_page_down)
        safe_call(event.stop)

    def on_focus(self) -> None:  # type: ignore[override]
        pass

    def on_blur(self) -> None:  # type: ignore[override]
        pass

    # ---- Content management ----
    def set_lines(self, lines: List[str]) -> None:
        self._lines = list(lines or [])
        self._base_text = None
        self._renderable = None
        if self.search:
            self.search.set_lines(self._lines)
        self.apply_search()

    def set_text(self, text: str) -> None:
        self.set_lines((text or "").splitlines())

    def set_base_text(self, base_text: "Text", raw_text: str) -> None:
        """Set a pre-styled base Text and raw content for search overlay."""
        self._base_text = base_text
        self._renderable = None
        self._lines = (raw_text or "").splitlines()
        if self.search:
            self.search.set_lines(self._lines)
        self.apply_search()

    def set_renderable(self, renderable: Any, *, base_text: Optional["Text"] = None, raw_text: Optional[str] = None) -> None:
        """Set a generic renderable (e.g., Rich Table) and optional search base.

        If search is active and a base_text is provided, the pane will render
        the highlighted Text overlay instead of the raw renderable.
        """
        self._renderable = renderable
        self._base_text = base_text
        if raw_text is not None:
            self._lines = (raw_text or "").splitlines()
            if self.search:
                self.search.set_lines(self._lines)
        self.apply_search()

    def clear(self) -> None:
        self._lines = []
        self._base_text = None
        self._renderable = None
        # Clear RichLog content
        try:
            super().clear()
        except Exception:
            pass

    # ---- Search helpers ----
    def apply_search(self) -> None:
        # Clear the RichLog before writing new content
        try:
            super().clear()
        except Exception:
            pass

        # Decide what to render based on search/query presence
        has_query = bool(self.search and self.search.has_query())
        if has_query and self.search:
            # Build overlay on top of base_text (if available) else plain text
            from rich.text import Text
            if self._base_text is not None:
                # Copy to avoid mutating original
                out = self._base_text.copy()
            else:
                # If we have a renderable (e.g., Syntax/Table), capture once to Text
                if self._renderable is not None:
                    out = self._renderable_to_text(self._renderable)
                    # Cache as base for subsequent overlays
                    self._base_text = out.copy()
                else:
                    out = Text("\n".join(self._lines))
            # Apply match spans line-by-line
            # Compute absolute offsets per line
            lines = self._lines or []
            # Ensure controller lines are aligned
            self.search.set_lines(lines)
            matches = list(self.search.matches)
            if matches:
                # Use the actual line lengths from the rendered text, not original lines
                # The rendered text may have padding that affects offsets
                rendered_lines = out.plain.split('\n')

                # Precompute cumulative offsets based on rendered text
                cum = 0
                for i, line in enumerate(lines):
                    if i >= len(rendered_lines):
                        break
                    rendered_line_len = len(rendered_lines[i])

                    # Add spans for all matches on this line
                    for (li, start, end) in [m for m in matches if m[0] == i]:
                        try:
                            # Current match style stronger
                            cur = self.search.current_match()
                            is_current = bool(cur and cur[0] == li and cur[1] == start and cur[2] == end)
                            style = "black on yellow" if is_current else "dim on yellow"
                            out.stylize(style, cum + start, cum + end)
                        except Exception:
                            pass
                    # Advance based on rendered line length
                    if i < len(rendered_lines) - 1:
                        cum += rendered_line_len + 1  # +1 for newline
                    else:
                        cum += rendered_line_len
            # Write to RichLog
            self.write(out)
            return

        # No active search overlay
        if self._renderable is not None and not has_query:
            self.write(self._renderable)
            return
        if self._base_text is not None:
            self.write(self._base_text)
            return
        try:
            from rich.text import Text
            self.write(Text("\n".join(self._lines)))
        except Exception:
            # Fallback to plain text
            for line in self._lines:
                self.write_line(line)

    # ---- Utilities ----
    def _renderable_to_text(self, renderable: Any):
        from io import StringIO
        from rich.console import Console
        from rich.text import Text
        buf = StringIO()
        # Don't set a width to avoid padding - let it use the terminal width or default
        console = Console(file=buf, force_terminal=True, color_system="truecolor", legacy_windows=False)
        console.print(renderable, end="")
        return Text.from_ansi(buf.getvalue())

    def _scroll_to_y(self, target: int) -> None:
        """Scroll to a given y offset.

        RichLog inherits from ScrollView and handles scrolling properly.
        """
        if self._debug_keys:
            self._logr.debug("pane._scroll_to_y: id=%s target=%s", getattr(self, 'id', None), target)

        try:
            # RichLog/ScrollView scroll_to method
            self.scroll_to(y=target, animate=False)  # type: ignore[arg-type]
        except Exception as e:
            if self._debug_keys:
                self._logr.debug("pane._scroll_to_y error: %s", e)

        # Log the result
        if self._debug_keys:
            try:
                y_now = self._get_scroll_y()
                self._logr.debug("pane.after_scroll: id=%s y=%s", getattr(self, 'id', None), y_now)
            except Exception:
                pass

    # ---- Scrolling actions (robust fallbacks) ----
    def _get_scroll_y(self) -> int:
        try:
            off = getattr(self, "scroll_offset", None)
            y = getattr(off, "y", 0)
            if self._debug_keys:
                try:
                    self._logr.debug("pane.scroll_y: id=%s y=%s", getattr(self, 'id', None), y)
                except Exception:
                    pass
            return int(y or 0)
        except Exception:
            return 0

    def get_scroll_y(self) -> int:
        """Return the current vertical scroll offset (in rows)."""
        return self._get_scroll_y()

    def scroll_to_y(self, target: int) -> None:
        """Public wrapper to scroll to an absolute y offset."""
        self._scroll_to_y(max(0, int(target)))

    # RichLog already has these actions, no need to override
    # Just add debug logging wrappers
    def action_scroll_up(self) -> None:  # type: ignore[override]
        if self._debug_keys:
            self._logr.debug("pane.action_scroll_up: id=%s", getattr(self, 'id', None))
        super().action_scroll_up()
        if self._debug_keys:
            self._logr.debug("pane.after_scroll_up: y=%s", self._get_scroll_y())

    def action_scroll_down(self) -> None:  # type: ignore[override]
        if self._debug_keys:
            self._logr.debug("pane.action_scroll_down: id=%s", getattr(self, 'id', None))
        super().action_scroll_down()
        if self._debug_keys:
            self._logr.debug("pane.after_scroll_down: y=%s", self._get_scroll_y())

    def action_page_up(self) -> None:  # type: ignore[override]
        if self._debug_keys:
            self._logr.debug("pane.action_page_up: id=%s", getattr(self, 'id', None))
        super().action_page_up()
        if self._debug_keys:
            self._logr.debug("pane.after_page_up: y=%s", self._get_scroll_y())

    def action_page_down(self) -> None:  # type: ignore[override]
        if self._debug_keys:
            self._logr.debug("pane.action_page_down: id=%s", getattr(self, 'id', None))
        super().action_page_down()
        if self._debug_keys:
            self._logr.debug("pane.after_page_down: y=%s", self._get_scroll_y())

    def action_go_home(self) -> None:  # type: ignore[override]
        if self._debug_keys:
            self._logr.debug("pane.go_home: id=%s", getattr(self, 'id', None))
        self.scroll_home(animate=False)
        if self._debug_keys:
            self._logr.debug("pane.after_go_home: y=%s", self._get_scroll_y())

    def action_go_end(self) -> None:  # type: ignore[override]
        if self._debug_keys:
            self._logr.debug("pane.go_end: id=%s", getattr(self, 'id', None))
        self.scroll_end(animate=False)
        if self._debug_keys:
            self._logr.debug("pane.after_go_end: y=%s", self._get_scroll_y())

    def scroll_match_into_view(self, *, center: bool = True) -> None:
        if not (self.search and self.search.has_matches()):
            return
        match = self.search.current_match()
        if not match:
            return
        line_idx, _s, _e = match
        height = getattr(self.size, "height", 0) or 1
        if center and height > 0:
            target = max(0, line_idx - max(height // 2, 0))
        else:
            target = max(0, line_idx)
        try:
            if self._debug_keys:
                self._logr.debug("pane.scroll_match_to: id=%s target_y=%s", getattr(self, 'id', None), target)
                self._logr.debug("pane.scroll_y: id=%s y=%s", getattr(self, 'id', None), self._get_scroll_y())
            # RichLog/ScrollView handles scrolling properly
            self.scroll_to(y=target, animate=False)  # type: ignore[arg-type]
        except Exception as e:
            if self._debug_keys:
                self._logr.debug("pane.scroll_match_error: %s", e)

    # ---- Key handling for search passthrough ----
    def on_key(self, event: events.Key) -> None:  # type: ignore[override]
        # Base pane doesn't handle search; leave it to concrete panes/App
        if self._debug_keys:
            try:
                self._logr.debug(
                    "pane.on_key: id=%s key=%s char=%s shift=%s ctrl=%s focus=%s",
                    getattr(self, 'id', None),
                    getattr(event, 'key', None),
                    getattr(event, 'character', None),
                    getattr(event, 'shift', 'NO_ATTR'),
                    getattr(event, 'ctrl', 'NO_ATTR'),
                    getattr(self, 'has_focus', None),
                )
            except Exception:
                pass
        try:
            return super().on_key(event)  # type: ignore
        except Exception:
            return None
