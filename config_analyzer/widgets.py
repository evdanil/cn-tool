from __future__ import annotations

from io import StringIO
import os
from typing import Any, List, Optional

from rich.console import Console
from rich.text import Text
from textual import events
from textual.geometry import Size
from textual.scroll_view import ScrollView
from textual.strip import Strip

from .debug import get_logger
from .search import SearchController, TextDocument


class SearchableTextPane(ScrollView, can_focus=True):
    """Scrollable line-based text pane with deterministic search rendering."""

    DEFAULT_CSS = """
    SearchableTextPane {
        overflow-y: scroll;
        overflow-x: auto;
        background: $surface;
        color: $foreground;
    }
    SearchableTextPane:focus {
        background-tint: $foreground 5%;
    }
    """

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        wrap: bool = False,
        highlight: bool = False,
        auto_scroll: bool = False,
    ) -> None:
        del highlight
        super().__init__(id=id)
        self._wrap = wrap
        self._auto_scroll = auto_scroll
        self._debug_keys = bool(os.environ.get("CN_TUI_DEBUG_KEYS"))
        self._logr = get_logger("pane")
        self._document: TextDocument = TextDocument.empty()
        self._lines: List[str] = []
        self._render_lines: List[Text] = []
        self._line_cache: dict[tuple[int, int, int, int], Strip] = {}
        self._render_version = 0
        self.search: Optional[SearchController] = None

    @property
    def document_id(self) -> str:
        return self._document.document_id

    def notify_style_update(self) -> None:
        super().notify_style_update()
        self._line_cache.clear()

    def on_mouse_down(self, event: events.MouseDown) -> None:  # type: ignore[override]
        self.focus()
        event.stop()

    def on_click(self, event: events.Click) -> None:  # type: ignore[override]
        self.focus()
        event.stop()

    def on_mouse_scroll_up(self, event: events.MouseScrollUp) -> None:  # type: ignore[override]
        self.action_page_up()
        event.stop()

    def on_mouse_scroll_down(self, event: events.MouseScrollDown) -> None:  # type: ignore[override]
        self.action_page_down()
        event.stop()

    def set_document(self, document: TextDocument) -> None:
        previous_id = self._document.document_id
        self._document = document
        self._lines = list(document.plain_lines)
        if self.search is not None:
            if previous_id and previous_id != document.document_id:
                self.search.reset()
            self.search.set_lines(document.plain_lines)
        self.apply_search()

    def set_lines(self, lines: List[str], *, document_id: str = "") -> None:
        self.set_document(TextDocument.from_lines(lines, document_id=document_id))

    def set_text(self, text: str, *, document_id: str = "") -> None:
        self.set_document(TextDocument.from_text(text, document_id=document_id))

    def set_base_text(
        self,
        base_text: Text,
        raw_text: Optional[str] = None,
        *,
        document_id: str = "",
    ) -> None:
        del raw_text
        self.set_document(TextDocument.from_text(base_text, document_id=document_id))

    def set_renderable(
        self,
        renderable: Any,
        *,
        base_text: Optional[Text] = None,
        raw_text: Optional[str] = None,
        document_id: str = "",
    ) -> None:
        del raw_text
        if base_text is None:
            base_text = self._renderable_to_text(renderable)
        self.set_document(TextDocument.from_text(base_text, document_id=document_id))

    def clear(self) -> None:
        self._document = TextDocument.empty()
        self._lines = []
        self._render_lines = []
        self._render_version += 1
        self._line_cache.clear()
        self.virtual_size = Size(0, 0)
        self.refresh()

    def apply_search(self) -> None:
        if self.search is not None:
            self.search.set_lines(self._document.plain_lines)
        if self.search and self.search.has_query():
            self._render_lines = self.search.build_highlighted_lines(self._document.styled_lines)
        else:
            self._render_lines = [line.copy() for line in self._document.styled_lines]

        width = max((line.cell_len for line in self._render_lines), default=0)
        self._render_version += 1
        self._line_cache.clear()
        self.virtual_size = Size(width, len(self._render_lines))
        self.refresh()
        if self._auto_scroll:
            self.scroll_end(animate=False, immediate=True, x_axis=False)

    def _render_width(self) -> int:
        width = 0
        try:
            width = int(getattr(self.scrollable_content_region, "width", 0) or 0)
        except Exception:
            width = 0
        if not width:
            try:
                width = int(getattr(self.size, "width", 0) or 0)
            except Exception:
                width = 0
        return max(width, 80)

    def _renderable_to_text(self, renderable: Any) -> Text:
        if isinstance(renderable, Text):
            return renderable.copy()
        buf = StringIO()
        console = Console(
            file=buf,
            force_terminal=True,
            color_system="truecolor",
            legacy_windows=False,
            width=self._render_width(),
        )
        console.print(renderable, end="")
        return Text.from_ansi(buf.getvalue())

    def render_line(self, y: int) -> Strip:
        scroll_x, scroll_y = self.scroll_offset
        strip = self._render_line(scroll_y + y, scroll_x, self.scrollable_content_region.width)
        return strip.apply_style(self.rich_style)

    def _render_line(self, y: int, scroll_x: int, width: int) -> Strip:
        if y >= len(self._render_lines):
            return Strip.blank(width, self.rich_style)

        key = (y, scroll_x, width, self._render_version)
        cached = self._line_cache.get(key)
        if cached is not None:
            return cached

        line = self._render_lines[y]
        strip = Strip(line.render(self.app.console), line.cell_len)
        cropped = strip.crop_extend(scroll_x, scroll_x + width, self.rich_style)
        self._line_cache[key] = cropped
        return cropped

    def get_scroll_y(self) -> int:
        try:
            return int(getattr(self.scroll_offset, "y", 0) or 0)
        except Exception:
            return 0

    def scroll_to_y(self, target: int) -> None:
        self.scroll_to(y=max(0, int(target)), animate=False, immediate=True)

    def action_scroll_up(self) -> None:  # type: ignore[override]
        super().action_scroll_up()

    def action_scroll_down(self) -> None:  # type: ignore[override]
        super().action_scroll_down()

    def action_page_up(self) -> None:  # type: ignore[override]
        super().action_page_up()

    def action_page_down(self) -> None:  # type: ignore[override]
        super().action_page_down()

    def action_go_home(self) -> None:  # type: ignore[override]
        self.scroll_home(animate=False, immediate=True)

    def action_go_end(self) -> None:  # type: ignore[override]
        self.scroll_end(animate=False, immediate=True)

    def scroll_match_into_view(self, *, center: bool = True) -> None:
        if not (self.search and self.search.has_matches()):
            return
        match = self.search.current_match()
        if match is None:
            return
        line_index, _start, _end = match
        height = getattr(self.size, "height", 0) or 1
        target = line_index
        if center and height > 0:
            target = max(0, line_index - max(height // 2, 0))
        self.scroll_to(y=target, animate=False, immediate=True)

    def on_key(self, event: events.Key) -> None:  # type: ignore[override]
        if self._debug_keys:
            self._logr.debug(
                "pane.on_key: id=%s key=%s char=%s focus=%s",
                getattr(self, "id", None),
                getattr(event, "key", None),
                getattr(event, "character", None),
                getattr(self, "has_focus", None),
            )
