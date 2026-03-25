from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Sequence, Tuple

from rich.text import Text


Match = Tuple[int, int, int]  # (line_index, start_col, end_col)


@dataclass
class TextDocument:
    """Exact line-based document model for scroll/search rendering."""

    document_id: str = ""
    plain_lines: List[str] = field(default_factory=list)
    styled_lines: List[Text] = field(default_factory=list)
    width: int = 0

    @classmethod
    def empty(cls) -> "TextDocument":
        return cls()

    @classmethod
    def from_text(cls, content: Text | str, *, document_id: str = "") -> "TextDocument":
        if isinstance(content, str):
            text = Text(content, no_wrap=True)
        else:
            text = content.copy()
        return cls.from_lines(list(text.split("\n", allow_blank=True)), document_id=document_id)

    @classmethod
    def from_lines(
        cls,
        lines: Sequence[Text | str],
        *,
        document_id: str = "",
    ) -> "TextDocument":
        if not lines:
            return cls(document_id=document_id)

        styled_lines: List[Text] = []
        plain_lines: List[str] = []
        width = 0
        for line in lines:
            text_line = Text(str(line), no_wrap=True) if isinstance(line, str) else line.copy()
            text_line.no_wrap = True
            styled_lines.append(text_line)
            plain_lines.append(text_line.plain)
            width = max(width, text_line.cell_len)
        return cls(
            document_id=document_id,
            plain_lines=plain_lines,
            styled_lines=styled_lines,
            width=width,
        )


@dataclass
class SearchController:
    """Stateful controller for find-in-text across a list of visible lines."""

    query: str = ""
    matches: List[Match] = field(default_factory=list)
    current: int = -1
    _lines: List[str] = field(default_factory=list)

    def reset(self) -> None:
        self.query = ""
        self.matches.clear()
        self.current = -1

    def set_lines(self, lines: List[str]) -> None:
        self._lines = list(lines or [])
        self._recompute_matches()

    def set_query(self, query: str) -> None:
        self.query = query or ""
        self._recompute_matches()

    def append_char(self, ch: str) -> None:
        if not ch:
            return
        self.set_query(self.query + ch)

    def backspace(self) -> None:
        if not self.query:
            return
        self.set_query(self.query[:-1])

    def has_query(self) -> bool:
        return bool(self.query)

    def has_matches(self) -> bool:
        return bool(self.matches)

    def next(self) -> Match | None:
        if not self.matches:
            return None
        if self.current < len(self.matches) - 1:
            self.current += 1
        elif self.current == -1:
            self.current = 0
        return self.matches[self.current] if self.current >= 0 else None

    def prev(self) -> Match | None:
        if not self.matches:
            return None
        if self.current > 0:
            self.current -= 1
        elif self.current == -1 and self.matches:
            self.current = len(self.matches) - 1
        return self.matches[self.current] if self.current >= 0 else None

    def current_match(self) -> Match | None:
        if self.current < 0 or self.current >= len(self.matches):
            return None
        return self.matches[self.current]

    def counter(self) -> Tuple[int, int]:
        if not self.matches:
            return (0, 0)
        return (self.current + 1 if self.current >= 0 else 0, len(self.matches))

    def counter_text(self) -> str:
        a, b = self.counter()
        return f"{a}/{b}" if b else "0/0"

    def build_highlighted_lines(
        self,
        base_lines: Sequence[Text] | None = None,
        *,
        highlight_all: bool = True,
    ) -> List[Text]:
        if base_lines is None:
            rendered = [Text(line, no_wrap=True) for line in self._lines]
        else:
            rendered = [line.copy() for line in base_lines]

        if not self.query:
            return rendered

        by_line: dict[int, List[Tuple[int, int, bool]]] = {}
        active = self.current_match()
        for line_index, start, end in self.matches:
            is_current = bool(
                active
                and active[0] == line_index
                and active[1] == start
                and active[2] == end
            )
            by_line.setdefault(line_index, []).append((start, end, is_current))

        for line_index, line in enumerate(rendered):
            line.no_wrap = True
            for start, end, is_current in by_line.get(line_index, []):
                if not highlight_all and not is_current:
                    continue
                s = max(0, min(start, len(line.plain)))
                e = max(s, min(end, len(line.plain)))
                if e > s:
                    line.stylize("black on yellow" if is_current else "dim on yellow", s, e)
        return rendered

    def build_text(self, highlight_all: bool = True) -> Text:
        lines = self.build_highlighted_lines(highlight_all=highlight_all)
        out = Text()
        for index, line in enumerate(lines):
            out.append(line)
            if index < len(lines) - 1:
                out.append("\n")
        return out

    def _recompute_matches(self) -> None:
        query = (self.query or "").lower()
        previous_match = self.current_match()
        self.matches = []
        if not query:
            self.current = -1
            return

        query_len = len(query)
        for line_index, line in enumerate(self._lines or []):
            if not line:
                continue
            haystack = line.lower()
            start = 0
            while True:
                pos = haystack.find(query, start)
                if pos < 0:
                    break
                self.matches.append((line_index, pos, pos + query_len))
                start = pos + max(query_len, 1)

        if not self.matches:
            self.current = -1
            return

        if previous_match and previous_match in self.matches:
            self.current = self.matches.index(previous_match)
            return

        if 0 <= self.current < len(self.matches):
            return

        self.current = 0
