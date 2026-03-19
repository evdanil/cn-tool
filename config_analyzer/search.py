from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple
from rich.text import Text


Match = Tuple[int, int, int]  # (line_index, start_col, end_col)


@dataclass
class SearchController:
    """Stateful controller for find-in-text across a list of lines.

    - Tracks the current query, list of matches, and the active match index.
    - Provides helpers to mutate the query and navigate next/prev.
    - Builds a Rich Text renderable with spans for highlighting.
    """

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
        # Don't wrap around - stop at last match
        if self.current < len(self.matches) - 1:
            self.current += 1
        elif self.current == -1:
            # Special case: if we haven't selected anything yet, go to first match
            self.current = 0
        return self.matches[self.current] if self.current >= 0 else None

    def prev(self) -> Match | None:
        if not self.matches:
            return None
        # Don't wrap around - stop at first match
        if self.current > 0:
            self.current -= 1
        elif self.current == -1 and self.matches:
            # Special case: if we haven't selected anything yet, go to last match
            self.current = len(self.matches) - 1
        return self.matches[self.current] if self.current >= 0 else None

    def current_match(self) -> Match | None:
        if self.current < 0 or self.current >= len(self.matches):
            return None
        return self.matches[self.current]

    def counter(self) -> Tuple[int, int]:
        """Return (current_index_1_based, total_matches)."""
        if not self.matches:
            return (0, 0)
        return (self.current + 1 if self.current >= 0 else 0, len(self.matches))

    def counter_text(self) -> str:
        a, b = self.counter()
        return f"{a}/{b}" if b else "0/0"

    def build_text(self, highlight_all: bool = True) -> Text:
        """Build a Rich Text renderable with highlighted matches.

        - All matches get a base 'search' style.
        - The active match (if any) is emphasized with 'search.current'.
        """
        lines = self._lines or []
        if not lines:
            return Text("")
        if not self.query:
            return Text("\n".join(lines))

        # Organize matches by line for easy application
        by_line: dict[int, List[Tuple[int, int, bool]]] = {}
        active = self.current_match()
        for i, start, end in self.matches:
            cur = bool(active and active[0] == i and active[1] == start and active[2] == end)
            by_line.setdefault(i, []).append((start, end, cur))

        out = Text()
        for i, line in enumerate(lines):
            segment = Text(line)
            if i in by_line:
                for start, end, is_current in by_line[i]:
                    style = "black on yellow" if is_current else "dim on yellow"
                    if highlight_all or is_current:
                        # Clip to line bounds defensively
                        s = max(0, min(start, len(line)))
                        e = max(s, min(end, len(line)))
                        if e > s:
                            try:
                                segment.stylize(style, s, e)
                            except Exception:
                                pass
            out.append(segment)
            if i < len(lines) - 1:
                out.append("\n")
        return out

    # Internal helpers
    def _recompute_matches(self) -> None:
        q = (self.query or "").lower()
        prev_match = self.current_match()
        self.matches = []
        if not q:
            self.current = -1
            return
        for i, line in enumerate(self._lines or []):
            if not line:
                continue
            hay = line.lower()
            start = 0
            qlen = len(q)
            while True:
                pos = hay.find(q, start)
                if pos < 0:
                    break
                self.matches.append((i, pos, pos + qlen))
                # Advance by 1 to catch overlapping results logically
                start = pos + max(qlen, 1)
        if not self.matches:
            self.current = -1
            return
        if prev_match and prev_match in self.matches:
            try:
                self.current = self.matches.index(prev_match)
                return
            except ValueError:
                pass
        if 0 <= self.current < len(self.matches):
            return
        # Auto-select first match when search starts
        self.current = 0
