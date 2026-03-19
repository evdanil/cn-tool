from __future__ import annotations

from typing import Any


class FilterMixin:
    """Reusable quick-filter behavior for Textual apps with a DataTable.

    Host class should implement:
    - self.table: a widget with .has_focus
    - _on_filter_changed(self): re-render rows and update tips
    """

    _filter_text: str = ""

    def filter_active(self) -> bool:
        return bool(getattr(self, "_filter_text", ""))

    def get_filter_hint(self) -> str:
        ft = getattr(self, "_filter_text", "")
        return f" | Filter: '{ft}' (Esc=clear)" if ft else ""

    def clear_filter(self) -> None:
        if getattr(self, "_filter_text", ""):
            self._filter_text = ""
            self._on_filter_changed()

    # Public helpers for widgets to invoke directly via actions
    def filter_backspace(self) -> None:
        if getattr(self, "_filter_text", ""):
            self._filter_text = self._filter_text[:-1]
            self._on_filter_changed()

    def filter_append_char(self, ch: str) -> None:
        if not ch:
            return
        self._filter_text = getattr(self, "_filter_text", "") + ch
        self._on_filter_changed()

    def _on_filter_changed(self) -> None:
        """Hook for host to refresh rows + tips. Overridden by host app."""
        pass

    def process_filter_key(self, event: Any, require_table_focus: bool = True) -> bool:
        """Handle printable, backspace, escape for quick filter.

        Returns True if the event was consumed and should not propagate.
        """
        # Optionally only when the table has focus
        if require_table_focus:
            try:
                if not getattr(self, "table", None) or not self.table.has_focus:
                    return False
            except Exception:
                return False

        k = getattr(event, "character", None) or getattr(event, "key", None)
        ctrl = getattr(event, "ctrl", False)
        alt = getattr(event, "alt", False)
        meta = getattr(event, "meta", False)

        # Printable single-character keys become part of filter
        if isinstance(k, str) and len(k) == 1 and k.isprintable() and not (ctrl or alt or meta):
            self._filter_text = getattr(self, "_filter_text", "") + k
            self._on_filter_changed()
            return True

        # Robust backspace handling across terminals/platforms
        if k in ("backspace", "ctrl+h", "\b"):
            if getattr(self, "_filter_text", ""):
                self._filter_text = self._filter_text[:-1]
                self._on_filter_changed()
                return True

        if k == "escape":
            if getattr(self, "_filter_text", ""):
                self._filter_text = ""
                self._on_filter_changed()
                return True

        return False
