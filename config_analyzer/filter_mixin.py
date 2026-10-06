from __future__ import annotations


class FilterMixin:
    """Quick-filter state shared by the list views.

    The text is typed into a ``FilterInput`` (an ``Input``); the host forwards ``Input.Changed``
    to ``set_filter_text`` and clears the filter through ``clear_filter``.

    Host class should implement:
    - _on_filter_changed(self): re-render rows and update tips
    """

    _filter_text: str = ""

    def filter_active(self) -> bool:
        return bool(getattr(self, "_filter_text", ""))

    def set_filter_text(self, text: str) -> None:
        """Replace the filter text (what a ``FilterInput`` holds); notify the host when it changed."""
        text = text or ""
        if text != getattr(self, "_filter_text", ""):
            self._filter_text = text
            self._on_filter_changed()

    def clear_filter(self) -> bool:
        """Drop the filter; True when there was one to drop."""
        if getattr(self, "_filter_text", ""):
            self._filter_text = ""
            self._on_filter_changed()
            return True
        return False

    def _on_filter_changed(self) -> None:
        """Hook for host to refresh rows + tips. Overridden by host app."""
        pass
