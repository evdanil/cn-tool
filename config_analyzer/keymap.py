from textual import events
from textual.binding import Binding
from textual.widgets import Input


# Centralized, per-view default key bindings.
# Views can import the builder function for their context to get Binding lists.
#
# Every binding carries a description: Textual's HelpPanel lists bindings by it, including the
# ones hidden from the footer (show=False).

# The printable keys a list view binds itself. They are never typed into the quick filter from
# the list: ``z`` maximises the document, ``/`` focuses the filter and ``?`` opens the help panel.
# The set is fixed and stateless on purpose. Deciding by ``screen.active_bindings`` would make
# ``z`` type in one state (no document shown, binding hidden) and maximise in another, and
# ``j``/``k``/space would steal the first letter of ``kul...`` or ``jdoe`` (those scroll keys
# now live on the document panes, so every other letter reaches the filter). A filter that
# starts with z, / or ? needs / first.
RESERVED_KEYS: frozenset[str] = frozenset({"z", "slash", "question_mark"})


def forward_printable(event: events.Key, filter_input: Input) -> bool:
    """Type a printable key from a list into its filter ``Input``; True when it was taken.

    Call it from the list's ``on_key``. The character goes in at the end of the filter, the
    ``Input`` takes the focus and the event stops here, so the rest of the word (bound letters
    included) is typed into the ``Input`` itself. Keys in ``RESERVED_KEYS`` are left to the
    bindings, and so is every key while the filter is not on screen (the find line has taken
    its row, or the list is hidden).
    """
    if not event.is_printable or event.key in RESERVED_KEYS or not filter_input.display:
        return False
    assert event.character is not None  # is_printable says so
    filter_input.cursor_position = len(filter_input.value)
    filter_input.insert_text_at_cursor(event.character)
    filter_input.focus()
    event.stop()
    event.prevent_default()
    return True


def browser_bindings() -> list[Binding]:
    """Build bindings for the repository browser view.

    All of them are declared as always available; the app hides the ones that do not apply right
    now in ``check_action`` (Maximize and Find without a document, Filter while the find line or a
    maximised preview has the screen).

    Escape runs ``back_out``: close find, restore a maximised preview, clear an active filter. It
    never leaves the browser (a focused ``FilterInput`` clears itself first). Ctrl+Q quits at once.
    """
    return [
        Binding("question_mark", "toggle_help", "Help"),
        Binding("slash", "focus_filter", "Filter"),
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+f", "start_find", "Find"),
        Binding("alt+f", "start_find", "Find", show=False),
        Binding("z", "toggle_maximize_pane", "Maximize"),
        Binding("enter", "enter_selected", "Enter/Open"),
        Binding("right", "enter_selected", "Enter/Open"),
        Binding("left", "go_up", "Up"),
        Binding("alt+up", "go_up", "Up"),
        Binding("ctrl+l", "toggle_layout", "Toggle Layout"),
        Binding("escape", "back_out", "Close Find / Restore / Clear Filter", show=False),
        Binding("home", "cursor_home", "First"),
        Binding("end", "cursor_end", "Last"),
    ]


def snapshot_bindings() -> list[Binding]:
    """Build bindings for the snapshot selector view.

    All of them are declared as always available. The app hides the ones that do not apply
    right now in ``check_action`` (Maximize and Find without a document, Toggle Select unless
    the list has the focus, Filter while the find line or a maximised document has the screen);
    Textual then drops them from ``active_bindings`` and the footer.

    Escape runs ``back_out``: close find, restore a maximised document, clear an active filter,
    hide the document, go back (a focused ``FilterInput`` clears itself first).
    """
    return [
        Binding("question_mark", "toggle_help", "Help"),
        Binding("slash", "focus_filter", "Filter"),
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+f", "start_find", "Find"),
        Binding("alt+f", "start_find", "Find", show=False),
        Binding("z", "toggle_maximize_pane", "Maximize"),
        Binding("enter", "toggle_row", "Toggle Select"),
        Binding("tab", "focus_next", "Switch Panel"),
        Binding("escape", "back_out", "Back / Hide Diff"),
        Binding("home", "cursor_home", "First"),
        Binding("end", "cursor_end", "Last"),
        Binding("ctrl+l", "toggle_layout", "Toggle Layout"),
    ]
