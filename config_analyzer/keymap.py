from textual.binding import Binding


# Centralized, per-view default key bindings.
# Views can import the builder function for their context to get Binding lists.


def browser_bindings() -> list[Binding]:
    return [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("enter", "enter_selected", "Enter/Open"),
        Binding("right", "enter_selected", "Enter/Open"),
        Binding("left", "go_up", "Up"),
        Binding("alt+up", "go_up", "Up"),
        Binding("ctrl+l", "toggle_layout", "Toggle Layout"),
        Binding("escape", "clear_filter", "", show=False),
        Binding("home", "cursor_home", "First"),
        Binding("end", "cursor_end", "Last"),
    ]


def snapshot_bindings(show_hide_diff_key, show_focus_next_key, show_select_key, show_diff_controls_key) -> list[Binding]:
    """Build bindings for the snapshot selector view.

    Accepts reactive flags from the app for dynamic visibility.
    """
    return [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("enter", "toggle_row", "Toggle Select", show=show_select_key),
        Binding("tab", "focus_next", "Switch Panel"),
        Binding("escape", "hide_diff", "Back / Hide Diff", show=show_hide_diff_key),
        Binding("home", "cursor_home", "First"),
        Binding("end", "cursor_end", "Last"),
        Binding("ctrl+l", "toggle_layout", "Toggle Layout"),
    ]
