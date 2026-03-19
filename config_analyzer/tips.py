def browser_tips(filter_hint: str = "", search_hint: str = "", preview_focused: bool = False) -> str:
    """Format tips line for the repository browser view."""
    if preview_focused:
        # When preview pane is focused, Enter doesn't do anything (unless in search mode)
        if search_hint:
            # In search mode, show search-specific tips
            base = "Tips: Ctrl+L=layout, Tab=back to list, Ctrl+Q=quit"
        else:
            base = "Tips: Ctrl+F=find, Ctrl+L=layout, Tab=back to list, Ctrl+Q=quit"
    else:
        # Table is focused - Enter opens/navigates
        base = "Tips: Enter=open, Left/Alt+Up=up, Ctrl+F=find, Ctrl+L=layout, Home/End=jump, Ctrl+Q=quit"
    return base + (filter_hint or "") + (search_hint or "")


def snapshot_tips(filter_hint: str = "", show_diff_controls: bool = False, show_tab: bool = True, search_hint: str = "") -> str:
    """Format tips line for the snapshot selector view.

    show_diff_controls: include D/H hints only when diff panel is the active focus.
    show_tab: include Tab hint only when switching panels is relevant.
    """
    parts = ["Tips: Enter=select"]
    if show_tab:
        parts.append("Tab=switch")
    parts.extend(["Ctrl+L=layout", "Ctrl+F=find"])
    if show_diff_controls:
        parts.extend(["D=diff", "H=hide"])
    parts.extend(["Esc=back/hide", "Ctrl+Q=quit"])
    return ", ".join(parts) + (filter_hint or "") + (search_hint or "")
