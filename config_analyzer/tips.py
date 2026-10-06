def browser_tips(
    search_hint: str = "",
    preview_focused: bool = False,
    filter_focused: bool = False,
    find_focused: bool = False,
) -> str:
    """Format tips line for the repository browser view.

    ``?=help`` comes first so a narrow terminal cannot cut it off; letter keys are written in
    lower case (Shift+Z is the different key "Z"). The filter text is not part of it: the filter
    ``Input`` shows what was typed.

    search_hint: the find counter (``" | Find: 'x' 1/2"``), appended while find has a query.
    preview_focused: the preview pane has the focus (Enter does nothing there).
    filter_focused: the filter line has the focus. It types ``?`` and ``/``, so neither key is offered.
    find_focused: the find line has the focus, so Enter/Down/Up/Esc move through the matches
        (``?`` is typed there too, so no ``?=help``).
    """
    if find_focused:
        base = "Tips: Enter/Down=next, Up=prev, Esc=close find, Ctrl+Q=quit"
    elif filter_focused:
        base = "Tips: Up/Down=move, Enter=open, Tab=preview, Esc=clear filter, Ctrl+Q=quit"
    elif preview_focused:
        # When preview pane is focused, Enter doesn't do anything (unless in search mode)
        if search_hint:
            # In search mode, show search-specific tips
            base = "Tips: ?=help, /=filter, z=max, Ctrl+L=layout, Tab=back to list, Ctrl+Q=quit"
        else:
            base = "Tips: ?=help, /=filter, Ctrl+F/Alt+F=find, z=max, Ctrl+L=layout, Tab=back to list, Ctrl+Q=quit"
    else:
        # Table is focused - Enter opens/navigates
        base = (
            "Tips: ?=help, /=filter, Enter=open, Left/Alt+Up=up, Ctrl+F/Alt+F=find, z=max, "
            "Ctrl+L=layout, Home/End=jump, Ctrl+Q=quit"
        )
    return base + (search_hint or "")


def snapshot_tips(
    show_diff_controls: bool = False,
    show_tab: bool = True,
    find_focused: bool = False,
    search_hint: str = "",
    filter_focused: bool = False,
) -> str:
    """Format tips line for the snapshot selector view.

    The filter text is not part of it: the filter ``Input`` shows what was typed.

    show_diff_controls: include d/h hints only when diff panel is the active focus.
    show_tab: include Tab hint only when switching panels is relevant.
    find_focused: the find line has the focus, so Enter/Down/Up/Esc move through the matches
        (it types ``?``, so no ``?=help``).
    search_hint: the find counter (``" | Find: 'x' 1/2"``), appended while find is open.
    filter_focused: the filter line has the focus. It types ``?`` and ``/``, so neither key is offered.
    """
    if find_focused:
        base = "Tips: Enter/Down=next, Up=prev, Esc=close find, Ctrl+Q=quit"
    elif filter_focused:
        parts = ["Tips: Up/Down=move", "Enter=select"]
        if show_tab:
            parts.append("Tab=switch")
        parts.extend(["Esc=clear filter", "Ctrl+Q=quit"])
        base = ", ".join(parts)
    else:
        parts = ["Tips: ?=help", "/=filter", "Enter=select"]
        if show_tab:
            parts.append("Tab=switch")
        parts.extend(["Ctrl+L=layout", "Ctrl+F/Alt+F=find", "z=max"])
        if show_diff_controls:
            parts.extend(["d=diff", "h=hide"])
        parts.extend(["Esc=back/hide", "Ctrl+Q=quit"])
        base = ", ".join(parts)
    return base + (search_hint or "")
