import difflib
from typing import TYPE_CHECKING, List
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich import box
from .debug import get_logger

# Use a forward reference to avoid circular import
if TYPE_CHECKING:
    from .parser import Snapshot

_log = get_logger("diff")
def get_diff(snapshot1: "Snapshot", snapshot2: "Snapshot") -> Syntax:
    """
    Generates a unified diff between the content of two snapshots and wraps it
    in a ``rich.syntax.Syntax`` object for optional colorization.

    Args:
        snapshot1: The first snapshot object.
        snapshot2: The second snapshot object.

    Returns:
        A ``Syntax`` instance containing the diff output.
    """
    lines1 = snapshot1.content_body.splitlines(keepends=True)
    lines2 = snapshot2.content_body.splitlines(keepends=True)

    diff_lines = difflib.unified_diff(
        lines1,
        lines2,
        fromfile=snapshot1.original_filename,
        tofile=snapshot2.original_filename,
        lineterm="",
    )

    diff_text = "".join(diff_lines)
    _log.debug(
        "get_diff: %s vs %s, len1=%d len2=%d diff_chars=%d",
        snapshot1.original_filename,
        snapshot2.original_filename,
        len(lines1),
        len(lines2),
        len(diff_text),
    )
    return Syntax(diff_text, "diff", line_numbers=True, word_wrap=True)
    
def get_diff_side_by_side(snapshot1: "Snapshot", snapshot2: "Snapshot", hide_unchanged: bool = False):
    """
    Generates a side-by-side diff table between two snapshots.

    Left column is snapshot1, right column is snapshot2. Colors:
    - red: deletion (only on left)
    - green: insertion (only on right)
    - yellow: replacement (both sides differ)
    - default: equal
    """
    left_lines: List[str] = snapshot1.content_body.splitlines()
    right_lines: List[str] = snapshot2.content_body.splitlines()

    sm = difflib.SequenceMatcher(None, left_lines, right_lines, autojunk=False)
    _log.debug(
        "get_diff_sbs: %s vs %s, hide_unchanged=%s, len1=%d len2=%d",
        snapshot1.original_filename,
        snapshot2.original_filename,
        hide_unchanged,
        len(left_lines),
        len(right_lines),
    )

    table = Table(
        show_header=True,
        header_style="bold",
        expand=True,
        pad_edge=False,
        show_lines=False,
        show_edge=False,
        box=box.SIMPLE,
    )
    table.add_column(snapshot1.original_filename, overflow="fold", ratio=1)
    table.add_column(snapshot2.original_filename, overflow="fold", ratio=1)

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            if hide_unchanged:
                continue
            for a, b in zip(left_lines[i1:i2], right_lines[j1:j2]):
                table.add_row(Text(a), Text(b))
        elif tag == "replace":
            left_block = left_lines[i1:i2]
            right_block = right_lines[j1:j2]
            max_len = max(len(left_block), len(right_block))
            for k in range(max_len):
                a = left_block[k] if k < len(left_block) else ""
                b = right_block[k] if k < len(right_block) else ""
                # Changed lines should be yellow - use markup instead of style
                # Escape any markup characters in the content
                a_escaped = a.replace("[", r"\[").replace("]", r"\]")
                b_escaped = b.replace("[", r"\[").replace("]", r"\]")
                table.add_row(
                    Text.from_markup(f"[bright_yellow]{a_escaped}[/bright_yellow]"),
                    Text.from_markup(f"[bright_yellow]{b_escaped}[/bright_yellow]")
                )
                _log.debug("Added replace row: left='%s' right='%s' with yellow markup", a[:30], b[:30])
        elif tag == "delete":
            for a in left_lines[i1:i2]:
                # Deleted lines should be red on left, empty on right - use markup
                a_escaped = a.replace("[", r"\[").replace("]", r"\]")
                table.add_row(
                    Text.from_markup(f"[bright_red]{a_escaped}[/bright_red]"),
                    Text("")
                )
                _log.debug("Added delete row: left='%s' with red markup", a[:30])
        elif tag == "insert":
            for b in right_lines[j1:j2]:
                # Inserted lines should be empty on left, green on right - use markup
                b_escaped = b.replace("[", r"\[").replace("]", r"\]")
                table.add_row(
                    Text(""),
                    Text.from_markup(f"[bright_green]{b_escaped}[/bright_green]")
                )
                _log.debug("Added insert row: right='%s' with green markup", b[:30])

    return table
