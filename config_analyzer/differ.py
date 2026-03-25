import difflib
from typing import TYPE_CHECKING, List

from rich.cells import cell_len, set_cell_size
from rich.syntax import Syntax
from rich.text import Text

from .debug import get_logger

if TYPE_CHECKING:
    from .parser import Snapshot


_log = get_logger("diff")


def get_diff(snapshot1: "Snapshot", snapshot2: "Snapshot") -> Syntax:
    """Return a unified diff renderable without line wrapping."""

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
    return Syntax(diff_text, "diff", line_numbers=True, word_wrap=False)


def _fit_cell(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if cell_len(text) <= width:
        return set_cell_size(text, width)
    if width <= 3:
        return set_cell_size(text[:width], width)
    return set_cell_size(text[: width - 3] + "...", width)


def get_diff_side_by_side(
    snapshot1: "Snapshot",
    snapshot2: "Snapshot",
    hide_unchanged: bool = False,
    total_width: int = 160,
) -> Text:
    """Return a fixed-width side-by-side diff as styled plain text."""

    left_lines: List[str] = snapshot1.content_body.splitlines()
    right_lines: List[str] = snapshot2.content_body.splitlines()
    matcher = difflib.SequenceMatcher(None, left_lines, right_lines, autojunk=False)

    divider = " | "
    column_width = max((max(total_width, 60) - len(divider)) // 2, 20)

    _log.debug(
        "get_diff_sbs: %s vs %s, hide_unchanged=%s, len1=%d len2=%d width=%d",
        snapshot1.original_filename,
        snapshot2.original_filename,
        hide_unchanged,
        len(left_lines),
        len(right_lines),
        total_width,
    )

    rendered = Text()
    header = Text()
    header.append(_fit_cell(snapshot1.original_filename, column_width), style="bold")
    header.append(divider, style="dim")
    header.append(_fit_cell(snapshot2.original_filename, column_width), style="bold")
    rendered.append(header)
    rendered.append("\n")

    separator = Text()
    separator.append("-" * column_width, style="dim")
    separator.append(divider, style="dim")
    separator.append("-" * column_width, style="dim")
    rendered.append(separator)

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            if hide_unchanged:
                continue
            pairs = zip(left_lines[i1:i2], right_lines[j1:j2])
            style_pairs = [("", "")]
        elif tag == "replace":
            left_block = left_lines[i1:i2]
            right_block = right_lines[j1:j2]
            pairs = (
                (
                    left_block[index] if index < len(left_block) else "",
                    right_block[index] if index < len(right_block) else "",
                )
                for index in range(max(len(left_block), len(right_block)))
            )
            style_pairs = [("bright_yellow", "bright_yellow")]
        elif tag == "delete":
            pairs = ((line, "") for line in left_lines[i1:i2])
            style_pairs = [("bright_red", "dim")]
        else:
            pairs = (("", line) for line in right_lines[j1:j2])
            style_pairs = [("dim", "bright_green")]

        left_style, right_style = style_pairs[0]
        for left_text, right_text in pairs:
            rendered.append("\n")
            line = Text()
            line.append(_fit_cell(left_text, column_width), style=left_style or None)
            line.append(divider, style="dim")
            line.append(_fit_cell(right_text, column_width), style=right_style or None)
            rendered.append(line)

    return rendered
