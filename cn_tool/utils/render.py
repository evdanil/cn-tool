"""Render a result (section title -> rows) as a table, JSON, Markdown or CSV text.

``render`` returns the text, ``emit`` writes it to stdout. The human formats (table, md, csv)
skip sections without rows; JSON keeps every section key. Every non-empty output ends with
exactly one newline.
"""
import csv
import errno
import io
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, TextIO

from rich.console import Console

from cn_tool.core.base import ScriptContext
from cn_tool.utils import oscompat
from cn_tool.utils.display import build_tables, table_columns

FORMATS = ("table", "json", "md", "csv")

Data = Dict[str, List[Dict[str, Any]]]


def markdown_table(headers: List[str], rows: List[List[Any]]) -> str:
    """A GitHub-style Markdown table; cells are stringified, ``|`` and newlines are escaped."""
    if not rows:
        return "_No data._"
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
        safe = [str(cell).replace("|", "\\|").replace("\n", "<br/>") for cell in row]
        lines.append("| " + " | ".join(safe) + " |")
    return "\n".join(lines)


def snake_key(key: str) -> str:
    """``"IP address"`` -> ``"ip_address"``: the stable spelling of a JSON key."""
    return re.sub(r"\W+", "_", key).strip("_").lower()


def _render_table(ctx: ScriptContext, data: Data, color: bool, width: Optional[int]) -> str:
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=color, width=width, emoji=False)
    for index, table in enumerate(build_tables(ctx, data)):
        if index:
            console.print()
        console.print(table)
    return buffer.getvalue()


def _render_json(data: Data) -> str:
    payload = {
        snake_key(title): [{snake_key(key): value for key, value in row.items()} for row in rows]
        for title, rows in data.items()
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n"


def _render_md(data: Data) -> str:
    blocks = []
    for title, rows in data.items():
        columns = table_columns(rows)
        cells = [["" if row.get(column) is None else row[column] for column in columns] for row in rows]
        body = markdown_table(columns, cells)
        blocks.append(f"## {title.upper()}\n\n{body}")
    return "\n\n".join(blocks) + "\n"


def _render_csv(data: Data) -> str:
    columns = table_columns([row for rows in data.values() for row in rows])
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["section", *columns])
    for title, rows in data.items():
        for row in rows:
            writer.writerow([title, *(row.get(column) for column in columns)])
    return buffer.getvalue()


def render(ctx: ScriptContext, data: Data, fmt: str, *, color: bool = False, width: Optional[int] = None) -> str:
    """
    Render ``data`` in ``fmt`` (one of ``FORMATS``).

    JSON is the scripting contract: every section key is kept, even with no rows, and section and
    column keys are normalised with ``snake_key`` (a later duplicate key within a row wins); an
    empty ``data`` gives ``{}``. The other formats skip sections without rows and print nothing
    when none is left. ``color`` and ``width`` only affect the table format.
    """
    if fmt not in FORMATS:
        raise ValueError(f"unsupported format {fmt!r}; expected one of {', '.join(FORMATS)}")
    if fmt == "json":
        return _render_json(data)
    data = {title: rows for title, rows in data.items() if rows}
    if not data:
        return ""
    if fmt == "table":
        return _render_table(ctx, data, color, width).rstrip("\n") + "\n"
    if fmt == "md":
        return _render_md(data)
    return _render_csv(data)


def emit(ctx: ScriptContext, data: Data, fmt: str, *, out: Optional[TextIO] = None, color: Optional[bool] = None) -> None:
    """Write ``render(...)`` to ``out`` (default: the current stdout); colour only for a terminal without NO_COLOR."""
    out = sys.stdout if out is None else out
    if color is None:
        color = out.isatty() and not os.environ.get("NO_COLOR")
    try:
        out.write(render(ctx, data, fmt, color=color))
        out.flush()
    except OSError as error:
        # The reader went away (cn ... | head): nothing more to say on stdout, and the interpreter
        # must not trip over the same pipe again when it flushes at exit. Windows reports a write to a
        # closed pipe as OSError EINVAL, not BrokenPipeError.
        if not (isinstance(error, BrokenPipeError) or (oscompat.is_windows() and error.errno == errno.EINVAL)):
            raise
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, out.fileno())
        os.close(devnull)
