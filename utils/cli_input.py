"""Collect the objects a command-line run works on: arguments, a ``--file`` and/or stdin."""
import sys
from typing import Iterable, List, Optional, Sequence, TextIO

STDIN_MARKER = "-"


def _tokens(lines: Iterable[str]) -> List[str]:
    """Whitespace-separated tokens of each line, with ``# comments`` and blank lines dropped."""
    tokens: List[str] = []
    for line in lines:
        tokens.extend(line.split("#", 1)[0].split())
    return tokens


def read_objects(objects: Sequence[str], file: Optional[str], *, stdin: Optional[TextIO] = None) -> List[str]:
    """
    Objects named on the command line, then those in ``file``; the first occurrence of each wins.

    A ``-`` argument, or ``file == "-"``, reads stdin (the current ``sys.stdin`` unless one is
    given), once, even when both are used. A ``-`` argument is replaced by the stdin objects
    where it stands; ``--file -`` puts them after the arguments. File and stdin text is split
    into whitespace-separated tokens after dropping ``# comments`` and blank lines.

    Raises:
        OSError: ``file`` cannot be read, or is not UTF-8 text.
    """
    stdin_objects: List[str] = []
    if STDIN_MARKER in objects or file == STDIN_MARKER:
        stream = sys.stdin if stdin is None else stdin
        # A piped file may carry a UTF-8 BOM; files opened here use utf-8-sig, stdin cannot.
        stdin_objects = _tokens(stream.read().removeprefix("﻿").splitlines())

    collected: List[str] = []
    for obj in objects:
        collected.extend(stdin_objects if obj == STDIN_MARKER else [obj])

    if file == STDIN_MARKER:
        collected.extend(stdin_objects)
    elif file:
        with open(file, encoding="utf-8-sig") as handle:
            try:
                collected.extend(_tokens(handle))
            except UnicodeDecodeError as exc:
                raise OSError(f"{file}: not UTF-8 text") from exc

    return list(dict.fromkeys(collected))
