import argparse
import csv
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class RawInputSource:
    kind: Literal["literal", "stdin", "file"]
    value: str | Path


def extract_input_sources_from_namespace(
    namespace: argparse.Namespace,
    arg_tokens: Sequence[str],
    extra_positionals: Sequence[str] = (),
) -> list[RawInputSource]:
    """Derive ordered input sources from a parsed argparse namespace.

    Walks *arg_tokens* (the raw tokens passed to the subparser — everything
    after the subcommand name) to recover the interleaved order of positional
    objects and ``--file`` references.  The actual values are taken from the
    *namespace* (``namespace.objects`` and ``namespace.file``) so that option
    values can never leak as phantom input objects regardless of what tokens
    appear in the stream (eliminates bug B2 class without needing a
    ``value_options`` skip-list).

    Parameters
    ----------
    namespace:
        Parsed argparse namespace.  Must have:
        - ``objects``: ``list[str]`` — positional objects in order
          (supports ``nargs="*"``).
        - ``file``: ``list[str]`` — file paths in order
          (supports ``action="append"``).
        Extra attributes (e.g. ``mode``, ``target_site``) are ignored.
    arg_tokens:
        Raw token sequence passed to the subparser (after the subcommand name).
        Used only for ordering — values are taken from *namespace*.
    extra_positionals:
        Additional positional tokens not captured by the namespace (typically
        ``unknown_args`` filtered to non-flag tokens from
        ``parser.parse_known_args``).  With ``nargs="*"``, argparse may place
        positionals that appear *after* options into ``unknown_args`` rather
        than ``namespace.objects``.  Pass those here so that mixed
        positional/option ordering is preserved.

    Returns
    -------
    list[RawInputSource]
        Sources in the order they appear in *arg_tokens*.  A ``"-"``
        positional becomes ``RawInputSource("stdin", "-")``.
    """
    # Take the classified values from the namespace (argparse already validated
    # and separated them — no option-value contamination possible).
    # Merge extra_positionals (from unknown_args) at the end — they appear
    # later in the token stream than namespace.objects, so appending is correct.
    base_objects: list[str] = list(getattr(namespace, "objects", []))
    extra: list[str] = [t for t in extra_positionals if not t.startswith("-") or t == "-"]
    remaining_objects: list[str] = base_objects + extra
    remaining_files: list[str] = list(getattr(namespace, "file", []))

    sources: list[RawInputSource] = []
    index = 0
    tokens = list(arg_tokens)

    while index < len(tokens):
        token = tokens[index]

        if token == "--":
            # Remaining positionals after '--' separator — consume from namespace.
            for _ in range(len(remaining_objects)):
                obj = remaining_objects.pop(0)
                sources.append(RawInputSource("stdin" if obj == "-" else "literal", obj))
            break

        # --file PATH  or  -f PATH
        if token in ("--file", "-f"):
            if remaining_files:
                sources.append(RawInputSource("file", remaining_files.pop(0)))
            index += 2
            continue

        # --file=PATH
        if token.startswith("--file="):
            if remaining_files:
                sources.append(RawInputSource("file", remaining_files.pop(0)))
            index += 1
            continue

        # -fPATH  (compact short form, e.g. -fobjects.txt)
        if token.startswith("-f") and token != "-f":
            if remaining_files:
                sources.append(RawInputSource("file", remaining_files.pop(0)))
            index += 1
            continue

        # Bare '-' is the stdin marker — a special positional, not a flag.
        if token == "-":
            if remaining_objects:
                remaining_objects.pop(0)  # consume the "-" from namespace.objects
                sources.append(RawInputSource("stdin", "-"))
            index += 1
            continue

        # Any other flag token (--foo or -x) — skip; argparse already classified
        # the following value as an option argument, not a positional.
        if token.startswith("-"):
            index += 1
            continue

        # Non-flag token.  Consume the next positional from the namespace if
        # available.  If namespace.objects is exhausted, this token is an
        # option value that argparse consumed (e.g. the value of --mode that
        # appears after a positional in corner-case token streams) — skip it.
        if remaining_objects:
            obj = remaining_objects.pop(0)
            sources.append(RawInputSource("stdin" if obj == "-" else "literal", obj))
        index += 1

    return sources


def collect_raw_inputs_from_sources(
    sources: Iterable[RawInputSource],
    csv_column: str | None = None,
    stdin_text: str | None = None,
) -> list[str]:
    raw_inputs: list[str] = []

    for source in sources:
        if source.kind == "stdin":
            raw_inputs.extend(_non_empty_lines(stdin_text or ""))
        elif source.kind == "literal":
            raw_inputs.append(str(source.value))
        elif source.kind == "file":
            path = Path(source.value)
            if csv_column is None:
                raw_inputs.extend(_non_empty_lines(path.read_text(encoding="utf-8")))
            else:
                raw_inputs.extend(_read_csv_column(path, csv_column))
        else:
            raise ValueError(f"unknown input source kind: {source.kind}")

    return raw_inputs


def _non_empty_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _read_csv_column(path: Path, csv_column: str) -> list[str]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or csv_column not in reader.fieldnames:
            raise ValueError(f"CSV file {path} is missing column {csv_column!r}")

        values: list[str] = []
        for row in reader:
            value = row.get(csv_column)
            if value is None:
                continue

            stripped_value = value.strip()
            if not stripped_value:
                continue

            values.append(stripped_value)

        return values
