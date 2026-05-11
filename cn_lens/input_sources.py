import csv
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class RawInputSource:
    kind: Literal["literal", "stdin", "file"]
    value: str | Path


def extract_ordered_input_sources(
    args: Sequence[str],
    *,
    file_options: set[str],
    value_options: set[str],
) -> list[RawInputSource]:
    sources: list[RawInputSource] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            sources.extend(RawInputSource("literal", value) for value in args[index + 1 :])
            break
        if token in file_options:
            if index + 1 < len(args):
                sources.append(RawInputSource("file", args[index + 1]))
            index += 2
            continue
        if token.startswith("--file="):
            sources.append(RawInputSource("file", token.split("=", 1)[1]))
            index += 1
            continue
        if token.startswith("-f") and token != "-f":
            sources.append(RawInputSource("file", token[2:]))
            index += 1
            continue
        if token in value_options:
            index += 2
            continue
        if any(token.startswith(f"{option}=") for option in value_options):
            index += 1
            continue
        if token == "-":
            sources.append(RawInputSource("stdin", token))
        elif not token.startswith("-"):
            sources.append(RawInputSource("literal", token))
        index += 1

    return sources


def collect_raw_inputs(
    positionals: Iterable[str],
    files: Iterable[Path | str] = (),
    csv_column: str | None = None,
    stdin_text: str | None = None,
) -> list[str]:
    sources: list[RawInputSource] = []
    for item in positionals:
        if item == "-":
            sources.append(RawInputSource("stdin", item))
        else:
            sources.append(RawInputSource("literal", item))
    for file_path in files:
        sources.append(RawInputSource("file", file_path))

    return collect_raw_inputs_from_sources(
        sources,
        csv_column=csv_column,
        stdin_text=stdin_text,
    )


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
