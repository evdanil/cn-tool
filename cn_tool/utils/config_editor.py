"""
Edit one ``.cn`` file in place: the Settings page of the web interface (``cn_tool/webui/settings_page.py``).

Pure apart from ``load_document`` and ``save_document``, which read and write the one file. The edit is a line edit,
never a ``configparser`` round trip: comments, blank lines, the order of the keys, the keys no schema knows and the
spelling of every line that is not changed stay as they were. A changed key is rewritten on its own line; a key that is
not yet in the file goes under its commented example (``# key = value``, as ``cn init`` writes them) or at the end of
its section; a key that is cleared is removed, so a lower layer or the default applies again. The new text is parsed
again before it is written, and nothing is written unless every key reads back exactly as intended.

The page never sees a password: ``SECRET_KEYS`` are neither listed nor written (their lines are kept as they are),
and ``HIDDEN_KEYS`` are internal settings that are not offered either.
"""
from __future__ import annotations

import configparser
import errno
import hashlib
import os
import re
import stat
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from cn_tool.utils.config import SECTION_ALIASES, is_env_name, parse_optional_bool

# Settings that hold a secret: never listed, read back or written by the editor.
SECRET_KEYS = frozenset({"email_password"})
# Internal settings that are not offered: changing [cache] version discards the configuration cache.
HIDDEN_KEYS = frozenset({"cache_version"})
# Regex settings, with the placeholders their templates take (validation.py renders them the same way). At run time
# an invalid one silently falls back to the default, so the editor refuses it instead.
REGEX_KEYS: Dict[str, Tuple[str, ...]] = {
    "site_code_pattern": (),
    "site_comment_pattern": ("site",),
    "site_hostname_pattern": ("site", "site_compact", "country"),
    "device_name_filter": (),
}
_BOM = "﻿"
_KEY_LINE = re.compile(r"^(?P<name>[^\s#;\[][^=:]*?)\s*[=:]")
_EXAMPLE_LINE = re.compile(r"^[#;]\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=")
_SECTION_LINE = re.compile(r"^\[(?P<name>[^\]]+)\]")
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f\x85\u2028\u2029]")  # every control character but tab
_NO_DEFAULT_SECTION = "\x00cn-editor"  # parse [DEFAULT] as a section of its own: its keys are not set elsewhere
_SAVE_LOCK = threading.Lock()  # two tabs of one cn-web save one at a time
_API_URL = "API_URL"  # the schema's "not configured" stand-in for [api] endpoint; it is never shown as a default

Change = Tuple[str, str]  # (section, ini_key)


class ConfigChanged(Exception):
    """The file changed on disk after it was loaded: the page reloads it rather than overwrite someone's edit."""


class ConfigEditRefused(Exception):
    """The edit cannot be made safely (the file does not parse, or a key would not read back as intended)."""


@dataclass(frozen=True)
class Field:
    """One editable setting: where it lives in the file, how it is typed, and what to tell the reader about it."""
    key: str
    section: str
    ini_key: str
    type: str
    default: str
    help: str = ""
    example: str = ""
    choices: Tuple[str, ...] = ()
    label: str = ""
    common: bool = False
    regex: Optional[Tuple[str, ...]] = None


@dataclass
class Document:
    """One configuration file as loaded: its text (None when it does not exist) and the raw values it sets."""
    path: Path
    text: Optional[str]
    digest: Optional[str]
    values: Dict[Change, str] = field(default_factory=dict)
    problem: str = ""
    section_names: frozenset = frozenset()  # every section of the file, [DEFAULT] and empty ones included

    @property
    def exists(self) -> bool:
        return self.text is not None


# --- The catalogue -----------------------------------------------------------------------------------------------

def _display_default(spec: Mapping[str, Any]) -> str:
    fallback = spec.get("fallback")
    if fallback is None or fallback == _API_URL:
        return ""
    if isinstance(fallback, bool):
        return "true" if fallback else "false"
    if isinstance(fallback, (list, tuple)):
        return ",".join(str(item) for item in fallback)
    return str(fallback)


def template_notes(text: str) -> Dict[Change, Tuple[str, str]]:
    """
    The explanation and the example value of each key of a template, from its comments.

    An explanation is the run of comment lines just above a key's first line (a commented example ``# key = value``
    or an active ``key = value``), up to a blank line or another key; ``cn_tool/sample.cn`` puts every explanation
    there. The example is the value of the key's first commented example. A comment ``# key: text`` is explanation.
    """
    notes: Dict[Change, Tuple[str, str]] = {}
    section = ""
    pending: List[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        header = _SECTION_LINE.match(line)
        if header:
            section, pending = header.group("name").strip(), []
            continue
        if not line:
            pending = []
            continue
        example = _EXAMPLE_LINE.match(line)
        active = None if line[0] in "#;" else _KEY_LINE.match(line)
        if example or active:
            name = (example or active).group("name").strip().lower()
            value = line[example.end():].strip() if example else ""
            if (section, name) not in notes:
                notes[(section, name)] = (" ".join(pending), value)
            elif value and not notes[(section, name)][1]:
                notes[(section, name)] = (notes[(section, name)][0], value)
            pending = []
            continue
        if line[0] in "#;":
            pending.append(line.lstrip("#;").strip())
    return notes


def settings_fields(schema: Mapping[str, Mapping[str, Any]], template: str = "",
                    curated: Sequence[Mapping[str, Any]] = ()) -> List[Field]:
    """
    Every setting the page offers, grouped by section in the template's order (sections it lacks follow).

    ``schema`` is the merged schema (``collect_plugin_schemas(BASE_CONFIG_SCHEMA)``): a plugin's ``help`` and
    ``choices`` refine the base entry. ``curated`` is what the terminal Setup offers (``collect_plugin_settings()``):
    those settings are ``common`` and take its ``prompt`` as their label; any other is labelled by its INI key.
    A secret (``SECRET_KEYS``), an internal setting (``HIDDEN_KEYS``) and an entry without a section are left out.
    """
    notes = template_notes(template)
    prompts = {str(entry["key"]): str(entry.get("prompt") or "") for entry in curated if entry.get("key")}
    order = []
    for raw in template.splitlines():
        header = _SECTION_LINE.match(raw.strip())
        if header and header.group("name").strip() not in order:
            order.append(header.group("name").strip())
    fields: List[Field] = []
    for key, spec in schema.items():
        if key in SECRET_KEYS or key in HIDDEN_KEYS or not isinstance(spec, Mapping) or not spec.get("section") or not spec.get("ini_key"):
            continue
        section, ini_key = str(spec["section"]), str(spec["ini_key"]).lower()
        explanation, example = notes.get((section, ini_key), ("", ""))
        fields.append(Field(
            key=key, section=section, ini_key=ini_key, type=str(spec.get("type", "str")),
            default=_display_default(spec), help=str(spec.get("help") or explanation), example=example,
            choices=tuple(str(choice) for choice in spec.get("choices") or ()),
            label=prompts.get(key) or ini_key, common=key in prompts, regex=REGEX_KEYS.get(key),
        ))
    rank = {name: index for index, name in enumerate(order)}
    return sorted(fields, key=lambda item: rank.get(item.section, len(rank)))


# --- Validation --------------------------------------------------------------------------------------------------

def _regex_problem(item: Field, text: str) -> str:
    sample = {name: "X" for name in item.regex or ()}
    try:
        re.compile(text.format(**sample) if item.regex else text, re.IGNORECASE)
    except re.error:
        return "is not a valid regular expression"
    except (KeyError, IndexError, ValueError, AttributeError, TypeError):
        names = ", ".join("{" + name + "}" for name in item.regex)
        return f"is not a valid template: use {names} and a valid regular expression"
    return ""


def validate_value(item: Field, raw: Optional[str]) -> Tuple[Optional[str], str]:
    """
    ``(value, "")`` for the text to write, or ``(None, problem)``; ``None`` in is ``(None, "")`` (not set).

    An empty value is written as ``key =`` (it overrides a lower file, and ``[ssh] config_file`` reads it as "off")
    for text, path and list settings; a number, a boolean or a choice cannot be empty. The problem never repeats the
    value.
    """
    if raw is None:
        return None, ""
    text = str(raw)
    if "\n" in text or "\r" in text:
        return None, "must fit on one line"
    if _CONTROL.search(text):
        return None, "must not contain control characters"
    text = text.strip()
    if item.type == "bool":
        if not text:
            return None, "choose true or false, or remove the setting"
        flag = parse_optional_bool(text)
        if flag is None:
            return None, "must be true or false"
        return ("true" if flag else "false"), ""
    if item.type == "int":
        if not text:
            return None, "enter a whole number, or remove the setting"
        try:
            number = int(text)
        except ValueError:
            return None, "must be a whole number"
        if number < 0:
            return None, "must not be negative"
        return str(number), ""
    if item.choices:
        if not text:
            return None, "choose a value, or remove the setting"
        lowered = [choice.lower() for choice in item.choices]
        if text.lower() not in lowered:
            return None, "must be one of: " + ", ".join(item.choices)
        return item.choices[lowered.index(text.lower())], ""
    if not text and not empty_allowed(item):
        return None, "cannot be empty: remove the setting instead"
    if item.type == "list[str]":
        return ",".join(part.strip() for part in text.split(",") if part.strip()), ""
    if not text:
        return "", ""
    if item.section == "auth" and not is_env_name(text):
        return None, ("must name an environment variable (ASCII letters, digits and _, not starting with a digit), "
                      "never hold a password")
    if item.key == "api_endpoint" and not re.match(r"^https?://\S+$", text, re.IGNORECASE):
        return None, "must be an http:// or https:// URL"
    if item.type == "path":
        try:
            expanded = Path(text).expanduser()
        except RuntimeError:  # cn expands it when it starts and would stop there
            return None, "starts with ~ and a user name this computer does not know"
        directory = item.ini_key == "directory" or item.ini_key.endswith("_directory")
        try:
            folder = not directory and expanded.is_dir()
        except (OSError, ValueError):
            folder = False
        if folder:  # cn would open it as a file and stop at start
            return None, "names a folder: give a file name"
    if item.regex is not None:
        problem = _regex_problem(item, text)
        if problem:
            return None, problem
    return text, ""


def empty_allowed(item: Field) -> bool:
    """
    Whether ``key =`` is a meaningful value: text and lists, and a path with no default (empty is "not set").

    A path with a default is read as the current directory when it is empty, so it is removed instead.
    """
    if item.type == "path":
        return not item.default
    return item.type in ("str", "list[str]") and not item.choices


def path_note(item: Field, value: Optional[str]) -> str:
    """A note (never a refusal) when a path setting points into a folder that does not exist yet."""
    if item.type != "path" or not value:
        return ""
    try:
        path = Path(value).expanduser()
        folder = path if item.ini_key == "directory" or item.ini_key.endswith("_directory") else path.parent
        missing = not folder.is_dir()
    except (OSError, RuntimeError, ValueError):  # ~nosuchuser, an embedded NUL: validation names the value
        return ""
    return f"The folder {folder} does not exist yet." if missing else ""


# --- Reading -----------------------------------------------------------------------------------------------------

def _digest(data: Optional[bytes]) -> Optional[str]:
    return None if data is None else hashlib.sha256(data).hexdigest()


def _parse(text: str) -> configparser.ConfigParser:
    """The file's own keys, section by section: ``[DEFAULT]`` is one more section, never copied into the others."""
    parser = configparser.ConfigParser(interpolation=None, default_section=_NO_DEFAULT_SECTION)
    parser.read_string(text[1:] if text.startswith(_BOM) else text)
    return parser


def _lines(text: str) -> List[str]:
    """Split as configparser reads a string: at "\\n" only (``str.splitlines`` also splits at form feeds and more)."""
    return [line for line in re.split(r"(?<=\n)", text) if line]


def _values(parser: configparser.ConfigParser) -> Dict[Change, str]:
    values: Dict[Change, str] = {}
    for section in parser.sections():
        for name in parser.options(section):
            values[(section, name)] = parser.get(section, name, raw=True)
    return values


def file_value(document: Document, item: Field) -> Optional[str]:
    """The raw value this file sets for ``item`` (its own section first, then an alias, as ``read_config``)."""
    for section in [item.section] + SECTION_ALIASES.get(item.section, []):
        if (section, item.ini_key) in document.values:
            return document.values[(section, item.ini_key)]
    return None


def _read_bytes(path: Path) -> Optional[bytes]:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def target_path(path: Path) -> Path:
    """The file to write: a symlink is followed, so the link stays a link."""
    return Path(os.path.realpath(path))


def load_document(path: Path) -> Document:
    """Read ``path`` (UTF-8, with or without a byte-order mark). A file that does not parse comes back with ``problem``."""
    try:
        data = _read_bytes(target_path(path))
    except OSError as exc:
        return Document(path=path, text="", digest="unreadable",
                        problem=f"The file cannot be read ({exc.strerror or exc.__class__.__name__}). "
                                "Check that it is a file you may read, then reload.")
    if data is None:
        return Document(path=path, text=None, digest=None)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return Document(path=path, text="", digest=_digest(data),
                        problem="The file is not UTF-8 text. Save it as UTF-8, then reload.")
    try:
        parser = _parse(text)
        values = _values(parser)
    except configparser.Error as exc:
        first = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        return Document(path=path, text=text, digest=_digest(data),
                        problem=f"The file does not parse ({first}). Correct it in a text editor, then reload.")
    return Document(path=path, text=text, digest=_digest(data), values=values,
                    section_names=frozenset(parser.sections()))


# --- The line edit -----------------------------------------------------------------------------------------------

def _newline(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def _sections(lines: Sequence[str]) -> List[Tuple[str, int, int]]:
    """(name, header index, end index) of each section; the end is the index after its last line."""
    found: List[Tuple[str, int, int]] = []
    for index, line in enumerate(lines):
        header = None if line[:1].isspace() else _SECTION_LINE.match(line.strip())
        if header:
            if found:
                found[-1] = (found[-1][0], found[-1][1], index)
            found.append((header.group("name").strip(), index, len(lines)))
    return found


def _continuation_end(lines: Sequence[str], start: int, end: int) -> int:
    index = start + 1
    while index < end and lines[index][:1].isspace() and lines[index].strip():
        index += 1
    return index


def _key_line(name: str, value: str, newline: str) -> str:
    return f"{name} = {value}{newline}" if value else f"{name} ={newline}"


def _apply_one(lines: List[str], section: str, ini_key: str, value: Optional[str], newline: str) -> None:
    span = next((item for item in _sections(lines) if item[0] == section), None)
    if span is None:
        if value is None:
            return
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += newline
        if lines and lines[-1].strip():
            lines.append(newline)
        lines.extend([f"[{section}]{newline}", _key_line(ini_key, value, newline)])
        return
    _, header, end = span
    example_at = None
    for index in range(header + 1, end):
        line = lines[index]
        if line[:1].isspace():
            continue
        active = _KEY_LINE.match(line)
        if active and active.group("name").strip().lower() == ini_key:
            stop = _continuation_end(lines, index, end)
            if value is None:
                del lines[index:stop]
            else:
                lines[index:stop] = [_key_line(active.group("name").strip(), value, newline)]
            return
        example = _EXAMPLE_LINE.match(line.strip())
        if example and example.group("name").lower() == ini_key:
            example_at = index
    if value is None:
        return
    if example_at is not None:
        at = example_at + 1
    else:
        at = end
        while at > header + 1 and not lines[at - 1].strip():
            at -= 1
    if at > 0 and not lines[at - 1].endswith(("\n", "\r")):
        lines[at - 1] += newline
    lines.insert(at, _key_line(ini_key, value, newline))


def apply_changes(text: str, changes: Mapping[Change, Optional[str]]) -> str:
    """
    ``text`` with each ``(section, ini_key)`` set to its value, or removed for None; every other line unchanged.

    Raises ``ConfigEditRefused`` unless the result parses and every key reads back as intended, the changed keys
    with their new values and every other key as before.
    """
    bom = text.startswith(_BOM)
    body = text[1:] if bom else text
    newline = _newline(body)
    lines = _lines(body)
    try:
        before = _values(_parse(body))
    except configparser.Error as exc:
        raise ConfigEditRefused("The file does not parse; correct it in a text editor.") from exc
    expected = dict(before)
    for (section, ini_key), value in changes.items():
        if value is not None and ("\n" in value or "\r" in value or value != value.strip()):
            raise ConfigEditRefused(f"[{section}] {ini_key} must fit on one line.")
        _apply_one(lines, section, ini_key, value, newline)
        if value is None:
            expected.pop((section, ini_key), None)
        else:
            expected[(section, ini_key)] = value
    result = "".join(lines)
    try:
        after = _values(_parse(result))
    except configparser.Error as exc:
        raise ConfigEditRefused("The change would leave the file unreadable; edit it in a text editor.") from exc
    if after != expected:
        wrong = sorted({key for key in set(after) | set(expected) if after.get(key) != expected.get(key)})
        names = ", ".join(f"[{section}] {name}" for section, name in wrong[:3])
        raise ConfigEditRefused(f"The file's layout keeps {names} from being changed safely; edit it in a text editor.")
    return (_BOM if bom else "") + result


# --- Writing -----------------------------------------------------------------------------------------------------

def _write_new(path: Path, data: bytes) -> None:
    """Create ``path`` (never overwrite it), private to the user as ``cn init`` makes it."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _replace(path: Path, data: bytes) -> None:
    """Replace ``path`` in one step, keeping its permission bits; a failed write leaves the old file."""
    mode = stat.S_IMODE(path.stat().st_mode)
    if not mode & stat.S_IWUSR:  # read-only on purpose (on Windows, the read-only attribute): never replace it
        raise PermissionError(errno.EACCES, "The file is read-only", str(path))
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".cn-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        try:
            Path(temporary).unlink(missing_ok=True)
        except OSError:
            pass  # the write's own error is the one to report
        raise


def save_document(document: Document, changes: Mapping[Change, Optional[str]], template: str) -> Document:
    """
    Write ``changes`` to ``document``'s file and return the file as now loaded.

    A file that does not exist is created from ``template`` (the text ``cn init`` writes, with the platform's line
    ends) and then edited. Raises ``ConfigChanged`` when the file is no longer what was loaded (another editor saved
    it, or it was created or removed), ``ConfigEditRefused`` when the edit cannot be made safely, ``OSError`` when it
    cannot be written.
    """
    if any(key in SECRET_KEYS for key in changes):  # pragma: no cover - the page never offers one
        raise ConfigEditRefused("A secret cannot be written here.")
    with _SAVE_LOCK:
        return _save(document, changes, template)


def _save(document: Document, changes: Mapping[Change, Optional[str]], template: str) -> Document:
    path = target_path(document.path)
    current = _read_bytes(path)
    if _digest(current) != document.digest:
        raise ConfigChanged("The file changed on disk after it was loaded.")
    if current is None:
        base = template.replace("\r\n", "\n").replace("\n", os.linesep)
        _write_new(path, apply_changes(base, changes).encode("utf-8"))
    else:
        try:
            text = current.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigEditRefused("The file is not UTF-8 text.") from exc
        new_text = apply_changes(text, changes)
        if new_text != text:
            _replace(path, new_text.encode("utf-8"))
    return load_document(document.path)


def changed_values(fields: Iterable[Field], document: Document,
                   entered: Mapping[str, Optional[str]]) -> Tuple[Dict[Change, Optional[str]], Dict[str, str]]:
    """
    The edits among ``entered`` and the problems, by field key.

    ``entered`` maps a field key to the text of its box, or to None when the setting is not to be in this file. A box
    equal to the file's value (or an equivalent spelling of it) is no change, even when the file's own value would not
    pass validation; None over a key that the file sets removes it; text over a key it does not set adds it. The
    change is keyed by the field's own section, and a copy of the key in an alias section is removed with it.
    """
    changes: Dict[Change, Optional[str]] = {}
    problems: Dict[str, str] = {}
    for item in fields:
        if item.key not in entered:
            continue
        raw, current = entered[item.key], file_value(document, item)
        if raw is None:
            if current is None:
                continue
            value = None
        else:
            if current is not None and raw.strip() == current.strip():
                continue
            value, problem = validate_value(item, raw)
            if problem:
                problems[item.key] = problem
                continue
            if current is not None:
                shown, unreadable = validate_value(item, current)
                if not unreadable and value == shown:
                    continue
        changes[(item.section, item.ini_key)] = value
        for alias in SECTION_ALIASES.get(item.section, []):
            if (alias, item.ini_key) in document.values:
                changes[(alias, item.ini_key)] = None
    return changes, problems


def inherited_values(fields: Iterable[Field], documents: Sequence[Document],
                     target: Optional[Document] = None) -> Dict[str, Tuple[str, Any]]:
    """
    What each setting is when the edited file does not set it: ``(value, source)`` as ``read_config`` reads
    ``documents`` (the files before it, in order) and ``target`` (the edited file) as one, without ``target``'s own
    values in its sections. A later file overrides an earlier one, a section's own value beats a ``[DEFAULT]`` value,
    a setting's own section is read before an alias, and a ``[DEFAULT]`` key applies to every section that exists in
    any of the files. The source is the file that holds the value, or ``"[DEFAULT] in <file>"``. A setting none of
    them sets keeps its default and is left out.
    """
    values: Dict[Change, Tuple[str, Any]] = {}
    defaults: Dict[str, Tuple[str, Any]] = {}
    sections = set()
    for document in [*documents, *([target] if target is not None else [])]:
        for (section, name), value in document.values.items():
            if section == "DEFAULT":
                defaults[name] = (value, f"[DEFAULT] in {document.path}")
            elif document is not target:
                values[(section, name)] = (value, document.path)
        sections |= set(document.section_names) - {"DEFAULT"}
    found: Dict[str, Tuple[str, Any]] = {}
    for item in fields:
        for section in [item.section] + SECTION_ALIASES.get(item.section, []):
            if (section, item.ini_key) in values:
                found[item.key] = values[(section, item.ini_key)]
                break
            if section in sections and item.ini_key in defaults:
                found[item.key] = defaults[item.ini_key]
                break
    return found


def overlay_header(earlier: Sequence[Path]) -> str:
    """
    The start of a new file that overlays existing ones: a comment, then only the keys set on the page. The template
    is not copied into it, because its live placeholder values would override the earlier files.
    """
    names = ", ".join(str(path) for path in earlier)
    return ("# Written by the cn-web Settings page.\n"
            f"# {names} {'is' if len(earlier) == 1 else 'are'} read first; a setting here overrides it there.\n")
