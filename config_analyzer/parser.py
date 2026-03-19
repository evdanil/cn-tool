import os
import re
from datetime import datetime, timezone
from typing import Optional, NamedTuple, Tuple
from dateutil.parser import parse as date_parse
from .debug import get_logger

# Using a NamedTuple for a lightweight, immutable data structure.
class Snapshot(NamedTuple):
    """Represents a single parsed configuration snapshot."""
    path: str
    author: str
    timestamp: datetime
    content_body: str
    original_filename: str

# Pre-compiled regexes for efficiency.
_CHANGE_CISCO_RE = re.compile(r"^\!\s*Last configuration change at\s*(.*?)\s*by\s*(\S+)\s*$", re.MULTILINE)
_AUTHOR_HEADER_RE = re.compile(r"^(?:[#;!%\s]*)(?:Last\s*Updated\s*By|Updated-?by|Author|Owner|User(?:name)?|Changed-?by)\s*[:=-]\s*(.+)$", re.IGNORECASE)
_DATE_HEADER_RE = re.compile(r"^(?:[#;!%\s]*)(?:Last\s*Updated|Updated|Date|Timestamp)\s*[:=-]\s*(.+)$", re.IGNORECASE)
_FILENAME_DATE_RE = re.compile(r"(\d{4}[-_]?\d{2}[-_]?\d{2}[ T_]?\d{2}[:-]?\d{2}(?:[:-]?\d{2})?)")
_FILENAME_USER_RE = re.compile(r"(?:user[-_])([A-Za-z0-9._-]+)|(?:^|__)by[-_]?([A-Za-z0-9._-]+)", re.IGNORECASE)

_log = get_logger("parser")

def _safe_read(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        _log.debug("safe_read: failed to read %s", path)
        return None

def _safe_read_head(path: str, max_lines: int = 10) -> Optional[str]:
    """Read up to max_lines from a file safely for metadata parsing."""
    try:
        out_lines = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                out_lines.append(line.rstrip("\n"))
        return "\n".join(out_lines)
    except OSError:
        _log.debug("safe_read_head: failed to read %s", path)
        return None

def _extract_metadata_from_text(text: str) -> Tuple[Optional[str], Optional[datetime]]:
    # Cisco-style single line
    m = _CHANGE_CISCO_RE.search(text)
    if m:
        date_str, author = m.groups()
        try:
            ts = date_parse(date_str.replace("GMT", "+0000"))
            return author.strip(), ts
        except Exception:
            # fallthrough to other heuristics
            pass

    # Scan first N lines for generic headers
    head = "\n".join(text.splitlines()[:50])
    author = None
    ts = None
    ma = _AUTHOR_HEADER_RE.search(head)
    if ma:
        author = ma.group(1).strip()
    md = _DATE_HEADER_RE.search(head)
    if md:
        try:
            ts = date_parse(md.group(1).strip())
        except Exception:
            ts = None

    return author, ts

def _extract_metadata_from_filename(filename: str) -> Tuple[Optional[str], Optional[datetime]]:
    author = None
    ts = None
    md = _FILENAME_DATE_RE.search(filename)
    if md:
        try:
            ts = date_parse(md.group(1))
        except Exception:
            ts = None

    mu = _FILENAME_USER_RE.search(filename)
    if mu:
        author = next((g for g in mu.groups() if g), None)
    return author, ts

def parse_snapshot(file_path: str) -> Optional[Snapshot]:
    """
    Parse a configuration file to extract metadata and content heuristically.

    - Attempts Cisco-style header, generic headers, then filename hints.
    - Falls back to file mtime for timestamp and "unknown" for author.
    - Always returns a Snapshot if the file is readable.
    """
    _log.debug("parse_snapshot: start path=%s", file_path)
    full_content = _safe_read(file_path)
    if full_content is None:
        _log.debug("parse_snapshot: unreadable %s", file_path)
        return None

    # Heuristic metadata extraction
    author, ts = _extract_metadata_from_text(full_content)
    if ts is None or author is None:
        # Use filename hints where available
        f_author, f_ts = _extract_metadata_from_filename(os.path.basename(file_path))
        author = author or f_author
        ts = ts or f_ts

    # Fallbacks
    if ts is None:
        try:
            # Use UTC-aware timestamp from file mtime
            ts = datetime.fromtimestamp(os.path.getmtime(file_path), tz=timezone.utc)
        except OSError:
            ts = datetime.now(timezone.utc)
    if author is None:
        author = "unknown"
    _log.debug("parse_snapshot: meta author=%s ts=%s", author, ts)

    # Normalize to timezone-aware UTC for consistent comparisons
    if ts.tzinfo is None or (ts.tzinfo and ts.tzinfo.utcoffset(ts) is None):
        ts = ts.replace(tzinfo=timezone.utc)
    else:
        ts = ts.astimezone(timezone.utc)

    # Determine where the real config body starts; strip common preambles
    lines = full_content.splitlines()
    body_start_index = 0
    for i, line in enumerate(lines):
        # Skip empty lines or common banner/preamble markers
        if not line:
            continue
        if line.startswith(("!", "#", ";", "Building", "Current", "%")):
            continue
        body_start_index = i
        break

    content_body = "\n".join(lines[body_start_index:])
    original_filename = os.path.basename(file_path)
    _log.debug("parse_snapshot: body_start=%d file=%s", body_start_index, original_filename)

    return Snapshot(
        path=file_path,
        author=author,
        timestamp=ts,
        content_body=content_body,
        original_filename=original_filename,
    )


def parse_snapshot_meta(file_path: str, head_lines: int = 10) -> Optional[Snapshot]:
    """Parse only metadata (author, timestamp) from a configuration file.

    Reads only the head of the file and never the full content to keep it fast for
    directory listings. Returns a Snapshot with an empty content_body.
    """
    _log.debug("parse_snapshot_meta: start path=%s", file_path)
    head = _safe_read_head(file_path, max_lines=head_lines)
    if head is None:
        return None

    author, ts = _extract_metadata_from_text(head)
    if ts is None or author is None:
        f_author, f_ts = _extract_metadata_from_filename(os.path.basename(file_path))
        author = author or f_author
        ts = ts or f_ts

    if ts is None:
        try:
            ts = datetime.fromtimestamp(os.path.getmtime(file_path), tz=timezone.utc)
        except OSError:
            ts = datetime.now(timezone.utc)
    if author is None:
        author = "unknown"

    if ts.tzinfo is None or (ts.tzinfo and ts.tzinfo.utcoffset(ts) is None):
        ts = ts.replace(tzinfo=timezone.utc)
    else:
        ts = ts.astimezone(timezone.utc)

    return Snapshot(
        path=file_path,
        author=author,
        timestamp=ts,
        content_body="",
        original_filename=os.path.basename(file_path),
    )
