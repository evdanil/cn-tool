from __future__ import annotations

from datetime import datetime, timezone


def format_timestamp(dt: datetime) -> str:
    """Return a standardized string for timestamps (UTC, YYYY-MM-DD HH:MM TZ)."""
    if dt.tzinfo is None or (dt.tzinfo and dt.tzinfo.utcoffset(dt) is None):
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M %Z")

