from __future__ import annotations

from typing import Any, Mapping


_SAFE_QUERY_VALUE_KEYS = frozenset({
    "_inheritance",
    "_max_results",
    "_paging",
    "_return_as_object",
    "_return_fields",
    "_return_fields+",
    "_return_type",
})


def infoblox_debug_payloads_enabled(ctx_or_cfg: Any) -> bool:
    """Return whether explicit Infoblox troubleshooting logs are enabled."""
    cfg = getattr(ctx_or_cfg, "cfg", ctx_or_cfg)
    if not isinstance(cfg, Mapping):
        return False
    return bool(cfg.get("api_debug_payloads", False))


def redact_infoblox_target(value: Any) -> str:
    """Redact a single lookup target value for normal logs."""
    text = str(value or "").strip()
    return "<redacted>" if text else ""


def redact_infoblox_uri(uri: str) -> str:
    """Redact sensitive query values while preserving Infoblox request shape."""
    text = str(uri or "").strip()
    if not text:
        return ""
    base, sep, query = text.partition("?")
    if not sep:
        return base
    parts = []
    for item in query.split("&"):
        if not item:
            continue
        key, has_equals, value = item.partition("=")
        if not has_equals:
            parts.append(item)
            continue
        if key in _SAFE_QUERY_VALUE_KEYS:
            parts.append(f"{key}={value}")
        else:
            parts.append(f"{key}=<redacted>")
    return f"{base}?{'&'.join(parts)}" if parts else base
