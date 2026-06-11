"""config get / set / test workflow helpers for cn-lens (P5.5).

Public surface
--------------
``config_get(key=None, runtime, extra_config_paths=[]) -> list[dict]``
    Return a list of ``{"key": k, "value": v, "section": s, "ini_key": ik}``
    dicts for the config key *key* (or all keys when *key* is ``None``).
    Secret keys (those whose name contains "password", "credentials", "secret",
    "key", or the GPG credentials path) are replaced with ``"***"``.  Values
    are taken from ``runtime.cfg`` when available; otherwise the schema
    fallback is used.

``config_set(key, value, runtime, user_config_path) -> dict``
    Validate *key* against the merged schema, then write the value to the user
    config file via ``utils.config.write_config_value``.  Returns
    ``{"status": "ok", "key": key}`` on success or ``{"status": "error",
    "message": ...}`` on failure.

``config_test(runtime) -> dict``
    Run connectivity probes for Infoblox (``infoblox.deep_health``) and Active
    Directory (``active_directory.deep_health``).  In offline mode the probes
    are not called and both sources are reported as ``"disabled"``.  Exceptions
    from probes are caught and reported as ``"error"`` status.

    Returns::

        {
            "infoblox": {"status": str, "detail": str},
            "ad":        {"status": str, "detail": str},
        }

Design notes
------------
- No ``print`` / ``console`` calls — all diagnostic output goes through
  ``runtime.logger``.
- ``config_get`` and ``config_set`` do not mutate ``runtime.cfg``; they read
  the schema and optionally the config file directly.
- ``config_test`` reuses the doctor adapter's ``deep_health`` callables so
  behaviour is identical to ``cn-lens doctor`` probe results.
- Secret detection: any schema key whose name or ini_key contains "password",
  "credentials", "secret", or "key" as a whole word, plus explicit overrides
  (``gpg_credentials``), is considered a secret.  The check is name-based
  (no runtime value inspection needed).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

# ---------------------------------------------------------------------------
# Secret-key detection
# ---------------------------------------------------------------------------

# Patterns (whole-word) that mark a schema key as a secret.
# Matched against both the schema key name and its ``ini_key`` value.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bpassword\b", re.IGNORECASE),
    re.compile(r"\bcredentials\b", re.IGNORECASE),
    re.compile(r"\bsecret\b", re.IGNORECASE),
    re.compile(r"\bprivkey\b", re.IGNORECASE),
    re.compile(r"\bpriv_key\b", re.IGNORECASE),
)


def _is_secret_key(key: str, spec: Dict[str, Any]) -> bool:
    """Return True when *key* or its ``ini_key`` suggests it holds a secret value."""
    targets = [key, spec.get("ini_key", "")]
    for target in targets:
        for pattern in _SECRET_PATTERNS:
            if pattern.search(target):
                return True
    # Explicit override: gpg_credentials holds a path to a private key file.
    if key == "gpg_credentials":
        return True
    return False


def is_secret_key(key: str) -> bool:
    """Return True when *key* is a secret config key that must be redacted.

    Public helper used by CLI and REPL handlers so that ``config set`` output
    redacts the same set of keys as ``config get``.  The check is schema-driven
    (same logic as :func:`_is_secret_key`) and is safe to call before any
    runtime is available.
    """
    schema = _get_schema()
    spec = schema.get(key, {})
    return _is_secret_key(key, spec)


def _build_secret_keys(schema: Dict[str, Dict[str, Any]]) -> frozenset[str]:
    """Return the set of schema keys that should be redacted in ``config get``."""
    return frozenset(
        key for key, spec in schema.items() if _is_secret_key(key, spec)
    )


def _merged_schema() -> Dict[str, Dict[str, Any]]:
    """Return the merged config schema (BASE_CONFIG_SCHEMA + all plugin schemas)."""
    from utils.config import BASE_CONFIG_SCHEMA
    from core.loader import collect_plugin_schemas
    return collect_plugin_schemas(BASE_CONFIG_SCHEMA)


#: Cached merged schema (built lazily on first access via :func:`_get_schema`).
_SCHEMA_CACHE: Dict[str, Dict[str, Any]] | None = None


def _get_schema() -> Dict[str, Dict[str, Any]]:
    """Return the merged config schema, building it once and caching the result."""
    global _SCHEMA_CACHE
    if _SCHEMA_CACHE is None:
        _SCHEMA_CACHE = _merged_schema()
    return _SCHEMA_CACHE


#: Lazily computed frozenset of secret config key names.
#: Derived from :func:`_get_schema` on first access.
_SECRET_KEYS_CACHE: frozenset[str] | None = None


def _get_secret_keys() -> frozenset[str]:
    global _SECRET_KEYS_CACHE
    if _SECRET_KEYS_CACHE is None:
        _SECRET_KEYS_CACHE = _build_secret_keys(_get_schema())
    return _SECRET_KEYS_CACHE


# ---------------------------------------------------------------------------
# config_get
# ---------------------------------------------------------------------------

_REDACTED = "***"


def config_get(
    key: Optional[str] = None,
    *,
    runtime: Optional["LensRuntime"] = None,
    extra_config_paths: Optional[List[Path]] = None,
) -> List[Dict[str, Any]]:
    """Return config entries, redacting secret values.

    Parameters
    ----------
    key:
        Schema key name to retrieve.  When ``None``, all keys are returned.
    runtime:
        Active ``LensRuntime``.  When provided, values are read from
        ``runtime.cfg`` (the runtime's already-merged config dict).  When
        ``None`` the schema fallbacks are used.
    extra_config_paths:
        Additional ``.cn``-style config files to read (merged on top of
        ``runtime.cfg``).  Used in tests to inject a temporary config file
        without modifying the runtime.

    Returns
    -------
    list of dicts
        Each entry is ``{"key": k, "value": v, "section": s, "ini_key": ik}``.
        Secret values are replaced with ``"***"``.
    """
    schema = _get_schema()
    secret_keys = _get_secret_keys()

    # Resolve the set of keys to report.
    if key is not None:
        if key not in schema:
            return []
        keys_to_report = [key]
    else:
        keys_to_report = sorted(schema.keys())

    # Build the base value source (runtime.cfg or fallbacks).
    cfg: Dict[str, Any] = {}
    if runtime is not None:
        cfg = dict(getattr(runtime, "cfg", {}))

    # Overlay any extra config paths on top of the runtime cfg.
    if extra_config_paths:
        import configparser
        extra_parser = configparser.ConfigParser()
        readable = [str(p) for p in extra_config_paths if Path(p).is_file()]
        if readable:
            extra_parser.read(readable)
            for k in keys_to_report:
                spec = schema[k]
                section = spec.get("section", "")
                ini_key = spec.get("ini_key", "")
                if extra_parser.has_option(section, ini_key):
                    cfg[k] = extra_parser.get(section, ini_key)

    entries: List[Dict[str, Any]] = []
    for k in keys_to_report:
        spec = schema[k]
        raw_value = cfg.get(k, spec.get("fallback", ""))

        # Convert value to a display string.
        if raw_value is None:
            display = ""
        elif isinstance(raw_value, (list, tuple)):
            display = ",".join(str(v) for v in raw_value)
        elif isinstance(raw_value, Path):
            display = str(raw_value)
        else:
            display = str(raw_value)

        # Redact secrets.
        if k in secret_keys and display:
            display = _REDACTED

        entries.append({
            "key": k,
            "value": display,
            "section": spec.get("section", ""),
            "ini_key": spec.get("ini_key", ""),
        })

    return entries


# ---------------------------------------------------------------------------
# config_set
# ---------------------------------------------------------------------------

def config_set(
    key: str,
    value: str,
    *,
    runtime: Optional["LensRuntime"] = None,
    user_config_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Write a config value to the user config file.

    Parameters
    ----------
    key:
        Schema key name (e.g. ``"api_endpoint"``).  Must exist in the merged
        schema; unknown keys are rejected with ``{"status": "error", ...}``.
    value:
        String value to write.
    runtime:
        Active ``LensRuntime``.  Used only for its logger.  May be ``None``
        in tests (a NullHandler logger is used as fallback).
    user_config_path:
        Path to the user config file to write.  Defaults to ``~/.cn`` when
        ``None``.

    Returns
    -------
    dict
        ``{"status": "ok", "key": key, "section": s, "ini_key": ik}``
        on success, or ``{"status": "error", "message": msg}`` on failure.
    """
    import logging as _logging
    from utils.config import write_config_value

    logger = (
        getattr(runtime, "logger", None) or _logging.getLogger("cn_lens.config_cmd")
    )

    schema = _get_schema()
    if key not in schema:
        msg = f"Unknown config key: {key!r}. Use 'config get' to list valid keys."
        logger.warning("config_set: %s", msg)
        return {"status": "error", "message": msg}

    spec = schema[key]
    section = spec.get("section", "")
    ini_key = spec.get("ini_key", "")

    if not section or not ini_key:
        msg = f"Config key {key!r} has no section/ini_key in schema (cannot write)."
        logger.warning("config_set: %s", msg)
        return {"status": "error", "message": msg}

    if user_config_path is None:
        user_config_path = Path.home() / ".cn"

    try:
        write_config_value(
            logger,
            user_config_path,
            section,
            ini_key,
            value,
            log_value=not is_secret_key(key),
        )
    except Exception as exc:
        msg = f"Failed to write config: {exc}"
        logger.error("config_set: %s", msg)
        return {"status": "error", "message": msg}

    return {"status": "ok", "key": key, "section": section, "ini_key": ini_key}


# ---------------------------------------------------------------------------
# config_test
# ---------------------------------------------------------------------------

def config_test(
    *,
    runtime: Optional["LensRuntime"] = None,
) -> Dict[str, Dict[str, str]]:
    """Run connectivity probes for Infoblox and Active Directory.

    Reuses the same ``deep_health`` callables as ``cn-lens doctor`` so the
    results are semantically identical to the doctor workflow.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.  When ``None`` or ``runtime.offline`` is
        ``True``, no probes are run; both sources are reported as
        ``"disabled"``.

    Returns
    -------
    dict
        ``{
            "infoblox": {"status": str, "detail": str},
            "ad":        {"status": str, "detail": str},
        }``

        ``status`` is one of: ``ok``, ``error``, ``not_configured``,
        ``disabled``, ``not_queried``.
    """
    import logging as _logging

    logger = (
        getattr(runtime, "logger", None) or _logging.getLogger("cn_lens.config_cmd")
    )

    offline = (runtime is None) or getattr(runtime, "offline", False)

    if offline:
        disabled = {"status": "disabled", "detail": "offline mode — no probes run"}
        return {
            "infoblox": dict(disabled),
            "ad": dict(disabled),
        }

    result: Dict[str, Dict[str, str]] = {}

    # --- Infoblox probe ---
    try:
        from cn_lens.adapters.infoblox import deep_health as ib_deep_health
        ib_health = ib_deep_health(runtime)
        result["infoblox"] = {"status": ib_health.status, "detail": ib_health.detail}
    except Exception as exc:
        logger.warning("config_test: infoblox probe raised: %s", exc)
        result["infoblox"] = {"status": "error", "detail": str(exc)}

    # --- AD probe ---
    try:
        from cn_lens.adapters.active_directory import deep_health as ad_deep_health
        ad_health = ad_deep_health(runtime)
        result["ad"] = {"status": ad_health.status, "detail": ad_health.detail}
    except Exception as exc:
        logger.warning("config_test: ad probe raised: %s", exc)
        result["ad"] = {"status": "error", "detail": str(exc)}

    return result
