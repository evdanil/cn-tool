"""cn-lens doctor — adapter health reporting (P2.2).

This module provides the single shared implementation of the ``doctor``
command so that both the CLI (``cli.py``) and the interactive REPL
(``interactive.py``) stay thin entry points with no duplicated logic.

Public surface
--------------
``run_doctor(runtime, *, fmt="human") -> str``
    Return a formatted health report for all registered adapters.
    The caller is responsible for printing or forwarding the string.

Design
------
- **offline** mode (``runtime.offline``):
  Every adapter is reported as ``not_queried``; no probes, no credential
  prompts.  Deep probes are guarded by this flag exclusively — the caller
  does not need to special-case anything.

- **online** mode:
  1. Cheap, config-only health is obtained from the registry for every
     adapter (``registry.source_statuses(runtime)``).
  2. For adapters that support **deep probes** (Infoblox and AD): if the
     cheap status indicates the adapter is configured (i.e. it is NOT
     ``not_configured`` and NOT ``disabled``), the corresponding deep probe
     is run and its result overrides the cheap one.  Deep probes include
     credential acquisition as part of their own internal logic; doctor
     does not call ``runtime.ensure_credentials()`` separately.
  3. Output is either a rich table (``fmt="human"``) or a JSON dict
     (``fmt="json"``).

Exit semantics (enforced by callers)
-------------------------------------
- Exit 0 when doctor itself ran successfully (informational — an unconfigured
  adapter does not fail doctor, per spec US2 scenario 1).
- Exit 2 only on internal error (raised as ``RuntimeError`` from this
  function so the caller can catch and map to 2).
"""
from __future__ import annotations

import io
import json
from typing import TYPE_CHECKING, Dict

from cn_lens.adapters.registry import AdapterRegistry, get_registry
from cn_lens.adapters.types import AdapterHealth

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

# Adapters for which a deep connectivity probe is available.
# Maps adapter name → dotted import path for the deep_health callable.
# Add a new entry here (P6+) to register additional deep probes — no other
# change is needed anywhere in this module.
_DEEP_PROBES: Dict[str, str] = {
    "infoblox": "cn_lens.adapters.infoblox",
    "ad": "cn_lens.adapters.active_directory",
}

# Map friendly status strings to a Rich style (used in human table).
_STATUS_STYLE: Dict[str, str] = {
    "ok": "green",
    "partial": "yellow",
    "error": "bold red",
    "not_configured": "dim",
    "not_queried": "dim",
    "disabled": "dim",
}


def _get_deep_probe(name: str):
    """Return the deep_health callable for *name*, or None if none exists.

    Performs a lazy import from the module path recorded in ``_DEEP_PROBES``;
    the import is deferred so that adapters with optional heavy dependencies
    (e.g. LDAP bindings) do not slow down the common offline path.
    """
    module_path = _DEEP_PROBES.get(name)
    if module_path is None:
        return None
    import importlib  # noqa: PLC0415
    mod = importlib.import_module(module_path)
    return getattr(mod, "deep_health", None)


def _collect_statuses(
    registry: AdapterRegistry,
    runtime: "LensRuntime",
) -> Dict[str, AdapterHealth]:
    """Gather per-adapter health, running deep probes where available.

    Returns a dict mapping adapter name → ``AdapterHealth``.
    """
    offline = runtime.offline

    # Step 1: cheap config-only health for all adapters.
    cheap: Dict[str, str] = registry.source_statuses(runtime, offline=offline)

    result: Dict[str, AdapterHealth] = {}
    for name, status in cheap.items():
        health = AdapterHealth(status=status)

        # Step 2: for deep-probe-capable adapters, upgrade if configured.
        if not offline and name in _DEEP_PROBES:
            probe = _get_deep_probe(name)
            if probe is not None and status not in ("not_configured", "disabled"):
                try:
                    health = probe(runtime)
                except Exception as exc:
                    health = AdapterHealth(status="error", detail=str(exc))

        result[name] = health

    return result


def run_doctor(
    runtime: "LensRuntime",
    registry: AdapterRegistry | None = None,
    *,
    fmt: str = "human",
) -> str:
    """Run adapter health checks and return a formatted report string.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.  If ``runtime.offline`` is True every
        adapter is returned as ``not_queried`` with no probes.
    registry:
        ``AdapterRegistry`` to use.  When ``None`` the shared singleton
        from ``cn_lens.adapters.registry.get_registry()`` is used.
        Pass an isolated registry in tests to avoid side-effects.
    fmt:
        ``"human"`` (default) — Rich-rendered table.
        ``"json"``            — JSON dict ``{name: {status, detail}}``.

    Returns
    -------
    str
        Formatted output ready for printing.  Always ends with a newline.

    Raises
    ------
    ValueError
        When *fmt* is not ``"human"`` or ``"json"``.
    """
    if fmt not in ("human", "json"):
        raise ValueError(f"doctor: unsupported format {fmt!r}; choose 'human' or 'json'")

    if registry is None:
        registry = get_registry()

    statuses = _collect_statuses(registry, runtime)

    if fmt == "json":
        return _render_json(statuses)
    return _render_human(statuses, runtime)


def _render_json(statuses: Dict[str, AdapterHealth]) -> str:
    """Render statuses as a JSON object string."""
    data = {
        name: {"status": h.status, "detail": h.detail}
        for name, h in statuses.items()
    }
    return json.dumps(data, indent=2) + "\n"


def _render_human(
    statuses: Dict[str, AdapterHealth],
    runtime: "LensRuntime",
) -> str:
    """Render statuses as a Rich table."""
    from rich.console import Console  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415
    from rich.text import Text  # noqa: PLC0415

    mode = "offline" if runtime.offline else "online"
    title = f"cn-lens doctor — adapter health ({mode})"

    table = Table(title=title, show_header=True, header_style="bold")
    table.add_column("Source", style="bold", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detail")

    for name, health in statuses.items():
        style = _STATUS_STYLE.get(health.status, "")
        status_text = Text(health.status, style=style)
        table.add_row(name, status_text, health.detail or "")

    buf = io.StringIO()
    # Do not force no_color — Rich auto-detects TTY and strips ANSI when writing
    # to a StringIO (non-TTY), so tests capture plain text deterministically
    # while real terminals get styled output.
    console = Console(file=buf, highlight=False)
    console.print(table)
    return buf.getvalue()
