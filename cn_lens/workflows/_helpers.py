"""Shared helpers for cn_lens workflow modules.

Public surface
--------------
OFFLINE_FINDING_MESSAGE : str
    Classifier finding message used on the offline / None-runtime path.
    Indicates that adapters were not consulted; only classification ran.

CLASSIFIED_FINDING_MESSAGE : str
    Classifier finding message used on the online path (default case).
    Directs the reader to the sources block for adapter health and to the
    summary block for adapter results.

synthesise_error_finding(source, exc, *, detail_extra=...) -> LensFinding
    Build a synthesised error finding for an unexpected adapter exception.

call_adapter(summary, key, fn, to_row, *, findings, log_prefix,
             on_success=None, on_error_extra=None) -> bool
    Standardised try/except wrapper for a single adapter call.
    Calls ``fn()``; on success stores ``to_row(result)`` under ``summary[key]``
    and invokes ``on_success(result)`` if provided (for extending findings or
    matches lists).  On failure logs the error, appends a synthesised error
    finding, and stores ``{**on_error_extra, "error": str(exc)}`` under
    ``summary[key]``.  Returns True on success, False on failure.

make_run_id(now=None) -> str
    Return a UTC timestamp string suitable for use as a run ID.

is_short_hostname(value) -> bool
    Return True when the value has fewer than 3 dot-separated labels
    (short hostname / hostname prefix — not a fully-qualified domain name).

maybe_persist(run, runtime) -> None
    Persist *run* to disk when *runtime* is online.  Swallows all errors.

run_workflow(workflow_name, object_set, runtime, *, run_id, dispatch,
             offline_result_fn, pre_online_fn, run_warnings) -> LensRun
    Template that owns run_id resolution, offline short-circuit (registry-driven
    sources), per-object dispatch with last-resort error capture, summary
    assembly, and ``maybe_persist``.

    Each workflow module shrinks to: dispatch table of ``LensObjectType →
    handler(runtime, obj, base_summary) → (summary, findings)`` + handlers +
    workflow-specific findings.

    ``offline_result_fn`` is required (every workflow supplies its own).
    ``pre_online_fn`` and ``run_warnings`` are optional live hooks.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, TYPE_CHECKING

from cn_lens.models import LensFinding, LensObject, LensObjectType, LensResult, LensRun, ObjectSet

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

_LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Minimal stats shim — satisfies StatsManager.start_module_run's BaseModule
# requirement without importing the full modules package.
# ---------------------------------------------------------------------------

class _WorkflowStatsShim:
    """Lightweight shim that satisfies the ``menu_key`` / ``menu_title``
    contract required by ``StatsManager.start_module_run`` without depending
    on ``core.base.BaseModule``."""

    def __init__(self, workflow_name: str) -> None:
        self._name = workflow_name

    @property
    def menu_key(self) -> str:
        return self._name

    @property
    def menu_title(self) -> str:
        # Use the workflow name as the display title, capitalised.
        return self._name.replace("_", " ").replace("-", " ").title()


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

OFFLINE_FINDING_MESSAGE: str = (
    "offline mode — adapters not consulted; only classifier ran"
)

CLASSIFIED_FINDING_MESSAGE: str = (
    "object classified; see sources block for adapter health"
    " and summary block for adapter results"
)


# ---------------------------------------------------------------------------
# make_run_id
# ---------------------------------------------------------------------------

def make_run_id(now: datetime | None = None) -> str:
    """Return a UTC timestamp string suitable for use as a run ID.

    Format: ``%Y%m%dT%H%M%SZ`` (e.g. ``20240510T142300Z``).
    """
    if now is None:
        now = datetime.now(timezone.utc)
    return now.strftime("%Y%m%dT%H%M%SZ")


# ---------------------------------------------------------------------------
# Shared finding factories
# ---------------------------------------------------------------------------

def synthesise_error_finding(
    source: str,
    exc: BaseException,
    *,
    detail_extra: Mapping[str, Any] | None = None,
) -> LensFinding:
    """Return a synthesised error finding for an unexpected adapter exception.

    Parameters
    ----------
    source:
        The adapter or source name (e.g. ``"infoblox"``, ``"ad"``).
    exc:
        The caught exception.
    detail_extra:
        Additional key-value pairs merged into the ``detail`` dict alongside
        the auto-populated ``"exception"`` key.
    """
    detail: dict[str, Any] = {"exception": type(exc).__name__}
    if detail_extra:
        detail.update(detail_extra)
    return LensFinding(
        severity="error",
        source=source,
        message=str(exc),
        detail=detail,
    )


def call_adapter(
    summary: Dict[str, Any],
    key: str,
    fn: Callable[[], Any],
    to_row: Callable[[Any], Dict[str, Any]],
    *,
    findings: List[LensFinding],
    log_prefix: str,
    on_success: Optional[Callable[[Any], None]] = None,
    on_error_extra: Optional[Dict[str, Any]] = None,
) -> bool:
    """Standardised try/except wrapper for a single adapter call.

    Calls ``fn()``; on success stores ``to_row(result)`` under
    ``summary[key]`` and invokes ``on_success(result)`` when provided (use
    this to extend findings or matches lists from the adapter result).  On
    failure logs the error via the module logger, appends a synthesised error
    finding to ``findings``, and stores
    ``{**on_error_extra, "error": str(exc)}`` under ``summary[key]``.

    Parameters
    ----------
    summary:
        The per-object summary dict being built (mutated in-place).
    key:
        The top-level key under which the adapter result is stored.
    fn:
        Zero-argument callable that performs the adapter call and returns
        the raw adapter result.  Capture arguments via closure or
        ``functools.partial``.
    to_row:
        Maps the adapter result to the success summary dict stored under
        ``summary[key]``.  Field differences between workflows (e.g.
        inspect's full IP row vs impact's slimmer IP row) are expressed
        as explicit ``to_row`` lambdas at the call site, making drift
        visible.
    findings:
        Mutable list of ``LensFinding`` objects for the current object
        (mutated in-place on both success and failure paths).
    log_prefix:
        String prepended to the error log message
        (e.g. ``"inspect: infoblox.lookup_ip"``).  Formats as
        ``"<log_prefix> raised unexpectedly: <exc>"``.
    on_success:
        Optional callback ``(result) -> None`` called after the success
        summary row is stored.  Use it to extend ``findings`` and/or
        ``matches`` lists from the adapter result.  No-op when ``None``.
    on_error_extra:
        Optional extra keys merged into the failure summary dict alongside
        the mandatory ``"error"`` key (e.g. ``{"found": False}`` for
        adapters whose callers inspect ``summary[key]["found"]``).

    Returns
    -------
    bool
        ``True`` on success, ``False`` when an exception was caught.
    """
    try:
        result = fn()
        summary[key] = to_row(result)
        if on_success is not None:
            on_success(result)
        return True
    except Exception as exc:
        _LOG.error("%s raised unexpectedly: %s", log_prefix, exc)
        error_row: Dict[str, Any] = {}
        if on_error_extra:
            error_row.update(on_error_extra)
        error_row["error"] = str(exc)
        summary[key] = error_row
        findings.append(synthesise_error_finding(key, exc))
        return False


# ---------------------------------------------------------------------------
# Hostname / FQDN label helpers
# ---------------------------------------------------------------------------

def is_short_hostname(value: str) -> bool:
    """Return True when *value* has fewer than 3 dot-separated labels.

    Rule used across inspect, dns, and device workflows to distinguish a short
    hostname / prefix (e.g. ``"host"``, ``"device1.corp"``) from a fully-
    qualified domain name (e.g. ``"host.example.com"``).

    Examples
    --------
    >>> is_short_hostname("host")
    True
    >>> is_short_hostname("device1.corp")
    True
    >>> is_short_hostname("host.example.com")
    False
    >>> is_short_hostname("sub.host.example.com")
    False
    """
    return len(value.split(".")) < 3


# ---------------------------------------------------------------------------
# Auto-persistence helper
# ---------------------------------------------------------------------------

def maybe_persist(run: LensRun, runtime: Optional["LensRuntime"]) -> None:
    """Persist *run* to disk when *runtime* is online.

    This is a fire-and-forget helper: all exceptions are caught, logged, and
    silently swallowed so that persistence failures never affect the workflow's
    return value.

    Parameters
    ----------
    run:
        The finished ``LensRun`` to persist.
    runtime:
        Active ``LensRuntime``.  When ``None`` or offline, the call is a no-op.
    """
    if runtime is None or runtime.offline:
        return
    try:
        from cn_lens.reports.persistence import persist_run
        persist_run(run, runtime)
    except Exception as exc:
        logger = getattr(runtime, "logger", _LOG)
        logger.warning("maybe_persist: persistence skipped due to error: %s", exc)


# ---------------------------------------------------------------------------
# Handler / offline callable type aliases
# ---------------------------------------------------------------------------

# Standard handler: (runtime, obj, base_summary) -> (summary, findings)
# Handlers that need extra context capture it via closures in their workflow
# module before being placed into the dispatch table.
_Handler = Callable[
    ["LensRuntime", LensObject, Dict[str, Any]],
    Tuple[Dict[str, Any], List[LensFinding]],
]

# Offline result builder: (obj, sources) -> LensResult
_OfflineResultFn = Callable[[LensObject, Dict[str, str]], LensResult]


# ---------------------------------------------------------------------------
# run_workflow — the shared template
# ---------------------------------------------------------------------------

def run_workflow(
    workflow_name: str,
    object_set: "ObjectSet",
    runtime: "Optional[LensRuntime]",
    *,
    registry: Any,
    run_id: Optional[str] = None,
    dispatch: Dict[LensObjectType, _Handler],
    offline_result_fn: _OfflineResultFn,
    pre_online_fn: Optional[Callable[["LensRuntime", Dict[str, str]], None]] = None,
    run_warnings: Optional[List[str]] = None,
) -> LensRun:
    """Template that owns scaffolding common to all standard cn-lens workflows.

    Parameters
    ----------
    workflow_name:
        The ``LensRun.workflow`` field value (e.g. ``"inspect"``).
    object_set:
        The ``ObjectSet`` produced by ``classify_many``.
    runtime:
        Optional ``LensRuntime``.  When ``None`` or ``runtime.offline`` is
        ``True``, returns the offline MVP-shape output.
    registry:
        The ``AdapterRegistry`` singleton, obtained by calling
        ``get_registry()`` in the workflow module.  Passed explicitly so that
        tests can patch ``<workflow_module>.get_registry`` and have the patch
        take effect inside the template.
    run_id:
        Explicit run identifier.  Precedence:
        1. ``run_id`` kwarg (if not None)
        2. ``runtime.options.run_id`` (if not None)
        3. Auto-generated UTC timestamp.
    dispatch:
        ``LensObjectType → handler`` mapping.  Each handler is called as
        ``handler(runtime, obj, base_summary) → (summary, findings)``.
        Handlers capture any extra per-run state (mode, probe, etc.) via
        closures.  Types absent from the table produce a bare
        base-summary result with no extra findings.
    offline_result_fn:
        Required callable ``(obj, sources) → LensResult`` for the offline
        path.  Every workflow supplies its own; there is no default fallback.
    pre_online_fn:
        Optional ``(runtime, sources) → None`` hook called once on the
        online path *after* sources are built but *before* the per-object
        loop.  Used for workflow-level setup (e.g. reachability's AD deep
        health probe that mutates ``sources["ad"]``).
    run_warnings:
        Optional mutable list that handlers (via closures) can append
        workflow-level warning strings to during the per-object loop.
        When provided, the template uses this list for ``LensRun.warnings``.
        When ``None`` the template creates its own empty list.

    Returns
    -------
    LensRun
        Always returned; never raises.
    """
    # --- Resolve run_id ---
    effective_run_id: str
    if run_id is not None:
        effective_run_id = run_id
    elif runtime is not None and runtime.options.run_id is not None:
        effective_run_id = runtime.options.run_id
    else:
        effective_run_id = make_run_id()

    # Record start time for stats duration calculation (used on both paths).
    _stats_start: datetime = datetime.now(timezone.utc)
    _stats = getattr(runtime, "stats", None) if runtime is not None else None
    _shim = _WorkflowStatsShim(workflow_name) if _stats is not None else None
    if _stats is not None and _shim is not None:
        try:
            _stats.start_module_run(_shim)  # type: ignore[arg-type]
        except Exception:
            _stats = None  # gracefully degrade if stats setup fails

    # --- Offline path ---
    if runtime is None or runtime.offline:
        offline_sources: Dict[str, str] = {"classifier": "ok"}
        offline_sources.update(registry.source_statuses(runtime, offline=True))

        offline_results = tuple(
            offline_result_fn(obj, offline_sources)
            for obj in object_set.objects
        )
        offline_run = LensRun(
            schema_version=1,
            tool="cn-lens",
            workflow=workflow_name,
            run_id=effective_run_id,
            inputs=object_set,
            results=offline_results,
            warnings=(),
            errors=(),
        )
        _emit_stats_event(
            runtime, _stats, _stats_start, workflow_name,
            len(offline_results), run_status="completed",
        )
        return offline_run

    # --- Online path ---
    sources: Dict[str, str] = {"classifier": "ok"}
    sources.update(registry.source_statuses(runtime))

    # Allow workflow-level pre-loop setup (e.g. deep health probes)
    if pre_online_fn is not None:
        pre_online_fn(runtime, sources)

    # Use caller-provided mutable list (so handler closures can append to it)
    # or create a fresh one.
    _run_warnings: List[str] = run_warnings if run_warnings is not None else []

    online_results: List[LensResult] = []
    for obj in object_set.objects:
        base_summary: Dict[str, Any] = {
            "original": obj.original,
            "normalized": obj.normalized,
            "type": obj.object_type.value,
        }
        handler = dispatch.get(obj.object_type)
        if handler is not None:
            try:
                summary, adapter_findings = handler(runtime, obj, base_summary)
            except Exception as exc:
                runtime.logger.error(
                    "%s: unexpected error in dispatcher for %s: %s",
                    workflow_name, obj.value, exc,
                )
                summary = dict(base_summary)
                # Prepend a generic classifier finding before the error finding
                # so the findings tuple shape matches the pre-phase (classifier, error)
                # contract — consumers expecting findings[0].source=="classifier" are
                # satisfied even on the last-resort exception path.
                classifier_finding = LensFinding(
                    severity="info",
                    source="classifier",
                    message=CLASSIFIED_FINDING_MESSAGE,
                    detail={"workflow": workflow_name},
                )
                adapter_findings = [classifier_finding, synthesise_error_finding(workflow_name, exc)]
        else:
            summary = dict(base_summary)
            adapter_findings = []

        online_results.append(LensResult(
            lens_object=obj,
            status="classified",
            summary=summary,
            sources=sources,
            findings=tuple(adapter_findings),
        ))

    run = LensRun(
        schema_version=1,
        tool="cn-lens",
        workflow=workflow_name,
        run_id=effective_run_id,
        inputs=object_set,
        results=tuple(online_results),
        warnings=tuple(_run_warnings),
        errors=(),
    )
    _emit_stats_event(
        runtime, _stats, _stats_start, workflow_name,
        len(online_results), run_status="completed",
    )
    maybe_persist(run, runtime)
    return run


# ---------------------------------------------------------------------------
# Stats event emission helper
# ---------------------------------------------------------------------------

def _emit_stats_event(
    runtime: "Optional[LensRuntime]",
    stats: Any,
    start: datetime,
    workflow_name: str,
    object_count: int,
    run_status: str = "completed",
) -> None:
    """Publish ``stats:module_detail`` and finalise the StatsManager run.

    Called at the end of ``run_workflow`` on both the offline and online paths.
    All exceptions are swallowed — stats collection must never affect the
    workflow's return value.

    Parameters
    ----------
    runtime:
        The active ``LensRuntime`` (may be ``None``).
    stats:
        The ``StatsManager`` captured at the start of ``run_workflow`` (may be
        ``None`` if stats are not enabled or setup failed).
    start:
        UTC datetime recorded at the start of the run.
    workflow_name:
        The workflow name — stored as ``payload["workflow"]``.
    object_count:
        Number of objects processed — stored as ``payload["object_count"]``.
    run_status:
        StatsManager run-completion status (``"completed"`` or ``"failed"``).
    """
    if runtime is None:
        return
    try:
        end = datetime.now(timezone.utc)
        duration_seconds = max(0.0, round((end - start).total_seconds(), 3))
        payload: Dict[str, Any] = {
            "workflow": workflow_name,
            "object_count": object_count,
            "unit_count": max(1, object_count),
            "duration_seconds": duration_seconds,
        }
        # Publish on the event_bus — StatsManager (when attached) picks this
        # up via its subscription and records it to the active run.
        runtime.context.event_bus.publish("stats:module_detail", payload)
        # Finalise the StatsManager run so the session file is flushed.
        if stats is not None:
            try:
                stats.finish_module_run(run_status)
            except Exception:
                pass
    except Exception:
        pass
