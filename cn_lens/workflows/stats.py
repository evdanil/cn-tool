"""stats workflow — offline-capable usage statistics report.

Reads and aggregates cn-tool/cn-lens shared stats files from the configured
stats directory.  No live adapters are consulted; this command always works
offline.

The aggregation logic lives entirely in ``utils/stats.StatsManager.build_report``
— the same function used by ``modules/stats_report.py`` in the cn-tool menu.
No extraction from that module is needed: the display layer (Rich/console) is
the only UI-coupled part of ``modules/stats_report.py``, and it already delegates
all computation to ``StatsManager``.  cn-lens consumes the same ``build_report``
output and renders it via the standard cn-lens renderers.

Design (plan D8)
-----------------
- ``run_workflow`` template publishes one ``stats:module_detail`` event per run;
  ``LensRuntime.stats`` (a ``StatsManager``) subscribes to that event and records
  it into the shared stats directory (when ``stats_collect_enabled`` is True).
- ``cn-lens stats`` reads and aggregates those files via
  ``LensRuntime.stats.build_report(period_key)`` — identical semantics to the
  cn-tool statistics menu.
- Privacy model unchanged: per-user sharded JSON.gz files, no new data fields.

Public surface
--------------
stats_report(runtime, period_key) -> dict
    Read/aggregate stats and return the StatsManager.build_report() dict.
    Returns an empty-summary report when runtime.stats is None.

stats_objects(object_set, runtime, *, period_key, ...) -> LensRun
    Standard workflow entry-point wrapping stats_report() into a LensRun.
    The LensRun carries a single result whose summary["stats"] holds the
    build_report() output.

Output summary shape (per result)
----------------------------------
::

    {
        "period_key":          "all",
        "period_label":        "All time",
        "covered_range_display": "...",
        "summary": {
            "session_count":        int,
            "completed_run_count":  int,
            ...
        },
        "by_user":   [...],   # aggregated user rows
        "by_module": [...],   # aggregated module rows
    }
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

from cn_lens.models import LensFinding, LensObject, LensObjectType, LensResult, LensRun, ObjectSet
from cn_lens.workflows._helpers import make_run_id

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

_LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# _EMPTY_REPORT — returned when StatsManager is not available
# ---------------------------------------------------------------------------

def _empty_report(period_key: str = "all") -> Dict[str, Any]:
    """Return an empty report dict matching StatsManager.build_report() shape."""
    from utils.stats import PERIOD_PRESETS
    label = "All time"
    for preset in PERIOD_PRESETS:
        if preset.key == period_key:
            label = preset.label
            break
    return {
        "period_key": period_key,
        "period_label": label,
        "period_window_start": None,
        "period_window_end": None,
        "covered_start": None,
        "covered_end": None,
        "covered_range_display": "N/A",
        "sessions": [],
        "summary": {
            "session_count": 0,
            "completed_run_count": 0,
            "completed_action_count": 0,
            "failed_run_count": 0,
            "interrupted_run_count": 0,
            "abandoned_session_count": 0,
            "actual_active_seconds": 0,
            "observed_active_seconds": 0,
            "session_elapsed_seconds": 0,
            "uncredited_idle_seconds": 0,
            "estimated_saved_seconds": 0,
            "utilization_display": "N/A",
        },
        "by_user": [],
        "by_module": [],
        "user_pivot": [],
        "user_pivot_columns": [],
    }


# ---------------------------------------------------------------------------
# stats_report — pure read/aggregate
# ---------------------------------------------------------------------------

def stats_report(
    runtime: Optional["LensRuntime"],
    period_key: str = "all",
) -> Dict[str, Any]:
    """Read and aggregate stats files from the stats directory.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.  When ``None`` or ``runtime.stats`` is ``None``,
        returns an empty-summary report (offline-safe).
    period_key:
        One of ``"all"``, ``"7d"``, ``"4w"``, ``"1m"``, ``"12m"`` — the same
        period presets available in the cn-tool statistics menu.

    Returns
    -------
    dict
        Report dict from ``StatsManager.build_report(period_key)``, or an
        empty-summary report when stats are unavailable.
    """
    if runtime is None or runtime.stats is None:
        return _empty_report(period_key)
    try:
        return runtime.stats.build_report(period_key)
    except Exception as exc:
        _LOG.warning("stats_report: build_report failed: %s", exc)
        return _empty_report(period_key)


# ---------------------------------------------------------------------------
# stats_objects — workflow entry-point
# ---------------------------------------------------------------------------

def stats_objects(
    object_set: ObjectSet,
    runtime: Optional["LensRuntime"] = None,
    *,
    run_id: Optional[str] = None,
    period_key: str = "all",
) -> LensRun:
    """Offline-capable stats command — read/aggregate shared stats files.

    This workflow does not follow the standard ``run_workflow`` template because
    it has no per-object dispatch — it returns a single aggregate result rather
    than one result per input object.  Stats collection is inherently offline-
    capable (reads local files; no live adapters consulted).

    Parameters
    ----------
    object_set:
        Ignored (stats has no per-object semantics); present for interface
        consistency with other workflow callables.
    runtime:
        Active ``LensRuntime``.  When ``None`` or offline, stats are still read
        from the local directory — offline does not prevent reading stats.
    run_id:
        Explicit run ID; ``None`` → auto-generated timestamp.
    period_key:
        Reporting period.  One of ``"all"``, ``"7d"``, ``"4w"``, ``"1m"``,
        ``"12m"``.

    Returns
    -------
    LensRun
        A ``LensRun`` with ``workflow="stats"`` and a single result whose
        ``summary["stats"]`` holds the ``build_report()`` output dict.
    """
    # Resolve run_id.
    if run_id is None and runtime is not None and runtime.options.run_id is not None:
        run_id = runtime.options.run_id
    if run_id is None:
        run_id = make_run_id()

    report = stats_report(runtime, period_key=period_key)

    # Strip raw sessions[] from the stored report (privacy + payload-size fix, F3).
    # Only aggregate keys are stored; sessions[] contains per-user paths/PIDs.
    report_aggregate = {k: v for k, v in report.items() if k != "sessions"}

    # Build a single aggregate result.
    summary: Dict[str, Any] = {
        "stats": report_aggregate,
        "period_key": report.get("period_key", period_key),
        "period_label": report.get("period_label", ""),
        "covered_range_display": report.get("covered_range_display", "N/A"),
        "session_count": report.get("summary", {}).get("session_count", 0),
    }

    finding = LensFinding(
        severity="info",
        source="stats",
        message=(
            "stats read offline — no live adapters consulted"
        ),
        detail={"period": period_key},
    )

    # Use a sentinel LensObject for the aggregate result — stats has no input
    # objects, but LensResult requires a lens_object.  REPORT is the canonical
    # sentinel type for non-network aggregate results.
    sentinel_obj = LensObject(
        original="(stats)",
        normalized="(stats)",
        object_type=LensObjectType.REPORT,
        value="(stats)",
    )

    result = LensResult(
        lens_object=sentinel_obj,
        status="classified",
        summary=summary,
        sources={"classifier": "ok", "stats": "ok"},
        findings=(finding,),
    )

    return LensRun(
        schema_version=1,
        tool="cn-lens",
        workflow="stats",
        run_id=run_id,
        inputs=object_set,
        results=(result,),
        warnings=(),
        errors=(),
    )
