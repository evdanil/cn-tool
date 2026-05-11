"""Report workflow — bundle persisted LensRun objects into a LensReport.

This module exposes two public callables:

report_objects(object_set, *, runtime, ...) -> LensRun
    Returns a ``LensRun`` whose ``workflow == "report"``.  The first
    ``LensResult`` carries a ``summary["report"]`` block containing
    ``report_id``, ``runs_included``, ``email_sent``, and ``output_path``.
    Suitable for the standard ``render_run`` pipeline.

report_runs(*, runtime, ...) -> LensReport
    Returns the actual ``LensReport`` aggregate, suitable for ``render_report``.

Internal helper:

_build_report_artifacts(*, runtime, run_id, include, from_last, email,
                         _last_run) -> tuple[LensReport, LensRun]
    Collects bundled runs, performs email dispatch, and returns both the
    ``LensReport`` (with findings) and a synthesised summary ``LensRun``
    (``workflow="report"``) in a single call.  Both ``report_objects`` and
    ``report_runs`` (via ``_run_report`` in the CLI) delegate to this helper
    so email dispatch is unified.

Email-plugin discovery
----------------------
The workflow looks for a plugin in ``runtime.context.plugins`` whose class name
or ``name`` attribute contains the string ``"email"`` (case-insensitive).
It never imports ``plugins.email_support`` directly — it uses duck typing via
the ``EmailSender`` Protocol defined here.

Offline / None runtime
-----------------------
Both functions return their respective empty-bundle results without consulting
persistence.

Findings severity conventions
------------------------------
- ``info`` : normal informational events (no previous run, email skipped).
- ``warning`` : recoverable data issue (run_id not found in persistence).
- ``error`` : runtime exception (email send failure).
"""
from __future__ import annotations

import logging
import collections.abc
from pathlib import Path
from typing import Any, Protocol, TYPE_CHECKING

from cn_lens.models import (
    LensFinding,
    LensObject,
    LensObjectType,
    LensResult,
    LensRun,
    ObjectSet,
)
from cn_lens.workflows._helpers import (
    make_run_id,
    maybe_persist,
    synthesise_error_finding as _synthesise_error_finding,
)

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime
    from cn_lens.reports.aggregate import LensReport

_LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# EmailSender Protocol — duck-typed, never imports the plugin directly.
# ---------------------------------------------------------------------------

class EmailSender(Protocol):
    """Narrow protocol for the email plugin interface."""

    def send(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        attachments: collections.abc.Sequence[Path],
    ) -> bool:
        """Send an email.  Return True on success, False otherwise."""
        ...


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _make_empty_object_set() -> ObjectSet:
    return ObjectSet(objects=(), invalid=(), duplicate_count=0)


def _find_email_plugin(runtime: "LensRuntime") -> EmailSender | None:
    """Return the first plugin that quacks like an EmailSender, or None."""
    plugins = getattr(getattr(runtime, "context", None), "plugins", []) or []
    for plugin in plugins:
        cls_name = type(plugin).__name__.lower()
        plugin_name = str(getattr(plugin, "name", "")).lower()
        if "email" in cls_name or "email" in plugin_name:
            if callable(getattr(plugin, "send", None)):
                return plugin  # type: ignore[return-value]
    return None


def _try_send_email(
    plugin: EmailSender,
    *,
    to: str,
    report_id: str,
    run_count: int,
    attachments: collections.abc.Sequence[Path] | None = None,
) -> bool:
    """Invoke ``plugin.send`` and return True on success."""
    body = (
        f"cn-lens report {report_id}\n"
        f"Runs included: {run_count}\n"
    )
    return bool(
        plugin.send(
            to=to,
            subject=f"cn-lens report {report_id}",
            body=body,
            attachments=list(attachments or []),
        )
    )


def _load_runs_from_include(
    include: collections.abc.Sequence[str],
    runtime: "LensRuntime",
    findings: list[LensFinding],
) -> list[LensRun]:
    """Load runs by run_id from persistence; add warning findings for misses.

    Each missing-id warning is also emitted at ``runtime.logger.warning``
    level so operators have an out-of-band signal in addition to the in-band
    ``LensReport.findings`` field.
    """
    from cn_lens.reports.persistence import load_run

    loaded: list[LensRun] = []
    for run_id in include:
        run = load_run(run_id, runtime)
        if run is None:
            msg = f"run_id not found in persistence: {run_id}"
            runtime.logger.warning("report: %s", msg)
            findings.append(
                LensFinding(
                    severity="warning",
                    source="report",
                    message=msg,
                    detail={"run_id": run_id},
                )
            )
        else:
            loaded.append(run)
    return loaded


def _build_report_result(
    run_id: str,
    summary_block: dict[str, Any],
    findings: list[LensFinding],
    sources: dict[str, str],
) -> LensResult:
    """Produce the single LensResult contained in the report LensRun.

    The sentinel ``LensObject`` uses ``LensObjectType.REPORT`` to distinguish
    the synthetic report object from normal network objects.
    """
    sentinel = LensObject(
        original="(report)",
        normalized="(report)",
        object_type=LensObjectType.REPORT,
        value="report",
    )
    return LensResult(
        lens_object=sentinel,
        status="reported",
        summary={"report": summary_block},
        findings=tuple(findings),
        sources=sources,
    )


# ---------------------------------------------------------------------------
# Private core: _build_report_artifacts
# ---------------------------------------------------------------------------

def _build_report_artifacts(
    *,
    runtime: "LensRuntime | None",
    run_id: str,
    include: collections.abc.Sequence[str] | None,
    from_last: bool,
    email: str | None,
    _last_run: LensRun | None,
    object_set: ObjectSet,
) -> "tuple[LensReport, LensRun]":
    """Collect bundled runs, dispatch email, and return (LensReport, LensRun).

    This is the single implementation shared by :func:`report_objects` and
    the :func:`report_runs` / CLI path.  It handles:

    - Offline / None runtime → returns empty-bundle artifacts with no
      persistence access.
    - Online → loads runs from ``include`` and/or ``from_last``; emits
      log messages and attaches findings for every anomaly; dispatches
      email when requested.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.  When ``None`` or ``offline``, returns an
        offline-shape result without reading persistence.
    run_id:
        Effective run ID for the synthesised summary ``LensRun``.
    include:
        Explicit run IDs to load from persistence.
    from_last:
        When ``True``, also include the most-recent persisted run.
    email:
        Recipient address for email dispatch; ``None`` to skip.
    _last_run:
        Injected "last run" (used by REPL/tests); bypasses persistence lookup.
    object_set:
        Carried through to the summary ``LensRun.inputs`` field.

    Returns
    -------
    tuple[LensReport, LensRun]
        The aggregate ``LensReport`` (with ``findings``) and the summary
        ``LensRun`` (``workflow="report"``).
    """
    from cn_lens.reports.aggregate import build_report, LensReport  # noqa: F401

    findings: list[LensFinding] = []

    # ------------------------------------------------------------------
    # Offline / no runtime path — no persistence access
    # ------------------------------------------------------------------
    if runtime is None or runtime.offline:
        # Offline sources dict is a constant; no registry call needed.
        sources: dict[str, str] = {"classifier": "ok"}
        summary_block: dict[str, Any] = {
            "report_id": run_id,
            "runs_included": 0,
            "email_sent": False,
            "output_path": None,
        }
        report = build_report([], report_id=run_id, findings=findings)
        result = _build_report_result(run_id, summary_block, findings, sources)
        summary_run = LensRun(
            schema_version=1,
            tool="cn-lens",
            workflow="report",
            run_id=run_id,
            inputs=object_set,
            results=(result,),
            warnings=(),
            errors=(),
        )
        return report, summary_run

    # ------------------------------------------------------------------
    # Online path — collect runs
    # ------------------------------------------------------------------
    bundled_runs: list[LensRun] = []

    # 1. --include runs (always first)
    if include:
        bundled_runs.extend(_load_runs_from_include(include, runtime, findings))

    # 2. --from-last
    if from_last:
        last: LensRun | None = _last_run
        if last is None:
            # Try to load the single most-recent run from persistence
            from cn_lens.reports.persistence import list_runs, load_run
            recent = list_runs(runtime, limit=1)
            if recent:
                last = load_run(recent[0].parent.name, runtime)
        if last is None:
            msg = "No previous run available"
            runtime.logger.info("report: %s", msg)
            findings.append(
                LensFinding(
                    severity="info",
                    source="report",
                    message=msg,
                    detail={},
                )
            )
        else:
            bundled_runs.append(last)

    # 3. Build aggregate report (includes findings)
    report = build_report(bundled_runs, report_id=run_id, findings=findings)

    # 4. Email dispatch
    email_sent = False
    if email:
        plugin = _find_email_plugin(runtime)
        if plugin is None:
            findings.append(
                LensFinding(
                    severity="info",
                    source="report",
                    message="email plugin not loaded — skipping",
                    detail={"to": email},
                )
            )
        else:
            try:
                email_sent = _try_send_email(
                    plugin,
                    to=email,
                    report_id=report.report_id,
                    run_count=len(bundled_runs),
                )
            except Exception as exc:
                runtime.logger.error("report: email send failed: %s", exc)
                findings.append(
                    LensFinding(
                        severity="error",
                        source="report",
                        message=f"email send failed: {exc}",
                        detail={"exception": type(exc).__name__, "to": email},
                    )
                )
                email_sent = False

    # Rebuild report with the final findings list (email findings added above)
    report = build_report(bundled_runs, report_id=run_id, findings=findings)

    # 5. Resolve sources via registry (mirrors the online inspect path)
    from cn_lens.adapters.registry import get_registry
    registry = get_registry()
    online_sources: dict[str, str] = {"classifier": "ok"}
    online_sources.update(registry.source_statuses(runtime))

    summary_block = {
        "report_id": report.report_id,
        "runs_included": len(bundled_runs),
        "email_sent": email_sent,
        "output_path": None,
    }

    result = _build_report_result(run_id, summary_block, findings, online_sources)
    summary_run = LensRun(
        schema_version=1,
        tool="cn-lens",
        workflow="report",
        run_id=run_id,
        inputs=object_set,
        results=(result,),
        warnings=(),
        errors=(),
    )
    return report, summary_run


# ---------------------------------------------------------------------------
# Public: report_objects
# ---------------------------------------------------------------------------

def report_objects(
    object_set: ObjectSet,
    *,
    runtime: "LensRuntime | None" = None,
    run_id: str | None = None,
    include: collections.abc.Sequence[str] | None = None,
    from_last: bool = False,
    email: str | None = None,
    # Internal hook: allows callers (tests) to inject the "last run" directly
    # without going through REPL state.
    _last_run: LensRun | None = None,
) -> LensRun:
    """Bundle persisted runs into a LensRun summary.

    Parameters
    ----------
    object_set:
        Input object set (usually empty for report; carried through to satisfy
        the LensRun model).
    runtime:
        Active ``LensRuntime``.  When ``None`` or ``offline``, returns an
        offline-shape result without reading persistence.
    run_id:
        Explicit run ID for this report run.  Auto-generated when ``None``.
    include:
        List of run_id strings to include from persistence.
    from_last:
        When ``True``, also include the last run from persistence (or
        ``_last_run`` when provided).
    email:
        When set, attempt to send the report via the email plugin.
    _last_run:
        Injected "last run" (used by REPL/tests); bypasses persistence lookup.

    Returns
    -------
    LensRun
        A ``LensRun`` with ``workflow="report"`` whose first ``LensResult``
        carries ``summary["report"]`` with ``report_id``, ``runs_included``,
        ``email_sent``, and ``output_path``.  Never raises.
    """
    # Resolve run_id
    if run_id is not None:
        effective_run_id = run_id
    elif runtime is not None and runtime.options.run_id is not None:
        effective_run_id = runtime.options.run_id
    else:
        effective_run_id = make_run_id()

    _report, summary_run = _build_report_artifacts(
        runtime=runtime,
        run_id=effective_run_id,
        include=include,
        from_last=from_last,
        email=email,
        _last_run=_last_run,
        object_set=object_set,
    )
    return summary_run


# ---------------------------------------------------------------------------
# Public: report_runs
# ---------------------------------------------------------------------------

def report_runs(
    *,
    runtime: "LensRuntime | None" = None,
    run_id: str | None = None,
    include: collections.abc.Sequence[str] | None = None,
    from_last: bool = False,
    email: str | None = None,
    _last_run: LensRun | None = None,
) -> "LensReport":
    """Build and return a ``LensReport`` aggregate.

    Same parameters as :func:`report_objects`; delegates all work to
    :func:`_build_report_artifacts` and returns the ``LensReport`` directly
    (not wrapped in a ``LensRun``).

    The returned ``LensReport.findings`` tuple contains report-level signals
    such as "No previous run available" (when ``from_last=True`` and no run
    exists) and per-missing-id warning findings (when ``include`` references
    run IDs not found in persistence).

    The CLI path uses this function and renders via ``render_report``.
    """
    from cn_lens.reports.aggregate import LensReport  # noqa: F401

    # Resolve run_id
    if run_id is not None:
        effective_run_id = run_id
    elif runtime is not None and hasattr(runtime, "options") and runtime.options.run_id is not None:
        effective_run_id = runtime.options.run_id
    else:
        effective_run_id = make_run_id()

    report, _summary_run = _build_report_artifacts(
        runtime=runtime,
        run_id=effective_run_id,
        include=include,
        from_last=from_last,
        email=email,
        _last_run=_last_run,
        object_set=_make_empty_object_set(),
    )
    return report
