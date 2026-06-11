"""Report workflow — bundle persisted LensRun objects into a LensReport.

This module exposes two public callables:

report_runs(*, runtime, ...) -> LensReport
    Returns the actual ``LensReport`` aggregate, suitable for ``render_report``.

Internal helper:

_build_report_artifacts(*, runtime, run_id, include, from_last, email,
                         attachment_path, _last_run) -> tuple[LensReport, LensRun]
    Collects bundled runs, performs email dispatch, and returns both the
    ``LensReport`` (with findings) and a synthesised summary ``LensRun``
    (``workflow="report"``) in a single call.  ``report_runs`` (via
    ``_run_report`` in the CLI) delegates to this helper so email dispatch
    is unified.

Email dispatch
--------------
When ``--email TO`` is provided the workflow calls
``utils.email_helper.send_report_email`` directly using the SMTP configuration
keys that ``plugins.email_support.EmailReportPlugin`` contributes to the
merged ``cfg`` dict (``email_server``, ``email_port``, ``email_from``,
``email_use_tls``, ``email_use_ssl``, ``email_use_auth``, ``email_user``,
``email_password``).

The plugin schemas are collected by ``cn_lens.runtime._build_cfg`` via
``core.loader.collect_plugin_schemas``, so email keys are always present in
``runtime.cfg`` even though no plugin instances are loaded at runtime.

Unconfigured detection mirrors the plugin: ``email_enabled`` must be truthy in
``runtime.cfg``.  When falsy a warning-severity finding
``"email: not_configured"`` is appended and ``email_sent`` stays ``False``.

Attachment
----------
Pass ``attachment_path`` (typically the ``--output`` file) to supply an
attachment.  When ``None`` or not a regular file, ``send_report_email`` returns
``False`` (file-not-found guard inside the helper) and an error finding is
recorded.  The CLI (``_run_report``) renders the report first and then calls
the workflow with the output path so the rendered file is attached.

Offline / None runtime
-----------------------
Both functions return their respective empty-bundle results without consulting
persistence.

Findings severity conventions
------------------------------
- ``info`` : normal informational events (no previous run, email sent OK).
- ``warning`` : recoverable data issue (run_id not found; email unconfigured).
- ``error`` : runtime exception (email send failure).
"""
from __future__ import annotations

import logging
import collections.abc
from pathlib import Path
from typing import Any, TYPE_CHECKING

from cn_lens.models import (
    LensFinding,
    LensObject,
    LensObjectType,
    LensResult,
    LensRun,
    ObjectSet,
)
from cn_lens.workflows._helpers import make_run_id

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime
    from cn_lens.reports.aggregate import LensReport

_LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _make_empty_object_set() -> ObjectSet:
    return ObjectSet(objects=(), invalid=(), duplicate_count=0)


def _is_email_configured(cfg: dict) -> bool:
    """Return True when the email feature is enabled in ``cfg``.

    Mirrors ``plugins.email_support.EmailReportPlugin.disconnect`` which checks
    ``interpret_bool(ctx.cfg.get("email_enabled"))`` before attempting to send.
    The ``email_enabled`` key is contributed by the plugin's ``config_schema``
    and is present in ``runtime.cfg`` via ``collect_plugin_schemas``.
    """
    from utils.email_helper import interpret_bool
    return interpret_bool(cfg.get("email_enabled", False))


def _smtp_kwargs(cfg: dict) -> dict:
    """Return the SMTP keyword arguments extracted from ``cfg``.

    Single source of truth for SMTP configuration defaults and int-coercion of
    ``email_port``.  Used by both ``_build_report_artifacts`` (via
    ``dispatch_report_email``) and any future callers that need the same keys.
    """
    from utils.email_helper import interpret_bool
    try:
        port = int(cfg.get("email_port", 25))
    except (TypeError, ValueError):
        port = 25
    return {
        "smtp_server": cfg.get("email_server", "localhost"),
        "smtp_port": port,
        "sender_email": cfg.get("email_from", "cn-lens@localhost"),
        "use_tls": interpret_bool(cfg.get("email_use_tls", False)),
        "use_ssl": interpret_bool(cfg.get("email_use_ssl", False)),
        "use_auth": interpret_bool(cfg.get("email_use_auth", False)),
        "username": cfg.get("email_user", ""),
        "password": cfg.get("email_password", ""),
    }


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
        status="classified",
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
    attachment_path: Path | None = None,
) -> "tuple[LensReport, LensRun]":
    """Collect bundled runs, dispatch email, and return (LensReport, LensRun).

    This is the single implementation shared by both the REPL and CLI paths.
    It handles:

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
    attachment_path:
        Path to the rendered report file to attach to the email.  When
        ``None`` or not a regular file, ``send_report_email`` returns
        ``False`` (its own file-not-found guard) and an error finding is
        recorded.  Callers that want an attachment should render the report
        first and pass the output path here.

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

    # 4. Email dispatch — delegate to dispatch_report_email (single implementation)
    email_sent = False
    if email:
        email_sent, email_findings = dispatch_report_email(
            runtime,
            to=email,
            report_id=report.report_id,
            run_count=len(bundled_runs),
            attachment_path=attachment_path,
        )
        findings.extend(email_findings)

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
# Public: report_runs
# ---------------------------------------------------------------------------

def report_runs(
    *,
    runtime: "LensRuntime | None" = None,
    run_id: str | None = None,
    include: collections.abc.Sequence[str] | None = None,
    from_last: bool = False,
    email: str | None = None,
    attachment_path: Path | None = None,
    _last_run: LensRun | None = None,
) -> "LensReport":
    """Build and return a ``LensReport`` aggregate.

    Delegates all work to :func:`_build_report_artifacts` and returns the
    ``LensReport`` directly (not wrapped in a ``LensRun``).

    The returned ``LensReport.findings`` tuple contains report-level signals
    such as "No previous run available" (when ``from_last=True`` and no run
    exists) and per-missing-id warning findings (when ``include`` references
    run IDs not found in persistence).
    """
    from cn_lens.reports.aggregate import LensReport  # noqa: F401

    # Resolve run_id
    if run_id is not None:
        effective_run_id = run_id
    elif runtime is not None and runtime.options.run_id is not None:
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
        attachment_path=attachment_path,
    )
    return report


# ---------------------------------------------------------------------------
# Public: dispatch_report_email
# ---------------------------------------------------------------------------

def dispatch_report_email(
    runtime: "LensRuntime",
    *,
    to: str,
    report_id: str,
    run_count: int,
    attachment_path: Path | None = None,
) -> "tuple[bool, list[LensFinding]]":
    """Send the rendered report via ``send_report_email`` and return the outcome.

    This function is the CLI's post-render email hook.  It is called by
    ``cn_lens.cli._run_report`` *after* ``render_report`` has written the
    output file so that the rendered file can be attached.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime`` — must be online (not ``None``).
    to:
        Recipient e-mail address (the ``--email`` value).
    report_id:
        Report identifier used in the email subject / body.
    run_count:
        Number of runs included in the report (informational).
    attachment_path:
        Path to the rendered output file.  When ``None`` or not a regular
        file, ``send_report_email`` returns ``False`` (its own guard) and an
        error finding is recorded.

    Returns
    -------
    tuple[bool, list[LensFinding]]
        ``(email_sent, findings)`` where *findings* contains one finding
        describing the outcome (info on success, warning when unconfigured,
        error on failure).
    """
    findings: list[LensFinding] = []

    # Guard: email without a rendered output file is a no-op — do not fall back
    # to Path("report.json") which silently sends a non-existent attachment.
    if attachment_path is None:
        msg = "email requires --output: no attachment rendered, email not sent"
        runtime.logger.warning("report: %s", msg)
        findings.append(
            LensFinding(
                severity="warning",
                source="report",
                message=msg,
                detail={"to": to},
            )
        )
        return False, findings

    if not _is_email_configured(runtime.cfg):
        runtime.logger.warning(
            "report: email requested but email is not configured "
            "(email_enabled=False in cfg) — skipping"
        )
        findings.append(
            LensFinding(
                severity="warning",
                source="report",
                message="email: not_configured",
                detail={"to": to},
            )
        )
        return False, findings

    from utils.email_helper import send_report_email
    cfg = runtime.cfg
    body = (
        f"cn-lens report {report_id}\n"
        f"Runs included: {run_count}\n"
    )
    try:
        sent = send_report_email(
            logger=runtime.logger,
            receiver_email=to,
            subject=cfg.get("email_subject", f"cn-lens report {report_id}"),
            body=cfg.get("email_body", body),
            attachment_path=attachment_path,
            **_smtp_kwargs(cfg),
        )
    except Exception as exc:
        runtime.logger.error("report: email send failed: %s", exc)
        findings.append(
            LensFinding(
                severity="error",
                source="report",
                message=f"email send failed: {exc}",
                detail={"exception": type(exc).__name__, "to": to},
            )
        )
        return False, findings

    if sent:
        findings.append(
            LensFinding(
                severity="info",
                source="report",
                message=f"report emailed to {to}",
                detail={"to": to},
            )
        )
    else:
        findings.append(
            LensFinding(
                severity="error",
                source="report",
                message=f"email send failed to {to} — check SMTP config and attachment path",
                detail={"to": to},
            )
        )
    return sent, findings
