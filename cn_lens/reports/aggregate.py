"""Aggregate layer — wraps multiple LensRun objects into a LensReport.

Public surface
--------------
LensReport
    Frozen dataclass holding multiple ``LensRun`` instances plus report-level
    metadata (report_id, generated_at, schema_version, tool).

build_report(runs, *, report_id=None) -> LensReport
    Construct a ``LensReport`` from an ordered sequence of ``LensRun`` objects.

report_to_dict(report) -> dict
    Convert a ``LensReport`` to a plain dict safe for JSON / YAML serialisation
    (no datetime objects, no Enum values).
"""
from __future__ import annotations

import collections.abc
from dataclasses import dataclass
from datetime import datetime, timezone

from cn_lens.models import LensFinding, LensRun
from cn_lens.renderers import run_to_dict
from cn_lens.workflows._helpers import make_run_id


# ---------------------------------------------------------------------------
# LensReport dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LensReport:
    """Aggregate report wrapping multiple ``LensRun`` objects.

    Attributes
    ----------
    schema_version:
        Monotonically increasing schema version (currently 1).
    tool:
        Always ``"cn-lens"``.
    report_id:
        Unique identifier for this report (UTC timestamp via ``make_run_id``).
    runs:
        Ordered tuple of ``LensRun`` objects included in this report.
    generated_at:
        ISO 8601 UTC timestamp string (e.g. ``"2026-05-10T14:23:00+00:00"``).
    findings:
        Report-level findings (e.g. "No previous run available", missing run_id
        warnings).  These are workflow-level signals that do not belong to any
        single ``LensRun`` in ``runs``.
    """

    schema_version: int
    tool: str
    report_id: str
    runs: tuple[LensRun, ...]
    generated_at: str
    findings: tuple[LensFinding, ...] = ()


# ---------------------------------------------------------------------------
# build_report
# ---------------------------------------------------------------------------

def build_report(
    runs: collections.abc.Sequence[LensRun],
    *,
    report_id: str | None = None,
    findings: collections.abc.Sequence[LensFinding] | None = None,
) -> LensReport:
    """Construct a ``LensReport`` from an ordered sequence of ``LensRun`` objects.

    Parameters
    ----------
    runs:
        Zero or more ``LensRun`` objects to include.  Ordering is preserved.
    report_id:
        Explicit report identifier.  When ``None``, a UTC timestamp is
        auto-generated via ``make_run_id()``.
    findings:
        Report-level findings (e.g. "No previous run available", missing-run
        warnings).  When ``None`` an empty tuple is used.

    Returns
    -------
    LensReport
        Frozen aggregate report.
    """
    effective_id = report_id if report_id is not None else make_run_id()
    generated_at = datetime.now(timezone.utc).isoformat()
    return LensReport(
        schema_version=1,
        tool="cn-lens",
        report_id=effective_id,
        runs=tuple(runs),
        generated_at=generated_at,
        findings=tuple(findings) if findings else (),
    )


# ---------------------------------------------------------------------------
# report_to_dict
# ---------------------------------------------------------------------------

def _finding_to_dict(finding: LensFinding) -> dict[str, object]:
    return {
        "severity": finding.severity,
        "source": finding.source,
        "message": finding.message,
        "detail": dict(finding.detail),
    }


def report_to_dict(report: LensReport) -> dict[str, object]:
    """Convert a ``LensReport`` to a JSON/YAML-safe plain dict.

    All ``LensRun`` objects are converted via the existing ``run_to_dict``
    helper so enum values and dataclass fields are fully serialised.
    The ``findings`` list contains report-level signals (missing runs, info
    messages) that do not belong to any single run.
    """
    return {
        "schema_version": report.schema_version,
        "tool": report.tool,
        "report_id": report.report_id,
        "generated_at": report.generated_at,
        "findings": [_finding_to_dict(f) for f in report.findings],
        "runs": [run_to_dict(r) for r in report.runs],
    }
