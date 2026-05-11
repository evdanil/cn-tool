from __future__ import annotations

import json
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

import yaml
from openpyxl import Workbook

from cn_lens.models import (
    InvalidLensObject,
    LensFinding,
    LensObject,
    LensResult,
    LensRun,
    ObjectSet,
)

if TYPE_CHECKING:
    from cn_lens.reports.aggregate import LensReport


# Workflow names whose summary blocks receive per-workflow rendering treatment.
# When a LensResult's summary dict has one of these keys the renderer emits a
# fenced code block (markdown) or a Per-Workflow row (xlsx).
_WORKFLOW_SUMMARY_KEYS: frozenset[str] = frozenset(
    {
        "impact",
        "dns",
        "reachability",
        "device",
        "validate_site",
        "decommission_site",
        "allocate",
        "config_find",
        "report",
    }
)


def _plain_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _plain_value(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, Mapping):
        return {str(key): _plain_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_value(item) for item in value]
    if isinstance(value, list):
        return [_plain_value(item) for item in value]
    return value


def _object_to_dict(lens_object: LensObject) -> dict[str, Any]:
    return {
        "original": lens_object.original,
        "normalized": lens_object.normalized,
        "object_type": lens_object.object_type.value,
        "value": lens_object.value,
        "notes": list(lens_object.notes),
    }


def _invalid_to_dict(invalid: InvalidLensObject) -> dict[str, str]:
    return {
        "original": invalid.original,
        "reason": invalid.reason,
    }


def _object_set_to_dict(inputs: ObjectSet) -> dict[str, Any]:
    return {
        "objects": [_object_to_dict(lens_object) for lens_object in inputs.objects],
        "invalid": [_invalid_to_dict(invalid) for invalid in inputs.invalid],
        "duplicate_count": inputs.duplicate_count,
    }


def _finding_to_dict(finding: LensFinding) -> dict[str, Any]:
    return {
        "severity": finding.severity,
        "source": finding.source,
        "message": finding.message,
        "detail": _plain_value(finding.detail),
    }


def _result_to_dict(result: LensResult) -> dict[str, Any]:
    return {
        "lens_object": _object_to_dict(result.lens_object),
        "status": result.status,
        "summary": _plain_value(result.summary),
        "findings": [_finding_to_dict(finding) for finding in result.findings],
        "sources": _plain_value(result.sources),
    }


def run_to_dict(run: LensRun) -> dict[str, Any]:
    return {
        "schema_version": run.schema_version,
        "tool": run.tool,
        "workflow": run.workflow,
        "run_id": run.run_id,
        "inputs": _object_set_to_dict(run.inputs),
        "results": [_result_to_dict(result) for result in run.results],
        "warnings": list(run.warnings),
        "errors": list(run.errors),
    }


def render_json(run: LensRun) -> str:
    return json.dumps(run_to_dict(run), indent=2, sort_keys=False) + "\n"


def render_yaml(run: LensRun) -> str:
    return yaml.safe_dump(run_to_dict(run), sort_keys=False)


def render_markdown(run: LensRun) -> str:
    lines = [
        f"# {run.tool} {run.workflow} report",
        "",
        "## Summary",
        "",
        f"- Schema version: {run.schema_version}",
        f"- Run ID: {run.run_id}",
        f"- Objects: {len(run.inputs.objects)}",
        f"- Invalid inputs: {len(run.inputs.invalid)}",
        f"- Duplicate inputs: {run.inputs.duplicate_count}",
        f"- Results: {len(run.results)}",
    ]
    if run.warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in run.warnings)
    if run.errors:
        lines.extend(["", "## Errors", ""])
        lines.extend(f"- {error}" for error in run.errors)
    if run.inputs.invalid:
        lines.extend(["", "## Invalid Inputs", ""])
        lines.extend(
            f"- `{invalid.original}`: {invalid.reason}" for invalid in run.inputs.invalid
        )
    if run.results:
        lines.extend(["", "## Results", ""])
        for result in run.results:
            obj = result.lens_object
            lines.extend(
                [
                    f"### {obj.value}",
                    "",
                    f"- Type: {obj.object_type.value}",
                    f"- Status: {result.status}",
                ]
            )
            if result.sources:
                lines.append("- Sources: " + _join_mapping(result.sources))
            if result.summary:
                workflow_blocks = _extract_workflow_summary_blocks(result.summary)
                plain_summary = _plain_value(result.summary)
                if workflow_blocks:
                    # Emit non-workflow summary keys inline (if any remain)
                    non_workflow = {
                        k: v
                        for k, v in plain_summary.items()  # type: ignore[union-attr]
                        if k not in _WORKFLOW_SUMMARY_KEYS
                    }
                    if non_workflow:
                        lines.append(
                            "- Summary: "
                            + json.dumps(non_workflow, sort_keys=True)
                        )
                    # Emit each workflow-specific block as a fenced YAML block
                    for wf_key, wf_value in _plain_value(workflow_blocks).items():
                        lines.extend(
                            [
                                "",
                                f"#### Workflow: {wf_key}",
                                "",
                                "```yaml",
                                yaml.safe_dump(
                                    {wf_key: wf_value}, sort_keys=False
                                ).rstrip(),
                                "```",
                            ]
                        )
                else:
                    lines.append(
                        "- Summary: "
                        + json.dumps(plain_summary, sort_keys=True)
                    )
            if result.findings:
                lines.append("- Findings:")
                lines.extend(
                    f"  - {finding.severity} {finding.source}: {finding.message}"
                    for finding in result.findings
                )
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _join_mapping(values: Mapping[str, Any]) -> str:
    return ", ".join(f"{key}: {values[key]}" for key in sorted(values))


def _extract_workflow_summary_blocks(
    summary: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the subset of *summary* whose keys are known workflow names."""
    return {
        key: value
        for key, value in summary.items()
        if key in _WORKFLOW_SUMMARY_KEYS
    }


def _xlsx_safe_value(value: Any) -> Any:
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value


def _xlsx_safe_row(values: tuple[Any, ...]) -> tuple[Any, ...]:
    return tuple(_xlsx_safe_value(value) for value in values)


def _append_xlsx_row(sheet: Any, values: tuple[Any, ...]) -> None:
    sheet.append(_xlsx_safe_row(values))


def render_text(run: LensRun) -> str:
    lines = [
        f"{run.tool} {run.workflow} report",
        f"schema_version: {run.schema_version}",
        f"run_id: {run.run_id}",
        f"objects: {len(run.inputs.objects)}",
        f"invalid_inputs: {len(run.inputs.invalid)}",
        f"duplicate_inputs: {run.inputs.duplicate_count}",
    ]
    if run.warnings:
        lines.extend(["", "warnings:"])
        lines.extend(f"- {warning}" for warning in run.warnings)
    if run.errors:
        lines.extend(["", "errors:"])
        lines.extend(f"- {error}" for error in run.errors)
    if run.inputs.invalid:
        lines.extend(["", "invalid inputs:"])
        lines.extend(
            f"- {invalid.original}: {invalid.reason}" for invalid in run.inputs.invalid
        )
    if run.results:
        lines.extend(["", "results:"])
        for result in run.results:
            obj = result.lens_object
            lines.append(f"- {obj.value} ({obj.object_type.value}) status: {result.status}")
            if result.sources:
                lines.append(f"  sources: {_join_mapping(result.sources)}")
            if result.summary:
                lines.append(f"  summary: {json.dumps(_plain_value(result.summary), sort_keys=True)}")
            for finding in result.findings:
                lines.append(
                    f"  finding: {finding.severity} {finding.source}: {finding.message}"
                )
    return "\n".join(lines) + "\n"


def render_human(run: LensRun) -> str:
    return render_text(run)


def write_xlsx(run: LensRun, path: Path) -> None:
    workbook = Workbook()
    summary = workbook.active
    summary.title = "Summary"
    _append_xlsx_row(summary, ("Field", "Value"))
    _append_xlsx_row(summary, ("schema_version", run.schema_version))
    _append_xlsx_row(summary, ("tool", run.tool))
    _append_xlsx_row(summary, ("workflow", run.workflow))
    _append_xlsx_row(summary, ("run_id", run.run_id))
    _append_xlsx_row(summary, ("objects", len(run.inputs.objects)))
    _append_xlsx_row(summary, ("invalid_inputs", len(run.inputs.invalid)))
    _append_xlsx_row(summary, ("duplicate_inputs", run.inputs.duplicate_count))
    _append_xlsx_row(summary, ("warnings", len(run.warnings)))
    _append_xlsx_row(summary, ("errors", len(run.errors)))

    inputs = workbook.create_sheet("Inputs")
    _append_xlsx_row(
        inputs,
        ("kind", "original", "normalized", "object_type", "value", "reason", "notes"),
    )
    for obj in run.inputs.objects:
        _append_xlsx_row(
            inputs,
            (
                "object",
                obj.original,
                obj.normalized,
                obj.object_type.value,
                obj.value,
                "",
                "; ".join(obj.notes),
            ),
        )
    for invalid in run.inputs.invalid:
        _append_xlsx_row(
            inputs,
            ("invalid", invalid.original, "", "invalid", "", invalid.reason, ""),
        )

    results = workbook.create_sheet("Results")
    _append_xlsx_row(results, ("object", "object_type", "status", "summary", "sources"))
    for result in run.results:
        _append_xlsx_row(
            results,
            (
                result.lens_object.value,
                result.lens_object.object_type.value,
                result.status,
                json.dumps(_plain_value(result.summary), sort_keys=True),
                json.dumps(_plain_value(result.sources), sort_keys=True),
            ),
        )

    findings = workbook.create_sheet("Findings")
    _append_xlsx_row(findings, ("object", "severity", "source", "message", "detail"))
    for result in run.results:
        for finding in result.findings:
            _append_xlsx_row(
                findings,
                (
                    result.lens_object.value,
                    finding.severity,
                    finding.source,
                    finding.message,
                    json.dumps(_plain_value(finding.detail), sort_keys=True),
                ),
            )

    # --- Per-Workflow sheet (only when workflow-specific summary keys exist) ---
    per_workflow_rows: list[tuple[str, str, str, str]] = []
    for result in run.results:
        workflow_blocks = _extract_workflow_summary_blocks(result.summary)
        if not workflow_blocks:
            continue
        plain_blocks = _plain_value(workflow_blocks)
        for wf_key, wf_value in plain_blocks.items():
            if isinstance(wf_value, dict):
                for k, v in wf_value.items():
                    str_v = (
                        json.dumps(v, sort_keys=True)
                        if isinstance(v, (dict, list))
                        else str(v)
                    )
                    per_workflow_rows.append(
                        (result.lens_object.value, wf_key, str(k), str_v)
                    )
            elif isinstance(wf_value, list):
                for item in wf_value:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            str_v = (
                                json.dumps(v, sort_keys=True)
                                if isinstance(v, (dict, list))
                                else str(v)
                            )
                            per_workflow_rows.append(
                                (result.lens_object.value, wf_key, str(k), str_v)
                            )
                    else:
                        per_workflow_rows.append(
                            (result.lens_object.value, wf_key, "", str(item))
                        )
            else:
                per_workflow_rows.append(
                    (result.lens_object.value, wf_key, "", str(wf_value))
                )

    if per_workflow_rows:
        pw_sheet = workbook.create_sheet("Per-Workflow")
        _append_xlsx_row(pw_sheet, ("object", "workflow", "key", "value"))
        for row in per_workflow_rows:
            _append_xlsx_row(pw_sheet, row)

    workbook.save(path)


def render_report(report: "LensReport", fmt: str, output: Path | None = None) -> str | None:
    """Render a ``LensReport`` aggregate in the requested format.

    Parameters
    ----------
    report:
        The ``LensReport`` to render.
    fmt:
        Output format string.  Same set as ``render_run`` plus aliases.
    output:
        When provided, write to file and return ``None``.  When ``None``,
        return the rendered string.

    Returns
    -------
    str | None
        Rendered text, or ``None`` when *output* is supplied.

    Raises
    ------
    ValueError
        Unknown format string, or xlsx requested without *output*.
    OSError
        Write failure when *output* is supplied.
    """
    # Lazy import to break the renderers ↔ aggregate circular dependency.
    # Imported once here and passed as an argument to the inner helpers that
    # require it, avoiding three separate identical local imports.
    from cn_lens.reports.aggregate import report_to_dict

    normalized_fmt = fmt.lower()
    if normalized_fmt == "yml":
        normalized_fmt = "yaml"

    if normalized_fmt == "xlsx":
        if output is None:
            raise ValueError("xlsx output requires an output path")
        _write_report_xlsx(report, output)
        return None

    report_dict = report_to_dict(report)

    renderers_map = {
        "json": _render_report_json,
        "yaml": _render_report_yaml,
        "markdown": _render_report_markdown,
        "md": _render_report_markdown,
        "text": _render_report_text,
        "txt": _render_report_text,
        "human": _render_report_text,
    }
    renderer = renderers_map.get(normalized_fmt)
    if renderer is None:
        raise ValueError(f"unknown render format: {fmt}")

    rendered = renderer(report, report_dict)
    if output is None:
        return rendered
    output.write_text(rendered, encoding="utf-8")
    return None


def _render_report_json(report: "LensReport", report_dict: dict[str, Any]) -> str:
    return json.dumps(report_dict, indent=2, sort_keys=False) + "\n"


def _render_report_yaml(report: "LensReport", report_dict: dict[str, Any]) -> str:
    return yaml.safe_dump(report_dict, sort_keys=False)


def _render_report_markdown(report: "LensReport", report_dict: dict[str, Any]) -> str:
    lines = [
        "# cn-lens report",
        "",
        "## Summary",
        "",
        f"- Report ID: {report.report_id}",
        f"- Tool: {report.tool}",
        f"- Schema version: {report.schema_version}",
        f"- Generated at: {report.generated_at}",
        f"- Runs included: {len(report.runs)}",
    ]
    if report.findings:
        lines.extend(["", "## Findings", ""])
        for finding in report.findings:
            lines.append(
                f"- {finding.severity} {finding.source}: {finding.message}"
            )
    for run in report.runs:
        lines.extend([
            "",
            f"## Run {run.run_id} ({run.workflow})",
            "",
            f"- Tool: {run.tool}",
            f"- Workflow: {run.workflow}",
            f"- Objects: {len(run.inputs.objects)}",
            f"- Results: {len(run.results)}",
        ])
        if run.warnings:
            lines.append(f"- Warnings: {len(run.warnings)}")
        if run.errors:
            lines.append(f"- Errors: {len(run.errors)}")
    return "\n".join(lines).rstrip() + "\n"


def _render_report_text(report: "LensReport", report_dict: dict[str, Any]) -> str:
    lines = [
        "cn-lens report",
        f"report_id: {report.report_id}",
        f"tool: {report.tool}",
        f"schema_version: {report.schema_version}",
        f"generated_at: {report.generated_at}",
        f"runs: {len(report.runs)}",
    ]
    if report.findings:
        lines.extend(["", "findings:"])
        for finding in report.findings:
            lines.append(
                f"- {finding.severity} {finding.source}: {finding.message}"
            )
    for run in report.runs:
        lines.extend([
            "",
            f"run: {run.run_id} ({run.workflow})",
            f"  tool: {run.tool}",
            f"  objects: {len(run.inputs.objects)}",
            f"  results: {len(run.results)}",
        ])
    return "\n".join(lines) + "\n"


def _write_report_xlsx(report: "LensReport", path: Path) -> None:
    """Write a LensReport to an xlsx workbook with per-run sheets."""
    workbook = Workbook()

    # --- Summary sheet ---
    summary_sheet = workbook.active
    summary_sheet.title = "Report Summary"
    _append_xlsx_row(summary_sheet, ("Field", "Value"))
    _append_xlsx_row(summary_sheet, ("schema_version", report.schema_version))
    _append_xlsx_row(summary_sheet, ("tool", report.tool))
    _append_xlsx_row(summary_sheet, ("report_id", report.report_id))
    _append_xlsx_row(summary_sheet, ("generated_at", report.generated_at))
    _append_xlsx_row(summary_sheet, ("runs_count", len(report.runs)))
    _append_xlsx_row(summary_sheet, ("findings_count", len(report.findings)))

    # --- Per-run sheets ---
    for run in report.runs:
        # Create a short sheet title slug from the run_id (max 31 chars for xlsx)
        slug = run.run_id[-15:] if len(run.run_id) > 15 else run.run_id
        sheet_title = f"{slug}"[:31]

        run_sheet = workbook.create_sheet(title=sheet_title)
        _append_xlsx_row(run_sheet, ("Field", "Value"))
        _append_xlsx_row(run_sheet, ("run_id", run.run_id))
        _append_xlsx_row(run_sheet, ("workflow", run.workflow))
        _append_xlsx_row(run_sheet, ("tool", run.tool))
        _append_xlsx_row(run_sheet, ("objects", len(run.inputs.objects)))
        _append_xlsx_row(run_sheet, ("results", len(run.results)))
        _append_xlsx_row(run_sheet, ("warnings", len(run.warnings)))
        _append_xlsx_row(run_sheet, ("errors", len(run.errors)))

        # Results sub-table
        run_sheet.append([])
        _append_xlsx_row(run_sheet, ("object", "object_type", "status", "summary"))
        for result in run.results:
            _append_xlsx_row(
                run_sheet,
                (
                    result.lens_object.value,
                    result.lens_object.object_type.value,
                    result.status,
                    json.dumps(_plain_value(result.summary), sort_keys=True),
                ),
            )

    workbook.save(path)


def render_run(run: LensRun, fmt: str, output: Path | None = None) -> str | None:
    normalized_fmt = fmt.lower()
    if normalized_fmt == "yml":
        normalized_fmt = "yaml"
    if normalized_fmt == "xlsx":
        if output is None:
            raise ValueError("xlsx output requires an output path")
        write_xlsx(run, output)
        return None

    renderers = {
        "json": render_json,
        "yaml": render_yaml,
        "markdown": render_markdown,
        "md": render_markdown,
        "text": render_text,
        "txt": render_text,
        "human": render_human,
    }
    renderer = renderers.get(normalized_fmt)
    if renderer is None:
        raise ValueError(f"unknown render format: {fmt}")

    rendered = renderer(run)
    if output is None:
        return rendered
    output.write_text(rendered, encoding="utf-8")
    return None
