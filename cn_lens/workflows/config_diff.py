"""config_diff workflow — non-TUI snapshot diff via config_analyzer components.

Design decision D7 (specs/004-lens-foundation/plan.md):
    Reuse ``config_analyzer/utils.py`` to locate device snapshots and
    ``config_analyzer/parser.py`` to load them; produce pure Python unified diff
    via ``difflib``.  Textual is *never* imported.  If a function in
    ``config_analyzer/differ.py`` is needed and is Textual-coupled, the pure
    part is extracted to ``config_analyzer/core.py`` first; existing TUI tests
    stay green either way.

    Exit semantics (pipeline-friendly, like ``diff(1)``):
      exit 0  — snapshots are identical
      exit 1  — snapshots differ

CommandSpec surface:
    config diff DEVICE [--repo-root PATH] [--snapshots A B]
                       [--side-by-side] [--context N]

Summary block per result (``summary["config_diff"]``):
    has_changes     : bool      — True when diff is non-empty
    snapshot_a      : str       — filename/path label of the "from" snapshot
    snapshot_b      : str       — filename/path label of the "to" snapshot
    unified_diff    : str       — raw unified diff text (empty string when identical)
    hunks           : list[dict]— parsed hunk list; each hunk has:
                                   header : str   ("@@ -L,N +L,N @@" line)
                                   lines  : list[str]  (diff body lines)
    side_by_side    : str       — side-by-side text (only when --side-by-side)
    context_lines   : int       — context lines used (default 3)
"""
from __future__ import annotations

import dataclasses
import difflib
import os
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from cn_lens.models import (
    InvalidLensObject,
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
    synthesise_error_finding,
)

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


# ---------------------------------------------------------------------------
# Pure diff helpers (no Textual, no Rich imports)
# ---------------------------------------------------------------------------

def _unified_diff_text(
    content_a: str,
    content_b: str,
    filename_a: str,
    filename_b: str,
    context: int = 3,
) -> str:
    """Return a raw unified diff string in standard format.

    Uses ``splitlines(keepends=True)`` on input and the default ``lineterm``
    so that header lines (``---``, ``+++``, ``@@``) each end with ``\\n``.
    This produces a proper line-oriented string that can be reliably split
    back into individual lines for hunk parsing.

    No Rich/Textual dependency — pure stdlib only.
    """
    context = max(0, context)  # negative n makes difflib emit malformed @@ headers
    lines_a = content_a.splitlines(keepends=True)
    lines_b = content_b.splitlines(keepends=True)
    diff_lines = list(difflib.unified_diff(
        lines_a,
        lines_b,
        fromfile=filename_a,
        tofile=filename_b,
        n=context,
    ))
    # Ensure every header line (---/+++/@@) ends with \n so the concatenated
    # string can be split cleanly.  Content lines already have \n from
    # splitlines(keepends=True); header lines produced by unified_diff do not.
    result: List[str] = []
    for line in diff_lines:
        if line and not line.endswith("\n"):
            line = line + "\n"
        result.append(line)
    return "".join(result)


def _parse_hunks(diff_text: str) -> List[Dict[str, Any]]:
    """Parse a unified diff string into a list of hunk dicts.

    Each hunk:
        header : str          — the ``@@ … @@`` line
        lines  : list[str]    — body lines (context, additions, deletions)
    """
    hunks: List[Dict[str, Any]] = []
    current_hunk: Optional[Dict[str, Any]] = None

    for line in diff_text.splitlines():
        if line.startswith("@@"):
            if current_hunk is not None:
                hunks.append(current_hunk)
            current_hunk = {"header": line, "lines": []}
        elif line.startswith(("---", "+++")):
            # File headers — skip (they are part of diff preamble, not hunks)
            continue
        elif current_hunk is not None:
            current_hunk["lines"].append(line)

    if current_hunk is not None:
        hunks.append(current_hunk)

    return hunks


def _side_by_side_text(
    content_a: str,
    content_b: str,
    filename_a: str,
    filename_b: str,
    total_width: int = 160,
) -> str:
    """Return a plain-text side-by-side diff.

    Produces the same logical output as ``config_analyzer.differ.get_diff_side_by_side``
    but as a plain string (no Rich Text/Syntax objects) so it can be written to
    files, piped through tools, and included in structured output formats.
    """
    left_lines = content_a.splitlines()
    right_lines = content_b.splitlines()
    matcher = difflib.SequenceMatcher(None, left_lines, right_lines, autojunk=False)

    divider = " | "
    column_width = max((max(total_width, 60) - len(divider)) // 2, 20)

    def _fit(text: str, width: int) -> str:
        if len(text) <= width:
            return text.ljust(width)
        return text[: width - 3] + "..."

    output_lines: List[str] = []
    output_lines.append(_fit(filename_a, column_width) + divider + _fit(filename_b, column_width))
    output_lines.append("-" * column_width + divider + "-" * column_width)

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for left, right in zip(left_lines[i1:i2], right_lines[j1:j2]):
                output_lines.append(_fit(left, column_width) + divider + _fit(right, column_width))
        elif tag == "replace":
            left_block = left_lines[i1:i2]
            right_block = right_lines[j1:j2]
            for idx in range(max(len(left_block), len(right_block))):
                left = left_block[idx] if idx < len(left_block) else ""
                right = right_block[idx] if idx < len(right_block) else ""
                output_lines.append(_fit(left, column_width) + divider + _fit(right, column_width))
        elif tag == "delete":
            for left in left_lines[i1:i2]:
                output_lines.append(_fit(left, column_width) + divider + _fit("", column_width))
        else:  # insert
            for right in right_lines[j1:j2]:
                output_lines.append(_fit("", column_width) + divider + _fit(right, column_width))

    return "\n".join(output_lines)


# ---------------------------------------------------------------------------
# Snapshot loading helpers (reuse config_analyzer.utils — pure, no Textual)
# ---------------------------------------------------------------------------

def _load_snapshots_auto(
    device: str,
    repo_root: str,
) -> Tuple[Optional[Any], Optional[Any], Optional[str]]:
    """Locate and load the two most recent snapshots for *device*.

    Returns ``(snap_a, snap_b, error_message)``.  On success error_message is
    ``None``.  ``snap_a`` is the newer snapshot (latest), ``snap_b`` is older
    (previous).
    """
    try:
        from config_analyzer.utils import collect_snapshots
    except ImportError as exc:
        return None, None, f"config_analyzer not importable: {exc}"

    try:
        snapshots = collect_snapshots(repo_root, device, None, "history")
    except Exception as exc:
        return None, None, f"Failed to collect snapshots: {exc}"

    if len(snapshots) < 2:
        msg = (
            f"Device {device!r} has fewer than 2 snapshots in {repo_root!r} "
            f"(found {len(snapshots)}); cannot diff"
        )
        return None, None, msg

    # collect_snapshots returns [Current (if present and different), ...history newest first]
    snap_a = snapshots[0]
    snap_b = snapshots[1]
    return snap_a, snap_b, None


def _load_snapshot_from_path(path: str) -> Tuple[Optional[Any], Optional[str]]:
    """Load a snapshot from an explicit file path.

    Returns ``(snapshot, error_message)``.
    """
    try:
        from config_analyzer.parser import parse_snapshot
    except ImportError as exc:
        return None, f"config_analyzer.parser not importable: {exc}"

    try:
        snap = parse_snapshot(path)
    except Exception as exc:
        return None, f"Failed to parse snapshot {path!r}: {exc}"

    if snap is None:
        return None, f"Snapshot file not readable or empty: {path!r}"

    return snap, None


# ---------------------------------------------------------------------------
# Core diff computation
# ---------------------------------------------------------------------------

def _compute_diff(
    snap_a: Any,
    snap_b: Any,
    *,
    side_by_side: bool = False,
    context: int = 3,
) -> Dict[str, Any]:
    """Compute the diff summary dict from two Snapshot objects."""
    content_a = snap_a.content_body
    content_b = snap_b.content_body
    filename_a = snap_a.original_filename
    filename_b = snap_b.original_filename

    unified = _unified_diff_text(content_a, content_b, filename_a, filename_b, context=context)
    has_changes = bool(unified)
    hunks = _parse_hunks(unified) if has_changes else []

    result: Dict[str, Any] = {
        "has_changes": has_changes,
        "snapshot_a": snap_a.path,
        "snapshot_b": snap_b.path,
        "unified_diff": unified,
        "hunks": hunks,
        "context_lines": context,
    }

    if side_by_side:
        result["side_by_side"] = _side_by_side_text(
            content_a, content_b, filename_a, filename_b
        )

    return result


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def config_diff(
    device: str,
    *,
    repo_root: Optional[str] = None,
    snapshot_a: Optional[str] = None,
    snapshot_b: Optional[str] = None,
    side_by_side: bool = False,
    context: int = 3,
    runtime: Optional["LensRuntime"] = None,
    run_id: Optional[str] = None,
) -> LensRun:
    """Diff two snapshots for *device* and return a LensRun.

    Parameters
    ----------
    device:
        Device name (without ``.cfg`` extension).
    repo_root:
        Path to the config repository root.  Used when locating snapshots
        automatically (when ``snapshot_a``/``snapshot_b`` are not given).
        Falls back to ``runtime.config.get('config_repo', 'repo_path')``
        when available.
    snapshot_a:
        Explicit path to the "from" snapshot file.  When ``None``, the
        most recent snapshot for *device* is used.
    snapshot_b:
        Explicit path to the "to" snapshot file.  When ``None``, the
        second-most-recent snapshot for *device* is used.
    side_by_side:
        When ``True``, also populate ``summary["config_diff"]["side_by_side"]``
        with a plain-text side-by-side diff.
    context:
        Number of context lines in the unified diff (default 3).
    runtime:
        Optional ``LensRuntime``.  Used for run_id resolution and config
        lookup (``config_repo``/``repo_path``).
    run_id:
        Explicit run identifier.  Precedence:
        1. ``run_id`` kwarg
        2. ``runtime.options.run_id``
        3. Auto-generated UTC timestamp.

    Returns
    -------
    LensRun
        Always returned; never raises.  Error conditions are captured as
        ``LensFinding`` entries with severity ``"error"``.
    """
    # --- Resolve run_id ---
    if run_id is not None:
        effective_run_id = run_id
    elif runtime is not None and runtime.options.run_id is not None:
        effective_run_id = runtime.options.run_id
    else:
        effective_run_id = make_run_id()

    # --- Build the single-object ObjectSet (device name as DEVICE type) ---
    device_object = LensObject(
        original=device,
        normalized=device,
        object_type=LensObjectType.DEVICE,
        value=device,
    )
    object_set = ObjectSet(
        objects=(device_object,),
        invalid=(),
        duplicate_count=0,
    )

    # --- Resolve repo_root from runtime config if not given ---
    effective_repo_root = repo_root
    if effective_repo_root is None and runtime is not None:
        effective_repo_root = runtime.cfg.get("config_repo_directory") or None

    # --- Load snapshots ---
    findings: List[LensFinding] = []
    diff_summary: Dict[str, Any]

    if snapshot_a is not None and snapshot_b is not None:
        # Explicit snapshot paths
        snap_a, err_a = _load_snapshot_from_path(snapshot_a)
        snap_b, err_b = _load_snapshot_from_path(snapshot_b)

        if err_a or snap_a is None:
            msg = err_a or f"Cannot read {snapshot_a!r}"
            findings.append(LensFinding(
                severity="error",
                source="config_diff",
                message=msg,
                detail={"path": snapshot_a},
            ))
            diff_summary = {
                "has_changes": False,
                "snapshot_a": snapshot_a,
                "snapshot_b": snapshot_b,
                "unified_diff": "",
                "hunks": [],
                "context_lines": context,
                "error": msg,
            }
        elif err_b or snap_b is None:
            msg = err_b or f"Cannot read {snapshot_b!r}"
            findings.append(LensFinding(
                severity="error",
                source="config_diff",
                message=msg,
                detail={"path": snapshot_b},
            ))
            diff_summary = {
                "has_changes": False,
                "snapshot_a": snapshot_a,
                "snapshot_b": snapshot_b,
                "unified_diff": "",
                "hunks": [],
                "context_lines": context,
                "error": msg,
            }
        else:
            diff_summary = _compute_diff(snap_a, snap_b, side_by_side=side_by_side, context=context)
    else:
        # Auto-locate from repo
        if effective_repo_root is None:
            msg = (
                "No --repo-root provided and config_repo path not found in runtime config. "
                "Provide --repo-root or configure config_repo.repo_path."
            )
            findings.append(LensFinding(
                severity="error",
                source="config_diff",
                message=msg,
                detail={},
            ))
            diff_summary = {
                "has_changes": False,
                "snapshot_a": "",
                "snapshot_b": "",
                "unified_diff": "",
                "hunks": [],
                "context_lines": context,
                "error": msg,
            }
        else:
            snap_a, snap_b, error_msg = _load_snapshots_auto(device, effective_repo_root)
            if error_msg:
                findings.append(LensFinding(
                    severity="error",
                    source="config_diff",
                    message=error_msg,
                    detail={"device": device, "repo_root": effective_repo_root},
                ))
                diff_summary = {
                    "has_changes": False,
                    "snapshot_a": "",
                    "snapshot_b": "",
                    "unified_diff": "",
                    "hunks": [],
                    "context_lines": context,
                    "error": error_msg,
                }
            else:
                diff_summary = _compute_diff(
                    snap_a, snap_b, side_by_side=side_by_side, context=context
                )

    result_summary: Dict[str, Any] = {
        "original": device,
        "normalized": device,
        "type": LensObjectType.DEVICE.value,
        "config_diff": diff_summary,
    }

    result = LensResult(
        lens_object=device_object,
        status="classified",
        summary=result_summary,
        findings=tuple(findings),
        sources={"classifier": "ok"},
    )

    run = LensRun(
        schema_version=1,
        tool="cn-lens",
        workflow="config_diff",
        run_id=effective_run_id,
        inputs=object_set,
        results=(result,),
        warnings=(),
        errors=(),
    )
    maybe_persist(run, runtime)
    return run
