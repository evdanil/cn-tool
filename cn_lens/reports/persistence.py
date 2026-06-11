"""Persistence layer for LensRun objects.

Saves and loads LensRun instances as gzipped JSON files stored at:
    <output_dir>/cn-lens/<run_id>/run.json.gz

Public surface
--------------
persist_run(run, runtime) -> Path | None
    Write run to disk.  Returns the path on success or None if skipped/errored.

load_run(run_id, runtime) -> LensRun | None
    Read and reconstruct a LensRun.  Returns None on any failure.

list_runs(runtime, *, limit=None) -> list[Path]
    Return paths to run.json.gz files, sorted newest-first by mtime.
    Each path's parent.name is the run_id directory.

Design
------
- runtime is None or offline → persist_run returns None without writing.
- All IO errors are caught, logged, and never re-raised.
- Reconstruction uses a minimal dataclass-aware deserialiser contained here.
"""
from __future__ import annotations

import gzip
import json
import logging
from pathlib import Path
from typing import Any, TYPE_CHECKING

from cn_lens.models import (
    InvalidLensObject,
    LensFinding,
    LensObject,
    LensObjectType,
    LensResult,
    LensRun,
    ObjectSet,
)
from cn_lens.renderers import run_to_dict

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

_LOG = logging.getLogger(__name__)

_DEFAULT_OUTPUT_DIR = "./output"


# ---------------------------------------------------------------------------
# Internal: output directory resolution
# ---------------------------------------------------------------------------

def _output_dir(runtime: "LensRuntime") -> Path:
    """Resolve the base output directory from the runtime config.

    Only accepts a ``str`` or ``Path`` value from the config; any other type
    (e.g. a ``MagicMock`` in tests, or an unexpected object at runtime) is
    silently discarded in favour of ``_DEFAULT_OUTPUT_DIR``.
    """
    raw = runtime.cfg.get("output_dir")
    if not isinstance(raw, (str, Path)) or not str(raw).strip():
        raw = _DEFAULT_OUTPUT_DIR
    return Path(str(raw)).expanduser()


def _run_path(run_id: str, runtime: "LensRuntime") -> Path:
    """Return the full path to the gzipped JSON file for *run_id*."""
    return _output_dir(runtime) / "cn-lens" / run_id / "run.json.gz"


# ---------------------------------------------------------------------------
# persist_run
# ---------------------------------------------------------------------------

def persist_run(
    run: LensRun,
    runtime: "LensRuntime | None",
) -> "Path | None":
    """Write *run* to disk as gzipped JSON.

    Parameters
    ----------
    run:
        The ``LensRun`` to persist.
    runtime:
        Active ``LensRuntime``.  Pass ``None`` (or an offline runtime) to skip.

    Returns
    -------
    Path
        The path written to, on success.
    None
        When skipped or an error occurs.
    """
    if runtime is None or runtime.offline:
        return None

    path = _run_path(run.run_id, runtime)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(run_to_dict(run), indent=2, sort_keys=False).encode("utf-8")
        with gzip.open(path, "wb") as fh:
            fh.write(payload)
        runtime.logger.debug("persist_run: wrote %s", path)
        return path
    except Exception as exc:
        logger = getattr(runtime, "logger", _LOG)
        logger.warning("persist_run: could not write %s: %s", path, exc)
        return None


# ---------------------------------------------------------------------------
# load_run
# ---------------------------------------------------------------------------

def load_run(
    run_id: str,
    runtime: "LensRuntime | None",
) -> "LensRun | None":
    """Load a ``LensRun`` previously saved by :func:`persist_run`.

    Returns ``None`` when the file does not exist or is unreadable.
    """
    if runtime is None:
        return None

    path = _run_path(run_id, runtime)
    if not path.exists():
        return None

    try:
        with gzip.open(path, "rb") as fh:
            data = json.loads(fh.read().decode("utf-8"))
        return _dict_to_run(data)
    except Exception as exc:
        logger = getattr(runtime, "logger", _LOG)
        logger.warning("load_run: could not read %s: %s", path, exc)
        return None


# ---------------------------------------------------------------------------
# list_runs
# ---------------------------------------------------------------------------

def list_runs(
    runtime: "LensRuntime | None",
    *,
    limit: int | None = None,
) -> list[Path]:
    """Return paths to all persisted run files, sorted newest-first by mtime.

    Each returned ``Path`` is the ``run.json.gz`` file; the parent directory
    name is the ``run_id``.

    Parameters
    ----------
    runtime:
        Active runtime.  Returns ``[]`` when ``None``.
    limit:
        If provided, return at most this many paths.
    """
    if runtime is None:
        return []

    base = _output_dir(runtime) / "cn-lens"
    if not base.exists():
        return []

    paths: list[Path] = []
    for run_dir in base.iterdir():
        candidate = run_dir / "run.json.gz"
        if candidate.exists():
            paths.append(candidate)

    # Sort newest-first
    paths.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    if limit is not None:
        paths = paths[:limit]
    return paths


# ---------------------------------------------------------------------------
# prune_runs
# ---------------------------------------------------------------------------

def prune_runs(
    runtime: "LensRuntime | None",
    *,
    keep: int | None = None,
    older_than_days: int | None = None,
) -> list[str]:
    """Delete persisted runs according to the given pruning policy.

    Parameters
    ----------
    runtime:
        Active runtime.  Returns ``[]`` when ``None``.
    keep:
        When provided, keep the *keep* newest runs and delete all others.
        Mutually exclusive with *older_than_days*.
    older_than_days:
        When provided, delete every run whose ``run.json.gz`` was last modified
        more than *older_than_days* days ago.  Mutually exclusive with *keep*.

    Returns
    -------
    list[str]
        List of run_ids that were deleted.

    Raises
    ------
    ValueError
        When both *keep* and *older_than_days* are given (mutually exclusive),
        or when neither is given.
    """
    if keep is not None and older_than_days is not None:
        raise ValueError(
            "prune_runs: --keep and --older-than are mutually exclusive; provide exactly one"
        )
    if keep is None and older_than_days is None:
        raise ValueError(
            "prune_runs: specify either keep= or older_than_days="
        )
    if older_than_days is not None and older_than_days < 0:
        raise ValueError(
            f"prune_runs: older_than_days must be >= 0, got {older_than_days!r}"
        )
    if keep is not None and keep < 0:
        raise ValueError(
            f"prune_runs: keep must be >= 0, got {keep!r}"
        )

    if runtime is None:
        return []

    all_paths = list_runs(runtime)  # newest-first, each is run.json.gz
    to_delete: list[Path] = []

    if keep is not None:
        # Keep the *keep* newest; delete the rest
        to_delete = all_paths[keep:]
    else:
        # older_than_days is set
        import time as _time
        cutoff = _time.time() - (older_than_days * 86400)  # type: ignore[operator]
        to_delete = [p for p in all_paths if p.stat().st_mtime < cutoff]

    deleted_ids: list[str] = []
    for p in to_delete:
        run_dir = p.parent
        run_id = run_dir.name
        try:
            import shutil
            shutil.rmtree(run_dir)
            deleted_ids.append(run_id)
            _LOG.debug("prune_runs: removed %s", run_dir)
        except Exception as exc:
            _LOG.warning("prune_runs: could not remove %s: %s", run_dir, exc)

    return deleted_ids


# ---------------------------------------------------------------------------
# delete_run
# ---------------------------------------------------------------------------

def delete_run(
    run_id: str,
    runtime: "LensRuntime | None",
) -> bool:
    """Delete the run directory for *run_id*.

    The delete is strictly scoped to ``<output_dir>/cn-lens/``.  Any *run_id*
    that would resolve to a path outside that directory (path traversal via
    ``../../``, absolute paths, or symlinks) is rejected with ``ValueError``
    before any filesystem access.

    Parameters
    ----------
    run_id:
        The run identifier (directory name under ``<output_dir>/cn-lens/``).
    runtime:
        Active runtime.  Returns ``False`` when ``None``.

    Returns
    -------
    bool
        ``True`` if the run directory existed and was removed; ``False``
        if it did not exist (or *runtime* is ``None``).

    Raises
    ------
    ValueError
        When *run_id* resolves to a path outside the lens directory.
    """
    if runtime is None:
        return False

    # Early token-level validation: run_id must be a single directory-name
    # token with no path separators and must not be a dot-alias.
    if (
        not run_id
        or not run_id.strip()
        or "/" in run_id
        or "\\" in run_id
        or run_id in (".", "..")
    ):
        raise ValueError(
            f"delete_run: invalid run_id {run_id!r} — must be a single "
            "non-empty directory name with no path separators"
        )

    base = (_output_dir(runtime) / "cn-lens").resolve()

    # Resolve the candidate path.  We use .resolve() so that both relative
    # traversal (``../../etc``) and symlinks pointing outside are caught.
    candidate = (base / run_id).resolve()

    # Safety: the resolved candidate must be a strict child of base.
    try:
        rel = candidate.relative_to(base)
    except ValueError:
        raise ValueError(
            f"delete_run: run_id {run_id!r} resolves outside the lens directory "
            f"({candidate} is not under {base})"
        )

    # Guard against self-deletion: reject candidates that resolve to the
    # lens directory itself (e.g. run_id="./", or "../cn-lens").
    if rel == Path(".") or candidate == base:
        raise ValueError(
            f"delete_run: run_id {run_id!r} resolves to the lens directory "
            "itself, refusing to delete"
        )

    # The run directory is candidate itself (which equals base / run_id after
    # resolution).  Only delete if it is a real directory (not a file, not a
    # symlink to outside — already guarded above).
    if not candidate.is_dir():
        return False

    try:
        import shutil
        shutil.rmtree(candidate)
        _LOG.debug("delete_run: removed %s", candidate)
        return True
    except Exception as exc:
        logger = getattr(runtime, "logger", _LOG)
        logger.warning("delete_run: could not remove %s: %s", candidate, exc)
        return False


# ---------------------------------------------------------------------------
# Internal: deserialisation
# ---------------------------------------------------------------------------

def _dict_to_run(data: dict[str, Any]) -> LensRun:
    """Reconstruct a ``LensRun`` from the dict produced by ``run_to_dict``."""
    inputs_data = data.get("inputs", {})
    inputs = _dict_to_object_set(inputs_data)

    results: list[LensResult] = []
    for r in data.get("results", []):
        results.append(_dict_to_result(r))

    return LensRun(
        schema_version=int(data.get("schema_version", 1)),
        tool=str(data.get("tool", "cn-lens")),
        workflow=str(data.get("workflow", "")),
        run_id=str(data.get("run_id", "")),
        inputs=inputs,
        results=tuple(results),
        warnings=tuple(data.get("warnings", [])),
        errors=tuple(data.get("errors", [])),
    )


def _dict_to_object_set(data: dict[str, Any]) -> ObjectSet:
    objects = tuple(_dict_to_lens_object(o) for o in data.get("objects", []))
    invalid = tuple(
        InvalidLensObject(original=str(i["original"]), reason=str(i["reason"]))
        for i in data.get("invalid", [])
    )
    return ObjectSet(
        objects=objects,
        invalid=invalid,
        duplicate_count=int(data.get("duplicate_count", 0)),
    )


def _dict_to_lens_object(data: dict[str, Any]) -> LensObject:
    return LensObject(
        original=str(data.get("original", "")),
        normalized=str(data.get("normalized", "")),
        object_type=LensObjectType(data.get("object_type", "ip")),
        value=str(data.get("value", "")),
        notes=tuple(data.get("notes", [])),
    )


def _dict_to_result(data: dict[str, Any]) -> LensResult:
    obj = _dict_to_lens_object(data.get("lens_object", {}))
    findings = tuple(_dict_to_finding(f) for f in data.get("findings", []))
    return LensResult(
        lens_object=obj,
        status=str(data.get("status", "")),
        summary=data.get("summary", {}),
        findings=findings,
        sources=data.get("sources", {}),
    )


def _dict_to_finding(data: dict[str, Any]) -> LensFinding:
    return LensFinding(
        severity=str(data.get("severity", "info")),
        source=str(data.get("source", "")),
        message=str(data.get("message", "")),
        detail=data.get("detail", {}),
    )
