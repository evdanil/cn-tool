"""config_find workflow — search config_repo and SD-WAN YAML for an ObjectSet.

Offline / None runtime
-----------------------
Returns an empty LensRun with workflow="config_find".  No adapter I/O.

Online runtime
--------------
For each valid LensObject in the ObjectSet:
- Uses ``obj.value`` as the search query string (regardless of object type).
- Dispatches to adapters based on ``scope``:
    "cfg"  → only ``config_repo.search``
    "yaml" → only ``sdwan_yaml.search_by_keyword``; PREFIX also calls
             ``sdwan_yaml.lookup_prefix``; SITE also calls ``sdwan_yaml.lookup_site``
    "all"  → both of the above

Scope validation
----------------
``scope`` must be one of ``{"all", "cfg", "yaml"}`` (case-sensitive).
Any other value raises ``ValueError`` *before* any adapter is called,
including before the offline/runtime check — so invalid scope is always an
error regardless of runtime state.

INVALID objects
---------------
INVALID-type LensObjects are skipped; they appear only in LensRun.inputs.invalid.

Summary block per result
------------------------
Each LensResult carries a ``summary["config_find"]`` dict with:
    cfg_matches          : list[dict]   – ConfigMatch objects as dicts
    yaml_matches         : list[dict]   – SdwanMatch objects as dicts
    total_cfg_files_scanned : int
    truncated            : bool

Truncation
----------
When ``config_repo.search`` returns ``truncated=True``, the summary block
reflects that AND a workflow-level warning string is appended to LensRun.warnings.

Adapter exceptions
------------------
Each adapter call is wrapped; exceptions produce an error LensFinding and
do not propagate.  The other adapter (when scope="all") is still called.
"""
from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from cn_lens.adapters.registry import get_registry
from cn_lens.models import (
    LensFinding,
    LensObject,
    LensObjectType,
    LensResult,
    LensRun,
    ObjectSet,
)
from cn_lens.workflows._helpers import (
    OFFLINE_FINDING_MESSAGE,
    make_run_id,
    maybe_persist,
    synthesise_error_finding,
)

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VALID_SCOPES = frozenset({"all", "cfg", "yaml"})



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# _error_finding is an alias for the shared helper; kept for readability at
# call sites within this module.
_error_finding = synthesise_error_finding


# ---------------------------------------------------------------------------
# Per-object adapter dispatch (online path)
# ---------------------------------------------------------------------------

def _run_object(
    obj: LensObject,
    runtime: "LensRuntime",
    scope: str,
    limit: Optional[int],
) -> Tuple[Dict[str, Any], List[LensFinding]]:
    """Call adapters for a single object and return (config_find_summary, findings)."""
    from cn_lens.adapters import config_repo as _cr_mod
    from cn_lens.adapters import sdwan_yaml as _sdwan_mod

    query = obj.value
    findings: List[LensFinding] = []
    cfg_matches: List[dict] = []
    yaml_matches: List[dict] = []
    total_cfg_files_scanned: int = 0
    truncated: bool = False

    # --- config_repo side ---
    if scope in ("all", "cfg"):
        try:
            cr_result = _cr_mod.search(runtime, query, limit=limit)
            cfg_matches = [dataclasses.asdict(m) for m in cr_result.matches]
            total_cfg_files_scanned = cr_result.total_files_scanned
            truncated = cr_result.truncated
        except Exception as exc:
            runtime.logger.error(
                "config_find: config_repo.search raised unexpectedly: %s", exc
            )
            findings.append(_error_finding("config_repo", exc))

    # --- sdwan_yaml side ---
    if scope in ("all", "yaml"):
        # 1. search_by_keyword — always for yaml scope
        try:
            kw_matches = _sdwan_mod.search_by_keyword(runtime, query)
            yaml_matches.extend(dataclasses.asdict(m) for m in kw_matches)
        except Exception as exc:
            runtime.logger.error(
                "config_find: sdwan_yaml.search_by_keyword raised unexpectedly: %s", exc
            )
            findings.append(_error_finding("sdwan_yaml", exc))

        # 2. lookup_prefix — only for PREFIX type
        if obj.object_type == LensObjectType.PREFIX:
            try:
                pfx_result = _sdwan_mod.lookup_prefix(runtime, query)
                # findings from the prefix result are informational; include them
                findings.extend(pfx_result.findings)
            except Exception as exc:
                runtime.logger.error(
                    "config_find: sdwan_yaml.lookup_prefix raised unexpectedly: %s", exc
                )
                findings.append(_error_finding("sdwan_yaml.lookup_prefix", exc))

        # 3. lookup_site — only for SITE type
        if obj.object_type == LensObjectType.SITE:
            try:
                site_result = _sdwan_mod.lookup_site(runtime, query)
                findings.extend(site_result.findings)
            except Exception as exc:
                runtime.logger.error(
                    "config_find: sdwan_yaml.lookup_site raised unexpectedly: %s", exc
                )
                findings.append(_error_finding("sdwan_yaml.lookup_site", exc))

    cf_summary: Dict[str, Any] = {
        "cfg_matches": cfg_matches,
        "yaml_matches": yaml_matches,
        "total_cfg_files_scanned": total_cfg_files_scanned,
        "truncated": truncated,
    }
    return cf_summary, findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def config_find_objects(
    object_set: ObjectSet,
    *,
    runtime: Optional["LensRuntime"] = None,
    run_id: Optional[str] = None,
    scope: str = "all",
    limit: Optional[int] = None,
) -> LensRun:
    """Search config_repo and SD-WAN YAML for each object in *object_set*.

    Parameters
    ----------
    object_set:
        The ``ObjectSet`` produced by ``classify_many``.
    runtime:
        Optional ``LensRuntime``.  When ``None`` or ``runtime.offline`` is
        ``True`` the function returns an empty-results LensRun without
        contacting any adapters.
    run_id:
        Explicit run identifier.  Precedence order:
        1. ``run_id`` kwarg (if not None)
        2. ``runtime.options.run_id`` (if runtime is not None and not None)
        3. Auto-generated UTC timestamp.
    scope:
        One of ``"all"``, ``"cfg"``, ``"yaml"``.  Raises ``ValueError`` for
        any other value.
    limit:
        Maximum number of ``ConfigMatch`` objects returned per query by
        ``config_repo.search``.  ``None`` means no limit.

    Returns
    -------
    LensRun
        Always returned; never raises (after scope validation).
    """
    # --- Scope validation (always, even offline) ---
    if scope not in _VALID_SCOPES:
        raise ValueError(
            f"Invalid scope {scope!r}. Must be one of: {sorted(_VALID_SCOPES)}"
        )

    # --- Resolve run_id ---
    if run_id is not None:
        effective_run_id = run_id
    elif runtime is not None and runtime.options.run_id is not None:
        effective_run_id = runtime.options.run_id
    else:
        effective_run_id = make_run_id()

    # --- Offline / None runtime path ---
    if runtime is None or runtime.offline:
        registry = get_registry()
        offline_sources: Dict[str, str] = {"classifier": "ok"}
        offline_sources.update(registry.source_statuses(runtime, offline=True))
        offline_finding = LensFinding(
            severity="info",
            source="classifier",
            message=OFFLINE_FINDING_MESSAGE,
            detail={},
        )
        offline_results = tuple(
            LensResult(
                lens_object=obj,
                status="classified",
                summary={
                    "original": obj.original,
                    "normalized": obj.normalized,
                    "type": obj.object_type.value,
                },
                sources=offline_sources,
                findings=(offline_finding,),
            )
            for obj in object_set.objects
        )
        return LensRun(
            schema_version=1,
            tool="cn-lens",
            workflow="config_find",
            run_id=effective_run_id,
            inputs=object_set,
            results=offline_results,
            warnings=(),
            errors=(),
        )

    # --- Online path ---
    from cn_lens.adapters import config_repo as _cr_mod
    from cn_lens.adapters import sdwan_yaml as _sdwan_mod

    registry = get_registry()
    # classifier: ok is always present for uniformity with other workflows (e.g. inspect)
    sources: Dict[str, str] = {"classifier": "ok"}
    sources.update(registry.source_statuses(runtime))

    results: List[LensResult] = []
    warnings: List[str] = []

    # ---- single-pass multi-term config_repo search (F2) ----
    # One search_multi_term call over all query terms replaces N calls to
    # config_repo.search (N-pass).  This surfaces source_status (indexed/live)
    # and per-term matched/missed statistics from MultiTermResult.
    terms = [obj.value for obj in object_set.objects]
    multi_result = None
    multi_findings: List[LensFinding] = []

    if scope in ("all", "cfg") and terms:
        try:
            multi_result = _cr_mod.search_multi_term(runtime, terms, limit=limit)
            if multi_result.truncated:
                warnings.append(
                    f"config_find: config_repo results were truncated (limit={limit})"
                )
        except Exception as exc:
            runtime.logger.error(
                "config_find: config_repo.search_multi_term raised unexpectedly: %s", exc
            )
            multi_findings.append(_error_finding("config_repo", exc))

    # Build per-term match dicts for fast lookup using the authoritative
    # matches_by_term mapping produced directly by the scan loop.  This avoids
    # the unreliable snippet re-inference that misattributed CIDR/IP matches
    # whose lines contain an IP inside the queried prefix (but not the CIDR
    # text itself) to terms[0] instead of the prefix term that claimed them.
    per_term_matches: Dict[str, List[dict]] = {t: [] for t in terms}
    if multi_result is not None:
        for term in terms:
            per_term_matches[term] = [
                dataclasses.asdict(m)
                for m in multi_result.matches_by_term.get(term, [])
            ]

    for obj in object_set.objects:
        query = obj.value
        findings: List[LensFinding] = list(multi_findings)
        cfg_matches = per_term_matches.get(query, [])

        # term_status from multi_result (or fallback when search failed/offline)
        if multi_result is not None:
            term_stat = multi_result.term_results.get(query, {"matched": len(cfg_matches), "missed": len(cfg_matches) == 0})
            source_status = multi_result.source_status
        else:
            term_stat = {"matched": len(cfg_matches), "missed": len(cfg_matches) == 0}
            source_status = "live"

        total_cfg_files_scanned = (
            multi_result.total_files_scanned if multi_result is not None else 0
        )
        truncated = multi_result.truncated if multi_result is not None else False

        # ---- sdwan_yaml side (per-object, unchanged) ----
        yaml_matches: List[dict] = []
        if scope in ("all", "yaml"):
            try:
                kw_matches = _sdwan_mod.search_by_keyword(runtime, query)
                yaml_matches.extend(dataclasses.asdict(m) for m in kw_matches)
            except Exception as exc:
                runtime.logger.error(
                    "config_find: sdwan_yaml.search_by_keyword raised unexpectedly: %s", exc
                )
                findings.append(_error_finding("sdwan_yaml", exc))

            if obj.object_type == LensObjectType.PREFIX:
                try:
                    pfx_result = _sdwan_mod.lookup_prefix(runtime, query)
                    findings.extend(pfx_result.findings)
                except Exception as exc:
                    runtime.logger.error(
                        "config_find: sdwan_yaml.lookup_prefix raised unexpectedly: %s", exc
                    )
                    findings.append(_error_finding("sdwan_yaml.lookup_prefix", exc))

            if obj.object_type == LensObjectType.SITE:
                try:
                    site_result = _sdwan_mod.lookup_site(runtime, query)
                    findings.extend(site_result.findings)
                except Exception as exc:
                    runtime.logger.error(
                        "config_find: sdwan_yaml.lookup_site raised unexpectedly: %s", exc
                    )
                    findings.append(_error_finding("sdwan_yaml.lookup_site", exc))

        cf_summary: Dict[str, Any] = {
            "cfg_matches": cfg_matches,
            "yaml_matches": yaml_matches,
            "total_cfg_files_scanned": total_cfg_files_scanned,
            "truncated": truncated,
            "term_status": term_stat,
            "source_status": source_status,
        }

        result_summary: Dict[str, Any] = {
            "original": obj.original,
            "normalized": obj.normalized,
            "type": obj.object_type.value,
            "config_find": cf_summary,
        }

        results.append(
            LensResult(
                lens_object=obj,
                status="classified",
                summary=result_summary,
                sources=sources,
                findings=tuple(findings),
            )
        )

    run = LensRun(
        schema_version=1,
        tool="cn-lens",
        workflow="config_find",
        run_id=effective_run_id,
        inputs=object_set,
        results=tuple(results),
        warnings=tuple(warnings),
        errors=(),
    )
    maybe_persist(run, runtime)
    return run
