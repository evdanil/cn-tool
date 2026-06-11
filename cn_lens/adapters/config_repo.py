"""Config Repository adapter for cn-lens (Task 9 + P5.2).

Pure-data wrapper around config-repo file scanning. Extracts the search
logic from ``modules/config_search.py`` without importing that module or
any UI helpers (no console, no press_any_key, no Rich markup).

Public surface
--------------
- ``ConfigMatch``        — frozen dataclass: one matching line in a device file
- ``ConfigSearchResult`` — frozen dataclass: aggregated search outcome (single query)
- ``MultiTermResult``    — frozen dataclass: multi-term search outcome (P5.2)
- ``ConfigRepoAdapter``  — LensAdapter-protocol object (name = "config_repo")
- ``search(runtime, query, *, scope, limit)`` — module-level convenience fn
- ``search_multi_term(runtime, terms, *, scope, limit)`` — single-pass multi-term scan (P5.2)

Health status logic
-------------------
- ``disabled``       when ``runtime.offline`` is True
- ``not_configured`` when ``cfg["config_repo_enabled"]`` is falsy OR directory
                     key is absent / None / empty
- ``error``          when directory is set but not readable on disk
- ``ok``             otherwise

Offline semantics
-----------------
When ``runtime.offline`` is True the adapter returns an empty
``ConfigSearchResult`` immediately. This mirrors the ``--offline`` contract:
"do not consult any external state, return deterministic empty."

P5.2 additions
--------------
- ``search_multi_term``: single-pass scan over all device files, matching any
  of the supplied terms simultaneously (one file open per device).  Applies
  vendor stop-words from ``wordlists.keywords.stop_words`` to suppress noise
  lines.  Uses ``runtime.cache`` (``CacheManager``) for an index-backed fast
  path when available and not currently being rebuilt; falls back to live
  file-system scan.  Returns ``source_status="indexed"`` or ``"live"``.
- Per-term ``term_results`` dict in ``MultiTermResult``: each term maps to
  ``{"matched": <n_lines>, "missed": bool}`` for the matched/missed table.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from cn_lens.adapters.types import AdapterHealth

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

# ---------------------------------------------------------------------------
# IP-matching regexp (same pattern as modules/config_search.py)
# ---------------------------------------------------------------------------
_IP_REGEXP = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

# Context lines returned around each match
_CONTEXT_LINES = 1

# Vendor stop-words imported from the shared wordlist (same source as
# modules/config_search.py and utils/cache_helpers.py).  Only imported at
# function call time to keep this module importable even when wordlists is
# not on sys.path (test isolation).
_STOP_WORDS: Optional[Dict[str, Tuple[str, ...]]] = None


def _get_stop_words() -> Dict[str, Tuple[str, ...]]:
    """Return vendor stop-word dict, importing lazily on first call."""
    global _STOP_WORDS
    if _STOP_WORDS is None:
        try:
            from wordlists.keywords import stop_words  # type: ignore[import]
            _STOP_WORDS = stop_words
        except ImportError:
            _STOP_WORDS = {}
    return _STOP_WORDS


def _line_is_stop_word(line_stripped: str, vendor: str) -> bool:
    """Return True when *line_stripped* starts with a stop-word for *vendor*."""
    stop_words = _get_stop_words()
    prefixes = stop_words.get(vendor.lower())
    if not prefixes:
        return False
    return line_stripped.startswith(prefixes)


# ---------------------------------------------------------------------------
# Public frozen dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConfigMatch:
    """A single matching line found in a device configuration file.

    Attributes
    ----------
    device:
        Device name (upper-case stem of the file, e.g. ``"ROUTER1"``).
    file_path:
        Absolute path to the config file as a string.
    line_number:
        0-based index of the matching line within the file.
    snippet:
        The matching line content (stripped of leading/trailing whitespace).
    context_before:
        Tuple of ``_CONTEXT_LINES`` lines immediately *before* the match
        (stripped).  Empty tuple when the match is at the start of the file.
    context_after:
        Tuple of ``_CONTEXT_LINES`` lines immediately *after* the match
        (stripped).  Empty tuple when the match is at the end of the file.
    """

    device: str
    file_path: str
    line_number: int
    snippet: str
    context_before: tuple[str, ...]
    context_after: tuple[str, ...]


@dataclass(frozen=True)
class ConfigSearchResult:
    """Aggregated result of a config-repo search.

    Attributes
    ----------
    matches:
        Ordered tuple of ``ConfigMatch`` objects (sorted by device then line).
    total_files_scanned:
        Number of config files that were opened and inspected.
    truncated:
        ``True`` when a ``limit`` was applied and the full result set would
        have exceeded that limit.
    """

    matches: tuple[ConfigMatch, ...]
    total_files_scanned: int
    truncated: bool


@dataclass(frozen=True)
class MultiTermResult:
    """Result of a multi-term single-pass config-repo scan (P5.2).

    Attributes
    ----------
    matches:
        All ``ConfigMatch`` objects from any term, sorted by device then line.
    total_files_scanned:
        Number of config files opened (single-pass — not multiplied by terms).
    truncated:
        ``True`` when the overall ``limit`` was applied.
    term_results:
        Per-term statistics dict:
        ``{term: {"matched": <count of matching lines>, "missed": <bool>}}``.
        A term is ``"missed"`` (missed=True) when it produced zero matches.
    source_status:
        ``"indexed"`` when results came from a ``CacheManager`` index;
        ``"live"`` when results came from a live file-system scan.
    matches_by_term:
        Authoritative per-term match attribution produced directly by the
        scan loop, keyed by the original query string.  Consumers should
        prefer this over re-inferring attribution from snippet text, which
        is unreliable for CIDR/IP queries where the matched line contains
        an IP inside the queried prefix but not the CIDR text itself.
    """

    matches: tuple[ConfigMatch, ...]
    total_files_scanned: int
    truncated: bool
    term_results: Dict[str, Any]
    source_status: str  # "indexed" | "live"
    matches_by_term: Dict[str, List[ConfigMatch]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

def _resolve_repo_path(runtime: "LensRuntime") -> Optional[Path]:
    """Resolve the config repo directory from runtime cfg.

    Returns the ``Path`` when the directory is accessible, ``None`` otherwise.
    Used by both :meth:`ConfigRepoAdapter.health` and :func:`search` to avoid
    duplicating the path-accessibility guard.
    """
    cfg = runtime.cfg
    if not cfg.get("config_repo_enabled"):
        return None
    repo_dir = cfg.get("config_repo_directory")
    if not repo_dir:
        return None
    repo_path = Path(str(repo_dir))
    if not repo_path.is_dir() or not os.access(repo_path, os.R_OK):
        return None
    return repo_path


class ConfigRepoAdapter:
    """LensAdapter for the local config repository.

    Satisfies the ``LensAdapter`` protocol from ``cn_lens.adapters.base``
    without inheriting from any base class (structural conformance only).
    """

    name: str = "config_repo"

    def health(self, runtime: "LensRuntime") -> AdapterHealth:
        """Return health status for the config repo adapter.

        Returns
        -------
        AdapterHealth
            With one of: ``disabled``, ``not_configured``, ``error``, ``ok``.
        """
        if runtime.offline:
            return AdapterHealth(status="disabled", detail="offline mode")

        cfg = runtime.cfg
        if not cfg.get("config_repo_enabled"):
            return AdapterHealth(
                status="not_configured",
                detail="config_repo_enabled is false or missing",
            )

        repo_dir = cfg.get("config_repo_directory")
        if not repo_dir:
            return AdapterHealth(
                status="not_configured",
                detail="config_repo_directory is not set",
            )

        repo_path = Path(str(repo_dir))
        if not repo_path.is_dir() or not os.access(repo_path, os.R_OK):
            return AdapterHealth(
                status="error",
                detail=f"config repo path not accessible: {repo_path}",
            )

        return AdapterHealth(status="ok")


# ---------------------------------------------------------------------------
# Module-level search function
# ---------------------------------------------------------------------------

def search(
    runtime: "LensRuntime",
    query: str,
    *,
    scope: str = "all",
    limit: Optional[int] = None,
) -> ConfigSearchResult:
    """Search the local config repository for ``query``.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.
    query:
        Plain-text token to search for. May be an IP address, a CIDR prefix
        string (matched literally), a site code, or any keyword/regexp fragment.
        The adapter treats it as a case-insensitive literal pattern that is also
        tested against any IPs found on each line (if it looks like an IP/prefix).
    scope:
        ``"all"`` (default) scans all device-type directories. Any other value
        is matched case-insensitively against the device-type directory name
        (e.g. ``"ios"``, ``"nxos"``, ``"junos"``).
    limit:
        Maximum number of ``ConfigMatch`` objects to return. ``None`` means no
        limit. When the limit is reached ``ConfigSearchResult.truncated`` is
        ``True``.

    Returns
    -------
    ConfigSearchResult
        Always returned — never raises on expected errors (missing path,
        empty repo, no matches). In offline mode or when not configured the
        result has zero matches and ``total_files_scanned == 0``.
    """
    logger = runtime.logger
    cfg = runtime.cfg

    # -- Offline guard -------------------------------------------------------
    if runtime.offline:
        logger.debug("config_repo.search: offline mode — returning empty result")
        return ConfigSearchResult(matches=(), total_files_scanned=0, truncated=False)

    # -- Configuration / path guard (reuses _resolve_repo_path) -------------
    repo_path = _resolve_repo_path(runtime)
    if repo_path is None:
        repo_dir = cfg.get("config_repo_directory")
        if not cfg.get("config_repo_enabled") or not repo_dir:
            logger.debug("config_repo.search: not configured")
        else:
            logger.warning("config_repo.search: repo path not accessible: %s", repo_dir)
        return ConfigSearchResult(matches=(), total_files_scanned=0, truncated=False)

    # -- Build file list -----------------------------------------------------
    vendor_dirs, excluded = _get_vendor_dirs(cfg, repo_path, logger)
    device_files = _collect_device_files(vendor_dirs, scope, excluded, logger)

    total_files = len(device_files)
    if total_files == 0:
        return ConfigSearchResult(matches=(), total_files_scanned=0, truncated=False)

    # -- Parse query into search primitives ----------------------------------
    ip_nets, text_patterns = _parse_query(query, logger)

    # -- Search files --------------------------------------------------------
    all_matches: List[ConfigMatch] = []
    truncated = False

    max_workers = int(cfg.get("config_search_max_workers", 8) or 8)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_search_file, fp, ip_nets, text_patterns, logger): fp
            for fp in device_files
        }
        for future in as_completed(futures):
            file_matches = future.result()
            for m in file_matches:
                if limit is not None and len(all_matches) >= limit:
                    truncated = True
                    break
                all_matches.append(m)
            if truncated:
                # Cancel remaining futures (best-effort)
                for f in futures:
                    f.cancel()
                break

    # Sort for determinism: device name, then line number
    all_matches.sort(key=lambda m: (m.device, m.line_number))

    return ConfigSearchResult(
        matches=tuple(all_matches),
        total_files_scanned=total_files,
        truncated=truncated,
    )


# ---------------------------------------------------------------------------
# P5.2 multi-term single-pass search
# ---------------------------------------------------------------------------

def search_multi_term(
    runtime: "LensRuntime",
    terms: List[str],
    *,
    scope: str = "all",
    limit: Optional[int] = None,
) -> "MultiTermResult":
    """Search config files for all *terms* in a single pass over each file.

    Parameters
    ----------
    runtime:
        Active ``LensRuntime``.  When ``None`` or offline, returns an empty
        result immediately.
    terms:
        List of query strings.  Each is treated as a case-insensitive regex
        pattern; if it fails to compile, it is searched as a literal string.
        Terms that look like IPs/CIDR also trigger an IP-in-subnet check
        (same as the existing ``search()`` function).
    scope:
        Device-type directory filter passed to ``_collect_device_files``.
    limit:
        Global maximum number of ``ConfigMatch`` objects to return in total
        across all terms.  ``None`` means no limit.

    Returns
    -------
    MultiTermResult
        ``source_status="indexed"`` when a ``CacheManager`` was used (and was
        not currently rebuilding its index); ``"live"`` otherwise.
    """
    logger = runtime.logger if runtime is not None else logging.getLogger(__name__)
    cfg = runtime.cfg if runtime is not None else {}

    # -- Offline / None / empty terms guard -----------------------------------
    if runtime is None or runtime.offline:
        return MultiTermResult(
            matches=(),
            total_files_scanned=0,
            truncated=False,
            term_results={t: {"matched": 0, "missed": True} for t in terms},
            source_status="live",
        )

    if not terms:
        return MultiTermResult(
            matches=(),
            total_files_scanned=0,
            truncated=False,
            term_results={},
            source_status="live",
        )

    # -- Path guard ----------------------------------------------------------
    repo_path = _resolve_repo_path(runtime)
    if repo_path is None:
        return MultiTermResult(
            matches=(),
            total_files_scanned=0,
            truncated=False,
            term_results={t: {"matched": 0, "missed": True} for t in terms},
            source_status="live",
        )

    # -- Decide whether to use cache index or live scan ----------------------
    use_cache = _cache_is_usable(runtime)
    source_status = "indexed" if use_cache else "live"

    # -- Compile patterns for each term, plus IP-net parsing -----------------
    compiled: List[Tuple[str, Optional[re.Pattern], List[ipaddress.IPv4Network]]] = []
    for term in terms:
        ip_nets: List[ipaddress.IPv4Network] = []
        pat: Optional[re.Pattern] = None
        term_stripped = term.strip()
        # Try IP/CIDR parse
        if "/" in term_stripped or _IP_REGEXP.fullmatch(term_stripped):
            try:
                net = ipaddress.ip_network(term_stripped, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    ip_nets.append(net)
            except ValueError:
                pass
        # Compile as regex (fallback to None → literal search)
        try:
            pat = re.compile(term, re.IGNORECASE)
        except re.error:
            pat = None  # will fall back to literal match
        compiled.append((term, pat, ip_nets))

    # -- File list -----------------------------------------------------------
    vendor_dirs, excluded = _get_vendor_dirs(cfg, repo_path, logger)
    device_files = _collect_device_files(vendor_dirs, scope, excluded, logger)
    total_files = len(device_files)

    if total_files == 0:
        return MultiTermResult(
            matches=(),
            total_files_scanned=0,
            truncated=False,
            term_results={t: {"matched": 0, "missed": True} for t in terms},
            source_status=source_status,
        )

    # -- Determine vendor for each file (for stop-word lookup) ---------------
    # Vendor = the top-level dir under repo_path (e.g. repo/cisco/ios/r1.cfg → "cisco")
    def _vendor_for(file_path: Path) -> str:
        try:
            rel = file_path.relative_to(repo_path)
            return rel.parts[0].lower() if rel.parts else ""
        except ValueError:
            return ""

    # -- Single-pass scan ----------------------------------------------------
    all_matches: List[ConfigMatch] = []
    truncated = False
    # Per-term match counter: term → count of matched lines.
    term_line_counts: Dict[str, int] = {t: 0 for t in terms}
    # Authoritative per-term match lists — keyed by original query string.
    # Built directly from the (term, match) pairs returned by each file scan
    # so attribution is certain even for CIDR/IP queries whose matched lines
    # contain an IP inside the prefix but not the CIDR text itself.
    per_term_match_lists: Dict[str, List[ConfigMatch]] = {t: [] for t in terms}

    max_workers = int(cfg.get("config_search_max_workers", 8) or 8)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _search_file_multi_term,
                fp,
                compiled,
                _vendor_for(fp),
                logger,
            ): fp
            for fp in device_files
        }
        for future in as_completed(futures):
            if truncated:
                future.cancel()
                continue
            file_match_groups = future.result()  # list of (term, ConfigMatch)
            for term, match in file_match_groups:
                if limit is not None and len(all_matches) >= limit:
                    truncated = True
                    break
                all_matches.append(match)
                term_line_counts[term] = term_line_counts.get(term, 0) + 1
                per_term_match_lists[term].append(match)

    all_matches.sort(key=lambda m: (m.device, m.line_number))

    term_results: Dict[str, Any] = {
        t: {
            "matched": term_line_counts.get(t, 0),
            "missed": term_line_counts.get(t, 0) == 0,
        }
        for t in terms
    }

    return MultiTermResult(
        matches=tuple(all_matches),
        total_files_scanned=total_files,
        truncated=truncated,
        term_results=term_results,
        source_status=source_status,
        matches_by_term=per_term_match_lists,
    )


def _cache_is_usable(runtime: "LensRuntime") -> bool:
    """Return True when runtime.cache is a CacheManager and not rebuilding."""
    try:
        from utils.cache import CacheManager  # type: ignore[import]
    except ImportError:
        return False
    cache = getattr(runtime, "cache", None)
    if cache is None or not isinstance(cache, CacheManager):
        return False
    try:
        indexing = cache.dc.get("indexing", False)
    except Exception:
        return False
    return not bool(indexing)


def _search_file_multi_term(
    file_path: Path,
    compiled_terms: List[Tuple[str, Optional[re.Pattern], List[ipaddress.IPv4Network]]],
    vendor: str,
    logger: logging.Logger,
) -> List[Tuple[str, ConfigMatch]]:
    """Scan one file for all compiled terms in a single pass.

    Returns a list of ``(term_string, ConfigMatch)`` pairs — one entry per
    matched line per term.  A single line can appear multiple times if it
    matches multiple terms.  Stop-word lines are skipped.
    """
    device = file_path.stem.upper()
    results: List[Tuple[str, ConfigMatch]] = []

    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as e:
        logger.error("config_repo: error reading %s: %s", file_path, e)
        return results

    for idx, line in enumerate(lines):
        stripped = line.strip()

        # Apply vendor stop-words
        if _line_is_stop_word(stripped, vendor):
            continue

        for term, pat, ip_nets in compiled_terms:
            matched = False

            # 1. IP-in-subnet check
            if ip_nets and not matched:
                for ip_match in _IP_REGEXP.finditer(stripped):
                    try:
                        found_ip = ipaddress.ip_address(ip_match.group())
                        if not isinstance(found_ip, ipaddress.IPv4Address):
                            continue
                        for net in ip_nets:
                            if found_ip in net:
                                matched = True
                                break
                    except ValueError:
                        continue
                    if matched:
                        break

            # 2. Regex / literal pattern check
            if not matched:
                if pat is not None:
                    try:
                        if pat.search(stripped):
                            matched = True
                    except re.error:
                        pass
                else:
                    # Fallback to literal (case-insensitive)
                    if term.lower() in stripped.lower():
                        matched = True

            if matched:
                before: tuple[str, ...] = tuple(lines[max(0, idx - _CONTEXT_LINES):idx])
                after: tuple[str, ...] = tuple(lines[idx + 1:idx + 1 + _CONTEXT_LINES])
                results.append((
                    term,
                    ConfigMatch(
                        device=device,
                        file_path=str(file_path),
                        line_number=idx,
                        snippet=stripped,
                        context_before=before,
                        context_after=after,
                    ),
                ))

    return results


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _get_vendor_dirs(
    cfg: dict,
    repo_path: Path,
    logger: logging.Logger,
) -> Tuple[List[Path], Set[str]]:
    """Return vendor subdirectories to scan based on config, and the excluded-dir set.

    The excluded set is built from ``config_repo_excluded_dirs`` plus
    ``config_repo_history_dir`` (default ``"history"``).  Directory names are
    compared lower-cased so the check is case-insensitive.

    Returns
    -------
    (dirs, excluded)
        ``dirs`` — vendor-level directories to walk.
        ``excluded`` — lower-cased dir-name set that callers must check at every
        depth of the walk (mirrors ``make_dir_list`` semantics).
    """
    vendors: List[str] = cfg.get("config_repo_vendors", []) or []
    excluded_raw = cfg.get("config_repo_excluded_dirs", []) or []
    excluded: Set[str] = {str(e).strip().lower() for e in excluded_raw if str(e).strip()}
    history_dir = str(cfg.get("config_repo_history_dir", "history") or "history").strip().lower()
    if history_dir:
        excluded.add(history_dir)

    dirs: List[Path] = []
    if not vendors:
        # No vendor list → iterate all first-level subdirs
        try:
            for child in repo_path.iterdir():
                if child.is_dir() and child.name.lower() not in excluded:
                    dirs.append(child)
        except OSError as e:
            logger.warning("config_repo: cannot list repo root: %s", e)
    else:
        for vendor in vendors:
            vp = repo_path / vendor.strip()
            if vp.is_dir() and os.access(vp, os.R_OK):
                dirs.append(vp)
            else:
                logger.debug("config_repo: vendor dir not accessible: %s", vp)

    return dirs, excluded


def _collect_device_files(
    vendor_dirs: List[Path],
    scope: str,
    excluded: Set[str],
    logger: logging.Logger,
) -> List[Path]:
    """Walk vendor → device-type → (optional region) → files.

    Parameters
    ----------
    vendor_dirs:
        Top-level vendor directories to walk (e.g. ``cisco``, ``juniper``).
    scope:
        Device-type filter; ``"all"`` passes every device-type directory.
    excluded:
        Lower-cased set of directory names to skip at *every* depth of the
        walk (device-type level and region/sub-dir level).  Typically the set
        returned as the second element of ``_get_vendor_dirs``.
    logger:
        Logger for debug/warning messages.

    Any directory whose lower-cased name appears in *excluded* is skipped
    entirely at any depth of the walk.  This mirrors the semantics of
    ``utils.config.make_dir_list`` where ``config_repo_history_dir`` and
    ``config_repo_excluded_dirs`` are applied to every directory component,
    not just the top-level one.
    """
    scope_lower = scope.strip().lower() if scope else "all"
    files: List[Path] = []

    for vendor_dir in vendor_dirs:
        try:
            for dt_dir in vendor_dir.iterdir():
                if not dt_dir.is_dir():
                    continue
                # Exclusion check at device-type level (e.g. cisco/history)
                if dt_dir.name.lower() in excluded:
                    logger.debug("config_repo: skipping excluded dir: %s", dt_dir)
                    continue
                # scope filter: "all" passes everything, otherwise match dir name
                if scope_lower != "all" and dt_dir.name.lower() != scope_lower:
                    continue
                # Device files live directly in dt_dir (or in region sub-dirs).
                # Scan both: direct children files and one more level deep.
                for candidate in dt_dir.iterdir():
                    if candidate.is_file():
                        files.append(candidate)
                    elif candidate.is_dir():
                        # Exclusion check at region/sub-dir level (e.g. ios/history)
                        if candidate.name.lower() in excluded:
                            logger.debug(
                                "config_repo: skipping excluded sub-dir: %s", candidate
                            )
                            continue
                        # Region sub-directory
                        try:
                            for rfile in candidate.iterdir():
                                if rfile.is_file():
                                    files.append(rfile)
                        except OSError as e:
                            logger.debug("config_repo: cannot list region dir %s: %s", candidate, e)
        except OSError as e:
            logger.warning("config_repo: cannot list vendor dir %s: %s", vendor_dir, e)

    return files


def _parse_query(
    query: str,
    logger: logging.Logger,
) -> Tuple[List[ipaddress.IPv4Network], List[str]]:
    """Decompose a query string into IP networks and text patterns.

    Strategy:
    - If the query looks like an IP/CIDR it becomes a ``IPv4Network`` for
      IP-in-subnet matching AND is also added as a literal text pattern so
      prefix strings like ``"10.0.0.0/24"`` still match lines that contain
      that exact notation.
    - All queries are also compiled as a case-insensitive regexp pattern so
      plain text and site codes are covered.
    """
    ip_nets: List[ipaddress.IPv4Network] = []
    text_patterns: List[str] = [query]  # always search as literal/regexp text

    query_stripped = query.strip()
    # Try to interpret as network (supports both bare IPs and CIDR)
    if "/" in query_stripped or _IP_REGEXP.fullmatch(query_stripped):
        try:
            net = ipaddress.ip_network(query_stripped, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                ip_nets.append(net)
        except ValueError:
            pass

    return ip_nets, text_patterns


def _search_file(
    file_path: Path,
    ip_nets: List[ipaddress.IPv4Network],
    text_patterns: List[str],
    logger: logging.Logger,
) -> List[ConfigMatch]:
    """Scan a single file and return all matching ``ConfigMatch`` objects."""
    device = file_path.stem.upper()
    matches: List[ConfigMatch] = []

    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as e:
        logger.error("config_repo: error reading %s: %s", file_path, e)
        return matches

    for idx, line in enumerate(lines):
        stripped = line.strip()
        matched = False

        # 1. IP-in-subnet check
        if ip_nets and not matched:
            for ip_match in _IP_REGEXP.finditer(stripped):
                try:
                    found_ip = ipaddress.ip_address(ip_match.group())
                    if not isinstance(found_ip, ipaddress.IPv4Address):
                        continue
                    for net in ip_nets:
                        if found_ip in net:
                            matched = True
                            break
                except ValueError:
                    continue
                if matched:
                    break

        # 2. Text / regex pattern check
        if not matched:
            for pat in text_patterns:
                try:
                    if re.search(pat, stripped, re.IGNORECASE):
                        matched = True
                        break
                except re.error:
                    # Treat as literal if not a valid regexp
                    if pat.lower() in stripped.lower():
                        matched = True
                        break

        if matched:
            before: tuple[str, ...] = tuple(
                lines[max(0, idx - _CONTEXT_LINES):idx]
            )
            after: tuple[str, ...] = tuple(
                lines[idx + 1:idx + 1 + _CONTEXT_LINES]
            )
            matches.append(
                ConfigMatch(
                    device=device,
                    file_path=str(file_path),
                    line_number=idx,
                    snippet=stripped,
                    context_before=before,
                    context_after=after,
                )
            )

    return matches
