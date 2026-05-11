"""Config Repository adapter for cn-lens (Task 9).

Pure-data wrapper around config-repo file scanning. Extracts the search
logic from ``modules/config_search.py`` without importing that module or
any UI helpers (no console, no press_any_key, no Rich markup).

Public surface
--------------
- ``ConfigMatch``        — frozen dataclass: one matching line in a device file
- ``ConfigSearchResult`` — frozen dataclass: aggregated search outcome
- ``ConfigRepoAdapter``  — LensAdapter-protocol object (name = "config_repo")
- ``search(runtime, query, *, scope, limit)`` — module-level convenience fn

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
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Set, Tuple

from cn_lens.adapters.types import AdapterHealth

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

# ---------------------------------------------------------------------------
# IP-matching regexp (same pattern as modules/config_search.py)
# ---------------------------------------------------------------------------
_IP_REGEXP = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

# Context lines returned around each match
_CONTEXT_LINES = 1


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
    vendor_dirs = _get_vendor_dirs(cfg, repo_path, logger)
    device_files = _collect_device_files(vendor_dirs, scope, logger)

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
# Private helpers
# ---------------------------------------------------------------------------

def _get_vendor_dirs(
    cfg: dict,
    repo_path: Path,
    logger: logging.Logger,
) -> List[Path]:
    """Return vendor subdirectories to scan based on config."""
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

    return dirs


def _collect_device_files(
    vendor_dirs: List[Path],
    scope: str,
    logger: logging.Logger,
) -> List[Path]:
    """Walk vendor → device-type → (optional region) → files."""
    scope_lower = scope.strip().lower() if scope else "all"
    files: List[Path] = []

    for vendor_dir in vendor_dirs:
        try:
            for dt_dir in vendor_dir.iterdir():
                if not dt_dir.is_dir():
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
