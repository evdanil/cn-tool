"""SD-WAN YAML adapter for cn-lens.

Provides pure-data lookups over a directory tree of SD-WAN YAML site
configuration files.  Logic is lifted from ``plugins/sdwan_yaml_search.py``
via copy-adapt (no imports from the plugin module so the plugin is unaffected).

Public surface
--------------
ADAPTER       -- module-level singleton; satisfies LensAdapter Protocol
lookup_prefix(runtime, prefix) -> SdwanPrefixResult
lookup_site(runtime, site_code) -> SdwanSiteResult
search_by_keyword(runtime, term) -> list[SdwanMatch]

No ``console``, no ``print``, no ``press_any_key``.  Logger only.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Tuple

import yaml

from cn_lens.adapters.types import AdapterHealth
from cn_lens.models import LensFinding

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


# ---------------------------------------------------------------------------
# Config key constants
# ---------------------------------------------------------------------------

_CFG_REPO_PATHS = "sdwan_yaml_repo_paths"
_CFG_REPO_PATH_LEGACY = "sdwan_yaml_repo_path"  # backward compat

_IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


# ---------------------------------------------------------------------------
# Result dataclasses (frozen)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SdwanPrefixResult:
    """Result of a prefix lookup in the SD-WAN YAML store.

    Fields
    ------
    prefix      : The queried prefix string.
    status      : "found" | "not_found" | "partial".
    site_code   : Site that owns the match (empty string when not found).
    file_path   : Path to the YAML file containing the match.
    match_type  : "exact" | "contained" | "" (when not found).
    findings    : Advisory findings as ``LensFinding`` instances
                  (at minimum one ``info`` for not_found).
    raw         : The raw YAML value that matched (empty when not found).
    """

    prefix: str
    status: str
    site_code: str = field(default="")
    file_path: str = field(default="")
    match_type: str = field(default="")
    findings: Tuple[LensFinding, ...] = field(default_factory=tuple)
    raw: str = field(default="")


@dataclass(frozen=True)
class SdwanSiteResult:
    """Result of a site lookup in the SD-WAN YAML store.

    Fields
    ------
    site_code   : Queried site code.
    status      : "found" | "not_found".
    site_name   : Human-readable name from YAML (empty if not_found).
    file_path   : Path to the YAML file for this site.
    prefixes    : List of prefix strings configured at the site.
    devices     : List of device hostname strings at the site.
    findings    : Advisory findings as ``LensFinding`` instances.
    """

    site_code: str
    status: str
    site_name: str = field(default="")
    file_path: str = field(default="")
    prefixes: Tuple[str, ...] = field(default_factory=tuple)
    devices: Tuple[str, ...] = field(default_factory=tuple)
    findings: Tuple[LensFinding, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SdwanMatch:
    """A single match returned by search_by_keyword.

    Fields
    ------
    site_code     : Site owning the matched file.
    file_path     : Absolute path to the YAML file.
    path          : Dot-notation key path within the YAML document.
    matched_value : String representation of the matching value.
    """

    site_code: str
    file_path: str
    path: str
    matched_value: str


# ---------------------------------------------------------------------------
# Internal helpers (adapted from plugins/sdwan_yaml_search.py)
# ---------------------------------------------------------------------------

def _sdwan_finding(severity: str, message: str, detail: str = "") -> LensFinding:
    """Construct a ``LensFinding`` with ``source='sdwan_yaml'``."""
    return LensFinding(
        severity=severity,
        source="sdwan_yaml",
        message=message,
        detail={"detail": detail} if detail else {},
    )


def _short_circuit_prefix(runtime: "LensRuntime", prefix: str) -> Optional[SdwanPrefixResult]:
    """Return a short-circuit SdwanPrefixResult when offline or unconfigured; else None."""
    if runtime.offline:
        return SdwanPrefixResult(
            prefix=prefix,
            status="not_found",
            findings=(
                _sdwan_finding("info", "SD-WAN YAML adapter is disabled (offline mode)", "offline"),
            ),
        )
    repo_paths = _resolve_repo_paths(runtime.cfg)
    if not repo_paths:
        return SdwanPrefixResult(
            prefix=prefix,
            status="not_found",
            findings=(
                _sdwan_finding("info", "SD-WAN YAML adapter is not configured", "not_configured"),
            ),
        )
    return None


def _short_circuit_site(runtime: "LensRuntime", site_code: str) -> Optional[SdwanSiteResult]:
    """Return a short-circuit SdwanSiteResult when offline or unconfigured; else None."""
    if runtime.offline:
        return SdwanSiteResult(
            site_code=site_code,
            status="not_found",
            findings=(
                _sdwan_finding("info", "SD-WAN YAML adapter is disabled (offline mode)", "offline"),
            ),
        )
    repo_paths = _resolve_repo_paths(runtime.cfg)
    if not repo_paths:
        return SdwanSiteResult(
            site_code=site_code,
            status="not_found",
            findings=(
                _sdwan_finding("info", "SD-WAN YAML adapter is not configured", "not_configured"),
            ),
        )
    return None


def _resolve_repo_paths(cfg: Dict[str, Any]) -> List[str]:
    """Return list of configured repo paths, preferring new key over legacy."""
    raw = cfg.get(_CFG_REPO_PATHS, "") or cfg.get(_CFG_REPO_PATH_LEGACY, "")
    if not raw:
        return []
    return [p.strip() for p in str(raw).split(",") if p.strip()]


def _load_yaml_files(repo_paths: List[str], logger: Any) -> Dict[str, Any]:
    """Load all YAML files from the given repository directories.

    Returns a dict mapping absolute file path -> parsed YAML content.
    Skips unreadable / oversized (>10MB) files, logging warnings.
    Deduplicates by filename (first path wins).
    """
    MAX_SIZE = 10 * 1024 * 1024
    loaded: Dict[str, Any] = {}
    seen_names: set[str] = set()

    for repo_path in repo_paths:
        repo = Path(repo_path)
        if not repo.is_dir():
            logger.warning("sdwan_yaml adapter: repo path %r is not a directory, skipping", repo_path)
            continue

        for file in sorted(repo.rglob("*")):
            if file.suffix.lower() not in {".yml", ".yaml"} or not file.is_file():
                continue

            if file.name in seen_names:
                logger.debug("sdwan_yaml adapter: duplicate file %r, skipping", file.name)
                continue

            try:
                if file.stat().st_size > MAX_SIZE:
                    logger.warning("sdwan_yaml adapter: %s exceeds size limit, skipping", file)
                    continue

                with file.open(encoding="utf-8") as fh:
                    content = yaml.safe_load(fh.read())

                loaded[str(file)] = content
                seen_names.add(file.name)

            except Exception as exc:
                logger.error("sdwan_yaml adapter: failed to load %s: %s", file, exc)

    return loaded


def _traverse(
    obj: Any,
    path: str = "",
) -> Iterator[Tuple[str, Any]]:
    """Recursively yield (dot-path, value) for every leaf in *obj*."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_path = f"{path}.{k}" if path else k
            yield from _traverse(v, new_path)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _traverse(v, f"{path}[{i}]")
    else:
        yield path, obj


def _site_code_from_file(file_path: str, yaml_content: Any) -> str:
    """Derive a site code from YAML content or fall back to file stem."""
    if isinstance(yaml_content, dict):
        for key in ("site_code", "site", "name"):
            val = yaml_content.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip().upper()
    return Path(file_path).stem.upper()


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

def _health(runtime: "LensRuntime") -> AdapterHealth:
    """Determine adapter health for the given runtime."""
    # Offline wins first
    if runtime.offline:
        return AdapterHealth(status="disabled", detail="runtime is offline")

    # Check configuration
    repo_paths = _resolve_repo_paths(runtime.cfg)
    if not repo_paths:
        return AdapterHealth(
            status="not_configured",
            detail="sdwan_yaml_repo_paths is absent or empty in config",
        )

    # Check each path is readable
    unreadable = []
    for p in repo_paths:
        if not Path(p).is_dir():
            unreadable.append(p)

    if unreadable:
        detail = "path(s) not readable: " + ", ".join(unreadable)
        return AdapterHealth(status="error", detail=detail)

    return AdapterHealth(status="ok", detail="")


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def lookup_prefix(runtime: "LensRuntime", prefix: str) -> SdwanPrefixResult:
    """Look up a prefix in the SD-WAN YAML store.

    Returns a ``SdwanPrefixResult`` with status ``"found"`` (exact or IP
    containment), ``"partial"`` (query prefix is a subnet of a configured
    supernet), or ``"not_found"``.  Never raises on expected misses.

    Uses a **single traversal pass** per file, maintaining both
    ``best_exact`` and ``best_supernet`` accumulators so the YAML data is
    read only once.
    """
    logger = runtime.logger

    sc = _short_circuit_prefix(runtime, prefix)
    if sc is not None:
        return sc

    repo_paths = _resolve_repo_paths(runtime.cfg)

    try:
        query_net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return SdwanPrefixResult(
            prefix=prefix,
            status="not_found",
            findings=(
                _sdwan_finding("error", f"Invalid prefix: {prefix!r}", "parse_error"),
            ),
        )

    yaml_data = _load_yaml_files(repo_paths, logger)

    # Single-pass: accumulate best_exact (highest priority) and best_supernet
    best_exact: Optional[SdwanPrefixResult] = None
    best_supernet: Optional[SdwanPrefixResult] = None

    for file_path, content in yaml_data.items():
        site_code = _site_code_from_file(file_path, content)

        for yaml_path, value in _traverse(content):
            str_val = str(value)

            # --- Network literal check ---
            try:
                candidate = ipaddress.ip_network(str_val, strict=False)

                # Exact match: return immediately (highest priority)
                if candidate == query_net:
                    return SdwanPrefixResult(
                        prefix=prefix,
                        status="found",
                        site_code=site_code,
                        file_path=file_path,
                        match_type="exact",
                        raw=str_val,
                        findings=(
                            _sdwan_finding(
                                "info",
                                f"Exact match found in {site_code}",
                                f"path={yaml_path}",
                            ),
                        ),
                    )

                # Supernet check: query_net is a subnet of candidate
                if (
                    best_supernet is None
                    and candidate != query_net
                    and query_net.network_address >= candidate.network_address
                    and query_net.broadcast_address <= candidate.broadcast_address
                ):
                    best_supernet = SdwanPrefixResult(
                        prefix=prefix,
                        status="partial",
                        site_code=site_code,
                        file_path=file_path,
                        match_type="contained",
                        raw=str_val,
                        findings=(
                            _sdwan_finding(
                                "info",
                                f"{prefix} is contained within {str_val} in {site_code}",
                                f"path={yaml_path}",
                            ),
                        ),
                    )

            except ValueError:
                pass  # not a network literal — check IP containment below

            # --- IP containment: IPs extracted from the value inside query_net ---
            if best_exact is None:
                for ip_str in _IP_PATTERN.findall(str_val):
                    try:
                        ip_addr = ipaddress.ip_address(ip_str)
                        if ip_addr in query_net:
                            best_exact = SdwanPrefixResult(
                                prefix=prefix,
                                status="found",
                                site_code=site_code,
                                file_path=file_path,
                                match_type="contained",
                                raw=str_val,
                                findings=(
                                    _sdwan_finding(
                                        "info",
                                        f"IP {ip_str} within {prefix} found in {site_code}",
                                        f"path={yaml_path}",
                                    ),
                                ),
                            )
                            break
                    except ValueError:
                        continue

    # Return in priority order: exact IP-containment > supernet > not_found
    if best_exact is not None:
        return best_exact
    if best_supernet is not None:
        return best_supernet

    return SdwanPrefixResult(
        prefix=prefix,
        status="not_found",
        findings=(
            _sdwan_finding("info", f"No SD-WAN YAML entry found for prefix {prefix!r}"),
        ),
    )


def lookup_site(runtime: "LensRuntime", site_code: str) -> SdwanSiteResult:
    """Look up a site by its site code in the SD-WAN YAML store.

    Returns a ``SdwanSiteResult`` with status ``"found"`` or ``"not_found"``.
    """
    logger = runtime.logger

    sc = _short_circuit_site(runtime, site_code)
    if sc is not None:
        return sc

    repo_paths = _resolve_repo_paths(runtime.cfg)
    yaml_data = _load_yaml_files(repo_paths, logger)
    query_upper = site_code.upper()

    for file_path, content in yaml_data.items():
        derived_code = _site_code_from_file(file_path, content)
        if derived_code != query_upper:
            continue

        # Found the site — extract prefixes and device hostnames
        prefixes: List[str] = []
        devices: List[str] = []

        if isinstance(content, dict):
            raw_prefixes = content.get("prefixes", [])
            if isinstance(raw_prefixes, list):
                for entry in raw_prefixes:
                    if isinstance(entry, dict) and "prefix" in entry:
                        prefixes.append(str(entry["prefix"]))
                    elif isinstance(entry, str):
                        prefixes.append(entry)

            raw_devices = content.get("devices", [])
            if isinstance(raw_devices, list):
                for entry in raw_devices:
                    if isinstance(entry, dict):
                        hostname = entry.get("hostname") or entry.get("name")
                        if hostname:
                            devices.append(str(hostname))
                    elif isinstance(entry, str):
                        devices.append(entry)

        site_name = ""
        if isinstance(content, dict):
            site_name = str(content.get("site_name", "") or "")

        return SdwanSiteResult(
            site_code=query_upper,
            status="found",
            site_name=site_name,
            file_path=file_path,
            prefixes=tuple(prefixes),
            devices=tuple(devices),
            findings=(
                _sdwan_finding(
                    "info",
                    f"Site {query_upper!r} found in SD-WAN YAML store",
                    f"file={file_path}",
                ),
            ),
        )

    return SdwanSiteResult(
        site_code=site_code,
        status="not_found",
        findings=(
            _sdwan_finding("info", f"No SD-WAN YAML entry found for site {site_code!r}"),
        ),
    )


def search_by_keyword(runtime: "LensRuntime", term: str) -> List[SdwanMatch]:
    """Search all loaded YAML files for a keyword (case-insensitive regex).

    Returns a list of ``SdwanMatch`` objects — one per matching leaf value.
    Returns an empty list in offline mode or when nothing matches.
    """
    logger = runtime.logger

    if runtime.offline:
        return []

    repo_paths = _resolve_repo_paths(runtime.cfg)
    if not repo_paths:
        return []

    # re.escape always produces a valid regex — no try/except needed.
    pattern = re.compile(re.escape(term), re.IGNORECASE)

    yaml_data = _load_yaml_files(repo_paths, logger)
    matches: List[SdwanMatch] = []

    for file_path, content in yaml_data.items():
        site_code = _site_code_from_file(file_path, content)

        for yaml_path, value in _traverse(content):
            str_val = str(value)
            if pattern.search(str_val):
                matches.append(
                    SdwanMatch(
                        site_code=site_code,
                        file_path=file_path,
                        path=yaml_path,
                        matched_value=str_val,
                    )
                )

    return matches


# ---------------------------------------------------------------------------
# Adapter singleton
# ---------------------------------------------------------------------------

class _SdwanYamlAdapter:
    """LensAdapter-compatible singleton for SD-WAN YAML."""

    name: str = "sdwan_yaml"

    def health(self, runtime: "LensRuntime") -> AdapterHealth:
        return _health(runtime)


ADAPTER = _SdwanYamlAdapter()
