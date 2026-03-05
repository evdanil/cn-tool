from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import hashlib
import ipaddress
import logging
import re
import queue
import threading
from time import time
from pathlib import Path
from time import perf_counter
from typing import Dict, List, Optional, Set, Tuple, Union, Any
from types import SimpleNamespace
from diskcache import Index
from wordlists.keywords import stop_words
from core.base import ScriptContext
from .cache import CacheManager
from .cache_optimized import (
    SortedKeyIndex,
    IPRangeIndex,
    get_config_lines_cached,
    clear_config_cache,
)
from .config import make_dir_list
from .hash import calculate_config_hash
from .search_helpers import extract_keywords, extract_literal_ips
from .validation import ip_regexp

HEX8_RE = re.compile(r"^[0-9A-F]{8}\b")
LONG_HEX_RE = re.compile(r"^[0-9A-Fa-f]{24,}$")
B64ish_RE = re.compile(r"^[0-9A-Za-z+/=]{64,}$")
MAX_INDEXABLE_LINE_LENGTH = 4096

# =============================================================================
# P3 Optimization: Precompiled Stop Word Patterns
# =============================================================================
# Instead of using tuple.startswith() which iterates O(n) prefixes,
# compile all stop words for each vendor into a single regex pattern.


def _build_stopword_regex(prefixes: Tuple[str, ...]) -> Optional[re.Pattern]:
    """
    Build a single compiled regex from a tuple of stop word prefixes.

    Args:
        prefixes: Tuple of string prefixes to match at line start.

    Returns:
        Compiled regex pattern, or None if prefixes is empty.
    """
    if not prefixes:
        return None

    # Escape special regex characters and join with |
    escaped = [re.escape(prefix) for prefix in prefixes]
    # Sort by length descending to match longer prefixes first
    escaped.sort(key=len, reverse=True)
    pattern = f"^({'|'.join(escaped)})"
    return re.compile(pattern)


# Precompiled stop word patterns per vendor (built once at module load)
STOPWORD_PATTERNS: Dict[str, Optional[re.Pattern]] = {
    vendor: _build_stopword_regex(prefixes)
    for vendor, prefixes in stop_words.items()
}

# Volatile config line prefixes for hash computation (skip these lines)
HASH_SKIP_PREFIXES: Tuple[str, ...] = (
    '!', '---', 'Building configuration...', 'Current configuration', '#'
)


def matches_stopword(line: str, vendor: str) -> bool:
    """
    Check if a line starts with any stop word for the given vendor.

    Uses precompiled regex for O(1) matching instead of O(n) tuple iteration.

    Args:
        line: The line to check (should be stripped).
        vendor: The vendor name (lowercase).

    Returns:
        True if line starts with a stop word, False otherwise.
    """
    pattern = STOPWORD_PATTERNS.get(vendor)
    if pattern is None:
        return False
    return pattern.match(line) is not None


def build_config_path(
    ctx: ScriptContext,
    hostname: str,
    region: str,
    vendor: str,
    device_type: str
) -> Optional[Path]:
    """
    Builds the full, OS-agnostic path to a device's configuration file.

    This is a highly efficient helper function that directly assembles the path
    from the provided components without performing any cache lookups.

    Args:
        ctx: The script context, used to access the base config repository directory.
        hostname: The hostname of the device (e.g., 'router_bne001').
        region: The region of the device (e.g., 'bne').
        vendor: The vendor of the device (e.g., 'cisco').
        device_type: The type of the device (e.g., 'router').

    Returns:
        A pathlib.Path object for the configuration file, or None if the
        base directory is not configured.
    """
    # Safely get the base directory from the application configuration.
    # This is the only external data lookup needed.
    base_dir = ctx.cfg.get('config_repo_directory')

    # A check for the base directory is essential for robustness.
    if not base_dir:
        ctx.logger.error("Base configuration directory is not set in config_repo.directory")
        return None

    # Assume the on-disk filename is the lowercase version of the hostname.
    config_filename = f"{hostname.lower()}.cfg"

    return Path(base_dir) / vendor.lower() / device_type.lower() / region.lower() / config_filename


def _excluded_dir_names(ctx: ScriptContext) -> Set[str]:
    excluded = {
        str(item).strip().lower()
        for item in ctx.cfg.get("config_repo_excluded_dirs", [])
        if str(item).strip()
    }
    history_dir = str(ctx.cfg.get("config_repo_history_dir", "history")).strip().lower()
    if history_dir:
        excluded.add(history_dir)
    return excluded


def _cfg_vendor_set(ctx: ScriptContext, key: str) -> Set[str]:
    values = ctx.cfg.get(key, [])
    if isinstance(values, str):
        values = [item.strip() for item in values.split(",") if item.strip()]
    return {str(item).strip().lower() for item in values if str(item).strip()}


def _parse_repo_metadata(ctx: ScriptContext, filename: Path) -> Optional[Tuple[str, str, str]]:
    """
    Parse vendor/type/region from config-repo relative path in a layout-safe way.

    Expected shapes:
    - no-region mode: vendor/device_type/device.cfg
    - region mode:   vendor/device_type/region/device.cfg
    """
    base_dir = ctx.cfg.get("config_repo_directory")
    if not base_dir:
        return None

    try:
        rel_path = filename.relative_to(base_dir)
    except ValueError:
        return None

    parts = rel_path.parts
    has_regions = bool(ctx.cfg.get("config_repo_regions", []))
    expected_depth = 4 if has_regions else 3
    if len(parts) != expected_depth:
        return None

    excluded = _excluded_dir_names(ctx)
    if any(str(part).lower() in excluded for part in parts[:-1]):
        return None

    vendor = str(parts[0]).lower()
    device_type = str(parts[1]).upper()
    region = str(parts[2]).upper() if has_regions else ''
    return vendor, device_type, region


class _NoopLogger:
    """Minimal logger for process workers where full logger objects are not picklable."""

    def error(self, *_args: Any, **_kwargs: Any) -> None:
        return


def _index_worker_cfg_from_cfg(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Build a small picklable cfg subset required by get_device_facts()."""

    def _to_list(key: str) -> List[str]:
        raw = cfg.get(key, [])
        if isinstance(raw, str):
            return [item.strip() for item in raw.split(",") if item.strip()]
        return [str(item).strip() for item in raw if str(item).strip()]

    return {
        "cache_index_skip_vendors": _to_list("cache_index_skip_vendors"),
        "cache_index_skip_keyword_vendors": _to_list("cache_index_skip_keyword_vendors"),
        "cache_index_skip_ip_vendors": _to_list("cache_index_skip_ip_vendors"),
        "cache_index_max_positions_per_key": int(cfg.get("cache_index_max_positions_per_key", 64) or 64),
    }


def _check_file_change_worker(task: Tuple[str, str, int, str]) -> Tuple[str, str, int, int, str, str, bool]:
    """
    Worker for parallel change detection.
    Returns: (hostname, path, cached_mtime, current_mtime, old_hash, new_hash, changed)
    """
    hostname, path_str, cached_mtime, old_hash = task
    file_path = Path(path_str)

    try:
        current_mtime = int(file_path.stat().st_mtime)
    except OSError:
        # Force reindex when file metadata can't be read.
        return hostname, path_str, cached_mtime, cached_mtime, old_hash, "stat-error", True

    if (current_mtime - cached_mtime) <= 1:
        return hostname, path_str, cached_mtime, current_mtime, old_hash, old_hash, False

    new_hash = calculate_config_hash(file_path)
    return hostname, path_str, cached_mtime, current_mtime, old_hash, new_hash, new_hash != old_hash


def _index_file_worker_process(
    task: Tuple[str, str, str, str, str, Dict[str, Any]]
) -> Tuple[Dict[str, Any], Dict[Tuple[str, str], Tuple[int, ...]], Dict[Tuple[str, str], Tuple[int, ...]], Dict[str, Any]]:
    """
    Process-safe indexing worker.
    task: (hostname, vendor, region, device_type, filename_str, worker_cfg)
    """
    hostname, vendor, region, device_type, filename_str, worker_cfg = task
    proc_ctx = SimpleNamespace(cfg=worker_cfg, logger=_NoopLogger())
    return get_device_facts(proc_ctx, hostname, vendor, region, device_type, Path(filename_str))


def _list_cfg_files(folder: Path) -> List[Path]:
    """List .cfg files for a folder, swallowing transient filesystem errors."""
    try:
        return [path for path in folder.glob("*.cfg") if path.is_file()]
    except OSError:
        return []


def cache_writer(
    ctx: ScriptContext,
    write_queue: queue.Queue,
    ip_idx: Index,
    kw_idx: Index,
    dev_idx: Index,
    rev_idx: Index,
    total_files: int,
    batch_size: int,
):
    """
    Consumer thread function. Pulls parsed data from a queue and writes it
    to diskcache in batches to keep memory usage low.
    """
    logger = ctx.logger
    # Keep batches configurable to balance throughput and memory.
    BATCH_SIZE = max(1, int(batch_size))
    processed_count = 0
    last_update_ts = time()
    fatal_error = False
    event_bus = getattr(ctx, "event_bus", None)
    writer_started = perf_counter()
    aggregate_seconds = 0.0
    write_seconds = 0.0

    while processed_count < total_files:
        # 1. Collect a batch of results from the queue
        batch_results = []
        try:
            # Block and wait for the first item to avoid busy-waiting
            item = write_queue.get(timeout=1.0)
            batch_results.append(item)
            # Drain the queue for up to BATCH_SIZE items
            while len(batch_results) < BATCH_SIZE:
                batch_results.append(write_queue.get_nowait())
        except queue.Empty:
            # This happens when the queue is drained or at the very end
            pass

        if not batch_results:
            continue

        # 2. Aggregate data for this batch only
        aggregate_started = perf_counter()
        batch_dev_updates = {}
        batch_rev_updates = {}
        batch_ip_updates = defaultdict(lambda: defaultdict(list))
        batch_kw_updates = defaultdict(lambda: defaultdict(list))

        for dev_data, ip_data, kw_data, rev_data in batch_results:
            batch_dev_updates.update(dev_data)
            batch_rev_updates.update(rev_data)
            for (ip, host), lines in ip_data.items():
                batch_ip_updates[ip][host].extend(lines)
            for (kw, host), lines in kw_data.items():
                batch_kw_updates[kw][host].extend(lines)
        aggregate_seconds += perf_counter() - aggregate_started

        # 3. Write this batch to diskcache using the efficient read-modify-write
        if not fatal_error:
            try:
                write_started = perf_counter()
                with ip_idx.transact(), kw_idx.transact(), dev_idx.transact(), rev_idx.transact():
                    dev_idx.update(batch_dev_updates)
                    rev_idx.update(batch_rev_updates)

                    for ip, new_host_dict in batch_ip_updates.items():
                        current_ip_entry = ip_idx.get(ip, {})
                        for host, lines in list(new_host_dict.items()):
                            if isinstance(lines, list):
                                new_host_dict[host] = tuple(lines)
                        current_ip_entry.update(new_host_dict)
                        ip_idx[ip] = current_ip_entry

                    for kw, new_host_dict in batch_kw_updates.items():
                        current_kw_entry = kw_idx.get(kw, {})
                        for host, lines in list(new_host_dict.items()):
                            if isinstance(lines, list):
                                new_host_dict[host] = tuple(lines)
                        current_kw_entry.update(new_host_dict)
                        kw_idx[kw] = current_kw_entry
                write_seconds += perf_counter() - write_started
            except Exception as e:
                fatal_error = True
                logger.error(f"FATAL error during cache batch write: {e}")
                # Signal the error to the UI via cache (and cfg as fallback)
                try:
                    msg = str(e)
                    err = "disk_full" if 'No space left' in msg or 'ENOSPC' in msg else "io_error"
                    ctx.cache.dc.set("indexing_error", f"{err}: {msg}")
                    ctx.cache.dc.set("indexing_error_time", int(time()))
                    ctx.cache.dc.set("indexing_phase", "error")
                except Exception:
                    try:
                        ctx.cfg["indexing_error"] = f"io_error: {e}"
                    except Exception:
                        pass
                if event_bus:
                    event_bus.publish(
                        "status:update",
                        {
                            "component": "cache",
                            "state": "error",
                            "error": str(e),
                        },
                    )

        processed_count += len(batch_results)
        elapsed = max(perf_counter() - writer_started, 0.001)
        rate = processed_count / elapsed
        try:
            q_depth = write_queue.qsize()
        except Exception:
            q_depth = -1
        logger.info(
            f"Index Cache - {processed_count}/{total_files} files written to cache "
            f"({rate:.1f} files/s, q={q_depth}, batch={BATCH_SIZE})..."
        )

        # Publish progress so the main menu can show live status
        try:
            if ctx.cache and ctx.cache.dc:
                if not fatal_error:
                    ctx.cache.dc.set("indexing_phase", "indexing")
                ctx.cache.dc.set("indexing_total", int(total_files))
                ctx.cache.dc.set("indexing_done", int(processed_count))
                now = time()
                ctx.cache.dc.set("indexing_last_update", int(now))
                last_update_ts = now
                if event_bus and not fatal_error:
                    event_bus.publish(
                        "status:update",
                        {
                            "component": "cache",
                            "state": "indexing",
                            "phase": ctx.cache.dc.get("indexing_phase", "indexing") if ctx.cache else "indexing",
                            "done": processed_count,
                            "total": total_files,
                        },
                    )
        except Exception:
            # Never allow telemetry to break indexing
            pass

    total_elapsed = max(perf_counter() - writer_started, 0.001)
    logger.info(
        "Index Cache writer breakdown: total=%.2fs aggregate=%.2fs write=%.2fs other=%.2fs",
        total_elapsed,
        aggregate_seconds,
        write_seconds,
        max(total_elapsed - aggregate_seconds - write_seconds, 0.0),
    )


def mt_index_configurations(ctx: ScriptContext) -> None:
    """
    Multithreaded, memory-optimized version to index configuration files
    using a producer-consumer model to prevent high RAM usage.
    """
    logger = ctx.logger
    cache: Union[CacheManager, None] = ctx.cache
    event_bus = getattr(ctx, "event_bus", None)
    index_workers = max(1, min(32, int(ctx.cfg.get("cache_index_workers", 4) or 4)))

    if not cache:
        return

    start = perf_counter()
    # Keep indexing marker persistent for long runs; liveness is tracked via indexing_last_update.
    cache.dc.set("indexing", True)
    try:
        cache.dc.set("indexing_started", int(time()))
        cache.dc.set("indexing_phase", "checking")
        cache.dc.pop("checking_total", None)
        cache.dc.pop("checking_done", None)
        cache.dc.pop("cleaning_total", None)
        cache.dc.pop("cleaning_done", None)
        cache.dc.pop("indexing_total", None)
        cache.dc.pop("indexing_done", None)
        cache.dc.pop("indexing_last_update", None)
    except Exception:
        pass
    if event_bus:
        event_bus.publish(
            "status:update",
            {"component": "cache", "state": "indexing", "phase": "checking"},
        )

    # 1. Get the current state from disk
    all_disk_files: Dict[str, Path] = {}
    discovery_folders = make_dir_list(ctx)
    discovery_workers = max(1, min(16, index_workers))
    with ThreadPoolExecutor(max_workers=discovery_workers) as executor:
        future_to_folder = {
            executor.submit(_list_cfg_files, folder): folder
            for folder in discovery_folders
        }
        for future in as_completed(future_to_folder):
            folder = future_to_folder[future]
            try:
                folder_files = future.result()
            except Exception as exc:
                logger.error(f"Failed to enumerate configs in {folder}: {exc}")
                continue
            for file_path in folder_files:
                if _parse_repo_metadata(ctx, file_path) is None:
                    logger.debug(f"Skipping non-canonical config path: {file_path}")
                    continue
                # All keys should be upper case to match cache keys
                all_disk_files[file_path.stem.upper()] = file_path
    total_bytes = 0
    for path in all_disk_files.values():
        try:
            total_bytes += int(path.stat().st_size)
        except OSError:
            continue

    # 2. Get the last known state from cache
    dev_idx = cache.dev_idx
    rev_idx = cache.rev_idx
    ip_idx = cache.ip_idx
    kw_idx = cache.kw_idx

    cfg_cache_version = int(ctx.cfg.get("cache_version", 0))
    current_cache_version = int(cache.dc.get("version", 0) or 0)
    if current_cache_version != cfg_cache_version:
        logger.warning(
            "Cache version mismatch detected (cache=%s, config=%s). Resetting all cache indexes.",
            current_cache_version,
            cfg_cache_version,
        )
        with ip_idx.transact(), kw_idx.transact(), dev_idx.transact(), rev_idx.transact():
            ip_idx.clear()
            kw_idx.clear()
            dev_idx.clear()
            rev_idx.clear()
        cache.dc.set("version", cfg_cache_version)

    # All keys in cache already uppercased
    cached_hostnames = set(dev_idx.keys())
    disk_hostnames = set(all_disk_files.keys())

    # 3. Identify changes
    new_files = disk_hostnames - cached_hostnames
    deleted_files = cached_hostnames - disk_hostnames
    potentially_updated_files = disk_hostnames.intersection(cached_hostnames)

    files_to_reindex: List[Path] = [all_disk_files[host] for host in new_files]

    logger.info(f"Disk files(total):{len(disk_hostnames)}")
    logger.info(f"Cached files:{len(cached_hostnames)}")
    logger.info(f"Deleted files:{len(deleted_files)}")
    logger.info(f"New files:{len(new_files)}")
    logger.info(f"Potentially updated files:{len(potentially_updated_files)}")
    logger.info(f"Files to re-index:{len(files_to_reindex)}")
    logger.info(f"Approx input size:{round(total_bytes / (1024 * 1024), 1)} MiB")

    logger.info("Checking existing files for content changes...")
    files_reindexed_count = 0
    last_checking_heartbeat = time()
    check_workers_default = max(2, min(16, index_workers))
    check_workers = max(1, min(64, int(ctx.cfg.get("cache_check_workers", check_workers_default) or check_workers_default)))
    try:
        cache.dc.set("checking_total", int(len(potentially_updated_files)))
        cache.dc.set("checking_done", 0)
        cache.dc.set("indexing_last_update", int(time()))
    except Exception:
        pass

    check_tasks: List[Tuple[str, str, int, str]] = []
    prechecked_count = 0
    for hostname in potentially_updated_files:
        file_path = all_disk_files[hostname]
        cached_device_info = dev_idx.get(hostname)  # Use .get()

        # --- NEW, CRITICAL DEBUGGING ---
        if not isinstance(cached_device_info, dict):
            logger.error(f"FATAL: Cached info for '{hostname}' is not a dictionary! Got: {type(cached_device_info)}. Re-indexing.")
            files_to_reindex.append(file_path)
            prechecked_count += 1
            continue
        # --- END CRITICAL DEBUGGING ---

        # Get values with defaults for safety
        cached_mtime = int(cached_device_info.get("updated", 0) or 0)
        old_hash = str(cached_device_info.get("hash", "no-hash-in-cache"))
        check_tasks.append((hostname, str(file_path), cached_mtime, old_hash))

    logger.info(f"Checking phase runtime settings: workers={check_workers}")
    if check_tasks:
        with ThreadPoolExecutor(max_workers=check_workers) as executor:
            future_to_task = {
                executor.submit(_check_file_change_worker, task): task
                for task in check_tasks
            }
            for idx, future in enumerate(as_completed(future_to_task), start=1):
                fallback_task = future_to_task[future]
                try:
                    hostname, path_str, cached_mtime, current_mtime, old_hash, new_hash, changed = future.result()
                except Exception as exc:
                    hostname, path_str, cached_mtime, old_hash = fallback_task
                    logger.error(
                        f"Checking worker failed for {hostname} ({path_str}): {exc}. Scheduling re-index.",
                        exc_info=True,
                    )
                    files_to_reindex.append(Path(path_str))
                    changed = False
                else:
                    if changed:
                        logger.info(f"Content changed for {hostname} (mtime and hash mismatch), scheduling for re-index.")
                        logger.debug(f"  - Details for {hostname}:")
                        logger.debug(f"  - Cached MTime: {cached_mtime}, Current MTime: {current_mtime}")
                        logger.debug(f"  - Cached Hash:  {old_hash}")
                        logger.debug(f"  - New Hash:     {new_hash}")
                        files_to_reindex.append(Path(path_str))
                        files_reindexed_count += 1

                done_count = prechecked_count + idx
                now = time()
                if idx % 100 == 0 or (now - last_checking_heartbeat) >= 5:
                    try:
                        cache.dc.set("checking_done", int(done_count))
                        cache.dc.set("indexing_last_update", int(now))
                        last_checking_heartbeat = now
                    except Exception:
                        pass

    logger.info(f"Finished checking files. Found {files_reindexed_count} files that need re-indexing.")
    try:
        cache.dc.set("checking_done", int(len(potentially_updated_files)))
        cache.dc.set("indexing_last_update", int(time()))
    except Exception:
        pass

    # We need a unified list of all hosts whose entries need to be cleaned
    hosts_to_clean = set(deleted_files)
    # Also clean hosts that are being re-indexed
    for file_path in files_to_reindex:
        hosts_to_clean.add(file_path.stem.upper())

    # Release discovery-phase structures no longer needed
    del all_disk_files, cached_hostnames, disk_hostnames, potentially_updated_files

    # 4. Clean all obsolete entries using the reverse index
    if hosts_to_clean:
        logger.info(f"Cleaning {len(hosts_to_clean)} obsolete/updated host entries from indexes...")
        try:
            cache.dc.set("indexing_phase", "cleaning")
            cache.dc.set("cleaning_total", int(len(hosts_to_clean)))
            cache.dc.set("cleaning_done", 0)
            cache.dc.set("indexing_last_update", int(time()))
        except Exception:
            pass
        if event_bus:
            event_bus.publish(
                "status:update",
                {
                    "component": "cache",
                    "state": "indexing",
                    "phase": "cleaning",
                    "total": len(hosts_to_clean),
                },
            )

        # Step 1: Identify all IP/Keyword keys we need to modify.
        ips_to_modify = set()
        kws_to_modify = set()
        last_cleaning_heartbeat = time()
        for hostname in hosts_to_clean:
            old_rev_data = rev_idx.get(hostname, {})
            ips_to_modify.update(old_rev_data.get('ips', []))
            kws_to_modify.update(old_rev_data.get('kws', []))
            # Keep background stale-check from clearing a healthy long-running clean phase.
            now = time()
            if (now - last_cleaning_heartbeat) >= 5:
                try:
                    cache.dc.set("indexing_last_update", int(now))
                    last_cleaning_heartbeat = now
                except Exception:
                    pass

        logger.info(f"Identified {len(ips_to_modify)} IP keys and {len(kws_to_modify)} keyword keys to modify.")

        # Step 2: Bulk load only the necessary data into memory.
        logger.info("Loading relevant index entries into memory...")
        # Use dict comprehensions for a fast, single-pass load.
        in_memory_ip_idx = {ip_key: ip_idx.get(ip_key, {}) for ip_key in ips_to_modify}
        in_memory_kw_idx = {kw_key: kw_idx.get(kw_key, {}) for kw_key in kws_to_modify}
        logger.info("In-memory load complete.")

        # Step 3: Perform all cleanup operations on the fast in-memory dicts.
        logger.info("Performing cleanup operations in memory...")
        for clean_idx, hostname in enumerate(hosts_to_clean, start=1):
            old_rev_data = rev_idx.get(hostname, {})  # Still need this to know what to clean

            # Clean the in-memory ip_idx
            for ip_key in old_rev_data.get('ips', []):
                if ip_key in in_memory_ip_idx and hostname in in_memory_ip_idx[ip_key]:
                    del in_memory_ip_idx[ip_key][hostname]

            # Clean the in-memory kw_idx
            for keyword in old_rev_data.get('kws', []):
                if keyword in in_memory_kw_idx and hostname in in_memory_kw_idx[keyword]:
                    del in_memory_kw_idx[keyword][hostname]
            now = time()
            if clean_idx % 100 == 0 or (now - last_cleaning_heartbeat) >= 5:
                try:
                    cache.dc.set("cleaning_done", int(clean_idx))
                    cache.dc.set("indexing_last_update", int(now))
                    last_cleaning_heartbeat = now
                except Exception:
                    pass
        logger.info("In-memory cleanup complete.")

        # Step 4: Write all changes back to diskcache in a single transaction.
        logger.info("Writing all changes back to disk cache...")
        with ip_idx.transact(), kw_idx.transact(), dev_idx.transact(), rev_idx.transact():

            # Delete the hosts from the primary and reverse indexes
            for hostname in hosts_to_clean:
                if hostname in dev_idx:
                    del dev_idx[hostname]
                if hostname in rev_idx:
                    del rev_idx[hostname]

            # Write back the modified ip_idx entries
            for ip_key, modified_entry in in_memory_ip_idx.items():
                if not modified_entry:  # If the dict for this IP is now empty
                    if ip_key in ip_idx:
                        del ip_idx[ip_key]
                else:
                    ip_idx[ip_key] = modified_entry

            # Write back the modified kw_idx entries
            for kw_key, modified_entry in in_memory_kw_idx.items():
                if not modified_entry:  # If the dict for this keyword is now empty
                    if kw_key in kw_idx:
                        del kw_idx[kw_key]
                else:
                    kw_idx[kw_key] = modified_entry

        logger.info("Cleaning complete.")
        try:
            cache.dc.set("cleaning_done", int(len(hosts_to_clean)))
            cache.dc.set("indexing_last_update", int(time()))
        except Exception:
            pass
        if event_bus:
            event_bus.publish(
                "status:update",
                {
                    "component": "cache",
                    "state": "indexing",
                    "phase": "cleaning",
                    "done": len(hosts_to_clean),
                    "total": len(hosts_to_clean),
                },
            )

        # Release cleaning-phase structures before indexing phase
        del in_memory_ip_idx, in_memory_kw_idx
        del ips_to_modify, kws_to_modify

    # 5. Handle Additions/Updates
    index_inputs_by_host: Dict[str, Tuple[str, str, str, str, Path]] = {}
    for file_path in files_to_reindex:
        parsed = _parse_repo_metadata(ctx, file_path)
        if parsed is None:
            logger.debug(f"Skipping file with unsupported path layout before indexing: {file_path}")
            continue
        vendor, device_type, region = parsed
        hostname = file_path.stem.upper()
        index_inputs_by_host[hostname] = (hostname, vendor, region, device_type, file_path)
    index_inputs = list(index_inputs_by_host.values())

    logger.info(f"Index Cache - Found {len(index_inputs)} new or updated files. Indexing...")
    if not index_inputs:
        logger.info("Index Cache - No configuration changes detected.")
        try:
            cache.dc.pop("indexing", None)
            cache.dc.pop("indexing_phase", None)
            cache.dc.pop("checking_total", None)
            cache.dc.pop("checking_done", None)
            cache.dc.pop("cleaning_total", None)
            cache.dc.pop("cleaning_done", None)
            cache.dc.pop("indexing_total", None)
            cache.dc.pop("indexing_done", None)
            cache.dc.pop("indexing_last_update", None)
            cache.dc.set("updated", int(time()))
        except Exception:
            pass
        if event_bus:
            event_bus.publish(
                "status:update",
                {"component": "cache", "state": "ready"},
            )
        return

    # Create a thread-safe queue to hold results from worker threads/processes.
    # Maxsize prevents producers from running too far ahead of the consumer, acting as back-pressure.
    queue_size = max(8, int(ctx.cfg.get("cache_index_queue_size", 64) or 64))
    batch_size = max(1, int(ctx.cfg.get("cache_index_batch_size", 100) or 100))
    executor_mode = str(ctx.cfg.get("cache_index_executor", "thread") or "thread").strip().lower()
    if executor_mode not in {"thread", "process"}:
        logger.warning(f"Unsupported cache index executor '{executor_mode}', falling back to 'thread'.")
        executor_mode = "thread"
    logger.info(
        "Index runtime settings: workers=%s queue_size=%s batch_size=%s mode=%s",
        index_workers,
        queue_size,
        batch_size,
        executor_mode,
    )
    write_queue = queue.Queue(maxsize=queue_size)

    # Start the consumer thread (the cache writer)
    try:
        cache.dc.set("indexing_phase", "indexing")
        cache.dc.set("indexing_total", int(len(index_inputs)))
        cache.dc.set("indexing_done", 0)
        cache.dc.set("indexing_last_update", int(time()))
    except Exception:
        pass

    writer_thread = threading.Thread(
        target=cache_writer,
        args=(
            ctx,
            write_queue,
            cache.ip_idx,
            cache.kw_idx,
            cache.dev_idx,
            cache.rev_idx,
            len(index_inputs),
            batch_size,
        ),
    )
    writer_thread.start()

    # Produce data (read/parse files) via threads or processes.
    if executor_mode == "process":
        worker_cfg = _index_worker_cfg_from_cfg(ctx.cfg)
        with ProcessPoolExecutor(max_workers=index_workers) as executor:
            future_to_hostname = {
                executor.submit(
                    _index_file_worker_process,
                    (hostname, vendor, region, device_type, str(filename), worker_cfg),
                ): hostname
                for hostname, vendor, region, device_type, filename in index_inputs
            }
            for idx, future in enumerate(as_completed(future_to_hostname), start=1):
                hostname = future_to_hostname[future]
                try:
                    result = future.result()
                except Exception as exc:
                    logger.error(f"Index worker failed for {hostname}: {exc}", exc_info=True)
                    result = ({}, {}, {}, {})
                write_queue.put(result)
                if idx % 100 == 0:
                    try:
                        cache.dc.set("indexing_last_update", int(time()))
                    except Exception:
                        pass
    else:
        with ThreadPoolExecutor(max_workers=index_workers) as executor:
            # Submit all file processing tasks. They will put results on the queue.
            for item in index_inputs:
                executor.submit(_index_file_worker_thread, ctx, item, write_queue)

    # Wait for the writer thread to finish processing all items from the queue
    writer_thread.join()

    # If a fatal error occurred, mark indexing as finished with error and avoid marking cache updated
    fatal = False
    try:
        fatal = bool(cache.dc.get("indexing_error"))
    except Exception:
        fatal = bool(ctx.cfg.get("indexing_error", False))

    logger.info("Disk cache update complete.")

    # Clear in-memory file content LRU cache after indexing to ensure fresh reads
    clear_config_cache()

    # Release memory held by Python allocator and SQLite after indexing
    _release_post_indexing_memory(cache, logger)

    end = perf_counter()
    if not fatal:
        cache.dc.set("updated", int(time()))
        if cache.dc.get("version", 0) != ctx.cfg["cache_version"]:
            cache.dc.set("version", ctx.cfg["cache_version"])

    try:
        cache.dc.pop("indexing", None)
        if not fatal:
            cache.dc.pop("indexing_phase", None)
        cache.dc.pop("checking_total", None)
        cache.dc.pop("checking_done", None)
        cache.dc.pop("cleaning_total", None)
        cache.dc.pop("cleaning_done", None)
        cache.dc.pop("indexing_total", None)
        cache.dc.pop("indexing_done", None)
        cache.dc.pop("indexing_last_update", None)
        if fatal:
            cache.dc.set("indexing_phase", "error")
    except Exception:
        pass
    if event_bus:
        if fatal:
            event_bus.publish(
                "status:update",
                {"component": "cache", "state": "error"},
            )
        else:
            event_bus.publish(
                "status:update",
                {"component": "cache", "state": "ready"},
            )
    logger.info(f"Index Cache - Update took {round(end - start, 3)} seconds")


def _release_post_indexing_memory(cache: CacheManager, logger: logging.Logger) -> None:
    """Release memory held by Python allocator and SQLite after indexing."""
    import gc
    gc.collect()

    # Shrink SQLite page caches across all connections
    try:
        for shard in cache.dc._shards:
            shard._sql('PRAGMA shrink_memory').fetchall()
        for idx_obj in cache.dc._indexes.values():
            idx_obj._cache._sql('PRAGMA shrink_memory').fetchall()
        logger.debug("Post-indexing: SQLite shrink_memory completed.")
    except Exception as exc:
        logger.warning("Post-indexing: SQLite shrink_memory failed (diskcache internals may have changed): %s", exc)

    # Return freed pages to OS (Linux only)
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6")
        libc.malloc_trim(0)
        logger.debug("Post-indexing: malloc_trim completed.")
    except Exception:
        pass


def _index_file_worker_thread(
    ctx: ScriptContext,
    item: Tuple[str, str, str, str, Path],
    write_queue: Optional[queue.Queue] = None,
) -> Optional[Tuple[Dict[str, Any], Dict[Tuple[str, str], Tuple[int, ...]], Dict[Tuple[str, str], Tuple[int, ...]], Dict[str, Any]]]:
    """
    Thread worker that indexes one file using pre-parsed metadata.
    item: (hostname, vendor, region, device_type, filename)
    """
    hostname, vendor, region, device_type, filename = item
    try:
        result = get_device_facts(ctx, hostname, vendor, region, device_type, filename)
    except Exception as exc:
        ctx.logger.error(f"Index worker failed for {hostname} ({filename}): {exc}", exc_info=True)
        result = ({}, {}, {}, {})
    if write_queue:
        write_queue.put(result)
        return None
    return result


def get_facts_helper(
    ctx: ScriptContext, filename: Path, write_queue: Optional[queue.Queue] = None
) -> Optional[Tuple[Dict[str, Any], defaultdict, defaultdict, Dict[str, Any]]]:
    """
    Function is a helper to run get_device_facts in Multithreaded fashion.
    It can either return data or put it on a queue for batch processing.
    """
    hostname = filename.stem.upper()
    parsed = _parse_repo_metadata(ctx, filename)
    if parsed is None:
        ctx.logger.debug(f"Skipping file with unsupported path layout: {filename}")
        result = ({}, {}, {}, {})
        if write_queue:
            write_queue.put(result)
            return None
        return result

    vendor, device_type, region = parsed

    ctx.logger.debug(f"Index Cache - Building {hostname.upper()} index data...")
    result = get_device_facts(ctx, hostname, vendor, region, device_type, filename)

    if write_queue:
        write_queue.put(result)
        return None  # Explicitly return None when using the queue
    else:
        return result


def get_device_facts(ctx: ScriptContext, hostname: str, vendor: str, region: str, device_type: str, filename: Path) -> Tuple[Dict[str, Any], defaultdict, defaultdict, Dict[str, Any]]:
    """
    Extract device metadata, IPs, and keywords from a config file.

    P2 Optimization: Computes content hash in the same pass as index extraction,
    eliminating duplicate file reads.

    P3 Optimization: Uses precompiled regex patterns for stop word matching.
    """
    logger = ctx.logger

    # P2 Optimization: Single-pass hash + index extraction
    # Open in binary mode for accurate hash computation, decode for processing
    hasher = hashlib.sha256()
    # Use lists for line number accumulation: append is O(1), tuple concat is O(n).
    ip_list: defaultdict = defaultdict(list)
    kw_list: defaultdict = defaultdict(list)

    vendor_lower = vendor.lower()
    skip_vendors = _cfg_vendor_set(ctx, "cache_index_skip_vendors")
    skip_kw_vendors = skip_vendors.union(_cfg_vendor_set(ctx, "cache_index_skip_keyword_vendors"))
    skip_ip_vendors = skip_vendors.union(_cfg_vendor_set(ctx, "cache_index_skip_ip_vendors"))
    skip_keywords = vendor_lower in skip_kw_vendors
    skip_ips = vendor_lower in skip_ip_vendors
    max_positions = max(1, int(ctx.cfg.get("cache_index_max_positions_per_key", 64) or 64))
    content_hash = "error-generating-hash"  # Default in case of error

    try:
        with open(filename, "rb") as f:
            for index, line_bytes in enumerate(f):
                # Decode for processing
                line_str = line_bytes.decode('utf-8', errors='ignore')
                line_strip = line_str.strip()

                # Hash computation: skip volatile lines (same logic as hash.py)
                # P3 Optimization: Use module-level HASH_SKIP_PREFIXES tuple
                if line_strip and not line_strip.startswith(HASH_SKIP_PREFIXES):
                    hasher.update(line_bytes)

                if not line_strip:
                    continue
                if len(line_strip) > MAX_INDEXABLE_LINE_LENGTH:
                    continue

                # Index extraction: skip stop words and noise patterns
                # P3 Optimization: Use precompiled regex via matches_stopword()
                if (
                    matches_stopword(line_strip, vendor_lower)
                    or HEX8_RE.match(line_strip)
                    or LONG_HEX_RE.match(line_strip)
                    or B64ish_RE.match(line_strip)
                ):
                    continue

                # Extract IPs
                if not skip_ips:
                    for match in ip_regexp.finditer(line_strip):
                        s = match.group()
                        try:
                            ip = ipaddress.ip_address(s)
                            if s.startswith(("255.", "0.")) or ip.is_reserved:
                                continue
                            line_numbers = ip_list[(str(int(ip)), hostname)]
                            if len(line_numbers) < max_positions:
                                line_numbers.append(index)
                        except ValueError:
                            pass

                # Extract keywords
                if not skip_keywords:
                    for word in extract_keywords(line_strip, vendor=vendor_lower):
                        line_numbers = kw_list[(word, hostname)]
                        if len(line_numbers) < max_positions:
                            line_numbers.append(index)

        content_hash = hasher.hexdigest()

    except (IOError, OSError) as e:
        logger.error(f"Error reading device file {filename}: {e}")

    # Build device metadata with computed hash
    device = {
        "region": region,
        "type": device_type,
        "vendor": vendor,
        "updated": int(filename.stat().st_mtime),
        "hash": content_hash
    }

    # Convert to tuples once (linear cost) to keep queue/cache payloads compact.
    ip_data = {key: tuple(lines) for key, lines in ip_list.items()}
    kw_data = {key: tuple(lines) for key, lines in kw_list.items()}

    reverse_index_data = {
            'ips': list(set(ip for ip, host in ip_data.keys())),
            'kws': list(set(kw for kw, host in kw_data.keys()))
        }

    return ({hostname: device}, ip_data, kw_data, {hostname: reverse_index_data})


def search_cache_config(
    ctx: ScriptContext,
    folder: str,
    nets: Optional[List[ipaddress.IPv4Network]],
    search_terms: List[str],
    search_input: str
) -> Tuple[List[List[Any]], Set[ipaddress.IPv4Network]]:

    data_to_save: List[List[Any]] = []
    data, matched_nets = search_cache_subnets(ctx, nets, search_input)
    data_to_save.extend(data)

    kw_data, kw_matched_nets = search_cache_keywords(ctx, search_terms, search_input)
    data_to_save.extend(kw_data)
    matched_nets.update(kw_matched_nets)

    return data_to_save, matched_nets


def search_cache_keywords(ctx: ScriptContext, search_terms: List[str], search_input: str) -> Tuple[List[List[Any]], Set[ipaddress.IPv4Network]]:
    """
    Performs a hybrid cached search for regex terms.
    1. Uses the keyword index (kw_idx) for a fast pre-selection of candidate lines.
    2. Performs the full, expensive regex match only on the small set of candidate lines.
    3. Falls back to IP index hints and, if needed, a bounded on-disk scan to guarantee parity with live searches.

    Optimized to use O(log n) prefix search via SortedKeyIndex and LRU file caching.
    """
    logger = ctx.logger
    data_to_save: List[List[Any]] = []
    matched_nets: Set[ipaddress.IPv4Network] = set()

    # Ensure cache is available
    if not isinstance(ctx.cache, CacheManager) or not search_terms:
        return data_to_save, matched_nets

    cache = ctx.cache
    kw_idx = cache.kw_idx
    dev_idx = cache.dev_idx

    # P1 Optimization: Use SortedKeyIndex for O(log n) prefix search
    sorted_kw_idx = SortedKeyIndex(kw_idx)

    seen_rows: Set[Tuple[str, int, str]] = set()
    missing_terms: List[str] = []
    aggregated_ip_hints: Set[str] = set()

    compiled_patterns: Dict[str, Optional[re.Pattern]] = {}

    def get_compiled(term: str) -> Optional[re.Pattern]:
        if term not in compiled_patterns:
            try:
                compiled_patterns[term] = re.compile(term, re.IGNORECASE)
            except re.error as exc:
                logger.warning(f"Skipping invalid regex '{term}': {exc}")
                compiled_patterns[term] = None
        return compiled_patterns[term]

    for term in search_terms:
        candidate_words = extract_keywords(term, preserve_stopwords=True)
        candidate_lines_by_host: Dict[str, Set[int]] = defaultdict(set)
        pattern = get_compiled(term)
        if pattern is None:
            continue

        for word in candidate_words:
            # P1 Optimization: O(log n) prefix search instead of O(n) linear scan
            matching_keys = sorted_kw_idx.prefix_search(word.lower())

            for key in matching_keys:
                word_entry = kw_idx.get(key)
                if isinstance(word_entry, dict):
                    for hostname, lines in word_entry.items():
                        candidate_lines_by_host[hostname.upper()].update(lines)

        term_has_results = False

        if candidate_lines_by_host:
            for hostname, line_numbers in candidate_lines_by_host.items():
                device_info = dev_idx.get(hostname.upper())
                if not isinstance(device_info, dict):
                    continue

                fname = build_config_path(
                    ctx,
                    hostname,
                    device_info.get('region', ''),
                    device_info.get('vendor', ''),
                    device_info.get('type', ''),
                )
                if not fname:
                    logger.warning(f"Unable to read configuration file for {hostname}. Cache entry invalid.")
                    continue

                # P2 Optimization: Use LRU cached file reads
                try:
                    full_config_lines = get_config_lines_cached(str(fname))
                except (IOError, OSError) as e:
                    logger.error(f"Could not read config for {hostname}: {e}")
                    continue

                for line_num in sorted(list(line_numbers)):
                    if 0 <= line_num < len(full_config_lines):
                        line_content = full_config_lines[line_num]
                        if pattern.search(line_content):
                            row_key = (hostname.upper(), line_num, line_content.strip())
                            if row_key in seen_rows:
                                continue
                            data_to_save.append([
                                search_input,
                                hostname.upper(),
                                line_num,
                                line_content.strip(),
                                str(fname),
                            ])
                            seen_rows.add(row_key)
                            term_has_results = True

        # Collect IP hints to reuse subnet index later.
        literal_ips = extract_literal_ips(term)
        if literal_ips:
            aggregated_ip_hints.update(literal_ips)

        if not term_has_results:
            missing_terms.append(term)

    # Attempt IP-based fallback if keyword index was insufficient.
    if aggregated_ip_hints:
        ip_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        for ip_text in aggregated_ip_hints:
            try:
                ip_obj = ipaddress.ip_address(ip_text)
            except ValueError:
                continue

            mask = 32 if isinstance(ip_obj, ipaddress.IPv4Address) else 128
            try:
                ip_net = ipaddress.ip_network(f"{ip_text}/{mask}", strict=False)
            except ValueError:
                continue
            ip_networks.append(ip_net)

        if ip_networks:
            logger.info("Cache search fallback: consulting IP index for %d literal IPs", len(ip_networks))
            subnet_data, subnet_matches = search_cache_subnets(ctx, ip_networks, search_input)
            matched_nets.update(subnet_matches)

            for row in subnet_data:
                row_key = (row[1], row[2], row[3])
                if row_key in seen_rows:
                    continue

                line_text = row[3]
                if not any(pattern and pattern.search(line_text) for pattern in compiled_patterns.values()):
                    continue

                if not row[4]:
                    device_info = dev_idx.get(row[1], {})
                    fname = build_config_path(
                        ctx,
                        row[1],
                        device_info.get('region', ''),
                        device_info.get('vendor', ''),
                        device_info.get('type', ''),
                    )
                    if fname:
                        row[4] = str(fname)

                data_to_save.append(row)
                seen_rows.add(row_key)

    # Remove missing terms that already found matches via IP fallback.
    if missing_terms and data_to_save:
        still_missing: List[str] = []
        for term in missing_terms:
            pattern = compiled_patterns.get(term)
            if not pattern:
                continue

            if not any(pattern.search(row[3]) for row in data_to_save):
                still_missing.append(term)

        missing_terms = still_missing

    # Final slow-path fallback: direct regex scan over cached files.
    if missing_terms:
        logger.info("Cache search fallback: running bounded regex scan for %d terms", len(missing_terms))
        slow_rows = _slow_regex_scan(ctx, search_input, missing_terms, seen_rows)
        data_to_save.extend(slow_rows)

    return data_to_save, matched_nets


def _slow_regex_scan(
    ctx: ScriptContext,
    search_input: str,
    terms: List[str],
    seen_rows: Set[Tuple[str, int, str]],
) -> List[List[Any]]:
    """
    Last-resort fallback for cached searches: iterate configs on disk and evaluate
    the regex terms directly. This path should be rare and is intentionally verbose in logging.
    """
    logger = ctx.logger
    cache = ctx.cache

    if not isinstance(cache, CacheManager):
        return []

    compiled_terms: List[Tuple[str, re.Pattern]] = []
    for term in terms:
        try:
            compiled_terms.append((term, re.compile(term, re.IGNORECASE)))
        except re.error as exc:
            logger.warning(f"Skipping invalid regex '{term}' in slow fallback: {exc}")

    if not compiled_terms:
        return []

    results: List[List[Any]] = []
    dev_idx = cache.dev_idx

    for hostname, device_info in dev_idx.items():
        if not isinstance(device_info, dict):
            continue

        fname = build_config_path(
            ctx,
            hostname,
            device_info.get('region', ''),
            device_info.get('vendor', ''),
            device_info.get('type', ''),
        )
        if not fname:
            continue

        vendor = str(device_info.get('vendor', '')).lower()

        try:
            with open(fname, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f):
                    line_strip = line.strip()
                    # P3 Optimization: Use precompiled regex via matches_stopword()
                    if matches_stopword(line_strip, vendor):
                        continue

                    for term, pattern in compiled_terms:
                        if pattern.search(line):
                            row_key = (hostname.upper(), line_num, line_strip)
                            if row_key in seen_rows:
                                break
                            results.append([
                                search_input,
                                hostname.upper(),
                                line_num,
                                line_strip,
                                str(fname),
                            ])
                            seen_rows.add(row_key)
                            break
        except (IOError, OSError) as exc:
            logger.error(f"Slow fallback failed for {hostname}: {exc}")

    return results


def search_cache_subnets(
    ctx: ScriptContext, nets: Optional[List[ipaddress.IPv4Network]], search_input: str
) -> Tuple[List[List[Any]], Set[ipaddress.IPv4Network]]:
    """
    Search for IPs within given subnets using the IP index.

    Optimized to use O(log n) range queries via IPRangeIndex and LRU file caching.
    """
    logger = ctx.logger

    matched_nets: Set[ipaddress.IPv4Network] = set()
    data_to_save: List[List[Any]] = []

    if isinstance(ctx.cache, CacheManager):
        ip_idx: Index = ctx.cache.ip_idx
        dev_idx: Index = ctx.cache.dev_idx
    else:
        return data_to_save, matched_nets

    if not nets or not ip_idx or not dev_idx:
        return data_to_save, matched_nets

    # P1 Optimization: Use IPRangeIndex for O(log n) range queries
    ip_range_idx = IPRangeIndex(ip_idx)

    rows_to_save: Dict[str, Dict[int, Tuple[str, str]]] = defaultdict(dict)

    for net in nets:
        # P1 Optimization: O(log n + k) search instead of O(subnet_size) iteration
        matching_ips = ip_range_idx.search_subnet(net)

        if matching_ips:
            matched_nets.add(net)

        for ip_int, ip_entry in matching_ips:
            if isinstance(ip_entry, dict):
                for hostname, line_nums in ip_entry.items():
                    device_info = dev_idx.get(hostname.upper(), {})
                    fname = build_config_path(ctx, hostname, device_info.get('region', ''), device_info.get('vendor', ''), device_info.get('type', ''))
                    if not fname:
                        logger.warning(f"Unable to read configuration file for {hostname}. Cache entry invalid.")
                        continue

                    # P2 Optimization: Use LRU cached file reads
                    try:
                        all_lines = get_config_lines_cached(str(fname))
                        if isinstance(line_nums, (list, tuple)):
                            for line_num in line_nums:
                                try:
                                    idx = int(line_num)
                                    if 0 <= idx < len(all_lines):
                                        rows_to_save[hostname.upper()][line_num] = (all_lines[idx].strip(), str(fname))
                                except (ValueError, IndexError):
                                    # Log bad line number from cache if needed
                                    pass
                    except IOError:
                        # Log file reading error if needed
                        pass

    for hostname, indices in sorted(rows_to_save.items()):
        for index, (line, path) in sorted(indices.items()):
            data_to_save.append([search_input, hostname.upper(), index, line, path])

    return data_to_save, matched_nets
