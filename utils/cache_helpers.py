from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import re
import queue
import threading
from time import time
from pathlib import Path
from time import perf_counter
from typing import Dict, List, Optional, Set, Tuple, Union, Any
from diskcache import Index
from wordlists.keywords import stop_words, standard_keywords
from core.base import ScriptContext
from .cache import CacheManager
from .config import make_dir_list
from .hash import calculate_config_hash
from .search_helpers import extract_keywords
from .validation import ip_regexp

HEX8_RE = re.compile(r"^[0-9A-F]{8}\b")
B64ish_RE = re.compile(r"^[0-9a-zA-Z/+]{65}$")


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


def cache_writer(
    ctx: ScriptContext,
    write_queue: queue.Queue,
    ip_idx: Index,
    kw_idx: Index,
    dev_idx: Index,
    rev_idx: Index,
    total_files: int
):
    """
    Consumer thread function. Pulls parsed data from a queue and writes it
    to diskcache in batches to keep memory usage low.
    """
    logger = ctx.logger
    BATCH_SIZE = 500  # Tunable: process 500 files before writing to disk
    processed_count = 0

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

        # 3. Write this batch to diskcache using the efficient read-modify-write
        try:
            with ip_idx.transact(), kw_idx.transact(), dev_idx.transact(), rev_idx.transact():
                dev_idx.update(batch_dev_updates)
                rev_idx.update(batch_rev_updates)

                for ip, new_host_dict in batch_ip_updates.items():
                    current_ip_entry = ip_idx.get(ip, {})
                    current_ip_entry.update(new_host_dict)
                    ip_idx[ip] = current_ip_entry

                for kw, new_host_dict in batch_kw_updates.items():
                    current_kw_entry = kw_idx.get(kw, {})
                    current_kw_entry.update(new_host_dict)
                    kw_idx[kw] = current_kw_entry
        except Exception as e:
            logger.error(f"FATAL error during cache batch write: {e}")

        processed_count += len(batch_results)
        logger.info(f"Index Cache - {processed_count}/{total_files} files written to cache...")


def mt_index_configurations(ctx: ScriptContext) -> None:
    """
    Multithreaded, memory-optimized version to index configuration files
    using a producer-consumer model to prevent high RAM usage.
    """
    logger = ctx.logger
    cache: Union[CacheManager, None] = ctx.cache

    if not cache:
        return

    start = perf_counter()
    cache.dc.set("indexing", True, expire=120)

    # 1. Get the current state from disk
    all_disk_files: Dict[str, Path] = {}
    for folder in make_dir_list(ctx):
        for file_path in folder.glob("*.cfg"):
            # All keys should be upper case to match cache keys
            all_disk_files[file_path.stem.upper()] = file_path

    # 2. Get the last known state from cache
    dev_idx = cache.dev_idx
    rev_idx = cache.rev_idx
    ip_idx = cache.ip_idx
    kw_idx = cache.kw_idx
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

    logger.info("Checking existing files for content changes...")
    files_reindexed_count = 0

    for hostname in potentially_updated_files:
        file_path = all_disk_files[hostname]
        cached_device_info = dev_idx.get(hostname)  # Use .get()

        # --- NEW, CRITICAL DEBUGGING ---
        if not isinstance(cached_device_info, dict):
            logger.error(f"FATAL: Cached info for '{hostname}' is not a dictionary! Got: {type(cached_device_info)}. Re-indexing.")
            files_to_reindex.append(file_path)
            continue
        # --- END CRITICAL DEBUGGING ---

        # Get values with defaults for safety
        cached_mtime = cached_device_info.get("updated", 0)
        old_hash = cached_device_info.get("hash", "no-hash-in-cache")

        # Get current file properties
        current_mtime = int(file_path.stat().st_mtime)

        # Compare. Let's add a tiny tolerance to the mtime comparison.
        if (current_mtime - cached_mtime) > 1:
            # The file is definitely newer. Now check the hash.
            new_hash = calculate_config_hash(file_path)
            if new_hash != old_hash:
                logger.info(f"Content changed for {hostname} (mtime and hash mismatch), scheduling for re-index.")
                logger.debug(f"  - Details for {hostname}:")
                logger.debug(f"  - Cached MTime: {cached_mtime}, Current MTime: {current_mtime}")
                logger.debug(f"  - Cached Hash:  {old_hash}")
                logger.debug(f"  - New Hash:     {new_hash}")
                files_to_reindex.append(file_path)
                files_reindexed_count += 1

    logger.info(f"Finished checking files. Found {files_reindexed_count} files that need re-indexing.")

    # We need a unified list of all hosts whose entries need to be cleaned
    hosts_to_clean = set(deleted_files)
    # Also clean hosts that are being re-indexed
    for file_path in files_to_reindex:
        hosts_to_clean.add(file_path.stem.upper())

    # 4. Clean all obsolete entries using the reverse index
    if hosts_to_clean:
        logger.info(f"Cleaning {len(hosts_to_clean)} obsolete/updated host entries from indexes...")

        # Step 1: Identify all IP/Keyword keys we need to modify.
        ips_to_modify = set()
        kws_to_modify = set()
        for hostname in hosts_to_clean:
            old_rev_data = rev_idx.get(hostname, {})
            ips_to_modify.update(old_rev_data.get('ips', []))
            kws_to_modify.update(old_rev_data.get('kws', []))

        logger.info(f"Identified {len(ips_to_modify)} IP keys and {len(kws_to_modify)} keyword keys to modify.")

        # Step 2: Bulk load only the necessary data into memory.
        logger.info("Loading relevant index entries into memory...")
        # Use dict comprehensions for a fast, single-pass load.
        in_memory_ip_idx = {ip_key: ip_idx.get(ip_key, {}) for ip_key in ips_to_modify}
        in_memory_kw_idx = {kw_key: kw_idx.get(kw_key, {}) for kw_key in kws_to_modify}
        logger.info("In-memory load complete.")

        # Step 3: Perform all cleanup operations on the fast in-memory dicts.
        logger.info("Performing cleanup operations in memory...")
        for hostname in hosts_to_clean:
            old_rev_data = rev_idx.get(hostname, {})  # Still need this to know what to clean

            # Clean the in-memory ip_idx
            for ip_key in old_rev_data.get('ips', []):
                if ip_key in in_memory_ip_idx and hostname in in_memory_ip_idx[ip_key]:
                    del in_memory_ip_idx[ip_key][hostname]

            # Clean the in-memory kw_idx
            for keyword in old_rev_data.get('kws', []):
                if keyword in in_memory_kw_idx and hostname in in_memory_kw_idx[keyword]:
                    del in_memory_kw_idx[keyword][hostname]
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

    # 5. Handle Additions/Updates
    logger.info(f"Index Cache - Found {len(files_to_reindex)} new or updated files. Indexing...")
    if not files_to_reindex:
        logger.info("Index Cache - No configuration changes detected.")
        cache.dc.pop("indexing", None)
        cache.dc.set("updated", int(time()))
        return

    # Create a thread-safe queue to hold results from worker threads
    # Maxsize prevents producers from running too far ahead of the consumer, acting as back-pressure.
    write_queue = queue.Queue(maxsize=1000)

    # Start the consumer thread (the cache writer)
    writer_thread = threading.Thread(
        target=cache_writer,
        args=(ctx, write_queue, cache.ip_idx, cache.kw_idx, cache.dev_idx, cache.rev_idx, len(files_to_reindex))
    )
    writer_thread.start()

    # Use the thread pool to produce data (read/parse files)
    with ThreadPoolExecutor(max_workers=4) as executor:
        # Submit all file processing tasks. They will put results on the queue.
        for filename in files_to_reindex:
            executor.submit(get_facts_helper, ctx, filename, write_queue)

    # Wait for the writer thread to finish processing all items from the queue
    writer_thread.join()

    logger.info("Disk cache update complete.")

    end = perf_counter()
    cache.dc.set("updated", int(time()))
    if cache.dc.get("version", 0) != ctx.cfg["cache_version"]:
        cache.dc.set("version", ctx.cfg["cache_version"])

    cache.dc.pop("indexing", None)
    logger.info(f"Index Cache - Update took {round(end - start, 3)} seconds")


def get_facts_helper(
    ctx: ScriptContext, filename: Path, write_queue: Optional[queue.Queue] = None
) -> Optional[Tuple[Dict[str, Any], defaultdict, defaultdict, Dict[str, Any]]]:
    """
    Function is a helper to run get_device_facts in Multithreaded fashion.
    It can either return data or put it on a queue for batch processing.
    """
    parts = filename.parts
    region = ''
    regions = ctx.cfg.get("regions", False)

    if regions and regions != '':
        vendor = str(parts[-4]).lower()
        device_type = str(parts[-3]).upper()
        region = str(parts[-2]).upper()
    else:
        vendor = str(parts[-3]).lower()
        device_type = str(parts[-2]).upper()

    hostname = filename.stem.upper()

    ctx.logger.debug(f"Index Cache - Building {hostname.upper()} index data...")
    result = get_device_facts(ctx, hostname, vendor, region, device_type, filename)

    if write_queue:
        write_queue.put(result)
        return None  # Explicitly return None when using the queue
    else:
        return result


def get_device_facts(ctx: ScriptContext, hostname: str, vendor: str, region: str, device_type: str, filename: Path) -> Tuple[Dict[str, Any], defaultdict, defaultdict, Dict[str, Any]]:

    logger = ctx.logger
    # Calculate the hash of the relevant content
    content_hash = calculate_config_hash(filename)

    device = {"region": region, "type": device_type, "vendor": vendor, "updated": int(filename.stat().st_mtime), "hash": content_hash}
    ip_list: defaultdict = defaultdict(lambda: tuple())
    kw_list: defaultdict = defaultdict(lambda: tuple())

    vendor_stop_words = stop_words.get(vendor.lower(), ())
    try:
        with open(filename, "r", encoding="utf-8") as f:
            for index, line in enumerate(f):
                line_strip = line.strip()
                if line_strip.startswith(vendor_stop_words) or HEX8_RE.match(line_strip) or B64ish_RE.match(line_strip):
                    continue

                for match in ip_regexp.finditer(line_strip):
                    s = match.group()
                    try:
                        ip = ipaddress.ip_address(s)
                        if s.startswith(("255.", "0.")) or ip.is_reserved:
                            continue
                        ip_list[(str(int(ip)), hostname)] += (index,)
                    except ValueError:
                        pass

                for word in set(extract_keywords(line_strip)) - set(standard_keywords.get(vendor, ())):
                    kw_list[(word, hostname)] += (index,)
    except (IOError, OSError) as e:
        logger.error(f"Error reading device file {filename}: {e}")

    reverse_index_data = {
            'ips': list(set(ip for ip, host in ip_list.keys())),
            'kws': list(set(kw for kw, host in kw_list.keys()))
        }

    return ({hostname: device}, ip_list, kw_list, {hostname: reverse_index_data})


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

    data = search_cache_keywords(ctx, search_terms, search_input)
    data_to_save.extend(data)

    return data_to_save, matched_nets


def search_cache_keywords(ctx: ScriptContext, search_terms: List[str], search_input: str) -> List[List[Any]]:
    """
    Performs a hybrid cached search for regex terms.
    1. Uses the keyword index (kw_idx) for a fast pre-selection of candidate lines.
    2. Performs the full, expensive regex match only on the small set of candidate lines.
    """
    logger = ctx.logger
    data_to_save: List[List[Any]] = []

    # Ensure cache is available
    if not isinstance(ctx.cache, CacheManager):
        return data_to_save

    cache = ctx.cache
    kw_idx = cache.kw_idx
    dev_idx = cache.dev_idx

    all_cache_keywords = list(kw_idx.keys())  # Get all keys for prefix matching

    if not search_terms:
        return data_to_save

    for term in search_terms:
        # Step 1: Find candidate lines using the keyword index.
        # Extract simple, indexable words from the user's regex term.
        candidate_words = extract_keywords(term)

        # This will hold all potential lines to check, keyed by hostname (UPPERCASE).
        # Using a set for line numbers prevents duplicate checks.
        candidate_lines_by_host: Dict[str, Set[int]] = defaultdict(set)

        # If the regex has no simple words (e.g., "^\s*$"), we can't use the index.
        if not candidate_words:
            logger.warning(f"Regex '{term}' contains no indexable keywords. A full scan would be needed (cached search skipped for this term).")
            continue

        for word in candidate_words:
            # Looking up all keys which start with the search term
            matching_keys = [key for key in all_cache_keywords if key.startswith(word.lower())]

            # Keys in kw_idx should be lowercase if your indexing is correct.
            for key in matching_keys:
                word_entry = kw_idx.get(key)
                if isinstance(word_entry, dict):
                    for hostname, lines in word_entry.items():
                        candidate_lines_by_host[hostname.upper()].update(lines)

        # If no candidate lines were found for any of the words, move to the next search term.
        if not candidate_lines_by_host:
            continue

        # Step 2: Perform the full regex search only on the candidate lines.
        for hostname, line_numbers in candidate_lines_by_host.items():

            device_info = dev_idx.get(hostname.upper())  # Ensure lookup is also uppercase
            if not isinstance(device_info, dict):
                continue

            fname = build_config_path(ctx, hostname, device_info.get('region', ''), device_info.get('vendor', ''), device_info.get('type', ''))
            if not fname:
                logger.warning(f"Unable to read configuration file for {hostname}. Cache entry invalid.")
                continue

            try:
                # Read the entire file into memory once per file.
                with open(fname, "r", encoding="utf-8") as f:
                    full_config_lines = f.readlines()

                # Check only the specific lines we found in the index.
                for line_num in sorted(list(line_numbers)):
                    if 0 <= line_num < len(full_config_lines):
                        line_content = full_config_lines[line_num]

                        # THE CRITICAL STEP: The expensive regex search is performed here.
                        if re.search(term, line_content, re.IGNORECASE):
                            # It's a true match, so add it to the results.
                            data_to_save.append([
                                search_input,
                                hostname.upper(),
                                line_num,
                                line_content.strip(),
                                ''  # Placeholder for filename consistency
                            ])
            except (IOError, OSError) as e:
                logger.error(f"Could not read config for {hostname}: {e}")

    return data_to_save


def search_cache_subnets(
    ctx: ScriptContext, nets: Optional[List[ipaddress.IPv4Network]], search_input: str
) -> Tuple[List[List[Any]], Set[ipaddress.IPv4Network]]:

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

    rows_to_save: Dict[str, Dict[int, str]] = defaultdict(dict)

    for net in nets:
        for ip_obj in net:
            ip_key = str(int(ip_obj))

            ip_entry = ip_idx.get(ip_key)

            if isinstance(ip_entry, dict):
                for hostname, line_nums in ip_entry.items():
                    device_info = dev_idx.get(hostname.upper(), {})
                    fname = build_config_path(ctx, hostname, device_info.get('region', ''), device_info.get('vendor', ''), device_info.get('type', ''))
                    if not fname:
                        logger.warning(f"Unable to read configuration file for {hostname}. Cache entry invalid.")
                        continue

                    try:
                        with open(fname, 'r', encoding='utf-8') as f:
                            all_lines = f.readlines()
                            if isinstance(line_nums, (list, tuple)):
                                for line_num in line_nums:
                                    try:
                                        idx = int(line_num)
                                        if 0 <= idx < len(all_lines):
                                            rows_to_save[hostname.upper()][line_num] = all_lines[line_num].strip()
                                    except (ValueError, IndexError):
                                        # Log bad line number from cache if needed
                                        pass
                    except IOError:
                        # Log file reading error if needed
                        pass
                matched_nets.add(net)

    for hostname, indices in sorted(rows_to_save.items()):
        for index, line in sorted(indices.items()):
            data_to_save.append([search_input, hostname.upper(), index, line, ""])

    return data_to_save, matched_nets
