import re
import ipaddress
import json
import os
import stat
from dataclasses import dataclass, field
from contextlib import closing
from pathlib import Path
from time import perf_counter
from typing import List, Dict, Set, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor

from rich.markup import escape

from cn_tool.core.base import BaseModule, ScriptContext
from cn_tool.utils import oscompat
from cn_tool.utils.user_input import press_any_key, read_user_input
from cn_tool.utils.auth import ensure_infoblox_auth
from cn_tool.utils.display import console, get_global_color_scheme, print_search_config_data, print_table_data
from cn_tool.utils.file_io import check_dir_accessibility, queue_save
from cn_tool.utils.infoblox_ux import format_no_match_message, format_partial_results_message
from cn_tool.utils.network_views import NETWORK_VIEW, present_rows, view_scope
from cn_tool.utils.validation import is_valid_site, site_hostname_regex
from cn_tool.utils.config import iter_config_dirs, make_dir_list
from cn_tool.utils.process_data import remove_duplicate_rows_sorted_by_col
from cn_tool.utils.api import fetch_network_data
from cn_tool.utils.cache import CacheManager
from cn_tool.utils.cache_helpers import build_config_path, parse_repo_metadata

# Assuming search_cache_config is a helper you'll create in a cache_helpers.py or similar
# For now, this module will handle both live and cached logic paths.
from cn_tool.utils.cache_helpers import search_cache_config
from cn_tool.wordlists.keywords import stop_words

# Module-specific regex
ip_regexp = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
CONFIG_SEARCH_CACHE_UNAVAILABLE_MESSAGE = (
    "Cached configuration search is not yet available in the WebUI. "
    "Use the menu or disable the cache using your existing configuration."
)


@dataclass(frozen=True)
class ConfigSearchInputError:
    line: int
    reason: str


@dataclass
class ParsedConfigSearch:
    networks: List[ipaddress.IPv4Network]
    terms: List[str]
    search_input: str
    errors: List[ConfigSearchInputError]


def parse_search_inputs(inputs: List[str], site_pattern: Optional[str]) -> ParsedConfigSearch:
    """Parse independent lines using the configuration lookup's menu rules."""
    networks: List[ipaddress.IPv4Network] = []
    terms: List[str] = []
    accepted: List[str] = []
    errors: List[ConfigSearchInputError] = []
    for line_number, raw_input in enumerate(inputs, 1):
        value = raw_input.strip()
        if not value:
            continue
        try:
            if "/" in value or re.fullmatch(ip_regexp, value):
                network = ipaddress.ip_network(value, strict=False)
                if isinstance(network, ipaddress.IPv4Network):
                    networks.append(network)
                    accepted.append(str(network))
                    continue
        except (ValueError, TypeError):
            pass

        looks_like_site = bool(site_pattern) and is_valid_site(value, site_pattern)
        if len(value) < 5 and not looks_like_site:
            errors.append(ConfigSearchInputError(line_number, f"Input keyword is too short: {value}"))
            continue
        try:
            re.compile(value, re.IGNORECASE)
        except re.error as exc:
            errors.append(ConfigSearchInputError(line_number, f"Invalid regular expression: {exc}"))
            continue
        terms.append(value)
        accepted.append(value)
    return ParsedConfigSearch(networks, terms, "\n".join(accepted), errors)


def prepare_demob_terms(ctx: ScriptContext, sitecode: str, locations: List[Dict[str, Any]]) -> Tuple[List[ipaddress.IPv4Network], List[str]]:
    """Build the menu's network and hostname searches from Infoblox rows."""
    networks: List[ipaddress.IPv4Network] = []
    country: Optional[str] = None
    for location in locations:
        try:
            network = ipaddress.ip_network(location["network"])
            if not isinstance(network, ipaddress.IPv4Network):
                continue
            if country is None:
                country = location.get("comment", "XX")[:2].upper()
            networks.append(network)
        except ValueError:
            ctx.logger.warning(f"Skipping invalid network from Infoblox: {location.get('network')}")
    networks = list(dict.fromkeys(networks))
    return networks, [site_hostname_regex(sitecode, ctx.cfg.get("site_hostname_pattern"), country)]


@dataclass(frozen=True)
class BoundedSearchLimits:
    max_entries: int = 10000
    max_work_bytes: int = 8 * 1024 * 1024
    max_rows: int = 10000
    max_result_bytes: int = 8 * 1024 * 1024
    max_line_bytes: int = 16 * 1024


@dataclass
class BoundedSearchResult:
    rows: List[List[Any]]
    matched_nets: Set[ipaddress.IPv4Network]
    status: str
    message: str = ""
    source_identities: Dict[str, Tuple[Any, ...]] = field(default_factory=dict)


class _SearchLimit(Exception):
    pass


def config_search_mode(ctx: ScriptContext) -> str:
    """Make the menu's cache decision without falling back on a cache error."""
    try:
        if not ctx.cache or not isinstance(ctx.cache, CacheManager) or ctx.cache.dc.get("indexing", False):
            return "live"
        return "cached_unavailable"
    except Exception:
        return "unavailable"


def _match_config_line(line: str, vendor_stop_list: tuple, networks: List, terms: List[str]) -> Tuple[bool, Set]:
    """Apply the menu's IP and stop-word-aware keyword rules to one line."""
    matched: Set[ipaddress.IPv4Network] = set()
    for match in re.finditer(ip_regexp, line) if networks else ():
        try:
            address = ipaddress.ip_address(match.group())
        except (re.error, ValueError):
            continue
        if isinstance(address, ipaddress.IPv4Address):
            for network in networks:
                if address in network:
                    matched.add(network)
                    break
    term_match = not line.startswith(vendor_stop_list) and any(
        re.search(term, line, re.IGNORECASE) for term in terms
    )
    return bool(matched) or term_match, matched


def _bounded_lines(stream, max_bytes, digest=None):
    """Read UTF-8 lines with universal newlines and bounded raw byte buffers."""
    line = bytearray()
    after_cr = False
    while True:
        chunk = stream.read(4096)
        if not chunk:
            break
        if digest is not None:
            digest.update(chunk)
        for byte in chunk:
            if after_cr:
                after_cr = False
                if byte == 10:
                    continue
            if byte in (10, 13):
                yield bytes(line).decode("utf-8", errors="ignore")
                line.clear()
                after_cr = byte == 13
            else:
                if len(line) >= max_bytes:
                    raise _SearchLimit
                line.append(byte)
    if line:
        yield bytes(line).decode("utf-8", errors="ignore")


def _file_identity(info):
    # Windows 3.14 can report different ctime values for stat and fstat.
    # Birth time is stable between those interfaces; older Python uses ctime.
    changed = getattr(info, "st_birthtime_ns", info.st_ctime_ns) if oscompat.is_windows() else info.st_ctime_ns
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, changed)


def search_live_bounded(ctx: ScriptContext, networks: List, search_terms: List[str], search_input: str,
                        *, limits: Optional[BoundedSearchLimits] = None) -> BoundedSearchResult:
    """Search live files with bounded storage; run regex only in a killable child."""
    import hashlib
    limits = limits or BoundedSearchLimits()
    entries = work_bytes = 0
    result_bytes = 2  # JSON array brackets
    rows: List[List[Any]] = []
    matched_nets: Set[ipaddress.IPv4Network] = set()
    source_identities: Dict[str, Tuple[Any, ...]] = {}
    excluded = {str(item).strip().lower() for item in ctx.cfg.get("config_repo_excluded_dirs", []) if str(item).strip()}
    history = str(ctx.cfg.get("config_repo_history_dir", "history")).strip().lower()
    if history:
        excluded.add(history)
    vendors = {str(item).strip().lower() for item in ctx.cfg.get("config_repo_vendors", []) if str(item).strip()}
    regions = {str(item).strip().lower() for item in ctx.cfg.get("config_repo_regions", []) if str(item).strip()}

    def confined(path, *, strict=True, scope=None):
        resolved = Path(path).resolve(strict=strict)
        try:
            relative = resolved.relative_to(repo_root)
        except ValueError as exc:
            raise OSError("Configuration source is outside the repository") from exc
        parts = relative.parts
        if not parts or parts[0].lower() not in vendors:
            raise OSError("Configuration source is outside the selected vendors")
        directories = parts if resolved.is_dir() else parts[:-1]
        if any(part.lower() in excluded for part in directories[1:]):
            raise OSError("Configuration source is in an excluded directory")
        if regions and len(parts) >= 3 and parts[2].lower() not in regions:
            raise OSError("Configuration source is outside the selected regions")
        minimum = (3 if regions else 2) + (scope == "file")
        if scope is not None and len(parts) < minimum:
            raise OSError("Configuration source is outside the selected directory scope")
        return resolved

    def count_entry(path):
        nonlocal entries, work_bytes
        entries += 1
        work_bytes += len(os.fsencode(path))
        if entries > limits.max_entries or work_bytes > limits.max_work_bytes:
            raise _SearchLimit
        # Discovery counts excluded directories before skipping them.
        if Path(path).name.lower() not in excluded:
            confined(path, strict=False)

    def scan_paths(path, *, scope=None):
        # POSIX scandir accepts a directory descriptor. Verify the opened
        # directory before enumeration so a replaced path cannot be listed.
        resolved = confined(path, scope=scope)
        before = path.stat()
        expected = _file_identity(before)
        if not stat.S_ISDIR(before.st_mode) or not expected[0] or not expected[1]:
            raise OSError("Directory identity unavailable")
        if oscompat.is_windows():
            # Windows scandir is path-based. These checks detect observed
            # changes, but cannot make enumeration an atomic snapshot.
            with os.scandir(path) as entries:
                if confined(path, scope=scope) != resolved or _file_identity(path.stat()) != expected:
                    raise OSError("Directory changed")
                for entry in entries:
                    yield path / entry.name
        else:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(path, flags)
            try:
                if (_file_identity(os.fstat(descriptor)) != expected or
                        confined(path, scope=scope) != resolved or
                        _file_identity(resolved.stat()) != expected):
                    raise OSError("Directory changed")
                with os.scandir(descriptor) as entries:
                    for entry in entries:
                        yield path / entry.name
            finally:
                os.close(descriptor)
        if confined(path, scope=scope) != resolved or _file_identity(path.stat()) != expected:
            raise OSError("Directory changed")

    try:
        repo_root = Path(ctx.cfg["config_repo_directory"]).resolve(strict=True)
        with closing(iter_config_dirs(ctx, on_entry=count_entry, strict=True, strict_scan=scan_paths)) as folders:
            for folder in folders:
                with closing(scan_paths(folder, scope="folder")) as file_entries:
                    for filename in file_entries:
                        count_entry(filename)
                        # These directory trees are not searched, but still consume budget.
                        # Do not skip symlinks: aliases must pass containment checks.
                        if filename.name.lower() in excluded:
                            info = filename.lstat()
                            # Windows junctions and other reparse points are aliases too.
                            reparse = getattr(info, "st_file_attributes", 0) & getattr(
                                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
                            )
                            if stat.S_ISDIR(info.st_mode) and not reparse:
                                continue
                        resolved = confined(filename)
                        before = filename.stat()
                        if _file_identity(before) != _file_identity(resolved.stat()):
                            raise OSError("File changed")
                        if not stat.S_ISREG(before.st_mode):
                            continue
                        if confined(filename, scope="file") != resolved:
                            raise OSError("File changed")
                        if not _file_identity(before)[1]:
                            raise OSError("File identifier unavailable")
                        meta = parse_repo_metadata(ctx, filename)
                        vendor = meta[0] if meta else str(folder.relative_to(ctx.cfg["config_repo_directory"]).parts[0]).lower()
                        stop_list = stop_words.get(vendor, ("NEVERMATCHED",))
                        first_row = len(rows)
                        digest = hashlib.sha256()
                        with open(filename, "rb") as stream:
                            if (_file_identity(before) != _file_identity(os.fstat(stream.fileno())) or
                                    confined(filename, scope="file") != resolved or
                                    _file_identity(before) != _file_identity(resolved.stat())):
                                raise OSError("File changed")
                            for index, raw_line in enumerate(_bounded_lines(stream, limits.max_line_bytes, digest)):
                                line = raw_line.strip()
                                hit, matched = _match_config_line(line, stop_list, networks, search_terms)
                                matched_nets.update(matched)
                                if hit:
                                    row = [search_input, filename.stem.upper(), index, line, str(filename)]
                                    size = len(json.dumps(row, ensure_ascii=False).encode("utf-8")) + bool(rows)
                                    if len(rows) >= limits.max_rows or result_bytes + size > limits.max_result_bytes:
                                        raise _SearchLimit
                                    rows.append(row)
                                    result_bytes += size
                            if _file_identity(before) != _file_identity(os.fstat(stream.fileno())):
                                raise OSError("File changed")
                        if (confined(filename, scope="file") != resolved or
                                _file_identity(before) != _file_identity(filename.stat()) or
                                _file_identity(before) != _file_identity(resolved.stat())):
                            raise OSError("File changed")
                        if len(rows) > first_row:
                            identity = (str(resolved), *_file_identity(before), digest.hexdigest())
                            identity_size = len(json.dumps([str(filename), *identity], ensure_ascii=False).encode("utf-8")) + 64
                            if result_bytes + identity_size > limits.max_result_bytes:
                                raise _SearchLimit
                            result_bytes += identity_size
                            source_identities[str(filename)] = identity
    except _SearchLimit:
        return BoundedSearchResult([], set(), "limit", "Search exceeded its limits. Narrow the search.")
    except (OSError, UnicodeError, RuntimeError):
        return BoundedSearchResult([], set(), "incomplete", "A configuration file or directory could not be read or changed during the search.")
    return BoundedSearchResult(rows, matched_nets, "complete", source_identities=source_identities)


class ConfigSearchModule(BaseModule):
    """
    Module for searching through device configuration files.
    Handles both generic keyword/subnet searches and specialized
    site demobilization checks.
    """
    # This flag tells the main loop that this module needs the config repo to function.
    requires_config_repo = True

    @property
    def menu_key(self) -> str:
        return "5"

    @property
    def menu_title(self) -> str:
        return "Configuration Lookup (by subnet or keyword)"

    @property
    def visibility_config_key(self) -> Optional[str]:
        return "config_repo_enabled"

    def _show_help(self, ctx: ScriptContext):
        """Private helper to display help if the config repo is missing."""
        colors = get_global_color_scheme(ctx.cfg)
        ctx.console.print(
            "\n"
            f"[{colors['warning']}]Unable to access configuration repository[/]\n"
            f"[{colors['description']}]Check the [{colors['header']} {colors['bold']}]{escape('[config_repo]')}[/] section in your configuration file.[/]\n"
            f"[{colors['description']}]Verify that [{colors['success']} {colors['bold']}]directory[/] is set to the correct path.[/]\n"
            f"[{colors['description']}]If the path is correct, verify that you have read access to it.[/]\n"
        )

    def run(self, ctx: ScriptContext) -> None:
        """
        Main entry point for the generic configuration search feature.
        (Original `search_config_request` logic)
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)

        # --- Pre-flight check ---
        if not check_dir_accessibility(ctx.logger, ctx.cfg.get("config_repo_directory", '')):
            self._show_help(ctx)
            return

        logger.info("Configuration Repository - Search Request")

        console.print(
            f"\n[{colors['description']}]Enter subnet([{colors['code']}]IP_ADDRESS/[MASK][/]) or keyword(regular expression), one item per line[/]\n"
            f"[{colors['description']}]Empty input line starts the process[/]\n"
            "\n"
            f"[{colors['header']}]Subnet Examples:[/]\n"
            f"[{colors['success']} {colors['bold']}]10.10.10.0/24[/]\n"
            f"[{colors['success']} {colors['bold']}]134.143.169.176/29[/]\n"
            f"[{colors['header']}]Keywords Regex Examples:[/]\n"
            f"[{colors['success']} {colors['bold']}]router bgp 655\\d+$[/]\n"
            f"[{colors['success']} {colors['bold']}]neighbor \\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}} description VOCUS\\s+[/]\n"
        )

        keyword_regexps: List[str] = []
        networks: List[ipaddress.IPv4Network] = []
        validated_search_input: List[str] = []
        while True:
            search_input = read_user_input(ctx, "").strip()
            if search_input == "":
                break

            parsed = parse_search_inputs([search_input], ctx.cfg.get("site_code_pattern"))
            for error in parsed.errors:
                console.print(f"[{colors['error']}]{error.reason}[/]")
            networks.extend(parsed.networks)
            keyword_regexps.extend(parsed.terms)
            if parsed.networks or parsed.terms:
                validated_search_input.append(parsed.search_input)

        if not networks and not keyword_regexps:
            return

        logger.info(f"User input - {', '.join(validated_search_input)}")
        search_input_str = "\n".join(validated_search_input)

        total_start_time = perf_counter()

        # Allow plugins early access to parsed input
        pre_run_data: Dict[str, Any] = {
            "networks": networks,
            "terms": keyword_regexps,
            "search_input": search_input_str,
        }
        pre_run_result: Dict[str, Any] = self.execute_hook("pre_run", ctx, pre_run_data)
        networks = pre_run_result.get("networks", networks)
        keyword_regexps = pre_run_result.get("terms", keyword_regexps)
        search_input_str = pre_run_result.get("search_input", search_input_str)

        data_to_save, matched_nets, core_search_time = self._execute_search(ctx, networks, keyword_regexps, search_input_str)
        logger.info(f"Core search took {core_search_time} seconds!")

        processed: Dict[str, Any] = self.execute_hook(
            "process_data",
            ctx,
            {
                "results": data_to_save,
                "matched_nets": matched_nets,
                "networks": networks,
                "search_terms": keyword_regexps,
                "search_input": search_input_str,
            },
        )
        data_to_save = processed.get("results", data_to_save)
        matched_nets = processed.get("matched_nets", matched_nets)

        total_end_time = perf_counter()
        total_duration = round(total_end_time - total_start_time, 3)
        logger.info(f"Total search (core + plugins) took {total_duration} seconds!")
        console.print(f"[{get_global_color_scheme(ctx.cfg)['description']}]Search took [{get_global_color_scheme(ctx.cfg)['success']}]{total_duration}[/] seconds![/]")        

        if not data_to_save:
            logger.info("Configuration Repository - No matches found!")
            console.print(f"[{colors['error']}]No matches found![/]")
            press_any_key(ctx)
            return

        missing_nets = list(set(networks) - set(matched_nets)) if networks else []

        for missed_net in missing_nets:
            net_str = str(missed_net)
            if net_str.endswith("/32"):
                net_str = net_str[:-3]
            console.print(f"[{colors['description']}]Subnet [{colors['hostname']}]{net_str}[/] - [{colors['error']}]No matches found[/]")

        sorted_data = remove_duplicate_rows_sorted_by_col(data_to_save, 2)
        print_search_config_data(ctx, sorted_data)

        if ctx.cfg["report_auto_save"]:
            self._save_found_data(ctx, data_to_save, missing_nets, matched_nets, "Config Check", site_search=False)

        ctx.event_bus.publish(
            "stats:module_detail",
            {
                "unit_count": max(1, len(validated_search_input)),
                "query_count": len(validated_search_input),
                "network_count": len(networks),
                "term_count": len(keyword_regexps),
                "match_count": len(sorted_data),
                "matched_subnet_count": len(matched_nets),
                "miss_count": len(missing_nets),
                "search_mode": "generic",
            },
        )

        press_any_key(ctx)

    def execute_demob_search(self, ctx: ScriptContext, sitecode: str, ensure_auth: bool = True):
        """
        Executes the search logic for a given sitecode.
        This is a public method designed to be called by other modules.

        The subnets come from ``fetch_network_data`` with the configured network view (``[api]
        network_view``; every view when it is unset), so a subnet that exists in several views is one
        row per view in the table. Each CIDR is searched in the configurations once.

        Args:
            ctx: The script context.
            sitecode: The validated site code to search for.
        """
        logger = ctx.logger
        console = ctx.console
        colors = get_global_color_scheme(ctx.cfg)
        normalized_sitecode = str(sitecode or "").strip().upper()
        if not is_valid_site(normalized_sitecode, ctx.cfg.get("site_code_pattern")):
            logger.info(f"Executing demobilization search rejected invalid sitecode: {sitecode}")
            console.print(f"[{colors['error']}]Invalid site code format.[/]")
            press_any_key(ctx)
            return

        sitecode = normalized_sitecode
        logger.info(f"Executing demobilization search for sitecode: {sitecode}")

        if ensure_auth:
            ensure_infoblox_auth(ctx)

        # Step 1: Fetch network data from Infoblox (the configured network view applies)
        scope = view_scope(ctx)
        lookup_result = fetch_network_data(ctx, sitecode, ensure_auth=False)
        processed_data = lookup_result.data

        if lookup_result.status == "error" and not lookup_result.has_data:
            console.print(f"[{colors['error']}]{escape(lookup_result.message)}[/]")  # may name "[site]"
            press_any_key(ctx)
            return

        if lookup_result.status == "partial_error":
            console.print(f"[{colors['warning']}]{escape(format_partial_results_message(lookup_result.message))}[/]")  # may name the account

        for notice in lookup_result.notices:
            console.print(f"[{colors['warning']}]{escape(notice)}[/]")

        if not processed_data.get("location"):
            console.print(f"[{colors['error']}]{escape(scope.scoped(format_no_match_message('subnet records', sitecode)))}[/]")
            press_any_key(ctx)
            return

        view_labels = [row.get(NETWORK_VIEW) for row in processed_data["location"]]
        shown_rows = present_rows(processed_data["location"], NETWORK_VIEW, scope.column(view_labels), fallback=scope.requested)
        print_table_data(ctx, {**processed_data, "location": shown_rows})
        console.print(f'[{colors["description"]}]Received {len(processed_data["location"])} subnet records for [{colors["success"]} {colors["bold"]}]{sitecode}[/]')

        if read_user_input(ctx, f"[{colors['warning']}]Proceed with configuration search for this site code (Y/N)? [/]").lower() != "y":
            return

        if not check_dir_accessibility(ctx.logger, ctx.cfg.get("config_repo_directory", '')):
            self._show_help(ctx)
            press_any_key(ctx)
            return

        # Step 2: Prepare search terms from the fetched network data
        networks, search_terms = prepare_demob_terms(ctx, sitecode, processed_data["location"])

        # Step 3: Execute the search using the internal helper
        data_to_save, matched_nets, core_search_time = self._execute_search(
            ctx, networks, search_terms, sitecode
        )
        logger.info(f"Demob core search took {core_search_time} seconds!")

        if not data_to_save:
            logger.info(f"Configuration Repository - No matches for {sitecode} found!")
            console.print(f"[{colors['error']}]No matching configuration entries found for site code [{colors['success']} {colors['bold']}]{sitecode}[/].[/]")
            press_any_key(ctx)
            return

        # Step 4: Process and display results
        missing_nets = list(set(networks) - set(matched_nets))
        if missing_nets:
            for missed_net in missing_nets:
                net_str = str(missed_net)
                if net_str.endswith("/32"):
                    net_str = net_str[:-3]
                console.print(f"[{colors['description']}]Subnet [{colors['success']} {colors['bold']}]{net_str}[/] - [{colors['error']}]No configuration matches found[/]")

        sorted_data = remove_duplicate_rows_sorted_by_col(data_to_save, 2)
        print_search_config_data(ctx, sorted_data)

        if ctx.cfg["report_auto_save"]:
            self._save_found_data(ctx, data_to_save, missing_nets, matched_nets, "Demob Site Check", site_search=True)

        ctx.event_bus.publish(
            "stats:module_detail",
            {
                "unit_count": 1,
                "query_count": 1,
                "network_count": len(networks),
                "match_count": len(sorted_data),
                "matched_subnet_count": len(matched_nets),
                "miss_count": len(missing_nets),
                "search_mode": "demob",
            },
        )

        press_any_key(ctx)

    def _execute_search(self, ctx: ScriptContext, networks: List, search_terms: List, search_input: str) -> Tuple[List, Set, float]:
        """A centralized method to run the search via cache or live scan."""
        logger = ctx.logger
        start = perf_counter()
        data_to_save: List[List[Any]] = []
        matched_nets: Set[ipaddress.IPv4Network] = set()

        if not ctx.cache or not isinstance(ctx.cache, CacheManager) or ctx.cache.dc.get("indexing", False):
            logger.info("Performing live file system search...")
            for folder in make_dir_list(ctx):
                lines, nets = self._search_folder_live(ctx, folder, networks, search_terms, search_input)
                data_to_save.extend(lines)
                matched_nets.update(nets)
        else:
            logger.info("Performing cached search...")
            with console.status(f"[{get_global_color_scheme(ctx.cfg)['description']}]Searching through configurations...[/]", spinner="dots12"):
                data_to_save, matched_nets = search_cache_config(ctx, "", networks, search_terms, search_input)

        end = perf_counter()
        duration = round(end - start, 3)

        return data_to_save, matched_nets, duration

    def _search_folder_live(self, ctx: ScriptContext, folder: Path, nets: List, search_terms: List, search_input: str) -> Tuple[List, Set]:
        """Private helper containing the logic of the original `search_config` function."""
        colors = get_global_color_scheme(ctx.cfg)
        data_to_save: List[Any] = []
        matched_nets: Set[ipaddress.IPv4Network] = set()

        try:
            dir_list = list(folder.iterdir())
        except FileNotFoundError:
            return data_to_save, matched_nets

        # Derive vendor/type/region by anchoring on the repo base (parts[0..]),
        # the same way the cache indexer does (parse_repo_metadata). Negative
        # indexing off the absolute folder path (parts[-4]) depended on
        # filesystem depth and mis-derived vendor (often the base-dir name),
        # silently disabling stop-word filtering and diverging from cached
        # search. This label is for display/fallback; per-file vendor is
        # resolved authoritatively in _matched_lines via parse_repo_metadata.
        vendor, device_type = 'vendor', 'type'
        base_dir = ctx.cfg.get("config_repo_directory")
        regions = bool(ctx.cfg.get("config_repo_regions", []))
        try:
            rel_parts = folder.relative_to(base_dir).parts if base_dir else ()
        except ValueError:
            rel_parts = ()
        if len(rel_parts) >= (3 if regions else 2):
            vendor = str(rel_parts[0]).lower()
            device_type = str(rel_parts[1]).upper()
        else:
            ctx.logger.warning('Repository has non-expected directory path(missing vendor/type/region)')

        with ThreadPoolExecutor() as executor, console.status(f"[{colors['description']}]Searching through [{colors['type']}]{vendor.upper()}/{device_type}[/] configurations...[/]"):
            futures = [
                executor.submit(self._matched_lines, ctx, device, vendor, nets, search_terms, search_input)
                for device in dir_list if device.is_file()
            ]
            for future in futures:
                lines, subnets = future.result()
                if lines:
                    data_to_save.extend(lines)
                if subnets:
                    matched_nets.update(subnets)

        return data_to_save, matched_nets

    def _matched_lines(self, ctx: ScriptContext, filename: Path, vendor: str, ip_nets: Optional[List], search_terms: List, search_input: str) -> Tuple[List, Set]:
        """Private worker method, containing the logic from the original `matched_lines`."""
        logger = ctx.logger
        data_to_save: List[List[Any]] = []
        matched_nets: Set[ipaddress.IPv4Network] = set()

        rows_to_save: Dict[int, str] = {}
        device = filename.stem.upper()

        # Resolve vendor via the same helper the cache indexer uses so live
        # and cached searches classify the device identically (parity on
        # stop-word filtering). Fall back to the caller-supplied vendor for
        # off-layout files the helper cannot classify.
        meta = parse_repo_metadata(ctx, filename)
        resolved_vendor = meta[0] if meta else str(vendor).lower()
        vendor_stop_list = stop_words.get(resolved_vendor, ("NEVERMATCHED",))

        try:
            with open(filename, "r", encoding="utf-8", errors='ignore') as f:
                for index, line in enumerate(f):
                    line_strip = line.strip()

                    hit, line_nets = _match_config_line(line_strip, vendor_stop_list, ip_nets, search_terms)
                    matched_nets.update(line_nets)
                    if hit:
                        rows_to_save[index] = line_strip
        except (IOError, OSError) as e:
            logger.error(f"Error reading file {filename} for device {device}: {e}")

        if rows_to_save:
            rows = [[search_input, device, index, line, str(filename)] for index, line in sorted(rows_to_save.items())]
            data_to_save.extend(rows)

        return data_to_save, matched_nets

    def _save_found_data(
        self,
        ctx: ScriptContext,
        data: List,
        missed_nets: List,
        matched_nets: Set,
        sheet: str,
        *,
        site_search: bool = False,
    ) -> None:
        """Private save method, containing the logic from the original `save_found_data`.

        ``site_search`` names the subnet sheet's first column "Site Code" (demob searches)
        instead of "Search Terms"; it is decided by the caller, not by the input's shape.
        """
        logger = ctx.logger
        logger.info(f"Configuration Search - Saving results to sheet: {sheet}")
        if not data:
            return

        search_input = str(data[0][0])
        if missed_nets or matched_nets:
            missed_data = [[search_input, str(net), "No match"] for net in missed_nets if net]
            matched_data = [[search_input, str(net), "Used"] for net in matched_nets if net]
            save_nets_data = missed_data + matched_data

            columns = ["Site Code", "Subnet", "Status"] if site_search else ["Search Terms", "Subnet", "Status"]
            if save_nets_data:
                queue_save(ctx, columns, save_nets_data, sheet_name=sheet, index=False, force_header=True)

        columns_check = ["Search Terms", "Device", "Line number", "Line"]
        sorted_data = [[search_input, row[1], f'=HYPERLINK("#\'{row[1]}\'!A{int(row[2]) + 1}", {row[2]})', row[3]] for row in data]
        queue_save(ctx, columns_check, sorted_data, sheet_name=sheet, index=False, force_header=True)

        # --- Device Config Saving Logic ---
        device_list: Set[Tuple[str, Optional[str]]] = set()
        is_cached_run = ctx.cache and isinstance(ctx.cache, CacheManager)

        if is_cached_run:
            logger.info("Saving device configs using data from cache index...")

            if ctx.cache is None:
                return

            dev_idx = ctx.cache.dev_idx
            device_names = {(row[1], row[4])for row in data}

            for device_name, filename in device_names:
                if filename != '' and Path(filename).exists():
                    device_list.add((device_name, filename))
                else:
                    device_info = dev_idx.get(device_name, {})
                    fname = build_config_path(ctx, device_name, device_info.get('region', ''), device_info.get('vendor', ''), device_info.get('type', ''))
                    if fname:
                        device_list.add((device_name, fname))
        else:
            logger.info("Saving device configs using data from direct file scan...")
            device_list = {(row[1], row[4]) for row in data}

        if len(device_list) > 50:
            logger.info(f"Too many devices ({len(device_list)}) have matches, skipping full config report update.")
            return

        max_config_tab_kb = int(ctx.cfg.get("report_max_config_tab_kb", 512) or 512)
        max_config_tab_bytes = max(1, max_config_tab_kb) * 1024

        logger.info(f"Saving full configs for {len(device_list)} devices.")
        for device, filename in device_list:
            if not filename:
                logger.error(f"{device} is missing full pathname information; unable to save.")
                continue
            file_path = Path(filename)
            try:
                file_size = file_path.stat().st_size
                if file_size > max_config_tab_bytes:
                    message = (
                        f"Config omitted: size {round(file_size / 1024, 1)} KB exceeds "
                        f"limit {max_config_tab_kb} KB. Adjust [report] max_config_tab_kb to include."
                    )
                    logger.info(f"{device}: {message}")
                    queue_save(
                        ctx,
                        columns=["Notice"],
                        raw_data=[[message]],
                        sheet_name=device.upper(),
                        index=False,
                        skip_if_exists=True,
                        force_header=True,
                    )
                    continue

                with open(file_path, "r", encoding="utf-8", errors='ignore') as f:
                    file_content = f.readlines()
                    queue_save(ctx, columns=None, raw_data=file_content, sheet_name=device.upper(), index=False, skip_if_exists=True)
            except (IOError, OSError) as e:
                logger.error(f"Error reading file {filename} for device {device}: {e}")
