import re
import ipaddress
from pathlib import Path
from time import perf_counter
from typing import List, Dict, Set, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor

from core.base import BaseModule, ScriptContext
from utils.user_input import press_any_key, read_user_input
from utils.display import console, get_global_color_scheme, print_search_config_data, print_table_data
from utils.file_io import check_dir_accessibility, queue_save
from utils.validation import is_valid_site
from utils.config import make_dir_list
from utils.data_processing import remove_duplicate_rows_sorted_by_col
from utils.api import fetch_network_data
from utils.cache import CacheManager

# Assuming search_cache_config is a helper you'll create in a cache_helpers.py or similar
# For now, this module will handle both live and cached logic paths.
from utils.cache_helpers import search_cache_config
from wordlists.keywords import stop_words

# Module-specific regex
ip_regexp = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")


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
            f"[{colors['description']}]Check the [{colors['header']} {colors['bold']}][config_repository][/] section in your configuration file.[/]\n"
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
        MIN_INPUT_LEN = 5

        while True:
            search_input = read_user_input(ctx, "").strip()
            if search_input == "":
                break

            is_network = False
            try:
                if "/" in search_input or re.fullmatch(ip_regexp, search_input):
                    net = ipaddress.ip_network(search_input, strict=False)
                    if isinstance(net, ipaddress.IPv4Network):
                        networks.append(net)
                        validated_search_input.append(str(net))
                        is_network = True
            except (ValueError, TypeError):
                pass

            if not is_network:
                if len(search_input) < MIN_INPUT_LEN and not is_valid_site(search_input):
                    console.print(f"[{colors['error']}]Input keyword is too short: {search_input}[/]")
                    continue

                try:
                    re.compile(search_input, re.IGNORECASE)
                    keyword_regexps.append(search_input)
                    validated_search_input.append(search_input)
                except re.error as e:
                    console.print(f"[{colors['error']}]Invalid regular expression: {e}[/]")

        if not networks and not keyword_regexps:
            return

        logger.info(f"User input - {', '.join(validated_search_input)}")
        search_input_str = "\n".join(validated_search_input)

        data_to_save, matched_nets = self._execute_search(ctx, networks, keyword_regexps, search_input_str)

        if not data_to_save:
            logger.info("Configuration Repository - No matches found!")
            console.print(f"[{colors['error']}]No matches found![/]")
            press_any_key(ctx)
            return

        missing_nets = list(set(networks) - matched_nets) if networks else []
        for missed_net in missing_nets:
            net_str = str(missed_net)
            if net_str.endswith("/32"):
                net_str = net_str[:-3]
            console.print(f"[{colors['description']}]Subnet [{colors['hostname']}]{net_str}[/] - [{colors['error']}]No matches found[/]")

        sorted_data = remove_duplicate_rows_sorted_by_col(data_to_save, 2)
        print_search_config_data(ctx, sorted_data)

        if ctx.cfg["report_auto_save"]:
            self._save_found_data(ctx, data_to_save, missing_nets, matched_nets, "Config Check")

        press_any_key(ctx)

    def execute_demob_search(self, ctx: ScriptContext, sitecode: str):
        """
        Executes the search logic for a given sitecode.
        This is a public method designed to be called by other modules.

        Args:
            ctx: The script context.
            sitecode: The validated site code to search for.
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info(f"Executing demobilization search for sitecode: {sitecode}")

        # Step 1: Fetch network data from Infoblox
        processed_data = fetch_network_data(ctx, sitecode)

        if not processed_data.get("location"):
            console.print(f"[{colors['error']}]No [{colors['success']} {colors['bold']}]{sitecode}[/] subnets registered in Infoblox[/]")
            press_any_key(ctx)
            return

        print_table_data(ctx, processed_data)
        console.print(f'[{colors["description"]}]Received {len(processed_data["location"])} subnet records for [{colors["success"]} {colors["bold"]}]{sitecode}[/]')

        if read_user_input(ctx, f"[{colors['warning']}]Would you like to proceed searching configuration files (Y/N)? [/]").lower() != "y":
            return

        # Step 2: Prepare search terms from the fetched network data
        locations = processed_data["location"]
        networks: List[ipaddress.IPv4Network] = []
        country: Optional[str] = None
        for location in locations:
            try:
                net = ipaddress.ip_network(location["network"])
                if not isinstance(net, ipaddress.IPv4Network):
                    continue
                if country is None:
                    country = location.get("comment", "XX")[:2].upper()
                networks.append(net)
            except ValueError:
                logger.warning(f"Skipping invalid network from Infoblox: {location.get('network')}")

        search_terms: List[str] = []
        if country:
            pattern = rf'\b(?:{country}{re.escape(sitecode.replace("-", ""))}|{re.escape(sitecode)}[_0-9]+[-\w\d]*)\b'
        else:
            pattern = rf'\b(?:[A-Z]{{2}}{re.escape(sitecode.replace("-", ""))}|{re.escape(sitecode)}[_0-9]+[-\w\d]*)\b'
        search_terms.append(pattern)

        # Step 3: Execute the search using the internal helper
        data_to_save, matched_nets = self._execute_search(ctx, networks, search_terms, sitecode)

        if not data_to_save:
            logger.info(f"Configuration Repository - No matches for {sitecode} found!")
            console.print(f"[{colors['error']}]No matches found![/]")
            press_any_key(ctx)
            return

        # Step 4: Process and display results
        missing_nets = list(set(networks) - matched_nets)
        if missing_nets:
            for missed_net in missing_nets:
                net_str = str(missed_net)
                if net_str.endswith("/32"):
                    net_str = net_str[:-3]
                console.print(f"[{colors['description']}]Subnet [{colors['success']} {colors['bold']}]{net_str}[/] - [{colors['error']}]No matches found[/]")

        sorted_data = remove_duplicate_rows_sorted_by_col(data_to_save, 2)
        print_search_config_data(ctx, sorted_data)

        if ctx.cfg["report_auto_save"]:
            self._save_found_data(ctx, data_to_save, missing_nets, matched_nets, "Demob Site Check")

        # Commented because we await for any key in demob_check module itself
        # press_any_key(ctx)

    def _execute_search(self, ctx: ScriptContext, networks: List, search_terms: List, search_input: str) -> Tuple[List, Set]:
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
        logger.info(f"Search took {round(end - start, 3)} seconds!")
        console.print(f"[{get_global_color_scheme(ctx.cfg)['description']}]Search took [{get_global_color_scheme(ctx.cfg)['success']}]{round(end-start, 3)}[/] seconds![/]")

        return data_to_save, matched_nets

    def _search_folder_live(self, ctx: ScriptContext, folder: Path, nets: List, search_terms: List, search_input: str) -> Tuple[List, Set]:
        """Private helper containing the logic of the original `search_config` function."""
        data_to_save: List[Any] = []
        matched_nets: Set[ipaddress.IPv4Network] = set()

        try:
            dir_list = list(folder.iterdir())
        except FileNotFoundError:
            return data_to_save, matched_nets

        parts = folder.parts
        vendor = str(parts[-3]).lower() if len(parts) > 2 else ""

        with ThreadPoolExecutor() as executor:
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

        try:
            with open(filename, "r", encoding="utf-8", errors='ignore') as f:
                for index, line in enumerate(f):
                    line_strip = line.strip()
                    if line_strip.startswith(stop_words.get(vendor, ("NEVERMATCHED",))):
                        continue

                    if ip_nets:
                        found_matches = re.finditer(ip_regexp, line_strip)
                        for match in found_matches:
                            try:
                                found_ip = ipaddress.ip_address(match.group())
                                if not isinstance(found_ip, ipaddress.IPv4Address):
                                    continue
                            except (re.error, ValueError):
                                continue
                            else:
                                for net in ip_nets:
                                    if found_ip in net:
                                        matched_nets.add(net)
                                        rows_to_save[index] = line_strip
                                        break

                    if search_terms:
                        for search_term in search_terms:
                            if re.search(search_term, line_strip, re.IGNORECASE):
                                rows_to_save[index] = line_strip
                                break
        except (IOError, OSError) as e:
            logger.error(f"Error reading file {filename} for device {device}: {e}")

        if rows_to_save:
            rows = [[search_input, device, index, line, str(filename)] for index, line in sorted(rows_to_save.items())]
            data_to_save.extend(rows)

        return data_to_save, matched_nets

    def _save_found_data(self, ctx: ScriptContext, data: List, missed_nets: List, matched_nets: Set, sheet: str) -> None:
        """Private save method, containing the logic from the original `save_found_data`."""
        logger = ctx.logger
        logger.info(f"Configuration Search - Saving results to sheet: {sheet}")
        if not data:
            return

        search_input = str(data[0][0])
        if missed_nets or matched_nets:
            missed_data = [[search_input, str(net), "No match"] for net in missed_nets if net]
            matched_data = [[search_input, str(net), "Used"] for net in matched_nets if net]
            save_nets_data = missed_data + matched_data

            columns = ["Site Code", "Subnet", "Status"] if is_valid_site(search_input) else ["Search Terms", "Subnet", "Status"]
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
            device_names = {row[1].upper() for row in data}
            for device_name in device_names:
                fname = dev_idx.get(device_name, {}).get("fname")
                device_list.add((device_name, fname))
        else:
            logger.info("Saving device configs using data from direct file scan...")
            device_list = {(row[1], row[4]) for row in data}

        if len(device_list) > 50:
            logger.info(f"Too many devices ({len(device_list)}) have matches, skipping full config report update.")
            return

        logger.info(f"Saving full configs for {len(device_list)} devices.")
        for device, fname_str in device_list:
            if not fname_str:
                logger.error(f"{device} is missing full pathname information; unable to save.")
                continue
            try:
                with open(fname_str, "r", encoding="utf-8", errors='ignore') as f:
                    file_content = f.readlines()
                    queue_save(ctx, columns=None, raw_data=file_content, sheet_name=device.upper(), index=False, skip_if_exists=True)
            except (IOError, OSError) as e:
                logger.error(f"Error reading file {fname_str} for device {device}: {e}")
