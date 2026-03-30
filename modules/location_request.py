import re
from typing import Dict, Optional

from core.base import BaseModule, ScriptContext
from utils.auth import ensure_infoblox_auth
from utils.user_input import press_any_key, read_user_input
from utils.display import get_global_color_scheme, print_table_data
from utils.api import fetch_network_data
from utils.file_io import queue_save
from utils.infoblox_ux import format_no_match_message, format_partial_results_message
from utils.validation import is_valid_site


class LocationRequestModule(BaseModule):
    """
    Module to find subnets based on a location site code or an arbitrary keyword
    search within the subnet's comment/description field.
    """
    @property
    def menu_key(self) -> str:
        return "4"

    @property
    def menu_title(self) -> str:
        return "Subnet Lookup (by site code or keyword)"

    @property
    def visibility_config_key(self) -> Optional[str]:
        # This module will only appear in the menu if 'infoblox_enabled' is True in the config.
        return "infoblox_enabled"

    def run(self, ctx: ScriptContext) -> None:
        """
        Requests user to provide a site code or keyword to find subnets.
        (Original `location_request` logic)
        """
        logger = ctx.logger
        console = ctx.console
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - Subnet Lookup by Location/Keyword")

        ensure_infoblox_auth(ctx)

        console.print(
            "\n"
            f"[{colors['description']}]Search for registered subnets by [{colors['bold']}]site code[/] or [{colors['bold']}]keyword[/].[/]\n"
            f"[{colors['description']}]Supported site code format: [{colors['success']} {colors['bold']}]XXX, XXXXXXX, XXX-XX\\[XX][/]\n"
            f"[{colors['description']}]Keyword searches look in the subnet description/comment field.[/]\n"
            f"[{colors['description']}]Request has a limit of [{colors['error']} {colors['bold']}]1000[/] records per search.[/]\n"
        )

        search_mode = self._read_search_mode(ctx)
        if not search_mode:
            return

        if search_mode == "sitecode":
            raw_input = read_user_input(
                ctx,
                f"Enter [{colors['success']} {colors['bold']}]location code[/]: ",
            ).strip()
        else:
            raw_input = read_user_input(
                ctx,
                f"Enter [{colors['success']} {colors['bold']}]keyword[/] (min 3 chars): ",
            ).strip()

        logger.info(f"User input - {raw_input}")

        if not raw_input:
            logger.info("User input - Empty input")
            console.print(f"[{colors['error']}]No search value provided.[/]")
            press_any_key(ctx)
            return

        # --- Input Parsing and Validation ---
        search_term: str = ""
        is_keyword_search = search_mode == "keyword"
        prefix: Dict[str, str] = {}
        suffix: Dict[str, str] = {}

        if is_keyword_search:
            search_term = raw_input.strip()
            if len(search_term) < 3:
                logger.info(f"User input - Keyword too short {search_term}")
                console.print(f"[{colors['error']}]Keyword searches require at least 3 characters.[/]")
                press_any_key(ctx)
                return
            if not re.match(r"^[a-zA-Z0-9_-]*$", search_term):
                logger.info(f"User input - Invalid keyword {search_term}")
                console.print(f"[{colors['error']}]Keyword contains invalid characters.[/]")
                press_any_key(ctx)
                return

            logger.info(f"User input - Keyword search for '{search_term}'")
        else:
            search_term = raw_input
            if not is_valid_site(search_term):
                logger.info(f"User input - Incorrect site code {search_term}")
                console.print(f"[{colors['error']}]Incorrect site code format.[/]")
                press_any_key(ctx)
                return

            prefix = {"location": search_term.upper()}
            suffix = {"location": "Subnets"}
            logger.info(f"User input - Sitecode search for '{search_term}'")

        # --- API Call and Data Processing ---
        lookup_result = fetch_network_data(ctx, search_term, keyword=is_keyword_search, ensure_auth=False)
        processed_data = lookup_result.data

        # --- HOOK: Allow plugins to modify the processed data ---
        processed_data = self.execute_hook('process_data', ctx, processed_data)

        if lookup_result.status == "error" and not lookup_result.has_data:
            logger.info("Request Type - Location/Keyword Search - Request failed")
            console.print(f"[{colors['error']}]{lookup_result.message}[/]")
            press_any_key(ctx)
            return

        if lookup_result.status == "partial_error":
            console.print(f"[{colors['warning']}]{format_partial_results_message(lookup_result.message)}[/]")

        if not processed_data.get("location"):
            logger.info("Request Type - Location/Keyword Search - No matching records found")
            console.print(f"[{colors['error']}]{format_no_match_message('subnet records', search_term)}[/]")
            press_any_key(ctx)
            return

        # --- Display and Save Results ---
        print_table_data(ctx, processed_data, prefix=prefix, suffix=suffix)
        logger.debug(f"Request Type - Location/Keyword Search - processed data: {processed_data}")

        if ctx.cfg["report_auto_save"]:
            # The list of dictionaries is our source of truth
            results_data_list_of_dicts = processed_data.get("location", [])

            # --- HOOK: Allow plugins to modify data before saving ---
            # This hook operates on the list of dictionaries.
            final_save_data = self.execute_hook('pre_save', ctx, results_data_list_of_dicts)

            if final_save_data:
                # Dynamically determine the columns from the final data, in case
                # a plugin added a new column/key.
                final_columns = list(final_save_data[0].keys())

                # Convert the list of dictionaries to a list of lists for queue_save
                save_data_list_of_lists = [[row.get(col, '') for col in final_columns] for row in final_save_data]

                queue_save(ctx, final_columns, save_data_list_of_lists, sheet_name="Subnet Lookup", index=False, force_header=True)

        ctx.event_bus.publish(
            "stats:module_detail",
            {
                "unit_count": 1,
                "query_count": 1,
                "result_count": len(processed_data.get("location", [])),
                "success_count": 1,
                "search_mode": "keyword" if is_keyword_search else "sitecode",
            },
        )

        press_any_key(ctx)

    def _read_search_mode(self, ctx: ScriptContext) -> Optional[str]:
        colors = get_global_color_scheme(ctx.cfg)
        console = ctx.console
        console.print(
            f"[{colors['header']}]Search modes:[/]\n"
            f"[{colors['success']}]1[/]. site code\n"
            f"[{colors['success']}]2[/]. keyword (description search)"
        )
        mode = read_user_input(ctx, "Select search mode [1/2]: ").strip().lower()
        if not mode:
            return None
        if mode in {"site", "s", "1", "sitecode", "site code"}:
            return "sitecode"
        if mode in {"keyword", "k", "2"}:
            return "keyword"
        console.print(f"[{colors['error']}]Invalid search mode. Use 1 for site code or 2 for keyword.[/]")
        press_any_key(ctx)
        return None
