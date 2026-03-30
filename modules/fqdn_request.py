# modules/fqdn_request.py
import re
from typing import Dict, Any, Optional

from core.base import BaseModule, ScriptContext
from utils.api import describe_infoblox_failure, request_result
from utils.auth import ensure_infoblox_auth
from utils.display import console, get_global_color_scheme, print_table_data
from utils.file_io import queue_save
from utils.infoblox_ux import format_no_match_message
from utils.process_data import process_data
from utils.user_input import press_any_key, read_user_input


class FQDNRequestModule(BaseModule):
    """
    Module to search for DNS A/AAAA records using a full FQDN or a prefix.
    """
    @property
    def menu_key(self) -> str:
        return "3"

    @property
    def menu_title(self) -> str:
        return "FQDN Prefix Lookup"

    @property
    def visibility_config_key(self) -> Optional[str]:
        # This module will only appear in the menu if 'infoblox_enabled' is True in the config.
        return "infoblox_enabled"

    def run(self, ctx: ScriptContext) -> None:
        """
        Requests user to provide an FQDN string or prefix, validates it,
        fetches and processes data, and then prints or saves it.
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - FQDN Search - DNS A/AAAA records")

        ensure_infoblox_auth(ctx)

        console.print(
            "\n"
            f"[{colors['description']}]Type in just a part of the name or a complete FQDN (not less than 3 chars).[/]\n"
            f"[{colors['description']}]This request fetches DNS records matching or containing the provided text.[/]\n"
            f"[{colors['description']}]Request has a limit of [{colors['error']} {colors['bold']}]1000[/] records.[/]\n"
            f"[{colors['header']}]Examples:[/]\n"
            f"[{colors['success']}][{colors['bold']}]'aucicbst'[/] fetches records starting with [{colors['white']} {colors['bold']}]aucicbst[/].\n"
            f"[{colors['success']}][{colors['bold']}]'aucicbstwc010'[/] fetches the specific record for the device.\n"
            f"[{colors['success']}][{colors['bold']}]'aucicbstwc010.net-equip.shell.net'[/] also fetches the specific record.[/]\n"
        )

        # --- User Input and Validation ---
        fqdn = read_user_input(
            ctx, "Enter the device name (FQDN or prefix): "
        ).lower().strip()

        logger.info(f"User input - FQDN Search for: {fqdn}")

        if len(fqdn) < 3:
            logger.info("User input - FQDN Search - Prefix is less than 3 chars")
            console.print(f"[{colors['error']}]Please use a longer prefix (at least 3 characters).[/]")
            press_any_key(ctx)
            return

        # A simple prefix is not a valid FQDN, so we just check for invalid characters.
        if not re.match(r"^[a-zA-Z0-9.-]+$", fqdn):
            logger.info(f"User input - FQDN Search - Incorrect FQDN/prefix: {fqdn}")
            console.print(f"[{colors['error']}]Input contains invalid characters.[/]")
            press_any_key(ctx)
            return

        # --- API Call and Data Processing ---
        uri = f"search?fqdn~={fqdn}&_return_fields=ipv4addr,ipv6addr,name&_max_results=1000"
        with ctx.console.status(f"[{colors['description']}]Fetching data for [{colors['header']}]{fqdn}[/]...[/]"):
            result = request_result(ctx, uri, ensure_auth=False)

        processed_data: Dict[str, Any] = {}
        if result.ok:
            processed_data = process_data(ctx, type="fqdn", content=result.content)
            processed_data = self.execute_hook('process_data', ctx, processed_data)
        elif result.failed:
            logger.info("Request Type - FQDN Search - Request failed")
            console.print(f"[{colors['error']}]{describe_infoblox_failure(result)}[/]")
            press_any_key(ctx)
            return

        if not processed_data or not processed_data.get("fqdn"):
            logger.info("Request Type - FQDN Search - No matching records found")
            console.print(f"[{colors['error']}]{format_no_match_message('DNS records', fqdn)}[/]")
            logger.debug(f"Request Type - FQDN Search - raw data: {result.content}")
            press_any_key(ctx)
            return

        # --- Display and Save Results ---
        print_table_data(ctx, processed_data, suffix={"fqdn": "Search Results"})
        logger.debug(f"Request Type - FQDN Search - processed data: {processed_data}")

        if ctx.cfg["report_auto_save"]:
            save_data_list_of_dicts = processed_data.get("fqdn", [])
            final_save_data = self.execute_hook('pre_save', ctx, save_data_list_of_dicts)

            if final_save_data:
                final_columns = list(final_save_data[0].keys())
                save_data_list_of_lists = [[row.get(col, '') for col in final_columns] for row in final_save_data]
                queue_save(ctx, final_columns, save_data_list_of_lists, sheet_name="FQDN Data", index=False, force_header=True)

        ctx.event_bus.publish(
            "stats:module_detail",
            {
                "unit_count": 1,
                "query_count": 1,
                "result_count": len(processed_data.get("fqdn", [])),
                "success_count": 1,
            },
        )

        press_any_key(ctx)
