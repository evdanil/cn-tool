# modules/fqdn_request.py
import re
from typing import Dict, Any

from core.base import BaseModule, ScriptContext
from utils.user_input import read_user_input
from utils.display import console, get_global_color_scheme, print_table_data
from utils.api import do_fancy_request
from utils.file_io import queue_save
from utils.process_data import process_data


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

    def run(self, ctx: ScriptContext) -> None:
        """
        Requests user to provide an FQDN string or prefix, validates it,
        fetches and processes data, and then prints or saves it.
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - FQDN Search - DNS A/AAAA records")

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
            return

        # A simple prefix is not a valid FQDN, so we just check for invalid characters.
        if not re.match(r"^[a-zA-Z0-9.-]+$", fqdn):
            logger.info(f"User input - FQDN Search - Incorrect FQDN/prefix: {fqdn}")
            console.print(f"[{colors['error']}]Input contains invalid characters.[/]")
            return

        # --- API Call and Data Processing ---
        uri = f"search?fqdn~={fqdn}&_return_fields=ipv4addr,ipv6addr,name&_max_results=1000"
        content = do_fancy_request(
            ctx,
            message=f"[{colors['description']}]Fetching data for [{colors['header']}]{fqdn}[/]...[/]",
            uri=uri,
        )

        processed_data: Dict[str, Any] = {}
        if content:
            processed_data = process_data(ctx, type="fqdn", content=content)
            processed_data = self.execute_hook('process_data', ctx, processed_data)

        if not processed_data or not processed_data.get("fqdn"):
            logger.info("Request Type - FQDN Search - No information received")
            console.print(f"[{colors['error']}]No information received for '{fqdn}'.[/]")
            logger.debug(f"Request Type - FQDN Search - raw data: {content}")
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
