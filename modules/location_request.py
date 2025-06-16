import re
from typing import Dict

from core.base import BaseModule, ScriptContext
from utils.user_input import read_user_input
from utils.display import console, get_global_color_scheme, print_table_data
from utils.api import fetch_network_data
from utils.file_io import queue_save
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

    def run(self, ctx: ScriptContext) -> None:
        """
        Requests user to provide a site code or keyword to find subnets.
        (Original `location_request` logic)
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - Subnet Lookup by Location/Keyword")

        console.print(
            "\n"
            f"[{colors['description']}]Type in a location site code to obtain a list of registered [{colors['bold']}]subnets[/].[/]\n"
            f"[{colors['description']}]Supported site code format: [{colors['success']} {colors['bold']}]XXX, XXXXXXX, XXX-XX\\[XX][/]\n"
            f"[{colors['description']}]Request has a limit of [{colors['error']} {colors['bold']}]1000[/] records per search.[/]\n"
            f"[{colors['header']} {colors['bold']}]Examples:[/]\n"
            f"[{colors['success']} {colors['bold']}]CIC[/] -> Fetches subnets for [{colors['warning']} {colors['bold']}]Chinchilla site[/]\n"
            f"[{colors['success']} {colors['bold']}]WND-RYD[/] -> Fetches subnets for [{colors['warning']} {colors['bold']}]Wandoan site[/]\n"
            "\n"
            f"[{colors['description']}]Alternatively, type '[{colors['error']} {colors['bold']}] + [/]' followed by a keyword to search in the description.[/]\n"
            f"[{colors['header']} {colors['bold']}]Examples:[/]\n"
            f"[{colors['error']} {colors['bold']}] +[/][{colors['success']} {colors['bold']}]PRJ18[/] -> Fetches subnets with [{colors['bold']}]PRJ18[/] in the description.[/]\n"
        )

        raw_input = read_user_input(
            ctx,
            f"Enter [{colors['success']} {colors['bold']}]location code[/] or '[{colors['error']} {colors['bold']}] + [/]'[{colors['success']} {colors['bold']}]keyword[/]: "
        ).strip()

        logger.info(f"User input - {raw_input}")

        if not raw_input:
            logger.info("User input - Empty input")
            console.print(f"[{colors['error']}]No input provided.[/]")
            return

        # --- Input Parsing and Validation ---
        search_term: str = ""
        is_keyword_search = False
        prefix: Dict[str, str] = {}
        suffix: Dict[str, str] = {}

        if raw_input.startswith("+"):
            is_keyword_search = True
            search_term = raw_input[1:].strip()
            # Basic validation for keyword
            if not re.match(r"^[a-zA-Z0-9_-]*$", search_term):
                logger.info(f"User input - Invalid keyword {search_term}")
                console.print(f"[{colors['error']}]Keyword contains invalid characters.[/]")
                return
            logger.info(f"User input - Keyword search for '{search_term}'")
        else:
            search_term = raw_input
            if not is_valid_site(search_term):
                logger.info(f"User input - Incorrect site code {search_term}")
                console.print(f"[{colors['error']}]Incorrect site code format.[/]")
                return
            prefix = {"location": search_term.upper()}
            suffix = {"location": "Subnets"}
            logger.info(f"User input - Sitecode search for '{search_term}'")

        # --- API Call and Data Processing ---
        processed_data = fetch_network_data(ctx, search_term, keyword=is_keyword_search)

        # --- HOOK: Allow plugins to modify the processed data ---
        processed_data = self.execute_hook('process_data', ctx, processed_data)

        if not processed_data.get("location"):
            logger.info("Request Type - Location/Keyword Search - No information received")
            console.print(f"[{colors['error']}]No information received for '{search_term}'.[/]")
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
