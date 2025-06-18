import ipaddress
from time import perf_counter
from typing import Dict, Any, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor

from core.base import BaseModule, ScriptContext
from utils.user_input import read_user_input
from utils.display import console, get_global_color_scheme, print_table_data
from utils.api import do_fancy_request
from utils.file_io import queue_save
from utils.process_data import process_data


class IPRequestModule(BaseModule):
    """
    Module to fetch detailed information about one or more IP addresses from the API.
    """
    @property
    def menu_key(self) -> str:
        return "1"

    @property
    def menu_title(self) -> str:
        return "IP Information"

    @property
    def visibility_config_key(self) -> Optional[str]:
        # This module will only appear in the menu if 'infoblox_enabled' is True in the config.
        return "infoblox_enabled"

    def run(self, ctx: ScriptContext) -> None:
        """
        Requests user to provide IP address(es), validates the input, calls the API,
        processes the data, and then prints and/or saves it.
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - IP Information")

        console.print(
            "\n"
            f"[{colors['description']}]Please provide an IP address or a list of IP addresses, one per line.[/]\n"
            f"[{colors['description']}]The tool will request detailed information, such as hostname, location, and network configuration.[/]\n"
            f"[{colors['description']}]Empty input line starts the process.[/]\n"
            f"[{colors['header']}]Example:[/]\n"
            f"[{colors['success']} {colors['bold']}]134.162.104.110[/]\n"
            f"[{colors['success']} {colors['bold']}]8.8.8.8[/]\n"
        )

        # --- User Input Gathering ---
        ip_addresses_input: List[str] = []
        while True:
            search_input = read_user_input(ctx, "").strip()
            if not search_input:
                break
            try:
                ip = ipaddress.ip_address(search_input)
                if ip.is_unspecified or ip.is_reserved or ip.is_link_local:
                    console.print(f"[{colors['error']}]Invalid IP: Broadcast, unspecified, and reserved IPs are excluded.[/]")
                else:
                    ip_addresses_input.append(search_input)
            except ValueError:
                console.print(f"[{colors['error']}]Invalid IP format. Please enter a valid IPv4 or IPv6 address.[/]")

        if not ip_addresses_input:
            return

        # Remove duplicates while preserving order
        ip_addresses = list(dict.fromkeys(ip_addresses_input))
        log_value = ", ".join(ip_addresses)
        logger.info(f"User input - IPs: {log_value}")

        # --- API Call and Data Processing ---
        start = perf_counter()
        req_urls = {ip: f"ipv4address?ip_address={ip}&_return_fields=network,names,status,types,lease_state,mac_address" for ip in ip_addresses}

        with ThreadPoolExecutor() as executor, console.status(f"[{colors['description']}]Fetching IP information...[/]"):
            future_to_ip = {executor.submit(do_fancy_request, ctx, "", uri, spinner=None): ip for ip, uri in req_urls.items()}
            results = {future_to_ip[future]: future.result() for future in future_to_ip}

        processed_data_by_ip: Dict[str, Dict[str, Any]] = {}
        successful_ips: Set[str] = set()
        for ip, response in results.items():
            if response:
                # Initial processing
                data = process_data(ctx, type="ip", content=response)

                # --- HOOK: Allows plugins to modify the processed data ---
                data = self.execute_hook('process_data', ctx, data)

                if data and data.get("general"):
                    processed_data_by_ip[ip] = data
                    successful_ips.add(ip)

        end = perf_counter()
        logger.info(f"IP Information search took {round(end - start, 3)} seconds!")
        console.print(f"[{colors['description']}]Request Type - IP Information - Search took [{colors['success']}]{round(end-start, 3)}[/] seconds![/]")

        # --- Display and Save Results ---
        for ip in ip_addresses:
            if ip not in successful_ips:
                console.print(f"[{colors['success']} {colors['bold']}]{ip}[/] - [{colors['error']}]No data received[/]")

        # Prepare data for both printing and saving
        save_data_all: List[List[Any]] = []
        print_data_all: List[Dict[str, Any]] = []
        columns = ["Subnet", "IP", "Name", "Status", "Lease State", "Record Type", "MAC"]

        for ip in successful_ips:
            if ip in processed_data_by_ip:
                general_data = processed_data_by_ip[ip].get("general", [{}])[0]
                extra_data = processed_data_by_ip[ip].get("extra", [{}])[0]

                row_data_list = [
                    general_data.get("network"), general_data.get("ip"), general_data.get("name"),
                    general_data.get("status"), extra_data.get("lease state"),
                    extra_data.get("record type"), extra_data.get("mac")
                ]

                # HOOK: Allows plugins to modify data just before saving.
                # The data is a list here.
                final_save_row = self.execute_hook('pre_save', ctx, row_data_list)
                save_data_all.append(final_save_row)

                # For printing, we work with a dictionary to make it easier for plugins
                # to add new columns by name.
                row_data_dict = dict(zip(columns, row_data_list))

                # HOOK: Allows plugins to modify data just before rendering.
                # The data is a dictionary here.
                final_print_row = self.execute_hook('pre_render', ctx, row_data_dict)
                print_data_all.append(final_print_row)

        if print_data_all:
            # The print_table_data utility is designed to handle a list of dictionaries.
            # It will automatically determine the columns from the keys of the first dictionary.
            # This correctly handles cases where a plugin might have added a new column.
            print_table_data(ctx, {"IP Information": print_data_all})

        if ctx.cfg["report_auto_save"]:
            missing_ip_addresses = [ip for ip in ip_addresses if ip not in successful_ips]
            if missing_ip_addresses:
                missed_ip_data = [[ip, "No Information"] for ip in missing_ip_addresses]
                queue_save(ctx, ["IP", "Status"], missed_ip_data, sheet_name="IP Data", index=False, force_header=True)

            if save_data_all:
                # To ensure the header in the saved file is correct (especially if a plugin
                # changed the data), we should derive the final columns from the print data.
                final_columns_for_saving = list(print_data_all[0].keys()) if print_data_all else columns
                # We need to reconstruct the save_data_all list if a plugin changed the print data
                # to ensure columns and data align.
                final_save_data = [[row.get(col, '') for col in final_columns_for_saving] for row in print_data_all]

                queue_save(ctx, final_columns_for_saving, final_save_data, sheet_name="IP Data", index=False, force_header=True)
