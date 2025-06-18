# subnet_request_module.py

import ipaddress
from time import perf_counter
import time
from typing import Any, Optional, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Assuming these are your project's utility modules
from core.base import BaseModule, ScriptContext
from utils.user_input import read_user_input, read_single_keypress
from utils.display import get_global_color_scheme, print_table_data
from utils.api import do_fancy_request, make_api_call
from utils.file_io import queue_save
from utils.process_data import process_data

# Type alias for clarity
NetworkObject = Union[ipaddress.IPv4Network, ipaddress.IPv4Address]
RowDict = dict[str, Any]


class SubnetRequestModule(BaseModule):
    """
    Module to fetch detailed information for one or more subnets from an API.
    It accepts input as plain IPs, CIDR notation (e.g., 1.2.3.0/24), or
    IP/subnet mask (e.g., 1.2.3.0/255.255.255.0).
    """
    @property
    def menu_key(self) -> str:
        return "2"

    @property
    def menu_title(self) -> str:
        return "Subnet Information"

    @property
    def visibility_config_key(self) -> Optional[str]:
        # This module will only appear in the menu if 'infoblox_enabled' is True in the config.
        return "infoblox_enabled"

    def run(self, ctx: ScriptContext) -> None:
        """
        Main execution flow for the module.
        Orchestrates user input, data fetching, processing, and display.
        """
        # It's also good practice to check at the start of the run method.
        if not ctx.cfg.get("infoblox_enabled"):
            ctx.console.print("[red]Infoblox feature is disabled. Please configure the API endpoint.[/red]")
            time.sleep(1)
            return

        self.execute_hook('pre_run', ctx, None)
        try:
            logger = ctx.logger
            console = ctx.console
            colors = get_global_color_scheme(ctx.cfg)
            logger.info("Request Type - Subnet Information")

            # --- 1. Get User Input ---
            user_inputs = self._get_networks_from_user(ctx)
            if not user_inputs:
                return

            logger.info(f"User provided inputs: {', '.join(user_inputs)}")
            start = perf_counter()

            # --- 2. Resolve all inputs into a definitive list of subnets to query ---
            all_nets_to_query = self._resolve_inputs_to_subnets(ctx, user_inputs)
            if not all_nets_to_query:
                console.print(f"[{colors['error']}]Could not resolve any of the provided inputs to a valid subnet.[{colors['error']}]")
                return

            # --- 3. Main Data Fetching and Processing Loop ---
            all_processed_data: dict[str, dict[str, Any]] = {}
            data_to_save: dict[str, list[RowDict]] = defaultdict(list)

            with ThreadPoolExecutor(max_workers=ctx.cfg.get("max_threads", 10)) as executor:
                # Create a future for each network to fetch its data
                future_to_net = {
                    executor.submit(self._fetch_and_process_subnet_data, ctx, network): network
                    for network in all_nets_to_query
                }

                for future in as_completed(future_to_net):
                    network = future_to_net[future]
                    net_str = str(network)
                    console.print(f"[{colors['description']}]Processing results for [{colors['header']}]{net_str}[/]...[/]")

                    processed_data, save_data = future.result()

                    if processed_data:
                        all_processed_data[net_str] = processed_data
                    if save_data:
                        data_to_save[net_str] = save_data

            end = perf_counter()
            duration = round(end - start, 3)
            logger.info(f"Subnet Information search took {duration} seconds!")
            console.print(f"\n[{colors['description']}]Search took [{colors['success']}]{duration}[/] seconds![/]\n")

            # --- 4. Display and Save ---
            self._display_results(ctx, all_nets_to_query, all_processed_data)

            if ctx.cfg["report_auto_save"] and data_to_save:
                self._save_subnet_data(ctx, all_nets_to_query, data_to_save)
        finally:
            # Execute post_run hook for cleanup, guaranteed to run
            self.execute_hook('post_run', ctx, None)

    def _get_networks_from_user(self, ctx: ScriptContext) -> list[str]:
        """
        Prompts the user to enter network addresses one per line.

        Returns:
            A list of unique, non-empty input strings from the user.
        """
        colors = get_global_color_scheme(ctx.cfg)
        ctx.console.print(
            "\n" f"[{colors['description']}]Enter network addresses and press Enter twice to start.[/]\n"
            f"[{colors['description']}]Formats: '1.2.3.0/24', '1.2.3.0/255.255.255.0', or just '1.2.3.4'[/]\n"
        )

        inputs = []
        while True:
            # Assuming read_user_input handles the prompt display
            search_input = read_user_input(ctx, "").strip()
            if not search_input:
                break
            inputs.append(search_input)

        return list(dict.fromkeys(inputs))  # Return unique inputs

    def _resolve_inputs_to_subnets(self, ctx: ScriptContext, inputs: list[str]) -> list[ipaddress.IPv4Network]:
        """
        Takes raw user input strings and resolves them into a list of IPv4Network objects.
        - Handles plain IPs by finding their containing subnet.
        - Handles CIDRs by validating them.
        - Handles larger "supernets" by finding all subnets they contain.
        """
        resolved_nets = set()
        tasks = []

        with ctx.console.status(f"[{get_global_color_scheme(ctx.cfg)['description']}]Resolving inputs and finding subnets...[/]"):
            with ThreadPoolExecutor() as executor:
                for item in inputs:
                    tasks.append(executor.submit(self._resolve_single_input, ctx, item))

                for future in as_completed(tasks):
                    try:
                        nets = future.result()
                        resolved_nets.update(nets)
                    except Exception as e:
                        ctx.logger.error(f"Error resolving input: {e}")

        return sorted(list(resolved_nets))

    def _resolve_single_input(self, ctx: ScriptContext, an_input: str) -> set[ipaddress.IPv4Network]:
        """
        Worker function to resolve a single input string into one or more network objects.

        NOTE: This function makes assumptions about your API endpoints.
        - `network?network_container={...}`: To find subnets within a supernet.
        - `network?contains_address={...}`: To find the subnet for a single IP.
        Adjust the API calls if your endpoints differ.
        """
        try:
            # ip_network handles '1.2.3.0/24' and '1.2.3.0/255.255.255.0'
            # strict=False allows '1.2.3.4' to be parsed as '1.2.3.4/32'
            net = ipaddress.ip_network(an_input, strict=False)
            if not isinstance(net, ipaddress.IPv4Network):
                raise ValueError("Only IPv4 is supported.")

            # Case 1: A single IP address was entered (becomes a /32 network)
            if net.prefixlen == 32:
                # Find the subnet that contains this single IP address
                response = make_api_call(ctx, f'network?contains_address={net.network_address}')
                if response and response.ok:
                    # Assuming API returns a list with the containing network
                    content = response.json()
                    if content and 'network' in content[0]:
                        return {ipaddress.IPv4Network(content[0]['network'])}
                return set()  # IP not found in any subnet

            # Case 2: A subnet was entered. Check if it's a "supernet" that might contain smaller subnets.
            # We check prefixes smaller than /30 as /30, /31, /32 are typically point-to-point or host routes.
            elif net.prefixlen < 30:
                response = make_api_call(ctx, f'network?network_container={net.compressed}')
                if response and response.ok:
                    supernet_data = process_data(ctx, type='supernet', content=response.content)
                    found_subnets = {ipaddress.IPv4Network(sub["network"]) for sub in supernet_data.get("subnets", [])}
                    # If we find subnets, return them. Otherwise, fall through to return the original net.
                    if found_subnets:
                        return found_subnets

            # Case 3: A regular subnet (/30, /31, /32) or a supernet with no children found.
            return {net}

        except ValueError:
            ctx.logger.warning(f"Invalid IP/Subnet format for input: '{an_input}'")
            return set()

    def _fetch_and_process_subnet_data(self, ctx: ScriptContext, network: ipaddress.IPv4Network) -> tuple[dict, list]:
        """
        Fetches all data for a single subnet, processes it, and prepares it for display and saving.
        This function is designed to be run in a thread pool.
        """
        processed_data = self._fetch_all_data_for_subnet(ctx, network)

        # HOOK: Allow plugins to add/modify the full processed data set
        processed_data = self.execute_hook('process_data', ctx, processed_data)

        if not processed_data.get("general"):
            return {}, []

        save_data = self._prepare_subnet_save_data(processed_data)

        # HOOK: Allow plugins to modify the data just before saving
        save_data = self.execute_hook('pre_save', ctx, save_data)

        return processed_data, save_data

    def _fetch_all_data_for_subnet(self, ctx: ScriptContext, network: NetworkObject) -> dict[str, Any]:
        """Fetches all related data points for a single subnet in parallel."""
        net_str = str(network)
        req_urls = {
            "general": f"network?network={net_str}&_return_fields=network,comment,extattrs",
            "DNS records": f"ipv4address?network={net_str}&usage=DNS&_return_fields=ip_address,names",
            "network options": f"network?network={net_str}&_return_fields=options,members",
            "DHCP range": f"range?network={net_str}",
            "DHCP failover": f"range?network={net_str}&_return_fields=member,failover_association",
            "fixed addresses": f"fixedaddress?network={net_str}&_return_fields=ipv4addr,mac,name",
        }

        processed_data_for_net: dict[str, Any] = defaultdict(list)
        with ThreadPoolExecutor() as executor:
            future_to_label = {
                executor.submit(do_fancy_request, ctx, "", uri, spinner=None): label
                for label, uri in req_urls.items()
            }
            for future in as_completed(future_to_label):
                label = future_to_label[future]
                try:
                    response_content = future.result()
                    if response_content:
                        processed_data_for_net.update(process_data(ctx, type=label, content=response_content))
                except Exception as e:
                    ctx.logger.error(f"Failed to fetch data for '{label}' in {net_str}: {e}")

        return processed_data_for_net

    def _display_results(self, ctx: ScriptContext, networks: list, all_data: dict) -> None:
        """Handles the logic for displaying summary and/or detailed views."""
        colors = get_global_color_scheme(ctx.cfg)
        console = ctx.console

        # Show a summary table if there are multiple results
        if len(networks) > 1:
            summary_data = []
            for network in networks:
                net_str = str(network)
                net_info = all_data.get(net_str)
                if net_info and net_info.get("general"):
                    description = net_info["general"][0].get("description", "N/A")
                    summary_net = {"Subnet": net_str, "Description": description}
                    # Check for plugin-injected data and add it if it exists
                    ad_info = net_info.get("Active Directory", [{}])[0]
                    if ad_info:  # Only add if the plugin provided data
                        summary_net["AD Site"] = ad_info.get("AD Site", "N/A")
                else:
                    summary_net = {"Subnet": net_str, "Description": "No data found"}
                summary_data.append(summary_net)

            print_table_data(ctx, {"Subnet Summary": summary_data})
            console.print(f"\n([{colors['success']}]Press [{colors['error']}{colors['bold']}]Q[/] to return / Any other key for details[/])")
            if read_single_keypress().lower() == "q":
                return

        # Display detailed view for each network
        for i, network in enumerate(networks):
            net_str = str(network)
            if net_str in all_data and all_data[net_str]:
                console.clear()
                print_table_data(ctx, all_data[net_str], suffix={"general": "Information"})
            else:
                console.print(f"[{colors['success']}]Network [{colors['error']}{colors['bold']}] {net_str} [/] has no data in Infoblox[/]")

            if len(networks) > 1 and i < len(networks) - 1:
                console.print(f"\n[{colors['success']}]Press [{colors['bold']}]SPACE[/] for next ({i + 2}/{len(networks)}) / Any other key to exit details view[/]")
                if read_single_keypress() != ' ':
                    break

    def _prepare_subnet_save_data(self, processed_data: dict[str, Any]) -> list[RowDict]:
        """Prepares the processed API data into a list of lists for CSV/Excel saving."""
        data_rows: list[RowDict] = []

        # Extract data with safe defaults
        general_info = processed_data.get("general", [{}])[0]
        subnet_parts = general_info.get("subnet", "/").split("/")
        ip_part, mask_part = (subnet_parts[0], f"/{subnet_parts[1]}") if len(subnet_parts) == 2 else (subnet_parts[0], "")

        dhcp_members = processed_data.get("DHCP members", [])
        dhcp_options = processed_data.get("DHCP options", [])
        dhcp_ranges = processed_data.get("DHCP range", [])
        dhcp_failover = processed_data.get("DHCP failover", [])
        dns_records = processed_data.get("DNS records", [])
        fixed_addrs = processed_data.get("fixed addresses", [])
        ext_attrs = processed_data.get("Extensible Attributes", [])
        ad_info = processed_data.get("Active Directory", [{}])[0]

        # Format complex fields
        is_dhcp = "Y" if dhcp_members or dhcp_ranges else "N"
        dhcp_start = dhcp_ranges[0].get("start address", "") if dhcp_ranges else ""
        dhcp_end = dhcp_ranges[0].get("end address", "") if dhcp_ranges else ""
        dhcp_servers = "\n".join([f"{m['name']} - {m['IP Address']}" for m in dhcp_members])
        dhcp_opts_str = "\n".join([f"{o['name']} - {o['value']}" for o in dhcp_options])
        dhcp_fail_str = dhcp_failover[0].get("dhcp failover", "") if dhcp_failover else ""

        # Row 1: General Subnet Information
        main_row = {
            "IP": ip_part, "Mask": mask_part, "Name": "Subnet", "MAC": "",
            "DHCP": is_dhcp, "DHCP Scope Start": dhcp_start, "DHCP Scope End": dhcp_end,
            "DHCP Servers": dhcp_servers, "DHCP Options\nOption - Value": dhcp_opts_str,
            "DHCP Failover Association": dhcp_fail_str, "Notes": general_info.get("description", "")
        }

        # Conditionally add plugin data to the row dictionary
        if ad_info:
            main_row["AD Site"] = ad_info.get("AD Site", "")
            main_row["AD Location"] = ad_info.get("AD Location", "")
            main_row["AD Description"] = ad_info.get("AD Description", "")
        data_rows.append(main_row)

        if ext_attrs:
            ext_attr_str = "\n".join([f"{a['Attribute']}:{a['Value']}" for a in ext_attrs])
            data_rows.append({
                "IP": ip_part, "Mask": mask_part, "Name": ext_attr_str,
                "Notes": "Extensible Attributes Data"
            })

        for rec in dns_records:
            data_rows.append({"IP": rec.get("IP address"), "Mask": "/32", "Name": rec.get("A Record"), "Notes": "DNS record"})
        for fa in fixed_addrs:
            data_rows.append({"IP": fa.get("IP address"), "Mask": "/32", "Name": fa.get("name"), "MAC": fa.get("MAC"), "Notes": "Fixed IP"})

        return data_rows

    def _save_subnet_data(self, ctx: ScriptContext, networks: list, data_to_save: dict[str, list[RowDict]]) -> None:
        """Saves the collected subnet data by dynamically generating columns from the data itself."""
        common_search_results: list[list[str]] = []
        all_row_dicts: list[RowDict] = []

        # First, collate all row dictionaries and summary results
        for network in networks:
            net_str = str(network)
            if net_str in data_to_save and data_to_save[net_str]:
                common_search_results.append([net_str, "Data Found"])
                all_row_dicts.extend(data_to_save[net_str])
            else:
                common_search_results.append([net_str, "No Match / No Data"])

        # Save the summary sheet (this is simple and unchanged)
        if common_search_results:
            columns_common = ["Search Network", "Status"]
            queue_save(ctx, columns_common, common_search_results, sheet_name="Subnet Search Summary", force_header=True)

        # Now, process the detailed data dynamically
        if all_row_dicts:
            # Define a preferred order for columns that are always present
            base_columns = [
                "IP", "Mask", "Name", "MAC", "DHCP", "DHCP Scope Start", "DHCP Scope End",
                "DHCP Servers", "DHCP Options\nOption - Value", "DHCP Failover Association", "Notes"
            ]

            # Discover all unique column headers from the data, maintaining order
            discovered_headers = {}  # Use dict as an ordered set
            for row in all_row_dicts:
                for key in row.keys():
                    discovered_headers[key] = True

            # Combine base columns with any extra discovered columns (e.g., from plugins)
            final_columns = list(base_columns)
            for header in discovered_headers.keys():
                if header not in final_columns:
                    final_columns.append(header)

            # Normalize all rows to ensure they match the final header order
            data_to_write = []
            for row_dict in all_row_dicts:
                row_list = [row_dict.get(col, "") for col in final_columns]
                data_to_write.append(row_list)

            queue_save(ctx, final_columns, data_to_write, sheet_name="Subnet Data Detail", force_header=True)
