# modules/bulk_ping.py
import ipaddress
import shutil
from logging import Logger
from subprocess import DEVNULL, STDOUT, Popen
from typing import Dict, List, Optional, Tuple

from core.base import BaseModule, ScriptContext
from utils.user_input import press_any_key, read_user_input
from utils.display import console, get_global_color_scheme, print_table_data
from utils.file_io import queue_save
from utils.validation import is_fqdn, validate_ip


class BulkPingModule(BaseModule):
    """
    Module to perform a bulk ping against a list of user-supplied IP addresses,
    hostnames, and subnets, with smart display logic for large subnets.
    """
    @property
    def menu_key(self) -> str:
        return "6"

    @property
    def menu_title(self) -> str:
        return "Bulk PING"

    @property
    def visibility_config_key(self) -> Optional[str]:
        return None

    def run(self, ctx: ScriptContext) -> None:
        """
        Runs multiple parallel ping processes against a list of user-supplied targets.
        """
        # The subnet size below which we always display all results.
        display_threshold = 32

        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - Bulk PING")
        if shutil.which("ping") is None:
            logger.error("'ping' command not found. Aborting.")
            press_any_key(ctx)
            return

        console.print(
            "\n"
            f"[{colors['description']}]Enter IPs/FQDNs/Subnets to ping, one per line.[/]\n"
            f"[{colors['header']} {colors['bold']}]Example formats[/]: 192.168.0.1, example.com, 192.168.0.0/24\n"
            f"[{colors['warning']}]Subnets will be expanded and every host IP will be pinged.[/]\n"
            f"[{colors['description']}]Empty input line starts the ping process.[/]\n"
        )

        # --- User Input and Target Parsing ---
        # The parser returns the original input structure and a flat list of all hosts.
        user_inputs, hosts_to_ping = self._parse_user_input(ctx)

        if not hosts_to_ping:
            logger.info("Bulk PING - No valid hosts to ping.")
            press_any_key(ctx)
            return

        logger.info(f"User input - Pinging {len(hosts_to_ping)} unique hosts.")

        # --- Pinging Logic ---
        results: List[Dict[str, str]] = []
        batch_size = 100

        total_batches = int(len(hosts_to_ping) / batch_size) + 1
        for i in range(0, len(hosts_to_ping), batch_size):
            batch = hosts_to_ping[i:i + batch_size]
            ending = '...'
            # Ping the batch and get results. We re-order them to match the input order.
            if total_batches > 1:
                ending = f' batch {int( i / batch_size + 1)} out of {total_batches}'

            with console.status(f"[{colors['description']}]Pinging hosts{ending}[/]", spinner="dots12"):
                batch_results_map = {res['Host']: res['Result'] for res in self._ping_batch(batch, logger)}
                # Ensure the results are added in the same order as the batch was given.
                for host in batch:
                    results.append({'Host': host, 'Result': batch_results_map.get(host, "ERROR (No Result)")})

        # --- HOOK: Allow plugins to modify the raw results list ---
        final_results = self.execute_hook('process_data', ctx, results)

        if not final_results:
            console.print(f"[{colors['info']}]Ping process completed with no results to display.[/]")
            press_any_key(ctx)
            return

        # --- Smart Display Logic ---
        # This block creates a filtered list for on-screen display ONLY.
        results_map = {item['Host']: item['Result'] for item in final_results}
        display_data = []

        for input_item in user_inputs:
            input_type, original_value, hosts_in_item = input_item

            # Always show single hosts/IPs or small subnets fully
            if input_type == 'single' or len(hosts_in_item) <= display_threshold:
                for host in hosts_in_item:
                    display_data.append({'Host': host, 'Result': results_map.get(host, 'N/A')})
            else:
                # This is a large subnet. We will ONLY display the successful pings.
                success_results = []
                for host in hosts_in_item:
                    if results_map.get(host) == "OK":
                        success_results.append({'Host': host, 'Result': "OK"})

                if success_results:
                    # If we found any successful pings, display them.
                    display_data.extend(success_results)

                    # Then, add a single summary line for all the non-responsive hosts.
                    num_failures = len(hosts_in_item) - len(success_results)
                    if num_failures > 0:
                        display_data.append({
                            'Host': f"(... and {num_failures} other hosts in {original_value})",
                            'Result': "NO RESPONSE"
                        })
                else:
                    # If there were ZERO successful pings, just show one summary line for the whole subnet.
                    display_data.append({
                        'Host': f"All {len(hosts_in_item)} hosts in {original_value}",
                        'Result': "NO RESPONSE"
                    })

        # Display the intelligently filtered data
        print_table_data(ctx, {"Bulk PING Results": display_data})

        # --- Save Results ---
        # This part is UNCHANGED and saves the original, complete `final_results`.
        if ctx.cfg["report_auto_save"]:
            # Derive columns and data from the final, unfiltered results
            if final_results:
                final_columns = list(final_results[0].keys())
                save_data_lol = [[row.get(col, '') for col in final_columns] for row in final_results]
                queue_save(ctx, final_columns, save_data_lol, sheet_name="Bulk PING", index=False, force_header=True)

        press_any_key(ctx)

    def _parse_user_input(self, ctx: ScriptContext) -> Tuple[List[Tuple[str, str, List[str]]], List[str]]:
        """
        Parses multi-format user input into a flat list of unique hosts, preserving order,
        and also returns the structured input for smart display.

        Returns:
            A tuple containing:
            1. A list of tuples: (input_type, original_value, list_of_hosts_from_it)
            2. A flat list of all unique hosts to be pinged.
        """
        user_inputs: List[Tuple[str, str, List[str]]] = []
        all_hosts: List[str] = []
        seen = set()  # Use a set for fast duplicate checking

        while True:
            raw_input = read_user_input(ctx, "").strip()
            if not raw_input:
                break

            # This list will hold hosts found on the current line
            current_line_hosts = []
            input_type = 'single'  # Default to single host
            original_value = raw_input

            if is_fqdn(raw_input):
                current_line_hosts.append(raw_input)
            else:
                try:
                    net = ipaddress.ip_network(raw_input, strict=False)
                    if net.num_addresses > 1:  # It's a subnet
                        input_type = 'subnet'
                    if isinstance(net, ipaddress.IPv6Network):
                        ctx.console.print('IPv6 subnets are not supported')
                        continue

                    host_iterator = net.hosts()
                    for ip in host_iterator:
                        if not (ip.is_loopback or ip.is_multicast or ip.is_reserved):
                            current_line_hosts.append(str(ip))
                except ValueError:
                    # Fallback for comma/space separated IPs
                    found_words = [word for word in raw_input.replace(',', ' ').split() if validate_ip(word)]
                    if found_words:
                        current_line_hosts.extend(found_words)
                        if len(found_words) > 1:
                            input_type = 'list'

            # Add unique hosts from the current line to the main flat list
            unique_line_hosts = []
            for host in current_line_hosts:
                if host not in seen:
                    seen.add(host)
                    all_hosts.append(host)
                    unique_line_hosts.append(host)

            # If we found any valid hosts on this line, record the user's input structure
            if unique_line_hosts:
                user_inputs.append((input_type, original_value, unique_line_hosts))

        return user_inputs, all_hosts

    def _ping_batch(self, batch: List[str], logger: Logger) -> List[Dict[str, str]]:
        """Pings a batch of hosts in parallel and returns the results."""
        processes: Dict[str, Popen] = {}
        results: List[Dict[str, str]] = []

        for host in batch:
            # Using -n to prevent name resolution, -w3 for 3-sec timeout, -c2 for 2 packets
            command = ["ping", "-n", "-w3", "-c2", host]
            try:
                processes[host] = Popen(command, stdout=DEVNULL, stderr=STDOUT)
            except FileNotFoundError:
                logger.error("'ping' command not found.")
                return []

        for host, proc in processes.items():
            # proc.wait() blocks until the process finishes, consuming no CPU while waiting.
            proc.wait()
            # Determine the result based on the return code
            if proc.returncode == 0:
                result_status = "OK"
            elif proc.returncode in [1, 2]:  # Common exit codes for unreachable hosts
                result_status = "NO RESPONSE"
            else:
                result_status = "ERROR"
            results.append({"Host": host, "Result": result_status})

        return results
