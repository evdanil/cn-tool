# modules/bulk_ping.py
import ipaddress
from typing import Dict, List, Optional
from subprocess import Popen, DEVNULL, STDOUT

from core.base import BaseModule, ScriptContext
from utils.user_input import read_user_input
from utils.display import console, get_global_color_scheme, print_table_data
from utils.file_io import queue_save
from utils.validation import is_fqdn, validate_ip


class BulkPingModule(BaseModule):
    """
    Module to perform a bulk ping against a list of user-supplied IP addresses,
    hostnames, and subnets, preserving the user's input order.
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
        (Original `bulk_ping_request` logic, modified to preserve order)
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - Bulk PING")

        console.print(
            "\n"
            f"[{colors['description']}]Enter IPs/FQDNs/Subnets to ping, one per line.[/]\n"
            f"[{colors['header']} {colors['bold']}]Example formats[/]: 192.168.0.1, example.com, 192.168.0.0/24\n"
            f"[{colors['warning']}]Subnets will be expanded and every host IP will be pinged.[/]\n"
            f"[{colors['description']}]Empty input line starts the ping process.[/]\n"
        )

        # --- User Input and Target Parsing ---
        # The _parse_user_input helper already returns a unique list in order of appearance.
        hosts_to_ping = self._parse_user_input(ctx)

        if not hosts_to_ping:
            logger.info("Bulk PING - No valid hosts to ping.")
            return

        logger.info(f"User input - Pinging {len(hosts_to_ping)} unique hosts.")

        # --- Pinging Logic ---
        results: List[Dict[str, str]] = []
        batch_size = 100

        with console.status(f"[{colors['description']}]Pinging hosts...[/]", spinner="dots12"):
            for i in range(0, len(hosts_to_ping), batch_size):
                batch = hosts_to_ping[i:i + batch_size]
                # Ping the batch and get results. We need to re-order them to match the batch input order.
                batch_results_map = {res['Host']: res['Result'] for res in self._ping_batch(batch)}
                # Ensure the results are added in the same order as the batch was given.
                for host in batch:
                    results.append({'Host': host, 'Result': batch_results_map.get(host, "ERROR (No Result)")})

        # --- Process, Display, and Save Results ---

        # --- HOOK: Allow plugins to modify the raw results list ---
        final_results = self.execute_hook('process_data', ctx, results)

        if not final_results:
            console.print(f"[{colors['info']}]Ping process completed with no results to display.[/]")
            return

        # The sorting logic has been removed to preserve user input order.
        print_table_data(ctx, {"Bulk PING Results": final_results})

        if ctx.cfg["report_auto_save"]:
            # Derive columns and data from the final results
            final_columns = list(final_results[0].keys())
            save_data_lol = [[row.get(col, '') for col in final_columns] for row in final_results]
            queue_save(ctx, final_columns, save_data_lol, sheet_name="Bulk PING", index=False, force_header=True)

    def _parse_user_input(self, ctx: ScriptContext) -> List[str]:
        """Parses multi-format user input into a flat list of unique hosts, preserving order."""
        hosts: List[str] = []
        seen = set()  # Use a set for fast duplicate checking

        while True:
            raw_input = read_user_input(ctx, "").strip()
            if not raw_input:
                break

            # This list will hold hosts found on the current line
            current_line_hosts = []

            if is_fqdn(raw_input):
                current_line_hosts.append(raw_input)
            else:
                try:
                    net = ipaddress.ip_network(raw_input, strict=False)
                    for ip in net.hosts():
                        if not (ip.is_loopback or ip.is_multicast or ip.is_reserved):
                            current_line_hosts.append(str(ip))
                except ValueError:
                    for word in raw_input.replace(',', ' ').split():
                        if validate_ip(word):
                            current_line_hosts.append(word)

            # Add unique hosts from the current line to the main list
            for host in current_line_hosts:
                if host not in seen:
                    seen.add(host)
                    hosts.append(host)

        return hosts

    def _ping_batch(self, batch: List[str]) -> List[Dict[str, str]]:
        """Pings a batch of hosts in parallel and returns the results."""
        # The logic inside this function remains the same, as it processes in parallel
        # and returns an unordered list of results for the batch. The re-ordering is
        # handled by the caller (`run` method).
        processes: Dict[str, Popen] = {}
        results: List[Dict[str, str]] = []

        for host in batch:
            command = ["ping", "-n", "-w3", "-c3", host]
            processes[host] = Popen(command, stdout=DEVNULL, stderr=STDOUT)

        while processes:
            finished_hosts = []
            for host, proc in processes.items():
                if proc.poll() is not None:
                    if proc.returncode == 0:
                        result_status = "OK"
                    elif proc.returncode in [1, 2]:
                        result_status = "NO RESPONSE"
                    else:
                        result_status = "ERROR"

                    results.append({"Host": host, "Result": result_status})
                    finished_hosts.append(host)

            for host in finished_hosts:
                del processes[host]

        return results
