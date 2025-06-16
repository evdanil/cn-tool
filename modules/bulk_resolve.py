import ipaddress
import socket
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor
from core.base import BaseModule, ScriptContext
from utils.user_input import read_user_input
from utils.display import console, get_global_color_scheme, print_table_data
from utils.file_io import queue_save
from utils.validation import is_fqdn


class BulkResolveModule(BaseModule):
    """
    Module to perform a bulk DNS lookup for a list of user-supplied IP addresses,
    hostnames, and subnets, preserving the user's input order.
    """
    @property
    def menu_key(self) -> str:
        return "7"

    @property
    def menu_title(self) -> str:
        return "Bulk DNS Lookup"

    def run(self, ctx: ScriptContext) -> None:
        """
        Resolves user-supplied IPs/FQDNs using the system resolver in parallel.
        (Original `bulk_resolve_request` logic)
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - Bulk DNS Lookup")

        # --- Nested Helper Functions ---
        def resolve_ip(ip: str) -> Tuple[str, Optional[Tuple[str, List[str], List[str]]]]:
            try:
                # Returns (hostname, aliaslist, ipaddrlist)
                return (ip, socket.gethostbyaddr(ip))
            except (socket.gaierror, socket.herror, socket.timeout):
                return (ip, None)

        def resolve_name(name: str) -> Tuple[str, Optional[List[str]]]:
            try:
                addrinfo = socket.getaddrinfo(name, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
                # Use dict.fromkeys to get unique IPs, then convert back to a list
                return (name, list(dict.fromkeys([str(addr[4][0]) for addr in addrinfo])))
            except (socket.gaierror, socket.herror, socket.timeout):
                return (name, None)

        # --- User Input and Target Parsing ---
        console.print(
            "\n"
            f"[{colors['description']}]Enter FQDNs/IPs/Subnets, one per line. Invalid entries are ignored.[/]\n"
            f"[{colors['warning']}]Subnets will be expanded and every host IP will be resolved.[/]\n"
            f"[{colors['description']}]Empty input line starts the lookup process.[/]\n"
        )

        # This helper will parse the input and maintain the order of first appearance.
        ips_to_resolve, names_to_resolve = self._parse_user_input(ctx)

        if not ips_to_resolve and not names_to_resolve:
            logger.info("Bulk Resolve - No valid targets to resolve.")
            return

        logger.info(f"User input - Resolving {len(ips_to_resolve)} IPs and {len(names_to_resolve)} names.")

        # --- Parallel Resolution ---
        results_ip: List[Dict[str, str]] = []
        results_name: List[Dict[str, str]] = []

        with console.status(f"[{colors['description']}]Resolving...[/]", spinner="dots12"), ThreadPoolExecutor() as executor:
            # Submit all jobs
            ip_futures = {executor.submit(resolve_ip, ip): ip for ip in ips_to_resolve}
            name_futures = {executor.submit(resolve_name, name): name for name in names_to_resolve}

            # Process IP results
            ip_results_map = {ip_futures[future]: future.result() for future in ip_futures}
            for ip in ips_to_resolve:  # Iterate in the original order
                _, data = ip_results_map[ip]
                if data:
                    hostname = data[0]
                    aliases = data[1]
                    results_ip.append({"IP": ip, "Name": hostname})
                    for alias in aliases:
                        results_ip.append({"IP": ip, "Name": alias})
                else:
                    results_ip.append({"IP": ip, "Name": "Not Resolved"})

            # Process Name results
            name_results_map = {name_futures[future]: future.result() for future in name_futures}
            for name in names_to_resolve:  # Iterate in the original order
                _, data = name_results_map[name]
                if data:
                    for ip_addr in data:
                        results_name.append({"Name": name, "IP": ip_addr})
                else:
                    results_name.append({"Name": name, "IP": "Not Resolved"})

        # --- Display and Save ---
        final_results_for_display: Dict[str, List[Dict[str, str]]] = {}
        if results_ip:
            final_results_for_display["IP to Name Lookup"] = results_ip
        if results_name:
            final_results_for_display["Name to IP Lookup"] = results_name

        # The hook can modify the dictionary containing both result lists
        final_results_for_display = self.execute_hook('process_data', ctx, final_results_for_display)

        if not final_results_for_display:
            console.print(f"[{colors['info']}]Resolve process completed with no results.[/]")
            return

        print_table_data(ctx, final_results_for_display)

        if ctx.cfg["report_auto_save"]:
            save_data: List[Tuple[str, str]] = []
            # Extract data from the final (potentially modified) results for saving
            for item in final_results_for_display.get("Name to IP Lookup", []):
                save_data.append((item.get("Name", ""), item.get("IP", "")))
            for item in final_results_for_display.get("IP to Name Lookup", []):
                save_data.append((item.get("IP", ""), item.get("Name", "")))

            if save_data:
                # The hook could modify this list of tuples before it gets saved
                final_save_data = self.execute_hook('pre_save', ctx, save_data)
                queue_save(ctx, ["Query", "Result"], final_save_data, sheet_name="Bulk DNS Lookup", index=False, force_header=True)

    def _parse_user_input(self, ctx: ScriptContext) -> Tuple[List[str], List[str]]:
        """Parses user input into separate lists for IPs and names, preserving order."""
        ips = []
        names = []
        seen_ips = set()
        seen_names = set()

        while True:
            raw_input = read_user_input(ctx, "").strip()
            if not raw_input:
                break

            # Check if it's an FQDN first
            if is_fqdn(raw_input):
                if raw_input not in seen_names:
                    names.append(raw_input)
                    seen_names.add(raw_input)
                continue

            # If not FQDN, check if it's a subnet or IP
            try:
                net = ipaddress.ip_network(raw_input, strict=False)
                # Expand subnets, add individual hosts
                for ip_obj in net.hosts():
                    ip_str = str(ip_obj)
                    if ip_str not in seen_ips:
                        ips.append(ip_str)
                        seen_ips.add(ip_str)
                # Also add the /32 address itself if it was just an IP
                if net.num_addresses == 1:
                    ip_str = str(net.network_address)
                    if ip_str not in seen_ips:
                        ips.append(ip_str)
                        seen_ips.add(ip_str)

            except ValueError:
                ctx.logger.warning(f"Invalid input for DNS lookup, skipping: {raw_input}")

        return ips, names
