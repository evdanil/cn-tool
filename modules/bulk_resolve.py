import ipaddress
import socket
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base import BaseModule, ScriptContext
from utils.user_input import press_any_key, read_user_input
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

    @property
    def visibility_config_key(self) -> Optional[str]:
        return None

    def run(self, ctx: ScriptContext) -> None:
        """
        Resolves user-supplied IPs/FQDNs using the system resolver in parallel.
        (Original `bulk_resolve_request` logic)
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - Bulk DNS Lookup")

        # --- Nested Helper Functions ---
        def lookup_ip(ip: str) -> Optional[Tuple[str, List[str], List[str]]]:
            try:
                return socket.gethostbyaddr(ip)
            except (socket.gaierror, socket.herror, socket.timeout):
                return None

        def resolve_ip(ip: str) -> Tuple[str, Optional[Tuple[str, List[str], List[str]]]]:
            return (ip, lookup_ip(ip))

        def lookup_name(name: str) -> Optional[List[str]]:
            try:
                addrinfo = socket.getaddrinfo(name, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
                # Use dict.fromkeys to get unique IPs, then convert back to a list
                return list(dict.fromkeys([str(addr[4][0]) for addr in addrinfo]))
            except (socket.gaierror, socket.herror, socket.timeout):
                return None

        def resolve_name(name: str) -> Tuple[str, Optional[List[str]]]:
            return (name, lookup_name(name))

        def format_joined(values: Optional[List[str]]) -> str:
            if not values:
                return "Not Resolved"
            return ", ".join(values)

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
            press_any_key(ctx)
            return

        logger.info(f"User input - Resolving {len(ips_to_resolve)} IPs and {len(names_to_resolve)} names.")

        # This dictionary will store results as they complete, keyed by the original query.
        # The value will be a list of result dictionaries.
        ip_results_map: Dict[str, List[Dict[str, str]]] = {ip: [] for ip in ips_to_resolve}
        name_results_map: Dict[str, List[Dict[str, str]]] = {name: [] for name in names_to_resolve}

        with console.status(f"[{colors['description']}]Resolving...[/]", spinner="dots12"), ThreadPoolExecutor() as executor:
            ip_futures = {executor.submit(resolve_ip, ip) for ip in ips_to_resolve}
            name_futures = {executor.submit(resolve_name, name) for name in names_to_resolve}

            # Process IP results as they complete
            for future in as_completed(ip_futures):
                original_ip, data = future.result()
                if data:
                    hostname, aliases, _ = data
                    resolved_names = [hostname] + aliases
                    for resolved_name in resolved_names:
                        reverse_ips = lookup_name(resolved_name)
                        ip_results_map[original_ip].append(
                            {
                                "IP": original_ip,
                                "Resolved Name": resolved_name,
                                "Reverse Result": format_joined(reverse_ips),
                            }
                        )
                else:
                    ip_results_map[original_ip].append(
                        {
                            "IP": original_ip,
                            "Resolved Name": "Not Resolved",
                            "Reverse Result": "Not Resolved",
                        }
                    )

            # Process Name results as they complete
            for future in as_completed(name_futures):
                original_name, ip_list = future.result()
                if ip_list:
                    for ip_addr in ip_list:
                        reverse_lookup = lookup_ip(ip_addr)
                        reverse_name = reverse_lookup[0] if reverse_lookup else "Not Resolved"
                        name_results_map[original_name].append(
                            {
                                "Name": original_name,
                                "Resolved IP": ip_addr,
                                "Reverse Result": reverse_name,
                            }
                        )
                else:
                    name_results_map[original_name].append(
                        {
                            "Name": original_name,
                            "Resolved IP": "Not Resolved",
                            "Reverse Result": "Not Resolved",
                        }
                    )

        # --- Display and Save (logic is now much simpler) ---
        # Assemble final results in the original user-provided order.
        final_results_ip = [result for ip in ips_to_resolve for result in ip_results_map[ip]]
        final_results_name = [result for name in names_to_resolve for result in name_results_map[name]]

        final_results_for_display: Dict[str, List[Dict[str, str]]] = {}
        if final_results_ip:
            final_results_for_display["IP to Name Lookup"] = final_results_ip
        if final_results_name:
            final_results_for_display["Name to IP Lookup"] = final_results_name

        # Hooks and saving logic remain the same and should now work correctly.
        final_results_for_display = self.execute_hook('process_data', ctx, final_results_for_display)
        if not final_results_for_display:
            console.print(f"[{colors['info']}]Resolve process completed with no results.[/]")
            press_any_key(ctx)
            return

        print_table_data(ctx, final_results_for_display)

        if ctx.cfg["report_auto_save"]:
            save_data: List[Tuple[str, str]] = []
            # Extract data from the final (potentially modified) results for saving
            for item in final_results_for_display.get("Name to IP Lookup", []):
                save_data.append((
                    item.get("Name", ""),
                    item.get("Resolved IP", ""),
                    item.get("Reverse Result", ""),
                ))
            for item in final_results_for_display.get("IP to Name Lookup", []):
                save_data.append((
                    item.get("IP", ""),
                    item.get("Resolved Name", ""),
                    item.get("Reverse Result", ""),
                ))
            if save_data:
                final_save_data = self.execute_hook('pre_save', ctx, save_data)
                queue_save(
                    ctx,
                    ["Query", "Result", "Reverse Result"],
                    final_save_data,
                    sheet_name="Bulk DNS Lookup",
                    index=False,
                    force_header=True,
                )

        press_any_key(ctx)

    def _parse_user_input(self, ctx: ScriptContext) -> Tuple[List[str], List[str]]:
        """
        Parses user input into separate lists for IPs and names, preserving order.
        Checks for IP/Subnet format FIRST, then falls back to FQDN.
        """
        ips_ordered_set = {}
        names_ordered_set = {}

        while True:
            raw_input = read_user_input(ctx, "").strip()
            if not raw_input:
                break

            # Try to parse as an IP/Subnet FIRST.
            is_ip_or_subnet = False
            try:
                net = ipaddress.ip_network(raw_input, strict=False)
                if isinstance(net, ipaddress.IPv6Network):
                    ctx.console.print('IPv6 subnets are not supported')
                    continue
                # If this succeeds, it's a valid IP/Subnet.
                is_ip_or_subnet = True

                if net.num_addresses == 1:
                    ips_ordered_set[str(net.network_address)] = True
                else:
                    for ip_obj in net.hosts():
                        ips_ordered_set[str(ip_obj)] = True
            except ValueError:
                # It's not a valid IP or subnet.
                is_ip_or_subnet = False

            # If it wasn't an IP, NOW we check if it's an FQDN.
            if not is_ip_or_subnet:
                if is_fqdn(raw_input):
                    names_ordered_set[raw_input] = True
                else:
                    # It's neither a valid IP/Subnet nor a valid FQDN.
                    ctx.logger.warning(f"Invalid input for DNS lookup, skipping: {raw_input}")

        return list(ips_ordered_set.keys()), list(names_ordered_set.keys())
