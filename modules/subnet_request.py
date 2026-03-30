import ipaddress
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from time import perf_counter
from typing import Any, Dict, List, Optional, Set, Union

# Assuming these are your project's utility modules
from core.base import BaseModule, ScriptContext
from utils.api import bound_infoblox_workers, describe_infoblox_failure, request_result
from utils.auth import ensure_infoblox_auth
from utils.display import get_global_color_scheme, print_table_data
from utils.file_io import queue_save
from utils.infoblox_ux import format_no_match_message, format_partial_results_message
from utils.process_data import process_data
from utils.user_input import press_any_key, read_user_input

# Type alias for clarity
NetworkObject = Union[ipaddress.IPv4Network, ipaddress.IPv4Address]
RowDict = Dict[str, Any]


@dataclass(frozen=True, eq=True)
class QueryTarget:
    """Represents a single query, linking an original input to a resolved network."""
    original_input: str
    resolved_network: ipaddress.IPv4Network


@dataclass(frozen=True)
class InputResolutionResult:
    networks: Set[ipaddress.IPv4Network]
    failure_message: str = ""


@dataclass(frozen=True)
class SubnetFetchOutcome:
    data: Dict[str, Any]
    warnings: List[str]


@dataclass(frozen=True)
class SubnetSummaryState:
    status: str
    description: str


class SubnetRequestModule(BaseModule):
    """
    Module to fetch detailed information for one or more subnets from an API.
    It accepts input as plain IPs, CIDR notation (e.g., 1.2.3.0/24), or
    IP/subnet mask (e.g., 1.2.3.0/255.255.255.0).
    It preserves the original input and its order in the final results.
    """
    @property
    def menu_key(self) -> str:
        return "2"

    @property
    def menu_title(self) -> str:
        return "Subnet Information"

    @property
    def visibility_config_key(self) -> Optional[str]:
        return "infoblox_enabled"

    def run(self, ctx: ScriptContext) -> None:
        """
        Main execution flow for the module.
        Orchestrates user input, data fetching, processing, and display.
        """
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

            ensure_infoblox_auth(ctx)

            # --- 1. Get User Input ---
            user_inputs = self._get_networks_from_user(ctx)
            if not user_inputs:
                return

            logger.info(f"User provided inputs: {', '.join(user_inputs)}")
            start = perf_counter()

            # --- 2. Resolve all inputs into an ordered list of query targets ---
            query_targets, resolution_errors = self._resolve_inputs_to_targets(ctx, user_inputs)
            for original_input, message in resolution_errors.items():
                console.print(f"[{colors['warning']}]{original_input}[/] - [{colors['error']}]{message}[/]")
            if not query_targets:
                console.print(f"[{colors['error']}]Could not resolve any of the provided inputs to a valid subnet.[{colors['error']}]")
                press_any_key(ctx)
                return

            # --- 3. Main Data Fetching and Processing ---
            # Fetch data for unique subnets only to avoid redundant API calls
            unique_networks = sorted(list({qt.resolved_network for qt in query_targets}), key=lambda ip: ip.network_address)
            logger.info(f"Resolved to {len(unique_networks)} unique subnets for data fetching.")
            console.print(f"[{colors['description']}]Found [{colors['success']}]{len(unique_networks)}[/] unique subnets to query.[/]")

            subnet_data_cache: Dict[str, Dict] = {}
            subnet_warning_cache: Dict[str, List[str]] = {}
            with ctx.console.status(f"[{get_global_color_scheme(ctx.cfg)['description']}]Fetching subnets information...[/]"):
                with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, len(unique_networks))) as executor:
                    future_to_net = {
                        executor.submit(self._fetch_and_process_subnet_data, ctx, network): network
                        for network in unique_networks
                    }

                    for future in as_completed(future_to_net):
                        network = future_to_net[future]
                        net_str = str(network)
                        console.print(f"[{colors['description']}]Processing results for [{colors['header']}]{net_str}[/]...[/]")
                        outcome = future.result()
                        if outcome.data:
                            subnet_data_cache[net_str] = outcome.data
                        if outcome.warnings:
                            subnet_warning_cache[net_str] = outcome.warnings

            # --- 4. Prepare data for display and saving ---
            grouped_by_network = defaultdict(list)
            for target in query_targets:
                grouped_by_network[target.resolved_network].append(target.original_input)

            all_data_to_save: List[List[RowDict]] = []
            for network, original_inputs in grouped_by_network.items():
                net_str = str(network)
                data = subnet_data_cache.get(net_str, {})

                if ctx.cfg["report_auto_save"] and data:
                    combined_input_str = ", ".join(original_inputs)
                    save_data = self._prepare_subnet_save_data(combined_input_str, data)
                    save_data = self.execute_hook('pre_save', ctx, save_data)
                    if save_data:
                        all_data_to_save.append(save_data)

            end = perf_counter()
            duration = round(end - start, 3)
            logger.info(f"Subnet Information search took {duration} seconds!")
            console.print(f"\n[{colors['description']}]Search took [{colors['success']}]{duration}[/] seconds![/]\n")

            # --- 5. Display and Save ---
            self._display_results(ctx, query_targets, subnet_data_cache, grouped_by_network, subnet_warning_cache)

            if ctx.cfg["report_auto_save"] and all_data_to_save:
                self._save_subnet_data(ctx, query_targets, all_data_to_save)

            ctx.event_bus.publish(
                "stats:module_detail",
                {
                    "unit_count": len(unique_networks),
                    "input_count": len(user_inputs),
                    "unique_count": len(unique_networks),
                    "resolved_target_count": len(query_targets),
                    "success_count": len(subnet_data_cache),
                    "miss_count": max(0, len(unique_networks) - len(subnet_data_cache)),
                },
            )
        finally:
            self.execute_hook('post_run', ctx, None)

        press_any_key(ctx)

    def _get_networks_from_user(self, ctx: ScriptContext) -> List[str]:
        """
        Prompts the user to enter network addresses one per line.
        Returns a list of unique, non-empty input strings from the user.
        """
        colors = get_global_color_scheme(ctx.cfg)
        ctx.console.print(
            "\n" f"[{colors['description']}]Enter network addresses and press Enter twice to start.[/]\n"
            f"[{colors['description']}]Formats: '1.2.3.0/24', '1.2.3.0/255.255.255.0', or just '1.2.3.4'[/]\n"
        )
        inputs = []
        while True:
            search_input = read_user_input(ctx, "").strip()
            if not search_input:
                break
            inputs.append(search_input)
        return list(dict.fromkeys(inputs))

    def _resolve_inputs_to_targets(self, ctx: ScriptContext, inputs: List[str]) -> tuple[List[QueryTarget], Dict[str, str]]:
        """
        Takes raw user input strings and resolves them into an ordered list of QueryTarget objects.
        This preserves the original input and its order.
        """
        all_targets: List[QueryTarget] = []
        errors: Dict[str, str] = {}
        with ctx.console.status(f"[{get_global_color_scheme(ctx.cfg)['description']}]Resolving inputs and finding subnets...[/]"):
            # Using executor.map preserves the order of the inputs
            with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, len(inputs))) as executor:
                results_generator = executor.map(lambda item: self._resolve_single_input_detailed(ctx, item), inputs)
                for original_input, resolution in zip(inputs, results_generator):
                    if resolution.failure_message:
                        errors[original_input] = resolution.failure_message
                    if not resolution.networks:
                        ctx.logger.warning(f"Could not resolve '{original_input}' to any subnet.")
                        continue
                    # Sort to ensure consistent order for supernets
                    for net in sorted(list(resolution.networks), key=lambda ip: ip.network_address):
                        all_targets.append(QueryTarget(original_input=original_input, resolved_network=net))
        return all_targets, errors

    def _resolve_single_input(self, ctx: ScriptContext, an_input: str) -> Set[ipaddress.IPv4Network]:
        return self._resolve_single_input_detailed(ctx, an_input).networks

    def _resolve_single_input_detailed(self, ctx: ScriptContext, an_input: str) -> InputResolutionResult:
        """
        Worker function to resolve a single input string into one or more network objects.
        """
        try:
            net = ipaddress.ip_network(an_input, strict=False)
            if not isinstance(net, ipaddress.IPv4Network):
                raise ValueError("Only IPv4 is supported.")
            if net.prefixlen == 32:
                result = request_result(ctx, f'network?contains_address={net.network_address}', ensure_auth=False)
                if result.ok and result.has_items and 'network' in result.items[0]:
                    return InputResolutionResult(networks={ipaddress.IPv4Network(result.items[0]['network'])})
                if result.failed:
                    return InputResolutionResult(networks=set(), failure_message=describe_infoblox_failure(result))
                return InputResolutionResult(networks=set())
            elif net.prefixlen < 30:
                result = request_result(ctx, f'network?network_container={net.compressed}', ensure_auth=False)
                if result.ok:
                    supernet_data = process_data(ctx, type='supernet', content=result.content)
                    found_subnets = {ipaddress.IPv4Network(sub["network"]) for sub in supernet_data.get("subnets", [])}
                    if found_subnets:
                        return InputResolutionResult(networks=found_subnets)
                elif result.failed:
                    return InputResolutionResult(networks=set(), failure_message=describe_infoblox_failure(result))
            return InputResolutionResult(networks={net})
        except ValueError:
            ctx.logger.warning(f"Invalid IP/Subnet format for input: '{an_input}'")
            return InputResolutionResult(networks=set())
        except Exception as e:
            ctx.logger.error(f"Error resolving input '{an_input}': {e}")
            return InputResolutionResult(networks=set(), failure_message="Subnet resolution failed.")

    def _fetch_and_process_subnet_data(self, ctx: ScriptContext, network: ipaddress.IPv4Network) -> SubnetFetchOutcome:
        """
        Fetches all data for a single subnet, processes it, and prepares it for display.
        This function is designed to be run in a thread pool for a *unique* network.
        """
        outcome = self._fetch_all_data_for_subnet(ctx, network)
        processed_data = self.execute_hook('process_data', ctx, outcome.data)
        return SubnetFetchOutcome(data=processed_data, warnings=outcome.warnings)

    def _fetch_all_data_for_subnet(self, ctx: ScriptContext, network: NetworkObject) -> SubnetFetchOutcome:
        """Fetches all related data points for a single subnet in parallel."""
        net_str = str(network)
        request_specs = {
            "network bundle": {
                "uri": f"network?network={net_str}&_return_fields=network,comment,extattrs,options,members",
                "parser_types": ("general", "network options"),
                "warning_labels": ("general", "network options"),
            },
            "DNS records": {
                "uri": f"ipv4address?network={net_str}&usage=DNS&_return_fields=ip_address,names",
                "parser_types": ("DNS records",),
                "warning_labels": ("DNS records",),
            },
            "range bundle": {
                "uri": f"range?network={net_str}&_return_fields=network,start_addr,end_addr,member,failover_association",
                "parser_types": ("DHCP range", "DHCP failover"),
                "warning_labels": ("DHCP range", "DHCP failover"),
            },
            "fixed addresses": {
                "uri": f"fixedaddress?network={net_str}&_return_fields=ipv4addr,mac,name",
                "parser_types": ("fixed addresses",),
                "warning_labels": ("fixed addresses",),
            },
        }
        processed_data_for_net: Dict[str, Any] = defaultdict(list)
        warnings: List[str] = []
        with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, len(request_specs))) as executor:
            future_to_label = {
                executor.submit(request_result, ctx, spec["uri"], ensure_auth=False): label
                for label, spec in request_specs.items()
            }
            for future in as_completed(future_to_label):
                label = future_to_label[future]
                spec = request_specs[label]
                try:
                    result = future.result()
                    if result.ok:
                        for parser_type in spec["parser_types"]:
                            processed_data_for_net.update(process_data(ctx, type=parser_type, content=result.content))
                    elif result.failed:
                        message = describe_infoblox_failure(result)
                        for warning_label in spec["warning_labels"]:
                            warnings.append(f"{warning_label}: {message}")
                except Exception as e:
                    ctx.logger.error(f"Failed to fetch data for '{label}' in {net_str}: {e}")
                    for warning_label in spec["warning_labels"]:
                        warnings.append(f"{warning_label}: request processing failed.")
        return SubnetFetchOutcome(data=processed_data_for_net, warnings=warnings)

    def _display_results(self, ctx: ScriptContext, query_targets: List[QueryTarget], subnet_data_cache: Dict[str, Dict], grouped_by_network: Dict[ipaddress.IPv4Network, List[str]], subnet_warning_cache: Optional[Dict[str, List[str]]] = None) -> None:
        """Handles the logic for displaying summary and/or detailed views in order."""
        colors = get_global_color_scheme(ctx.cfg)
        console = ctx.console
        subnet_warning_cache = subnet_warning_cache or {}

        # Preserve insertion order so summary and details use the user-provided sequence.
        unique_networks_for_display = list(grouped_by_network.keys())
        if len(unique_networks_for_display) > 1:
            while True:
                selected_networks, return_to_summary = self._prompt_for_detail_selection(
                    ctx,
                    unique_networks_for_display,
                    grouped_by_network,
                    subnet_data_cache,
                    subnet_warning_cache,
                )
                if not selected_networks:
                    return
                self._print_selected_subnet_details(
                    ctx,
                    selected_networks,
                    grouped_by_network,
                    subnet_data_cache,
                    subnet_warning_cache,
                )
                if not return_to_summary:
                    return
        else:
            self._print_selected_subnet_details(
                ctx,
                unique_networks_for_display,
                grouped_by_network,
                subnet_data_cache,
                subnet_warning_cache,
            )

    def _prompt_for_detail_selection(
        self,
        ctx: ScriptContext,
        networks: List[ipaddress.IPv4Network],
        grouped_by_network: Dict[ipaddress.IPv4Network, List[str]],
        subnet_data_cache: Dict[str, Dict],
        subnet_warning_cache: Dict[str, List[str]],
    ) -> tuple[List[ipaddress.IPv4Network], bool]:
        colors = get_global_color_scheme(ctx.cfg)
        summary_data: List[Dict[str, str]] = []
        for index, network in enumerate(networks, start=1):
            net_info = subnet_data_cache.get(str(network), {})
            warnings = subnet_warning_cache.get(str(network), [])
            summary_state = self._build_summary_state(net_info, warnings)
            summary_net: Dict[str, str] = {
                "#": str(index),
                "Original Input(s)": ", ".join(grouped_by_network[network]),
                "Resolved Subnet": str(network),
                "Status": summary_state.status,
            }

            if net_info and net_info.get("general"):
                description = net_info["general"][0].get("description", "N/A")
                summary_net["Description"] = description
                ext_attrs_list = net_info.get("Extensible Attributes", [])
                ea_map = {attr.get("Attribute"): attr.get("Value") for attr in ext_attrs_list if attr.get("Attribute")}
                summary_net.update({
                    "Location": ea_map.get("Location", "N/A"),
                    "Region": ea_map.get("Region", "N/A"),
                    "Country": ea_map.get("Country", "N/A"),
                    "VLAN": ea_map.get("VLAN", "N/A"),
                })
                ad_info = net_info.get("Active Directory", [{}])[0]
                if ad_info:
                    summary_net["AD Site"] = ad_info.get("AD Site", "N/A")
            else:
                summary_net["Description"] = summary_state.description

            summary_data.append(summary_net)

        print_table_data(ctx, {"Subnet Summary": summary_data})

        while True:
            console = ctx.console
            console.print(
                f"\n[{colors['description']}]Detail view: "
                f"[{colors['success']}][Enter][/]/[{colors['success']}]A[/]=all, "
                f"[{colors['success']}]1-{len(networks)}[/]=one subnet, "
                f"[{colors['error']}][{colors['bold']}]Q[/]=return[/]"
            )
            choice = read_user_input(ctx, "Selection: ").strip().lower()
            if choice in ("", "a", "all"):
                return networks, False
            if choice == "q":
                return [], False
            if choice.isdigit():
                index = int(choice)
                if 1 <= index <= len(networks):
                    return [networks[index - 1]], True
            console.print(f"[{colors['error']}]Invalid selection. Use Enter, A, a result number, or Q.[/]")

    def _print_selected_subnet_details(
        self,
        ctx: ScriptContext,
        selected_networks: List[ipaddress.IPv4Network],
        grouped_by_network: Dict[ipaddress.IPv4Network, List[str]],
        subnet_data_cache: Dict[str, Dict],
        subnet_warning_cache: Dict[str, List[str]],
    ) -> None:
        colors = get_global_color_scheme(ctx.cfg)
        console = ctx.console
        total_selected = len(selected_networks)
        for index, network in enumerate(selected_networks, start=1):
            if total_selected > 1:
                console.print(f"\n[{colors['description']}]{'-' * 72}[/]")
            self._print_subnet_details(
                ctx,
                network,
                grouped_by_network[network],
                subnet_data_cache.get(str(network), {}),
                subnet_warning_cache.get(str(network), []),
                index=index,
                total=total_selected,
            )

    def _print_subnet_details(
        self,
        ctx: ScriptContext,
        network: ipaddress.IPv4Network,
        original_inputs: List[str],
        data: Dict[str, Any],
        warnings: List[str],
        *,
        index: int,
        total: int,
    ) -> None:
        colors = get_global_color_scheme(ctx.cfg)
        console = ctx.console
        inputs_str = ", ".join(f"'{inp}'" for inp in original_inputs)

        if total > 1:
            console.print(f"[{colors['description']}]Details [{index}/{total}] for: [{colors['header']} bold]{network}[/][/]")
        else:
            console.print(f"[{colors['description']}]Details for: [{colors['header']} bold]{network}[/][/]")
        console.print(f"[{colors['description']}] (Resolved from input(s): {inputs_str})[/]\n")

        if warnings:
            console.print(f"[{colors['warning']}]{format_partial_results_message(f'{len(warnings)} lookup issue(s) for {network}.')}[/]")
            for warning in warnings:
                console.print(f"[{colors['warning']}]Warning:[/] [{colors['error']}]{warning}[/]")

        if data:
            print_table_data(
                ctx,
                data,
                suffix={"general": "Information"},
                table_order=['general', 'DHCP range', 'DHCP options', 'DHCP members', 'DHCP failover', 'DNS records', 'fixed addresses'],
            )
            return

        if warnings:
            console.print(f"[{colors['warning']}]No subnet details available because one or more Infoblox lookups failed.[/]")
            return

        console.print(f"[{colors['error']}]{format_no_match_message('subnet records', str(network))}[/]")

    def _build_summary_state(self, data: Dict[str, Any], warnings: List[str]) -> SubnetSummaryState:
        has_primary_details = bool(data.get("general"))
        has_secondary_details = bool(data) and not has_primary_details
        has_warnings = bool(warnings)

        if has_primary_details and has_warnings:
            return SubnetSummaryState(status="Data with warnings", description="General subnet data with lookup warnings")
        if has_primary_details:
            return SubnetSummaryState(status="Data found", description="Subnet data available")
        if has_secondary_details and has_warnings:
            return SubnetSummaryState(status="Partial data with warnings", description="Partial subnet detail without general metadata")
        if has_secondary_details:
            return SubnetSummaryState(status="Partial data", description="Partial subnet detail without general metadata")
        if has_warnings:
            return SubnetSummaryState(status="Warnings only", description=warnings[0])
        return SubnetSummaryState(status="No data", description="No matching subnet records found")

    def _prepare_subnet_save_data(self, original_input: str, processed_data: Dict[str, Any]) -> List[RowDict]:
        """
        Prepares data for saving. The Original Input is only added to the main 'Subnet' row
        for improved report readability.
        """
        data_rows: List[RowDict] = []
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

        is_dhcp = "Y" if dhcp_members or dhcp_ranges else "N"
        main_row = {
            "Original Input": original_input,  # This is the main row, so it gets the input
            "IP": ip_part, "Mask": mask_part, "Name": "Subnet", "MAC": "",
            "DHCP": is_dhcp, "DHCP Scope Start": dhcp_ranges[0].get("start address", "") if dhcp_ranges else "",
            "DHCP Scope End": dhcp_ranges[0].get("end address", "") if dhcp_ranges else "",
            "DHCP Servers": "\n".join([f"{m['name']} - {m['IP Address']}" for m in dhcp_members]),
            "DHCP Options\nOption - Value": "\n".join([f"{o['name']} - {o['value']}" for o in dhcp_options]),
            "DHCP Failover Association": dhcp_failover[0].get("dhcp failover", "") if dhcp_failover else "",
            "Notes": general_info.get("description", "")
        }

        if ad_info:
            main_row.update({"AD Site": ad_info.get("AD Site", ""), "AD Location": ad_info.get("AD Location", ""), "AD Description": ad_info.get("AD Description", "")})
        data_rows.append(main_row)

        # **FIX:** Secondary rows no longer have the "Original Input" key.
        if ext_attrs:
            data_rows.append({
                "IP": ip_part, "Mask": mask_part,
                "Name": "\n".join([f"{a['Attribute']}:{a['Value']}" for a in ext_attrs]),
                "Notes": "Extensible Attributes Data"
            })
        for rec in dns_records:
            data_rows.append({
                "IP": rec.get("IP address"), "Mask": "/32",
                "Name": rec.get("A Record"), "Notes": "DNS record"
            })
        for fa in fixed_addrs:
            data_rows.append({
                "IP": fa.get("IP address"), "Mask": "/32",
                "Name": fa.get("name"), "MAC": fa.get("MAC"), "Notes": "Fixed IP"
            })
        return data_rows

    def _save_subnet_data(self, ctx: ScriptContext, query_targets: List[QueryTarget], all_data_to_save: List[List[RowDict]]) -> None:
        """
        Saves collected data, ensuring no pandas index is added to the output file.
        NOTE: Requires the `queue_save` utility to handle the `index=False` parameter.
        """
        # --- Save Summary Sheet ---
        summary_results: List[List[str]] = []
        seen_inputs = set()
        for target in query_targets:
            # Handle cases where one input resolves to multiple subnets (supernets)
            # but we only want one summary line per original input.
            if target.original_input in seen_inputs:
                continue
            status = "Data Found" if any(ds[0].get("Original Input") == target.original_input for ds in all_data_to_save) else "No Match / No Data"
            # Show the first resolved network for simplicity in summary
            summary_results.append([target.original_input, str(target.resolved_network), status])
            seen_inputs.add(target.original_input)

        if summary_results:
            columns_common = ["Original Input", "Resolved Subnet", "Status"]
            queue_save(ctx, columns_common, summary_results, sheet_name="Subnet Search Summary", force_header=True, index=False)

        # --- Save Detailed Data Sheet ---
        if all_data_to_save:
            all_row_dicts = [row for sublist in all_data_to_save for row in sublist]
            base_columns = [
                "Original Input", "IP", "Mask", "Name", "MAC", "DHCP", "DHCP Scope Start", "DHCP Scope End",
                "DHCP Servers", "DHCP Options\nOption - Value", "DHCP Failover Association", "Notes"
            ]
            discovered_headers = {}
            for row in all_row_dicts:
                for key in row.keys():
                    discovered_headers[key] = True
            final_columns = list(base_columns)
            for header in discovered_headers.keys():
                if header not in final_columns:
                    final_columns.append(header)
            data_to_write = [[row_dict.get(col, "") for col in final_columns] for row_dict in all_row_dicts]
            queue_save(ctx, final_columns, data_to_write, sheet_name="Subnet Data Detail", force_header=True, index=False)
