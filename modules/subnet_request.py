import argparse
import ipaddress
import json
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from functools import partial
from time import perf_counter
from typing import Any, Dict, List, Optional, Sequence, Set, Union

from rich.markup import escape

# Assuming these are your project's utility modules
from core.base import BaseModule, CliResult, ScriptContext, cli_exit_code
from utils.api import (
    WAPI_MAX_ROWS,
    bound_infoblox_workers,
    describe_infoblox_failure,
    request_result,
    request_result_with_inheritance,
)
from utils.auth import ensure_infoblox_auth
from utils.cli_input import read_objects
from utils.display import get_global_color_scheme, print_table_data
from utils.file_io import queue_save
from utils.infoblox_inheritance import normalize_record_fields
from utils.infoblox_ux import format_no_match_message, format_partial_results_message
from utils.process_data import CONTAINER_UTILIZATION_SCALE, process_data, utilization_percent
from utils.user_input import press_any_key, read_user_input

# Type alias for clarity
NetworkObject = Union[ipaddress.IPv4Network, ipaddress.IPv4Address]
RowDict = Dict[str, Any]

#: Tables of one subnet's details, in the order the menu shows them (the rest follow alphabetically).
DETAIL_TABLE_ORDER = ("general", "DHCP range", "DHCP options", "DHCP members", "DHCP failover", "DNS records", "fixed addresses")
#: The section (and menu table) listing the containers inside a container prefix; they are listed, never expanded.
CHILD_CONTAINERS = "child containers"
#: What ``cn subnet`` always returns besides ``subnets``, the child containers and ``warnings``, so the JSON keys do not depend on the data.
CLI_DETAIL_SECTIONS = (*DETAIL_TABLE_ORDER, "Extensible Attributes", "Active Directory")
TRUNCATION_NOTICE = f"showing the first {WAPI_MAX_ROWS:,} only (paging limit); query a smaller subnet"
MALFORMED_MESSAGE = "Not an IPv4 address or network."


@dataclass(frozen=True, eq=True)
class QueryTarget:
    """Represents a single query, linking an original input to a resolved network."""
    original_input: str
    resolved_network: ipaddress.IPv4Network


@dataclass(frozen=True)
class InputResolutionResult:
    networks: Set[ipaddress.IPv4Network]
    failure_message: str = ""
    containers: List[Dict[str, Any]] = field(default_factory=list)


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
    cli_name = "subnet"

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
            query_targets, resolution_errors, containers = self._resolve_inputs_to_targets(ctx, user_inputs)
            self._print_resolution_errors(ctx, resolution_errors)
            if not query_targets:
                if containers:  # only child containers: they are the answer, there is no subnet to look up
                    self._print_child_containers(ctx, containers)
                else:
                    console.print(f"[{colors['error']}]Could not resolve any of the provided inputs to a valid subnet.[{colors['error']}]")
                press_any_key(ctx)
                return

            # --- 3. Main Data Fetching and Processing ---
            # Fetch data for unique subnets only to avoid redundant API calls
            unique_networks = self._unique_networks(query_targets)
            logger.info(f"Resolved to {len(unique_networks)} unique subnets for data fetching.")
            console.print(f"[{colors['description']}]Found [{colors['success']}]{len(unique_networks)}[/] unique subnets to query.[/]")

            subnet_data_cache, subnet_warning_cache = self._fetch_subnets(ctx, unique_networks)

            # --- 4. Prepare data for display and saving ---
            grouped_by_network = self._group_by_network(query_targets)
            all_data_to_save = self._collect_save_data(ctx, grouped_by_network, subnet_data_cache)

            end = perf_counter()
            duration = round(end - start, 3)
            logger.info(f"Subnet Information search took {duration} seconds!")
            console.print(f"\n[{colors['description']}]Search took [{colors['success']}]{duration}[/] seconds![/]\n")

            # --- 5. Display and Save ---
            self._print_child_containers(ctx, containers)
            self._display_results(ctx, query_targets, subnet_data_cache, grouped_by_network, subnet_warning_cache)

            if ctx.cfg["report_auto_save"] and all_data_to_save:
                self._save_subnet_data(ctx, query_targets, all_data_to_save)

            self._publish_stats(ctx, len(user_inputs), query_targets, unique_networks, subnet_data_cache)
        finally:
            self.execute_hook('post_run', ctx, None)

        press_any_key(ctx)

    def run_cli(self, ctx: ScriptContext, args: argparse.Namespace) -> CliResult:
        """
        ``cn subnet``: the menu's lookup for the objects named on the command line, as sections.

        Nothing is asked of the user. An object that is not an IPv4 address or network, and one whose
        lookup failed, are reported on the console (stderr) with the reason. A well-formed address or
        network that is in no managed network is a "No data" row in ``subnets``. A container prefix also
        lists its child containers in ``child containers`` (not expanded); they count as data. The exit
        status follows ``cli_exit_code``: a failed lookup (even a partial one) 3, a malformed object 2,
        data 0, else 1.
        """
        self.execute_hook('pre_run', ctx, None)
        try:
            ctx.logger.info("Request Type - Subnet Information (command line)")
            inputs = read_objects(args.objects, args.file)
            if not inputs:
                return CliResult(cli_exit_code(found=False, invalid=True, failed=False), {})

            # Syntax is checked locally first: nobody is asked for credentials to reject "bogus".
            malformed = {item for item in inputs if not self._is_ipv4_network(item)}
            candidates = [item for item in inputs if item not in malformed]
            query_targets, resolution_errors, containers = [], {}, []
            if candidates:
                ensure_infoblox_auth(ctx)
                query_targets, resolution_errors, containers = self._resolve_inputs_to_targets(ctx, candidates)
            # An input that is only a container prefix, with child containers and no subnets, is answered too.
            resolved_inputs = {target.original_input for target in query_targets} | {row["container"] for row in containers}
            misses = [
                item for item in inputs
                if item not in resolved_inputs and item not in resolution_errors and item not in malformed
            ]
            self._print_resolution_errors(
                ctx,
                {item: resolution_errors.get(item, MALFORMED_MESSAGE) for item in inputs if item in resolution_errors or item in malformed},
            )
            invalid = bool(malformed)
            failed = bool(resolution_errors)
            if not query_targets:
                no_sections = self._build_cli_sections(ctx, [], {}, {}, {}, misses, containers)
                return CliResult(cli_exit_code(found=bool(containers), invalid=invalid, failed=failed), no_sections)

            unique_networks = self._unique_networks(query_targets)
            ctx.logger.info(f"Resolved to {len(unique_networks)} unique subnets for data fetching.")
            subnet_data_cache, subnet_warning_cache = self._fetch_subnets(ctx, unique_networks)

            grouped_by_network = self._group_by_network(query_targets)
            all_data_to_save = self._collect_save_data(ctx, grouped_by_network, subnet_data_cache)
            sections = self._build_cli_sections(
                ctx, list(grouped_by_network), grouped_by_network, subnet_data_cache, subnet_warning_cache, misses, containers,
            )
            if ctx.cfg["report_auto_save"] and all_data_to_save:
                self._save_subnet_data(ctx, query_targets, all_data_to_save)
            self._publish_stats(ctx, len(inputs), query_targets, unique_networks, subnet_data_cache)

            failed = failed or self._has_failed_lookup(subnet_warning_cache)
            return CliResult(cli_exit_code(found=bool(subnet_data_cache or containers), invalid=invalid, failed=failed), sections)
        finally:
            self.execute_hook('post_run', ctx, None)

    @staticmethod
    def _unique_networks(query_targets: List[QueryTarget]) -> List[ipaddress.IPv4Network]:
        """The distinct networks to query, by address."""
        return sorted({target.resolved_network for target in query_targets}, key=lambda net: net.network_address)

    @staticmethod
    def _group_by_network(query_targets: List[QueryTarget]) -> Dict[ipaddress.IPv4Network, List[str]]:
        """Original inputs per resolved network; the networks keep the order the user gave them."""
        grouped_by_network: Dict[ipaddress.IPv4Network, List[str]] = defaultdict(list)
        for target in query_targets:
            grouped_by_network[target.resolved_network].append(target.original_input)
        return grouped_by_network

    @staticmethod
    def _print_resolution_errors(ctx: ScriptContext, errors: Dict[str, str]) -> None:
        """One line per input that could not be resolved, with the reason."""
        colors = get_global_color_scheme(ctx.cfg)
        for original_input, message in errors.items():
            ctx.console.print(f"[{colors['warning']}]{escape(original_input)}[/] - [{colors['error']}]{escape(message)}[/]")

    @staticmethod
    def _print_child_containers(ctx: ScriptContext, containers: List[Dict[str, Any]]) -> None:
        """The child containers table, then one line per input saying they are listed, not expanded."""
        if not containers:
            return
        colors = get_global_color_scheme(ctx.cfg)
        print_table_data(ctx, {CHILD_CONTAINERS: containers})
        for prefix, count in Counter(row["container"] for row in containers).items():
            if count == 1:
                note = "1 child container (not expanded; query it to see its subnets)."
            else:
                note = f"{count} child containers (not expanded; query one to see its subnets)."
            ctx.console.print(f"[{colors['description']}]{prefix}: {note}[/]")

    def _fetch_subnets(
        self, ctx: ScriptContext, networks: List[ipaddress.IPv4Network]
    ) -> tuple[Dict[str, Dict], Dict[str, List[str]]]:
        """Fetch every network in parallel: (data, warnings), each keyed by the network's text, only when non-empty."""
        colors = get_global_color_scheme(ctx.cfg)
        subnet_data_cache: Dict[str, Dict] = {}
        subnet_warning_cache: Dict[str, List[str]] = {}
        with ctx.console.status(f"[{colors['description']}]Fetching subnets information...[/]"):
            with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, len(networks))) as executor:
                future_to_net = {
                    executor.submit(self._fetch_and_process_subnet_data, ctx, network): network
                    for network in networks
                }

                for future in as_completed(future_to_net):
                    net_str = str(future_to_net[future])
                    ctx.console.print(f"[{colors['description']}]Processing results for [{colors['header']}]{net_str}[/]...[/]")
                    outcome = future.result()
                    if outcome.data:
                        subnet_data_cache[net_str] = outcome.data
                    if outcome.warnings:
                        subnet_warning_cache[net_str] = outcome.warnings
        return subnet_data_cache, subnet_warning_cache

    def _collect_save_data(
        self,
        ctx: ScriptContext,
        grouped_by_network: Dict[ipaddress.IPv4Network, List[str]],
        subnet_data_cache: Dict[str, Dict],
    ) -> List[List[RowDict]]:
        """The report rows of every network with data, after the ``pre_save`` hook; empty unless saving is on."""
        all_data_to_save: List[List[RowDict]] = []
        for network, original_inputs in grouped_by_network.items():
            data = subnet_data_cache.get(str(network), {})

            if ctx.cfg["report_auto_save"] and data:
                combined_input_str = ", ".join(original_inputs)
                save_data = self._prepare_subnet_save_data(combined_input_str, data)
                save_data = self.execute_hook('pre_save', ctx, save_data)
                if save_data:
                    all_data_to_save.append(save_data)
        return all_data_to_save

    @staticmethod
    def _publish_stats(
        ctx: ScriptContext,
        input_count: int,
        query_targets: List[QueryTarget],
        unique_networks: List[ipaddress.IPv4Network],
        subnet_data_cache: Dict[str, Dict],
    ) -> None:
        ctx.event_bus.publish(
            "stats:module_detail",
            {
                "unit_count": len(unique_networks),
                "input_count": input_count,
                "unique_count": len(unique_networks),
                "resolved_target_count": len(query_targets),
                "success_count": len(subnet_data_cache),
                "miss_count": max(0, len(unique_networks) - len(subnet_data_cache)),
            },
        )

    @staticmethod
    def _has_failed_lookup(subnet_warning_cache: Dict[str, List[str]]) -> bool:
        """True when any warning is a failed Infoblox lookup rather than only the paging-limit notice."""
        return any(
            not warning.endswith(f": {TRUNCATION_NOTICE}")
            for warnings in subnet_warning_cache.values()
            for warning in warnings
        )

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

    def _resolve_inputs_to_targets(
        self, ctx: ScriptContext, inputs: List[str]
    ) -> tuple[List[QueryTarget], Dict[str, str], List[Dict[str, Any]]]:
        """
        Takes raw user input strings and resolves them into an ordered list of QueryTarget objects.
        This preserves the original input and its order. Also returns the errors by input and the
        child containers of every container prefix, which are listed but never expanded.
        """
        all_targets: List[QueryTarget] = []
        errors: Dict[str, str] = {}
        containers: List[Dict[str, Any]] = []
        with ctx.console.status(f"[{get_global_color_scheme(ctx.cfg)['description']}]Resolving inputs and finding subnets...[/]"):
            # Using executor.map preserves the order of the inputs
            with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, len(inputs))) as executor:
                results_generator = executor.map(lambda item: self._resolve_single_input_detailed(ctx, item), inputs)
                for original_input, resolution in zip(inputs, results_generator):
                    if resolution.failure_message:
                        errors[original_input] = resolution.failure_message
                    containers.extend(resolution.containers)
                    if not resolution.networks:
                        if not resolution.containers:
                            ctx.logger.warning(f"Could not resolve '{original_input}' to any subnet.")
                        continue
                    # Sort to ensure consistent order for supernets
                    for net in sorted(list(resolution.networks), key=lambda ip: ip.network_address):
                        all_targets.append(QueryTarget(original_input=original_input, resolved_network=net))
        return all_targets, errors, containers

    def _resolve_single_input(self, ctx: ScriptContext, an_input: str) -> Set[ipaddress.IPv4Network]:
        return self._resolve_single_input_detailed(ctx, an_input).networks

    @staticmethod
    def _parse_ipv4_network(text: str) -> ipaddress.IPv4Network:
        """What the resolver accepts: an IPv4 address (a /32), CIDR or address/mask; ValueError otherwise."""
        net = ipaddress.ip_network(text, strict=False)
        if not isinstance(net, ipaddress.IPv4Network):
            raise ValueError("Only IPv4 is supported.")
        return net

    @classmethod
    def _is_ipv4_network(cls, text: str) -> bool:
        try:
            cls._parse_ipv4_network(text)
        except ValueError:
            return False
        return True

    def _resolve_single_input_detailed(self, ctx: ScriptContext, an_input: str) -> InputResolutionResult:
        """
        Worker function to resolve a single input string into one or more network objects.
        """
        try:
            net = self._parse_ipv4_network(an_input)
            if net.prefixlen == 32:
                result = request_result(ctx, f'network?contains_address={net.network_address}', ensure_auth=False)
                if result.ok and result.has_items and 'network' in result.items[0]:
                    return InputResolutionResult(networks={ipaddress.IPv4Network(result.items[0]['network'])})
                if result.failed:
                    return InputResolutionResult(networks=set(), failure_message=describe_infoblox_failure(result))
                return InputResolutionResult(networks=set())
            elif net.prefixlen < 30:
                result = request_result(ctx, f'network?network_container={net.compressed}', ensure_auth=False)
                found_subnets: Set[ipaddress.IPv4Network] = set()
                if result.ok:
                    supernet_data = process_data(ctx, type='supernet', content=result.content)
                    found_subnets = {ipaddress.IPv4Network(sub["network"]) for sub in supernet_data.get("subnets", [])}
                elif result.failed:
                    return InputResolutionResult(networks=set(), failure_message=describe_infoblox_failure(result))
                # The child containers are listed, not expanded. A failed lookup is reported next to what
                # the first one found, so a grid that refuses it still answers for a plain /24.
                container_result = request_result(
                    ctx,
                    f'networkcontainer?network_container={net.compressed}&_return_fields=network,comment,utilization',
                    ensure_auth=False,
                )
                containers = self._child_container_rows(an_input, container_result.items) if container_result.ok else []
                failure = describe_infoblox_failure(container_result) if container_result.failed else ""
                networks = found_subnets or ({net} if not containers else set())
                return InputResolutionResult(networks=networks, failure_message=failure, containers=containers)
            return InputResolutionResult(networks={net})
        except ValueError:
            ctx.logger.warning(f"Invalid IP/Subnet format for input: '{an_input}'")
            return InputResolutionResult(networks=set())
        except Exception as e:
            ctx.logger.error(f"Error resolving input '{an_input}': {e}")
            return InputResolutionResult(networks=set(), failure_message="Subnet resolution failed.")

    @staticmethod
    def _child_container_rows(container: str, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """``networkcontainer`` records as ``child containers`` rows, by address; the first of a repeated network wins."""
        children: Dict[ipaddress.IPv4Network, Dict[str, Any]] = {}
        for item in items:
            if "network" in item:
                children.setdefault(ipaddress.IPv4Network(item["network"]), item)
        return [
            {
                "container": container,
                "child container": str(child),
                "comment": children[child].get("comment", ""),
                "utilization %": utilization_percent(children[child].get("utilization"), CONTAINER_UTILIZATION_SCALE),
            }
            for child in sorted(children)
        ]

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
        paged_request = partial(request_result, paged=True)  # these lists can outgrow one WAPI page
        request_specs = {
            "network bundle": {
                "uri": f"network?network={net_str}&_return_fields=network,comment,extattrs,options,members,dhcp_utilization",
                "parser_types": ("general", "network options"),
                "warning_labels": ("general", "network options"),
                "request_fn": request_result_with_inheritance,
            },
            "DNS records": {
                "uri": f"ipv4address?network={net_str}&usage=DNS&_return_fields=ip_address,names",
                "parser_types": ("DNS records",),
                "warning_labels": ("DNS records",),
                "request_fn": paged_request,
            },
            "range bundle": {
                "uri": (
                    f"range?network={net_str}&_return_fields=network,start_addr,end_addr,member,failover_association,"
                    "dhcp_utilization,dhcp_utilization_status,dynamic_hosts,static_hosts,total_hosts"
                ),
                "parser_types": ("DHCP range", "DHCP failover"),
                "warning_labels": ("DHCP range", "DHCP failover"),
                "request_fn": paged_request,
            },
            "fixed addresses": {
                "uri": f"fixedaddress?network={net_str}&_return_fields=ipv4addr,mac,name",
                "parser_types": ("fixed addresses",),
                "warning_labels": ("fixed addresses",),
                "request_fn": paged_request,
            },
        }
        processed_data_for_net: Dict[str, Any] = defaultdict(list)
        warnings: List[str] = []
        with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, len(request_specs))) as executor:
            future_to_label = {
                executor.submit(spec["request_fn"], ctx, spec["uri"], ensure_auth=False): label
                for label, spec in request_specs.items()
            }
            for future in as_completed(future_to_label):
                label = future_to_label[future]
                spec = request_specs[label]
                try:
                    result = future.result()
                    notice = ""
                    if result.ok:
                        raw_data = None
                        if label == "network bundle":
                            raw_data = [
                                normalize_record_fields(
                                    item,
                                    scalar_fields=("comment",),
                                    extattrs_fields=("extattrs",),
                                    list_struct_fields=("options", "members"),
                                )
                                for item in result.items
                            ]
                        payload_content = json.dumps(raw_data).encode() if raw_data is not None else result.content
                        for parser_type in spec["parser_types"]:
                            processed_data_for_net.update(process_data(ctx, type=parser_type, content=payload_content))
                        if result.truncated:
                            notice = TRUNCATION_NOTICE
                    elif result.failed:
                        notice = describe_infoblox_failure(result)
                    if notice:
                        for warning_label in spec["warning_labels"]:
                            warnings.append(f"{warning_label}: {notice}")
                except Exception as e:
                    ctx.logger.error(f"Failed to fetch data for '{label}' in {net_str}: {e}")
                    for warning_label in spec["warning_labels"]:
                        warnings.append(f"{warning_label}: request processing failed.")
        if not processed_data_for_net.get("DHCP range"):
            # WAPI answers 0 for a network that has no DHCP range, which would read as "idle DHCP".
            for general_row in processed_data_for_net.get("general", []):
                general_row["DHCP utilization %"] = ""
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

    def _build_summary_rows(
        self,
        ctx: ScriptContext,
        networks: List[ipaddress.IPv4Network],
        grouped_by_network: Dict[ipaddress.IPv4Network, List[str]],
        subnet_data_cache: Dict[str, Dict],
        subnet_warning_cache: Dict[str, List[str]],
    ) -> List[Dict[str, str]]:
        """One summary row per network, in the order given: the menu's selection list and ``cn subnet``'s ``subnets``."""
        summary_data: List[Dict[str, str]] = []
        any_inherited = False
        for network in networks:
            net_info = subnet_data_cache.get(str(network), {})
            warnings = subnet_warning_cache.get(str(network), [])
            summary_state = self._build_summary_state(net_info, warnings)
            summary_net: Dict[str, str] = {
                "Original Input(s)": ", ".join(grouped_by_network[network]),
                "Resolved Subnet": str(network),
                "Status": summary_state.status,
            }

            if net_info and net_info.get("general"):
                description = net_info["general"][0].get("description", "N/A")
                summary_net["Description"] = description
                ext_attrs_list = net_info.get("Extensible Attributes", [])
                ea_map = {attr.get("Attribute"): attr.get("Value") for attr in ext_attrs_list if attr.get("Attribute")}
                inherited_fields = self._collect_summary_inherited_fields(net_info)
                summary_net.update({
                    "Location": ea_map.get("Location", "N/A"),
                    "Region": ea_map.get("Region", "N/A"),
                    "Country": ea_map.get("Country", "N/A"),
                    "VLAN": ea_map.get("VLAN", "N/A"),
                    "DHCP utilization %": net_info["general"][0].get("DHCP utilization %", ""),
                })
                if inherited_fields:
                    summary_net["inherited"] = ", ".join(inherited_fields)
                    any_inherited = True
                ad_info = net_info.get("Active Directory", [{}])[0]
                if ad_info:
                    summary_net["AD Site"] = ad_info.get("AD Site", "N/A")
            else:
                summary_net["Description"] = summary_state.description

            summary_data.append(summary_net)

        if any_inherited:
            for row in summary_data:
                row.setdefault("inherited", "")
        return summary_data

    def _build_cli_sections(
        self,
        ctx: ScriptContext,
        networks: List[ipaddress.IPv4Network],
        grouped_by_network: Dict[ipaddress.IPv4Network, List[str]],
        subnet_data_cache: Dict[str, Dict],
        subnet_warning_cache: Dict[str, List[str]],
        misses: Sequence[str] = (),
        containers: Sequence[Dict[str, Any]] = (),
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        The sections of a ``cn subnet`` result: ``subnets`` (the summary, then a "No data" row with no
        resolved subnet for each of ``misses``, the well-formed inputs that are in no network),
        ``child containers`` (``containers``: the containers inside a container prefix, listed and not
        expanded), each detail table over all networks with the network as its first column, then ``warnings``.

        Detail tables come in the menu's order, the rest alphabetically; the ones every run has (see
        ``CLI_DETAIL_SECTIONS``) are present even when empty.
        """
        details: Dict[str, List[Dict[str, Any]]] = {name: [] for name in CLI_DETAIL_SECTIONS}
        for network in networks:
            net_str = str(network)
            for name, rows in subnet_data_cache.get(net_str, {}).items():
                details.setdefault(name, []).extend(
                    {"network": net_str, **{key: value for key, value in row.items() if key != "network"}} for row in rows
                )

        no_data = self._build_summary_state({}, [])
        miss_rows = [
            {"Original Input(s)": item, "Resolved Subnet": "", "Status": no_data.status, "Description": no_data.description}
            for item in misses
        ]
        sections: Dict[str, List[Dict[str, Any]]] = {
            "subnets": [
                *self._build_summary_rows(ctx, networks, grouped_by_network, subnet_data_cache, subnet_warning_cache),
                *miss_rows,
            ],
            CHILD_CONTAINERS: list(containers),
        }
        ordered = [*DETAIL_TABLE_ORDER, *sorted(name for name in details if name not in DETAIL_TABLE_ORDER)]
        sections.update({name: details[name] for name in ordered})
        sections["warnings"] = [
            {"network": str(network), "warning": warning}
            for network in networks
            for warning in subnet_warning_cache.get(str(network), [])
        ]
        return sections

    def _prompt_for_detail_selection(
        self,
        ctx: ScriptContext,
        networks: List[ipaddress.IPv4Network],
        grouped_by_network: Dict[ipaddress.IPv4Network, List[str]],
        subnet_data_cache: Dict[str, Dict],
        subnet_warning_cache: Dict[str, List[str]],
    ) -> tuple[List[ipaddress.IPv4Network], bool]:
        colors = get_global_color_scheme(ctx.cfg)
        summary_rows = self._build_summary_rows(ctx, networks, grouped_by_network, subnet_data_cache, subnet_warning_cache)
        summary_data = [{"#": str(index), **row} for index, row in enumerate(summary_rows, start=1)]

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
                table_order=list(DETAIL_TABLE_ORDER),
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
        inherited_fields = self._collect_save_inherited_fields(processed_data)
        has_decoded_options = any(option.get("decoded value") for option in dhcp_options)

        is_dhcp = "Y" if dhcp_members or dhcp_ranges else "N"
        main_row = {
            "Original Input": original_input,  # This is the main row, so it gets the input
            "IP": ip_part, "Mask": mask_part, "Name": "Subnet", "MAC": "",
            "DHCP": is_dhcp, "DHCP Scope Start": dhcp_ranges[0].get("start address", "") if dhcp_ranges else "",
            "DHCP Scope End": dhcp_ranges[0].get("end address", "") if dhcp_ranges else "",
            "DHCP Servers": "\n".join([f"{m['name']} - {m['IP Address']}" for m in dhcp_members]),
            "DHCP Options\nOption - Value": "\n".join([f"{o['name']} - {o['value']}" for o in dhcp_options]),
            "DHCP Options\nOption - Decoded Value": "\n".join([
                f"{o['name']} - {o.get('decoded value', '')}" for o in dhcp_options
            ]) if has_decoded_options else "",
            "DHCP Failover Association": dhcp_failover[0].get("dhcp failover", "") if dhcp_failover else "",
            "Notes": general_info.get("description", ""),
            "Inherited Fields": ", ".join(inherited_fields),
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

    def _collect_summary_inherited_fields(self, processed_data: Dict[str, Any]) -> List[str]:
        inherited_fields: List[str] = []
        general_info = processed_data.get("general", [{}])[0]
        if general_info.get("inherited"):
            inherited_fields.append("Description")

        for attr in processed_data.get("Extensible Attributes", []):
            if attr.get("inherited") and attr.get("Attribute") in {"Location", "Region", "Country", "VLAN"}:
                inherited_fields.append(str(attr.get("Attribute")))

        # Preserve display order while removing duplicates.
        return list(dict.fromkeys(inherited_fields))

    def _collect_save_inherited_fields(self, processed_data: Dict[str, Any]) -> List[str]:
        inherited_fields = self._collect_summary_inherited_fields(processed_data)

        if any(row.get("inherited") for row in processed_data.get("DHCP options", [])):
            inherited_fields.append("DHCP options")
        if any(row.get("inherited") for row in processed_data.get("DHCP members", [])):
            inherited_fields.append("DHCP members")

        return list(dict.fromkeys(inherited_fields))

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
                "DHCP Servers", "DHCP Options\nOption - Value", "DHCP Options\nOption - Decoded Value",
                "DHCP Failover Association", "Notes"
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
