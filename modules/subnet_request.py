import argparse
import ipaddress
import json
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from functools import partial
from time import perf_counter
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

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
from utils.network_views import (
    NETWORK_VIEW,
    NETWORK_VIEW_TITLE,
    ViewScope,
    present_rows,
    scope_network,
    view_scope,
)
from utils.process_data import CONTAINER_UTILIZATION_SCALE, process_data, utilization_percent
from utils.user_input import press_any_key, read_user_input
from utils.validation import ipv6_form_problem

# Type aliases for clarity: a network of either family, and what a lookup may start from.
Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
NetworkObject = Union[ipaddress.IPv4Network, ipaddress.IPv6Network, ipaddress.IPv4Address, ipaddress.IPv6Address]
RowDict = Dict[str, Any]

#: Tables of one subnet's details, in the order the menu shows them (the rest follow alphabetically).
DETAIL_TABLE_ORDER = ("general", "DHCP range", "DHCP options", "DHCP members", "DHCP failover", "DNS records", "fixed addresses")
#: The section (and menu table) listing the containers inside a container prefix; they are listed, never expanded.
CHILD_CONTAINERS = "child containers"
#: What ``cn subnet`` always returns besides ``subnets``, the child containers and ``warnings``, so the JSON keys do not depend on the data.
CLI_DETAIL_SECTIONS = (*DETAIL_TABLE_ORDER, "Extensible Attributes", "Active Directory")
TRUNCATION_NOTICE = f"showing the first {WAPI_MAX_ROWS:,} only (paging limit); query a smaller subnet"
#: The paging notice when the truncated list holds several network views: the cap is shared by all of them.
_SHARED_CAP_HEAD = f"showing the first {WAPI_MAX_ROWS:,} only (paging limit), shared by network views "
_SHARED_CAP_TAIL = "; query a smaller subnet or use --view"
MALFORMED_MESSAGE = "Not an IP address or network."

#: Every WAPI lookup of ``cn subnet``, by address family and purpose. ``{address}`` is the network address
#: and ``{cidr}`` the network as ``str(network)``; every URI then goes through ``scope_network``. The IPv4
#: entries are the strings the requests were always built from. IPv6 asks only for the fields its objects
#: have: ``ipv6network`` has no ``dhcp_utilization`` (WAPI answers 400 to it), ``ipv6range`` has no
#: ``failover_association`` and no utilisation or host counts, and ``ipv6fixedaddress`` has the DUID.
WAPI_URIS: Dict[int, Dict[str, str]] = {
    4: {
        "contains": "network?contains_address={address}",
        "children": "network?network_container={cidr}",
        "child containers": "networkcontainer?network_container={cidr}&_return_fields=network,comment,utilization,network_view",
        "exact": "network?network={cidr}&_return_fields=network,network_view",
        "network bundle": "network?network={cidr}&_return_fields=network,comment,extattrs,options,members,dhcp_utilization,network_view",
        "DNS records": "ipv4address?network={cidr}&usage=DNS&_return_fields=ip_address,names,network_view",
        "range bundle": (
            "range?network={cidr}&_return_fields=network,start_addr,end_addr,member,failover_association,"
            "dhcp_utilization,dhcp_utilization_status,dynamic_hosts,static_hosts,total_hosts,network_view"
        ),
        "fixed addresses": "fixedaddress?network={cidr}&_return_fields=ipv4addr,mac,name,network_view",
    },
    6: {
        "contains": "ipv6network?contains_address={address}",
        "children": "ipv6network?network_container={cidr}",
        "child containers": "ipv6networkcontainer?network_container={cidr}&_return_fields=network,comment,utilization,network_view",
        "exact": "ipv6network?network={cidr}&_return_fields=network,network_view",
        "network bundle": "ipv6network?network={cidr}&_return_fields=network,comment,extattrs,options,members,network_view",
        "DNS records": "ipv6address?network={cidr}&usage=DNS&_return_fields=ip_address,names,network_view",
        "range bundle": "ipv6range?network={cidr}&_return_fields=network,start_addr,end_addr,member,network_view",
        "fixed addresses": "ipv6fixedaddress?network={cidr}&_return_fields=ipv6addr,duid,mac_address,name,network_view",
    },
}
#: The sections the range answer feeds, which are also its warning labels; IPv6 has no failover section.
RANGE_SECTIONS: Dict[int, Tuple[str, ...]] = {4: ("DHCP range", "DHCP failover"), 6: ("DHCP range",)}
#: The column of a fixed address's DHCPv6 identity (JSON ``duid``), shown whenever the run has an IPv6 object.
DUID = "DUID"


def _view_of(network: Network) -> str:
    """The network view a target network belongs to; "" for a plain network (no view known)."""
    return getattr(network, "network_view", "")


def _in_view(network: Network) -> str:
    """" in network view lab" for a network of a view, else "": the words a menu line adds after the network."""
    view = _view_of(network)
    return f" in network view {view}" if view else ""


def _cache_key(network: Network) -> str:
    """The key of a network's data and warnings: its CIDR, and ``(view)`` after it for a network of a view."""
    view = _view_of(network)
    return f"{network} ({view})" if view else str(network)


def _network_order(network: Network) -> Tuple[int, int, int, str]:
    """
    Sort key: address family, address, prefix length, then view. IPv4 sorts before IPv6, so a mixed run
    never compares an IPv4 object with an IPv6 one using ``<`` (that raises TypeError), and an IPv4 run
    sorts as it always did. Plain and view networks are never compared with ``<`` either.
    """
    return network.version, int(network.network_address), network.prefixlen, _view_of(network)


def _host_mask(address: str) -> str:
    """The mask of a single address in the report: ``/128`` for an IPv6 address, else ``/32``."""
    return "/128" if ":" in (address or "") else "/32"


def _with_duid(rows: List[RowDict], duid: bool) -> List[RowDict]:
    """
    ``rows`` with the ``DUID`` column on every row when ``duid`` is set (the run has an IPv6 object): a row
    that has none gets it empty, after its other keys. Without ``duid`` the rows are handed back as they are.
    """
    if not duid:
        return rows
    return [{**row, DUID: row.get(DUID, "")} for row in rows]


def _wapi_uri(purpose: str, network: Network, network_view: str = "") -> str:
    """The lookup ``purpose`` (a key of ``WAPI_URIS``) for ``network``, in the table of its family, limited to one view."""
    template = WAPI_URIS[network.version][purpose]
    return scope_network(template.format(address=str(network.network_address), cidr=str(network)), network_view)


def _is_truncation(warning: str) -> bool:
    """True for either paging notice: the plain one, or the one that names the views sharing the cap."""
    return warning.endswith(f": {TRUNCATION_NOTICE}") or (
        f": {_SHARED_CAP_HEAD}" in warning and warning.endswith(_SHARED_CAP_TAIL)
    )


def _truncation_notice(views: Iterable[str]) -> str:
    """The paging notice for a list whose items name ``views``: the shared-cap one when several views share it."""
    named = sorted({view for view in views if view})
    if len(named) > 1:
        return f"{_SHARED_CAP_HEAD}{', '.join(named)}{_SHARED_CAP_TAIL}"
    return TRUNCATION_NOTICE


def _view_partitions(items: List[Any]) -> Dict[str, List[Any]]:
    """The items of an answer grouped by their ``network_view``, in the order the views first appear; "" holds the unlabelled."""
    groups: Dict[str, List[Any]] = {}
    for item in items:
        groups.setdefault(str(item.get("network_view") or ""), []).append(item)
    return groups


def _content_partitions(content: Optional[bytes]) -> Dict[str, Optional[bytes]]:
    """
    An answer's JSON content split by network view, each part as JSON again. An answer that names no
    view (or is not a list) comes back as it is under "", the very bytes: that is today's data.
    """
    try:
        items = json.loads(content)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        items = None
    if not isinstance(items, list):
        return {"": content}
    groups = _view_partitions(items)
    if set(groups) <= {""}:
        return {"": content}
    return {view: json.dumps(group).encode() for view, group in groups.items()}


class _InView:
    """
    What a network of one Infoblox network view shares in both address families: it prints and behaves
    as its CIDR, and carries the view.

    Equality and hash include the view, so the same CIDR in two views makes two dictionary keys. A plain
    network (no view known) never equals a view network; Python tries the subclass's ``__eq__`` first for
    the reflected comparison, so that holds both ways, and networks of the two families never compare
    equal (``ipaddress`` compares the version first). Build one only for a non-empty view.
    """

    network_view: str

    def __init__(self, address: Any, network_view: str) -> None:
        if not network_view:
            raise ValueError(f"A {type(self).__name__} needs a network view; use a plain network for none.")
        super().__init__(str(address))  # type: ignore[call-arg]
        self.network_view = network_view

    def __eq__(self, other: object) -> bool:
        return super().__eq__(other) is True and self.network_view == _view_of(other)  # type: ignore[arg-type]

    def __hash__(self) -> int:
        return hash((super().__hash__(), self.network_view))

    def __repr__(self) -> str:
        return f"{type(self).__name__}({str(self)!r}, {self.network_view!r})"

    def __reduce__(self) -> Tuple[Any, Tuple[str, str]]:
        return type(self), (str(self), self.network_view)


class ViewNetwork(_InView, ipaddress.IPv4Network):
    """An IPv4 network of one network view (see ``_InView``)."""


class ViewNetwork6(_InView, ipaddress.IPv6Network):
    """An IPv6 network of one network view (see ``_InView``)."""


def _make_network(address: Any, network_view: str = "") -> Network:
    """
    The one place that builds a target network: a ViewNetwork or ViewNetwork6 (by family) when the
    answer item names a view, else a plain network. ``address`` must be a canonical network, as the
    grid answers it.
    """
    network = ipaddress.ip_network(str(address))
    if not network_view:
        return network
    return (ViewNetwork6 if network.version == 6 else ViewNetwork)(network, network_view)


@dataclass(frozen=True, eq=True)
class QueryTarget:
    """Represents a single query, linking an original input to a resolved network."""
    original_input: str
    resolved_network: Network


@dataclass(frozen=True)
class InputResolutionResult:
    networks: Set[Network]
    failure_message: str = ""
    containers: List[Dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class SubnetFetchOutcome:
    """
    What the four lookups of one CIDR returned. ``data`` is the part of the answers that named no
    network view (today's data); ``by_view`` has one entry for each view the answers named. The
    warnings belong to the CIDR, so every view shares them.
    """
    data: Dict[str, Any]
    warnings: List[str]
    by_view: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass(frozen=True)
class SubnetSummaryState:
    status: str
    description: str


class SubnetRequestModule(BaseModule):
    """
    Module to fetch detailed information for one or more subnets from an API.
    It accepts input as plain IPs, CIDR notation (e.g., 1.2.3.0/24, 2001:db8:20::/64), or
    IPv4 address/subnet mask (e.g., 1.2.3.0/255.255.255.0), of either address family; a mixed
    run keeps the order of the inputs, whatever their family.
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
        Orchestrates user input, data fetching, processing, and display. A configured network view
        (``[api] network_view``) is checked before anything is asked, and named under the instructions.
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

            # A configured network view must exist: say so before the user types anything.
            scope = view_scope(ctx, None, request_result)
            view_problem = scope.problem()
            if view_problem:
                console.print(f"[{colors['error']}]{escape(view_problem.message)}[/]")
                press_any_key(ctx)
                return
            banner = scope.banner()

            # --- 1. Get User Input ---
            user_inputs = self._get_networks_from_user(ctx, banner) if banner else self._get_networks_from_user(ctx)
            if not user_inputs:
                return

            logger.info(f"User provided inputs: {', '.join(user_inputs)}")
            duid = self._has_ipv6_object(user_inputs)  # the report's DUID column follows the input, never the answers
            start = perf_counter()

            # --- 2. Resolve all inputs into an ordered list of query targets ---
            query_targets, resolution_errors, containers = self._resolve_inputs_to_targets(ctx, user_inputs, scope.requested)
            self._print_resolution_errors(ctx, resolution_errors)
            if not query_targets:
                if containers:  # only child containers: they are the answer, there is no subnet to look up
                    *_, containers, _ = self._settle_views(ctx, scope, [], {}, {}, {}, containers)
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

            subnet_data_cache, subnet_warning_cache, views_by_network = self._fetch_subnets(ctx, unique_networks, scope.requested)

            # --- 4. Prepare data for display and saving ---
            query_targets, subnet_data_cache, subnet_warning_cache, containers, save_view = self._settle_views(
                ctx, scope, query_targets, subnet_data_cache, subnet_warning_cache, views_by_network, containers,
            )
            grouped_by_network = self._group_by_network(query_targets)
            all_data_to_save = self._collect_save_data(ctx, grouped_by_network, subnet_data_cache, save_view=save_view)

            end = perf_counter()
            duration = round(end - start, 3)
            logger.info(f"Subnet Information search took {duration} seconds!")
            console.print(f"\n[{colors['description']}]Search took [{colors['success']}]{duration}[/] seconds![/]\n")

            # --- 5. Display and Save ---
            self._print_child_containers(ctx, containers)
            self._display_results(ctx, query_targets, subnet_data_cache, grouped_by_network, subnet_warning_cache)

            if ctx.cfg["report_auto_save"] and all_data_to_save:
                self._save_subnet_data(ctx, query_targets, all_data_to_save, duid=duid)

            self._publish_stats(ctx, len(user_inputs), query_targets, list(grouped_by_network), subnet_data_cache)
        finally:
            self.execute_hook('post_run', ctx, None)

        press_any_key(ctx)

    def run_cli(self, ctx: ScriptContext, args: argparse.Namespace) -> CliResult:
        """
        ``cn subnet``: the menu's lookup for the objects named on the command line, as sections.

        Nothing is asked of the user. An object that is not an IP address or network (IPv4 or IPv6), and
        one whose lookup failed, are reported on the console (stderr) with the reason; an IPv6 spelling
        Infoblox cannot store (IPv4-mapped, zone ID) is refused before any login, with the form to type
        instead. A well-formed address or network that is in no managed network is a "No data" row in
        ``subnets``. A container prefix also lists its child containers in ``child containers`` (not
        expanded); they count as data. The exit status follows ``cli_exit_code``: a failed lookup (even a
        partial one) 3, a malformed or refused object 2, data 0, else 1.

        IPv6 subnets have no DHCP utilisation and no failover in Infoblox, so those cells are empty. When
        the run has an IPv6 object (an address or a prefix), every ``fixed addresses`` row has a ``DUID``
        column (JSON ``duid``), empty for an IPv4 address; an IPv4 run has none.

        A network that exists in several views has a row for each of them (``Network view``, JSON
        ``network_view``); ``--view`` / ``[api] network_view`` limit the search to one view. A view that
        is not on the grid ends the run with 2, a view list that cannot be read with 3, both after the
        login and before any lookup, with an empty result.
        """
        self.execute_hook('pre_run', ctx, None)
        try:
            ctx.logger.info("Request Type - Subnet Information (command line)")
            inputs = read_objects(args.objects, args.file)
            if not inputs:
                return CliResult(cli_exit_code(found=False, invalid=True, failed=False), {})

            # Syntax is checked locally first: nobody is asked for credentials to reject "bogus" or a
            # spelling Infoblox cannot store (IPv4-mapped, zone ID), and each object gets its own reason.
            problems = {item: self._network_problem(item) for item in inputs}
            malformed = {item for item, problem in problems.items() if problem}
            candidates = [item for item in inputs if item not in malformed]
            # DUID shows in the fixed addresses and in the saved report whenever the run has an IPv6 object:
            # a column rule taken from the input, never from which rows came back (the rule ``cn ip`` follows too).
            duid = self._has_ipv6_object(candidates)
            scope = view_scope(ctx, args, request_result)
            query_targets, resolution_errors, containers = [], {}, []
            if candidates:
                ensure_infoblox_auth(ctx)
                view_problem = scope.problem()
                if view_problem:  # a view that is not on the grid, or a grid that cannot say: nothing is looked up
                    ctx.console.print(f"cn subnet: {view_problem.message}", markup=False)
                    return CliResult(view_problem.exit_code, {})
                query_targets, resolution_errors, containers = self._resolve_inputs_to_targets(ctx, candidates, scope.requested)
            # An input that is only a container prefix, with child containers and no subnets, is answered too.
            resolved_inputs = {target.original_input for target in query_targets} | {row["container"] for row in containers}
            misses = [
                item for item in inputs
                if item not in resolved_inputs and item not in resolution_errors and item not in malformed
            ]
            self._print_resolution_errors(
                ctx,
                {item: resolution_errors.get(item) or problems[item] for item in inputs if item in resolution_errors or item in malformed},
            )
            invalid = bool(malformed)
            failed = bool(resolution_errors)
            if not query_targets:
                *_, containers, _ = self._settle_views(ctx, scope, [], {}, {}, {}, containers)
                no_sections = self._build_cli_sections(
                    ctx, [], {}, {}, {}, misses, containers, fallback_view=scope.requested, duid=duid,
                )
                return CliResult(cli_exit_code(found=bool(containers), invalid=invalid, failed=failed), no_sections)

            unique_networks = self._unique_networks(query_targets)
            ctx.logger.info(f"Resolved to {len(unique_networks)} unique subnets for data fetching.")
            subnet_data_cache, subnet_warning_cache, views_by_network = self._fetch_subnets(ctx, unique_networks, scope.requested)

            query_targets, subnet_data_cache, subnet_warning_cache, containers, save_view = self._settle_views(
                ctx, scope, query_targets, subnet_data_cache, subnet_warning_cache, views_by_network, containers,
            )
            grouped_by_network = self._group_by_network(query_targets)
            all_data_to_save = self._collect_save_data(ctx, grouped_by_network, subnet_data_cache, save_view=save_view)
            sections = self._build_cli_sections(
                ctx, list(grouped_by_network), grouped_by_network, subnet_data_cache, subnet_warning_cache, misses, containers,
                fallback_view=scope.requested, duid=duid,
            )
            if ctx.cfg["report_auto_save"] and all_data_to_save:
                self._save_subnet_data(ctx, query_targets, all_data_to_save, duid=duid)
            self._publish_stats(ctx, len(inputs), query_targets, list(grouped_by_network), subnet_data_cache)

            failed = failed or self._has_failed_lookup(subnet_warning_cache)
            return CliResult(cli_exit_code(found=bool(subnet_data_cache or containers), invalid=invalid, failed=failed), sections)
        finally:
            self.execute_hook('post_run', ctx, None)

    @staticmethod
    def _unique_networks(query_targets: List[QueryTarget]) -> List[Network]:
        """
        The distinct CIDRs to query, as plain networks sorted by address then prefix length. One fetch
        serves a CIDR in every view (the answers carry their view), so the view is dropped here.
        """
        cidrs = {ipaddress.ip_network(str(target.resolved_network)) for target in query_targets}
        return sorted(cidrs, key=_network_order)

    @staticmethod
    def _group_by_network(query_targets: List[QueryTarget]) -> Dict[Network, List[str]]:
        """Original inputs per resolved network; the networks keep the order the user gave them."""
        grouped_by_network: Dict[Network, List[str]] = defaultdict(list)
        for target in query_targets:
            grouped_by_network[target.resolved_network].append(target.original_input)
        return grouped_by_network

    def _settle_views(
        self,
        ctx: ScriptContext,
        scope: ViewScope,
        query_targets: List[QueryTarget],
        subnet_data_cache: Dict[str, Dict],
        subnet_warning_cache: Dict[str, List[str]],
        views_by_network: Dict[str, Tuple[str, ...]],
        containers: List[Dict[str, Any]],
    ) -> tuple[List[QueryTarget], Dict[str, Dict], Dict[str, List[str]], List[Dict[str, Any]], bool]:
        """
        Take the run's two view decisions once, over the labels of the targets, the views the answers
        named and the child-container rows, then settle the targets with the first one: the rows handed
        back to the renderer (and the menu) follow ``scope.result_column``, the saved sheet follows
        ``scope.column`` (asked only when a report is being saved, so a JSON run reads no view list).

        Returns the settled targets, data and warnings (see ``_settle_targets``), the child-container
        rows with their ``network view`` column shown or hidden, and whether the report names the view.
        """
        labels = [
            *(_view_of(target.resolved_network) for target in query_targets),
            *(view for views in views_by_network.values() for view in views),
            *(str(row.get(NETWORK_VIEW) or "") for row in containers),
        ]
        label = scope.result_column(labels)
        save_view = bool(ctx.cfg["report_auto_save"]) and scope.column(labels)
        settled, data, warnings = self._settle_targets(
            query_targets, subnet_data_cache, subnet_warning_cache, views_by_network, label,
        )
        rows = present_rows(containers, NETWORK_VIEW, label, fallback=scope.requested, before="container")
        return settled, data, warnings, rows, save_view

    @staticmethod
    def _settle_targets(
        query_targets: List[QueryTarget],
        subnet_data_cache: Dict[str, Dict],
        subnet_warning_cache: Dict[str, List[str]],
        views_by_network: Dict[str, Tuple[str, ...]],
        label_targets: bool,
    ) -> tuple[List[QueryTarget], Dict[str, Dict], Dict[str, List[str]]]:
        """
        Make the targets, data and warnings agree with the run's decision to show the view or not.

        With ``label_targets`` a plain target whose CIDR answered with views is replaced by one
        ``ViewNetwork`` for each view (names sorted), and a target that already has a view stays; each
        CIDR's warnings are copied to every view, because a failure belongs to the CIDR. Without it every
        target is its plain CIDR again and the CIDR's single labelled partition is re-keyed to the CIDR:
        the shape of the data when no view is named (the column rule leaves at most one view then).
        The returned data and warnings hold only the keys of the settled targets (``_cache_key``).
        """
        settled: List[QueryTarget] = []
        seen: Set[Tuple[str, Network]] = set()
        for target in query_targets:
            network = target.resolved_network
            cidr = ipaddress.ip_network(str(network))
            if not label_targets:
                networks = [cidr]
            elif _view_of(network):
                networks = [network]
            else:
                networks = [_make_network(cidr, view) for view in views_by_network.get(str(cidr), ())] or [network]
            for settled_network in networks:
                if (target.original_input, settled_network) not in seen:
                    seen.add((target.original_input, settled_network))
                    settled.append(QueryTarget(original_input=target.original_input, resolved_network=settled_network))

        data: Dict[str, Dict] = {}
        warnings: Dict[str, List[str]] = {}
        for target in settled:
            key = _cache_key(target.resolved_network)
            cidr = str(target.resolved_network)
            found = subnet_data_cache.get(key)
            if not label_targets:
                partitions = (subnet_data_cache.get(f"{cidr} ({view})") for view in views_by_network.get(cidr, ()))
                found = next((partition for partition in partitions if partition), found)
            if found:
                data[key] = found
            if cidr in subnet_warning_cache:
                warnings[key] = list(subnet_warning_cache[cidr])
        return settled, data, warnings

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
        self, ctx: ScriptContext, networks: List[Network], network_view: str = ""
    ) -> tuple[Dict[str, Dict], Dict[str, List[str]], Dict[str, Tuple[str, ...]]]:
        """
        Fetch every CIDR in parallel (``network_view`` limits the lookups to one view, "" searches every
        view): (data, warnings, views). Data and warnings are keyed by the CIDR's text, only when
        non-empty. The part of a CIDR's answers that names no view is its data under the plain CIDR;
        the part of each view it names is under ``_cache_key(_make_network(cidr, view))``. ``views`` lists,
        for each CIDR whose answers named any, those views (sorted).
        """
        colors = get_global_color_scheme(ctx.cfg)
        subnet_data_cache: Dict[str, Dict] = {}
        subnet_warning_cache: Dict[str, List[str]] = {}
        views_by_network: Dict[str, Tuple[str, ...]] = {}
        with ctx.console.status(f"[{colors['description']}]Fetching subnets information...[/]"):
            with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, len(networks))) as executor:
                future_to_net = {
                    executor.submit(self._fetch_and_process_subnet_data, ctx, network, network_view): network
                    for network in networks
                }

                for future in as_completed(future_to_net):
                    network = future_to_net[future]
                    net_str = str(network)
                    ctx.console.print(f"[{colors['description']}]Processing results for [{colors['header']}]{net_str}[/]...[/]")
                    outcome = future.result()
                    if outcome.data:
                        subnet_data_cache[net_str] = outcome.data
                    for view, view_data in outcome.by_view.items():
                        if view_data:
                            subnet_data_cache[_cache_key(_make_network(network, view))] = view_data
                    if outcome.by_view:
                        views_by_network[net_str] = tuple(sorted(outcome.by_view))
                    if outcome.warnings:
                        subnet_warning_cache[net_str] = outcome.warnings
        return subnet_data_cache, subnet_warning_cache, views_by_network

    def _collect_save_data(
        self,
        ctx: ScriptContext,
        grouped_by_network: Dict[Network, List[str]],
        subnet_data_cache: Dict[str, Dict],
        *,
        save_view: bool = False,
    ) -> List[List[RowDict]]:
        """
        The report rows of every network with data, after the ``pre_save`` hook; empty unless saving is
        on. ``save_view`` names the network view on every row of a network that has one.
        """
        all_data_to_save: List[List[RowDict]] = []
        for network, original_inputs in grouped_by_network.items():
            data = subnet_data_cache.get(_cache_key(network), {})

            if ctx.cfg["report_auto_save"] and data:
                combined_input_str = ", ".join(original_inputs)
                save_data = self._prepare_subnet_save_data(
                    combined_input_str, data, _view_of(network) if save_view else ""
                )
                save_data = self.execute_hook('pre_save', ctx, save_data)
                if save_data:
                    all_data_to_save.append(save_data)
        return all_data_to_save

    @staticmethod
    def _publish_stats(
        ctx: ScriptContext,
        input_count: int,
        query_targets: List[QueryTarget],
        unique_networks: List[Network],
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
        """True when any warning is a failed Infoblox lookup rather than only a paging-limit notice."""
        return any(
            not _is_truncation(warning)
            for warnings in subnet_warning_cache.values()
            for warning in warnings
        )

    def _get_networks_from_user(self, ctx: ScriptContext, banner: str = "") -> List[str]:
        """
        Prompts the user to enter network addresses one per line; ``banner``, when given, names the
        network view the lookup searches and follows the instructions. Returns a list of unique,
        non-empty input strings from the user.
        """
        colors = get_global_color_scheme(ctx.cfg)
        ctx.console.print(
            "\n" f"[{colors['description']}]Enter network addresses and press Enter twice to start.[/]\n"
            f"[{colors['description']}]Formats: '1.2.3.0/24', '1.2.3.0/255.255.255.0', '2001:db8:20::/64', "
            f"or just an address ('1.2.3.4', '2001:db8:20::5')[/]\n"
        )
        if banner:
            ctx.console.print(f"[{colors['warning']}]{escape(banner)}[/]\n")
        inputs = []
        while True:
            search_input = read_user_input(ctx, "").strip()
            if not search_input:
                break
            inputs.append(search_input)
        return list(dict.fromkeys(inputs))

    def _resolve_inputs_to_targets(
        self, ctx: ScriptContext, inputs: List[str], network_view: str = ""
    ) -> tuple[List[QueryTarget], Dict[str, str], List[Dict[str, Any]]]:
        """
        Takes raw user input strings and resolves them into an ordered list of QueryTarget objects.
        This preserves the original input and its order. Also returns the errors by input and the
        child containers of every container prefix, which are listed but never expanded.
        ``network_view`` limits every lookup to that view; "" searches every view.
        """
        all_targets: List[QueryTarget] = []
        errors: Dict[str, str] = {}
        containers: List[Dict[str, Any]] = []
        with ctx.console.status(f"[{get_global_color_scheme(ctx.cfg)['description']}]Resolving inputs and finding subnets...[/]"):
            # Using executor.map preserves the order of the inputs
            with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, len(inputs))) as executor:
                results_generator = executor.map(
                    lambda item: self._resolve_single_input_detailed(ctx, item, network_view), inputs
                )
                for original_input, resolution in zip(inputs, results_generator):
                    if resolution.failure_message:
                        errors[original_input] = resolution.failure_message
                    containers.extend(resolution.containers)
                    if not resolution.networks:
                        if not resolution.containers:
                            ctx.logger.warning(f"Could not resolve '{original_input}' to any subnet.")
                        continue
                    # Sort to ensure consistent order for supernets: address, prefix length, then view
                    for net in sorted(resolution.networks, key=_network_order):
                        all_targets.append(QueryTarget(original_input=original_input, resolved_network=net))
        return all_targets, errors, containers

    def _resolve_single_input(
        self, ctx: ScriptContext, an_input: str, network_view: str = ""
    ) -> Set[Network]:
        return self._resolve_single_input_detailed(ctx, an_input, network_view).networks

    @staticmethod
    def _parse_network(text: str) -> Network:
        """
        What the resolver accepts: an address (a /32 or /128), a CIDR or an IPv4 address/mask, of either
        family. ValueError carries the reason otherwise: the form to type instead for an IPv6 spelling
        Infoblox cannot store (IPv4-mapped, zone ID), ``MALFORMED_MESSAGE`` for any other text.
        """
        refused = ipv6_form_problem(text)
        if refused:
            raise ValueError(refused)
        try:
            return ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise ValueError(MALFORMED_MESSAGE) from None

    @classmethod
    def _network_problem(cls, text: str) -> str:
        """Why ``text`` cannot be looked up, as ``_parse_network`` words it; "" when it can."""
        try:
            cls._parse_network(text)
        except ValueError as error:
            return str(error)
        return ""

    @classmethod
    def _has_ipv6_object(cls, inputs: Iterable[str]) -> bool:
        """
        True when any of ``inputs`` is an IPv6 address or prefix the resolver accepts: the run-level
        decision behind every ``DUID`` column (the table, the JSON and the saved report). It is taken
        from what was typed, before any lookup, so a miss still counts; a malformed or refused object
        (``_parse_network`` raises) counts for nothing.
        """
        for item in inputs:
            try:
                if cls._parse_network(item).version == 6:
                    return True
            except ValueError:
                continue
        return False

    def _resolve_single_input_detailed(
        self, ctx: ScriptContext, an_input: str, network_view: str = ""
    ) -> InputResolutionResult:
        """
        Worker function to resolve a single input string into one or more network objects.

        Every lookup is limited to ``network_view`` when one is given. An answer item that names its
        view gives a ``ViewNetwork`` (``ViewNetwork6`` for IPv6): an address found in two views resolves
        to a target for each, and a container's children are targets per (network, view). An item without
        a view gives a plain network, as it always did (an address: the first item). A network without a
        lookup (a /30 or longer, a /126 or longer for IPv6, or a container prefix without children)
        belongs to the requested view, if any. Unscoped, children that name a view are followed by one
        lookup of the prefix itself: it is a target in every view where it is an ordinary network, even
        when another view holds children for it.

        An address (a /32, a /128) goes through ``contains_address``; a prefix shorter than
        ``max_prefixlen - 2`` asks for its child networks and child containers, in the table of its
        family. An IPv6 spelling Infoblox cannot store (IPv4-mapped, zone ID) comes back as the failure
        message, with the form to type instead; any other malformed text resolves to nothing, silently.
        """
        try:
            net = self._parse_network(an_input)
            if net.prefixlen == net.max_prefixlen:
                result = request_result(ctx, _wapi_uri("contains", net, network_view), ensure_auth=False)
                if result.ok and result.has_items:
                    labelled = {
                        _make_network(item["network"], item["network_view"])
                        for item in result.items
                        if item.get("network") and item.get("network_view")
                    }
                    if labelled:
                        return InputResolutionResult(networks=labelled)
                    if 'network' in result.items[0]:
                        return InputResolutionResult(networks={_make_network(result.items[0]['network'])})
                if result.failed:
                    return InputResolutionResult(networks=set(), failure_message=describe_infoblox_failure(result))
                return InputResolutionResult(networks=set())
            own_network = _make_network(net, network_view)
            if net.prefixlen < net.max_prefixlen - 2:
                result = request_result(ctx, _wapi_uri("children", net, network_view), ensure_auth=False)
                found_subnets: Set[Network] = set()
                if result.ok:
                    supernet_data = process_data(ctx, type='supernet', content=result.content)
                    found_subnets = {
                        _make_network(sub["network"], sub.get(NETWORK_VIEW, "")) for sub in supernet_data.get("subnets", [])
                    }
                elif result.failed:
                    return InputResolutionResult(networks=set(), failure_message=describe_infoblox_failure(result))
                # The child containers are listed, not expanded. A failed lookup is reported next to what
                # the first one found, so a grid that refuses it still answers for a plain /24.
                container_result = request_result(
                    ctx, _wapi_uri("child containers", net, network_view), ensure_auth=False
                )
                containers = self._child_container_rows(an_input, container_result.items) if container_result.ok else []
                failure = describe_infoblox_failure(container_result) if container_result.failed else ""
                networks = found_subnets or ({own_network} if not containers else set())
                # Children in one view say nothing about another view, where the prefix may be an ordinary
                # network. One view holds a prefix as a container or a network, never both, so the question
                # only exists unscoped and once an answer has named a view.
                if not network_view and (
                    any(_view_of(child) for child in found_subnets) or any(row.get(NETWORK_VIEW) for row in containers)
                ):
                    exact_result = request_result(ctx, _wapi_uri("exact", net), ensure_auth=False)
                    networks = networks | {
                        _make_network(net, item["network_view"]) for item in exact_result.items if item.get("network_view")
                    }
                    failure = failure or (describe_infoblox_failure(exact_result) if exact_result.failed else "")
                return InputResolutionResult(networks=networks, failure_message=failure, containers=containers)
            return InputResolutionResult(networks={own_network})
        except ValueError:
            ctx.logger.warning(f"Invalid IP/Subnet format for input: '{an_input}'")
            return InputResolutionResult(networks=set(), failure_message=ipv6_form_problem(an_input))
        except Exception as e:
            ctx.logger.error(f"Error resolving input '{an_input}': {e}")
            return InputResolutionResult(networks=set(), failure_message="Subnet resolution failed.")

    @staticmethod
    def _child_container_rows(container: str, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        ``networkcontainer`` and ``ipv6networkcontainer`` records as ``child containers`` rows, sorted by
        address family, address, prefix length and view (a container prefix's children are all of one
        family, so IPv4 lists sort as they always did). A container that exists in two views is listed
        once for each (a row names its view in a leading ``network view`` column when the record does);
        within one view the first of a repeated network wins.
        """
        children: Dict[Tuple[Network, str], Dict[str, Any]] = {}
        for item in items:
            if "network" in item:
                children.setdefault((ipaddress.ip_network(item["network"]), str(item.get("network_view") or "")), item)
        rows: List[Dict[str, Any]] = []
        for child, view in sorted(children, key=lambda key: (key[0].version, int(key[0].network_address), key[0].prefixlen, key[1])):
            item = children[(child, view)]
            row = {
                "container": container,
                "child container": str(child),
                "comment": item.get("comment", ""),
                "utilization %": utilization_percent(item.get("utilization"), CONTAINER_UTILIZATION_SCALE),
            }
            rows.append({NETWORK_VIEW: view, **row} if view else row)
        return rows

    def _fetch_and_process_subnet_data(
        self, ctx: ScriptContext, network: Network, network_view: str = ""
    ) -> SubnetFetchOutcome:
        """
        Fetches all data for a single subnet, processes it, and prepares it for display.
        This function is designed to be run in a thread pool for a *unique* network.

        The ``process_data`` hook runs once on the data that named no view (always, when no view was
        named at all: that is today's single call) and once on the data of each view the answers named.
        """
        outcome = self._fetch_all_data_for_subnet(ctx, network, network_view)
        processed_data = outcome.data
        if outcome.data or not outcome.by_view:
            processed_data = self.execute_hook('process_data', ctx, outcome.data)
        by_view = {view: self.execute_hook('process_data', ctx, data) for view, data in outcome.by_view.items()}
        return SubnetFetchOutcome(data=processed_data, warnings=outcome.warnings, by_view=by_view)

    def _fetch_all_data_for_subnet(
        self, ctx: ScriptContext, network: Network, network_view: str = ""
    ) -> SubnetFetchOutcome:
        """
        Fetches all related data points for a single subnet in parallel: four requests, each one asking
        for the ``network_view`` field (``network_view`` limits them to that view; "" searches every view).
        The URIs come from ``WAPI_URIS`` by the subnet's family: an IPv6 subnet asks the IPv6 objects only
        for the fields they have, and its range answer feeds the ``DHCP range`` section alone (Infoblox
        holds no failover association for it), so IPv6 has no utilisation figures and no failover.

        Every answer is split by the view its items name. The part that names none is ``data``; each
        view gets its own entry in ``by_view`` and is parsed on its own, so one view's description or
        DHCP figure is never read from another view's item.
        """
        net_str = str(network)
        paged_request = partial(request_result, paged=True)  # these lists can outgrow one WAPI page
        range_sections = RANGE_SECTIONS[network.version]
        request_specs = {
            "network bundle": {
                "uri": _wapi_uri("network bundle", network, network_view),
                "parser_types": ("general", "network options"),
                "warning_labels": ("general", "network options"),
                "request_fn": request_result_with_inheritance,
            },
            "DNS records": {
                "uri": _wapi_uri("DNS records", network, network_view),
                "parser_types": ("DNS records",),
                "warning_labels": ("DNS records",),
                "request_fn": paged_request,
            },
            "range bundle": {
                "uri": _wapi_uri("range bundle", network, network_view),
                "parser_types": range_sections,
                "warning_labels": range_sections,
                "request_fn": paged_request,
            },
            "fixed addresses": {
                "uri": _wapi_uri("fixed addresses", network, network_view),
                "parser_types": ("fixed addresses",),
                "warning_labels": ("fixed addresses",),
                "request_fn": paged_request,
            },
        }
        partitions: Dict[str, Dict[str, Any]] = {}  # network view -> its parsed sections; "" = no view named
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
                        if label == "network bundle":
                            items = [
                                normalize_record_fields(
                                    item,
                                    scalar_fields=("comment",),
                                    extattrs_fields=("extattrs",),
                                    list_struct_fields=("options", "members"),
                                )
                                for item in result.items
                            ]
                            payloads = {view: json.dumps(group).encode() for view, group in _view_partitions(items).items()}
                            payloads = payloads or {"": json.dumps(items).encode()}
                        else:
                            payloads = _content_partitions(result.content)
                        for view, payload_content in payloads.items():
                            sections = partitions.setdefault(view, defaultdict(list))
                            for parser_type in spec["parser_types"]:
                                sections.update(process_data(ctx, type=parser_type, content=payload_content))
                        if result.truncated:
                            notice = _truncation_notice(payloads)
                    elif result.failed:
                        notice = describe_infoblox_failure(result)
                    if notice:
                        for warning_label in spec["warning_labels"]:
                            warnings.append(f"{warning_label}: {notice}")
                except Exception as e:
                    ctx.logger.error(f"Failed to fetch data for '{label}' in {net_str}: {e}")
                    for warning_label in spec["warning_labels"]:
                        warnings.append(f"{warning_label}: request processing failed.")
        for sections in partitions.values():
            if not sections.get("DHCP range"):
                # WAPI answers 0 for a network that has no DHCP range, which would read as "idle DHCP".
                for general_row in sections.get("general", []):
                    general_row["DHCP utilization %"] = ""
        unlabelled = partitions.pop("", defaultdict(list))
        return SubnetFetchOutcome(
            data=unlabelled,
            warnings=warnings,
            by_view={view: partitions[view] for view in sorted(partitions)},
        )

    def _display_results(self, ctx: ScriptContext, query_targets: List[QueryTarget], subnet_data_cache: Dict[str, Dict], grouped_by_network: Dict[Network, List[str]], subnet_warning_cache: Optional[Dict[str, List[str]]] = None) -> None:
        """Handles the logic for displaying summary and/or detailed views in order."""
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
        networks: List[Network],
        grouped_by_network: Dict[Network, List[str]],
        subnet_data_cache: Dict[str, Dict],
        subnet_warning_cache: Dict[str, List[str]],
    ) -> List[Dict[str, str]]:
        """
        One summary row per network, in the order given: the menu's selection list and ``cn subnet``'s
        ``subnets``. When any of the networks belongs to a view, every row has a ``Network view`` column
        between the input and the resolved subnet (blank for a network without a view).
        """
        summary_data: List[Dict[str, str]] = []
        any_inherited = False
        show_view = any(_view_of(network) for network in networks)
        for network in networks:
            net_info = subnet_data_cache.get(_cache_key(network), {})
            warnings = subnet_warning_cache.get(_cache_key(network), [])
            summary_state = self._build_summary_state(net_info, warnings)
            summary_net: Dict[str, str] = {"Original Input(s)": ", ".join(grouped_by_network[network])}
            if show_view:
                summary_net[NETWORK_VIEW_TITLE] = _view_of(network)
            summary_net["Resolved Subnet"] = str(network)
            summary_net["Status"] = summary_state.status

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
        networks: List[Network],
        grouped_by_network: Dict[Network, List[str]],
        subnet_data_cache: Dict[str, Dict],
        subnet_warning_cache: Dict[str, List[str]],
        misses: Sequence[str] = (),
        containers: Sequence[Dict[str, Any]] = (),
        fallback_view: str = "",
        duid: bool = False,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        The sections of a ``cn subnet`` result: ``subnets`` (the summary, then a "No data" row with no
        resolved subnet for each of ``misses``, the well-formed inputs that are in no network),
        ``child containers`` (``containers``: the containers inside a container prefix, listed and not
        expanded), each detail table over all networks with the network as its first column, then ``warnings``.

        Detail tables come in the menu's order, the rest alphabetically; the ones every run has (see
        ``CLI_DETAIL_SECTIONS``) are present even when empty. When any of the networks belongs to a
        network view, every detail and ``warnings`` row leads with ``network view`` (before ``network``)
        and the ``subnets`` rows, the misses included, have ``Network view`` (see ``_build_summary_rows``).

        ``fallback_view`` is the requested view (``ViewScope.requested``). A requested view always shows
        the column, even when no network is left to carry it (every input missed), and it is the view a
        miss row names; without one a miss row's view is blank.

        ``duid`` (the run has an IPv6 object) gives every ``fixed addresses`` row a ``DUID`` column, empty for
        an IPv4 address; without it an IPv4 run has no such column.
        """
        show_view = bool(fallback_view) or any(_view_of(network) for network in networks)
        details: Dict[str, List[Dict[str, Any]]] = {name: [] for name in CLI_DETAIL_SECTIONS}
        for network in networks:
            net_str = str(network)
            lead = {NETWORK_VIEW: _view_of(network), "network": net_str} if show_view else {"network": net_str}
            for name, rows in subnet_data_cache.get(_cache_key(network), {}).items():
                details.setdefault(name, []).extend(
                    {**lead, **{key: value for key, value in row.items() if key not in lead}} for row in rows
                )

        no_data = self._build_summary_state({}, [])
        details["fixed addresses"] = _with_duid(details["fixed addresses"], duid)

        miss_rows = [
            {
                "Original Input(s)": item,
                **({NETWORK_VIEW_TITLE: fallback_view} if show_view else {}),
                "Resolved Subnet": "",
                "Status": no_data.status,
                "Description": no_data.description,
            }
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
            {
                **({NETWORK_VIEW: _view_of(network)} if show_view else {}),
                "network": str(network),
                "warning": warning,
            }
            for network in networks
            for warning in subnet_warning_cache.get(_cache_key(network), [])
        ]
        return sections

    def _prompt_for_detail_selection(
        self,
        ctx: ScriptContext,
        networks: List[Network],
        grouped_by_network: Dict[Network, List[str]],
        subnet_data_cache: Dict[str, Dict],
        subnet_warning_cache: Dict[str, List[str]],
    ) -> tuple[List[Network], bool]:
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
        selected_networks: List[Network],
        grouped_by_network: Dict[Network, List[str]],
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
                subnet_data_cache.get(_cache_key(network), {}),
                subnet_warning_cache.get(_cache_key(network), []),
                index=index,
                total=total_selected,
            )

    def _print_subnet_details(
        self,
        ctx: ScriptContext,
        network: Network,
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

        in_view = _in_view(network)  # " in network view lab" when the network belongs to a view
        if total > 1:
            console.print(
                f"[{colors['description']}]Details [{index}/{total}] for: [{colors['header']} bold]{network}[/]{escape(in_view)}[/]"
            )
        else:
            console.print(f"[{colors['description']}]Details for: [{colors['header']} bold]{network}[/]{escape(in_view)}[/]")
        console.print(f"[{colors['description']}] (Resolved from input(s): {inputs_str})[/]\n")

        if warnings:
            issues = format_partial_results_message(f'{len(warnings)} lookup issue(s) for {network}{in_view}.')
            console.print(f"[{colors['warning']}]{escape(issues)}[/]")
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

        no_match = format_no_match_message('subnet records', str(network))
        if in_view:  # the view goes before the closing period
            no_match = f"{no_match[:-1]}{in_view}."
        console.print(f"[{colors['error']}]{escape(no_match)}[/]")

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

    def _prepare_subnet_save_data(
        self, original_input: str, processed_data: Dict[str, Any], network_view: str = ""
    ) -> List[RowDict]:
        """
        Prepares data for saving. The Original Input is only added to the main 'Subnet' row
        for improved report readability. A ``network_view`` is named in the ``Network view`` column of
        every row of the subnet (before ``IP``, so right after ``Original Input``), which keeps a filter
        on that column from splitting a subnet. A DNS-record or fixed-address row has the mask of its
        address (``/32``, or ``/128`` for an IPv6 address), and an IPv6 fixed address row also carries
        its ``DUID`` (the sheet puts that column after ``MAC``).
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
                "IP": rec.get("IP address"), "Mask": _host_mask(rec.get("IP address")),
                "Name": rec.get("A Record"), "Notes": "DNS record"
            })
        for fa in fixed_addrs:
            data_rows.append({
                "IP": fa.get("IP address"), "Mask": _host_mask(fa.get("IP address")),
                "Name": fa.get("name"), "MAC": fa.get("MAC"),
                **({DUID: fa[DUID]} if DUID in fa else {}),  # an IPv6 fixed address; an IPv4 row has no key
                "Notes": "Fixed IP"
            })
        if network_view:
            data_rows = present_rows(data_rows, NETWORK_VIEW_TITLE, True, fallback=network_view, before="IP")
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

    def _save_subnet_data(
        self,
        ctx: ScriptContext,
        query_targets: List[QueryTarget],
        all_data_to_save: List[List[RowDict]],
        duid: bool = False,
    ) -> None:
        """
        Saves collected data, ensuring no pandas index is added to the output file.
        NOTE: Requires the `queue_save` utility to handle the `index=False` parameter.

        ``duid`` (the run has an IPv6 object, see ``_has_ipv6_object``) puts a ``DUID`` column after ``MAC`` in
        "Subnet Data Detail", empty for every row that has no identity to show: the column follows the
        input, not the rows, so a run whose IPv6 object missed still has it next to an IPv4 fixed address.
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
            if duid:
                base_columns.insert(base_columns.index("MAC") + 1, DUID)  # next to the MAC it stands beside
            if any(NETWORK_VIEW_TITLE in row for row in all_row_dicts):
                base_columns.insert(1, NETWORK_VIEW_TITLE)  # right after Original Input
            final_columns = list(base_columns)
            for header in discovered_headers.keys():
                if header not in final_columns:
                    final_columns.append(header)
            data_to_write = [[row_dict.get(col, "") for col in final_columns] for row_dict in all_row_dicts]
            queue_save(ctx, final_columns, data_to_write, sheet_name="Subnet Data Detail", force_header=True, index=False)
