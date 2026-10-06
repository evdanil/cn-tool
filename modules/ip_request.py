import argparse
import ipaddress
import json
from time import perf_counter
from typing import Callable, Dict, Any, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor

from rich.markup import escape

from core.base import BaseModule, CliResult, ScriptContext, cli_exit_code
from utils.api import bound_infoblox_workers, describe_infoblox_failure, request_result
from utils.auth import ensure_infoblox_auth
from utils.cli_input import read_objects
from utils.display import console, get_global_color_scheme, print_table_data, table_columns
from utils.file_io import queue_save
from utils.network_views import NETWORK_VIEW, NETWORK_VIEW_TITLE, ViewScope, present_rows, scope_network, view_scope
from utils.process_data import process_data
from utils.user_input import press_any_key, read_user_input
from utils.validation import ipv6_form_problem

RESERVED_ADDRESS = "Invalid IP: Broadcast, unspecified, and reserved IPs are excluded."
INVALID_FORMAT = "Invalid IP format. Please enter a valid IPv4 or IPv6 address."
NO_RECORD = "No matching IPv4 record found"
NO_RECORD_V6 = "No matching IPv6 record found"

COLUMNS = ["Subnet", "IP", "Name", "Status", "Lease State", "Record Type", "MAC", "PTR name"]
DUID = "DUID"
# A run that looks up an IPv6 address shows the DUID column (empty for an IPv4 row); an IPv4-only run never does.
COLUMNS_WITH_DUID = [*COLUMNS[:-1], DUID, COLUMNS[-1]]

# The address lookup answers once per network view that holds the address; the PTR lookup is never scoped,
# because a PTR record belongs to a DNS view. ``ipv6address`` has no MAC, and asks for the address back (the IPv4
# object's ``_ref`` carries it).
ADDRESS_URI = "ipv4address?ip_address={ip}&_return_fields=network,names,status,types,lease_state,mac_address,network_view"
ADDRESS_URI_V6 = "ipv6address?ip_address={ip}&_return_fields=ip_address,network,names,status,types,lease_state,duid,network_view"
PTR_URI = "record:ptr?ipv4addr={ip}&_return_fields=ptrdname,view"
PTR_URI_V6 = "record:ptr?ipv6addr={ip}&_return_fields=ptrdname,view"

# An IPv6 row never shows None: an answer without extra data (an unused address) gives empty cells.
_NO_EXTRA = {"lease state": "", "record type": "", "mac": "", "duid": ""}

OwnerFn = Callable[[str], str]  # the network view that holds a DNS view ("" when no network view lists it)


def _is_ipv6(ip: str) -> bool:
    """True for an IPv6 address (or a lookup key), by its colons: the family never comes from a setting."""
    return ":" in ip


def _lookup_key(text: str) -> str:
    """
    The address as it is sent and compared: the compressed lower-case form for IPv6, so that two
    spellings of one address are one lookup. IPv4 text is already canonical and is kept as typed.
    ``text`` has passed ``_validate_ip``.
    """
    return ipaddress.ip_address(text).compressed if _is_ipv6(text) else text


def _validate_ip(ctx: ScriptContext, text: str) -> Optional[str]:
    """
    Why ``text`` cannot be looked up (the message the menu shows), or None for a usable IPv4 or IPv6 address.

    The order matters for IPv6: an IPv4-mapped address gets its hint first (Python versions disagree on
    whether it is "reserved"), then an unspecified, reserved or link-local address is refused (so a
    zoned ``fe80::1%eth0`` is refused once, as reserved), and only then does a zone ID get its hint.

    ``ctx`` is not used yet; it keeps the call shape every module's validator shares.
    """
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return INVALID_FORMAT
    mapped = ipv6_form_problem(text, zone_ok=True)
    if mapped:
        return mapped
    if ip.is_unspecified or ip.is_reserved or ip.is_link_local:
        return RESERVED_ADDRESS
    return ipv6_form_problem(text) or None


def _publishes_ptr(data: Dict[str, Any]) -> bool:
    """True when the record types of a processed address (``extra``/``record type``) include PTR."""
    return "PTR" in str(data.get("extra", [{}])[0].get("record type", "")).split(",")


def _item_payloads(content: bytes) -> List[bytes]:
    """
    The answer of one address split into one JSON payload per network view, in view-name order, so
    each address-view is parsed (and handed to the ``process_data`` hook) on its own.

    Items that carry no ``network_view`` label keep only the first one, as the lookup always did.
    An answer that is not a list of items (empty, or not JSON) is returned whole as the only payload.
    """
    try:
        payload = json.loads(content)
    except (TypeError, ValueError):
        return [content]
    items = [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []
    if not items:
        return [content]

    payloads: List[bytes] = []
    seen: Set[Optional[str]] = set()
    for item in sorted(items, key=lambda item: str(item.get("network_view") or "")):
        view = str(item["network_view"] or "") if "network_view" in item else None
        if view not in seen:
            seen.add(view)
            payloads.append(json.dumps([item]).encode())
    return payloads


def _ptr_addresses(ip_addresses: List[str], processed_data_by_ip: Dict[str, List[Dict[str, Any]]]) -> List[str]:
    """The addresses, in input order, with a record of the PTR type in any view: the ones worth a PTR lookup."""
    return [
        ip for ip in ip_addresses
        if any(_publishes_ptr(data) for data in processed_data_by_ip.get(ip, []))
    ]


def _ptr_name(pairs: List[Tuple[str, str]], network_view: str, owner: Optional[OwnerFn]) -> str:
    """
    The ``PTR name`` of the row of ``network_view``, from the ``(DNS view, name)`` pairs of its address.

    A name in a DNS view that belongs to ``network_view`` is shown, and so is one in a DNS view no
    network view lists (or in none): it is shown on every row rather than lost. Without ``owner`` (the
    views could not be paired) every name is shown, as before the views were told apart. A name
    held in several views appears once.
    """
    names = (
        name for dns_view, name in pairs
        if owner is None or not network_view or owner(dns_view) in ("", network_view)
    )
    return ",".join(dict.fromkeys(names))


def _ptr_warnings(ptr_failures: Dict[str, str]) -> List[Dict[str, str]]:
    """The ``warnings`` rows (``object``/``warning``) of the failed PTR lookups, in lookup order."""
    return [{"object": ip, "warning": f"PTR lookup failed: {reason}"} for ip, reason in ptr_failures.items()]


def _explain_misses(
    ip_addresses: List[str],
    processed_data_by_ip: Dict[str, List[Dict[str, Any]]],
    failed_ips: Dict[str, str],
    no_record: str = NO_RECORD,
    no_record_v6: str = NO_RECORD_V6,
) -> Dict[str, str]:
    """
    The reason each address in ``ip_addresses`` (lookup keys) has no row, in input order: the failure of
    its lookup, else ``no_record`` for an IPv4 address and ``no_record_v6`` for an IPv6 one (both name the
    requested network view when there is one).
    """
    return {
        ip: failed_ips.get(ip, no_record_v6 if _is_ipv6(ip) else no_record)
        for ip in ip_addresses
        if ip not in processed_data_by_ip
    }


def _publish_stats(
    ctx: ScriptContext,
    input_count: int,
    ip_addresses: List[str],
    processed_data_by_ip: Dict[str, List[Dict[str, Any]]],
    print_data_all: List[Dict[str, Any]],
) -> None:
    """
    Report the run to the usage statistics: the same event from the menu and the command line.
    ``result_count`` counts rows (one per address and network view); the other counts are addresses.
    """
    ctx.event_bus.publish(
        "stats:module_detail",
        {
            "unit_count": len(ip_addresses),
            "input_count": input_count,
            "unique_count": len(ip_addresses),
            "success_count": len(processed_data_by_ip),
            "miss_count": max(0, len(ip_addresses) - len(processed_data_by_ip)),
            "result_count": len(print_data_all),
        },
    )


class IPRequestModule(BaseModule):
    """
    Module to fetch detailed information about one or more IPv4 or IPv6 addresses from the API.
    """
    cli_name = "ip"

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
        Requests user to provide IPv4 or IPv6 address(es), validates the input, calls the API,
        processes the data, and then prints and/or saves it.

        An address is looked up in its compressed form, so two spellings of one IPv6 address are one
        lookup and one row, and the miss line prints that form.
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - IP Information")

        ensure_infoblox_auth(ctx)

        # A configured view is checked before any input is read, so a wrong setting is not found out after
        # fifty addresses have been typed in.
        scope = view_scope(ctx, None, request_result)
        view_problem = scope.problem()
        if view_problem:
            console.print(f"[{colors['error']}]{escape(view_problem.message)}[/]")
            press_any_key(ctx)
            return

        console.print(
            "\n"
            f"[{colors['description']}]Please provide an IP address (IPv4 or IPv6) or a list of addresses, one per line.[/]\n"
            f"[{colors['description']}]This module will request hostname, location, and network configuration details.[/]\n"
            f"[{colors['description']}]Empty input line starts the process.[/]\n"
            f"[{colors['header']}]Example:[/]\n"
            f"[{colors['success']} {colors['bold']}]134.162.104.110[/]\n"
            f"[{colors['success']} {colors['bold']}]8.8.8.8[/]\n"
            f"[{colors['success']} {colors['bold']}]2001:db8:20::5[/]\n"
        )
        banner = scope.banner()
        if banner:
            console.print(f"[{colors['warning']}]{escape(banner)}[/]\n")

        # --- User Input Gathering ---
        ip_addresses_input: List[str] = []
        while True:
            search_input = read_user_input(ctx, "").strip()
            if not search_input:
                break
            problem = _validate_ip(ctx, search_input)
            if problem:
                console.print(f"[{colors['error']}]{problem}[/]")
            else:
                ip_addresses_input.append(_lookup_key(search_input))

        if not ip_addresses_input:
            return

        # Remove duplicates while preserving order (the keys: two spellings of one IPv6 address are one)
        ip_addresses = list(dict.fromkeys(ip_addresses_input))

        # --- API Call and Data Processing ---
        processed_data_by_ip, failed_ips = self._fetch_ips(ctx, ip_addresses, scope.requested)
        ptr_names, ptr_failures = self._fetch_ptr_names(ctx, _ptr_addresses(ip_addresses, processed_data_by_ip))

        # --- Display and Save Results ---
        misses = _explain_misses(
            ip_addresses, processed_data_by_ip, failed_ips, scope.scoped(NO_RECORD), scope.scoped(NO_RECORD_V6)
        )
        for ip, reason in misses.items():
            console.print(f"[{colors['success']} {colors['bold']}]{ip}[/] - [{colors['error']}]{reason}[/]")

        save_rows, print_data_all = self._rows_for(ctx, scope, ip_addresses, processed_data_by_ip, ptr_names)

        if print_data_all:
            # The print_table_data utility is designed to handle a list of dictionaries.
            # It will automatically determine the columns from the keys of the first dictionary.
            # This correctly handles cases where a plugin might have added a new column.
            print_table_data(ctx, {"IP Information": print_data_all})

        for row in _ptr_warnings(ptr_failures):
            console.print(f"[{colors['warning']}]{row['object']} - {escape(row['warning'])}[/]")

        self._save_report(ctx, ip_addresses, processed_data_by_ip, save_rows)
        _publish_stats(ctx, len(ip_addresses_input), ip_addresses, processed_data_by_ip, print_data_all)

        press_any_key(ctx)

    def run_cli(self, ctx: ScriptContext, args: argparse.Namespace) -> CliResult:
        """
        ``cn ip``: look up the IPv4 and IPv6 addresses named on the command line, in ``--file`` and/or on
        stdin.

        Returns the sections ``IP Information`` (one row per address and network view with a record, an
        unused address inside a managed network included; led by ``Network view`` when ``view_scope``
        says it shows, which a JSON run does for every labelled row; with a ``DUID`` column, empty for an
        IPv4 row, when the run looks up an IPv6 address), ``not_found`` (every other object and why: a
        miss keeps the object as typed) and ``warnings`` (``object``/``warning`` for each address whose
        PTR lookup failed); every key is always present and the caller renders them. Never prompts.
        Two spellings of one IPv6 address are one lookup and one row.

        A requested view (``--view``, or ``[api] network_view``) that is not on the grid returns exit 2,
        one whose list cannot be read exit 3, both with the message on the console and no sections.
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - IP Information")

        try:
            objects = read_objects(args.objects, args.file)
        except (OSError, UnicodeDecodeError) as exc:  # a file that is missing, a directory or not UTF-8
            source = "standard input" if args.file in (None, "-") else args.file
            reason = getattr(exc, "strerror", None) or exc
            console.print(f"[{colors['error']}]cn ip: cannot read {escape(str(source))}: {escape(str(reason))}[/]")
            return CliResult(2, {})
        if not objects:
            console.print(f"[{colors['error']}]cn ip: no addresses given; see cn ip --help[/]")
            return CliResult(2, {})

        reasons: Dict[str, str] = {}
        keys: Dict[str, str] = {}  # each usable object -> its lookup key
        for obj in objects:
            problem = _validate_ip(ctx, obj)
            if problem:
                reasons[obj] = problem
            else:
                keys[obj] = _lookup_key(obj)
        invalid = bool(reasons)
        ip_addresses = list(dict.fromkeys(keys.values()))

        processed_data_by_ip: Dict[str, List[Dict[str, Any]]] = {}
        failed_ips: Dict[str, str] = {}
        ptr_failures: Dict[str, str] = {}
        print_data_all: List[Dict[str, Any]] = []
        if ip_addresses:
            ensure_infoblox_auth(ctx)
            scope = view_scope(ctx, args, request_result)
            view_problem = scope.problem()
            if view_problem:  # a view that is not on the grid, or a grid that will not say: nothing is looked up
                console.print(f"cn ip: {view_problem.message}", markup=False)
                return CliResult(view_problem.exit_code, {})
            processed_data_by_ip, failed_ips = self._fetch_ips(ctx, ip_addresses, scope.requested)
            ptr_names, ptr_failures = self._fetch_ptr_names(ctx, _ptr_addresses(ip_addresses, processed_data_by_ip))
            save_rows, print_data_all = self._rows_for(ctx, scope, ip_addresses, processed_data_by_ip, ptr_names)
            self._save_report(ctx, ip_addresses, processed_data_by_ip, save_rows)
            _publish_stats(ctx, len(keys), ip_addresses, processed_data_by_ip, print_data_all)
            misses = _explain_misses(
                ip_addresses, processed_data_by_ip, failed_ips, scope.scoped(NO_RECORD), scope.scoped(NO_RECORD_V6)
            )
            reasons.update({obj: misses[key] for obj, key in keys.items() if key in misses})

        data = {
            "IP Information": print_data_all,
            "not_found": [{"object": obj, "reason": reasons[obj]} for obj in objects if obj in reasons],
            "warnings": _ptr_warnings(ptr_failures),
        }
        failed = bool(failed_ips or ptr_failures)
        return CliResult(cli_exit_code(found=bool(print_data_all), invalid=invalid, failed=failed), data)

    def _fetch_ips(
        self, ctx: ScriptContext, ip_addresses: List[str], network_view: str = ""
    ) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, str]]:
        """
        Ask Infoblox about each address (``ipv4address`` or ``ipv6address`` by its family; in
        ``network_view`` only, or in every view when it is "") and run the ``process_data`` hook on
        every address-view of every answer, one at a time.

        Returns the processed data of the addresses that have a record (one entry per network view
        that holds the address, in view-name order), and the failure message of each address whose
        lookup failed (an address with no record is in neither).
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info(f"User input - IPs: {', '.join(ip_addresses)}")

        start = perf_counter()
        req_urls = {
            ip: scope_network((ADDRESS_URI_V6 if _is_ipv6(ip) else ADDRESS_URI).format(ip=ip), network_view)
            for ip in ip_addresses
        }

        with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, len(req_urls))) as executor, console.status(f"[{colors['description']}]Fetching IP information...[/]"):
            future_to_ip = {executor.submit(request_result, ctx, uri, ensure_auth=False): ip for ip, uri in req_urls.items()}
            results = {future_to_ip[future]: future.result() for future in future_to_ip}

        processed_data_by_ip: Dict[str, List[Dict[str, Any]]] = {}
        failed_ips: Dict[str, str] = {}
        for ip, response in results.items():
            if response.ok:
                for payload in _item_payloads(response.content):
                    data = process_data(ctx, type="ip", content=payload)

                    # --- HOOK: Allows plugins to modify the processed data (once per address and view) ---
                    data = self.execute_hook('process_data', ctx, data)

                    if data and data.get("general"):
                        processed_data_by_ip.setdefault(ip, []).append(data)
            elif response.failed:
                failed_ips[ip] = describe_infoblox_failure(response)

        end = perf_counter()
        logger.info(f"IP Information search took {round(end - start, 3)} seconds!")
        console.print(f"[{colors['description']}]Request Type - IP Information - Search took [{colors['success']}]{round(end-start, 3)}[/] seconds![/]")
        return processed_data_by_ip, failed_ips

    def _fetch_ptr_names(
        self, ctx: ScriptContext, ips: List[str]
    ) -> Tuple[Dict[str, List[Tuple[str, str]]], Dict[str, str]]:
        """
        Ask Infoblox for the PTR records at each address of ``ips``: one ``record:ptr`` request per
        address (by ``ipv4addr`` or ``ipv6addr``, never scoped to a view), in parallel, none when ``ips``
        is empty.

        Returns ``(pairs, failures)``: the ``(DNS view, ptrdname)`` pairs of each address that has any
        (a pair listed once; the DNS view is "" when the record names none), and the failure message of
        each address whose lookup failed. An address with no PTR record is in neither. ``_ptr_name``
        turns the pairs into the ``PTR name`` of a row.
        """
        if not ips:
            return {}, {}

        colors = get_global_color_scheme(ctx.cfg)
        req_urls = {ip: (PTR_URI_V6 if _is_ipv6(ip) else PTR_URI).format(ip=ip) for ip in ips}

        with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, len(req_urls))) as executor, console.status(f"[{colors['description']}]Fetching PTR records...[/]"):
            futures = {ip: executor.submit(request_result, ctx, uri, ensure_auth=False) for ip, uri in req_urls.items()}
            results = {ip: future.result() for ip, future in futures.items()}

        pairs: Dict[str, List[Tuple[str, str]]] = {}
        failures: Dict[str, str] = {}
        for ip, response in results.items():
            if response.failed:
                failures[ip] = describe_infoblox_failure(response)
                continue
            found = list(dict.fromkeys(
                (str(item.get("view") or ""), item["ptrdname"]) for item in response.items if item.get("ptrdname")
            ))
            if found:
                pairs[ip] = found
        return pairs, failures

    def _rows_for(
        self,
        ctx: ScriptContext,
        scope: ViewScope,
        ip_addresses: List[str],
        processed_data_by_ip: Dict[str, List[Dict[str, Any]]],
        ptr_pairs: Dict[str, List[Tuple[str, str]]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        The ``(save_rows, print_rows)`` of a run, with the ``Network view`` column where ``scope`` says it
        belongs: the rows handed back to the caller follow ``result_column`` (JSON always carries the
        view), the saved sheet follows ``column``. In the menu both are the same decision.

        When the rows carry a view and a PTR record names its DNS view, and the grid's views could be
        listed, each PTR name goes to the row of the network view that holds its DNS view; otherwise
        every row shows every PTR name. The grid is asked for its views only when one of these decisions
        needs them: unlabelled rows never do, and a JSON run that saves nothing needs them for the PTR
        pairing alone.
        """
        labels = [
            str(data.get("general", [{}])[0].get(NETWORK_VIEW) or "")
            for datas in processed_data_by_ip.values() for data in datas
        ]
        owner: Optional[OwnerFn] = None
        pairs_name_a_dns_view = any(dns_view for pairs in ptr_pairs.values() for dns_view, _ in pairs)
        if pairs_name_a_dns_view and any(label.strip() for label in labels):
            grid = scope.grid()
            owner = None if grid.error else grid.owner
        row_view = scope.result_column(labels)
        # The sheet is decided only when a report is saved; otherwise the hook sees the same row as pre_render.
        save_view = scope.column(labels) if ctx.cfg["report_auto_save"] else row_view
        return self._build_rows(
            ctx, ip_addresses, processed_data_by_ip, ptr_pairs,
            row_view=row_view, save_view=save_view, owner=owner, fallback_view=scope.requested,
            duid=any(_is_ipv6(ip) for ip in ip_addresses),  # decided by the addresses looked up, not by the answers
        )

    def _build_rows(
        self,
        ctx: ScriptContext,
        ip_addresses: List[str],
        processed_data_by_ip: Dict[str, List[Dict[str, Any]]],
        ptr_pairs: Dict[str, List[Tuple[str, str]]],
        *,
        row_view: bool = False,
        save_view: bool = False,
        owner: Optional[OwnerFn] = None,
        fallback_view: str = "",
        duid: bool = False,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        One row per address and network view that has a record, in input order then view order, passed
        through the ``pre_save`` and ``pre_render`` hooks. Both hooks receive their own dict of the row,
        keyed by ``COLUMNS`` (``COLUMNS_WITH_DUID`` when ``duid``: the run looks up an IPv6 address, and an
        IPv4 row has an empty ``DUID``), led by ``Network view`` when it is shown (``row_view`` for the
        printed row, ``save_view`` for the saved one; ``fallback_view`` names a row the answer did not label).
        ``PTR name`` comes from ``ptr_pairs[ip]`` through ``_ptr_name`` (``owner`` pairs the DNS views with
        the network views), empty for an address without one (or whose lookup failed). An IPv6 row has no
        MAC (Infoblox keeps none for ``ipv6address``) and never a ``None`` cell: what its answer lacks is "".

        Returns ``(save_rows, print_rows)``. A save row is what ``pre_save`` returned (it may add,
        drop or reorder fields; an empty row is left out of the report) plus every column that
        ``pre_render`` added to the printed row and ``pre_save`` did not set.
        """
        save_rows: List[Dict[str, Any]] = []
        print_rows: List[Dict[str, Any]] = []
        columns = COLUMNS_WITH_DUID if duid else COLUMNS

        for ip in ip_addresses:
            for data in processed_data_by_ip.get(ip, []):
                general_data = data.get("general", [{}])[0]
                extra_data = data.get("extra", [{}])[0]
                if _is_ipv6(ip):
                    extra_data = {**_NO_EXTRA, **extra_data}
                view = str(general_data.get(NETWORK_VIEW) or "")

                values = [
                    general_data.get("network"), general_data.get("ip"), general_data.get("name"),
                    general_data.get("status"), extra_data.get("lease state"),
                    extra_data.get("record type"), extra_data.get("mac"),
                ]
                if duid:
                    values.append(extra_data.get("duid") or "")
                values.append(_ptr_name(ptr_pairs.get(ip, []), view or fallback_view, owner))
                row = dict(zip(columns, values))
                if NETWORK_VIEW in general_data:
                    row = {NETWORK_VIEW_TITLE: view, **row}

                # HOOK: Allows plugins to modify data just before saving.
                save_row = self.execute_hook(
                    'pre_save', ctx, present_rows([row], NETWORK_VIEW_TITLE, save_view, fallback=fallback_view)[0]
                )

                # HOOK: Allows plugins to modify data just before rendering.
                print_row = self.execute_hook(
                    'pre_render', ctx, present_rows([row], NETWORK_VIEW_TITLE, row_view, fallback=fallback_view)[0]
                )
                print_rows.append(print_row)

                if save_row:
                    added = {
                        name: value for name, value in print_row.items()
                        if name not in columns and name != NETWORK_VIEW_TITLE and name not in save_row
                    }
                    save_rows.append({**save_row, **added})

        return save_rows, print_rows

    def _save_report(
        self,
        ctx: ScriptContext,
        ip_addresses: List[str],
        processed_data_by_ip: Dict[str, List[Dict[str, Any]]],
        save_rows: List[Dict[str, Any]],
    ) -> None:
        """Queue the "IP Data" sheet rows (misses, then hits) when ``report_auto_save`` is on."""
        if not ctx.cfg["report_auto_save"]:
            return

        successful_ips: Set[str] = set(processed_data_by_ip)
        missing_ip_addresses = [ip for ip in ip_addresses if ip not in successful_ips]
        if missing_ip_addresses:
            missed_ip_data = [[ip, "No Information"] for ip in missing_ip_addresses]
            queue_save(ctx, ["IP", "Status"], missed_ip_data, sheet_name="IP Data", index=False, force_header=True)

        if save_rows:
            # The header is the union of the rows' field names, so every value sits under its own name.
            columns = table_columns(save_rows)
            queue_save(
                ctx, columns, [[row.get(column, '') for column in columns] for row in save_rows],
                sheet_name="IP Data", index=False, force_header=True,
            )
