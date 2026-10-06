import argparse
import ipaddress
from time import perf_counter
from typing import Dict, Any, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor

from rich.markup import escape

from core.base import BaseModule, CliResult, ScriptContext, cli_exit_code
from utils.api import bound_infoblox_workers, describe_infoblox_failure, request_result
from utils.auth import ensure_infoblox_auth
from utils.cli_input import read_objects
from utils.display import console, get_global_color_scheme, print_table_data, table_columns
from utils.file_io import queue_save
from utils.process_data import process_data
from utils.user_input import press_any_key, read_user_input

RESERVED_ADDRESS = "Invalid IP: Broadcast, unspecified, and reserved IPs are excluded."
IPV6_UNSUPPORTED = "IPv6 lookups are not supported in this module yet. Please enter an IPv4 address."
INVALID_FORMAT = "Invalid IP format. Please enter a valid IPv4 address."
NO_RECORD = "No matching IPv4 record found"

COLUMNS = ["Subnet", "IP", "Name", "Status", "Lease State", "Record Type", "MAC", "PTR name"]


def _validate_ip(ctx: ScriptContext, text: str) -> Optional[str]:
    """
    Why ``text`` cannot be looked up (the message the menu shows), or None for a usable IPv4 address.

    ``ctx`` is not used yet; it keeps the call shape every module's validator shares.
    """
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return INVALID_FORMAT
    if ip.is_unspecified or ip.is_reserved or ip.is_link_local:
        return RESERVED_ADDRESS
    if ip.version != 4:
        return IPV6_UNSUPPORTED
    return None


def _publishes_ptr(data: Dict[str, Any]) -> bool:
    """True when the record types of a processed address (``extra``/``record type``) include PTR."""
    return "PTR" in str(data.get("extra", [{}])[0].get("record type", "")).split(",")


def _ptr_addresses(ip_addresses: List[str], processed_data_by_ip: Dict[str, Dict[str, Any]]) -> List[str]:
    """The addresses, in input order, that have a record with the PTR type: the ones worth a PTR lookup."""
    return [ip for ip in ip_addresses if ip in processed_data_by_ip and _publishes_ptr(processed_data_by_ip[ip])]


def _ptr_warnings(ptr_failures: Dict[str, str]) -> List[Dict[str, str]]:
    """The ``warnings`` rows (``object``/``warning``) of the failed PTR lookups, in lookup order."""
    return [{"object": ip, "warning": f"PTR lookup failed: {reason}"} for ip, reason in ptr_failures.items()]


def _explain_misses(
    ip_addresses: List[str], processed_data_by_ip: Dict[str, Dict[str, Any]], failed_ips: Dict[str, str]
) -> Dict[str, str]:
    """The reason each address in ``ip_addresses`` has no row, in input order."""
    return {
        ip: failed_ips.get(ip, NO_RECORD)
        for ip in ip_addresses
        if ip not in processed_data_by_ip
    }


def _publish_stats(
    ctx: ScriptContext,
    input_count: int,
    ip_addresses: List[str],
    processed_data_by_ip: Dict[str, Dict[str, Any]],
    print_data_all: List[Dict[str, Any]],
) -> None:
    """Report the run to the usage statistics: the same event from the menu and the command line."""
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
    Module to fetch detailed information about one or more IP addresses from the API.
    """
    cli_name = "ip"

    @property
    def menu_key(self) -> str:
        return "1"

    @property
    def menu_title(self) -> str:
        return "IP Information (IPv4)"

    @property
    def visibility_config_key(self) -> Optional[str]:
        # This module will only appear in the menu if 'infoblox_enabled' is True in the config.
        return "infoblox_enabled"

    def run(self, ctx: ScriptContext) -> None:
        """
        Requests user to provide IPv4 address(es), validates the input, calls the API,
        processes the data, and then prints and/or saves it.
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - IP Information (IPv4)")

        ensure_infoblox_auth(ctx)

        console.print(
            "\n"
            f"[{colors['description']}]Please provide an IPv4 address or a list of IPv4 addresses, one per line.[/]\n"
            f"[{colors['description']}]This module is IPv4-only and will request hostname, location, and network configuration details.[/]\n"
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
            problem = _validate_ip(ctx, search_input)
            if problem:
                console.print(f"[{colors['error']}]{problem}[/]")
            else:
                ip_addresses_input.append(search_input)

        if not ip_addresses_input:
            return

        # Remove duplicates while preserving order
        ip_addresses = list(dict.fromkeys(ip_addresses_input))

        # --- API Call and Data Processing ---
        processed_data_by_ip, failed_ips = self._fetch_ips(ctx, ip_addresses)
        ptr_names, ptr_failures = self._fetch_ptr_names(ctx, _ptr_addresses(ip_addresses, processed_data_by_ip))

        # --- Display and Save Results ---
        for ip, reason in _explain_misses(ip_addresses, processed_data_by_ip, failed_ips).items():
            console.print(f"[{colors['success']} {colors['bold']}]{ip}[/] - [{colors['error']}]{reason}[/]")

        save_rows, print_data_all = self._build_rows(ctx, ip_addresses, processed_data_by_ip, ptr_names)

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
        ``cn ip``: look up the addresses named on the command line, in ``--file`` and/or on stdin.

        Returns the sections ``IP Information`` (one row per address with a record, an unused
        address inside a managed network included), ``not_found`` (every other object and why) and
        ``warnings`` (``object``/``warning`` for each address whose PTR lookup failed); every key is
        always present and the caller renders them. Never prompts.
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - IP Information (IPv4)")

        try:
            objects = read_objects(args.objects, args.file)
        except (OSError, UnicodeDecodeError) as exc:  # a file that is missing, a directory or not UTF-8
            source = "standard input" if args.file in (None, "-") else args.file
            reason = getattr(exc, "strerror", None) or exc
            console.print(f"[{colors['error']}]cn ip: cannot read {escape(str(source))}: {escape(str(reason))}[/]")
            return CliResult(2, {})
        if not objects:
            console.print(f"[{colors['error']}]cn ip: no IPv4 addresses given; see cn ip --help[/]")
            return CliResult(2, {})

        reasons: Dict[str, str] = {}
        ip_addresses: List[str] = []
        for obj in objects:
            problem = _validate_ip(ctx, obj)
            if problem:
                reasons[obj] = problem
            else:
                ip_addresses.append(obj)
        invalid = bool(reasons)

        processed_data_by_ip: Dict[str, Dict[str, Any]] = {}
        failed_ips: Dict[str, str] = {}
        ptr_failures: Dict[str, str] = {}
        print_data_all: List[Dict[str, Any]] = []
        if ip_addresses:
            ensure_infoblox_auth(ctx)
            processed_data_by_ip, failed_ips = self._fetch_ips(ctx, ip_addresses)
            ptr_names, ptr_failures = self._fetch_ptr_names(ctx, _ptr_addresses(ip_addresses, processed_data_by_ip))
            save_rows, print_data_all = self._build_rows(ctx, ip_addresses, processed_data_by_ip, ptr_names)
            self._save_report(ctx, ip_addresses, processed_data_by_ip, save_rows)
            _publish_stats(ctx, len(ip_addresses), ip_addresses, processed_data_by_ip, print_data_all)
            reasons.update(_explain_misses(ip_addresses, processed_data_by_ip, failed_ips))

        data = {
            "IP Information": print_data_all,
            "not_found": [{"object": obj, "reason": reasons[obj]} for obj in objects if obj in reasons],
            "warnings": _ptr_warnings(ptr_failures),
        }
        failed = bool(failed_ips or ptr_failures)
        return CliResult(cli_exit_code(found=bool(print_data_all), invalid=invalid, failed=failed), data)

    def _fetch_ips(
        self, ctx: ScriptContext, ip_addresses: List[str]
    ) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
        """
        Ask Infoblox about each address and run the ``process_data`` hook on every answer.

        Returns the processed data of the addresses that have a record, and the failure
        message of each address whose lookup failed (an address with no record is in neither).
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info(f"User input - IPs: {', '.join(ip_addresses)}")

        start = perf_counter()
        req_urls = {ip: f"ipv4address?ip_address={ip}&_return_fields=network,names,status,types,lease_state,mac_address" for ip in ip_addresses}

        with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, len(req_urls))) as executor, console.status(f"[{colors['description']}]Fetching IP information...[/]"):
            future_to_ip = {executor.submit(request_result, ctx, uri, ensure_auth=False): ip for ip, uri in req_urls.items()}
            results = {future_to_ip[future]: future.result() for future in future_to_ip}

        processed_data_by_ip: Dict[str, Dict[str, Any]] = {}
        failed_ips: Dict[str, str] = {}
        for ip, response in results.items():
            if response.ok:
                data = process_data(ctx, type="ip", content=response.content)

                # --- HOOK: Allows plugins to modify the processed data ---
                data = self.execute_hook('process_data', ctx, data)

                if data and data.get("general"):
                    processed_data_by_ip[ip] = data
            elif response.failed:
                failed_ips[ip] = describe_infoblox_failure(response)

        end = perf_counter()
        logger.info(f"IP Information search took {round(end - start, 3)} seconds!")
        console.print(f"[{colors['description']}]Request Type - IP Information (IPv4) - Search took [{colors['success']}]{round(end-start, 3)}[/] seconds![/]")
        return processed_data_by_ip, failed_ips

    def _fetch_ptr_names(self, ctx: ScriptContext, ips: List[str]) -> Tuple[Dict[str, str], Dict[str, str]]:
        """
        Ask Infoblox for the PTR records at each address of ``ips``: one ``record:ptr`` request per
        address, in parallel, none when ``ips`` is empty.

        Returns ``(names, failures)``: the ptrdnames of each address that has any (comma-joined,
        a name held in several views once), and the failure message of each address whose
        lookup failed. An address with no PTR record is in neither.
        """
        if not ips:
            return {}, {}

        colors = get_global_color_scheme(ctx.cfg)
        req_urls = {ip: f"record:ptr?ipv4addr={ip}&_return_fields=ptrdname" for ip in ips}

        with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, len(req_urls))) as executor, console.status(f"[{colors['description']}]Fetching PTR records...[/]"):
            futures = {ip: executor.submit(request_result, ctx, uri, ensure_auth=False) for ip, uri in req_urls.items()}
            results = {ip: future.result() for ip, future in futures.items()}

        names: Dict[str, str] = {}
        failures: Dict[str, str] = {}
        for ip, response in results.items():
            if response.failed:
                failures[ip] = describe_infoblox_failure(response)
                continue
            found = list(dict.fromkeys(item["ptrdname"] for item in response.items if item.get("ptrdname")))
            if found:
                names[ip] = ",".join(found)
        return names, failures

    def _build_rows(
        self,
        ctx: ScriptContext,
        ip_addresses: List[str],
        processed_data_by_ip: Dict[str, Dict[str, Any]],
        ptr_names: Dict[str, str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        One row per address that has a record, in input order, passed through the ``pre_save``
        and ``pre_render`` hooks. Both hooks receive their own dict of the row, keyed by ``COLUMNS``;
        ``PTR name`` is ``ptr_names[ip]``, empty for an address without one (or whose lookup failed).

        Returns ``(save_rows, print_rows)``. A save row is what ``pre_save`` returned (it may add,
        drop or reorder fields; an empty row is left out of the report) plus every column that
        ``pre_render`` added to the printed row and ``pre_save`` did not set.
        """
        save_rows: List[Dict[str, Any]] = []
        print_rows: List[Dict[str, Any]] = []

        for ip in ip_addresses:
            if ip in processed_data_by_ip:
                general_data = processed_data_by_ip[ip].get("general", [{}])[0]
                extra_data = processed_data_by_ip[ip].get("extra", [{}])[0]

                row = dict(zip(COLUMNS, [
                    general_data.get("network"), general_data.get("ip"), general_data.get("name"),
                    general_data.get("status"), extra_data.get("lease state"),
                    extra_data.get("record type"), extra_data.get("mac"), ptr_names.get(ip, ""),
                ]))

                # HOOK: Allows plugins to modify data just before saving.
                save_row = self.execute_hook('pre_save', ctx, dict(row))

                # HOOK: Allows plugins to modify data just before rendering.
                print_row = self.execute_hook('pre_render', ctx, dict(row))
                print_rows.append(print_row)

                if save_row:
                    added = {name: value for name, value in print_row.items() if name not in COLUMNS and name not in save_row}
                    save_rows.append({**save_row, **added})

        return save_rows, print_rows

    def _save_report(
        self,
        ctx: ScriptContext,
        ip_addresses: List[str],
        processed_data_by_ip: Dict[str, Dict[str, Any]],
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
