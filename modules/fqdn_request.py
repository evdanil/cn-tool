# modules/fqdn_request.py
import argparse
import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Collection, Dict, List, Optional, Set, Tuple, Union

from rich.markup import escape

from core.base import BaseModule, CliResult, ScriptContext, cli_exit_code
from utils.api import (
    WAPI_MAX_ROWS, InfobloxResult, bound_infoblox_workers, describe_infoblox_failure, request_result,
)
from utils.auth import ensure_infoblox_auth
from utils.cli_input import read_objects
from utils.display import console, get_global_color_scheme, print_table_data
from utils.file_io import queue_save
from utils.infoblox_ux import format_no_match_message
from utils.network_views import DNS_VIEW, ViewScope, present_rows, scope_dns, scope_network, view_scope
from utils.process_data import process_data
from utils.user_input import press_any_key, read_user_input

# (label, WAPI object, return fields) of the four record searches, each filtered by ``name~=<prefix>``.
RECORD_SEARCHES: Tuple[Tuple[str, str, str], ...] = (
    ("A", "record:a", "name,ipv4addr,zone,ttl,use_ttl,view"),
    ("AAAA", "record:aaaa", "name,ipv6addr,zone,ttl,use_ttl,view"),
    ("HOST", "record:host", "name,ipv4addrs,ipv6addrs,zone,ttl,use_ttl,configure_for_dns,view"),
    ("CNAME", "record:cname", "name,canonical,zone,ttl,use_ttl,view"),
)
# The PTR records pointing at a name that contains the prefix: one search per prefix, not one per address.
PTR_SEARCH = "record:ptr?ptrdname~={prefix}&_return_fields=ptrdname,ipv4addr,ipv6addr,view"
NO_MATCH_REASON = "No matching record"
PTR_LEGEND = (
    "PTR: ok = a PTR record on the grid at this address points back to the name; "
    "missing = no PTR record on the grid does (cn ip <address> shows the PTR it has); "
    "host record = a host record configured for DNS publishes its own PTR (not checked)."
)


@dataclass
class FqdnLookup:
    """
    The outcome of searching one prefix.

    ``warnings`` holds a line per failed or truncated search, ``failed`` says that a search
    failed (the lookup is incomplete), and ``reason`` is why ``rows`` may be empty: the first
    failure, else "No matching record".
    """

    rows: List[Dict[str, Any]]
    warnings: List[str]
    failed: bool
    reason: str = ""


IN_DNS_VIEW = " in DNS view "  # a search of one DNS view is labelled "A records in DNS view default.prod"


def _search_uris(
    prefix: str, scope: Optional[ViewScope]
) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str, str]]]:
    """
    The searches of one prefix: ``([(label, uri)], [(DNS view, label, uri)])``, the record searches and the PTR searches.

    Without a requested network view these are today's five searches (the PTR one has the DNS view "").
    With one, A, AAAA, CNAME and PTR run once per DNS view of the network view, labelled "A records in DNS
    view default.prod" and "PTR check in DNS view default.prod", and host records run once, limited to the
    network view: ``1 + 4k`` requests for k DNS views. A host record search also finds the IPAM-only hosts,
    which have no DNS view. A network view without a DNS view runs only the host search.
    """
    ptr_uri = PTR_SEARCH.format(prefix=prefix)
    requested = scope.requested if scope is not None else ""
    if scope is None or not requested:
        records = [(f"{label} records", f"{wapi_object}?name~={prefix}&_return_fields={fields}")
                   for label, wapi_object, fields in RECORD_SEARCHES]
        return records, [("", "PTR check", ptr_uri)]

    dns_views = scope.dns_views()
    records = []
    for label, wapi_object, fields in RECORD_SEARCHES:
        uri = f"{wapi_object}?name~={prefix}&_return_fields={fields}"
        if label == "HOST":  # by network view: its DNS view is not what finds an IPAM-only host
            records.append((f"{label} records", scope_network(uri, requested)))
        else:
            records.extend((f"{label} records{IN_DNS_VIEW}{dns_view}", scope_dns(uri, dns_view)) for dns_view in dns_views)
    ptr = [(dns_view, f"PTR check{IN_DNS_VIEW}{dns_view}", scope_dns(ptr_uri, dns_view)) for dns_view in dns_views]
    return records, ptr


def _validate_prefix(ctx: ScriptContext, text: str) -> Optional[str]:
    """Why ``text`` (lower-cased and stripped) cannot be searched, or None when it can."""
    if len(text) < 3:
        ctx.logger.info("User input - FQDN Search - Prefix is less than 3 chars")
        return "Please use a longer prefix (at least 3 characters)."

    # A simple prefix is not a valid FQDN, so we just check for invalid characters.
    if not re.match(r"^[a-zA-Z0-9.-]+$", text):
        ctx.logger.info(f"User input - FQDN Search - Incorrect FQDN/prefix: {text}")
        return "Input contains invalid characters."

    return None


def _publish_stats(ctx: ScriptContext, queries: int, successes: int, results: int) -> None:
    ctx.event_bus.publish(
        "stats:module_detail",
        {
            "unit_count": queries,
            "query_count": queries,
            "result_count": results,
            "success_count": successes,
        },
    )


def _unique_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    ``rows`` without repeats, in first-seen order (overlapping prefixes find the same record twice).

    Only true duplicates merge: the copies of a record in two DNS views differ in their ``DNS view``.
    """
    # A repeated key keeps its first position in the dict; the row it re-assigns is equal anyway.
    return list({tuple(sorted(row.items())): row for row in rows}.values())


def _dns_views(rows: List[Dict[str, Any]]) -> List[str]:
    """The DNS views the ``rows`` name (a row of an IPAM-only host names none)."""
    return [str(row.get(DNS_VIEW) or "") for row in rows]


def _with_dns_view_column(rows: List[Dict[str, Any]], show: bool) -> List[Dict[str, Any]]:
    """Copies of ``rows`` with the ``DNS view`` column before the zone (``show``) or without it."""
    return present_rows(rows, DNS_VIEW, show, before="zone")


def _address(text: Any) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """``text`` as an address object (so every spelling of an IPv6 address compares equal), or None."""
    try:
        return ipaddress.ip_address(str(text))
    except ValueError:
        return None


def _bare_name(name: Any) -> str:
    """``name`` for comparison: lower case, without the trailing dot."""
    return str(name or "").lower().rstrip(".")


def _apply_ptr_verdicts(
    rows: List[Dict[str, Any]],
    ptr_items: Optional[List[Dict[str, Any]]],
    unchecked_views: Collection[str] = (),
) -> None:
    """
    Set the ``PTR`` column of ``rows``: ok, missing, host record (not checked) or "" (CNAME).

    A row is ``ok`` when a PTR record at its address points back to its name. A row that names a
    DNS view needs that PTR in the same DNS view; a row without one (an IPAM-only host, or an answer
    without the field) is ``ok`` with a PTR in any view. A host row says ``host record`` instead,
    unless its ``configure_for_dns`` is False (a host that publishes no DNS; absent means True): that
    one is checked like an A record. The flag only feeds the verdict, so it is removed from the rows.

    ``ptr_items`` is None when the PTR search failed or was cut short: no verdict can be trusted, so
    every one stays "". A row of a DNS view in ``unchecked_views`` (its own PTR search failed or was
    cut short) stays "" too, while the rows of the other views get their verdicts.
    """
    in_view: Set[Tuple[str, Any, str]] = set()  # (DNS view, address, name) of every PTR record
    in_any_view: Set[Tuple[Any, str]] = set()  # the same without the DNS view, for a row that has none
    for item in ptr_items or ():
        address = _address(item.get("ipv4addr") or item.get("ipv6addr"))
        if address is None:
            continue
        name = _bare_name(item.get("ptrdname"))
        in_view.add((str(item.get("view") or "").strip(), address, name))
        in_any_view.add((address, name))
    for row in rows:
        configured_for_dns = row.pop("configure_for_dns", True)
        dns_view = str(row.get(DNS_VIEW) or "")
        if ptr_items is None or row["type"] == "CNAME" or (dns_view and dns_view in unchecked_views):
            row["PTR"] = ""
        elif row["type"] == "HOST" and configured_for_dns:
            row["PTR"] = "host record"
        else:
            pointer = (_address(row["ip"]), _bare_name(row["name"]))
            found = (dns_view, *pointer) in in_view if dns_view else pointer in in_any_view
            row["PTR"] = "ok" if found else "missing"


def _failure_reason(label: str, result: InfobloxResult) -> str:
    """Why a search failed, as the ``not_found`` reason: plain, except that a DNS view's search names its DNS view."""
    reason = describe_infoblox_failure(result)
    return f"{label}: {reason.removesuffix('.')}" if IN_DNS_VIEW in label else reason


def _no_dns_view_note(scope: ViewScope) -> str:
    """The note for a requested network view that holds no DNS view (only its host records are found); "" otherwise."""
    if scope.requested and not scope.dns_views():
        return f"network view {scope.requested} has no DNS view: only host records were searched"
    return ""


def _ptr_left_empty(dns_view: str) -> str:
    """What a PTR warning says about the column: all of it, or the rows of the DNS view that was searched."""
    return "PTR left empty for that view's rows." if dns_view else "PTR column left empty."


class FQDNRequestModule(BaseModule):
    """
    Module to search for DNS A, AAAA, host and CNAME records by a full FQDN or a part of a name.
    """
    cli_name = "fqdn"

    @property
    def menu_key(self) -> str:
        return "3"

    @property
    def menu_title(self) -> str:
        return "FQDN Prefix Lookup"

    @property
    def visibility_config_key(self) -> Optional[str]:
        # This module will only appear in the menu if 'infoblox_enabled' is True in the config.
        return "infoblox_enabled"

    def _search(self, ctx: ScriptContext, prefix: str, scope: Optional[ViewScope] = None) -> FqdnLookup:
        """
        Search the A, AAAA, host and CNAME records of one valid prefix, and the PTR records of the same names.

        Without a requested network view (``scope`` None, or one that requests none) five paged requests
        run in parallel. With one, each DNS view of the network view is searched for A, AAAA, CNAME and PTR
        records and the host records are searched once by network view (``_search_uris``): ``1 + 4k``
        requests. A search that failed or hit the paging limit adds a warning naming its DNS view; the
        rows of the others are still returned, sorted by name, type, address and DNS view. Only true
        duplicates are merged: a record held in two DNS views is two rows. Each row gets its PTR verdict
        from the PTR records of its own DNS view, and the ``process_data`` hook then sees the rows unless
        every record search failed. Shared by the menu and the command line.
        """
        colors = get_global_color_scheme(ctx.cfg)
        record_searches, ptr_searches = _search_uris(prefix, scope)
        uris = [uri for _, uri in record_searches] + [uri for _, _, uri in ptr_searches]
        with ctx.console.status(f"[{colors['description']}]Fetching data for [{colors['header']}]{prefix}[/]...[/]"):
            with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, len(uris))) as executor:
                futures = [executor.submit(request_result, ctx, uri, ensure_auth=False, paged=True) for uri in uris]
                results = [future.result() for future in futures]
        record_results, ptr_results = results[:len(record_searches)], results[len(record_searches):]

        items: List[Dict[str, Any]] = []
        warnings: List[str] = []
        reasons: List[str] = []
        for (label, _), result in zip(record_searches, record_results):
            if result.failed:
                reasons.append(_failure_reason(label, result))
                warnings.append(f"{label}: {describe_infoblox_failure(result).removesuffix('.')}")
                continue
            items.extend(result.items)
            if result.truncated:
                warnings.append(f"{label}: showing the first {WAPI_MAX_ROWS:,} only (paging limit); use a longer name.")
        every_record_search_failed = len(reasons) == len(record_searches)

        ptr_items: List[Dict[str, Any]] = []  # the PTR records of every search that answered in full
        ptr_trusted = True  # False: the one search of every view failed, so there is no PTR verdict at all
        unchecked_views: Set[str] = set()  # DNS views whose rows get no PTR verdict
        for (dns_view, label, _), result in zip(ptr_searches, ptr_results):
            if result.failed:
                reasons.append(_failure_reason(label, result))
                cause = describe_infoblox_failure(result).removesuffix(".")
                warnings.append(f"{label}: {cause}; " + _ptr_left_empty(dns_view))
            elif result.truncated:
                warnings.append(f"{label}: more than {WAPI_MAX_ROWS:,} PTR records match; " + _ptr_left_empty(dns_view))
            else:
                ptr_items.extend(result.items)
                continue
            if dns_view:
                unchecked_views.add(dns_view)
            else:
                ptr_trusted = False

        rows = process_data(ctx, type="fqdn", content=json.dumps(items).encode()).get("fqdn") or []
        rows = sorted(rows, key=lambda row: (row["name"], row["type"], row["ip"], row.get(DNS_VIEW, "")))
        _apply_ptr_verdicts(rows, ptr_items if ptr_trusted else None, unchecked_views)
        rows = _unique_rows(rows)  # after the verdicts: they drop the flag that could keep two copies apart
        if not every_record_search_failed:
            rows = (self.execute_hook('process_data', ctx, {"fqdn": rows}) or {}).get("fqdn") or []
        no_match = scope.scoped(NO_MATCH_REASON) if scope is not None else NO_MATCH_REASON
        return FqdnLookup(rows, warnings, failed=bool(reasons), reason=reasons[0] if reasons else no_match)

    def _save(self, ctx: ScriptContext, rows: List[Dict[str, Any]], scope: Optional[ViewScope] = None) -> None:
        """
        Queue ``rows``, as changed by the ``pre_save`` hook, for the report when auto-save is on.

        The sheet carries the ``DNS view`` column by the same per-grid rule as a table (``scope.column``),
        also in a JSON run: the report does not follow the format.
        """
        if not ctx.cfg["report_auto_save"]:
            return
        if scope is not None:
            rows = _with_dns_view_column(rows, scope.column(_dns_views(rows), dns=True))
        final_save_data = self.execute_hook('pre_save', ctx, rows)

        if final_save_data:
            final_columns = list(final_save_data[0].keys())
            save_data_list_of_lists = [[row.get(col, '') for col in final_columns] for row in final_save_data]
            queue_save(ctx, final_columns, save_data_list_of_lists, sheet_name="FQDN Data", index=False, force_header=True)

    def run(self, ctx: ScriptContext) -> None:
        """
        Requests user to provide an FQDN string or prefix, validates it,
        fetches and processes data, and then prints or saves it.

        A network view set in ``[api] network_view`` is checked first, before anything is asked, and
        named in a banner; only its DNS views and host records are then searched.
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - FQDN Search - DNS A/AAAA/host/CNAME records")

        ensure_infoblox_auth(ctx)

        # A configured network view is checked before anything is asked: a wrong setting should not cost a typed name.
        scope = view_scope(ctx, None, request_result)
        view_problem = scope.problem()
        if view_problem:
            console.print(f"[{colors['error']}]{escape(view_problem.message)}[/]")
            press_any_key(ctx)
            return

        console.print(
            "\n"
            f"[{colors['description']}]Type in just a part of the name or a complete FQDN (not less than 3 chars).[/]\n"
            f"[{colors['description']}]This request fetches A, AAAA, host and CNAME records whose name contains the provided text.[/]\n"
            f"[{colors['description']}]Results are paged: up to [{colors['error']} {colors['bold']}]{WAPI_MAX_ROWS:,}[/] records per record type.[/]\n"
            f"[{colors['header']}]Examples:[/]\n"
            f"[{colors['success']}][{colors['bold']}]'branchsw'[/] fetches records starting with [{colors['white']} {colors['bold']}]branchsw[/].\n"
            f"[{colors['success']}][{colors['bold']}]'branchsw010'[/] fetches the specific record for the device.\n"
            f"[{colors['success']}][{colors['bold']}]'branchsw010.example.net'[/] also fetches the specific record.[/]\n"
        )
        banner = scope.banner(dns=True)  # names the network view and its DNS views; "" when every view is searched
        if banner:
            console.print(f"[{colors['warning']}]{escape(banner)}[/]\n")

        # --- User Input and Validation ---
        fqdn = read_user_input(
            ctx, "Enter the device name (FQDN or prefix): "
        ).lower().strip()

        logger.info(f"User input - FQDN Search for: {fqdn}")

        problem = _validate_prefix(ctx, fqdn)
        if problem:
            console.print(f"[{colors['error']}]{problem}[/]")
            press_any_key(ctx)
            return

        # --- API Call and Data Processing ---
        note = _no_dns_view_note(scope)
        if note:
            console.print(f"[{colors['warning']}]{escape(note)}[/]")
        lookup = self._search(ctx, fqdn, scope)
        for warning in lookup.warnings:
            console.print(f"[{colors['warning']}]{escape(warning)}[/]")

        if not lookup.rows:
            if lookup.failed:
                logger.info("Request Type - FQDN Search - Request failed")
                console.print(f"[{colors['error']}]{escape(lookup.reason)}[/]")
            else:
                logger.info("Request Type - FQDN Search - No matching records found")
                console.print(f"[{colors['error']}]{escape(scope.scoped(format_no_match_message('DNS records', fqdn)))}[/]")
            press_any_key(ctx)
            return

        # --- Display and Save Results ---
        shown = _with_dns_view_column(lookup.rows, scope.column(_dns_views(lookup.rows), dns=True))
        print_table_data(ctx, {"fqdn": shown}, suffix={"fqdn": "Search Results"})
        console.print(f"[dim]{PTR_LEGEND}[/]")
        logger.debug(f"Request Type - FQDN Search - processed data: {lookup.rows}")

        self._save(ctx, lookup.rows, scope)

        _publish_stats(ctx, queries=1, successes=1, results=len(lookup.rows))

        press_any_key(ctx)

    def run_cli(self, ctx: ScriptContext, args: argparse.Namespace) -> CliResult:
        """
        ``cn fqdn <prefix>...``: the searches of every prefix, the records of all of them in one section.

        Five searches run per prefix; with a requested network view (``--view`` or ``[api] network_view``)
        its DNS views are searched instead, ``1 + 4k`` for k DNS views. The view is checked after the login,
        once something valid is left to search: an unknown one exits 2 and a view list that cannot be read
        exits 3, with ``{}`` as the result.

        A record held in several DNS views is a row for each. A record found under several prefixes is
        listed once. A prefix that cannot be searched or has no record is listed in ``not_found`` with the
        reason (the first failure when a search failed, naming its DNS view). A failed or truncated search
        is a row of ``warnings``; a failed one also makes the run incomplete (exit 3). Every section key is
        always present, and the rows carry ``DNS view`` (JSON ``dns_view``) by the per-grid rule of
        ``ViewScope.result_column``.
        """
        logger = ctx.logger
        logger.info("Request Type - FQDN Search - command line")

        try:
            objects = read_objects(args.objects, args.file)
        except OSError as exc:
            ctx.console.print(f"Cannot read the object file: {exc}", markup=False)
            return CliResult(2, {})
        if not objects:
            ctx.console.print("No FQDN or prefix given.")
            return CliResult(2, {})

        scope = view_scope(ctx, args, request_result)
        rows: List[Dict[str, Any]] = []
        not_found: List[Dict[str, str]] = []
        warnings: List[Dict[str, str]] = []
        searched = successes = 0
        invalid = failed = authenticated = False
        for obj in objects:
            prefix = obj.lower()
            problem = _validate_prefix(ctx, prefix)
            if problem:
                invalid = True
                not_found.append({"object": obj, "reason": problem})
                continue

            if not authenticated:  # only once there is something to search
                ensure_infoblox_auth(ctx)
                authenticated = True
                view_problem = scope.problem()
                if view_problem:
                    ctx.console.print(f"cn fqdn: {view_problem.message}", markup=False)
                    return CliResult(view_problem.exit_code, {})
                note = _no_dns_view_note(scope)
                if note:
                    ctx.console.print(f"cn fqdn: {note}", markup=False)

            searched += 1
            lookup = self._search(ctx, prefix, scope)
            if lookup.failed:
                failed = True
                logger.info(f"Request Type - FQDN Search - Request failed for {prefix}")
            for warning in lookup.warnings:
                ctx.console.print(f"{obj}: {warning}", markup=False)
                warnings.append({"object": obj, "warning": warning})

            if not lookup.rows:
                logger.info(f"Request Type - FQDN Search - No records for {prefix}: {lookup.reason}")
                not_found.append({"object": obj, "reason": lookup.reason})
                continue

            successes += 1
            rows.extend(lookup.rows)

        rows = _unique_rows(rows)  # before the save and the statistics: both count each record once
        if rows:
            self._save(ctx, rows, scope)
            _publish_stats(ctx, queries=searched, successes=successes, results=len(rows))
            rows = _with_dns_view_column(rows, scope.result_column(_dns_views(rows), dns=True))

        exit_code = cli_exit_code(found=bool(rows), invalid=invalid, failed=failed)
        return CliResult(exit_code, {"fqdn": rows, "not_found": not_found, "warnings": warnings})
