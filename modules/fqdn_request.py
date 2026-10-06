# modules/fqdn_request.py
import argparse
import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from core.base import BaseModule, CliResult, ScriptContext, cli_exit_code
from utils.api import WAPI_MAX_ROWS, bound_infoblox_workers, describe_infoblox_failure, request_result
from utils.auth import ensure_infoblox_auth
from utils.cli_input import read_objects
from utils.display import console, get_global_color_scheme, print_table_data
from utils.file_io import queue_save
from utils.infoblox_ux import format_no_match_message
from utils.process_data import process_data
from utils.user_input import press_any_key, read_user_input

# (label, WAPI object, return fields) of the four record searches, each filtered by ``name~=<prefix>``.
RECORD_SEARCHES: Tuple[Tuple[str, str, str], ...] = (
    ("A", "record:a", "name,ipv4addr,zone,ttl,use_ttl"),
    ("AAAA", "record:aaaa", "name,ipv6addr,zone,ttl,use_ttl"),
    ("HOST", "record:host", "name,ipv4addrs,ipv6addrs,zone,ttl,use_ttl,configure_for_dns"),
    ("CNAME", "record:cname", "name,canonical,zone,ttl,use_ttl"),
)
# The PTR records pointing at a name that contains the prefix: one search per prefix, not one per address.
PTR_SEARCH = "record:ptr?ptrdname~={prefix}&_return_fields=ptrdname,ipv4addr,ipv6addr"
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
    """``rows`` without repeats, in first-seen order (overlapping prefixes find the same record twice)."""
    # A repeated key keeps its first position in the dict; the row it re-assigns is equal anyway.
    return list({tuple(sorted(row.items())): row for row in rows}.values())


def _address(text: Any) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """``text`` as an address object (so every spelling of an IPv6 address compares equal), or None."""
    try:
        return ipaddress.ip_address(str(text))
    except ValueError:
        return None


def _bare_name(name: Any) -> str:
    """``name`` for comparison: lower case, without the trailing dot."""
    return str(name or "").lower().rstrip(".")


def _ptr_verdict(row: Dict[str, Any], pointers: Optional[Set[Tuple[Any, str]]], configured_for_dns: bool) -> str:
    if pointers is None or row["type"] == "CNAME":
        return ""
    if row["type"] == "HOST" and configured_for_dns:
        return "host record"
    return "ok" if (_address(row["ip"]), _bare_name(row["name"])) in pointers else "missing"


def _apply_ptr_verdicts(rows: List[Dict[str, Any]], ptr_items: Optional[List[Dict[str, Any]]]) -> None:
    """
    Set the ``PTR`` column of ``rows``: ok, missing, host record (not checked) or "" (CNAME).

    A row is ``ok`` when a PTR record at its address points back to its name. A host row says
    ``host record`` instead, unless its ``configure_for_dns`` is False (a host that publishes no
    DNS; absent means True): that one is checked like an A record. The flag only feeds the
    verdict, so it is removed from the rows. ``ptr_items`` is None when the PTR search failed or
    was cut short: no verdict can be trusted, so every one stays "".
    """
    pointers: Optional[Set[Tuple[Any, str]]] = None
    if ptr_items is not None:
        pointers = {
            (address, _bare_name(item.get("ptrdname")))
            for item in ptr_items
            if (address := _address(item.get("ipv4addr") or item.get("ipv6addr"))) is not None
        }
    for row in rows:
        row["PTR"] = _ptr_verdict(row, pointers, row.pop("configure_for_dns", True))


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

    def _search(self, ctx: ScriptContext, prefix: str) -> FqdnLookup:
        """
        Search the A, AAAA, host and CNAME records of one valid prefix, and the PTR records of the same names.

        Five paged requests run in parallel. A search that failed or hit the paging limit adds a
        warning; the rows of the others are still returned, sorted by name, type and address, and
        without the copies a record has in several views. Each row gets its PTR verdict, and the
        ``process_data`` hook then sees the rows unless every record search failed. Shared by the
        menu and the command line.
        """
        colors = get_global_color_scheme(ctx.cfg)
        uris = [f"{wapi_object}?name~={prefix}&_return_fields={fields}" for _, wapi_object, fields in RECORD_SEARCHES]
        uris.append(PTR_SEARCH.format(prefix=prefix))
        with ctx.console.status(f"[{colors['description']}]Fetching data for [{colors['header']}]{prefix}[/]...[/]"):
            with ThreadPoolExecutor(max_workers=bound_infoblox_workers(ctx, len(uris))) as executor:
                futures = [executor.submit(request_result, ctx, uri, ensure_auth=False, paged=True) for uri in uris]
                *record_results, ptr_result = [future.result() for future in futures]

        items: List[Dict[str, Any]] = []
        warnings: List[str] = []
        reasons: List[str] = []
        for (label, _, _), result in zip(RECORD_SEARCHES, record_results):
            if result.failed:
                reasons.append(describe_infoblox_failure(result))
                warnings.append(f"{label} records: {reasons[-1].removesuffix('.')}")
                continue
            items.extend(result.items)
            if result.truncated:
                warnings.append(f"{label} records: showing the first {WAPI_MAX_ROWS:,} only (paging limit); use a longer name.")
        every_record_search_failed = len(reasons) == len(RECORD_SEARCHES)

        ptr_items: Optional[List[Dict[str, Any]]] = None  # None: no PTR verdicts
        if ptr_result.failed:
            reasons.append(describe_infoblox_failure(ptr_result))
            warnings.append(f"PTR check: {reasons[-1].removesuffix('.')}; PTR column left empty.")
        elif ptr_result.truncated:
            warnings.append(f"PTR check: more than {WAPI_MAX_ROWS:,} PTR records match; PTR column left empty.")
        else:
            ptr_items = ptr_result.items

        rows = process_data(ctx, type="fqdn", content=json.dumps(items).encode()).get("fqdn") or []
        rows = sorted(rows, key=lambda row: (row["name"], row["type"], row["ip"]))
        _apply_ptr_verdicts(rows, ptr_items)
        rows = _unique_rows(rows)  # after the verdicts: they drop the flag that could keep two copies apart
        if not every_record_search_failed:
            rows = (self.execute_hook('process_data', ctx, {"fqdn": rows}) or {}).get("fqdn") or []
        return FqdnLookup(rows, warnings, failed=bool(reasons), reason=reasons[0] if reasons else NO_MATCH_REASON)

    def _save(self, ctx: ScriptContext, rows: List[Dict[str, Any]]) -> None:
        """Queue ``rows``, as changed by the ``pre_save`` hook, for the report when auto-save is on."""
        if not ctx.cfg["report_auto_save"]:
            return
        final_save_data = self.execute_hook('pre_save', ctx, rows)

        if final_save_data:
            final_columns = list(final_save_data[0].keys())
            save_data_list_of_lists = [[row.get(col, '') for col in final_columns] for row in final_save_data]
            queue_save(ctx, final_columns, save_data_list_of_lists, sheet_name="FQDN Data", index=False, force_header=True)

    def run(self, ctx: ScriptContext) -> None:
        """
        Requests user to provide an FQDN string or prefix, validates it,
        fetches and processes data, and then prints or saves it.
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - FQDN Search - DNS A/AAAA/host/CNAME records")

        ensure_infoblox_auth(ctx)

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
        lookup = self._search(ctx, fqdn)
        for warning in lookup.warnings:
            console.print(f"[{colors['warning']}]{warning}[/]")

        if not lookup.rows:
            if lookup.failed:
                logger.info("Request Type - FQDN Search - Request failed")
                console.print(f"[{colors['error']}]{lookup.reason}[/]")
            else:
                logger.info("Request Type - FQDN Search - No matching records found")
                console.print(f"[{colors['error']}]{format_no_match_message('DNS records', fqdn)}[/]")
            press_any_key(ctx)
            return

        # --- Display and Save Results ---
        print_table_data(ctx, {"fqdn": lookup.rows}, suffix={"fqdn": "Search Results"})
        console.print(f"[dim]{PTR_LEGEND}[/]")
        logger.debug(f"Request Type - FQDN Search - processed data: {lookup.rows}")

        self._save(ctx, lookup.rows)

        _publish_stats(ctx, queries=1, successes=1, results=len(lookup.rows))

        press_any_key(ctx)

    def run_cli(self, ctx: ScriptContext, args: argparse.Namespace) -> CliResult:
        """
        ``cn fqdn <prefix>...``: five searches per prefix, the records of all of them in one section.

        A record found under several prefixes is listed once. A prefix that cannot be searched or
        has no record is listed in ``not_found`` with the reason (the first failure when a search
        failed). A failed or truncated search is a row of ``warnings``; a failed one also makes the
        run incomplete (exit 3). Every section key is always present.
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

            searched += 1
            lookup = self._search(ctx, prefix)
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
            self._save(ctx, rows)
            _publish_stats(ctx, queries=searched, successes=successes, results=len(rows))

        exit_code = cli_exit_code(found=bool(rows), invalid=invalid, failed=failed)
        return CliResult(exit_code, {"fqdn": rows, "not_found": not_found, "warnings": warnings})
