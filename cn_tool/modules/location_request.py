import argparse
import re
from typing import Any, Dict, List, Optional, Tuple

from rich.markup import escape

from cn_tool.core.base import BaseModule, CliResult, ScriptContext, cli_exit_code
from cn_tool.utils.auth import ensure_infoblox_auth
from cn_tool.utils.cli_input import read_objects
from cn_tool.utils.user_input import press_any_key, read_user_input
from cn_tool.utils.display import get_global_color_scheme, print_table_data
from cn_tool.utils.api import WAPI_MAX_ROWS, NetworkSearchResult, fetch_network_data, site_ea_name
from cn_tool.utils.file_io import queue_save
from cn_tool.utils.infoblox_ux import format_no_match_message, format_partial_results_message
from cn_tool.utils.network_views import NETWORK_VIEW, ViewScope, present_rows, view_scope
from cn_tool.utils.validation import is_valid_site, site_code_format_hint

# fetch_network_data pages IPv4 and IPv6 networks separately, so the cap is per address family.
# Printed by the menu and carried as a ``warnings`` row by ``run_cli``.
TRUNCATED_WARNING = (
    f"Subnets: showing the first {WAPI_MAX_ROWS:,} per address family only (paging limit); narrow the search."
)


def _no_match_in_attribute_and_comments(ea_name: str) -> str:
    """Why a site code found nothing when ``[site] ea_name`` is set: both searches came back empty."""
    return f"No matching network (extensible attribute {ea_name}, then subnet comments)"


def _view_labels(rows: List[Dict[str, Any]]) -> List[Any]:
    """The network view each row names (a row may carry none)."""
    return [row.get(NETWORK_VIEW) for row in rows]


def _with_view_column(rows: List[Dict[str, Any]], scope: ViewScope, show: bool) -> List[Dict[str, Any]]:
    """``rows`` with the ``network view`` column shown (first, the requested view for a row without one) or hidden."""
    return present_rows(rows, NETWORK_VIEW, show, fallback=scope.requested)


class LocationRequestModule(BaseModule):
    """
    Module to find subnets based on a location site code or an arbitrary keyword
    search within the subnet's comment/description field.
    """
    cli_name = "site"

    @property
    def menu_key(self) -> str:
        return "4"

    @property
    def menu_title(self) -> str:
        return "Subnet Lookup (by site code or keyword)"

    @property
    def visibility_config_key(self) -> Optional[str]:
        # This module will only appear in the menu if 'infoblox_enabled' is True in the config.
        return "infoblox_enabled"

    def run(self, ctx: ScriptContext) -> None:
        """
        Requests user to provide a site code or keyword to find subnets.
        (Original `location_request` logic)
        """
        logger = ctx.logger
        console = ctx.console
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - Subnet Lookup by Location/Keyword")

        ensure_infoblox_auth(ctx)

        # A configured network view must exist: say so before the user types anything.
        scope = view_scope(ctx)
        view_problem = scope.problem()
        if view_problem:
            console.print(f"[{colors['error']}]{escape(view_problem.message)}[/]")
            press_any_key(ctx)
            return

        attribute = site_ea_name(ctx)
        attribute_line = (
            f"[{colors['description']}]Site codes are looked up in the extensible attribute [{colors['bold']}]{escape(attribute)}[/]; "
            "subnet comments are searched only when no subnet carries it.[/]\n"
            if attribute
            else ""
        )

        console.print(
            "\n"
            f"[{colors['description']}]Search for registered subnets by [{colors['bold']}]site code[/] or [{colors['bold']}]keyword[/].[/]\n"
            f"[{colors['description']}]Site code format: [{colors['success']} {colors['bold']}]{site_code_format_hint(ctx.cfg.get('site_code_pattern'))}[/]\n"
            f"{attribute_line}"
            f"[{colors['description']}]Keyword searches look in the subnet description/comment field.[/]\n"
            f"[{colors['description']}]Results are paged: up to [{colors['error']} {colors['bold']}]{WAPI_MAX_ROWS:,}[/] records per address family (IPv4 and IPv6).[/]\n"
        )
        banner = scope.banner()
        if banner:
            console.print(f"[{colors['warning']}]{escape(banner)}[/]\n")

        search_mode = self._read_search_mode(ctx)
        if not search_mode:
            return

        if search_mode == "sitecode":
            raw_input = read_user_input(
                ctx,
                f"Enter [{colors['success']} {colors['bold']}]location code[/]: ",
            ).strip()
        else:
            raw_input = read_user_input(
                ctx,
                f"Enter [{colors['success']} {colors['bold']}]keyword[/] (min 3 chars): ",
            ).strip()

        logger.info(f"User input - {raw_input}")

        if not raw_input:
            logger.info("User input - Empty input")
            console.print(f"[{colors['error']}]No search value provided.[/]")
            press_any_key(ctx)
            return

        # --- Input Parsing and Validation ---
        search_term: str = raw_input
        is_keyword_search = search_mode == "keyword"
        prefix: Dict[str, str] = {}
        suffix: Dict[str, str] = {}

        problem = self._validate_term(ctx, search_term, is_keyword_search)
        if problem:
            console.print(f"[{colors['error']}]{problem}[/]")
            press_any_key(ctx)
            return

        if is_keyword_search:
            logger.info(f"User input - Keyword search for '{search_term}'")
        else:
            prefix = {"location": search_term.upper()}
            suffix = {"location": "Subnets"}
            logger.info(f"User input - Sitecode search for '{search_term}'")

        # --- API Call and Data Processing (runs the process_data hook) ---
        lookup_result, processed_data = self._fetch_term(ctx, search_term, is_keyword_search, scope.requested)

        if lookup_result.status == "error" and not lookup_result.has_data:
            logger.info("Request Type - Location/Keyword Search - Request failed")
            console.print(f"[{colors['error']}]{escape(lookup_result.message)}[/]")  # may name "[site]"
            press_any_key(ctx)
            return

        if lookup_result.status == "partial_error":
            console.print(f"[{colors['warning']}]{escape(format_partial_results_message(lookup_result.message))}[/]")  # may name the account

        if lookup_result.truncated:
            console.print(f"[{colors['warning']}]{TRUNCATED_WARNING}[/]")

        for notice in lookup_result.notices:
            console.print(f"[{colors['warning']}]{escape(notice)}[/]")

        if not processed_data.get("location"):
            logger.info("Request Type - Location/Keyword Search - No matching records found")
            attribute = self._lookup_attribute(ctx, is_keyword_search)
            if attribute:
                message = _no_match_in_attribute_and_comments(attribute)
            else:
                message = format_no_match_message('subnet records', search_term)
            console.print(f"[{colors['error']}]{escape(scope.scoped(message))}[/]")
            press_any_key(ctx)
            return

        # --- Display and Save Results ---
        rows = processed_data["location"]
        shown_data = {**processed_data, "location": _with_view_column(rows, scope, scope.column(_view_labels(rows)))}
        print_table_data(ctx, shown_data, prefix=prefix, suffix=suffix)
        logger.debug(f"Request Type - Location/Keyword Search - processed data: {processed_data}")

        self._save_rows(ctx, rows, scope)
        self._publish_stats(ctx, is_keyword_search, queries=1, successes=1, results=len(processed_data.get("location", [])))

        press_any_key(ctx)

    def run_cli(self, ctx: ScriptContext, args: argparse.Namespace) -> CliResult:
        """
        ``cn site [-k] TERM...``: look up every site code (or, with ``-k``, keyword) given on the
        command line or in ``--file`` and return the sections for the renderer.

        Sections: ``location`` (one row per network), ``not_found`` (``object``/``reason`` for each
        term that is unusable, unanswered or without networks) and, only when there is something
        to say, ``warnings`` (``object``/``warning`` for truncated or partial answers and for an
        address family the attribute search could not cover). The note that a site code was found
        in subnet comments, not in the extensible attribute, goes to the console (stderr).

        ``--view NAME`` (or ``[api] network_view``) limits the search to one network view; without
        either, every view is searched and a network that exists in several views is one row per view.
        The view is checked after the login and before any lookup: a name that is not on the grid
        exits 2, a list of views that cannot be read exits 3 (both with ``{}`` as the data). Rows
        carry the ``network view`` column as ``ViewScope.result_column`` says.
        Never prompts. Exit status: see ``cli_exit_code``.
        """
        logger = ctx.logger
        logger.info("Request Type - Subnet Lookup by Location/Keyword (command line)")
        keyword: bool = args.keyword

        try:
            terms = read_objects(args.objects, args.file)
        except OSError as exc:
            ctx.console.print(f"Cannot read the list of sites or keywords: {exc}")
            return CliResult(2, {})
        if not terms:
            ctx.console.print("Give at least one site code (or keyword with -k), or a --file listing them.")
            return CliResult(2, {})

        scope = view_scope(ctx, args)
        checked = [(term, self._validate_term(ctx, term, keyword)) for term in terms]
        if any(problem is None for _, problem in checked):
            ensure_infoblox_auth(ctx)
            view_problem = scope.problem()
            if view_problem:
                ctx.console.print(f"cn site: {view_problem.message}", markup=False)
                return CliResult(view_problem.exit_code, {})

        rows: List[Dict[str, Any]] = []
        not_found: List[Dict[str, str]] = []
        warnings: List[Dict[str, str]] = []
        invalid = failed = False
        queries = successes = 0
        attribute = self._lookup_attribute(ctx, keyword)

        for term, problem in checked:
            if problem:
                invalid = True
                hint = site_code_format_hint(ctx.cfg.get("site_code_pattern"))
                not_found.append({"object": term, "reason": problem if keyword else f"{problem} Site codes: {hint}"})
                continue

            queries += 1
            logger.info(f"User input - {'Keyword' if keyword else 'Sitecode'} search for '{term}'")
            lookup_result, processed_data = self._fetch_term(ctx, term, keyword, scope.requested)

            if lookup_result.status == "error" and not lookup_result.has_data:
                logger.info("Request Type - Location/Keyword Search - Request failed")
                failed = True
                not_found.append({"object": term, "reason": lookup_result.message})
                continue
            if lookup_result.status == "partial_error":
                failed = True
                warnings.append({"object": term, "warning": format_partial_results_message(lookup_result.message)})
            if lookup_result.truncated:
                warnings.append({"object": term, "warning": TRUNCATED_WARNING})
            if lookup_result.skipped:
                warnings.append({"object": term, "warning": lookup_result.skipped})
            if lookup_result.note:
                ctx.console.print(f"{term}: {lookup_result.note}", markup=False)

            term_rows = processed_data.get("location", [])
            if not term_rows:
                logger.info("Request Type - Location/Keyword Search - No matching records found")
                reason = _no_match_in_attribute_and_comments(attribute) if attribute else "No matching network"
                not_found.append({"object": term, "reason": scope.scoped(reason)})
                continue
            successes += 1
            rows.extend(term_rows)

        # A network that several terms share is listed once per network view, where first seen: rows do not name the term.
        rows = list({(row.get("network"), row.get(NETWORK_VIEW) or ""): row for row in rows}.values())
        self._save_rows(ctx, rows, scope)
        if successes:
            self._publish_stats(ctx, keyword, queries=queries, successes=successes, results=len(rows))

        # Every section key is always present (JSON contract); the human renderers skip empty ones.
        returned = _with_view_column(rows, scope, scope.result_column(_view_labels(rows)))
        data: Dict[str, List[Dict[str, Any]]] = {"location": returned, "not_found": not_found, "warnings": warnings}
        return CliResult(cli_exit_code(found=bool(rows), invalid=invalid, failed=failed), data)

    def _validate_term(self, ctx: ScriptContext, text: str, keyword: bool) -> Optional[str]:
        """What is wrong with a search term (also logged), or None when it can be looked up.

        A keyword is at least 3 letters, digits, ``_`` or ``-``; a site code must match the
        configured ``[site] code_pattern`` (the permissive default when none is set).
        """
        logger = ctx.logger
        if keyword:
            if len(text) < 3:
                logger.info(f"User input - Keyword too short {text}")
                return "Keyword searches require at least 3 characters."
            if not re.match(r"^[a-zA-Z0-9_-]*$", text):
                logger.info(f"User input - Invalid keyword {text}")
                return "Keyword contains invalid characters."
        elif not is_valid_site(text, ctx.cfg.get("site_code_pattern")):
            logger.info(f"User input - Incorrect site code {text}")
            return "Incorrect site code format."
        return None

    def _lookup_attribute(self, ctx: ScriptContext, keyword: bool) -> str:
        """The extensible attribute a lookup searches before the subnet comments; "" for a keyword or when none is set."""
        return "" if keyword else site_ea_name(ctx)

    def _fetch_term(
        self, ctx: ScriptContext, term: str, keyword: bool, network_view: str = ""
    ) -> Tuple[NetworkSearchResult, Dict[str, Any]]:
        """
        One Infoblox lookup (auth is ensured by the caller) and the ``process_data`` hook over its data.
        ``network_view`` is the view to search; "" searches every view (never the configured one).
        """
        lookup_result = fetch_network_data(ctx, term, keyword=keyword, ensure_auth=False, network_view=network_view)
        # --- HOOK: Allow plugins to modify the processed data ---
        return lookup_result, self.execute_hook('process_data', ctx, lookup_result.data)

    def _save_rows(self, ctx: ScriptContext, rows: List[Dict[str, Any]], scope: ViewScope) -> None:
        """
        Queue ``rows`` for the report when ``report_auto_save`` is on (after the ``pre_save`` hook).
        The sheet has the ``network view`` column when ``ViewScope.column`` says so, as the menu table does.
        """
        if not ctx.cfg["report_auto_save"]:
            return
        rows = _with_view_column(rows, scope, scope.column(_view_labels(rows)))

        # --- HOOK: Allow plugins to modify data before saving ---
        # This hook operates on the list of dictionaries.
        final_save_data = self.execute_hook('pre_save', ctx, rows)

        if final_save_data:
            # Dynamically determine the columns from the final data, in case
            # a plugin added a new column/key.
            final_columns = list(final_save_data[0].keys())

            # Convert the list of dictionaries to a list of lists for queue_save
            save_data_list_of_lists = [[row.get(col, '') for col in final_columns] for row in final_save_data]

            queue_save(ctx, final_columns, save_data_list_of_lists, sheet_name="Subnet Lookup", index=False, force_header=True)

    def _publish_stats(self, ctx: ScriptContext, keyword: bool, *, queries: int, successes: int, results: int) -> None:
        ctx.event_bus.publish(
            "stats:module_detail",
            {
                "unit_count": queries,
                "query_count": queries,
                "result_count": results,
                "success_count": successes,
                "search_mode": "keyword" if keyword else "sitecode",
            },
        )

    def _read_search_mode(self, ctx: ScriptContext) -> Optional[str]:
        colors = get_global_color_scheme(ctx.cfg)
        console = ctx.console
        console.print(
            f"[{colors['header']}]Search modes:[/]\n"
            f"[{colors['success']}]1[/]. site code\n"
            f"[{colors['success']}]2[/]. keyword (description search)"
        )
        mode = read_user_input(ctx, "Select search mode [1/2]: ").strip().lower()
        if not mode:
            return None
        if mode in {"site", "s", "1", "sitecode", "site code"}:
            return "sitecode"
        if mode in {"keyword", "k", "2"}:
            return "keyword"
        console.print(f"[{colors['error']}]Invalid search mode. Use 1 for site code or 2 for keyword.[/]")
        press_any_key(ctx)
        return None
