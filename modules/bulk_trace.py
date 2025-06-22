# modules/bulk_trace.py

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any

# Core and utils imports
from core.base import BaseModule, ScriptContext
from utils.diagnostics import process_mtr_target
from utils.user_input import press_any_key, read_user_input
from utils.file_io import queue_save
from utils.display import create_table, get_global_color_scheme


class BulkTraceModule(BaseModule):
    """
    Performs a bulk network trace to a list of targets, reporting the last responding hop.
    This module can be extended by plugins to perform additional validation (e.g., site checks).
    """

    # def __init__(self):
    #     super().__init__()
    #     # Define a new hook specific to this module for row-by-row data enrichment.
    #     # self.hooks['process_audit_result'] = []

    @property
    def menu_key(self) -> str:
        return 't'  # Or any other available key

    @property
    def menu_title(self) -> str:
        return "Bulk Network Trace (MTR)"

    def run(self, ctx: ScriptContext) -> None:
        """Main execution method for the module."""
        ctx.logger.info("Starting Bulk Network Trace module.")
        colors = get_global_color_scheme(ctx.cfg)
        self.execute_hook('pre_run', ctx, None)

        # 1. Get user input line by line
        ctx.console.print(f"\n[{colors['bold']}]Enter targets (IPs or networks), one per line.[/]")
        ctx.console.print(f"[{colors['description']}]Press Enter on an empty line or Ctrl+D to start processing.[/]")

        targets: List[str] = []
        while True:
            try:
                line = read_user_input(ctx, "")
                if not line:  # User pressed Enter on an empty line
                    break
                targets.append(line.strip())
            except EOFError:  # User pressed Ctrl+D
                ctx.console.print()  # Move to the next line after Ctrl+D
                break

        if not targets:
            ctx.console.print(f"[{colors['warning']}]No targets entered.[/]")
            return

        # 2. Process targets in parallel
        all_results: List[Dict[str, Any]] = []
        max_workers = 10

        ctx.console.print(f"\nTracing {len(targets)} targets with up to {max_workers} workers...")
        with ctx.console.status(f"[{colors['description']}]Running network traces...", spinner="dots"):
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_target = {executor.submit(process_mtr_target, ctx, t): t for t in targets}

                for i, future in enumerate(as_completed(future_to_target)):
                    target_name = future_to_target[future]
                    try:
                        generic_result = future.result()
                        enriched_result = self.execute_hook('process_audit_result', ctx, generic_result)
                        all_results.append(enriched_result)
                    except Exception as exc:
                        ctx.logger.error(f"Target {target_name} generated an unhandled exception: {exc}", exc_info=True)
                        all_results.append({'target': target_name, 'status': f"FATAL_ERROR: {type(exc).__name__}"})

                    status = all_results[-1].get('status', 'ERROR')
                    ctx.console.print(f"Completed {i+1}/{len(targets)}: {target_name} \t\t-> [cyan]{status}[/cyan]")

        all_results = self.execute_hook('process_data', ctx, all_results)

        # 3. Display results and queue for saving
        self._render_and_save(ctx, all_results)
        self.execute_hook('post_run', ctx, all_results)

        press_any_key(ctx)

    def _render_and_save(self, ctx: ScriptContext, results: List[Dict[str, Any]]):
        """Creates and prints a Rich table, then queues the data for saving to Excel."""
        colors = get_global_color_scheme(ctx.cfg)

        if not results:
            ctx.console.print(f"[{colors['warning']}]No results to display.[/]")
            return

        results = self.execute_hook('pre_render', ctx, results)

        # Define the column order and discover any additional columns added by plugins.
        base_columns = ['Target', 'Last Hop IP', 'Last Hop Hostname', 'Hop Count', 'Status']
        discovered_columns = set()
        for res in results:
            for key in res.keys():
                title_case_key = key.replace('_', ' ').title()
                if title_case_key not in base_columns:
                    discovered_columns.add(title_case_key)

        final_columns = base_columns + sorted(list(discovered_columns))

        # Prepare the data in a list-of-lists format for the create_table and queue_save functions.
        data_for_display = []
        for res in sorted(results, key=lambda x: x.get('target', '')):
            row = [str(res.get(col.replace(' ', '_').lower(), "N/A")) for col in final_columns]
            data_for_display.append(row)

        # --- Use the application's standard table creation function ---
        table = create_table(
            ctx,
            title="Network Trace Results",
            columns=final_columns,
            data=data_for_display,
            exclude_columns=["Mtr Output"],
            title_justify="left",
            expand=True
        )

        # The create_table function handles styling, so we just print the result.
        ctx.console.print(table)

        # --- Save to Excel using the background worker ---
        results_to_save = self.execute_hook('pre_save', ctx, data_for_display)
        if results_to_save:
            ctx.logger.info(f"Queueing {len(results_to_save)} rows of data for saving to sheet 'Bulk Trace'.")
            queue_save(
                ctx=ctx,
                columns=final_columns,
                raw_data=results_to_save,
                sheet_name='Bulk Trace',
                index=False,
                # truncate_sheet=True  # Overwrite the sheet each time this module runs
            )
