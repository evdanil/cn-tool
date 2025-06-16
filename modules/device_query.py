import ipaddress
import re
from typing import Dict, Any, List, Tuple, Callable, Union
from concurrent.futures import ThreadPoolExecutor

from rich.table import Table
from rich.panel import Panel

from core.base import BaseModule, ScriptContext
from utils.user_input import read_user_input
from utils.display import (
    get_global_color_scheme, print_multi_table_panel,
    create_device_error_table, create_show_version_table,
    create_license_reservation_tables, create_license_summary_table,
    create_show_license_table
)
from utils.file_io import queue_save
from utils.validation import is_fqdn, ip_regexp

# These imports are specific to the device interaction logic
from utils.parsers import (
    process_device_commands, process_device_data, prepare_device_data,
    parse_show_version, parse_show_license_reservation,
    parse_show_license_summary, parse_show_license
)


class DeviceQueryModule(BaseModule):
    """
    Module to connect to network devices, run a series of commands,
    parse the output, and display/save the structured information.
    """

    @property
    def menu_key(self) -> str:
        return "9"

    @property
    def menu_title(self) -> str:
        return "Device Information Request"

    def run(self, ctx: ScriptContext) -> None:
        """
        Requests user to provide device IPs or hostnames and fetches information.
        (Original `device_query` logic)
        """
        logger = ctx.logger
        console = ctx.console
        colors = get_global_color_scheme(ctx.cfg)

        # This command list is highly specific to this module's function
        cmd_list: Dict[str, Tuple[Callable[[str], Any], Callable[..., Any]]] = {
            "show_version": (parse_show_version, create_show_version_table),
            "show_license_reservation": (parse_show_license_reservation, create_license_reservation_tables),
            "show_license_summary": (parse_show_license_summary, create_license_summary_table),
            "show_license": (parse_show_license, create_show_license_table),
        }

        logger.info("Device Query - User input phase")
        console.print(
            "\n"
            f"[{colors['description']}]Please provide a list of device IP addresses or hostnames, one per line.[/]\n"
            f"[{colors['description']}]Empty input line starts the process.[/]\n"
            f"[{colors['header']}]Example:[/]\n"
            f"[{colors['success']} {colors['bold']}]134.162.104.110[/]\n"
            f"[{colors['success']} {colors['bold']}]my-router.example.com[/]\n"
        )

        # --- User Input and Validation ---
        devices: List[str] = []
        while True:
            search_input = read_user_input(ctx, "").strip()
            if not search_input:
                break

            if "/" not in search_input and re.match(ip_regexp, search_input):
                try:
                    ip = ipaddress.ip_address(search_input)
                    if ip.is_unspecified or ip.is_reserved or ip.is_link_local:
                        console.print(f"[{colors['error']}]Invalid IP: Broadcast, reserved, and loopback IPs are excluded.[/]")
                    else:
                        devices.append(search_input)
                except ValueError:
                    console.print(f"[{colors['error']}]Invalid IP format.[/]")
            elif is_fqdn(search_input):
                devices.append(search_input)
            else:
                logger.warning(f"Invalid input for device query: {search_input}")
                console.print(f"[{colors['error']}]Input must be a valid IP address or FQDN.[/]")

        if not devices:
            return

        unique_devices = list(dict.fromkeys(devices))
        logger.info(f"User input - Querying devices: {', '.join(unique_devices)}")

        # --- Device Interaction ---
        results: Dict[str, Dict[str, Any]] = {}
        with console.status(f"[{colors['description']}]Connecting to devices and running commands...[/]", spinner="dots12"):
            with ThreadPoolExecutor(max_workers=10) as executor:  # Increased workers for network-bound tasks
                future_to_device = {
                    executor.submit(process_device_commands, logger, device, cmd_list, ctx.username, ctx.password): device
                    for device in unique_devices
                }
                for future in future_to_device:
                    device = future_to_device[future]
                    try:
                        results[device] = future.result()
                    except Exception as exc:
                        logger.error(f'Device "{device}" generated an exception during command processing: {exc}')
                        results[device] = {device: 'Failed to process'}

        # --- HOOK: Allow plugins to modify the raw command output results ---
        final_results = self.execute_hook('process_data', ctx, results)

        # --- Display Results ---
        for hostname, device_data in final_results.items():
            tables_to_print: List[Union[Table, Panel]] = []
            if device_data.get(hostname) == 'Failed to process':
                error_table = create_device_error_table(hostname, ctx.cfg.get("theme_name", "default"))
                if error_table:
                    tables_to_print.append(error_table)
            else:
                for command, parsed_output in device_data.items():
                    # The second element in the cmd_list tuple is the display function
                    display_function = cmd_list.get(command, (None, None))[1]
                    if display_function:
                        tables = display_function(parsed_output, hostname, ctx.cfg.get("theme_name", "default"))
                        if tables:
                            # Ensure we always deal with a list
                            if isinstance(tables, list):
                                tables_to_print.extend(t for t in tables if t)
                            else:
                                tables_to_print.append(tables)

            if tables_to_print:
                print_multi_table_panel(ctx, tables_to_print, f'Device {hostname.upper()}')

        # --- Save Results ---
        if ctx.cfg.get("report_auto_save", True):
            # Create two separate lists to hold successful data and failures.
            successful_processed_data: List[Dict[str, Any]] = []
            failed_devices: List[List[Any]] = []

            for hostname, device_data in final_results.items():
                # Explicitly check for the failure marker.
                if device_data.get(hostname) == 'Failed to process':
                    # Add failure info as a simple list of lists for saving.
                    failed_devices.append([hostname, "Failed to connect or process commands"])
                else:
                    # If successful, process the data. process_device_data returns List[Dict].
                    # Use .extend() to add all dictionaries from the result to our master list.
                    successful_processed_data.extend(process_device_data(hostname, device_data))

            # --- HOOK: Allow plugins to modify the list of SUCCESSFUL data dicts ---
            final_successful_data = self.execute_hook('pre_save', ctx, successful_processed_data)

            # --- Now, prepare and save the successful data ---
            if final_successful_data:
                # This is now SAFE. prepare_device_data will only ever see a list of dicts.
                columns, data_to_save = prepare_device_data(final_successful_data)

                # Queue the successful data with its full set of columns.
                queue_save(
                    ctx,
                    columns,
                    data_to_save,
                    sheet_name="Device Data",
                    index=False,
                    force_header=True
                )

            # --- Finally, append the failed devices to the same sheet ---
            # This happens AFTER the main data and header have been written.
            if failed_devices:
                # Use a simple, two-column header for the error rows.
                # If the sheet is new, this will be the header. If appending, it's just two more cells.
                # To be truly robust, we should check if the file/sheet exists and decide
                # whether to write a header, but for now this is a big improvement.
                queue_save(
                    ctx,
                    columns=["Hostname", "Status"],
                    raw_data=failed_devices,
                    sheet_name="Device Data",
                    index=False,
                    # We can force a header for clarity, or set to False if we only want to append
                    # to a potentially existing file from a previous run.
                    force_header=True
                )
