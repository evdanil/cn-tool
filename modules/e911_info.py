# modules/e911_info.py
"""
E911 Switch Information Module

Connects to network switches in parallel, executes 'show switch' command,
parses stack member information, and presents/saves MAC addresses for E911 purposes.
"""
import ipaddress
import re
from typing import Dict, Any, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
from socket import gethostbyaddr

from rich.table import Table

from core.base import BaseModule, ScriptContext
from utils.user_input import press_any_key, read_user_input
from utils.display import get_global_color_scheme, print_table_data
from utils.file_io import queue_save
from utils.validation import is_fqdn, ip_regexp

# Netmiko imports for device connections
from netmiko import SSHDetect, BaseConnection
from utils.parsers import ConnLogOnly


def parse_show_switch(output: str) -> Dict[str, Any]:
    """
    Parses the output of 'show switch' command from Cisco IOS/IOS-XE devices.

    Returns a dictionary with:
        - stack_mac: The stack/switch MAC address
        - members: List of switch members with their details
        - is_valid: Boolean indicating if this is valid switch output
        - error: Error message if parsing failed
    """
    result: Dict[str, Any] = {
        "stack_mac": None,
        "members": [],
        "is_valid": False,
        "error": None
    }

    # Check for error indicators (non-switch devices)
    error_patterns = [
        r'Invalid input detected',
        r'Incomplete command',
        r'Invalid syntax',
        r'% .*command'
    ]

    for pattern in error_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            result["error"] = "Device does not support 'show switch' command"
            return result

    # Parse Stack/Switch MAC Address
    # Pattern: "Switch/Stack Mac Address : c4ab.4dec.3b60" or similar
    stack_mac_match = re.search(
        r'Switch/Stack Mac Address\s*:\s*([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})',
        output
    )
    if stack_mac_match:
        result["stack_mac"] = stack_mac_match.group(1).lower()

    # Parse member switch lines
    # Format varies slightly but generally:
    # *1       Active   c4ab.4dec.3b60     15     V02     Ready
    #  2       Standby  cc7f.76ed.b000     14     V02     Ready
    # Or for older format:
    # *1       Master ecbd.1d63.ee80     15     3       Ready

    # Pattern to match switch member lines
    # Captures: switch_num, role, mac_address, priority, version, state
    member_pattern = re.compile(
        r'^\s*\*?(\d+)\s+'                           # Switch number (with optional * for active)
        r'(Active|Standby|Member|Master)\s+'         # Role
        r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+'  # MAC Address
        r'(\d+)\s+'                                  # Priority
        r'(V?\d+)\s+'                                # H/W Version
        r'(\w+)',                                    # State
        re.IGNORECASE | re.MULTILINE
    )

    for match in member_pattern.finditer(output):
        switch_num = match.group(1)
        role = match.group(2)
        mac_address = match.group(3).lower()
        priority = match.group(4)
        hw_version = match.group(5)
        state = match.group(6)

        # Skip unprovisioned switches (MAC 0000.0000.0000)
        if mac_address == "0000.0000.0000":
            continue

        # Skip entries that are not in Ready state (optional, but recommended)
        if state.lower() == "unprovisioned":
            continue

        result["members"].append({
            "switch_num": switch_num,
            "role": role,
            "mac_address": mac_address,
            "priority": priority,
            "hw_version": hw_version,
            "state": state
        })

    # Mark as valid if we found at least one member
    if result["members"]:
        result["is_valid"] = True
    elif not result["error"]:
        result["error"] = "No valid switch stack members found in output"

    return result


def query_switch_info(
    logger: Any,
    device: str,
    username: Optional[str],
    password: Optional[str]
) -> Dict[str, Any]:
    """
    Connect to a device and execute 'show switch' command.

    Returns a dictionary with device info and parsed switch data.
    """
    result: Dict[str, Any] = {
        "device": device,
        "hostname": None,
        "dns_name": None,
        "success": False,
        "error": None,
        "switch_data": None
    }

    # Try reverse DNS lookup
    try:
        result["dns_name"] = gethostbyaddr(device)[0]
    except Exception:
        pass

    dev: Dict[str, Any] = {
        "device_type": "autodetect",
        "host": device,
        "username": username,
        "password": password,
        "secret": ''
    }

    conn: Optional[BaseConnection] = None
    try:
        # Auto-detect device type
        guesser = SSHDetect(**dev)
        detected_type = guesser.autodetect()

        if not detected_type:
            result["error"] = "Unable to autodetect device type"
            return result

        # Only proceed for Cisco IOS/IOS-XE devices
        if 'cisco' not in detected_type.lower():
            result["error"] = f"Unsupported device type: {detected_type}"
            return result

        # Connect to device
        dev["device_type"] = detected_type
        conn = ConnLogOnly(**dev)

        if not conn:
            result["error"] = "Unable to create device connection"
            return result

        # Get hostname from prompt
        prompt = conn.find_prompt()
        if prompt:
            # Remove trailing # or > from prompt
            result["hostname"] = prompt.rstrip('#>')

        # Execute 'show switch' command
        command_output = conn.send_command("show switch\n", auto_find_prompt=True)

        if isinstance(command_output, str):
            result["switch_data"] = parse_show_switch(command_output)
            result["success"] = result["switch_data"]["is_valid"]
            if not result["success"] and result["switch_data"]["error"]:
                result["error"] = result["switch_data"]["error"]
        else:
            result["error"] = "Command did not return valid output"

    except Exception as e:
        result["error"] = f"Connection/Command error: {str(e)}"
    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass

    return result


def normalize_mac_format(mac: str, output_format: str = "colon") -> str:
    """
    Convert MAC address to specified format.

    Args:
        mac: MAC address in any format (e.g., "c4ab.4dec.3b60")
        output_format: "colon" for XX:XX:XX:XX:XX:XX, "dot" for XXXX.XXXX.XXXX

    Returns:
        Formatted MAC address in uppercase
    """
    # Remove all separators and convert to lowercase
    clean_mac = mac.replace(":", "").replace("-", "").replace(".", "").lower()

    if len(clean_mac) != 12:
        return mac.upper()  # Return original if invalid

    if output_format == "colon":
        return ":".join(clean_mac[i:i+2] for i in range(0, 12, 2)).upper()
    elif output_format == "dot":
        return ".".join(clean_mac[i:i+4] for i in range(0, 12, 4)).upper()
    else:
        return clean_mac.upper()


class E911InfoModule(BaseModule):
    """
    Module to gather E911 switch information from network devices.
    Connects to switches, retrieves stack member MAC addresses,
    and presents/saves the information for E911 compliance purposes.
    """

    @property
    def menu_key(self) -> str:
        return "o"

    @property
    def menu_title(self) -> str:
        return "E911 Switch Information"

    def run(self, ctx: ScriptContext) -> None:
        """
        Main entry point for the E911 Switch Information module.
        """
        logger = ctx.logger
        console = ctx.console
        colors = get_global_color_scheme(ctx.cfg)

        logger.info("E911 Switch Information - User input phase")

        console.print(
            "\n"
            f"[{colors['description']}]E911 Switch Information Collector[/]\n"
            f"[{colors['description']}]Provide a list of switch IP addresses or hostnames, one per line.[/]\n"
            f"[{colors['description']}]Empty input line starts the process.[/]\n"
            f"[{colors['header']}]Example:[/]\n"
            f"[{colors['success']} {colors['bold']}]10.1.1.1[/]\n"
            f"[{colors['success']} {colors['bold']}]switch01.example.com[/]\n"
        )

        # --- User Input and Validation ---
        devices: List[str] = []
        while True:
            search_input = read_user_input(ctx, "").strip()
            if not search_input:
                break

            # Validate IP address
            if "/" not in search_input and re.match(ip_regexp, search_input):
                try:
                    ip = ipaddress.ip_address(search_input)
                    if ip.is_unspecified or ip.is_reserved or ip.is_link_local:
                        console.print(
                            f"[{colors['error']}]Invalid IP: Broadcast, reserved, "
                            f"and loopback IPs are excluded.[/]"
                        )
                    else:
                        devices.append(search_input)
                except ValueError:
                    console.print(f"[{colors['error']}]Invalid IP format.[/]")
            elif is_fqdn(search_input):
                devices.append(search_input)
            else:
                logger.warning(f"Invalid input for E911 query: {search_input}")
                console.print(
                    f"[{colors['error']}]Input must be a valid IP address or FQDN.[/]"
                )

        if not devices:
            console.print(f"[{colors['error']}]No devices provided[/]")
            press_any_key(ctx)
            return

        # Remove duplicates while preserving order
        unique_devices = list(dict.fromkeys(devices))
        logger.info(f"E911 Query - Querying devices: {', '.join(unique_devices)}")

        # --- Device Query (Parallel) ---
        results: Dict[str, Dict[str, Any]] = {}

        with console.status(
            f"[{colors['description']}]Connecting to switches and gathering E911 information...[/]",
            spinner="dots12"
        ):
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_device = {
                    executor.submit(
                        query_switch_info,
                        logger,
                        device,
                        ctx.username,
                        ctx.password
                    ): device
                    for device in unique_devices
                }

                for future in future_to_device:
                    device = future_to_device[future]
                    try:
                        results[device] = future.result()
                    except Exception as exc:
                        logger.error(
                            f'Device "{device}" generated an exception: {exc}'
                        )
                        results[device] = {
                            "device": device,
                            "success": False,
                            "error": str(exc)
                        }

        # --- HOOK: Allow plugins to modify the raw results ---
        final_results = self.execute_hook('process_data', ctx, results)

        # --- Process and Display Results ---
        all_data: List[Dict[str, str]] = []
        failed_devices: List[Tuple[str, str]] = []

        for device, result in final_results.items():
            if result.get("success") and result.get("switch_data"):
                switch_data = result["switch_data"]
                hostname = result.get("hostname") or result.get("dns_name") or device
                stack_mac = switch_data.get("stack_mac", "N/A")

                for member in switch_data.get("members", []):
                    # Convert MAC to colon format for E911
                    mac_colon = normalize_mac_format(member["mac_address"], "colon")
                    mac_dot = normalize_mac_format(member["mac_address"], "dot")

                    all_data.append({
                        "Device": device,
                        "Hostname": hostname,
                        "Switch #": member["switch_num"],
                        "Role": member["role"],
                        "MAC (Colon)": mac_colon,
                        "MAC (Dot)": mac_dot,
                        "Priority": member["priority"],
                        "H/W Version": member["hw_version"],
                        "State": member["state"],
                        "Stack MAC": normalize_mac_format(stack_mac, "colon") if stack_mac else "N/A"
                    })
            else:
                error_msg = result.get("error", "Unknown error")
                failed_devices.append((device, error_msg))

        # --- HOOK: Allow plugins to modify data before rendering ---
        final_data = self.execute_hook('pre_render', ctx, all_data)

        # --- Display Results ---
        if final_data:
            # Create a summary table for display
            display_data: List[Dict[str, str]] = []
            for row in final_data:
                display_data.append({
                    "Hostname": row.get("Hostname", ""),
                    "Switch #": row.get("Switch #", ""),
                    "Role": row.get("Role", ""),
                    "MAC Address": row.get("MAC (Colon)", ""),
                    "State": row.get("State", "")
                })

            print_table_data(ctx, {"E911 Switch Information": display_data})

        # Display failed devices
        if failed_devices:
            console.print(f"\n[{colors['error']}]Failed Devices:[/]")
            error_table = Table(show_header=True, header_style=f"{colors['header']}")
            error_table.add_column("Device", style=colors['code'])
            error_table.add_column("Error", style=colors['error'])

            for device, error in failed_devices:
                error_table.add_row(device, error)

            console.print(error_table)

        # Summary
        console.print(
            f"\n[{colors['description']}]Summary: "
            f"[{colors['success']}]{len(final_data)}[/] MAC addresses from "
            f"[{colors['success']}]{len([r for r in final_results.values() if r.get('success')])}[/] devices. "
            f"[{colors['error']}]{len(failed_devices)}[/] devices failed.[/]"
        )

        # --- HOOK: Allow plugins to modify data before saving ---
        save_data = self.execute_hook('pre_save', ctx, final_data)

        # --- Save Results ---
        if ctx.cfg.get("report_auto_save", True) and save_data:
            # Prepare columns for the report
            columns = [
                "Device", "Hostname", "Switch #", "Role",
                "MAC (Colon)", "MAC (Dot)", "Priority",
                "H/W Version", "State", "Stack MAC"
            ]

            # Convert list of dicts to list of lists
            data_to_save = [
                [row.get(col, "") for col in columns]
                for row in save_data
            ]

            queue_save(
                ctx,
                columns,
                data_to_save,
                sheet_name="E911 Switch Info",
                index=False,
                force_header=True
            )

            # Also save failed devices if any
            if failed_devices:
                queue_save(
                    ctx,
                    columns=["Device", "Error"],
                    raw_data=[[d, e] for d, e in failed_devices],
                    sheet_name="E911 Switch Info - Errors",
                    index=False,
                    force_header=True
                )

            logger.info(f"E911 data queued for saving: {len(data_to_save)} entries")

        press_any_key(ctx)
