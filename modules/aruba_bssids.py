# modules/aruba_bssids.py
from typing import Dict, List

from core.base import BaseModule, ScriptContext
from utils.user_input import read_user_input
from utils.display import console, get_global_color_scheme, print_table_data
from utils.file_io import queue_save
from utils.validation import validate_and_normalize_mac_address

# --- Helper Function ---
# This function is specific to this module, so it's good practice to keep it here.
# If another module ever needs it, it can be promoted to a util.


def _wired_mac_to_bssids(wired_mac: str, bssid: str) -> List[str]:
    """
    Aruba BSSID from Ethernet MAC
    Author - Kieran Morton - mortonese.com
    """
    # (The full, unchanged body of your original wired_mac_to_bssids function goes here)
    clean_mac = wired_mac.replace(":", "")
    nic = clean_mac[6:16]
    nic = nic[1:16]
    binary_nic = format(int(nic, 16), "020b")
    binary_nic = binary_nic + "0000"
    a = binary_nic[0:4]
    b = "1000"
    y = int(a, 2) ^ int(b, 2)
    z = bin(y)[2:].zfill(len(a))
    binary_r0_nic = z + binary_nic[4:]
    binary_bssid = format(int(bssid, 10), "020b").zfill(len(binary_r0_nic))
    binary_r1_nic = bin(int(binary_r0_nic, 2) + int(binary_bssid, 2))[2:]
    r0_nic = hex(int(binary_r0_nic, 2))[2:]
    r1_nic = hex(int(binary_r1_nic, 2))[2:]
    r0_mac = clean_mac[0:6] + r0_nic
    r1_mac = clean_mac[0:6] + r1_nic
    r0_mac = (':'.join(r0_mac[i:i+2] for i in range(0, len(r0_mac), 2))).upper()
    r1_mac = (':'.join(r1_mac[i:i+2] for i in range(0, len(r1_mac), 2))).upper()
    return [r0_mac, r1_mac]


class ArubaBSSIDModule(BaseModule):
    """
    Module to convert a list of wired MAC addresses to their corresponding
    Aruba BSSID MACs for 2.4GHz and 5GHz radios.
    """
    @property
    def menu_key(self) -> str:
        return "b"

    @property
    def menu_title(self) -> str:
        return "Aruba BSSID MACs"

    def run(self, ctx: ScriptContext) -> None:
        """
        Requests user to provide a list of MAC addresses, converts them,
        and prints/saves the results.
        (Original `aruba_bssids` logic)
        """
        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - Aruba BSSID MAC Information")

        console.print(
            "\n"
            f"[{colors['description']}]Enter MAC addresses (one per line).[/]\n"
            f"[{colors['description']}]Empty input line starts the process.[/]\n"
            "[cyan]Supported MAC formats:[/]\n"
            "[red]xx:xx:xx:xx:xx:xx\n"
            "xx-xx-xx-xx-xx-xx\n"
            "xxxx.xxxx.xxxx\n"
            "xxxxxxxxxxxx[/]"
        )

        mac_addresses: List[str] = []
        while True:
            search_input = read_user_input(ctx, "").strip()
            if not search_input:
                break
            mac = validate_and_normalize_mac_address(search_input)
            if mac:
                mac_addresses.append(mac)

        unique_macs = list(dict.fromkeys(mac_addresses))
        if not unique_macs:
            return

        logger.info(f"User input - MACs for Aruba BSSID conversion: {', '.join(unique_macs)}")

        # --- Data Processing ---
        results_data: List[Dict[str, str]] = []
        # Define the columns ONCE, as the source of truth for the structure.
        columns = ["Wired MAC", "5GHz MAC", "2.4GHz MAC"]

        for wired_mac in unique_macs:
            mac24, mac5 = _wired_mac_to_bssids(wired_mac, '16')
            # Create a dictionary for each row, ensuring keys match the columns.
            results_data.append({
                columns[0]: wired_mac,
                columns[1]: mac5,
                columns[2]: mac24
            })

        # --- HOOK: Allow plugins to modify the list of result dictionaries ---
        final_results_data = self.execute_hook('process_data', ctx, results_data)

        # --- Display and Save ---
        if final_results_data:
            print_table_data(ctx, {"Aruba BSSIDs": final_results_data})

            if ctx.cfg["report_auto_save"]:
                # The final columns should be derived from the data, in case a plugin added one.
                final_columns = list(final_results_data[0].keys())

                # Convert the list of dictionaries to a list of lists for saving.
                save_data_lol = [[row.get(col, '') for col in final_columns] for row in final_results_data]

                queue_save(ctx, final_columns, save_data_lol, sheet_name="Aruba BSSIDs", index=False, force_header=True)
