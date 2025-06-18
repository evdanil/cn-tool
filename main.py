#!/usr/bin/env python
# Copyright 2024 - Evgeny Danilchenko evdanil@gmail.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import configparser
import logging
import signal
import argparse
import time
import sys
from pathlib import Path
import warnings

# This suppresses the specific CryptographyDeprecationWarning from paramiko
# which can be noisy on some systems.
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except ImportError:
    # If cryptography is not installed, we don't need to do anything.
    pass

# --- Core Application Imports ---
from core.base import ScriptContext
from core.loader import load_modules_and_plugins

# --- Utility Imports ---
from utils.api import session
from utils.app_lifecycle import exit_now
from utils.auth import get_auth_creds
from utils.config import BASE_CONFIG_SCHEMA, read_config, setup_from_args
from utils.display import console, get_global_color_scheme, set_global_color_scheme
from utils.file_io import start_worker, check_dir_accessibility
from utils.logging import configure_logging
from utils.user_input import read_user_input
from core.background import start_background_tasks


# --- Global Constants ---
VERSION = '0.2.21 hash e740052'


def _get_config_paths(args: argparse.Namespace) -> list[Path]:
    """
    Determines the prioritized list of configuration files to read.

    Priority Order (lowest to highest):
    1. Global config (`.cn` next to the script)
    2. User config (`~/.cn`)
    3. Explicitly provided config file via `-c` argument.

    """

    # Otherwise, build the standard layered list.
    script_dir = Path(sys.argv[0]).resolve().parent
    global_config = script_dir / ".cn"
    user_config = Path.home() / ".cn"

    final_list = [global_config, user_config]

    if args.config:
        final_list.append(Path(args.config).expanduser())

    # The order here is important! User config should override global.
    return final_list


def bootstrap_logging(args: argparse.Namespace) -> logging.Logger:
    """
    A special pre-configuration function to set up logging at the earliest possible moment.
    It only looks for log file and log level settings.
    """

    # Defaults
    log_file = str(Path.home() / "cn.log")
    log_level = "INFO"

    # Find the config files to read using our new helper
    config_paths = _get_config_paths(args)
    existing_files = [f for f in config_paths if f.is_file()]

    if existing_files:
        parser = configparser.ConfigParser()
        parser.read(existing_files)  # Read all found files in order
        if parser.has_section("logging"):
            log_file = parser.get("logging", "logfile", fallback=log_file)
            log_level = parser.get("logging", "level", fallback=log_level)

    # CLI arguments still have the highest priority
    if args.log_file:
        log_file = args.log_file
    if args.log_level:
        log_level = args.log_level

    return configure_logging(str(Path(log_file).expanduser()), log_level.upper())


def main() -> None:
    """
    Main function that orchestrates the execution of the script.
    """

    description = """
cn-tool v{version}

The tool allows to retrieve information from Infoblox and perform network operations.

Features:

- Performs IP/Subnet/DNS/Site information lookups using Infoblox API
- Performs bulk FQDN/IP ping operations
- Performs bulk FQDN/IP lookups using system resolver
- Performs search configuration storage (`/opt/data/configs/`) for obsolete data(cleanups on BGP borders/prefixes/ACLs)
- Obtains device information (sn, ios version and image, license data) in parallel
- Saves all requested information for later information processing(by default `report.xlsx` in $HOME directory)
- Keeps log of requests/responses(by default `cn.log` in $HOME directory)
- Can be easily configured by creating/changing configuration file(by default `.cn` in $HOME directory)
- Supports several color themes (default, monochrome, pastel, dark)

Useful tips:

Request for credential can be skipped if environmental variable `TACACS_PW` is set or device-apply.gpg file with credentials present in user directory.

- for environmental variable set up - copy lines below(including EOF) and paste in the terminal window:

cat >> ~/.bash_profile <<EOF
echo -n "Enter current TACACS_PW:"
read -s TACACS_PW
export TACACS_PW
EOF

It will update .bash_profile with the request to read `TACACS_PW` credential during login time. Re-login to the terminal to see it in action.

- for device-apply.gpg file creation use commands below, if file is older than 24 hours it won't be used:

device-apply --make-key
device-apply --make-credentials --overwrite

Create an alias for convenience by adding line to `.bash_profile`:

cat >> ~/.bash_profile <<EOF
alias cn="{exec_file}"
EOF

Re-login and start using cn-tool by running:
cn

Please send any feedback/feature requests to evdanil@gmail.com
"""
    parser = argparse.ArgumentParser(description=description.format(version=VERSION, exec_file=Path(__file__).name), formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-c", "--config", default=None, help="specify configuration file")
    parser.add_argument("-nc", "--no-cache", action="store_true", help="run without cache use")
    parser.add_argument("-t", "--theme", choices=['default', 'monochrome', 'pastel', 'dark'], help="color theme")
    parser.add_argument("-l", "--log-file", help="specify logfile")
    parser.add_argument("-r", "--report-file", help="report filename")
    parser.add_argument("-g", "--gpg-file", help="GPG credentials file")
    parser.add_argument("-v", "--version", action="version", version=f"cn-tool v{VERSION}")
    parser.add_argument("--log-level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help="Set the logging level.")
    args = parser.parse_args()

    logger = bootstrap_logging(args)

    logger.info(f"cn-tool v{VERSION} starting up...")
    logger.debug(f"Command-line arguments received: {args}")

    logger.info("Loading application modules and plugins...")
    loaded_modules, all_plugins, final_schema = load_modules_and_plugins(BASE_CONFIG_SCHEMA)
    logger.info(f"Loaded {len(loaded_modules)} modules and {len(all_plugins)} plugins.")

    # Determine the configuration file hierarchy
    config_paths_to_check = _get_config_paths(args)

    # read_config now handles the logic of checking and reading the files
    cfg = read_config(config_paths_to_check, final_schema, logger)

    # Then, we override any values from the config with command-line arguments.
    cfg = setup_from_args(cfg, args, logger)

    # Add non-user-configurable values to the config dict
    cfg["version"] = VERSION

    # 1. Check for Infoblox API readiness
    final_message = ''
    if cfg.get("api_endpoint") == "API_URL" or not cfg.get("api_endpoint"):
        log_msg = "Infoblox API URL is not set. Infoblox-related modules will be disabled."
        logger.warning(log_msg)
        final_message += log_msg + '\n'
        cfg['infoblox_enabled'] = False
    else:
        cfg['infoblox_enabled'] = True

    # 2. Check for Configuration Repo readiness
    if not check_dir_accessibility(logger, cfg.get("config_repo_directory", "dummy_dir")):
        log_msg = "Configuration repository directory is not accessible. Config search modules will be disabled."
        logger.warning(log_msg)
        final_message += log_msg + '\n'
        cfg['config_repo_enabled'] = False
    else:
        cfg['config_repo_enabled'] = True

    # 3. Check report file accessibility
    if not check_dir_accessibility(logger, cfg["report_file"].parent):
        log_msg = "Report directory not accessible, using current directory."
        logger.warning(log_msg)
        final_message += log_msg + '\n'
        cfg["report_file"] = Path(cfg["report_file"].name)

    if final_message:
        console.print(f"[bold]{final_message}[/]")
        time.sleep(5)
    ctx = ScriptContext(cfg=cfg, logger=logger, console=console, cache=None, username='', password='', plugins=all_plugins)

    username, password = get_auth_creds(ctx)
    if username and password:
        session.auth = (username, password)
    else:
        ctx.logger.warning("Auth - Incomplete credentials provided; Infoblox API calls may fail.")

    # Connect global plugins
    for plugin in ctx.plugins:
        if plugin.manages_global_connection:
            plugin.connect(ctx)

    set_global_color_scheme(ctx)
    signal.signal(signal.SIGINT, lambda s, f: exit_now(ctx, 1, "Interrupted... Exiting..."))

    start_background_tasks(ctx)
    start_worker()

    colors = get_global_color_scheme(cfg)
    menu_header = """  """
    # Define the structure and order of your menu
    menu_layout = {
        "--- Tasks ---": ['1', '2', '3', '4', '5', '6', '7', '8', '9', 'b'],
        "--- Info ---": ['a'],
        "--- Reporting ---": ['e', 'd'],
        "--- Application ---": ['s', '0']
    }

    menu_lines = [menu_header, f"    [{colors['error']} {colors['title']}]MENU[/][{colors['code']}]"]

    for header, keys in menu_layout.items():
        # A flag to track if we should print the header for this section
        header_printed = False
        section_lines = []

        for key in keys:
            # Handle the static 'Exit' case
            if key == '0':
                section_lines.append(f"    [{colors['warning']} {colors['bold']}]0. Exit[/]")
                continue

            module = loaded_modules.get(key)
            if not module:
                continue

            # Check visibility based on the module's declared dependency
            visibility_key = module.visibility_config_key

            if visibility_key and not cfg.get(visibility_key, False):
                continue  # Skip this module if its dependency is not met

            # If we are here, the module is visible, so add it to the list
            section_lines.append(f"    {module.menu_key}. {module.menu_title}")

            # If we found any visible items in this section, print the header and the items
        if section_lines:
            if not header_printed:
                menu_lines.append(f"\n    [{colors['header']}]{header}[/]")
                header_printed = True
            menu_lines.extend(section_lines)

    menu = "\n".join(menu_lines)

    while True:
        ctx.console.clear()
        ctx.console.print(menu)
        choice = read_user_input(ctx, "\nEnter your choice: ")

        # '0' is now handled by the menu structure, but we still need the exit logic
        if choice == '' or choice == '0':
            exit_now(ctx)

        module_to_run = loaded_modules.get(choice)
        if module_to_run:
            # Check visibility again before running, as a safety measure
            visibility_key = module_to_run.visibility_config_key
            if visibility_key and not ctx.cfg.get(visibility_key, False):
                ctx.console.print(f"[{colors['error']}]This feature is currently disabled.[/]")
                time.sleep(2)
            else:
                module_to_run.run(ctx)
        else:
            ctx.console.print(f"[{colors['error']}]Invalid choice. Please try again.[/]")
            time.sleep(1)
            continue

        # ctx.console.print(f"[{colors['description']}]Press [{colors['error']}]Enter[/] key to continue[/]")
        # read_user_input(ctx, "")


if __name__ == "__main__":
    main()
