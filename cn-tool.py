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

import os
import ipaddress
import signal
import json
from operator import itemgetter
from time import perf_counter
from socket import gaierror, herror, timeout
import socket
from concurrent.futures import ThreadPoolExecutor
import re
import configparser
from argparse import RawTextHelpFormatter
import argparse
import logging
import pandas as pd
import requests
from requests.exceptions import HTTPError, Timeout, RequestException, MissingSchema
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
from rich.console import Console
from rich.table import Table
from rich import box
import subprocess
from subprocess import Popen, DEVNULL, STDOUT
from datetime import datetime, timedelta

# Fix MAC address emoji issue
from rich._emoji_codes import EMOJI

del EMOJI["cd"]

MIN_INPUT_LEN = 6
version = '0.1.81 hash 6beab68'

# Disable SSL self-signed cert warnings, comment out line below if Infoblox
# deployment uses proper certificate
urllib3.disable_warnings()

console = Console()

# Define session object to handle all https requests
# Handle rate-limit and server errors
retries = Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"],
    backoff_factor=2
)

adapter = HTTPAdapter(max_retries=retries, pool_connections=10)
session = requests.Session()
session.mount("https://", adapter)
session.headers.update({"Content-Type": "application/json"})


def interrupt_handler(logger: logging.Logger, signum: int, frame: any) -> None:
    """
    Signal handler for SIGINT (Ctrl+C) interruption.

    @param signum: Signal number.
    @param frame: Current stack frame.
    """
    if isinstance(logger, logging.Logger):
        logger.info(f"CTRL-C Interrupt({signum}) - Terminating... Stack:{frame}")

    console.print("[red bold]Interrupted... Exiting...[/red bold]")
    exit_now(logger, exit_code=1)


def read_config(cfg: dict, config_file: str = ".cn") -> dict:
    """
    Reads configuration file

    @param config_file: path to configuration file with filename(can be
        relative or absolute)

    @return cfg(dict): populated dictionary with configuration values
        read from the file or default values(if config missing specific
        parameter)
    """

    if os.path.exists(config_file):
        config = configparser.ConfigParser()
        config.read(config_file)

        read_cfg = {
            "api_endpoint": config.get("api", "endpoint", fallback=cfg["api_endpoint"]),
            "logfile_location": os.path.expanduser(config.get("logging", "logfile", fallback=cfg["logfile_location"])),
            "log_level_str": config.get("logging", "level", fallback="INFO"),
            "report_filename": os.path.expanduser(config.get("output", "filename", fallback=cfg["report_filename"])),
            "gpg_credentials": os.path.expanduser(config.get("gpg", "credentials", fallback=cfg["gpg_credentials"])),
            "auto_save": config.getboolean("output", "auto_save", fallback=True),
            "store": os.path.expanduser(config.get("config_repository", "storage_directory", fallback=cfg["store"])),
            "regions": config.get("config_repository", "regions", fallback="ap,eu,am").split(','),
            "vendors": config.get("config_repository", "vendors", fallback="cisco,aruba,f5,bluecoat,paloalto").split(','),
        }
    else:
        read_cfg = cfg

    return read_cfg


def data_to_dict(column_names: list, data: list) -> dict:
    """
    Converts a list of column names and corresponding data into a dictionary.

    @param column_names: List of column names.
    @param data: List of lists representing the data rows.
    @return: Dictionary with column names as keys and data as values.
    """
    # Function need two dimension array, in case if only single raw was sent it might be a simple list only

    result_dict = {}

    if isinstance(data, list) and len(data) > 0:
        if not isinstance(data[0], list):
            data = [data]
    else:
        # if nothing to save or data is not list - return empty dict
        return result_dict

    # Iterate through column names
    for col_name in column_names:
        result_dict[col_name] = []

    # Iterate through data rows
    for row in data:
        # Iterate through column names and corresponding row data
        for col_name, col_data in zip(column_names, row):
            # Append data to the corresponding key in the dictionary
            result_dict[col_name].append(col_data)

    return result_dict


def print_search_config_data(data: list) -> None:
    """
    Prints the configuration search data in a formatted manner.
    Sort the data array based on the device name and line number, then prints out data per device.
    Columns in the data are as follows:
    [ip(search ip matching), device_name(str), line_num(int), config_line(str)]

    @param data(list[list]): config data to print out
    """

    if len(data) == 0:
        # Nothing to print
        return

    data.sort(key=lambda x: (x[1], x[2]))

    current_device = ''
    current_line = 0

    for row in data:
        device = row[1].upper()
        line_number = row[2]
        line = row[3]

        if device != current_device:
            current_device = device
            current_line = line_number
            console.print(f'\n[purple bold]Device {current_device}[/purple bold]:')
            console.print(f'[yellow bold]Line[/yellow bold] {current_line}:')
        elif line_number - current_line >= 100:
            current_line = line_number
            console.print(f'\n[yellow bold]Line[/yellow bold] {current_line}:')

        console.print(line)
    console.print('\n')

    return


def make_dir_list(logger: logging.Logger, cfg: dict) -> list:
    """
    Reads cfg and makes up a list of directories to read devices from

    @param logger(Logger): logger instance.

    @return list
    """
    dir_list = []
    for vendor in cfg["vendors"]:
        vendor = vendor.strip()
        dir_path = os.path.join(cfg["store"], vendor)
        if not check_dir_accessibility(dir_path, logger):
            logger.info(f'Configuration Repository - No data directory for {vendor.upper()} found!')
            continue

        for device_type in os.listdir(dir_path):
            for region in cfg["regions"]:
                region = region.strip()
                device_directory = os.path.join(dir_path, device_type, region)
                if not check_dir_accessibility(device_directory, logger):
                    logger.info(f'Configuration Repository - No data directory for {region.upper()} found!')
                    continue
                dir_list.append(device_directory)

    return dir_list


def search_config(logger: logging.Logger, cfg: dict, dir: str, nets: list[ipaddress.IPv4Network], search_term: list[re.Pattern], search_input: str) -> tuple[list,list]:
    """
    Searches files in a given directory for keywords(regex) or subnet addresses, or a single IP
    @param logger: logger instance
    @param cfg: configuration parameters
    @param dir: directory path
    @param nets: list of ipaddress.IPv4Network objects
    @param search_terms: list of regular expressions to match
    @param search_input: only used in interacive mode when user explicitly looks for a single subnet/keyword

    @return None
    """

    data_to_save = []
    matched_nets = set()
    dir_list = os.listdir(dir)
    parts = dir.split('/')
    with console.status(
        f'[yellow]Searching through [green bold]{parts[4].upper()}/{parts[5].upper()}[/green bold] configurations in [green bold]{parts[6].upper()}[/green bold] region...[/yellow]',
        spinner="dots12"
    ):

        with ThreadPoolExecutor() as executor:
            futures = {
                device: executor.submit(
                    matched_lines,
                    logger,
                    os.path.join(dir, device),
                    nets,
                    search_term,
                    search_input
                ) for device in dir_list
            }
            results = {device: future.result() for device, future in futures.items()}
        for _, result in results.items():
            # result has a tuple with two lists:
            # list 1 - actual config matches
            # list 2 - matched subnets
            if result and len(result[0]) > 0:
                data_to_save.extend(result[0])
            if result and len(result[1]) > 0:
                matched_nets.update(result[1])

    return (data_to_save, matched_nets)


def search_config_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Searches configuration repository files for keywords(regex) or subnet addresses, or a single IP

    Requests user to provide a search string or subnet with mask (IP/XX form)
    Validates user input, expands subnet to include all IPs within the subnet
    Performs search over configuration repository for keywords or expanded IP list
    Displays formatted data to a user (calls print_search_config_data)
    Saves references to tabs/config lines in 'Config Check' tab
    Copies device configurations into new tabs = device names

    @param logger(Logger): logger instance.

    @return None
    """
    logger.info('Configuration Repository - Search Request')
    console.print(
        "\n"
        "[yellow]Enter subnets in the format [green]IP_ADDRESS/\\[MASK][/green], one subnet per line[/yellow]\n"
        "[yellow]Alternatively a [red bold]single line[/red bold] with [green]KEYWORDS(regex supported)[/green] can be used(longer than 6 chars)[/yellow]\n"
        "[yellow]Empty input line starts the process[/yellow]\n"
        "\n"
        "[magenta]Subnet Examples:[/magenta]\n"
        "[green bold]10.10.10.0/24[/green bold]\n"
        "[green bold]134.143.169.176/29[/green bold]\n"
        "[magenta]Keywords Regex Examples:[/magenta]\n"
        "[green bold]router bgp 655\\d+$[/green bold]\n"
        "[green bold]neighbor \\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3} description VOCUS\\s+[/green bold]\n"
        )

    search_input = 'none'
    search_term = None
    keyword_regexp = None
    networks = None
    while True:
        search_input = read_user_input(logger, '').strip()
        if search_input == '':
            break

        # Check if input looks like an IP address or subnet
        if '/' not in search_input and re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', search_input):
            # IP address without mask, append default mask of /32
            search_input += '/32'

        if '/' in search_input and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$', search_input):
            # IP address with mask
            try:
                network = ipaddress.ip_network(search_input, strict=False)
            except ValueError:
                logger.info(f'User input - Not matching network address: {search_input}')
                console.print('[red]Invalid subnet format. Enter a valid subnet or IP (e.g., 192.168.1.0/24 or 192.168.1.10)[/red]')
                continue
            else:
                if network.is_multicast or network.is_unspecified or network.is_reserved or network.is_link_local:
                    logger.info(f'User input - Invalid subnet: {search_input}')
                    console.print(
                        '[red]Invalid IP - multicast, broadcast, and reserved subnets excluded.\n'
                        'Enter a valid non-reserved subnet or IP (e.g., 10.10.1.0/24 or 192.168.1.10)[/red]')
                    continue
                if networks is None:
                    networks = []
                networks.append(network)
                continue

        if len(search_input) < MIN_INPUT_LEN:
            logger.info(f'User input - Input keyword is too short: {search_input}')
            console.print(f'[red]Input keyword is too short: {search_input}')
            # Skipping wrong line
            continue

        # Try to compile the input as a regular expression
        try:
            keyword_regexp = re.compile(search_input)
        except re.error as e:
            logger.info(f'User input - Invalid regexp: {e}')
            console.print(f'[red]Invalid regular expression - {e.msg}')
            # Skipping wrong line
            continue
        else:
            # Last added regexp or string line is considered as search term.
            # However, if subnets were supplied, we ignore it
            if networks:
                continue
            else:
                search_term = keyword_regexp
                break

    if networks and len(networks) > 0:
        # just as a precaution we set search_term to None if we have networks populated
        search_term = None
        search_input = ',\n'.join([str(network) for network in networks])
        log_value = search_input.replace(",\n", " ")
        logger.info(f'User input - {log_value}')
    else:
        logger.info(f'User input - {search_input}')

    if not networks and not search_term:
        return

    data_to_save = []
    matched_nets = set()

    start = perf_counter()
    for dir in make_dir_list(logger, cfg):
        lines, nets = search_config(logger, cfg, dir, networks, search_term, search_input)

        data_to_save.extend(lines)
        matched_nets.update(nets)
    end = perf_counter()
    logger.info(f'Configuration Repository - Search took {round(end-start, 2)} seconds!')
    console.print(f'Configuration Repository - Search took {round(end-start, 2)} seconds!')

    if len(data_to_save) == 0:
        logger.info('Configuration Repository - No matches found!')
        console.print('No matches found!')
        return

    if networks:
        missing_nets = list(set(networks) - set(matched_nets))
        for missed_net in missing_nets:
            if str(missed_net).endswith('/32'):
                missed_net = str(missed_net)[:-3]
            console.print(f'[yellow]Subnet [green bold]{missed_net}[/green bold] - [red]No matches found[/red]')
    else:
        missing_nets = None

    data = [
        [search_input, device, line_num, line_content] for search_input, device, line_num, line_content, _ in data_to_save
    ]
    sorted_data = sorted(data, key=itemgetter(1, 2))
    print_search_config_data(sorted_data)

    # Saving data automatically unless user requested not to (relies on global auto_save flag)
    if cfg["auto_save"]:
        save_found_data(logger, cfg, data_to_save, missing_nets, 'Config Check')


def demob_site_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Requests user to provide FQDN string
    Validates user input
    Calls do_fancy_request
    Calls process_site_data
    Prints data if present
    Saves data if auto_save enabled

    @param logger(Logger): logger instance.

    @return: None
    """

    console.print(
        "\n"
        "[yellow bold]This request is to verify if any subnets exist on the devices for a given sitecode, subnets pulled from Infoblox matching description field[/yellow bold]\n"
        "[red bold]Always check provided results[/red bold]\n"
        "[yellow]Request has a limit of [red bold]50[/red bold] subnet records per site[/yellow]\n"
        "[yellow]Type in location site code to perform search[/yellow]\n"
        "[yellow]Supported site code format: [green bold]XXX[/green bold] or [green bold]XXX-XX\\[X][/green bold][/yellow]\n"
        "[magenta]Site Code Examples:[/magenta]\n"
        "[green bold]AMS-DC, WND-RYD[/green bold]\n"
    )

    raw_input = read_user_input(logger, "Enter location site code: ").lower().strip()

    logger.info(f'User input - {raw_input}')
    if is_valid_site(raw_input):
        search_term = raw_input
        logger.info(f'User input - Sitecode search for {search_term}')
    else:
        logger.info(f'User input - Incorrect site code {raw_input}')
        console.print("[red]Incorrect site code[/red]")
        return

    uri = f'network?comment:~={search_term}&_max_results=50'
    processed_data = {}

    data = do_fancy_request(
        logger,
        message=f'Fetching data for [magenta]{search_term.upper()}[/magenta]...',
        endpoint=cfg["api_endpoint"],
        uri=uri,
    )

    if data and len(data) > 0:
        # process_data if not empty has 'location' key with subnet data
        processed_data = process_data(logger, type=f"location_{search_term}", content=data)

    if len(processed_data.get("location", '')) == 0:
        logger.info('Request Type - Location Information - No information received')
        console.print('[red]No information received[/red]')
        return

    print_table_data(
        logger,
        processed_data
    )

    message = f'Received {len(processed_data["location"])} subnet records registered for {search_term.upper()}'
    console.print(message)
    logger.info(f'Request Type - Location Information - {message}')
    logger.debug(f'Request Type - Location Information - Processed data {processed_data}')

    if read_user_input(logger, "Would you like to proceed(Y/N)? ").lower() != "y":
        return

    # Now for each location subnet we have to perform configuration lookup, it might take longer than we expect
    locations = processed_data["location"]
    networks = []
    for location in locations:
        networks.append(ipaddress.ip_network(location["network"]))

    start = perf_counter()
    data_to_save = []
    matched_nets = set()
    for dir in make_dir_list(logger, cfg):
        lines, nets = search_config(logger, cfg, dir, networks, None, search_term.upper())
        data_to_save.extend(lines)
        matched_nets.update(nets)

    end = perf_counter()
    logger.info(f'Configuration Repository - Search took {round(end-start, 2)} seconds!')

    if len(data_to_save) == 0:
        logger.info(f'Configuration Repository - No matches for {search_term.upper()} found!')
        console.print('No matches found!')
        return

    missing_nets = list(set(networks) - set(matched_nets))
    if len(missing_nets) > 0:
        for missed_net in missing_nets:
            if str(missed_net).endswith('/32'):
                missed_net = str(missed_net)[:-3]
            console.print(f'[yellow]Subnet [green bold]{missed_net}[/green bold] - [red]No matches found[/red]')
    else:
        missing_nets = None

    data = [
        [search_input, device, line_num, line_content] for search_input, device, line_num, line_content, _ in data_to_save
    ]
    sorted_data = sorted(data, key=itemgetter(1, 2))
    print_search_config_data(sorted_data)

    # Saving data automatically unless user requested not to (relies on global auto_save flag)
    if cfg["auto_save"]:
        save_found_data(logger, cfg, data_to_save, missing_nets, 'Demob Site Check')


def save_found_data(logger: logging.Logger, cfg: dict, data: list, missed_nets: set, sheet: str = 'Config Check') -> None:
    """
    Saves provided data in report file, used by search_config_request and demob_site_request functions

    @param logger(Logger): logger instance
    @param cfg(dict): configuration params
    @param data(list): data to save
    @param sheet(str): excel tab to save config matches

    @return: None
    """

    logger.info(f'Configuration Search - {sheet} saving configuration matches')

    with console.status(
                f'Saving data to {cfg["report_filename"]}...',
                spinner="dots12"
            ):
        # Adding information about subnets which did not have any matches
        search_input = data[0][0]

        if missed_nets:
            missed_nets_data = [
                [search_input, net] for net in missed_nets
            ]
            if is_valid_site(search_input):
                columns = ["Site Code", "Unused Subnets"]
            else:
                columns = ["Search Terms", "Unused Subnets"]
            # Saving Subnet Data first
            append_df_to_excel(
                logger,
                cfg["report_filename"],
                columns,
                missed_nets_data,
                sheet_name=sheet,
                index=False,
                force_header=True
            )

        # Adding hyperlinks to Line number
        columns = ["Search Terms", "Device", "Line number", "Line"]
        sorted_data = [
            [search_input, device, '=HYPERLINK("#\'{}\'!A{}", {})'.format(device, key+1, key), value, _] for search_input, device, key, value, _ in data
        ]
        # Saving Check data
        append_df_to_excel(
            logger,
            cfg["report_filename"],
            columns,
            sorted_data,
            sheet_name=sheet,
            index=False,
            force_header=True
        )

    # Adding device configurations to the report
    device_list = {(device_name, fname) for _, device_name, _, _, fname in data}
    # Not saving configs if we have more than 50 devices matched
    if len(device_list) > 50:
        console.print(f'Too many devices({len(device_list)}) have matches, skipping report update')
        return
    logger.info(f'Configuration Search - {sheet} saving device configs')
    with console.status(
                f'Appending device configuration to {cfg["report_filename"]}...',
                spinner="dots12"
            ):

        for device, fname in device_list:
            with open(fname, 'r', encoding='utf-8') as f:
                file_content = f.readlines()
                append_df_to_excel(
                    logger,
                    cfg["report_filename"],
                    columns=None,
                    raw_data=file_content,
                    sheet_name=device,
                    index=False,
                    skip_if_exists=True
                )


def matched_lines(logger: logging.Logger, filename: str, ip_nets: list[ipaddress.IPv4Network], search_term: re.Pattern, search_input: str) -> tuple[list, set]:
    """
    Looks up for matches in a file for a given list of IP networks or search pattern
    Returns data list

    @param logger(Logger): logger instance
    @param filename(str): filename to match data on
    @param ip_nets(IPv4Network): subnets to lookup
    @param search_term(re.Pattern): keyword regexp to match
    @search_input(str): to save in file as info if provided

    @return: tuple[list, list] first list in tuple is the matched lines data, second list in tuple is the list of matched subnets
    """
    data_to_save = []
    matched_nets = set()

    if ip_nets:
        search_term = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    else:
        # return if no search_term given and no ip_nets defined (should'nt happen)
        if search_term is None:
            return (data_to_save, matched_nets)

    if os.path.isfile(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            file_content = f.readlines()

            # Strip spaces
            current_config = [line.strip() for line in file_content]

            device = f'{os.path.split(filename)[1].split(".")[0].upper()}'
            rows_to_save = {}

            # console.print(device)

            for index, current_line in enumerate(current_config):
                # if there is a match in line check if we have ip_data and verify found IP within the subnet range
                if ip_nets:
                    found_matches = re.findall(search_term, current_line)
                    for match in found_matches:
                        try:
                            found_ip = ipaddress.ip_address(match)
                        except (re.error, ValueError):
                            logger.debug(f'Config Check - Found {match} bad IP(skipped) in {device.upper()} line {index}')
                            continue
                        else:
                            matched_subnet = next((net for net in ip_nets if found_ip in net), None)
                            if matched_subnet:
                                matched_nets.add(matched_subnet)
                                logger.debug(f'Config Check - Found {found_ip} matching subnet {matched_subnet} in {device.upper()} line {index}')
                                rows_to_save[index] = f'{current_config[index]}'
                else:
                    matched = re.search(search_term, current_line)
                    if matched:
                        logger.debug(f'Config Check - Found expresison "{matched.group()}" in {device.upper()} line {index}')
                        rows_to_save[index] = f'{current_config[index]}'

        # Saving all gathered data to data_to_save array
        if len(rows_to_save) > 0:
            # Sorting by config line prior saving
            rows = [
                [search_input, device, key, value, filename]
                for key, value in sorted(
                    rows_to_save.items(),
                    key=lambda x: (
                        x[0] if isinstance(x[0], int) else float("inf")
                    ),
                )
            ]
            data_to_save.extend(rows)

    return (data_to_save, matched_nets)


def append_df_to_excel(
    logger: logging.Logger,
    filename: str,
    columns: list,
    raw_data: list,
    sheet_name: str = "Sheet1",
    startrow: int = None,
    truncate_sheet: bool = False,
    skip_if_exists: bool = False,
    force_header: bool = False,
    **to_excel_kwargs: any,
) -> None:
    """
    Append a DataFrame [df] to existing Excel file [filename] into [sheet_name] Sheet.
    If [filename] doesn't exist, then this function will create it.

    @param logger(Logger): logger instance.
    @param filename: File path or existing ExcelWriter
                     (Example: '/path/to/file.xlsx')
    @param columns(list): list of column names - headers
    @param raw_data: 2d array with data

    @param sheet_name: Name of sheet which will contain DataFrame.
                       (default: 'Sheet1')
    @param startrow: upper left cell row to dump data frame.
                     Per default (startrow=None) calculate the last row
                     in the existing DF and write to the next row...
    @param truncate_sheet: truncate (remove and recreate) [sheet_name]
                           before writing DataFrame to Excel file
    @param skip_if_exists: if sheet exists, do nothing
    @param force_header: write header no matter what
    @param to_excel_kwargs: arguments which will be passed to `DataFrame.to_excel()`
                            [can be a dictionary]

    @return: None

    Original Author: (c) [MaxU](https://stackoverflow.com/users/5741205/maxu?tab=profile)

    evgeny: - fixed append feature which was not working due to newer pandas version
            - added prepare_df helper function(creates df set)
            - added required parameters to integrate into common codebase
            - minor fixes/checks
    """

    def prepare_df(columns: list, data: list) -> pd.DataFrame:
        """
        Helper function prepares Pandas DataFrame
        """
        data_to_save = data_to_dict(columns, data)
        data_frame = pd.DataFrame.from_dict(data_to_save)

        return data_frame

    #  If columns were provided need to prepare data set, otherwise we have to save data as is
    if columns:
        df = prepare_df(columns, raw_data)
    else:
        df = pd.DataFrame(raw_data)

    # Excel file doesn't exist - saving and exiting
    if not check_file_accessibility(filename, logger):
        # Log report creation
        logger.info(f"Export - Report {filename} doesn't exist - creating...")

        df.to_excel(
            filename,
            sheet_name=sheet_name,
            startrow=startrow if startrow is not None else 0,
            **to_excel_kwargs,
        )
        # Log success
        logger.info(f'Export - {filename} - created successfully')

        return

    # ignore [engine] parameter if it was passed
    if "engine" in to_excel_kwargs:
        to_excel_kwargs.pop("engine")

    # To find out if there is any data in existing file and if it is there how many rows occupied
    try:
        existing_data = pd.read_excel(filename, sheet_name=sheet_name, engine='openpyxl')
    # If no sheet in the workbook we get ValueError exception
    except ValueError:
        existing_data = ""

    filled_rows = len(existing_data)

    if filled_rows > 0 and skip_if_exists:
        return

    if filled_rows > 0 and not truncate_sheet:
        logger.info(
            f'Export - Found {filename} report - Sheet {sheet_name} has {filled_rows} rows'
        )
        # New data will be placed right after last row
        startrow = filled_rows + 1
    elif filled_rows > 0:
        logger.info(
            f'Export - Found {filename} report - Truncating {sheet_name}, adding new data'
        )
        startrow = 0
    else:
        logger.info(
            f'Export - Found {filename} report - No {sheet_name} sheet found, creating...'
        )
        startrow = 0

    with pd.ExcelWriter(
        filename, engine="openpyxl", if_sheet_exists="overlay", mode="a"
    ) as writer:

        # if force_header is set we always write header, otherwise
        # if filled_rows = 0 then we need header, otherwise header is already in the sheet
        # in no columns provided we dont need a header
        if columns and force_header:
            header = True
        elif columns:
            header = not bool(filled_rows)
        else:
            header = False

        # write out the data to the sheet
        df.to_excel(
            writer,
            startrow=startrow,
            header=header,
            sheet_name=sheet_name,
            **to_excel_kwargs,
        )

        # log success
        logger.info(f'Export - Updated {filename} successfully')

    return


def configure_logging(logfile_location: str, log_level=logging.INFO) -> logging.Logger:
    """
    Sets up logger facility

    @param logfile_location(str): path and filename to write log to
    @param log_level(int): severity level number for log message (logger.[INFO|WARNING|ERROR] and etc)

    @return instance(logger): initialised logger instance.
    """

    # Create a logger
    logger = logging.getLogger(__name__)

    # Set the log level
    logger.setLevel(log_level)

    # Create a file handler
    file_handler = logging.FileHandler(logfile_location)

    # Create a formatter
    file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    # Add the formatter to the file handler
    file_handler.setFormatter(file_formatter)

    # Add the file handler to the logger
    logger.addHandler(file_handler)

    return logger


def validate_ip(ip: str) -> bool:
    """
    Validates an IP address using a regular expression.

    @param ip: IP address to validate

    @return: bool: True if the IP address is valid, False otherwise.
    """

    # Valid IP regex
    ip_regex = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

    # pass the regular expression
    # and the string in search() method
    if re.search(ip_regex, ip):
        return True

    return False


def is_valid_site(sitecode: str) -> bool:
    """
    Validates a site code using a regular expression.

    @param sitecode: Site code to validate.
    @return: True if the site code is valid, False otherwise.
    """

    # This regex allows for either three alphanumeric characters followed by a hyphen and another three alphanumeric characters,
    # or simply three alphanumeric characters without the hyphen.
    valid_site_regex = "^[A-Za-z0-9]{3}(?:-[A-Za-z0-9]{2,3})?$"

    if re.search(valid_site_regex, sitecode):
        return True

    return False


def is_fqdn(hostname: str) -> bool:
    """
    Validates a fully qualified domain name (FQDN) based on its structure and length.

    @param hostname: Hostname to validate.
    @return: True if the hostname is a valid FQDN, False otherwise.
    """
    if not 1 < len(hostname) < 253:
        return False

    # Remove trailing dot
    if hostname[-1] == '.':
        hostname = hostname[0:-1]

    #  Split hostname into list of DNS labels
    labels = hostname.split('.')

    #  Define pattern of DNS label
    #  Can begin and end with a number or letter only
    #  Can contain hyphens, a-z, A-Z, 0-9
    #  1 - 63 chars allowed
    fqdn = re.compile(r"^[a-z][a-z0-9][-a-z0-9]{0,61}[a-z0-9]?$", re.IGNORECASE)

    # Check that all labels match that pattern.
    return all(fqdn.match(label) for label in labels)


def create_table(
    logger: logging.Logger,
    title: str,
    columns: list,
    data: list[list],
    title_style: str = "bold yellow",
    box: box = box.MINIMAL,
) -> Table:
    """
    Creates a Rich table with the provided parameters.

    @param    logger(Logger): logger instance.
    @param    title (str): The title of the table.
    @param    columns (list[str]): A list of column names.
    @param    data (list[list]): A list of rows, where each row is a list of data values.
    @param    title_style (str, optional): The style for the table title. Defaults to "bold yellow".
    @param    box (box, optional): The box style for the table. Defaults to box.MINIMAL.

    @return    Table: The created Rich table.
    """

    title = title.upper()

    logger.debug(f'Table - title = {title} columns = {len(columns)} rows = {len(data)}')

    table = Table(title=title, title_style=title_style, box=box)
    for column in columns:
        table.add_column(
            column, justify="left", style="spring_green3", no_wrap=False
        )  # You can customize styles here
    for row in data:
        table.add_row(*row)
    return table


def print_table_data(
    logger: logging.Logger, data: dict, prefix: dict = {}, suffix: dict = {}
) -> None:
    """
    Prints data using keys as column names, can use prefix/suffix dictionary to add additional information to title (main keys)
    keys in data should match keys in suffix/prefix
    @param data(dict)
    @param prefix(dict)
    @param suffix(dict)

    @return None
    """
    if len(data) == 0:
        console.print('No data to display')
        return

    for key, value_list in data.items():
        # Capitalize the first letter of the key
        section_title = key
        # Add prefix and suffix to the section title if available
        prefix_text = prefix.get(key, '')
        suffix_text = suffix.get(key, '')
        section_title = f'{prefix_text} {section_title} {suffix_text}'
        section_title.upper()
        # Define colums
        columns = []
        # Define table data
        table_data = []

        # Dont do anything if dict has no values
        if len(value_list) == 0:
            continue

        # Since we get list of dict objects - each has same keys() which we can use as column names
        for name in value_list[0].keys():
            columns.append(name.upper())

        for record in value_list:
            table_data.extend([record.values()])

        table = create_table(logger, section_title, columns, table_data)
        console.print(table)


def exit_now(logger: logging.Logger, cfg: dict = None, exit_code: int = 0) -> None:
    """
    Gracefully exits from application

    @param logger(Logger): logger instance.
    @param exit_code(int): exit code =0 clean exit, >0 means an error.

    @return: exit_code
    """
    if not exit_code:
        logger.info('Terminating by user request - Have a nice day!')
        console.print('[green]Have a nice day![/green] :smiley:')
    else:
        logger.info('Abnormal termination - Hoping for a patch!')

    exit(exit_code)


def make_api_call(logger: logging.Logger, endpoint: str, uri: str) -> any:
    """
    Performs Infoblox API requests, handles exceptions and validates that response.content is a valid json object
    in case of API errors logs error and terminates program execution

    @return: response(Response): Returns complete response without parsing for data
    """

    logger.info(f'Performing API request - URL: {endpoint}{uri}')

    try:
        response = session.get(f'{endpoint}{uri}', verify=False)
        response.raise_for_status()

    except (Timeout, ConnectionError) as e:
        logger.error(f'API Error - {e.response.status_code} - {e.response.text}')
        console.print(f'[red]API Error[/red] - {e.response.text}')
        exit_now(logger, exit_code=1)

    except (HTTPError, RequestException, MissingSchema) as e:
        if response.status_code == 400:
            logger.info(f'API - Missing data - {e.response.text}')
        elif response.status_code == 401:
            logger.error(f'API Error - Authentication error - {e.response.text}')
            console.print(
                f'[red]Authentication error - verify credentials[/red] - {e.response.text}'
            )
            exit_now(logger, exit_code=1)
        else:
            logger.error(f'API Error - {e}')
            console.print('[red]API Error[/red]')

        logger.debug(f'API response: {response.content}')

        try:
            json.loads(response.content)
        except json.JSONDecodeError as e:
            logger.error(f'API Error - Failed to parse JSON response - {e}')
            console.print('[red]Failed[/red] to parse JSON response|Check API URL!')
            exit_now(logger, exit_code=1)

    return response


def do_fancy_request(
    logger: logging.Logger,
    message: str,
    endpoint: str,
    uri: str,
    spinner: str = "dots12",
) -> any:
    """
    Prepares shows message, spinner and performs make_api_call
    Validates response status

    @param logger(Logger): logger instance.

    @return: content(response.content) or None if request has error
    """
    def execute_request():
        response = make_api_call(logger, endpoint, uri)
        if response.ok:
            return response.content
        else:
            return None

    if spinner:
        # If spinner is not None, use the context manager with spinner
        with console.status(status=message, spinner=spinner):
            return execute_request()
    else:
        # If spinner is None, execute the request directly
        return execute_request()


def process_data(logger: logging.Logger, type: str, content: str) -> dict:
    """
    Process raw information according to 'type' and return data dict to be used in print/save

    @param logger(Logger): logger instance.
    @param type(str): a key to be used in processing logic and as a key in the returned
        dictionary(unless other keys required by processing logic)
    @param content(json string): Response.content returned by do_fancy_call

    @return: process_data(dict) or None: Contains keys holding processed information
        or returns {} if no data gathered
    """

    logger.info(f'Processing data - {type.upper()}')

    logger.debug(f'Processing data {type.upper()} content: {content}')

    try:
        raw_data = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f'Failed to parse JSON response - {e}')
        console.print('[red]Failed[/red] to parse JSON response|Check API URL!')
        exit_now(logger, exit_code=1)

    # If data present, process it and return corresponding dict
    if len(raw_data) == 0:
        return {}

    data = raw_data[0]
    processed_data = {}
    if type == "ip":
        processed_data = {"general": [], "extra": []}

        # General IP information output
        processed_data["general"].append(
            {
                "network": data.get('network'),
                "ip": str(data.get('_ref')).split(':')[1],
                "name": ",".join(data.get('names')),
                "status": data.get('status'),
            }
        )

        # Extra IP information output
        if data.get('lease_state'):
            lease_state = data.get('lease_state')
        else:
            lease_state = ''

        if data.get('types') and len(data.get('types')) != 0:
            types = data.get('types')
        else:
            types = ''

        if data.get('mac_address') and len(data.get('mac_address')) != 0:
            mac_address = data.get('mac_address')
        else:
            mac_address = ''

        # Only print additional table if it has some data
        if len(mac_address + ''.join(types) + lease_state) > 0:

            processed_data['extra'].append(
                {
                    "lease state": lease_state,
                    "record type": ','.join(types),
                    "mac": mac_address,
                }
            )

    elif type == "location_keyword":
        processed_data = {"location": []}
        processed_data["location"] = [
            {"network": location.get('network'), "comment": location.get('comment')}
            for location in raw_data
            if location.get('network')
        ]
    elif type.startswith("location_"):
        # extract sitecode from type argument
        sitecode = type.split('_')[1].lower()
        processed_data = {"location": []}
        processed_data["location"] = [
            {"network": location.get('network'), "comment": location.get('comment')}
            for location in raw_data
            if location.get('network')
            and len(location.get('comment', '').split(';')) > 1
            and location.get('comment', '').split(';')[1].strip().lower() == sitecode
        ]
    elif type == "fqdn":
        processed_data = {"fqdn": []}
        processed_data["fqdn"] = [
            {"ip": f"{fqdn.get('ipv4addr')}", "name": f"{fqdn.get('name')}"}
            for fqdn in raw_data
            if fqdn.get('ipv4addr')
        ]
    elif type == "general":
        processed_data = {"general": []}
        # General subnet information
        if data and len(data) > 0:
            processed_data["general"] = [
                {
                    "subnet": data.get('network', ''),
                    "description": data.get('comment', ''),
                }
            ]

    elif type == "DNS records":
        # DNS Information
        processed_data = {"DNS records": []}
        processed_data["DNS records"] = [
            {
                "IP address": record.get('ip_address'),
                "A Record": ", ".join(record.get('names', '')),
            }
            for record in raw_data
        ]

    elif type == "network options":

        if data and len(data) > 0:
            processed_data = {"DHCP members": [], "DHCP options": []}
            # Network DHCP Members Information
            dhcp_members_data = data.get("members", [])
            dhcp_options_data = data.get("options", [])
            if len(dhcp_members_data) > 0:
                processed_data["DHCP members"] = [
                    {"IP Address": member.get('ipv4addr'), "name": member.get('name')}
                    for member in dhcp_members_data
                ]
            if len(dhcp_options_data) > 0:
                # Network DHCP Options Information output
                processed_data["DHCP options"] = [
                    {
                        "name": option.get('name'),
                        "num": str(option.get('num')),
                        "value": option.get('value'),
                        "vendor class": option.get('vendor_class'),
                        "use option": str(option.get('use_option')),
                    }
                    for option in dhcp_options_data
                ]

    elif type == "DHCP range":
        processed_data = {"DHCP range": []}
        # Network DHCP Range Information output
        processed_data["DHCP range"] = [
            {
                "network": range.get('network'),
                "start address": range.get('start_addr'),
                "end address": range.get('end_addr'),
            }
            for range in raw_data
        ]
    elif type == "DHCP failover":
        processed_data = {"DHCP failover": []}
        # Network DHCP Failover Association Information output
        processed_data["DHCP failover"] = [
            {"dhcp failover": dhcp_failover.get('failover_association')}
            for dhcp_failover in raw_data
        ]
    elif type == "fixed addresses":
        processed_data = {"fixed addresses": []}
        # Network DHCP Fixed Addresses Information output
        processed_data["fixed addresses"] = [
            {
                "IP address": addr_obj.get('ipv4addr'),
                "name": addr_obj.get('name'),
                "MAC": addr_obj.get('mac'),
            }
            for addr_obj in raw_data
        ]

    return processed_data


def ip_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Requests user to provide IP address
    Validates user input
    Calls do_fancy_request
    Calls process_ip_data
    Prints data if present
    Saves data if auto_save enabled

    @param logger(Logger): logger instance.

    @return: None
    """

    logger.info('Request Type - IP Information')

    console.print(
            "\n"
            "[yellow]Please provide IP address, tool will request API and return detailed information,\n"
            "such as its hostname, location, and network configuration[/yellow]\n"
        )

    ip = read_user_input(logger, 'Enter the IP Address: ')

    logger.info(f'User input - {ip}')

    if not validate_ip(ip):
        logger.info(f'User input - Not valid IP address: {ip}')
        console.print('[red]Not valid IP address[/red]')
        return

    processed_data = {}

    data = do_fancy_request(
        logger,
        message=f'Fetching data for [magenta]{ip}[/magenta]...',
        endpoint=cfg["api_endpoint"],
        uri=f'ipv4address?ip_address={ip}&_return_fields=network,names,status,types,lease_state,mac_address',
    )

    if data and len(data) > 0:
        # process_data if not empty has 'general' and 'extra' keys with IP data
        processed_data = process_data(logger, type="ip", content=data)

    if len(processed_data) == 0:
        logger.info('Request Type - IP Information - No information received')
        console.print('[red]No information received[/red]')
        logger.debug(f'Request Type - IP Information - raw data {data}')
        return

    print_table_data(
        logger,
        processed_data,
        suffix={"general": "IP Information", "extra": "IP Information"},
    )
    logger.debug(f'Request Type - IP Information - processed data {processed_data}')

    # Saving data automatically unless user requested to not to(relies on global auto_save flag)
    if cfg["auto_save"]:
        columns = [
            "Subnet",
            "IP",
            "Name",
            "Status",
            "Lease State",
            "Record Type",
            "MAC",
        ]
        save_data, save_data_general, save_data_extra = [], [], []

        for ip in processed_data["general"]:
            save_data_general.append([value for value in ip.values()])
        for ip_data in processed_data["extra"]:
            save_data_extra.append([value for value in ip_data.values()])

        # Combine two arrays
        # Iterate over the rows of save_data_general and save_data_extra simultaneously using zip()
        # If save_data_extra has fewer rows than save_data_general, we add empty lists ([]) to save_data_extra to make their lengths equal
        # For each pair of rows (row1 from save_data_general and row2 from save_data_extra), we check if row2 has the same length as row1:
        # If they have the same length, we concatenate row1 and row2 as is.
        # If row2 is shorter than row1, we concatenate row2 with a list of empty strings ([''] * (len(row1) - len(row2))) to make their lengths equal before concatenating with row1.
        # This ensures that if save_data_extra has fewer elements in a row compared to save_data_general, the missing elements are filled with empty strings in the resulting save_data list
        save_data = [
            row1
            + (
                row2
                if len(row2) == len(row1)
                else row2 + [""] * (len(row1) - len(row2))
            )
            for row1, row2 in zip(
                save_data_general,
                save_data_extra
                + [[] for _ in range(len(save_data_general) - len(save_data_extra))],
            )
        ]

        append_df_to_excel(
            logger,
            cfg["report_filename"],
            columns,
            save_data,
            sheet_name="IP Data",
            index=False,
        )

    return


def fqdn_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Requests user to provide FQDN string
    Validates user input
    Calls do_fancy_request
    Calls process_fqdn_data
    Prints data if present
    Saves data if auto_save enabled

    @param logger(Logger): logger instance.

    @return: None
    """

    logger.info('Request Type - FQDN Search - DNS A records')

    console.print(
        "\n"
        "[yellow]Type in just a part of the name or complete FQDN name(not less than 3 chars)\n"
        "Request fetches DNS A records matching or containing prefix, short hostname or full FQDN\n"
        "Request has a limit of [red bold]1000[/red bold] records\n"
        "[magenta]Examples:[/magenta]\n"
        "[green][bold]'aucicbst'[/bold] fetches records starting with [white bold]aucicbst[/white bold] prefix\n"
        "[bold]'aucicbstwc010'[/bold] fetches record for the device\n"
        "[bold]'aucicbstwc010.net-equip.shell.net'[/bold] fetches record for the device[/green]\n"
    )

    fqdn = read_user_input(logger, 'Enter the device name(fqdn or short prefix): ').lower()

    logger.info(f'User input - FQDN Search - {fqdn}')

    if not is_fqdn(fqdn):
        logger.info(f'User input - FQDN Search - Incorrect FQDN/prefix - {fqdn}')
        console.print('[red]Incorrect FQDN/prefix[/red]')
        return

    if len(fqdn) < 3:
        logger.info('User input - FQDN Search - Prefix is less than 3 chars')
        console.print('[red]Please use longer prefix(at least 3 characters)[/red]')
        return

    uri = f'search?fqdn~={fqdn}&_max_results=1000'
    data = do_fancy_request(
        logger,
        message=f'Fetching data for [magenta]{fqdn}[/magenta]...',
        endpoint=cfg["api_endpoint"],
        uri=uri,
    )

    processed_data = {}

    if data and len(data) > 0:
        # process_data if not empty has 'fqdn' key with found A DNS records
        processed_data = process_data(logger, type="fqdn", content=data)

    if len(processed_data) == 0:
        logger.info('Request Type - FQDN Search - No information received')
        console.print('[red]No information received[/red]')
        logger.debug(f'Request Type - FQDN Search - raw data {data}')
        return

    print_table_data(logger, processed_data, suffix={"general": "Search Results"})
    logger.debug(f'Request Type - FQDN Search - processed data {processed_data}')

    # Saving data automatically unless user requested to not to(relies on global auto_save flag)
    if cfg["auto_save"]:
        columns = ["IP Address", "Device Name"]
        save_data = []
        for fqdn in processed_data["fqdn"]:
            save_data.append([value for value in fqdn.values()])

        append_df_to_excel(
            logger,
            cfg["report_filename"],
            columns,
            save_data,
            sheet_name="FQDN Data",
            index=False,
        )

    return


def location_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Requests user to provide FQDN string
    Validates user input
    Calls do_fancy_request
    Calls process_site_data
    Prints data if present
    Saves data if auto_save enabled

    @param logger(Logger): logger instance.

    @return: None
    """
    logger.info('Request Type - Search for site subnet records')

    console.print(
        "\n"
        "[yellow]Type in location site code to obtain a list of registered [yellow bold]subnets[/yellow bold]\n"
        "Supported location format [green bold]XXX[/green bold] or [green bold]XXX-XX\\[X][/green bold]\n"
        "Request has a limit of [red bold]1000[/red bold] records[/yellow]\n"
        "[magenta bold]Examples:[/magenta bold]\n"
        "[green][bold]CIC[/bold] fetches [yellow bold]subnets[/yellow bold] for Chinchilla location\n"
        "[bold]WND-RYD[/bold] fetches [yellow bold]subnets[/yellow bold] for Wandoan office[/green]\n"
        "\n"
        "[yellow]Type in '[green bold]+[/green bold]' as a first symbol followed by arbitrary keyword(cannot have spaces)[/yellow]\n"
        "[magenta bold]Examples:[/magenta bold]\n"
        "[green][bold]+[/bold]CNBEJWTCMP610[/green] [yellow]fetches subnets with [bold]CNBEJWTCMP610[/bold] in description[/yellow]\n"
        "[green][bold]+[/bold]PRJ18[/green] [yellow]fetches subnets with [bold]PRJ18[/bold] in description[/yellow]\n"
    )

    raw_input = read_user_input(logger, "Enter location code or '+'keyword: ").lower()

    logger.info(f'User input - {raw_input}')

    search_term = ''
    search_type = ''
    prefix = {}
    suffix = {}
    if raw_input.startswith("+"):
        if re.match(r'^[a-zA-Z0-9_]*$', raw_input[1:]):
            search_term = raw_input[1:]
            logger.info(f'User input - Keyword search for {search_term}')
            search_type = 'keyword'
        else:
            logger.info(f'User input -  Incorrect input {raw_input}')
            console.print("[red]Incorrect input provided[/red]")
            return
    else:
        if is_valid_site(raw_input):
            search_term = raw_input
            # to handle in the process_data sitecodes
            search_type = raw_input
            prefix.update({"location": f'{search_term.upper()}'})
            suffix.update({"location": "Subnets"})
            logger.info(f'User input - Sitecode search for {search_term}')
        else:
            logger.info(f'User input -  Incorrect site code {raw_input}')
            console.print("[red]Incorrect site code[/red]")
            return

    if len(search_term) == 0:
        logger.info('User input -  Empty input')
        console.print("[red]Incorrect input provided[/red]")
        return

    uri = f'network?comment:~={search_term}&_max_results=1000'

    data = do_fancy_request(
        logger,
        message=f'Fetching data for [magenta]{search_term.upper()}[/magenta]...',
        endpoint=cfg["api_endpoint"],
        uri=uri,
    )

    processed_data = {}
    if data and len(data) > 0:
        # process_data if not empty has 'location' key with subnet data
        processed_data = process_data(logger, type=f"location_{search_type}", content=data)

    if len(processed_data.get("location", '')) == 0:
        logger.info('Request Type - Location Information - No information received')
        console.print('[red]No information received[/red]')
        return

    print_table_data(
        logger,
        processed_data,
        prefix=prefix,
        suffix=suffix,
    )
    logger.debug(
        f'Request Type - Location Information - processed data {processed_data}'
    )

    if cfg["auto_save"]:
        columns = ["Subnet", "Description"]
        save_data = []
        for subnet in processed_data["location"]:
            save_data.append([value for value in subnet.values()])

        append_df_to_excel(
            logger,
            cfg["report_filename"],
            columns,
            save_data,
            sheet_name="Subnet Lookup",
            index=False,
        )

    return


def subnet_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Requests user to provide network IP
    Validates user input
    Calls do_fancy_request for general, dns_records, network_options,
        dhcp_range, dhcp_failover, fixed_address data
    Calls process_network_data
    Prints data if present
    Saves data if auto_save enabled

    @param logger(Logger): logger instance.

    @return: None
    """

    logger.info('Request Type - Subnet Information')

    console.print(
        "\n"
        "[yellow]Enter a network address in the format 'x.x.x.x\\[/x]', where:\n"
        "- 'x.x.x.x' represents the IP address.\n"
        "- '/x' (optional) represents the subnet mask prefix in CIDR notation\n"
    )
    raw_input = read_user_input(logger, "(x.x.x.x\\[/x]): ")

    logger.info(f"User input - {raw_input}")

    net_addr = raw_input.split("/")

    if not validate_ip(net_addr[0]):
        logger.info(f'User input - Not valid IP address: {net_addr[0]}')
        console.print('[red]Not valid IP address[/red]')
        return

    network = net_addr[0]

    # Catching exception if non-numerical mask
    if len(net_addr) == 2:
        try:
            subnet_prefix = int(net_addr[1])
        except ValueError:
            logger.info(f'Wrong network mask - Use only digits - {subnet_prefix}')
            console.print('[red]Wrong network mask - Use only digits[/red]')
            return
        else:
            # Checking if mask is outside 32 bits
            if subnet_prefix < 0 or subnet_prefix > 32:
                logger.info(f'Wrong network mask - Out of bounds - {subnet_prefix}')
                console.print('[red]Wrong network mask - Out of bounds[/red]')
                return

    # If valid mask is given update network address with the mask
    if len(net_addr) == 2:
        network = f'{network}/{net_addr[1]}'

    # Compile API request URIs to obtain general network information
    req_urls = {
        "general": f'network?network={network}',
        "DNS records": f'ipv4address?network={network}&usage=DNS&_return_fields=ip_address,names',
        "network options": f'network?network={network}&_return_fields=options,members',
        "DHCP range": f'range?network={network}',
        "DHCP failover": f'range?network={network}&_return_fields=member,failover_association',
        "fixed addresses": f'fixedaddress?network={network}&_return_fields=ipv4addr,mac,name',
    }
    # process_data function will return 'DHCP members' and 'DHCP options' when type = 'network options'
    processed_data = {
        "general": [],
        "DNS records": [],
        "DHCP options": [],
        "DHCP members": [],
        "DHCP range": [],
        "DHCP failover": [],
        "fixed addresses": [],
    }

    # Request general network information
    with ThreadPoolExecutor() as executor:
        with console.status(status=f'Fetching [magenta]{network}[/magenta] information...'):
            futures = {
                label: executor.submit(
                    do_fancy_request,
                    logger=logger,
                    message='',
                    endpoint=cfg["api_endpoint"],
                    uri=uri,
                    spinner=None
                ) for label, uri in req_urls.items()
            }

            results = {label: future.result() for label, future in futures.items()}

    for key, response in results.items():
        if response and len(response) > 0:
            processed_data.update(process_data(logger, type=key, content=response))

    # display data only if it is available
    if len(processed_data["general"]) > 0:
        print_table_data(logger, processed_data, suffix={"general": "Information"})

        # save data
        if cfg["auto_save"]:
            # Need to compile single 2d array with all the data to save it in xlsx
            dhcp_members_data = processed_data.get("DHCP members", "")
            dhcp_options_data = processed_data.get("DHCP options", "")
            dhcp_ranges_data = processed_data.get("DHCP range", "")
            dhcp_failover_data = processed_data.get("DHCP failover", "")
            dns_data = processed_data.get("DNS records", "")
            fixed_address_data = processed_data.get("fixed addresses", "")
            columns = [
                "IP",
                "Mask",
                "Name",
                "MAC",
                "DHCP",
                "DHCP Scope Start",
                "DHCP Scope End",
                "DHCP Servers",
                "DHCP Options\nOption - Value",
                "DHCP Failover Association",
                "Notes",
            ]
            data = []
            DHCP = "N"
            DHCP_Start = ""
            DHCP_End = ""
            DHCP_Servers = ""
            DHCP_Options = ""
            DHCP_Failover = ""
            Notes = processed_data.get("general", [])[0].get("description", "")
            subnet = processed_data["general"][0].get("subnet").split("/")

            if len(dhcp_members_data) > 0 and len(dhcp_members_data[0]) > 0:
                DHCP = "Y"
                DHCP_Servers = "\n".join(
                    [
                        " - ".join([member["name"], member["IP Address"]])
                        for member in dhcp_members_data
                    ]
                )

            if len(dhcp_options_data) > 0 and len(dhcp_options_data[0]) > 0:
                DHCP_Options = "\n".join(
                    [
                        " - ".join([option["name"], option["value"]])
                        for option in dhcp_options_data
                    ]
                )
            # Only support single DHCP range with index 0
            if len(dhcp_ranges_data) > 0 and len(dhcp_ranges_data[0]) > 2:
                DHCP_Start = dhcp_ranges_data[0]["start address"]
                DHCP_End = dhcp_ranges_data[0]["end address"]
            if len(dhcp_failover_data) > 0 and len(dhcp_failover_data[0]) > 0:
                DHCP_Failover = dhcp_failover_data[0]["dhcp failover"]

            # Subnet row
            first_row = [
                subnet[0],
                f'/{subnet[1]}',
                "Subnet",
                "",
                DHCP,
                DHCP_Start,
                DHCP_End,
                DHCP_Servers,
                DHCP_Options,
                DHCP_Failover,
                Notes,
            ]

            data.append(first_row)

            # Preparing DNS A records
            if len(dns_data) > 0:
                # Saving only first A record, as many found it more usable
                dns_rows = [
                    [
                        record["IP address"],
                        "/32",
                        record["A Record"].split(",")[0],
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "DNS record",
                    ]
                    for record in dns_data
                ]
                data.extend(dns_rows)

            # Preparing Fixed IP records registerd in IPAM/DHCP
            if len(fixed_address_data) > 0:

                fixed_ip_rows = [
                    [
                        fixed_ip["IP address"],
                        "/32",
                        fixed_ip["name"],
                        fixed_ip["MAC"],
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "Fixed IP",
                    ]
                    for fixed_ip in fixed_address_data
                ]
                data.extend(fixed_ip_rows)

            # Save data
            append_df_to_excel(
                logger,
                cfg["report_filename"],
                columns,
                data,
                sheet_name="Subnet Data",
                index=False,
            )
    else:
        # No network data available
        logger.info(f'Subnet Information - No information received for {network}')
        console.print('[red]No information received[red]')

    return


def read_user_input(logger: logging.Logger, prompt: str = " ", read_pass: bool = False) -> str:
    """
    Read user input and checks for CTRL-D/CTRL-C combinations
    If read_pass is True, function will request password string
    """
    raw_input = ''
    try:
        raw_input = console.input(
            f'[bold green]{prompt}[/bold green]', password=read_pass, markup=True
        )
    except EOFError:
        pass
    except KeyboardInterrupt:
        interrupt_handler(logger, signal.SIGINT, None)

    return raw_input


def clear_report(logger: logging.Logger, cfg: dict) -> None:
    """
    Deletes the specified report file or the default report file (report.xlsx).

    @param logger: Logger instance.
    """
    filename = cfg["report_filename"]
    if os.path.exists(filename):
        if logger:
            logger.info(f'Clear report - Deleting {filename}')

        os.remove(filename)
        console.print(f'Report {filename} deleted')
    else:
        console.print(f'Report {filename} already deleted')


def show_config_search_help(logger: logging.Logger, cfg: dict) -> None:
    console.print(
        "\n"
        "[yellow]Unable to access configuration repository\n"
        "Check [magenta bold]\\[config_repository][/magenta bold] section in the configuration file,\n"
        "Verify that [green bold]storage_directory[/bold green] parameter set to a proper path\n"
        "If path is correct, verify that your account has read access to it[/yellow]\n"
    )


def bulk_ping_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Runs multiple parallel ping processes against list of user supplied IP addresses
    """

    logger.info('Request Type - Bulk PING')

    console.print(
        "\n"
        "[yellow]Enter IPs/FQDNs to ping, one per line, non-valid IP/FQDNs are ignored.\n"
        "Empty input line starts ping process:[/yellow]"
    )
    hosts = []
    raw_input = 'none'
    while raw_input != '':
        raw_input = read_user_input(logger, "").strip()
        if not validate_ip(raw_input) and not is_fqdn(raw_input):
            continue
        hosts.append(raw_input)

    logger.info(f'User input - {", ".join(hosts)}')

    # Stackoverflow good example on how to run multiple pings at once
    # ip -> process
    p = {}
    results = {'Bulk PING': []}

    with console.status('Pinging...', spinner="dots12"):

        for host in hosts:
            # start ping processes - wait for 5 seconds to get 3 successful pings
            p[host] = Popen(['ping', '-n', '-w5', '-c3', host], stdout=DEVNULL, stderr=STDOUT)

        while p:
            for host, proc in p.items():
                # ping finished
                if proc.poll() is not None:
                    # remove from the process list
                    del p[host]
                    # console.print(host, proc)
                    if proc.returncode == 0:
                        # console.print('%s active' % host)
                        results['Bulk PING'].append({'Host': f'{host}', 'Result': 'OK'})
                    elif proc.returncode == 1:
                        # console.print('%s no response' % host)
                        results['Bulk PING'].append({'Host': f'{host}', 'Result': 'NO RESPONSE'})
                    else:
                        # console.print('%s error' % host)
                        results['Bulk PING'].append({'Host': f'{host}', 'Result': 'ERROR'})
                    break

    print_table_data(logger, results)

    logger.debug(
        f'Request Type - Bulk PING - processed data {results}'
    )

    if cfg["auto_save"] and len(results["Bulk PING"]) > 0:
        columns = ["Host", "Result"]
        save_data = []
        for ping_result in results["Bulk PING"]:
            save_data.append([ping_result['Host'], ping_result['Result']])

        append_df_to_excel(
            logger,
            cfg["report_filename"],
            columns,
            save_data,
            sheet_name="Bulk PING",
            index=False,
        )

    return


def bulk_resolve_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Resolves user supplied IP/FQDNs using system resolver using parallel threads
    """
    def resolve_ip(ip):
        try:
            result = socket.gethostbyaddr(ip)
        except (gaierror,  herror, timeout):
            result = None

        return (ip, result)

    def resolve_name(name):
        try:
            result = socket.gethostbyname_ex(name)
        except (gaierror,  herror, timeout):
            result = None

        return (name, result)

    logger.info('Request Type - Bulk DNS Lookup')

    console.print(
        "\n"
        "[yellow]Enter FQDNs/IP addresses, one FQDN/IP address per line. Non-valid FQDNs/IPs are ignored.\n"
        "Empty input line starts lookup process:[/yellow]"
    )

    data_lines = {'ip': [], 'name': []}
    raw_input = 'none'
    while raw_input != '':
        raw_input = read_user_input(logger, "").strip()
        if validate_ip(raw_input):
            data_lines['ip'].append(raw_input)
        elif is_fqdn(raw_input):
            data_lines['name'].append(raw_input)
        else:
            continue

    if len(data_lines['ip']) == 0 and len(data_lines['name']) == 0:
        logger.info('No input data')
        return

    logger.info(f"User input - {data_lines}")

    results = {'Bulk Name Lookup': [], 'Bulk IP Lookup': []}

    with console.status('Resolving...', spinner="dots12"):

        with ThreadPoolExecutor() as executor:
            ip_data = executor.map(resolve_ip, data_lines['ip'])
            name_data = executor.map(resolve_name, data_lines['name'])

    # bulk_ip_results = [{'IP': req, 'Name': f'{",".join([data[0],*data[1]])}'} if data else {'IP': req, 'Name': 'Not Resolved'} for req, data in ip_data]
    bulk_ip_results = []

    for req, data in ip_data:
        if data:
            # data[0] has primary result and data[1] is a list with the rest of the results
            bulk_ip_results.append({'IP': req, 'Name': data[0]})
            for name in data[1]:
                bulk_ip_results.append({'IP': req, 'Name': name})
        else:
            bulk_ip_results.append({'IP': req, 'Name': 'Not Resolved'})

    results['Bulk IP Lookup'].extend(remove_duplicates(bulk_ip_results))

    # bulk_name_results = [{'Name': req, 'IP': f'{",".join(data[2])}'} if data else {'Name': req, 'IP': 'Not Resolved'} for req, data in name_data]
    bulk_name_results = []

    for req, data in name_data:
        if data:
            # data[0] has proper fqdn if short hostname has been used
            # data[2] has a list of IPs resolved for the given fqdn
            if req != data[0]:
                name = f'{req}, {data[0]}'
            else:
                name = req
            for ip in data[2]:
                bulk_name_results.append({'Name': name, 'IP': ip})
        else:
            bulk_name_results.append({'Name': req, 'IP': 'Not Resolved'})

    results['Bulk Name Lookup'].extend(remove_duplicates(bulk_name_results))

    # import ipdb; ipdb.set_trace()
    if len(results['Bulk IP Lookup']) == 0 and len(results['Bulk Name Lookup']) == 0:
        results['Bulk IP Lookup'].extend(list({'IP': ip, 'Name': 'Not Resolved'} for ip in data_lines['ip']))
        results['Bulk Name Lookup'].extend(list({'Name': name, 'IP': 'Not Resolved'} for name in data_lines['name']))
        print_table_data(logger, results)
        logger.debug('Request Type - Bulk DNS Lookup - unable to resolve any')
        return

    print_table_data(logger, results)

    logger.debug(
        f'Request Type - Bulk DNS Lookup - processed data {results}'
    )

    if cfg["auto_save"] and (len(results['Bulk Name Lookup']) > 0 or len(results["Bulk IP Lookup"]) > 0):
        columns = ["Query", "Result"]
        save_data = []
        for name_result in results['Bulk Name Lookup']:
            save_data.append([name_result['Name'], name_result['IP']])

        for ip_result in results['Bulk IP Lookup']:
            save_data.append([ip_result['IP'], ip_result['Name']])

        append_df_to_excel(
            logger,
            cfg["report_filename"],
            columns,
            save_data,
            sheet_name="Bulk DNS Lookup",
            index=False,
        )

    return


def remove_duplicates(data):
    """Remove duplicate elements from a list of IP/Name objects"""
    seen = set()  # A set to keep track of seen (data) pairs
    unique_data = []  # A list to store unique objects

    for item in data:
        # Use (item['Name'], item['IP']) tuple as a unique identifier
        identifier = (item['Name'], item['IP'])

        if identifier not in seen:
            seen.add(identifier)
            unique_data.append(item)  # Append only if it's not in the seen set

    return unique_data


def check_file_accessibility(file_path: str, logger: logging.Logger) -> bool:
    """Check if the file exists and is readable."""
    if not os.path.isfile(file_path) or not os.access(file_path, os.R_OK):
        logger.info(f'Unable to read {file_path}')
        return False
    return True


def check_dir_accessibility(dir_path: str, logger: logging.Logger) -> bool:
    """Check if the directory exists and is readable and accessible"""
    if len(dir_path) == 0:
        logger.info('Directory is not specified')
        return False
    if not os.path.isdir(dir_path) or not os.access(dir_path, os.R_OK):
        logger.info(f'Unable to access {dir_path}')
        return False
    return True


def check_file_timeliness(file_path: str, logger: logging.Logger) -> bool:
    """Check if the file's modification time is less than 24 hours ago."""
    modify_time = datetime.fromtimestamp(os.path.getmtime(file_path))
    if datetime.now() - modify_time > timedelta(hours=24):
        logger.info(f'File {file_path} is older than 24 hours')
        return False
    return True


def decrypt_gpg_file(file_path: str, logger: logging.Logger) -> str:
    """Attempt to decrypt the GPG file and handle possible subprocess exceptions."""
    try:
        result = subprocess.run(['gpg', '--batch', '-d', file_path],
                                capture_output=True, text=True, check=True, timeout=90)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f'Unable to decrypt {file_path} - {e}')
    except subprocess.TimeoutExpired:
        logger.error("GPG decryption took too long")
    return None


def parse_gpg_credentials(gpg_output: str) -> tuple:
    """Parse decrypted GPG output to extract user and password."""
    user = password = None
    for line in gpg_output.split('\n'):
        if line.startswith('User ='):
            user = line.split('=')[1].strip()
        elif line.startswith('Password ='):
            password = line.split('=')[1].strip()
    return (None, None) if not user or not password else (user, password)


def get_gpg_credentials(logger: logging.Logger, cfg: dict) -> any:
    """Main function to get decrypted GPG credentials."""
    file_path = cfg["gpg_credentials"]
    if not check_file_accessibility(file_path, logger) or not check_file_timeliness(file_path, logger):
        return None

    decrypted_output = decrypt_gpg_file(file_path, logger)
    if decrypted_output is None:
        return None

    return parse_gpg_credentials(decrypted_output)


def get_auth_creds(logger: logging.Logger, cfg: dict) -> tuple:
    # Read login credentials
    username = os.getenv("USER")
    password = os.getenv("TACACS_PW")

    # If TACACS_PW is not set, try GPG credential file
    creds = None
    if password is None or password == '':
        logger.info('Auth - TACACS_PW not set, checking GPG credentials')
        creds = get_gpg_credentials(logger, cfg)

        # If GPG credentials file does not exist or stale, request fresh credential from user
        if creds is None or (creds[0] is None or creds[1] is None):
            logger.info('Auth - GPG credentials not available, requesting credential from user')
            while password is None or password == "":
                console.clear()
                console.print(
                    "\n"
                    "[cyan]Set up '[red]TACACS_PW[/red]' environment variable to avoid typing in credential\n"
                    "with each run or create/update [red]device-apply.gpg[/red] credentials file\n"
                    f"For more infrmation run {os.path.basename(__file__)} with -h argument[/cyan]\n"
                )
                password = read_user_input(
                    logger,
                    '[yellow bold]Provide security credential:[/yellow bold]',
                    True,
                )
        else:
            logger.info('Auth - GPG credentials obtained')
            username = creds[0]
            password = creds[1]

    return (username, password)


def main() -> None:
    """
    Main function that orchestrates the execution of the script.
    """

    menu = """
    [red bold]MENU[/red bold]
    [cyan]
    1. IP Information
    2. Subnet Information
    3. FQDN Prefix Lookup
    4. Subnet Lookup (by site code or keyword)
    5. Configuration Lookup (by subnet address or keyword)
    6. Bulk PING
    7. Bulk DNS Lookup
    8. Site Demobilization Check
    d. Delete Report[/cyan]
    [bold yellow]
    0. Exit
    [/bold yellow]
    """

    # default params if config is missing
    cfg = {
        "gpg_credentials": os.path.expanduser("~/device-apply.gpg"),
        "api_endpoint": "API_URL",
        "logfile_location": os.path.expanduser("~/cn.log"),
        "log_level_str": "INFO",
        "report_filename": os.path.expanduser("~/report.xlsx"),
        "auto_save": True,
        # Network devices confuration repository
        "store": "/opt/data/configs",
        "regions": ["ap", "eu", "am"],
        "vendors": ["cisco", "aruba", "paloalto", "f5", "bluecoat"],
    }

    switch = {
        "1": ip_request,
        "2": subnet_request,
        "3": fqdn_request,
        "4": location_request,
        "5": search_config_request,
        "6": bulk_ping_request,
        "7": bulk_resolve_request,
        "8": demob_site_request,
        "d": clear_report,
        "0": exit_now,
    }

    # Command-line argument parsing
    description = """
cn-tool v{version}

The tool allows to retrieve information from Infoblox and perform network operations.

Features:

- Performs IP/Subnet/DNS/Site information lookups using Infoblox API
- Performs bulk FQDN/IP ping operations
- Performs bulk FQDN/IP lookups using system resolver
- Performs search configuration storage (`/opt/data/configs/`) for obsolete data(cleanups on BGP borders/prefixes/ACLs)
- Saves all requested information for later information processing(by default `report.xlsx` in $HOME directory)
- Keeps log of requests/responses(by default `cn.log` in $HOME directory)
- Can be easily configured by creating/changing configuration file(by default `.cn` in $HOME directory)

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
""".format(version=version, exec_file=os.path.basename(__file__))

    version_message = """
cn-tool v{version}

Please send any feedback/feature requests to evdanil@gmail.com
""".format(version=version)

    home_dir = os.getenv('HOME')

    parser = argparse.ArgumentParser(description=description, formatter_class=RawTextHelpFormatter)

    parser.add_argument("-c", "--config", default=os.path.join(home_dir, '.cn'), help='specify configuration file(default $HOME/.cn)')
    parser.add_argument("-l", "--log-file", help='specify logfile(default $HOME/cn.log)')
    parser.add_argument("-r", "--report-file", help='report filename(default $HOME/report.xlsx)')
    parser.add_argument("-g", "--gpg-file", help='GPG credentials file')
    parser.add_argument("-v", "--version", action="version", version=version_message, help='show version number and exit')
    args = parser.parse_args()

    # Read configuration
    cfg = read_config(cfg, os.path.expanduser(args.config))

    # Overwrite config values with values from args
    if args.report_file and args.report_file != cfg['report_filename']:
        cfg['report_filename'] = os.path.expanduser(args.report_file)

    if args.log_file and args.log_file != cfg['logfile_location']:
        cfg['logfile_location'] = os.path.expanduser(args.log_file)

    if args.gpg_file and args.gpg_file != cfg['gpg_credentials']:
        cfg['gpg_credentials'] = os.path.expanduser(args.gpg_file)

    # Configure logging
    cfg["log_level"] = logging.getLevelName(cfg["log_level_str"].upper())
    logger = configure_logging(cfg["logfile_location"], cfg["log_level"])

    # TODO add support for xls output format in parallel to console
    logger.info(
        f'cn-tool v{version} - api_endpoint: {cfg["api_endpoint"]} config_file: {args.config}'
    )

    # Auth tuple
    session.auth = get_auth_creds(logger, cfg)

    report_dir = os.path.split(cfg["report_filename"])[0]

    if len(report_dir) > 0 and not check_dir_accessibility(report_dir, logger):
        logger.info(
            f'Application - Reporting: Unable to access {report_dir} - Using current directory {os.getcwd()}'
        )
        cfg["report_filename"] = os.path.split(cfg["report_filename"])[1]
    elif len(report_dir) > 0:
        logger.info(f'Application - Reporting: Using directory {report_dir}')
    else:
        logger.info(f'Application - Reporting: Using directory {os.getcwd()}')

    directory = cfg["store"]
    if not check_dir_accessibility(directory, logger):
        logger.info(
            f'Application - Configuration Repository: Unable to access {directory} - configuration check disabled'
        )
        console.print(f'Unable to access {directory} - configuration check disabled')
        switch["5"] = show_config_search_help

    choice = "-1"

    # Setting CTRL-C intercept
    signal.signal(
        signal.SIGINT, lambda signum, frame: interrupt_handler(logger, signum, frame)
    )

    if cfg['api_endpoint'] == "API_URL":
        logger.error('API Error - Infoblox API endpoint URL is not set')
        console.print(
            '[red]Correct Infoblox API URL is required(update configuration)[/red]'
        )
        exit_now(logger, exit_code=1)

    while choice != '0':
        console.clear()
        console.print(menu)

        choice = read_user_input(logger, 'Enter your choice: ')

        switch.get(choice, exit_now)(logger, cfg)

        console.print('Press [red]Enter[/red] key to continue')
        read_user_input(logger, '')


if __name__ == "__main__":
    main()
