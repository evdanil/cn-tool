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
import signal
import json
from operator import itemgetter
import re
import configparser
import argparse
import logging
import pandas as pd
import requests
from requests.exceptions import HTTPError, Timeout
from requests.exceptions import RequestException, MissingSchema
import urllib3
# from rich import print
from rich.console import Console
from rich.table import Table
from rich import box


# Fix MAC address emoji issue
from rich._emoji_codes import EMOJI

del EMOJI["cd"]

version = "0.1.0"

# Disable SSL self-signed cert warnings, comment out line below if Infoblox
# deployment uses proper certificate
urllib3.disable_warnings()

# Credentials from environment variables
# Add to ~/.bash_profile 4 lines below

# echo -n "Enter current TACACS_PW:"
# read -s TACACS_PW
# export TACACS_PW
# alias cn='path_to_/cn-tool.py'

# do not forget to chmod +x path_to_/cn-tool.py

console = Console()


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
            "logfile_location": config.get("logging", "logfile", fallback=cfg["logfile_location"]),
            "log_level_str": config.get("logging", "level", fallback="INFO"),
            "report_filename": config.get("output", "filename", fallback="report.xlsx"),
            "auto_save": config.getboolean("output", "auto_save", fallback=True),
            "config_storage": config.get("config_repository", "storage_directory", fallback=cfg["config_storage"]),
            "config_regions": config.get("config_repository", "regions", fallback="ap,eu,am").split(','),
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


def search_config_line(logger: logging.Logger, cfg: dict) -> None:
    """
    Searches configuration repository files for network address match

    Requests user to provide network IP address(without mask)
    Validates user input and expands it to include interface and HSRP addresses
    Compiles a list of key strings to match on
    Performs search over configuration repository with expanded IP list
    Once match found performs context lookup back and ahead to match
        configured configuration lines
    Displays formatted data to user (calls print_search_config_data)
    Saves data to report file

    @param logger(Logger): logger instance.

    @return None
    """
    # Regexp matching IP address with space at the end or IP/MASK within text line
    ip_line_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?=/\d{1,2}|\b(?!\S))")

    # regexp matching inner lines in extended ACL
    extended_acl_re = re.compile(r"^\s*(\d+\s+)?(permit|deny)\s+(ip|udp|tcp|gre|icmp|esp|ospf|eigrp|ahp|ipinip|pim|pcp|nos|igmp|\d{1,3})\s+")

    # regexp matching HSRP standby XX keywords
    hsrp_ip_re = re.compile(r"^\s*standby\s+\d+\s+ip\s+")
    hsrp_track_re = re.compile(r"^\s*standby\s+\d+\s+track")
    hsrp_preempt_re = re.compile(r"^\s*standby\s+\d+\s+preempt")
    hsrp_priority_re = re.compile(r"^\s*standby\s+\d+\s+priority\s+(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)$")

    logger.info('Configuration Repository - Search Request')

    console.print(
        "\n"
        "[yellow]Use [green]Network Address[/green] or loopback [green]IP address[/green]\n"
        "Matching devices and configuration will be shown[/yellow]\n"
    )

    search_network = read_user_input(logger, 'Enter the Subnet Address: ')

    logger.info(f'User input - {search_network}')

    def lookup(index: int, key: str) -> dict:
        """
        Looks up for a line matching keywords(array) in reverse order
        (default), index has to be > 0 direction can be 'back'(default)
        or 'ahead' to look for lines beyond or after index

        @param index: current configuration line number matched IP address
        @param key: keyword to get proper context, if it matches to the line
            - proceed with the context search

        @return matched_lines:  Returns dictionary where key is the line
            number and value is matched context lines
        """
        # console.print(key)
        if index == 0 or len(keywords[key].get("lines")) == 0:
            return {}

        # dict to store line_num:line_config data
        matched_lines = {}

        # safeguard if supplied value is not an array
        if not isinstance(keywords[key].get("lines"), list):
            values = [keywords[key]["lines"]]
        else:
            values = keywords[key]["lines"]

        # by default going back
        delta = -1

        # going forward for ahead
        if keywords[key].get("look") == "ahead":
            delta = 1

        # Matching regular expression to current line if match save it
        # in matched_lines
        if isinstance(keywords[key].get('re'), re.Pattern):

            match_line = re.match(keywords[key].get('re', ''),
                                  current_config[index])
            matched_lines[index] = current_config[index]
            if match_line is None:
                return matched_lines

        # Using last value to do interim check to discard missing values
        # early, if values  = 0 return
        if len(values) > 0:
            last_value = values[len(values) - 1]
        else:
            return matched_lines

        for value in values:
            line_pos = index + delta
            # if value is string - match until while check is matching,
            # otherwise continue to scan
            if isinstance(value, str):
                while not (
                    current_config[line_pos].startswith(value)
                    or current_config[line_pos].startswith(last_value)
                ):
                    line_pos += delta
                    # stop if reached beginning of the file or end
                    if line_pos < 0 or line_pos >= len(current_config) - 1:
                        break
            else:
                # value is regex if not str continue to scan until match
                while (
                    re.match(value, current_config[line_pos]) is None
                    and re.match(last_value, current_config[line_pos]) is None
                ):
                    line_pos += delta
                    # stop if reached beginning of the file or its end
                    if line_pos < 0 or line_pos >= len(current_config) - 1:
                        break
            # line number is < 0 or > than len(current_config) - return
            # otherwise matched line found
            if line_pos >= 0 and line_pos < len(current_config) - 1:
                matched_lines[line_pos] = current_config[line_pos]

        return matched_lines

    if not validate_ip(search_network):
        logger.info(f'User input - Not a valid IP address: {search_network}')
        console.print('[red]Not a valid IP address[/red]')
        return

    # Searching for supplied network address AND +1,+2,+3
    # (to cover HSRP enabled interfaces)
    ip_parts = search_network.split('.')
    net_prefix = f'{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.'

    # if 4th octet is less than 252, check HSRP addresses
    # Extra space is useful to match an exact ip and avoid
    # matching 192.168.1.1 to 192.168.1.10 or 192.168.1.110 and etc
    if int(ip_parts[3]) < 252:
        search_ip_addrs = [
            search_network,
            f'{net_prefix}{int(ip_parts[3])+1} ',
            f'{net_prefix}{int(ip_parts[3])+2} ',
            f'{net_prefix}{int(ip_parts[3])+3} ',
        ]
    else:
        search_ip_addrs = [search_network, f'{net_prefix}{int(ip_parts[3])+1} ']

    # keywords is a dictionary where key is what we match first(or indication
    # that match has to happen against regexp),
    # 're' - regexp to match if keyword has regex word inside
    # 'look' - indicates lookup direction
    # 'lines' - is an array to what we match in reverse order
    # (should be sorted in reverse as well)

    keywords = {
        # Defining keys with regexes first as they will be the same for every lookup
        "extended_acl": {
            "re": extended_acl_re,
            "look": "back",
            "lines": ["ip access-list extended"],
        },
        "hsrp_ip": {
            "re": hsrp_ip_re,
            "look": "ahead",
            "lines": [hsrp_priority_re, hsrp_preempt_re, hsrp_track_re],
        },
    }
    for n in search_ip_addrs:
        # Need to strip extra space as we have some other string after for
        # keywords which is in fact key config line prefixes
        net = n.strip()
        keywords.update(
            {
                f'ip address {net} ': {
                    "look": "back",
                    "lines": ["ip vrf forwarding ", "description ",
                              "interface "],
                },
                f'network {net} mask ': {
                    "look": "back",
                    "lines": ["address-family ipv4", "router bgp "],
                },
                f'network {net} 0.0.0': {"look": "back",
                                         "lines": ["router ospf "]},
                f'match address local {net}': {
                    "look": "back",
                    "lines": ["crypto ikev2 policy", "crypto ikev2 profile"],
                },
            }
        )

    data_to_save = []
    for region in cfg["config_regions"]:
        with console.status(
            f'Searching through configurations in [green bold]{region.upper()}[/green bold] region...',
            spinner="dots12",
        ):
            dir_path = f'{cfg["config_storage"]}/{region}/'
            if os.path.isdir(dir_path):
                dir_list = os.listdir(f'{cfg["config_storage"]}/{region}/')
                logger.info(
                    f'Configuration Repository - Checking {region.upper()} region - Storage directory{dir_path}'
                )
            else:
                logger.info(
                    f'Configuration Repository - {region.upper()} region - {dir_path} does not exist!'
                )
                console.print(f'Configuration Repository - {dir_path} does not exist!')
                continue

            for fname in dir_list:

                if os.path.isfile(dir_path + os.sep + fname):
                    with open(dir_path + os.sep + fname, 'r', encoding='utf-8') as f:
                        file_content = f.readlines()

                        # Strip spaces
                        current_config = [line.strip() for line in file_content]

                        device = f'{fname.split(".")[0].upper()}'
                        rows_to_save = {}

                        for ip in search_ip_addrs:
                            ip_stripped = ip.strip()
                            for index, current_line in enumerate(current_config):

                                # Returns None if there is no match to IP pattern
                                ip_match = re.search(ip_line_re, current_line)

                                # if there is an IP in line we match our IP with IP captured in regexp
                                if ip_match and ip_stripped == ip_match.group():

                                    for keyword in keywords.keys():

                                        if (keyword in current_line or isinstance(keywords[keyword].get('re'), re.Pattern)):

                                            # _line_data will contain matches with the context(keyword -> values) elements
                                            _line_data = lookup(index, keyword)

                                            if len(_line_data) > 0:
                                                logger.debug(
                                                    f'Config Check - Found {keyword} match in {device.upper()} line {index}'
                                                )

                                                sorted_line_data = [
                                                    [key, value] for key, value in sorted(
                                                        _line_data.items(), key=lambda x: (x[0] if isinstance(x[0], int) else float("inf")),
                                                    )
                                                ]

                                                for x in range(0, len(sorted_line_data)):
                                                    rows_to_save[
                                                        sorted_line_data[x][0]
                                                    ] = f'{sorted_line_data[x][1]}'

                                                rows_to_save[index] = f'{current_config[index]}'

                    # Saving all gathered data to data_to_save array
                    if len(rows_to_save) > 0:
                        # Sorting by config line prior saving
                        search_network_stripped = search_network.strip()
                        rows = [
                            [search_network_stripped, device, key, value]
                            for key, value in sorted(
                                rows_to_save.items(),
                                key=lambda x: (
                                    x[0] if isinstance(x[0], int) else float("inf")
                                ),
                            )
                        ]
                        data_to_save.extend(rows)

    if len(data_to_save) == 0:
        logger.info(f'Configuration Repository - No {search_network} matches found!')
        console.print(f'Configuration Repository - No {search_network} matches found!')

        return

    sorted_data = sorted(data_to_save, key=itemgetter(1, 2))

    print_search_config_data(sorted_data)

    # Saving data automatically unless user requested not to (relies on global auto_save flag)
    if cfg["auto_save"]:
        columns = ["Search Address", "Device", "Line number", "Line"]

        append_df_to_excel(
            logger,
            cfg["report_filename"],
            columns,
            sorted_data,
            sheet_name="Config Check",
            index=False,
        )

    return


def append_df_to_excel(
    logger: logging.Logger,
    filename: str,
    columns: list,
    raw_data: list,
    sheet_name: str = "Sheet1",
    startrow: int = None,
    truncate_sheet: bool = False,
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

    df = prepare_df(columns, raw_data)

    # Excel file doesn't exist - saving and exiting
    if not os.path.isfile(filename):
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
        existing_data = pd.read_excel(filename, sheet_name=sheet_name)
    # If no sheet in the workbook we get ValueError exception
    except ValueError:
        existing_data = ""

    filled_rows = len(existing_data)

    if filled_rows != 0:
        logger.info(
            f'Export - Found {filename} report - Sheet {sheet_name} has {filled_rows} rows'
        )
        # New data will be placed right after last row
        startrow = filled_rows + 1
    else:
        logger.info(
            f'Export - Found {filename} report - No {sheet_name} sheet found, creating...'
        )
        startrow = 0

    writer = pd.ExcelWriter(
        filename, engine="openpyxl", if_sheet_exists="overlay", mode="a"
    )

    # if filled_rows = 0 then we need header, otherwise header is already in the sheet
    header = not bool(filled_rows)

    # write out the data to the sheet
    df.to_excel(
        writer,
        startrow=startrow,
        header=header,
        sheet_name=sheet_name,
        **to_excel_kwargs,
    )

    # close the workbook
    writer.close()

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
    fqdn = re.compile(r"^[a-z0-9][-a-z0-9]{0,61}[a-z0-9]?$", re.IGNORECASE)

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
            column, justify="left", style="spring_green3", no_wrap=True
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
    # Standard headers
    headers = {"Content-Type": "application/json"}

    logger.info(f'Performing API request - URL:{endpoint}{uri}')

    try:
        response = requests.get(f'{endpoint}{uri}', auth=auth, headers=headers, verify=False)
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
    with console.status(status=message, spinner=spinner):
        response = make_api_call(logger, endpoint, uri)

        if response.ok:
            return response.content

    return None


def process_data(logger: logging.Logger, type: int, content: str) -> dict:
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

    elif type == "location":
        processed_data = {"location": []}
        processed_data["location"] = [
            {"network": location.get('network'), "comment": location.get('comment')}
            for location in raw_data
            if location.get('network')
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
        "Request limits response to [red bold]1000[/red bold] records\n"
        "Use longer prefix(more specific) if getting error response[/yellow]\n\n"
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
    logger.info('Request Type - Search for registered to site subnet records')

    console.print(
        "\n"
        "[yellow]Type in location site code to obtain a list of registered [yellow bold]subnets[/yellow bold]\n"
        "Supported location format [green bold]XXX[/green bold] or [green bold]XXX-XX\\[X][/green bold]\n"
        "Request limits response to [red bold]1000[/red bold] records[/yellow]\n"
        "[magenta bold]Examples:[/magenta bold]\n"
        "[green]'CIC' fetches [yellow bold]subnets[/yellow bold] for Chinchilla location\n"
        "'WND-RYD' fetches [yellow bold]subnets[/yellow bold] for Wandoan office[/green]\n"
    )

    sitecode = read_user_input(logger, "Enter location code: ").lower()

    logger.info(f'User input - {sitecode}')

    if not is_valid_site(sitecode):
        logger.info(f'User input - Incorrect site code {sitecode}')
        console.print("[red]Incorrect site code[/red]")
        return

    uri = f'network?comment:~={sitecode}&_max_results=1000'
    processed_data = {}

    data = do_fancy_request(
        logger,
        message=f'Fetching data for [magenta]{sitecode.upper()}[/magenta]...',
        endpoint=cfg["api_endpoint"],
        uri=uri,
    )

    if data and len(data) > 0:
        # process_data if not empty has 'location' key with subnet data
        processed_data = process_data(logger, type="location", content=data)

    if len(processed_data) == 0:
        logger.info('Request Type - Location Information - No information received')
        console.print('[red]No information received[/red]')
        return

    print_table_data(
        logger,
        processed_data,
        prefix={"location": f'{sitecode.upper()}'},
        suffix={"location": "Subnets"},
    )
    logger.debug(
        f'Request Type- Location Information - processed data {processed_data}'
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
            sheet_name="Site Subnets",
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
    for label, uri in req_urls.items():
        message = f'Fetching [magenta]{label.upper()}[/magenta] information...'
        data = do_fancy_request(logger, message=message, endpoint=cfg["api_endpoint"], uri=uri)

        if data and len(data) > 0:
            processed_data.update(process_data(logger, type=label, content=data))
            if len(processed_data.get("general", '')) == 0:
                break
            logger.debug(f'Request Type - Subnet Information - processed data {processed_data}')
            continue

        if len(processed_data.get(label, '')) == 0:
            logger.info(
                f'Request Type - Subnet Information - No information received for {label.upper()}'
            )
            logger.debug(f'Request Type - Subnet Information - raw data {data}')
            continue

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


def main() -> None:
    """
    Main function that orchestrates the execution of the script.
    """

    menu = """
    [red bold]MENU[/red bold]
    [cyan]
    1. IP Information
    2. Subnet Information
    3. FQDN Lookup(A Record)
    4. Subnet Lookup based on Description(Location - SGP-PBU)
    5. Configuration Lookup (by subnet address)
    d. Delete report file
    [/cyan]
    [bold yellow]
    0. Exit
    [/bold yellow]
    """

    # default params if config is missing
    cfg = {
        "api_endpoint": "API_URL",
        "logfile_location": "cn.log",
        "log_level_str": "INFO",
        "report_filename": "report.xlsx",
        "auto_save": True,
        # Network devices confuration repository
        "config_storage": "/opt/data/configs/cisco/router",
        "config_regions": ["ap", "eu", "am"],
    }

    switch = {
        "1": ip_request,
        "2": subnet_request,
        "3": fqdn_request,
        "4": location_request,
        "5": search_config_line,
        "d": clear_report,
        "0": exit_now,
    }

    # Command-line argument parsing
    parser = argparse.ArgumentParser(description=f'Infoblox API Tool version {version}')
    parser.add_argument("-c", "--config", default='.cn', help='Path to configuration file')
    parser.add_argument("-l", "--log-file", default='cn.log', help='Path to log file')
    parser.add_argument("-r", "--report-file", default='report.xlsx', help='Report filename')
    args = parser.parse_args()

    # Read configuration
    cfg = read_config(cfg, args.config)

    # Configure logging
    cfg["log_level"] = logging.getLevelName(cfg["log_level_str"].upper())
    logger = configure_logging(cfg["logfile_location"], cfg["log_level"])

    # TODO add support for xls output format in parallel to console
    logger.info(
        f'Application Started - API: api_endpoint={cfg["api_endpoint"]} Configuration: {args.config}'
    )

    choice = "-1"

    # Setting CTRL-C intercept
    signal.signal(
        signal.SIGINT, lambda signum, frame: interrupt_handler(logger, signum, frame)
    )
    
    if cfg['api_endpoint'] == "API_URL":
        logger.error('API Error - Infoblox API endpoint URL is not set')
        console.print(
            '[red]Please set correct Infoblox API URL in configuration file[/red]'
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
    dummy_logger = logging.Logger("dummy", logging.INFO)

    # Read login credentials
    username = os.getenv("USER")
    password = os.getenv("TACACS_PW")

    while password is None or password == "":
        console.clear()
        password = read_user_input(
            dummy_logger,
            '[yellow bold]Please provide security credential:[/yellow bold]',
            True,
        )

    # Auth tuple
    auth = (username, password)
    main()
else:
    console.print('Cannot be used as a module')
    exit(0)
