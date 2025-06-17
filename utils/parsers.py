from socket import gethostbyaddr
from typing import Optional, List, Dict, Any, Set, Tuple
from netmiko import ConnLogOnly, SSHDetect, BaseConnection
import logging
import re


def parse_show_version(output: str) -> Dict[str, Any]:
    # This function parses 'show version' output

    result: Dict[str, Any] = {
        "Software Version": "",
        "Software Image": "",
        "Part Number": "",
        "Uptime": "",
        "Serial Number": "",
        "Switches": []
    }

    # Extract Software Version
    version_match = re.search(r'(Version|Cisco IOS XE Software, Version)\s+([\d.()]+[A-Z]?\d*)', output)
    if version_match:
        result["Software Version"] = version_match.group(2)

    # Extract Software Image
    image_match = re.search(r'System image file is\s+"(.+)"', output)
    if image_match:
        result["Software Image"] = image_match.group(1)

    # Extract Uptime
    uptime_match = re.search(r'(\S+)?\s*uptime is (.+?)(?=\n)', output)
    if uptime_match:
        result["Uptime"] = f"{uptime_match.group(2)}"

    # Extract Serial Number
    serial_match = re.search(r'(Processor board ID|System Serial Number\s+:)\s*(\S+)', output)
    if serial_match:
        result["Serial Number"] = serial_match.group(2)

    return result


def parse_show_license_reservation(output: str) -> Dict[str, Dict[str, Any]]:
    # This function parses 'show license reservation' output

    result: Dict[str, Dict[str, Any]] = {}

    # Extract License Reservation status
    license_reservation_match = re.search(r'License reservation: (\S+)', output)
    license_reservation = license_reservation_match.group(1) if license_reservation_match else 'UNKNOWN'

    sections = output.split('Specified license reservations:')
    overall_status = sections[0].strip()
    license_info_str = sections[1].strip() if len(sections) > 1 else ''

    # Parse overall status
    for block in re.split(r'\n\s+(?=(?:Active|Standby|Member))', overall_status):
        match = re.match(r'\s*(Active|Standby|Member): PID:([^,]+),SN:(\S+)', block)
        if match:
            device_type, pid, sn = match.groups()
            device_info: Dict[str, Any] = {
                'TYPE': device_type,
                'PID': pid,
                'SN': sn,
                'LICENSE_RESERVATION': license_reservation,
                'LICENSES': []
            }
            for line in block.split('\n')[1:]:
                if 'Status:' in line or 'Reservation status:' in line:
                    status_match = re.search(r'(?:Reservation )?[Ss]tatus: (.+?)(?: on (.+))?$', line)
                    if status_match:
                        device_info['RESERVATION_STATUS'] = status_match.group(1)
                        device_info['RESERVATION_DATE'] = status_match.group(2) if status_match.group(2) else ''
                elif 'Export-Controlled Functionality:' in line:
                    device_info['EXPORT_CONTROLLED'] = line.split(':')[1].strip()
                elif 'Last Confirmation code:' in line:
                    device_info['CONFIRMATION_CODE'] = line.split(':')[1].strip()
            result[sn] = device_info

    # Parse license info
    license_blocks = re.split(r'\n\s+(?=\S+\s+\()', license_info_str)
    for block in license_blocks:
        license_match = re.search(r'(\S+.*?) \((.*?)\):\s+Description: (.+?)\s+Total reserved count: (\d+)', block, re.DOTALL)
        if license_match:
            license_name, license_full_name, description, total_reserved = license_match.groups()
            enforcement_type_match = re.search(r'Enforcement type: (.+)', block)
            enforcement_type = enforcement_type_match.group(1) if enforcement_type_match else ''

            for device_block in re.findall(r'((?:Active|Standby|Member): PID:[^,]+,SN:\S+\s+(?:Authorization type:[^\n]+\s+)?License type:[^\n]+(?:\s+Start Date:[^\n]+\s+End Date:[^\n]+)?\s+Term Count: \d+)', block):
                device_match = re.search(r'(?:Active|Standby|Member): PID:[^,]+,SN:(\S+)', device_block)
                if device_match:
                    sn = device_match.group(1)
                    if sn in result:
                        license_info_dict: Dict[str, Any] = {
                            'LICENSE_NAME': license_name,
                            'LICENSE_FULL_NAME': license_full_name,
                            'LICENSE_DESCRIPTION': description,
                            'TOTAL_RESERVED': total_reserved,
                            'ENFORCEMENT_TYPE': enforcement_type
                        }
                        auth_type_match = re.search(r'Authorization type: (.+)', device_block)
                        license_info_dict['AUTHORIZATION_TYPE'] = auth_type_match.group(1) if auth_type_match else ''

                        license_type_match = re.search(r'License type: (\S+)', device_block)
                        license_info_dict['LICENSE_TYPE'] = license_type_match.group(1) if license_type_match else ''

                        start_date_match = re.search(r'Start Date: (.+)', device_block)
                        license_info_dict['START_DATE'] = start_date_match.group(1) if start_date_match else ''

                        end_date_match = re.search(r'End Date: (.+)', device_block)
                        license_info_dict['END_DATE'] = end_date_match.group(1) if end_date_match else ''

                        term_count_match = re.search(r'Term Count: (\d+)', device_block)
                        license_info_dict['TERM_COUNT'] = term_count_match.group(1) if term_count_match else ''

                        result[sn]['LICENSES'].append(license_info_dict)
    return result


def parse_show_license_summary(output: str) -> List[Dict[str, str]]:
    # This function parses 'show license summary' output

    licenses: List[Dict[str, str]] = []
    lines = output.strip().split('\n')
    if not lines or 'Index' in lines[0]:
        # This is not expected for show license summary on modern devices, however it happens on 4500-x platform
        # call parse_show_license as the output matches it
        return parse_show_license(output)

    # Skip header lines
    for line in lines[3:]:
        match = re.match(r'^\s*(\S+)\s+\(([^)]+)\)\s+(\d+)\s+(.+)$', line)
        if match:
            license_dict = {
                'License': match.group(1),
                'Entitlement Tag': match.group(2),
                'Count': match.group(3),
                'Status': match.group(4).strip()
            }
            licenses.append(license_dict)

    return licenses


def parse_show_license(output: str) -> List[Dict[str, str]]:
    # This function parses 'show license' output
    features: List[Dict[str, str]] = []
    current_feature: Optional[Dict[str, str]] = None

    for line in output.strip().split('\n'):
        index_match = re.match(r'Index (\d+)\s+Feature: (.+)', line)
        if index_match:
            if current_feature:
                features.append(current_feature)
            current_feature = {
                'Index': index_match.group(1),
                'Feature': index_match.group(2).strip()
            }
        elif current_feature:
            key_value_match = re.match(r'\s+([^:]+?):\s*(.+)', line)
            if key_value_match:
                key = key_value_match.group(1).strip()
                value = key_value_match.group(2).strip()
                current_feature[key] = value

    if current_feature:
        features.append(current_feature)

    return features


def prepare_device_data(processed_data: List[Dict[str, Any]]) -> Tuple[List[str], List[List[Any]]]:
    """
    This function prepares a flat list of dictionaries for saving to an Excel table.
    It merges rows based on a composite key and ensures all rows have all columns.

    Args:
        processed_data: A flat list of dictionaries, where each dict represents a potential row.
    """
    if not processed_data:
        return [], []

    all_columns: Set[str] = set()
    devices: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    def merge_device_info(info1: Dict[str, Any], info2: Dict[str, Any]) -> Dict[str, Any]:
        merged = info1.copy()
        for key, value in info2.items():
            if not merged.get(key) and value:
                merged[key] = value
        return merged

    # --- THIS IS THE CORRECTED LOGIC ---
    # The input is now a flat list, so we only need one loop.
    for row in processed_data:
        # This check is crucial for safety
        if not isinstance(row, dict):
            # Log a warning or skip if an invalid item is found
            continue

        all_columns.update(row.keys())
        device_key = (row.get('Device Name', ''), row.get('Serial Number', ''), row.get('License Name', ''))

        if device_key not in devices:
            devices[device_key] = row.copy()
        else:
            devices[device_key] = merge_device_info(devices[device_key], row)
    # --- END OF CORRECTION ---

    # Create final rows from the merged devices
    rows = list(devices.values())

    # Define priority columns (this logic is correct)
    priority_columns = [
        'Device Name', 'Serial Number', 'Product ID (PID)', 'Parent Device Name',
        'Stack Role', 'Software Version', 'Software Image', 'License Name',
        'License Type', 'Confirmation Code', 'License Count', 'License Entitlement Tag',
        'License Period Left', 'License Priority', 'License Reservation Status',
        'License State', 'License Status', 'Uptime'
    ]

    # Sort columns (this logic is correct)
    other_columns = sorted(col for col in all_columns if col not in priority_columns)
    final_columns = priority_columns + other_columns

    # Ensure all rows have all columns (this logic is correct)
    for row in rows:
        for col in final_columns:
            row.setdefault(col, '')  # setdefault is slightly cleaner than if/not in

    # Convert rows to list of lists (this logic is correct)
    row_data = [[row.get(col, '') for col in final_columns] for row in rows]

    return final_columns, row_data


def process_device_data(device_name: str, data: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Function processes responses from a set of prepared dictionaries with different command results and returns a list
    # of dictionaries with merged data
    rows: List[Dict[str, Any]] = []
    platform = data.get('platform', 'iosxe')

    version_output = data.get('show version', {})  # Both platforms use this key
    base_info: Dict[str, Any] = {
        'Device Name': device_name,
        'Software Version': version_output.get('show_version', {}).get('Software Version', ''),
        'Software Image': version_output.get('show_version', {}).get('Software Image', ''),
        'Uptime': version_output.get('show_version', {}).get('Uptime', ''),
        'Serial Number': version_output.get('show_version', {}).get('Serial Number', ''),
        'Product ID (PID)': '',
        'Stack Role': 'N/A',
        'Parent Device Name': None,
        'License Name': '',
        'License Type': '',
        'Confirmation Code': '',
        'License Count': '',
        'License Entitlement Tag': '',
        'License Period Left': '',
        'License Priority': '',
        'License Reservation Status': '',
        'License State': '',
        'License Status': '',
    }

    if platform == 'iosxe':
        # --- Handle IOS/XE data (existing logic) ---
        # Process license reservation data
        reservation_data = data.get('show_license_reservation', {})
        for sn, info in reservation_data.items():
            row = base_info.copy()
            row['Serial Number'] = sn
            row['Product ID (PID)'] = info.get('PID', '')
            row['Stack Role'] = info.get('TYPE', 'N/A')
            row['License Reservation Status'] = info.get('LICENSE_RESERVATION', '')
            row['Confirmation Code'] = info.get('CONFIRMATION_CODE', '')

            if row['Stack Role'] in ('Standby', 'Member'):
                row['Parent Device Name'] = device_name

            for license_item in info.get('LICENSES', []):
                license_row = row.copy()
                license_timeframe = f"{license_item.get('START_DATE', '')} to {license_item.get('END_DATE', '')}"
                if license_timeframe == " to ":
                    license_timeframe = ""
                license_row.update({
                    'License Name': license_item.get('LICENSE_NAME', ''),
                    'License Type': license_item.get('LICENSE_TYPE', ''),
                    'License Period Left': license_timeframe,
                })
                rows.append(license_row)

            if not info.get('LICENSES'):
                rows.append(row)

        # Process license summary data
        for license_item in data.get('show_license_summary', []):
            row = base_info.copy()
            row.update({
                'License Name': license_item.get('License', ''),
                'License Entitlement Tag': license_item.get('Entitlement Tag', ''),
                'License Count': license_item.get('Count', ''),
                'License Status': license_item.get('Status', ''),
            })
            rows.append(row)

        # Process detailed license data
        for license_item in data.get('show_license', []):
            row = base_info.copy()
            row.update({
                'License Name': license_item.get('Feature', ''),
                'License Type': license_item.get('License Type', ''),
                'License State': license_item.get('License State', ''),
                'License Period Left': license_item.get('Period left', ''),
                'License Priority': license_item.get('License Priority', ''),
                'License Count': license_item.get('License Count', ''),
            })
            rows.append(row)

        # If no license data was found, add at least one row with base info
        if not rows:
            rows.append(base_info)

    elif platform == 'nxos':
        # --- Handle NX-OS data ---
        # The 'show license all' command gives us what we need
        license_data = data.get('show license all', [])
        for license_item in license_data:
            row = base_info.copy()
            row.update({
                'License Name': license_item.get('License Name', ''),
                # We need to decide what to map 'License Status' to.
                # 'License State' or 'License Status' are good candidates. Let's use 'License Status'.
                'License Status': license_item.get('License Status', ''),
                'License Count': license_item.get('License Count', ''),
                'License Type': license_item.get('License Type', 'N/A'),
                'Description': license_item.get('Description', ''),  # Add this useful field
            })
            rows.append(row)

    # If no specific data was found for the platform, add a base row
    if not rows:
        rows.append(base_info)

    return rows


def process_device_commands(logger: logging.Logger, device: str, platform_commands: Dict[str, Dict[str, Tuple]], username: Optional[str], password: Optional[str], type: str = 'cisco_ios') -> Dict[str, Any]:
    # interrogate device and get serial/mac/license data
    # check for reverse DNS entry

    dns_name: Optional[str] = None
    try:
        dns_name = gethostbyaddr(device)[0]
    except Exception:
        pass
    if dns_name and not re.search(r'(es|mp|vi|bl|sp|lf)\d{3}', dns_name):
        logger.info(f'{device} - Not supported device type!')
        return {device: 'Not supported device type'}

    output: Dict[str, Any] = {}

    dev: Dict[str, Any] = {
        "device_type": "autodetect",
        "host": device,
        "username": username,
        "password": password,
        "secret": ''
        }

    conn: Optional[BaseConnection] = None
    try:
        # We don't connect right away, we detect first.
        guesser = SSHDetect(**dev)
        detected_type = guesser.autodetect()

        if not detected_type:
            logger.info(f'{device} - Unable to autodetect device type!')
            return {device: 'Unable to autodetect device type'}

        # Determine platform family (e.g., 'iosxe' or 'nxos')
        platform_family = 'unknown'
        if 'nxos' in detected_type:
            platform_family = 'nxos'
        elif 'cisco' in detected_type:  # Catches 'cisco_ios', 'cisco_xe'
            platform_family = 'iosxe'

        if platform_family == 'unknown':
            logger.info(f'{device} - Not a supported platform family: {detected_type}')
            return {device: 'Not supported platform family'}

        # Add the detected device_type for the actual connection
        dev["device_type"] = detected_type
        conn = ConnLogOnly(**dev)
        if not conn:
            logger.info(f'{device} - Unable to create device connection!')
            return {device: 'Unable to create device connection'}

        # Get the correct command list for the detected platform
        cmd_list_for_platform = platform_commands.get(platform_family, {})
        if not cmd_list_for_platform:
            logger.warning(f"{device} - No commands defined for platform '{platform_family}'")
            return {device: f"No commands for platform '{platform_family}'"}

        # Store the platform in the output for later use
        output['platform'] = platform_family

        # Execute the commands for this platform
        for command, funcs in cmd_list_for_platform.items():
            command_output = conn.send_command(f"{command}\n", auto_find_prompt=True)
            parser_func = funcs[0]
            if isinstance(command_output, str):
                output[command] = parser_func(command_output)  # Use the correct parser
            else:
                logger.warning(f"Command '{command}' on {device} did not return a string.")
                output[command] = {}

    except Exception as e:
        logger.info(f'{device} - Unable to connect or execute command! Error: {e}')
        return {device: f'Connection/Command error: {e}'}
    finally:
        if conn:
            conn.disconnect()

    return output


def parse_nexus_show_version(output: str) -> Dict[str, Any]:
    """
    Parses 'show version' output specifically for Cisco Nexus (NX-OS) devices,
    updated for modern NX-OS output.
    """
    result: Dict[str, Any] = {
        "Software Version": "N/A",
        "Software Image": "N/A",
        "Uptime": "N/A",
        "Serial Number": "N/A",
    }

    # NX-OS Software Version (more specific regex)
    # Example: NXOS: version 10.2(7) [Maintenance Release]
    version_match = re.search(r'NXOS: version\s+([\d.()]+)', output)
    if version_match:
        result["Software Version"] = version_match.group(1)

    # NX-OS System Image
    # Example: NXOS image file is: bootflash:///nxos64-cs.10.2.7.M.bin
    image_match = re.search(r'NXOS image file is:\s+(.+)', output)
    if image_match:
        result["Software Image"] = image_match.group(1).strip()

    # NX-OS Uptime
    # Example: Kernel uptime is 257 day(s), 17 hour(s), 29 minute(s), 47 second(s)
    uptime_match = re.search(r'Kernel uptime is\s+(.+)', output)
    if uptime_match:
        result["Uptime"] = uptime_match.group(1).strip()

    # NX-OS Serial Number (Processor Board ID is more reliable for chassis)
    # Example: Processor Board ID FDO272612ZJ
    serial_match = re.search(r'Processor Board ID\s+(\S+)', output)
    if serial_match:
        result["Serial Number"] = serial_match.group(1)

    return result


def parse_nexus_show_license_all(output: str) -> List[Dict[str, str]]:
    """
    Parses 'show license all' output for modern Smart Licensing on NX-OS.
    Extracts license usage details.
    """
    licenses: List[Dict[str, str]] = []

    # The relevant data is in the "License Usage" section.
    # We first isolate this block of text.
    usage_section_match = re.search(r'License Usage\n=+\n(.+?)\n\nProduct Information', output, re.DOTALL)
    if not usage_section_match:
        return []  # No usage section found

    usage_text = usage_section_match.group(1)

    # Split the section into blocks for each license. A license block starts with a name in parentheses.
    license_blocks = re.split(r'\n\((.+?)\):', usage_text)

    # The split results in [garbage, license_name1, license_details1, license_name2, license_details2, ...]
    # We iterate over pairs.
    for i in range(1, len(license_blocks), 2):
        license_name = license_blocks[i]
        license_details = license_blocks[i+1]

        license_dict = {'License Name': license_name}

        # Now parse the details within the block
        desc_match = re.search(r'Description:\s*(.+)', license_details)
        if desc_match:
            license_dict['Description'] = desc_match.group(1).strip()

        count_match = re.search(r'Count:\s*(\d+)', license_details)
        if count_match:
            license_dict['License Count'] = count_match.group(1)

        status_match = re.search(r'Status:\s*(.+)', license_details)
        if status_match:
            license_dict['License Status'] = status_match.group(1).strip()

        type_match = re.search(r'License Type:\s*(.+)', license_details)
        if type_match:
            license_dict['License Type'] = type_match.group(1).strip()

        licenses.append(license_dict)

    return licenses
