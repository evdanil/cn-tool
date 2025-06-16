from socket import gethostbyaddr
from typing import Callable, Optional, List, Dict, Any, Set, Tuple
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
    base_info: Dict[str, Any] = {
        'Device Name': device_name,
        'Software Version': data.get('show_version', {}).get('Software Version', ''),
        'Software Image': data.get('show_version', {}).get('Software Image', ''),
        'Uptime': data.get('show_version', {}).get('Uptime', ''),
        'Serial Number': data.get('show_version', {}).get('Serial Number', ''),
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

    return rows


def process_device_commands(logger: logging.Logger, device: str, cmd_list: Dict[str, Tuple[Callable[[str], Any], Any]], username: Optional[str], password: Optional[str], type: str = 'cisco_ios') -> Dict[str, Any]:
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
        conn = ConnLogOnly(**dev)
        if not conn:
            logger.info(f'{device} - Unable to create device connection!')
            return {device: 'Unable to create device connection'}

        guesser = SSHDetect(**dev)
        detected_type = guesser.autodetect()
        if detected_type:
            dev["device_type"] = detected_type
        else:
            logger.info(f'{device} - Unable to autodetect device type!')
            return {device: 'Unable to autodetect device type'}

        if "cisco" not in dev["device_type"]:
            logger.info(f'{device} - Not supported device type!')
            return {device: 'Not supported device type'}

        for cmd_key, funcs in cmd_list.items():
            command_output = conn.send_command(f"{cmd_key.replace('_', ' ')}\n", auto_find_prompt=True)
            if isinstance(command_output, str):
                output[cmd_key] = funcs[0](command_output)
            else:
                logger.warning(f"Command '{cmd_key}' on {device} did not return a string.")
                output[cmd_key] = {}

    except Exception as e:
        logger.info(f'{device} - Unable to connect or execute command! Error: {e}')
        return {device: f'Connection/Command error: {e}'}
    finally:
        if conn:
            conn.disconnect()

    return output
