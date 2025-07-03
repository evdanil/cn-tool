"""
This module contains dedicated parser functions for processing different types of raw data
returned from the API. Each function is responsible for transforming a specific JSON
structure into a standardized dictionary format for use in the main application.
"""

from collections import defaultdict
import json
from typing import Dict, List, Any, Optional

from core.base import ScriptContext


def _parse_ip_data(raw_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Parses data for the 'ip' type."""
    processed_data = defaultdict(list)
    if not raw_data:
        return processed_data

    data = raw_data[0]
    processed_data["general"].append({
        "network": data.get("network", ""),
        "ip": str(data.get("_ref", "")).split(":")[-1],
        "name": ",".join(data.get("names", [])),
        "status": data.get("status", ""),
    })

    extra_info = {
        "lease state": data.get("lease_state", ""),
        "record type": ",".join(data.get("types", [])),
        "mac": data.get("mac_address", ""),
    }
    if any(extra_info.values()):
        processed_data["extra"].append(extra_info)

    return processed_data


def _parse_supernet_data(raw_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Parses data for the 'supernet' type."""
    processed_data = defaultdict(list)
    processed_data["subnets"] = [
        {"network": net["network"]} for net in raw_data if "network" in net
    ]
    return processed_data


def _parse_location_data(raw_data: List[Dict[str, Any]], sitecode: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """
    Parses location data. If a sitecode is provided, it filters results
    to match the sitecode in the comment field. Otherwise, it returns all locations.
    """
    processed_data = defaultdict(list)
    all_locations = [
        {"network": loc["network"], "comment": loc.get("comment", "")}
        for loc in raw_data if "network" in loc
    ]

    if sitecode:
        # Filter by the provided sitecode
        processed_data["location"] = [
            loc for loc in all_locations
            if len(loc.get("comment", "").split(";")) > 1
            and loc["comment"].split(";")[1].strip().lower() == sitecode
        ]
    else:
        # No sitecode, so it's a keyword search. Return all valid locations.
        processed_data["location"] = all_locations

    return processed_data


def _parse_fqdn_data(raw_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Parses data for the 'fqdn' type."""
    processed_data = defaultdict(list)
    processed_data["fqdn"] = [
        {"ip": fqdn.get("ipv4addr") or fqdn.get("ipv6addr", ""), "name": fqdn.get("name", "")}
        for fqdn in raw_data if fqdn.get("ipv4addr") or fqdn.get("ipv6addr")
    ]
    return processed_data


def _parse_general_subnet_data(raw_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Parses data for the 'general' subnet information type."""
    processed_data = defaultdict(list)
    if not raw_data:
        return processed_data

    data = raw_data[0]
    processed_data["general"] = [{"subnet": data.get("network", ""), "description": data.get("comment", "")}]
    processed_data["Extensible Attributes"] = [
        {"Attribute": key, "Value": record.get("value", "")}
        for key, record in data.get("extattrs", {}).items()
    ]
    return processed_data


def _parse_dns_records_data(raw_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Parses data for the 'DNS records' type."""
    processed_data = defaultdict(list)
    processed_data["DNS records"] = [
        {"IP address": rec.get("ip_address", ""), "A Record": ", ".join(rec.get("names", []))}
        for rec in raw_data
    ]
    return processed_data


def _parse_network_options_data(raw_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Parses data for the 'network options' type."""
    processed_data = defaultdict(list)
    if not raw_data:
        return processed_data

    data = raw_data[0]
    if "members" in data:
        processed_data["DHCP members"] = [
            {"IP Address": mem.get("ipv4addr", ""), "name": mem.get("name", "")}
            for mem in data.get("members", [])
        ]
    if "options" in data:
        processed_data["DHCP options"] = [
            {
                "name": opt.get("name", ""), "num": str(opt.get("num", "")),
                "value": opt.get("value", ""), "vendor class": opt.get("vendor_class", ""),
                "use option": str(opt.get("use_option", "")),
            } for opt in data.get("options", [])
        ]
    return processed_data


def _parse_dhcp_range_data(raw_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Parses data for the 'DHCP range' type."""
    processed_data = defaultdict(list)
    processed_data["DHCP range"] = [
        {"network": r.get("network", ""), "start address": r.get("start_addr", ""), "end address": r.get("end_addr", "")}
        for r in raw_data
    ]
    return processed_data


def _parse_dhcp_failover_data(raw_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Parses data for the 'DHCP failover' type."""
    processed_data = defaultdict(list)
    processed_data["DHCP failover"] = [
        {"dhcp failover": failover.get("failover_association", "")}
        for failover in raw_data
    ]
    return processed_data


def _parse_fixed_addresses_data(raw_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Parses data for the 'fixed addresses' type."""
    processed_data = defaultdict(list)
    processed_data["fixed addresses"] = [
        {"IP address": addr.get("ipv4addr", ""), "name": addr.get("name", ""), "MAC": addr.get("mac", "")}
        for addr in raw_data
    ]
    return processed_data


def process_data(ctx: ScriptContext, type: str, content: Optional[bytes]) -> Dict[str, Any]:
    """
    Process raw API data by dispatching to the appropriate parser based on the 'type'.

    This function acts as a controller: it handles common tasks like JSON decoding and
    error handling, then uses a registry (`DATA_PARSERS`) to call the specific
    function responsible for parsing the data structure.

    @param ctx: The script's context object.
    @param type: A string key indicating the data type (e.g., 'ip', 'fqdn').
    @param content: The raw JSON bytes from the API response.

    @return: A dictionary containing the processed data, or an empty defaultdict
             if processing fails or yields no data.
    """
    logger = ctx.logger
    logger.info(f"Processing data - {type.upper()}")
    logger.debug(f"Processing data {type.upper()} content: {content}")

    if not content:
        return defaultdict(list)

    try:
        raw_data: Any = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON response for type '{type}': {e}")
        # It's better to return empty data than to crash the entire application
        return defaultdict(list)

    if not raw_data:
        return defaultdict(list)

    # --- Special Handlers for Dynamic Types ---
    # The 'location' types are dynamic and handled separately from the registry.
    if type.startswith("location_"):
        if type == "location_keyword":
            # This is a keyword search, so no sitecode filtering is needed.
            return _parse_location_data(raw_data)
        else:
            # This is a sitecode search, so extract the sitecode and pass it for filtering.
            sitecode = type.split("_", 1)[1].lower()
            return _parse_location_data(raw_data, sitecode)

    # --- Dispatch to registered parsers ---
    parser_func = DATA_PARSERS.get(type)

    if parser_func:
        return parser_func(raw_data)
    else:
        logger.warning(f"No parser implemented for data type '{type}'.")
        return defaultdict(list)


def remove_duplicate_rows_sorted_by_col(data: List[List[Any]], col: int) -> List[List[Any]]:
    """
    Removes duplicate rows from a list of lists, preserving order,
    and sorts the result by a specified column index.
    """
    seen = set()
    result = []
    for sublist in data:
        sublist_tuple = tuple(sublist)
        if sublist_tuple not in seen:
            seen.add(sublist_tuple)
            result.append(sublist)
    result.sort(key=lambda x: x[col])
    return result


# This dictionary acts as a registry to dispatch to the correct parser.
DATA_PARSERS = {
    "ip": _parse_ip_data,
    "supernet": _parse_supernet_data,
    "fqdn": _parse_fqdn_data,
    "general": _parse_general_subnet_data,
    "DNS records": _parse_dns_records_data,
    "network options": _parse_network_options_data,
    "DHCP range": _parse_dhcp_range_data,
    "DHCP failover": _parse_dhcp_failover_data,
    "fixed addresses": _parse_fixed_addresses_data,
}
