"""
This module contains dedicated parser functions for processing different types of raw data
returned from the API. Each function is responsible for transforming a specific JSON
structure into a standardized dictionary format for use in the main application.
"""

from collections import defaultdict
import json
from typing import Dict, List, Any, Optional

from core.base import ScriptContext
from utils.dhcp_options import decode_dhcp_option_value
from utils.infoblox_safety import infoblox_debug_payloads_enabled


def _is_inherited_entry(meta: Dict[str, Any], row: Dict[str, Any]) -> bool:
    return bool(meta.get("inherited") or meta.get("multisource") or row.get("inheritance_source"))


def _ensure_column_present(rows: List[Dict[str, Any]], column: str) -> List[Dict[str, Any]]:
    if any(row.get(column) for row in rows):
        for row in rows:
            row.setdefault(column, "")
    return rows


def _dedupe_dhcp_option_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped_rows: List[Dict[str, Any]] = []
    row_index_by_key: Dict[tuple[str, str, str, str, str], int] = {}

    for row in rows:
        key = (
            str(row.get("name", "")),
            str(row.get("num", "")),
            str(row.get("value", "")),
            str(row.get("vendor class", "")),
            str(row.get("use option", "")),
        )
        existing_index = row_index_by_key.get(key)
        if existing_index is None:
            deduped_rows.append(dict(row))
            row_index_by_key[key] = len(deduped_rows) - 1
            continue

        if row.get("inherited"):
            deduped_rows[existing_index]["inherited"] = "Yes"
        if row.get("decoded value") and not deduped_rows[existing_index].get("decoded value"):
            deduped_rows[existing_index]["decoded value"] = row["decoded value"]

    return deduped_rows


def _build_dhcp_option_row(option: Dict[str, Any], inherited: bool) -> Dict[str, Any]:
    row = {
        "name": option.get("name", ""),
        "num": str(option.get("num", "")),
        "value": option.get("value", ""),
        "vendor class": option.get("vendor_class", ""),
        "use option": str(option.get("use_option", "")),
    }
    decoded_value = decode_dhcp_option_value(option.get("num", ""), option.get("value", ""))
    if decoded_value:
        row["decoded value"] = decoded_value
    if inherited:
        row["inherited"] = "Yes"
    return row


def _normalize_dhcp_option_row_order(row: Dict[str, Any]) -> Dict[str, Any]:
    ordered_keys = (
        "name",
        "num",
        "value",
        "vendor class",
        "use option",
        "inherited",
        "decoded value",
    )
    normalized = {key: row.get(key, "") for key in ordered_keys}
    for key, value in row.items():
        if key not in normalized:
            normalized[key] = value
    return normalized


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
    inheritance = data.get("_inheritance", {})
    comment_meta = inheritance.get("comment", {})
    extattrs_meta = inheritance.get("extattrs", {})

    general_row = {"subnet": data.get("network", ""), "description": data.get("comment", "")}
    if comment_meta.get("inherited") or comment_meta.get("multisource"):
        general_row["inherited"] = "Description"
    processed_data["general"] = [general_row]

    extattrs_rows = [
        {
            "Attribute": key,
            "Value": record.get("value", ""),
            **({"inherited": "Yes"} if _is_inherited_entry(extattrs_meta.get(key, {}), record) else {}),
        }
        for key, record in data.get("extattrs", {}).items()
    ]
    processed_data["Extensible Attributes"] = _ensure_column_present(extattrs_rows, "inherited")
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
    inheritance = data.get("_inheritance", {})
    member_meta = inheritance.get("members", [])
    option_meta = inheritance.get("options", [])
    if "members" in data:
        member_rows = [
            {
                "IP Address": mem.get("ipv4addr", ""),
                "name": mem.get("name", ""),
                **({"inherited": "Yes"} if _is_inherited_entry(member_meta[idx] if idx < len(member_meta) else {}, mem) else {}),
            }
            for idx, mem in enumerate(data.get("members", []))
        ]
        processed_data["DHCP members"] = _ensure_column_present(member_rows, "inherited")
    if "options" in data:
        option_rows = [
            _build_dhcp_option_row(
                opt,
                _is_inherited_entry(option_meta[idx] if idx < len(option_meta) else {}, opt),
            )
            for idx, opt in enumerate(data.get("options", []))
        ]
        option_rows = _dedupe_dhcp_option_rows(option_rows)
        option_rows = _ensure_column_present(option_rows, "decoded value")
        option_rows = _ensure_column_present(option_rows, "inherited")
        processed_data["DHCP options"] = [_normalize_dhcp_option_row_order(row) for row in option_rows]
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


def process_data(
    ctx: ScriptContext,
    type: str,
    content: Optional[bytes] = None,
) -> Dict[str, Any]:
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
    payload_size = len(content or b"")
    logger.debug(f"Processing data {type.upper()} payload size: {payload_size} bytes")
    if infoblox_debug_payloads_enabled(ctx):
        logger.debug(f"Processing data {type.upper()} content: {content}")

    if not content:
        return defaultdict(list)

    try:
        raw_data = json.loads(content)
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
