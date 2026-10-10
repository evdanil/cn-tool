"""
This module contains dedicated parser functions for processing different types of raw data
returned from the API. Each function is responsible for transforming a specific JSON
structure into a standardized dictionary format for use in the main application.
"""

from collections import defaultdict
import json
import re
from typing import Dict, List, Any, Optional, Union

from cn_tool.core.base import ScriptContext
from cn_tool.utils.dhcp_options import decode_dhcp_option_value
from cn_tool.utils.infoblox_safety import infoblox_debug_payloads_enabled
from cn_tool.utils.network_views import DNS_VIEW, NETWORK_VIEW
from cn_tool.utils.validation import site_comment_regex


#: WAPI documents ``dhcp_utilization`` as the percentage "multiplied by 1000": per-mille, so 975 is 97.5 %.
DHCP_UTILIZATION_SCALE = 10
#: ``networkcontainer.utilization`` is shown as returned until the grid check says otherwise.
CONTAINER_UTILIZATION_SCALE = 1


def utilization_percent(raw: Any, scale: int) -> Union[float, str]:
    """A WAPI utilisation figure as a percentage with one decimal; ``""`` when it is absent or unreadable."""
    try:
        return round(float(raw) / scale, 1)
    except (TypeError, ValueError):
        return ""


def dhcp_percent(raw: Any) -> Union[float, str]:
    """A ``dhcp_utilization`` value (per-mille) as a percentage; ``""`` when the field is absent."""
    return utilization_percent(raw, DHCP_UTILIZATION_SCALE)


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


def _build_dhcp_option_row(option: Dict[str, Any], inherited: bool, *, decode: bool = True) -> Dict[str, Any]:
    """One DHCP option row. ``decode=False`` shows the option as returned: ``decode_dhcp_option_value``
    reads the DHCPv4 options 43 and 120, and DHCPv6 option codes mean something else."""
    row = {
        "name": option.get("name", ""),
        "num": str(option.get("num", "")),
        "value": option.get("value", ""),
        "vendor class": option.get("vendor_class", ""),
        "use option": str(option.get("use_option", "")),
    }
    decoded_value = decode_dhcp_option_value(option.get("num", ""), option.get("value", "")) if decode else ""
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


def _view_label(item: Dict[str, Any]) -> Dict[str, str]:
    """``{"network view": view}`` when the item carries the field, else ``{}``: no label, no change."""
    return {NETWORK_VIEW: str(item["network_view"] or "")} if "network_view" in item else {}


def _parse_ip_data(raw_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Parses data for the 'ip' type: the first item only, as each address in each network view is
    parsed on its own. The general row names the network view when the item has the field.
    """
    processed_data = defaultdict(list)
    if not raw_data:
        return processed_data

    data = raw_data[0]
    # The ref ends in "<address>/<network view>" after the object id (which has no colon); only
    # the address is the IP, and the view is never read from it (the ``network_view`` field is).
    # An IPv6 address holds colons itself, so the ref is split at the first one only.
    ref_address = str(data.get("_ref", "")).split(":", 1)[-1].split("/")[0]
    processed_data["general"].append({
        "network": data.get("network", ""),
        "ip": data.get("ip_address") or ref_address,
        "name": ",".join(data.get("names", [])),
        "status": data.get("status", ""),
        **_view_label(data),
    })

    extra_info = {
        "lease state": data.get("lease_state", ""),
        "record type": ",".join(data.get("types", [])),
        "mac": data.get("mac_address", ""),
    }
    if "duid" in data:  # ipv6address only; an IPv4 item has no DUID and no key
        extra_info["duid"] = data["duid"] or ""
    if any(extra_info.values()):
        processed_data["extra"].append(extra_info)

    return processed_data


def _parse_supernet_data(raw_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Parses data for the 'supernet' type; a row names its network view when the item has the field."""
    processed_data = defaultdict(list)
    processed_data["subnets"] = [
        {"network": net["network"], **_view_label(net)} for net in raw_data if "network" in net
    ]
    return processed_data


def _parse_location_data(
    raw_data: List[Dict[str, Any]],
    sitecode: Optional[str] = None,
    comment_pattern: Optional[str] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Parses location data. If a sitecode is provided, it keeps only the subnets whose
    comment matches the site (``[site] comment_pattern``, default: the code as a whole
    word anywhere in the comment). Otherwise, it returns all locations. A row leads with its
    network view when the item has the field.
    """
    processed_data = defaultdict(list)
    all_locations = [
        {
            **_view_label(loc),
            "network": loc["network"],
            "comment": loc.get("comment", ""),
            "DHCP utilization %": dhcp_percent(loc.get("dhcp_utilization")),
        }
        for loc in raw_data if "network" in loc
    ]

    if sitecode:
        matcher = re.compile(site_comment_regex(sitecode, comment_pattern), re.IGNORECASE)
        processed_data["location"] = [
            loc for loc in all_locations if matcher.search(loc.get("comment", "") or "")
        ]
    else:
        # No sitecode, so it's a keyword search. Return all valid locations.
        processed_data["location"] = all_locations

    return processed_data


# The record type of an 'fqdn' item, from the object part of its ``_ref`` ("record:host/ZG5z..." is a host record).
FQDN_RECORD_TYPES = {"record:a": "A", "record:aaaa": "AAAA", "record:host": "HOST", "record:cname": "CNAME"}


def _parse_fqdn_data(raw_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Parses the A, AAAA, host and CNAME records of the 'fqdn' type, one row per address.

    A host record yields a row for each of its addresses, a CNAME row has an empty ``ip`` and
    its target in ``canonical``. ``TTL`` is empty unless the record sets its own (the zone's
    default applies). A host row also carries ``configure_for_dns``: False for a record that
    publishes no DNS (DHCP/IPAM only), True otherwise, also when the grid does not return the
    field. A row names the record's DNS view (before ``zone``) when the record's ``view`` is not
    blank. Items of any other type are skipped.
    """
    rows: List[Dict[str, Any]] = []
    for record in raw_data:
        record_type = FQDN_RECORD_TYPES.get(str(record.get("_ref", "")).split("/", 1)[0])
        if not record_type:
            continue
        dns_view = str(record.get("view") or "").strip()
        if record_type == "HOST":
            addresses = [
                entry.get("ipv4addr") or entry.get("ipv6addr", "")
                for entry in record.get("ipv4addrs", []) + record.get("ipv6addrs", [])
            ]
        else:  # an A or AAAA record holds one address, a CNAME none
            addresses = [record.get("ipv4addr") or record.get("ipv6addr", "")]
        for address in addresses:
            rows.append({
                "ip": address,
                "name": record.get("name", ""),
                "type": record_type,
                "canonical": record.get("canonical", ""),
                **({DNS_VIEW: dns_view} if dns_view else {}),
                "zone": record.get("zone", ""),
                "TTL": record.get("ttl", "") if record.get("use_ttl") else "",
                **({"configure_for_dns": bool(record.get("configure_for_dns", True))} if record_type == "HOST" else {}),
            })
    return {"fqdn": rows}


def _parse_general_subnet_data(raw_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Parses data for the 'general' subnet information type."""
    processed_data = defaultdict(list)
    if not raw_data:
        return processed_data

    data = raw_data[0]
    inheritance = data.get("_inheritance", {})
    comment_meta = inheritance.get("comment", {})
    extattrs_meta = inheritance.get("extattrs", {})

    general_row = {
        "subnet": data.get("network", ""),
        "description": data.get("comment", ""),
        "DHCP utilization %": dhcp_percent(data.get("dhcp_utilization")),
    }
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
    ipv6 = ":" in str(data.get("network", ""))
    inheritance = data.get("_inheritance", {})
    member_meta = inheritance.get("members", [])
    option_meta = inheritance.get("options", [])
    if "members" in data:
        member_rows = [
            {
                # ``dhcpmember`` has both addresses; an IPv6 network shows the IPv6 one when it has it.
                "IP Address": (mem.get("ipv6addr") or mem.get("ipv4addr", "")) if ipv6 else mem.get("ipv4addr", ""),
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
                decode=not ipv6,
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
        {
            "network": r.get("network", ""),
            "start address": r.get("start_addr", ""),
            "end address": r.get("end_addr", ""),
            "utilization %": dhcp_percent(r.get("dhcp_utilization")),
            "utilization status": r.get("dhcp_utilization_status", ""),
            "leases": r.get("dynamic_hosts", ""),
            "static": r.get("static_hosts", ""),
            "total": r.get("total_hosts", ""),
        }
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
    """
    Parses data for the 'fixed addresses' type. An IPv4 fixed address has a ``mac``; an IPv6 one has a DUID and
    no MAC (``ipv6fixedaddress`` has no such field), so its ``MAC`` cell stays empty, there for the one shape of a mixed run.
    """
    processed_data = defaultdict(list)
    processed_data["fixed addresses"] = [
        {
            "IP address": addr["ipv4addr"] if "ipv4addr" in addr else addr.get("ipv6addr", ""),
            "name": addr.get("name", ""),
            "MAC": addr.get("mac", ""),
            # An IPv6 fixed address always has the key, also when it matches by MAC and has no DUID.
            **({"DUID": addr.get("duid") or ""} if "ipv6addr" in addr else {}),
        }
        for addr in raw_data
    ]
    return processed_data


#: The types of an address that is only part of the subnet's structure, not of anything anyone put there: the
#: network and broadcast addresses, and the filler addresses of a DHCP range (the "DHCP range" section describes it).
STRUCTURAL_ADDRESS_TYPES = frozenset({"NETWORK", "BROADCAST", "DHCP_RANGE"})


def _parse_ip_addresses_data(raw_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Parses the 'IP addresses' type: the used addresses of a subnet (``ipv4address`` / ``ipv6address``
    objects), one row each with all of its record types, whatever they are.

    An address whose types are all structural (``STRUCTURAL_ADDRESS_TYPES``) has no row; one that is
    structure and something else (a lease inside a range) keeps all of its types. An unknown type is
    printed as returned, and an address with no type at all keeps a row with an empty ``types``. An IPv4
    item gets ``MAC``, an IPv6 item (it has the ``duid`` field) gets ``DUID`` instead. With nothing left
    there is no section: an empty one would make a subnet that has no other data read as partial.
    """
    rows: List[Dict[str, Any]] = []
    for item in raw_data:
        types = list(item.get("types") or [])
        if types and all(kind in STRUCTURAL_ADDRESS_TYPES for kind in types):
            continue
        rows.append({
            "IP address": item.get("ip_address", ""),
            "types": ",".join(types),
            "usage": ",".join(item.get("usage") or []),
            "names": ", ".join(item.get("names") or []),
            "lease state": item.get("lease_state") or "",
            **({"MAC": item["mac_address"] or ""} if "mac_address" in item else {}),
            **({"DUID": item["duid"] or ""} if "duid" in item else {}),
        })
    processed_data = defaultdict(list)
    if rows:
        processed_data["IP addresses"] = rows
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
            return _parse_location_data(raw_data, sitecode, ctx.cfg.get("site_comment_pattern"))

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
    "IP addresses": _parse_ip_addresses_data,
}
