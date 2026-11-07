"""The Unused address rule: which host addresses of a subnet have no record in Infoblox, or a refusal to say
(docs/plans/2026-11-06-show-available-design.md, section "Subnet").

``unused_addresses`` takes one group, a network in one network view, with the sections the subnet lookup already
holds for it (``tables``) and the warnings it raised. An empty answer looks exactly like an empty subnet, so the
rule lists addresses only with positive proof: the network is IPv4, Infoblox confirmed it (a ``general`` row), the
view list was readable, no lookup warned, and the network is no bigger than ``MAX_LISTED_ADDRESSES``. Anything
else is a refusal that names its reason, and a refusal never carries addresses. An address in use shown as free is
the failure that matters, so a record that cannot be read refuses the whole list. A lookup that answered the grid's
miss ("does not match any network") warned of nothing, so the caller hands such a group one more warning
(``with_unconfirmed``) and it is refused as incomplete.

A list is every host address (``ipaddress``' ``hosts()``: never the network or the broadcast address) minus the
addresses of the four record lists: ``fixed addresses``, ``DNS records`` and ``IP addresses`` (rows with
``IP address``) and ``DHCP range`` (rows with ``start address`` and ``end address``, every address between them).
It never uses the grid's ``status=UNUSED``, which returns reserved-range addresses. ``CONTAINER`` is the caller's
reason for a child container: it is listed but never expanded, so no ``general`` row stands for it.

Pure: no I/O, no request.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, List, Mapping, Optional, Sequence, Tuple

MAX_LISTED_ADDRESSES = 65_536  # a network with more addresses than this is not listed

NOT_A_NETWORK = "not a network in Infoblox"
INCOMPLETE = "its records could not all be read"
VIEWS_UNREADABLE = "the network views could not be listed, so records in other views may be missing"
CONTAINER = "a container, not a network"
IPV6_NOT_LISTED = "IPv6 subnets are not listed"
TOO_LARGE = "too large to list"
UNCONFIRMED_WARNING = "a list lookup missed its network, or rows named no view"  # added by ``with_unconfirmed``, never shown

_ADDRESS_SECTIONS = ("fixed addresses", "DNS records", "IP addresses")  # rows with one ``IP address``
_RANGE_SECTION = "DHCP range"  # rows with ``start address`` and ``end address``

Interval = Tuple[int, int]  # first and last address of a run, as integers, both included


@dataclass(frozen=True)
class UnusedList:
    """The addresses with no record, in numeric order, or the reason there is no list. Never both."""

    addresses: Tuple[str, ...] = ()
    refusal: str = ""


def unused_addresses(network: str, tables: Mapping[str, Sequence[Mapping[str, Any]]],
                     warnings: Sequence[str], *, views_readable: bool = True) -> UnusedList:
    """
    The unused host addresses of ``network`` (one network in one view), or a refusal. The checks run in this order:
    text that is no network, IPv6, unreadable view list, any warning, no ``general`` row, size, then the records. Text
    with no mask is no network (``ipaddress`` would read an address as a /32), and IPv6 text is IPv6 whatever its
    host bits. A section missing from ``tables`` has no rows, but a row that has no readable address, or is no
    mapping, refuses the list.
    """
    text = str(network).strip()
    try:
        net = ipaddress.ip_network(text, strict=True)
    except ValueError:
        # Not a network: a mistyped mask, host bits set. IPv6 text that fails only on host bits is still IPv6.
        return UnusedList(refusal=IPV6_NOT_LISTED if _is_ipv6(text) else NOT_A_NETWORK)
    if net.version != 4:
        return UnusedList(refusal=IPV6_NOT_LISTED)
    if "/" not in text:  # ipaddress reads a bare address as a /32, and a /32 would list that address as free
        return UnusedList(refusal=NOT_A_NETWORK)
    if not views_readable:
        return UnusedList(refusal=VIEWS_UNREADABLE)
    if len(warnings):  # before the general row: a failed network lookup also leaves it empty, and is not a mistyped mask
        return UnusedList(refusal=INCOMPLETE)
    if not tables.get("general"):
        return UnusedList(refusal=NOT_A_NETWORK)
    if net.num_addresses > MAX_LISTED_ADDRESSES:
        return UnusedList(refusal=TOO_LARGE)

    used = _used_intervals(tables)
    if used is None:
        return UnusedList(refusal=INCOMPLETE)
    return UnusedList(addresses=_free_addresses(net, used))


def with_unconfirmed(warnings: Sequence[str], tables: Mapping[str, Sequence[Mapping[str, Any]]],
                     unconfirmed: bool) -> List[str]:
    """
    The ``warnings`` to hand ``unused_addresses`` for a group the lookup could not prove complete (``unconfirmed``: a list
    lookup missed in its view, or rows that name no view were dropped beside rows that do). The one added text refuses
    the list as ``INCOMPLETE``, but only for a group Infoblox confirmed (a ``general`` row): a prefix that is no network
    has every list lookup miss, and its reason stays ``NOT_A_NETWORK``. The CLI and the Subnets page both call it.
    """
    if unconfirmed and tables.get("general"):
        return [*warnings, UNCONFIRMED_WARNING]
    return list(warnings)


def _is_ipv6(text: str) -> bool:
    """Whether ``text`` is IPv6 network text once its host bits are set aside."""
    try:
        return ipaddress.ip_network(text, strict=False).version == 6
    except ValueError:
        return False


def _address(value: Any) -> Optional[int]:
    """The IPv4 address in ``value`` as an integer, or None when there is no readable one."""
    try:
        return int(ipaddress.IPv4Address(str(value).strip()))
    except ValueError:
        return None


def _used_intervals(tables: Mapping[str, Sequence[Mapping[str, Any]]]) -> Optional[List[Interval]]:
    """
    Every address the four record lists take, as sorted, merged intervals; None when any row is unreadable (an
    address that does not parse, or a row that is no mapping).
    """
    intervals: List[Interval] = []
    for name in _ADDRESS_SECTIONS:
        for row in tables.get(name) or ():
            value = _address(row.get("IP address")) if isinstance(row, Mapping) else None
            if value is None:
                return None
            intervals.append((value, value))
    for row in tables.get(_RANGE_SECTION) or ():
        if not isinstance(row, Mapping):
            return None
        first, last = _address(row.get("start address")), _address(row.get("end address"))
        if first is None or last is None or first > last:
            return None
        intervals.append((first, last))
    intervals.sort()
    merged: List[Interval] = []
    for first, last in intervals:
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], last))
        else:
            merged.append((first, last))
    return merged


def _free_addresses(net: ipaddress.IPv4Network, used: Sequence[Interval]) -> Tuple[str, ...]:
    """The host addresses of ``net`` outside ``used`` (sorted, merged), in numeric order."""
    low = int(net.network_address)
    high = int(net.broadcast_address)
    if net.prefixlen < 31:  # a /31 and a /32 have no network or broadcast address: every address is a host
        low, high = low + 1, high - 1
    free: List[str] = []
    cursor = low
    for first, last in used:
        if last < cursor:
            continue
        if first > high:
            break
        free.extend(str(ipaddress.IPv4Address(value)) for value in range(cursor, min(first, high + 1)))
        cursor = max(cursor, last + 1)
    free.extend(str(ipaddress.IPv4Address(value)) for value in range(cursor, high + 1))
    return tuple(free)
