"""
One reader for the text a person types or pastes into a Targets box (web UI, plan 7.3).

Pure: the standard library and ``cn_tool.utils.validation`` only, so it is safe to import without the web stack.
The command line does not call it (its grammar stays as it is); the web UI calls it to show what a box holds and to
submit one item per line. The tools' own validation stays the authority: ``parse`` warns, the tool decides, and what
is not understood is still submitted as typed so that the tool reports it as it does today.

Per line, in this order:

1. ``#`` and everything after it is a comment.
2. The rest is split on commas, semicolons, tabs and spaces.
3. An IPv4 address followed, after whitespace only, by a contiguous netmask or a wildcard mask is one network.
4. ``a.b.c.10-20`` and ``a.b.c.10-a.b.c.20`` are a range (not understood for Subnets).
5. A URL gives its host; ``host:port`` gives the host and the note "port ignored".
6. An address or network in any spelling ``ipaddress`` accepts is itself, submitted as typed, unless the tool
   refuses it, in which case it is not understood, with the tool's own reason, and is submitted unchanged: IPv4-mapped
   and zoned IPv6 (zone IDs are fine for Ping and Monitor); for Ping and Monitor an IPv6 link-local address without
   a zone and a network wider than a /16 (IPv6 /112); for IP a reserved, unspecified or link-local address.
7. A name is a target for Ping and Monitor only. A network wider than one address is not understood for IP.
8. Anything else is not understood and is submitted as typed.

Ping and Monitor read a line of several words today as a list of addresses and silently drop every word that is
not one. A word like that, on a line that holds an address, is kind ``ignored``: shown with a note, never submitted
and never counted as a target (``10.0.0.1 (gw) OK``). Also ``10.0.0.1 - 10.0.0.5`` is a range, and only a plausible
mask pairs with an address (a netmask or wildcard mask that starts with 255 or 0).

``parse`` is bounded: the ranges of one box expand to ``RANGE_LIMIT[tool]`` addresses in all (the rest are not
understood), and ``expand=False`` builds no ``lines`` at all, for a live preview.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, replace
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from cn_tool.utils.validation import ipv6_form_problem, is_fqdn

TOOLS = ("subnet", "ip", "ping", "monitor")

#: The most addresses the ranges of one box may stand for in all, per tool. IP's 1,024 is this plan's limit (the tool
#: has none); Ping's and Monitor's is ``bulk_ping.MAX_PING_HOSTS`` (a test pins it, so this module need not import
#: the tool).
RANGE_LIMIT: Dict[str, int] = {"ip": 1024, "ping": 65534, "monitor": 65534}

NOTE_PORT = "port ignored"
NOTE_URL = "host taken from the URL"
NOTE_PREFIX = "prefix dropped"
NOTE_HOST_BITS = "host bits cleared"
NOTE_RANGE_SUBNETS = "Subnets takes addresses and networks"
NOTE_RANGE_BACKWARDS = "the range ends before it starts"
NOTE_RANGE_INVALID = "not a valid address range"
NOTE_NETWORK_FOR_IP = "IP takes single addresses; use Subnets"
NOTE_NAME_SUBNETS = "Subnets takes addresses and networks, not names"
NOTE_NAME_IP = "IP takes addresses, not names"
NOTE_NAME_ON_ADDRESS_LINE = "a host name counts only on a line without addresses"
NOTE_NOT_IPV4 = "not an IPv4 address"
# What the tools say, pinned to their own constants by tests.
NOTE_RESERVED = "Invalid IP: Broadcast, unspecified, and reserved IPs are excluded."
NOTE_LINK_LOCAL = "link-local IPv6 needs an interface: ping one address with %<interface> appended, e.g. %eth0"
NOTE_UNKNOWN = {
    "subnet": "not an IP address or network",
    "ip": "not an IP address",
    "ping": "not an address, network or host name",
    "monitor": "not an address, network or host name",
}

_WORD = re.compile(r"[^,;\s]+")
_SHORT_RANGE = re.compile(r"((?:\d{1,3}\.){3}\d{1,3})-(\d{1,3})")
_FULL_RANGE = re.compile(r"((?:\d{1,3}\.){3}\d{1,3})-((?:\d{1,3}\.){3}\d{1,3})")
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
_HOST_PORT = re.compile(r"(?P<host>[^:\[\]]+|\[[^\]]+\]):(?P<port>\d{1,5})")
_DIGITS_AND_DOTS = re.compile(r"[0-9.]+")


@dataclass(frozen=True)
class Token:
    """
    One item of the box.

    ``kind`` is address, network, range, name, unknown or ignored. ``text`` is what the tool is given: the item as
    typed unless the grammar rewrote it (a mask pair gives CIDR, a URL its host, ``host:port`` its host, a ``/32``
    given to IP its address). A range is one token whose ``text`` is the range in full form (``10.0.0.10-10.0.0.12``);
    ``Parsed.lines`` holds its addresses, one per line. ``hosts`` is the number of addresses the item stands for
    (what the tool would take of a network), None for an item that is not understood. An ``ignored`` word is one the
    tool drops from a line of addresses: it is not submitted and not counted as a target.
    """

    kind: str
    text: str
    source: str
    line: int
    hosts: Optional[int]
    note: str = ""


@dataclass(frozen=True)
class Parsed:
    tokens: Tuple[Token, ...]
    lines: Tuple[str, ...]
    summary: str


def parse(text: str, tool: str, *, expand: bool = True) -> Parsed:
    """
    Read ``text`` for ``tool`` ('subnet', 'ip', 'ping' or 'monitor').

    Returns the tokens, the lines to submit (one item per line; blank and comment lines gone; ``parse`` of them gives
    the same lines again) and the one-line summary. Lines break as ``str.splitlines`` breaks them, as the pages do.
    With ``expand=False`` no ``lines`` are built (the tuple is empty): ranges are counted, not expanded, which is
    all a live preview needs. Raises ``ValueError`` for another tool.
    """
    if tool not in TOOLS:
        raise ValueError(f"unknown tool: {tool!r}")
    budget = [RANGE_LIMIT.get(tool, 0)]  # addresses the ranges of this box may still stand for
    tokens: List[Token] = []
    lines: List[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        for token in _line_tokens(raw.partition("#")[0], number, tool, budget):
            tokens.append(token)
            if token.kind == "range":
                if expand:
                    lines.extend(_range_addresses(token.text))
            elif token.kind != "ignored" and expand:
                lines.append(token.text)
    return Parsed(tuple(tokens), tuple(lines), _summary(tokens))


def _line_tokens(text: str, number: int, tool: str, budget: List[int]) -> List[Token]:
    """The tokens of one line without its comment."""
    words = list(_WORD.finditer(text))
    tokens: List[Token] = []
    index = 0
    while index < len(words):
        word = words[index].group()
        together = lambda ahead: not text[words[index + ahead - 1].end():words[index + ahead].start()].strip(" \t\v\f")
        if index + 2 < len(words) and words[index + 1].group() == "-" and together(1) and together(2) \
                and _is_ipv4(word) and _is_ipv4(words[index + 2].group()):
            last = words[index + 2].group()
            tokens.append(_merged(f"{word}-{last}", f"{word} - {last}", number, tool, budget))
            index += 3
            continue
        if index + 1 < len(words) and together(1):
            prefix = _mask_prefix(word, words[index + 1].group(), tool)
            if prefix is not None:
                tokens.append(_merged(_mask_network(word, prefix), f"{word} {words[index + 1].group()}", number, tool, budget,
                                      NOTE_HOST_BITS if _host_bits(word, prefix) else ""))
                index += 2
                continue
        tokens.append(_classify(word, word, number, tool, "", budget))
        index += 1
    if tool in ("ping", "monitor") and len(words) > 1 and any(_is_pingable_address(w.group()) for w in words):
        tokens = [_ignored(token) if _dropped_today(token) else token for token in tokens]
    return tokens


def _merged(text: str, source: str, number: int, tool: str, budget: List[int], note: str = "") -> Token:
    """A token made of several typed words: classified as the one item it stands for, with the words as its source."""
    token = _classify(text, text, number, tool, note, budget)
    return replace(token, source=source)


def _dropped_today(token: Token) -> bool:
    """True for a word that Ping and Monitor drop from a line that holds an address (a bare name, anything unknown)."""
    return token.kind == "unknown" or (token.kind == "name" and not token.note)


def _ignored(token: Token) -> Token:
    # A valid host name is dropped too (Ping reads a line that holds an address as addresses only): say that.
    reason = NOTE_NAME_ON_ADDRESS_LINE if token.kind == "name" else (token.note or "not an address")
    return Token("ignored", token.source, token.source, token.line, None, f"ignored on a line of addresses: {reason}")


def _is_pingable_address(word: str) -> bool:
    """``bulk_ping._is_ip``: what Ping and Monitor keep of a word on a line of several (never a prefix)."""
    if "/" in word:
        return False
    address = _address(word)
    if address is None or ipv6_form_problem(word, zone_ok=True):
        return False
    return "%" in word or not (address.version == 6 and address.is_link_local)


def _mask_prefix(address: str, mask: str, tool: str) -> Optional[int]:
    """
    The prefix length when ``address`` is an IPv4 address and ``mask`` a plausible netmask (first octet 255) or
    wildcard mask (first octet 0), never 0.0.0.0. 255.255.255.255 is a mask for IP and Subnets only: Ping and
    Monitor would be reading a host away.
    """
    if not (_is_ipv4(address) and _is_ipv4(mask)):
        return None
    value = int(ipaddress.IPv4Address(mask))
    if value == 0:
        return None
    if value >> 24 == 255 and _contiguous_ones(value):
        return None if value == 0xFFFFFFFF and tool in ("ping", "monitor") else bin(value).count("1")
    inverse = value ^ 0xFFFFFFFF
    if value >> 24 == 0 and value != 0xFFFFFFFF and _contiguous_ones(inverse):
        return bin(inverse).count("1")
    return None


def _mask_network(address: str, prefix: int) -> str:
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def _host_bits(address: str, prefix: int) -> bool:
    return ipaddress.ip_network(f"{address}/{prefix}", strict=False).network_address != ipaddress.ip_address(address)


def _contiguous_ones(value: int) -> bool:
    """True for ones, then zeros (and not 0.0.0.0)."""
    return value != 0 and (value ^ 0xFFFFFFFF) & ((value ^ 0xFFFFFFFF) + 1) == 0


def _is_ipv4(word: str) -> bool:
    try:
        ipaddress.IPv4Address(word)
    except ValueError:
        return False
    return True


def _usable(network, tool: str) -> int:
    """
    The hosts a network stands for. Subnets and IP: all but the ends of an IPv4 network, all but the first of an
    IPv6 one (a /31, /32 and /128 keep every address). Ping and Monitor: what ``bulk_ping._parse_target`` expands,
    which also drops the loopback, multicast and reserved addresses of a subnet.
    """
    count = network.num_addresses
    if count == 1:
        return 1
    if count <= 4:
        hosts = list(network.hosts())  # let the interpreter decide the short ones (a /31, an IPv6 /127)
        usable = len(hosts) if tool in ("subnet", "ip") else sum(1 for h in hosts if not _special(h))
        return usable
    if tool in ("ping", "monitor") and _special(network.network_address):
        return 0  # every special block is wider than a network the tools take
    return count - 2 if network.version == 4 else count - 1


def _special(address) -> bool:
    return address.is_loopback or address.is_multicast or address.is_reserved


def _unknown(word: str, number: int, tool: str, note: str = "") -> Token:
    return Token("unknown", word, word, number, None, note or NOTE_UNKNOWN[tool])


def _too_many(network) -> str:
    limit = RANGE_LIMIT["ping"]
    if network.version == 6:
        return f"more than {limit + 1:,} hosts; ping at most a /112"
    return f"more than {limit:,} hosts; ping at most a /16"


def _ip_tool_problem(word: str, address) -> str:
    """The order of ``ip_request._validate_ip``: mapped hint, reserved, then the zone ID hint."""
    mapped = ipv6_form_problem(word, zone_ok=True)
    if mapped:
        return mapped
    if address.is_unspecified or address.is_reserved or address.is_link_local:
        return NOTE_RESERVED
    return ipv6_form_problem(word)


def _classify(word: str, source: str, number: int, tool: str, note: str, budget: List[int]) -> Token:
    """
    Classify one word. ``source`` is what was typed (``word`` differs after a URL or ``host:port`` was opened);
    ``note`` is what was dropped on the way. A word that is not understood is returned as ``source``. ``budget``
    holds the addresses the ranges of the box may still stand for.
    """
    short, full = _SHORT_RANGE.fullmatch(word), _FULL_RANGE.fullmatch(word)
    if short or full:
        return _range_token(word, source, number, tool, short or full, bool(full), budget)

    if word is source and _URL.match(word):
        return _from_url(word, number, tool, budget)
    if word is source:
        hosted = _HOST_PORT.fullmatch(word)
        if hosted and 0 < int(hosted["port"]) < 65536 and _not_ipv6(hosted["host"]):
            host = hosted["host"]
            host = host[1:-1] if host.startswith("[") else host
            return _classify(host, source, number, tool, NOTE_PORT, budget)

    if "%" in word and "/" in word:
        return _unknown(source, number, tool)
    address = _address(word)
    if tool == "ip":
        if address is not None:
            problem = _ip_tool_problem(word, address)
            return _unknown(source, number, tool, problem) if problem else Token("address", word, source, number, 1, note)
    else:
        problem = ipv6_form_problem(word, zone_ok=tool in ("ping", "monitor"))
        if problem:
            return _unknown(source, number, tool, problem)
        if address is not None:
            if tool != "subnet" and address.version == 6 and address.is_link_local and "%" not in word:
                return _unknown(source, number, tool, NOTE_LINK_LOCAL)
            return Token("address", word, source, number, 1, note)
    network = None if "%" in word else _network(word)
    if network is not None:
        if tool == "ip":
            if network.num_addresses == 1:
                return _classify(word.partition("/")[0], source, number, tool, NOTE_PREFIX, budget)
            return _unknown(source, number, tool, NOTE_NETWORK_FOR_IP)
        if tool != "subnet":
            if network.version == 6 and network.network_address.is_link_local:
                return _unknown(source, number, tool, NOTE_LINK_LOCAL)
            if network.num_addresses > RANGE_LIMIT["ping"] + 2:
                return _unknown(source, number, tool, _too_many(network))
        return Token("network", word, source, number, _usable(network, tool), note)

    if _DIGITS_AND_DOTS.fullmatch(word):
        return _unknown(source, number, tool, NOTE_NOT_IPV4)
    if is_fqdn(word) and ":" not in word:
        if tool in ("ping", "monitor"):
            return Token("name", word, source, number, 1, note)
        return _unknown(source, number, tool, NOTE_NAME_SUBNETS if tool == "subnet" else NOTE_NAME_IP)
    return _unknown(source, number, tool)


def _not_ipv6(host: str) -> bool:
    return host.startswith("[") or ":" not in host


def _from_url(word: str, number: int, tool: str, budget: List[int]) -> Token:
    try:
        parts = urlsplit(word)
        host, port = parts.hostname, parts.port
    except ValueError:
        return _unknown(word, number, tool)
    if not host:
        return _unknown(word, number, tool)
    return _classify(host, word, number, tool, NOTE_URL + ("; " + NOTE_PORT if port is not None else ""), budget)


def _address(word: str):
    try:
        return ipaddress.ip_address(word)
    except ValueError:
        return None


def _network(word: str):
    try:
        return ipaddress.ip_network(word, strict=False)
    except ValueError:
        return None


def _range_token(word: str, source: str, number: int, tool: str, match, full: bool, budget: List[int]) -> Token:
    if tool == "subnet":
        return _unknown(source, number, tool, NOTE_RANGE_SUBNETS)
    try:
        start = ipaddress.IPv4Address(match.group(1))
        if full:
            end = ipaddress.IPv4Address(match.group(2))
        else:
            last = int(match.group(2))
            if last > 255:
                raise ValueError(word)
            end = ipaddress.IPv4Address((int(start) & 0xFFFFFF00) | last)
    except ValueError:
        return _unknown(source, number, tool, NOTE_RANGE_INVALID)
    if int(end) < int(start):
        return _unknown(source, number, tool, NOTE_RANGE_BACKWARDS)
    count = int(end) - int(start) + 1
    limit = RANGE_LIMIT[tool]
    if count > limit:
        return _unknown(source, number, tool, f"a range may hold at most {limit:,} addresses; this one holds {count:,}")
    if count > budget[0]:
        return _unknown(source, number, tool, f"the ranges of one box may hold at most {limit:,} addresses in all")
    budget[0] -= count
    return Token("range", f"{start}-{end}", source, number, count)


def _range_addresses(text: str) -> List[str]:
    first, _, last = text.partition("-")
    start, end = int(ipaddress.IPv4Address(first)), int(ipaddress.IPv4Address(last))
    return [str(ipaddress.IPv4Address(value)) for value in range(start, end + 1)]


def _plural(count: int, one: str, many: str) -> str:
    return f"{count:,} {one if count == 1 else many}"


def _summary(tokens: List[Token]) -> str:
    """
    '14 targets: 3 subnets (766 hosts), 9 addresses, 2 names · 2 not understood'; '' for an empty box. An item typed
    twice counts once, as the tools take every host once.
    """
    if not tokens:
        return ""
    understood = [token for token in tokens if token.kind not in ("unknown", "ignored")]
    refused = sum(1 for token in tokens if token.kind == "unknown")
    ignored = sum(1 for token in tokens if token.kind == "ignored")
    parts: List[str] = []
    total = 0
    for kind, one, many, unit in (
        ("network", "subnet", "subnets", ("host", "hosts")),
        ("range", "range", "ranges", ("address", "addresses")),
        ("address", "address", "addresses", None),
        ("name", "name", "names", None),
    ):
        group = list({token.text: token for token in understood if token.kind == kind}.values())
        if not group:
            continue
        total += len(group)
        part = _plural(len(group), one, many)
        if unit:
            part += f" ({_plural(sum(token.hosts or 0 for token in group), *unit)})"
        parts.append(part)
    text = f"{_plural(total, 'target', 'targets')}: {', '.join(parts)}" if parts else _plural(total, "target", "targets")
    if refused:
        text += f" · {refused:,} not understood"
    if ignored:
        text += f" · {ignored:,} ignored"
    return text
