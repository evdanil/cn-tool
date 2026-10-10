"""The Ping Monitor's live view, laid out: pure functions from blocks of hosts to lines of styled text.

``build_blocks`` turns the request's targets into blocks: one per subnet, cell *i* being the
subnet's address *i*, and one ``Hosts`` block for the single addresses and names. ``grid_lines``
draws them with one character per host, or gives ``None`` when they do not fit the screen, and
``compact_lines`` gives the counter line per block that replaces the grid then. ``legend``
explains the characters drawn.

A host is known by its index into the request's host list, and the caller gives each host's
character. A line is a list of ``(text, style name)`` segments: the module draws no colour and
imports no Rich, and the caller turns the segments into a ``Text``.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Address, IPv6Network, ip_network
from typing import AbstractSet, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

Segment = Tuple[str, str]  # (text, style name)
Line = List[Segment]

CHARS = "!RTxUE?. "
STYLES: Dict[str, str] = {"!": "ok", "R": "info", "T": "info", "x": "warning", "U": "error",
                          "E": "error", "?": "error", ".": "dim", " ": "dim"}
# The legend's order.
LEGEND: Dict[str, str] = {"!": "replied", "R": "rejected (up, firewalled)", "T": "TCP only",
                          "U": "unreachable (reported since first probed)", "x": "gone", ".": "silent",
                          "E": "error", "?": "name did not resolve"}
GROUP = 8
ROW_SIZES = (64, 32, 16)

_HOSTS = "Hosts"
_INDENT = "  "
_PAIR_GAP = "   "
_COUNTED = "!RTxUE?."  # the compact view's order; a host not yet probed is not counted
_BLANK: Segment = (" ", "dim")


@dataclass(frozen=True)
class Block:
    """One subnet's cells, or (``network`` ``None``) the ``Hosts`` block's labelled hosts."""

    title: str  # "10.1.2.0/24", or "Hosts"
    network: Optional[Union[IPv4Network, IPv6Network]]  # None for the Hosts block
    cells: Tuple[Optional[int], ...] = ()  # subnet: one entry per address of the network; host index or None
    names: Tuple[Tuple[str, int], ...] = ()  # Hosts block: (label, host index)


def build_blocks(subnets: Sequence[str], singles: Sequence[str], host_index: Mapping[str, int]) -> List[Block]:
    """
    One block per subnet, in the order given, then one ``Hosts`` block for ``singles``.

    Cell *i* of a subnet's block is ``host_index.get(str(network[i]))``: the network and broadcast
    addresses, and an address the subnet expansion skipped, are ``None``. A single that is not in
    ``host_index`` is left out, and so is a ``Hosts`` block with nothing in it.
    """
    blocks: List[Block] = []
    for subnet in subnets:
        network = ip_network(subnet)
        blocks.append(Block(subnet, network, cells=tuple(map(host_index.get, _spellings(network)))))
    names = tuple((label, host_index[label]) for label in singles if label in host_index)
    if names:
        blocks.append(Block(_HOSTS, None, names=names))
    return blocks


def grid_lines(
    blocks: Sequence[Block],
    chars: Sequence[str],
    *,
    width: int,
    height: int,
    changed: AbstractSet[int] = frozenset(),
    partial: AbstractSet[int] = frozenset(),
) -> Optional[List[Line]]:
    """
    The grid of ``blocks``, one blank line between blocks, or ``None`` when it does not fit.

    Every block's rows hold the same number of cells, the largest of ``ROW_SIZES`` that fits
    ``width`` next to the widest row label; ``None`` when not even the smallest fits, when the
    lines outnumber ``height``, or when a ``Hosts`` pair is wider than a line. ``chars[i]`` is
    host *i*'s character. A host in ``changed`` is drawn in reverse video, and one in ``partial``
    that replied in the warning colour.
    """
    for size in ROW_SIZES:
        if _fewest_lines(blocks, size) > height:  # a smaller row size only adds rows
            return None
        labels = [_row_labels(block, size) if block.network is not None else [] for block in blocks]
        label_width = max((len(label) for rows in labels for label in rows), default=0)
        if any(block.network is None for block in blocks):
            label_width = max(label_width, len(_HOSTS))
        if label_width + 1 + size + size // GROUP - 1 <= width:
            break
    else:
        return None

    look = _Look(chars, changed, partial)
    lines: List[Line] = []
    for block, rows in zip(blocks, labels):
        if lines:
            lines.append([])
        if block.network is None:
            hosts = _hosts_lines(block, look, label_width, width)
            if hosts is None:
                return None
            lines.extend(hosts)
            continue
        lines.append(_header(block.title, min(size, len(block.cells)), label_width))
        for row, label in enumerate(rows):
            lines.append(_row(label, block.cells[row * size:(row + 1) * size], look, label_width))
    return None if len(lines) > height else lines


def compact_lines(blocks: Sequence[Block], chars: Sequence[str]) -> List[Line]:
    """One line per block: its title and how many of its hosts show each character, e.g. ``3 ! · 61,102 .``."""
    lines: List[Line] = []
    for block in blocks:
        hosts = block.cells if block.network is not None else [host for _, host in block.names]
        counts = Counter(chars[host] for host in hosts if host is not None)
        line: Line = [(block.title, "label"), (": ", "text")]
        for char in _COUNTED:
            if counts[char]:
                if len(line) > 2:
                    line.append((" · ", "text"))
                line += [(f"{counts[char]:,} ", "text"), (char, STYLES[char])]
        lines.append(line)
    return lines


def legend(chars_present: Iterable[str]) -> Line:
    """The meaning of each character in ``chars_present``, in ``LEGEND``'s order."""
    present = set(chars_present)
    line: Line = []
    for char, meaning in LEGEND.items():
        if char in present:
            if line:
                line.append(("  ", "text"))
            line += [(char, STYLES[char]), (" " + meaning, "text")]
    return line


@dataclass(frozen=True)
class _Look:
    """What styles a host's cell: its character, and whether it changed or replied partly."""

    chars: Sequence[str]
    changed: AbstractSet[int]
    partial: AbstractSet[int]

    def cell(self, host: Optional[int]) -> Segment:
        if host is None:
            return _BLANK
        char = self.chars[host]
        style = "warning" if char == "!" and host in self.partial else STYLES[char]
        if host in self.changed:
            style += " reverse"
        return (char, style)


def _spellings(network: Union[IPv4Network, IPv6Network]) -> List[str]:
    """
    ``str(network[i])`` for every address *i* of ``network``, without an address object for each.

    In a /112 or smaller IPv6 network every address after the first has a last hextet that is not
    zero, so it cannot join a run of zeros that ``::`` replaces: they all share the spelling of the
    first seven hextets. Python 3.13 spells an IPv4-mapped address (``::ffff:0:0/96``) with a
    dotted tail, so those, and wider networks, are spelled one address at a time.
    """
    first = int(network.network_address)
    addresses = range(first, first + network.num_addresses)
    if network.version == 4:
        return [f"{address >> 24}.{(address >> 16) & 255}.{(address >> 8) & 255}.{address & 255}"
                for address in addresses]
    if network.prefixlen < 112 or first >> 32 == 0xFFFF:
        return [str(IPv6Address(address)) for address in addresses]
    stem = str(IPv6Address((first & ~0xFFFF) | 1))[:-1]  # the first seven hextets, then ":"
    return [str(network.network_address)] + [f"{stem}{address & 0xFFFF:x}" for address in addresses[1:]]


def _row_labels(block: Block, size: int) -> List[str]:
    """The label of each row of ``size`` cells: the row's first address, shortened for IPv4."""
    network = block.network
    assert network is not None
    first = int(network.network_address)
    starts = range(first, first + len(block.cells), size)
    if network.version == 4 and network.prefixlen >= 24:
        return [f"{_INDENT}.{start & 255}" for start in starts]
    if network.version == 4 and network.prefixlen >= 16:
        return [f"{_INDENT}.{(start >> 8) & 255}.{start & 255}" for start in starts]
    address = type(network.network_address)
    return [_INDENT + str(address(start)) for start in starts]


def _fewest_lines(blocks: Sequence[Block], size: int) -> int:
    """The grid's line count with rows of ``size`` cells, counting one line for a ``Hosts`` block."""
    rows = sum(1 + -(-len(block.cells) // size) if block.network is not None else 1 for block in blocks)
    return rows + max(len(blocks) - 1, 0)


def _header(title: str, row_cells: int, label_width: int) -> Line:
    """The title, then each group's offset above the group's first cell; an offset the title covers is left out."""
    line: Line = [(title, "label")]
    column = len(title)
    for group in range(-(-row_cells // GROUP)):
        at = label_width + 1 + group * (GROUP + 1)
        if at <= len(title):  # at least one space after the title
            continue
        offset = str(group * GROUP)
        line += [(" " * (at - column), "text"), (offset, "header")]
        column = at + len(offset)
    return line


def _row(label: str, cells: Sequence[Optional[int]], look: _Look, label_width: int) -> Line:
    line: Line = [(label.ljust(label_width), "label"), (" ", "text")]
    for start in range(0, len(cells), GROUP):
        if start:
            line.append((" ", "text"))
        line += [look.cell(host) for host in cells[start:start + GROUP]]
    return _merged(line)


def _hosts_lines(block: Block, look: _Look, label_width: int, width: int) -> Optional[List[Line]]:
    """``label char`` pairs after the block's title, wrapped at ``width``; ``None`` if a pair is wider than a line."""
    indent = label_width + 1
    lines: List[Line] = []
    line: Line = [(_HOSTS.ljust(label_width), "label"), (" ", "text")]
    used = indent
    for label, host in block.names:
        pair = len(label) + 2
        if indent + pair > width:
            return None
        if used > indent and used + len(_PAIR_GAP) + pair > width:
            lines.append(line)
            line, used = [(" " * indent, "text")], indent
        if used > indent:
            line.append((_PAIR_GAP, "text"))
            used += len(_PAIR_GAP)
        line += [(label, "label"), (" ", "text"), look.cell(host)]
        used += pair
    lines.append(line)
    return lines


def _merged(line: Line) -> Line:
    """``line`` with neighbouring segments of one style joined."""
    merged: Line = []
    for part, style in line:
        if merged and merged[-1][1] == style:
            merged[-1] = (merged[-1][0] + part, style)
        else:
            merged.append((part, style))
    return merged
