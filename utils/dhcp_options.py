from __future__ import annotations

import ipaddress
import re
from string import printable
from typing import Optional, Set, Tuple


_HEX_TEXT_RE = re.compile(r"^(?:0x)?[0-9A-Fa-f][0-9A-Fa-f\s:.-]*$")


def _hex_bytes_from_value(value: object) -> Optional[bytes]:
    text = str(value or "").strip()
    if not text:
        return None
    if not _HEX_TEXT_RE.fullmatch(text):
        return None
    if text.lower().startswith("0x"):
        text = text[2:]
    normalized = re.sub(r"[\s:.-]", "", text)
    if not normalized or len(normalized) % 2 != 0:
        return None
    try:
        return bytes.fromhex(normalized)
    except ValueError:
        return None


def _is_printable_ascii(data: bytes) -> bool:
    return bool(data) and all(chr(byte) in printable and chr(byte) not in "\r\n\t\x0b\x0c" for byte in data)


def _decode_dns_name(data: bytes, offset: int, visited_offsets: Optional[Set[int]] = None) -> Optional[Tuple[str, int]]:
    labels = []
    next_offset = offset
    visited = set() if visited_offsets is None else set(visited_offsets)

    while True:
        if offset >= len(data):
            return None

        length = data[offset]
        if length == 0:
            if next_offset == offset:
                next_offset = offset + 1
            return ".".join(labels), next_offset

        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                return None
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer >= len(data) or pointer in visited:
                return None
            visited.add(pointer)
            if next_offset == offset:
                next_offset = offset + 2
            resolved = _decode_dns_name(data, pointer, visited)
            if resolved is None:
                return None
            pointed_name, _ = resolved
            if pointed_name:
                labels.append(pointed_name)
            return ".".join(labels), next_offset

        if length & 0xC0:
            return None

        offset += 1
        if offset + length > len(data):
            return None
        label_bytes = data[offset: offset + length]
        if not _is_printable_ascii(label_bytes):
            return None
        labels.append(label_bytes.decode("ascii"))
        offset += length
        next_offset = offset


def _decode_dns_name_list(data: bytes) -> str:
    names = []
    offset = 0

    while offset < len(data):
        decoded = _decode_dns_name(data, offset)
        if decoded is None:
            return ""
        name, offset = decoded
        if name:
            names.append(name)

    return ", ".join(names)


def _decode_ip_list(data: bytes) -> str:
    if not data or len(data) % 4 != 0:
        return ""
    return ", ".join(str(ipaddress.IPv4Address(data[index:index + 4])) for index in range(0, len(data), 4))


def _decode_option_43(data: bytes) -> str:
    parts = []
    offset = 0

    while offset < len(data):
        code = data[offset]
        offset += 1
        if code == 0:
            continue
        if code == 255:
            break
        if offset >= len(data):
            return ""
        length = data[offset]
        offset += 1
        if offset + length > len(data):
            return ""
        payload = data[offset: offset + length]
        offset += length

        decoded_payload = ""
        if _is_printable_ascii(payload):
            decoded_payload = payload.decode("ascii")
        if not decoded_payload:
            decoded_payload = f"0x{payload.hex()}"
        parts.append(f"subopt {code}: {decoded_payload}")

    return "; ".join(parts)


def _decode_option_120(data: bytes) -> str:
    if len(data) < 2:
        return ""
    encoding = data[0]
    payload = data[1:]
    if encoding == 0:
        return _decode_dns_name_list(payload)
    if encoding == 1:
        return _decode_ip_list(payload)
    return ""


def decode_dhcp_option_value(option_num: object, raw_value: object) -> str:
    try:
        number = int(str(option_num or "").strip())
    except ValueError:
        return ""

    data = _hex_bytes_from_value(raw_value)
    if data is None:
        return ""

    if number == 43:
        return _decode_option_43(data)
    if number == 120:
        return _decode_option_120(data)
    return ""
