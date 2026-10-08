import ipaddress
import re
from typing import Optional, Tuple


# Precise match to IP, however search takes over 60 seconds
# ip_regexp = re.compile(r'(?:(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|)\d)\.?\b){4}')
# Generic 4 1-3 numbers, lots of false positives but search takes 32 seconds
ip_regexp = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

subnet_regexp = re.compile(
    r"(?:(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|)\d)\.?\b){4}\/((?:[1-2][0-9])|(?:3[0-2])|(?:[0-9]\b))"
)

str_ip_subnet_regexp = re.compile(
    r".*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^\d]*(?:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\/(\d{1,2}))"
)

# A more precise IP validation regex for internal functions that need to be sure.
# Uses fullmatch and word boundaries to avoid matching parts of larger numbers.
PRECISE_IP_REGEXP = re.compile(r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d)")

# Company-specific regex for extracting a site code from a device hostname.
# This should be customized to your environment's naming convention.
# Example: Extracts 'SFO-R01' from 'cr01.sfo-r01.us.example.com'
# Site-code conventions differ between organisations, so none is hard-coded here. The
# defaults below are permissive; `.cn` can tighten them via the ``[site]`` section:
#   code_pattern     - regex the whole site code must match (case-insensitive)
#   comment_pattern  - regex template matched against Infoblox network comments; ``{site}``
#                      is replaced by the escaped site code. Used for the WAPI ``comment:~=``
#                      query and for the local filter, so keep it to syntax both accept
#                      (anchors, groups, bracket classes; avoid look-arounds).
#   hostname_pattern - regex template used to find a site's devices in config files;
#                      placeholders ``{site}``, ``{site_compact}`` (hyphens removed) and
#                      ``{country}`` (first two letters of the first subnet comment).
DEFAULT_SITE_CODE_PATTERN = r"^[A-Za-z0-9][\w.-]{1,63}$"
DEFAULT_SITE_COMMENT_PATTERN = r"(^|[^A-Za-z0-9_-]){site}($|[^A-Za-z0-9_-])"
DEFAULT_SITE_HOSTNAME_PATTERN = r"\b{site_compact}[-_\w]*\b|\b{site}[-_\w]*\b"


def validate_and_normalize_mac_address(mac: str) -> Optional[str]:
    # Remove any whitespace and convert to lowercase
    mac = mac.strip().lower()

    # Define regex patterns for each format
    patterns = [
        r'^([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})$',  # xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx
        r'^([0-9a-f]{4})\.([0-9a-f]{4})\.([0-9a-f]{4})$',    # xxxx.xxxx.xxxx
        r'^([0-9a-f]{12})$'                         # xxxxxxxxxxxx
    ]

    for pattern in patterns:
        match = re.match(pattern, mac)
        if match:
            if len(match.groups()) == 6:
                # Already in the correct format, just uppercase it
                return ':'.join(group.upper() for group in match.groups())
            elif len(match.groups()) == 3:
                # xxxx.xxxx.xxxx format
                mac_parts = ''.join(match.groups())
                return ':'.join(mac_parts[i:i+2].upper() for i in range(0, 12, 2))
            else:
                # xxxxxxxxxxxx format
                return ':'.join(mac[i:i+2].upper() for i in range(0, 12, 2))

    # Return None for invalid MAC addresses
    return None


def validate_ip(ip: str) -> bool:
    """
    Validates an IP address using a regular expression.

    @param ip: IP address to validate

    @return: bool: True if the IP address is valid, False otherwise.
    """
    if re.fullmatch(ip_regexp, ip):
        return True

    return False


# Two IPv6 spellings Infoblox has no object for. The hint after "use" is the form to type instead
# and never the object itself, so a reason fits "<object>: <reason>" lines and a line on its own.
IPV4_MAPPED = "IPv4-mapped IPv6 address; use {ipv4}"
ZONE_ID = "Infoblox stores no zone ID ({zone}); use {address}"


def ipv6_form_problem(text: str, *, zone_ok: bool = False) -> str:
    """
    Names the IPv6 spelling of ``text`` that Infoblox cannot look up, with the form to type instead.

    Two spellings are refused: an IPv4-mapped address or prefix (``::ffff:10.20.0.5``, which
    gives ``IPV4_MAPPED`` with the IPv4 object) and one with a zone ID (``2001:db8::5%eth0``,
    which gives ``ZONE_ID`` with the object as typed, without its zone). The mapped form is
    checked first, so ``is_reserved`` (which Python 3.10 and 3.14 answer differently for it) never
    decides. A caller that works with the zone, such as ``ping``, passes ``zone_ok=True``.

    The zone is found in the text and the rest is parsed without it, so the outcome does not
    depend on how a Python version treats a scope ID inside ``IPv6Network``.

    @param text: One object as typed: an address or an ``address/length`` prefix.
    @param zone_ok: True when a zone ID is acceptable to the caller.
    @return: The reason, or ``""`` for IPv4 text, a plain IPv6 object and malformed text (the
             caller reports that with its own reason).
    """
    bare, has_zone, rest = text.partition("%")
    zone, slash, length = rest.partition("/")
    if has_zone and ("/" in bare or not zone or "%" in zone):  # fe80::/64%eth0, 2001:db8::5%, fe80::1%a%b
        return ""
    bare_text = bare + ("/" + length if slash else "")
    try:
        network = ipaddress.ip_network(bare_text, strict=False)
    except ValueError:
        return ""
    if network.version != 6:
        return ""
    mapped = network.network_address.ipv4_mapped
    if mapped is not None:
        ipv4 = str(mapped) if network.prefixlen == 128 else f"{mapped}/{network.prefixlen - 96}"
        return IPV4_MAPPED.format(ipv4=ipv4)
    if has_zone and not zone_ok:
        return ZONE_ID.format(zone=f"%{zone}", address=bare_text)
    return ""


def _compile_or_default(pattern: Optional[str], default: str) -> "re.Pattern[str]":
    """Compile a configured regex, falling back to ``default`` when it is empty or invalid."""
    candidate = (pattern or "").strip() or default
    try:
        return re.compile(candidate, re.IGNORECASE)
    except re.error:
        return re.compile(default, re.IGNORECASE)


def is_valid_site(sitecode: str, pattern: Optional[str] = None) -> bool:
    """
    Validates a site code against ``pattern`` (the ``[site] code_pattern`` setting) or, when
    no pattern is configured, against the permissive default: 2-64 characters made of
    letters, digits, ``.``, ``_`` and ``-``.

    @param sitecode: Site code to validate.
    @param pattern: Optional regex the whole code must match (case-insensitive).
    @return: True if the site code is valid, False otherwise.
    """
    if not sitecode:
        return False
    return _compile_or_default(pattern, DEFAULT_SITE_CODE_PATTERN).fullmatch(sitecode) is not None


def site_code_format_hint(pattern: Optional[str] = None) -> str:
    """Human-readable description of the accepted site code format, for prompts."""
    configured = (pattern or "").strip()
    if configured:
        return f"must match {configured}"
    return "2-64 letters, digits, '.', '_' or '-'"


def _render_site_template(template: Optional[str], default: str, **fields: str) -> str:
    """Fill a ``{placeholder}`` template with regex-escaped values; fall back to ``default``."""
    candidate = (template or "").strip() or default
    escaped = {key: re.escape(value) for key, value in fields.items()}
    try:
        rendered = candidate.format(**escaped)
        re.compile(rendered, re.IGNORECASE)
        return rendered
    except (KeyError, IndexError, ValueError, re.error):
        return default.format(**escaped)


def site_comment_regex(sitecode: str, template: Optional[str] = None) -> str:
    """Regex that an Infoblox network comment must match to belong to ``sitecode``."""
    return _render_site_template(template, DEFAULT_SITE_COMMENT_PATTERN, site=sitecode)


def site_hostname_regex(sitecode: str, template: Optional[str] = None, country: Optional[str] = None) -> str:
    """Regex that finds ``sitecode``'s devices in configuration files."""
    return _render_site_template(
        template,
        DEFAULT_SITE_HOSTNAME_PATTERN,
        site=sitecode,
        site_compact=sitecode.replace("-", ""),
        country=country or "",
    )


def is_fqdn(hostname: str) -> bool:
    """
    Validates a fully qualified domain name (FQDN) based on its structure and length.

    @param hostname: Hostname to validate.
    @return: True if the hostname is a valid FQDN, False otherwise.
    """
    if not 1 < len(hostname) < 253:
        return False

    # Remove trailing dot
    if hostname.endswith("."):
        hostname = hostname[0:-1]

    #  Split hostname into list of DNS labels
    labels = hostname.split(".")

    #  Define pattern of DNS label
    #  Can begin and end with a number or letter only
    #  Can contain hyphens, a-z, A-Z, 0-9
    #  1 - 63 chars allowed
    fqdn_re = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

    # Check that all labels match that pattern.
    return all(fqdn_re.match(label) for label in labels)


# The one wording for a bad ``--tcp`` list, shared by the CLI (argparse) and the menu prompt.
MAX_TCP_PORTS = 5
PORT_LIST_MESSAGE = "'{text}' is not a port list: use up to 5 ports from 1 to 65535, separated by commas"


def parse_tcp_ports(text: str) -> Tuple[int, ...]:
    """
    Parse a comma-separated TCP port list such as ``"22, 443,22"``.

    Spaces around each port are stripped and duplicates are dropped, keeping the first
    occurrence's order. At most ``MAX_TCP_PORTS`` distinct ports, each 1-65535.

    @param text: The list as typed.
    @return: The ports, in order, without duplicates.
    @raise ValueError: ``PORT_LIST_MESSAGE`` for an empty, malformed or oversized list.
    """
    ports = []
    for part in text.split(","):
        part = part.strip()
        # ASCII digits only: int() would also take "+22", "٢٢" and "2_2", and a long run of digits.
        if not re.fullmatch(r"[0-9]{1,5}", part) or not 1 <= int(part) <= 65535:
            raise ValueError(PORT_LIST_MESSAGE.format(text=text))
        ports.append(int(part))
    unique = tuple(dict.fromkeys(ports))
    if len(unique) > MAX_TCP_PORTS:
        raise ValueError(PORT_LIST_MESSAGE.format(text=text))
    return unique
