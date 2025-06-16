import re
from typing import Optional


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


def is_valid_site(sitecode: str) -> bool:
    """
    Validates a site code using a regular expression.

    @param sitecode: Site code to validate.
    @return: True if the site code is valid, False otherwise.
    """

    # This regex allows for either three alphanumeric characters followed by a hyphen and another one to four alphanumeric characters,
    # or simply three alphanumeric characters without the hyphen.
    valid_site_regex = "^[a-z0-9]{7}$|^[a-z0-9]{3}$|^[a-z0-9]{3}(?:-[a-z0-9]{1,4})?$"

    if re.search(valid_site_regex, sitecode, re.IGNORECASE):
        return True

    return False


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