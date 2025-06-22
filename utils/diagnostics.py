# utils/diagnostics.py

import re
import ipaddress
import subprocess
import socket
from typing import Dict, Any

from core.base import ScriptContext


def _validate_ip(ip_str: str) -> bool:
    """A simple local validator for IP addresses."""
    if not isinstance(ip_str, str):
        return False
    # This regex is sufficient for basic validation.
    ip_regex = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    return bool(re.match(ip_regex, ip_str))


def _resolve_hostname(ctx: ScriptContext, ip_address: str) -> str:
    """Performs a reverse DNS lookup for a given IP address."""
    if not ip_address or not _validate_ip(ip_address):
        return "Invalid IP"
    try:
        # Use a timeout to prevent long hangs on unresponsive DNS servers.
        socket.setdefaulttimeout(3)
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname.rstrip('.').split('.')[0]
    except (socket.herror, socket.gaierror, socket.timeout):
        ctx.logger.debug(f"DNS resolution failed for {ip_address}")
        return ip_address  # Return the IP itself on failure
    except Exception as e:
        ctx.logger.warning(f"Unexpected error resolving hostname for {ip_address}: {e}")
        return ip_address
    finally:
        socket.setdefaulttimeout(None)  # Reset to default


def _run_mtr_and_get_last_hop(ctx: ScriptContext, target_ip: str) -> Dict[str, Any]:
    """
    Runs MTR, parses the output, and returns the IP, hostname, and number of the last responding hop.
    """
    result = {'pre_last_hop_ip': "Unreachable", 'last_hop_ip': "Unreachable", 'last_hop_hostname': "N/A", 'hop_count': 0, 'mtr_output': ''}

    mtr_base_cmd_str = 'mtr --report --report-cycles=1 --timeout=1 --max-ttl=30 --no-dns '
    mtr_hop_re_str = re.compile(r"^\s*(\d+)\.\|--\s*([\w.-]+|\?\?\?)(?:\s+\(([\d\.]+)\))?\s*")

    mtr_command = mtr_base_cmd_str.split() + [target_ip]
    ctx.logger.info(f"Running MTR: {' '.join(mtr_command)}")

    try:
        process = subprocess.run(
            mtr_command,
            capture_output=True,
            text=True,
            timeout=45,  # Generous timeout for the whole MTR process
            check=False
        )
        mtr_output = process.stdout
    except FileNotFoundError:
        ctx.logger.error(f"MTR command not found. Ensure '{mtr_base_cmd_str.split()[0]}' is in system PATH.")
        result['last_hop_ip'] = "MTR_NOT_FOUND"
        return result
    except subprocess.TimeoutExpired:
        ctx.logger.warning(f"MTR command timed out for {target_ip}")
        result['last_hop_ip'] = "MTR_TIMEOUT"
        return result
    except Exception as e:
        ctx.logger.error(f"An unexpected error occurred while running MTR for {target_ip}: {e}", exc_info=True)
        result['last_hop_ip'] = "MTR_EXEC_ERROR"
        return result

    valid_hops = []
    result['mtr_output'] = mtr_output
    for line in mtr_output.splitlines():
        match = re.match(mtr_hop_re_str, line)
        if match:
            # Group 2 is display name (host or IP or ???), Group 3 is IP in parens (optional)
            display_name, ip_in_parens = match.group(2), match.group(3)
            hop_ip = ip_in_parens if ip_in_parens and _validate_ip(ip_in_parens) else display_name

            if hop_ip != "???" and _validate_ip(hop_ip):
                valid_hops.append({'hop_num': int(match.group(1)), 'ip': hop_ip})

    if valid_hops:
        ctx.logger.debug(f'Dumping valid_hops: {valid_hops}')
        last_hop = valid_hops[-1]
        # If the last hop is the target itself, we are more interested in the hop *before* it.
        if last_hop['ip'] == target_ip and len(valid_hops) > 1:
            result['pre_last_hop_ip'] = valid_hops[-2]['ip']

        result['last_hop_ip'] = last_hop['ip']
        result['last_hop_hostname'] = _resolve_hostname(ctx, last_hop['ip'])
        result['hop_count'] = last_hop['hop_num']

    return result


def process_mtr_target(ctx: ScriptContext, original_target: str) -> Dict[str, Any]:
    """
    Processes a single target: resolves it to an IP and runs MTR.
    Returns a generic dictionary for the core module and plugins.
    """
    result = {
        'target': original_target,
        'pre_last_hop_ip': "Unreachable",
        'last_hop_ip': "Unreachable",
        'last_hop_hostname': "N/A",
        'hop_count': 0,
        'status': "OK",  # Default status, can be overwritten
        'mtr_output': ''
    }

    try:
        # Use ipaddress to handle both single IPs and networks gracefully
        net = ipaddress.ip_network(original_target, strict=False)
        # For networks, pick the first usable host to trace to
        if isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and net.num_addresses > 2:
            mtr_target_ip = str(next(net.hosts()))
        else:
            mtr_target_ip = str(net.network_address)
    except ValueError:
        result['status'] = "Invalid Input"
        return result

    mtr_result = _run_mtr_and_get_last_hop(ctx, mtr_target_ip)
    result.update(mtr_result)

    if result['last_hop_ip'] in ["Unreachable", "MTR_TIMEOUT", "MTR_NOT_FOUND", "MTR_EXEC_ERROR"]:
        result['status'] = result['last_hop_ip']  # The status is the error itself

    return result
