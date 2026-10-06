# modules/bulk_ping.py
import argparse
import errno
import ipaddress
import re
import shutil
import socket
from concurrent.futures import ThreadPoolExecutor
from logging import Logger
from subprocess import PIPE, STDOUT, Popen
from typing import Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

from rich.markup import escape

from core.base import BaseModule, CliResult, ScriptContext, cli_exit_code
from utils.cli_input import read_objects
from utils.user_input import press_any_key, read_user_input
from utils.display import console, get_global_color_scheme, print_table_data, table_columns
from utils.file_io import queue_save
from utils.validation import ipv6_form_problem, is_fqdn, parse_tcp_ports


BATCH_SIZE = 100  # hosts pinged and probed at once
TCP_TIMEOUT = 3.0  # seconds a TCP connection attempt may take
MAX_PING_HOSTS = 65534  # a /16; an IPv6 /112 expands to 65,535 hosts and is allowed as well
MAX_TCP_HOSTS = 1024  # per run, a /22 or an IPv6 /118
NOT_RUN = "not run"  # the Result of a host whose ICMP check was skipped
NO_ROUTE = "NO ROUTE"  # the Result of an IPv6 ping from a host with no IPv6 route, or with IPv6 switched off

_NOT_A_TARGET = "not an IP address, network or host name"
_TOO_MANY_HOSTS = f"more than {MAX_PING_HOSTS:,} hosts; ping at most a /16"
_TOO_MANY_HOSTS_V6 = f"more than {MAX_PING_HOSTS + 1:,} hosts; ping at most a /112"
_TOO_MANY_TCP_HOSTS = f"more than {MAX_TCP_HOSTS:,} hosts with --tcp; test at most a /22"
_TOO_MANY_TCP_HOSTS_V6 = f"more than {MAX_TCP_HOSTS:,} hosts with --tcp; test at most a /118"
_LINK_LOCAL = "link-local IPv6 needs an interface: ping one address with %<interface> appended, e.g. %eth0"
_NO_SUCH_HOST = "no such host"
_TCP_PROMPT = "TCP ports to test as well, e.g. 22,443 (Enter for ping only): "
_TCP_SKIPPED = f"TCP test needs at most {MAX_TCP_HOSTS:,} hosts (a /22); pinging only."
_PING_MISSING = "cn: ping: the 'ping' command is not installed"

_PING_RECEIVED_RE = re.compile(r"(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets\s+)?received")
# What iputils prints, with no counts, when an IPv6 ping cannot leave the host: no IPv6 route, or no IPv6 at all.
_NO_ROUTE_TEXTS = ("Network is unreachable", "Address family not supported")
_DIGITS_AND_DOTS = re.compile(r"[0-9.]+")  # never a host name, even when it is not an IPv4 address

# (host as typed, address to ping and connect to): a name is resolved once, an address is its own.
Target = Tuple[str, str]
Row = Dict[str, str]
# (input type, the line as typed, its new hosts): what the menu summarises large subnets from.
UserInput = Tuple[str, str, List[str]]


def tcp_probe(address: str, port: int, timeout: float = TCP_TIMEOUT) -> str:
    """
    Try one TCP connection and say how it ended.

    @return: ``open`` (connected), ``closed`` (refused or reset; a rejecting firewall looks the
        same), ``timeout``, ``unreachable`` (no route to the host or network, or, for an IPv6
        address, no IPv6 on this host) or ``error`` (any other failure, such as running out of
        file descriptors).
    """
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return "open"
    except (ConnectionRefusedError, ConnectionResetError):
        return "closed"
    except (TimeoutError, socket.timeout):
        return "timeout"
    except OSError as exc:
        # EAFNOSUPPORT: the host has IPv6 switched off; it never occurs for an IPv4 address.
        unreachable = (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EAFNOSUPPORT)
        return "unreachable" if exc.errno in unreachable else "error"


def _tcp_column(port: int) -> str:
    return f"TCP {port}"


def _row(host: str, address: str, result: str, tcp_ports: Sequence[int], outcomes: Optional[Mapping[Tuple[str, int], str]] = None) -> Row:
    """One result row: Host, Address, Result and a ``TCP <port>`` column for every port tested."""
    row = {"Host": host, "Address": address, "Result": result}
    for port in tcp_ports:
        row[_tcp_column(port)] = (outcomes or {}).get((host, port), "")
    return row


def _icmp_answered(row: Mapping[str, str]) -> bool:
    return str(row.get("Result", "")).startswith("OK")


def _tcp_answered(row: Mapping[str, str], tcp_ports: Sequence[int]) -> bool:
    """Something answered on a port: connected, or refused or reset the connection."""
    return any(row.get(_tcp_column(port)) in ("open", "closed") for port in tcp_ports)


def _probe_failed(row: Mapping[str, str], tcp_ports: Sequence[int]) -> bool:
    """A probe that could not run, as opposed to one that got no answer."""
    return str(row.get("Result", "")).startswith("ERROR") or any(
        row.get(_tcp_column(port)) == "error" for port in tcp_ports
    )


def _fold_result(hosts: Sequence[str], results_by_host: Mapping[str, Row]) -> str:
    """What the menu's fold line says: ``NO ROUTE`` when every host it stands for had none, else ``NO RESPONSE``."""
    no_route = all(results_by_host.get(host, {}).get("Result") == NO_ROUTE for host in hosts)
    return NO_ROUTE if no_route else "NO RESPONSE"


def _lookup_address(name: str) -> Optional[str]:
    """
    The address to ping for ``name``: its IPv4 address, or, only when it has none, its IPv6 address.

    A dual-stack name is therefore pinged at the same address as before IPv6 was supported, and a
    name with an AAAA record only is pinged over IPv6. None when neither lookup finds it.
    """
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            return str(socket.getaddrinfo(name, None, family)[0][4][0])
        except (OSError, UnicodeError):  # gaierror, or a name the resolver cannot encode
            continue
    return None


def _is_ip_literal(host: str) -> bool:
    """An address, never a name: digits and dots (even when no IPv4 address) or an IPv6 spelling (colons)."""
    return ":" in host or _DIGITS_AND_DOTS.fullmatch(host) is not None


def _is_ip(word: str) -> bool:
    """
    An address of either family that can be pinged as typed: not a prefix, not an IPv4-mapped
    IPv6 address, and a link-local IPv6 address only with its interface (``fe80::1%eth0``).
    """
    if "/" in word:  # a prefix, or a zone that swallowed one (Python before 3.14 reads fe80::1%eth0/64 as an address)
        return False
    try:
        address = ipaddress.ip_address(word)
    except ValueError:
        return False
    if ipv6_form_problem(word, zone_ok=True):
        return False
    return "%" in word or not (address.version == 6 and address.is_link_local)


def _tcp_limit_reason(text: str) -> str:
    """Why a line takes the ``--tcp`` run past its host limit; an IPv6 line is told the /118 instead of the /22."""
    return _TOO_MANY_TCP_HOSTS_V6 if ":" in text else _TOO_MANY_TCP_HOSTS


def _typed_lines(ctx: ScriptContext) -> Iterator[str]:
    """What the user types at the target prompt, up to the first empty line."""
    while True:
        line = read_user_input(ctx, "").strip()
        if not line:
            return
        yield line


def _print_rejected(ctx: ScriptContext, target: str, reason: str) -> None:
    colors = get_global_color_scheme(ctx.cfg)
    console.print(f"[{colors['warning']}]{escape(f'{target}: {reason}')}[/]")


class BulkPingModule(BaseModule):
    """
    Module to perform a bulk ping, and optionally a TCP port check, against a list of
    user-supplied IPv4 and IPv6 addresses, hostnames, and subnets, with smart display logic for
    large subnets. ``ping`` picks the address family from the address; a host name is pinged at
    its IPv4 address, or at its IPv6 address when it has no IPv4 one. An IPv6 ping from a host
    with no IPv6 route (or with IPv6 switched off) reads ``NO ROUTE``, which is not a failure.
    """
    cli_name = "ping"

    @property
    def menu_key(self) -> str:
        return "6"

    @property
    def menu_title(self) -> str:
        return "Bulk PING"

    @property
    def visibility_config_key(self) -> Optional[str]:
        return None

    def run(self, ctx: ScriptContext) -> None:
        """
        Runs multiple parallel ping processes against a list of user-supplied targets.
        """
        # The subnet size below which we always display all results.
        display_threshold = 32

        logger = ctx.logger
        colors = get_global_color_scheme(ctx.cfg)
        logger.info("Request Type - Bulk PING")
        if shutil.which("ping") is None:
            logger.error("'ping' command not found. Aborting.")
            press_any_key(ctx)
            return

        console.print(
            "\n"
            f"[{colors['description']}]Enter IPs/FQDNs/Subnets to ping, one per line.[/]\n"
            f"[{colors['header']} {colors['bold']}]Example formats[/]: 192.168.0.1, 2001:db8::1, example.com, 192.168.0.0/24\n"
            f"[{colors['warning']}]Subnets will be expanded and every host IP will be pinged.[/]\n"
            f"[{colors['description']}]Empty input line starts the ping process.[/]\n"
        )

        # --- User Input and Target Parsing ---
        # The parser returns the original input structure and a flat list of all hosts.
        user_inputs, hosts_to_ping = self._parse_user_input(ctx)
        targets, unresolvable = self._address_targets(hosts_to_ping)
        for name in unresolvable:
            _print_rejected(ctx, name, _NO_SUCH_HOST)

        if not targets:
            logger.info("Bulk PING - No valid hosts to ping.")
            press_any_key(ctx)
            return

        gone = set(unresolvable)
        user_inputs = [
            (input_type, original_value, kept)
            for input_type, original_value, hosts_in_item in user_inputs
            if (kept := [host for host in hosts_in_item if host not in gone])
        ]
        logger.info(f"User input - Pinging {len(targets)} unique hosts.")

        tcp_ports = self._ask_tcp_ports(ctx, len(targets))

        # --- HOOK: Allow plugins to modify the raw results list (run by _ping_all) ---
        final_results = self._ping_all(ctx, targets, tcp_ports)

        if not final_results:
            console.print(f"[{colors['info']}]Ping process completed with no results to display.[/]")
            press_any_key(ctx)
            return

        # The filtered list is for the screen ONLY; the report gets every row.
        display_data = self._display_rows(user_inputs, final_results, tcp_ports, display_threshold)
        print_table_data(ctx, {"Bulk PING Results": display_data})

        self._save_report(ctx, final_results)

        press_any_key(ctx)

    def run_cli(self, ctx: ScriptContext, args: argparse.Namespace) -> CliResult:
        """
        ``cn ping``: ping, and with ``--tcp`` also connect to, the hosts named on the command line,
        in ``--file`` and/or on stdin. A name is resolved once; the address is used for both tests.

        Returns the sections ``ping`` (one row per host, never folded: ``Host``, ``Address``,
        ``Result`` and a ``TCP <port>`` column for each port, in the order given) and ``not_found``
        (``object``/``reason`` for each target that cannot be used or whose name does not resolve);
        both keys are always present. Exit status: 0 when a host answered ICMP (with ``--tcp``: a
        port was open), 1 when none did (an IPv6 target the host has no route to, ``NO ROUTE``,
        is no answer and no failure), 2 for an unusable target, 3 when a probe could not run.
        Never prompts.
        """
        ctx.logger.info("Request Type - Bulk PING (command line)")
        try:
            objects = read_objects(args.objects, args.file)
        except (OSError, UnicodeDecodeError) as exc:  # a file that is missing, a directory or not UTF-8
            source = "standard input" if args.file in (None, "-") else args.file
            reason = getattr(exc, "strerror", None) or exc
            console.print(f"cn: ping: cannot read {source}: {reason}", markup=False, soft_wrap=True)
            return CliResult(2, {})
        if not objects:
            console.print("cn: ping: no targets given; see cn ping --help", markup=False, soft_wrap=True)
            return CliResult(2, {})

        tcp_ports: Tuple[int, ...] = tuple(args.tcp or ())
        icmp = shutil.which("ping") is not None
        if not icmp:
            if not tcp_ports:
                console.print(_PING_MISSING, markup=False, soft_wrap=True)
                return CliResult(2, {})
            console.print(f"{_PING_MISSING}; ICMP skipped", markup=False, soft_wrap=True)

        not_found: List[Dict[str, str]] = []
        _, hosts = self._expand_targets(
            objects,
            lambda target, reason: not_found.append({"object": target, "reason": reason}),
            MAX_TCP_HOSTS if tcp_ports else None,
        )
        invalid = bool(not_found)
        targets, unresolvable = self._address_targets(hosts)
        not_found.extend({"object": name, "reason": _NO_SUCH_HOST} for name in unresolvable)

        rows = self._ping_all(ctx, targets, tcp_ports, icmp) if targets else []
        self._save_report(ctx, rows)

        if tcp_ports:
            found = any(row.get(_tcp_column(port)) == "open" for row in rows for port in tcp_ports)
        else:
            found = any(_icmp_answered(row) for row in rows)
        failed = any(_probe_failed(row, tcp_ports) for row in rows)
        return CliResult(cli_exit_code(found, invalid, failed), {"ping": rows, "not_found": not_found})

    def _ask_tcp_ports(self, ctx: ScriptContext, host_count: int) -> Tuple[int, ...]:
        """The menu's second question: which TCP ports to test as well (Enter for none)."""
        colors = get_global_color_scheme(ctx.cfg)
        if host_count > MAX_TCP_HOSTS:
            console.print(f"[{colors['warning']}]{_TCP_SKIPPED}[/]")
            return ()
        while True:
            answer = read_user_input(ctx, _TCP_PROMPT).strip()
            if not answer:
                return ()
            try:
                return parse_tcp_ports(answer)
            except ValueError as exc:
                console.print(f"[{colors['error']}]{escape(str(exc))}[/]")

    def _parse_user_input(self, ctx: ScriptContext) -> Tuple[List[UserInput], List[str]]:
        """
        Reads target lines until an empty one and parses them into a flat list of unique hosts,
        preserving order, together with the structured input for smart display. A line that cannot
        be used is reported as ``<target>: <reason>`` as soon as it is typed.

        Returns:
            A tuple containing:
            1. A list of tuples: (input_type, original_value, list_of_hosts_from_it)
            2. A flat list of all unique hosts to be pinged.
        """
        return self._expand_targets(_typed_lines(ctx), lambda target, reason: _print_rejected(ctx, target, reason))

    def _expand_targets(
        self,
        lines: Iterable[str],
        reject: Callable[[str, str], None],
        host_limit: Optional[int] = None,
    ) -> Tuple[List[UserInput], List[str]]:
        """
        Parse each target line with ``_parse_target``, keeping the first occurrence of every host.

        A line that cannot be used goes to ``reject(line, reason)``. With ``host_limit``, a line
        that would take the run's unique hosts past it is rejected whole, and a later, smaller one
        may still fit.
        """
        user_inputs: List[UserInput] = []
        all_hosts: List[str] = []
        seen = set()

        for text in lines:
            input_type, hosts, reason = self._parse_target(text)
            new_hosts = [host for host in dict.fromkeys(hosts) if host not in seen]
            if reason is None and host_limit is not None and len(all_hosts) + len(new_hosts) > host_limit:
                reason = _tcp_limit_reason(text)
            if reason:
                reject(text, reason)
                continue

            seen.update(new_hosts)
            all_hosts.extend(new_hosts)
            # If we found any valid hosts on this line, record the user's input structure
            if new_hosts:
                user_inputs.append((input_type, text, new_hosts))

        return user_inputs, all_hosts

    def _parse_target(self, text: str) -> Tuple[str, List[str], Optional[str]]:
        """
        Classify one target line and expand it.

        Tried in order: an IPv4-mapped IPv6 address or network (refused, with the IPv4 form to
        use); an IPv4 or IPv6 address or network; digits and dots that are not IPv4 (rejected,
        although they would pass for a host name); a host name; a comma/space list of addresses
        (a single one with a zone ID, ``fe80::1%eth0``, is such a list). A single address, bare
        or /32 or /128, is used as given; only a subnet loses its loopback, multicast and reserved
        addresses. An IPv4 subnet may hold up to a /16, an IPv6 one up to a /112. A link-local
        IPv6 address or prefix needs an interface, which only a single address can carry, so the
        others are refused; a zone ID is used as typed.

        Returns:
            (input_type, hosts, reason): ``reason`` is None when the line is usable, otherwise
            ``hosts`` is empty and ``reason`` says why, without repeating the line.
        """
        mapped = ipv6_form_problem(text, zone_ok=True)
        if mapped:
            return "single", [], mapped

        try:
            # A zone ID is never parsed as part of a network: Python releases differ on what that gives.
            network = None if "%" in text else ipaddress.ip_network(text, strict=False)
        except ValueError:
            network = None
        if network is not None:
            ipv6 = network.version == 6
            if ipv6 and network.network_address.is_link_local:
                return ("single" if network.num_addresses == 1 else "subnet"), [], _LINK_LOCAL
            if network.num_addresses == 1:
                return "single", [str(network.network_address)], None
            if network.num_addresses > MAX_PING_HOSTS + 2:  # network and broadcast address; a /112 is as many
                return "subnet", [], _TOO_MANY_HOSTS_V6 if ipv6 else _TOO_MANY_HOSTS
            usable = [str(ip) for ip in network.hosts() if not (ip.is_loopback or ip.is_multicast or ip.is_reserved)]
            return "subnet", usable, None

        if _DIGITS_AND_DOTS.fullmatch(text):
            return "single", [], _NOT_A_TARGET
        if is_fqdn(text):
            return "single", [text], None

        addresses = [word for word in text.replace(",", " ").split() if _is_ip(word)]
        if not addresses:
            return "single", [], _NOT_A_TARGET
        return ("list" if len(addresses) > 1 else "single"), addresses, None

    def _resolve(self, names: List[str]) -> Tuple[Dict[str, str], List[str]]:
        """
        Resolve host names to addresses, each name once, in a pool of at most a batch of workers.
        A name gets its IPv4 address; only a name with none gets its IPv6 address (``_lookup_address``).

        Returns:
            (name -> address for the names that resolve, the names that do not, in input order)
        """
        if not names:
            return {}, []
        with ThreadPoolExecutor(max_workers=min(BATCH_SIZE, len(names))) as pool:
            answers = list(pool.map(_lookup_address, names))
        addresses = {name: address for name, address in zip(names, answers) if address}
        return addresses, [name for name, address in zip(names, answers) if not address]

    def _address_targets(self, hosts: List[str]) -> Tuple[List[Target], List[str]]:
        """Pair every host with the address to test: its own, or the one its name resolves to."""
        addresses, unresolvable = self._resolve([host for host in hosts if not _is_ip_literal(host)])
        gone = set(unresolvable)
        return [(host, addresses.get(host, host)) for host in hosts if host not in gone], unresolvable

    def _ping_all(
        self, ctx: ScriptContext, targets: List[Target], tcp_ports: Sequence[int], icmp: bool = True
    ) -> List[Row]:
        """
        Test the targets a batch at a time, then let the ``process_data`` hook change the rows.

        Returns one row per target in the order given (see ``_row``); a target the batch did not
        report on is an ``ERROR`` row.
        """
        colors = get_global_color_scheme(ctx.cfg)
        results: List[Row] = []
        total_batches = -(-len(targets) // BATCH_SIZE)
        for number, start in enumerate(range(0, len(targets), BATCH_SIZE), 1):
            batch = targets[start:start + BATCH_SIZE]
            ending = f" batch {number} out of {total_batches}" if total_batches > 1 else "..."

            with console.status(f"[{colors['description']}]Pinging hosts{ending}[/]", spinner="dots12"):
                batch_rows = {row["Host"]: row for row in self._ping_batch(batch, ctx.logger, tcp_ports, icmp)}
            # Ensure the results are added in the same order as the batch was given.
            for host, address in batch:
                results.append(batch_rows[host] if host in batch_rows else _row(host, address, "ERROR (No Result)", tcp_ports))

        return self.execute_hook('process_data', ctx, results)

    def _ping_batch(
        self, batch: List[Target], logger: Logger, tcp_ports: Sequence[int] = (), icmp: bool = True
    ) -> List[Row]:
        """
        Pings a batch of hosts in parallel and, for each of ``tcp_ports``, connects to every
        host's address while the pings run. Returns one row per host (see ``_row``), or nothing
        when ``ping`` cannot be started.
        """
        processes: Dict[str, Popen] = {}

        if icmp:
            for host, address in batch:
                # Using -n to prevent name resolution, -w3 for 3-sec timeout, -c2 for 2 packets
                command = ["ping", "-n", "-w3", "-c2", address]
                try:
                    processes[host] = Popen(
                        command,
                        stdout=PIPE,
                        stderr=STDOUT,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                    )
                except FileNotFoundError:
                    logger.error("'ping' command not found.")
                    return []

        outcomes: Dict[Tuple[str, int], str] = {}
        if tcp_ports:
            with ThreadPoolExecutor(max_workers=min(BATCH_SIZE, len(batch) * len(tcp_ports))) as pool:
                probes = {
                    (host, port): pool.submit(tcp_probe, address, port) for host, address in batch for port in tcp_ports
                }
                outcomes = {key: probe.result() for key, probe in probes.items()}

        address_of = dict(batch)
        statuses: Dict[str, str] = {}
        for host, proc in processes.items():
            output, _ = proc.communicate()
            statuses[host] = self._classify_ping_result(proc.returncode, output, ipv6=":" in address_of[host])

        # Without ICMP there is no process, so no status: the check was not run.
        return [_row(host, address, statuses.get(host, NOT_RUN), tcp_ports, outcomes) for host, address in batch]

    def _display_rows(
        self, user_inputs: List[UserInput], results: List[Row], tcp_ports: Sequence[int], display_threshold: int
    ) -> List[Row]:
        """
        The rows for the screen: every host of a single address, a list or a small subnet; for a
        large subnet only the hosts that answered (ICMP reply, or a TCP port open or closed), then
        one line for the rest. That line reads ``NO ROUTE`` when every host it stands for had no
        route (an IPv6 subnet pinged from a host without IPv6), else ``NO RESPONSE``.
        """
        results_by_host = {item['Host']: item for item in results}
        display_data: List[Row] = []

        for input_type, original_value, hosts_in_item in user_inputs:
            # Always show single hosts/IPs or small subnets fully
            if input_type == 'single' or len(hosts_in_item) <= display_threshold:
                for host in hosts_in_item:
                    display_data.append(results_by_host[host] if host in results_by_host else _row(host, "", "N/A", tcp_ports))
                continue

            # This is a large subnet. We will ONLY display the responsive hosts.
            responsive = [
                results_by_host[host] for host in hosts_in_item
                if host in results_by_host
                and (_icmp_answered(results_by_host[host]) or _tcp_answered(results_by_host[host], tcp_ports))
            ]
            if responsive:
                # If we found any responsive hosts, display them.
                display_data.extend(responsive)

                # Then, add a single summary line for all the non-responsive hosts.
                answered = {row["Host"] for row in responsive}
                silent = [host for host in hosts_in_item if host not in answered]
                if silent:
                    summary = f"(... and {len(silent)} other hosts in {original_value})"
                    display_data.append(_row(summary, "", _fold_result(silent, results_by_host), tcp_ports))
            else:
                # If there were ZERO responsive hosts, just show one summary line for the whole subnet.
                summary = f"All {len(hosts_in_item)} hosts in {original_value}"
                display_data.append(_row(summary, "", _fold_result(hosts_in_item, results_by_host), tcp_ports))

        return display_data

    def _save_report(self, ctx: ScriptContext, rows: List[Row]) -> None:
        """Queue the complete, unfiltered rows as the "Bulk PING" sheet when ``report_auto_save`` is on."""
        if ctx.cfg["report_auto_save"] and rows:
            columns = table_columns(rows)
            save_data_lol = [[row.get(column, '') for column in columns] for row in rows]
            queue_save(ctx, columns, save_data_lol, sheet_name="Bulk PING", index=False, force_header=True)

    def _classify_ping_result(self, returncode: Optional[int], output: str, *, ipv6: bool = False) -> str:
        """
        Classify ping results, keeping any reply as success while reporting probe loss.

        An IPv6 ping that printed no counts but says ``Network is unreachable`` or ``Address family
        not supported`` never left this host: it is ``NO ROUTE``, neither an answer nor a failure.
        An IPv4 ping with the same output stays ``ERROR``.
        """
        counts = self._extract_ping_counts(output)
        if counts is not None:
            transmitted, received = counts
            if received >= transmitted:
                return "OK"
            if received > 0:
                return f"OK ({received}/{transmitted} replies)"
            return "NO RESPONSE"

        if ipv6 and any(text in str(output or "") for text in _NO_ROUTE_TEXTS):
            return NO_ROUTE
        if returncode == 0:
            return "OK"
        if returncode == 1:
            return "NO RESPONSE"
        return "ERROR"  # iputils exits 2 for "other error" (no permission, bad address): not "no reply"

    def _extract_ping_counts(self, output: str) -> Optional[tuple[int, int]]:
        match = _PING_RECEIVED_RE.search(str(output or ""))
        if not match:
            return None
        return int(match.group(1)), int(match.group(2))
