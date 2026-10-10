#!/usr/bin/env python
# Copyright 2024 - Evgeny Danilchenko evdanil@gmail.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import configparser
import ipaddress
import logging
import re
import shlex
import signal
import argparse
import textwrap
import threading
import time
import sys
from datetime import datetime
from pathlib import Path
import warnings
from typing import Any, Callable, Dict, List, NoReturn, Optional, TypeVar

# This suppresses the specific CryptographyDeprecationWarning from paramiko
# which can be noisy on some systems.
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except ImportError:
    # If cryptography is not installed, we don't need to do anything.
    pass

# --- Core Application Imports ---
from cn_tool import cn_buildstamp
from cn_tool.core.base import BaseModule, ScriptContext
from cn_tool.core.event_bus import EventBus
from cn_tool.core.loader import load_modules_and_plugins

# --- Utility Imports ---
from cn_tool.utils import file_io, oscompat
from cn_tool.utils.app_lifecycle import EXIT_INTERRUPTED, exit_now
from cn_tool.utils.config import (
    AUTH_ENV_DEFAULTS,
    BASE_CONFIG_SCHEMA,
    new_parser,
    no_config_file_found,
    normalize_runtime_flags,
    parse_optional_bool,
    read_config,
    setup_from_args,
    user_config_path,
    write_sample_config,
)
from cn_tool.utils.display import console, get_global_color_scheme, set_global_color_scheme
from cn_tool.utils.file_io import start_worker, check_dir_accessibility
from cn_tool.utils.logging import configure_logging
from cn_tool.utils.user_input import read_user_input, read_user_input_live
from cn_tool.utils.cache_status import build_cache_status_line
from cn_tool.utils.cli_input import read_objects
from cn_tool.utils.render import FORMATS, emit
from cn_tool.utils.config_history import parse_since
from cn_tool.utils.ping_history import parse_duration, parse_window
from cn_tool.utils.network_views import parse_view_name
from cn_tool.utils.validation import ipv6_form_problem, is_fqdn, parse_tcp_ports, validate_and_normalize_mac_address
from cn_tool.core.background import start_background_tasks

from rich.markup import escape

# Fix MAC address emoji issue
from rich._emoji_codes import EMOJI

del EMOJI["cd"]


# --- Global Constants ---
# Read at runtime from the ``cn_tool/version`` file (CI-managed). Previously
# the CI injected this string into the source via sed at build time; reading it
# at runtime keeps cn-tool consistent with the bundled CLIs and lets it report a
# real version straight from a git checkout. Falls back to "unknown" only when
# the version file is absent.
# NOTE: the ``VERSION`` name is load-bearing — downstream release patching
# injects an f-string referencing ``{VERSION}`` into this file, so renaming this
# global passes local tests but NameErrors in the patched release.
VERSION = cn_buildstamp.package_version_string()


def _global_config_path() -> Optional[Path]:
    """
    The ``.cn`` at the root of a checkout or an unpacked archive, or None when there is no such root.

    The root is the directory of the script that was started: ``main.py`` and ``cn-tool.py`` sit beside
    ``.cn`` (a symlink to them is followed), and so does a console script's own directory, as before.
    ``python -m cn_tool`` starts the package's ``__main__.py`` one directory below the root, so it uses
    the package directory's parent, and only where a ``main.py`` sits beside the package. A pip install
    has none (the parent is ``site-packages``), so it reads no global ``.cn`` and a stray file there is
    never read.
    """
    started = Path(sys.argv[0]).resolve()
    package_dir = Path(__file__).resolve().parent
    if started != package_dir / "__main__.py":
        return started.parent / ".cn"
    root = package_dir.parent
    return root / ".cn" if (root / "main.py").is_file() else None


def _get_config_paths(args: argparse.Namespace) -> list[Path]:
    """
    Determines the prioritized list of configuration files to read.

    Priority Order (lowest to highest):
    1. Global config (`.cn` at the root of a checkout or an unpacked archive, next to `main.py`;
       also for `python -m cn_tool`, and none for a pip install)
    2. User config (`~/.cn`)
    3. Explicitly provided config file via `-c` argument.

    """

    # Otherwise, build the standard layered list.
    global_config = _global_config_path()
    user_config = user_config_path()

    final_list = [user_config] if global_config is None else [global_config, user_config]

    if args.config:
        final_list.append(Path(args.config).expanduser())

    # The order here is important! User config should override global.
    return final_list


def bootstrap_logging(args: argparse.Namespace) -> logging.Logger:
    """
    A special pre-configuration function to set up logging at the earliest possible moment.
    It only looks for log file and log level settings.
    """

    # Defaults
    log_file = str(Path.home() / "cn.log")
    log_level = "INFO"

    # Find the config files to read using our new helper
    config_paths = _get_config_paths(args)
    existing_files = [f for f in config_paths if f.is_file()]

    if existing_files:
        parser = new_parser()
        try:
            parser.read(existing_files, encoding="utf-8-sig")  # Read all found files in order
        except (configparser.Error, UnicodeDecodeError):
            # A file that cannot be parsed (read_config logs why, into the log this function opens) leaves the
            # defaults, as it does for every other setting.
            parser = new_parser()
        if parser.has_section("logging"):
            log_file = parser.get("logging", "logfile", fallback=log_file)
            log_level = parser.get("logging", "level", fallback=log_level)

    # CLI arguments still have the highest priority
    if args.log_file:
        log_file = args.log_file
    if args.log_level:
        log_level = args.log_level

    return configure_logging(str(Path(log_file).expanduser()), log_level.upper())


# --- Command line ---------------------------------------------------------------------------------
T = TypeVar("T")


def _arg_type(parse: Callable[[str], T]) -> Callable[[str], T]:
    """argparse ``type=`` for a utils parser: its ValueError becomes ``argument --opt: <message>``."""

    def convert(text: str) -> T:
        try:
            return parse(text)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from None

    return convert


# One spec per global option. It feeds the root parser, the copy accepted after the command
# (defaults suppressed, so an option that is not repeated keeps the root's value) and
# _infer_command, which derives the options that take a value from it.
_GLOBAL_OPTIONS: tuple[dict[str, Any], ...] = (
    {"flags": ("-c", "--config"), "default": None, "help": "specify configuration file"},
    {"flags": ("-nc", "--no-cache"), "action": "store_true", "help": "run without cache use"},
    {"flags": ("-t", "--theme"), "choices": ["default", "monochrome", "pastel", "dark"], "help": "color theme"},
    {"flags": ("-l", "--log-file"), "help": "specify logfile"},
    {"flags": ("-r", "--report-file"), "help": "report filename (with a command it also turns --report on)"},
    {"flags": ("-g", "--gpg-file"), "help": "GPG credentials file of the TACACS login"},
    {"flags": ("-v", "--version"), "action": "version", "version": f"cn-tool v{VERSION}", "root_only": True},
    {"flags": ("--log-level",), "choices": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], "help": "Set the logging level."},
)

# The options a command takes unless its spec says otherwise (``needs`` names the spec key that
# must allow it: no --file without objects, no --report for a command that writes no report).
_COMMAND_OPTIONS: tuple[dict[str, Any], ...] = (
    {
        "flags": ("-f", "--file"), "metavar": "FILE", "default": None, "needs": "objects",
        "help": "one object per line; '#' comments and blanks ignored; '-' reads stdin",
    },
    {"flags": ("--format",), "metavar": "FMT", "choices": FORMATS, "default": "table", "help": "table (default), json, md, csv"},
    {
        "flags": ("--report",), "action": "store_true", "needs": "report",
        "help": "also append to the xlsx report (-r FILE chooses it); the menu saves automatically, the command line only with --report",
    },
    # Both write ``args.view``: None = not given, "" = every view, a name = that view. They are command
    # options, not a command's own ``options``, so that no command owns them: ``cn 10.1.2.3 --view prod``.
    {
        "flags": ("--view",), "metavar": "NAME", "type": _arg_type(parse_view_name), "default": None, "needs": "views",
        "help": "search only this network view (cn doctor lists them); default: [api] network_view, else every view",
    },
    {
        "flags": ("--all-views",), "action": "store_const", "dest": "view", "const": "", "needs": "views",
        "help": "search every network view (overrides [api] network_view)",
    },
)

# Registered in one place so a command never needs another edit of main.py; dispatch is by the
# module's ``cli_name``.
CLI_COMMANDS: tuple[tuple[str, str], ...] = (
    ("ip", "IPv4/IPv6 address: subnet, DNS name, status (menu 1)"),
    ("subnet", "subnet: DHCP, DNS, fixed IPs, attributes (menu 2)"),
    ("fqdn", "DNS records containing TEXT, 3+ chars (menu 3)"),
    ("site", "subnets of a site code, or a keyword with -k (menu 4)"),
    ("ping", "ICMP/TCP reachability of hosts and subnets (menu 6)"),
    ("monitor", "ping over a period, with history (menu m)"),
    ("diff", "config changes of devices since a time (menu c)"),
    ("doctor", "configuration, credential and Infoblox checks (menu s)"),
    ("init", "write a starting configuration to ~/.cn"),
)


def _nonempty_text(text: str) -> str:
    """The text itself; an empty one matches every line, which is never what was meant."""
    if not text:
        raise ValueError("TEXT must not be empty")
    return text


# What ``cn <command> --help`` says and which options the command takes. ``menu`` is (menu key,
# menu title) of the module behind the command, None for ``init``, which has no module; a test compares it
# with the real modules. Optional:
#   objects    None for a command that takes no objects (no OBJECT, no --file, nothing is read)
#   report     False for a command that writes no report (no --report, -r is refused)
#   views      True for a command that takes --view and --all-views (the Infoblox lookups and doctor)
#   options    option specs of this command alone, in the _GLOBAL_OPTIONS format
#   exit       the whole exit line, when the codes are not found / none / invalid / Infoblox
#   menu_line  replaces "Same lookup as menu item ..."
_COMMAND_DETAILS: dict[str, dict[str, Any]] = {
    "ip": {
        "menu": ("1", "IP Information"),
        "about": (
            "Infoblox details for IPv4 and IPv6 addresses: subnet, DNS name, status, lease state, record type, "
            "MAC (IPv4), DUID (IPv6) and PTR name."
        ),
        "objects": "IPv4 or IPv6 address, e.g. 10.1.2.3 or 2001:db8::5; '-' reads objects from stdin",
        "views": True,
        "examples": ("cn ip 10.1.2.3 2001:db8::5 --format md", "cn ip --file ips.txt --format csv > ips.csv"),
        "found": "data for at least one address",
    },
    "subnet": {
        "menu": ("2", "Subnet Information"),
        "about": (
            "Subnet details from Infoblox: general data and extensible attributes, DHCP ranges with "
            "utilisation, options, members and failover, DNS records and fixed addresses. Lists are paged up "
            "to 10,000 rows per subnet. For IPv6 subnets Infoblox reports no DHCP utilisation and no failover, "
            "so those cells are empty. Every used address is also listed with all its record types (HOST, A, "
            "PTR, FA, RESERVATION, LEASE, ...)."
        ),
        "objects": (
            "10.1.2.0/24, 10.1.2.0/255.255.255.0, 2001:db8:20::/64, or an address (its subnet); a container "
            "prefix expands to its subnets (child containers are listed, not expanded); '-' reads objects "
            "from stdin"
        ),
        "examples": (
            "cn subnet 10.1.2.3 --format md",
            "cn subnet 2001:db8:20::/64 --format md",
            "cn subnet --file change-4711.txt --report",
            "cn subnet 10.1.2.0/24 --format json | jq -r '.dns_records[].a_record'",
        ),
        "views": True,
        "found": "data for at least one subnet",
    },
    "fqdn": {
        "menu": ("3", "FQDN Prefix Lookup"),
        "about": (
            "A, AAAA, host and CNAME records whose name contains the text (at least 3 characters), with a PTR "
            "check; paged up to 10,000 records per type. With a network view (--view or [api] network_view), "
            "only its DNS views and host records are searched."
        ),
        "objects": "a name or part of one, e.g. branchsw or branchsw010.example.net; '-' reads objects from stdin",
        "views": True,
        "examples": ("cn fqdn branchsw", "cn host.example.com --format json"),
        "found": "data for at least one name",
    },
    "site": {
        "menu": ("4", "Subnet Lookup (by site code or keyword)"),
        "about": (
            "Registered subnets of a site code, found by the [site] ea_name attribute when set (by the subnet "
            "comment when no subnet carries it), or those whose description contains a keyword."
        ),
        "objects": "site code; with -k a keyword (3+ chars); '-' reads objects from stdin",
        "views": True,
        "options": (
            {
                "flags": ("-k", "--keyword"), "action": "store_true",
                "help": "treat the objects as keywords to look for in the subnet description, not as site codes",
            },
        ),
        "examples": ("cn site dns", "cn site -k branch --format csv"),
        "found": "data for at least one search",
    },
    "ping": {
        "menu": ("6", "Bulk PING"),
        "about": (
            "ICMP ping of IPv4 and IPv6 addresses, host names and subnets, and with --tcp a TCP connection "
            "test of up to 5 ports. A subnet is expanded to its hosts (at most a /16, for IPv6 a /112; with "
            "--tcp at most 1,024 hosts). Every probe gives up after 3 seconds."
        ),
        "menu_line": 'Same check as menu item 6, "Bulk PING".',
        "objects": "10.1.2.3, 2001:db8::5, a host name, or 10.1.2.0/24; '-' reads objects from stdin",
        "options": (
            {
                "flags": ("--tcp",), "metavar": "PORTS", "type": _arg_type(parse_tcp_ports), "default": None,
                "help": (
                    "also connect to these TCP ports, e.g. 22,443 (up to 5): open = connected, closed = reset, "
                    "timeout = no answer"
                ),
            },
        ),
        "examples": (
            "cn ping 10.1.2.3 web01.example.net",
            "cn ping 10.1.2.0/28 --tcp 22,443 --format md",
            "cn ping db01 --tcp 5432 && echo '5432 is open'",
        ),
        "exit": (
            "exit: 0 at least one host answered (with --tcp: at least one port was open), 1 none did, "
            "2 invalid input or no ping command, 3 a probe could not run or the report could not be written, "
            "130 interrupted."
        ),
    },
    "diff": {
        "menu": ("c", "Config Repository Browser (TUI)"),
        "about": (
            "Configuration lines added or removed on devices, each attributed to the snapshot (and author) "
            "that made the change; blank lines and lines that are only '!' are ignored. Without --since: the "
            "last change; with --line and no --since: the whole history."
        ),
        "menu_line": 'Menu item c, "Config Repository Browser (TUI)", shows the same history interactively.',
        "objects": "device name, as in <name>.cfg in the configuration repositories; '-' reads objects from stdin",
        "report": False,
        "options": (
            {
                "flags": ("--since",), "metavar": "WHEN", "type": _arg_type(parse_since), "default": None,
                "help": (
                    "compare from the newest snapshot at or before WHEN: 30m, 24h, 7d, 2w, 2026-10-01, "
                    "2026-10-01T14:00 (UTC unless an offset is given) or a snapshot file name"
                ),
            },
            {
                "flags": ("--line",), "metavar": "TEXT", "type": _arg_type(_nonempty_text), "default": None,
                "help": "only changed lines that contain TEXT (any case)",
            },
        ),
        "examples": (
            "cn diff r1 --since 24h",
            "cn diff r1 r2 --since 2026-10-01 --format md",
            "cn diff r1 --line 'ip route 0.0.0.0'",
        ),
        "exit": (
            "exit: 0 at least one changed line, 1 none (no change in the window, or no such device), "
            "2 invalid input or no configuration repository, 3 a repository or snapshot could not be read, "
            "130 interrupted."
        ),
    },
    "doctor": {
        "menu": ("s", "Application Setup"),
        "about": (
            "Checks the configuration and, when Infoblox is configured, the credentials: it logs in, reads "
            "the WAPI version the endpoint serves, checks the site attribute ([site] ea_name), lists the "
            "network views and checks the one the lookups search ([api] network_view or --view). Nothing is "
            "changed."
        ),
        "menu_line": 'Menu item s, "Application Setup", shows the offline part of these checks.',
        "objects": None,
        "report": False,
        "views": True,
        "examples": ("cn doctor", """cn doctor --format json | jq '.checks[] | select(.status == "error")'"""),
        "exit": (
            "exit: 0 no check failed (warnings allowed), 2 a setting is wrong (for example [site] ea_name, "
            "[api] network_view or the [api] endpoint path) or --view names no network view, 3 the "
            "credentials or Infoblox failed a live check, 130 interrupted."
        ),
    },
    "init": {
        "menu": None,  # the only command without a menu item (and without a module: _init_config does it all)
        "about": (
            "Writes a commented starting configuration to ~/.cn (on Windows %USERPROFILE%\\.cn). "
            "It never overwrites a file: edit the one that exists."
        ),
        "menu_line": (
            "No menu item. Edit ~/.cn in a text editor: the menu's Application Setup (s) "
            "rewrites the file without its comments."
        ),
        "objects": None,
        "report": False,
        "examples": ("cn init",),
        "exit": "exit: 0 written, 2 the file exists (nothing changed), 3 it could not be written.",
    },
    # Last on purpose: _OPTION_OWNERS keeps the first command that declares a flag, so --tcp stays
    # ping's and --since diff's in the hint for a bare object.
    "monitor": {
        "menu": ("m", "Ping Monitor"),
        "about": (
            "Pings the targets round after round and records every round in the ping history ([ping] "
            "history_file, default ~/.cn-ping-history.db): which hosts were seen, when first and last, and "
            "when they stayed online. Targets, --tcp and the limits are cn ping's. Without --every and --for "
            "it records one round and adds the earlier rounds of the same targets to the summary. --list, "
            "--show and --follow read the history and ping nothing."
        ),
        "menu_line": 'Same as menu item m, "Ping Monitor".',
        "objects": "10.1.2.3, 2001:db8::5, a host name, or 10.1.2.0/24; '-' reads objects from stdin",
        "objects_optional_with": ("list", "show", "follow"),
        "options": (
            {
                "flags": ("--tcp",), "metavar": "PORTS", "type": _arg_type(parse_tcp_ports), "default": None,
                "help": "also connect to these TCP ports, e.g. 22,443 (up to 5), as cn ping does",
            },
            {
                "flags": ("--every",), "metavar": "INTERVAL", "type": _arg_type(parse_duration), "default": None,
                "help": "start a round every INTERVAL (30s, 5m, 1h; at least 10s); without --for, until q or Ctrl+C",
            },
            {
                "flags": ("--for",), "dest": "run_for", "metavar": "DURATION", "type": _arg_type(parse_duration),
                "default": None,
                "help": "stop starting rounds after DURATION (30m, 2h, 1d; at least 10s); without --every, one round"
                        " a minute",
            },
            {
                "flags": ("--since",), "metavar": "WHEN", "type": _arg_type(parse_window), "default": None,
                "help": "earlier rounds to include: 24h, 7d, 2026-10-01 (UTC); default all kept, 0m this run only",
            },
            {"flags": ("--list",), "action": "store_true", "help": "list the recorded requests, running ones included; no targets"},
            {
                "flags": ("--show",), "metavar": "ID", "default": None,
                "help": "the summary of a recorded request (an ID or a prefix from --list); no targets",
            },
            {
                "flags": ("--follow",), "metavar": "ID", "default": None,
                "help": "the live view of a request another process is recording, then its summary; needs a terminal",
            },
        ),
        "examples": (
            "cn monitor 10.1.2.0/24 --for 2h --every 1m",
            "cn monitor --file sites.txt --tcp 22",
            "cn monitor --list",
            "cn monitor --show a3f9 --since 24h --format md",
        ),
        "exit": (
            "exit: 0 a host was seen in the window (with --tcp: a port was open), 1 none was, 2 invalid input or "
            "options, no such ID, or --follow without a terminal, 3 a probe could not run, the history could not "
            "be read or written (the summary is still printed) or the report failed, 130 a second Ctrl+C."
        ),
    },
}

_USAGE = (
    "cn [global options] <command> [objects ...] [options]\n"
    "       cn IP|CIDR|FQDN ...        shortcut for ip / subnet / fqdn\n"
    "       cn                         interactive menu"
)

# The root help epilog is a template: ``_epilog()`` fills in the credential variables (the defaults of
# AUTH_ENV_DEFAULTS, which differ by platform) and the stdin example.
_EPILOG_TEMPLATE = """\
examples:
  cn 10.1.2.3                           same as: cn ip 10.1.2.3
  cn 10.1.2.0/24 --format md            paste into a ticket
  cn 2001:db8::5                        same as: cn ip 2001:db8::5
  cn ip --file ips.txt --format csv > ips.csv
  {stdin_example}
  cn ping web01 --tcp 443               is TCP 443 open?

Results go to stdout; progress, warnings and errors go to stderr.
Colour is off when stdout is not a terminal or NO_COLOR is set.
Exit status: 0 found, 1 nothing found, 2 usage error, 3 Infoblox,
credential, repository or report failure, 130 interrupted.
Credentials: ${device_user} and ${device_password}, or a GPG credentials file (-g FILE or
[gpg] credentials; ignored when older than 24 h). Infoblox can use its
own account: ${infoblox_user} (or [api] user) with ${infoblox_password}, or a GPG
file in [gpg] infoblox_credentials. [auth] in .cn renames the variables;
cn doctor shows which login applies.
Without a terminal cn never prompts. More: cn <command> --help.
Global options also work after the command (not -v).
"""


def _epilog() -> str:
    """
    The root help epilog.

    The credential variables are the defaults of ``AUTH_ENV_DEFAULTS``: ``$USER`` on POSIX, ``$USERNAME`` on
    Windows. The example that reads objects from stdin uses ``--file`` on Windows, because PowerShell reserves
    ``<``. Every other character is the same on every platform.
    """
    stdin_example = (
        "cn subnet --file scope.txt --format json | jq '.dns_records'"
        if oscompat.is_windows()
        else "cn subnet - --format json < scope.txt | jq '.dns_records'"
    )
    return _EPILOG_TEMPLATE.format(
        stdin_example=stdin_example,
        device_user=AUTH_ENV_DEFAULTS["auth_device_user_var"],
        device_password=AUTH_ENV_DEFAULTS["auth_device_password_var"],
        infoblox_user=AUTH_ENV_DEFAULTS["auth_infoblox_user_var"],
        infoblox_password=AUTH_ENV_DEFAULTS["auth_infoblox_password_var"],
    )

_NO_VALUE_ACTIONS = ("store_true", "store_const", "version")
_GLOBAL_FLAGS = {flag for spec in _GLOBAL_OPTIONS for flag in spec["flags"]}
_OWN_OPTIONS = tuple(spec for detail in _COMMAND_DETAILS.values() for spec in detail.get("options", ()))
_VALUE_FLAGS = {
    flag
    for spec in (*_GLOBAL_OPTIONS, *_COMMAND_OPTIONS, *_OWN_OPTIONS)
    if spec.get("action") not in _NO_VALUE_ACTIONS
    for flag in spec["flags"]
}
# flag -> the command that takes it, for the options that belong to one command (``cn 10.1.2.3 --tcp 443``). The
# first command that declares a flag keeps it: monitor repeats --tcp and --since, which stay ping's and diff's.
_OPTION_OWNERS: dict[str, str] = {}
for _name, _detail in _COMMAND_DETAILS.items():
    for _spec in _detail.get("options", ()):
        for _flag in _spec["flags"]:
            _OPTION_OWNERS.setdefault(_flag, _name)
del _name, _detail, _spec, _flag


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Raw descriptions, and the commands listed flush with the options rather than nested under "<command>"."""

    def _format_action(self, action: argparse.Action) -> str:
        format_action = super()._format_action
        if isinstance(action, argparse._SubParsersAction):
            return "".join(format_action(choice) for choice in action._get_subactions())
        return format_action(action)


def _add_options(target: Any, specs: Any, **overrides: Any) -> None:
    """Add the options of ``specs`` to a parser or group; ``overrides`` replace spec keys such as ``default``."""
    for spec in specs:
        kwargs = {key: value for key, value in spec.items() if key not in ("flags", "root_only", "needs")}
        target.add_argument(*spec["flags"], **{**kwargs, **overrides})


def _build_parser() -> argparse.ArgumentParser:
    """The ``cn`` parser: global options, then one sub-parser per entry of CLI_COMMANDS."""
    parser = argparse.ArgumentParser(
        prog="cn",
        usage=_USAGE,
        description=f"cn-tool v{VERSION}: Infoblox lookups and network checks.",
        epilog=_epilog(),
        formatter_class=_HelpFormatter,
        add_help=False,
        allow_abbrev=False,  # "--report" must not mean the hidden "--report-file" of a command with no report
    )
    subparsers = parser.add_subparsers(dest="command", title="commands", metavar="<command>", prog="cn")

    # Built apart from the root's own actions: with the defaults suppressed, an option that is not
    # repeated after the command leaves the root's value (e.g. -c given before it) alone.
    after_command = argparse.ArgumentParser(add_help=False)
    _add_options(
        after_command,
        [spec for spec in _GLOBAL_OPTIONS if not spec.get("root_only")],
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )

    for name, summary in CLI_COMMANDS:
        detail = _COMMAND_DETAILS[name]
        menu_line = detail.get("menu_line")
        if not menu_line:  # a command with neither a menu_line nor a menu item cannot exist
            key, title = detail["menu"]
            menu_line = f'Same lookup as menu item {key}, "{title}".'
        exit_line = detail.get("exit") or (
            f"exit: 0 {detail['found']}, 1 none, 2 invalid input, 3 Infoblox, credential or report failure "
            "(stdout still holds what was found), 130 interrupted."
        )
        command = subparsers.add_parser(
            name,
            help=summary,
            description=textwrap.fill(detail["about"], width=78) + "\n\n" + textwrap.fill(menu_line, width=78),
            epilog="examples:\n"
            + "".join(f"  {example}\n" for example in detail["examples"])
            + "\n"
            + textwrap.fill(exit_line, width=78),
            formatter_class=_HelpFormatter,
            allow_abbrev=False,
            parents=[after_command],
        )
        takes = {
            "objects": detail["objects"] is not None,
            "report": detail.get("report", True),
            "views": detail.get("views", False),
        }
        _add_options(command, [spec for spec in _COMMAND_OPTIONS if takes.get(spec.get("needs"), True)])
        if takes["objects"]:
            command.add_argument("objects", nargs="*", metavar="OBJECT", help=detail["objects"])
        _add_options(command, detail.get("options", ()))
        if not takes["report"]:
            command.set_defaults(report=False)  # nothing to save: _run_cli still reads args.report

    global_options = parser.add_argument_group("global options")
    global_options.add_argument("-h", "--help", action="help", help="show this help message and exit")
    _add_options(global_options, _GLOBAL_OPTIONS)
    return parser


def _usage_error(message: str) -> NoReturn:
    """A mistake in what was typed, found before anything is started: one line on stderr, exit status 2."""
    print(f"cn: {message}", file=sys.stderr)
    sys.exit(2)


_DIGITS_AND_DOTS = re.compile(r"[\d.]+")
_ADDRESS_LIKE = re.compile(r"[./:]")  # a token with one of these was meant as an address, not as a word


def _is_ip_object(text: str) -> bool:
    """
    An IPv4 or IPv6 address or prefix, however spelled.

    An IPv4-mapped or zoned IPv6 spelling counts: the module behind the command refuses it with the
    form to type instead. Whether ``ipaddress`` keeps a zone ID inside ``ip_network`` depends on
    the Python version, so those spellings are told by ``ipv6_form_problem``, which reads the zone
    from the text.
    """
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        return bool(ipv6_form_problem(text))
    return True


def _classify_object(text: str) -> Optional[str]:
    """What a bare argument is: "subnet" (a prefix) or "ip" (an address), of either family, "mac", "fqdn", or None."""
    if _is_ip_object(text):
        return "subnet" if "/" in text else "ip"
    if validate_and_normalize_mac_address(text):
        return "mac"
    # is_fqdn() accepts "10.1.2" and "aabb.ccdd.eeff" (labels of digits); neither is a name
    if "." in text and not _DIGITS_AND_DOTS.fullmatch(text) and is_fqdn(text):
        return "fqdn"
    return None


_UNSUPPORTED_OBJECTS = {"mac": "is a MAC address; MAC lookups are not supported"}


def _infer_command(argv: list[str]) -> list[str]:
    """
    Insert the command a bare object asks for (``cn 10.1.2.3`` is ``cn ip 10.1.2.3``).

    Global options and their values are skipped; the command goes in front of the first other
    token, so ``cn --format json 10.1.2.3`` works. Every positional is classified (an IPv4 or
    IPv6 prefix or address, MAC, FQDN) and must agree; the two families mix inside one kind
    (``cn 10.1.2.3 2001:db8::5`` is ``ip``). Words that are not addresses, such as a command name
    or a typo, are left to argparse; a MAC address, a malformed address, mixed object types or an
    option that another command owns (``cn 10.1.2.3 --tcp 443``: say ``cn ping``) exit with status
    2 and a one-line reason.
    """
    start = 0
    while start < len(argv):
        flag = argv[start].split("=", 1)[0] if argv[start].startswith("--") else argv[start]
        if flag not in _GLOBAL_FLAGS:
            break
        start += 2 if flag in _VALUE_FLAGS and "=" not in argv[start] else 1

    positionals: list[str] = []
    flags: list[str] = []
    index = start
    while index < len(argv):
        token = argv[index]
        if token.startswith("-") and token != "-":
            flag = token.split("=", 1)[0] if token.startswith("--") else token
            flags.append(flag)
            index += 2 if flag in _VALUE_FLAGS and "=" not in token else 1
        else:
            positionals.append(token)
            index += 1

    objects = [token for token in positionals if token != "-"]
    if not objects:
        return list(argv)

    kinds: list[str] = []
    for position, token in enumerate(objects):
        kind = _classify_object(token)
        if kind is None:
            if position == 0 and not _ADDRESS_LIKE.search(token):
                return list(argv)  # a plain word: argparse accepts a command name and rejects the rest
            _usage_error(f"'{token}' is not an IP address, network or FQDN")
        if kind in _UNSUPPORTED_OBJECTS:
            _usage_error(f"'{token}' {_UNSUPPORTED_OBJECTS[kind]}")
        kinds.append(kind)

    found = list(dict.fromkeys(kinds))
    if len(found) > 1:
        _usage_error(f"mixed object types ({', '.join(found)}); use one command per type")
    command = found[0]
    for flag in flags:
        owner = _OPTION_OWNERS.get(flag)
        if owner not in (None, command):
            _usage_error(f"{flag} is an option of 'cn {owner}': cn {owner} {shlex.join(argv[start:])}")
    return [*argv[:start], command, *argv[start:]]


def _takes_no_objects(args: argparse.Namespace) -> bool:
    """A mode of the command that reads no objects (``cn monitor --list``): its spec's ``objects_optional_with``."""
    # Given as an option, even empty (``--show ''``): its value is checked later, never read as no option at all.
    names = _COMMAND_DETAILS[args.command].get("objects_optional_with", ())
    return any(getattr(args, name, None) not in (None, False) for name in names)


def _check_monitor_modes(args: argparse.Namespace) -> None:
    """``cn monitor``'s mode conflicts are usage errors, found before anything is read or started."""
    from cn_tool.modules.ping_monitor import usage_problem  # only cn monitor needs the module this early

    problem = usage_problem(args)
    if problem:
        _usage_error(problem)


def _writes_report(command: Optional[str]) -> bool:
    """The menu and most commands write a report; ``diff`` and ``doctor`` do not."""
    return command is None or _COMMAND_DETAILS[command].get("report", True)


def _has_terminal() -> bool:
    """The menu needs a terminal to read from and to draw on."""
    return sys.stdin.isatty() and sys.stdout.isatty()


# --- Start-up shared by the menu and the command line ---------------------------------------------
def _startup(args: argparse.Namespace) -> tuple[ScriptContext, Dict[str, BaseModule]]:
    """
    Logging, modules, plugins, configuration and the context: everything the menu and the command
    line have in common. The menu adds the cache, the writer thread, its status line and signals.
    """
    cli_mode = args.command is not None  # main() has already moved the console to stderr in this mode

    logger = bootstrap_logging(args)

    logger.info(f"cn-tool v{VERSION} starting up...")
    logger.debug(f"Command-line arguments received: {args}")

    logger.info("Loading application modules and plugins...")
    loaded_modules, all_plugins, final_schema = load_modules_and_plugins(BASE_CONFIG_SCHEMA)
    logger.info(f"Loaded {len(loaded_modules)} modules and {len(all_plugins)} plugins.")

    # Determine the configuration file hierarchy
    config_paths_to_check = _get_config_paths(args)

    # read_config now handles the logic of checking and reading the files
    cfg = read_config(config_paths_to_check, final_schema, logger)

    # Then, we override any values from the config with command-line arguments.
    cfg = setup_from_args(cfg, args, logger)

    # Add non-user-configurable values to the config dict
    cfg["version"] = VERSION

    # 1 & 2. Normalize infoblox_enabled and config_repo_enabled booleans.
    #    normalize_runtime_flags encapsulates the same logic used by the standalone CLIs so
    #    both entry-points share identical semantics.
    final_message = ''
    _repo_explicit_true = parse_optional_bool(cfg.get("config_repo_enabled")) is True
    normalize_runtime_flags(cfg, logger)

    # Rebuild the user-visible banner from the normalized bools so the
    # interactive UI still shows the startup warning with the sleep delay.
    if not cfg['infoblox_enabled'] and not cli_mode:  # a command says why it is unavailable by itself
        log_msg = "Infoblox API URL is not set. Infoblox-related modules will be disabled."
        final_message += log_msg + '\n'
        if no_config_file_found(cfg):  # a new install: say how to start (the path is printed as text, not markup)
            final_message += f"No configuration file found: run cn init to create {escape(str(user_config_path()))}.\n"
    if _repo_explicit_true and not cfg['config_repo_enabled']:
        log_msg = "Configuration repository directory is not accessible. Config search modules will be disabled."
        final_message += log_msg + '\n'

    # 3. Check report file accessibility (a command that writes no report has nothing to check)
    report_dir = cfg["report_file"].parent
    if _writes_report(args.command) and not check_dir_accessibility(logger, report_dir):
        if cli_mode and args.report_file:
            # Automation asked for this very path: never save somewhere else and report success.
            reason = "not accessible" if report_dir.exists() else "No such file or directory"
            _input_error(f"cn: cannot write the report to {report_dir}: {reason}")
        log_msg = "Report directory not accessible, using current directory."
        logger.warning(log_msg)
        final_message += log_msg + '\n'
        cfg["report_file"] = Path(cfg["report_file"].name)

    if final_message:
        console.print(f"[bold]{final_message}[/]")
        if not cli_mode:
            time.sleep(5)
    event_bus = EventBus(logger)
    ctx = ScriptContext(
        cfg=cfg,
        logger=logger,
        console=console,
        cache=None,
        event_bus=event_bus,
        username='',
        password='',
        plugins=all_plugins,
    )

    if cli_mode:
        # The menu connects AD early to hide latency; a one-shot command connects on first use (the
        # plugin's hook), so malformed input never asks for credentials or opens LDAP.
        ctx.cfg["ad_connect_on_startup"] = False

    # Connect global plugins. A one-shot command skips plugins that serve another module only (the
    # SD-WAN YAML loader targets config_search and reads a whole repository on connect); plugins
    # without a target (statistics, email) and the command's own plugin connect as in the menu.
    wanted = _cli_module_name(loaded_modules, args.command) if cli_mode else None
    for plugin in ctx.plugins:
        if not plugin.manages_global_connection:
            continue
        target = getattr(plugin, "target_module_name", "")
        if cli_mode and target and target != wanted:
            continue
        plugin.connect(ctx)

    set_global_color_scheme(ctx)
    return ctx, loaded_modules


def _cli_module_name(modules: Dict[str, BaseModule], command: Optional[str]) -> Optional[str]:
    """The file name of the module behind ``command`` (how plugins name their target), or None."""
    module = next((m for m in modules.values() if getattr(m, "cli_name", None) == command), None)
    return type(module).__module__.rsplit(".", 1)[-1] if module is not None else None


def _tracked_stats(ctx: ScriptContext, module: BaseModule) -> Any:
    """The statistics collector when this module's runs are recorded, else None."""
    stats = getattr(ctx, "stats", None)
    return stats if stats and getattr(module, "track_in_stats", True) else None


def _run_tracked(
    ctx: ScriptContext,
    module: BaseModule,
    call: Callable[[], T],
    *,
    outcome: Optional[Callable[[T], str]] = lambda _result: "completed",
) -> T:
    """
    Run ``call`` (a module's menu or command-line entry point), recording the run in the statistics.
    ``outcome`` names the recorded status of a run that returned (the menu's always completed);
    None leaves the run open for the caller to finish once it knows the real outcome.
    """
    stats = _tracked_stats(ctx, module)
    tracked = stats is not None
    if tracked:
        stats.start_module_run(module)
    try:
        result = call()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        if tracked:
            stats.prepare_for_shutdown("interrupted")
        raise
    except Exception:
        ctx.logger.exception("Unhandled exception while running module '%s'", module.menu_title)
        if tracked:
            stats.prepare_for_shutdown("failed")
        raise
    if tracked and outcome is not None:
        stats.finish_module_run(outcome(result))
    return result


# --- Command line mode ----------------------------------------------------------------------------
def _stop(ctx: ScriptContext, code: int, message: str) -> NoReturn:
    """End the run with ``message`` on the console (stderr in command line mode) and exit status ``code``."""
    exit_now(ctx, code, message)
    raise AssertionError("exit_now returned")  # pragma: no cover


def _read_cli_objects(args: argparse.Namespace) -> None:
    """
    Resolve the objects named on the command line (positionals, ``--file``, ``-``) into
    ``args.objects`` before anything else starts: a ``-`` must consume stdin before any plugin or
    module can prompt, and a bad file or an empty list must fail before cn logs in anywhere.
    """
    try:
        objects = read_objects(args.objects, args.file)
    except (OSError, UnicodeDecodeError) as exc:
        source = args.file if args.file and args.file != "-" else "stdin"
        reason = getattr(exc, "strerror", None) or exc
        _input_error(f"cn: cannot read {source}: {reason}")
    if not objects:
        piped = not (sys.stdin.isatty() or "-" in args.objects or args.file == "-")
        hint = f"did you mean 'cn {args.command} -'?" if piped else f"see cn {args.command} --help"
        _input_error(f"cn: no objects given; {hint}")
    # The module reads the objects again (it is testable on its own); handing it the resolved
    # list makes that a pass-through that never touches stdin. The file's name stays known: cn monitor
    # names a recorded request by it.
    args.source_file = None if args.file in (None, "-") else args.file
    args.objects, args.file = objects, None


def _input_error(message: str) -> NoReturn:
    """Bad command-line input, found before start-up: one line on the (stderr) console, exit status 2."""
    console.print(message, markup=False, soft_wrap=True)
    sys.exit(2)


def _run_cli(ctx: ScriptContext, modules: Dict[str, BaseModule], args: argparse.Namespace) -> int:
    """
    Run ``cn <command>`` once and return its exit status: dispatch to the module with that
    ``cli_name``, write its result to stdout, wait for the report and check it was written.
    """
    saving = bool(args.report or args.report_file)
    ctx.cfg["report_auto_save"] = saving  # the menu saves every run; the command line only when asked
    signal.signal(signal.SIGINT, lambda s, f: exit_now(ctx, EXIT_INTERRUPTED, "cn: interrupted"))

    module = next((m for m in modules.values() if getattr(m, "cli_name", None) == args.command), None)
    if module is None:
        _stop(ctx, 2, f"cn: '{args.command}' is not available (no module provides it)")
    key = module.visibility_config_key
    if key and not ctx.cfg.get(key, False):
        if key == "infoblox_enabled" and no_config_file_found(ctx.cfg):
            # A new install's first lookup: say what to do, not which internal key is off. [api] is escaped:
            # Rich would read it as a style tag and print nothing.
            _stop(
                ctx, 2,
                escape(
                    f"cn: '{args.command}' is not available: no configuration file was found; "
                    f"run cn init to create {user_config_path()}, then set [api] endpoint in it."
                ),
            )
        _stop(ctx, 2, f"cn: '{args.command}' is not available: {module.menu_title} needs {key}, which is off in this configuration")

    try:
        # The run's outcome is only known once the report has been written (or not): finished below.
        result = _run_tracked(ctx, module, lambda: module.run_cli(ctx, args), outcome=None)
    except Exception:
        _stop(ctx, 3, "cn: unexpected error. Check logs.")

    emit(ctx, result.data, args.format)  # stdout first: a slow or failing report must not delay it
    file_io.wait_for_all_saves()
    code = result.exit_code
    if saving:
        if file_io.save_failures():
            code = 3
        elif file_io.saves_completed():  # a run with nothing to save appends nothing
            ctx.console.print(f"cn: report: appended to {ctx.cfg['report_file']}", markup=False, soft_wrap=True)
    stats = _tracked_stats(ctx, module)
    if stats:
        stats.finish_module_run("failed" if code == 3 else "completed")  # 3: lookup or report incomplete
    return code


def _init_config() -> int:
    """
    ``cn init``: write the packaged template to ``~/.cn`` and return the exit status.

    0 written (I1), 2 the file exists and nothing was changed (I2), 3 it cannot be written (I3). It runs before
    start-up: it reads no configuration, loads no module, writes no log and never prompts. The messages go to
    stderr with markup off, as ``_input_error`` prints, so that ``[api]`` and a path are shown as they are.
    """
    path = user_config_path()
    try:
        write_sample_config(path)
    except FileExistsError:
        message, code = f"cn: {path} exists; nothing was changed. Edit it, or rename it and run cn init again.", 2
    except OSError as exc:
        message, code = f"cn: cannot write {path}: {exc.strerror or exc}", 3
    else:
        message, code = f"cn: wrote {path}. Set [api] endpoint in it, then run cn doctor.", 0
    console.print(message, markup=False, soft_wrap=True)
    return code


def _use_utf8_stdio() -> None:
    """
    Windows only: make stdin, stdout and stderr UTF-8.

    Redirected, a Windows console program writes in the locale's code page (cp1252), which has no box drawing
    (a table through a pipe raised UnicodeEncodeError) and no room for a name from Infoblox. A console is
    unaffected: Python already talks to it in UTF-16 (PEP 528).

    Each stream is reconfigured in place and keeps its error handler (``reconfigure`` resets it to "strict"
    unless it is passed again). A stream is never replaced: ``getpass.win_getpass``, behind a password
    prompt, falls back to an *echoing* read when ``sys.stdin`` is not ``sys.__stdin__``. A stream that
    cannot be reconfigured is left as it is: under pytest ``sys.stdin`` has no ``reconfigure``, under
    ``pythonw`` the streams are None, and a stream that was read from or is closed refuses.
    """
    if not oscompat.is_windows():
        return
    for name in ("stdin", "stdout", "stderr"):
        stream = getattr(sys, name)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        errors = getattr(stream, "errors", None)
        try:
            if errors:
                reconfigure(encoding="utf-8", errors=errors)
            else:
                reconfigure(encoding="utf-8")
        except (ValueError, OSError):
            pass


def main() -> None:
    """
    Main function that orchestrates the execution of the script: parse the command line, then
    either run one command (``cn <command> ...``) or open the interactive menu.
    """
    _use_utf8_stdio()
    args = _build_parser().parse_args(_infer_command(sys.argv[1:]))
    if args.command is None and not _has_terminal():
        _usage_error("no command given and no terminal for the menu; see cn --help")
    if args.command is not None:
        if args.report_file and not _writes_report(args.command):
            _usage_error(f"{args.command} does not write a report; drop -r")
        console.set_stderr(True)  # from here on stdout carries results only
        if args.command == "init":
            sys.exit(_init_config())  # before objects and start-up: no configuration, no module, no log
        if args.command == "monitor":
            _check_monitor_modes(args)  # before stdin is read: a mode that takes no objects never consumes it
        if _COMMAND_DETAILS[args.command]["objects"] is not None and not _takes_no_objects(args):
            _read_cli_objects(args)  # before any plugin connects: '-' is consumed, bad input never logs in

    ctx, modules = _startup(args)
    if args.command is None:
        _run_menu(ctx, modules)
    else:
        exit_now(ctx, _run_cli(ctx, modules, args), "", quiet=True)


# --- Interactive menu -----------------------------------------------------------------------------
# The structure and order of the menu: a section header, then its keys.
_MENU_LAYOUT: Dict[str, List[str]] = {
    "--- Tasks ---": ['1', '2', '3', '4', '5', '6', 'm', '7', '8', '9', 'b', 'o', 't'],
    # Keep 'a' for your existing module and add 'c' for Config Analyzer
    "--- Info ---": ['a', 'c'],
    "--- Reporting ---": ['e', 'd', 'u'],
    "--- Application ---": ['s', '0']
}


def _run_menu(ctx: ScriptContext, loaded_modules: Dict[str, BaseModule]) -> None:
    """The interactive menu: start the cache and the writer, then loop until the user exits."""
    cfg = ctx.cfg
    logger = ctx.logger
    signal.signal(signal.SIGINT, lambda s, f: exit_now(ctx, 1, "Interrupted... Exiting..."))

    start_background_tasks(ctx)
    start_worker()

    colors = get_global_color_scheme(cfg)
    menu_header = """  """
    menu_lines = [menu_header, f"    [{colors['error']} {colors['title']}]MENU[/][{colors['code']}]"]

    for header, keys in _MENU_LAYOUT.items():
        # A flag to track if we should print the header for this section
        header_printed = False
        section_lines = []

        for key in keys:
            # Handle the static 'Exit' case
            if key == '0':
                section_lines.append(f"    [{colors['warning']} {colors['bold']}]0. Exit[/]")
                continue

            module = loaded_modules.get(key)
            if not module:
                continue

            # Check visibility based on the module's declared dependency
            visibility_key = module.visibility_config_key

            if visibility_key and not cfg.get(visibility_key, False):
                continue  # Skip this module if its dependency is not met

            # If we are here, the module is visible, so add it to the list
            section_lines.append(f"    {module.menu_key}. {module.menu_title}")

            # If we found any visible items in this section, print the header and the items
        if section_lines:
            if not header_printed:
                menu_lines.append(f"\n    [{colors['header']}]{header}[/]")
                header_printed = True
            menu_lines.extend(section_lines)

    base_menu = "\n".join(menu_lines)

    status_refresh_event = threading.Event()
    status_state_lock = threading.Lock()
    status_state = {
        "report_state": None,
        "report_path": Path(ctx.cfg.get("report_file", "report.xlsx")),
    }
    # Initialize report status based on existing file, so the status shows on first render
    try:
        initial_report = status_state["report_path"].expanduser()
        if initial_report.exists():
            status_state["report_state"] = "completed"
    except Exception:
        pass

    def _handle_status_update(payload: Optional[dict[str, Any]]) -> None:
        if isinstance(payload, dict) and payload.get("component") == "report":
            with status_state_lock:
                if payload.get("state") == "deleted":
                    status_state["report_state"] = None
                elif payload.get("state") == "error":
                    status_state["report_state"] = "error"
        status_refresh_event.set()

    def _handle_report_generating(payload: Optional[dict[str, Any]]) -> None:
        with status_state_lock:
            status_state["report_state"] = "generating"
            if isinstance(payload, dict) and payload.get("path"):
                status_state["report_path"] = Path(payload["path"]).expanduser()
        status_refresh_event.set()

    def _handle_report_done(payload: Optional[dict[str, Any]]) -> None:
        with status_state_lock:
            status_state["report_state"] = "completed"
            if isinstance(payload, dict) and payload.get("path"):
                status_state["report_path"] = Path(payload["path"]).expanduser()
        status_refresh_event.set()

    subscriptions = [
        ctx.event_bus.subscribe("status:update", _handle_status_update),
        ctx.event_bus.subscribe("status:report_generating", _handle_report_generating),
        ctx.event_bus.subscribe("status:report_done", _handle_report_done),
    ]

    timer_stop_event = threading.Event()

    def _minute_tick() -> None:
        while not timer_stop_event.is_set():
            now = datetime.now()
            seconds_until_next_minute = 60 - now.second
            if seconds_until_next_minute <= 0:
                seconds_until_next_minute = 60
            if timer_stop_event.wait(seconds_until_next_minute):
                break
            ctx.event_bus.publish("status:update", {"component": "timer", "state": "tick"})

    threading.Thread(target=_minute_tick, name="status-minute-tick", daemon=True).start()

    try:
        while True:
            # Live-rendered menu with dynamic cache status and non-blocking input
            # Ensure clean screen before first Live render in each loop iteration

            ctx.console.clear()
            def _render_menu() -> str:
                status_line = build_cache_status_line(ctx)
                report_suffix = ""
                with status_state_lock:
                    report_state = status_state.get("report_state")
                    report_path = status_state.get("report_path")
                if report_path:
                    candidate = report_path if isinstance(report_path, Path) else Path(report_path)
                    candidate = candidate.expanduser()
                    exists = candidate.exists()
                    # Show meaningful status even if the file is being created (may not exist yet)
                    if report_state == "generating":
                        report_suffix = f"  • Report: [{colors['warning']}]Generating[/]"
                    elif report_state == "error":
                        report_suffix = f"  • Report: [{colors['error']}]Error[/]"
                    elif report_state == "completed" and exists:
                        report_suffix = f"  • Report: [{colors['success']}]Ready[/]"
                    elif not report_state and exists:
                        # If a report already exists at startup (no events yet), show it as ready
                        report_suffix = f"  • Report: [{colors['success']}]Ready[/]"
                return f"{status_line}{report_suffix}\n\n{base_menu}"

            # Check if cache indexing is currently active
            try:
                indexing_active = bool(ctx.cache and ctx.cache.dc and ctx.cache.dc.get("indexing", False))
            except Exception:
                indexing_active = False

            # Adaptive interval: 2.5s during indexing, 60s when idle (handled in read_user_input_live)
            choice = read_user_input_live(
                ctx,
                _render_menu,
                indexing_active=indexing_active,
                refresh_signal=status_refresh_event,
            ).strip()

            # '0' is now handled by the menu structure, but we still need the exit logic
            if choice == '' or choice == '0':
                timer_stop_event.set()
                for token in subscriptions:
                    ctx.event_bus.unsubscribe(token)
                exit_now(ctx)

            module_to_run = loaded_modules.get(choice)
            if module_to_run:
                # Check visibility again before running, as a safety measure
                visibility_key = module_to_run.visibility_config_key
                if visibility_key and not ctx.cfg.get(visibility_key, False):
                    ctx.console.print(f"[{colors['error']}]This feature is currently disabled.[/]")
                    time.sleep(2)
                else:
                    # Warn if a config-repo-dependent module runs while indexing
                    requires_repo = getattr(module_to_run, 'requires_config_repo', False)
                    try:
                        indexing_active = bool(ctx.cache and ctx.cache.dc and ctx.cache.dc.get("indexing", False))
                    except Exception:
                        indexing_active = False
                    if requires_repo and indexing_active:
                        ctx.console.print(f"[{colors['warning']}]Configuration repository is being indexed. Live search is available but slower.[/]")
                        proceed = read_user_input(ctx, f"[{colors['warning']}]Proceed anyway? (y/N): [/] ").strip().lower()
                        if proceed != 'y':
                            continue
                    _run_tracked(ctx, module_to_run, lambda: module_to_run.run(ctx))
            else:
                ctx.console.print(f"[{colors['error']}]Invalid choice. Please try again.[/]")
                time.sleep(1)
                continue
    except Exception:
        logger.exception("Unhandled exception in main loop")
        exit_now(ctx, 1, "Unexpected error. Check logs.")
    finally:
        timer_stop_event.set()
        for token in subscriptions:
            ctx.event_bus.unsubscribe(token)


if __name__ == "__main__":
    main()
