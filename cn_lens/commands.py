"""Single source of truth for cn-lens command definitions.

This module defines one :class:`CommandSpec` per workflow. Both entry points
(:mod:`cn_lens.cli` and :mod:`cn_lens.interactive`) derive their subparser
definitions, dispatch tables, help text, and input-source value-option sets
from this table.

Design decision D2 (specs/004-lens-foundation/plan.md):

    New ``cn_lens/commands.py``: one ``CommandSpec`` per workflow — name,
    aliases, workflow callable, extra argparse options, names of options that
    take values (metadata only; the namespace-derived input extractor uses
    these for documentation/future use), REPL help text, render summary key.
    ``cli.py`` builds subparsers from the table; ``interactive.py`` builds its
    parser + dispatch + help from the same table.  Retires: duplicated flag
    definitions, dispatch chains, ``INSPECT_VALUE_OPTIONS`` drift (B2 class),
    triple REPL help structures, argv scanner (P3.2).

Adding a new workflow
---------------------
1. Add a :class:`CommandSpec` entry to :data:`COMMAND_TABLE`.
2. No changes needed in ``cli.py`` or ``interactive.py`` — the table drives both.
3. ``value_option_names`` is preserved for documentation; the namespace-derived
   extractor in ``cn_lens/input_sources.py`` does not need an explicit skip-list.
4. Add ``"cn_lens/commands.py"`` to ``scripts/stage_public_release.sh`` if not
   already present (it already is after P3.1).
"""

from __future__ import annotations

import argparse
import dataclasses
from collections.abc import Callable
from typing import Any


def _non_negative_int(value: str) -> int:
    """Argparse type that accepts only non-negative integers."""
    try:
        n = int(value)
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer")
    if n < 0:
        raise argparse.ArgumentTypeError(f"value must be >= 0, got {n}")
    return n


# ---------------------------------------------------------------------------
# CommandSpec
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class CommandSpec:
    """Specification for one cn-lens command.

    Parameters
    ----------
    name:
        Primary command name as it appears on the CLI / in the REPL.
    aliases:
        Alternative names (e.g. ``("decommission",)``).  Unused today; reserved
        for future alias support.
    workflow_callable:
        The workflow function to invoke (e.g. ``impact_objects``).  ``None`` for
        commands that are handled specially (``interactive``, ``doctor``,
        ``config``, ``report``).
    is_standard_workflow:
        ``True`` when the command follows the standard pattern: positional
        objects, ``--file``, ``--column``, ``--format``, ``--output``.
        ``False`` for commands with a non-standard argument surface (``config``,
        ``report``, ``doctor``, ``interactive``).
    options:
        Extra ``(flags_list, kwargs_dict)`` tuples added via
        ``parser.add_argument(*flags, **kwargs)`` *after* the standard input
        args.  Empty for commands that only need the common surface.
    value_option_names:
        Names of every extra (per-command) option that consumes one following
        argument token.  Retained for documentation; the namespace-derived
        input extractor in ``cn_lens/input_sources.py`` no longer requires an
        explicit skip-list (argparse separates option values from positionals
        before extraction runs).
    dispatch_kwargs_fn:
        Optional callable ``(namespace) -> dict`` that extracts workflow-
        specific keyword arguments from the parsed namespace.  ``None`` for
        commands that take no extra keyword arguments.
    cli_description:
        Description string passed to the subparser's ``description=`` argument.
    cli_epilog:
        Epilog string passed to the subparser's ``epilog=`` argument.
    repl_help:
        Per-command help text shown by ``help <command>`` in the interactive
        REPL.
    summary_key:
        Key under ``result.summary`` that holds the command's primary output
        block.  Used by renderers / tests.  ``None`` for non-workflow commands.
    """

    name: str
    aliases: tuple[str, ...] = ()
    workflow_callable: Callable[..., Any] | None = None
    is_standard_workflow: bool = True
    options: tuple[tuple[list[str], dict[str, Any]], ...] = ()
    value_option_names: frozenset[str] = dataclasses.field(
        default_factory=frozenset
    )
    dispatch_kwargs_fn: Callable[..., dict[str, Any]] | None = None
    cli_description: str = ""
    cli_epilog: str = ""
    repl_help: str = ""
    summary_key: str | None = None


# ---------------------------------------------------------------------------
# Command table — populated after imports to avoid circular dependency
# ---------------------------------------------------------------------------

# NOTE: workflow callables are imported lazily at module end to avoid
# circular imports (cn_lens.workflows imports cn_lens.models etc.).

def _make_table() -> list[CommandSpec]:
    """Build and return the command table.

    Called once at module import time, after all imports are resolved.
    """
    from cn_lens.workflows import (
        allocate_objects,
        decommission_site_objects,
        device_objects,
        dns_objects,
        e911_objects,
        impact_objects,
        inspect_objects,
        reachability_objects,
        validate_site_objects,
    )
    from cn_lens.workflows.bssid import bssid_convert
    from cn_lens.workflows.stats import stats_objects

    return [
        # ------------------------------------------------------------------ #
        # inspect
        # ------------------------------------------------------------------ #
        CommandSpec(
            name="inspect",
            workflow_callable=inspect_objects,
            is_standard_workflow=True,
            options=(
                (
                    ["--deep"],
                    {
                        "action": "store_true",
                        "default": False,
                        "help": (
                            "perform a deep-dive for PREFIX and IP objects: "
                            "fan-out to DHCP ranges, fixed addresses, "
                            "in-subnet DNS records, member assignments, and decoded DHCP options "
                            "(parity with 'Subnet Data Detail' sheet)"
                        ),
                    },
                ),
            ),
            value_option_names=frozenset(),
            dispatch_kwargs_fn=lambda ns: {"deep": ns.deep},
            cli_description=(
                "Classify network objects and render an offline inspection run. "
                "Accepts IPs, prefixes, FQDNs, site codes, and device names. "
                "Invalid inputs are reported without stopping valid ones."
            ),
            cli_epilog=(
                "Output formats: human, text/txt, md/markdown, json, yaml/yml, xlsx.\n\n"
                "Examples:\n"
                "  cn-lens inspect 10.0.0.1\n"
                "  cn-lens inspect 10.0.0.1 10.0.0.0/24 host.example.net\n"
                "  cn-lens inspect 10.0.0.0/24 --deep\n"
                "  cn-lens inspect - --format json\n"
                "  cn-lens inspect --file objects.txt --format md\n"
                "  cn-lens inspect --file data.csv --column target --format xlsx --output out.xlsx"
            ),
            repl_help=(
                "inspect [<object>...] [--deep] [--file PATH] [--column COL] [--format FMT] [--output PATH]\n\n"
                "Classify network objects and render an offline inspection run.\n\n"
                "Flags:\n"
                "  --deep   Deep-dive for PREFIX/IP: DHCP ranges, fixed addresses, DNS records,\n"
                "           member assignments, decoded DHCP options (Subnet Data Detail parity).\n\n"
                "Examples:\n"
                "  inspect 10.0.0.1\n"
                "  inspect 10.0.0.0/24 --deep\n"
                "  inspect 10.0.0.1 10.0.0.0/24 host.example.net\n"
                "  inspect --file objects.txt --format md\n"
                "  inspect --file data.csv --column target --format json"
            ),
            summary_key="inspect",
        ),

        # ------------------------------------------------------------------ #
        # impact
        # ------------------------------------------------------------------ #
        CommandSpec(
            name="impact",
            workflow_callable=impact_objects,
            is_standard_workflow=True,
            options=(
                (
                    ["--all-matches"],
                    {
                        "action": "store_true",
                        "default": False,
                        "dest": "all_matches",
                        "help": (
                            "return ALL SD-WAN YAML prefix matches across every file "
                            "(plugin-equivalent exhaustive output) instead of the "
                            "single best match; applies to PREFIX and IP objects "
                            "(plan D9)"
                        ),
                    },
                ),
            ),
            value_option_names=frozenset(),
            dispatch_kwargs_fn=lambda ns: {"all_matches": ns.all_matches},
            cli_description=(
                "Find all references to objects across available sources: "
                "config_repo, SD-WAN YAML, Infoblox containers, and AD group memberships. "
                "Findings are grouped by source."
            ),
            cli_epilog=(
                "Examples:\n"
                "  cn-lens impact 10.1.0.0/24\n"
                "  cn-lens impact 10.1.0.0/24 --all-matches\n"
                "  cn-lens impact SITE01 --format json\n"
                "  cn-lens impact --file prefixes.txt --format xlsx --output impact.xlsx"
            ),
            repl_help=(
                "impact [<object>...] [--all-matches] [--file PATH] [--column COL]"
                " [--format FMT] [--output PATH]\n\n"
                "Find all references to objects across config_repo, SD-WAN YAML, Infoblox, and AD.\n\n"
                "Flags:\n"
                "  --all-matches   Return ALL SD-WAN YAML prefix matches (exhaustive mode);\n"
                "                  default returns only the single best match per PREFIX.\n\n"
                "Examples:\n"
                "  impact 10.1.0.0/24\n"
                "  impact 10.1.0.0/24 --all-matches\n"
                "  impact SITE01 --format json"
            ),
            summary_key="impact",
        ),

        # ------------------------------------------------------------------ #
        # dns
        # ------------------------------------------------------------------ #
        CommandSpec(
            name="dns",
            workflow_callable=dns_objects,
            is_standard_workflow=True,
            options=(),
            value_option_names=frozenset(),
            dispatch_kwargs_fn=None,
            cli_description=(
                "Resolve DNS and Infoblox DNS records for network objects. "
                "Performs forward and reverse lookups, PTR records, and FQDN prefix expansion."
            ),
            cli_epilog=(
                "Examples:\n"
                "  cn-lens dns host.example.net\n"
                "  cn-lens dns 10.0.0.1 --format json\n"
                "  cn-lens dns --file hosts.txt"
            ),
            repl_help=(
                "dns [<object>...] [--file PATH] [--column COL] [--format FMT] [--output PATH]\n\n"
                "Resolve DNS and Infoblox DNS records (forward, reverse, PTR, FQDN expansion).\n\n"
                "Examples:\n"
                "  dns host.example.net\n"
                "  dns 10.0.0.1 --format json"
            ),
            summary_key="dns",
        ),

        # ------------------------------------------------------------------ #
        # reachability
        # ------------------------------------------------------------------ #
        CommandSpec(
            name="reachability",
            workflow_callable=reachability_objects,
            is_standard_workflow=True,
            options=(
                (
                    ["--mode"],
                    {
                        "choices": ("ping", "trace", "both"),
                        "default": "ping",
                        "help": "reachability probe mode: ping, trace, or both (default: ping)",
                    },
                ),
                (
                    ["--max-hosts"],
                    {
                        "type": _non_negative_int,
                        "default": 32,
                        "dest": "max_hosts",
                        "metavar": "N",
                        "help": (
                            "maximum host IPs to probe for PREFIX objects "
                            "(0 = full expansion, default: 32)"
                        ),
                    },
                ),
                (
                    ["--probe"],
                    {
                        "choices": ("traceroute", "mtr"),
                        "default": "traceroute",
                        "dest": "probe",
                        "help": (
                            "trace probe tool: traceroute (default) or mtr "
                            "(requires mtr binary in PATH; degrades gracefully when absent)"
                        ),
                    },
                ),
            ),
            value_option_names=frozenset({"--mode", "--max-hosts", "--probe"}),
            dispatch_kwargs_fn=lambda ns: {
                "mode": ns.mode,
                "max_hosts": ns.max_hosts,
                "probe": ns.probe,
            },
            cli_description=(
                "Perform reachability checks (ping and/or traceroute) for network objects. "
                "When Infoblox is configured, traceroute results include a site-validity verdict "
                "(valid/site_mismatch/site_unknown) derived from extattr Site lookups. "
                "When AD is online and Infoblox site data is absent, traceroute hops are "
                "enriched with AD site codes as a fallback."
            ),
            cli_epilog=(
                "Examples:\n"
                "  cn-lens reachability 10.0.0.1\n"
                "  cn-lens reachability 10.0.0.1 --mode trace\n"
                "  cn-lens reachability 10.0.0.1 --mode trace --probe mtr\n"
                "  cn-lens reachability --file hosts.txt --mode both --format json\n"
                "  cn-lens reachability 10.0.0.0/24 --max-hosts 0"
            ),
            repl_help=(
                "reachability [<object>...] [--mode ping|trace|both] [--max-hosts N]"
                " [--probe traceroute|mtr] [--format FMT] [--output PATH]\n\n"
                "Perform reachability checks (ping and/or traceroute).\n\n"
                "Flags:\n"
                "  --mode ping|trace|both        Probe mode (default: ping).\n"
                "  --max-hosts N                 Max hosts per PREFIX (0 = full expansion, default: 32).\n"
                "  --probe traceroute|mtr        Trace tool (default: traceroute).\n"
                "                                mtr requires the mtr binary in PATH;\n"
                "                                degrades gracefully when absent.\n\n"
                "Trace site verdict (mode=trace or both, Infoblox configured):\n"
                "  Each trace result carries site_verdict: valid | site_mismatch | site_unknown.\n"
                "  Derived from Infoblox extattr Site for target, last hop, and pre-last hop.\n\n"
                "Examples:\n"
                "  reachability 10.0.0.1\n"
                "  reachability 10.0.0.1 --mode trace\n"
                "  reachability 10.0.0.1 --mode trace --probe mtr\n"
                "  reachability 10.0.0.0/24 --max-hosts 0\n"
                "  reachability --file hosts.txt --mode both"
            ),
            summary_key="reachability",
        ),

        # ------------------------------------------------------------------ #
        # device
        # ------------------------------------------------------------------ #
        CommandSpec(
            name="device",
            workflow_callable=device_objects,
            is_standard_workflow=True,
            options=(
                (
                    ["--probe"],
                    {
                        "action": "store_true",
                        "default": False,
                        "help": "ping resolved IPs to probe device reachability (default: false)",
                    },
                ),
                (
                    ["--collect"],
                    {
                        "action": "store_true",
                        "default": False,
                        "help": (
                            "connect via SSH and collect show version / license output "
                            "(requires device_ssh_enabled=true in config and device-scope "
                            "credentials; degrades gracefully when SSH is not configured)"
                        ),
                    },
                ),
            ),
            value_option_names=frozenset(),
            dispatch_kwargs_fn=lambda ns: {"probe": ns.probe, "collect": ns.collect},
            cli_description=(
                "Classify and enrich device-oriented network objects. "
                "Combines AD OU path, Infoblox host records, and config_repo references. "
                "Use --probe to additionally test reachability of resolved IPs. "
                "Use --collect to SSH-connect and gather serial/version/license data "
                "(parity with cn-tool Device Information Request)."
            ),
            cli_epilog=(
                "Examples:\n"
                "  cn-lens device router1.example.net\n"
                "  cn-lens device router1.example.net --probe\n"
                "  cn-lens device router1.example.net --collect\n"
                "  cn-lens device router1.example.net --collect --probe\n"
                "  cn-lens device --file devices.txt --format xlsx --output devices.xlsx"
            ),
            repl_help=(
                "device [<object>...] [--probe] [--collect] [--format FMT] [--output PATH]\n\n"
                "Classify and enrich device-oriented objects via AD, Infoblox, and config-repo.\n\n"
                "Flags:\n"
                "  --probe     Ping resolved IPs to test reachability (default: false).\n"
                "  --collect   SSH-connect and gather show version / license data; adds\n"
                "              serial/version/image/license to summary['collect'].\n"
                "              Requires device_ssh_enabled=true in config.\n"
                "              Degrades gracefully when SSH is not configured.\n\n"
                "Examples:\n"
                "  device router1.example.net\n"
                "  device router1.example.net --probe\n"
                "  device router1.example.net --collect\n"
                "  device --file devices.txt --format json"
            ),
            summary_key="device",
        ),

        # ------------------------------------------------------------------ #
        # validate-site
        # ------------------------------------------------------------------ #
        CommandSpec(
            name="validate-site",
            workflow_callable=validate_site_objects,
            is_standard_workflow=True,
            options=(),
            value_option_names=frozenset(),
            dispatch_kwargs_fn=None,
            cli_description=(
                "Validate site objects across AD, SD-WAN YAML, Infoblox, config-repo, and DNS. "
                "Reports per-check pass/fail in summary['validate_site']."
            ),
            cli_epilog=(
                "Examples:\n"
                "  cn-lens validate-site SITE01\n"
                "  cn-lens validate-site SITE01 SITE02 --format json"
            ),
            repl_help=(
                "validate-site [<object>...] [--format FMT] [--output PATH]\n\n"
                "Validate site consistency across AD, SD-WAN, Infoblox, config-repo, and DNS.\n\n"
                "Examples:\n"
                "  validate-site SITE01\n"
                "  validate-site SITE01 SITE02 --format json"
            ),
            summary_key="validate_site",
        ),

        # ------------------------------------------------------------------ #
        # decommission-site
        # ------------------------------------------------------------------ #
        CommandSpec(
            name="decommission-site",
            workflow_callable=decommission_site_objects,
            is_standard_workflow=True,
            options=(),
            value_option_names=frozenset(),
            dispatch_kwargs_fn=None,
            cli_description=(
                "Run decommission-readiness checks for site objects. "
                "Active prefixes, config references, AD accounts, or DHCP scopes block "
                "decommission and are reported as 'error' findings. "
                "A clean site produces an 'info' finding: safe to decommission."
            ),
            cli_epilog=(
                "Examples:\n"
                "  cn-lens decommission-site SITE01\n"
                "  cn-lens decommission-site SITE01 --format json"
            ),
            repl_help=(
                "decommission-site [<object>...] [--format FMT] [--output PATH]\n\n"
                "Run decommission-readiness checks. Active prefixes, config refs, AD accounts,\n"
                "or DHCP scopes block decommission (reported as error findings).\n\n"
                "Examples:\n"
                "  decommission-site SITE01\n"
                "  decommission-site SITE01 --format json"
            ),
            summary_key="decommission_site",
        ),

        # ------------------------------------------------------------------ #
        # allocate
        # ------------------------------------------------------------------ #
        CommandSpec(
            name="allocate",
            workflow_callable=allocate_objects,
            is_standard_workflow=True,
            options=(
                (
                    ["--target-site"],
                    {
                        "default": None,
                        "metavar": "SITE_CODE",
                        "dest": "target_site",
                        "help": "site code to allocate the prefix into",
                    },
                ),
            ),
            value_option_names=frozenset({"--target-site"}),
            dispatch_kwargs_fn=lambda ns: {"target_site": ns.target_site},
            cli_description=(
                "Safety-check a candidate prefix before allocation. "
                "Confirms the prefix is available in Infoblox, has no overlap with existing "
                "networks, passes inheritance checks, and the target AD site can host it. "
                "Use --target-site to specify the destination site code."
            ),
            cli_epilog=(
                "Examples:\n"
                "  cn-lens allocate 10.5.0.0/24 --target-site SITE01\n"
                "  cn-lens allocate 10.5.0.0/24 --format json"
            ),
            repl_help=(
                "allocate [<object>...] [--target-site SITE_CODE] [--format FMT] [--output PATH]\n\n"
                "Safety-check a candidate prefix before allocation in Infoblox.\n\n"
                "Flags:\n"
                "  --target-site SITE_CODE   Destination site for the allocation.\n\n"
                "Examples:\n"
                "  allocate 10.5.0.0/24 --target-site SITE01\n"
                "  allocate 10.5.0.0/24 --format json"
            ),
            summary_key="allocate",
        ),

        # ------------------------------------------------------------------ #
        # bssid  (offline-always: pure MAC → BSSID conversion, no adapters)
        # ------------------------------------------------------------------ #
        CommandSpec(
            name="bssid",
            workflow_callable=None,  # non-standard: handled separately in both entry points
            is_standard_workflow=False,
            options=(),
            value_option_names=frozenset(),
            dispatch_kwargs_fn=None,
            cli_description=(
                "Convert wired Ethernet MAC addresses to Aruba BSSID radio MACs.\n\n"
                "Accepts one or more MAC addresses as positional targets.\n"
                "Outputs the 2.4GHz and 5GHz BSSID MACs for each wired MAC.\n\n"
                "This command is offline-always: no live adapters are contacted.\n\n"
                "Accepted MAC formats (case-insensitive):\n"
                "  xx:xx:xx:xx:xx:xx\n"
                "  xx-xx-xx-xx-xx-xx\n"
                "  xxxx.xxxx.xxxx\n"
                "  xxxxxxxxxxxx"
            ),
            cli_epilog=(
                "Examples:\n"
                "  cn-lens bssid d0:4d:c6:c8:6d:6e\n"
                "  cn-lens bssid d0:4d:c6:c8:6d:6e aa:bb:cc:dd:ee:ff\n"
                "  cn-lens bssid d0:4d:c6:c8:6d:6e --format json\n"
                "  cn-lens bssid --file macs.txt --format xlsx --output bssids.xlsx"
            ),
            repl_help=(
                "bssid <mac>... [--file PATH] [--format FMT] [--output PATH]\n\n"
                "Convert wired Ethernet MAC addresses to Aruba BSSID radio MACs.\n\n"
                "This command is offline-always: no live adapters are contacted.\n\n"
                "Accepted MAC formats (case-insensitive):\n"
                "  xx:xx:xx:xx:xx:xx\n"
                "  xx-xx-xx-xx-xx-xx\n"
                "  xxxx.xxxx.xxxx\n"
                "  xxxxxxxxxxxx\n\n"
                "Examples:\n"
                "  bssid d0:4d:c6:c8:6d:6e\n"
                "  bssid d0:4d:c6:c8:6d:6e aa:bb:cc:dd:ee:ff\n"
                "  bssid d0:4d:c6:c8:6d:6e --format json\n"
                "  bssid --file macs.txt"
            ),
            summary_key="bssid",
        ),

        # ------------------------------------------------------------------ #
        # config  (special: two-token form, handled separately in both entry points)
        # ------------------------------------------------------------------ #
        CommandSpec(
            name="config",
            workflow_callable=None,
            is_standard_workflow=False,
            options=(),
            value_option_names=frozenset({"--scope", "--limit", "--repo-root", "--snapshots", "--context"}),
            dispatch_kwargs_fn=None,
            cli_description=(
                "Config repository commands.\n\n"
                "Subcommands:\n"
                "  find  Search config repository and SD-WAN YAML.\n"
                "  diff  Diff two snapshots for a device.\n"
                "  get   Show current config values (secrets redacted).\n"
                "  set   Write a config value to ~/.cn.\n"
                "  test  Probe Infoblox + AD connectivity."
            ),
            cli_epilog="",
            repl_help=(
                "config find <query>... [--scope all|cfg|yaml] [--limit N] [--format FMT] [--output PATH]\n"
                "config diff DEVICE [--repo-root PATH] [--snapshots A B] [--side-by-side] [--context N]\n"
                "config get [KEY]\n"
                "config set KEY VALUE\n"
                "config test\n\n"
                "Config repository commands.\n\n"
                "config find:\n"
                "  Search config repository and SD-WAN YAML for the given query strings.\n"
                "  Flags: --scope all|cfg|yaml (default: all), --limit N\n\n"
                "config diff:\n"
                "  Diff two snapshots for a device. Exit 1 when differences found, 0 when identical.\n"
                "  Flags: --repo-root PATH, --snapshots A B, --side-by-side, --context N\n\n"
                "config get [KEY]:\n"
                "  Show one or all config values. Secret keys (password, credentials) are redacted.\n\n"
                "config set KEY VALUE:\n"
                "  Write KEY=VALUE to ~/.cn (user config layer).\n\n"
                "config test:\n"
                "  Probe Infoblox API and Active Directory connectivity.\n\n"
                "Examples:\n"
                "  config find 10.1.0.0/24\n"
                "  config find bgp --scope cfg --limit 20\n"
                "  config diff router01 --repo-root /repo\n"
                "  config diff router01 --snapshots /repo/history/r1/v1.cfg /repo/r1.cfg\n"
                "  config get\n"
                "  config get api_endpoint\n"
                "  config set api_endpoint https://infoblox.example.com\n"
                "  config test"
            ),
            summary_key="config_find",
        ),

        # ------------------------------------------------------------------ #
        # report  (special: no positional objects, uses --from-last / --include)
        # ------------------------------------------------------------------ #
        CommandSpec(
            name="report",
            workflow_callable=None,
            is_standard_workflow=False,
            options=(),
            value_option_names=frozenset({"--include", "--email", "--keep", "--older-than", "--delete"}),
            dispatch_kwargs_fn=None,
            cli_description=(
                "Bundle one or more persisted LensRun objects into a LensReport. "
                "Use --from-last to include the most recent run, or --include to "
                "specify run IDs explicitly. At least one of --from-last or "
                "--include must be provided. "
                "Runs are persisted under <output_dir>/cn-lens/<run_id>/run.json.gz.\n\n"
                "Pruning / deletion:\n"
                "  --prune --keep N         Delete all but the N newest runs.\n"
                "  --prune --older-than DAYS  Delete runs older than DAYS days.\n"
                "  --delete RUN_ID          Delete a single run by ID."
            ),
            cli_epilog=(
                "Examples:\n"
                "  cn-lens report --from-last\n"
                "  cn-lens report --from-last --format xlsx --output report.xlsx\n"
                "  cn-lens report --include 20260511T120000Z --email ops@example.com\n"
                "  cn-lens report --prune --keep 10\n"
                "  cn-lens report --prune --older-than 30\n"
                "  cn-lens report --delete 20260511T120000Z"
            ),
            repl_help=(
                "report [--from-last] [--include RUN_ID]... [--email ADDR] [--format FMT] [--output PATH]\n"
                "       [--prune --keep N | --prune --older-than DAYS] [--delete RUN_ID]\n\n"
                "Bundle persisted LensRun objects into a LensReport.\n"
                "Runs are stored under <output_dir>/cn-lens/<run_id>/run.json.gz.\n\n"
                "Flags:\n"
                "  --from-last            Include the most recent persisted run.\n"
                "  --include RUN_ID       Add a specific run (repeatable).\n"
                "  --email ADDR           Send via email plugin (if loaded).\n"
                "  --prune                Prune persisted runs (requires --keep or --older-than).\n"
                "  --keep N               Keep N newest runs (use with --prune).\n"
                "  --older-than DAYS      Delete runs older than DAYS days (use with --prune).\n"
                "  --delete RUN_ID        Delete a single run by ID.\n\n"
                "Examples:\n"
                "  report --from-last\n"
                "  report --from-last --format xlsx --output report.xlsx\n"
                "  report --include 20260511T120000Z --email ops@example.com\n"
                "  report --prune --keep 10\n"
                "  report --prune --older-than 30\n"
                "  report --delete 20260511T120000Z"
            ),
            summary_key="report",
        ),

        # ------------------------------------------------------------------ #
        # stats  (offline-capable read-only; no per-object dispatch)
        # ------------------------------------------------------------------ #
        CommandSpec(
            name="stats",
            workflow_callable=stats_objects,
            is_standard_workflow=False,
            options=(
                (
                    ["--period"],
                    {
                        "default": "all",
                        "choices": ("all", "7d", "4w", "1m", "12m"),
                        "dest": "period",
                        "help": (
                            "reporting period: all (default), 7d, 4w, 1m, 12m"
                        ),
                    },
                ),
            ),
            value_option_names=frozenset({"--period"}),
            dispatch_kwargs_fn=lambda ns: {"period_key": getattr(ns, "period", "all")},
            cli_description=(
                "Display cn-tool/cn-lens shared usage statistics.\n\n"
                "Reads and aggregates per-user session files from the configured\n"
                "stats directory (stats_directory in [stats] section of .cn config).\n\n"
                "This command is offline-capable: no live adapters are consulted.\n\n"
                "Requires stats collection to be enabled in the config:\n"
                "  [stats]\n"
                "  collect_enabled = true\n"
                "  menu_enabled = true\n"
                "  directory = /shared/stats"
            ),
            cli_epilog=(
                "Examples:\n"
                "  cn-lens stats\n"
                "  cn-lens stats --period 7d\n"
                "  cn-lens stats --period all --format json\n"
                "  cn-lens stats --format xlsx --output stats.xlsx"
            ),
            repl_help=(
                "stats [--period all|7d|4w|1m|12m] [--format FMT] [--output PATH]\n\n"
                "Display cn-tool/cn-lens shared usage statistics.\n\n"
                "Reads and aggregates per-user session files from the configured\n"
                "stats directory.  Offline-capable: no live adapters consulted.\n\n"
                "Flags:\n"
                "  --period all|7d|4w|1m|12m   Reporting period (default: all).\n\n"
                "Requires stats_collect_enabled or stats_menu_enabled in .cn config.\n\n"
                "Examples:\n"
                "  stats\n"
                "  stats --period 7d\n"
                "  stats --format json"
            ),
            summary_key="stats",
        ),

        # ------------------------------------------------------------------ #
        # e911  (online: SSH collect via device_ssh adapter)
        # ------------------------------------------------------------------ #
        CommandSpec(
            name="e911",
            workflow_callable=e911_objects,
            is_standard_workflow=True,
            options=(),
            value_option_names=frozenset(),
            dispatch_kwargs_fn=None,
            cli_description=(
                "Collect E911 stack member MAC addresses from network switches.\n\n"
                "Connects to each target device via SSH (netmiko), runs 'show switch',\n"
                "and returns per-stack-member MAC addresses in both colon\n"
                "(AA:BB:CC:DD:EE:FF) and dot (AABB.CCDD.EEFF) formats.\n\n"
                "Requires device_ssh_enabled=true in config and device-scope credentials.\n"
                "Degrades gracefully when SSH is not configured.\n\n"
                "Per-device error isolation: one unreachable device does not cancel\n"
                "results from other devices in the same batch."
            ),
            cli_epilog=(
                "Examples:\n"
                "  cn-lens e911 10.0.0.1\n"
                "  cn-lens e911 10.0.0.1 10.0.0.2 switch01.example.com\n"
                "  cn-lens e911 10.0.0.1 --format json\n"
                "  cn-lens e911 --file switches.txt --format xlsx --output e911.xlsx"
            ),
            repl_help=(
                "e911 [<device>...] [--file PATH] [--column COL] [--format FMT] [--output PATH]\n\n"
                "Collect E911 stack member MAC addresses from network switches via SSH.\n\n"
                "Runs 'show switch' on each target and returns per-member MACs in both\n"
                "colon (AA:BB:CC:DD:EE:FF) and dot (AABB.CCDD.EEFF) formats.\n\n"
                "Requires device_ssh_enabled=true in config.\n"
                "Degrades gracefully when SSH is not configured (status: not_configured).\n\n"
                "Examples:\n"
                "  e911 10.0.0.1\n"
                "  e911 10.0.0.1 10.0.0.2 switch01.example.com\n"
                "  e911 --file switches.txt --format json"
            ),
            summary_key="e911",
        ),

        # ------------------------------------------------------------------ #
        # interactive  (shell-only, no workflow)
        # ------------------------------------------------------------------ #
        CommandSpec(
            name="interactive",
            workflow_callable=None,
            is_standard_workflow=False,
            options=(),
            value_option_names=frozenset(),
            dispatch_kwargs_fn=None,
            cli_description=(
                "Start the interactive REPL shell. "
                "Equivalent to running cn-lens with no arguments. "
                "Type 'help' inside the shell for a list of commands."
            ),
            cli_epilog="",
            repl_help="",
            summary_key=None,
        ),

        # ------------------------------------------------------------------ #
        # doctor  (special: --offline uses SUPPRESS in CLI, --format choices)
        # ------------------------------------------------------------------ #
        CommandSpec(
            name="doctor",
            workflow_callable=None,
            is_standard_workflow=False,
            options=(),
            value_option_names=frozenset({"--format"}),
            dispatch_kwargs_fn=None,
            cli_description=(
                "Check health of live source adapters (Infoblox, AD, config-repo, DNS).\n\n"
                "In online mode doctor runs cheap config-only checks for all adapters,\n"
                "then performs deep connectivity probes for Infoblox (HTTP grid endpoint)\n"
                "and Active Directory (LDAP bind).  Deep probes may prompt for credentials\n"
                "when the adapter is configured but credentials are not yet cached.\n\n"
                "In offline mode (--offline) all adapters are reported as not_queried;\n"
                "no probes are run and no credentials are requested."
            ),
            cli_epilog="",
            repl_help=(
                "doctor [--format human|json] [--offline]\n\n"
                "Check health of live source adapters (Infoblox, AD, config-repo, DNS).\n\n"
                "In online mode doctor runs cheap config-only checks for all adapters,\n"
                "then performs deep connectivity probes for Infoblox (HTTP grid endpoint)\n"
                "and Active Directory (LDAP bind).  Deep probes may prompt for credentials\n"
                "when the adapter is configured but credentials are not yet cached.\n\n"
                "In offline mode (--offline or when the shell was started with --offline)\n"
                "all adapters are reported as not_queried; no probes are run.\n\n"
                "Examples:\n"
                "  doctor\n"
                "  doctor --format json\n"
                "  doctor --offline"
            ),
            summary_key=None,
        ),
    ]


#: The command table — single source of truth for all commands.
COMMAND_TABLE: list[CommandSpec] = _make_table()


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------


def get_command(name: str) -> CommandSpec | None:
    """Return the :class:`CommandSpec` for *name*, or ``None`` if not found."""
    for spec in COMMAND_TABLE:
        if spec.name == name or name in spec.aliases:
            return spec
    return None


def get_standard_workflow_commands() -> list[CommandSpec]:
    """Return all :class:`CommandSpec` entries that follow the standard workflow pattern."""
    return [spec for spec in COMMAND_TABLE if spec.is_standard_workflow]


