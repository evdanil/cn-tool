from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import cn_buildstamp
from cn_lens import __version__
from cn_lens.classifier import classify_many
from cn_lens.commands import COMMAND_TABLE, CommandSpec, get_command
from cn_lens.input_sources import (
    RawInputSource,
    collect_raw_inputs_from_sources,
    extract_input_sources_from_namespace,
)
from cn_lens.models import LensRun
from cn_lens.renderers import render_run, render_report
from cn_lens.runtime import LensOptions, LensRuntime, build_runtime
from cn_lens.workflows import (
    allocate_objects,
    config_find_objects,
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
from cn_lens.workflows.config_diff import config_diff
from cn_lens.workflows.report import _build_report_artifacts, _make_empty_object_set, dispatch_report_email
from cn_lens.workflows.stats import stats_objects
from cn_lens.workflows._helpers import make_run_id, maybe_persist


def _derive_known_commands(
    command_table: "list[CommandSpec] | None" = None,
) -> frozenset:
    """Derive the set of known command names+aliases from *command_table*.

    Called at module-load time to initialise :data:`KNOWN_COMMANDS`, and
    exposed as a public helper so tests can re-derive the set from a monkeypatched
    table without re-importing the module.

    Parameters
    ----------
    command_table:
        The command table to derive from.  When ``None`` (the default), reads
        from :data:`cn_lens.commands.COMMAND_TABLE` at call time so that
        monkeypatched tables are picked up correctly.
    """
    import cn_lens.commands as _cmd_mod
    table = command_table if command_table is not None else _cmd_mod.COMMAND_TABLE
    return frozenset(
        {spec.name for spec in table}
        | {alias for spec in table for alias in spec.aliases}
    )


KNOWN_COMMANDS: frozenset = _derive_known_commands()
RENDER_FORMATS = ("human", "text", "txt", "md", "markdown", "json", "yaml", "yml", "xlsx")
GLOBAL_OPTIONS_WITH_VALUES = {"--config"}
# Flags that argparse handles at the top level without needing a subcommand.
# These cause _inject_default_command to return early so argparse can process
# them directly (e.g. --help prints help and exits, --version prints version).
GLOBAL_ABORT_FLAGS = {"-h", "--help", "--version"}
# Valueless flags that should be skipped (continued past) while scanning for
# the first bare token — they must NOT abort default-command injection.
# Example: cn-lens --offline 10.0.0.1  →  injects 'inspect' after --offline.
GLOBAL_SKIP_FLAGS = {"--offline"}

class CliUsageError(Exception):
    pass


class LensArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliUsageError(message)


def main(
    argv: Sequence[str] | None = None,
    _registry: Any = None,
) -> int:
    """Entry-point for the cn-lens CLI.

    Parameters
    ----------
    argv:
        Argument list (defaults to ``sys.argv[1:]`` when ``None``).
    _registry:
        Optional ``AdapterRegistry`` override injected by tests.  When
        ``None`` (the default) the shared singleton is used.  Not a public
        interface; use only in tests.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()

    if not args:
        # No subcommand: enter interactive shell with a runtime built from
        # default options so that future callers (e.g. cn-lens --offline) get
        # correct runtime state.  Parse global flags first even in this branch.
        namespace = argparse.Namespace()
        runtime = _build_runtime_from_namespace(namespace)
        return _run_interactive(runtime=runtime)

    args = _inject_default_command(args)

    try:
        namespace, unknown_args = parser.parse_known_args(args)
        command = getattr(namespace, "command", None)
        if unknown_args and not _unknown_args_are_positional_objects(command, unknown_args):
            raise CliUsageError(f"unrecognized arguments: {' '.join(unknown_args)}")
    except SystemExit as exc:
        if exc.code is None or exc.code == 0:
            return 0
        try:
            return int(exc.code)
        except (TypeError, ValueError):
            return 2
    except CliUsageError as exc:
        print(f"cn-lens: {exc}", file=sys.stderr)
        return 2

    command = getattr(namespace, "command", None)
    runtime = _build_runtime_from_namespace(namespace)

    _exit_code = 0
    _exc_to_reraise = None
    try:
        if command == "doctor":
            _exit_code = _run_doctor(namespace, runtime, _registry=_registry)
        elif command == "interactive":
            _exit_code = _run_interactive(runtime=runtime)

        # --- Standard workflow subcommands driven by the command table ---
        else:
            spec = get_command(command) if command is not None else None
            workflow_callable = _get_workflow_callable_for(command) if spec is not None and spec.is_standard_workflow else None
            if spec is not None and spec.is_standard_workflow and workflow_callable is not None:
                input_sources = _extract_subcommand_input_sources(args, command, namespace, unknown_args)
                workflow_kwargs: dict[str, Any] = {}
                if spec.dispatch_kwargs_fn is not None:
                    workflow_kwargs = spec.dispatch_kwargs_fn(namespace)
                _exit_code = _run_workflow(
                    namespace,
                    input_sources,
                    workflow_callable,
                    runtime=runtime,
                    **workflow_kwargs,
                )

            elif command == "bssid":
                _exit_code = _run_bssid(namespace, runtime)

            elif command == "config":
                # The 'config' subcommand dispatches to 'find' or 'diff'.
                sub = getattr(namespace, "config_subcommand", None)
                if sub == "find":
                    # 'queries' holds the positional arguments after 'find'.
                    queries: list[str] = getattr(namespace, "queries", [])
                    if not queries:
                        print(
                            "cn-lens: config find requires at least one query", file=sys.stderr
                        )
                        _exit_code = 1
                    else:
                        # Build ObjectSet directly from query tokens — config find
                        # accepts arbitrary regex/multi-word patterns that must NOT
                        # be routed through classify_many (which would reject them
                        # as invalid, landing exit 1 or silently truncating them).
                        # Each shell-quoted/argv token is exactly one query.
                        object_set = _make_query_object_set(queries)
                        run_id = runtime.options.run_id if runtime is not None else None
                        run = config_find_objects(
                            object_set,
                            runtime=runtime,
                            run_id=run_id,
                            scope=namespace.scope,
                            limit=namespace.limit,
                        )
                        fmt = getattr(namespace, "format", "human") or "human"
                        output = Path(namespace.output) if getattr(namespace, "output", None) else None
                        if fmt == "xlsx" and output is None:
                            print("cn-lens: xlsx output requires --output", file=sys.stderr)
                            _exit_code = 2
                        else:
                            try:
                                rendered = render_run(run, fmt, output)
                            except (OSError, ValueError) as exc:
                                print(f"cn-lens: {exc}", file=sys.stderr)
                                _exit_code = 2
                            else:
                                if output is None:
                                    if rendered is not None:
                                        print(rendered, end="")
                                else:
                                    print(f"Wrote {output}")
                                _exit_code = 0 if object_set.objects else 1

                elif sub == "diff":
                    _exit_code = _run_config_diff(namespace, runtime)

                elif sub == "get":
                    _exit_code = _run_config_get(namespace, runtime)

                elif sub == "set":
                    _exit_code = _run_config_set(namespace, runtime)

                elif sub == "test":
                    _exit_code = _run_config_test(namespace, runtime)

                else:
                    # Unreachable in normal flow (argparse already raises), but guard here.
                    print(
                        f"cn-lens: config requires a subcommand: find, diff, get, set, test",
                        file=sys.stderr,
                    )
                    _exit_code = 2

            elif command == "report":
                _exit_code = _run_report(namespace, runtime)

            elif command == "stats":
                _exit_code = _run_stats(namespace, runtime)

            else:
                _exit_code = _run_interactive(runtime=runtime)

    except KeyboardInterrupt:
        _exc_to_reraise = None
        if runtime is not None and runtime.stats is not None:
            try:
                runtime.stats.finalize_session("interrupted")
                runtime.stats.close()
            except Exception:
                pass
        raise
    except Exception:
        if runtime is not None and runtime.stats is not None:
            try:
                runtime.stats.finalize_session("failed")
                runtime.stats.close()
            except Exception:
                pass
        raise
    else:
        # Normal exit — finalize session as completed.
        if runtime is not None and runtime.stats is not None:
            try:
                runtime.stats.finalize_session("completed")
                runtime.stats.close()
            except Exception:
                pass

    return _exit_code


def _inject_default_command(args: list[str]) -> list[str]:
    """Inject 'inspect' before the first bare non-option token when no subcommand is present.

    Scanning rules (first match wins for each token):
    - GLOBAL_ABORT_FLAGS (-h, --help, --version): return early — argparse handles
      these at the top level without needing a subcommand.
    - GLOBAL_SKIP_FLAGS (--offline, ...): skip while scanning — these are valueless
      pass-through flags shared by the top-level parser and every subcommand.
      They must NOT block default-command injection.  When injection happens, any
      leading GLOBAL_SKIP_FLAGS tokens are moved to after the injected 'inspect'
      token so that the inspect subparser (not the top-level parser) sees them and
      records the correct value in the namespace.
    - GLOBAL_OPTIONS_WITH_VALUES (--config): skip the option AND its value token.
    - A bare KNOWN_COMMAND token: return early — user specified a subcommand.
    - Any other token (bare object, '-', etc.): inject 'inspect' before it.
    """
    for index, token in enumerate(args):
        if token in GLOBAL_ABORT_FLAGS:
            return args
        if token in GLOBAL_SKIP_FLAGS:
            continue
        if token in GLOBAL_OPTIONS_WITH_VALUES:
            if index + 1 >= len(args):
                return args
            continue
        if any(token.startswith(f"{option}=") for option in GLOBAL_OPTIONS_WITH_VALUES):
            continue
        if index > 0 and args[index - 1] in GLOBAL_OPTIONS_WITH_VALUES:
            continue
        if token in KNOWN_COMMANDS:
            return args
        # Inject 'inspect'.  Move any leading GLOBAL_SKIP_FLAGS tokens (e.g.
        # --offline) to after the injected subcommand so the inspect subparser
        # sees them and sets the attribute correctly in the namespace.
        prefix = args[:index]   # tokens before the bare object (global flags/opts)
        rest = args[index:]     # bare object onwards
        skip_flags = [t for t in prefix if t in GLOBAL_SKIP_FLAGS]
        non_skip = [t for t in prefix if t not in GLOBAL_SKIP_FLAGS]
        return [*non_skip, "inspect", *skip_flags, *rest]
    return args


def _build_parser(_command_table: list[CommandSpec] | None = None) -> argparse.ArgumentParser:
    """Build and return the top-level argument parser.

    Parameters
    ----------
    _command_table:
        Command table to use.  When ``None`` (the default), reads from
        :data:`cn_lens.commands.COMMAND_TABLE` at call time so that tests can
        monkeypatch the module-level list and have the parser reflect the
        patched table without needing to pass it explicitly.
    """
    if _command_table is None:
        import cn_lens.commands as _cmd_mod
        _command_table = _cmd_mod.COMMAND_TABLE

    parser = LensArgumentParser(
        prog="cn-lens",
        description=(
            "Task-first network object lens.\n\n"
            "Workflows (by purpose):\n"
            "  inspect            Classify objects and render offline inspection evidence.\n"
            "  impact             Find all references to objects across available sources.\n"
            "  dns                Resolve DNS and Infoblox DNS records.\n"
            "  reachability       Ping/trace reachability checks.\n"
            "  device             Enrich device-oriented objects (AD, IB, config).\n"
            "  validate-site      Validate site consistency across AD, IB, DNS, config.\n"
            "  decommission-site  Run decommission-readiness checks for a site.\n"
            "  allocate           Safety-check a candidate prefix before allocation.\n"
            "  e911               Resolve E911 location records for IP/MAC objects.\n"
            "  config find        Search config repository and SD-WAN YAML.\n"
            "  config diff        Diff two snapshots for a device.\n"
            "  config get         Show current configuration values.\n"
            "  config set         Write a configuration value to ~/.cn.\n"
            "  config test        Probe adapter connectivity.\n"
            "  report             Bundle persisted runs into a LensReport.\n"
            "  stats              Display cn-tool/cn-lens usage statistics.\n"
            "  bssid              Convert wired MAC addresses to Aruba BSSID radio MACs.\n\n"
            "Shell:\n"
            "  interactive        Start the interactive REPL (default when no args given).\n"
            "  doctor             Check live source adapter health."
        ),
        epilog=(
            "Run 'cn-lens <subcommand> --help' for per-workflow options and examples.\n"
            "Input: positional args, --file PATH, CSV --column NAME, or stdin '-'.\n"
            "Output: --format human|text|md|json|yaml|xlsx  --output PATH"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", help="path to .cn configuration file")
    parser.add_argument(
        "--offline",
        action="store_true",
        default=False,
        help="skip all live adapters; use offline classification only",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=cn_buildstamp.version_line("cn-lens", __version__),
    )
    subparsers = parser.add_subparsers(dest="command")

    # Build subparsers for standard workflow commands from the table.
    for spec in _command_table:
        if not spec.is_standard_workflow:
            continue
        sub = subparsers.add_parser(
            spec.name,
            description=spec.cli_description,
            epilog=spec.cli_epilog or None,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        _add_common_input_args(sub)
        # Add per-command extra options.
        for flags, kwargs in spec.options:
            sub.add_argument(*flags, **kwargs)
        # Every standard workflow gets --offline with SUPPRESS (parent-namespace
        # shadowing fix), so the flag works in trailing position uniformly.
        sub.add_argument(
            "--offline",
            action="store_true",
            # SUPPRESS prevents the subparser from writing a default value into the
            # namespace when --offline is absent.  Without this, argparse applies the
            # subparser default (False) AFTER the parent parser has already set the
            # attribute to True (e.g. `cn-lens --offline inspect 10.0.0.1`), silently
            # clobbering the parent value.  When --offline IS present at the subparser
            # level, store_true still fires and correctly sets the attribute to True.
            # The top-level parser defines --offline with default=False, so the
            # attribute always exists in the namespace regardless of this SUPPRESS.
            default=argparse.SUPPRESS,
            help="skip all live adapters; use offline classification only",
        )
        sub.add_argument(
            "--version",
            action="version",
            # NOTE: action="version" never writes a namespace attribute — argparse
            # prints the version string and calls sys.exit(0) immediately.  There is
            # no default-shadowing risk for --version; no change needed here.
            version=cn_buildstamp.version_line("cn-lens", __version__),
        )

    # --- bssid (offline-always: MAC → BSSID conversion) ---
    bssid_parser = subparsers.add_parser(
        "bssid",
        description=(
            "Convert wired Ethernet MAC addresses to Aruba BSSID radio MACs.\n\n"
            "This command is offline-always: no live adapters are contacted.\n\n"
            "Accepted MAC formats (case-insensitive):\n"
            "  xx:xx:xx:xx:xx:xx\n"
            "  xx-xx-xx-xx-xx-xx\n"
            "  xxxx.xxxx.xxxx\n"
            "  xxxxxxxxxxxx"
        ),
        epilog=(
            "Examples:\n"
            "  cn-lens bssid d0:4d:c6:c8:6d:6e\n"
            "  cn-lens bssid d0:4d:c6:c8:6d:6e aa:bb:cc:dd:ee:ff\n"
            "  cn-lens bssid d0:4d:c6:c8:6d:6e --format json\n"
            "  cn-lens bssid --file macs.txt --format xlsx --output bssids.xlsx"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    bssid_parser.add_argument(
        "targets",
        nargs="*",
        help="wired MAC addresses to convert",
    )
    bssid_parser.add_argument(
        "--file",
        "-f",
        action="append",
        default=[],
        help="read MAC addresses from a text file (one per line)",
    )
    bssid_parser.add_argument(
        "--format",
        choices=RENDER_FORMATS,
        default="human",
        help="output format: human,text,txt,md,markdown,json,yaml,yml,xlsx",
    )
    bssid_parser.add_argument("--output", "-o", help="write rendered output to a file")
    bssid_parser.add_argument(
        "--offline",
        action="store_true",
        default=argparse.SUPPRESS,
        help="(accepted but ignored — bssid is offline-always)",
    )

    # --- config (two-token: config find <queries...>) ---
    # Strategy (a): single 'config' subparser with a required second-level
    # subparser for 'find'.  This gives clean error messages like:
    #   "cn-lens: argument config_subcommand: invalid choice: 'xyz'"
    # when the user types 'config xyz', and the 'find' sub-subparser holds
    # --scope, --limit, and the positional queries.
    config_parser = subparsers.add_parser(
        "config",
        description=(
            "Search config repository and SD-WAN YAML.\n"
            "Usage: cn-lens config find <query> [<query>...] [--scope all|cfg|yaml] [--limit N]"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    config_subparsers = config_parser.add_subparsers(dest="config_subcommand")
    config_subparsers.required = True
    find_parser = config_subparsers.add_parser(
        "find",
        description=(
            "Search config_repo/SD-WAN YAML for the given query strings. "
            "All positional tokens after 'find' are treated as independent queries."
        ),
        epilog=(
            "Examples:\n"
            "  cn-lens config find 10.1.0.0/24\n"
            "  cn-lens config find SITE01 --scope cfg --limit 20\n"
            "  cn-lens config find bgp --format json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    find_parser.add_argument(
        "queries",
        nargs="*",
        help="one or more query strings to search for",
    )
    find_parser.add_argument(
        "--scope",
        choices=("all", "cfg", "yaml"),
        default="all",
        help="search scope: all, cfg, or yaml (default: all)",
    )
    find_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="maximum number of matches to return per query",
    )
    find_parser.add_argument(
        "--format",
        choices=RENDER_FORMATS,
        default="human",
        help="output format (default: human)",
    )
    find_parser.add_argument("--output", "-o", help="write rendered output to a file")
    find_parser.add_argument(
        "--offline",
        action="store_true",
        default=argparse.SUPPRESS,
        help="skip all live adapters; use cached/offline data only",
    )

    # --- config diff sub-subparser ---
    diff_parser = config_subparsers.add_parser(
        "diff",
        description=(
            "Diff two snapshots for a device from the config repository.\n\n"
            "By default the two most recent snapshots are compared. "
            "Use --snapshots A B to specify exact snapshot file paths.\n\n"
            "Exit code: 1 when differences found; 0 when identical (like diff(1))."
        ),
        epilog=(
            "Examples:\n"
            "  cn-lens config diff router01 --repo-root /repo\n"
            "  cn-lens config diff router01 --repo-root /repo --format json\n"
            "  cn-lens config diff router01 --snapshots /repo/history/r1/r1_v1.cfg /repo/r1.cfg\n"
            "  cn-lens config diff router01 --repo-root /repo --side-by-side\n"
            "  cn-lens config diff router01 --repo-root /repo --context 5"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    diff_parser.add_argument(
        "device",
        help="device name (without .cfg extension)",
    )
    diff_parser.add_argument(
        "--repo-root",
        default=None,
        dest="repo_root",
        metavar="PATH",
        help=(
            "path to the config repository root "
            "(required when --snapshots are not given)"
        ),
    )
    diff_parser.add_argument(
        "--snapshots",
        nargs=2,
        default=None,
        metavar=("A", "B"),
        help="explicit pair of snapshot file paths to compare (A is 'from', B is 'to')",
    )
    diff_parser.add_argument(
        "--side-by-side",
        action="store_true",
        default=False,
        dest="side_by_side",
        help="also include a plain-text side-by-side diff in the output",
    )
    diff_parser.add_argument(
        "--context",
        type=int,
        default=3,
        metavar="N",
        help="number of context lines in the unified diff (default: 3)",
    )
    diff_parser.add_argument(
        "--format",
        choices=RENDER_FORMATS,
        default="human",
        help="output format (default: human)",
    )
    diff_parser.add_argument("--output", "-o", help="write rendered output to a file")
    diff_parser.add_argument(
        "--offline",
        action="store_true",
        default=argparse.SUPPRESS,
        help="(accepted but ignored — config diff reads local repo files only)",
    )

    # --- config get sub-subparser ---
    get_parser = config_subparsers.add_parser(
        "get",
        description=(
            "Show current configuration values. "
            "Secret keys (password, credentials, gpg path) are shown as ***."
        ),
        epilog=(
            "Examples:\n"
            "  cn-lens config get\n"
            "  cn-lens config get api_endpoint\n"
            "  cn-lens config get --format json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    get_parser.add_argument(
        "key",
        nargs="?",
        default=None,
        help="config key to show (omit for all keys)",
    )
    get_parser.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="output format: human (default) or json",
    )
    get_parser.add_argument(
        "--offline",
        action="store_true",
        default=argparse.SUPPRESS,
        help="(accepted but ignored — config get reads local config only)",
    )

    # --- config set sub-subparser ---
    set_parser = config_subparsers.add_parser(
        "set",
        description=(
            "Write a configuration value to the user config file (~/.cn). "
            "The key must be a known schema key."
        ),
        epilog=(
            "Examples:\n"
            "  cn-lens config set api_endpoint https://infoblox.example.com\n"
            "  cn-lens config set logging_level DEBUG"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    set_parser.add_argument("key", help="config key name (e.g. api_endpoint)")
    set_parser.add_argument("value", help="value to write")
    set_parser.add_argument(
        "--offline",
        action="store_true",
        default=argparse.SUPPRESS,
        help="(accepted but ignored — config set writes local config only)",
    )

    # --- config test sub-subparser ---
    test_parser = config_subparsers.add_parser(
        "test",
        description=(
            "Probe Infoblox API and Active Directory connectivity using the "
            "current runtime configuration. Reports ok/error/not_configured per source."
        ),
        epilog="Examples:\n  cn-lens config test\n  cn-lens config test --format json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    test_parser.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="output format: human (default) or json",
    )
    test_parser.add_argument(
        "--offline",
        action="store_true",
        default=argparse.SUPPRESS,
        help="skip all live probes; report every adapter as not_queried",
    )

    # --- report ---
    report_parser = subparsers.add_parser(
        "report",
        description=(
            "Bundle one or more persisted LensRun objects into a LensReport. "
            "Use --from-last to include the most recent run, or --include to "
            "specify run IDs explicitly. At least one of --from-last or "
            "--include must be provided. "
            "Runs are persisted under <output_dir>/cn-lens/<run_id>/run.json.gz."
        ),
        epilog=(
            "Examples:\n"
            "  cn-lens report --from-last\n"
            "  cn-lens report --from-last --format xlsx --output report.xlsx\n"
            "  cn-lens report --include 20260511T120000Z --email ops@example.com"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    report_parser.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="RUN_ID",
        dest="include",
        help="add a persisted run by run_id (repeatable)",
    )
    report_parser.add_argument(
        "--from-last",
        action="store_true",
        default=False,
        dest="from_last",
        help="include the most recent persisted run",
    )
    report_parser.add_argument(
        "--email",
        default=None,
        metavar="TO_ADDR",
        help="send the report via the email plugin (if loaded)",
    )
    report_parser.add_argument(
        "--format",
        choices=RENDER_FORMATS,
        default="human",
        help="output format",
    )
    report_parser.add_argument("--output", "-o", help="write rendered output to a file")
    report_parser.add_argument(
        "--prune",
        action="store_true",
        default=False,
        help="prune persisted runs (requires --keep or --older-than)",
    )
    report_parser.add_argument(
        "--keep",
        type=int,
        default=None,
        metavar="N",
        help="keep N newest runs; delete the rest (use with --prune)",
    )
    report_parser.add_argument(
        "--older-than",
        type=int,
        default=None,
        dest="older_than",
        metavar="DAYS",
        help="delete runs older than DAYS days (use with --prune)",
    )
    report_parser.add_argument(
        "--delete",
        default=None,
        metavar="RUN_ID",
        dest="delete_run_id",
        help="delete a single persisted run by run_id",
    )
    report_parser.add_argument(
        "--offline",
        action="store_true",
        default=argparse.SUPPRESS,
        help="(accepted but ignored — report reads persisted runs from disk only)",
    )

    # --- stats ---
    stats_parser = subparsers.add_parser(
        "stats",
        description=(
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
        epilog=(
            "Examples:\n"
            "  cn-lens stats\n"
            "  cn-lens stats --period 7d\n"
            "  cn-lens stats --period all --format json\n"
            "  cn-lens stats --format xlsx --output stats.xlsx"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    stats_parser.add_argument(
        "--period",
        choices=("all", "7d", "4w", "1m", "12m"),
        default="all",
        dest="period",
        help="reporting period: all (default), 7d, 4w, 1m, 12m",
    )
    stats_parser.add_argument(
        "--format",
        choices=RENDER_FORMATS,
        default="human",
        help="output format",
    )
    stats_parser.add_argument("--output", "-o", help="write rendered output to a file")
    stats_parser.add_argument(
        "--offline",
        action="store_true",
        default=argparse.SUPPRESS,
        help="skip all live adapters (stats is always offline-capable)",
    )

    # --- interactive, doctor ---
    subparsers.add_parser(
        "interactive",
        description=(
            "Start the interactive REPL shell. "
            "Equivalent to running cn-lens with no arguments. "
            "Type 'help' inside the shell for a list of commands."
        ),
    )
    doctor_parser = subparsers.add_parser(
        "doctor",
        description=(
            "Check health of live source adapters (Infoblox, AD, config-repo, DNS).\n\n"
            "In online mode doctor runs cheap config-only checks for all adapters,\n"
            "then performs deep connectivity probes for Infoblox (HTTP grid endpoint)\n"
            "and Active Directory (LDAP bind).  Deep probes may prompt for credentials\n"
            "when the adapter is configured but credentials are not yet cached.\n\n"
            "In offline mode (--offline) all adapters are reported as not_queried;\n"
            "no probes are run and no credentials are requested."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    doctor_parser.add_argument(
        "--offline",
        action="store_true",
        default=argparse.SUPPRESS,
        help="skip all probes; report every adapter as not_queried",
    )
    doctor_parser.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="output format: human (rich table, default) or json (machine-readable)",
    )
    return parser


def _add_common_input_args(p: argparse.ArgumentParser) -> None:
    """Add the standard positional + file/format/output options to a subparser."""
    p.add_argument("objects", nargs="*", help="objects or '-' for stdin")
    p.add_argument(
        "--file",
        "-f",
        action="append",
        default=[],
        help="read objects from a text or CSV file",
    )
    p.add_argument("--column", help="CSV column to read when using --file")
    p.add_argument(
        "--format",
        choices=RENDER_FORMATS,
        default="human",
        help="output format: human,text,txt,md,markdown,json,yaml,yml,xlsx",
    )
    p.add_argument("--output", "-o", help="write rendered output to a file")


def _default_config_paths() -> list[Path]:
    """Return layered .cn config paths in priority order (low -> high).

    1. Global config (.cn next to the script / repo root)
    2. User config (~/.cn)
    3. Current working directory (./.cn)

    The script-dir slot is probed via two sources to cover both invocation styles:
    - ``./cn-lens.py`` wrapper -> ``sys.argv[0]`` parent is the repo root.
    - ``python -m cn_lens.cli`` -> ``sys.argv[0]`` is the module file; the repo
      root is ``Path(__file__).resolve().parent.parent``.
    Duplicate resolved paths are collapsed while preserving low->high priority.
    """
    argv_dir = Path(sys.argv[0]).resolve().parent if sys.argv and sys.argv[0] else None
    module_repo_root = Path(__file__).resolve().parent.parent
    candidates: list[Path] = []
    if argv_dir is not None:
        candidates.append(argv_dir / ".cn")
    candidates.append(module_repo_root / ".cn")
    candidates.append(Path.home() / ".cn")
    candidates.append(Path.cwd() / ".cn")
    return _dedupe_paths(candidates)


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    """Drop duplicate resolved paths, keeping the highest-priority slot.

    Within layered ``.cn`` lookup the list is ordered low -> high priority, so
    when the same file appears twice (e.g. running from the repo root makes
    script-dir and CWD identical) we keep the last occurrence so the log shows
    the slot that actually wins.
    """
    seen: set[Path] = set()
    reversed_out: list[Path] = []
    for p in reversed(paths):
        try:
            key = p.resolve()
        except OSError:
            key = p
        if key in seen:
            continue
        seen.add(key)
        reversed_out.append(p)
    return list(reversed(reversed_out))


def _build_runtime_from_namespace(namespace: argparse.Namespace) -> LensRuntime:
    """Build a LensRuntime from parsed CLI namespace."""
    config_paths = _default_config_paths()
    if getattr(namespace, "config", None):
        config_paths.append(Path(namespace.config).expanduser())
        config_paths = _dedupe_paths(config_paths)
    opts = LensOptions(
        offline=getattr(namespace, "offline", False),
        run_id=None,
    )
    return build_runtime(opts, config_paths=config_paths)


def _run_interactive(*, runtime: LensRuntime | None = None) -> int:
    from cn_lens.interactive import LensShell

    return LensShell(runtime=runtime).run()


def _run_doctor(
    namespace: argparse.Namespace,
    runtime: LensRuntime,
    _registry: Any = None,
) -> int:
    """Execute the doctor subcommand and print results.

    Returns 0 on success (always — doctor is informational).
    Returns 2 only on internal error.
    """
    from cn_lens.doctor import run_doctor

    fmt = getattr(namespace, "format", "human") or "human"
    try:
        output = run_doctor(runtime, _registry, fmt=fmt)
    except Exception as exc:
        print(f"cn-lens doctor: internal error: {exc}", file=sys.stderr)
        return 2
    print(output, end="")
    return 0


def _run_workflow(
    namespace: argparse.Namespace,
    input_sources: Sequence[RawInputSource],
    workflow_callable: Callable[..., LensRun],
    *,
    runtime: LensRuntime | None = None,
    **workflow_kwargs: Any,
) -> int:
    """Shared implementation for all workflow subcommands.

    Collects raw inputs from *input_sources*, classifies them, invokes
    *workflow_callable* with the resulting ``ObjectSet`` (plus *runtime* and any
    extra *workflow_kwargs*), then renders the run according to the format /
    output options on *namespace*.

    Exit codes mirror the ``inspect`` contract:
    - 0: success with at least one valid object.
    - 1: no valid objects (or empty input).
    - 2: I/O or render error.
    """
    fmt: str = getattr(namespace, "format", "human") or "human"
    output = Path(namespace.output) if getattr(namespace, "output", None) else None
    if fmt == "xlsx" and output is None:
        print("cn-lens: xlsx output requires --output", file=sys.stderr)
        return 2

    stdin_text = (
        sys.stdin.read()
        if any(source.kind == "stdin" for source in input_sources)
        else None
    )
    try:
        raw_inputs = collect_raw_inputs_from_sources(
            input_sources,
            csv_column=getattr(namespace, "column", None),
            stdin_text=stdin_text,
        )
    except (OSError, ValueError) as exc:
        print(f"cn-lens: {exc}", file=sys.stderr)
        return 2

    if not raw_inputs:
        command = getattr(namespace, "command", "workflow")
        print(f"cn-lens: {command} requires at least one object", file=sys.stderr)
        return 1

    object_set = classify_many(raw_inputs)
    run_id = runtime.options.run_id if runtime is not None else None
    run = workflow_callable(object_set, runtime=runtime, run_id=run_id, **workflow_kwargs)

    try:
        rendered = render_run(run, fmt, output)
    except (OSError, ValueError) as exc:
        print(f"cn-lens: {exc}", file=sys.stderr)
        return 2

    if output is None:
        if rendered is not None:
            print(rendered, end="")
    else:
        print(f"Wrote {output}")

    return 0 if object_set.objects else 1


# Module-level mapping from command name to the CLI module-level callable name.
# Derived from COMMAND_TABLE so that adding a new workflow spec is the only
# required edit.  Using module-level attribute names means tests can patch
# ``cn_lens.cli.impact_objects`` and have the patch take effect in the dispatch
# path.  The derivation runs at module load time from the live table.
def _derive_workflow_callable_names() -> dict[str, str]:
    """Build the command-name → module-attr-name mapping from COMMAND_TABLE."""
    import cn_lens.commands as _cmd_mod
    result: dict[str, str] = {}
    for spec in _cmd_mod.COMMAND_TABLE:
        if spec.workflow_callable is not None:
            fn_name = spec.workflow_callable.__name__
            result[spec.name] = fn_name
    return result


_WORKFLOW_CALLABLE_NAMES: dict[str, str] = _derive_workflow_callable_names()


def _get_workflow_callable_for(name: str) -> Callable[..., LensRun] | None:
    """Return the module-level workflow callable for command *name*.

    Uses the module's own namespace so that ``patch("cn_lens.cli.impact_objects")``
    correctly intercepts calls made via this function.  Falls back to the
    ``CommandSpec.workflow_callable`` for dynamically-injected probe specs.
    """
    import cn_lens.cli as _self
    attr = _WORKFLOW_CALLABLE_NAMES.get(name)
    if attr is not None:
        return getattr(_self, attr)
    # For dynamically-injected specs (e.g. probe-cmd in tests), fall back to
    # the callable stored in the spec itself.
    spec = get_command(name)
    if spec is not None:
        return spec.workflow_callable
    return None


def _run_report(
    namespace: argparse.Namespace,
    runtime: LensRuntime | None = None,
) -> int:
    """Handle the 'report' CLI subcommand.

    Unlike inspect-style subcommands, 'report' does not take object positionals.
    It requires at least one of --from-last or --include to produce output.

    After building the ``LensReport`` aggregate, this function also persists a
    synthesised summary ``LensRun`` (``workflow="report"``) via
    :func:`~cn_lens.workflows._helpers.maybe_persist` so that the report
    workflow participates in the standard auto-persistence pipeline.
    """
    include: list[str] = getattr(namespace, "include", []) or []
    from_last: bool = getattr(namespace, "from_last", False)
    email: str | None = getattr(namespace, "email", None)
    fmt: str = getattr(namespace, "format", "human") or "human"
    output = Path(namespace.output) if getattr(namespace, "output", None) else None
    prune: bool = getattr(namespace, "prune", False)
    keep: int | None = getattr(namespace, "keep", None)
    older_than: int | None = getattr(namespace, "older_than", None)
    delete_run_id: str | None = getattr(namespace, "delete_run_id", None)

    # --- prune / delete dispatch (mutually exclusive with bundling) ---
    if delete_run_id is not None:
        from cn_lens.reports.persistence import delete_run
        try:
            deleted = delete_run(delete_run_id, runtime)
        except ValueError as exc:
            print(f"cn-lens: {exc}", file=sys.stderr)
            return 2
        if deleted:
            print(f"Deleted run: {delete_run_id}")
        else:
            print(f"cn-lens: run not found: {delete_run_id}", file=sys.stderr)
            return 1
        return 0

    if prune:
        if keep is not None and older_than is not None:
            print(
                "cn-lens: --keep and --older-than are mutually exclusive",
                file=sys.stderr,
            )
            return 2
        if keep is None and older_than is None:
            print(
                "cn-lens: --prune requires --keep N or --older-than DAYS",
                file=sys.stderr,
            )
            return 2
        from cn_lens.reports.persistence import prune_runs
        try:
            deleted_ids = prune_runs(runtime, keep=keep, older_than_days=older_than)
        except ValueError as exc:
            print(f"cn-lens: {exc}", file=sys.stderr)
            return 2
        if deleted_ids:
            print(f"Pruned {len(deleted_ids)} run(s):")
            for rid in deleted_ids:
                print(f"  {rid}")
        else:
            print("No runs pruned.")
        return 0

    if fmt == "xlsx" and output is None:
        print("cn-lens: xlsx output requires --output", file=sys.stderr)
        return 2

    if not include and not from_last:
        print("cn-lens: error: no runs available to bundle", file=sys.stderr)
        return 1

    # Resolve an effective run_id for the synthesised summary LensRun.
    effective_run_id: str = (
        runtime.options.run_id
        if runtime is not None and runtime.options.run_id is not None
        else make_run_id()
    )

    # Build the report data (no email dispatch here — we need the rendered file
    # as attachment, which doesn't exist until after render_report below).
    report, summary_run = _build_report_artifacts(
        runtime=runtime,
        run_id=effective_run_id,
        include=include or None,
        from_last=from_last,
        email=None,  # email dispatched after render; see dispatch_report_email call below
        _last_run=None,
        object_set=_make_empty_object_set(),
    )

    try:
        rendered = render_report(report, fmt, output)
    except (OSError, ValueError) as exc:
        print(f"cn-lens: {exc}", file=sys.stderr)
        return 2

    if output is None:
        if rendered is not None:
            print(rendered, end="")
    else:
        print(f"Wrote {output}")

    # Email dispatch — happens after render so the output file can be attached.
    if email and runtime is not None:
        _sent, _email_findings = dispatch_report_email(
            runtime,
            to=email,
            report_id=report.report_id,
            run_count=len(report.runs),
            attachment_path=output,
        )
        for finding in _email_findings:
            if finding.severity in ("error", "warning"):
                print(f"cn-lens: email: {finding.message}", file=sys.stderr)
            # info findings are silent (logged by send_report_email)

        # Fold the email outcome back into summary_run before persisting so that
        # the persisted LensRun accurately reflects the email result.  The
        # summary["report"]["email_sent"] flag and the email findings must match
        # what the workflow path (_build_report_artifacts with email=...) produces
        # so the two entry points yield identical persisted artefacts.
        if summary_run.results:
            import dataclasses
            old_result = summary_run.results[0]
            old_report_block = dict(old_result.summary.get("report", {}))
            old_report_block["email_sent"] = _sent
            new_summary = dict(old_result.summary)
            new_summary["report"] = old_report_block
            new_findings = old_result.findings + tuple(_email_findings)
            new_result = dataclasses.replace(
                old_result,
                summary=new_summary,
                findings=new_findings,
            )
            summary_run = dataclasses.replace(
                summary_run,
                results=(new_result,) + summary_run.results[1:],
            )

    # Persist the synthesised summary LensRun for the report workflow — AFTER
    # email dispatch so the persisted run carries the accurate email outcome.
    maybe_persist(summary_run, runtime)

    return 0


def _run_stats(
    namespace: argparse.Namespace,
    runtime: LensRuntime | None = None,
) -> int:
    """Handle the 'stats' CLI subcommand.

    Offline-capable: reads local stats files via StatsManager.build_report().
    No live adapters are consulted.

    Exit codes:
    - 0: success.
    - 2: render error.
    """
    from cn_lens.models import ObjectSet

    fmt: str = getattr(namespace, "format", "human") or "human"
    output = Path(namespace.output) if getattr(namespace, "output", None) else None
    if fmt == "xlsx" and output is None:
        print("cn-lens: xlsx output requires --output", file=sys.stderr)
        return 2

    period_key: str = getattr(namespace, "period", "all") or "all"
    run_id = runtime.options.run_id if runtime is not None else None
    object_set = ObjectSet(objects=(), invalid=(), duplicate_count=0)
    run = stats_objects(object_set, runtime=runtime, run_id=run_id, period_key=period_key)

    try:
        rendered = render_run(run, fmt, output)
    except (OSError, ValueError) as exc:
        print(f"cn-lens: {exc}", file=sys.stderr)
        return 2

    if output is None:
        if rendered is not None:
            print(rendered, end="")
    else:
        print(f"Wrote {output}")

    return 0


def _run_bssid(
    namespace: argparse.Namespace,
    runtime: LensRuntime | None = None,
) -> int:
    """Handle the 'bssid' CLI subcommand.

    Unlike standard workflow subcommands, bssid accepts raw MAC addresses (not
    classified network objects) and is offline-always.  It reads targets from
    positional args and/or ``--file`` (one MAC per line).

    Exit codes:
    - 0: at least one valid MAC was converted.
    - 1: no targets provided, or all targets were invalid.
    - 2: I/O or render error.
    """
    fmt: str = getattr(namespace, "format", "human") or "human"
    output = Path(namespace.output) if getattr(namespace, "output", None) else None
    if fmt == "xlsx" and output is None:
        print("cn-lens: xlsx output requires --output", file=sys.stderr)
        return 2

    # Collect raw MAC strings from positionals and --file paths.
    targets: list[str] = list(getattr(namespace, "targets", []) or [])
    for file_path in getattr(namespace, "file", []) or []:
        try:
            lines = Path(file_path).read_text(encoding="utf-8").splitlines()
            targets.extend(line.strip() for line in lines if line.strip())
        except OSError as exc:
            print(f"cn-lens: {exc}", file=sys.stderr)
            return 2

    if not targets:
        print("cn-lens: bssid requires at least one MAC address", file=sys.stderr)
        return 1

    run_id = runtime.options.run_id if runtime is not None else None
    run = bssid_convert(targets, run_id=run_id)

    try:
        rendered = render_run(run, fmt, output)
    except (OSError, ValueError) as exc:
        print(f"cn-lens: {exc}", file=sys.stderr)
        return 2

    if output is None:
        if rendered is not None:
            print(rendered, end="")
    else:
        print(f"Wrote {output}")

    return 0 if run.results else 1


def _run_config_diff(
    namespace: argparse.Namespace,
    runtime: LensRuntime | None = None,
) -> int:
    """Handle the 'config diff' CLI subcommand.

    Exit codes (like diff(1)):
    - 0: snapshots are identical.
    - 1: differences found.
    - 2: usage / I/O error (missing required args, render failure).
    """
    fmt: str = getattr(namespace, "format", "human") or "human"
    output = Path(namespace.output) if getattr(namespace, "output", None) else None
    if fmt == "xlsx" and output is None:
        print("cn-lens: xlsx output requires --output", file=sys.stderr)
        return 2

    device: str = namespace.device
    repo_root: str | None = getattr(namespace, "repo_root", None)
    snapshots: list[str] | None = getattr(namespace, "snapshots", None)
    snapshot_a: str | None = snapshots[0] if snapshots else None
    snapshot_b: str | None = snapshots[1] if snapshots else None
    side_by_side: bool = getattr(namespace, "side_by_side", False)
    context: int = getattr(namespace, "context", 3)

    run_id = runtime.options.run_id if runtime is not None else None
    run = config_diff(
        device=device,
        repo_root=repo_root,
        snapshot_a=snapshot_a,
        snapshot_b=snapshot_b,
        side_by_side=side_by_side,
        context=context,
        runtime=runtime,
        run_id=run_id,
    )

    try:
        rendered = render_run(run, fmt, output)
    except (OSError, ValueError) as exc:
        print(f"cn-lens: {exc}", file=sys.stderr)
        return 2

    if output is None:
        if rendered is not None:
            print(rendered, end="")
    else:
        print(f"Wrote {output}")

    # Exit code follows diff(1) convention: 1 = differences, 0 = identical.
    if run.results:
        cd = run.results[0].summary.get("config_diff", {})
        # If there's an error finding, return 2 (usage/IO error)
        if any(f.severity == "error" for f in run.results[0].findings):
            return 2
        return 1 if cd.get("has_changes") else 0
    return 2


def _run_config_get(
    namespace: argparse.Namespace,
    runtime: LensRuntime | None = None,
) -> int:
    """Handle 'config get [KEY]' CLI subcommand."""
    import json as _json
    from cn_lens.workflows.config_cmd import config_get

    key = getattr(namespace, "key", None)
    fmt = getattr(namespace, "format", "human") or "human"

    entries = config_get(key=key, runtime=runtime)

    if key is not None and not entries:
        print(f"cn-lens: unknown config key: {key!r}", file=sys.stderr)
        return 1

    if fmt == "json":
        print(_json.dumps(entries, indent=2))
        return 0

    # Human: table-style output
    for entry in entries:
        print(f"{entry['key']} = {entry['value']}")
    return 0


def _run_config_set(
    namespace: argparse.Namespace,
    runtime: LensRuntime | None = None,
) -> int:
    """Handle 'config set KEY VALUE' CLI subcommand."""
    from cn_lens.workflows.config_cmd import config_set

    key: str = namespace.key
    value: str = namespace.value

    result = config_set(key=key, value=value, runtime=runtime)
    if result["status"] == "ok":
        from cn_lens.workflows.config_cmd import is_secret_key
        display_value = "***" if is_secret_key(key) else value
        print(f"Set {key} = {display_value}")
        return 0
    else:
        print(f"cn-lens: config set failed: {result.get('message', 'unknown error')}",
              file=sys.stderr)
        return 1


def _run_config_test(
    namespace: argparse.Namespace,
    runtime: LensRuntime | None = None,
) -> int:
    """Handle 'config test' CLI subcommand."""
    import json as _json
    from cn_lens.workflows.config_cmd import config_test

    fmt = getattr(namespace, "format", "human") or "human"
    result = config_test(runtime=runtime)

    if fmt == "json":
        print(_json.dumps(result, indent=2))
    else:
        for source, info in result.items():
            status = info.get("status", "unknown")
            detail = info.get("detail", "")
            detail_str = f"  {detail}" if detail else ""
            print(f"{source}: {status}{detail_str}")

    # Return 1 if any probe returned error status
    if any(info.get("status") == "error" for info in result.values()):
        return 1
    return 0


def _extract_subcommand_input_sources(
    args: Sequence[str],
    command: str,
    namespace: argparse.Namespace,
    unknown_args: Sequence[str] = (),
) -> list[RawInputSource]:
    """Extract input sources for a named subcommand.

    Uses the already-parsed *namespace* to derive sources, so that option values
    can never be mistaken for positional input objects (eliminates B2 class bugs
    without needing an explicit value-option skip-list).  The raw *args* token
    list is used only to recover positional/file interleaving order.

    *unknown_args* carries any positional tokens that ``parse_known_args``
    placed outside the namespace because they appeared after an option in the
    stream (argparse ``nargs="*"`` limitation).  They are folded into
    ``namespace.objects`` in the correct relative order.
    """
    args_list = list(args)
    try:
        index = args_list.index(command) + 1
    except ValueError:
        index = 0

    return extract_input_sources_from_namespace(
        namespace,
        args_list[index:],
        extra_positionals=unknown_args,
    )


def _make_query_object_set(queries: list[str]) -> "Any":
    """Build an ObjectSet from raw config-find query tokens.

    Each token is wrapped as a ``LensObjectType.QUERY`` LensObject so that
    arbitrary regex patterns, multi-word strings, and special characters are
    preserved intact.  The classifier is intentionally bypassed.

    Parameters
    ----------
    queries:
        Raw query strings exactly as delivered by shell argv (one per token).

    Returns
    -------
    ObjectSet
        All tokens as valid QUERY LensObjects; invalid tuple is always empty.
    """
    from cn_lens.models import LensObject, LensObjectType, ObjectSet, InvalidLensObject

    objects: list[LensObject] = []
    seen: set[str] = set()
    for q in queries:
        if not q:
            continue
        if q in seen:
            continue
        seen.add(q)
        objects.append(
            LensObject(
                original=q,
                normalized=q,
                object_type=LensObjectType.QUERY,
                value=q,
            )
        )
    return ObjectSet(
        objects=tuple(objects),
        invalid=(),
        duplicate_count=len(queries) - len(objects),
    )


def _unknown_args_are_positional_objects(
    command: str | None,
    unknown_args: Sequence[str],
) -> bool:
    """Return True when all unknown args are bare positionals (non-flag tokens).

    Allows standard workflow subcommands to receive extra positional object
    tokens without raising a usage error. Applies to all standard workflows
    (inspect, dns, impact, reachability, etc.) not just inspect.
    """
    spec = get_command(command) if command is not None else None
    if spec is None or not spec.is_standard_workflow:
        return False
    return all(arg == "-" or not arg.startswith("-") for arg in unknown_args)
