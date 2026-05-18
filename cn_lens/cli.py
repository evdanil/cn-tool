from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any

from cn_lens.classifier import classify_many
from cn_lens.input_sources import (
    RawInputSource,
    collect_raw_inputs_from_sources,
    extract_ordered_input_sources,
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
    impact_objects,
    inspect_objects,
    reachability_objects,
    validate_site_objects,
)
from cn_lens.workflows.report import _build_report_artifacts, _make_empty_object_set
from cn_lens.workflows._helpers import make_run_id, maybe_persist


KNOWN_COMMANDS = {
    "inspect",
    "interactive",
    "doctor",
    "impact",
    "dns",
    "reachability",
    "device",
    "validate-site",
    "decommission-site",
    "allocate",
    "config",
    "report",
}
RENDER_FORMATS = ("human", "text", "txt", "md", "markdown", "json", "yaml", "yml", "xlsx")
GLOBAL_OPTIONS_WITH_VALUES = {"--config"}
GLOBAL_FLAGS = {"-h", "--help", "--offline", "--version"}


@lru_cache(maxsize=1)
def _read_version() -> str:
    """Read the version from the 'version' file at repo root.

    Returns a ``MAJOR.MINOR.BUILD`` string when the file is present and
    parseable; falls back to ``"unknown"`` otherwise.  Result is cached after
    the first call.
    """
    try:
        # cn_lens/ is one level below the repo root
        version_file = Path(__file__).parent.parent / "version"
        if not version_file.exists():
            return "unknown"
        content = version_file.read_text(encoding="utf-8")
        parts: dict[str, str] = {}
        for line in content.splitlines():
            if "=" in line:
                key, _, val = line.partition("=")
                parts[key.strip()] = val.strip()
        major = parts.get("MAJOR", "")
        minor = parts.get("MINOR", "")
        build = parts.get("BUILD", "")
        if major and minor:
            return f"{major}.{minor}.{build}" if build else f"{major}.{minor}"
    except OSError:
        pass
    return "unknown"
INSPECT_FILE_OPTIONS = {"--file", "-f"}
INSPECT_VALUE_OPTIONS = {"--column", "--format", "--output", "-o"}


class CliUsageError(Exception):
    pass


class LensArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliUsageError(message)


def main(argv: Sequence[str] | None = None) -> int:
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
        if unknown_args and not _unknown_args_are_inspect_objects(command, unknown_args):
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

    if command == "inspect":
        input_sources = _extract_inspect_input_sources(args)
        return _run_inspect(namespace, input_sources, runtime)
    if command == "doctor":
        print("cn-lens doctor: informational — check the 'sources' block of any workflow output for live adapter health")
        return 0
    if command == "interactive":
        return _run_interactive(runtime=runtime)

    # --- New workflow subcommands ---
    if command == "impact":
        input_sources = _extract_subcommand_input_sources(args, command)
        return _run_workflow(namespace, input_sources, impact_objects, runtime=runtime)
    if command == "dns":
        input_sources = _extract_subcommand_input_sources(args, command)
        return _run_workflow(namespace, input_sources, dns_objects, runtime=runtime)
    if command == "reachability":
        input_sources = _extract_subcommand_input_sources(args, command)
        return _run_workflow(
            namespace,
            input_sources,
            reachability_objects,
            runtime=runtime,
            mode=namespace.mode,
        )
    if command == "device":
        input_sources = _extract_subcommand_input_sources(args, command)
        return _run_workflow(
            namespace,
            input_sources,
            device_objects,
            runtime=runtime,
            probe=namespace.probe,
        )
    if command == "validate-site":
        input_sources = _extract_subcommand_input_sources(args, command)
        return _run_workflow(
            namespace, input_sources, validate_site_objects, runtime=runtime
        )
    if command == "decommission-site":
        input_sources = _extract_subcommand_input_sources(args, command)
        return _run_workflow(
            namespace, input_sources, decommission_site_objects, runtime=runtime
        )
    if command == "allocate":
        input_sources = _extract_subcommand_input_sources(args, command)
        return _run_workflow(
            namespace,
            input_sources,
            allocate_objects,
            runtime=runtime,
            target_site=namespace.target_site,
        )
    if command == "config":
        # The 'config' subcommand requires a second token 'find'; enforced by
        # the sub-subparser inside _build_parser().
        sub = getattr(namespace, "config_subcommand", None)
        if sub != "find":
            # Unreachable in normal flow (argparse already raises), but guard here.
            print("cn-lens: config requires a subcommand: find", file=sys.stderr)
            return 2
        # 'queries' holds the positional arguments after 'find'.
        queries: list[str] = getattr(namespace, "queries", [])
        if not queries:
            print(
                "cn-lens: config find requires at least one query", file=sys.stderr
            )
            return 1
        # Build an object_set from the query strings directly (no file/stdin).
        object_set = classify_many(queries)
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
            return 2
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

    if command == "report":
        return _run_report(namespace, runtime)

    return _run_interactive(runtime=runtime)


def _inject_default_command(args: list[str]) -> list[str]:
    for index, token in enumerate(args):
        if token in GLOBAL_FLAGS:
            return args
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
        return [*args[:index], "inspect", *args[index:]]
    return args


def _build_parser() -> argparse.ArgumentParser:
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
            "  config find        Search config repository and SD-WAN YAML.\n"
            "  report             Bundle persisted runs into a LensReport.\n\n"
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
        version=f"cn-lens {_read_version()}",
    )
    subparsers = parser.add_subparsers(dest="command")

    # --- inspect ---
    inspect_parser = subparsers.add_parser(
        "inspect",
        description=(
            "Classify network objects and render an offline inspection run. "
            "Accepts IPs, prefixes, FQDNs, site codes, and device names. "
            "Invalid inputs are reported without stopping valid ones."
        ),
        epilog=(
            "Output formats: human, text/txt, md/markdown, json, yaml/yml, xlsx.\n\n"
            "Examples:\n"
            "  cn-lens inspect 10.0.0.1\n"
            "  cn-lens inspect 10.0.0.1 10.0.0.0/24 host.example.net\n"
            "  cn-lens inspect - --format json\n"
            "  cn-lens inspect --file objects.txt --format md\n"
            "  cn-lens inspect --file data.csv --column target --format xlsx --output out.xlsx"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common_input_args(inspect_parser)
    inspect_parser.add_argument(
        "--offline",
        action="store_true",
        default=False,
        help="skip all live adapters; use offline classification only",
    )
    inspect_parser.add_argument(
        "--version",
        action="version",
        version=f"cn-lens {_read_version()}",
    )

    # --- impact ---
    impact_parser = subparsers.add_parser(
        "impact",
        description=(
            "Find all references to objects across available sources: "
            "config_repo, SD-WAN YAML, Infoblox containers, and AD group memberships. "
            "Findings are grouped by source."
        ),
        epilog=(
            "Examples:\n"
            "  cn-lens impact 10.1.0.0/24\n"
            "  cn-lens impact SITE01 --format json\n"
            "  cn-lens impact --file prefixes.txt --format xlsx --output impact.xlsx"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common_input_args(impact_parser)

    # --- dns ---
    dns_parser = subparsers.add_parser(
        "dns",
        description=(
            "Resolve DNS and Infoblox DNS records for network objects. "
            "Performs forward and reverse lookups, PTR records, and FQDN prefix expansion."
        ),
        epilog=(
            "Examples:\n"
            "  cn-lens dns host.example.net\n"
            "  cn-lens dns 10.0.0.1 --format json\n"
            "  cn-lens dns --file hosts.txt"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common_input_args(dns_parser)

    # --- reachability ---
    reachability_parser = subparsers.add_parser(
        "reachability",
        description=(
            "Perform reachability checks (ping and/or traceroute) for network objects. "
            "When AD is online, traceroute hops are enriched with site codes."
        ),
        epilog=(
            "Examples:\n"
            "  cn-lens reachability 10.0.0.1\n"
            "  cn-lens reachability 10.0.0.1 --mode trace\n"
            "  cn-lens reachability --file hosts.txt --mode both --format json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common_input_args(reachability_parser)
    reachability_parser.add_argument(
        "--mode",
        choices=("ping", "trace", "both"),
        default="ping",
        help="reachability probe mode: ping, trace, or both (default: ping)",
    )

    # --- device ---
    device_parser = subparsers.add_parser(
        "device",
        description=(
            "Classify and enrich device-oriented network objects. "
            "Combines AD OU path, Infoblox host records, and config_repo references. "
            "Use --probe to additionally test reachability of resolved IPs."
        ),
        epilog=(
            "Examples:\n"
            "  cn-lens device router1.example.net\n"
            "  cn-lens device router1.example.net --probe\n"
            "  cn-lens device --file devices.txt --format xlsx --output devices.xlsx"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common_input_args(device_parser)
    device_parser.add_argument(
        "--probe",
        action="store_true",
        default=False,
        help="ping resolved IPs to probe device reachability (default: false)",
    )

    # --- validate-site ---
    validate_site_parser = subparsers.add_parser(
        "validate-site",
        description=(
            "Validate site objects across AD, SD-WAN YAML, Infoblox, config-repo, and DNS. "
            "Reports per-check pass/fail in summary['validate_site']."
        ),
        epilog=(
            "Examples:\n"
            "  cn-lens validate-site SITE01\n"
            "  cn-lens validate-site SITE01 SITE02 --format json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common_input_args(validate_site_parser)

    # --- decommission-site ---
    decommission_site_parser = subparsers.add_parser(
        "decommission-site",
        description=(
            "Run decommission-readiness checks for site objects. "
            "Active prefixes, config references, AD accounts, or DHCP scopes block "
            "decommission and are reported as 'error' findings. "
            "A clean site produces an 'info' finding: safe to decommission."
        ),
        epilog=(
            "Examples:\n"
            "  cn-lens decommission-site SITE01\n"
            "  cn-lens decommission-site SITE01 --format json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common_input_args(decommission_site_parser)

    # --- allocate ---
    allocate_parser = subparsers.add_parser(
        "allocate",
        description=(
            "Safety-check a candidate prefix before allocation. "
            "Confirms the prefix is available in Infoblox, has no overlap with existing "
            "networks, passes inheritance checks, and the target AD site can host it. "
            "Use --target-site to specify the destination site code."
        ),
        epilog=(
            "Examples:\n"
            "  cn-lens allocate 10.5.0.0/24 --target-site SITE01\n"
            "  cn-lens allocate 10.5.0.0/24 --format json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common_input_args(allocate_parser)
    allocate_parser.add_argument(
        "--target-site",
        default=None,
        metavar="SITE_CODE",
        help="site code to allocate the prefix into",
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

    # --- interactive, doctor ---
    subparsers.add_parser(
        "interactive",
        description=(
            "Start the interactive REPL shell. "
            "Equivalent to running cn-lens with no arguments. "
            "Type 'help' inside the shell for a list of commands."
        ),
    )
    subparsers.add_parser(
        "doctor",
        description="Check health of live source adapters (Infoblox, AD, config-repo, DNS).",
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
        format=getattr(namespace, "format", "human") or "human",
        output=Path(namespace.output) if getattr(namespace, "output", None) else None,
        run_id=None,
    )
    return build_runtime(opts, config_paths=config_paths)


def _run_interactive(*, runtime: LensRuntime | None = None) -> int:
    from cn_lens.interactive import LensShell

    return LensShell(runtime=runtime).run()


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


def _run_inspect(
    namespace: argparse.Namespace,
    input_sources: Sequence[RawInputSource],
    runtime: LensRuntime | None = None,
) -> int:
    """Thin wrapper that delegates to _run_workflow for the inspect subcommand."""
    return _run_workflow(namespace, input_sources, inspect_objects, runtime=runtime)


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

    if fmt == "xlsx" and output is None:
        print("cn-lens: xlsx output requires --output", file=sys.stderr)
        return 2

    if not include and not from_last:
        print("cn-lens: error: no runs available to bundle", file=sys.stderr)
        return 1

    # Resolve an effective run_id for the synthesised summary LensRun.
    effective_run_id: str = (
        runtime.options.run_id
        if runtime is not None
        and hasattr(runtime, "options")
        and runtime.options.run_id is not None
        else make_run_id()
    )

    report, summary_run = _build_report_artifacts(
        runtime=runtime,
        run_id=effective_run_id,
        include=include or None,
        from_last=from_last,
        email=email,
        _last_run=None,
        object_set=_make_empty_object_set(),
    )

    # Persist the synthesised summary LensRun for the report workflow.
    maybe_persist(summary_run, runtime)

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

    return 0


def _extract_inspect_input_sources(args: Sequence[str]) -> list[RawInputSource]:
    try:
        index = list(args).index("inspect") + 1
    except ValueError:
        index = 0

    return extract_ordered_input_sources(
        args[index:],
        file_options=INSPECT_FILE_OPTIONS,
        value_options=INSPECT_VALUE_OPTIONS,
    )


def _extract_subcommand_input_sources(
    args: Sequence[str], command: str
) -> list[RawInputSource]:
    """Extract input sources for a named subcommand (non-inspect workflows)."""
    args_list = list(args)
    try:
        index = args_list.index(command) + 1
    except ValueError:
        index = 0

    return extract_ordered_input_sources(
        args_list[index:],
        file_options=INSPECT_FILE_OPTIONS,
        value_options=INSPECT_VALUE_OPTIONS,
    )


def _unknown_args_are_inspect_objects(
    command: str | None,
    unknown_args: Sequence[str],
) -> bool:
    return command == "inspect" and all(
        arg == "-" or not arg.startswith("-") for arg in unknown_args
    )
