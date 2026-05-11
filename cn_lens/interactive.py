from __future__ import annotations

import argparse
import shlex
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cn_lens.classifier import classify_many
from cn_lens.input_sources import (
    collect_raw_inputs_from_sources,
    extract_ordered_input_sources,
)
from cn_lens.models import LensRun
from cn_lens.renderers import render_run, render_report
from cn_lens.workflows import (
    allocate_objects,
    config_find_objects,
    decommission_site_objects,
    device_objects,
    dns_objects,
    impact_objects,
    inspect_objects,
    reachability_objects,
    report_runs,
    validate_site_objects,
)

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


DISPLAY_FORMATS = ("human", "text", "txt", "md", "markdown", "json", "yaml", "yml")
EXPORT_FORMATS = (*DISPLAY_FORMATS, "xlsx")
INSPECT_FILE_OPTIONS = {"--file", "-f"}
INSPECT_VALUE_OPTIONS = {"--column", "--format", "--output", "-o"}

# Commands that are dispatched through the workflow helper rather than as
# bare-object fallback.  Used to gate the default-inspect fallback.
_WORKFLOW_COMMANDS = frozenset(
    {
        "inspect",
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
)

# All commands known to the REPL, used for autocomplete and the help listing.
_ALL_REPL_COMMANDS: tuple[str, ...] = (
    "inspect",
    "impact",
    "dns",
    "reachability",
    "device",
    "validate-site",
    "decommission-site",
    "allocate",
    "config",
    "report",
    "set",
    "export",
    "history",
    "help",
    "doctor",
    "quit",
    "exit",
)

_HELP_TEXT = """\
cn-lens interactive shell — available commands:

  Workflows (network object lens):
    inspect          Classify objects (default when bare objects are entered).
    impact           Find all cross-source references to an object.
    dns              Resolve DNS/Infoblox records.
    reachability     Ping/trace reachability checks  (--mode ping|trace|both).
    device           Enrich device objects via AD, IB, config-repo  (--probe).
    validate-site    Validate site consistency across AD/IB/DNS/config.
    decommission-site  Run decommission-readiness checks for a site.
    allocate         Safety-check a candidate prefix  (--target-site SITE).
    config find      Search config-repo / SD-WAN YAML  (--scope cfg|yaml|all).
    report           Bundle persisted runs  (--from-last / --include RUN_ID).

  Shell commands:
    set format <fmt>            Change default output format.
    export last --format <fmt> --output <path>   Export last run to file.
    history                     Show command history.
    doctor                      Check live adapter health.
    help [command]              Show this help, or per-command usage.
    quit / exit                 Leave the shell.

Type 'help <command>' for per-command flags and examples.
"""

_COMMAND_HELP: dict[str, str] = {
    "inspect": (
        "inspect [<object>...] [--file PATH] [--column COL] [--format FMT] [--output PATH]\n\n"
        "Classify network objects and render an offline inspection run.\n\n"
        "Examples:\n"
        "  inspect 10.0.0.1\n"
        "  inspect 10.0.0.1 10.0.0.0/24 host.example.net\n"
        "  inspect --file objects.txt --format md\n"
        "  inspect --file data.csv --column target --format json"
    ),
    "impact": (
        "impact [<object>...] [--file PATH] [--column COL] [--format FMT] [--output PATH]\n\n"
        "Find all references to objects across config_repo, SD-WAN YAML, Infoblox, and AD.\n\n"
        "Examples:\n"
        "  impact 10.1.0.0/24\n"
        "  impact SITE01 --format json"
    ),
    "dns": (
        "dns [<object>...] [--file PATH] [--column COL] [--format FMT] [--output PATH]\n\n"
        "Resolve DNS and Infoblox DNS records (forward, reverse, PTR, FQDN expansion).\n\n"
        "Examples:\n"
        "  dns host.example.net\n"
        "  dns 10.0.0.1 --format json"
    ),
    "reachability": (
        "reachability [<object>...] [--mode ping|trace|both] [--format FMT] [--output PATH]\n\n"
        "Perform reachability checks (ping and/or traceroute).\n\n"
        "Flags:\n"
        "  --mode ping|trace|both   Probe mode (default: ping).\n\n"
        "Examples:\n"
        "  reachability 10.0.0.1\n"
        "  reachability 10.0.0.1 --mode trace\n"
        "  reachability --file hosts.txt --mode both"
    ),
    "device": (
        "device [<object>...] [--probe] [--format FMT] [--output PATH]\n\n"
        "Classify and enrich device-oriented objects via AD, Infoblox, and config-repo.\n\n"
        "Flags:\n"
        "  --probe   Ping resolved IPs to test reachability (default: false).\n\n"
        "Examples:\n"
        "  device router1.example.net\n"
        "  device router1.example.net --probe\n"
        "  device --file devices.txt --format json"
    ),
    "validate-site": (
        "validate-site [<object>...] [--format FMT] [--output PATH]\n\n"
        "Validate site consistency across AD, SD-WAN, Infoblox, config-repo, and DNS.\n\n"
        "Examples:\n"
        "  validate-site SITE01\n"
        "  validate-site SITE01 SITE02 --format json"
    ),
    "decommission-site": (
        "decommission-site [<object>...] [--format FMT] [--output PATH]\n\n"
        "Run decommission-readiness checks. Active prefixes, config refs, AD accounts,\n"
        "or DHCP scopes block decommission (reported as error findings).\n\n"
        "Examples:\n"
        "  decommission-site SITE01\n"
        "  decommission-site SITE01 --format json"
    ),
    "allocate": (
        "allocate [<object>...] [--target-site SITE_CODE] [--format FMT] [--output PATH]\n\n"
        "Safety-check a candidate prefix before allocation in Infoblox.\n\n"
        "Flags:\n"
        "  --target-site SITE_CODE   Destination site for the allocation.\n\n"
        "Examples:\n"
        "  allocate 10.5.0.0/24 --target-site SITE01\n"
        "  allocate 10.5.0.0/24 --format json"
    ),
    "config": (
        "config find <query>... [--scope all|cfg|yaml] [--limit N] [--format FMT] [--output PATH]\n\n"
        "Search config repository and SD-WAN YAML for the given query strings.\n\n"
        "Flags:\n"
        "  --scope all|cfg|yaml   Search scope (default: all).\n"
        "  --limit N              Maximum matches per query.\n\n"
        "Examples:\n"
        "  config find 10.1.0.0/24\n"
        "  config find bgp --scope cfg --limit 20"
    ),
    "report": (
        "report [--from-last] [--include RUN_ID]... [--email ADDR] [--format FMT] [--output PATH]\n\n"
        "Bundle persisted LensRun objects into a LensReport.\n"
        "Runs are stored under <output_dir>/cn-lens/<run_id>/run.json.gz.\n\n"
        "Flags:\n"
        "  --from-last          Include the most recent persisted run.\n"
        "  --include RUN_ID     Add a specific run (repeatable).\n"
        "  --email ADDR         Send via email plugin (if loaded).\n\n"
        "Examples:\n"
        "  report --from-last\n"
        "  report --from-last --format xlsx --output report.xlsx\n"
        "  report --include 20260511T120000Z --email ops@example.com"
    ),
    "set": (
        "set format <fmt>\n\n"
        "Change the default output format for this session.\n\n"
        "Formats: human, text, txt, md, markdown, json, yaml, yml.\n\n"
        "Example:\n"
        "  set format json"
    ),
    "export": (
        "export last --format <fmt> --output <path>\n\n"
        "Export the last run result to a file.\n\n"
        "Formats: human, text, txt, md, markdown, json, yaml, yml, xlsx.\n\n"
        "Example:\n"
        "  export last --format xlsx --output result.xlsx"
    ),
    "history": "history\n\nShow the session command history.",
    "doctor": "doctor\n\nCheck health of live source adapters (Infoblox, AD, config-repo, DNS).",
    "help": "help [command]\n\nShow the command list, or per-command usage for the given command.",
    "quit": "quit\n\nExit the interactive shell (also: exit).",
    "exit": "exit\n\nExit the interactive shell (also: quit).",
}


def _make_completer() -> "Callable[[str, int], str | None]":
    """Return a readline-compatible completer for REPL command names.

    The returned callable accepts ``(text, state)`` and returns the *state*-th
    match for *text* (case-insensitive prefix), or ``None`` when no more
    matches exist.  The matches list is rebuilt on every new ``state == 0``
    call so it is safe to call across multiple tab-presses.
    """
    matches: list[str] = []

    def completer(text: str, state: int) -> "str | None":
        nonlocal matches
        if state == 0:
            lower = text.lower()
            matches = [cmd for cmd in _ALL_REPL_COMMANDS if cmd.lower().startswith(lower)]
        if state < len(matches):
            return matches[state]
        return None

    return completer


def setup_readline() -> None:
    """Bind the REPL completer to readline, if readline is available.

    When ``readline`` cannot be imported (e.g. on Windows without pyreadline),
    this function silently returns without raising.
    """
    try:
        import readline  # noqa: PLC0415  (local import intentional)
        if readline is None:
            return
        readline.set_completer(_make_completer())
        readline.parse_and_bind("tab: complete")
    except (ImportError, AttributeError):
        pass


class ShellUsageError(Exception):
    pass


class ShellArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ShellUsageError(message)


class LensShell:
    def __init__(
        self,
        *,
        default_format: str = "human",
        runtime: "LensRuntime | None" = None,
    ) -> None:
        if default_format not in DISPLAY_FORMATS:
            raise ValueError(f"invalid default format: {default_format}")
        self.default_format = default_format
        self.last_run: LensRun | None = None
        self.history: list[str] = []
        self.runtime = runtime

    def handle_line(self, line: str) -> tuple[int, str]:
        command_line = line.strip()
        if not command_line:
            return 0, ""

        try:
            tokens = shlex.split(command_line)
        except ValueError as exc:
            return 2, f"cn-lens: {exc}\n"

        if not tokens:
            return 0, ""

        command = tokens[0]
        if command in {"quit", "exit"}:
            self.history.append(command_line)
            return 0, "bye\n"
        if command == "help":
            return self._handle_help(tokens[1:])
        if command == "history":
            return 0, self._render_history()
        if command == "doctor":
            self.history.append(command_line)
            return 0, "cn-lens doctor: informational — check the 'sources' block of any workflow output for live adapter health\n"
        if command == "set":
            code, output = self._handle_set(tokens[1:])
            if code == 0:
                self.history.append(command_line)
            return code, output
        if command == "export":
            code, output = self._handle_export(tokens[1:])
            if code == 0:
                self.history.append(command_line)
            return code, output
        if command == "report":
            code, output = self._handle_report(tokens[1:])
            if code == 0:
                self.history.append(command_line)
            return code, output

        # --- workflow dispatch ---
        if command == "impact":
            code, output = self._handle_workflow(
                "impact", tokens[1:], impact_objects
            )
        elif command == "dns":
            code, output = self._handle_workflow(
                "dns", tokens[1:], dns_objects
            )
        elif command == "reachability":
            code, output = self._handle_workflow(
                "reachability",
                tokens[1:],
                reachability_objects,
                extra_args=_reachability_extra_args(),
                extra_kwargs_from_namespace=lambda ns: {"mode": ns.mode},
            )
        elif command == "device":
            code, output = self._handle_workflow(
                "device",
                tokens[1:],
                device_objects,
                extra_args=_device_extra_args(),
                extra_kwargs_from_namespace=lambda ns: {"probe": ns.probe},
            )
        elif command == "validate-site":
            code, output = self._handle_workflow(
                "validate-site", tokens[1:], validate_site_objects
            )
        elif command == "decommission-site":
            code, output = self._handle_workflow(
                "decommission-site", tokens[1:], decommission_site_objects
            )
        elif command == "allocate":
            code, output = self._handle_workflow(
                "allocate",
                tokens[1:],
                allocate_objects,
                extra_args=_allocate_extra_args(),
                extra_kwargs_from_namespace=lambda ns: {"target_site": ns.target_site},
            )
        elif command == "config":
            code, output = self._handle_config(tokens[1:])
        else:
            # Bare objects (or explicit 'inspect') → inspect workflow
            inspect_args = tokens[1:] if command == "inspect" else tokens
            code, output = self._handle_inspect(inspect_args)

        if code == 0:
            self.history.append(command_line)
        return code, output

    def run(self) -> int:
        setup_readline()
        while True:
            try:
                line = input("cn-lens> ")
            except (EOFError, KeyboardInterrupt):
                print("bye")
                return 0

            code, output = self.handle_line(line)
            if output:
                print(output, end="")
            if line.strip() in {"quit", "exit"}:
                return 0

    def _handle_set(self, args: Sequence[str]) -> tuple[int, str]:
        if len(args) != 2 or args[0] != "format":
            return 2, "cn-lens: usage: set format <fmt>\n"

        fmt = args[1].lower()
        if fmt not in DISPLAY_FORMATS:
            return 2, (
                "cn-lens: invalid format "
                f"{args[1]!r}; expected one of {', '.join(DISPLAY_FORMATS)}\n"
            )

        self.default_format = fmt
        return 0, f"Default format set to {fmt}\n"

    def _handle_export(self, args: Sequence[str]) -> tuple[int, str]:
        parser = _build_export_parser()
        try:
            namespace = parser.parse_args(list(args))
        except (ShellUsageError, SystemExit) as exc:
            return 2, _usage_message(exc)

        if namespace.target != "last":
            return 2, "cn-lens: export supports only: export last\n"
        if self.last_run is None:
            return 1, "cn-lens: no previous run to export\n"
        if namespace.output is None:
            return 2, "cn-lens: export requires --output\n"

        output = Path(namespace.output)
        try:
            render_run(self.last_run, namespace.format, output)
        except (OSError, ValueError) as exc:
            return 2, f"cn-lens: {exc}\n"

        return 0, f"Wrote {output}\n"

    def _handle_workflow(
        self,
        command: str,
        args: Sequence[str],
        workflow_callable: Callable[..., LensRun],
        *,
        extra_args: list[tuple[list[str], dict[str, Any]]] | None = None,
        extra_kwargs_from_namespace: Callable[[argparse.Namespace], dict[str, Any]]
        | None = None,
    ) -> tuple[int, str]:
        """Shared REPL handler for all standard workflow commands.

        Parameters
        ----------
        command:
            The command name used in error messages (e.g. "impact").
        args:
            Tokens after the command name.
        workflow_callable:
            The workflow function to invoke (e.g. ``impact_objects``).
        extra_args:
            Additional ``(positionals, kwargs)`` tuples to add to the parser via
            ``parser.add_argument(*positionals, **kwargs)``.
        extra_kwargs_from_namespace:
            Callable that extracts workflow-specific kwargs from the parsed
            namespace (e.g. ``lambda ns: {"mode": ns.mode}``).
        """
        parser = _build_workflow_parser(
            command, self.default_format, extra_args=extra_args
        )
        try:
            arg_list = list(args)
            namespace, unknown_args = parser.parse_known_args(arg_list)
            if unknown_args and not _unknown_args_are_inspect_objects(unknown_args):
                raise ShellUsageError(
                    f"unrecognized arguments: {' '.join(unknown_args)}"
                )
        except (ShellUsageError, SystemExit) as exc:
            return 2, _usage_message(exc)

        if namespace.format not in DISPLAY_FORMATS:
            return 2, (
                "cn-lens: invalid format "
                f"{namespace.format!r}; expected one of {', '.join(DISPLAY_FORMATS)}\n"
            )

        try:
            raw_inputs = collect_raw_inputs_from_sources(
                extract_ordered_input_sources(
                    arg_list,
                    file_options=INSPECT_FILE_OPTIONS,
                    value_options=INSPECT_VALUE_OPTIONS,
                ),
                csv_column=getattr(namespace, "column", None),
            )
        except (OSError, ValueError) as exc:
            return 2, f"cn-lens: {exc}\n"

        if not raw_inputs:
            return 1, f"cn-lens: {command} requires at least one object\n"

        workflow_kwargs: dict[str, Any] = {}
        if extra_kwargs_from_namespace is not None:
            workflow_kwargs.update(extra_kwargs_from_namespace(namespace))

        object_set = classify_many(raw_inputs)
        run = workflow_callable(
            object_set, runtime=self.runtime, **workflow_kwargs
        )
        self.last_run = run

        output = Path(namespace.output) if namespace.output else None
        try:
            rendered = render_run(run, namespace.format, output)
        except (OSError, ValueError) as exc:
            return 2, f"cn-lens: {exc}\n"

        if output is not None:
            return 0 if object_set.objects else 1, f"Wrote {output}\n"
        return 0 if object_set.objects else 1, rendered or ""

    def _handle_config(self, args: Sequence[str]) -> tuple[int, str]:
        """Handle 'config find <query>...' REPL command (two-token form)."""
        arg_list = list(args)
        if not arg_list or arg_list[0] != "find":
            sub = arg_list[0] if arg_list else "(none)"
            return 2, (
                f"cn-lens: config: unknown subcommand {sub!r}; expected 'find'\n"
            )

        # Parse the 'find' arguments
        parser = _build_config_find_parser(self.default_format)
        try:
            namespace = parser.parse_args(arg_list[1:])
        except (ShellUsageError, SystemExit) as exc:
            return 2, _usage_message(exc)

        queries: list[str] = namespace.queries or []
        if not queries:
            return 1, "cn-lens: config find requires at least one query\n"

        object_set = classify_many(queries)
        run = config_find_objects(
            object_set,
            runtime=self.runtime,
            scope=namespace.scope,
            limit=namespace.limit,
        )
        self.last_run = run

        output = Path(namespace.output) if namespace.output else None
        try:
            rendered = render_run(run, namespace.format, output)
        except (OSError, ValueError) as exc:
            return 2, f"cn-lens: {exc}\n"

        if output is not None:
            return 0 if object_set.objects else 1, f"Wrote {output}\n"
        return 0 if object_set.objects else 1, rendered or ""

    def _handle_inspect(self, args: Sequence[str]) -> tuple[int, str]:
        return self._handle_workflow("inspect", args, inspect_objects)

    def _handle_report(self, args: Sequence[str]) -> tuple[int, str]:
        """Handle the 'report' REPL command.

        Mirrors CLI: --from-last, --include RUN_ID (repeatable), --email ADDR,
        --format FMT, --output PATH.  Does not take object positionals.
        """
        parser = _build_report_parser(self.default_format)
        try:
            namespace = parser.parse_args(list(args))
        except (ShellUsageError, SystemExit) as exc:
            return 2, _usage_message(exc)

        include: list[str] = namespace.include or []
        from_last: bool = namespace.from_last
        email: str | None = namespace.email

        if not include and not from_last:
            return 1, "cn-lens: no runs available to bundle\n"

        report = report_runs(
            runtime=self.runtime,
            include=include or None,
            from_last=from_last,
            email=email,
            _last_run=self.last_run if from_last else None,
        )

        output = Path(namespace.output) if namespace.output else None
        try:
            rendered = render_report(report, namespace.format, output)
        except (OSError, ValueError) as exc:
            return 2, f"cn-lens: {exc}\n"

        if output is not None:
            return 0, f"Wrote {output}\n"
        return 0, rendered or ""

    def _render_history(self) -> str:
        if not self.history:
            return ""
        return "\n".join(self.history) + "\n"

    def _handle_help(self, args: Sequence[str]) -> tuple[int, str]:
        """Handle the 'help [command]' REPL command.

        With no arguments: print the full command listing (_HELP_TEXT).
        With one argument:  print the per-command usage from _COMMAND_HELP.
        Unknown command:    return code 2 with an error message.
        """
        if not args:
            return 0, _HELP_TEXT
        cmd = args[0]
        text = _COMMAND_HELP.get(cmd)
        if text is None:
            return 2, f"cn-lens: help: unknown command {cmd!r}\n"
        return 0, text + "\n"


# ---------------------------------------------------------------------------
# Parser builders
# ---------------------------------------------------------------------------


def _build_inspect_parser(default_format: str) -> argparse.ArgumentParser:
    parser = ShellArgumentParser(prog="inspect", add_help=False)
    parser.add_argument("objects", nargs="*")
    parser.add_argument("--file", "-f", action="append", default=[])
    parser.add_argument("--column")
    parser.add_argument("--format", choices=DISPLAY_FORMATS, default=default_format)
    parser.add_argument("--output", "-o")
    return parser


def _build_workflow_parser(
    command: str,
    default_format: str,
    *,
    extra_args: list[tuple[list[str], dict[str, Any]]] | None = None,
) -> argparse.ArgumentParser:
    """Build a generic workflow parser with the standard inspect-like surface."""
    parser = ShellArgumentParser(prog=command, add_help=False)
    parser.add_argument("objects", nargs="*")
    parser.add_argument("--file", "-f", action="append", default=[])
    parser.add_argument("--column")
    parser.add_argument("--format", choices=DISPLAY_FORMATS, default=default_format)
    parser.add_argument("--output", "-o")
    if extra_args:
        for positionals, kwargs in extra_args:
            parser.add_argument(*positionals, **kwargs)
    return parser


def _build_config_find_parser(default_format: str) -> argparse.ArgumentParser:
    """Build parser for 'config find <queries...> [--scope] [--limit] [--format] [--output]'."""
    parser = ShellArgumentParser(prog="config find", add_help=False)
    parser.add_argument("queries", nargs="*")
    parser.add_argument(
        "--scope", choices=("all", "cfg", "yaml"), default="all"
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--format", choices=DISPLAY_FORMATS, default=default_format)
    parser.add_argument("--output", "-o")
    return parser


def _build_export_parser() -> argparse.ArgumentParser:
    parser = ShellArgumentParser(prog="export", add_help=False)
    parser.add_argument("target")
    parser.add_argument("--format", choices=EXPORT_FORMATS, required=True)
    parser.add_argument("--output", "-o")
    return parser


def _build_report_parser(default_format: str) -> argparse.ArgumentParser:
    """Build parser for the REPL 'report' command."""
    parser = ShellArgumentParser(prog="report", add_help=False)
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="RUN_ID",
        dest="include",
        help="add a persisted run by run_id (repeatable)",
    )
    parser.add_argument(
        "--from-last",
        action="store_true",
        default=False,
        dest="from_last",
    )
    parser.add_argument("--email", default=None, metavar="TO_ADDR")
    parser.add_argument("--format", choices=DISPLAY_FORMATS, default=default_format)
    parser.add_argument("--output", "-o", default=None)
    return parser


# ---------------------------------------------------------------------------
# Extra-arg descriptors for subcommand-specific flags
# ---------------------------------------------------------------------------


def _reachability_extra_args() -> list[tuple[list[str], dict[str, Any]]]:
    return [
        (
            ["--mode"],
            {"choices": ("ping", "trace", "both"), "default": "ping"},
        )
    ]


def _device_extra_args() -> list[tuple[list[str], dict[str, Any]]]:
    return [
        (
            ["--probe"],
            {"action": "store_true", "default": False},
        )
    ]


def _allocate_extra_args() -> list[tuple[list[str], dict[str, Any]]]:
    return [
        (
            ["--target-site"],
            {"default": None, "metavar": "SITE_CODE", "dest": "target_site"},
        )
    ]


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _usage_message(exc: BaseException) -> str:
    if isinstance(exc, ShellUsageError):
        return f"cn-lens: {exc}\n"
    return "cn-lens: invalid arguments\n"


def _unknown_args_are_inspect_objects(unknown_args: Sequence[str]) -> bool:
    return all(arg == "-" or not arg.startswith("-") for arg in unknown_args)
