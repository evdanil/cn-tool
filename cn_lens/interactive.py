from __future__ import annotations

import argparse
import shlex
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cn_lens.classifier import classify_many
from cn_lens.commands import COMMAND_TABLE, CommandSpec, get_command
from cn_lens.input_sources import (
    collect_raw_inputs_from_sources,
    extract_input_sources_from_namespace,
)
from cn_lens.models import LensRun
from cn_lens.renderers import render_run, render_report
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
from cn_lens.workflows.report import (
    _build_report_artifacts,
    _make_empty_object_set,
    dispatch_report_email,
)
from cn_lens.workflows.stats import stats_objects
from cn_lens.workflows._helpers import make_run_id, maybe_persist

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


DISPLAY_FORMATS = ("human", "text", "txt", "md", "markdown", "json", "yaml", "yml")
EXPORT_FORMATS = (*DISPLAY_FORMATS, "xlsx")
# All commands known to the REPL, used for autocomplete and the help listing.
# Built from COMMAND_TABLE plus shell-only commands.
_ALL_REPL_COMMANDS: tuple[str, ...] = (
    *(spec.name for spec in COMMAND_TABLE if spec.name != "interactive"),
    "set",
    "export",
    "history",
    "reload",
    "help",
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
    e911             Resolve E911 location records for IP/MAC objects.
    config find      Search config-repo / SD-WAN YAML  (--scope cfg|yaml|all).
    config diff      Diff two device snapshots  (--repo-root / --snapshots A B).
    config get       Show current configuration values  (--format human|json).
    config set       Write a config value to ~/.cn  (key value).
    config test      Probe adapter connectivity  (--format human|json).
    report           Bundle persisted runs  (--from-last / --include RUN_ID).
    stats            Display cn-tool/cn-lens usage statistics  (--period 7d|4w|1m|12m|all).
    bssid            Convert wired MAC addresses to Aruba BSSID radio MACs (offline).

  Shell commands:
    set format <fmt>            Change default output format.
    export last --format <fmt> --output <path>   Export last run to file.
    history                     Show command history.
    reload                      Clear cached source data (re-reads on next use).
    doctor                      Check live adapter health.
    help [command]              Show this help, or per-command usage.
    quit / exit                 Leave the shell.

Type 'help <command>' for per-command flags and examples.
"""

# Per-command help text — derived from COMMAND_TABLE (spec.repl_help) where
# available, supplemented with shell-only commands below.
def _build_command_help() -> dict[str, str]:
    """Build the _COMMAND_HELP dict from COMMAND_TABLE and static shell commands."""
    result: dict[str, str] = {}
    for spec in COMMAND_TABLE:
        if spec.repl_help:
            result[spec.name] = spec.repl_help
    # Shell-only commands not in COMMAND_TABLE:
    result["set"] = (
        "set format <fmt>\n\n"
        "Change the default output format for this session.\n\n"
        "Formats: human, text, txt, md, markdown, json, yaml, yml.\n\n"
        "Example:\n"
        "  set format json"
    )
    result["export"] = (
        "export last --format <fmt> --output <path>\n\n"
        "Export the last run result to a file.\n\n"
        "Formats: human, text, txt, md, markdown, json, yaml, yml, xlsx.\n\n"
        "Example:\n"
        "  export last --format xlsx --output result.xlsx"
    )
    result["history"] = "history\n\nShow the session command history."
    result["reload"] = (
        "reload\n\n"
        "Clear all cached source data for this session so the next lookup\n"
        "re-reads from disk.  Useful after updating the SD-WAN YAML repository\n"
        "or other configuration files without restarting the shell."
    )
    result["help"] = "help [command]\n\nShow the command list, or per-command usage for the given command."
    result["quit"] = "quit\n\nExit the interactive shell (also: exit)."
    result["exit"] = "exit\n\nExit the interactive shell (also: quit)."
    return result


_COMMAND_HELP: dict[str, str] = _build_command_help()


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
            code, output = self._handle_doctor(tokens[1:])
            if code == 0:
                self.history.append(command_line)
            return code, output
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
        if command == "reload":
            code, output = self._handle_reload()
            if code == 0:
                self.history.append(command_line)
            return code, output
        if command == "report":
            code, output = self._handle_report(tokens[1:])
            if code == 0:
                self.history.append(command_line)
            return code, output

        if command == "bssid":
            code, output = self._handle_bssid(tokens[1:])
            if code == 0:
                self.history.append(command_line)
            return code, output

        if command == "stats":
            code, output = self._handle_stats(tokens[1:])
            if code == 0:
                self.history.append(command_line)
            return code, output

        # --- workflow dispatch driven by COMMAND_TABLE ---
        # Look up the command in the table to find standard workflow commands.
        spec = _get_command_from_table(command)
        workflow_callable = _get_workflow_callable_for(command) if spec is not None and spec.is_standard_workflow else None
        if spec is not None and spec.is_standard_workflow and workflow_callable is not None:
            extra_args = _spec_to_extra_args(spec) if spec.options else None
            extra_kwargs_fn = spec.dispatch_kwargs_fn
            code, output = self._handle_workflow(
                command,
                tokens[1:],
                workflow_callable,
                extra_args=extra_args,
                extra_kwargs_from_namespace=extra_kwargs_fn,
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
        try:
            while True:
                try:
                    line = input("cn-lens> ")
                except (EOFError, KeyboardInterrupt):
                    print("bye")
                    self._finalize_session("completed")
                    return 0

                code, output = self.handle_line(line)
                if output:
                    print(output, end="")
                _first_token = line.split()[0] if line.split() else ""
                if _first_token in {"quit", "exit"}:
                    self._finalize_session("completed")
                    return 0
        except Exception:
            self._finalize_session("failed")
            raise

    def _finalize_session(self, status: str) -> None:
        """Finalize the stats session on REPL exit."""
        if self.runtime is not None and self.runtime.stats is not None:
            try:
                self.runtime.stats.finalize_session(status)
                self.runtime.stats.close()
            except Exception:
                pass

    def _handle_doctor(
        self,
        args: Sequence[str],
        _registry=None,
    ) -> tuple[int, str]:
        """Run the doctor health check and return (exit_code, output_string).

        Parameters
        ----------
        args:
            Token list after the ``doctor`` command name.
        _registry:
            Optional ``AdapterRegistry`` to pass through to ``run_doctor``.
            When ``None`` the shared singleton is used.  Exposed as a seam for
            tests — mirrors the pattern used by the CLI ``main()`` function.
        """
        import argparse as _ap  # local import to avoid shadowing module-level name
        from cn_lens.doctor import run_doctor

        # Parse doctor-specific flags inline.
        p = _ap.ArgumentParser(prog="doctor", add_help=False)
        p.add_argument(
            "--format",
            choices=("human", "json"),
            default="human",
            dest="fmt",
        )
        p.add_argument(
            "--offline",
            action="store_true",
            default=False,
        )
        try:
            ns, unknown = p.parse_known_args(list(args))
        except SystemExit:
            return 2, "cn-lens: usage: doctor [--format human|json] [--offline]\n"

        if unknown:
            return 2, f"cn-lens: doctor: unrecognized arguments: {' '.join(unknown)}\n"

        # Determine effective runtime.
        # Priority:
        #   1. If `--offline` flag was given on the doctor line, produce an
        #      offline twin of the existing runtime (or create a fresh one) so
        #      this specific invocation runs offline without mutating the
        #      shell's persistent runtime.  Uses LensRuntime.as_offline() to
        #      safely copy all current fields — new fields added in the future
        #      will automatically be included without updating this code.
        #   2. If the shell has a runtime, use it as-is (it already knows
        #      whether it is offline from the shell startup flags).
        #   3. If no runtime on the shell, build a minimal transient offline
        #      one (cannot run online without a live config + credentials).
        runtime = self.runtime
        if ns.offline and runtime is not None and not runtime.offline:
            # Produce a transient offline twin — session format is NOT overridden
            # here because fmt is passed explicitly to run_doctor anyway.
            runtime = runtime.as_offline()
        elif runtime is None:
            # No shell runtime at all — build a transient offline runtime.
            from cn_lens.runtime import build_runtime, LensOptions  # noqa: PLC0415
            opts = LensOptions(
                offline=True,
                run_id=None,
            )
            runtime = build_runtime(opts, config_paths=[])

        try:
            output = run_doctor(runtime, _registry, fmt=ns.fmt)
        except Exception as exc:
            return 2, f"cn-lens doctor: internal error: {exc}\n"

        return 0, output

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

    def _handle_reload(self) -> tuple[int, str]:
        """Clear all per-runtime source caches so the next lookup re-reads from disk.

        Currently clears:
        * SD-WAN YAML store (``runtime._sdwan_store``) — re-parsed on first
          subsequent sdwan_yaml adapter call.

        Returns ``(0, message)`` always; ``(1, message)`` when no runtime is
        attached to the shell (no-op).
        """
        if self.runtime is None:
            return 1, "cn-lens: reload: no active runtime\n"
        self.runtime._sdwan_store = None
        return 0, "Source caches cleared. Data will be re-read on next use.\n"

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

        # xlsx requires --output (same guard as CLI _run_workflow)
        if namespace.format == "xlsx" and not namespace.output:
            return 2, "cn-lens: xlsx output requires --output\n"

        try:
            raw_inputs = collect_raw_inputs_from_sources(
                extract_input_sources_from_namespace(
                    namespace,
                    arg_list,
                    extra_positionals=unknown_args,
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
        """Handle 'config find/diff/get/set/test ...' REPL commands."""
        arg_list = list(args)
        if not arg_list:
            return 2, (
                "cn-lens: config: missing subcommand; "
                "expected 'find', 'diff', 'get', 'set', or 'test'\n"
            )

        if arg_list[0] == "diff":
            return self._handle_config_diff(arg_list[1:])

        if arg_list[0] == "get":
            return self._handle_config_get(arg_list[1:])

        if arg_list[0] == "set":
            return self._handle_config_set(arg_list[1:])

        if arg_list[0] == "test":
            return self._handle_config_test(arg_list[1:])

        if arg_list[0] != "find":
            sub = arg_list[0]
            return 2, (
                f"cn-lens: config: unknown subcommand {sub!r}; "
                "expected 'find', 'diff', 'get', 'set', or 'test'\n"
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

        # xlsx requires --output (same guard as CLI config find path)
        if namespace.format == "xlsx" and not namespace.output:
            return 2, "cn-lens: xlsx output requires --output\n"

        # Build ObjectSet directly — config find accepts arbitrary regex /
        # multi-word patterns that must not be routed through classify_many.
        # shlex tokenisation already delivers each shell-quoted argument as
        # one token; we map each token to a QUERY LensObject intact.
        object_set = _make_query_object_set(queries)
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

    def _handle_config_diff(self, args: Sequence[str]) -> tuple[int, str]:
        """Handle 'config diff DEVICE [--repo-root PATH] [--snapshots A B] ...' REPL command."""
        parser = _build_config_diff_parser(self.default_format)
        try:
            namespace = parser.parse_args(list(args))
        except (ShellUsageError, SystemExit) as exc:
            return 2, _usage_message(exc)

        device: str = namespace.device
        repo_root: str | None = getattr(namespace, "repo_root", None)
        snapshots: list[str] | None = getattr(namespace, "snapshots", None)
        snapshot_a: str | None = snapshots[0] if snapshots else None
        snapshot_b: str | None = snapshots[1] if snapshots else None
        side_by_side: bool = getattr(namespace, "side_by_side", False)
        context: int = getattr(namespace, "context", 3)

        if namespace.format == "xlsx" and not namespace.output:
            return 2, "cn-lens: xlsx output requires --output\n"

        run = config_diff(
            device=device,
            repo_root=repo_root,
            snapshot_a=snapshot_a,
            snapshot_b=snapshot_b,
            side_by_side=side_by_side,
            context=context,
            runtime=self.runtime,
        )
        self.last_run = run

        output = Path(namespace.output) if namespace.output else None
        try:
            rendered = render_run(run, namespace.format, output)
        except (OSError, ValueError) as exc:
            return 2, f"cn-lens: {exc}\n"

        if output is not None:
            result_str = f"Wrote {output}\n"
        else:
            result_str = rendered or ""

        # Exit code: 1 = differences, 0 = identical (like diff(1))
        # REPL does not exit on non-zero — the code is just returned.
        if run.results:
            cd = run.results[0].summary.get("config_diff", {})
            if any(f.severity == "error" for f in run.results[0].findings):
                return 2, result_str
            exit_code = 1 if cd.get("has_changes") else 0
        else:
            exit_code = 2
        return exit_code, result_str

    def _handle_config_get(self, args: Sequence[str]) -> tuple[int, str]:
        """Handle 'config get [KEY] [--format human|json]' REPL command."""
        import json as _json
        from cn_lens.workflows.config_cmd import config_get

        arg_list = list(args)
        # Parse optional --format and optional positional key
        fmt = "human"
        key = None
        i = 0
        while i < len(arg_list):
            token = arg_list[i]
            if token in ("--format", "-f") and i + 1 < len(arg_list):
                fmt = arg_list[i + 1]
                i += 2
            elif token.startswith("--format="):
                fmt = token.split("=", 1)[1]
                i += 1
            elif not token.startswith("-"):
                key = token
                i += 1
            else:
                return 2, f"cn-lens: config get: unknown argument {token!r}\n"

        if fmt not in ("human", "json"):
            return 2, f"cn-lens: config get: invalid format {fmt!r}; expected human or json\n"

        entries = config_get(key=key, runtime=self.runtime)

        if key is not None and not entries:
            return 1, f"cn-lens: unknown config key: {key!r}\n"

        if fmt == "json":
            return 0, _json.dumps(entries, indent=2) + "\n"

        lines = [f"{e['key']} = {e['value']}" for e in entries]
        return 0, "\n".join(lines) + "\n" if lines else ""

    def _handle_config_set(self, args: Sequence[str]) -> tuple[int, str]:
        """Handle 'config set KEY VALUE' REPL command."""
        from cn_lens.workflows.config_cmd import config_set

        arg_list = list(args)
        if len(arg_list) < 2:
            return 2, "cn-lens: usage: config set KEY VALUE\n"

        key = arg_list[0]
        value = " ".join(arg_list[1:])

        result = config_set(key=key, value=value, runtime=self.runtime)
        if result["status"] == "ok":
            from cn_lens.workflows.config_cmd import is_secret_key
            display_value = "***" if is_secret_key(key) else value
            return 0, f"Set {key} = {display_value}\n"
        else:
            msg = result.get("message", "unknown error")
            return 1, f"cn-lens: config set failed: {msg}\n"

    def _handle_config_test(self, args: Sequence[str]) -> tuple[int, str]:
        """Handle 'config test [--format human|json]' REPL command."""
        import json as _json
        from cn_lens.workflows.config_cmd import config_test

        arg_list = list(args)
        fmt = "human"
        i = 0
        while i < len(arg_list):
            token = arg_list[i]
            if token in ("--format",) and i + 1 < len(arg_list):
                fmt = arg_list[i + 1]
                i += 2
            elif token.startswith("--format="):
                fmt = token.split("=", 1)[1]
                i += 1
            else:
                return 2, f"cn-lens: config test: unknown argument {token!r}\n"

        if fmt not in ("human", "json"):
            return 2, f"cn-lens: config test: invalid format {fmt!r}; expected human or json\n"

        result = config_test(runtime=self.runtime)

        if fmt == "json":
            output = _json.dumps(result, indent=2) + "\n"
        else:
            lines = []
            for source, info in result.items():
                status = info.get("status", "unknown")
                detail = info.get("detail", "")
                detail_str = f"  {detail}" if detail else ""
                lines.append(f"{source}: {status}{detail_str}")
            output = "\n".join(lines) + "\n"

        exit_code = 1 if any(info.get("status") == "error" for info in result.values()) else 0
        return exit_code, output

    def _handle_inspect(self, args: Sequence[str]) -> tuple[int, str]:
        return self._handle_workflow("inspect", args, inspect_objects)

    def _handle_report(self, args: Sequence[str]) -> tuple[int, str]:
        """Handle the 'report' REPL command.

        Mirrors CLI: --from-last, --include RUN_ID (repeatable), --email ADDR,
        --format FMT, --output PATH.  Does not take object positionals.

        Mirrors cli._run_report exactly:
          1. build with email=None (no dispatch yet)
          2. render
          3. dispatch email after render so attachment exists
          4. fold email outcome into summary_run via dataclasses.replace
          5. maybe_persist(summary_run, self.runtime)
        """
        parser = _build_report_parser(self.default_format)
        try:
            namespace = parser.parse_args(list(args))
        except (ShellUsageError, SystemExit) as exc:
            return 2, _usage_message(exc)

        include: list[str] = namespace.include or []
        from_last: bool = namespace.from_last
        email: str | None = namespace.email
        prune: bool = getattr(namespace, "prune", False)
        keep: int | None = getattr(namespace, "keep", None)
        older_than: int | None = getattr(namespace, "older_than", None)
        delete_run_id: str | None = getattr(namespace, "delete_run_id", None)

        # --- prune / delete dispatch (mutually exclusive with bundling) ---
        if delete_run_id is not None:
            from cn_lens.reports.persistence import delete_run
            try:
                deleted = delete_run(delete_run_id, self.runtime)
            except ValueError as exc:
                return 2, f"cn-lens: {exc}\n"
            if deleted:
                return 0, f"Deleted run: {delete_run_id}\n"
            return 1, f"cn-lens: run not found: {delete_run_id}\n"

        if prune:
            if keep is not None and older_than is not None:
                return 2, "cn-lens: --keep and --older-than are mutually exclusive\n"
            if keep is None and older_than is None:
                return 2, "cn-lens: --prune requires --keep N or --older-than DAYS\n"
            from cn_lens.reports.persistence import prune_runs
            try:
                deleted_ids = prune_runs(self.runtime, keep=keep, older_than_days=older_than)
            except ValueError as exc:
                return 2, f"cn-lens: {exc}\n"
            if deleted_ids:
                lines = "\n".join(f"  {rid}" for rid in deleted_ids)
                return 0, f"Pruned {len(deleted_ids)} run(s):\n{lines}\n"
            return 0, "No runs pruned.\n"

        if not include and not from_last:
            return 1, "cn-lens: no runs available to bundle\n"

        output = Path(namespace.output) if namespace.output else None

        # Resolve an effective run_id for the synthesised summary LensRun.
        effective_run_id: str = (
            self.runtime.options.run_id
            if self.runtime is not None and self.runtime.options.run_id is not None
            else make_run_id()
        )

        # Step 1: build the report aggregate (no email dispatch here).
        report, summary_run = _build_report_artifacts(
            runtime=self.runtime,
            run_id=effective_run_id,
            include=include or None,
            from_last=from_last,
            email=None,  # email dispatched after render; see below
            _last_run=self.last_run if from_last else None,
            object_set=_make_empty_object_set(),
        )

        # Step 2: render — writes the output file when --output is given.
        try:
            rendered = render_report(report, namespace.format, output)
        except (OSError, ValueError) as exc:
            return 2, f"cn-lens: {exc}\n"

        # Step 3: email dispatch AFTER render so the attachment file exists.
        email_findings: list = []
        _sent = False
        if email and self.runtime is not None:
            _sent, email_findings = dispatch_report_email(
                self.runtime,
                to=email,
                report_id=report.report_id,
                run_count=len(report.runs),
                attachment_path=output,
            )

        # Step 4: fold email outcome into summary_run (mirrors cli._run_report).
        if email and summary_run.results:
            import dataclasses
            old_result = summary_run.results[0]
            old_report_block = dict(old_result.summary.get("report", {}))
            old_report_block["email_sent"] = _sent
            new_summary = dict(old_result.summary)
            new_summary["report"] = old_report_block
            new_findings = old_result.findings + tuple(email_findings)
            new_result = dataclasses.replace(
                old_result,
                summary=new_summary,
                findings=new_findings,
            )
            summary_run = dataclasses.replace(
                summary_run,
                results=(new_result,) + summary_run.results[1:],
            )

        # Step 5: persist the synthesised summary LensRun — AFTER email dispatch.
        maybe_persist(summary_run, self.runtime)

        # Surface email-related findings so the REPL user sees send failures and
        # "no attachment" warnings inline.  Anchor on source=="report" (set by all
        # email findings) plus "email" in the message as a secondary filter.
        all_findings = list(report.findings) + list(email_findings)
        email_finding_lines: list[str] = []
        for finding in all_findings:
            if (
                finding.severity in ("warning", "error")
                and finding.source == "report"
                and "email" in finding.message.lower()
            ):
                email_finding_lines.append(
                    f"cn-lens: report: {finding.severity}: {finding.message}\n"
                )

        if output is not None:
            base = f"Wrote {output}\n"
        else:
            base = rendered or ""

        return 0, base + "".join(email_finding_lines)

    def _handle_bssid(self, args: Sequence[str]) -> tuple[int, str]:
        """Handle the 'bssid <mac>...' REPL command.

        Accepts MAC addresses as positionals and/or via ``--file PATH``.
        Returns converted 2.4GHz and 5GHz BSSIDs.  Offline-always.
        """
        parser = _build_bssid_parser(self.default_format)
        try:
            namespace = parser.parse_args(list(args))
        except (ShellUsageError, SystemExit) as exc:
            return 2, _usage_message(exc)

        if namespace.format == "xlsx" and not namespace.output:
            return 2, "cn-lens: xlsx output requires --output\n"

        # Collect raw MAC strings from positionals and --file paths.
        targets: list[str] = list(namespace.targets or [])
        for file_path in namespace.file or []:
            try:
                lines = Path(file_path).read_text(encoding="utf-8").splitlines()
                targets.extend(line.strip() for line in lines if line.strip())
            except OSError as exc:
                return 2, f"cn-lens: {exc}\n"

        if not targets:
            return 1, "cn-lens: bssid requires at least one MAC address\n"

        run = bssid_convert(targets)
        self.last_run = run

        output = Path(namespace.output) if namespace.output else None
        try:
            rendered = render_run(run, namespace.format, output)
        except (OSError, ValueError) as exc:
            return 2, f"cn-lens: {exc}\n"

        if output is not None:
            return 0 if run.results else 1, f"Wrote {output}\n"
        return 0 if run.results else 1, rendered or ""

    def _handle_stats(self, args: Sequence[str]) -> tuple[int, str]:
        """Handle the 'stats [--period all|7d|4w|1m|12m] [--format FMT] [--output PATH]' REPL command.

        Offline-capable: reads local stats files.  Never calls sys.exit.
        """
        from cn_lens.models import ObjectSet

        parser = _build_stats_parser(self.default_format)
        try:
            namespace = parser.parse_args(list(args))
        except (ShellUsageError, SystemExit) as exc:
            return 2, _usage_message(exc)

        if namespace.format == "xlsx" and not namespace.output:
            return 2, "cn-lens: xlsx output requires --output\n"

        period_key: str = getattr(namespace, "period", "all") or "all"
        object_set = ObjectSet(objects=(), invalid=(), duplicate_count=0)
        run = stats_objects(object_set, runtime=self.runtime, period_key=period_key)
        self.last_run = run

        output = Path(namespace.output) if namespace.output else None
        try:
            rendered = render_run(run, namespace.format, output)
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
        # Read from COMMAND_TABLE dynamically so that injected probe specs are visible.
        text = _get_repl_help(cmd)
        if text is None:
            return 2, f"cn-lens: help: unknown command {cmd!r}\n"
        return 0, text + "\n"


# ---------------------------------------------------------------------------
# Dynamic dispatch helpers (read from COMMAND_TABLE at call time)
# ---------------------------------------------------------------------------

# Module-level mapping from command name to the workflow callable name.
# Derived from COMMAND_TABLE so that adding a new workflow spec is the only
# required edit.  Using module-level attribute names means tests can patch
# ``cn_lens.interactive.<name>_objects`` and have the patch take effect in
# the dispatch path — the same pattern tests used with the old entry-point
# that imported workflows directly.
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


def _get_command_from_table(name: str) -> CommandSpec | None:
    """Look up *name* in the live COMMAND_TABLE (module-level, patchable by tests)."""
    import cn_lens.commands as _cmd_mod
    for spec in _cmd_mod.COMMAND_TABLE:
        if spec.name == name or name in spec.aliases:
            return spec
    return None


def _get_workflow_callable_for(name: str):
    """Return the module-level workflow callable for command *name*.

    Uses the module's own namespace so that ``patch("cn_lens.interactive.impact_objects")``
    correctly intercepts calls made via this function.  Falls back to the
    ``CommandSpec.workflow_callable`` for dynamically-injected probe specs that
    are not in :data:`_WORKFLOW_CALLABLE_NAMES`.
    """
    import cn_lens.interactive as _self
    attr = _WORKFLOW_CALLABLE_NAMES.get(name)
    if attr is not None:
        return getattr(_self, attr)
    # For dynamically-injected specs (e.g. probe-cmd in tests), fall back to
    # the callable stored in the spec itself.
    spec = _get_command_from_table(name)
    if spec is not None:
        return spec.workflow_callable
    return None


def _get_repl_help(cmd: str) -> str | None:
    """Return per-command help text for *cmd* from the live COMMAND_TABLE or static dict."""
    import cn_lens.commands as _cmd_mod
    # Check COMMAND_TABLE first (covers dynamically injected specs).
    for spec in _cmd_mod.COMMAND_TABLE:
        if spec.name == cmd and spec.repl_help:
            return spec.repl_help
    # Fall back to static shell-only commands.
    return _COMMAND_HELP.get(cmd)


def _spec_to_extra_args(
    spec: CommandSpec,
) -> list[tuple[list[str], dict[str, Any]]]:
    """Convert a CommandSpec's options tuple to the extra_args format used by
    :meth:`LensShell._handle_workflow`."""
    return [(list(flags), dict(kwargs)) for flags, kwargs in spec.options]


# ---------------------------------------------------------------------------
# Parser builders
# ---------------------------------------------------------------------------


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
    # Accept xlsx (same surface as CLI); xlsx without --output is rejected in
    # _handle_workflow (not here) so argparse can parse the namespace first.
    parser.add_argument("--format", choices=EXPORT_FORMATS, default=default_format)
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
    # Accept xlsx (same surface as CLI); xlsx without --output rejected in _handle_config.
    parser.add_argument("--format", choices=EXPORT_FORMATS, default=default_format)
    parser.add_argument("--output", "-o")
    return parser


def _build_config_diff_parser(default_format: str) -> argparse.ArgumentParser:
    """Build parser for 'config diff DEVICE [--repo-root PATH] [--snapshots A B] ...'."""
    parser = ShellArgumentParser(prog="config diff", add_help=False)
    parser.add_argument("device", help="device name (without .cfg extension)")
    parser.add_argument("--repo-root", default=None, dest="repo_root", metavar="PATH")
    parser.add_argument("--snapshots", nargs=2, default=None, metavar=("A", "B"))
    parser.add_argument(
        "--side-by-side", action="store_true", default=False, dest="side_by_side"
    )
    parser.add_argument("--context", type=int, default=3)
    parser.add_argument("--format", choices=EXPORT_FORMATS, default=default_format)
    parser.add_argument("--output", "-o", default=None)
    return parser


def _build_bssid_parser(default_format: str) -> argparse.ArgumentParser:
    """Build parser for 'bssid <mac>... [--file PATH] [--format FMT] [--output PATH]'."""
    parser = ShellArgumentParser(prog="bssid", add_help=False)
    parser.add_argument("targets", nargs="*", help="wired MAC addresses to convert")
    parser.add_argument("--file", "-f", action="append", default=[],
                        help="read MAC addresses from a text file")
    # Accept xlsx; xlsx without --output rejected in _handle_bssid.
    parser.add_argument("--format", choices=EXPORT_FORMATS, default=default_format)
    parser.add_argument("--output", "-o", default=None)
    return parser


def _build_stats_parser(default_format: str) -> argparse.ArgumentParser:
    """Build parser for 'stats [--period all|7d|4w|1m|12m] [--format FMT] [--output PATH]'."""
    parser = ShellArgumentParser(prog="stats", add_help=False)
    parser.add_argument(
        "--period",
        choices=("all", "7d", "4w", "1m", "12m"),
        default="all",
        dest="period",
        help="reporting period: all (default), 7d, 4w, 1m, 12m",
    )
    parser.add_argument("--format", choices=EXPORT_FORMATS, default=default_format)
    parser.add_argument("--output", "-o", default=None)
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
    parser.add_argument("--format", choices=EXPORT_FORMATS, default=default_format)
    parser.add_argument("--output", "-o", default=None)
    parser.add_argument(
        "--prune",
        action="store_true",
        default=False,
        help="prune persisted runs (requires --keep or --older-than)",
    )
    parser.add_argument(
        "--keep",
        type=int,
        default=None,
        metavar="N",
        help="keep N newest runs; delete the rest (use with --prune)",
    )
    parser.add_argument(
        "--older-than",
        type=int,
        default=None,
        dest="older_than",
        metavar="DAYS",
        help="delete runs older than DAYS days (use with --prune)",
    )
    parser.add_argument(
        "--delete",
        default=None,
        metavar="RUN_ID",
        dest="delete_run_id",
        help="delete a single persisted run by run_id",
    )
    return parser


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _make_query_object_set(queries: list[str]) -> "Any":
    """Build an ObjectSet from raw config-find query tokens.

    Each token is wrapped as a ``LensObjectType.QUERY`` LensObject so that
    arbitrary regex patterns and special characters are preserved intact.
    The classifier is intentionally bypassed — config find must not reject
    legitimate search patterns as "invalid" objects.

    Parameters
    ----------
    queries:
        Raw query strings as delivered by shlex tokenisation (one per token).

    Returns
    -------
    ObjectSet
        All non-empty tokens as QUERY LensObjects; invalid tuple is always empty.
    """
    from cn_lens.models import LensObject, LensObjectType, ObjectSet

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


def _usage_message(exc: BaseException) -> str:
    if isinstance(exc, ShellUsageError):
        return f"cn-lens: {exc}\n"
    return "cn-lens: invalid arguments\n"


def _unknown_args_are_inspect_objects(unknown_args: Sequence[str]) -> bool:
    return all(arg == "-" or not arg.startswith("-") for arg in unknown_args)
