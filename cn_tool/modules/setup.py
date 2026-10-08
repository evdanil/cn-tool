import argparse
from pathlib import Path
from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Sequence, Tuple
from urllib.parse import quote

from rich.markup import escape

from cn_tool.core.base import BaseModule, CliResult, ScriptContext, cli_exit_code
from cn_tool.modules.config_analyzer_module import resolve_repo_roots
from cn_tool.utils.auth import (
    InfobloxSource, credential_source, credentials_hint, ensure_infoblox_auth, infoblox_credentials_hint,
    infoblox_credentials_known, infoblox_source,
)
from cn_tool.utils.config import (
    BASE_CONFIG_SCHEMA, coerce_bool, coerce_config_value, env_name, env_name_problem, no_config_file_found,
    unset_env_note, user_config_path, write_config_value,
)
from cn_tool.utils.file_io import check_dir_accessibility
from cn_tool.utils.network_views import ViewScope, configured_view, scope_network, view_scope
from cn_tool.utils.user_input import press_any_key, read_user_input


class HealthCheck(NamedTuple):
    """One row of the status block and of ``cn doctor``; ``status`` is ok, warning, error, off, info or skipped."""

    check: str
    status: str
    label: str
    detail: str = ""

    @property
    def text(self) -> str:
        """``label (detail)``: what ``cn doctor`` prints in its ``detail`` column."""
        return f"{self.label} ({self.detail})" if self.detail else self.label


# How the menu colours a row's label.
_STATUS_STYLES = {"ok": "green", "warning": "yellow", "error": "red", "off": "dim", "info": "cyan", "skipped": "dim"}


def _enabled(check: str, enabled: Any, detail: Any) -> HealthCheck:
    return HealthCheck(check, "ok", "Enabled", str(detail)) if enabled else HealthCheck(check, "off", "Disabled")


def _config_repo_check(ctx: ScriptContext) -> HealthCheck:
    """
    The directories ``cn diff`` and the repository browser read, and the key that names them.

    "Disabled" is only an explicit ``[config_repo] enabled = false``: the derived flags are false for a
    repository whose directories cannot be read too, and that is a wrong setting (``error``) to show.
    """
    if ctx.cfg.get("config_repo_enabled_explicit") is False:
        return HealthCheck("Config Repo", "off", "Disabled")
    roots = resolve_repo_roots(ctx)
    if not roots.source:
        return HealthCheck("Config Repo", "off", "Not configured")
    shown = [str(root) for root, _label in roots.accessible] + [f"{path} (not accessible)" for path in roots.inaccessible]
    if not roots.accessible:
        status = "error"
    else:
        status = "warning" if roots.inaccessible else "ok"
    return HealthCheck("Config Repo", status, "Enabled", f"{roots.source}: {', '.join(shown)}")


_NETWORK_VIEW_CHECK = "Network view"
_NETWORK_VIEW_KEY = "[api] network_view"


def _network_view_setting(ctx: ScriptContext) -> HealthCheck:
    """The menu's ``Network view`` row: what ``[api] network_view`` says, with no question to the grid."""
    configured = configured_view(ctx)
    if configured:
        return HealthCheck(_NETWORK_VIEW_CHECK, "info", configured, _NETWORK_VIEW_KEY)
    return HealthCheck(_NETWORK_VIEW_CHECK, "info", "every view", f"{_NETWORK_VIEW_KEY} not set")


def health_checks(ctx: ScriptContext, live: Sequence[HealthCheck] = ()) -> List[HealthCheck]:
    """
    The status rows of the menu and of ``cn doctor``, in their fixed order.

    They are read from the configuration alone, so the menu can show them at any time. ``cn doctor``
    passes the ``live`` rows (credentials, WAPI, site attribute, network view), which follow the
    Infoblox row; without them a configured Infoblox is followed by the offline network view row.

    When ``read_config`` found no configuration file at all (``config_files`` is an empty list; a missing key
    is "unknown" and adds nothing), the first row says so and names ``cn init``: a new user's first look.
    """
    cfg = ctx.cfg
    first: List[HealthCheck] = []
    if no_config_file_found(cfg):
        first.append(HealthCheck("Config file", "warning", "none found", f"run cn init to create {user_config_path()}"))
    offline: List[HealthCheck] = []
    if cfg.get("infoblox_enabled"):
        infoblox = HealthCheck("Infoblox API", "ok", "Configured", str(cfg.get("api_endpoint", "")))
        if not live:
            offline.append(_network_view_setting(ctx))
    else:
        infoblox = HealthCheck("Infoblox API", "off", "Not configured")

    ad_uri = cfg.get("ad_uri", "")
    if cfg.get("ad_enabled") and not ad_uri:
        active_dir = HealthCheck("Active Dir", "warning", "Enabled", "no URI")
    else:
        active_dir = _enabled("Active Dir", cfg.get("ad_enabled"), ad_uri)

    return [
        *first,
        infoblox,
        *offline,
        *live,
        _config_repo_check(ctx),
        active_dir,
        _enabled("Cache", cfg.get("cache_enabled"), cfg.get("cache_directory", "")),
        HealthCheck("Theme", "info", str(cfg.get("theme_name", "default"))),
    ]


class _Live(NamedTuple):
    """A live check: its row, and whether it found a wrong setting (exit 2) or a failure (exit 3)."""

    row: HealthCheck
    invalid: bool = False
    failed: bool = False


_SITE_ATTRIBUTE_OFF = "not set: site codes are matched in subnet comments"


def _infoblox_account_row(source: InfobloxSource) -> Tuple[str, str]:
    """
    The ``Credentials`` row of Infoblox's own account: its label, and where each half comes from (the detail).

    A half that a person would be asked for says so; ``source.note`` (a GPG file that could not be used, a
    custom variable that is not set) follows, and makes the row a warning.
    """
    if not source.username:  # the user name would be asked for
        if source.password_from == "prompt":
            return "Infoblox user and password will be asked for", source.note
        password = f"password from {source.password_from}"
        return "Infoblox user will be asked for", "; ".join(filter(None, (password, source.note)))
    label = f"Infoblox account {source.username}"
    if source.user_from == source.password_from:  # both lines of one GPG file
        return label, f"user and password from {source.user_from}"
    if source.password_from == "prompt":
        asked = f"password will be asked for: {source.note}" if source.note else "password will be asked for"
        return label, f"user from {source.user_from}, {asked}"
    return label, f"user from {source.user_from}, password from {source.password_from}"


def _credentials_check(ctx: ScriptContext) -> _Live:
    """
    The ``Credentials`` row: the login Infoblox would use, found without prompting.

    A wrong ``[auth]`` setting is a wrong setting (``invalid``), named by its key, never by its value. With
    an Infoblox setting present the row describes Infoblox's own account (``infoblox_source``): ``error``
    when a login would stop (a half is missing and nobody can be asked, or the GPG file is for another user),
    ``warning`` when a half will be asked for although a GPG file or a custom variable was meant to give it,
    else ``ok``. Otherwise it is the TACACS login Infoblox shares, as it always was; a custom variable that
    is not set makes the "will be asked for" row a warning too.
    """
    problem = env_name_problem(ctx.cfg)
    if problem:
        return _Live(HealthCheck("Credentials", "error", problem), invalid=True)
    own = infoblox_source(ctx)
    if own is not None:
        if not own.complete:
            return _Live(HealthCheck("Credentials", "error", infoblox_credentials_hint(ctx, own)), failed=True)
        label, detail = _infoblox_account_row(own)
        return _Live(HealthCheck("Credentials", "warning" if own.note else "ok", label, detail))
    source = credential_source(ctx)
    if source is None:
        return _Live(HealthCheck("Credentials", "error", f"none: {credentials_hint(ctx)}"), failed=True)
    if source == env_name(ctx.cfg, "auth_device_password_var"):  # it exists (it gave the password), so its name is safe
        return _Live(HealthCheck("Credentials", "ok", f"{source} is set"))
    if source == "prompt":
        note = unset_env_note(ctx.cfg, "auth_device_password_var")
        if note:
            return _Live(HealthCheck("Credentials", "warning", "will be asked for", f"terminal; {note}"))
        return _Live(HealthCheck("Credentials", "ok", "will be asked for", "terminal"))
    return _Live(HealthCheck("Credentials", "ok", source))  # a GPG file is named by its path


def _newest_version(versions: Any) -> str:
    """The highest of a schema's ``supported_versions``, compared as numbers (2.13.7 is above 2.9); "" if none parse."""
    numbered: Dict[Tuple[int, ...], str] = {}
    for version in versions if isinstance(versions, list) else []:
        try:
            numbered[tuple(int(part) for part in str(version).split("."))] = str(version)
        except ValueError:
            continue
    return numbered[max(numbered)] if numbered else ""


def _wapi_check(ctx: ScriptContext) -> _Live:
    """Log in, then read the WAPI version the endpoint serves from ``<endpoint>?_schema``."""
    from cn_tool.utils.api import describe_infoblox_failure, request_result

    user, _ = ensure_infoblox_auth(ctx)
    result = request_result(ctx, "?_schema", ensure_auth=False)
    schema = result.items[0] if result.items else {}
    version = str(schema.get("requested_version") or "")
    if result.ok and version:
        newest = _newest_version(schema.get("supported_versions"))
        detail = f"grid supports up to v{newest}" if newest else ""
        return _Live(HealthCheck("Infoblox WAPI", "ok", f"v{version}, logged in as {user}", detail))
    if result.ok or result.status in ("invalid_query", "not_found"):  # an endpoint that is no WAPI: a wrong setting
        no_schema = f"no WAPI schema at {ctx.cfg.get('api_endpoint')}: check [api] endpoint, e.g. https://gm.example.com/wapi/v2.12/"
        return _Live(HealthCheck("Infoblox WAPI", "error", no_schema), invalid=True)
    message = describe_infoblox_failure(result)
    if result.status == "auth_error" and result.account:  # Infoblox's own account: say what to check
        message = f"{message.removesuffix('.')}: check that password, and that the account may use the API"
    return _Live(HealthCheck("Infoblox WAPI", "error", message), failed=True)


def _site_attribute_check(ctx: ScriptContext, logged_in: bool) -> _Live:
    """
    Is ``[site] ea_name`` defined on the grid, and for networks? An unset name is "off", not a failure.

    The site search filters ``network`` by the attribute, which the grid rejects when the attribute is
    restricted to other object types (``allowed_object_types``; empty means every type): a wrong
    setting. Without ``IPv6Network`` only the IPv6 half of the search is skipped: a warning.
    """
    from cn_tool.utils.api import describe_infoblox_failure, request_result, site_ea_name

    name = site_ea_name(ctx)
    if not name:
        return _Live(HealthCheck("Site attribute", "off", _SITE_ATTRIBUTE_OFF))
    if not logged_in:
        return _Live(HealthCheck("Site attribute", "skipped", "needs a working WAPI connection"))
    uri = f"extensibleattributedef?name={quote(name, safe='')}&_return_fields=name,type,allowed_object_types"
    result = request_result(ctx, uri, ensure_auth=False)
    if not result.ok:
        return _Live(HealthCheck("Site attribute", "error", describe_infoblox_failure(result)), failed=True)
    if not result.items:
        return _Live(HealthCheck("Site attribute", "error", f"'{name}' is not defined on the grid ([site] ea_name)"), invalid=True)
    definition = result.items[0]
    attribute_type = str(definition.get("type") or "")
    allowed = definition.get("allowed_object_types")
    object_types = [str(kind) for kind in allowed] if isinstance(allowed, list) else []  # [] is every type
    lowered = {kind.lower() for kind in object_types}
    if object_types and "network" not in lowered:
        message = f"'{name}' is not allowed on Network objects (allowed: {', '.join(object_types)})"
        return _Live(HealthCheck("Site attribute", "error", message), invalid=True)
    if object_types and "ipv6network" not in lowered:
        skipped = "not allowed on IPv6Network: IPv6 subnets are not searched"
        return _Live(HealthCheck("Site attribute", "warning", name, ", ".join(filter(None, (attribute_type, skipped)))))
    return _Live(HealthCheck("Site attribute", "ok", name, attribute_type))


def _probe_every_view(ctx: ScriptContext, scope: ViewScope) -> str:
    """
    The first network view a search without a view did not reach, or "" (nothing was missed, or the probe
    could not tell). Two requests: one network of the first non-default view, then the same CIDR asked for
    in no view. A search that spans every view must return the copy in the first view too.
    """
    from cn_tool.utils.api import request_result

    grid = scope.grid()  # more than one view, so the first or the second is not the default
    other = grid.names[1] if grid.names[0] == grid.default else grid.names[0]
    uri = scope_network("network?_max_results=1&_return_fields=network,network_view", other)
    first = request_result(ctx, uri, ensure_auth=False)
    cidr = str(first.items[0].get("network") or "") if first.ok and first.items else ""
    if not cidr:
        return ""
    second = request_result(ctx, f"network?network={cidr}&_return_fields=network,network_view", ensure_auth=False)
    if not second.ok:
        return ""
    return "" if any(item.get("network_view") == other for item in second.items) else other


def _network_view_check(ctx: ScriptContext, args: Optional[argparse.Namespace], logged_in: bool) -> _Live:
    """
    The network views of the grid, and whether the one the lookups search exists (``--view`` or
    ``[api] network_view``; ``--all-views`` and an empty setting search every view). An unknown view is a
    wrong setting (exit 2); an unreadable list is a failure (exit 3) when a view is requested and a warning
    when none is. With several views and none requested, the every-view probe checks that a search without
    a view really spans them.
    """
    if not logged_in:
        return _Live(HealthCheck(_NETWORK_VIEW_CHECK, "skipped", "needs a working WAPI connection"))
    scope = view_scope(ctx, args)
    problem = scope.problem(for_doctor=True)
    if problem:
        row = HealthCheck(_NETWORK_VIEW_CHECK, "error", problem.message)
        return _Live(row, invalid=problem.exit_code == 2, failed=problem.exit_code == 3)

    grid = scope.grid()
    listing = f"network views: {', '.join(grid.names)}"
    if scope.requested:
        dns_views = scope.dns_views()
        dns = f"DNS views: {', '.join(dns_views)}" if dns_views else "no DNS view: cn fqdn finds only its host records"
        return _Live(HealthCheck(_NETWORK_VIEW_CHECK, "ok", scope.requested, "; ".join((scope.source, dns, listing))))

    lead = [scope.source] if scope.source else []  # "--all-views", or nothing when the setting is empty
    if grid.error:
        reason = f"could not list the network views: {grid.error.rstrip('.')}"
        return _Live(HealthCheck(_NETWORK_VIEW_CHECK, "warning", "every view", "; ".join((*lead, reason))))
    if len(grid.names) == 1:
        return _Live(HealthCheck(_NETWORK_VIEW_CHECK, "ok", grid.names[0], "the grid's only network view"))
    count = f"{len(grid.names)} {listing}"
    missed = _probe_every_view(ctx, scope)
    if missed:
        miss = f"a search without a view did not reach '{missed}': use --view {missed}, or set {_NETWORK_VIEW_KEY}"
        return _Live(HealthCheck(_NETWORK_VIEW_CHECK, "warning", "every view", "; ".join((*lead, count, miss))))
    return _Live(HealthCheck(_NETWORK_VIEW_CHECK, "ok", "every view", "; ".join((*lead, count))))


def _live_checks(
    ctx: ScriptContext, args: Optional[argparse.Namespace] = None
) -> Tuple[List[HealthCheck], bool, bool]:
    """
    The four live checks (credentials, WAPI version, site attribute, network view), in that order; then
    "a setting is wrong" and "a check failed". ``args`` carry ``--view`` / ``--all-views`` for the last one.

    The WAPI check logs in unless the credentials check failed or found a wrong setting: a ``warning`` row
    (a GPG file or a custom variable that gave nothing, so a prompt answers) still logs in.
    """
    credentials = _credentials_check(ctx)
    if not (credentials.failed or credentials.invalid):
        wapi = _wapi_check(ctx)
    else:
        wapi = _Live(HealthCheck("Infoblox WAPI", "skipped", "needs credentials"))
    logged_in = wapi.row.status == "ok"
    site = _site_attribute_check(ctx, logged_in=logged_in)
    view = _network_view_check(ctx, args, logged_in=logged_in)
    checks = (credentials, wapi, site, view)
    return [check.row for check in checks], any(check.invalid for check in checks), any(check.failed for check in checks)


class SetupModule(BaseModule):
    """Interactive configuration for plugins with user-facing settings."""
    cli_name = "doctor"

    @property
    def menu_key(self) -> str:
        return "s"

    @property
    def menu_title(self) -> str:
        return "Application Setup"

    def run(self, ctx: ScriptContext) -> None:
        ctx.logger.info("Request Type - Application Setup")

        config_path = user_config_path()

        while True:
            ctx.console.clear()
            configurable_plugins = sorted(
                (plugin for plugin in ctx.plugins if plugin.user_configurable_settings),
                key=lambda plug: getattr(plug, "name", plug.__class__.__name__)
            )

            if not configurable_plugins:
                ctx.console.print("[yellow]No configurable plugins found.[/yellow]")
                return

            self._show_health_summary(ctx)
            ctx.console.print("[bold cyan]--- Plugin Configuration ---[/bold cyan]")
            for index, plugin in enumerate(configurable_plugins, start=1):
                ctx.console.print(f"  [green]{index}.[/green] Configure [yellow]{plugin.name}[/yellow]")
            ctx.console.print("  [green]0.[/green] Return to Main Menu")

            choice = read_user_input(ctx, "\nSelect a plugin to configure: ")
            if choice == '' or choice == '0':
                break
            if not choice.isdigit():
                continue

            choice_idx = int(choice)
            if not (1 <= choice_idx <= len(configurable_plugins)):
                continue

            selected_plugin = configurable_plugins[choice_idx - 1]
            self._configure_plugin(ctx, selected_plugin, config_path)

    def run_cli(self, ctx: ScriptContext, args: argparse.Namespace) -> CliResult:
        """
        ``cn doctor``: the rows of the menu's status block and, when Infoblox is configured, four
        live checks (credentials, WAPI version, site attribute, network view). Nothing is changed.

        One section, ``checks`` (``check``, ``status``, ``detail``). Never prompts without a
        terminal. Exit status: 0 when no check failed (warnings, "off" and skipped rows are fine),
        2 when a setting is wrong, 3 when the credentials or Infoblox failed; never 1.
        """
        ctx.logger.info("Request Type - Application Setup (doctor, command line)")
        live, invalid, failed = _live_checks(ctx, args) if ctx.cfg.get("infoblox_enabled") else ([], False, False)
        checks = health_checks(ctx, live)
        invalid = invalid or any(row.check == "Config Repo" and row.status == "error" for row in checks)
        rows = [{"check": row.check, "status": row.status, "detail": row.text} for row in checks]
        return CliResult(cli_exit_code(found=True, invalid=invalid, failed=failed), {"checks": rows})

    def _show_health_summary(self, ctx: ScriptContext) -> None:
        """Display a compact infrastructure health summary above the plugin list."""
        ctx.console.print("[bold cyan]--- System Status ---[/bold cyan]")
        for row in health_checks(ctx):
            style = _STATUS_STYLES[row.status]
            detail = f" ({escape(row.detail)})" if row.detail else ""
            ctx.console.print(f"  {row.check + ':':<15}[{style}]{escape(row.label)}[/{style}]{detail}")
        ctx.console.print()

    def _configure_plugin(self, ctx: ScriptContext, plugin, user_config_path: Path) -> None:
        settings = self._normalize_settings(plugin.user_configurable_settings)
        schema: Mapping[str, Mapping[str, Any]] = plugin.config_schema or {}

        while True:
            ctx.console.clear()
            ctx.console.print(f"[bold cyan]--- Configuring {plugin.name} ---[/bold cyan]")

            is_ad_plugin = getattr(plugin, "name", "").lower() == "active directory support"
            ad_enabled = True
            if is_ad_plugin:
                ad_enabled = coerce_bool(ctx.cfg.get("ad_enabled", False))

            for index, setting in enumerate(settings, start=1):
                key = setting.get("key")
                prompt = setting.get("prompt", key)
                current_value = ctx.cfg.get(key, "Not Set")
                spec = self._merged_setting_spec(key, schema)

                display_value = self._format_display_value(current_value, spec)
                if is_ad_plugin and key != "ad_enabled" and not ad_enabled:
                    display_value = f"{display_value} [italic](ignored while AD integration is disabled)[/italic]"

                ctx.console.print(f"  [green]{index}.[/green] {prompt}: {display_value}")
            ctx.console.print("  [green]0.[/green] Back to Plugin List")

            choice = read_user_input(ctx, "\nSelect a setting to change: ")
            if choice == '' or choice == '0':
                break
            if not choice.isdigit():
                continue

            choice_idx = int(choice)
            if not (1 <= choice_idx <= len(settings)):
                continue

            selected_setting = settings[choice_idx - 1]
            setting_key = selected_setting.get("key")
            setting_spec = self._merged_setting_spec(setting_key, schema)
            if not setting_spec:
                ctx.console.print(f"[red]No configuration schema found for setting '{setting_key}'.[/red]")
                press_any_key(ctx)
                continue

            current_value = ctx.cfg.get(setting_key)
            ad_setting_ignored = is_ad_plugin and setting_key != "ad_enabled" and not ad_enabled
            new_value_to_write: Optional[str] = None

            if setting_spec.get("type") == "bool":
                current_bool = coerce_bool(current_value)
                new_value = not current_bool
                new_value_to_write = "true" if new_value else "false"
                state_label = "Enabled" if new_value else "Disabled"
                ctx.console.print(f"[cyan]{selected_setting['prompt']}[/cyan] has been set to [yellow]{state_label}[/yellow].")
                if ad_setting_ignored:
                    ctx.console.print("[yellow]Note: Active Directory integration is disabled; this setting is ignored until it is enabled.[/yellow]")
            else:
                while True:
                    prompt = selected_setting.get("prompt", setting_key)
                    choices = setting_spec.get("choices")
                    if choices:
                        prompt += f" (choices: {', '.join(choices)})"

                    # Show current and default values in prompt
                    hint_parts: list[str] = []
                    if current_value not in (None, "Not Set"):
                        hint_parts.append(f"current: {current_value}")
                    spec_default = setting_spec.get("fallback")
                    if spec_default is not None and str(spec_default) != "":
                        hint_parts.append(f"default: {spec_default}")
                    hint = f" ({', '.join(hint_parts)})" if hint_parts else ""

                    # Show help text if available
                    help_text = setting_spec.get("help")
                    if help_text:
                        ctx.console.print(f"  [dim]{help_text}[/dim]")

                    raw = read_user_input(ctx, f"Enter new value for [yellow]{prompt}[/yellow]{hint}: ")

                    valid, normalized, err = self._validate_and_normalize_setting(ctx, setting_key, setting_spec, raw)
                    if valid:
                        new_value_to_write = str(normalized)
                        ctx.console.print(f"[cyan]{selected_setting['prompt']}[/cyan] has been set to [yellow]{normalized}[/yellow].")
                        if ad_setting_ignored:
                            ctx.console.print("[yellow]Note: Active Directory integration is disabled; this setting is ignored until it is enabled.[/yellow]")
                        break
                    else:
                        ctx.console.print(f"[red]Invalid value[/red]: {err}")

            if new_value_to_write is None:
                continue

            # No-change detection
            if not self._value_changed(current_value, new_value_to_write, setting_spec):
                ctx.console.print("[dim]Value unchanged.[/dim]")
                press_any_key(ctx)
                continue

            write_config_value(
                ctx.logger,
                user_config_path,
                setting_spec['section'],
                setting_spec['ini_key'],
                new_value_to_write,
            )

            # Update in-memory config only after successful write
            ctx.cfg[setting_key] = coerce_config_value(new_value_to_write, setting_spec, ctx.logger)

            # Theme live preview
            if setting_key == "theme_name":
                from cn_tool.utils.display import set_global_color_scheme
                set_global_color_scheme(ctx)

            # Accurate effectiveness message
            if setting_spec.get("immediate", True):
                ctx.console.print("[green]Setting updated and applied.[/green]")
            else:
                ctx.console.print("[green]Setting saved. Full effect requires an application restart.[/green]")

            # Offer connection test for API/AD settings
            self._offer_connection_test(ctx, setting_key)

            press_any_key(ctx)

    def _offer_connection_test(self, ctx: ScriptContext, setting_key: str) -> None:
        """Offer a connection test after changing API or AD settings."""
        api_keys = {"api_endpoint", "api_verify_ssl", "api_timeout"}
        ad_keys = {"ad_enabled", "ad_uri", "ad_user", "ad_connect_on_startup"}

        if setting_key in api_keys:
            answer = read_user_input(ctx, "Test Infoblox API connection now? (y/N): ")
            if answer.strip().lower() in ("y", "yes"):
                self._test_infoblox_connection(ctx)

        elif setting_key in ad_keys:
            if coerce_bool(ctx.cfg.get("ad_enabled", False)):
                answer = read_user_input(ctx, "Test AD connection now? (y/N): ")
                if answer.strip().lower() in ("y", "yes"):
                    self._test_ad_connection(ctx)

    def _test_infoblox_connection(self, ctx: ScriptContext) -> None:
        """
        Test Infoblox API connectivity using existing infrastructure.

        The test waits until an Infoblox login is known (``infoblox_credentials_known``): Infoblox's own
        account once resolved, else the TACACS login when Infoblox shares it.
        """
        endpoint = ctx.cfg.get("api_endpoint", "")
        if not endpoint or endpoint == "API_URL":
            ctx.console.print("[yellow]No API endpoint configured. Skipping test.[/yellow]")
            return

        if not infoblox_credentials_known(ctx):
            ctx.console.print("[yellow]Connection test skipped (no credentials available yet).[/yellow]")
            return

        from cn_tool.utils.api import request_result, describe_infoblox_failure

        try:
            with ctx.console.status("[cyan]Testing Infoblox API connection...[/cyan]"):
                result = request_result(ctx, "networkview?_max_results=1")

            if result.ok:
                ctx.console.print("[green]Infoblox API is reachable. Server responded successfully.[/green]")
            else:
                msg = describe_infoblox_failure(result)
                ctx.console.print(f"[red]Connection test failed:[/red] {escape(msg)}")  # may name the account
        except Exception as exc:
            ctx.console.print(f"[red]Connection test error:[/red] {exc}")

    def _test_ad_connection(self, ctx: ScriptContext) -> None:
        """Test Active Directory connectivity."""
        uri = ctx.cfg.get("ad_uri", "")
        if not uri:
            ctx.console.print("[yellow]No AD URI configured. Skipping test.[/yellow]")
            return

        try:
            from cn_tool.utils.auth import ensure_device_auth
            from cn_tool.utils.ad_helper import init_ad_link

            if not getattr(ctx, "password", ""):
                ensure_device_auth(ctx)

            with ctx.console.status("[cyan]Testing AD connection...[/cyan]"):
                conn = init_ad_link(
                    ctx.logger,
                    ctx.cfg.get("ad_user", ""),
                    getattr(ctx, "password", ""),
                    ctx.cfg.get("ad_uri", ""),
                )

            if conn and conn.bound:
                ctx.console.print("[green]Active Directory connection successful.[/green]")
                conn.unbind()
            else:
                ctx.console.print("[red]AD connection test failed. Check URI, credentials, and network.[/red]")
        except ImportError:
            ctx.console.print("[yellow]AD helper module not available.[/yellow]")
        except Exception as exc:
            ctx.console.print(f"[red]AD connection test error:[/red] {exc}")

    def _value_changed(self, current_value: Any, new_raw: str, spec: Mapping[str, Any]) -> bool:
        """Check if the value actually changed."""
        if current_value in (None, "Not Set"):
            return True
        if spec.get("type") == "bool":
            return coerce_bool(current_value) != coerce_bool(new_raw)
        if spec.get("type") == "list[str]":
            if isinstance(current_value, (list, tuple)):
                current_str = ",".join(str(v) for v in current_value)
            else:
                current_str = str(current_value)
            return current_str != new_raw
        return str(current_value) != new_raw

    def _merged_setting_spec(self, key: Any, plugin_schema: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
        """Combine base schema metadata with plugin-specific UI extensions."""
        key_name = str(key)
        return {
            **BASE_CONFIG_SCHEMA.get(key_name, {}),
            **plugin_schema.get(key_name, {}),
        }

    def _normalize_settings(self, raw_settings: Any) -> List[dict[str, Any]]:
        """Return a list of setting dictionaries from a sequence of mappings."""
        if not isinstance(raw_settings, (list, tuple)):
            raise TypeError("Settings must be a list of dicts with 'key' and 'prompt'.")
        return [dict(entry) for entry in raw_settings]

    def _format_display_value(self, value: Any, spec: Mapping[str, Any]) -> str:
        if value in (None, "Not Set"):
            return "[yellow]Not Set[/yellow]"
        option_type = spec.get("type")
        if option_type == "bool":
            return "[green]Enabled[/green]" if coerce_bool(value) else "[red]Disabled[/red]"
        if isinstance(value, Path):
            return str(value)
        if option_type == "list[str]" and isinstance(value, (list, tuple)):
            return ", ".join(str(item) for item in value)
        return str(value)

    def _validate_and_normalize_setting(self, ctx: ScriptContext, key: str, spec: dict, raw: str) -> tuple[bool, str, str]:
        """Validate user input according to the plugin's config schema."""
        raw = (raw or '').strip()
        if not raw:
            return False, raw, "value cannot be empty"

        t = spec.get('type')
        choices = spec.get('choices')
        if choices and t == 'str':
            lower = raw.lower()
            cl = [c.lower() for c in choices]
            if lower not in cl:
                return False, raw, f"must be one of: {', '.join(choices)}"
            return True, choices[cl.index(lower)], ''

        if t == 'path':
            p = Path(raw).expanduser()
            if spec.get('validate') == 'file':
                parent = p.parent or Path('.')
                if not check_dir_accessibility(ctx.logger, parent):
                    return False, raw, f"parent directory not accessible: {parent}"
            elif not check_dir_accessibility(ctx.logger, p):
                return False, raw, f"directory not accessible: {p}"
            return True, str(p), ''

        if t == 'list[str]':
            items = [segment.strip() for segment in raw.split(',') if segment.strip()]
            if not items:
                return False, raw, "must contain at least one value"
            if spec.get('validate') == 'path':
                normalized: list[str] = []
                inaccessible: list[str] = []
                for segment in items:
                    candidate = Path(segment).expanduser()
                    if not check_dir_accessibility(ctx.logger, candidate):
                        inaccessible.append(segment)
                    else:
                        normalized.append(str(candidate))
                if inaccessible:
                    return False, raw, f"directories not accessible: {', '.join(inaccessible)}"
                items = normalized
            return True, ','.join(items), ''

        if t == 'int':
            try:
                int(raw)
            except ValueError:
                return False, raw, "must be a whole number"
            return True, raw, ''

        return True, raw, ''
