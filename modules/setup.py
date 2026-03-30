from pathlib import Path
from typing import Any, List, Mapping, Optional

from core.base import BaseModule, ScriptContext
from utils.config import BASE_CONFIG_SCHEMA, coerce_bool, coerce_config_value, write_config_value
from utils.file_io import check_dir_accessibility
from utils.user_input import press_any_key, read_user_input


class SetupModule(BaseModule):
    """Interactive configuration for plugins with user-facing settings."""

    @property
    def menu_key(self) -> str:
        return "s"

    @property
    def menu_title(self) -> str:
        return "Application Setup"

    def run(self, ctx: ScriptContext) -> None:
        ctx.logger.info("Request Type - Application Setup")

        user_config_path = Path.home() / ".cn"

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
            self._configure_plugin(ctx, selected_plugin, user_config_path)

    def _show_health_summary(self, ctx: ScriptContext) -> None:
        """Display a compact infrastructure health summary above the plugin list."""
        cfg = ctx.cfg
        lines: list[str] = []

        # Infoblox API
        endpoint = cfg.get("api_endpoint", "")
        if cfg.get("infoblox_enabled"):
            lines.append(f"  Infoblox API:  [green]Configured[/green] ({endpoint})")
        else:
            lines.append("  Infoblox API:  [red]Not configured[/red]")

        # Config Repo
        if cfg.get("config_repo_enabled"):
            repo_dir = cfg.get("config_repo_directory", "")
            lines.append(f"  Config Repo:   [green]Enabled[/green] ({repo_dir})")
        else:
            lines.append("  Config Repo:   [dim]Disabled[/dim]")

        # Active Directory
        if cfg.get("ad_enabled"):
            ad_uri = cfg.get("ad_uri", "")
            lines.append(f"  Active Dir:    [green]Enabled[/green] ({ad_uri})" if ad_uri else "  Active Dir:    [yellow]Enabled[/yellow] (no URI)")
        else:
            lines.append("  Active Dir:    [dim]Disabled[/dim]")

        # Cache
        if cfg.get("cache_enabled"):
            cache_dir = cfg.get("cache_directory", "")
            lines.append(f"  Cache:         [green]Enabled[/green] ({cache_dir})")
        else:
            lines.append("  Cache:         [dim]Disabled[/dim]")

        # Theme
        theme = cfg.get("theme_name", "default")
        lines.append(f"  Theme:         [cyan]{theme}[/cyan]")

        ctx.console.print("[bold cyan]--- System Status ---[/bold cyan]")
        for line in lines:
            ctx.console.print(line)
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
                from utils.display import set_global_color_scheme
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
        """Test Infoblox API connectivity using existing infrastructure."""
        endpoint = ctx.cfg.get("api_endpoint", "")
        if not endpoint or endpoint == "API_URL":
            ctx.console.print("[yellow]No API endpoint configured. Skipping test.[/yellow]")
            return

        if not getattr(ctx, "password", None):
            ctx.console.print("[yellow]Connection test skipped (no credentials available yet).[/yellow]")
            return

        from utils.api import request_result, describe_infoblox_failure

        try:
            with ctx.console.status("[cyan]Testing Infoblox API connection...[/cyan]"):
                result = request_result(ctx, "networkview?_max_results=1")

            if result.ok:
                ctx.console.print("[green]Infoblox API is reachable. Server responded successfully.[/green]")
            else:
                msg = describe_infoblox_failure(result)
                ctx.console.print(f"[red]Connection test failed:[/red] {msg}")
        except Exception as exc:
            ctx.console.print(f"[red]Connection test error:[/red] {exc}")

    def _test_ad_connection(self, ctx: ScriptContext) -> None:
        """Test Active Directory connectivity."""
        uri = ctx.cfg.get("ad_uri", "")
        if not uri:
            ctx.console.print("[yellow]No AD URI configured. Skipping test.[/yellow]")
            return

        try:
            from utils.ad_helper import init_ad_link

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
