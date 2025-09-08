import time
from core.base import BaseModule, ScriptContext
from utils.user_input import read_user_input
from utils.config import write_config_value
from utils.file_io import check_dir_accessibility
from pathlib import Path


class SetupModule(BaseModule):
    """
    A module for interactively configuring settings for loaded plugins.
    """
    @property
    def menu_key(self) -> str: return "s"
    @property
    def menu_title(self) -> str: return "Application Setup"

    def run(self, ctx: ScriptContext) -> None:
        ctx.logger.info("Request Type - Application Setup")

        user_config_path = Path.home() / ".cn"

        while True:
            ctx.console.clear()
            configurable_plugins = [p for p in ctx.plugins if p.user_configurable_settings]
            if not configurable_plugins:
                ctx.console.print("[yellow]No configurable plugins found.[/yellow]")
                return

            ctx.console.print("[bold cyan]--- Plugin Configuration ---[/bold cyan]")
            for i, plugin in enumerate(configurable_plugins):
                ctx.console.print(f"  [green]{i + 1}.[/green] Configure [yellow]{plugin.name}[/yellow]")
            ctx.console.print("  [green]0.[/green] Return to Main Menu")

            choice = read_user_input(ctx, "\nSelect a plugin to configure: ")

            if choice == '' or choice == '0':
                break

            if not choice.isdigit():
                continue

            choice_idx = int(choice)
            if choice_idx == 0:
                break
            if not (1 <= choice_idx <= len(configurable_plugins)):
                continue

            selected_plugin = configurable_plugins[choice_idx - 1]
            self._configure_plugin(ctx, selected_plugin, user_config_path)

    def _configure_plugin(self, ctx: ScriptContext, plugin, user_config_path):
        """Handles the configuration menu for a single plugin."""
        settings = plugin.user_configurable_settings
        schema = plugin.config_schema

        while True:
            ctx.console.clear()
            ctx.console.print(f"[bold cyan]--- Configuring {plugin.name} ---[/bold cyan]")
            for i, setting in enumerate(settings):
                key = setting['key']
                prompt = setting['prompt']
                current_value = ctx.cfg.get(key, 'Not Set')

                spec = schema.get(key, {})
                display_value = current_value
                if spec.get('type') == 'bool':
                    display_value = "[green]Enabled[/green]" if current_value else "[red]Disabled[/red]"

                ctx.console.print(f"  [green]{i + 1}.[/green] {prompt}: {display_value}")
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
            setting_key = selected_setting['key']
            setting_spec = schema[setting_key]

            current_value = ctx.cfg.get(setting_key)
            new_value_to_write = ""

            # <<< NEW: Smart handling for boolean toggling >>>
            if setting_spec.get('type') == 'bool':
                # Toggle the boolean value
                new_value = not current_value
                new_value_to_write = str(new_value)
                ctx.cfg[setting_key] = new_value  # Update live context
                ctx.console.print(f"[cyan]{selected_setting['prompt']}[/cyan] has been set to [yellow]{'Enabled' if new_value else 'Disabled'}[/yellow].")
            else:
                # Validation-aware input for non-boolean settings
                while True:
                    prompt = selected_setting['prompt']
                    choices = setting_spec.get('choices')
                    if choices:
                        prompt += f" (choices: {', '.join(choices)})"
                    raw = read_user_input(ctx, f"Enter new value for [yellow]{prompt}[/yellow]: ")

                    valid, normalized, err = self._validate_and_normalize_setting(ctx, setting_key, setting_spec, raw)
                    if valid:
                        new_value_to_write = normalized
                        # Update live context with typed value when possible
                        if setting_spec.get('type') == 'path':
                            ctx.cfg[setting_key] = Path(normalized).expanduser()
                        else:
                            ctx.cfg[setting_key] = normalized
                        ctx.console.print(f"[cyan]{selected_setting['prompt']}[/cyan] has been set to [yellow]{normalized}[/yellow].")
                        break
                    else:
                        ctx.console.print(f"[red]Invalid value[/red]: {err}")

            # Write the string representation to the config file
            write_config_value(
                ctx.logger,
                user_config_path,
                setting_spec['section'],
                setting_spec['ini_key'],
                new_value_to_write
            )

            ctx.console.print("[green]Setting updated! It will be fully effective on the next application run.[/green]")
            time.sleep(1.5)
    def _validate_and_normalize_setting(self, ctx: ScriptContext, key: str, spec: dict, raw: str) -> tuple[bool, str, str]:
        """Validate user input according to the plugin's config schema.

        Returns (is_valid, normalized_value, error_message).
        """
        raw = (raw or '').strip()
        if not raw:
            return False, raw, "value cannot be empty"

        t = spec.get('type')
        choices = spec.get('choices')
        # Restrict to choice set (case-insensitive), persist canonical choice value
        if choices and t == 'str':
            lower = raw.lower()
            cl = [c.lower() for c in choices]
            if lower not in cl:
                return False, raw, f"must be one of: {', '.join(choices)}"
            return True, choices[cl.index(lower)], ''

        if t == 'path':
            p = Path(raw).expanduser()
            if not check_dir_accessibility(ctx.logger, p):
                return False, raw, f"directory not accessible: {p}"
            return True, str(p), ''

        # Accept any non-empty string for other types here
        return True, raw, ''
