import time
from pathlib import Path
from typing import Any, List, Mapping, Optional, Sequence

from core.base import BaseModule, ScriptContext
from utils.config import write_config_value
from utils.file_io import check_dir_accessibility
from utils.user_input import read_user_input


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

    def _configure_plugin(self, ctx: ScriptContext, plugin, user_config_path: Path) -> None:
        settings = self._normalize_settings(plugin.user_configurable_settings)
        schema: Mapping[str, Mapping[str, Any]] = plugin.config_schema or {}

        while True:
            ctx.console.clear()
            ctx.console.print(f"[bold cyan]--- Configuring {plugin.name} ---[/bold cyan]")

            is_ad_plugin = getattr(plugin, "name", "").lower() == "active directory support"
            ad_enabled = True
            if is_ad_plugin:
                ad_enabled = self._coerce_bool(ctx.cfg.get("ad_enabled", False))

            for index, setting in enumerate(settings, start=1):
                key = setting.get("key")
                prompt = setting.get("prompt", key)
                current_value = ctx.cfg.get(key, "Not Set")
                spec = schema.get(key, {})

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
            setting_spec = schema.get(setting_key)
            if not setting_spec:
                ctx.console.print(f"[red]No configuration schema found for setting '{setting_key}'.[/red]")
                time.sleep(1.5)
                continue

            current_value = ctx.cfg.get(setting_key)
            ad_setting_ignored = is_ad_plugin and setting_key != "ad_enabled" and not ad_enabled
            new_value_to_write: Optional[str] = None

            if setting_spec.get("type") == "bool":
                current_bool = self._coerce_bool(current_value)
                new_value = not current_bool
                new_value_to_write = "true" if new_value else "false"
                ctx.cfg[setting_key] = new_value
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
                    raw = read_user_input(ctx, f"Enter new value for [yellow]{prompt}[/yellow]: ")

                    valid, normalized, err = self._validate_and_normalize_setting(ctx, setting_key, setting_spec, raw)
                    if valid:
                        new_value_to_write = str(normalized)
                        setting_type = setting_spec.get("type")
                        if setting_type == "path":
                            ctx.cfg[setting_key] = Path(normalized).expanduser()
                        elif setting_type == "list[str]":
                            ctx.cfg[setting_key] = [segment.strip() for segment in str(normalized).split(',') if segment.strip()]
                        else:
                            ctx.cfg[setting_key] = normalized
                        ctx.console.print(f"[cyan]{selected_setting['prompt']}[/cyan] has been set to [yellow]{normalized}[/yellow].")
                        if ad_setting_ignored:
                            ctx.console.print("[yellow]Note: Active Directory integration is disabled; this setting is ignored until it is enabled.[/yellow]")
                        break
                    else:
                        ctx.console.print(f"[red]Invalid value[/red]: {err}")

            if new_value_to_write is None:
                continue

            write_config_value(
                ctx.logger,
                user_config_path,
                setting_spec['section'],
                setting_spec['ini_key'],
                new_value_to_write,
            )

            ctx.console.print("[green]Setting updated! It will be fully effective on the next application run.[/green]")
            time.sleep(1.5)

    def _normalize_settings(self, raw_settings: Any) -> List[dict[str, Any]]:
        """Return a deterministic list of setting dictionaries."""
        if isinstance(raw_settings, Mapping):
            normalized: List[dict[str, Any]] = []
            for key in sorted(raw_settings.keys()):
                entry = raw_settings[key]
                if isinstance(entry, Mapping):
                    item = dict(entry)
                    item.setdefault("key", key)
                else:
                    item = {"key": key, "prompt": str(entry)}
                normalized.append(item)
            return normalized

        if isinstance(raw_settings, Sequence) and not isinstance(raw_settings, (str, bytes)):
            normalized_list: List[dict[str, Any]] = []
            for entry in raw_settings:
                if isinstance(entry, Mapping):
                    normalized_list.append(dict(entry))
                else:
                    raise TypeError("SetupModule settings entries must be mappings with 'key' and 'prompt'.")
            return normalized_list

        raise TypeError("Unsupported settings collection type: expected mapping or sequence of mappings.")

    def _coerce_bool(self, value: Any) -> bool:
        if isinstance(value, str):
            return value.strip().lower() in {"true", "1", "t", "y", "yes", "on"}
        return bool(value)

    def _format_display_value(self, value: Any, spec: Mapping[str, Any]) -> str:
        if value in (None, "Not Set"):
            return "[yellow]Not Set[/yellow]"
        option_type = spec.get("type")
        if option_type == "bool":
            return "[green]Enabled[/green]" if self._coerce_bool(value) else "[red]Disabled[/red]"
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
            if not check_dir_accessibility(ctx.logger, p):
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

        return True, raw, ''
