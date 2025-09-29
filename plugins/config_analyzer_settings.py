from typing import Dict, Any, List

from core.base import BasePlugin, BaseModule


class ConfigAnalyzerSettingsPlugin(BasePlugin):
    """
    Exposes settings for the Config Analyzer integration to the Setup module.

    This is a lifecycle (non-targeting) plugin used purely to surface
    user-configurable options such as the configuration repository path,
    history folder name, default layout, and scrolling behavior.
    """

    @property
    def name(self) -> str:
        return "Config Analyzer"

    @property
    def target_module_name(self) -> str:
        # Lifecycle plugin – does not register any hooks against a module
        return ""

    @property
    def user_configurable_settings(self) -> List[Dict[str, str]]:
        return [
            {"key": "config_analyzer_repo_directories", "prompt": "Analyzer repo directories (comma-separated paths)"},
            {"key": "config_analyzer_repo_names", "prompt": "Analyzer repo display names (comma-separated)"},
            {"key": "config_repo_history_dir", "prompt": "History folder name (e.g. 'history')"},
            {"key": "config_analyzer_layout", "prompt": "Default layout (right/left/top/bottom)"},
            {"key": "config_analyzer_scroll_to_end", "prompt": "Scroll to end on load (toggle)"},
            {"key": "config_analyzer_debug", "prompt": "Enable debug logging (toggle)"},
        ]

    @property
    def config_schema(self) -> Dict[str, Dict[str, Any]]:
        # Mirror utils/config.BASE_CONFIG_SCHEMA entries so Setup can persist values
        return {
            # Existing base config keys (duplicated spec for Setup writing)
            "config_analyzer_repo_directories": {
                "section": "config_analyzer",
                "ini_key": "repo_directories",
                "type": "list[str]",
                "fallback": "/opt/data/configs",
                "validate": "path",
            },
            "config_analyzer_repo_names": {
                "section": "config_analyzer",
                "ini_key": "repo_names",
                "type": "list[str]",
                "fallback": "",
            },
            # Legacy single-directory override remains for backward compatibility
            "config_analyzer_repo_directory": {
                "section": "config_analyzer",
                "ini_key": "repo_directory",
                "type": "path",
                "fallback": "/opt/data/configs",
            },
            "config_repo_history_dir": {"section": "config_repo", "ini_key": "history_dir", "type": "str", "fallback": "history"},

            # Analyzer UI preferences
            "config_analyzer_layout": {"section": "config_analyzer", "ini_key": "layout", "type": "str", "fallback": "right", "choices": ["right", "left", "top", "bottom"]},
            "config_analyzer_scroll_to_end": {"section": "config_analyzer", "ini_key": "scroll_to_end", "type": "bool", "fallback": False},
            "config_analyzer_debug": {"section": "config_analyzer", "ini_key": "debug", "type": "bool", "fallback": False},
        }

    def register(self, module: BaseModule) -> None:
        # Lifecycle plugin – nothing to register
        return

