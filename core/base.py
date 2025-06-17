# core/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
import logging
import threading
from typing import Dict, Any, List, Callable, Optional, TYPE_CHECKING


class ThreadSafeFileHandler(logging.FileHandler):
    def __init__(self, filename: str, mode: str = 'a', encoding: Optional[str] = None, delay: bool = False):
        super().__init__(filename, mode, encoding, delay)
        self._lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        with self._lock:
            super().emit(record)


if TYPE_CHECKING:
    from utils.display import ThemedConsole
    from utils.cache import CacheManager


@dataclass
class ScriptContext:
    """A container for shared objects used throughout the script."""
    cfg: Dict[str, Any]
    logger: logging.Logger
    console: "ThemedConsole"  # Use quotes for forward reference
    cache: Optional["CacheManager"]  # Use quotes for forward reference
    username: str
    password: str
    plugins: List["BasePlugin"]


class BaseModule(ABC):
    """Abstract Base Class for all main menu modules."""

    def __init__(self):
        # Hooks are points where plugins can inject logic.
        # The key is the hook name, the value is a list of callback functions.
        self.hooks: Dict[str, List[Callable]] = {
            'pre_run': [],  # Called at the absolute beginning of a module's run method.
            'process_data': [],  # Called after initial data processing.
            'pre_render': [],   # Called just before creating tables for display.
            'pre_save': [],     # Called just before queueing data for saving.
            'post_run': [],     # Called at the very end of a module's run method, for cleanup.
        }

    @property
    def visibility_config_key(self) -> Optional[str]:
        """
        If a string is returned, this module will only be visible in the menu
        if the corresponding key in the configuration is True.
        e.g., return 'email_enabled'
        """
        return None

    @property
    @abstractmethod
    def menu_key(self) -> str:
        """The character key to trigger this module from the menu (e.g., '1', 'b')."""
        pass

    @property
    @abstractmethod
    def menu_title(self) -> str:
        """The title of the module to display in the menu."""
        pass

    def register_hook(self, hook_name: str, callback: Callable):
        """Allows plugins to register a callback for a specific hook."""
        if hook_name in self.hooks:
            self.hooks[hook_name].append(callback)
        else:
            print(f"Warning: Attempted to register for unknown hook '{hook_name}' in {self.menu_title}")

    def execute_hook(self, hook_name: str, ctx: ScriptContext, data: Any) -> Any:
        """Executes all registered callbacks for a hook, passing data through them."""
        modified_data = data
        for callback in self.hooks.get(hook_name, []):
            # Each callback receives the context and the data, and must return the (potentially modified) data.
            modified_data = callback(ctx, modified_data)
        return modified_data

    @abstractmethod
    def run(self, ctx: ScriptContext) -> None:
        """The main entry point for the module's execution."""
        pass


class BasePlugin(ABC):
    """Abstract Base Class for all plugins."""

    @property
    def user_configurable_settings(self) -> List[Dict[str, str]]:
        """
        A list of settings this plugin exposes to the user via the setup module.
        Each dict should contain:
        - 'key': The key in the config context (e.g., 'ad_user')
        - 'prompt': The user-friendly prompt (e.g., 'Active Directory Username')
        """
        return []
    
    @property
    @abstractmethod
    def name(self) -> str:
        """A descriptive name for the plugin."""
        pass

    @property
    @abstractmethod
    def target_module_name(self) -> str:
        """The filename of the module this plugin targets (e.g., 'ip_request')."""
        pass

    @property
    def config_schema(self) -> Dict[str, Dict[str, Any]]:
        """
        Defines the configuration schema required by this plugin.
        Each plugin can specify its own section, keys, types, and fallbacks.
        Example:
            return {
                'my_plugin_key': {'section': 'myplugin', 'ini_key': 'api_key', 'type': 'str', 'fallback': ''}
            }
        """
        return {}

    @property
    def manages_global_connection(self) -> bool:
        """
        If True, this plugin manages a persistent, application-wide connection.
        The main application will call connect() on startup and disconnect() on exit.
        """
        return False

    def connect(self, ctx: ScriptContext) -> None:
        """
        Called once on application startup if manages_global_connection is True.
        Used to initialize persistent resources like API connections.
        """
        pass

    def disconnect(self, ctx: ScriptContext) -> None:
        """
        Called once on application exit if manages_global_connection is True.
        Used to clean up persistent resources.
        """
        pass

    @abstractmethod
    def register(self, module: BaseModule) -> None:
        """Called by the loader to register the plugin's hooks with its target module."""
        pass
