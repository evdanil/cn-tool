# core/loader.py
import os
import importlib
import inspect
from typing import Dict, Any
from core.base import BaseModule, BasePlugin


def load_modules_and_plugins(master_schema: Dict[str, Any]) -> tuple[Dict[str, BaseModule], list[BasePlugin], Dict[str, Any]]:
    """
    Discovers, loads, and registers all modules and plugins.
    It also collects configuration schemas from plugins and merges them.

    Args:
        master_schema: The base configuration schema of the application.

    Returns:
        A tuple containing:
        - A dictionary of loaded and configured module instances.
        - The updated master schema including plugin configurations.
    """
    # Start with a copy of the base schema
    updated_schema = master_schema.copy()
    all_plugins: list[BasePlugin] = []

    modules_path = os.path.join(os.path.dirname(__file__), '..', 'modules')
    plugins_path = os.path.join(os.path.dirname(__file__), '..', 'plugins')

    modules = _load_modules(modules_path)
    # The plugin loader now returns the updated schema
    updated_schema = _load_and_register_plugins(plugins_path, modules, updated_schema, all_plugins)

    # Return a dictionary keyed by menu_key for easy access in the main loop
    modules_by_key = {mod.menu_key: mod for mod in modules.values()}

    return modules_by_key, all_plugins, updated_schema


def _load_modules(path: str) -> Dict[str, BaseModule]:
    """Loads all BaseModule subclasses from a given directory."""
    loaded_modules: Dict[str, BaseModule] = {}
    for filename in os.listdir(path):
        if filename.endswith('.py') and not filename.startswith('__'):
            module_name = filename[:-3]
            module_path = f"modules.{module_name}"
            try:
                module = importlib.import_module(module_path)
                for name, obj in inspect.getmembers(module):
                    try:
                        if inspect.isclass(obj) and issubclass(obj, BaseModule) and obj is not BaseModule:
                            loaded_modules[module_name] = obj()  # Instantiate the module
                    except TypeError:
                        continue
            except ImportError as e:
                print(f"Error loading module {module_path}: {e}")
    return loaded_modules


def _load_and_register_plugins(path: str, modules: Dict[str, BaseModule], schema: Dict[str, Any], plugin_list: list[BasePlugin]) -> Dict[str, Any]:
    """
    Loads plugins, registers their hooks, and merges their config schemas.
    """
    for filename in os.listdir(path):
        if filename.endswith('.py') and not filename.startswith('__'):
            module_name = filename[:-3]
            module_path = f"plugins.{module_name}"
            try:
                module = importlib.import_module(module_path)
                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj):
                        try:
                            if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                                plugin = obj()
                                plugin_list.append(plugin)

                                plugin_schema = plugin.config_schema
                                if plugin_schema:
                                    print(f"Info: Loading config schema from plugin '{plugin.name}'")
                                    schema.update(plugin_schema)

                                target_name = plugin.target_module_name
                                # Only attempt to register if the plugin specifies a target.
                                if target_name:
                                    target_module = modules.get(target_name)
                                    if target_module:
                                        plugin.register(target_module)
                                    else:
                                        # This warning will now only show for plugins that
                                        # SPECIFY a target that does not exist.
                                        print(f"Warning: Plugin '{plugin.name}' targets non-existent module '{target_name}'")
                                # If target_name is empty, we do nothing. This is expected for lifecycle plugins.
                        except TypeError:
                            continue
            except ImportError as e:
                print(f"Error loading plugin {module_path}: {e}")
    return schema
