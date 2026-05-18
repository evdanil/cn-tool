# core/loader.py
import os
import importlib
import inspect
import logging
from typing import Dict, Any
from core.base import BaseModule, BasePlugin


logger = logging.getLogger(__name__)


def _merge_plugin_schema(schema: Dict[str, Any], plugin_schema: Dict[str, Any]) -> Dict[str, Any]:
    """Merge plugin schema entries without discarding required base metadata."""
    merged = schema.copy()
    for key, plugin_spec in plugin_schema.items():
        current_spec = merged.get(key)
        if isinstance(current_spec, dict) and isinstance(plugin_spec, dict):
            merged[key] = {**current_spec, **plugin_spec}
        else:
            merged[key] = plugin_spec
    return merged


def collect_plugin_schemas(master_schema: Dict[str, Any]) -> Dict[str, Any]:
    """Harvest config_schema from every plugin without registering hooks.

    Returns ``master_schema`` extended with each plugin's contributed keys.
    Used by cn-lens (``cn_lens.runtime``) so it sees the same schema surface as
    cn-tool's main entry point without pulling in module loading or hook
    registration. Plugin files are walked in ``sorted(os.listdir(...))`` order
    -- the same order ``_load_and_register_plugins`` uses -- so merge precedence
    matches between the two callers.

    NOTE: this instantiates each ``BasePlugin`` subclass to read its
    ``config_schema`` property. Plugin authors must keep ``__init__`` free of
    I/O or thread/process creation, otherwise cn-lens runtime build incurs
    those side effects on every invocation.
    """
    plugins_path = os.path.join(os.path.dirname(__file__), "..", "plugins")
    schema = master_schema.copy()
    if not os.path.isdir(plugins_path):
        return schema
    for filename in sorted(os.listdir(plugins_path)):
        if not filename.endswith(".py") or filename.startswith("__"):
            continue
        module_path = f"plugins.{filename[:-3]}"
        try:
            mod = importlib.import_module(module_path)
        except Exception as exc:
            logger.debug("collect_plugin_schemas: import failed %s: %s", module_path, exc)
            continue
        for _, obj in inspect.getmembers(mod):
            if not inspect.isclass(obj) or obj is BasePlugin:
                continue
            try:
                if not issubclass(obj, BasePlugin):
                    continue
            except TypeError:
                continue
            try:
                plugin_schema = obj().config_schema or {}
            except Exception as exc:
                logger.warning(
                    "collect_plugin_schemas: could not read schema from %s: %s",
                    obj.__name__,
                    exc,
                )
                continue
            schema = _merge_plugin_schema(schema, plugin_schema)
    return schema


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
    for filename in sorted(os.listdir(path)):
        if filename.endswith('.py') and not filename.startswith('__'):
            module_name = filename[:-3]
            module_path = f"modules.{module_name}"
            try:
                module = importlib.import_module(module_path)
                for name, obj in inspect.getmembers(module):
                    try:
                        if inspect.isclass(obj) and issubclass(obj, BaseModule) and obj is not BaseModule:
                            instance = obj()
                            logger.info(f"  -> Loaded module: {instance.menu_title} ({module_name})")
                            loaded_modules[module_name] = instance  # Instantiate the module
                    except TypeError:
                        continue
            except ImportError as e:
                logger.error("Error loading module %s: %s", module_path, e)
    return loaded_modules


def _load_and_register_plugins(path: str, modules: Dict[str, BaseModule], schema: Dict[str, Any], plugin_list: list[BasePlugin]) -> Dict[str, Any]:
    """
    Loads plugins, registers their hooks, and merges their config schemas.
    """
    for filename in sorted(os.listdir(path)):
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
                                logger.info(f"  -> Loaded plugin: {plugin.name}")
                                plugin_list.append(plugin)

                                plugin_schema = plugin.config_schema
                                if plugin_schema:
                                    logger.info("Loading config schema from plugin '%s'", plugin.name)
                                    schema = _merge_plugin_schema(schema, plugin_schema)

                                target_name = plugin.target_module_name
                                # Only attempt to register if the plugin specifies a target.
                                if target_name:
                                    target_module = modules.get(target_name)
                                    if target_module:
                                        plugin.register(target_module)
                                    else:
                                        # This warning will now only show for plugins that
                                        # SPECIFY a target that does not exist.
                                        logger.warning("Plugin '%s' targets non-existent module '%s'", plugin.name, target_name)
                                # If target_name is empty, we do nothing. This is expected for lifecycle plugins.
                        except TypeError:
                            continue
            except ImportError as e:
                logger.error("Error loading plugin %s: %s", module_path, e)
    return schema
