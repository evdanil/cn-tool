import configparser
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List

from core.base import ScriptContext
from utils.file_io import check_dir_accessibility

# --- Configuration Schema ---
BASE_CONFIG_SCHEMA = {
    "api_endpoint":          {"section": "api", "ini_key": "endpoint", "type": "str", "fallback": "API_URL"},
    "logging_file":          {"section": "logging", "ini_key": "logfile", "type": "path", "fallback": "~/cn.log"},
    "logging_level":         {"section": "logging", "ini_key": "level", "type": "str", "fallback": "INFO"},
    "report_file":           {"section": "output", "ini_key": "filename", "type": "path", "fallback": "~/report.xlsx"},
    "report_auto_save":      {"section": "output", "ini_key": "auto_save", "type": "bool", "fallback": True},
    "gpg_credentials":       {"section": "gpg", "ini_key": "credentials", "type": "path", "fallback": "~/device-apply.gpg"},
    "config_repo_directory": {"section": "config_repo", "ini_key": "directory", "type": "path", "fallback": "/opt/data/configs"},
    "config_repo_regions":   {"section": "config_repo", "ini_key": "regions", "type": "list[str]", "fallback": "ap,eu,am"},
    "config_repo_vendors":   {"section": "config_repo", "ini_key": "vendors", "type": "list[str]", "fallback": "cisco,aruba,f5,bluecoat,paloalto"},
    "cache_directory":       {"section": "cache", "ini_key": "directory", "type": "path", "fallback": "~/.cn-cache"},
    "cache_enabled":         {"section": "cache", "ini_key": "enabled", "type": "bool", "fallback": True},
    "cache_version":         {"section": "cache", "ini_key": "version", "type": "int", "fallback": 2},
    "theme_name":            {"section": "theme", "ini_key": "theme", "type": "str", "fallback": "default"},
}


def _apply_types(cfg: Dict[str, Any], schema: Dict[str, Any]) -> Dict[str, Any]:
    """Helper function to convert raw string values to their proper types."""
    typed_cfg = cfg.copy()
    for key, spec in schema.items():
        if key in typed_cfg:
            raw_value = typed_cfg[key]
            option_type = spec["type"]
            if option_type == 'path':
                typed_cfg[key] = Path(str(raw_value)).expanduser()
            elif option_type == 'list[str]':
                typed_cfg[key] = [item.strip() for item in str(raw_value).split(',')]
            elif option_type == 'bool' and isinstance(raw_value, str):
                typed_cfg[key] = raw_value.lower() in ('true', '1', 't', 'y', 'yes')
    return typed_cfg


def read_config(config_files: List[Path], schema: Dict[str, Any], logger: logging.Logger) -> Dict[str, Any]:
    """
    Reads configuration from a prioritized list of files.

    Args:
        config_files: A list of paths to check for config files, in order
                      from lowest to highest priority.
        logger: The application logger.

    Returns:
        A dictionary of configuration settings.
    """

    # Step 1: Create a dictionary with all default values.
    loaded_cfg = {key: spec['fallback'] for key, spec in schema.items()}

    # --- DEBUG: Show the initial state with defaults ---
    logger.debug(f"CONFIG: Initialized with default values from schema: {loaded_cfg}")

    # Step 2: Find which of the potential config files actually exist.
    existing_files = [f for f in config_files if f.is_file()]

    if not existing_files:
        logger.warning("CONFIG: No configuration files found. Proceeding with default settings.")
        return _apply_types(loaded_cfg, schema)

    logger.info(f"CONFIG: Reading configuration from files: {existing_files}")

    # Step 3: Read all existing files. configparser handles the overrides.
    config = configparser.ConfigParser()
    try:
        # This is the key: read() processes the list in order.
        read_files = config.read(existing_files)
        logger.debug(f"Read and merged configuration from files: {read_files}")
    except configparser.Error as e:
        logger.error(f"CONFIG: Error parsing configuration files: {e}")
        return _apply_types(loaded_cfg, schema)  # Fallback to defaults on error

    for key, spec in schema.items():
        section = spec["section"]
        ini_key = spec["ini_key"]  # Use the key name from the INI file

        if config.has_option(section, ini_key):
            original_value = loaded_cfg[key]
            if spec['type'] == 'bool':
                new_value = config.getboolean(section, ini_key)
            else:
                new_value = config.get(section, ini_key)

            logger.debug(f"CONFIG: Overwriting '{key}' (from [{section}].{ini_key}). Default: '{original_value}' -> New: '{new_value}'")
            loaded_cfg[key] = new_value  # Store it using the unified key

    # Step 4: Apply final type conversions.
    final_cfg = _apply_types(loaded_cfg, schema)
    # --- DEBUG: Log the final configuration dictionary ---
    logger.debug(f"CONFIG: Final configuration object after type conversion: {final_cfg}")

    return final_cfg


def setup_from_args(cfg: Dict[str, Any], args: argparse.Namespace, logger: logging.Logger) -> Dict[str, Any]:
    """Updates the configuration dictionary based on command-line arguments."""
    # This function is straightforward, but we can add one debug line
    logger.debug("CONFIG: Checking for overrides from command-line arguments...")

    if args.report_file:
        logger.debug(f"CONFIG: CLI override for 'report_file': {args.report_file}")
        cfg["report_file"] = Path(args.report_file).expanduser()
    if args.log_file:
        logger.debug(f"CONFIG: CLI override for 'logfile_location': {args.log_file}")
        cfg["logging_file"] = Path(args.log_file).expanduser()
    if args.gpg_file:
        logger.debug(f"CONFIG: CLI override for 'gpg_credentials': {args.gpg_file}")
        cfg["gpg_credentials"] = Path(args.gpg_file).expanduser()
    if args.no_cache:
        logger.debug(f"CONFIG: CLI override for 'cache': {args.no_cache}")
        cfg["cache_enabled"] = False
    if args.theme:
        logger.debug(f"CONFIG: CLI override for 'theme_name': {args.theme}")
        cfg["theme_name"] = args.theme
    if args.log_level:
        logger.debug(f"CONFIG: CLI override for 'logging_level': {args.log_level}")
        cfg["logging_level"] = args.log_level.upper()

    return cfg


def make_dir_list(ctx: ScriptContext) -> List[Path]:
    """
    Reads the config from the context and generates a list of device configuration 
    directories to scan. This is a shared utility used by both caching and live search.
    """
    logger = ctx.logger
    cfg = ctx.cfg
    config_repo = cfg.get("config_repo_directory")

    dir_list: List[Path] = []

    if not config_repo or not check_dir_accessibility(logger, config_repo):
        logger.warning("Configuration repository storage directory is not accessible.")
        return dir_list

    for vendor in cfg.get("config_repo_vendors", []):
        vendor_path = config_repo / vendor.strip()
        if not check_dir_accessibility(logger, vendor_path):
            continue

        for device_type_path in vendor_path.iterdir():
            if not device_type_path.is_dir():
                continue
            for region in cfg.get("config_repo_regions", []):
                region_path = device_type_path / region.strip()
                if check_dir_accessibility(logger, region_path):
                    dir_list.append(region_path)
    return dir_list
