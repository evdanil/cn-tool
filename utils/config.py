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
    "api_verify_ssl":        {"section": "api", "ini_key": "verify_ssl", "type": "bool", "fallback": True},
    "api_timeout":           {"section": "api", "ini_key": "timeout", "type": "int", "fallback": 10},
    "logging_file":          {"section": "logging", "ini_key": "logfile", "type": "path", "fallback": "~/cn.log"},
    "logging_level":         {"section": "logging", "ini_key": "level", "type": "str", "fallback": "INFO"},
    "report_file":           {"section": "report", "ini_key": "filename", "type": "path", "fallback": "~/report.xlsx"},
    "report_auto_save":      {"section": "report", "ini_key": "auto_save", "type": "bool", "fallback": True},
    "report_lock_timeout":   {"section": "report", "ini_key": "lock_timeout", "type": "int", "fallback": 120},
    "report_max_config_tab_kb": {"section": "report", "ini_key": "max_config_tab_kb", "type": "int", "fallback": 512},
    "gpg_credentials":       {"section": "gpg", "ini_key": "credentials", "type": "path", "fallback": "~/device-apply.gpg"},
    "config_repo_directory": {"section": "config_repo", "ini_key": "directory", "type": "path", "fallback": "/opt/data/configs"},
    "config_repo_regions":   {"section": "config_repo", "ini_key": "regions", "type": "list[str]", "fallback": "ap,eu,am"},
    "config_repo_vendors":   {"section": "config_repo", "ini_key": "vendors", "type": "list[str]", "fallback": "cisco,aruba,f5,bluecoat,paloalto"},
    "config_repo_excluded_dirs": {"section": "config_repo", "ini_key": "excluded_dirs", "type": "list[str]", "fallback": ""},
    "cache_directory":       {"section": "cache", "ini_key": "directory", "type": "path", "fallback": "~/.cn-cache"},
    "cache_enabled":         {"section": "cache", "ini_key": "enabled", "type": "bool", "fallback": True},
    "cache_version":         {"section": "cache", "ini_key": "version", "type": "int", "fallback": 2},
    "cache_check_workers":   {"section": "cache", "ini_key": "check_workers", "type": "int", "fallback": 4},
    "cache_index_workers":   {"section": "cache", "ini_key": "index_workers", "type": "int", "fallback": 4},
    "cache_index_executor":  {"section": "cache", "ini_key": "index_executor", "type": "str", "fallback": "thread"},
    "cache_index_queue_size": {"section": "cache", "ini_key": "index_queue_size", "type": "int", "fallback": 64},
    "cache_index_batch_size": {"section": "cache", "ini_key": "index_batch_size", "type": "int", "fallback": 100},
    "cache_index_max_positions_per_key": {"section": "cache", "ini_key": "index_max_positions_per_key", "type": "int", "fallback": 64},
    "cache_index_skip_vendors": {"section": "cache", "ini_key": "index_skip_vendors", "type": "list[str]", "fallback": ""},
    "cache_index_skip_keyword_vendors": {"section": "cache", "ini_key": "index_skip_keyword_vendors", "type": "list[str]", "fallback": ""},
    "cache_index_skip_ip_vendors": {"section": "cache", "ini_key": "index_skip_ip_vendors", "type": "list[str]", "fallback": ""},
    "theme_name":            {"section": "theme", "ini_key": "theme", "type": "str", "fallback": "default"},
    # Config Analyzer (external TUI) settings
    "config_repo_history_dir":     {"section": "config_repo", "ini_key": "history_dir", "type": "str", "fallback": "history"},
    "config_analyzer_repo_directories": {"section": "config_analyzer", "ini_key": "repo_directories", "type": "list[str]", "fallback": "/opt/data/configs"},
    "config_analyzer_repo_names": {"section": "config_analyzer", "ini_key": "repo_names", "type": "list[str]", "fallback": ""},
    "config_analyzer_layout":      {"section": "config_analyzer", "ini_key": "layout", "type": "str", "fallback": "right"},
    "config_analyzer_scroll_to_end": {"section": "config_analyzer", "ini_key": "scroll_to_end", "type": "bool", "fallback": False},
    "config_analyzer_debug":       {"section": "config_analyzer", "ini_key": "debug", "type": "bool", "fallback": False},
}

# Backward/forward compatibility across section renames.
# Primary section is read first; aliases are checked only if primary key is absent.
SECTION_ALIASES: Dict[str, List[str]] = {
    "report": ["output"],
    "output": ["report"],
}


def _apply_types(cfg: Dict[str, Any], schema: Dict[str, Any], logger: logging.Logger) -> Dict[str, Any]:
    """
    Helper function to convert raw string values to their proper types and sanitize them.
    """
    typed_cfg = cfg.copy()
    for key, spec in schema.items():
        if key in typed_cfg:
            raw_value = typed_cfg[key]
            option_type = spec["type"]

            # This check handles the case where the value might already be a bool or int from a default.
            if not isinstance(raw_value, str):
                continue  # It's not a string that needs cleaning, so skip.

            # Strip leading/trailing whitespace, then strip standard quote characters.
            clean_value = raw_value.strip().strip('"\'')

            if option_type == 'path':
                typed_cfg[key] = Path(clean_value).expanduser()
            elif option_type == 'list[str]':
                # Split the raw string, then sanitize each individual item in the list.
                items = raw_value.split(',')
                typed_cfg[key] = [
                    item.strip().strip('"\'')
                    for item in items
                    if item.strip().strip('"\'')
                ]
            elif option_type == 'bool':
                typed_cfg[key] = clean_value.lower() in ('true', '1', 't', 'y', 'yes')
            elif option_type == 'str':
                typed_cfg[key] = clean_value
            # For 'int', we let the final conversion happen in read_config, but we use the clean string.
            elif option_type == 'int':
                try:
                    typed_cfg[key] = int(clean_value)
                except (ValueError, TypeError):
                    logger.warning(f"CONFIG: Could not convert '{clean_value}' to int for key '{key}'. Using fallback.")
                    typed_cfg[key] = spec['fallback']
    return typed_cfg


def read_config(config_files: List[Path], schema: Dict[str, Any], logger: logging.Logger) -> Dict[str, Any]:
    """
    Reads configuration from a prioritized list of files using a dynamic schema.
    """
    loaded_cfg = {key: spec['fallback'] for key, spec in schema.items()}
    logger.debug("CONFIG: Initialized with default values from schema.")

    existing_files = [f for f in config_files if f.is_file()]
    if not existing_files:
        logger.warning("CONFIG: No configuration files found. Proceeding with defaults.")
        return _apply_types(loaded_cfg, schema, logger)

    logger.info(f"CONFIG: Reading configuration from files: {existing_files}")
    config = configparser.ConfigParser()
    try:
        config.read(existing_files)
    except configparser.Error as e:
        logger.error(f"CONFIG: Error parsing configuration files: {e}")
        return _apply_types(loaded_cfg, schema, logger)

    # Read only RAW strings from the config file. Let _apply_types handle all conversions.
    for key, spec in schema.items():
        section = spec["section"]
        ini_key = spec["ini_key"]
        sections_to_check = [section] + SECTION_ALIASES.get(section, [])

        for section_name in sections_to_check:
            if not config.has_option(section_name, ini_key):
                continue

            # Always get the raw string value.
            new_value = config.get(section_name, ini_key)
            loaded_cfg[key] = new_value
            if section_name != section:
                logger.debug(
                    "CONFIG: Using compatibility section [%s] for [%s] %s",
                    section_name,
                    section,
                    ini_key,
                )
            break

    # Apply final type conversions and sanitization to the entire config dict.
    final_cfg = _apply_types(loaded_cfg, schema, logger)
    logger.debug(f"CONFIG: Final configuration object after processing: {final_cfg}")

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
    regions = cfg.get("config_repo_regions", [])
    excluded_dirs = {
        str(item).strip().lower()
        for item in cfg.get("config_repo_excluded_dirs", [])
        if str(item).strip()
    }
    history_dir = str(cfg.get("config_repo_history_dir", "history")).strip().lower()
    if history_dir:
        # History trees should not be indexed as live configs by default.
        excluded_dirs.add(history_dir)

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
            if device_type_path.name.lower() in excluded_dirs:
                logger.debug(f"Skipping excluded config directory: {device_type_path}")
                continue

            if regions:
                for region in regions:
                    region_path = device_type_path / region.strip()
                    if region_path.name.lower() in excluded_dirs:
                        logger.debug(f"Skipping excluded config directory: {region_path}")
                        continue
                    if check_dir_accessibility(logger, region_path):
                        dir_list.append(region_path)
            else:
                if check_dir_accessibility(logger, device_type_path):
                    dir_list.append(device_type_path)
    return dir_list


def write_config_value(
    logger: logging.Logger,
    user_config_path: Path,
    section: str,
    key: str,
    value: str
) -> None:
    """
    Writes a single key-value pair to the user's configuration file.
    Creates the file or section if it doesn't exist.
    """
    logger.info(f"CONFIG_WRITER: Attempting to set [{section}] {key} = {value} in {user_config_path}")
    config = configparser.ConfigParser()

    # Read the existing file to not overwrite other values
    if user_config_path.is_file():
        config.read(user_config_path)

    # Create the section if it doesn't exist
    if not config.has_section(section):
        logger.debug(f"CONFIG_WRITER: Creating new section [{section}]")
        config.add_section(section)

    # Set the new value
    config.set(section, key, str(value))

    # Write the changes back to the file
    try:
        with open(user_config_path, 'w') as configfile:
            config.write(configfile)
        logger.info("CONFIG_WRITER: Successfully saved configuration.")
    except IOError as e:
        logger.error(f"CONFIG_WRITER: Failed to write to config file {user_config_path}: {e}")
