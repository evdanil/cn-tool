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
                typed_cfg[key] = [item.strip().strip('"\'') for item in items]
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

        if config.has_option(section, ini_key):
            # Always get the raw string value.
            new_value = config.get(section, ini_key)
            loaded_cfg[key] = new_value

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