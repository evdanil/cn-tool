import configparser
import argparse
import logging
import math
import os
import re
from pathlib import Path
from typing import Dict, Any, List, Mapping, NamedTuple, Tuple

from cn_tool.core.base import ScriptContext
from cn_tool.utils import oscompat
from cn_tool.utils.file_io import check_dir_accessibility


def _default_device_user_var() -> str:
    """USERNAME on Windows (it has no USER), USER elsewhere."""
    return "USERNAME" if oscompat.is_windows() else "USER"


# --- Configuration Schema ---
# Names of the environment variables that hold the credentials: the defaults live here and nowhere else.
# [auth] in .cn renames them; it holds names, never passwords (see env_name and shown_env_name).
# The device user's default depends on the platform and is fixed when this module is imported; the test suite
# pins it to USER on every host (tests/conftest.py).
AUTH_ENV_DEFAULTS: Dict[str, str] = {
    "auth_device_user_var": _default_device_user_var(),
    "auth_device_password_var": "TACACS_PW",
    "auth_infoblox_user_var": "INFOBLOX_USER",
    "auth_infoblox_password_var": "INFOBLOX_PW",
}

BASE_CONFIG_SCHEMA = {
    "api_endpoint":          {"section": "api", "ini_key": "endpoint", "type": "str", "fallback": "API_URL"},
    "api_verify_ssl":        {"section": "api", "ini_key": "verify_ssl", "type": "bool", "fallback": True},
    "api_timeout":           {"section": "api", "ini_key": "timeout", "type": "int", "fallback": 10},
    "api_max_workers":       {"section": "api", "ini_key": "max_workers", "type": "int", "fallback": 8},
    "api_debug_payloads":    {"section": "api", "ini_key": "debug_payloads", "type": "bool", "fallback": False},
    "api_network_view":      {"section": "api", "ini_key": "network_view", "type": "str", "fallback": ""},
    # Infoblox's own account (optional): the user name only; the password never lives in this file.
    "api_user":              {"section": "api", "ini_key": "user", "type": "str", "fallback": ""},
    "ssh_config_file":       {"section": "ssh", "ini_key": "config_file", "type": "str", "fallback": "~/.ssh/config"},
    "logging_file":          {"section": "logging", "ini_key": "logfile", "type": "path", "fallback": "~/cn.log"},
    "logging_level":         {"section": "logging", "ini_key": "level", "type": "str", "fallback": "INFO"},
    "report_file":           {"section": "report", "ini_key": "filename", "type": "path", "fallback": "~/report.xlsx"},
    "report_auto_save":      {"section": "report", "ini_key": "auto_save", "type": "bool", "fallback": True},
    "report_lock_timeout":   {"section": "report", "ini_key": "lock_timeout", "type": "int", "fallback": 120},
    "report_max_config_tab_kb": {"section": "report", "ini_key": "max_config_tab_kb", "type": "int", "fallback": 512},
    "gpg_credentials":       {"section": "gpg", "ini_key": "credentials", "type": "path", "fallback": "~/cn-tool.gpg"},
    "gpg_infoblox_credentials": {"section": "gpg", "ini_key": "infoblox_credentials", "type": "path", "fallback": ""},
    # Names of the environment variables that hold the credentials; names only, never values.
    "auth_device_user_var":       {"section": "auth", "ini_key": "device_user_var", "type": "str", "fallback": AUTH_ENV_DEFAULTS["auth_device_user_var"]},
    "auth_device_password_var":   {"section": "auth", "ini_key": "device_password_var", "type": "str", "fallback": AUTH_ENV_DEFAULTS["auth_device_password_var"]},
    "auth_infoblox_user_var":     {"section": "auth", "ini_key": "infoblox_user_var", "type": "str", "fallback": AUTH_ENV_DEFAULTS["auth_infoblox_user_var"]},
    "auth_infoblox_password_var": {"section": "auth", "ini_key": "infoblox_password_var", "type": "str", "fallback": AUTH_ENV_DEFAULTS["auth_infoblox_password_var"]},
    "config_repo_enabled":   {"section": "config_repo", "ini_key": "enabled", "type": "str", "fallback": ""},
    "config_repo_directory": {"section": "config_repo", "ini_key": "directory", "type": "path", "fallback": ""},
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
    "cache_sqlite_cache_size": {"section": "cache", "ini_key": "sqlite_cache_size", "type": "str", "fallback": "16M"},
    "cache_sqlite_mmap_size":  {"section": "cache", "ini_key": "sqlite_mmap_size", "type": "str", "fallback": "32M"},
    "theme_name":            {"section": "theme", "ini_key": "theme", "type": "str", "fallback": "default"},
    # Config Analyzer (external TUI) settings
    "config_repo_history_dir":     {"section": "config_repo", "ini_key": "history_dir", "type": "str", "fallback": "history"},
    "config_analyzer_repo_directories": {"section": "config_analyzer", "ini_key": "repo_directories", "type": "list[str]", "fallback": ""},
    "config_analyzer_repo_names": {"section": "config_analyzer", "ini_key": "repo_names", "type": "list[str]", "fallback": ""},
    "config_analyzer_layout":      {"section": "config_analyzer", "ini_key": "layout", "type": "str", "fallback": "right"},
    "config_analyzer_scroll_to_end": {"section": "config_analyzer", "ini_key": "scroll_to_end", "type": "bool", "fallback": False},
    "config_analyzer_debug":       {"section": "config_analyzer", "ini_key": "debug", "type": "bool", "fallback": False},
    # SSH / Device query settings
    "device_ssh_enabled":        {"section": "ssh", "ini_key": "device_ssh_enabled", "type": "bool", "fallback": False},
    "device_query_workers":      {"section": "ssh", "ini_key": "device_query_workers", "type": "int", "fallback": 10},
    # Only connect to devices whose reverse-DNS name matches this regex (empty = no filtering).
    "device_name_filter":        {"section": "ssh", "ini_key": "device_name_filter", "type": "str", "fallback": ""},
    # Site-code conventions (see utils/validation.py for the defaults and placeholders).
    "site_code_pattern":         {"section": "site", "ini_key": "code_pattern", "type": "str", "fallback": ""},
    "site_comment_pattern":      {"section": "site", "ini_key": "comment_pattern", "type": "str", "fallback": ""},
    "site_hostname_pattern":     {"section": "site", "ini_key": "hostname_pattern", "type": "str", "fallback": ""},
    # Infoblox extensible attribute that holds the site code (empty = search subnet comments only).
    "site_ea_name":              {"section": "site", "ini_key": "ea_name", "type": "str", "fallback": ""},
}

# Backward/forward compatibility across section renames.
# Primary section is read first; aliases are checked only if primary key is absent.
SECTION_ALIASES: Dict[str, List[str]] = {
    "report": ["output"],
    "output": ["report"],
}


def parse_size(value) -> int:
    """Parse a size value with optional K/M/G suffix to bytes.
    Examples: '32M' -> 33554432, '512K' -> 524288, '1G' -> 1073741824
    Returns 0 for empty or non-positive values.
    """
    if isinstance(value, (int, float)):
        return max(0, int(value))
    s = str(value).strip().upper()
    if not s:
        return 0
    multipliers = {'K': 1024, 'M': 1024**2, 'G': 1024**3}
    if s[-1] in multipliers:
        result = int(float(s[:-1]) * multipliers[s[-1]])
    else:
        result = int(s)
    return max(0, result)


def parse_cache_pages(value, page_size: int = 4096) -> int:
    """Parse a cache size value to SQLite pages.
    Accepts plain page count (e.g. '4096') or human-readable bytes (e.g. '16M').
    When K/M/G suffix is detected, converts bytes to pages and rounds to nearest power of 2.
    Returns at least 1 page.
    """
    s = str(value).strip().upper()
    if not s:
        return 1
    has_suffix = s[-1] in ('K', 'M', 'G')
    if has_suffix:
        size_bytes = parse_size(value)
        pages = size_bytes / page_size
        if pages < 1:
            return 1
        return 1 << round(math.log2(pages))
    return max(1, int(s))


_TRUTHY = frozenset({"true", "1", "t", "y", "yes", "on"})
_FALSY = frozenset({"false", "0", "f", "n", "no", "off"})


def coerce_bool(value) -> bool:
    """Parse a value as boolean. Accepts strings like 'true', '1', 'yes', 'on', etc."""
    if isinstance(value, str):
        return value.strip().lower() in _TRUTHY
    return bool(value)


def parse_optional_bool(value) -> bool | None:
    """Parse a tri-state bool, returning None for blank or unrecognized values."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value in (0, 1):
            return bool(value)
        return None
    if not isinstance(value, str):
        return None

    normalized = value.strip().lower()
    if not normalized:
        return None
    if normalized in _TRUTHY:
        return True
    if normalized in _FALSY:
        return False
    return None


def coerce_config_value(raw: str, spec: Dict[str, Any], logger: logging.Logger = None):
    """Convert a raw string to the typed value described by a config schema spec."""
    if not isinstance(raw, str):
        return raw

    clean = raw.strip().strip('"\'')
    t = spec.get("type", "str")

    if t == "bool":
        return coerce_bool(clean)
    if t == "path":
        if not clean and not spec.get("fallback"):
            return None  # a path with no default is optional: left blank it is not set (not the current directory)
        return Path(clean).expanduser()
    if t == "list[str]":
        return [
            item.strip().strip('"\'')
            for item in raw.split(',')
            if item.strip().strip('"\'')
        ]
    if t == "int":
        try:
            return int(clean)
        except (ValueError, TypeError):
            if logger:
                logger.warning("CONFIG: Could not convert '%s' to int for key. Using fallback.", clean)
            return spec.get("fallback")
    return clean


def _apply_types(cfg: Dict[str, Any], schema: Dict[str, Any], logger: logging.Logger) -> Dict[str, Any]:
    """
    Helper function to convert raw string values to their proper types and sanitize them.
    """
    typed_cfg = cfg.copy()
    for key, spec in schema.items():
        if key in typed_cfg:
            typed_cfg[key] = coerce_config_value(typed_cfg[key], spec, logger)
    return typed_cfg


_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_AUTH_USER_KEYS = ("auth_device_user_var", "auth_infoblox_user_var")
_AUTH_PASSWORD_KEYS = ("auth_device_password_var", "auth_infoblox_password_var")


def _auth_ini_key(key: str) -> str:
    return BASE_CONFIG_SCHEMA[key]["ini_key"]


def _configured_env_name(cfg: Mapping[str, Any], key: str) -> str:
    """What the [auth] key holds, stripped; "" when it is missing, blank or not text (a test double)."""
    value = cfg.get(key)
    return value.strip() if isinstance(value, str) else ""


def env_name(cfg: Mapping[str, Any], key: str) -> str:
    """The variable name `key` configures: its stripped value, or the default when it is missing or blank.

    Call only after env_name_problem(cfg) is "" (an invalid value is returned as it is).
    """
    return _configured_env_name(cfg, key) or AUTH_ENV_DEFAULTS[key]


def env_name_problem(cfg: Mapping[str, Any]) -> str:
    """"" when the four [auth] names are usable; else the message for the first bad key, in table order.

    A key is bad when it is not an environment variable name, or when a user key names a password
    variable (the password would be used, and printed, as a user name). The text names keys only,
    never a configured value: a password typed into a *_var key by mistake is never echoed.
    The message has no "cn: " prefix; a caller that ends the run adds it.
    """
    for key, default in AUTH_ENV_DEFAULTS.items():
        name = env_name(cfg, key)
        if not _ENV_NAME.fullmatch(name):
            return (
                f"[auth] {_auth_ini_key(key)} must name an environment variable "
                "(ASCII letters, digits and _, not starting with a digit), not hold a password; "
                f"leave it empty for {default}"
            )
        if key in _AUTH_USER_KEYS:
            for password_key in _AUTH_PASSWORD_KEYS:
                if name == env_name(cfg, password_key):
                    return (
                        f"{_auth_key_label(cfg, key)} names the same variable as {_auth_key_label(cfg, password_key)}; "
                        "give the user name a variable of its own"
                    )
    return ""


def _auth_key_label(cfg: Mapping[str, Any], key: str) -> str:
    """"[auth] <ini_key>", and "(blank: <default>)" after it when the key is blank.

    The user may never have written a blank key, so a text that blames it says which variable it stands for.
    """
    blank = f" (blank: {AUTH_ENV_DEFAULTS[key]})" if not _configured_env_name(cfg, key) else ""
    return f"[auth] {_auth_ini_key(key)}{blank}"


def _env_name_is_shown(name: str, key: str) -> bool:
    """The display rule: a name is printed when it is the default, or is a variable that exists."""
    return name == AUTH_ENV_DEFAULTS[key] or (bool(_ENV_NAME.fullmatch(name)) and name in os.environ)


def shown_env_name(cfg: Mapping[str, Any], key: str) -> str:
    """How a text names the variable `key` configures.

    The name when it is the default or exists in the environment (exported, even empty); otherwise
    "the variable named in [auth] <key>". The reason: a password typed into a *_var key can pass
    the name check ("Winter2026" does), and a hint names the variable exactly when it is missing.
    A variable that exists is evidently a name.
    """
    name = env_name(cfg, key)
    if _env_name_is_shown(name, key):
        return name
    return f"the variable named in [auth] {_auth_ini_key(key)}"


def unset_env_note(cfg: Mapping[str, Any], key: str) -> str:
    """"the variable named in [auth] <key> is not set" when `key` holds a non-default name whose variable is
    unset or blank; "" otherwise (always "" with the default names, so a default run says nothing new).

    It is how ``cn doctor`` explains the common mistake, a misspelt or unexported custom name, and a password
    typed into the key, without printing the value.
    """
    name = env_name(cfg, key)
    if name == AUTH_ENV_DEFAULTS[key] or (os.environ.get(name) or "").strip():
        return ""
    return f"the variable named in [auth] {_auth_ini_key(key)} is not set"


def _loggable_config(cfg: Mapping[str, Any]) -> Dict[str, Any]:
    """The configuration for the DEBUG dump: an [auth] value that shown_env_name would not print is hidden."""
    masked = dict(cfg)
    for key in AUTH_ENV_DEFAULTS:
        raw = _configured_env_name(cfg, key)
        if raw and not _env_name_is_shown(raw, key):
            masked[key] = "<not shown>"
    return masked


def new_parser() -> configparser.ConfigParser:
    """The one non-interpolating parser every ini reader uses, so a literal '%' in a value is safe."""
    return configparser.ConfigParser(interpolation=None)


# --- The user's configuration file, and the template that starts it ---
SAMPLE_CONFIG = "sample.cn"  # the commented template, packaged next to the code (it is never named .cn there)


def user_config_path() -> Path:
    """``~/.cn``: the file the Setup menu writes and ``cn init`` creates (``%USERPROFILE%\\.cn`` on Windows)."""
    return Path.home() / ".cn"


def no_config_file_found(cfg: Mapping[str, Any]) -> bool:
    """True when ``read_config`` found no configuration file at all.

    An empty ``config_files`` list says so; a missing key means that nobody asked (a context built without
    reading any file), and that is "unknown", never "none".
    """
    return cfg.get("config_files") == []


def sample_config_text() -> str:
    """The packaged template (``cn_tool/sample.cn``), read as UTF-8."""
    from importlib import resources  # inside the function: start-up pays for it only when cn init runs

    return (resources.files("cn_tool") / SAMPLE_CONFIG).read_text(encoding="utf-8")


def write_sample_config(path: Path) -> None:
    """
    Create ``path`` holding the template. Never overwrites: raises FileExistsError when ``path`` exists
    (a directory, or a symlink, even a dangling one, counts), and OSError when it cannot be written.

    The file is created with ``O_EXCL``, so "never overwrite" is one atomic step, and with mode 0o600 because
    ``[email] password`` may later go into it (Windows ignores the mode). ``O_BINARY`` (only Windows defines it)
    keeps the C runtime from translating line ends: the text wrapper does that once, to CRLF on Windows, and
    without the flag the file would hold ``\\r\\r\\n``. A write that fails after the file was created removes it,
    so that the next ``cn init`` is not refused by an empty file.
    """
    text = sample_config_text()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def read_config(config_files: List[Path], schema: Dict[str, Any], logger: logging.Logger) -> Dict[str, Any]:
    """
    Reads configuration from a prioritized list of files using a dynamic schema.

    The files are read as UTF-8, with or without a byte-order mark (Notepad adds one when asked). A file that
    is not UTF-8 is a parse error like any other: it is logged and the defaults are used.

    The result also holds ``config_files``: the files of ``config_files`` that exist, in the order they were
    read, so an empty list means that no configuration file was found at all (a ``cn init`` hint hangs on it).
    """
    loaded_cfg = {key: spec['fallback'] for key, spec in schema.items()}
    logger.debug("CONFIG: Initialized with default values from schema.")

    existing_files = [f for f in config_files if f.is_file()]
    loaded_cfg["config_files"] = existing_files
    if not existing_files:
        logger.warning("CONFIG: No configuration files found. Proceeding with defaults.")
        return _apply_types(loaded_cfg, schema, logger)

    logger.info(f"CONFIG: Reading configuration from files: {existing_files}")
    config = new_parser()
    try:
        config.read(existing_files, encoding="utf-8-sig")
    except (configparser.Error, UnicodeDecodeError) as e:
        reason = f"not UTF-8 text ({e}); save the file as UTF-8" if isinstance(e, UnicodeDecodeError) else e
        logger.error(f"CONFIG: Error parsing configuration files: {reason}")
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
    logger.debug(f"CONFIG: Final configuration object after processing: {_loggable_config(final_cfg)}")

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


def _coerce_repo_inputs(value: Any) -> List[Path]:
    """Directories named by a configuration value (a path, a comma-separated string or a collection of either)."""
    if not value:
        return []
    items = list(value) if isinstance(value, (list, tuple, set)) else [value]

    paths: List[Path] = []
    for item in items:
        if item is None:
            continue
        if isinstance(item, Path):
            candidates = [item]
        else:
            text = str(item)
            if not text:
                continue
            fragments = [frag.strip() for frag in text.split(',')] if ',' in text else [text.strip()]
            candidates = [Path(fragment).expanduser() for fragment in fragments if fragment]
        for candidate in candidates:
            try:
                resolved = candidate.expanduser().resolve(strict=False)
            except Exception:
                resolved = candidate.expanduser()
            paths.append(resolved)
    return paths


def _normalize_repo_names(value: Any) -> List[str]:
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value]
    if isinstance(value, str):
        return [segment.strip() for segment in value.split(',')]
    return []


# The keys that name the configuration repository, in the order they are tried, with how the user writes each.
_REPO_DIRECTORY_KEYS = (
    ("config_analyzer_repo_directories", "[config_analyzer] repo_directories"),
    ("config_analyzer_repo_directory", "[config_analyzer] repo_directory"),
    ("config_repo_directory", "[config_repo] directory"),
)


class RepoRoots(NamedTuple):
    """Where ``cn diff`` and the repository browser read: the accessible and the inaccessible directories, and the key that named them."""

    accessible: List[Tuple[Path, str]]
    inaccessible: List[Path]
    source: str  # "" when no key names a directory


def resolve_config_repo_roots(cfg: Dict[str, Any], logger: logging.Logger) -> RepoRoots:
    """
    The configuration repositories ``cn diff``, the repository browser and ``cn doctor`` use.

    The directories come from the first of ``[config_analyzer] repo_directories`` (a comma-separated
    list), the legacy ``[config_analyzer] repo_directory`` and ``[config_repo] directory`` that is
    set (not empty), and ``source`` names that key. Each directory is paired with the label
    configured at its position in ``config_analyzer_repo_names`` ("" when there is none) *before*
    any is dropped, so a rejected directory never shifts the labels of the others. A directory
    named twice is listed once, under its first label.
    """
    candidates: List[Path] = []
    source = ""
    for key, written in _REPO_DIRECTORY_KEYS:
        candidates = _coerce_repo_inputs(cfg.get(key))
        if candidates:
            source = written
            break
    names = _normalize_repo_names(cfg.get("config_analyzer_repo_names"))

    seen: set[str] = set()
    accessible: List[Tuple[Path, str]] = []
    inaccessible: List[Path] = []
    for index, candidate in enumerate(candidates):
        key = candidate.as_posix()
        if key in seen:
            continue
        seen.add(key)
        if check_dir_accessibility(logger, candidate):
            accessible.append((candidate, names[index] if index < len(names) else ""))
        else:
            inaccessible.append(candidate)
    return RepoRoots(accessible, inaccessible, source)


def normalize_runtime_flags(cfg: Dict[str, Any], logger: logging.Logger) -> Dict[str, Any]:
    """Normalize derived runtime flags in *cfg* in-place and return cfg.

    Applies the same post-read normalization that ``main.py`` performs after
    ``read_config`` so that both the interactive cn-tool and the standalone CLIs share
    identical semantics:

    1. ``infoblox_enabled`` (bool) — ``True`` iff ``api_endpoint`` is set to a
       real URL (not the sentinel ``"API_URL"`` and not empty).

    2. ``config_repo_enabled`` (bool) — resolved via ``parse_optional_bool``:

       - Explicit ``true`` / ``1`` / ``yes`` / ``on``  →  ``True`` (then
         directory accessibility is also verified; inaccessible → ``False``).
       - Explicit ``false`` / ``0`` / ``no`` / ``off`` →  ``False``.
       - Blank or absent (schema fallback ``""`` / ``None``)  →  auto-detect:
         ``True`` iff ``config_repo_directory`` is set *and* accessible.
       - Unrecognized non-empty value  →  warning then auto-detect as above.

       This is the gate of config search, which reads ``[config_repo] directory`` only.

    3. ``config_analyzer_enabled`` (bool) — the gate of ``cn diff`` and the repository browser,
       which read the directories of ``resolve_config_repo_roots``. ``True`` iff
       ``config_repo_enabled`` is ``True`` or a directory those keys name is accessible; an
       explicit ``[config_repo] enabled = false`` switches it off too.

    4. ``config_repo_enabled_explicit`` (``True``, ``False`` or ``None``) — what ``[config_repo]
       enabled`` says, before the two flags above are derived from it. Both flags are also
       ``False`` when every configured directory is inaccessible, so only this tells "switched
       off" from "misconfigured" (``cn doctor`` shows the first as ``Disabled``, the second as an error).

    Mutates *cfg* directly and also returns it for convenience.
    """
    # 1. Infoblox readiness
    if cfg.get("api_endpoint") == "API_URL" or not cfg.get("api_endpoint"):
        logger.warning(
            "Infoblox API URL is not set. Infoblox-related modules will be disabled."
        )
        cfg["infoblox_enabled"] = False
    else:
        cfg["infoblox_enabled"] = True

    # 2. Config-repo readiness
    repo_enabled_value = cfg.get("config_repo_enabled", "")
    repo_enabled_raw = str(repo_enabled_value).strip()
    repo_enabled = parse_optional_bool(repo_enabled_value)
    cfg["config_repo_enabled_explicit"] = repo_enabled

    if repo_enabled is False:
        logger.info("Configuration repository explicitly disabled in config.")
        cfg["config_repo_enabled"] = False
    elif repo_enabled is True:
        if not check_dir_accessibility(logger, cfg.get("config_repo_directory") or ""):
            logger.warning(
                "Configuration repository directory is not accessible."
                " Config search modules will be disabled."
            )
            cfg["config_repo_enabled"] = False
        else:
            cfg["config_repo_enabled"] = True
    else:
        if repo_enabled_raw:
            logger.warning(
                "Invalid value for config_repo.enabled: %r. Falling back to auto-detect.",
                repo_enabled_raw,
            )
        # Not set — auto-detect: enabled iff directory is configured and accessible
        repo_dir = cfg.get("config_repo_directory")
        if repo_dir and check_dir_accessibility(logger, repo_dir):
            cfg["config_repo_enabled"] = True
        else:
            logger.info(
                "Configuration repository not configured or directory not accessible,"
                " skipping."
            )
            cfg["config_repo_enabled"] = False

    # 3. Analyzer readiness: the same directories, in the same order, as the command reads.
    analyzer_roots = resolve_config_repo_roots(cfg, logger)
    cfg["config_analyzer_enabled"] = bool(
        cfg["config_repo_enabled"] or (repo_enabled is not False and analyzer_roots.accessible)
    )

    return cfg


def write_config_value(
    logger: logging.Logger,
    user_config_path: Path,
    section: str,
    key: str,
    value: str,
    log_value: bool = True,
) -> None:
    """
    Writes a single key-value pair to the user's configuration file.
    Creates the file or section if it doesn't exist.

    Parameters
    ----------
    log_value:
        When ``True`` (default) the value is included in the log message.
        Pass ``False`` for secret/credential values so that they are never
        written to the log file in plain text.  The console display is
        controlled separately by the caller (config_set already redacts).
    """
    log_display = value if log_value else "***"
    logger.info(
        f"CONFIG_WRITER: Attempting to set [{section}] {key} = {log_display} in {user_config_path}"
    )
    config = new_parser()

    # Read the existing file to not overwrite other values (UTF-8, with or without a BOM, as read_config does)
    if user_config_path.is_file():
        config.read(user_config_path, encoding="utf-8-sig")

    # Create the section if it doesn't exist
    if not config.has_section(section):
        logger.debug(f"CONFIG_WRITER: Creating new section [{section}]")
        config.add_section(section)

    # Set the new value
    config.set(section, key, str(value))

    # Write the changes back to the file
    try:
        with open(user_config_path, 'w', encoding='utf-8') as configfile:
            config.write(configfile)
        logger.info("CONFIG_WRITER: Successfully saved configuration.")
    except IOError as e:
        logger.error(f"CONFIG_WRITER: Failed to write to config file {user_config_path}: {e}")
