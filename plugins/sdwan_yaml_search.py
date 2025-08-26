import re
import threading
import ipaddress
from pathlib import Path
from typing import Any, Dict, Iterator

import yaml

from core.base import BasePlugin, BaseModule, ScriptContext


class SDWANYamlSearchPlugin(BasePlugin):
    """Plugin that augments ConfigSearch results with SD-WAN YAML data."""

    def __init__(self) -> None:
        """Initializes the plugin and its threading components."""
        self._yaml_data: Dict[str, Any] = {}
        self._loading_thread: threading.Thread | None = None
        self._is_ready = threading.Event()  # An event to signal when loading is complete
        self._lock = threading.Lock()  # A lock to ensure thread-safe access to data
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    @property
    def name(self) -> str:
        return "SD-WAN YAML Search"

    @property
    def target_module_name(self) -> str:
        return "config_search"

    @property
    def manages_global_connection(self) -> bool:
        return True

    @property
    def config_schema(self) -> Dict[str, Dict[str, Any]]:
        return {
            "sdwan_yaml_enabled": {
                "section": "sdwan_yaml_search",
                "ini_key": "enabled",
                "type": "bool",
                "fallback": False,
            },
            "sdwan_yaml_repo_path": {
                "section": "sdwan_yaml_search",
                "ini_key": "repository_path",
                "type": "str",
                "fallback": "",
            },
        }

    def _load_data_in_background(self, ctx: ScriptContext) -> None:
        """The target function for the background thread to load and parse YAML files."""
        repo_path = ctx.cfg.get("sdwan_yaml_repo_path", "")
        repo = Path(repo_path)
        ctx.logger.info(f"SD-WAN YAML Search: Starting background load from {repo_path}...")

        if not repo.is_dir():
            ctx.logger.warning("SD-WAN YAML Search: repository path is invalid. Aborting load.")
            return

        temp_yaml_data = {}
        file_count = 0
        for file in repo.rglob("*"):
            if file.suffix.lower() in {".yml", ".yaml"} and file.is_file():
                try:
                    with file.open(encoding="utf-8") as f:
                        temp_yaml_data[str(file)] = yaml.safe_load(f)
                        file_count += 1
                except Exception as exc:
                    ctx.logger.error(f"SD-WAN YAML Search: failed to load or parse {file}: {exc}")

        ctx.logger.info(f"SD-WAN YAML Search: Successfully loaded and parsed {file_count} YAML files.")

        # Thread-safe update of the main data dictionary
        with self._lock:
            self._yaml_data = temp_yaml_data

        # Signal that the data is ready for searching
        self._is_ready.set()
        ctx.logger.info("SD-WAN YAML Search: Data is now ready for searching.")

    def connect(self, ctx: ScriptContext) -> None:
        """Starts the background thread to load YAML files."""
        if not ctx.cfg.get("sdwan_yaml_enabled"):
            ctx.logger.debug("SD-WAN YAML Search: Plugin is disabled.")
            return

        # Prevent starting multiple threads on reconnect
        if self._loading_thread and self._loading_thread.is_alive():
            ctx.logger.info("SD-WAN YAML Search: A loading process is already running.")
            return

        self._is_ready.clear()  # Reset the event in case of a reconnect
        self._yaml_data.clear()

        # Create and start the daemon thread
        self._loading_thread = threading.Thread(target=self._load_data_in_background, args=(ctx,), daemon=True)
        self._loading_thread.start()

    def _search_yaml_repo(self, ctx: ScriptContext, data: Dict[str, Any]) -> Dict[str, Any]:
        """Search through preloaded YAML data and extend results."""
        # If loading is not yet complete, log and return immediately.
        if not self._is_ready.is_set():
            ctx.logger.debug("SD-WAN YAML Search: Data is not ready for searching yet. Skipping.")
            return data

        search_terms = data.get("search_terms", [])
        search_networks = data.get("networks", [])

        if not search_terms and not search_networks:
            return data

        matched_networks_set = data.get("matched_nets", set())
        results = data.get("results", [])

        ctx.logger.debug(f"SD-WAN YAML Search: Starting search for terms: {search_terms if search_terms else None} and IPs: {search_networks if search_networks else None}")

        with self._lock:
            # We lock here to prevent any theoretical race condition if a reload is implemented
            yaml_data_snapshot = self._yaml_data

        for term in search_terms:
            try:
                pattern = re.compile(term, re.IGNORECASE)
            except re.error:
                pattern = re.compile(re.escape(term), re.IGNORECASE)

            ctx.logger.debug(f"SD-WAN YAML Search: Processing term '{term}' with pattern '{pattern.pattern}'")

            term_results_count = 0
            for filename, yaml_content in yaml_data_snapshot.items():
                if not yaml_content:
                    continue

                device = Path(filename).stem.upper()
                for path, value in self._find_in_obj(yaml_content, pattern):
                    ctx.logger.debug(f"Found match for '{term}' in '{filename}' at path '{path}' with value '{value}'")
                    line_content = f"{path}: {str(value)}"
                    results.append([term, device, 0, line_content, filename])
                    # results.append([term, device, path, str(value), filename])

                    term_results_count += 1
            ctx.logger.debug(f"SD-WAN YAML Search: Found {term_results_count} results for term '{term}'.")

        for network_str in search_networks:
            net_results_count = 0
            try:
                search_net = ipaddress.ip_network(network_str, strict=False)
                ctx.logger.debug(f"SD-WAN YAML Search: Processing network '{network_str}'")
            except ValueError:
                ctx.logger.warning(f"SD-WAN YAML Search: Invalid network format '{network_str}', skipping.")
                continue

            for filename, yaml_content in yaml_data_snapshot.items():
                if not yaml_content:
                    continue

                device = Path(filename).stem.upper()
                for path, found_ip in self._find_ips_in_obj(yaml_content, search_net):
                    line_content = f"{path}: {found_ip}"
                    results.append([network_str, device, 0, line_content, filename])
                    matched_networks_set.add(search_net)

                    net_results_count += 1

            ctx.logger.debug(f"SD-WAN YAML Search: Found {net_results_count} results for term '{str(network_str)}'.")

        data["results"] = results
        data["matched_nets"] = matched_networks_set
        return data

    def _find_ips_in_obj(self, obj: Any, network_obj: ipaddress.IPv4Network, path: str = "") -> Iterator[tuple[str, str]]:
        """
        Recursively search for IP addresses within a given network object.
        Yields the path and the matched IP address string.
        """
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_path = f"{path}.{k}" if path else k
                yield from self._find_ips_in_obj(v, network_obj, new_path)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                new_path = f"{path}[{i}]"
                yield from self._find_ips_in_obj(v, network_obj, new_path)
        elif isinstance(obj, str):
            # Find all potential IP-like strings in the value
            for ip_match in self.ip_pattern.finditer(obj):
                ip_str = ip_match.group(0)
                try:
                    # Validate the string is a real IP and check for membership
                    ip_addr = ipaddress.ip_address(ip_str)
                    if ip_addr in network_obj:
                        yield path, ip_str
                except ValueError:
                    # Not a valid IP address, ignore
                    continue

    def _find_in_obj(
        self, obj: Any, pattern: re.Pattern, path: str = ""
    ) -> Iterator[tuple[str, Any]]:
        """
        Recursively search for a pattern in the values of a nested object.
        Yields the path and the matched value.
        """
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_path = f"{path}.{k}" if path else k
                yield from self._find_in_obj(v, pattern, new_path)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                new_path = f"{path}[{i}]"
                yield from self._find_in_obj(v, pattern, new_path)
        # Check against the STRING representation of the value.
        # This handles integers, booleans, floats, etc., solving the potential search miss.
        elif pattern.search(str(obj)):
            yield path, obj

    def register(self, module: BaseModule) -> None:
        module.register_hook("process_data", self._search_yaml_repo)
