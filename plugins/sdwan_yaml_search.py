import re
import threading
import ipaddress
from pathlib import Path
from typing import Any, Dict, Iterator, Tuple

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

    @property
    def user_configurable_settings(self) -> list[dict[str, Any]]:
        """
        Exposes settings that can be configured by the user via the SetupModule.
        """
        return [
            {
                "key": "sdwan_yaml_enabled",
                "prompt": "Enable/Disable SD-WAN YAML Search"
            }
        ]

    def _load_data_in_background(self, ctx: ScriptContext) -> None:
        """The target function for the background thread to load and parse YAML files."""
        repo_path = ctx.cfg.get("sdwan_yaml_repo_path", "")
        repo = Path(repo_path)
        ctx.logger.info(f"SD-WAN YAML Search: Starting background load from {repo_path}...")

        if not repo_path or not repo.is_dir():
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
        """
        Search through preloaded YAML data efficiently in a single pass.
        """
        if not self._is_ready.is_set():
            return data

        search_terms = data.get("search_terms", [])
        search_networks = data.get("networks", [])
        if not search_terms and not search_networks:
            return data

        results = data.get("results", [])

        matched_networks_set = data.get("matched_nets", set())

        patterns = {}
        for term in search_terms:
            try:
                patterns[term] = re.compile(term, re.IGNORECASE)
            except re.error:
                ctx.logger.debug(f"Invalid regex '{term}', treating as literal string.")
                patterns[term] = re.compile(re.escape(term), re.IGNORECASE)

        network_objects = {}
        for net_str in search_networks:
            try:
                network_objects[net_str] = ipaddress.ip_network(net_str, strict=False)
            except ValueError:
                ctx.logger.warning(f"SD-WAN YAML Search: Invalid network format '{net_str}', skipping.")

        ctx.logger.debug(f"SD-WAN YAML Search: Starting single-pass search for {len(patterns)} terms and {len(network_objects)} networks.")

        with self._lock:
            yaml_data_snapshot = self._yaml_data

        for filename, yaml_content in yaml_data_snapshot.items():
            if not yaml_content:
                continue

            device = Path(filename).stem.upper()

            for criterion, path, value in self._traverse_and_match(yaml_content, patterns, network_objects):
                line_content = f"{path}: {str(value)}"
                results.append([criterion, device, 0, line_content, filename])

                if criterion in network_objects:
                    matched_networks_set.add(criterion)

        data["results"] = results
        data["matched_nets"] = matched_networks_set
        return data

    def _traverse_and_match(
        self,
        obj: Any,
        patterns: Dict[str, re.Pattern],
        network_objects: Dict[str, ipaddress.IPv4Network],
        path: str = ""
    ) -> Iterator[Tuple[str, str, Any]]:
        """
        A unified recursive function that traverses a data structure ONCE,
        checking each value against all keywords and all network criteria.

        Yields (matching_criterion, path, original_value).
        """
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_path = f"{path}.{k}" if path else k
                yield from self._traverse_and_match(v, patterns, network_objects, new_path)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                new_path = f"{path}[{i}]"
                yield from self._traverse_and_match(v, patterns, network_objects, new_path)
        else:
            str_value = str(obj)
            # 1. Check against all keyword patterns
            for term, pattern in patterns.items():
                if pattern.search(str_value):
                    yield term, path, obj

            # 2. Check against all network objects (if the value is a string)
            if isinstance(obj, str):
                for ip_str in self.ip_pattern.findall(obj):
                    try:
                        ip_addr = ipaddress.ip_address(ip_str)
                        for net_str, network in network_objects.items():
                            if ip_addr in network:
                                yield net_str, path, obj
                    except ValueError:
                        continue

    def register(self, module: BaseModule) -> None:
        module.register_hook("process_data", self._search_yaml_repo)
