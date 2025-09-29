import re
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterator, Tuple

import yaml

from core.base import BasePlugin, BaseModule, ScriptContext


class SDWANYamlSearchPlugin(BasePlugin):
    """Plugin that augments ConfigSearch results with SD-WAN YAML data from multiple repositories."""

    # Maximum file size to load (10MB)
    MAX_YAML_SIZE = 10 * 1024 * 1024

    def __init__(self) -> None:
        """Initializes the plugin and its threading components."""
        self._yaml_data: Dict[str, Any] = {}
        self._loading_thread: threading.Thread | None = None
        self._is_ready = threading.Event()  # An event to signal when loading is complete
        self._lock = threading.Lock()  # A lock to ensure thread-safe access to data
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self._loaded_files: Dict[str, str] = {}  # Track loaded files: {filename: filepath} for O(1) duplicate detection
        self._stop_loading = threading.Event()  # Event to signal thread to stop

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
            "sdwan_yaml_repo_paths": {
                "section": "sdwan_yaml_search",
                "ini_key": "repository_paths",
                "type": "str",
                "fallback": "",
            },
            # Backward compatibility
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
            },
            {
                "key": "sdwan_yaml_repo_paths",
                "prompt": "SD-WAN YAML repository paths (comma-separated, e.g., /path1,/path2,/path3)"
            }
        ]

    def _load_single_repository(self, repo_path: str, ctx: ScriptContext) -> Tuple[Dict[str, Any], Dict[str, Any], list]:
        """Load YAML files from a single repository. Returns (yaml_data, stats, duplicates)."""
        repo = Path(repo_path)
        repo_yaml_data = {}
        repo_file_count = 0
        repo_errors = 0
        local_duplicates = []

        if not repo.is_dir():
            ctx.logger.warning(f"SD-WAN YAML Search: Repository path '{repo_path}' is invalid or not a directory. Skipping.")
            return {}, {"status": "invalid", "files": 0, "errors": 0}, []

        ctx.logger.debug(f"SD-WAN YAML Search: Processing repository: {repo_path}")

        for file in repo.rglob("*"):
            if file.suffix.lower() in {".yml", ".yaml"} and file.is_file():
                file_str = str(file)
                file_name = file.name

                # Check for stop signal
                if self._stop_loading.is_set():
                    ctx.logger.info(f"SD-WAN YAML Search: Loading interrupted for repository {repo_path}")
                    break

                # Check file size before loading
                try:
                    file_size = file.stat().st_size
                    if file_size > self.MAX_YAML_SIZE:
                        ctx.logger.warning(f"SD-WAN YAML Search: File {file} exceeds size limit ({file_size} > {self.MAX_YAML_SIZE}), skipping")
                        repo_errors += 1
                        continue

                    # Check for duplicates (will be verified later in main thread)
                    with self._lock:
                        if file_name in self._loaded_files:
                            local_duplicates.append(file_name)
                            ctx.logger.debug(f"SD-WAN YAML Search: Duplicate file '{file_name}' found, skipping")
                            continue
                        # Reserve this filename to prevent other threads from loading it
                        self._loaded_files[file_name] = file_str

                    with file.open(encoding="utf-8") as f:
                        yaml_content = yaml.safe_load(f)
                        repo_yaml_data[file_str] = yaml_content
                        repo_file_count += 1

                except Exception as exc:
                    ctx.logger.error(f"SD-WAN YAML Search: Failed to load or parse {file}: {exc}")
                    repo_errors += 1
                    # Remove from loaded files if we failed to load it
                    with self._lock:
                        if file_name in self._loaded_files and self._loaded_files[file_name] == file_str:
                            del self._loaded_files[file_name]

        stats = {
            "status": "success",
            "files": repo_file_count,
            "errors": repo_errors
        }

        ctx.logger.info(f"SD-WAN YAML Search: Repository '{repo_path}' - loaded {repo_file_count} files, {repo_errors} errors")
        return repo_yaml_data, stats, local_duplicates

    def _load_data_in_background(self, ctx: ScriptContext) -> None:
        """The target function for the background thread to load and parse YAML files from multiple repositories in parallel."""
        # Get repository paths - check new config key first, fall back to old one for backward compatibility
        repo_paths_str = ctx.cfg.get("sdwan_yaml_repo_paths", "")
        if not repo_paths_str:
            # Fall back to old single path config for backward compatibility
            repo_paths_str = ctx.cfg.get("sdwan_yaml_repo_path", "")

        if not repo_paths_str:
            ctx.logger.warning("SD-WAN YAML Search: No repository paths configured. Aborting load.")
            return

        # Parse multiple paths separated by comma
        repo_paths = [path.strip() for path in repo_paths_str.split(",") if path.strip()]

        if not repo_paths:
            ctx.logger.warning("SD-WAN YAML Search: No valid repository paths found. Aborting load.")
            return

        ctx.logger.info(f"SD-WAN YAML Search: Starting parallel load from {len(repo_paths)} repository path(s)...")

        temp_yaml_data = {}
        repo_statistics = {}
        all_duplicates = []

        # Determine number of workers (max 4, but no more than number of repos)
        max_workers = min(4, len(repo_paths))

        # Process repositories in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all repository loading tasks
            future_to_repo = {
                executor.submit(self._load_single_repository, repo_path, ctx): repo_path
                for repo_path in repo_paths
            }

            # Collect results as they complete
            for future in as_completed(future_to_repo):
                repo_path = future_to_repo[future]
                try:
                    repo_data, stats, duplicates = future.result(timeout=60)  # 60 second timeout per repo
                    temp_yaml_data.update(repo_data)
                    repo_statistics[repo_path] = stats
                    all_duplicates.extend(duplicates)
                except Exception as exc:
                    ctx.logger.error(f"SD-WAN YAML Search: Exception loading repository {repo_path}: {exc}")
                    repo_statistics[repo_path] = {"status": "error", "files": 0, "errors": 1}

        # Calculate totals
        total_file_count = sum(stats["files"] for stats in repo_statistics.values())

        # Log summary
        ctx.logger.info(f"SD-WAN YAML Search: Successfully loaded {total_file_count} YAML files from {len(repo_paths)} repositories")

        if all_duplicates:
            ctx.logger.info(f"SD-WAN YAML Search: Skipped {len(all_duplicates)} duplicate files across repositories")

        # Log repository statistics
        successful_repos = sum(1 for stats in repo_statistics.values() if stats["status"] == "success")
        failed_repos = sum(1 for stats in repo_statistics.values() if stats["status"] in ["invalid", "error"])

        if failed_repos > 0:
            ctx.logger.warning(f"SD-WAN YAML Search: {failed_repos} repository path(s) were invalid or inaccessible")

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
        self._stop_loading.clear()  # Clear stop signal for new load
        with self._lock:
            self._yaml_data.clear()
            self._loaded_files.clear()  # Clear loaded files dictionary for fresh load

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

    def disconnect(self, ctx: ScriptContext) -> None:
        """Clean up resources on plugin disconnect or application shutdown."""
        # Signal the loading thread to stop
        self._stop_loading.set()

        if self._loading_thread and self._loading_thread.is_alive():
            ctx.logger.info("SD-WAN YAML Search: Waiting for background loading to complete...")
            self._loading_thread.join(timeout=5.0)  # Wait max 5 seconds
            if self._loading_thread.is_alive():
                ctx.logger.warning("SD-WAN YAML Search: Background thread did not complete in time")

        # Clean up data
        with self._lock:
            self._yaml_data.clear()
            self._loaded_files.clear()

        ctx.logger.debug("SD-WAN YAML Search: Plugin disconnected and cleaned up")

    def register(self, module: BaseModule) -> None:
        module.register_hook("process_data", self._search_yaml_repo)
