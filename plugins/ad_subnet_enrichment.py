import threading
from core.base import BasePlugin, BaseModule, ScriptContext
from utils.ad_helper import init_ad_link, get_ad_subnet_info, DEFAULT_SEARCH_BASE
from typing import Dict, Any


class ADSubnetEnrichmentPlugin(BasePlugin):
    """
    A stateful plugin that enriches subnet data with information from Active Directory.
    It establishes one connection per module run and reuses it for all queries.
    """
    def __init__(self):
        """Initializes the plugin's state."""
        self.conn = None
        self.ad_lock = None  # A lock to ensure thread-safe use of the connection
        self.is_globally_managed = False  # Flag to distinguish connection type

    @property
    def manages_global_connection(self) -> bool:
        return True  # This plugin wants to be managed by the application

    @property
    def name(self) -> str:
        return "Active Directory Subnet Enrichment"

    @property
    def target_module_name(self) -> str:
        # This must match the filename of the target module (without .py)
        return "subnet_request"

    @property
    def config_schema(self) -> Dict[str, Dict[str, Any]]:
        return {
            "ad_enabled":            {"section": "ad", "ini_key": "enabled", "type": "bool", "fallback": False},
            "ad_uri":                {"section": "ad", "ini_key": "uri", "type": "str", "fallback": ""},
            "ad_user":               {"section": "ad", "ini_key": "user", "type": "str", "fallback": ""},
            "ad_search_base":        {"section": "ad", "ini_key": "search_base", "type": "str", "fallback": DEFAULT_SEARCH_BASE},
            "ad_connect_on_startup": {"section": "ad", "ini_key": "connect_on_startup", "type": "bool", "fallback": False},
        }

    def connect(self, ctx: ScriptContext) -> None:
        """Called by main.py on startup."""
        if not ctx.cfg.get("ad_enabled"):
            return  # Don't do anything if the plugin is disabled

        # Only connect if the user wants to in their config
        if ctx.cfg.get("ad_connect_on_startup"):
            ctx.logger.info("AD Plugin: Establishing global connection as configured...")
            self.is_globally_managed = True
            self.setup_connection(ctx, None)  # Reuse the setup logic

    def disconnect(self, ctx: ScriptContext) -> None:
        """Called by main.py on exit."""
        # The teardown logic handles closing the connection if it exists
        self.teardown_connection(ctx, None)

    def register(self, module: BaseModule) -> None:
        """Registers all necessary hooks for the plugin's lifecycle."""
        module.register_hook('pre_run', self.setup_connection)
        module.register_hook('process_data', self.enrich_subnet_data)
        module.register_hook('post_run', self.teardown_connection)

    def setup_connection(self, ctx: ScriptContext, data: Any) -> Any:
        """Establishes AD connection either globally or on-demand."""
        if self.conn:  # Connection already exists, do nothing
            return

        if not ctx.cfg.get("ad_enabled"):
            return  # Don't do anything if the plugin is disabled

        mode = "global" if self.is_globally_managed else "on-demand"
        ctx.logger.info(f"AD Plugin: Initializing {mode} connection...")

        self.ad_lock = threading.Lock()  # Create the lock for this run
        self.conn = init_ad_link(
            logger=ctx.logger,
            user=ctx.cfg.get("ad_user", ""),
            password=ctx.password,
            ldap_uri=ctx.cfg.get("ad_uri", "")
        )
        if not self.conn:
            ctx.logger.error("AD Plugin: Failed to establish persistent connection for this run.")

    def enrich_subnet_data(self, ctx: ScriptContext, data: dict) -> dict:
        """
        Hook callback for 'process_data'. Uses the existing connection to query AD.
        """
        # If connection failed during setup, or plugin is disabled, do nothing.
        if not self.conn or not self.ad_lock:
            return data

        ctx.logger.debug("AD Plugin: Attempting to enrich data.")

        # Extract the subnet string from the data provided by the module
        # The data structure is based on what subnet_request module produces
        try:
            subnet_str = data.get("general", [{}])[0].get("subnet")
            if not subnet_str:
                ctx.logger.warning("AD Plugin: Could not find subnet string in provided data.")
                return data
        except (IndexError, AttributeError):
            ctx.logger.warning("AD Plugin: Data format from module is unexpected.")
            return data

        # Get AD configuration
        ad_search_base: str = ctx.cfg.get("ad_search_base", DEFAULT_SEARCH_BASE)

        # Use the lock to ensure only one thread queries AD at a time
        with self.ad_lock:
            ad_info = get_ad_subnet_info(
                logger=ctx.logger,
                ldap_link=self.conn,
                subnet=subnet_str,
                search_base=ad_search_base
            )

        if ad_info:
            ctx.logger.debug(f"AD Plugin: Successfully enriched data for {subnet_str} using persistent connection.")
            data['Active Directory'] = [ad_info]

        return data

    def teardown_connection(self, ctx: ScriptContext, data: Any) -> Any:
        """Closes the connection if it exists and was NOT globally managed."""
        # If the connection is globally managed, main.py's exit handler is responsible.
        # This hook only cleans up on-demand (module-scoped) connections.
        if self.is_globally_managed:
            return

        if self.conn:
            ctx.logger.info("AD Plugin: Closing persistent connection.")
            self.conn.unbind()
        # Reset state for the next run
        self.conn = None
        self.ad_lock = None
