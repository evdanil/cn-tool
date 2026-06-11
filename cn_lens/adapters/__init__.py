"""cn_lens.adapters — pure-data wrappers around existing cn-tool helpers.

Each adapter exposes lookup functions that take a ``LensRuntime`` and typed
inputs and return dataclasses.  No printing, no ``console``, no
``press_any_key``.

Public surface (added per task):
- T6: types, base, registry  (this task)
- T7: infoblox
- T8: active_directory
- T9: config_repo
- T10: sdwan_yaml
- T11: dns
- T12: reachability
- P6.1: device_ssh

P2.1: All six adapters (extended to seven in P6.1) are registered into the
module-level singleton at import time.  Registration is idempotent — re-importing
this module will not double-register because ``AdapterRegistry.register()`` raises
``ValueError`` for duplicates, which we silently swallow.
"""
from cn_lens.adapters.types import AdapterHealth, VALID_SOURCE_STATUSES
from cn_lens.adapters.base import LensAdapter
from cn_lens.adapters.registry import get_registry, AdapterRegistry

__all__ = [
    "AdapterHealth",
    "VALID_SOURCE_STATUSES",
    "LensAdapter",
    "get_registry",
    "AdapterRegistry",
]

# ---------------------------------------------------------------------------
# Register all six adapters into the shared singleton (idempotent).
# ---------------------------------------------------------------------------
# Import is deferred into a function to avoid circular-import issues at module
# load time (each adapter imports from cn_lens.adapters.types / models).

def _register_adapters() -> None:
    """Register all seven canonical adapters into the shared singleton.

    Called once at module import.  Safe to call multiple times — duplicate
    registration raises ``ValueError`` which is silently ignored.
    """
    from cn_lens.adapters.infoblox import InfobloxAdapter
    from cn_lens.adapters.active_directory import ActiveDirectoryAdapter
    from cn_lens.adapters.config_repo import ConfigRepoAdapter
    from cn_lens.adapters.dns import DnsAdapter
    from cn_lens.adapters.reachability import ReachabilityAdapter
    from cn_lens.adapters.sdwan_yaml import ADAPTER as SdwanYamlAdapter
    from cn_lens.adapters.device_ssh import DeviceSshAdapter

    registry = get_registry()
    for adapter in (
        InfobloxAdapter(),
        ActiveDirectoryAdapter(),
        ConfigRepoAdapter(),
        DnsAdapter(),
        ReachabilityAdapter(),
        SdwanYamlAdapter,
        DeviceSshAdapter(),
    ):
        try:
            registry.register(adapter)
        except ValueError:
            # Already registered (idempotent re-import guard).
            pass


_register_adapters()
