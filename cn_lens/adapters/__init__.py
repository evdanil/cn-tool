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
