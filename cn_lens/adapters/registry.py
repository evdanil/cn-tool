"""Adapter registry — the single source-of-truth for registered adapters.

Every workflow calls ``get_registry()`` to obtain the shared singleton and
then calls ``registry.source_statuses()`` to build the ``LensResult.sources``
dict.  At T6 the registry is always empty; adapters are registered in T7-T12.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, List

from cn_lens.adapters.types import AdapterHealth, VALID_SOURCE_STATUSES

if TYPE_CHECKING:
    from cn_lens.adapters.base import LensAdapter


class AdapterRegistry:
    """Ordered registry of ``LensAdapter``-compatible objects.

    Adapters are stored in insertion order.  Each registered object must have
    a ``name`` attribute (str); the registry validates this on ``register()``.
    """

    def __init__(self) -> None:
        self._adapters: List["LensAdapter"] = []

    # --- Mutation --------------------------------------------------------

    def register(self, adapter: "LensAdapter") -> None:
        """Register an adapter.

        Raises
        ------
        AttributeError
            If the adapter has no ``name`` attribute.
        ValueError
            If an adapter with the same name is already registered.
        """
        name = getattr(adapter, "name", _SENTINEL)
        if name is _SENTINEL:
            raise AttributeError(
                f"Adapter {adapter!r} must have a 'name' attribute to be registered."
            )
        if not isinstance(name, str) or not name:
            raise ValueError(f"Adapter 'name' must be a non-empty str; got {name!r}")

        existing_names = {a.name for a in self._adapters}
        if name in existing_names:
            raise ValueError(f"An adapter named {name!r} is already registered.")

        self._adapters.append(adapter)

    # --- Query -----------------------------------------------------------

    def list_adapters(self) -> "List[LensAdapter]":
        """Return all registered adapters in insertion order."""
        return list(self._adapters)

    def names(self) -> List[str]:
        """Return adapter names in insertion order."""
        return [a.name for a in self._adapters]

    def source_statuses(self, runtime: Any = None, offline: bool = False) -> Dict[str, str]:
        """Build the ``sources`` dict used by ``LensResult``.

        Parameters
        ----------
        runtime:
            Active ``LensRuntime``.  When ``None`` every adapter returns
            ``not_queried`` regardless of the ``offline`` flag.
        offline:
            When ``True`` every registered adapter returns ``not_queried``
            without calling any ``health()`` method.  This replaces the
            per-workflow ``_OFFLINE_SOURCES`` dicts (bug B1).

        All returned values are members of ``VALID_SOURCE_STATUSES``.
        """
        result: Dict[str, str] = {}
        for adapter in self._adapters:
            if offline or runtime is None:
                status = "not_queried"
            else:
                try:
                    health: AdapterHealth = adapter.health(runtime)
                    status = health.status if health.status in VALID_SOURCE_STATUSES else "error"
                except Exception as exc:
                    logging.getLogger(__name__).warning(
                        "health check for %s failed: %s", adapter.name, exc
                    )
                    status = "error"
            result[adapter.name] = status
        return result


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_SENTINEL = object()
_registry: AdapterRegistry | None = None


def get_registry() -> AdapterRegistry:
    """Return the module-level singleton AdapterRegistry.

    The registry is created on first access and reused for the lifetime of
    the process.  Tests that need an isolated registry should instantiate
    ``AdapterRegistry()`` directly.
    """
    global _registry
    if _registry is None:
        _registry = AdapterRegistry()
    return _registry
