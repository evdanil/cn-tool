"""LensAdapter Protocol — the contract every adapter must satisfy."""
from __future__ import annotations

from typing import TYPE_CHECKING, runtime_checkable, Protocol

from cn_lens.adapters.types import AdapterHealth

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime


@runtime_checkable
class LensAdapter(Protocol):
    """Structural protocol that all cn-lens adapters must satisfy.

    An adapter is any object that has:
    - a ``name`` class/instance attribute (str)
    - a ``health(runtime)`` method returning ``AdapterHealth``

    The Protocol is ``@runtime_checkable`` so tests can use ``isinstance``.
    Adapters do NOT inherit from this class; they merely satisfy its shape.
    """

    name: str

    def health(self, runtime: "LensRuntime") -> AdapterHealth:
        """Return the adapter's health/availability for the given runtime."""
        ...
