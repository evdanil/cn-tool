"""Shared types for the cn-lens adapter layer.

Status vocabulary
-----------------
Two separate vocabularies exist at different scopes:

``VALID_SOURCE_STATUSES``
    Used by :class:`AdapterHealth` to describe the *availability* of an
    adapter as a whole (is it configured? is it reachable? is it offline?).
    Values: ``ok | partial | error | not_configured | not_queried | disabled``.

``VALID_RESULT_STATUSES``
    Used by per-result dataclasses to describe the *outcome* of an individual
    lookup (did we find the object? only partially? did something fail?).
    Values: ``ok | found | not_found | partial | disabled | error``.

The two sets overlap intentionally (``ok``, ``partial``, ``error``,
``disabled``) but differ in their semantics and the dataclasses that carry
them.  Do not mix them up in ``__post_init__`` validators.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Source status vocabulary  (AdapterHealth.status)
# ---------------------------------------------------------------------------

VALID_SOURCE_STATUSES: frozenset[str] = frozenset({
    "ok",
    "partial",
    "error",
    "not_configured",
    "not_queried",
    "disabled",
})

# ---------------------------------------------------------------------------
# Result status vocabulary  (per-lookup result dataclasses)
# ---------------------------------------------------------------------------

VALID_RESULT_STATUSES: frozenset[str] = frozenset({
    "ok",
    "found",
    "not_found",
    "partial",
    "disabled",
    "error",
})


# ---------------------------------------------------------------------------
# AdapterHealth
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AdapterHealth:
    """Result of an adapter's self-check.

    Attributes
    ----------
    status:
        One of ``VALID_SOURCE_STATUSES``.
    detail:
        Human-readable detail string; empty string when no detail needed.
    """

    status: str
    detail: str = field(default="")

    def __post_init__(self) -> None:
        if self.status not in VALID_SOURCE_STATUSES:
            allowed = ", ".join(sorted(VALID_SOURCE_STATUSES))
            raise ValueError(
                f"AdapterHealth status {self.status!r} is not valid; "
                f"allowed: {allowed}"
            )
