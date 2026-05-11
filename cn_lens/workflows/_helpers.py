"""Shared helpers for cn_lens workflow modules.

Public surface
--------------
OFFLINE_FINDING_MESSAGE : str
    Classifier finding message used on the offline / None-runtime path.
    Indicates that adapters were not consulted; only classification ran.

CLASSIFIED_FINDING_MESSAGE : str
    Classifier finding message used on the online path (default case).
    Directs the reader to the sources block for adapter health and to the
    summary block for adapter results.

MVP_FINDING_MESSAGE : str  [deprecated]
    Backwards-compatible alias equal to ``OFFLINE_FINDING_MESSAGE``.  External
    callers that pin the literal string
    ``"deeper live source adapters are not enabled in this MVP"`` must migrate
    to ``OFFLINE_FINDING_MESSAGE`` or ``CLASSIFIED_FINDING_MESSAGE`` as
    appropriate.  The alias will be removed in a future release.

synthesise_error_finding(source, exc, *, detail_extra=...) -> LensFinding
    Build a synthesised error finding for an unexpected adapter exception.

classifier_finding(message=CLASSIFIED_FINDING_MESSAGE) -> LensFinding
    Build the initial classifier info finding (workflow-neutral).
    Defaults to the online message; pass ``OFFLINE_FINDING_MESSAGE``
    explicitly on the offline path.

make_run_id(now=None) -> str
    Return a UTC timestamp string suitable for use as a run ID.

is_short_hostname(value) -> bool
    Return True when the value has fewer than 3 dot-separated labels
    (short hostname / hostname prefix — not a fully-qualified domain name).

maybe_persist(run, runtime) -> None
    Persist *run* to disk when *runtime* is online.  Swallows all errors.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, TYPE_CHECKING

from cn_lens.models import LensFinding, LensRun

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

_LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

OFFLINE_FINDING_MESSAGE: str = (
    "offline mode — adapters not consulted; only classifier ran"
)

CLASSIFIED_FINDING_MESSAGE: str = (
    "object classified; see sources block for adapter health"
    " and summary block for adapter results"
)


# ---------------------------------------------------------------------------
# Deprecated back-compat alias
# ---------------------------------------------------------------------------

# MVP_FINDING_MESSAGE is kept as a plain string constant equal to
# OFFLINE_FINDING_MESSAGE so that existing importers continue to work.
# New code should import OFFLINE_FINDING_MESSAGE or CLASSIFIED_FINDING_MESSAGE
# directly.  The alias will be removed in a future release.
MVP_FINDING_MESSAGE: str = OFFLINE_FINDING_MESSAGE


# ---------------------------------------------------------------------------
# make_run_id
# ---------------------------------------------------------------------------

def make_run_id(now: datetime | None = None) -> str:
    """Return a UTC timestamp string suitable for use as a run ID.

    Format: ``%Y%m%dT%H%M%SZ`` (e.g. ``20240510T142300Z``).
    """
    if now is None:
        now = datetime.now(timezone.utc)
    return now.strftime("%Y%m%dT%H%M%SZ")


# ---------------------------------------------------------------------------
# Shared finding factories
# ---------------------------------------------------------------------------

def synthesise_error_finding(
    source: str,
    exc: BaseException,
    *,
    detail_extra: Mapping[str, Any] | None = None,
) -> LensFinding:
    """Return a synthesised error finding for an unexpected adapter exception.

    Parameters
    ----------
    source:
        The adapter or source name (e.g. ``"infoblox"``, ``"ad"``).
    exc:
        The caught exception.
    detail_extra:
        Additional key-value pairs merged into the ``detail`` dict alongside
        the auto-populated ``"exception"`` key.
    """
    detail: dict[str, Any] = {"exception": type(exc).__name__}
    if detail_extra:
        detail.update(detail_extra)
    return LensFinding(
        severity="error",
        source=source,
        message=str(exc),
        detail=detail,
    )


def classifier_finding(message: str = CLASSIFIED_FINDING_MESSAGE) -> LensFinding:
    """Return a classifier-level info finding (no workflow key in detail).

    For workflow-specific variants (with ``detail={"workflow": ...}``) each
    workflow continues to construct its own copy, but the default message
    constant is sourced from here.
    """
    return LensFinding(
        severity="info",
        source="classifier",
        message=message,
        detail={},
    )


# ---------------------------------------------------------------------------
# Hostname / FQDN label helpers
# ---------------------------------------------------------------------------

def is_short_hostname(value: str) -> bool:
    """Return True when *value* has fewer than 3 dot-separated labels.

    Rule used across inspect, dns, and device workflows to distinguish a short
    hostname / prefix (e.g. ``"host"``, ``"device1.corp"``) from a fully-
    qualified domain name (e.g. ``"host.example.com"``).

    Examples
    --------
    >>> is_short_hostname("host")
    True
    >>> is_short_hostname("device1.corp")
    True
    >>> is_short_hostname("host.example.com")
    False
    >>> is_short_hostname("sub.host.example.com")
    False
    """
    return len(value.split(".")) < 3


# ---------------------------------------------------------------------------
# Auto-persistence helper
# ---------------------------------------------------------------------------

def maybe_persist(run: LensRun, runtime: Optional["LensRuntime"]) -> None:
    """Persist *run* to disk when *runtime* is online.

    This is a fire-and-forget helper: all exceptions are caught, logged, and
    silently swallowed so that persistence failures never affect the workflow's
    return value.

    Parameters
    ----------
    run:
        The finished ``LensRun`` to persist.
    runtime:
        Active ``LensRuntime``.  When ``None`` or offline, the call is a no-op.
    """
    if runtime is None or runtime.offline:
        return
    try:
        from cn_lens.reports.persistence import persist_run
        persist_run(run, runtime)
    except Exception as exc:
        logger = getattr(runtime, "logger", _LOG)
        logger.warning("maybe_persist: persistence skipped due to error: %s", exc)
