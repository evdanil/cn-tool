"""DNS / Bulk Resolve adapter for cn-lens (Task 11).

Wraps stdlib ``socket`` (getaddrinfo / gethostbyaddr) — dnspython is not in
requirements.txt so we stay with the stdlib.

Public surface
--------------
DnsForwardResult   — A + AAAA records for a single name
DnsReverseResult   — PTR record for a single IP
DnsPrefixExpansion — mirrors fqdn_request.py prefix-expansion semantics

resolve_forward(runtime, name)         → DnsForwardResult
resolve_reverse(runtime, ip)           → DnsReverseResult
expand_fqdn_prefix(runtime, prefix)    → DnsPrefixExpansion

Rules
-----
- offline → every function returns a ``disabled`` status, zero socket calls
- DNS errors (NXDOMAIN, herror, timeout) → ``error``/``not_found`` finding,
  never raise
- No console / print; logger only
"""
from __future__ import annotations

import logging
import re
import socket
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

from cn_lens.adapters.types import AdapterHealth, VALID_RESULT_STATUSES

# Fallback module-level logger used only when no runtime logger is provided
# (e.g. when _forward_one / _reverse_one are called without a runtime context).
# Production code always passes runtime.logger via the helper wrappers.
_module_logger = logging.getLogger(__name__)

# Regex that mirrors fqdn_request.py input validation
_VALID_PREFIX_RE = re.compile(r"^[a-zA-Z0-9.\-]+$")
_MIN_PREFIX_LEN = 3


# ---------------------------------------------------------------------------
# Frozen result dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DnsForwardResult:
    """Result of a forward DNS lookup (A + AAAA).

    Fields
    ------
    name:       The queried name.
    a_records:  Tuple of IPv4 addresses resolved.
    aaaa_records: Tuple of IPv6 addresses resolved.
    status:     One of ``VALID_RESULT_STATUSES``.
    error:      Short error message when status is not ``ok``; else None.
    """
    name: str
    a_records: Tuple[str, ...] = field(default_factory=tuple)
    aaaa_records: Tuple[str, ...] = field(default_factory=tuple)
    status: str = "ok"
    error: Optional[str] = None

    def __post_init__(self) -> None:
        if self.status not in VALID_RESULT_STATUSES:
            allowed = ", ".join(sorted(VALID_RESULT_STATUSES))
            raise ValueError(
                f"DnsForwardResult status {self.status!r} is not valid; "
                f"allowed: {allowed}"
            )


@dataclass(frozen=True)
class DnsReverseResult:
    """Result of a reverse DNS lookup (PTR).

    Fields
    ------
    ip:      The queried IP address.
    ptr:     Hostname returned by gethostbyaddr; None when not found.
    aliases: Additional aliases returned by gethostbyaddr (may be empty).
    status:  One of ``VALID_RESULT_STATUSES``.
    error:   Short error message; None when status is ``ok``.
    """
    ip: str
    ptr: Optional[str] = None
    aliases: Tuple[str, ...] = field(default_factory=tuple)
    status: str = "ok"
    error: Optional[str] = None

    def __post_init__(self) -> None:
        if self.status not in VALID_RESULT_STATUSES:
            allowed = ", ".join(sorted(VALID_RESULT_STATUSES))
            raise ValueError(
                f"DnsReverseResult status {self.status!r} is not valid; "
                f"allowed: {allowed}"
            )


@dataclass(frozen=True)
class DnsPrefixExpansion:
    """Result of expand_fqdn_prefix().

    Mirrors fqdn_request.py semantics: given a hostname prefix the adapter
    attempts to resolve it directly via the system resolver and returns what
    it finds.

    Fields
    ------
    prefix:   The input prefix string.
    names:    Tuple of resolved hostnames / addresses (may be empty).
    status:   One of ``VALID_RESULT_STATUSES``.
    error:    Short error message; None when status is ``ok``.
    """
    prefix: str
    names: Tuple[str, ...] = field(default_factory=tuple)
    status: str = "ok"
    error: Optional[str] = None

    def __post_init__(self) -> None:
        if self.status not in VALID_RESULT_STATUSES:
            allowed = ", ".join(sorted(VALID_RESULT_STATUSES))
            raise ValueError(
                f"DnsPrefixExpansion status {self.status!r} is not valid; "
                f"allowed: {allowed}"
            )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _forward_one(name: str, log: Optional[logging.Logger] = None) -> DnsForwardResult:
    """Resolve a single name; catch all DNS exceptions, never raise.

    Parameters
    ----------
    name:
        Hostname or IP address to resolve.
    log:
        Logger to use for debug/warning messages.  Defaults to the module-level
        fallback logger when not provided (e.g. in legacy call-sites).
    """
    _log = log or _module_logger
    try:
        addrinfo = socket.getaddrinfo(name, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.timeout as exc:
        msg = f"timeout resolving {name!r}: {exc}"
        _log.debug(msg)
        return DnsForwardResult(name=name, status="error", error=msg)
    except (socket.gaierror, socket.herror) as exc:
        msg = str(exc)
        _log.debug("DNS lookup failed for %r: %s", name, msg)
        return DnsForwardResult(name=name, status="not_found", error=msg)
    except Exception as exc:
        msg = f"unexpected error resolving {name!r}: {exc}"
        _log.warning(msg)
        return DnsForwardResult(name=name, status="error", error=msg)

    a: List[str] = []
    aaaa: List[str] = []
    seen: set = set()
    for ai in addrinfo:
        family, _, _, _, sockaddr = ai
        ip = sockaddr[0]
        if ip in seen:
            continue
        seen.add(ip)
        if family == socket.AF_INET:
            a.append(ip)
        elif family == socket.AF_INET6:
            aaaa.append(ip)

    return DnsForwardResult(name=name, a_records=tuple(a), aaaa_records=tuple(aaaa), status="ok")


def _reverse_one(ip: str, log: Optional[logging.Logger] = None) -> DnsReverseResult:
    """Reverse-resolve a single IP; catch all DNS exceptions, never raise.

    Parameters
    ----------
    ip:
        IPv4 or IPv6 address string.
    log:
        Logger to use.  Defaults to the module-level fallback logger.
    """
    _log = log or _module_logger
    try:
        hostname, raw_aliases, _addresses = socket.gethostbyaddr(ip)
    except socket.timeout as exc:
        msg = f"timeout reverse-resolving {ip!r}: {exc}"
        _log.debug(msg)
        return DnsReverseResult(ip=ip, status="error", error=msg)
    except (socket.herror, socket.gaierror) as exc:
        msg = str(exc)
        _log.debug("Reverse DNS failed for %r: %s", ip, msg)
        return DnsReverseResult(ip=ip, status="not_found", error=msg)
    except Exception as exc:
        msg = f"unexpected error reverse-resolving {ip!r}: {exc}"
        _log.warning(msg)
        return DnsReverseResult(ip=ip, status="error", error=msg)

    return DnsReverseResult(ip=ip, ptr=hostname, aliases=tuple(raw_aliases), status="ok")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_forward(runtime: "LensRuntime", name: str) -> DnsForwardResult:
    """Forward DNS lookup: returns A and AAAA records for *name*.

    Returns a ``disabled`` result when the runtime is offline.
    Errors (NXDOMAIN, timeout, bad input) surface as an ``error`` / ``not_found``
    status — never raises.
    """
    if runtime.offline:
        return DnsForwardResult(name=name, status="disabled", error="offline mode")
    return _forward_one(name, log=runtime.logger)


def resolve_reverse(runtime: "LensRuntime", ip: str) -> DnsReverseResult:
    """Reverse DNS lookup (PTR) for *ip*.

    Returns a ``disabled`` result when the runtime is offline.
    """
    if runtime.offline:
        return DnsReverseResult(ip=ip, status="disabled", error="offline mode")
    return _reverse_one(ip, log=runtime.logger)


def expand_fqdn_prefix(runtime: "LensRuntime", prefix: str) -> DnsPrefixExpansion:
    """Expand a hostname prefix using the system resolver.

    Mirrors ``modules/fqdn_request.py`` input validation semantics:
    - Minimum 3 characters.
    - Only ``[a-zA-Z0-9.-]`` characters allowed.
    - Offline → disabled.

    The adapter resolves the prefix directly via ``getaddrinfo`` and returns
    the IP addresses and canonical name found.  Unlike the Infoblox-backed
    module, this uses the system resolver so results reflect what the local
    DNS sees, not Infoblox's zone data.
    """
    if runtime.offline:
        return DnsPrefixExpansion(prefix=prefix, status="disabled", error="offline mode")

    # Validate: minimum length
    if len(prefix) < _MIN_PREFIX_LEN:
        msg = f"prefix too short — minimum {_MIN_PREFIX_LEN} characters required"
        return DnsPrefixExpansion(prefix=prefix, status="error", error=msg)

    # Validate: character set
    if not _VALID_PREFIX_RE.match(prefix):
        msg = f"prefix {prefix!r} contains invalid characters (only a-z, 0-9, '.', '-' allowed)"
        return DnsPrefixExpansion(prefix=prefix, status="error", error=msg)

    # Resolve via system resolver
    fwd = _forward_one(prefix, log=runtime.logger)
    if fwd.status == "ok":
        # Collect all resolved addresses as names
        names = fwd.a_records + fwd.aaaa_records
        return DnsPrefixExpansion(prefix=prefix, names=tuple(names), status="ok")
    elif fwd.status == "not_found":
        return DnsPrefixExpansion(
            prefix=prefix, names=(), status="not_found", error=fwd.error
        )
    else:
        return DnsPrefixExpansion(
            prefix=prefix, names=(), status="error", error=fwd.error
        )


# ---------------------------------------------------------------------------
# Adapter class (satisfies LensAdapter Protocol)
# ---------------------------------------------------------------------------

class DnsAdapter:
    """DNS adapter — satisfies the LensAdapter Protocol.

    ``name = "dns"``.  ``health()`` returns ``ok`` when online and
    ``disabled`` when the runtime is in offline mode.  The system resolver
    is assumed available whenever online; no custom probe is issued.
    """

    name: str = "dns"

    def health(self, runtime: "LensRuntime") -> AdapterHealth:
        """Return adapter health.

        - ``disabled`` when offline.
        - ``ok`` otherwise (system resolver assumed available).
        """
        if runtime.offline:
            return AdapterHealth(status="disabled", detail="offline mode")
        return AdapterHealth(status="ok", detail="system resolver available")
