"""Reachability adapter — ping and traceroute via subprocess.

Public surface
--------------
ping(runtime, target, *, count, timeout) -> PingResult
ping_many(runtime, targets, *, count, max_workers) -> PingBatchResult
trace(runtime, target, *, max_hops) -> TraceResult
trace_with_site_mapping(runtime, target, *, ad_lookup) -> EnrichedTraceResult

Design constraints
------------------
- No console / print.  Logger only.
- No shell=True.  Explicit args list everywhere.
- Offline mode: return disabled results without any subprocess call.
- Missing binary (shutil.which returns None): return error result.
- Concurrency via ThreadPoolExecutor with configurable max_workers.
- All error messages truncated to MAX_ERROR_LEN characters.
- All result types are frozen dataclasses.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Dict, Mapping, Optional, Sequence, Tuple

from cn_lens.adapters.types import AdapterHealth

if TYPE_CHECKING:
    from cn_lens.runtime import LensRuntime

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_ERROR_LEN = 200  # Maximum length of any error string returned in results

# Regex: parse "N packets transmitted, M received" (Linux ping)
_PING_COUNTS_RE = re.compile(
    r"(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets\s+)?received"
)
# Regex: parse "rtt min/avg/max/mdev = A/B/C/D ms"
_PING_RTT_RE = re.compile(
    r"rtt min/avg/max(?:/\w+)?\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)"
)
# Regex: parse traceroute hop lines
# Matches: "  1  10.0.0.1 (10.0.0.1)  1.23 ms ..."  or  "  2  * * *"
_TRACE_HOP_RE = re.compile(
    r"^\s*(\d+)\s+"           # hop index
    r"(?:"
    r"([\w.\-]+)\s+\(([\d.]+)\)\s+(\d+\.\d+)"  # hostname (ip)  rtt_ms
    r"|"
    r"([\d.]+)\s+\(([\d.]+)\)\s+(\d+\.\d+)"    # ip (ip)        rtt_ms
    r"|"
    r"([\d.]+)\s+(\d+\.\d+)"                    # bare ip        rtt_ms
    r"|"
    r"(\*)"                                      # star line
    r")"
)


# ---------------------------------------------------------------------------
# Frozen dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Hop:
    """A single hop in a traceroute result."""
    index: int
    ip: str
    hostname: str
    rtt_ms: float


@dataclass(frozen=True)
class PingResult:
    """Result of a single ping run."""
    target: str
    sent: int
    received: int
    loss_pct: float
    rtt_min: float
    rtt_avg: float
    rtt_max: float
    success: bool
    error: str


@dataclass(frozen=True)
class PingBatchResult:
    """Aggregated result of ping_many."""
    results: Tuple[PingResult, ...]


@dataclass(frozen=True)
class TraceResult:
    """Result of a single traceroute run."""
    target: str
    hops: Tuple[Hop, ...]
    reached: bool
    error: str


@dataclass(frozen=True)
class EnrichedTraceResult:
    """TraceResult with per-hop site code annotations."""
    trace: TraceResult
    hop_sites: Mapping[str, Optional[str]]


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _trim_error(msg: str) -> str:
    """Trim an error string to MAX_ERROR_LEN characters."""
    if len(msg) <= MAX_ERROR_LEN:
        return msg
    return msg[:MAX_ERROR_LEN - 3] + "..."


def _parse_ping_output(output: str) -> Tuple[int, int, float, float, float, float]:
    """Return (sent, received, loss_pct, rtt_min, rtt_avg, rtt_max).

    All values default to 0.0 when parsing fails.
    """
    sent = received = 0
    loss_pct = 0.0
    rtt_min = rtt_avg = rtt_max = 0.0

    m_counts = _PING_COUNTS_RE.search(output)
    if m_counts:
        sent = int(m_counts.group(1))
        received = int(m_counts.group(2))
        if sent > 0:
            loss_pct = round((sent - received) / sent * 100.0, 1)

    m_rtt = _PING_RTT_RE.search(output)
    if m_rtt:
        rtt_min = float(m_rtt.group(1))
        rtt_avg = float(m_rtt.group(2))
        rtt_max = float(m_rtt.group(3))

    return sent, received, loss_pct, rtt_min, rtt_avg, rtt_max


def _parse_trace_output(output: str, target: str) -> Tuple[Tuple[Hop, ...], bool]:
    """Return (hops, reached).

    hops  — ordered tuple of Hop objects (star lines produce Hop with ip='').
    reached — True when the last non-star hop IP matches the target.
    """
    hops = []
    for line in output.splitlines():
        m = _TRACE_HOP_RE.match(line)
        if not m:
            continue
        idx = int(m.group(1))
        # star
        if m.group(10) == "*":
            hops.append(Hop(index=idx, ip="", hostname="*", rtt_ms=0.0))
            continue
        # hostname (ip)  rtt_ms
        if m.group(2) and m.group(3):
            hostname = m.group(2)
            ip = m.group(3)
            rtt_ms = float(m.group(4))
        # ip (ip) rtt_ms
        elif m.group(5) and m.group(6):
            ip = m.group(6)
            hostname = m.group(5)
            rtt_ms = float(m.group(7))
        # bare ip rtt_ms
        elif m.group(8):
            ip = m.group(8)
            hostname = ""
            rtt_ms = float(m.group(9))
        else:
            continue
        hops.append(Hop(index=idx, ip=ip, hostname=hostname, rtt_ms=rtt_ms))

    # reached: last hop with a real IP equals the target
    responding = [h for h in hops if h.ip]
    reached = bool(responding and responding[-1].ip == target)
    return tuple(hops), reached


def _find_binary(name: str) -> Optional[str]:
    """Return the path to a binary, or None if not found."""
    return shutil.which(name)


def _offline_ping_result(target: str) -> PingResult:
    return PingResult(
        target=target,
        sent=0, received=0, loss_pct=100.0,
        rtt_min=0.0, rtt_avg=0.0, rtt_max=0.0,
        success=False,
        error="offline mode — no network operations",
    )


def _offline_trace_result(target: str) -> TraceResult:
    return TraceResult(
        target=target,
        hops=(),
        reached=False,
        error="offline mode — no network operations",
    )


# ---------------------------------------------------------------------------
# Core single-target functions
# ---------------------------------------------------------------------------

def ping(
    runtime: "LensRuntime",
    target: str,
    *,
    count: int = 4,
    timeout: float = 1.0,
) -> PingResult:
    """Ping a single target.

    Parameters
    ----------
    runtime:
        LensRuntime (or any duck-type with .offline and .logger).
    target:
        IP address or hostname.
    count:
        Number of ICMP echo requests.
    timeout:
        Per-packet timeout in seconds (passed to ``-W`` on Linux).

    Returns
    -------
    PingResult
        Never raises; failures are returned as success=False with error text.
    """
    if runtime.offline:
        runtime.logger.debug("reachability.ping: offline, skipping %s", target)
        return _offline_ping_result(target)

    binary = _find_binary("ping")
    if binary is None:
        return PingResult(
            target=target,
            sent=0, received=0, loss_pct=100.0,
            rtt_min=0.0, rtt_avg=0.0, rtt_max=0.0,
            success=False,
            error="ping binary not found in PATH",
        )

    args = [binary, "-c", str(count), "-W", str(int(timeout)), "-n", target]
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=count * (timeout + 2) + 5,
        )
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return PingResult(
            target=target,
            sent=count, received=0, loss_pct=100.0,
            rtt_min=0.0, rtt_avg=0.0, rtt_max=0.0,
            success=False,
            error=_trim_error(f"ping timeout after {count * (timeout + 2) + 5:.0f}s"),
        )
    except Exception as exc:
        return PingResult(
            target=target,
            sent=0, received=0, loss_pct=100.0,
            rtt_min=0.0, rtt_avg=0.0, rtt_max=0.0,
            success=False,
            error=_trim_error(f"ping error: {type(exc).__name__}: {exc}"),
        )

    sent, received, loss_pct, rtt_min, rtt_avg, rtt_max = _parse_ping_output(output)
    # success requires all sent packets to be received (0% loss)
    success = sent > 0 and received == sent

    runtime.logger.debug(
        "reachability.ping %s: sent=%d received=%d loss=%.1f%%",
        target, sent, received, loss_pct,
    )
    return PingResult(
        target=target,
        sent=sent,
        received=received,
        loss_pct=loss_pct,
        rtt_min=rtt_min,
        rtt_avg=rtt_avg,
        rtt_max=rtt_max,
        success=success,
        error="",
    )


def trace(
    runtime: "LensRuntime",
    target: str,
    *,
    max_hops: int = 30,
) -> TraceResult:
    """Traceroute to a single target.

    Parameters
    ----------
    runtime:
        LensRuntime (or any duck-type with .offline and .logger).
    target:
        IP address or hostname.
    max_hops:
        Maximum TTL / hop count.

    Returns
    -------
    TraceResult
        Never raises; failures are returned as reached=False with error text.
    """
    if runtime.offline:
        runtime.logger.debug("reachability.trace: offline, skipping %s", target)
        return _offline_trace_result(target)

    # Try traceroute first, fall back to tracepath
    binary = _find_binary("traceroute")
    if binary is None:
        return TraceResult(
            target=target,
            hops=(),
            reached=False,
            error="traceroute binary not found in PATH",
        )

    args = [binary, "-m", str(max_hops), "-n", target]
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=max_hops * 3 + 10,
        )
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return TraceResult(
            target=target,
            hops=(),
            reached=False,
            error=_trim_error(f"traceroute timeout after {max_hops * 3 + 10}s"),
        )
    except Exception as exc:
        return TraceResult(
            target=target,
            hops=(),
            reached=False,
            error=_trim_error(f"traceroute error: {type(exc).__name__}: {exc}"),
        )

    hops, reached = _parse_trace_output(output, target)
    runtime.logger.debug(
        "reachability.trace %s: hops=%d reached=%s",
        target, len(hops), reached,
    )
    return TraceResult(target=target, hops=hops, reached=reached, error="")


def ping_many(
    runtime: "LensRuntime",
    targets: Sequence[str],
    *,
    count: int = 4,
    max_workers: int = 16,
) -> PingBatchResult:
    """Ping multiple targets concurrently.

    Parameters
    ----------
    runtime:
        LensRuntime.
    targets:
        Sequence of IP addresses or hostnames.
    count:
        Packets per target.
    max_workers:
        Maximum concurrent threads.

    Returns
    -------
    PingBatchResult
    """
    if runtime.offline:
        results = tuple(_offline_ping_result(t) for t in targets)
        return PingBatchResult(results=results)

    results: list[PingResult] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping, runtime, t, count=count): t for t in targets}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                target = futures[future]
                runtime.logger.error(
                    "reachability.ping_many: unhandled exception for %s: %s",
                    target, exc,
                )
                results.append(PingResult(
                    target=target,
                    sent=0, received=0, loss_pct=100.0,
                    rtt_min=0.0, rtt_avg=0.0, rtt_max=0.0,
                    success=False,
                    error=_trim_error(f"unexpected error: {exc}"),
                ))

    return PingBatchResult(results=tuple(results))


def trace_with_site_mapping(
    runtime: "LensRuntime",
    target: str,
    *,
    ad_lookup: Optional[Callable[[str], Optional[str]]] = None,
) -> EnrichedTraceResult:
    """Traceroute plus optional per-hop site enrichment.

    Parameters
    ----------
    runtime:
        LensRuntime.
    target:
        IP address or hostname.
    ad_lookup:
        Optional callable ``(ip: str) -> Optional[str]`` that maps an IP to a
        site code.  When None, all hop_sites values are None.  Typically the
        AD adapter's ``enrich_ip`` function is injected here.

    Returns
    -------
    EnrichedTraceResult
        Contains the underlying TraceResult and a dict mapping each responding
        hop IP to its site code (or None when unmapped / no lookup provided).
    """
    trace_result = trace(runtime, target)
    hop_sites: Dict[str, Optional[str]] = {}

    for hop in trace_result.hops:
        if not hop.ip:
            continue
        if hop.ip in hop_sites:
            continue
        if ad_lookup is not None:
            try:
                site = ad_lookup(hop.ip)
            except Exception as exc:
                runtime.logger.debug(
                    "reachability.trace_with_site_mapping: ad_lookup(%s) raised %s",
                    hop.ip, exc,
                )
                site = None
        else:
            site = None
        hop_sites[hop.ip] = site

    return EnrichedTraceResult(trace=trace_result, hop_sites=hop_sites)


# ---------------------------------------------------------------------------
# Adapter class satisfying LensAdapter protocol
# ---------------------------------------------------------------------------

class ReachabilityAdapter:
    """LensAdapter for reachability checks (ping / traceroute).

    Implements the ``LensAdapter`` protocol (name + health) so it can be
    registered with ``AdapterRegistry``.  All real work is delegated to the
    module-level functions above.
    """

    name: str = "reachability"

    def health(self, runtime) -> AdapterHealth:
        """Return adapter health.

        - ``disabled`` when offline.
        - ``error``    when ping binary is unavailable.
        - ``ok``       otherwise.
        """
        if runtime.offline:
            return AdapterHealth(status="disabled", detail="offline mode")

        if _find_binary("ping") is None:
            return AdapterHealth(
                status="error",
                detail="ping binary not found in PATH",
            )

        return AdapterHealth(status="ok", detail="")
