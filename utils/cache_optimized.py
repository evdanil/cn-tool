"""
Optimized cache index structures for O(log n) searches.

This module provides wrapper classes around diskcache Index objects that enable
efficient prefix and range queries using sorted key lists with binary search.

Performance Improvements:
- Keyword prefix search: O(n) -> O(log n + k) where k is result count
- Subnet IP search: O(subnet_size) -> O(log n + k)
"""

import bisect
import ipaddress
import threading
from functools import lru_cache
from typing import Dict, List, Optional, Tuple, Any
from diskcache import Index


class SortedKeyIndex:
    """
    Wrapper providing O(log n) prefix search over diskcache Index.

    The sorted key list is lazily built and cached. It is invalidated
    when the underlying index size changes.

    Thread-safe for concurrent reads; writes should be coordinated externally.
    """

    def __init__(self, index: Index):
        self._index = index
        self._sorted_keys: Optional[List[str]] = None
        self._keys_version: Optional[int] = None
        self._lock = threading.RLock()

    def _ensure_sorted_keys(self) -> None:
        """Lazily build/rebuild sorted key list when index changes."""
        current_len = len(self._index)
        if self._sorted_keys is None or self._keys_version != current_len:
            with self._lock:
                # Double-check after acquiring lock
                if self._sorted_keys is None or self._keys_version != current_len:
                    self._sorted_keys = sorted(self._index.keys())
                    self._keys_version = current_len

    def invalidate(self) -> None:
        """Force rebuild of sorted keys on next access."""
        with self._lock:
            self._sorted_keys = None
            self._keys_version = None

    def prefix_search(self, prefix: str) -> List[str]:
        """
        Find all keys starting with the given prefix.

        Complexity: O(log n + k) where n is total keys, k is result count.

        Args:
            prefix: The prefix to search for (case-insensitive).

        Returns:
            List of matching keys in sorted order.
        """
        self._ensure_sorted_keys()
        prefix_lower = prefix.lower()

        # Binary search to find insertion point
        left = bisect.bisect_left(self._sorted_keys, prefix_lower)

        # Collect all keys with matching prefix
        results = []
        for i in range(left, len(self._sorted_keys)):
            key = self._sorted_keys[i]
            if key.startswith(prefix_lower):
                results.append(key)
            else:
                # Sorted order means no more matches possible
                break

        return results

    def get(self, key: str, default: Any = None) -> Any:
        """Delegate to underlying index."""
        return self._index.get(key, default)

    def __contains__(self, key: str) -> bool:
        """Check if key exists in index."""
        return key in self._index

    def __len__(self) -> int:
        """Return number of keys in index."""
        return len(self._index)


class IPRangeIndex:
    """
    Sorted IP index enabling O(log n) range queries for subnet searches.

    IPs are stored as integers for efficient comparison and range queries.
    The sorted list is lazily built and cached.

    Thread-safe for concurrent reads; writes should be coordinated externally.
    """

    def __init__(self, ip_idx: Index):
        self._ip_idx = ip_idx
        self._sorted_ips: Optional[List[int]] = None
        self._version: Optional[int] = None
        self._lock = threading.RLock()

    def _ensure_sorted(self) -> None:
        """Lazily build sorted IP list."""
        current_len = len(self._ip_idx)
        if self._sorted_ips is None or self._version != current_len:
            with self._lock:
                # Double-check after acquiring lock
                if self._sorted_ips is None or self._version != current_len:
                    self._sorted_ips = sorted(int(k) for k in self._ip_idx.keys())
                    self._version = current_len

    def invalidate(self) -> None:
        """Force rebuild of sorted IPs on next access."""
        with self._lock:
            self._sorted_ips = None
            self._version = None

    def search_subnet(
        self, network: ipaddress.IPv4Network
    ) -> List[Tuple[int, Dict[str, Any]]]:
        """
        Find all IPs within the given subnet.

        Complexity: O(log n + k) where n is total IPs, k is result count.

        Args:
            network: The IPv4Network to search within.

        Returns:
            List of (ip_int, entry_dict) tuples for matching IPs.
        """
        self._ensure_sorted()

        start = int(network.network_address)
        end = int(network.broadcast_address)

        # Binary search to find range boundaries
        left = bisect.bisect_left(self._sorted_ips, start)
        right = bisect.bisect_right(self._sorted_ips, end)

        # Collect all IPs in range with their index entries
        results = []
        for i in range(left, right):
            ip_int = self._sorted_ips[i]
            entry = self._ip_idx.get(str(ip_int))
            if entry:
                results.append((ip_int, entry))

        return results

    def search_subnets(
        self, networks: List[ipaddress.IPv4Network]
    ) -> List[Tuple[int, Dict[str, Any], ipaddress.IPv4Network]]:
        """
        Find all IPs within any of the given subnets.

        Args:
            networks: List of IPv4Networks to search within.

        Returns:
            List of (ip_int, entry_dict, matched_network) tuples.
        """
        self._ensure_sorted()
        results = []

        for network in networks:
            start = int(network.network_address)
            end = int(network.broadcast_address)

            left = bisect.bisect_left(self._sorted_ips, start)
            right = bisect.bisect_right(self._sorted_ips, end)

            for i in range(left, right):
                ip_int = self._sorted_ips[i]
                entry = self._ip_idx.get(str(ip_int))
                if entry:
                    results.append((ip_int, entry, network))

        return results

    def get(self, ip_key: str, default: Any = None) -> Any:
        """Delegate to underlying index."""
        return self._ip_idx.get(ip_key, default)

    def __contains__(self, ip_key: str) -> bool:
        """Check if IP key exists in index."""
        return ip_key in self._ip_idx

    def __len__(self) -> int:
        """Return number of IPs in index."""
        return len(self._ip_idx)


# File content cache for search operations
@lru_cache(maxsize=128)
def get_config_lines_cached(filepath: str) -> Tuple[str, ...]:
    """
    Cache recently accessed config file contents.

    Uses LRU eviction with 128 file limit (~50-100MB for typical configs).
    Returns tuple for immutability (required for lru_cache).

    Args:
        filepath: Absolute path to the config file.

    Returns:
        Tuple of lines (with newlines preserved).

    Raises:
        IOError: If file cannot be read.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        return tuple(f.readlines())


def clear_config_cache() -> None:
    """
    Clear the file content cache.

    Call this after indexing completes or when files are known to have changed.
    """
    get_config_lines_cached.cache_clear()


def get_config_cache_info():
    """Return cache statistics for monitoring."""
    return get_config_lines_cached.cache_info()
