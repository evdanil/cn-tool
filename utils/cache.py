from pathlib import Path
from diskcache import FanoutCache, JSONDisk
from typing import Dict, Optional, Any
import logging

from .config import parse_cache_pages, parse_size


class CacheManager:
    _instance = None

    def __init__(self, directory: Path, logger: logging.Logger, cfg: Optional[Dict[str, Any]] = None):
        if CacheManager._instance is not None:
            raise Exception("This class is a singleton!")

        self.logger = logger
        self.logger.info(f"Initializing CacheManager for directory: {directory}")

        # SQLite memory tuning from config (defaults match schema fallbacks)
        cache_size = parse_cache_pages((cfg or {}).get("cache_sqlite_cache_size", "16M"))
        mmap_size = parse_size((cfg or {}).get("cache_sqlite_mmap_size", "32M"))
        logger.info(f"SQLite tuning: cache_size={cache_size} pages, mmap_size={mmap_size} bytes")

        # Main cache object
        self.dc = FanoutCache(
            directory=str(directory),
            shards=4,
            timeout=1,
            disk=JSONDisk,
            compress_level=6,
            sqlite_cache_size=cache_size,
            sqlite_mmap_size=mmap_size,
        )

        self.dc.check()

        # Index objects
        self.dev_idx = self.dc.index("d_idx")
        self.ip_idx = self.dc.index("i_idx")
        self.kw_idx = self.dc.index("w_idx")
        self.rev_idx = self.dc.index("r_idx")

        # FanoutCache.index() creates separate Cache objects that don't inherit
        # the SQLite tuning from the parent FanoutCache. Apply manually.
        for idx in (self.dev_idx, self.ip_idx, self.kw_idx, self.rev_idx):
            try:
                idx._cache._sql(f'PRAGMA cache_size={cache_size}').fetchall()
                idx._cache._sql(f'PRAGMA mmap_size={mmap_size}').fetchall()
            except Exception:
                pass

        self.log_stats("initialization")
        CacheManager._instance = self

    @classmethod
    def get_instance(cls, directory: Optional[Path] = None, logger: Optional[logging.Logger] = None,
                     cfg: Optional[Dict[str, Any]] = None) -> 'CacheManager':
        """
        Gets the singleton instance of the CacheManager.
        The directory and logger are only required on the first call.
        """
        # If the instance exists, return it immediately.
        if cls._instance:
            return cls._instance

        # If not, create it. First, validate we have the necessary arguments.
        if not directory or not logger:
            raise ValueError("CacheManager must be initialized with a directory and logger on its first call.")

        # The __init__ method will create and assign the instance to cls._instance.
        # This call implicitly handles the assignment.
        return cls(directory, logger, cfg=cfg)

    def log_stats(self, event: str):
        self.logger.info(
            f"Cache Stats ({event}) - "
            f"Version: {self.dc.get('version')}, "
            f"Updated: {self.dc.get('updated', 0)}, "
            f"Devices: {len(self.dev_idx)}, "
            f"IPs: {len(self.ip_idx)}, "
            f"Words: {len(self.kw_idx)}, "
            f"Rev: {len(self.rev_idx)}"
        )

    def reset_cache(self):
        """
        Resets the entire cache, deleting all entries and indexes.
        """
        self.logger.info("Resetting cache...")
        self.dc.clear()
        self.dev_idx.clear()
        self.ip_idx.clear()
        self.kw_idx.clear()
        self.rev_idx.clear()
        self.log_stats("cache_reset")
        self.logger.info("Cache reset complete.")
