from pathlib import Path
from diskcache import FanoutCache, JSONDisk
from typing import Optional
import logging


class CacheManager:
    _instance = None

    def __init__(self, directory: Path, logger: logging.Logger):
        if CacheManager._instance is not None:
            raise Exception("This class is a singleton!")

        self.logger = logger
        self.logger.info(f"Initializing CacheManager for directory: {directory}")

        # Main cache object
        self.dc = FanoutCache(directory=str(directory), shards=4, timeout=1, disk=JSONDisk, compress_level=6)

        self.dc.check()

        # Index objects
        self.dev_idx = self.dc.index("d_idx")
        self.ip_idx = self.dc.index("i_idx")
        self.kw_idx = self.dc.index("w_idx")
        self.rev_idx = self.dc.index("r_idx")

        self.log_stats("initialization")
        CacheManager._instance = self

    @classmethod
    def get_instance(cls, directory: Optional[Path] = None, logger: Optional[logging.Logger] = None) -> 'CacheManager':
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
        return cls(directory, logger)

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
