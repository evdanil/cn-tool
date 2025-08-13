import threading
from time import time
from core.base import ScriptContext
from utils.cache import CacheManager
from utils.cache_helpers import mt_index_configurations


def start_background_tasks(ctx: ScriptContext) -> None:
    """
    Initializes and starts all non-blocking background processes for the application.
    """
    if ctx.cfg.get("cache_enabled", False):
        # Initialize the CacheManager instance and attach it to the context
        ctx.cache = CacheManager.get_instance(
            directory=ctx.cfg["cache_directory"],
            logger=ctx.logger
        )
        # Start the cache indexing in a separate thread
        threading.Thread(target=_background_cache_init, args=[ctx], daemon=True).start()


def _background_cache_init(ctx: ScriptContext) -> None:
    """
    Checks the cache state and triggers a re-index if necessary.
    This function is designed to be run in a background thread.
    (Original `background_cache_init` logic)
    """
    logger = ctx.logger
    if not ctx.cache:
        logger.info("Index Cache - Cache does not exist, skipping.")
        return

    cache: CacheManager = ctx.cache

    if cache.dc.get("indexing"):
        logger.info("Index Cache - Another process is already indexing, skipping.")
        return

    updated_time = cache.dc.get("updated", 0)
    if not isinstance(updated_time, (int, float)):
        return

    # Check if the cache was updated recently and if versions match
    if (int(time()) - int(updated_time)) <= 30 and cache.dc.get("version") == ctx.cfg.get("cache_version", None):
        logger.info("Index Cache - State is up-to-date, skipping checks.")
        cache.log_stats("startup-check")
        return

    if cache.dc.get("version") != ctx.cfg["cache_version"]:
        logger.info(f"Index Cache - New cache version {ctx.cfg.get('cache_version', 'Unspecified')} in config.")
        cache.reset_cache()

    logger.info("Index Cache - Starting cache check and potential re-indexing.")
    try:
        mt_index_configurations(ctx)
    except Exception as e:
        logger.error(f"Index Cache - Error during background initialization: {e}", exc_info=True)
        # Ensure the indexing flag is cleared on error
        cache.dc.pop("indexing", None)
