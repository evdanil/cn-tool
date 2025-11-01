import threading
from time import time, sleep
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
        logger.info("Index Cache - Another process is already indexing; will watch and recheck later.")
        threading.Thread(target=_wait_for_indexing_and_recheck, args=[ctx], daemon=True).start()
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
        # Mark resetting so UI doesn't briefly show Ready/0 devices
        try:
            cache.dc.set("indexing", True)
            cache.dc.set("indexing_phase", "resetting")
            cache.dc.set("indexing_started", int(time()))
            cache.dc.set("indexing_last_update", int(time()))
        except Exception:
            pass
        cache.reset_cache()

    logger.info("Index Cache - Starting cache check and potential re-indexing.")
    try:
        mt_index_configurations(ctx)
    except Exception as e:
        logger.error(f"Index Cache - Error during background initialization: {e}", exc_info=True)
        # Ensure the indexing flag is cleared on error
        cache.dc.pop("indexing", None)


def _recheck_and_index_if_needed(ctx: ScriptContext) -> None:
    """
    Re-run the same readiness check and trigger indexing if needed.
    Used when we started while another process was indexing.
    """
    logger = ctx.logger
    cache: CacheManager = ctx.cache  # type: ignore

    if cache.dc.get("version") != ctx.cfg["cache_version"]:
        logger.info("Index Cache - Detected version change during recheck; resetting cache.")
        cache.reset_cache()

    updated_time = cache.dc.get("updated", 0)
    if not isinstance(updated_time, (int, float)):
        updated_time = 0

    if (int(time()) - int(updated_time)) <= 30 and cache.dc.get("version") == ctx.cfg.get("cache_version", None):
        logger.info("Index Cache - State is up-to-date on recheck, skipping.")
        cache.log_stats("post-foreign-index-recheck")
        return

    logger.info("Index Cache - Rechecking cache; starting (re-)index if necessary.")
    try:
        mt_index_configurations(ctx)
    except Exception as e:
        logger.error(f"Index Cache - Error during recheck: {e}", exc_info=True)
        cache.dc.pop("indexing", None)


def _wait_for_indexing_and_recheck(ctx: ScriptContext) -> None:
    """
    Waits for an external indexing to complete or become stale, then rechecks and indexes if needed.
    """
    logger = ctx.logger
    cache: CacheManager = ctx.cache  # type: ignore
    STALE_SECONDS = 180
    POLL_SECONDS = 5

    start_seen = int(cache.dc.get("indexing_started", 0) or 0)
    while True:
        try:
            # If an error was recorded during indexing, stop waiting and surface it
            if cache.dc.get("indexing_error"):
                logger.error("Index Cache - External indexing signaled an error. Rechecking will not start automatically.")
                cache.dc.pop("indexing", None)
                break
            if not cache.dc.get("indexing"):
                logger.info("Index Cache - External indexing finished (flag cleared). Rechecking.")
                break
            last = int(cache.dc.get("indexing_last_update", 0) or 0)
            if (int(time()) - last) > STALE_SECONDS:
                logger.warning("Index Cache - External indexing appears stale; clearing flag and rechecking.")
                cache.dc.pop("indexing", None)
                break
        except Exception:
            # Conservative: break and recheck if we cannot read the flag
            break
        sleep(POLL_SECONDS)

    _recheck_and_index_if_needed(ctx)
