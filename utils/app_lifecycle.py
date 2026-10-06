import sys
from core.base import ScriptContext
from .display import console, get_global_color_scheme
from . import file_io
from .cache import CacheManager


EXIT_INTERRUPTED = 130


def _final_status(exit_code: int, message: str) -> str:
    """
    The session status recorded for an exit.

    The menu reports every problem as exit 1 with a message (Ctrl-C included), while a command-line
    run uses 1 for "no record found" without one; so a message is what makes exit 1 a failure.
    """
    if exit_code == EXIT_INTERRUPTED or (exit_code == 1 and "Interrupted" in message):
        return "interrupted"
    if exit_code == 0 or (exit_code == 1 and not message):
        return "completed"
    return "failed"


def exit_now(ctx: ScriptContext, exit_code: int = 0, message: str = '', *, quiet: bool = False) -> None:
    """
    Gracefully exits from application, closing resources and logging the exit reason.

    ``quiet`` drops only the farewell line; a message, if given, is always printed.
    """
    colors = get_global_color_scheme(ctx.cfg)
    logger = ctx.logger
    cache = ctx.cache
    stats = getattr(ctx, "stats", None)

    final_status = _final_status(exit_code, message)

    # Mark exiting early so any final UI render indicates graceful shutdown
    ctx.cfg["exiting"] = True

    if stats:
        stats.prepare_for_shutdown(final_status)

    if file_io.worker_thread and file_io.worker_thread.is_alive():
        logger.info("Waiting for background save operations to complete...")
        if exit_code == 0:
            with console.status(f"[{colors['success']}]Closing report file... Please do not interrupt...[/]"):
                file_io.wait_for_all_saves()
        else:
            # For interruptions, don't show the status spinner, just wait.
            file_io.wait_for_all_saves()
        logger.info("All save operations complete.")

    if cache and isinstance(cache, CacheManager):
        logger.info("Closing disk cache...")
        # Close Index connections (FanoutCache.close() misses these)
        for idx in (cache.dev_idx, cache.ip_idx, cache.kw_idx, cache.rev_idx):
            try:
                idx._cache.close()
            except Exception:
                pass
        cache.dc.close()
        logger.info("Disk cache closed.")

    if final_status == "completed":
        # Normal exit requested by user (e.g., pressing '0'), or a command-line run that found nothing
        logger.info("Terminating by user request - Have a nice day!")
        if message:
            console.print(f"[{colors['success']}]{message}[/]")
        if exit_code == 0 and not quiet:
            console.print(f"[{colors['success']}]Have a nice day![/]")
    elif final_status == "interrupted":
        # Specific case for CTRL+C
        logger.warning(f"Abnormal termination: {message}")
        if message:
            console.print(f"\n[{colors['error']}]{message}[/]")
    else:
        # Any other error exit
        logger.error(f"Abnormal termination: {message}")
        if message:
            console.print(f"[{colors['error']}]{message}[/]")

    # Disconnect global plugins >>>
    ctx.logger.info("Shutting down application resources...")
    for plugin in ctx.plugins:
        if plugin.manages_global_connection:
            ctx.logger.info(f"Disconnecting plugin: {plugin.name}")
            plugin.disconnect(ctx)

    if stats:
        stats.finalize_session(final_status)
        stats.close()

    sys.exit(exit_code)
