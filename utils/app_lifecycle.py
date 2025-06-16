import sys
from core.base import BasePlugin, ScriptContext
from .display import console, get_global_color_scheme
from .file_io import wait_for_all_saves, worker_thread
from .cache import CacheManager


def exit_now(ctx: ScriptContext, all_plugins: list[BasePlugin], exit_code: int = 0, message: str = '') -> None:
    """
    Gracefully exits from application, closing resources and logging the exit reason.
    """
    colors = get_global_color_scheme(ctx.cfg)
    logger = ctx.logger
    cache = ctx.cache

    if worker_thread and worker_thread.is_alive():
        logger.info("Waiting for background save operations to complete...")
        if exit_code == 0:
            with console.status(f"[{colors['success']}]Closing report file... Please do not interrupt...[/]"):
                wait_for_all_saves()
        else:
            # For interruptions, don't show the status spinner, just wait.
            wait_for_all_saves()
        logger.info("All save operations complete.")

    if cache and isinstance(cache, CacheManager):
        logger.info("Closing disk cache...")
        cache.dc.close()
        logger.info("Disk cache closed.")

    if exit_code == 0:
        # Normal exit requested by user (e.g., pressing '0')
        logger.info("Terminating by user request - Have a nice day!")
        console.print(f"[{colors['success']}]Have a nice day![/] :smiley:")
    elif exit_code == 1 and "Interrupted" in message:
        # Specific case for CTRL+C
        logger.warning(f"Abnormal termination: {message}")
        console.print(f"\n[{colors['error']}]{message}[/]")
    else:
        # Any other error exit
        logger.error(f"Abnormal termination: {message}")
        console.print(f"[{colors['error']}]{message}[/]")

    # Disconnect global plugins >>>
    ctx.logger.info("Shutting down application resources...")
    for plugin in all_plugins:
        if plugin.manages_global_connection:
            ctx.logger.info(f"Disconnecting plugin: {plugin.name}")
            plugin.disconnect(ctx)

    sys.exit(exit_code)
