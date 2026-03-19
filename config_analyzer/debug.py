import logging
import os
from typing import Optional


_LOGGER: Optional[logging.Logger] = None


def _debug_enabled() -> bool:
    level_env = os.environ.get("CONFIG_ANALYZER_DEBUG", "0").lower()
    return level_env in {"1", "true", "yes", "on", "debug"}


def get_logger(name: str = "config_analyzer") -> logging.Logger:
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER.getChild(name)

    debug_enabled = _debug_enabled()
    level = logging.DEBUG if debug_enabled else logging.INFO

    main_logger = logging.getLogger("main")
    if main_logger.handlers:
        # Inherit the 'main' logger configuration/handlers. Do not override
        # to INFO which would suppress DEBUG if main is DEBUG.
        logger = main_logger.getChild("config_analyzer")
        # Inherit parent's effective level unless explicit debug override
        if debug_enabled:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.NOTSET)
        # If main is configured at INFO and we want DEBUG, attach our own
        # file handler to capture debug logs without altering main.
        if debug_enabled:
            log_path = os.environ.get("CONFIG_ANALYZER_LOG")
            if not log_path:
                log_path = os.path.join(os.getcwd(), "tui_debug.log")
            try:
                fh = logging.FileHandler(log_path, encoding="utf-8")
                fh.setLevel(logging.DEBUG)
                fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
                fh.setFormatter(fmt)
                logger.addHandler(fh)
            except OSError:
                pass
        _LOGGER = logger
        return logger.getChild(name)

    logger = logging.getLogger("config_analyzer")
    # If no 'main' logger, configure our own handler. Use DEBUG only when
    # explicitly enabled; otherwise default to INFO for local file handler.
    logger.setLevel(level)

    if logger.handlers:
        _LOGGER = logger
        return logger.getChild(name)

    root_logger = logging.getLogger()
    if root_logger.handlers:
        _LOGGER = logger
        return logger.getChild(name)

    log_path = os.environ.get("CONFIG_ANALYZER_LOG")
    if log_path:
        log_path = os.path.expanduser(log_path)
    elif debug_enabled:
        log_path = os.path.join(os.getcwd(), "tui_debug.log")

    handler_added = False
    if log_path:
        try:
            fh = logging.FileHandler(log_path, encoding="utf-8")
        except OSError as exc:
            stream_handler = logging.StreamHandler()
            stream_handler.setLevel(level)
            fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
            stream_handler.setFormatter(fmt)
            logger.addHandler(stream_handler)
            handler_added = True
            logger.warning(
                "Failed to create log file '%s': %s. Falling back to standard error.",
                log_path,
                exc,
            )
        else:
            fh.setLevel(level)
            fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
            fh.setFormatter(fmt)
            logger.addHandler(fh)
            handler_added = True

    if not handler_added:
        logger.addHandler(logging.NullHandler())

    _LOGGER = logger
    return logger.getChild(name)

