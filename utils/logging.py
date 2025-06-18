
import logging
from pathlib import Path
from typing import Optional
import threading


class ThreadSafeFileHandler(logging.FileHandler):
    def __init__(self, filename: str, mode: str = 'a', encoding: Optional[str] = None, delay: bool = False):
        super().__init__(filename, mode, encoding, delay)
        self._lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        with self._lock:
            super().emit(record)


def configure_logging(logfile_location: str, log_level_str: str) -> logging.Logger:
    """
    Sets up logger facility

    @param logfile_location(str): path and filename to write log to
    @param log_level(int): severity level number for log message (logger.[INFO|WARNING|ERROR] and etc)

    @return instance(logger): initialised logger instance.
    """

    log_level_numeric = getattr(logging, log_level_str.upper(), logging.INFO)

    # Create a logger
    logger = logging.getLogger('main')

    # Set the log level
    logger.setLevel(log_level_numeric)

    # Prevent messages from propagating to the root logger if it has handlers
    logger.propagate = False

    # If the logger already has handlers, don't add more. This prevents
    # duplicate log entries if this function is ever called more than once.
    if logger.hasHandlers():
        logger.handlers.clear()

    # Create a file handler
    if not Path(logfile_location).is_file():
        logfile_location = str(Path.home() / "cn.log")

    file_handler = ThreadSafeFileHandler(logfile_location)

    # Create a formatter
    file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    # Add the formatter to the file handler
    file_handler.setFormatter(file_formatter)

    # Add the file handler to the logger
    logger.addHandler(file_handler)

    # Log the successful configuration
    # logger.debug(f"Logger '{logger.name}' configured with level {log_level_str} ({log_level_numeric}) writing to {logfile_location}")

    return logger
