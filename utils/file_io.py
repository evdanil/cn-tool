from datetime import datetime, timedelta
import logging
import os
from pathlib import Path
import zipfile
from queue import Queue
from typing import Any, Dict, List, Optional
from core.base import ScriptContext
import threading
import pandas as pd
import time

from utils.display import get_global_color_scheme

# Adding another thread to save data into xlsx in the background
save_queue: Queue[Dict[str, Any]] = Queue()
save_lock = threading.Lock()
worker_thread: Optional[threading.Thread] = None

# Track how many save operations are currently pending so UI can
# reflect "Generating" until the queue is drained.
_pending_lock = threading.Lock()
_pending_saves: int = 0


def _lock_path_for(report_path: Path) -> Path:
    """Return a filesystem lock path for the given report file."""
    # Put lock next to the report to keep scope intuitive
    return report_path.with_suffix(report_path.suffix + ".lock")


def _acquire_report_lock(report_path: Path, *, timeout: float = 15.0, poll: float = 0.1, logger: Optional[logging.Logger] = None) -> tuple[Optional[int], Optional[Path]]:
    """Attempt to acquire a cross-process lock for the report file.

    Uses atomic lock-file creation. Returns (fd, lock_path) on success, (None, None) on timeout.
    Caller must ensure release via _release_report_lock.
    """
    lock_path = _lock_path_for(report_path)
    start = time.monotonic()
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o644)
            # Optionally write PID for debug/ops visibility
            try:
                os.write(fd, str(os.getpid()).encode())
            except Exception:
                pass
            return fd, lock_path
        except FileExistsError:
            if time.monotonic() - start >= timeout:
                if logger:
                    logger.warning(f"Report lock timeout: unable to acquire lock {lock_path}")
                return None, None
            time.sleep(poll)
        except Exception:
            # On unexpected errors, do not spin forever
            return None, None


def _release_report_lock(fd: Optional[int], lock_path: Optional[Path]) -> None:
    """Release cross-process lock by closing and removing the lock file."""
    try:
        if fd is not None:
            os.close(fd)
    except Exception:
        pass
    try:
        if lock_path is not None:
            os.unlink(str(lock_path))
    except Exception:
        pass


def worker() -> None:
    """
    Thread waiting for data to get saved in a report file.
    """
    global _pending_saves
    file_is_corrupt = False

    while True:
        save_task = save_queue.get()
        if save_task is None:  # Sentinel value to stop the worker
            # Mark this task as done to keep queue counters consistent
            save_queue.task_done()
            break

        if file_is_corrupt:
            # Even if file is corrupt, we must account for the queued task
            # so the pending counter can drain and UI won't get stuck.
            try:
                ctx = None
                if isinstance(save_task, dict) and save_task.get('args'):
                    ctx = save_task['args'][0]
            except Exception:
                ctx = None
            finally:
                with _pending_lock:
                    _pending_saves = max(0, _pending_saves - 1)
                save_queue.task_done()
                continue

        ctx = None  # Initialize ctx to None
        lock_fd: Optional[int] = None
        lock_fp: Optional[Path] = None
        try:
            if save_task['args']:
                ctx = save_task['args'][0]

            # Acquire cross-process report lock to guard Excel writes
            report_path = None
            if ctx and isinstance(ctx, ScriptContext):
                report_path = ctx.cfg.get("report_file")
                if isinstance(report_path, (str, Path)):
                    report_path = Path(report_path).expanduser()
            if isinstance(report_path, Path):
                lock_fd, lock_fp = _acquire_report_lock(report_path, timeout=30.0, logger=getattr(ctx, "logger", None))

            with save_lock:
                append_df_to_excel(*save_task['args'], **save_task['kwargs'])

        except zipfile.BadZipFile as e:
            # Try to auto-repair by deleting the corrupted report and retrying once
            repaired = False
            if ctx:
                ctx.logger.error(f"Failed to write to the report file (likely corrupt): {e}")
                # Ensure we have the same report_path and hold the lock
                report_path = ctx.cfg.get("report_file") if ctx else None
                if isinstance(report_path, (str, Path)):
                    report_path = Path(report_path).expanduser()
                if isinstance(report_path, Path):
                    # If lock wasn't acquired before, try now (short wait)
                    if lock_fd is None or lock_fp is None:
                        lock_fd, lock_fp = _acquire_report_lock(report_path, timeout=10.0, logger=ctx.logger)
                    try:
                        if report_path.exists():
                            ctx.logger.warning(f"Auto-repair: deleting corrupted report at {report_path}")
                            os.unlink(str(report_path))
                        # Retry write once after deletion
                        with save_lock:
                            append_df_to_excel(*save_task['args'], **save_task['kwargs'])
                        repaired = True
                        ctx.console.print("[yellow]Report file was corrupted and has been recreated automatically.[/yellow]")
                        ctx.logger.info("Auto-repair successful: report recreated")
                    except Exception as e2:
                        ctx.logger.error(f"Auto-repair failed: {e2}")

            if not repaired:
                if ctx:
                    ctx.console.print(
                        "\n[bold red]Error:[/bold red] Could not update the report file. "
                        "The file may be corrupt or unreadable. Please delete the report file.\n"
                    )
                    if getattr(ctx, "event_bus", None):
                        ctx.event_bus.publish(
                            "status:update",
                            {"component": "report", "state": "error", "error": str(e)},
                        )
                file_is_corrupt = True

        except Exception as e:
            if ctx:
                ctx.logger.error(f"An unexpected error occurred during the file save operation: {e}", exc_info=True)
                ctx.console.print(f"\n[bold red]Error:[/bold red] An unexpected error occurred while saving the file: {e}")

        finally:
            # Decrement pending saves count and, if it drains to zero,
            # announce completion (unless file is corrupt).
            try:
                with _pending_lock:
                    _pending_saves = max(0, _pending_saves - 1)
                    pending_now = _pending_saves
            finally:
                save_queue.task_done()
                # Always release cross-process lock
                _release_report_lock(lock_fd, lock_fp)
            if pending_now == 0 and not file_is_corrupt and ctx and getattr(ctx, "event_bus", None):
                report_path = ctx.cfg.get("report_file")
                if report_path:
                    ctx.event_bus.publish(
                        "status:report_done",
                        {"path": str(Path(report_path).expanduser())},
                    )


def start_worker() -> None:
    """
    Start the file saving thread
    """
    global worker_thread
    if worker_thread is None or not worker_thread.is_alive():
        worker_thread = threading.Thread(target=worker, daemon=True)
        worker_thread.start()


def stop_worker() -> None:
    """
    Stop the file saving thread (if running) and wait briefly for it to exit.
    A fresh worker will be started automatically on the next queue_save() call.
    """
    global worker_thread
    if worker_thread is not None and worker_thread.is_alive():
        try:
            # Enqueue sentinel to stop the worker after it drains pending tasks
            save_queue.put(None)
            worker_thread.join(timeout=2.0)
        except Exception:
            pass
        finally:
            worker_thread = None


def queue_save(*args: Any, **kwargs: Any) -> None:
    """
    Queing received data for saving thread to process
    """
    global _pending_saves
    start_worker()
    ctx = args[0] if args else None
    first_pending = False
    with _pending_lock:
        first_pending = (_pending_saves == 0)
        _pending_saves += 1
    if first_pending and isinstance(ctx, ScriptContext) and getattr(ctx, "event_bus", None):
        report_path = ctx.cfg.get("report_file")
        payload = {"path": str(Path(report_path).expanduser())} if report_path else None
        ctx.event_bus.publish("status:report_generating", payload)
    save_task = {
        'args': args,
        'kwargs': kwargs
    }
    save_queue.put(save_task)


def wait_for_all_saves() -> None:
    """
    Waiting for all saving tasks to finish here
    """
    save_queue.join()


def saves_in_progress() -> bool:
    """Return True if there are report save operations still pending."""
    with _pending_lock:
        return _pending_saves > 0


def check_file_accessibility(logger: logging.Logger, file_path: Path) -> bool:
    """Check if the file exists and is readable."""
    if not file_path.is_file() or not os.access(file_path, os.R_OK):
        logger.info(f"Unable to read {file_path}")
        return False
    return True


def check_dir_accessibility(logger: logging.Logger, dir_path: Path) -> bool:
    """Check if the directory exists and is readable and accessible"""
    if not dir_path:
        logger.info("Directory is not specified")
        return False
    if not dir_path.is_dir() or not os.access(dir_path, os.R_OK):
        logger.info(f"Unable to access {dir_path}")
        return False
    return True


def check_file_timeliness(logger: logging.Logger, file_path: Path) -> bool:
    """Check if the file's modification time is less than 24 hours ago."""
    try:
        modify_time = datetime.fromtimestamp(file_path.stat().st_mtime)
        if datetime.now() - modify_time > timedelta(hours=24):
            logger.info(f"File {file_path} is older than 24 hours")
            return False
    except OSError:
        return False
    return True


def clear_report(ctx: ScriptContext) -> None:
    """
    Deletes the specified report file or the default report file (report.xlsx).
    """
    colors = get_global_color_scheme(ctx.cfg)
    filename: Path = ctx.cfg["report_file"]
    if filename.exists():
        try:
            # Acquire cross-process lock to safely delete
            fd, lp = _acquire_report_lock(filename, timeout=10.0, logger=ctx.logger)
            try:
                filename.unlink()
            finally:
                _release_report_lock(fd, lp)
            ctx.console.print(f"[{colors['info']}]Report {filename} deleted[/]")
            ctx.logger.info(f"Clear report - Deleted {filename}")
            # Reset the background writer state so future saves resume normally
            stop_worker()
            start_worker()
            if getattr(ctx, "event_bus", None):
                ctx.event_bus.publish(
                    "status:update",
                    {"component": "report", "state": "deleted", "path": str(filename)},
                )
        except OSError as e:
            ctx.console.print(f"[{colors['error']}]Error deleting report {filename}: {e}[/]")
            ctx.logger.error(f"Error deleting report {filename}: {e}")
    else:
        ctx.console.print(f"[{colors['info']}]Report {filename} does not exist.[/]")
        if getattr(ctx, "event_bus", None):
            ctx.event_bus.publish(
                "status:update",
                {"component": "report", "state": "deleted", "path": str(filename)},
            )


def append_df_to_excel(
    ctx: ScriptContext,
    columns: Optional[List[str]],
    raw_data: List[Any],
    sheet_name: str = "Sheet1",
    startrow: int = 0,
    truncate_sheet: bool = False,
    skip_if_exists: bool = False,
    force_header: bool = False,
    **to_excel_kwargs: Any,
) -> None:
    """
    Append a DataFrame [df] to existing Excel file [filename] into [sheet_name] Sheet.
    If [filename] doesn't exist, then this function will create it.

    @param logger(Logger): logger instance.
    @param filename: File path or existing ExcelWriter
                     (Example: '/path/to/file.xlsx')
    @param columns(list): list of column names - headers
    @param raw_data: 2d array with data

    @param sheet_name: Name of sheet which will contain DataFrame.
                       (default: 'Sheet1')
    @param startrow: upper left cell row to dump data frame.
                     Per default (startrow=None) calculate the last row
                     in the existing DF and write to the next row...
    @param truncate_sheet: truncate (remove and recreate) [sheet_name]
                           before writing DataFrame to Excel file
    @param skip_if_exists: if sheet exists, do nothing
    @param force_header: write header no matter what
    @param to_excel_kwargs: arguments which will be passed to `DataFrame.to_excel()`
                            [can be a dictionary]

    @return: None

    Original Author: (c) [MaxU](https://stackoverflow.com/users/5741205/maxu?tab=profile)

    evgeny: - fixed append feature which was not working due to newer pandas version
            - added prepare_df helper function(creates df set)
            - added required parameters to integrate into common codebase
            - minor fixes/checks
    """

    logger = ctx.logger
    filename = ctx.cfg["report_file"]

    def prepare_df(columns: List[str], data: List[List[Any]]) -> pd.DataFrame:
        """
        Helper function prepares Pandas DataFrame
        """
        # Directly create the DataFrame from the raw data and columns.
        # This is the standard, robust way and avoids issues with
        # single-row data when converting to a dictionary first.
        return pd.DataFrame(data, columns=columns)

    df: pd.DataFrame
    #  If columns were provided need to prepare data set, otherwise we have to save data as is
    if columns:
        df = prepare_df(columns, raw_data)
    else:
        df = pd.DataFrame(raw_data)

    # Excel file doesn't exist - saving and exiting
    if not check_file_accessibility(logger, Path(filename)):
        # Log report creation
        logger.info(f"Export - Report {filename} doesn't exist - creating...")
        df.to_excel(
            filename,
            sheet_name=sheet_name,
            startrow=startrow if startrow is not None else 0,
            **to_excel_kwargs,
        )

        # Log success
        logger.info(f"Export - {filename} - created successfully")

        return

    # ignore [engine] parameter if it was passed
    if "engine" in to_excel_kwargs:
        to_excel_kwargs.pop("engine", None)

    # To find out if there is any data in existing file and if it is there how many rows occupied
    existing_data: pd.DataFrame
    try:
        existing_data = pd.read_excel(
            filename, sheet_name=sheet_name, engine="openpyxl"
        )
    # If no sheet in the workbook we get ValueError exception
    except ValueError:
        existing_data = pd.DataFrame()

    filled_rows = len(existing_data)

    if filled_rows > 0 and skip_if_exists:
        return

    if filled_rows > 0 and not truncate_sheet:
        logger.info(
            f"Export - Found {filename} report - Sheet {sheet_name} has {filled_rows} rows"
        )
        # New data will be placed right after last row
        startrow = filled_rows + 1
    elif filled_rows > 0:
        logger.info(
            f"Export - Found {filename} report - Truncating {sheet_name}, adding new data"
        )
        startrow = 0
    else:
        logger.info(
            f"Export - Found {filename} report - No {sheet_name} sheet found, creating..."
        )
        startrow = 0

    with pd.ExcelWriter(
        filename, engine="openpyxl", if_sheet_exists="overlay", mode="a"
    ) as writer:

        header: bool
        # if force_header is set we always write header, otherwise
        # if filled_rows = 0 then we need header, otherwise header is already in the sheet
        # in no columns provided we dont need a header
        if columns and force_header:
            header = True
        elif columns:
            header = not bool(filled_rows)
        else:
            header = False

        # write out the data to the sheet
        df.to_excel(
            writer,
            startrow=startrow,
            header=header,
            sheet_name=sheet_name,
            **to_excel_kwargs,
        )

        # log success
        logger.info(f"Export - Updated {filename} successfully")
