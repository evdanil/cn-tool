from datetime import datetime, timedelta
import logging
import os
from pathlib import Path
from queue import Queue
from typing import Any, Dict, List, Optional
from core.base import ScriptContext
import threading
import pandas as pd

from utils.data_processing import data_to_dict
from utils.display import get_global_color_scheme

# Adding another thread to save data into xlsx in the background
save_queue: Queue[Dict[str, Any]] = Queue()
save_lock = threading.Lock()
worker_thread: Optional[threading.Thread] = None


def worker() -> None:
    """
    Thread waiting for data to get saved in a report file (whatever received as args,kwargs passed into append_df_to_excel)
    """
    while True:
        save_task = save_queue.get()
        if save_task is None:  # Sentinel value to stop the worker
            break
        with save_lock:
            append_df_to_excel(*save_task['args'], **save_task['kwargs'])
        save_queue.task_done()


def start_worker() -> None:
    """
    Start the file saving thread
    """
    global worker_thread
    if worker_thread is None or not worker_thread.is_alive():
        worker_thread = threading.Thread(target=worker, daemon=True)
        worker_thread.start()


def queue_save(*args: Any, **kwargs: Any) -> None:
    """
    Queing received data for saving thread to process
    """
    start_worker()
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
            filename.unlink()
            ctx.console.print(f"[{colors['info']}]Report {filename} deleted[/]")
            ctx.logger.info(f"Clear report - Deleted {filename}")
        except OSError as e:
            ctx.console.print(f"[{colors['error']}]Error deleting report {filename}: {e}[/]")
            ctx.logger.error(f"Error deleting report {filename}: {e}")
    else:
        ctx.console.print(f"[{colors['info']}]Report {filename} does not exist.[/]")


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
        data_to_save = data_to_dict(columns, data)
        data_frame = pd.DataFrame.from_dict(data_to_save)

        return data_frame

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

