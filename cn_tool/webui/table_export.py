"""
Rows per page and the Export CSV / Copy text of the Ping and Monitor tables. Pure: no UI, no request.

A table is exported whole, as filtered and sorted, with the columns it shows. The CSV is what Excel writes (RFC 4180,
``\\r\\n`` rows) in UTF-8 with a byte-order mark: the owner's ruling, because Excel on Windows opens a double-clicked
UTF-8 file without one as ANSI (the one exception to "utf-8 for what cn writes"). The copy is tab-separated, because Excel splits pasted tabs into cells and pastes commas into
one column. A cell that a spreadsheet would run as a formula gets a leading ``'`` (CSV injection), unless it is a
plain number.
"""
import csv
import io
import re

# "All" is a page of at most this many rows: every row of a smaller table, pages of this size beyond it.
MAX_PAGE_ROWS = 1024
ALL = 'all'
PAGE_SIZES = [5, 10, 15, 20, 25, 50, 100, ALL]
# A sheet holds 1,048,576 rows, the header included.
MAX_EXPORT_ROWS = 1_048_575

_FORMULA_START = ('=', '+', '-', '@', '\t', '\r')
_NUMBER = re.compile(r'^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$')


def page_limit(size):
    """The rows a page of ``size`` asks for: ``ALL`` is ``MAX_PAGE_ROWS``."""
    return MAX_PAGE_ROWS if size == ALL else int(size)


def page_size_label(size):
    return f'All (up to {MAX_PAGE_ROWS:,})' if size == ALL else str(size)


def page_size_options():
    """The rows-per-page choices, value to label, for a select."""
    return {size: page_size_label(size) for size in PAGE_SIZES}


def table_columns(rows, order=()):
    """The columns of ``rows``: those of ``order`` that occur, in that order, then the others as they first appear."""
    seen = []
    for row in rows:
        for key in row:
            if key not in seen:
                seen.append(key)
    first = [key for key in order if key in seen]
    return first + [key for key in seen if key not in first]


def safe_cell(value):
    """The cell's text; one that starts like a formula (and is not a plain number, nor a lone ``-``) gets a ``'``."""
    if value is None:
        return ''
    text = str(value)
    if text.startswith(_FORMULA_START) and text != '-' and not _NUMBER.match(text):
        return "'" + text
    return text


def csv_text(columns, rows):
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator='\r\n')
    writer.writerow(columns)
    for row in rows:
        writer.writerow([safe_cell(row.get(column)) for column in columns])
    return buffer.getvalue()


def csv_bytes(columns, rows):
    return csv_text(columns, rows).encode('utf-8-sig')


def _tsv_cell(value):
    return re.sub(r'[\t\r\n]+', ' ', safe_cell(value)) if value is not None else ''


def tsv_text(columns, rows):
    lines = ['\t'.join(_tsv_cell(column) for column in columns)]
    lines += ['\t'.join(_tsv_cell(row.get(column)) for column in columns) for row in rows]
    return '\r\n'.join(lines) + '\r\n'


def export_filename(table, now):
    """``cn-<table>-<yyyymmdd-hhmmss>.csv``."""
    return f"cn-{table}-{now.strftime('%Y%m%d-%H%M%S')}.csv"
