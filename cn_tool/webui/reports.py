"""Completed lookup reporting; workbook ownership stays in file_io."""
from dataclasses import dataclass
from pathlib import Path

from cn_tool.utils import file_io


@dataclass(frozen=True)
class ReportStatus:
    state: str
    filename: str = ''
    message: str = ''


def finish_lookup_report(ctx, module, lookup):
    filename = Path(ctx.cfg['report_file']).name if ctx.cfg.get('report_file') else ''
    if not ctx.cfg.get('report_auto_save'):
        return ReportStatus('off', filename, 'Automatic reporting is off. Downloads contain the existing report only.')
    if lookup is None or lookup.stopped:
        return ReportStatus('idle', filename, 'This lookup was not saved.')
    file_io.wait_for_all_saves()
    failures, completed = file_io.save_failures(), file_io.saves_completed()
    try:
        rows = module._collect_save_data(ctx, lookup.grouped, lookup.subnet_data, save_view=lookup.save_view)
        if not rows:
            return ReportStatus('idle', filename, 'No reportable data.')
        module._save_subnet_data(ctx, lookup.query_targets, rows, duid=lookup.duid)
        file_io.wait_for_all_saves()
    except Exception:
        file_io.wait_for_all_saves()
        return ReportStatus('failed', filename, 'Could not save this lookup. Results remain available.')
    if file_io.save_failures() > failures:
        return ReportStatus('failed', filename, 'Could not save this lookup. Results remain available.')
    if file_io.saves_completed() > completed:
        return ReportStatus('saved', filename, 'Report saved.')
    return ReportStatus('idle', filename, 'No report data was written.')


def snapshot_report(ctx, destination):
    """Copy to a caller-created private file, never a browser-selected path."""
    file_io.snapshot_report(ctx, destination)
