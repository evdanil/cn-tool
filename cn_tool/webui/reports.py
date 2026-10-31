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


def finish_ip_lookup_report(ctx, module, lookup):
    filename = Path(ctx.cfg['report_file']).name if ctx.cfg.get('report_file') else ''
    if not ctx.cfg.get('report_auto_save'):
        return ReportStatus('off', filename, 'Automatic reporting is off. Downloads contain the existing report only.')
    if lookup is None or lookup.stopped:
        return ReportStatus('idle', filename, 'This lookup was not saved.')
    file_io.wait_for_all_saves()
    failures, completed = file_io.save_failures(), file_io.saves_completed()
    try:
        module._save_report(ctx, lookup.prepared.ip_addresses, lookup.processed_data_by_ip, lookup.save_rows)
        file_io.wait_for_all_saves()
    except Exception:
        file_io.wait_for_all_saves()
        return ReportStatus('failed', filename, 'Could not save this lookup. Results remain available.')
    if file_io.save_failures() > failures:
        return ReportStatus('failed', filename, 'Could not save this lookup. Results remain available.')
    if file_io.saves_completed() > completed:
        return ReportStatus('saved', filename, 'Report saved.')
    return ReportStatus('idle', filename, 'No report data was written.')


def snapshot_report(ctx, destination, cancel=None):
    """Copy to a caller-created private file, never a browser-selected path."""
    file_io.snapshot_report(ctx, destination, cancel)


def finish_ping_report(ctx, module, rows):
    filename = Path(ctx.cfg['report_file']).name if ctx.cfg.get('report_file') else ''
    if not ctx.cfg.get('report_auto_save'):
        return ReportStatus('off', filename, 'Automatic reporting is off. Downloads contain the existing report only.')
    if not rows:
        return ReportStatus('idle', filename, 'No reportable data.')
    file_io.wait_for_all_saves()
    failures, completed = file_io.save_failures(), file_io.saves_completed()
    try:
        module._save_report(ctx, rows)
        file_io.wait_for_all_saves()
    except Exception:
        file_io.wait_for_all_saves()
        return ReportStatus('failed', filename, 'Could not save this lookup. Results remain available.')
    if file_io.save_failures() > failures:
        return ReportStatus('failed', filename, 'Could not save this lookup. Results remain available.')
    if file_io.saves_completed() > completed:
        return ReportStatus('saved', filename, 'Report saved.')
    return ReportStatus('idle', filename, 'No report data was written.')


def finish_monitor_report(ctx, module, outcome):
    """Save reportable completed Monitor observations, including after Stop."""
    filename = Path(ctx.cfg['report_file']).name if ctx.cfg.get('report_file') else ''
    if not ctx.cfg.get('report_auto_save'):
        return ReportStatus('off', filename, 'Automatic reporting is off. Downloads contain the existing report only.')
    if outcome is None:
        return ReportStatus('idle', filename, 'No reportable data.')
    file_io.wait_for_all_saves()
    failures, completed = file_io.save_failures(), file_io.saves_completed()
    try:
        rows = module._seen_rows(outcome, 'report')
        if not rows:
            return ReportStatus('idle', filename, 'No reportable data.')
        module._save_report_rows(ctx, rows)
        file_io.wait_for_all_saves()
    except Exception:
        file_io.wait_for_all_saves()
        return ReportStatus('failed', filename, 'Could not save this monitor. Results remain available.')
    if file_io.save_failures() > failures:
        return ReportStatus('failed', filename, 'Could not save this monitor. Results remain available.')
    if file_io.saves_completed() > completed:
        return ReportStatus('saved', filename, 'Report saved.')
    return ReportStatus('idle', filename, 'No report data was written.')


class _ReportLimit(Exception):
    pass


class _ReportBudget:
    """Account for retained text and containers before staging or queueing."""
    def __init__(self):
        self.remaining = 8 * 1024 * 1024
        self.read_remaining = 8 * 1024 * 1024

    def add(self, value):
        if isinstance(value, (list, tuple)):
            self.remaining -= 32 + 8 * len(value)
            if self.remaining < 0:
                raise _ReportLimit
            for item in value:
                self.add(item)
        else:
            text = str(value)
            # UTF-8 can use four bytes per character; reject huge values before encoding.
            if len(text) > self.remaining:
                raise _ReportLimit
            self.remaining -= len(text.encode('utf-8')) + 64
            if self.remaining < 0:
                raise _ReportLimit


def _report_identity(info):
    from cn_tool.modules.config_search import _file_identity
    return _file_identity(info)


def _report_source(path, repo_root, expected):
    """Resolve and compare a source with the identity captured during scanning."""
    if (type(expected) is not tuple or len(expected) != 7 or type(expected[0]) is not str or
            expected[2] == 0 or any(type(value) is not int for value in expected[1:6]) or
            type(expected[6]) is not str or len(expected[6]) != 64 or
            any(c not in '0123456789abcdef' for c in expected[6])):
        raise OSError('Source identity unavailable')
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(repo_root)
    except ValueError as exc:
        raise OSError('Source outside repository') from exc
    if str(resolved) != expected[0] or _report_identity(path.stat()) != expected[1:6]:
        raise OSError('Source changed since scan')
    return resolved


def _read_report_config(path, max_bytes, budget, repo_root, expected):
    """Read only the scanned in-repository file, verifying the opened descriptor."""
    import hashlib
    import os
    import stat
    resolved = _report_source(path, repo_root, expected)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or _report_identity(before) != expected[1:6]:
        raise OSError('Source changed since scan')
    if before.st_size > budget.read_remaining or (before.st_size <= max_bytes and before.st_size > budget.remaining):
        raise _ReportLimit
    with path.open('rb') as stream:
        if _report_identity(os.fstat(stream.fileno())) != expected[1:6]:
            raise OSError('File changed')
        if _report_source(path, repo_root, expected) != resolved:
            raise OSError('File changed')
        raw = None if before.st_size > max_bytes else bytearray()
        digest = hashlib.sha256()
        while True:
            chunk = stream.read(min(65536, budget.read_remaining + 1))
            if not chunk:
                break
            budget.read_remaining -= len(chunk)
            if budget.read_remaining < 0:
                raise _ReportLimit
            digest.update(chunk)
            if raw is not None:
                raw.extend(chunk)
                if len(raw) > max_bytes or len(raw) > budget.remaining:
                    raise _ReportLimit
        if digest.hexdigest() != expected[6]:
            raise OSError('Source content changed since scan')
        if _report_identity(os.fstat(stream.fileno())) != expected[1:6]:
            raise OSError('File changed')
    if _report_source(path, repo_root, expected) != resolved:
        raise OSError('File changed')
    if raw is None:
        return None, before.st_size
    text = raw.decode('utf-8', errors='ignore').replace('\r\n', '\n').replace('\r', '\n')
    lines = []
    start = 0
    while start < len(text):
        end = text.find('\n', start)
        end = len(text) if end < 0 else end + 1
        line = text[start:end]
        if len(line.encode('utf-8')) > 16384:
            raise _ReportLimit
        budget.add(line)
        budget.remaining -= 8
        if budget.remaining < 0:
            raise _ReportLimit
        lines.append(line)
        start = end
    return lines, before.st_size


def _prepare_config_report(ctx, result, site_search, demob_scope=None):
    budget = _ReportBudget()
    repo_root = Path(ctx.cfg['config_repo_directory']).resolve(strict=True)
    tasks = []
    data = result.rows
    search_input = demob_scope.site if demob_scope is not None else str(data[0][0])
    sheet = 'Demob Site Check' if site_search else 'Config Check'
    matched = sorted(result.matched_nets)
    missing = sorted(set(result.networks) - result.matched_nets)
    if matched or missing:
        rows = []
        for network, status in [(net, 'No match') for net in missing] + [(net, 'Used') for net in matched]:
            row = [search_input, str(network), status]
            budget.add(row)
            rows.append(row)
        tasks.append((['Site Code' if site_search else 'Search Terms', 'Subnet', 'Status'], rows,
                      dict(sheet_name=sheet, index=False, force_header=True)))
    rows = []
    devices = set()
    many_devices = False
    verified_sources = set()
    for item in data:
        filename = item[4]
        if filename not in verified_sources:
            _report_source(Path(filename), repo_root, result.source_identities.get(filename))
            verified_sources.add(filename)
        row = [search_input, item[1], f'=HYPERLINK("#\'{item[1]}\'!A{int(item[2]) + 1}", {item[2]})', item[3]]
        budget.add(row)
        rows.append(row)
        if not many_devices:
            devices.add((item[1], item[4]))
            if len(devices) > 50:
                devices.clear()
                many_devices = True
    tasks.append((['Search Terms', 'Device', 'Line number', 'Line'], rows,
                  dict(sheet_name=sheet, index=False, force_header=True)))
    if many_devices:
        # No full files are exported; the summary is the bounded scan-time snapshot.
        return tasks, True
    max_config_tab_kb = int(ctx.cfg.get('report_max_config_tab_kb', 512) or 512)
    max_config_tab_bytes = max(1, max_config_tab_kb) * 1024
    for device, filename in devices:
        if not filename:
            raise OSError('Missing source')
        lines, size = _read_report_config(Path(filename), max_config_tab_bytes, budget, repo_root,
                                          result.source_identities.get(filename))
        if lines is None:
            message = (f'Config omitted: size {round(size / 1024, 1)} KB exceeds '
                       f'limit {max_config_tab_kb} KB. Adjust [report] max_config_tab_kb to include.')
            notice = [[message]]
            budget.add(notice)
            tasks.append((['Notice'], notice, dict(sheet_name=device.upper(), index=False,
                                                   skip_if_exists=True, force_header=True)))
        else:
            tasks.append((None, lines, dict(sheet_name=device.upper(), index=False, skip_if_exists=True)))
    return tasks, False


def finish_config_search_report(ctx, module, result, *, site_search=False, before_write=None, demob_scope=None):
    """Stage a complete bounded report before queuing any writes.

    ``before_write`` atomically decides whether report writing may begin; once
    accepted, queued work is drained and its actual save outcome is returned.
    """
    status = _finish_config_search_report(ctx, module, result, site_search=site_search, before_write=before_write, demob_scope=demob_scope)
    if demob_scope is not None and (demob_scope.status == 'partial_error' or demob_scope.message or demob_scope.notices):
        warning = ' '.join(filter(None, [demob_scope.message, *demob_scope.notices]))
        if not warning:
            warning = 'Subnet discovery was incomplete.'
        return ReportStatus(status.state, status.filename, f'{status.message} {warning}')
    return status


def _finish_config_search_report(ctx, module, result, *, site_search, before_write, demob_scope):
    filename = Path(ctx.cfg['report_file']).name if ctx.cfg.get('report_file') else ''
    if not ctx.cfg.get('report_auto_save'):
        return ReportStatus('off', filename, 'Automatic reporting is off. Reports may contain full device configurations.')
    if (result is None or result.status != 'complete' or not result.rows or
            (demob_scope is not None and demob_scope.status != 'ok')):
        return ReportStatus('idle', filename, 'This search was not saved.')
    try:
        tasks, summary_only = _prepare_config_report(ctx, result, site_search, demob_scope)
    except (_ReportLimit, OSError, ValueError, TypeError, UnicodeError, KeyError, RuntimeError):
        return ReportStatus('failed', filename, 'Could not prepare the report within its limits or read a configuration. No report was queued.')
    file_io.wait_for_all_saves()
    if before_write is not None and not before_write():
        return ReportStatus('idle', filename, 'Stopped search was not saved.')
    failures, completed = file_io.save_failures(), file_io.saves_completed()
    try:
        for columns, rows, options in tasks:
            file_io.queue_save(ctx, columns, rows, **options)
        file_io.wait_for_all_saves()
    except Exception:
        file_io.wait_for_all_saves()
        return ReportStatus('failed', filename, 'Could not save this search. Results remain available.')
    if file_io.save_failures() > failures:
        return ReportStatus('failed', filename, 'Could not save this search. Results remain available.')
    if file_io.saves_completed() > completed:
        message = ('Report saved using scan-time rows; full configuration tabs were omitted for this search because more than 50 devices matched. The workbook may still contain full device configurations from earlier searches.'
                   if summary_only else 'Report saved. It may contain full device configurations.')
        return ReportStatus('saved', filename, message)
    return ReportStatus('idle', filename, 'No report data was written.')
