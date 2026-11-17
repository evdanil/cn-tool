"""The Monitor page's words and cells: what its tables, notices, history lines and forms say, as plain functions.

Nothing here draws: every function takes the session's data (a row, a page, an update, a history item) and returns
text, cell parts, HTML for a table body or a parsed form, so it is tested without a browser. ``monitor.py`` draws
with them and re-exports the names. NiceGUI is not imported here.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
import time

from . import texts
from .ping import parse_ports


def export_too_many(limit):
    return f'The table has more than {limit:,} rows, more than a spreadsheet holds. Filter it, then try again.'


HISTORY_EXPIRED = 'History changed or expired. Return to requests to browse available records.'
# Show Available's own words: the block has no requests list to return to, but a Refresh history that reads it again.
COVERAGE_EXPIRED = 'The history changed while you were reading it. Use Refresh history to read it again.'
COVERAGE_TITLE = 'Available IPs (whole history)'
COVERAGE_MEANING = 'Unseen means it never replied to this machine in the rounds kept. Not tested means no round could test it.'


def history_error_message(error):
    if error == 'too_large':
        return 'This history is too large to sort or filter safely. Reset this view or return to another record.'
    return str(error)


class MonitorFormError(ValueError):
    def __init__(self, field, message):
        self.field = field
        super().__init__(message)


def parse_monitor_form(ports, interval, duration):
    """Parse the seconds fields without accepting locale digits or fractions."""
    def seconds(value, label, optional=False):
        value = value.strip()
        if optional and not value:
            return None
        if not re.fullmatch(r'[0-9]{1,9}', value) or int(value) < 10:
            raise MonitorFormError(label.lower(), f'{label} must be a whole number of at least 10 seconds.')
        return int(value)
    try:
        parsed_ports = parse_ports(ports)
    except ValueError as error:
        raise MonitorFormError('ports', str(error)) from error
    every = seconds(interval, 'Interval')
    until = seconds(duration, 'Duration', optional=True)
    if until is not None and until < every:
        raise MonitorFormError('duration', 'Duration must be at least the interval.')
    return parsed_ports, every, until


@dataclass
class HistoryView:
    kind: str = 'requests'
    parent: object = None
    cursors: list = field(default_factory=lambda: [None])
    ancestors: list = field(default_factory=list)
    view_only: bool = False

    @property
    def cursor(self):
        return self.cursors[-1]

    def next(self, cursor):
        if cursor:
            self.cursors.append(cursor)

    def previous(self):
        if len(self.cursors) > 1:
            self.cursors.pop()

    def refresh(self):
        self.cursors = [None]

    def open(self, kind, parent, *, view_only=None):
        self.ancestors.append((self.kind, self.parent, self.cursors[:], self.view_only))
        self.kind, self.parent, self.cursors = kind, parent, [None]
        if view_only is not None:
            self.view_only = view_only

    def back(self):
        if self.ancestors:
            self.kind, self.parent, self.cursors, self.view_only = self.ancestors.pop()

    def breadcrumbs(self):
        names = {'runs': 'Request', 'rounds': 'Run', 'hosts': 'Round'}
        return ' / '.join(['Requests'] + [f"{names[kind]} {parent}" for kind, parent in
            [(item[0], item[1]) for item in self.ancestors[1:]] + ([(self.kind, self.parent)] if self.kind != 'requests' else [])])

    def reset(self):
        self.kind, self.parent, self.cursors, self.ancestors, self.view_only = 'requests', None, [None], [], False


def live_fields(row):
    tcp = ', '.join(f"{entry['port']}: {entry['result']}" for entry in row.get('tcp', [])) or 'Not checked'
    return [('Host', str(row.get('host') or 'Unknown')), ('Address', str(row.get('address') or 'Unknown')),
            ('Result', str(row.get('result') or 'Unknown')), ('TCP', tcp)]


STATE_LABELS = {'DNS name did not resolve': 'DNS failed', 'Answered on TCP': 'TCP reply'}


def state_tone(text, observation=None):
    return ('ok' if observation in {'!', 'T', 'R'} or text == 'finished' else
            'problem' if observation in {'E', '?', 'U'} or text == 'failed' else
            'warning' if text == 'lost' else '')


def state_cell_parts(text, tone):
    return STATE_LABELS.get(text, text), f'cn-monitor-state {tone}'.strip(), text


# The rows of the three host tables as they show them (``cn_table`` draws, filters by and exports these texts; the
# worker filters by the same words, ``filter_field='any'``).
def live_row(row):
    """A row of the latest round: Target, Result, Address, TCP."""
    return {key.lower(): text for key, text in live_fields(row)}


def round_host_row(row):
    """A host of a saved round: Target, Status (its short words), Address, Probe result."""
    status = history_value('observation', row.get('observation'))
    return dict(host=row.get('host') or 'Unknown host', status=STATE_LABELS.get(status, status),
                address=row.get('address') or '—', result=row.get('result') or '—')


def coverage_row(row):
    """A host of Show Available: Target, Status, First seen, Last seen, Rounds answered, Failed rounds, Note."""
    return dict(host=row['host'], status=row['status'], first_seen=coverage_time(row['first_seen']),
                last_seen=coverage_time(row['last_seen']), answered=coverage_answered(row),
                failed=f"{row['failed']:,}", note=row['note'] or '—')


# What a table of the worker says when it cannot give its rows (``tables.TableUnavailable``).
EXPORT_PREPARING = 'Preparing the table.'
EXPORT_TABLE_CHANGED = 'Stopped because the table changed. Nothing was exported.'
EXPORT_TIMEOUT = 'The table did not answer in time. Try again.'
LIVE_CHANGED = 'The live round changed during the export. Download again.'
LIVE_UNAVAILABLE = 'The latest round is unavailable. Try again.'
ROUND_CHANGED = 'This round changed or was deleted during the export. Download again.'
ROUND_EXPIRED = 'This round changed or was deleted. Refresh history to select an available round.'
ROUND_TOO_LARGE = 'This round is too large to display safely. Select another round.'
COVERAGE_CHANGED = 'The history changed during the export. Use Refresh history, then download again.'
HISTORY_UNAVAILABLE = 'History is unavailable. Try refreshing.'


COVERAGE_TONES = {'Seen': 'ok', 'Unseen': 'warning', 'Not tested': 'problem'}


def coverage_defaults():
    """Show Available's state with the box off and nothing read: also what a reset puts back (the target line is kept
    apart, in ``latest``). The table's own arrangement is a ``tables.TableState`` the page starts again."""
    return dict(coverage_on=False, coverage_page=None, coverage_download=None, coverage_download_error='')


def coverage_download_note(page):
    """What the Download available IPs file holds, beside its button: every Unseen IP of the line, whatever group, sort or
    filter the table shows (``page['counts']`` describe the whole history). Nothing before the history is read."""
    if not page or page.get('error') or 'counts' not in page:
        return ''
    unseen = page['counts']['unseen']
    if not unseen:
        return 'No Unseen IP to download.'
    return f"{unseen:,} Unseen {'IP' if unseen == 1 else 'IPs'}, whatever filter is showing."


def coverage_time(value):
    """A first or last seen time as the history tables show a time, and ``—`` for an IP that never replied."""
    return '—' if value is None else history_value('started', value)


def coverage_answered(item):
    return f"{item['answered']:,} of {item['tested']:,}"


def coverage_summary_line(summary):
    """What the table rests on: the rounds kept for the target line and the day of the oldest."""
    rounds = summary['rounds']
    if not rounds:
        return 'No rounds are kept for this target line.'
    return f"{rounds:,} {'round' if rounds == 1 else 'rounds'} since {coverage_time(summary['since']).split(' ', 1)[0]}"


def coverage_notices(summary):
    """One line for each subnet where no IP ever replied, and a last one when the page could not name them all."""
    from cn_tool.utils.ping_coverage import PAGE_SILENT_SUBNETS

    names = summary['silent_subnets']
    lines = [f'No IP in {name} has ever replied. This machine may not be able to reach it, '
             'so these IPs are untested rather than unused.' for name in names]
    if len(names) >= PAGE_SILENT_SUBNETS:
        lines.append('and possibly more.')
    return lines


def history_run_summary(item):
    status = f"Status: {item.get('status') or 'unknown'}"
    count = item.get('rounds', 0)
    lines = [status, f"Started: {history_value('started', item.get('started'))}",
             f"{count} complete {'round' if count == 1 else 'rounds'}"]
    every = item.get('interval')
    lines.append('One round' if every is None else f'Every {every:g} seconds')
    if item.get('until') is not None:
        lines.append(f"Planned end: {history_value('until', item['until'])}")
    elif every is not None:
        lines.append('No planned end')
    if item.get('ended') is not None:
        lines.append(f"Ended: {history_value('ended', item['ended'])}")
    return lines


def history_template_error(error):
    if error == 'too_large':
        return 'This saved request is too large to load into the form. Enter its targets and ports manually.'
    return 'Saved settings are unavailable. Refresh history and try again.'


def history_template_form(item):
    from math import ceil, isfinite

    every = item.get('interval')
    interval = (str(int(every)) if type(every) in (int, float) and isfinite(every)
                and 10 <= every <= 999999999 and int(every) == every else '')
    duration = ''
    notice = 'Saved settings loaded. Review them before starting.'
    if item.get('until') is not None:
        seconds = item['until'] - item['started']
        if isfinite(seconds) and 10 <= seconds <= 999999999 and interval:
            duration = str(max(int(interval), ceil(seconds)))
            notice = 'Duration is estimated from the saved schedule. Review it before starting.'
        else:
            notice = 'The saved duration could not be restored. Enter a duration or leave it blank to run until stopped.'
    if not interval:
        notice += ' Enter an interval of at least 10 seconds; this run used a different schedule.'
    return ('\n'.join(item['targets']), ', '.join(str(port) for port in item['ports']), interval, duration), notice


def history_value(key, value):
    if key in {'started', 'ended', 'until', 'heartbeat'} and isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except (OverflowError, OSError, ValueError):
            return 'Unknown'
    if key == 'round_seconds':
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value < float('inf'):
            return 'Unknown'
        return f'{value:.1f} s' if value < 9.95 else texts.fmt_duration(value)
    if key == 'observation':
        return {'!': 'Replied', 'R': 'Rejected', 'T': 'Answered on TCP', 'U': 'Unreachable',
                '.': 'No response', 'E': 'Probe error', '?': 'DNS name did not resolve',
                ' ': 'Unknown'}.get(value, 'Unknown')
    return str(value) if value is not None else 'Unknown'


# What a run's Details menu names, in order: the stored key and the words for it.
RUN_DETAILS = (('id', 'Run id'), ('source', 'Source'), ('host', 'Computer'), ('pid', 'Process'),
               ('heartbeat', 'Last heartbeat'), ('round_seconds', 'Round duration'))


def history_run_details(item):
    """The labelled values of a run's Details menu: ``[(label, value)]``, leaving out what the run does not carry."""
    return [(label, history_value(key, item[key])) for key, label in RUN_DETAILS if item.get(key) is not None]


def delete_run_reason(item):
    """Why a run cannot be deleted, in words ('' when it can): the page shows it beside the disabled button."""
    if item.get('status') == 'running':
        return 'A running monitor cannot be deleted.'
    return '' if item.get('request_id') else 'Its saved targets are missing.'


def monitor_warnings(result, outcome):
    """What went wrong after the run. Probe errors are not here: they are the one line ``PROBE_ERRORS``."""
    warnings = []
    hook_error = (outcome.get('details') or {}).get('hook_error')
    if hook_error:
        warnings.append(str(hook_error))
    elif outcome.get('warning_count'):
        warnings.append(f"Monitor completed with {texts.plural(outcome['warning_count'], 'warning')}.")
    return warnings


def moment(epoch, now=None, *, seconds=True):
    """A time of day in UTC, '10:39:50 UTC' ('10:34 UTC' without ``seconds``), with its date in front when that is
    not today's: a time on this page never reads as today's when it is not."""
    stamp = texts.utc_stamp(epoch)
    today = texts.utc_stamp(time.time() if now is None else now)[:10]
    clock = stamp[11:19] if seconds else stamp[11:16]
    return f"{'' if stamp[:10] == today else stamp[:10] + ' '}{clock} UTC"


def monitor_header(update, request, *, active, rounds, hosts=None, started=None, now=None):
    """The line above the live view, in the parts the page draws: ``(round, doing, next_at, facts)``.

    ``round`` is the latest complete round and when it began ('Round 31 · 10:39:50 UTC'). ``doing`` is what a running
    monitor does now: 'next in' while it waits (the page counts down to ``next_at`` in the browser, so nothing is sent
    to keep the clock), else its stage ('probing 120 of 320'); empty for a run that has ended. ``facts`` are the run's
    own: its start, its hosts, its ports and its interval ('since 10:34 UTC · 320 hosts · TCP 22 · every 10 s').

    ``update`` is the run's ``monitor_update`` (None when the session no longer holds this run's), ``request`` the
    summary of what was asked (``active_request``, or the ended attempt's), ``rounds`` the run's complete rounds,
    ``hosts`` the size the page knows and ``started`` the start of a running monitor. Every time is UTC."""
    update, request = update or {}, request or {}
    head = f'Round {texts.fmt_count(rounds)}' if rounds else 'No complete round yet'
    if rounds and update.get('round_at'):
        head += ' · ' + moment(update['round_at'], now)
    doing, next_at = '', 0
    if active:
        stage = str(update.get('stage') or 'starting')
        next_at = update.get('next_at') or 0
        if next_at:
            doing = 'next in'
        elif stage.lower() != 'waiting':
            completed, total = update.get('completed'), update.get('total')
            counted = type(completed) is int and type(total) is int and total > 0
            doing = stage[0].lower() + stage[1:] + (f' {completed:,} of {total:,}' if counted else '')
    ports, every = request.get('tcp_ports') or (), request.get('interval_seconds')
    facts = ['since ' + moment(started, now, seconds=False) if active and started else '',
             texts.plural(hosts, 'host') if hosts else '',
             'TCP ' + ', '.join(str(port) for port in ports) if ports else '',
             'every ' + texts.fmt_duration(every) if every else '']
    return head, doing, next_at, ' · '.join(fact for fact in facts if fact)


def stopped_notice(outcome, meta, rounds, *, showing, probe_failed=False, now=None):
    """The notice of a run that has ended: 'Stopped 10:43:18 UTC after 52 rounds. Showing the last round.'

    ``outcome`` and ``meta`` are the attempt's (``meta['ended_at']`` is when it ended), ``rounds`` its complete
    rounds, and ``showing`` whether the live view still has its last round. A run that reached its planned end
    'Finished'; one with probe errors has the outcome of an error either way, so its own ``stopped`` flag says which."""
    ran_out = outcome.get('kind') == 'matched' or (bool(probe_failed) and outcome.get('stopped') is False)
    ended = (meta or {}).get('ended_at')
    what = ('Finished' if ran_out else 'Stopped') + (' ' + moment(ended, now) if ended else '')
    if not rounds:
        return texts.sentence(what + ' before the first round was complete')
    return texts.sentence(f"{what} after {texts.plural(rounds, 'round')}",
                          'Showing the last round' if showing else 'Its rounds are in History')


def request_form(request):
    """The form's four values (targets, ports, interval, duration) for the last accepted request of this tool
    (``controller.last_request('monitor')``), or None when there is none to show."""
    if not request or 'inputs' not in request:
        return None
    every, lasting = request.get('interval_seconds'), request.get('duration_seconds')
    typed = request.get('typed')
    return (typed if isinstance(typed, str) else '\n'.join(str(line) for line in request['inputs']),
            ', '.join(str(port) for port in request.get('tcp_ports') or ()),
            '' if every is None else str(every), '' if lasting is None else str(lasting))


def live_page_label(page):
    revision = page.get('revision', 0)
    return f'Showing complete round revision {revision}.' if revision else 'Waiting for the first complete round.'


def monitor_summary(data, *, active, previous):
    label = 'Current monitor' if active else 'Previous monitor result' if previous else 'Most recent completed run'
    count = data.get('current_rounds', 0)
    rounds = f"{texts.plural(count, 'complete round')} this run" if count else 'No complete round this run'
    text = f"{label}: {rounds}; {texts.plural(data.get('earlier_rounds', 0), 'earlier round')}."
    skipped = data.get('skipped_slots', 0)
    if skipped:
        text += f' {skipped} starts skipped because a round overran its interval.'
    return text


def request_summary(item):
    def preview(label, values, count):
        text = ', '.join(str(value) for value in values)
        if not text:
            text = 'unavailable' if count is None else 'None'
        if count is None and values:
            text += ' (total unavailable)'
        elif count is not None and count > len(values):
            text += f' (+{count - len(values)} more)'
        return f'{label}: {text}'
    hosts = item.get('host_count')
    return [preview('Targets', item.get('targets_preview') or [], item.get('target_count')),
            preview('TCP ports', item.get('ports_preview') or [], item.get('port_count')),
            f"Hosts: {hosts if hosts is not None else 'unavailable'}"]
