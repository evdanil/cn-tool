"""Words and numbers the web pages share (pure: no NiceGUI import).

Plan: `docs/plans/webui-ux-plan.md` section 3.1. The sentences about the running job are here: the banner of a page
that does not own it (`job_notice`), the header's indicator (`job_indicator`), the page's status line (`own_status`),
the toast when it ends elsewhere (`job_ended_notice`) and what Quit will do to it (`quit_warning`). Each reads a
`SessionSnapshot` and nothing else. The report has two voices: the header's Report menu says what the shared
workbook is (`report_menu_line`, `REPORT_DOWNLOAD_HELP`), and a page says only what its own latest attempt did to it
(`attempt_report_note`).
"""
from __future__ import annotations

import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone


def fmt_count(n: int) -> str:
    return f'{int(n):,}'


def fmt_duration(seconds: float) -> str:
    """At most two units: '59 s', '4 min 20 s', '1 h 1 min', '1 d 1 h'."""
    total = max(0, int(round(seconds)))
    parts = []
    for size, unit in ((86400, 'd'), (3600, 'h'), (60, 'min'), (1, 's')):
        amount, total = divmod(total, size)
        if amount or (not parts and size == 1):
            parts.append(f'{amount} {unit}')
        if len(parts) == 2 or (parts and not total):
            break
    return ' '.join(parts)


def plural(n: int, one: str, many: str | None = None) -> str:
    return f'{fmt_count(n)} {one if n == 1 else (many if many is not None else one + "s")}'


def _stopped(part: str) -> str:
    part = part.strip()
    if not part:
        return ''
    if part.endswith(('…', '...', '!', '?')):
        return part
    return part.rstrip('.') + '.'


def sentence(*parts: str) -> str:
    return ' '.join(text for text in map(_stopped, parts) if text)


def utc_time(epoch: float) -> str:
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime('%H:%M:%S UTC')


def utc_stamp(epoch: float) -> str:
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def counts_line(pairs: Iterable[tuple[int, str, str]]) -> str:
    return ' · '.join(plural(n, one, many) for n, one, many in pairs if n)


TOOL_NAMES = {'subnet': 'Subnets lookup', 'ip': 'IP lookup', 'ping': 'Ping', 'monitor': 'Monitor',
              'config_search': 'Configuration search', 'demob': 'Site check'}


@dataclass(frozen=True)
class JobNotice:
    text: str
    route: str
    link_label: str


@dataclass(frozen=True)
class QuitWarning:
    title: str
    lines: tuple[str, ...]
    confirm_label: str
    # What the lines are about, one key each ('job:monitor', 'saving', 'download', 'deleting', 'unsaved'), without
    # the numbers: a caller compares two warnings by these to see whether something new would be lost.
    facts: tuple[str, ...] = ()


# The page of each tool: its route and its name in the navigation (`shell.PAGES`; a test holds the two together).
TOOL_PAGES = {'subnet': ('/', 'Subnets'), 'ip': ('/ip', 'IP'), 'ping': ('/ping', 'Ping'), 'monitor': ('/monitor', 'Monitor'),
              'config_search': ('/config-search', 'Configuration Search'), 'demob': ('/demobilization', 'Site Demobilization')}

# A job in mid-sentence: "A Ping is running", "the report of the Ping".
_A_JOB = {'subnet': 'A Subnets lookup', 'ip': 'An IP lookup', 'ping': 'A Ping', 'monitor': 'A monitor',
          'config_search': 'A configuration search', 'demob': 'A site check'}
_THE_JOB = {'subnet': 'the Subnets lookup', 'ip': 'the IP lookup', 'ping': 'the Ping', 'monitor': 'the Monitor',
            'config_search': 'the configuration search', 'demob': 'the site check'}
_FIRST_STAGE = {'subnet': 'looking up', 'ip': 'looking up', 'ping': 'starting', 'monitor': 'starting',
                'config_search': 'searching configurations', 'demob': 'checking the site'}

# One word first on every page, the job after it. The Monitor's says "this session's": History lists the monitors of
# other processes too, and this control ends only the one this session started.
STOP_LABELS = {'subnet': 'Stop lookup', 'ip': 'Stop lookup', 'ping': 'Stop Ping', 'monitor': 'Stop this session’s monitor',
               'config_search': 'Stop search', 'demob': 'Stop site check'}

EXIT_ACTIONS = 'Then the configured exit actions run (for example the report e-mail) and the application closes.'
# What Quit does, for the shell's help: the same facts the confirmation gives one at a time.
QUIT_HELP = (
    'Closing this tab keeps cn-tool running; only Quit application ends it.',
    'Quit lets a running Subnets, IP or Ping lookup finish and saves it. A Monitor, a configuration search or a site '
    'check is stopped: the Monitor saves what it has, the other two save nothing.',
    EXIT_ACTIONS,
)

_ENDING = {'closing', 'closed', 'failed'}


def _job(state) -> str | None:
    """The tool whose job runs, stops or saves now; None when none does or the application is ending."""
    if state is None or state.phase in _ENDING or not state.active_job_id:
        return None
    return state.active_lookup_type if state.active_lookup_type in TOOL_NAMES else None


def _progress(state, tool):
    """(stage, completed, total) of the running job. A Monitor's come from its own update."""
    update = state.monitor_update if tool == 'monitor' else None
    if update:
        return update.get('stage') or '', update.get('completed'), update.get('total')
    return state.progress_stage or '', state.progress_completed, state.progress_total


def _counted(completed, total) -> bool:
    return type(completed) is int and type(total) is int and total > 0


def job_size(state) -> int | None:
    """How many hosts the running Ping or Monitor probes. A Monitor's update says it all the time (``hosts``, 0
    until the run knows); a Ping's count is known only while it probes, so a caller remembers it."""
    tool = _job(state)
    if tool not in ('ping', 'monitor'):
        return None
    if tool == 'monitor':
        known = (state.monitor_update or {}).get('hosts')
        if type(known) is int and known > 0:
            return known
    stage, completed, total = _progress(state, tool)
    return total if stage == 'probing' and _counted(completed, total) else None


def _round(state) -> int:
    """The Monitor's round in progress, or the one just completed while it waits for the next."""
    update = state.monitor_update or {}
    done = update.get('current_rounds') or 0
    return done if update.get('stage') == 'waiting' and done else done + 1


def _since(started, now) -> str:
    if not started:
        return ''
    day, today = utc_stamp(started)[:10], utc_stamp(time.time() if now is None else now)[:10]
    return f"since {day + ' ' if day != today else ''}{utc_time(started)[:5]} UTC"


# Two jobs can run (R3-03): a lookup makes the other lookups wait, and the Monitor is not one of the tools it holds back.
WAIT_FINISHES = 'Other lookups wait until it finishes'


def job_notice(state, *, page: str, hosts: int | None = None, now: float | None = None) -> JobNotice | None:
    """The banner of page ``page`` for a one-shot job it does not own, or None (a Monitor never has one: it makes
    nobody wait, and the indicator names it). ``hosts`` is the size the caller remembers
    (`job_size`) for the moments the snapshot does not carry it; ``now`` only decides whether the start needs a date."""
    if state is not None and state.phase not in _ENDING and state.report_delete_pending:
        return JobNotice('The report is being deleted. Tools wait until it finishes.', '', '')
    tool = _job(state)
    # A Monitor makes no tool wait (R3-03, plan 5.7): its place is the header's indicator, never a banner.
    if tool is None or tool == 'monitor' or tool == page or state.phase not in {'running', 'stopping', 'saving'}:
        return None
    name, (route, label) = TOOL_NAMES[tool], TOOL_PAGES[tool]
    if state.phase == 'saving':
        text = sentence(f'The report of {_THE_JOB[tool]} is being saved', WAIT_FINISHES)
    elif state.phase == 'stopping':
        text = sentence(f'{name} is stopping', 'Other lookups wait until it has stopped')
    else:
        # The banner is a live region (role=status): it names the job's size and start, which stand still. What
        # moves (a Ping's hosts probed, a Monitor's round) is in the header's pill, which announces nothing.
        size = (job_size(state) or hosts) if tool == 'ping' else None
        since = _since(state.active_started_at, now)
        running = (f"{name} is running: {', '.join([plural(size, 'host')] + ([since] if since else []))}" if size
                   else f'{name} is running {since}'.rstrip())
        text = sentence(running, WAIT_FINISHES)
    return JobNotice(text, route, f'Open {label}')


def job_indicator(state) -> JobNotice | None:
    """The header's pill while a job runs: a few words and the page of the tool that owns it."""
    tool = _job(state)
    if tool is None or state.phase not in {'running', 'stopping', 'saving'}:
        return None
    name, (route, label) = TOOL_NAMES[tool], TOOL_PAGES[tool]
    if state.phase == 'saving' and state.save_waiting:
        detail = 'waiting to save'  # another job holds the report gate (plan 5.9)
    elif state.phase != 'running':
        detail = state.phase
    elif tool == 'monitor':
        detail = f'round {_round(state)}'
    elif job_size(state):
        detail = f'{fmt_count(state.progress_completed)} of {fmt_count(state.progress_total)}'
    else:
        detail = ''
    return JobNotice(f'{name} · {detail}' if detail else name, route, label)


INDICATOR_STOP = 'Stop…'  # the indicator's button: it asks before it stops (``stop_warning``), hence the dots
_SHORT_STOP = {'subnet': 'lookup', 'ip': 'lookup', 'ping': 'Ping', 'monitor': 'Monitor', 'config_search': 'search',
               'demob': 'site check'}


def indicator_stop_label(tool: str) -> str:
    """The name of the indicator's Stop button for a screen reader: it says which job, as the dots cannot."""
    return f'Stop {TOOL_NAMES[tool]}…'


def stop_warning(state, *, hosts: int | None = None) -> QuitWarning | None:
    """The question the indicator's Stop… asks about the job in ``state`` (one slot's view), or None when that job
    cannot be stopped now (it is not running). A stop outside the page that owns the job asks first (B2)."""
    from .job_slots import stoppable

    tool = _job(state)
    if tool is None or not stoppable(state):
        return None
    if state.phase == 'saving':  # a one-shot job that waits for the report gate
        lines = (f'{_A_JOB[tool]} is waiting to save its report.', 'Stop ends it. It is not saved.')
    elif tool == 'monitor':
        size, rounds = job_size(state) or hosts, (state.monitor_update or {}).get('current_rounds') or 0
        counts = ', '.join(([plural(size, 'host')] if size else []) + ([plural(rounds, 'round')] if rounds else []))
        lines = (sentence('The Monitor is running' + (f': {counts}' if counts else '')),
                 'Stop ends it once the probes in flight have finished, and saves what it has.')
    elif tool in ('config_search', 'demob'):
        lines = (f'{_A_JOB[tool]} is running.', 'Stop ends it. Its results are not saved.')
    else:
        lines = (f'{_A_JOB[tool]} is running.', 'Stop ends it. A stopped lookup is not saved to the report.')
    return QuitWarning(f'Stop {_THE_JOB[tool]}?', lines, f'Stop {_SHORT_STOP[tool]}', (f'stop:{tool}:{state.active_job_id}',))


def stop_too_late(tool: str) -> str:
    """What the indicator's Stop… says when the job ended while the question was open ("The Monitor had already ended.")."""
    return sentence(f'{_THE_JOB[tool][0].upper()}{_THE_JOB[tool][1:]} had already ended')


def job_ended_notice(tool: str, *, hosts: int | None = None, stopped: bool = False) -> str:
    """The toast on a page that did not own the job: "Ping finished: 1,024 hosts. Open Ping."."""
    name, label = TOOL_NAMES[tool], TOOL_PAGES[tool][1]
    if tool == 'monitor' or stopped:
        return sentence(f'{name} stopped', f'Open {label}')
    return sentence(f"{name} finished{': ' + plural(hosts, 'host') if hosts else ''}", f'Open {label}')


def _error_text(error) -> str:
    return str(error.get('message', error) if isinstance(error, dict) else error)


def own_status(state, *, page: str) -> str:
    """The status line of page ``page``: its own job in words, or that it waits for another's (the banner names it)."""
    if state is None:
        return 'Ready'
    # The end of the session has its own card, which carries the reason: the line under it only names the state.
    ended = {'closing': 'Finishing…', 'closed': 'cn-tool has quit.', 'failed': 'cn-tool stopped unexpectedly.'}
    if state.phase in ended:
        return ended[state.phase]
    if state.error:
        return _error_text(state.error)
    fixed = {'starting': 'Checking configuration and credentials…', 'setup_required': 'Setup required.'}
    if state.phase in fixed:
        return fixed[state.phase]
    tool = _job(state)
    if tool is None:
        if state.report_delete_pending:
            return 'Waiting: the report is being deleted'
        return 'Ready' if state.phase == 'ready' else str(state.phase)
    if tool != page:
        if state.phase == 'saving':
            return 'Waiting: a report is being saved'
        return f"Waiting: {TOOL_NAMES[tool]} is {'stopping' if state.phase == 'stopping' else 'running'}"
    if state.phase == 'saving':
        return 'Waiting to save the report…' if state.save_waiting else 'Saving the report…'
    if state.phase == 'stopping':
        return 'Stopping… waiting for probes to finish' if tool in ('ping', 'monitor') else 'Stopping…'
    stage, completed, total = _progress(state, tool)
    stage = stage or _FIRST_STAGE[tool]
    if tool == 'monitor' and stage == 'waiting':
        return 'Running: waiting for the next round'
    if stage[1:2].islower():  # "Fetching IP information" reads on after the colon; an acronym keeps its capitals
        stage = stage[0].lower() + stage[1:]
    counts = f' {fmt_count(completed)} of {fmt_count(total)}' if _counted(completed, total) else ''
    return f'Running: {stage}{counts}'


def quit_warning(state, *, unsaved: bool = False, hosts: int | None = None) -> QuitWarning | None:
    """What Quit would end or wait for, one line per fact, or None when it can close at once.

    ``unsaved`` is the Settings page's own fact; ``hosts`` is the Monitor's size as the caller remembers it. A job's
    fact names the job itself, not only its tool: an answer given for one run is not an answer for the next."""
    from .job_slots import running_views

    lines, facts = [], []
    # Each slot's job (the one-shot job, then the Monitor: R3-03); a job that saves is said once, as "a report".
    jobs = [(view, _job(view)) for view in running_views(state) if _job(view) is not None]
    if any(view.phase == 'saving' for view, _ in jobs):
        lines.append('A report is being saved. Quit waits for it.')
        facts.append('saving')
    for view, tool in jobs:
        if view.phase == 'saving':
            continue
        if tool == 'monitor':
            size, rounds = job_size(view) or hosts, (view.monitor_update or {}).get('current_rounds') or 0
            counts = ', '.join(([plural(size, 'host')] if size else []) + ([plural(rounds, 'round')] if rounds else []))
            lines.append(sentence('A monitor is running' + (f': {counts}' if counts else ''),
                                  'Quit stops it and saves what it has'))
        elif tool in ('config_search', 'demob'):
            lines.append(f'{_A_JOB[tool]} is running. Quit stops it; its results are not saved.')
        else:
            lines.append(f'{_A_JOB[tool]} is running. Quit waits for it to finish and saves it.')
        facts.append(f'job:{tool}:{view.active_job_id}')
    if state is not None and state.phase not in _ENDING:
        if state.report_snapshot_pending:
            lines.append('A report download is being prepared. Quit cancels it.')
            facts.append('download')
        if state.report_delete_pending:
            lines.append('The report is being deleted. Quit cancels the deletion if it has not finished.')
            facts.append('deleting')
    if unsaved:
        lines.append('Unsaved settings changes will be lost.')
        facts.append('unsaved')
    if not lines:
        return None
    return QuitWarning('Quit cn-tool?', (*lines, EXIT_ACTIONS), 'Quit', tuple(facts))


_DOING = {'running': 'is running', 'stopping': 'is stopping', 'saving': 'is saving its report'}


def busy_reason(state) -> str:
    """Why nothing that needs a quiet session can start now, in words that name the jobs ("Ping is running and Monitor
    is stopping."), or '' when nothing says it. The Report menu's Delete report and Settings' Use the new settings now
    give it as their visible reason, and the controller's refusals begin with it."""
    from .job_slots import running_views

    if state is None or state.phase in _ENDING:
        return ''
    parts = [f"{TOOL_NAMES[tool]} {'is waiting to save its report' if view.save_waiting and view.phase == 'saving' else _DOING[view.phase]}"
             for view in running_views(state) if (tool := _job(view)) is not None and view.phase in _DOING]
    text = sentence(' and '.join(parts)) if parts else ''
    if state.report_snapshot_pending:
        text = sentence(text, 'A report download is being prepared')
    if state.report_delete_pending:
        text = sentence(text, 'The report is being deleted')
    return text


_JOBS_IN_THE_WAY = re.compile(r' is (running|stopping|saving|waiting)')


def _unavailable(state, what, jobs, download) -> str:
    """``what`` waits: the jobs that are in the way, or a download in preparation; nothing while a deletion runs (the
    status line already says "Deleting report…")."""
    if state is None or state.report_delete_pending:
        return ''
    reason = busy_reason(state)
    if not reason:
        return ''
    return sentence(reason, f'{what} is available once {jobs if _JOBS_IN_THE_WAY.search(reason) else download}')


def delete_unavailable(state) -> str:
    """The visible reason beside Delete report… while it is off because work runs; '' when work is not the reason."""
    return _unavailable(state, 'Delete report', 'nothing is running or saving', 'the download is ready')


def reload_unavailable(state) -> str:
    """The visible reason beside Settings' Use the new settings now while work runs; '' when it is not the reason."""
    return _unavailable(state, 'Use the new settings now', 'nothing is running', 'the download is ready')


def reload_refusal(state) -> str:
    """The controller's refusal of a reload while work runs: the reason, then the rule."""
    return sentence(busy_reason(state), 'The settings can be reloaded when no work is running',
                    'Try again when it finishes')


# Clear results (every one-shot page, and the Monitor once it has stopped): the page forgets its result and outcome.
CLEAR_RESULTS = 'Clear results'
CLEAR_HELP = 'Clears this page. The report keeps what was saved.'
RESULTS_CLEARED = 'Results cleared.'
NOT_CLEARED = 'Not cleared: the results changed.'
CLEARED_ELSEWHERE = 'Results were cleared in another tab.'


REPORT_DOWNLOAD_HELP = 'Download copies the report as it is once pending saves have finished.'


def _saving(state) -> bool:
    # A stopped Monitor always saves its rounds and stays `stopping` until it ends; a stopped one-shot job is not saved.
    return state.phase == 'saving' or state.monitor_phase in {'stopping', 'saving'}


def report_menu_line(state) -> str:
    """The Report menu's one line about the shared workbook: its name and whether it holds data, "No report yet" or
    "Reporting is off". It says nothing about any one tool's run (the pages' `attempt_report_note` does)."""
    if state is None:
        return 'The report is not known yet'
    report = state.report_state or {}
    kind, name, available = report.get('state'), report.get('filename') or '', report.get('available') is True
    # The workbook's state is the latest event's of either slot, so it cannot say that a save is on: the slots' own
    # phases do (a Monitor's end can overwrite the state while a lookup still saves).
    busy = _saving(state)
    saving = ' · a save is in progress' if busy else ''
    if not busy and kind != 'off' and state.monitor_phase == 'running':
        saving = ' · the Monitor is saved when it stops'  # a Monitor writes its rounds at its end, not round by round
    if available:
        if kind == 'off':
            return f'Reporting is off · {name} contains earlier data' if name else 'Reporting is off · the report contains earlier data'
        if not name:
            return 'The report contains earlier data' + saving
        latest = kind == 'saved' and report.get('saved_for_attempt') and not busy
        return f"{name} · {'includes the latest run' if latest else 'contains earlier data'}{saving}"
    if kind == 'off':
        return 'Reporting is off'
    if state.phase in {'starting', 'setup_required', 'closing', 'closed', 'failed'} and kind != 'deleted':
        return 'The report is not known yet'
    return 'No report yet' + saving


def attempt_report_note(report_state: dict | None, current: dict | None = None) -> str:
    """What a page says, inside its outcome, about the report: nothing when no save was due (reporting off, nothing to
    write, the tool has not run, the save has not finished), "Saved to the report." after a save and "Not saved: <reason>."
    when a save was due and did not happen. ``report_state`` is the page's own latest attempt, never another tool's;
    ``current`` is the workbook's (``SessionSnapshot.report_state``): once it has been deleted, an earlier save is no
    longer in it, so the page stops saying so."""
    report = report_state or {}
    kind, message = report.get('state'), str(report.get('message') or '').strip()
    if kind == 'saved':
        gone = (current or {}).get('state') == 'deleted' and not (current or {}).get('available')
        return '' if gone else 'Saved to the report.'
    if kind == 'failed':
        if not message:
            return 'Not saved.'
        # "Could not save this lookup." reads on after the colon; an acronym keeps its capitals ("ICMP not allowed")
        if message[1:2].islower() or message[1:2] == ' ':
            message = message[0].lower() + message[1:]
        return sentence('Not saved: ' + message)
    if kind == 'idle' and 'not saved' in message.lower():
        return sentence(message)  # it already says what was not saved and why
    return ''


# --- a typed password that Infoblox refused ---------------------------------------------------------------------------

def password_refused(username='') -> str:
    """The outcome of a lookup whose typed password Infoblox answered with 401: the login was dropped, so the same
    lookup started again asks again ("Sign in again")."""
    name = str(username or '').strip()
    return f'Infoblox did not accept the password for {name}.' if name else 'Infoblox did not accept the password.'


def refused_password(error, username=''):
    """The worker's exception for it: ``error`` (its ``SetupRequired``) with `password_refused`'s sentence, marked so
    that the job's ``error`` message carries ``sign_in_again`` (never recognised by its words)."""
    refusal = error(password_refused(username))
    refusal.sign_in_again = True
    return refusal


def sign_in_again(outcome) -> bool:
    """Whether an attempt's ``outcome`` offers "Sign in again": the worker said so (``sign_in_again``), and no later
    sign-in of the session has succeeded since (the controller then drops the mark)."""
    return isinstance(outcome, dict) and outcome.get('sign_in_again') is True


# --- The Monitor's change feed (plan 7.4, R3-08) --------------------------------------------------------------------
# Words come from the Map's own table (`monitor_map.STATE_WORDS`), cut at their bracket: a list line is short, the Map's
# popup gives the long form. "Went to no answer" is "the state after the change is not one of `ANSWERS`".
TITLE_COUNT = '({count}↓) {title}'  # the page script formats the same template (it is given this text)
TITLE_COUNT_MAX = 99


def state_word(char: str) -> str:
    from .monitor_map import STATE_WORDS
    return STATE_WORDS.get(char, 'unknown').split(' (')[0]


def change_words(before: str, after: str) -> str:
    return f'{state_word(before)} → {state_word(after)}'


def change_host(entry) -> str:
    host, address = entry['host'], entry['address']
    return f'{host} ({address})' if address and address != host else host


def change_line(entry) -> str:
    return ' · '.join((utc_time(entry['at']), change_host(entry), change_words(entry['before'], entry['after'])))


LOST = 'x.U'    # a host that answered and now does not: gone, silent or unreachable
UNPROBED = 'E?'  # the probe failed, or the name did not resolve: no evidence about the host


def went_silent(entry) -> bool:
    """The title's down count: a real loss of answer. A probe error or an unresolved name is not an outage."""
    return entry['after'] in LOST


def gap_line(count: int) -> str:
    from .protocol import CHANGES_KEPT
    return f"{plural(count, 'change is', 'changes are')} not available: the list keeps the last {CHANGES_KEPT}."


def round_changes(count: int, exact: bool = True) -> str:
    if not count:
        return ''
    return f"{'' if exact else 'At least '}{plural(count, 'change')} in the latest round."


def changes_count(count: int) -> str:
    """The closed section's line: how many changes the run has had (those the list holds and those it let go)."""
    return plural(count, 'change') if count else ''


def notification_text(entries, total: int | None = None) -> str:
    """One round's notification: counts only, no host names. ``total``: how many hosts changed (the feed's number,
    which includes changes it let go of); ``entries`` are the ones it still has and give the breakdown."""
    from .monitor_map import ANSWERS
    total = len(entries) if total is None else max(total, len(entries))
    stopped = sum(1 for e in entries if e['after'] in LOST and e['before'] in ANSWERS)
    unprobed = sum(1 for e in entries if e['after'] in UNPROBED)
    again = sum(1 for e in entries if e['before'] not in ANSWERS and e['after'] in ANSWERS)
    unlisted = total - len(entries)
    other = len(entries) - stopped - unprobed - again
    parts = [part for part in (
        f'{fmt_count(stopped)} stopped answering' if stopped else '',
        f"{fmt_count(again)} {'answers' if again == 1 else 'answer'} again" if again else '',
        f"{fmt_count(unprobed)} could not be probed" if unprobed else '',
        plural(other, 'other change') if other else '',
        f'{fmt_count(unlisted)} not itemised' if unlisted else '') if part]
    head = f"{plural(total, 'host')} changed"
    return f"{head}: {', '.join(parts)}" if parts else head


def title_with_count(title: str, count: int) -> str:
    if count <= 0:
        return title
    return TITLE_COUNT.format(count=f'{TITLE_COUNT_MAX}+' if count > TITLE_COUNT_MAX else count, title=title)


NOTIFY_LABEL = 'Notify me about changes'
NOTIFY_HELP = {
    'off': 'Off. Turn on to get one desktop notification per round that changed hosts, while this tab is in the '
           'background. It says how many hosts changed, never which. The choice lasts until cn-tool is restarted.',
    'on': 'On: one notification per round that changed hosts, while this tab is in the background. It says how many '
          'hosts changed, never which. Turn off here at any time; the choice lasts until cn-tool is restarted.',
    'blocked': 'Notifications are blocked for this site. Allow them in the browser\'s site settings, then turn this on.',
    'declined': 'The browser did not allow notifications, so none will be sent.',
    'unsupported': 'This browser cannot show desktop notifications. The tab title still counts hosts that stopped '
                   'answering while the tab is in the background.',
}
