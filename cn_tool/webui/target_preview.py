"""
Smart paste on the Targets boxes (plan 7.3, tracker M11 and S1): what a box holds, said under it, and what is sent.

The pure part (``submit_lines``, ``describe``) reads the box with ``cn_tool.utils.target_text`` and imports no web
stack. ``attach`` draws the live line under a box: 300 ms after the last change the server parses the text (without
expanding ranges) and writes the summary; what was not understood is listed when there are five items or fewer and
counted otherwise. The box keeps what was typed; only what the page submits is the tokenizer's lines.

The 64 KiB cap belongs to the preview alone: a larger text gets no line ("Too long to preview"), but a Run reads it
exactly as it reads a small one, so one more byte never changes what runs. Both reads run in a worker thread
(``asyncio.to_thread``), never on the page's event loop.

The line is not a live region (a page has one, its outcome): it is part of the box's description
(``aria-describedby``), read when the box takes the focus.
"""
import asyncio
from dataclasses import dataclass
from typing import Tuple

from cn_tool.utils.target_text import parse

from . import target_cap

MAX_BYTES = 64 * 1024  # what the live line reads
DEBOUNCE = 0.3  # seconds after the last change
LIST_LIMIT = 5  # more items than this are counted, not listed
#: Ping's limit of hosts per run with TCP ports (``bulk_ping.MAX_TCP_HOSTS``; a test pins them equal). The tool decides.
TCP_HOST_LIMIT = 1024
TOO_LONG = 'Too long to preview (over 64 KiB). It is read the same way when you run it.'
NO_TARGETS = 'Enter at least one target.'

CSS = """
.cn-target-preview { width:100%; gap:4px; min-width:0; }
.cn-target-summary { min-height:1.5em; color:var(--cn-muted); overflow-wrap:anywhere; }
.cn-target-groups { width:100%; gap:2px; }
.cn-target-groups:empty { display:none; }
.cn-target-cap { color:var(--cn-attention-ink); font-weight:600; overflow-wrap:anywhere; }
.cn-target-notes { margin:0; padding-left:1.25em; }
.cn-target-lead, .cn-target-notes li { overflow-wrap:anywhere; }
.cn-target-groups [data-kind=unknown], .cn-target-groups [data-kind=ignored],
.cn-target-groups [data-group=problems], .cn-target-groups [data-group=warning] { color:var(--cn-attention-ink); }
@media(min-width:800px) { .cn-ping-target-preview { grid-column:1; grid-row:6; } }
"""


@dataclass(frozen=True)
class Group:
    """A lead sentence and the items listed under it (each ``(kind, text)``, kind unknown, ignored or adjusted).
    ``name`` is problems, adjusted or warning."""
    name: str
    lead: str
    items: Tuple[Tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Description:
    """What the live line says: the ``summary`` and the ``groups`` under it."""
    summary: str
    groups: Tuple[Group, ...] = ()


def too_long(text):
    return len((text or '').encode('utf-8', 'surrogatepass')) > MAX_BYTES


def submit_lines(text, tool):
    """The lines to send for ``text``: the tokenizer's, one item per line, whatever the size of the text. An item
    that is not understood is among them as typed, so the tool reports it as it does today. Empty when the box holds
    no item (blank, or comments only): the page asks for a target."""
    return list(parse(text or '', tool).lines)


async def lines_for_submit(text, tool):
    """``submit_lines`` off the event loop. The caller asks whether its page is still there after the await."""
    return await asyncio.to_thread(submit_lines, text, tool)


def _item(token):
    where = f'Line {token.line}: {token.source}'
    if token.kind in ('unknown', 'ignored'):
        return f'{where} ({token.note})' if token.note else where
    shown = token.text if token.kind != 'range' else token.source
    changed = f' becomes {shown}' if shown != token.source else ''
    return f'{where}{changed} ({token.note})'


def _tcp_warning(parsed):
    hosts = sum(token.hosts or 0 for token in {t.text: t for t in parsed.tokens if t.kind not in ('unknown', 'ignored')}.values())
    if hosts <= TCP_HOST_LIMIT:
        return None
    return Group('warning', f'With TCP ports the tool tests at most {TCP_HOST_LIMIT:,} hosts per run; this box holds '
                            f'{hosts:,}. Remove ports or split the box.')


def describe(text, tool, ports=''):
    """The live line for ``text`` (reads at most 64 KiB; ranges are counted, not expanded). ``ports`` is the TCP ports
    box, for Ping and Monitor: a warning when the hosts exceed what the tool tests with ports."""
    if not (text or '').strip():
        return Description('')
    if too_long(text):
        return Description(TOO_LONG)
    parsed = parse(text, tool, expand=False)
    problems = [t for t in parsed.tokens if t.kind in ('unknown', 'ignored')]
    adjusted = [t for t in parsed.tokens if t.kind not in ('unknown', 'ignored') and t.note]
    groups = []
    if 0 < len(problems) <= LIST_LIMIT:
        groups.append(Group('problems', 'Not understood or ignored:', tuple((t.kind, _item(t)) for t in problems)))
    elif problems:
        first = problems[0]
        groups.append(Group('problems', f'{len(problems):,} items are not understood or ignored. The first is on line '
                                        f'{first.line}: {first.source} ({first.note}).'))
    if adjusted:
        items = [('adjusted', _item(t)) for t in adjusted[:LIST_LIMIT]]
        if len(adjusted) > LIST_LIMIT:
            items.append(('adjusted', f'and {len(adjusted) - LIST_LIMIT:,} more'))
        groups.append(Group('adjusted', 'Read as:', tuple(items)))
    if tool in ('ping', 'monitor') and (ports or '').strip():
        warning = _tcp_warning(parsed)
        if warning:
            groups.append(warning)
    return Description(parsed.summary, tuple(groups))


class Preview:
    """The live line of one Targets box: ``box`` is its container; ``use_ports(field)`` tells it the TCP ports box."""

    def __init__(self, box, ports, cap_message_id='', tool=''):
        self.box = box
        self._ports = ports
        self._cap = (cap_message_id, tool)

    def guard_js(self):
        """The statement that puts the cap (``target_cap``) on the box, for a script in which ``input`` is its textarea
        (the pages' restore scripts run it, so the cap is there before the box takes a value)."""
        return target_cap.guard_js(*self._cap)

    def use_ports(self, field):
        self._ports['field'] = field
        field.on_value_change(lambda _: self._ports['changed']())


def attach(field, tool, scope, classes=''):
    """Draw the live line under ``field`` (in the current container) and keep it up to date; returns a ``Preview``.
    ``scope`` is the page's ``PageScope``: nothing is written after the page was left. The line and the list are
    added to the box's ``aria-describedby`` after its helper line."""
    from nicegui import ui

    from .scope import add_once

    add_once(ui.context.client, 'target-preview', css=CSS)
    add_once(ui.context.client, 'target-cap', script=target_cap.SCRIPT)
    with ui.column().classes(('cn-target-preview ' + classes).strip()).props('data-target-preview') as box:
        # Text only, its space reserved (min-height); not a live region: the box's description carries it.
        summary = ui.label('').classes('cn-target-summary')
        groups = ui.column().classes('cn-target-groups').props('data-target-groups')
        # What a refused edit says (target_cap): shown and hidden by the browser's guard, an alert when it appears.
        cap_message = ui.label(target_cap.MESSAGE).classes('cn-target-cap').props('role=alert data-target-cap').style('display:none')
    field._props['aria-describedby'] = f"{field._props.get('aria-describedby', '')} {summary.html_id} {groups.html_id}".strip()
    field.update()
    state = {'version': 0, 'shown': None}
    ports = {'field': None}

    def ports_text():
        return (ports['field'].value or '') if ports['field'] is not None else ''

    def draw(description):
        if not scope.alive or box.is_deleted or state['shown'] == description:
            return  # nothing is redrawn for text the line already says
        state['shown'] = description
        summary.set_text(description.summary)
        groups.clear()
        with groups:
            for group in description.groups:
                ui.label(group.lead).classes('cn-target-lead').props(f'data-target-lead data-group={group.name}')
                if group.items:
                    with ui.element('ul').classes('cn-target-notes').props('data-target-notes'):
                        for kind, text in group.items:
                            item = ui.label(text).props(f'data-kind={kind}')
                            item.tag = 'li'

    async def later(text, with_ports, version):
        # A change makes a newer version; an older read stops before it starts, and one that is slow and finishes
        # after a newer change never overwrites the line (nothing is cancelled: the guard is the version).
        await asyncio.sleep(DEBOUNCE)
        if version != state['version']:
            return
        description = await asyncio.to_thread(describe, text, tool, with_ports)
        if version == state['version']:
            draw(description)

    def changed(event=None):
        text, with_ports = field.value or '', ports_text()
        state['version'] += 1
        if not text.strip():
            draw(Description(''))
            return
        scope.task(later(text, with_ports, state['version']), name='target-preview')

    ports['changed'] = changed
    field.on_value_change(changed)
    changed()
    return Preview(box, ports, cap_message.html_id, tool)
