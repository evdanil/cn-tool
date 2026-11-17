"""
Ping these / Monitor these: the rows of a lookup table, as filtered, become the Targets of Ping or Monitor.

Nothing is started here. The targets replace the tab's unsent draft of that tool (the ``sessionStorage`` entry its
form restores when it is built) and the tool opens, so the user reviews them and selects Run Ping or Run monitor. Pure but
for ``render_send_group``: no request, and never a shortened list.
"""
import asyncio
import ipaddress
import json

from .lookup_inputs import SOURCES, handoff_entry
from .table_actions import count_text
from .target_compact import handoff_text

# The column that holds a table's targets: IP results, the detail tables' addresses, the Subnets summary.
TARGET_COLUMNS = ('IP', 'IP address', 'Resolved Subnet')
TOOLS = {'ping': dict(label='Ping these', name='Ping', route='/ping', draft='cn-tool-draft-ping', run='Run Ping'),
         'monitor': dict(label='Monitor these', name='Monitor', route='/monitor', draft='cn-tool-draft-monitor-targets',
                         run='Run monitor')}
CONTINUE = 'Continue'
CANCEL = 'Cancel'


def target_column(keys):
    """The column of ``keys`` whose values are targets, or None: such a table has no buttons."""
    keys = list(keys)
    return next((column for column in TARGET_COLUMNS if column in keys), None)


def _network(text):
    if not text or '%' in text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def targets_of(rows, column):
    """
    ``(targets, skipped)``: each row's address or subnet once, in the rows' order, as the table shows it; ``skipped``
    counts the rows whose cell is neither (a blank, a name).
    """
    targets, skipped = {}, 0
    for row in rows:
        text = str(row.get(column) or '').strip()
        if _network(text) is None:
            skipped += 1
        else:
            targets.setdefault(text)
    return list(targets), skipped


def _hosts(network):
    if network.num_addresses <= 2:
        return network.num_addresses
    return network.num_addresses - (2 if network.version == 4 else 1)


def address_count(targets):
    """The addresses Ping would test: a subnet counts its hosts."""
    return sum(_hosts(_network(target)) for target in targets)


def too_large(targets):
    """The subnets Ping refuses for their size (``bulk_ping.MAX_PING_HOSTS``)."""
    from cn_tool.modules.bulk_ping import MAX_PING_HOSTS
    return [target for target in targets if _network(target).num_addresses > MAX_PING_HOSTS + 2]


def button_label(tool, count):
    return f"{TOOLS[tool]['label']} ({count_text(count)})"


def scope_line(count, skipped=0):
    """The visible line beside the two buttons: what they do, and what they leave out."""
    if not count:
        return 'No row of this table, as filtered, holds an address or a subnet.'
    text = 'Opens the tool with these targets. Nothing starts until you select Run.'
    if skipped:
        text += f" {count_text(skipped)} {'row has' if skipped == 1 else 'rows have'} no address and {'is' if skipped == 1 else 'are'} left out."
    return text


def confirm_lines(tool, targets, draft=''):
    """Why to ask before opening the tool, one line each; none means go straight on."""
    from cn_tool.modules.bulk_ping import MAX_TCP_HOSTS
    tool = TOOLS[tool]
    lines = []
    if (draft or '').strip() and draft.strip().splitlines() != list(targets):
        lines.append(f"The Targets box of {tool['name']} in this tab holds unsent text. It will be replaced.")
    addresses = address_count(targets)
    if addresses > MAX_TCP_HOSTS:
        lines.append(f"These targets cover {count_text(addresses)} addresses. TCP ports can be tested for at most "
                     f"{count_text(MAX_TCP_HOSTS)}.")
    large = too_large(targets)
    if large:
        lines.append(f"{count_text(len(large))} {'subnet is' if len(large) == 1 else 'subnets are'} larger than a /16 "
                     f"(for example {large[0]}): {tool['name']} will refuse {'it' if len(large) == 1 else 'them'}.")
    return lines


def read_draft_script(tool):
    return f"sessionStorage.getItem({json.dumps(TOOLS[tool]['draft'])}) || ''"


def too_many_line(count):
    """The line beside the buttons when the targets cannot go into a Targets box (``target_cap``): never cut."""
    return (f"{count_text(count)} targets make a list larger than a Targets box can send (about 900 KB), even with every run "
            f"of consecutive addresses written as a range. Filter the table to fewer rows, or use a file with the command line.")


def handoff_script(tool, targets, source='this table', text=None):
    """Store the targets as the tab's draft of ``tool``, tell it where they came from (``lookup_inputs``) and open it:
    inside the root without a load (``cnShell.go``, router.py) when the tool is routed there, else by a load. The tool
    reads the draft and the handoff when it is built, as on a load."""
    tool_name = tool
    tool = TOOLS[tool]
    entry = handoff_entry(tool_name, targets, source)
    text = chr(10).join(targets) if text is None else text
    return (f"sessionStorage.setItem({json.dumps(tool['draft'])}, {json.dumps(text)}); "
            f"sessionStorage.setItem({json.dumps('cn-tool-handoff-' + tool_name)}, {json.dumps(entry)}); "
            f"window.cnShell ? window.cnShell.go({json.dumps(tool['route'])}) "
            f": window.location.assign({json.dumps(tool['route'])});")


class SendGroup:
    """The two buttons and their line, for the rows last given to ``update``."""

    def __init__(self, column, buttons, line, refusal=None):
        self.column, self.buttons, self.line, self.refusal_line = column, buttons, line, refusal
        self.targets, self.skipped = [], 0

    async def refuse(self, text):
        """Say why nothing was handed over, as an alert: emptied first, so that a repeat is announced again."""
        self.refusal_line.set_text('')
        await asyncio.sleep(0.05)
        if not self.refusal_line.is_deleted:
            self.refusal_line.set_text(text)

    def update(self, rows):
        """Take the table's rows as they are filtered now: the counts on the buttons and what a click sends."""
        previous = self.targets
        self.targets, self.skipped = targets_of(rows, self.column)
        for tool, button in self.buttons.items():
            button.set_text(button_label(tool, len(self.targets)))
            # aria-disabled, not disabled: a native disabled button drops the focus the user has on it while typing
            # in the filter or after a click; the click is ignored in ``send``.
            off = 'false' if self.targets else 'true'
            if button._props.get('aria-disabled') != off:
                button._props['aria-disabled'] = off
                button.classes(add='disabled') if off == 'true' else button.classes(remove='disabled')
                button.update()
        self.line.set_text(scope_line(len(self.targets), self.skipped))
        if self.refusal_line is not None and previous != self.targets:
            self.refusal_line.set_text('')  # a refusal is about the rows it was made on


def render_send_group(rows, column, *, name, source=None):
    """The two buttons above a table. ``rows`` are the table's rows as filtered (``SendGroup.update`` gives it new
    ones); ``name`` marks the buttons and, unless ``source`` says it, names where the targets came from."""
    from nicegui import ui

    source = source or SOURCES.get(name, 'this table')

    async def send(tool):
        client = ui.context.client
        targets = list(group.targets)
        if not targets:
            return
        try:
            draft = await client.run_javascript(read_draft_script(tool), timeout=5)
        except TimeoutError:
            draft = ''
        if group.line.is_deleted:
            return  # the page of this table was left while the draft was read: no question over the next page
        # A list a box cannot send is written as ranges when they read the same, else refused: never cut (target_compact).
        # Decided first, so that nobody is asked to confirm what cannot be handed over.
        text, _ = await asyncio.to_thread(handoff_text, targets, tool)
        if group.line.is_deleted:
            return
        if text is None:
            await group.refuse(too_many_line(len(targets)))
            return
        lines = confirm_lines(tool, targets, draft if isinstance(draft, str) else '')
        if lines:
            from .dialogs import confirm_dialog
            if not await confirm_dialog(f"{button_label(tool, len(targets))}?", lines, confirm=CONTINUE, cancel=CANCEL,
                                        note=f"Nothing starts until you select {TOOLS[tool]['run']}.",
                                        fallback=f'[data-send-targets="{name}-{tool}"]'):
                return
        if group.line.is_deleted:
            return  # the page of this table was left while the question or the draft's read was awaited
        client.run_javascript(handoff_script(tool, targets, source, text))

    with ui.element('div').props('role=group aria-label="Send targets"').classes('row items-center gap-2 cn-send-targets'):
        buttons = {}
        for tool in TOOLS:
            button = ui.button(button_label(tool, 0), on_click=lambda _, tool=tool: send(tool)).props('outline dense no-caps')
            button._props['data-send-targets'] = f'{name}-{tool}'
            buttons[tool] = button
        line = ui.label('').classes('cn-muted text-sm')  # beside the buttons, always visible
        # What a refused handoff says: an alert (outside the page's one polite region), always there, emptied and then set.
        refusal = ui.label('').props('role=alert data-send-refusal').classes('text-sm')
        for button in buttons.values():
            button._props['aria-describedby'] = line.html_id
    group = SendGroup(column, buttons, line, refusal)
    group.update(rows)
    return group
