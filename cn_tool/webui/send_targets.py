"""
Ping these / Monitor these: the rows of a lookup table, as filtered, become the Targets of Ping or Monitor.

Nothing is started here. The targets replace the tab's unsent draft of that tool (the ``sessionStorage`` entry its
form restores on load) and the tool opens, so the user reviews them and selects Run Ping or Run monitor. Pure but
for ``render_send_group``: no request, and never a shortened list.
"""
import ipaddress
import json

from .table_actions import count_text

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


def scope_description(tool, count, skipped=0):
    """What the button takes, for ``aria-description`` and the tooltip."""
    tool = TOOLS[tool]
    noun = 'target' if count == 1 else 'targets'
    text = (f"Opens {tool['name']} with the {count_text(count)} {noun} of this table, every page, as filtered. "
            f"Nothing starts until you select {tool['run']}.")
    if not count:
        text = 'No row of this table, as filtered, holds an address or a subnet.'
    elif skipped:
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


def handoff_script(tool, targets):
    """Store the targets as the tab's draft of ``tool`` and open it."""
    tool = TOOLS[tool]
    return (f"sessionStorage.setItem({json.dumps(tool['draft'])}, {json.dumps(chr(10).join(targets))}); "
            f"window.location.href = {json.dumps(tool['route'])};")


def render_send_group(rows, column, *, name):
    """The two buttons above a table. ``rows`` are the table's rows as filtered; ``name`` marks the buttons."""
    from nicegui import ui

    targets, skipped = targets_of(rows, column)

    asking = []  # a second click while one is being asked (a double click) opens no second dialog

    async def send(tool):
        if asking:
            return
        asking.append(tool)
        try:
            await ask_and_send(tool)
        finally:
            asking.clear()

    async def ask_and_send(tool):
        client = ui.context.client
        try:
            draft = await client.run_javascript(read_draft_script(tool), timeout=5)
        except TimeoutError:
            draft = ''
        lines = confirm_lines(tool, targets, draft if isinstance(draft, str) else '')
        if not lines:
            client.run_javascript(handoff_script(tool, targets))
            return
        with ui.dialog() as dialog, ui.card().props('role=alertdialog'):
            ui.label(f"{button_label(tool, len(targets))}?").classes('text-h6')
            for line in lines:
                ui.label(line)
            ui.label(f"Nothing starts until you select {TOOLS[tool]['run']}.").classes('cn-muted')
            with ui.row():
                ui.button(CANCEL, on_click=lambda: dialog.submit(False)).props('outline')
                ui.button(CONTINUE, on_click=lambda: dialog.submit(True))
        confirmed = await dialog
        dialog.delete()
        if confirmed:
            client.run_javascript(handoff_script(tool, targets))

    with ui.element('div').props('role=group aria-label="Send targets"').classes('row items-center gap-2 cn-send-targets'):
        for tool in TOOLS:
            button = ui.button(button_label(tool, len(targets)), on_click=lambda _, tool=tool: send(tool)).props('outline dense no-caps')
            button._props['data-send-targets'] = f'{name}-{tool}'
            description = scope_description(tool, len(targets), skipped)
            button._props['aria-description'] = description
            button.tooltip(description)
            if not targets:
                button.disable()
