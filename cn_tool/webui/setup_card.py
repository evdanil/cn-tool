"""What a tool page shows when it cannot work yet: the setup card and the Setup required block.

Plan: `docs/plans/webui-ux-plan.md`, R1-14 (finding M5a).

- The **card** takes the place of the form on the pages that need Infoblox (Subnets, IP, Site Demobilization) while
  the settings name no API endpoint (`SessionSnapshot.infoblox_configured` is False): it says what is missing and
  opens Settings. Ping and Monitor work without Infoblox and never show it.
- The **block** is the top of the page in ``setup_required``: the reason, Retry setup and the way to Settings in one
  place.
"""
from __future__ import annotations

CARD_TITLE = 'Connect cn-tool to Infoblox'
CARD_TEXT = 'Open Settings and enter the API endpoint. Ping and Monitor work without it.'
OPEN_SETTINGS = 'Open Settings'
CARD_STATUS = 'Infoblox is not set up.'
RETRY = 'Retry setup'
RETRY_HELP = 'Retry setup reads the configuration again and retries credentials. Change the configuration in Settings.'
SETTINGS_LINK = 'Open Settings to change the configuration'
BLOCK_STATUS = 'Setup required.'
NEEDS_INFOBLOX = ('subnet', 'ip', 'demob')

CSS = '''
.cn-setup-card h2 { margin:0 0 6px; }
.cn-setup-card .q-btn { margin-top:12px; }
.cn-setup-block { display:flex; flex-direction:column; gap:8px; }
.cn-setup-block .cn-setup-reason { font-weight:600; }
.cn-setup-actions { display:flex; flex-wrap:wrap; align-items:center; gap:12px; }
'''


def needs_endpoint(state, tool) -> bool:
    """Whether page ``tool`` shows the setup card: it needs Infoblox, the session has started, and its settings name
    no API endpoint. Unknown (None: before the first ``ready``, and in ``setup_required``) is not "no"."""
    return (tool in NEEDS_INFOBLOX and state is not None and state.infoblox_configured is False
            and state.phase in ('ready', 'running', 'stopping', 'saving'))


def setup_reason(state) -> str:
    """The reason of ``setup_required`` as the worker gave it, or '' in any other phase."""
    if state is None or state.phase != 'setup_required':
        return ''
    error = state.error
    return str(error.get('message', '') if isinstance(error, dict) else error or '') or BLOCK_STATUS


class SetupBlock:
    """The block and the card of one page (`render_setup`)."""

    def __init__(self, tool, block, reason, retry):
        self.tool, self.block, self.reason, self.retry = tool, block, reason, retry
        self.card, self.form = None, []
        self._shown = None

    def add_card(self, *, form=()):
        """Draw the setup card where the page calls it (the place of its form). ``form`` are the elements it
        replaces: they are hidden while it shows."""
        from nicegui import ui

        # A named region that can take the focus: the header's skip link lands here while the card shows (keys.py).
        with ui.element('div').classes('cn-panel cn-setup-card').props('data-setup-card role=region tabindex=-1') as self.card:
            with ui.element('h2') as title:
                ui.label(CARD_TITLE)
            self.card.props(f'aria-labelledby={title.html_id}')
            ui.label(CARD_TEXT)
            ui.button(OPEN_SETTINGS, on_click=lambda: ui.navigate.to('/settings')).props('color=primary')
        self.card.set_visibility(False)
        self.form = list(form)
        return self.card

    def update(self, state):
        """Show what the snapshot calls for, and hide the form while the card stands in for it.

        @return: the page's status line while the card or the block is shown (they carry the reason), else None for
            the usual one (`PageShell.update(state, own=...)`).
        """
        card, reason = self.card is not None and needs_endpoint(state, self.tool), setup_reason(state)
        shown = (card, reason)
        if shown != self._shown:
            self._shown = shown
            self.block.set_visibility(bool(reason))
            self.reason.set_text(reason)
            if self.card is not None:
                self.card.set_visibility(card)
            for part in self.form:
                part.set_visibility(not card)
        return CARD_STATUS if card else BLOCK_STATUS if reason else None


def render_setup(controller, tool):
    """Draw, where the page calls it (the top of its content), the Setup required block, hidden until
    `SetupBlock.update` shows it from the page's poll. A page that needs Infoblox then calls `SetupBlock.add_card`
    where its form is."""
    from nicegui import ui

    from .scope import add_once

    add_once(ui.context.client, 'setup', css=CSS)

    def retry_setup():
        try:
            controller.retry_initialize()
        except RuntimeError:
            pass  # the session left Setup required between the poll and the click: the next poll hides the block

    with ui.element('div').classes('cn-notice cn-setup-block').props('data-setup-block') as block:
        reason = ui.label('').props('role=status').classes('cn-setup-reason')
        with ui.element('div').classes('cn-setup-actions'):
            retry = ui.button(RETRY, on_click=retry_setup).props('outline')
            ui.link(SETTINGS_LINK, '/settings').mark('settings-from-setup')
        ui.label(RETRY_HELP).classes('text-sm')
    block.set_visibility(False)
    return SetupBlock(tool, block, reason, retry)
