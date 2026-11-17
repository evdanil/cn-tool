"""The web UI's keyboard registry, the shell's skip link and the lines of Help.

One registry (``KEYS``) says every key the pages answer; the Help dialog lists it and one script (``KEYS_SCRIPT``)
installs it once per page, in the browser, so a key never waits for the server. The single-key shortcuts (``/``,
``?``, ``g`` then a letter) have an off switch in Help (WCAG 2.1.4): its state lasts for the tab (``sessionStorage``).
Escape in a filter's text field only acts while that field has the focus, so it needs no switch (the filter's
select beside it keeps its own Escape); Ctrl+Enter is the pages'. A key never fires while the focus is in a field,
with Ctrl, Alt or Meta held (AltGr, which Windows reports as Ctrl+Alt, is how some layouts type ``/`` and ``?``: it
counts as no modifier), while a dialog is open, or on the card of a session that has ended. The letters are read
whatever CapsLock says.

Plan: ``docs/plans/webui-ux-plan.md`` section 4, R1-13. NiceGUI is imported inside the functions.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from . import texts

SWITCH_LABEL = 'Single-key shortcuts'
SKIP_LABEL = 'Skip to results'  # where the page has a results region (or the setup card in the form's place)
SKIP_CONTENT_LABEL = 'Skip to content'  # where it has none: the target is the anchor, MAIN_LABEL
MAIN_LABEL = 'Page content'
MAIN_ID = 'cn-main'
REPORT_HELP = ('The report is one workbook for the whole session. The Report menu in the header names it and '
               'downloads it; a page only says what its own latest run did to it.')
STOP_HELP = ('Stop ends only the job of the page you are on. For a job of another tool, the header has Stop… '
             'beside its pill: it asks first and ends only that job.')


@dataclass(frozen=True)
class Key:
    combo: str  # as shown to the user
    label: str  # what it does
    scope: str  # 'single' (a single-key shortcut: the switch turns it off) or 'field' (only while a field has focus)


# The letters after "g": the key of each page of shell.PAGES (checked by a test, so a new page cannot lack one).
GO_LETTERS = {'s': 'subnet', 'i': 'ip', 'p': 'ping', 'm': 'monitor', 'c': 'config_search', 'd': 'demob', 't': 'settings'}

KEYS = (
    Key('/', 'Move to the first filter field of the page', 'single'),
    Key('Escape', 'In a filter field: clear the filter', 'field'),
    Key('?', 'Open this Help', 'single'),
    *(Key(f'g then {letter}', f'Open {{{key}}}', 'single') for letter, key in GO_LETTERS.items()),
    Key('Ctrl+Enter', 'In a form that has it (Targets, search terms, site): start; on a folded form\'s line: run again', 'field'),
)


def key_lines(pages) -> list[str]:
    """The registry as Help lines; ``pages`` is ``shell.PAGES`` (the names of the ``g`` keys)."""
    label = {page.key: page.label for page in pages}
    return [f'{key.combo}: {key.label.format(**label)}' for key in KEYS]


def help_lines(page_lines, pages) -> dict[str, list[str]]:
    """The sections of Help, in order: the page's own lines, the keys, Stop and Quit, the report."""
    return {
        'This page': [str(line) for line in page_lines],
        'Keyboard': key_lines(pages),
        'Stop and Quit': [STOP_HELP, *texts.QUIT_HELP],
        'The report': [REPORT_HELP],
    }


def skip_link():
    """The skip link: the first thing the page draws, so the first Tab stop. The script moves the focus, and names
    the link by its target when it gets the focus (``SKIP_LABEL`` or ``SKIP_CONTENT_LABEL``)."""
    from nicegui import ui

    link = ui.element('a').classes('cn-skip').props(f'href=#{MAIN_ID} data-skip-link')
    with link:
        ui.label(SKIP_LABEL)
    return link


def main_anchor():
    """Where the page's own content starts: the skip link's target on a page that marks no results region. A named
    region, so that a screen reader says where the focus went."""
    from nicegui import ui

    return ui.element('div').props(f'id={MAIN_ID} tabindex=-1 role=region aria-label="{MAIN_LABEL}"').classes('cn-main-anchor')


CSS = '''
.cn-skip { position:absolute; left:8px; top:-100px; z-index:10000; padding:8px 12px; background:var(--cn-panel);
  color:var(--cn-link); border:2px solid var(--cn-focus); font-weight:600; }
.cn-skip:focus { top:8px; }
.cn-main-anchor { outline:none; }
'''

# data-cn-results (or the pages' own marked results region) is the target; a page without one gets the anchor. The
# first visible match in the page's order wins, so the setup card (``setup_card``), which stands where the form was,
# is the target while it shows: the page has nothing else to say then, and its results region is empty.
_RESULTS = ('[data-setup-card], [data-cn-results], [data-config-results], '
            '[role=region][aria-label$="results" i][tabindex="-1"]')
_FILTERS = ('[data-cn-filter], .cn-field-filter, .cn-monitor-toolbar, .cn-config-filter, '
            '[role=group][aria-label*="filter" i]')

KEYS_SCRIPT = '''<script>
(() => {
  if (window.cnKeys) return;
  const STORE = 'cn-single-keys', GO = %(go)s;
  let on = true, pending = 0;
  try { on = sessionStorage.getItem(STORE) !== 'off'; } catch (e) {}
  const visible = (el) => el.getClientRects().length > 0;
  const typing = (el) => !!el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName)
                                  || ['textbox', 'combobox', 'searchbox', 'listbox'].includes(el.getAttribute('role')));
  const filterInput = () => {
    for (const box of document.querySelectorAll(%(filters)s)) {
      if (!visible(box)) continue;
      for (const field of box.querySelectorAll('.q-field:not(.q-select)')) {
        const input = field.querySelector('input:not([type=hidden])');
        if (input && visible(input)) return input;
      }
    }
    return null;
  };
  // A filter's text field: never its select (a Quasar select is a read-only input with role=combobox).
  const filterText = (el) => !!el && el.tagName === 'INPUT' && !el.readOnly && el.getAttribute('role') !== 'combobox'
                             && !el.closest('.q-select') && !!el.closest(%(filters)s);
  const clearFilter = (input) => {
    if (!input.value) return;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(input, '');
    input.dispatchEvent(new Event('input', {bubbles: true}));
    const box = input.closest(%(filters)s);
    for (const button of box ? box.querySelectorAll('button') : [])
      if (/^clear/i.test((button.getAttribute('aria-label') || button.textContent).trim())) { button.click(); break; }
  };
  const results = () => [...document.querySelectorAll(%(results)s)].find(visible) || document.getElementById(%(main)s);
  document.addEventListener('focusin', (event) => {
    const link = event.target.closest && event.target.closest('a.cn-skip');
    const text = link && link.firstElementChild, target = link && results();
    const name = target && target.id === %(main)s ? %(content)s : %(skip)s;
    if (text && text.textContent !== name) text.textContent = name;
  }, true);
  const skip = () => {
    const target = results();
    if (!target) return;
    if (!target.hasAttribute('tabindex')) target.setAttribute('tabindex', '-1');
    target.focus();
    target.scrollIntoView({block: 'start'});
  };
  document.addEventListener('click', (event) => {
    const link = event.target.closest && event.target.closest('a.cn-skip');
    if (link) { event.preventDefault(); skip(); }
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      if (filterText(event.target) && event.target.value) {
        clearFilter(event.target);
        event.preventDefault();
      }
      return;
    }
    if (['Shift', 'CapsLock', 'AltGraph', 'Control', 'Alt', 'Meta'].includes(event.key)) return;  // a modifier going down is no key of its own
    const altGr = event.getModifierState && event.getModifierState('AltGraph');
    if (!on || ((event.ctrlKey || event.altKey) && !altGr) || event.metaKey || event.defaultPrevented
        || typing(event.target) || document.body.dataset.cnClosed
        || document.querySelector('.q-dialog, .q-menu')) { pending = 0; return; }
    const key = event.key, letter = key.length === 1 ? key.toLowerCase() : '';
    const going = pending && Date.now() < pending;
    pending = 0;
    // After "g" a page's letter goes there; any other key is itself ("g" then "?" opens Help).
    if (going && GO[letter]) { event.preventDefault(); (window.cnShell ? window.cnShell.go(GO[letter]) : location.assign(GO[letter])); return; }
    if (letter === 'g') { pending = Date.now() + 1500; event.preventDefault(); }
    else if (key === '/') {
      const input = filterInput();
      if (input) { event.preventDefault(); input.focus(); input.select(); }
    } else if (key === '?') {
      const help = document.querySelector('[data-cn-help]');
      if (help) { event.preventDefault(); help.click(); }
    }
  });
  window.cnKeys = {
    enabled: () => on,
    set: (value) => { on = Boolean(value); pending = 0; try { sessionStorage.setItem(STORE, on ? 'on' : 'off'); } catch (e) {} },
  };
})();
</script>'''


def keys_script(routes):
    """The script with the ``g`` keys bound to ``routes`` ({letter: route})."""
    return KEYS_SCRIPT % dict(go=json.dumps(routes), filters=json.dumps(_FILTERS), results=json.dumps(_RESULTS),
                              main=json.dumps(MAIN_ID), skip=json.dumps(SKIP_LABEL), content=json.dumps(SKIP_CONTENT_LABEL))
