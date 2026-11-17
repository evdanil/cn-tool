"""The names a tab set needs (tracker A1, W-1): each tab says which panel it controls and each panel says which tab
names it. NiceGUI's ``ui.tab`` and ``ui.tab_panel`` write neither, and Quasar draws only the selected panel, so a tab
that is not selected names a panel that is not in the page yet (which ARIA allows).

Quasar's ``QTabPanels`` also gives the box that holds the selected panel ``role=tabpanel``, so a panel sits inside
another panel for a screen reader. The small script below turns that box into ``role=presentation`` whenever Quasar
draws one; the panel itself keeps its role and its name.
"""

PANEL_SCRIPT = """<script>
(() => {
  const OUTER = '.q-tab-panels .q-panel[role=tabpanel]';
  const fix = (root) => { for (const box of root.querySelectorAll(OUTER)) box.setAttribute('role', 'presentation'); };
  new MutationObserver((changes) => {
    for (const change of changes) for (const node of change.addedNodes) {
      if (node.nodeType === 1 && node.querySelector && (node.matches(OUTER) || node.querySelector(OUTER))) {
        if (node.matches(OUTER)) node.setAttribute('role', 'presentation');
        fix(node);
      }
    }
  }).observe(document.documentElement, {childList: true, subtree: true});
  fix(document);  // a tab set already drawn: the script came after it, with the Monitor opened inside the root (R2-11)
})();
</script>"""


def wire_tabs(pairs):
    """Name each ``(tab, panel)`` pair of a ``ui.tabs`` / ``ui.tab_panels`` set for assistive technology."""
    from nicegui import ui

    from .scope import add_once

    for tab, panel in pairs:
        tab._props['aria-controls'] = panel.html_id
        panel._props['aria-labelledby'] = tab.html_id
    add_once(ui.context.client, 'tab-aria', script=PANEL_SCRIPT)
