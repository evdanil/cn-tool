"""The shared theme's look: the stylesheet and the colours (plan `docs/plans/webui-ux-plan.md` section 3.2, R2-12).

`apply_theme()` is what a page calls instead of adding the stylesheet itself; a page module keeps its own layout rules.
The colours are custom properties on `:root` (`--cn-*`): `LIGHT` is the default set and `DARK` a second set of the same
names under `@media (prefers-color-scheme: dark)`, so the page follows the system setting and there is no toggle.
Colours exist here only: every other web UI module (and the Map) takes them from `var(--cn-*)` or from a system colour
keyword, and a test fails on a literal colour anywhere else. CSS stays a string constant of this module: nothing is
loaded from a file or a network.

The type scale is five sizes, also custom properties (R2-05, row m14): `--cn-text-small` (helper lines, captions, chips,
tooltips), `--cn-text-data` (tables, buttons, tabs, fields), `--cn-text-body` (text, labels, `h3`), `--cn-text-heading`
(`h2`, a banner's title) and `--cn-text-title` (`h1`). A page sets no other size. The one form style (a label above an
outlined, dense box) is `results_first.form_field`.
"""

LIGHT = {
    'ink': '#172B3A', 'muted': '#526675', 'page': '#F5F7FA', 'panel': '#FFFFFF', 'line': '#CBD5DF', 'field-line': '#6B7C8A',
    'link': '#145C87', 'focus': '#145C87', 'attention-ink': '#5E400C', 'attention-bg': '#FFF3D8', 'attention-line': '#775110',
    'error-ink': '#9B1C1C', 'ok-ink': '#1B6B3A', 'tip-ink': '#FFFFFF', 'tip-bg': '#3A4A57',
    'line-soft': '#E2E8ED', 'table-head': '#EDF2F6', 'table-hover': '#F4F8FB', 'chip-bg': '#EDF2F6', 'ok-bg': '#EAF5EE',
    'problem-bg': '#FBECEC', 'action-hover': '#E5F0F7', 'info-bg': '#EAF3F9', 'error-bg': '#FCEEEE',
    'mark-bg': '#FFE680', 'mark-ink': '#1B1B1B', 'ring-gap': '#FFFFFF', 'shadow': 'rgba(16,40,60,.22)',
    'primary': '#145C87', 'on-primary': '#FFFFFF', 'negative': '#C10015', 'on-negative': '#FFFFFF',
    'negative-text': '#C10015', 'warning-text': '#8A5300',
}
DARK = {
    'ink': '#E4ECF2', 'muted': '#A3B4C1', 'page': '#0E1820', 'panel': '#16232D', 'line': '#3A4E5E', 'field-line': '#8499A8',
    'link': '#86C5EE', 'focus': '#86C5EE', 'attention-ink': '#F1D9A4', 'attention-bg': '#33280E', 'attention-line': '#D9B25F',
    'error-ink': '#FF9C9C', 'ok-ink': '#7ED6A1', 'tip-ink': '#0E1820', 'tip-bg': '#DDE6EC',
    'line-soft': '#2A3C4A', 'table-head': '#1E3140', 'table-hover': '#1B2D3B', 'chip-bg': '#1E3140', 'ok-bg': '#173525',
    'problem-bg': '#3B1E22', 'action-hover': '#1F3B50', 'info-bg': '#14303F', 'error-bg': '#3B1E22',
    'mark-bg': '#7A6200', 'mark-ink': '#FFF4C2', 'ring-gap': '#0E1820', 'shadow': 'rgba(0,0,0,.6)',
    'primary': '#86C5EE', 'on-primary': '#0A2232', 'negative': '#FF9C9C', 'on-negative': '#2B0A0A',
    'negative-text': '#FF9C9C', 'warning-text': '#F0BE6A',
}
# Map colours are the status colours under other names: one set of values to keep readable in both themes.
ALIASES = {'map-ok': 'ok-ink', 'map-info': 'link', 'map-warning': 'attention-line', 'map-error': 'error-ink', 'map-dim': 'muted'}


def properties(palette):
    """The custom-property declarations of one palette, as one CSS string."""
    return ' '.join(f'--cn-{name}:{value};' for name, value in palette.items())


def root_css():
    """The ``:root`` rules of both themes (what a page that does not load the whole stylesheet, like the access card, needs)."""
    aliases = ' '.join(f'--cn-{name}:var(--cn-{target});' for name, target in ALIASES.items())
    return (f':root {{ color-scheme:light dark; {properties(LIGHT)} {aliases} }}\n'
            f'@media (prefers-color-scheme: dark) {{ :root {{ {properties(DARK)} }}\n'
            '  @layer overrides { body { --q-primary:var(--cn-primary) !important; --q-negative:var(--cn-negative) !important;\n'
            '    --q-warning:var(--cn-warning-text) !important; } } }\n')


CSS = root_css() + '''
:root { --cn-text-small:13px; --cn-text-data:14px; --cn-text-body:15px; --cn-text-heading:18px; --cn-text-title:28px; }
body, body.body--dark { background:var(--cn-page); color:var(--cn-ink); font:var(--cn-text-body) system-ui,sans-serif; }
.nicegui-content { max-width:1440px; margin:auto; padding:24px 28px; gap:18px; }
h1 { font-size:var(--cn-text-title); line-height:1.2; font-weight:650; margin:0; }
h2 { font-size:var(--cn-text-heading); line-height:1.35; font-weight:650; margin:14px 0 8px; }
h3 { font-size:var(--cn-text-body); line-height:1.4; font-weight:600; margin:12px 0 6px; }
.text-h4:not(h1), .text-h5:not(h1), .text-h6:not(h1) { font-size:var(--cn-text-heading); line-height:1.35; font-weight:650; letter-spacing:normal; }
.text-subtitle1, .text-body1 { font-size:var(--cn-text-body); line-height:1.4; letter-spacing:normal; }
.text-sm, .q-btn, .q-tab__label, .q-field, .q-item, .q-menu, .q-checkbox__label, .q-toggle__label { font-size:var(--cn-text-data); }
.text-xs, .text-caption, .q-badge, .q-chip { font-size:var(--cn-text-small); }
.cn-panel { background:var(--cn-panel); border:1px solid var(--cn-line); border-radius:6px; padding:20px; width:100%; }
.cn-muted { color:var(--cn-muted); max-width:78ch; }
.cn-table { width:100%; overflow-x:auto; border:1px solid var(--cn-line); border-radius:4px; }
.cn-table th { background:var(--cn-table-head); color:var(--cn-ink); font-weight:650; }
.cn-sort-button { border:0; background:transparent; color:inherit; font:inherit; text-align:left; cursor:pointer; padding:4px 2px; }
.cn-sort-button:focus-visible { outline:2px solid var(--cn-focus); outline-offset:2px; }
.cn-field-filter { display:flex; flex-wrap:wrap; align-items:center; gap:8px; width:100%; }
.cn-field-filter .q-field { min-width:130px; max-width:100%; }
.cn-field-filter .q-select__dropdown-icon.material-icons { overflow:hidden; }
.cn-field-filter [role=alert]:empty { display:none; }
.cn-table td { white-space:normal; min-width:100px; max-width:420px; overflow-wrap:anywhere; }
.cn-table .q-table { min-width:650px; }
.cn-table .q-table__middle { overflow:visible; }
.cn-network { font-family:ui-monospace,monospace; }
.cn-summary-network { font-weight:650; }
.cn-summary-status { background:var(--cn-chip-bg); color:var(--cn-ink); font-weight:600; padding:2px 6px; border-radius:3px; }
:focus-visible { outline:3px solid var(--cn-focus); outline-offset:3px; }
.q-btn:focus-visible, .q-tab:focus-visible, .q-item:focus-visible { box-shadow:0 0 0 2px var(--cn-ring-gap), 0 0 0 5px var(--cn-focus); }
.q-btn { text-transform:none; font-weight:600; }
/* Keep the icon ligature inside its box while the Material Icons font loads. */
.q-expansion-item__toggle-icon.material-icons { overflow:hidden; }
.cn-sr-only { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }
.cn-compact-summary { display:none; }
.cn-summary-row { min-width:0; width:100%; border:1px solid var(--cn-line); border-radius:4px; padding:12px; overflow-wrap:anywhere; }
@media(max-width:600px) { .nicegui-content {padding:16px 12px;} .cn-panel {padding:14px;}
.cn-desktop-summary {display:none !important;} .cn-compact-summary {display:flex;} }
.cn-shell { width:100%; min-width:0; overflow-wrap:anywhere; }
a, .nicegui-link { color:var(--cn-link); }
nav[aria-label=Tools] { gap:4px; }
nav[aria-label=Tools] a { display:inline-flex; align-items:center; min-height:32px; padding:0 12px; border-radius:16px; color:var(--cn-link); text-decoration:none; font-weight:600; }
nav[aria-label=Tools] a:hover { background:var(--cn-action-hover); }
nav[aria-label=Tools] a[aria-current=page] { background:var(--cn-link); color:var(--cn-on-primary); }
.cn-notice, .cn-monitor-notice { width:100%; min-width:0; overflow-wrap:anywhere; padding:8px 10px; border-left:3px solid var(--cn-attention-line); background:var(--cn-attention-bg); color:var(--cn-attention-ink); }
.q-field--outlined .q-field__control:before { border-color:var(--cn-field-line); }
.q-btn--rectangle.q-btn--dense { padding:4px 12px; }
.q-tooltip { font-size:var(--cn-text-small); background:var(--cn-tip-bg); color:var(--cn-tip-ink); }
/* Quasar draws its own colours from --q-* (the dark block sets those) and a few fixed ones: these take the theme's. */
.q-card { background:var(--cn-panel); color:var(--cn-ink); }
.q-field__label, .q-field__bottom, .q-field__marginal { color:var(--cn-muted); }
.q-field__native, .q-field__input, .q-select__dropdown-icon { color:var(--cn-ink); }
.q-menu { background:var(--cn-panel); color:var(--cn-ink); }
.q-table, .q-table__card, .q-table th, .q-table td { background:var(--cn-panel); color:var(--cn-ink); }
.q-separator { background:var(--cn-line); }
.q-tab, .q-tabs { color:var(--cn-ink); }
.q-tab--active { color:var(--cn-link); }
/* Quasar's !important rules sit in a later layer than this page's CSS, so an !important override must be in `overrides`. */
@layer overrides {
.q-btn.bg-primary { color:var(--cn-on-primary) !important; }
.q-btn.bg-negative { color:var(--cn-on-negative) !important; }
body .text-negative { color:var(--cn-negative-text) !important; }
body .text-warning { color:var(--cn-warning-text) !important; }
}
@layer overrides { @media (prefers-reduced-motion: reduce) {
  html { scroll-behavior:auto !important; }
  *, *::before, *::after { transition-duration:0.01ms !important; transition-delay:0s !important; animation-duration:0.01ms !important;
    animation-delay:0s !important; animation-iteration-count:1 !important; scroll-behavior:auto !important; }
  .q-ripple { display:none !important; }
} }
/* Forced colours (Windows High Contrast): backgrounds are replaced by the system's, so every boundary, state and focus
   mark that a colour alone carried gets a border, an outline or a system colour. */
@layer overrides { @media (forced-colors: active) {
  .q-btn:focus-visible, .q-tab:focus-visible, .q-item:focus-visible { outline:2px solid Highlight !important; }
  nav[aria-label=Tools] a[aria-current=page] { border:2px solid; }
  :focus-visible { outline-color:Highlight; }
  .q-btn { border:1px solid ButtonText; }
  .q-card, .q-menu, .q-tooltip { border:1px solid CanvasText; }
  .q-tab--active { border-bottom:3px solid Highlight; }
  .cn-notice, .cn-monitor-notice { border:1px solid CanvasText; border-left-width:4px; }
  .cn-monitor-state, .cn-summary-status { border:1px solid; }
  .cn-monitor-round-choice[aria-pressed=true] { forced-color-adjust:none; background:Highlight; color:HighlightText; }
  .cn-monitor-round-choice:focus-visible, .cn-monitor-scroll:focus-visible { outline:2px solid Highlight; }
  .cn-row-action, .cn-page-button { border:1px solid ButtonText; }
  .cn-page-button[aria-disabled=true] { border-color:GrayText; color:GrayText; }
  .cn-map-popup button, .cn-map .cn-map-jumpbtn, .cn-map .cn-map-show { border:1px solid ButtonText; }
  .cn-map .cn-map-index { border-bottom-color:CanvasText; }
} }
'''


def apply_theme():
    """Add the shared stylesheet to the page being built (once per page) and set the primary colour."""
    from nicegui import ui

    from .scope import add_once

    if not add_once(ui.context.client, 'theme', css=CSS):
        return
    ui.dark_mode(None)
    ui.colors(primary='#145C87', warning='#8A5300')


def tip(element, text):
    """Give ``element`` a tooltip that names it: 13 px, shown after 400 ms, on focus too, hidden by Escape.

    For names only; a consequence belongs in visible text or in a confirmation (plan finding M9).
    """
    from nicegui import ui

    with element:
        tooltip = ui.tooltip(text).props('delay=400')
    ref = f'getElement({tooltip.id})'
    element.on('focusin', js_handler=f'() => {ref}?.show?.()')
    element.on('focusout', js_handler=f'() => {ref}?.hide?.()')
    element.on('keydown.escape', js_handler=f'() => {ref}?.hide?.()')
    return tooltip
