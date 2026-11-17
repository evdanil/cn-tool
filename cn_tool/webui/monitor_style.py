"""The Monitor page's stylesheet and its two History focus scripts (moved out of `monitor.py`, which must not grow;
R2-05 adds the results-first order, R2-08 the scripts).

The page's own layout rules; the colours are the theme's `--cn-*` properties where the page has them, and every
`font-size` is one of the theme's five (`--cn-text-*`)."""

CSS = '''
.cn-monitor-row { width:100%; min-width:0; overflow-wrap:anywhere; }
.cn-monitor-row .q-field { min-width:0; }
.cn-monitor-scroll { max-height: min(60vh, 620px); width:100%; min-width:0; overflow:auto; border:1px solid var(--cn-line); border-radius:4px; }
.cn-monitor-table { width:100%; border-collapse:collapse; font-variant-numeric:tabular-nums; }
.cn-monitor-table th, .cn-monitor-table td { text-align:left; vertical-align:middle; padding:7px 10px; border-bottom:1px solid var(--cn-line-soft); }
.cn-monitor-history [role=status]:empty, .cn-monitor-history [role=alert]:empty { display:none; }
.cn-monitor-details { padding:12px 16px; max-width:min(360px, 92vw); overflow-wrap:anywhere; }
.cn-monitor-details > * { margin-bottom:2px; }
.cn-monitor-facts { display:grid; grid-template-columns:auto minmax(0,1fr); gap:2px 12px; margin:10px 0 0; padding-top:8px; border-top:1px solid var(--cn-line); }
.cn-monitor-facts dt { color:var(--cn-muted); white-space:nowrap; }
.cn-monitor-facts dd { margin:0; font-variant-numeric:tabular-nums; }
.cn-monitor-reason { font-size:var(--cn-text-small); max-width:22ch; line-height:1.25; }
.cn-monitor-danger { padding-left:16px; border-left:1px solid var(--cn-line); }
.cn-monitor-table th { position:sticky; top:0; z-index:1; background:var(--cn-table-head); color:var(--cn-ink); font-weight:600; white-space:nowrap; }
.cn-monitor-table tbody tr:hover { background:var(--cn-table-hover); }
.cn-monitor-table tr:last-child td { border-bottom:0; }
.cn-monitor-target { overflow-wrap:anywhere; white-space:normal; }
.cn-monitor-round-select { display:none; }
.cn-monitor-history { gap:8px; }
.cn-monitor-rounds-desktop { width:100%; }
.cn-monitor-state { display:inline-block; white-space:nowrap; font-size:var(--cn-text-small); line-height:22px; padding:0 6px; border-radius:3px; background:var(--cn-chip-bg); color:var(--cn-ink); }
.cn-monitor-state.ok { background:var(--cn-ok-bg); color:var(--cn-ok-ink); }
.cn-monitor-state.problem { background:var(--cn-problem-bg); color:var(--cn-error-ink); }
.cn-monitor-state.warning { background:var(--cn-attention-bg); color:var(--cn-attention-line); }
.cn-monitor-inspector { display:grid; grid-template-columns:240px minmax(0,1fr); gap:20px; width:100%; }
.cn-monitor-rounds { min-width:0; }
.cn-monitor-round-list { max-height:480px; overflow:auto; border:1px solid var(--cn-line); border-radius:4px; }
.cn-monitor-round-choice { display:flex; justify-content:space-between; gap:8px; width:100%; padding:9px 10px; text-align:left; border:0; border-bottom:1px solid var(--cn-line-soft); background:var(--cn-panel); color:var(--cn-ink); cursor:pointer; font:inherit; font-variant-numeric:tabular-nums; }
.cn-monitor-round-choice:hover { background:var(--cn-table-hover); }
.cn-monitor-round-choice[aria-pressed=true] { background:var(--cn-action-hover); box-shadow:inset 3px 0 var(--cn-focus); color:var(--cn-link); font-weight:600; }
.cn-monitor-round-choice:focus-visible, .cn-monitor-scroll:focus-visible { outline:2px solid var(--cn-focus); outline-offset:-2px; }
.cn-monitor-detail { min-width:0; width:100%; }
.cn-monitor-toolbar { display:flex; flex-wrap:wrap; align-items:center; gap:8px; width:100%; }
.cn-monitor-context { min-width:0; overflow-wrap:anywhere; }
.cn-monitor-header { width:100%; min-width:0; overflow-wrap:anywhere; font-weight:600; font-variant-numeric:tabular-nums; }
.cn-monitor-header > *, .cn-monitor-header-next > * { display:inline; }
.cn-monitor-exact { display:flex; flex-wrap:wrap; align-items:center; gap:4px 12px; }
.cn-live-view.cn-live-stopped .cn-map { opacity:.6; }
@media (forced-colors: active) { .cn-live-view.cn-live-stopped .cn-map { opacity:1; border:2px dashed CanvasText; } }
@media(max-width:900px) { .cn-monitor-inspector { grid-template-columns:1fr; } .cn-monitor-selected-title { display:none; } .cn-monitor-rounds-desktop { display:none; } .cn-monitor-round-select { display:block; width:100%; } }
@media(max-width:600px) { .cn-monitor-actions { flex-wrap:wrap; } .cn-monitor-table th, .cn-monitor-table td { padding:7px; } }
/* Results first (R2-05): the tab panels do not clip, so a table's toolbar can stick to the window. */
.cn-monitor-panels.q-panel-parent, .cn-monitor-panels > .q-panel, .cn-monitor-panels .q-tab-panel { overflow:visible; }
.cn-monitor-live { display:flex; flex-direction:column; gap:16px; }
'''


def focus_round_script(focus):
    """The History list was drawn again: the round chosen (``focus='round'``), or the button that stepped to it
    (``earlier``, ``later``, ``round-select``), takes the focus back, unless the reader has moved it on."""
    import json
    selector = ('.cn-monitor-round-choice[aria-pressed=true]' if focus == 'round'
                else f'[data-monitor-detail="{focus}"]')
    return f'''(() => {{
const selected = document.querySelector('.cn-monitor-round-choice[aria-pressed=true]');
const list = selected?.parentElement;
if (selected && selected.offsetParent !== null && list) list.scrollTop += selected.getBoundingClientRect().top - list.getBoundingClientRect().top - list.clientHeight / 2 + selected.offsetHeight / 2;
if (document.activeElement !== document.body) return;
const opposite = {{earlier:'later', later:'earlier'}}[{json.dumps(focus)}];
const candidates = [document.querySelector({json.dumps(selector)}),
  opposite ? document.querySelector(`[data-monitor-detail="${{opposite}}"]:not([disabled])`) : null,
  selected, document.querySelector('[data-monitor-detail="round-select"]')];
const control = candidates.find(element => element && element.offsetParent !== null && !element.matches('[disabled]'));
(control?.querySelector('input') || control)?.focus({{preventScroll:true}});
}})()'''


# A History pager that was disabled while its list was read gets the focus back from Refresh history, which held it
# meanwhile, only while Refresh still has it and the reader has done nothing else.
PAGER_FOCUS = '''(() => {
const fallback = document.querySelector('[data-monitor-history=refresh]');
const marker = fallback?.cnHistoryPendingFocus;
if (marker && document.activeElement === fallback && fallback.offsetParent !== null) {
  document.querySelector(`[data-monitor-history="${marker}"]:not([disabled])`)?.focus();
}
if (fallback) delete fallback.cnHistoryPendingFocus;
})()'''
