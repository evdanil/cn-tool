"""Resizable multi-line boxes (the Targets boxes, Configuration Search's terms): a vertical handle on a desktop.

On a desktop (a fine pointer and a window at least 600 px wide) a box that holds a list can be dragged taller, up to
``70vh``, and down to three lines. Typing in it still grows it by itself (Quasar's ``autogrow``) up to the ten-line
comfort height, as before. A height the user dragged to wins: from the end of the drag the box keeps it, whatever is
typed, pasted or restored into it afterwards (it scrolls inside when the text is longer). Nothing else is changed: a
phone, or any window that does not match the query, keeps the box as it was (autogrow, no handle).

How the drag is told from autogrow, which writes the same inline ``style.height``:

- Pressing the box's bottom-right corner (the handle) lifts the ten-line limit (``data-cn-drag``: ``max-height``
  ``70vh``) and takes any earlier hold off, so that the browser's own resize can write the height.
- At the end of the press, a height that differs from the one at the start is the user's: it is held by a rule with
  ``!important`` on a custom property (``--box-h``, ``data-cn-h``). A stylesheet ``!important`` wins over the inline
  height that autogrow writes on every input, and over a ``style.height`` assignment of any kind, so nothing needs
  to fight it; the text area keeps its scroll position because autogrow's measuring (it sets ``1px`` and reads
  ``scrollHeight``) has no effect on the layout either.
- Quasar's autogrow also writes ``overflow-y`` (hidden when the text fits under the box's max-height, which is 70vh
  here): a held box would lose its scrollbar and wheel with text taller than the box, so ``overflow-y:auto`` is held too.
- A press that moved nothing leaves the box as it was.

One listener pair on the document serves every box marked ``cn-resizable`` (``form_field`` marks a textarea); it is
installed once per document (``scope.add_once``). The dragged height lives on the element: a new box (a reload, a tool
opened again) starts from autogrow.
"""

MEDIA = '(pointer: fine) and (min-width: 600px)'
LINES = 3  # the least height of the box, in lines of 1.5em
COMFORT = 10  # the lines autogrow grows to by itself (the pages' own max-height)
CORNER = 22  # px from the box's bottom-right corner that count as the handle

CSS = f'''
@layer overrides {{ @media {MEDIA} {{
  .cn-resizable textarea {{ resize:vertical !important; min-height:calc({LINES} * 1.5em) !important; }}
  .cn-resizable textarea:not([data-cn-drag]):not([data-cn-h]) {{ max-height:calc({COMFORT} * 1.5em + 16px) !important; }}
  .cn-resizable textarea[data-cn-drag] {{ max-height:70vh !important; overflow-y:auto !important; }}
  .cn-resizable textarea[data-cn-h] {{ height:var(--box-h) !important; max-height:70vh !important; overflow-y:auto !important; }}
}} }}
'''

SCRIPT = '''<script>
(() => {
  if (window.cnBoxResize) return;
  window.cnBoxResize = true;
  const wide = window.matchMedia('%(media)s');
  const state = new WeakMap();   // textarea -> {height, held} at the press of its handle
  const finish = () => {
    for (const box of document.querySelectorAll('.cn-resizable textarea[data-cn-drag]')) {
      const before = state.get(box);
      state.delete(box);
      const height = Math.round(box.getBoundingClientRect().height);
      box.removeAttribute('data-cn-drag');
      if (before && Math.abs(height - before.height) >= 1) {
        box.style.setProperty('--box-h', height + 'px');
        box.setAttribute('data-cn-h', '');
      } else if (before && before.held) {
        box.style.setProperty('--box-h', before.held);
        box.setAttribute('data-cn-h', '');
      }
    }
  };
  document.addEventListener('pointerdown', (event) => {
    const box = event.target;
    if (!wide.matches || !(box instanceof HTMLTextAreaElement) || !box.closest('.cn-resizable')) return;
    const rect = box.getBoundingClientRect();
    if (event.clientX < rect.right - %(corner)d || event.clientY < rect.bottom - %(corner)d) return;
    const height = Math.round(rect.height);
    state.set(box, {height, held: box.hasAttribute('data-cn-h') ? box.style.getPropertyValue('--box-h') : ''});
    box.removeAttribute('data-cn-h');
    box.style.height = height + 'px';
    box.setAttribute('data-cn-drag', '');
  }, true);
  for (const name of ['pointerup', 'pointercancel', 'mouseup', 'dragend']) window.addEventListener(name, finish, true);
  // A press whose end was not seen (the pointer left the window): the box's next input settles it.
  document.addEventListener('input', (event) => { if (event.target?.hasAttribute?.('data-cn-drag')) finish(); }, true);
})();
</script>''' % dict(media=MEDIA, corner=CORNER)


def apply_assets():
    """The stylesheet and the listeners of the resizable boxes, once per document."""
    from nicegui import ui

    from .scope import add_once

    add_once(ui.context.client, 'box-resize', css=CSS, script=SCRIPT)


def mark(field):
    """Make ``field`` (a ``ui.textarea``) a resizable box. Returns it."""
    apply_assets()
    field.classes('cn-resizable')
    return field
