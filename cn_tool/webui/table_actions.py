"""
The Table export group (Download table (CSV), Copy table, Cancel) and the scroll keeper of the Ping and Monitor tables.

The texts and the clipboard outcome are pure (``clipboard_message``, ``progress_text``, ``done_text``); the rest draws
NiceGUI elements and runs a little browser script. Busy buttons are ``aria-disabled`` (clicks ignored), never
``disabled``: Chromium drops the focus of a disabled button to ``body``.
"""
import json

DOWNLOAD = 'Download table (CSV)'
COPY = 'Copy table'
CANCEL = 'Cancel'
COPIED = 'Copied {count} rows. Paste them into Excel.'
DOWNLOADED = 'Downloaded {count} rows.'
NOT_FOCUSED = 'The browser did not allow the copy because this tab was not active. Return to this tab and select Copy table again.'
NOT_ALLOWED = 'The browser did not allow the copy. Select Copy table again.'
UNAVAILABLE = 'This browser cannot copy here: use Download table (CSV).'
COPY_SLOW = ('The copy is taking long; the browser may still finish it. Check the clipboard before pasting, '
             'or use Download table (CSV).')
# A clipboard write carries the whole text over the page's connection: beyond this, Download table (CSV) instead.
MAX_COPY_ROWS = 100_000

# Writes the text, answering 'ok', 'unavailable' or the error's name and message.
_CLIPBOARD = '''(async () => {
  if (!navigator.clipboard || !navigator.clipboard.writeText) return 'unavailable';
  try { await navigator.clipboard.writeText(%s); return 'ok'; }
  catch (error) { return (error && error.name || 'Error') + ': ' + (error && error.message || ''); }
})()'''

# One listener for every kept table: the scroll position of each, with the page it belongs to.
SCROLL_SCRIPT = '''<script>
window.cnScroll = window.cnScroll || {};
document.addEventListener('scroll', event => {
  const box = event.target;
  if (box && box.dataset && box.dataset.cnScroll) {
    window.cnScroll[box.dataset.cnScroll] = {page: box.dataset.cnScrollPage, top: box.scrollTop, left: box.scrollLeft};
  }
}, true);
window.cnRestoreScroll = (name) => {
  const box = document.querySelector('[data-cn-scroll="' + name + '"]');
  const kept = window.cnScroll[name];
  if (!box) return;
  if (kept && kept.page === box.dataset.cnScrollPage) { box.scrollTop = kept.top; box.scrollLeft = kept.left; }
  else { window.cnScroll[name] = {page: box.dataset.cnScrollPage, top: 0, left: 0}; }
};
</script>'''


def count_text(count):
    return f'{count:,}'


def clipboard_message(result, count):
    """``(copied, text)`` for what the browser answered to a clipboard write of ``count`` rows."""
    result = str(result or '')
    if result == 'ok':
        return True, COPIED.format(count=count_text(count))
    if result == 'unavailable':
        return False, UNAVAILABLE
    if 'focus' in result.lower():
        return False, NOT_FOCUSED
    return False, NOT_ALLOWED


def copy_refusal(count):
    """'' when ``count`` rows may be copied, else why not and what to use instead."""
    if count <= MAX_COPY_ROWS:
        return ''
    return (f'{count_text(count)} rows are too many to copy. Use Download table (CSV); '
            f'Copy table takes up to {count_text(MAX_COPY_ROWS)}.')


def progress_text(done, total):
    if total is None:
        return f'Preparing the table: {count_text(done)} rows so far…'
    return f'Preparing {count_text(done)} of {count_text(total)} rows…'


def done_text(count, *, copied=False, note=''):
    text = (COPIED if copied else DOWNLOADED).format(count=count_text(count))
    return f'{text} {note}'.strip()


def scope_description(count, noun='rows'):
    """The scope of both buttons, for ``aria-description``: the whole table as filtered, every page."""
    return f'All {count_text(count)} matching {noun}, every page, as filtered and sorted.'


def render_export_group(*, name, on_download, on_copy, on_cancel=None, description=''):
    """
    The group of a table's toolbar. Returns ``dict(download=, copy=, cancel=, status=)``; ``cancel`` is None without
    ``on_cancel``. ``name`` makes the markers (``data-table-export="<name>-download"``) that focus restoration uses.
    """
    from nicegui import ui

    controls = {}
    with ui.element('div').props('role=group aria-label="Table export"').classes('row items-center gap-2 cn-table-export'):
        for key, label, handler in (('download', DOWNLOAD, on_download), ('copy', COPY, on_copy),
                                    ('cancel', CANCEL, on_cancel)):
            if handler is None:
                controls[key] = None
                continue
            button = ui.button(label, on_click=handler).props('outline dense no-caps')
            button._props['data-table-export'] = f'{name}-{key}'
            if description and key != 'cancel':
                button._props['aria-description'] = description
            controls[key] = button
        if controls['cancel'] is not None:
            controls['cancel'].set_visibility(False)
        controls['status'] = ui.label('').props('role=status aria-live=polite').classes('cn-muted cn-table-export-status')
    return controls


def set_busy(controls, busy):
    """Download and Copy are ignored while a table is prepared; Cancel is shown only then."""
    for key in ('download', 'copy'):
        button = controls.get(key)
        if button is not None:
            button._props['aria-disabled'] = 'true' if busy else 'false'
            button.update()
    if controls.get('cancel') is not None:
        controls['cancel'].set_visibility(busy)


def is_busy(controls):
    button = controls.get('download')
    return button is not None and button._props.get('aria-disabled') == 'true'


def offer_csv(data, filename):
    from nicegui import ui
    ui.download.content(data, filename, 'text/csv')


async def write_clipboard(client, text, count):
    """Put ``text`` on the clipboard; returns ``(copied, message)``."""
    try:
        result = await client.run_javascript(_CLIPBOARD % json.dumps(text), timeout=10)
    except TimeoutError:  # no answer yet: the write may still happen, so it is not reported as refused
        return False, COPY_SLOW
    except Exception:  # the tab went away
        result = ''
    return clipboard_message(result, count)


def keep_scroll(element, name, page):
    """
    Keep ``element``'s scroll position across redraws of the same ``page`` (any value that names it: offset, size,
    sort, filter, group); a different page starts at the top. Needs ``SCROLL_SCRIPT`` in the page head.
    """
    element._props['data-cn-scroll'] = name
    element._props['data-cn-scroll-page'] = json.dumps(page, sort_keys=True, default=str)
    element.client.run_javascript(f'setTimeout(() => window.cnRestoreScroll && window.cnRestoreScroll({json.dumps(name)}), 0)')
