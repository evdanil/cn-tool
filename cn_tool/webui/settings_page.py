"""Settings: edit the ``.cn`` file this session reads, line by line (``cn_tool/utils/config_editor.py``)."""
import asyncio
import json
from pathlib import Path

from .subnets import CSS

SETTINGS_CSS = '''
html { scroll-padding-bottom:96px; }
.cn-settings { min-width:0; overflow-wrap:anywhere; }
.cn-settings-files { margin:4px 0 0; padding-left:20px; }
.cn-settings-section { width:100%; background:white; border:1px solid #CBD5DF; border-radius:6px; }
.cn-settings-section .q-expansion-item__content { padding:4px 16px 12px; }
.cn-settings-grid { display:grid; grid-template-columns:repeat(auto-fill, minmax(min(340px, 100%), 1fr)); gap:14px 20px; width:100%; }
.cn-settings-field { min-width:0; gap:2px; }
.cn-settings-field .q-field { width:100%; }
.cn-settings-key { font-family:ui-monospace,monospace; font-size:12px; color:#526675; }
.cn-settings-label { font-weight:600; }
.cn-settings-note { color:#526675; font-size:13px; }
.cn-settings-state { color:#145C87; font-size:12px; font-weight:600; }
.cn-settings-warn { color:#8A5300; font-size:13px; }
.cn-settings-empty:empty { display:none; }
.cn-settings-toggles { gap:4px 20px; flex-wrap:wrap; align-items:center; }
.cn-settings-actions { position:sticky; bottom:0; z-index:2; background:#F5F7FA; padding:10px 0; width:100%; gap:8px; flex-wrap:wrap; align-items:center; border-top:1px solid #CBD5DF; }
'''

RESTART_NOTE = ('This window keeps using the settings it read when it started until you choose Use the new settings '
                'now (when no work is running), or Quit and start it again. Each cn command reads them when it starts.')
RELOAD_NOTE = 'Reading the settings again…'
RELOAD_DONE = ('The new settings are in use. A login typed in this window is asked for again; saved, environment and '
               'GPG credentials are found again.')
RELOAD_FAILED = ' The tools show Setup required until the settings load: correct them here, then select Retry setup.'

SECTION_TITLES = {
    'api': 'Infoblox', 'logging': 'Logging', 'report': 'Report', 'config_repo': 'Configuration repository',
    'gpg': 'GPG credential files', 'auth': 'Credential variable names', 'cache': 'Cache', 'ping': 'Ping Monitor',
    'theme': 'Theme', 'ssh': 'SSH', 'site': 'Site conventions', 'ad': 'Active Directory', 'email': 'Email',
    'sdwan_yaml_search': 'SD-WAN YAML search', 'config_analyzer': 'Config Analyzer', 'stats': 'Statistics',
}

_INFOBLOX_ACCOUNT = ('Setting this gives Infoblox its own account for every cn run of this user, cron jobs included: '
                     'Infoblox then never falls back to the TACACS login.')
_INFOBLOX_VARIABLE = ('When the variable it names is set, Infoblox has its own account for every cn run of this user, '
                      'cron jobs included, and never falls back to the TACACS login.')
SIDE_EFFECTS = {
    'api_user': _INFOBLOX_ACCOUNT,
    'gpg_infoblox_credentials': _INFOBLOX_ACCOUNT,
    'auth_infoblox_user_var': _INFOBLOX_VARIABLE,
    'auth_infoblox_password_var': _INFOBLOX_VARIABLE,
    'api_debug_payloads': 'When true, request and response bodies are written to the log file.',
    'email_send_on_exit': 'When true, cn emails the report each time it exits.',
}

# The select entry for "not in this file": not '' (an empty value in the file is a value of its own).
NOT_SET = 'cn-not-set'
HIDDEN_AUTH = 'a value that is not shown'

BEFORE_UNLOAD = '''<script>
window.addEventListener('beforeunload', event => {
  if (window.cnSettingsDirty) { event.preventDefault(); event.returnValue = ''; }
});
</script>'''


def configuration_files(config_file):
    """
    The file the page edits and the files a run reads, in order (a later file overrides an earlier one).

    The edited file is ``-c FILE`` when the session was started with one, else ``~/.cn``; it is always the last of
    the list, which is the one ``RuntimeSession.open`` reads (``cn_tool.main._get_config_paths``).
    """
    from cn_tool import main
    from cn_tool.utils.config import user_config_path

    arguments = [] if config_file is None else ['-c', str(config_file)]
    chain = main._get_config_paths(main._build_parser().parse_args(arguments))
    target = Path(config_file).expanduser() if config_file else user_config_path()
    return target, chain


def settings_catalogue():
    """Every setting the page offers (``settings_fields`` of the merged schema) and the template's text."""
    from cn_tool.core.loader import collect_plugin_schemas, collect_plugin_settings
    from cn_tool.utils.config import BASE_CONFIG_SCHEMA, sample_config_text
    from cn_tool.utils.config_editor import settings_fields

    template = sample_config_text()
    fields = settings_fields(collect_plugin_schemas(BASE_CONFIG_SCHEMA), template, collect_plugin_settings())
    return fields, template


def shown_value(item, raw):
    """What a box shows for the file's raw value: a readable boolean as true/false, anything else as it is."""
    from cn_tool.utils.config_editor import validate_value

    if raw is None:
        return ''
    if item.type == 'bool':
        value, problem = validate_value(item, raw)
        return raw.strip() if problem else (value or '')
    return raw.strip()


def hides_value(item, raw):
    """
    Whether an ``[auth]`` value stays out of the page: it names a variable, but a password typed there by mistake
    can pass the name check, so it is shown only when it is the default or a variable that exists
    (``env_name_is_shown``, the rule of every cn text that names one).
    """
    from cn_tool.utils.config import env_name_is_shown

    return item.section == 'auth' and bool((raw or '').strip()) and not env_name_is_shown(raw.strip(), item.key)


def inherited_text(item, inherited):
    """What applies when this file does not set ``item``."""
    if item.key in inherited:
        value, path = inherited[item.key]
        shown = HIDDEN_AUTH if hides_value(item, value) else (value or '(empty)')
        return f'Inherited: {shown} (from {path})'
    return f'Default: {item.default}' if item.default else 'Default: not set'


def render_settings(controller):
    from nicegui import ui
    from cn_tool.utils import config_editor as editor

    ui.add_css(CSS + SETTINGS_CSS)
    ui.add_head_html(BEFORE_UNLOAD)
    ui.colors(primary='#145C87')
    target, chain = configuration_files(controller.config_file)
    fields, template = settings_catalogue()
    by_key = {item.key: item for item in fields}
    sections = list(dict.fromkeys(item.section for item in fields))
    latest = dict(document=None, inherited={}, earlier=[], reapply=None, dirty=False, attempted=False,
                  changed=set(), confirmed=None)
    # One entry per field: its item, widget, mode ('auto', 'remove' or 'empty'), whether it was left once, and labels.
    rows, expansions, controls = {}, {}, {}
    save_lock = asyncio.Lock()

    def load():
        documents = [editor.load_document(path) for path in chain[:-1]]
        latest['earlier_documents'] = documents
        latest['earlier'] = [path for path in chain[:-1] if path.is_file()]
        latest['document'] = editor.load_document(target)
        latest['inherited'] = editor.inherited_values(fields, documents, latest['document'])

    load()

    with ui.dialog() as dialog, ui.card():
        dialog_text = ui.label('')
        with ui.row():
            async def confirmed():
                dialog.close()
                action, latest['confirmed'] = latest['confirmed'], None
                if action is not None:
                    result = action()
                    if asyncio.iscoroutine(result):
                        await result
            dialog_ok = ui.button('Continue', on_click=confirmed).mark('settings-confirm')
            ui.button('Cancel', on_click=dialog.close).props('outline')

    async def confirm_then(text, action_label, action):
        """Run ``action`` at once without unsaved changes, else after the person confirms."""
        if not latest['dirty']:
            result = action()
            if asyncio.iscoroutine(result):
                await result
            return
        dialog_text.set_text(text)
        dialog_ok.set_text(action_label)
        latest['confirmed'] = action
        dialog.open()

    with ui.row().classes('w-full items-center justify-between cn-settings'):
        ui.label('Settings').mark('title').classes('text-h4')
        ui.button('Quit application', on_click=lambda: confirm_then(
            'Quit with unsaved changes? They will be lost.', 'Quit', controller.quit)).props('outline').mark('settings-quit')
    with ui.element('nav').props('aria-label=Tools').classes('row items-center gap-4 cn-settings'):
        ui.link('Subnets', '/')
        ui.link('IP', '/ip')
        ui.link('Ping', '/ping')
        ui.link('Monitor', '/monitor')
        ui.link('Configuration Search', '/config-search')
        ui.link('Site Demobilization', '/demobilization')
        ui.link('Settings', '/settings').props('aria-current=page')

    with ui.column().classes('cn-panel cn-settings'):
        with ui.row().classes('items-baseline gap-2'):
            ui.label('Configuration file:').classes('text-weight-bold')
            ui.label(str(target)).classes('cn-settings-key text-body1').mark('settings-target')
        presence = ui.label('').classes('cn-muted').mark('settings-presence')
        ui.label('Settings are read from these files, in order; a later file overrides an earlier one, '
                 'and a setting no file sets keeps its default:').classes('cn-muted')
        with ui.element('ol').classes('cn-settings-files'):
            for path in chain:
                notes = [note for note, applies in (('edited here', _same(path, target)),
                                                    ('not found', not path.is_file())) if applies]
                with ui.element('li'):
                    ui.label(str(path) + (f" ({', '.join(notes)})" if notes else '')).classes('cn-settings-key')
        ui.label(RESTART_NOTE).classes('cn-muted')
        ui.label('Remove takes a setting out of this file, so the inherited value applies again; an emptied box sets '
                 'it to empty here. Passwords are never shown or saved on this page.').classes('cn-muted')

    with ui.row().classes('items-center gap-3 cn-settings'):
        status = ui.label('').props('role=status aria-live=polite').classes('text-weight-bold cn-settings-empty').mark('settings-status')
        use_now = ui.button('Use the new settings now', on_click=lambda: reload_configuration()).mark('settings-use-now')
        use_now.set_visibility(False)
        quit_now = ui.button('Quit now', on_click=controller.quit).props('outline').mark('settings-quit-now')
        quit_now.set_visibility(False)
    with ui.row().classes('items-center gap-3 cn-settings'):
        problem = ui.label('').props('role=alert').classes('text-negative cn-settings-empty').mark('settings-problem')
        keep = ui.button('Reload and keep my edits', on_click=lambda: reload(keep_edits=True)).props('outline').mark('settings-keep')
        keep.set_visibility(False)
    with ui.row().classes('w-full items-center cn-settings-toggles cn-settings'):
        find = ui.input('Find a setting', placeholder='endpoint, report, ssh…').props(
            'outlined dense clearable aria-label="Find a setting"').classes('col-grow').mark('settings-find')
        show_all = ui.switch('Show all settings').mark('settings-all')
        changed_only = ui.switch('Show changed only').mark('settings-changed')
    shown = ui.label('').props('role=status aria-live=polite').classes('cn-muted').mark('settings-shown')

    def entered_value(key):
        """The box as the editor reads it: text to write, '' for an explicit empty value, None for not in the file."""
        row = rows[key]
        item, value = row['item'], row['widget'].value or ''
        if item.type == 'bool' or item.choices:
            return None if value == NOT_SET else value
        if row['mode'] == 'remove':
            return None
        if value:
            return value
        current = editor.file_value(latest['document'], item)
        if row['hidden'] and row['mode'] == 'auto':
            return current  # a value kept out of the page stays as it is until it is replaced or removed
        return '' if current is not None or row['mode'] == 'empty' else None

    def pending():
        entered = {key: entered_value(key) for key in rows}
        return editor.changed_values(fields, latest['document'], entered)

    def field_state(key, changes):
        row = rows[key]
        item = row['item']
        current = editor.file_value(latest['document'], item)
        change = (item.section, item.ini_key) in changes
        value = entered_value(key)
        unsaved = ' (unsaved)' if change else ''
        if value is None:
            text = 'Will be removed from this file' if current is not None else ''
        elif row['hidden'] and value == current:
            text = 'Set in this file (not shown: it is not a variable that exists)'
        elif value == '':
            text = 'Set to empty in this file' + unsaved
        else:
            text = 'Set in this file' + unsaved
        row['state'].set_text(text)
        button = row['button']
        if button is not None:
            if row['mode'] == 'remove':
                button.set_text('Keep')
            elif value == '' and current is None:
                button.set_text("Don't set")
            elif current is not None or value:
                button.set_text('Remove')
            else:
                button.set_text('Set empty')
            # A number, or a path that has a default, cannot be empty: such a field offers Remove only.
            button.set_visibility(button.text != 'Set empty' or editor.empty_allowed(item))
        return change

    def update_actions(*_):
        if not controls:
            return  # the first drawing of the form: the action row comes after it
        document = latest['document']
        changes, problems = pending()
        changed_keys = set()
        for key, row in rows.items():
            if field_state(key, changes):
                changed_keys.add(key)
            message = problems.get(key, '') if (row['touched'] or latest['attempted']) else ''
            row['error'].set_text(message)
            _attribute(row['widget'], 'aria-invalid', 'true' if message else 'false')
            note = editor.path_note(row['item'], entered_value(key)) if row['touched'] and not message else ''
            row['path'].set_text(note)
        latest['changed'] = changed_keys
        count = len(changed_keys)
        if document.problem:
            text = ''
        elif not document.exists:
            if latest['earlier']:
                text = ('This file does not exist yet. Saving creates it with only the settings you set here; '
                        'the earlier files stay in effect.')
            else:
                text = 'This file does not exist yet. Saving creates it from the cn init template.'
            if count:
                text += f' {count} change{"s" if count != 1 else ""}.'
        else:
            text = f'{count} unsaved change{"s" if count != 1 else ""}' if count else 'No unsaved changes'
        if problems and not document.problem:
            text += f'; {len(problems)} setting{"s" if len(problems) != 1 else ""} to correct'
        controls['dirty'].set_text(text)
        controls['save'].set_text('Create file' if not document.exists else 'Save changes')
        # A box that does not pass keeps Save enabled: pressing it names what to correct.
        controls['save'].set_enabled(not document.problem and (bool(count) or bool(problems) or not document.exists)
                                     and not save_lock.locked())
        controls['discard'].set_enabled(bool(count) or bool(problems))
        dirty = bool(count or problems)
        if dirty != latest['dirty']:
            latest['dirty'] = dirty
            ui.run_javascript(f'window.cnSettingsDirty = {"true" if dirty else "false"}')
        apply_filter()

    def draw_presence():
        document = latest['document']
        if document.problem:
            presence.set_text('Read only until the file is corrected.')
            problem.set_text(document.problem)
        elif not document.exists:
            presence.set_text('Not created yet: the earlier files and the defaults apply.')
        else:
            count = len(document.values)
            presence.set_text(f'{count} setting{"s" if count != 1 else ""} in this file.')

    def mark_touched(key):
        rows[key]['touched'] = True
        update_actions()

    def toggle(key):
        """The field's Remove / Keep / Set empty / Don't set button."""
        row = rows[key]
        item = row['item']
        current = editor.file_value(latest['document'], item)
        value = entered_value(key)
        if row['mode'] == 'remove':
            row['mode'] = 'auto'
            row['widget'].value = row['initial']
        elif value == '' and current is None:
            row['mode'] = 'auto'
        elif current is not None or value:
            row['mode'] = 'remove'
            row['widget'].value = ''
        else:
            row['mode'] = 'empty'
        update_actions()

    def on_change(key):
        row = rows[key]
        if row['widget'].value and row['mode'] in ('remove', 'empty'):
            row['mode'] = 'auto'
        if row['item'].type == 'bool' or row['item'].choices:
            row['touched'] = True
        update_actions()

    def draw_field(item, document, inherited):
        current = editor.file_value(document, item)
        hidden = hides_value(item, current)
        initial = '' if hidden else shown_value(item, current)
        if (item.type == 'bool' or item.choices) and current is None:
            initial = NOT_SET
        with ui.column().classes('cn-settings-field') as holder:
            with ui.row().classes('items-baseline gap-2'):
                ui.label(item.label).classes('cn-settings-label')
                ui.label(f'[{item.section}] {item.ini_key}').classes('cn-settings-key')
            state = ui.label('').classes('cn-settings-state cn-settings-empty')
            hint = inherited_text(item, inherited)
            widget = _field_widget(ui, item, initial, hint, bool(document.problem))
            error = ui.label('').classes('text-negative text-sm cn-settings-empty')
            path = ui.label('').classes('cn-settings-warn cn-settings-empty')
            notes = [ui.label(hint).classes('cn-settings-note')]
            if item.help:
                notes.append(ui.label(item.help).classes('cn-settings-note'))
            if item.example and item.example != item.default:
                notes.append(ui.label(f'Template example: {item.example}').classes('cn-settings-note'))
            if item.key in SIDE_EFFECTS:
                notes.append(ui.label(SIDE_EFFECTS[item.key]).classes('cn-settings-warn'))
            button = None
            if not (item.type == 'bool' or item.choices or document.problem):
                button = ui.button('Remove', on_click=lambda key=item.key: toggle(key)).props(
                    'flat dense no-caps').classes('self-start').mark(f'setting-action-{item.section}-{item.ini_key}')
                _attribute(button, 'aria-label', f'Remove, keep or set empty: {item.label}')
        described = ' '.join(f'c{label.id}' for label in [error, path, *notes])
        _attribute(widget, 'aria-describedby', described)
        widget.on_value_change(lambda _, key=item.key: on_change(key))
        widget.on('blur', lambda _, key=item.key: mark_touched(key))
        rows[item.key] = dict(item=item, widget=widget, mode='auto', touched=False, holder=holder, state=state,
                              error=error, path=path, button=button, hidden=hidden, initial=initial)

    @ui.refreshable
    def form():
        rows.clear()
        expansions.clear()
        document = latest['document']
        inherited = latest['inherited']
        for section in sections:
            members = [item for item in fields if item.section == section]
            title = SECTION_TITLES.get(section, section.replace('_', ' ').title())
            set_here = sum(editor.file_value(document, item) is not None for item in members)
            caption = f'[{section}]' + (f' · {set_here} set in this file' if set_here else '')
            with ui.expansion(title, caption=caption, value=section == 'api').classes('cn-settings-section').props(
                    'header-class="text-weight-bold"').mark(f'settings-section-{section}') as expansion:
                expansions[section] = expansion
                if section == 'email':
                    ui.label('The SMTP password ([email] password) is not shown or changed here.').classes('cn-settings-note')
                with ui.element('div').classes('cn-settings-grid'):
                    for item in members:
                        draw_field(item, document, inherited)
        reapply, latest['reapply'] = latest['reapply'], None
        for key, (mode, value) in (reapply or {}).items():
            if key in rows:
                rows[key]['mode'] = mode
                rows[key]['widget'].value = value
        update_actions()  # a refresh may draw later than the call that asked for it: count against the new boxes

    def visible(key, needle):
        row = rows[key]
        item = row['item']
        if row['error'].text:
            return True
        if changed_only.value and key not in latest['changed']:
            return False
        if needle:
            return any(needle in text.lower() for text in (
                item.label, item.ini_key, item.section, f'[{item.section}] {item.ini_key}', item.help,
                SECTION_TITLES.get(item.section, '')))
        return (show_all.value or changed_only.value or item.common
                or editor.file_value(latest['document'], item) is not None)

    def apply_filter(*_):
        if not rows:
            return
        needle = (find.value or '').strip().lower()
        total = 0
        for section, expansion in expansions.items():
            count = 0
            for item in fields:
                if item.section == section:
                    show = visible(item.key, needle)
                    rows[item.key]['holder'].set_visibility(show)
                    count += show
            expansion.set_visibility(count > 0)
            if (needle or changed_only.value) and count:
                expansion.set_value(True)
            total += count
        if needle or changed_only.value:
            shown.set_text(f'{total} setting{"s" if total != 1 else ""} match.' if total else 'No setting matches.')
        elif not show_all.value:
            shown.set_text(f'Showing the common settings and those this file sets ({total} of {len(fields)}). '
                           'Turn on Show all settings for the rest.')
        else:
            shown.set_text(f'Showing all {len(fields)} settings.')

    find.on_value_change(apply_filter)
    show_all.on_value_change(apply_filter)
    changed_only.on_value_change(apply_filter)
    form()

    async def save_changes():
        if save_lock.locked():
            return
        if not await save_once():
            update_actions()  # the lock is free again: offer Save once more

    async def save_once():
        """Save the boxes; True once the form is being redrawn from the saved file (it then counts again itself)."""
        async with save_lock:
            latest['attempted'] = True
            changes, problems = pending()
            update_actions()
            keep.set_visibility(False)
            quit_now.set_visibility(False)
            use_now.set_visibility(False)
            if problems:
                status.set_text('')
                names = ', '.join(by_key[key].label for key in problems)
                problem.set_text(f'Nothing was saved. Correct {len(problems)} setting'
                                 f'{"s" if len(problems) != 1 else ""}: {names}.')
                focus_widget(rows[next(key for key in rows if key in problems)]['widget'])
                return False
            document = latest['document']
            if not changes and document.exists:
                return False
            problem.set_text('')
            status.set_text('Saving…')
            # The boxes stay editable while the file is written: what is typed meanwhile is kept for the new form.
            at_save = {key: (row['mode'], row['widget'].value or '') for key, row in rows.items()}
            base = template if not latest['earlier'] else editor.overlay_header(latest['earlier'])
            try:
                # asyncio.to_thread, not NiceGUI's run.io_bound: that returns None without running the call while
                # NiceGUI thinks the app is stopping, and a save must either happen or fail with a reason.
                saved = await asyncio.to_thread(editor.save_document, document, changes, base)
            except editor.ConfigChanged:
                status.set_text('')
                problem.set_text('The file changed on disk after this page loaded it, so nothing was saved. '
                                 'Reload it, keeping your edits or not.')
                keep.set_visibility(True)
                return False
            except editor.ConfigEditRefused as refusal:
                status.set_text('')
                problem.set_text(f'Nothing was saved: {refusal}')
                return False
            except OSError as exc:
                status.set_text('')
                problem.set_text(f'Could not write the file: {exc.strerror or exc.__class__.__name__}. '
                                 'Nothing was saved.')
                return False
            latest['document'] = saved
            latest['reapply'] = {key: (row['mode'], row['widget'].value or '') for key, row in rows.items()
                                 if (row['mode'], row['widget'].value or '') != at_save.get(key)}
            # A new section can bring a [DEFAULT] key into effect: what is inherited is read again.
            latest['inherited'] = editor.inherited_values(fields, latest['earlier_documents'], saved)
            latest['attempted'] = False
            count = len(changes)
            created = '' if document.exists else 'Created the file. '
            saved_text = f'Saved {count} change{"s" if count != 1 else ""}. ' if count else ''
            status.set_text(f'{created}{saved_text}{RESTART_NOTE}')
            quit_now.set_visibility(True)
            use_now.set_visibility(True)
            draw_presence()
            form.refresh()
            return True

    def reload_configuration():
        try:
            token = controller.reload_configuration()
        except RuntimeError as refusal:
            problem.set_text(str(refusal))
            return
        use_now.set_visibility(False)
        problem.set_text('')
        status.set_text(RELOAD_NOTE)
        latest['reload_token'] = token

        def follow():
            """Say how the reload ended: the worker answers once, and every tab reads the same snapshot."""
            result = controller.snapshot().reload_result or {}
            mine = latest.get('reload_token')
            if (result.get('token') or 0) > (mine or 0):
                latest['reload_token'] = None
                watcher.deactivate()
                status.set_text('The settings were reloaded from another tab.')
                return
            if result.get('token') != mine or result.get('status') == 'pending':
                return
            latest['reload_token'] = None
            watcher.deactivate()
            if result['status'] == 'applied':
                status.set_text(RELOAD_DONE)
                return
            status.set_text('')
            problem.set_text(result['message'] + (RELOAD_FAILED if result['status'] == 'failed' else ''))
            if result['status'] == 'refused':
                use_now.set_visibility(True)

        watcher = ui.timer(0.25, follow)

    async def reload(keep_edits=False):
        old = latest['document']
        kept = {}
        if keep_edits:
            for key, row in rows.items():
                if row['mode'] != 'auto' or (row['widget'].value or '') != row['initial']:
                    kept[key] = (row['mode'], row['widget'].value or '')
        await asyncio.to_thread(load)
        problem.set_text('')
        keep.set_visibility(False)
        quit_now.set_visibility(False)
        use_now.set_visibility(False)
        latest['attempted'] = False
        new = latest['document']
        if keep_edits:
            both = [by_key[key].label for key in kept
                    if editor.file_value(old, by_key[key]) != editor.file_value(new, by_key[key])]
            latest['reapply'] = kept
            status.set_text('Reloaded the file and kept your edits.' + (
                f' Also changed on disk: {", ".join(both)}. Check them before saving.' if both else ''))
        else:
            status.set_text('Reloaded the file.')
        draw_presence()
        form.refresh()

    def discard_changes():
        status.set_text('Discarded unsaved changes.')
        problem.set_text('')
        latest['attempted'] = False
        form.refresh()

    with ui.row().classes('cn-settings-actions'):
        controls['save'] = ui.button('Save changes', on_click=save_changes).mark('settings-save')
        controls['discard'] = ui.button('Discard changes', on_click=lambda: confirm_then(
            'Discard your unsaved changes?', 'Discard', discard_changes)).props('outline').mark('settings-discard')
        ui.button('Reload from file', on_click=lambda: confirm_then(
            'Reload the file and lose your unsaved changes?', 'Reload', reload)).props('outline').mark('settings-reload')
        controls['dirty'] = ui.label('').classes('cn-muted').mark('settings-dirty')
    draw_presence()
    update_actions()


def _field_widget(ui, item, value, hint, read_only):
    label = f'{item.label} ([{item.section}] {item.ini_key})'
    if item.type == 'bool' or item.choices:
        options = {NOT_SET: f'Not set ({hint[0].lower() + hint[1:]})'}
        options.update({choice: choice for choice in (('true', 'false') if item.type == 'bool' else item.choices)})
        if value not in options:
            options[value] = value or '(empty)'  # the file's own spelling, kept until it is changed
        widget = ui.select(options, value=value).props('outlined dense')
    else:
        placeholder = '' if hint == 'Default: not set' else hint.split(': ', 1)[1]
        widget = ui.input(value=value, placeholder=placeholder).props('outlined dense')
    _attribute(widget, 'aria-label', label)
    if read_only:
        widget.disable()
    return widget.mark(f'setting-{item.section}-{item.ini_key}')


def focus_widget(widget):
    """Focus a field when this message arrives, never later.

    ``run_method('focus')`` goes through Quasar's focus queue, which holds the request while a tooltip, menu or dialog
    is opening or closing and runs it when that ends: the reader can have moved on by then.
    """
    widget.client.run_javascript(f'''(() => {{
const root = document.getElementById({json.dumps(widget.html_id)});
(root?.matches('input, textarea') ? root : root?.querySelector('input, textarea, [tabindex]:not([tabindex="-1"])'))?.focus({{preventScroll:true}});
}})()''')


def _attribute(element, name, value):
    """Set one attribute as data: a ``.props('...')`` string is parsed as Python literals, so text never goes in one."""
    if element.props.get(name) != value:
        element.props[name] = value
        element.update()


def _same(left, right):
    try:
        return Path(left).expanduser().resolve() == Path(right).expanduser().resolve()
    except OSError:
        return False
