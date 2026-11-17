"""
The inputs of the lookup pages (Subnets, IP, Ping): their helper text, what a new tab is offered, and the handoff.

A tab's form is its draft (``sessionStorage``). Pure text and small scripts live here, so that the page modules stay
about layout; the functions that need the web stack import it themselves (``handoff_script`` and
``read_handoff_script`` are plain strings).

The handoff is how "Ping these" and "Monitor these" (``send_targets``) tell the tool what just happened: besides the
targets (the tool's draft) the sender writes ``cn-tool-handoff-<tool>``, ``{count, source, what}``. The tool reads
the entry and removes it at load, says "9 targets from IP results. Review them, then select Run Ping." and puts the
focus on Run. Nothing runs.
"""
import json

EXAMPLE = 'For example 192.0.2.1 or 2001:db8::/64'
TARGET_HELP = {
    'subnet': f'One IP address or subnet per line. {EXAMPLE}.',
    'ip': 'One IP address per line. For example 192.0.2.1 or 2001:db8::1.',
    'ping': f'One IP address, hostname or subnet per line. Hostnames use system DNS. {EXAMPLE}.',
    'monitor': 'One IP address, hostname or subnet per line. Hostnames use system DNS. '
               'For example 192.0.2.1 or example.com.',
}
PORT_HELP = 'Optional: up to five comma-separated ports, for example 22, 443. ICMP is used when available.'
KEYBOARD_HELP = ('Ctrl+Enter (Cmd+Enter on a Mac) in a box runs the tool, like the button; on the line the form folds into, '
                 'it runs the same request again.')
HELP = {
    'subnet': ('Enter one IP address or subnet per line. Subnets asks Infoblox which networks hold them and lists '
               'the networks with their details.', KEYBOARD_HELP),
    'ip': ('Enter one IP address per line. IP asks Infoblox for each address: its status, its names and its '
           'network view.', KEYBOARD_HELP),
    'ping': ('Enter IP addresses, hostnames or subnets, one per line. Ping tests them from this computer; it does '
             'not ask Infoblox, and hostnames use system DNS.',
             'TCP ports are optional (up to five). Without them Ping uses ICMP; with them it tests those ports.',
             KEYBOARD_HELP),
}
RUN_LABEL = {'ping': 'Run Ping', 'monitor': 'Run monitor'}
# Where the targets came from, by the name of the table that sent them (``send_targets.render_send_group``).
SOURCES = {'ip': 'IP results', 'summary': 'Subnet results', 'detail': 'Subnet details'}
MAX_SOURCE = 60  # a handoff entry is read as untrusted text


def keep_typed(key, initial=''):
    """A line for a draft's restore script (``input`` is in scope; ``key`` is a JavaScript expression for the
    draft's ``sessionStorage`` key): text that is in the field and is not what the page put there (``initial``) is
    the user's, though the field's ``input`` listener never saw it, and becomes the tab's draft instead of being
    overwritten by the stored one.

    That happens when a restore has timed out and the page lets the user type while it waits to try again: the
    listener's script and the update that enables the field are sent together, and NiceGUI sends an element's
    update before a queued script, so on a slow connection the field is enabled a moment before the listener is
    there."""
    return (f'if (!input.cnDraftEdited && input.value !== {json.dumps(initial)}) '
            f'{{ input.cnDraftEdited = true; sessionStorage.setItem({key}, input.value); }}')


def helper_text(field, text, classes='cn-muted'):
    """Draw ``text`` here as the helper line of ``field`` and make it the field's description
    (``aria-describedby``): the example a box accepts is text, never a placeholder (tracker O4)."""
    from nicegui import ui
    line = ui.label(text).classes(classes)
    field.props(f'aria-describedby={line.html_id}')
    return line


def draft_keys(lookup_type):
    """The ``sessionStorage`` keys of a lookup page's form: the targets, and Ping's TCP ports."""
    keys = ['cn-tool-draft-' + lookup_type]
    return keys + ['cn-tool-draft-ping-ports'] if lookup_type == 'ping' else keys


def request_form(request, lookup_type):
    """``(targets, ports)`` of the last accepted request of this tool (``controller.last_request``), or None."""
    if not request or 'inputs' not in request:
        return None
    ports = ', '.join(str(port) for port in request.get('tcp_ports') or ()) if lookup_type == 'ping' else ''
    return '\n'.join(str(line) for line in request['inputs']), ports


def new_tab_value(keys, text):
    """JavaScript for the value of a field in a tab that has none of ``keys``: ``text`` only for such a tab (decided
    once per tool and document, before its first field is written: under the root the document is the tab's, and each
    tool asks about its own keys); a tab that has any of the keys, even an empty one, gets ''."""
    return (f"(((window.cnLookupNewTab ??= {{}})[{json.dumps(keys[0])}] ??= "
            f"{json.dumps(keys)}.every(name => sessionStorage.getItem(name) === null)) ? {json.dumps(text)} : '')")


def what_text(targets):
    """What the handoff sends, in words: "9 targets", or, for one huge range, the range ("an IPv6 /64"): its
    address count is not a number anyone can use."""
    import ipaddress
    count = len(targets)
    if count == 1:
        try:
            network = ipaddress.ip_network(targets[0].strip(), strict=False)
        except ValueError:
            network = None
        if network is not None and network.num_addresses > 65536:
            return f"an IPv{network.version} /{network.prefixlen}"
    return f"{count:,} {'target' if count == 1 else 'targets'}"


def handoff_entry(tool, targets, source):
    """The text of the handoff entry for ``tool``."""
    return json.dumps(dict(count=len(targets), source=source, what=what_text(targets)))


def handoff_banner(tool, raw):
    """The sentence for a handoff entry read from storage, or '' when it is not one (nothing is trusted)."""
    try:
        entry = json.loads(raw) if isinstance(raw, str) else None
    except ValueError:
        return ''
    if not isinstance(entry, dict):
        return ''
    count, source, what = entry.get('count'), entry.get('source'), entry.get('what')
    if isinstance(count, bool) or not isinstance(count, int) or count < 1 or tool not in RUN_LABEL:
        return ''
    if not isinstance(source, str) or not source.strip():
        return ''
    if not isinstance(what, str) or not what.strip() or len(what) > 40:
        what = f"{count:,} {'target' if count == 1 else 'targets'}"
    source = ' '.join(source.split())[:MAX_SOURCE]
    return f"{what.strip()} from {source}. Review {'it' if count == 1 else 'them'}, then select {RUN_LABEL[tool]}."


def read_handoff_script(tool):
    """Reads the handoff entry of ``tool`` and removes it, in one step: a reload shows no banner."""
    key = json.dumps('cn-tool-handoff-' + tool)
    return (f"(() => {{ try {{ const value = sessionStorage.getItem({key}); sessionStorage.removeItem({key}); "
            f"return value; }} catch (error) {{ return null; }} }})()")


USED_EVENT = 'handoffused'  # sent to the note, in the browser, by the first edit of Targets or the first start


def handoff_note():
    """The (hidden) line that says where a tab's targets came from; ``show_handoff`` fills it. It is about the
    targets as they arrived, so it goes when the browser says they were edited or started (``USED_EVENT``)."""
    from nicegui import ui
    note = ui.label('').props('role=status data-handoff-note').classes('cn-notice')
    note.set_visibility(False)
    note.on(USED_EVENT, lambda _: note.set_visibility(False))
    return note


async def show_handoff(client, tool, note, run, fields=(), *, opened=None):
    """Say it once if this tab was opened by "Ping these" / "Monitor these" for ``tool``: the sentence in ``note``,
    the focus on ``run``. Nothing runs. ``opened()`` is called first when there is a handoff (the page opens its
    folded form: the targets are there to be reviewed). Returns whether there was one.

    The sentence goes with the first edit of Targets (``fields[0]``) and with the first start: a click on ``run``,
    or Ctrl+Enter / Cmd+Enter in one of ``fields`` while Run is on (``handoff_script``)."""
    if tool not in RUN_LABEL:
        return False
    try:
        raw = await client.run_javascript(read_handoff_script(tool), timeout=5)
    except TimeoutError:
        return False
    text = handoff_banner(tool, raw)
    # The note is deleted with its page when the tool was left during the read (router.py): nothing is drawn then.
    if text and not client.is_deleted and not note.is_deleted:
        if opened is not None:
            opened()
        note.set_text(text)
        note.set_visibility(True)
        client.run_javascript(handoff_script(run.html_id, note.html_id, [field.html_id for field in fields]))
        return True
    return False


def handoff_script(run_id, note_id, field_ids=()):
    """Focus Run once it is enabled (it is disabled until the session is ready, or another job has ended), and
    tell the note when its sentence is over.

    The focus: it only gets a place while it has none. Once the user has put it on a control, or a dialog is open
    (Help, a confirmation, a sign-in), the handoff gives way for good and never takes it back. The note says how
    that ended in ``data-handoff-focus``: 'waiting', 'done' (Run has the focus) or 'left'.

    The sentence: the note gets ``USED_EVENT`` once, at the first edit the user makes in the first field (the
    page's own writing of the draft is not the user's), a click on Run, or Ctrl+Enter / Cmd+Enter in a field
    while Run is on.
    """
    return f'''(() => {{
let tries = 0;
const note = document.getElementById({json.dumps(note_id)});
const run = () => document.getElementById({json.dumps(run_id)});
const off = (element) => !element || element.disabled || element.getAttribute('aria-disabled') === 'true';
const say = (state) => note?.setAttribute('data-handoff-focus', state);
// The h1 a switch inside the root put the focus on (router.py) is no place the user chose.
const free = () => {{
  const active = document.activeElement;
  return (!active || active === document.body || active.matches('h1.cn-page-title'))
    && !document.querySelector('.q-dialog');
}};
const attempt = () => {{
  if (!note?.isConnected) return;
  if (!free()) {{ say('left'); return; }}
  if (!off(run())) {{ run().focus({{preventScroll: true}}); say('done'); return; }}
  if (++tries < 100) setTimeout(attempt, 100); else say('left');
}};
const inside = (event, id) => {{ const root = document.getElementById(id); return !!root && root.contains(event.target); }};
const fields = {json.dumps(list(field_ids))};
const forget = () => {{ for (const type of ['input', 'click', 'keydown']) document.removeEventListener(type, used, true); }};
const used = (event) => {{
  if (!note?.isConnected) {{ forget(); return; }}  // the tool was left (router.py): the note is gone with it
  const edited = event.type === 'input' && event.isTrusted && fields.length > 0 && inside(event, fields[0]);
  const started = event.type === 'click' ? inside(event, {json.dumps(run_id)})
    : event.type === 'keydown' && event.key === 'Enter' && (event.ctrlKey || event.metaKey) && !off(run())
      && fields.some((id) => inside(event, id));
  if (!edited && !started) return;
  forget();
  note?.dispatchEvent(new CustomEvent({json.dumps(USED_EVENT)}));
}};
for (const type of ['input', 'click', 'keydown']) document.addEventListener(type, used, true);
say('waiting');
attempt();
}})()'''
