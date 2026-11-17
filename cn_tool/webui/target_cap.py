"""
The cap on a Targets box (R3-09): a box holds what it can send, and an edit that would pass that is not made.

Why. A value the page sends to the server travels in one socket message. NiceGUI's own client drops a message of
999,900 characters or more (it logs "Payload size ... exceeds the maximum allowed limit" in the browser's console and
shows a popup that goes after five seconds) and the server (engine.io's ``max_http_buffer_size``, 1,000,000 bytes)
closes the connection for one it receives over that size, so a paste of about a megabyte never reached the server: no
live line, no value. The limit is not raised (owner's ruling); the box is capped, in the browser, before anything is sent.

The measure is the size the value has on the wire, not a count of characters. The value is sent as a string inside a JSON
string inside the event, so ``wire_bytes(text)`` is the UTF-8 length of ``JSON.stringify(JSON.stringify(text))``: an
address is one byte a character and a line break three, so a list of 70,000 addresses fits, and a control character is
seven. The event's own fields add about 150 bytes. ``BUDGET`` is 900,000, which leaves ``ENVELOPE_BYTES`` and a margin
under the lower of the two limits (``tests/test_webui_target_cap.py`` pins both, read from NiceGUI). The Python function
and the script compute the same number (a table of texts tests it in the browser).

What the browser does. ``cnTargetsCap.guard`` listens for the box's ``input`` (and the end of an IME composition) before
anything else does. An edit that would leave the box over the budget is undone: the box keeps what it held before the
edit (nothing is dropped from it, the edit is refused whole, so a paste is never cut short in silence), the box is put
back before anything else reads it (Quasar, the draft listener and so the server only ever see what fits), and the
message under the box says so. The next edit that fits takes the message away. A composition (IME) is never undone while it runs; at its end an over-budget result is put back to what the box held
before it began, and the draft holds that. A draft stored over the budget (from a version without the cap) is
replaced by what the box then holds when it is refused on restore. The server never writes the box a value over the budget: see
``target_compact`` (the handoff) and ``lookup_inputs.typed_text``.
"""
import json
import re

#: What a value may cost on the wire (see ``wire_bytes``), well under what NiceGUI's client will send.
BUDGET = 900_000
#: What the event's own fields take (``42["event",{"id":..,"client_id":..,"listener_id":..,"args":[..]}]``), with room.
ENVELOPE_BYTES = 1_024
#: The smaller of the two limits: NiceGUI's client drops a message of 1,000,000 - 100 characters or more.
TRANSPORT_LIMIT = 1_000_000 - 100
#: The worst a character costs (a control character: ``\\\\u0001``); a text shorter than ``BUDGET // 7`` always fits.
WORST_WIRE_BYTES_PER_CHAR = 7

MESSAGE = ('Too long: this list is larger than a Targets box can send (about 900 KB). Split the list, use ranges or '
           'CIDR, or use a file with the command line. The box keeps what it had.')

#: The ``sessionStorage`` key of each page's Targets draft (``subnets`` and the Monitor write them).
DRAFT_KEYS = {'subnet': 'cn-tool-draft-subnet', 'ip': 'cn-tool-draft-ip', 'ping': 'cn-tool-draft-ping',
              'monitor': 'cn-tool-draft-monitor-targets'}

_LONE_SURROGATE = re.compile('[\ud800-\udfff]')

SCRIPT = '''
window.cnTargetsCap = window.cnTargetsCap || {
  budget: %d,
  wire(value) { return new TextEncoder().encode(JSON.stringify(JSON.stringify(value))).length; },
  over(value) { return value.length * %d + 6 > this.budget && this.wire(value) > this.budget; },
  guard(input, messageId, draftKey) {
    if (!input || input.cnCapGuard) return;
    input.cnCapGuard = true;
    // ``accepted`` is the last value the box held that fits: taken when an edit or a composition begins (never again
    // inside a composition), and after every check that passes. A refusal puts it back.
    let accepted = this.over(input.value) ? '' : input.value;
    let composing = false;
    const show = on => {
      const note = document.getElementById(messageId);
      if (!note) return;
      note.cnText = note.cnText || note.textContent;
      note.style.display = on ? '' : 'none';
      if (on) {  // cleared and set again, so that a second refusal is announced as well as the first
        note.textContent = '';
        requestAnimationFrame(() => { note.textContent = note.cnText; });
      }
    };
    const refuse = () => {
      const kept = this.over(accepted) ? '' : accepted;
      input.value = kept;  // before Quasar and the draft listener read the box: they and the server only ever see ``kept``
      try { if (draftKey) sessionStorage.setItem(draftKey, kept); } catch (e) { /* a private tab */ }
      show(true);
    };
    input.addEventListener('compositionstart', () => {  // a second start inside a composition (Chromium sends one) keeps the first
      if (composing) return;
      composing = true;
      accepted = this.over(input.value) ? '' : input.value;
    }, true);
    input.addEventListener('beforeinput', () => { if (!composing) accepted = input.value; }, true);
    input.addEventListener('input', event => {
      if (composing || event.isComposing) {  // never undone mid-composition; nothing over the budget goes further
        if (this.over(input.value)) { event.stopImmediatePropagation(); show(true); }
        return;
      }
      if (this.over(input.value)) refuse(); else { accepted = input.value; show(false); }
    }, true);
    input.addEventListener('compositionend', () => {  // never stopped: Quasar ends its own composing state with it
      composing = false;
      if (this.over(input.value)) refuse(); else { accepted = input.value; show(false); }
    }, true);
  },
};
''' % (BUDGET, WORST_WIRE_BYTES_PER_CHAR)


def wire_bytes(text):
    """The size of ``text`` as a Targets box's value goes on the wire: the UTF-8 length of the JSON of its JSON (what
    ``cnTargetsCap.wire`` computes in the browser). A lone surrogate is escaped as JavaScript does; a pair is one
    character."""
    text = (text or '').encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass')
    inner = json.dumps(text, ensure_ascii=False)
    inner = _LONE_SURROGATE.sub(lambda found: '\\u%04x' % ord(found.group()), inner)
    return len(json.dumps(inner, ensure_ascii=False).encode('utf-8'))


def too_long(text):
    """True when ``text`` is more than a Targets box can send."""
    text = text or ''
    return len(text) * WORST_WIRE_BYTES_PER_CHAR + 6 > BUDGET and wire_bytes(text) > BUDGET


def guard_js(message_id, tool):
    """A JavaScript statement for a script in which ``input`` is the Targets box's textarea."""
    return f'window.cnTargetsCap.guard(input, {json.dumps(message_id)}, {json.dumps(DRAFT_KEYS[tool])});'
