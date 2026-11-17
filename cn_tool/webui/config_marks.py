"""Where a configuration line matched: ``<mark>`` around the match, for the matches table (R2-07, finding m8).

The search child computes the spans (``cn_tool.modules.config_search.match_spans``: ``[start, end]`` offsets into the
line as sent, at most ``MAX_MARKS``) while it has the match, and they travel with the row (the sixth field of a wire
row, validated by ``protocol.validate``). This module only escapes the line and puts the marks around the spans: no
regular expression of a user is compiled or run in the web process, whatever the line. A row whose spans are missing
or malformed is shown unmarked. The line is escaped first, so nothing of a configuration is ever markup. Pure: the
standard library only.
"""
from html import escape

MAX_MARKS = 20


def valid_spans(line, spans) -> bool:
    """True for a list of at most ``MAX_MARKS`` ascending, non-overlapping ``[start, end]`` integer pairs with
    ``0 <= start < end <= len(line)`` (``bool`` is not an integer here)."""
    if not isinstance(spans, (list, tuple)) or len(spans) > MAX_MARKS:
        return False
    size, at = len(str(line)), 0
    for span in spans:
        if not isinstance(span, (list, tuple)) or len(span) != 2:
            return False
        start, end = span
        if type(start) is not int or type(end) is not int or not at <= start < end <= size:
            return False
        at = end
    return True


def mark_html(line, spans) -> str:
    """The line as escaped HTML with a ``<mark>`` around each span; unmarked when the spans are not valid for it."""
    line = '' if line is None else str(line)
    out, at = [], 0
    for start, end in spans if valid_spans(line, spans) else ():
        out.append(escape(line[at:start]))
        out.append(f'<mark>{escape(line[start:end])}</mark>')
        at = end
    out.append(escape(line[at:]))
    return ''.join(out)
