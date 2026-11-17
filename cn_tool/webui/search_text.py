"""The words of the Configuration Search and Site Demobilization pages: pure functions and the help lines.

Plan: `docs/plans/webui-ux-plan.md`, R1-11. The headline says what the user got, zero counts dropped.
"""
from __future__ import annotations

from . import texts

CONFIG_HELP = (
    'Search the configured live configuration repository. Cached search is not supported here; use the menu or '
    'change the configuration to live search.',
    'Keywords use regular expressions and need at least five characters unless recognized as site codes.',
    'A site code searches configuration text as a regular expression; it does not run the Site Demobilization Check.',
    'Up to 200 lines, 1,024 characters per line and 64 KiB in total. Ctrl+Enter starts the search.',
)

DEMOB_HELP = (
    'Look up the site’s networks in Infoblox, review them, then choose whether to search the configured live '
    'configuration repository.',
    'A search can include up to 200 distinct IPv4 networks. Cached configuration search is unavailable here.',
    'Ctrl+Enter in the site code box looks up the site.',
)


def headline(outcome) -> str:
    """"12 matches in 4 devices", "No matches": the result of a search by what it found."""
    if not outcome:
        return ''
    kind = outcome.get('kind')
    if kind not in ('matched', 'partial', 'no_match', 'invalid'):
        return str(outcome.get('message') or '')
    found = int(outcome.get('matched_count') or 0)
    devices = (outcome.get('details') or {}).get('device_count')
    head = []
    if found:
        head.append(texts.plural(found, 'match', 'matches') +
                    (f' in {texts.plural(devices, "device")}' if isinstance(devices, int) and devices else ''))
    elif kind == 'invalid':
        head.append('Nothing was searched')
    else:
        head.append('No matches')
    head.append(texts.counts_line([(int(outcome.get('invalid_count') or 0), 'line not understood', 'lines not understood'),
                                   (int(outcome.get('miss_count') or 0), 'network without a match', 'networks without a match')]))
    if found and outcome.get('warning_count'):
        head.append('network discovery incomplete')
    return ' · '.join(part for part in head if part)
