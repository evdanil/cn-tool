"""
What a handoff writes into a Targets box when the plain list would not fit (R3-09; ``target_cap`` says why a box has a
budget).

"Ping these" and "Monitor these" write one target per line. A result of 65,000 consecutive addresses costs about 15 bytes
each on the wire, more than a box can send, so a run of three or more consecutive IPv4 addresses is written as one
range (``10.0.0.1-10.0.0.200``), which the tokenizer reads as every address of it. The compact text is used only when
``parse`` reads it to exactly the lines the plain list gives (ranges stand for at most the tool's range limit; the rest
of a longer run stays as addresses), and only when it fits; otherwise the handoff is refused, never cut. Pure: no web stack.
"""
import ipaddress

from cn_tool.utils.target_text import RANGE_LIMIT, parse

from . import target_cap

MIN_RUN = 3  # a run shorter than this stays as addresses


def compact(targets, limit=None):
    """``targets`` (one per item) with every run of at least ``MIN_RUN`` consecutive IPv4 addresses, in the list's order,
    as ``first-last``; subnets, names, IPv6 and addresses that are not in canonical form stay as they are. The ranges
    stand for at most ``limit`` addresses in all (the tool's ``RANGE_LIMIT``; None for no limit): what is past it stays
    as single addresses, so the text reads the same."""
    out, run = [], []
    left = [limit]

    def flush():
        n = len(run)
        take = n if left[0] is None else min(n, left[0])
        if take >= MIN_RUN:
            out.append(f'{run[0][0]}-{run[take - 1][0]}')
            if left[0] is not None:
                left[0] -= take
        else:
            take = 0
        out.extend(text for text, _ in run[take:])
        run.clear()

    for target in targets:
        try:
            address = ipaddress.IPv4Address(target)
        except ValueError:
            address = None
        if address is None or str(address) != target:
            flush()
            out.append(target)
        else:
            if run and int(address) != run[-1][1] + 1:
                flush()
            run.append((target, int(address)))
    flush()
    return out


def handoff_text(targets, tool):
    """``(text, compacted)`` for the Targets box: the plain list when it fits, else the compact one when it fits and
    reads the same; ``(None, False)`` when neither (the handoff is refused)."""
    plain = '\n'.join(targets)
    if not target_cap.too_long(plain):
        return plain, False
    short = '\n'.join(compact(targets, RANGE_LIMIT.get(tool)))
    if target_cap.too_long(short) or parse(short, tool).lines != parse(plain, tool).lines:
        return None, False
    return short, True
