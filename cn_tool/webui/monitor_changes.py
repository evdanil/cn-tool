"""The Monitor's change feed (plan 7.4, R3-07): the hosts whose seen state a complete round changed, newest last.

Pure, no NiceGUI. One ``ChangeFeed`` belongs to one Monitor job's live cache (``worker.MonitorLiveCache``), which
calls ``record`` on the run thread under its lock after each complete round and ``since`` to answer
``monitor_live_changes``. The source is ``Tracker.changed()`` as the round's ``monitor_map.Snapshot`` copied it (the
hosts the Map shows in reverse video): ``before`` is the cell of the previous round's snapshot, ``after`` this one's,
``block`` and ``cell`` the host's place in the Map. The first round of a run has no entries.

Every change gets a sequence number, from 1, so ``changes_seq`` of ``monitor_update`` (the newest) says whether there
is anything new; the feed keeps the last ``CHANGES_KEPT`` entries and a gap in the numbers is what it let go.
"""
from collections import deque

from .protocol import CHANGES_KEPT, MAP_CELLS_MAX, SEQ_MAX, valid_change

HOST_MAX = 255  # protocol._valid_change: the host and address texts


def places(blocks):
    """Host index -> ``(block, cell)``: the first place the Map draws the host (a subnet's cell, or a ``Hosts`` row).

    Only places the protocol can carry (block and cell below ``MAP_CELLS_MAX``): a ``Hosts`` block of more single
    targets than that has rows the Map cannot address, and a host found only there has no place."""
    found = {}
    for number, block in enumerate(blocks[:MAP_CELLS_MAX]):
        hosts = block.cells if block.network is not None else [index for _, index in block.names]
        for cell, index in enumerate(hosts[:MAP_CELLS_MAX]):
            if index is not None:
                found.setdefault(index, (number, cell))
    return found


def unavailable(query):
    """The answer for a query of no live run: another job or run, or no Monitor yet."""
    answer = {key: query[key] for key in ('job_id', 'run_id', 'after', 'query_id')}
    answer.update(entries=[], last_seq=0, status='unavailable')
    return answer


class ChangeFeed:
    """The entries of one run. Not locked: its owner (the live cache) calls it under its own lock."""

    def __init__(self):
        self.entries = deque(maxlen=CHANGES_KEPT)
        self.last_seq = 0
        self._places = None  # built at the first round that records: the blocks are the run's, built once

    def record(self, revision, at, previous, snapshot, rows_by_host):
        """Add the round ``revision`` (started ``at``) whose ``snapshot`` follows ``previous`` (``None`` for the
        first). ``rows_by_host``: the round's rows, ``(host, address, result, tcp)`` by host. Only the entries the
        feed keeps are built, so a round that changes a /16 costs its changed set and no more. An entry the protocol
        would refuse is counted and not kept (a gap, as for one let go), so no answer of the feed can fail to encode
        and end the worker."""
        changed = snapshot.changed
        if previous is None or not changed or len(previous.cells) != len(snapshot.cells):
            return
        if self._places is None:
            self._places = places(snapshot.blocks)
        kept = sorted(changed)[-CHANGES_KEPT:]
        first = self.last_seq + len(changed) - len(kept) + 1
        last_seq = min(self.last_seq + len(changed), SEQ_MAX)
        for offset, index in enumerate(kept):
            host = str(snapshot.hosts[index])
            row = rows_by_host.get(host)
            block, cell = self._places.get(index, (None, None))
            entry = dict(seq=first + offset, at=at, round=revision, host=host[:HOST_MAX],
                         address=str(row[1] if row is not None else '')[:HOST_MAX],
                         before=previous.cells[index], after=snapshot.cells[index], block=block, cell=cell)
            if valid_change(entry, 0, last_seq):
                self.entries.append(entry)
        self.last_seq = last_seq

    def since(self, after, limit):
        """At most ``limit`` entries numbered after ``after``, oldest first, as copies."""
        found = []
        for entry in self.entries:
            if entry['seq'] > after:
                found.append(dict(entry))
                if len(found) == limit:
                    break
        return found
