"""The worker's side of a Ping's partial results (plan R2-06): a ``partial_result`` event for each batch of hosts.

``sender(emit, job)`` is the callback ``worker.perform_ping_lookup`` calls after a batch. A batch is one event, or
several when its rows are more than ``protocol.PARTIAL_BYTES_MAX`` bytes (each event's ``completed`` counts the hosts
up to its last row). Rows that cannot be sent (a row the protocol refuses, a closed pipe) cost the page those rows and
nothing else: the final result still carries every row, and the progress counts go on in their own event. Pure: no
worker state, no NiceGUI.
"""
import json

from .protocol import PARTIAL_BYTES_MAX


def chunks(rows):
    """``rows`` in runs whose JSON list is at most ``PARTIAL_BYTES_MAX`` bytes, in order; a row bigger than that alone
    is a run of its own (the protocol refuses it)."""
    run, size = [], 2  # the list's brackets
    for row in rows:
        try:
            length = len(json.dumps(row, ensure_ascii=False, allow_nan=False).encode('utf-8'))
        except (TypeError, ValueError):
            length = 0  # not JSON: the protocol refuses it with its run
        if run and size + 2 + length > PARTIAL_BYTES_MAX:
            yield run
            run, size = [], 2
        size += length + (2 if run else 0)  # ', ' before every row but the first, as json.dumps writes a list
        run.append(row)
    if run:
        yield run


def sender(emit, job):
    """``callback(batch, completed, total)``: emit the batch's rows with the counts of hosts probed so far."""
    def partial(batch, completed, total):
        done = completed - len(batch)
        for rows in chunks([dict(row) for row in batch]):
            done += len(rows)
            try:
                emit('partial_result', {'lookup_type': 'ping', 'rows': rows, 'completed': done, 'total': total}, job)
            except ValueError:
                pass  # the protocol refused these rows: the final result is what counts
    return partial
