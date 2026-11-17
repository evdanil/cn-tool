"""The worker's side of a Ping's partial results (plan R2-06): one ``partial_result`` event for each batch of hosts.

``sender(emit, job)`` is the callback ``worker.perform_ping_lookup`` calls after a batch. A batch that cannot be sent
(a row the protocol refuses, a closed pipe) costs the page that batch's rows and nothing else: the final result still
carries every row, and the progress counts go on in their own event. Pure: no worker state, no NiceGUI.
"""


def sender(emit, job):
    """``callback(batch, completed, total)``: emit the batch's rows with the counts of hosts probed so far."""
    def partial(batch, completed, total):
        if not batch:
            return
        try:
            emit('partial_result', {'lookup_type': 'ping', 'rows': [dict(row) for row in batch],
                                    'completed': completed, 'total': total}, job)
        except ValueError:
            pass  # the protocol refused these rows: the final result is what counts
    return partial
