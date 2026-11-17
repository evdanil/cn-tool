"""A page's own slot as the one job of a snapshot (plan 5.7, R3-03).

The session has two slots: the Monitor's (``SessionSnapshot.monitor_*``) and the one-shot slot of every other tool
(``phase`` and ``active_*``). The texts and the shell were written for one job; ``own_view(state, tool)`` gives the
page of ``tool`` its own slot in that shape: the snapshot itself for a one-shot tool, and for the Monitor a copy whose
``phase`` and ``active_*`` are the monitor slot's. Its ``phase`` is the Monitor's (``running``, ``stopping``,
``saving``), ``ready`` while that slot is idle and the session can take work, and the session's own otherwise
(``starting``, ``setup_required``, ``closing``, ``closed``, ``failed``).

Pure: no NiceGUI.
"""
from dataclasses import replace

USABLE = frozenset({'ready', 'running', 'stopping', 'saving'})


def monitor_view(state):
    """The snapshot as the Monitor's page sees it: its one job is the Monitor's (None for no snapshot)."""
    if state is None:
        return None
    job = state.monitor_job_id
    phase = (state.monitor_phase if job else 'ready') if state.phase in USABLE else state.phase
    # progress_* are the one-shot job's (or left by it): the Monitor's own progress is its monitor_update only.
    return replace(state, phase=phase, active_job_id=job, active_lookup_type='monitor' if job else None,
                   active_started_at=state.monitor_started_at if job else None,
                   active_request=state.monitor_request if job else None,
                   progress_stage='', progress_completed=None, progress_total=None,
                   save_waiting=state.monitor_save_waiting and bool(job))


def own_view(state, tool):
    """The snapshot as the page of ``tool`` sees its own slot."""
    return monitor_view(state) if tool == 'monitor' else state


def running_views(state):
    """The one-shot slot's view and the Monitor's, each only while its slot holds a job (one-shot first)."""
    if state is None:
        return ()
    return tuple(view for view in (state, monitor_view(state)) if view.active_job_id)


def stoppable(view):
    """Whether the job in ``view`` (one slot's view) can be stopped now: a running job, and a one-shot job that waits for
    the report gate (it leaves unsaved). Never a Monitor that saves (it saves what it has whatever it is told), and never
    a job inside the gate (``save_waiting`` is off then)."""
    if not view.active_job_id:
        return False
    return view.phase == 'running' or (view.phase == 'saving' and view.save_waiting
                                       and view.active_lookup_type != 'monitor')
