"""The worker's two job slots (plan section 5.4, R3-02): a Monitor runs beside one one-shot job.

The **monitor** slot holds a Monitor; the **one-shot** slot holds any other job (Subnets, IP, Ping, Configuration
Search, Site Demobilization) and also the runtime's start and reload threads. Each has its own thread, job, stop
and saving flag, so that each job stops alone and ``shutdown`` joins both.

Lock order (the worker relies on it): the report gate, then ``operation_lock``, then ``write_lock``. Nothing that
holds ``operation_lock`` waits for the gate, and the statistics lock (``StatsManager``'s own) is taken by
``_run_tracked`` and the modules' ``_publish_stats`` outside both.

Pure: no NiceGUI, and no pipe.
"""
from threading import Event

from .report_gate import ReportGate

MONITOR, ONE_SHOT = 'monitor', 'oneshot'
BUSY_MESSAGES = {MONITOR: 'A Monitor is already running. Try again when it finishes.',
                 ONE_SHOT: 'Another lookup is running. Try again when it finishes.'}


class Slot:
    """One job place of the worker.

    ``saving`` is true from the moment the job takes the report gate (not stopped then) until the job ends: a Stop
    is ignored from then on, so that a saved attempt is never reported as stopped. A job that has announced its save
    but still waits for the gate is not ``saving`` here, and a Stop then makes it leave without saving (5.9).
    """

    def __init__(self, name):
        self.name = name
        self.thread = None
        self.job = None
        self.job_type = None
        self.stop = Event()
        self.saving = False
        self.waiting_snapshot = False
        self.cache = None  # the monitor slot's MonitorLiveCache: kept once its run ends, until the next one starts

    def busy(self):
        return self.thread is not None and self.thread.is_alive()

    def ended(self):
        """What a job's ``finally`` resets (the cache stays: the last round is still answered)."""
        self.job = self.job_type = None
        self.saving = self.waiting_snapshot = False


def slot_name(kind, payload):
    """The slot a ``lookup``, ``demob_lookup`` or ``demob_confirm`` command belongs to."""
    return MONITOR if kind == 'lookup' and payload['lookup_type'] == 'monitor' else ONE_SHOT


class SlotGate:
    """The worker's one report gate as one slot takes it: taking it marks the slot ``saving``.

    ``enter(stop)`` waits for the gate as ``ReportGate.enter`` does; once it has it, it checks the slot's own stop
    again under ``lock`` (the worker's ``operation_lock``, which the cancel handler holds while it reads ``saving``)
    and either marks the slot or gives the gate back. So a Stop either lands before the mark, and the job leaves
    unsaved, or after it, and is ignored. A Monitor, which saves after Stop, waits with the control's ``abandon``
    event (or None) instead of its stop: a Monitor *waiting* for the gate gives up once the session is abandoned,
    but a free gate is always entered, so a lone Monitor still saves its rounds after a closed pipe or Ctrl+C.
    """

    def __init__(self, gate, slot, lock, on_wait=None, on_enter=None):
        self.gate, self.slot, self.lock = gate, slot, lock
        # ``on_wait()`` is called, holding no lock, when the gate is taken and the job has to wait; ``on_enter()`` when
        # such a job has got it. Neither is called for a free gate, so one job's events are as they always were (the
        # worker says `waiting`, then `saving` again: plan 5.9, R3-04).
        self.on_wait, self.on_enter = on_wait, on_enter

    def enter(self, stop=None):
        owned = getattr(self.lock, '_is_owned', None)  # RLock's own check: see the lock order in report_gate
        if owned is not None and owned():
            raise RuntimeError('The report gate is taken before operation_lock, never while holding it.')
        waited = []
        if self.on_wait is None:
            entered = self.gate.enter(stop)
        else:
            entered = self.gate.enter(stop, on_wait=lambda: (waited.append(True), self.on_wait()))
        if not entered:
            return False
        if waited and self.on_enter is not None:
            self.on_enter()
        with self.lock:
            entered = stop is not self.slot.stop or not stop.is_set()  # abandon only ends a wait, never an entry
            if entered:
                self.slot.saving = True
        if not entered:
            self.gate.leave()
        return entered

    def leave(self):
        self.gate.leave()

    turn = ReportGate.turn  # the same ``with`` block, over this class's enter and leave
