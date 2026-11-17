"""The report gate: one job at a time saves to the accumulated workbook (plan section 5.4, R3-01).

``reports.finish_*_report`` says whether *this* attempt saved by the difference of two process-wide counters of
``file_io`` (``saves_completed``, ``save_failures``) read before and after its writes. Two jobs that end at once
would count each other's writes, so each save runs inside one gate: a second saver waits in slices of
``SLICE_SECONDS``, checking its own stop between them, and leaves without saving once it is stopped. With one job
at a time (Release 3 until R3-03) the gate is always free and changes nothing.

Lock order: the gate is taken before the worker's ``operation_lock``, never while holding it. The cancel handler
needs ``operation_lock``; a job that waited for the gate with it held would block Stop and the other saver (which
takes ``operation_lock`` inside the gate) for good. ``worker_slots.SlotGate`` refuses such a call.

Pure: no NiceGUI, and no worker state; the worker builds one ``ReportGate`` and hands it to its jobs in their
``GatedControl``.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Event, Lock
from typing import Iterator, Optional

from cn_tool.core.operation import OperationControl

SLICE_SECONDS = 0.05


class ReportGate:
    """A lock taken in slices, so that a waiter can give up when its job is stopped."""

    def __init__(self) -> None:
        self._lock = Lock()

    def enter(self, stop: Optional[Event] = None, on_wait=None) -> bool:
        """Wait for the gate; False, without it, once ``stop`` is set while waiting (None: wait however long).
        ``on_wait()`` is called once, when the first slice has passed and the gate is still held (never for a gate that
        is free, or free again within a slice)."""
        told = False
        while not self._lock.acquire(timeout=SLICE_SECONDS):
            if on_wait is not None and not told:
                told = True
                on_wait()
            if stop is not None and stop.is_set():
                return False
        return True

    def leave(self) -> None:
        self._lock.release()

    @contextmanager
    def turn(self, stop: Optional[Event] = None) -> Iterator[bool]:
        """``enter`` for a ``with`` block: yields whether the gate was entered, and leaves it only then."""
        entered = self.enter(stop)
        try:
            yield entered
        finally:
            if entered:
                self.leave()


@dataclass
class GatedControl(OperationControl):
    """The control of a worker job: an ``OperationControl`` that also carries the worker's report gate.

    ``abandon`` is set when the session is given up (a closed pipe, an interrupt): a job that saves after Stop (the
    Monitor) and is waiting for the gate gives up its wait then; a free gate it still enters.
    """

    report_gate: Optional[ReportGate] = None
    abandon: Optional[Event] = None


@contextmanager
def report_turn(control: OperationControl, *, honour_stop: bool = True) -> Iterator[bool]:
    """The job's turn to save: always given to a control without a gate (callers outside the worker save as
    before). ``honour_stop=False`` for a job that saves after Stop (the Monitor): a wait for the gate ends when the
    control's ``abandon`` is set, if it has one; a free gate is entered whatever it says."""
    gate = getattr(control, 'report_gate', None)
    if gate is None:
        yield True
        return
    with gate.turn(control.stop if honour_stop else getattr(control, 'abandon', None)) as entered:
        yield entered
