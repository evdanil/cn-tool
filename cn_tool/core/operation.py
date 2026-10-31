"""Cooperative control for presentation-independent operations."""
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass
from threading import Event, BoundedSemaphore
from typing import Callable, Optional


class OperationCancelled(Exception):
    """The caller requested that no more work be scheduled."""


@dataclass
class OperationControl:
    stop: Event
    progress: Callable[[str], None]
    counted_progress: Optional[Callable[[str, int, int], None]] = None

    def checkpoint(self) -> None:
        if self.stop.is_set():
            raise OperationCancelled()

    def stage(self, name: str) -> None:
        self.checkpoint()
        self.progress(name)

    def counted_stage(self, stage: str, completed: int, total: int) -> None:
        self.checkpoint()
        if self.counted_progress is None:
            self.progress(stage)
        else:
            self.counted_progress(stage, completed, total)


class ControlledExecutor(ThreadPoolExecutor):
    """Bound submissions to active capacity and check Stop at each request boundary."""
    def __init__(self, control: OperationControl, max_workers: int):
        super().__init__(max_workers=max_workers)
        self.control = control
        self.capacity = BoundedSemaphore(max_workers)

    def submit(self, fn, /, *args, **kwargs):
        self.capacity.acquire()
        try:
            self.control.checkpoint()
        except OperationCancelled as exc:
            self.capacity.release()
            future = Future()
            future.set_exception(exc)
            return future
        def invoke():
            self.control.checkpoint()
            return fn(*args, **kwargs)
        try:
            future = super().submit(invoke)
        except BaseException:
            self.capacity.release()
            raise
        future.add_done_callback(lambda completed: self.capacity.release())
        return future


def controlled_map(fn, items, control: OperationControl, max_workers: int):
    """Yield ordered completed units with at most W submitted, draining on Stop."""
    from collections import deque
    pending = deque()
    iterator = iter(items)
    with ControlledExecutor(control, max_workers) as pool:
        def schedule():
            if control.stop.is_set():
                return
            try:
                item = next(iterator)
            except StopIteration:
                return
            pending.append((item, pool.submit(fn, item)))
        for _ in range(max_workers):
            schedule()
        while pending:
            item, future = pending.popleft()
            try:
                result = future.result()
            except OperationCancelled:
                continue
            yield item, result
            schedule()
