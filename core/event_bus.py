"""Simple publish/subscribe event bus used for cross-module notifications."""
from __future__ import annotations

from collections import defaultdict
import itertools
import logging
import threading
from typing import Any, Callable, DefaultDict, List, Optional, Tuple

EventCallback = Callable[[Any], None]


class EventBus:
    """Thread-safe in-process event dispatcher."""

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self._logger = logger
        self._lock = threading.Lock()
        self._subscribers: DefaultDict[str, List[Tuple[int, EventCallback]]] = defaultdict(list)
        self._token_source = itertools.count(1)

    def subscribe(self, event_name: str, callback: EventCallback) -> int:
        """Register *callback* to be invoked when *event_name* is published."""
        if not callable(callback):  # pragma: no cover - defensive guard
            raise TypeError("callback must be callable")
        token = next(self._token_source)
        with self._lock:
            self._subscribers[event_name].append((token, callback))
        return token

    def unsubscribe(self, token: int) -> bool:
        """Remove a previously registered callback using its subscription *token*."""
        with self._lock:
            for event_name, callbacks in list(self._subscribers.items()):
                for index, (stored_token, _) in enumerate(callbacks):
                    if stored_token == token:
                        callbacks.pop(index)
                        if not callbacks:
                            self._subscribers.pop(event_name, None)
                        return True
        return False

    def publish(self, event_name: str, payload: Any | None = None) -> None:
        """Invoke all listeners subscribed to *event_name* with *payload*."""
        with self._lock:
            callbacks = list(self._subscribers.get(event_name, ()))
        for _, callback in callbacks:
            try:
                callback(payload)
            except Exception:  # pragma: no cover - logging guard
                if self._logger:
                    self._logger.exception("Event handler failure for '%s'", event_name)

    def clear(self) -> None:
        """Remove every subscriber from the bus."""
        with self._lock:
            self._subscribers.clear()
