"""Cooperative cancellation/pause for long-running background pipeline jobs
(source scans, NVD discovery, Action1 sync). Python threads can't be safely
force-killed, so this is cooperative: long loops call token.checkpoint()
between units of work, and "stop" means "stop at the next safe point," not
instant termination.
"""
from __future__ import annotations

import threading


class JobCancelled(Exception):
    """Raised by CancellationToken.checkpoint() once a job has been
    cancelled, to unwind out of whatever loop is running."""


class CancellationToken:
    def __init__(self):
        self._cancel_event = threading.Event()
        self._pause_event = threading.Event()

    def cancel(self) -> None:
        self._cancel_event.set()
        self._pause_event.clear()  # wake up anything blocked in checkpoint()

    def pause(self) -> None:
        self._pause_event.set()

    def resume(self) -> None:
        self._pause_event.clear()

    @property
    def is_cancelled(self) -> bool:
        return self._cancel_event.is_set()

    @property
    def is_paused(self) -> bool:
        return self._pause_event.is_set()

    def checkpoint(self) -> None:
        """Call between units of work in any long-running loop. Blocks
        while paused (waking every 0.5s to also notice a cancel); raises
        JobCancelled once cancelled, including while waiting out a pause."""
        while self._pause_event.is_set():
            if self._cancel_event.wait(timeout=0.5):
                break
        if self._cancel_event.is_set():
            raise JobCancelled()
