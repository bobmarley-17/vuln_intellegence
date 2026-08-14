"""Tests for the cooperative cancellation/pause primitive used by every
background pipeline job (source scans, NVD discovery, Action1 sync)."""
from __future__ import annotations

import threading
import time
import unittest

from modules.job_control import CancellationToken, JobCancelled


class CancellationTokenTests(unittest.TestCase):
    def test_checkpoint_is_a_noop_when_untouched(self):
        token = CancellationToken()
        token.checkpoint()  # must not raise or block

    def test_cancel_makes_checkpoint_raise(self):
        token = CancellationToken()
        token.cancel()
        with self.assertRaises(JobCancelled):
            token.checkpoint()

    def test_pause_blocks_checkpoint_until_resumed(self):
        token = CancellationToken()
        token.pause()
        reached = threading.Event()

        def worker():
            token.checkpoint()
            reached.set()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        time.sleep(0.2)
        self.assertFalse(reached.is_set())  # still blocked

        token.resume()
        thread.join(timeout=2)
        self.assertTrue(reached.is_set())

    def test_cancel_while_paused_wakes_it_up_and_raises(self):
        token = CancellationToken()
        token.pause()
        error_seen = threading.Event()

        def worker():
            try:
                token.checkpoint()
            except JobCancelled:
                error_seen.set()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        time.sleep(0.2)
        token.cancel()
        thread.join(timeout=2)
        self.assertTrue(error_seen.is_set())

    def test_is_paused_and_is_cancelled_reflect_state(self):
        token = CancellationToken()
        self.assertFalse(token.is_paused)
        self.assertFalse(token.is_cancelled)
        token.pause()
        self.assertTrue(token.is_paused)
        token.cancel()
        self.assertTrue(token.is_cancelled)
        self.assertFalse(token.is_paused)  # cancel() also clears pause


if __name__ == "__main__":
    unittest.main()
