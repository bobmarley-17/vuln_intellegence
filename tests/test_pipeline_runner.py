"""Tests for PipelineRunner's pause/resume/cancel controls -- the single
global control that governs whatever background job (source scan, NVD
discovery, Action1 sync, full run) happens to be running, since only one
ever runs at a time."""
from __future__ import annotations

import threading
import time
import unittest

from dashboard.app import PipelineRunner


class DummyPipeline:
    """PipelineRunner only stores this; job functions passed to start()
    don't need a real Pipeline for these tests."""


class PipelineRunnerStatusTests(unittest.TestCase):
    def setUp(self):
        self.runner = PipelineRunner(DummyPipeline())

    def test_status_reports_idle_by_default(self):
        status = self.runner.status()
        self.assertFalse(status["running"])
        self.assertFalse(status["paused"])
        self.assertFalse(status["cancelled"])

    def test_pause_and_cancel_return_false_when_nothing_is_running(self):
        self.assertFalse(self.runner.pause())
        self.assertFalse(self.runner.resume())
        self.assertFalse(self.runner.cancel())


class PipelineRunnerPauseResumeTests(unittest.TestCase):
    def setUp(self):
        self.runner = PipelineRunner(DummyPipeline())

    def test_pause_blocks_progress_and_resume_continues_it(self):
        started = threading.Event()
        progress = {"n": 0}

        def job(token):
            started.set()
            for i in range(20):
                token.checkpoint()
                progress["n"] = i
                time.sleep(0.05)
            return "done"

        self.runner.start("Test job", job, wait_if_busy=False)
        self.assertTrue(started.wait(timeout=2))
        time.sleep(0.1)  # let it get a little way into the loop

        self.assertTrue(self.runner.pause())
        time.sleep(0.3)
        self.assertTrue(self.runner.status()["paused"])
        stalled_at = progress["n"]
        time.sleep(0.3)
        self.assertEqual(progress["n"], stalled_at)  # made no progress while paused

        self.assertTrue(self.runner.resume())
        deadline = time.time() + 3
        while time.time() < deadline and self.runner.status()["running"]:
            time.sleep(0.05)

        status = self.runner.status()
        self.assertFalse(status["running"])
        self.assertFalse(status["paused"])
        self.assertIsNone(status["last_error"])
        self.assertFalse(status["cancelled"])
        self.assertEqual(status["last_result"], "done")


class PipelineRunnerCancelTests(unittest.TestCase):
    def setUp(self):
        self.runner = PipelineRunner(DummyPipeline())

    def test_cancel_stops_a_running_job_and_marks_it_cancelled(self):
        started = threading.Event()

        def job(token):
            started.set()
            while True:
                token.checkpoint()
                time.sleep(0.05)

        self.runner.start("Test job", job, wait_if_busy=False)
        self.assertTrue(started.wait(timeout=2))
        self.assertTrue(self.runner.cancel())

        deadline = time.time() + 2
        while time.time() < deadline and self.runner.status()["running"]:
            time.sleep(0.05)

        status = self.runner.status()
        self.assertFalse(status["running"])
        self.assertTrue(status["cancelled"])
        self.assertIsNone(status["last_error"])  # cancellation is not a failure

    def test_cancel_wakes_up_a_paused_job_instead_of_leaving_it_stuck(self):
        started = threading.Event()

        def job(token):
            started.set()
            while True:
                token.checkpoint()
                time.sleep(0.05)

        self.runner.start("Test job", job, wait_if_busy=False)
        self.assertTrue(started.wait(timeout=2))
        self.assertTrue(self.runner.pause())
        time.sleep(0.2)
        self.assertTrue(self.runner.status()["paused"])

        self.assertTrue(self.runner.cancel())
        deadline = time.time() + 2
        while time.time() < deadline and self.runner.status()["running"]:
            time.sleep(0.05)

        self.assertFalse(self.runner.status()["running"])
        self.assertTrue(self.runner.status()["cancelled"])


if __name__ == "__main__":
    unittest.main()
