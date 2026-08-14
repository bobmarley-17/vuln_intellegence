"""Tests for NVD-based CVE discovery: the bulk date-range client method
(against a fake HTTP transport), and the pipeline's discover_from_nvd()
orchestration -- window/watermark math, relevance filtering, dedup, and
that it always reuses the exact same _enrich_cve() path as articles/manual
lookup rather than a second enrichment implementation."""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import requests

from config import Config
from modules.nvd import NVDClient
from modules.pipeline import Pipeline


class FakeNVDResponse:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self.payload = payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"{self.status_code} error")

    def json(self):
        return self.payload


class FakeNVDSession:
    """Stands in for requests.Session, keyed by the request's startIndex
    since every NVD discovery call hits the same URL."""

    def __init__(self, responses_by_start_index: dict):
        self.responses = responses_by_start_index
        self.calls: list[dict] = []

    def get(self, url, params=None, timeout=None):
        self.calls.append(params)
        return self.responses[params.get("startIndex", 0)]


def make_nvd_client(max_retries=2, backoff_factor=1.0):
    return NVDClient(api_key=None, timeout=5, max_retries=max_retries, backoff_factor=backoff_factor, rate_limit_delay=0)


@patch("modules.nvd.time.sleep", new=lambda *_: None)
class FetchPublishedBetweenTests(unittest.TestCase):
    def test_paginates_across_multiple_pages(self):
        session = FakeNVDSession(
            {
                0: FakeNVDResponse(200, {"totalResults": 3, "vulnerabilities": [
                    {"cve": {"id": "CVE-2026-0001"}}, {"cve": {"id": "CVE-2026-0002"}}
                ]}),
                2: FakeNVDResponse(200, {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-2026-0003"}}]}),
            }
        )
        client = make_nvd_client()
        client.session = session
        start = datetime(2026, 8, 12, tzinfo=timezone.utc)
        end = datetime(2026, 8, 14, tzinfo=timezone.utc)

        result = client.fetch_published_between(start, end)

        self.assertEqual(result, ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"])
        self.assertEqual(session.calls[0]["pubStartDate"], "2026-08-12T00:00:00.000Z")
        self.assertEqual(session.calls[0]["pubEndDate"], "2026-08-14T00:00:00.000Z")

    def test_rejects_windows_over_120_days(self):
        client = make_nvd_client()
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 6, 1, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            client.fetch_published_between(start, end)

    def test_retries_after_429_then_succeeds(self):
        class FlakySession:
            def __init__(self):
                self.calls = 0

            def get(self, url, params=None, timeout=None):
                self.calls += 1
                if self.calls == 1:
                    return FakeNVDResponse(429, {})
                return FakeNVDResponse(200, {"totalResults": 0, "vulnerabilities": []})

        session = FlakySession()
        client = make_nvd_client(max_retries=2)
        client.session = session
        result = client.fetch_published_between(
            datetime(2026, 8, 12, tzinfo=timezone.utc), datetime(2026, 8, 13, tzinfo=timezone.utc)
        )
        self.assertEqual(result, [])
        self.assertEqual(session.calls, 2)

    def test_raises_after_repeated_timeout_instead_of_returning_partial_data(self):
        class TimeoutSession:
            def get(self, url, params=None, timeout=None):
                raise requests.exceptions.Timeout()

        client = make_nvd_client(max_retries=1)
        client.session = TimeoutSession()
        with self.assertRaises(RuntimeError):
            client.fetch_published_between(
                datetime(2026, 8, 12, tzinfo=timezone.utc), datetime(2026, 8, 13, tzinfo=timezone.utc)
            )

    def test_api_key_never_appears_in_log_records(self):
        session = FakeNVDSession({0: FakeNVDResponse(429, {})})
        client = make_nvd_client(max_retries=1)
        client.api_key = "super-secret-key"
        client.session = session
        with self.assertLogs("vuln_intel.nvd", level="WARNING") as captured:
            with self.assertRaises(RuntimeError):
                client.fetch_published_between(
                    datetime(2026, 8, 12, tzinfo=timezone.utc), datetime(2026, 8, 13, tzinfo=timezone.utc)
                )
        self.assertTrue(captured.output)
        for line in captured.output:
            self.assertNotIn("super-secret-key", line)


def _make_pipeline(tmpdir) -> Pipeline:
    cfg = Config(cache_folder=str(Path(tmpdir)))
    cfg.ensure_folders()
    pipeline = Pipeline(cfg)
    # Every test stubs out the actual network-touching enrichment steps --
    # discover_from_nvd() must reuse the same _enrich_cve() as every other
    # path, so these are the *same* stub points the RT-draft pipeline tests use.
    pipeline.mitre.enrich = lambda cve_id, cve: None
    pipeline.epss.enrich = lambda cve_id, cve: None
    pipeline.nvd.enrich = lambda cve_id, cve: []
    pipeline.kev.enrich = lambda cve_id, cve: setattr(cve, "kev_listed", False)
    return pipeline


class DiscoverFromNvdRelevanceTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.pipeline = _make_pipeline(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_kev_listed_cve_is_kept(self):
        self.pipeline.kev.enrich = lambda cve_id, cve: setattr(cve, "kev_listed", True)
        self.pipeline.nvd.fetch_published_between = lambda start, end: ["CVE-2026-0001"]

        result = self.pipeline.discover_from_nvd()

        self.assertEqual(result, {"received": 1, "relevant": 1, "kev": 1})
        self.assertIsNotNone(self.pipeline.cache.get_cve("CVE-2026-0001"))

    def test_critical_but_unmatched_cve_is_kept(self):
        """The orphan-draft-avoidance case: Critical severity alone must be
        enough to keep a CVE, even with no KEV listing and no Action1
        match -- otherwise the RT auto-draft hook inside _enrich_cve (which
        fires on KEV-or-Critical) could create a draft for a CVE this
        function then discards, leaving the draft pointing nowhere."""
        self.pipeline.risk_scorer.score = lambda cve: setattr(cve, "risk_level", "Critical")
        self.pipeline.nvd.fetch_published_between = lambda start, end: ["CVE-2026-0002"]

        result = self.pipeline.discover_from_nvd()

        self.assertEqual(result["relevant"], 1)
        self.assertEqual(result["kev"], 0)
        self.assertIsNotNone(self.pipeline.cache.get_cve("CVE-2026-0002"))

    def test_action1_matched_but_not_critical_or_kev_is_kept(self):
        def fake_match_exposure(cve, cache):
            cache.replace_action1_exposures(
                cve.cve_id,
                [
                    {
                        "endpoint_id": "ep-1",
                        "hostname": "host-a",
                        "vendor": "Acme",
                        "product": "Widget",
                        "installed_version": "1.0",
                        "affected_range": "< 2.0",
                        "fixed_version": "2.0",
                        "version_status": "vulnerable",
                    }
                ],
            )

        self.pipeline.action1 = SimpleNamespace(match_exposure=fake_match_exposure)
        self.pipeline.nvd.fetch_published_between = lambda start, end: ["CVE-2026-0003"]

        result = self.pipeline.discover_from_nvd()

        self.assertEqual(result["relevant"], 1)
        self.assertIsNotNone(self.pipeline.cache.get_cve("CVE-2026-0003"))

    def test_irrelevant_cve_is_discarded_not_saved(self):
        self.pipeline.nvd.fetch_published_between = lambda start, end: ["CVE-2026-0004"]

        result = self.pipeline.discover_from_nvd()

        self.assertEqual(result["relevant"], 0)
        self.assertIsNone(self.pipeline.cache.get_cve("CVE-2026-0004"))
        self.assertTrue(self.pipeline.cache.is_nvd_cve_evaluated("CVE-2026-0004"))

    def test_discarded_cve_is_never_reevaluated_on_a_later_call(self):
        enrich_calls = []
        original_enrich_cve = self.pipeline._enrich_cve

        def counting_enrich_cve(cve_id, source_articles, discovered_via="article"):
            enrich_calls.append(cve_id)
            return original_enrich_cve(cve_id, source_articles, discovered_via)

        self.pipeline._enrich_cve = counting_enrich_cve
        self.pipeline.nvd.fetch_published_between = lambda start, end: ["CVE-2026-0005"]

        self.pipeline.discover_from_nvd()
        self.pipeline.discover_from_nvd()  # overlapping window finds the same candidate again

        self.assertEqual(enrich_calls, ["CVE-2026-0005"])  # only processed once, ever

    def test_action1_unavailable_does_not_crash_discovery(self):
        self.pipeline.action1 = None
        self.pipeline.kev.enrich = lambda cve_id, cve: setattr(cve, "kev_listed", True)
        self.pipeline.nvd.fetch_published_between = lambda start, end: ["CVE-2026-0006"]

        result = self.pipeline.discover_from_nvd()

        self.assertEqual(result["relevant"], 1)


class DiscoveredViaTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.pipeline = _make_pipeline(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_discovered_via_and_first_seen_at_are_preserved_on_reenrichment(self):
        first = self.pipeline._enrich_cve("CVE-2026-0007", [], discovered_via="article")
        self.pipeline.cache.save_cve(first)
        self.assertEqual(first.discovered_via, "article")
        self.assertIsNotNone(first.first_seen_at)

        second = self.pipeline._enrich_cve("CVE-2026-0007", [], discovered_via="nvd")

        self.assertEqual(second.discovered_via, "article")  # not overwritten to "nvd"
        self.assertEqual(second.first_seen_at, first.first_seen_at)


class NvdDiscoveryWindowTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.pipeline = _make_pipeline(self._tmpdir.name)
        self.calls: list[tuple] = []

        def fake_fetch(start, end):
            self.calls.append((start, end))
            return []

        self.pipeline.nvd.fetch_published_between = fake_fetch

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_first_run_uses_the_lookback_floor(self):
        self.pipeline.discover_from_nvd()
        start, end = self.calls[0]
        expected_floor = end - timedelta(hours=self.pipeline.config.nvd_discovery_lookback_hours)
        self.assertAlmostEqual(start.timestamp(), expected_floor.timestamp(), delta=2)

    def test_second_run_covers_the_gap_since_last_success(self):
        self.pipeline.discover_from_nvd()
        first_end = self.calls[0][1]
        self.pipeline.discover_from_nvd()
        second_start, _ = self.calls[1]
        self.assertAlmostEqual(second_start.timestamp(), first_end.timestamp(), delta=2)

    def test_stale_watermark_is_capped_by_the_safety_lookback(self):
        ancient = datetime.now(timezone.utc) - timedelta(days=10)
        self.pipeline.cache.set_nvd_discovery_state(ancient.isoformat())
        self.pipeline.discover_from_nvd()
        start, end = self.calls[0]
        expected_floor = end - timedelta(hours=self.pipeline.config.nvd_discovery_lookback_hours)
        self.assertAlmostEqual(start.timestamp(), expected_floor.timestamp(), delta=2)


class NvdDiscoverySourceIntegrationTests(unittest.TestCase):
    """Confirms the seeded system source and run_single()/_scan_source()
    routing record to the *existing* scan_history mechanism, with no new
    UI/plumbing needed."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.pipeline = _make_pipeline(self._tmpdir.name)
        self.pipeline.nvd.fetch_published_between = lambda start, end: []

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_nvd_source_is_seeded_exactly_once(self):
        sources = [s for s in self.pipeline.cache.get_all_sources() if s["source_type"] == "nvd_discovery"]
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]["name"], "NVD CVE Discovery")

    def test_run_single_records_to_scan_history(self):
        source = next(s for s in self.pipeline.cache.get_all_sources() if s["source_type"] == "nvd_discovery")
        result = self.pipeline.run_single(source["id"])

        self.assertEqual(result["sources"], 1)
        history = self.pipeline.cache.get_scan_history(source["id"])
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["status"], "Processed")

    def test_failed_discovery_is_recorded_without_crashing(self):
        def boom(start, end):
            raise RuntimeError("NVD is down")

        self.pipeline.nvd.fetch_published_between = boom
        source = next(s for s in self.pipeline.cache.get_all_sources() if s["source_type"] == "nvd_discovery")

        result = self.pipeline.run_single(source["id"])  # must not raise

        self.assertEqual(result["sources"], 1)
        history = self.pipeline.cache.get_scan_history(source["id"])
        self.assertEqual(history[0]["status"], "Failed")
        self.assertIn("NVD is down", history[0]["error_message"])


if __name__ == "__main__":
    unittest.main()
