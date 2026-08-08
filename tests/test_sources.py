"""Tests for UI-driven security source management: the sources/scan_history
cache API, and source-type-aware fetching."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from modules.cache import DuplicateSourceError, VulnCache
from modules.source_parsers import SourceFetcher, _json_title, _walk_json_strings


class FakeDownloader:
    """Stands in for modules.downloader.Downloader so fetch tests never hit
    the network -- returns canned content keyed by URL."""

    def __init__(self, responses: dict[str, str]):
        self.responses = responses
        self.fetched: list[str] = []

    def fetch(self, url: str) -> str | None:
        self.fetched.append(url)
        return self.responses.get(url)


RSS_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
<title>Example Security Feed</title>
<item>
<title>Critical flaw in Widget App</title>
<link>https://example.test/articles/widget-flaw</link>
<description>A vulnerability tracked as CVE-2024-12345 affects Widget App.</description>
<pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate>
</item>
<item>
<title>Routine maintenance notice</title>
<link>https://example.test/articles/maintenance</link>
<description>No security content here.</description>
</item>
</channel>
</rss>
"""

JSON_API_SAMPLE = """
{
  "advisories": [
    {"id": "adv-1", "summary": "Fixed CVE-2024-99999 in the parser."},
    {"id": "adv-2", "summary": "No CVEs in this one."}
  ]
}
"""


class SourceCacheTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.cache = VulnCache(str(Path(self._tmpdir.name) / "cache.db"))

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_add_source_rejects_duplicate_url(self):
        self.cache.add_source("https://example.test/feed", source_type="rss_feed")
        with self.assertRaises(DuplicateSourceError):
            self.cache.add_source("https://example.test/feed", source_type="rss_feed")

    def test_get_enabled_sources_excludes_disabled(self):
        sid = self.cache.add_source("https://example.test/a", enabled=True)
        self.cache.add_source("https://example.test/b", enabled=False)
        enabled = self.cache.get_enabled_sources()
        self.assertEqual([s["id"] for s in enabled], [sid])

    def test_set_source_enabled_toggles_and_persists(self):
        sid = self.cache.add_source("https://example.test/a", enabled=True)
        self.assertTrue(self.cache.set_source_enabled(sid, False))
        self.assertFalse(self.cache.get_source(sid)["enabled"])
        self.assertEqual(self.cache.get_enabled_sources(), [])

    def test_update_source_rejects_duplicate_url(self):
        self.cache.add_source("https://example.test/a")
        sid_b = self.cache.add_source("https://example.test/b")
        with self.assertRaises(DuplicateSourceError):
            self.cache.update_source(sid_b, url="https://example.test/a")

    def test_update_source_missing_id_returns_false(self):
        self.assertFalse(self.cache.update_source(999999, name="Nope"))

    def test_delete_source_preserves_scan_history(self):
        sid = self.cache.add_source("https://example.test/a")
        self.cache.record_scan(sid, status="Processed", duration_seconds=1.0, articles_processed=2, cves_found=1)
        self.cache.delete_source(sid)
        self.assertIsNone(self.cache.get_source(sid))
        self.assertEqual(len(self.cache.get_scan_history(sid)), 1)

    def test_record_scan_updates_source_summary_fields(self):
        sid = self.cache.add_source("https://example.test/a")
        self.cache.record_scan(
            sid, status="Failed", duration_seconds=0.5, articles_processed=0, cves_found=0, error_message="boom"
        )
        source = self.cache.get_source(sid)
        self.assertEqual(source["status"], "Failed")
        self.assertEqual(source["last_error"], "boom")
        self.assertEqual(source["last_articles_processed"], 0)


class JsonWalkTests(unittest.TestCase):
    def test_walk_json_strings_collects_nested_leaves(self):
        data = {"a": "hello", "b": {"c": ["world", 42, None]}, "d": ["CVE-2024-1"]}
        strings = _walk_json_strings(data)
        self.assertIn("hello", strings)
        self.assertIn("world", strings)
        self.assertIn("CVE-2024-1", strings)

    def test_json_title_prefers_title_key(self):
        self.assertEqual(_json_title({"title": "  My Advisory  "}), "My Advisory")
        self.assertIsNone(_json_title({"unrelated": "value"}))
        self.assertIsNone(_json_title(["not", "a", "dict"]))


class SourceFetcherTests(unittest.TestCase):
    def test_fetch_rss_feed_extracts_cves_and_items(self):
        downloader = FakeDownloader({"https://example.test/feed.xml": RSS_SAMPLE})
        fetcher = SourceFetcher(downloader)
        articles = fetcher.fetch({"url": "https://example.test/feed.xml", "source_type": "rss_feed"})

        self.assertEqual(len(articles), 2)
        flawed = next(a for a in articles if a.url.endswith("widget-flaw"))
        self.assertEqual(flawed.cves, ["CVE-2024-12345"])
        self.assertEqual(flawed.site_name, "Example Security Feed")
        routine = next(a for a in articles if a.url.endswith("maintenance"))
        self.assertEqual(routine.cves, [])

    def test_fetch_json_api_only_returns_articles_with_cves(self):
        downloader = FakeDownloader({"https://example.test/api": JSON_API_SAMPLE})
        fetcher = SourceFetcher(downloader)
        articles = fetcher.fetch({"url": "https://example.test/api", "source_type": "json_api"})

        self.assertEqual(len(articles), 1)
        self.assertEqual(articles[0].cves, ["CVE-2024-99999"])

    def test_fetch_json_api_returns_nothing_for_malformed_json(self):
        downloader = FakeDownloader({"https://example.test/api": "{not valid json"})
        fetcher = SourceFetcher(downloader)
        articles = fetcher.fetch({"url": "https://example.test/api", "source_type": "json_api"})
        self.assertEqual(articles, [])

    def test_fetch_feed_returns_nothing_when_download_fails(self):
        downloader = FakeDownloader({})
        fetcher = SourceFetcher(downloader)
        articles = fetcher.fetch({"url": "https://example.test/feed.xml", "source_type": "rss_feed"})
        self.assertEqual(articles, [])


if __name__ == "__main__":
    unittest.main()
