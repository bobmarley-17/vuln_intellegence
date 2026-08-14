"""Source-type-aware fetching.

Turns a configured source (RSS/Atom feed, XML feed, JSON API, or a plain
HTML page) into the `Article` records it yields, and provides a shared
`test_connection` check used by the dashboard's "Test Connection" action
before a source is even saved.

HTML source types (`security_blog`, `vendor_advisory`) delegate straight to
the existing `Downloader` + `ArticleExtractor` -- that's exactly what those
two types are. Feed and JSON API types are parsed here since they carry
their own structure.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

import feedparser
import requests
from bs4 import BeautifulSoup

from modules.downloader import Downloader
from modules.extractor import ArticleExtractor
from modules.models import Article

logger = logging.getLogger("vuln_intel.source_parsers")

SOURCE_TYPES = ("rss_feed", "xml_feed", "security_blog", "vendor_advisory", "json_api", "nvd_discovery")
DEFAULT_SOURCE_TYPE = "security_blog"
_FEED_TYPES = {"rss_feed", "xml_feed"}
_MAX_FEED_ITEMS = 25
_MAX_JSON_LIST_ITEMS = 200
_MAX_JSON_DEPTH = 6


class SourceFetcher:
    """Fetches one source (any type) and returns the Article records it
    yields for the enrichment pipeline to consume."""

    def __init__(self, downloader: Downloader):
        self.downloader = downloader
        self.extractor = ArticleExtractor()

    def fetch(self, source: dict) -> list[Article]:
        source_type = source.get("source_type") or DEFAULT_SOURCE_TYPE
        url = source["url"]
        if source_type in _FEED_TYPES:
            articles = self._fetch_feed(url)
        elif source_type == "json_api":
            articles = self._fetch_json_api(url)
        else:
            articles = self._fetch_html(url)
        for article in articles:
            article.source_id = source.get("id")
        return articles

    def _fetch_html(self, url: str) -> list[Article]:
        html = self.downloader.fetch(url)
        if not html:
            return []
        try:
            return [self.extractor.extract(url, html)]
        except Exception:
            logger.exception("Failed to extract article content from %s", url)
            return []

    def _fetch_feed(self, url: str) -> list[Article]:
        raw = self.downloader.fetch(url)
        if not raw:
            return []
        parsed = feedparser.parse(raw)
        if not parsed.entries:
            logger.warning("Feed at %s had no entries (bozo=%s)", url, parsed.get("bozo"))
            return []

        feed_site = parsed.feed.get("title") or urlparse(url).netloc
        articles = []
        for entry in parsed.entries[:_MAX_FEED_ITEMS]:
            title = entry.get("title")
            summary_html = entry.get("summary") or entry.get("description") or ""
            summary_text = _strip_html(summary_html)
            cves = self.extractor.extract_cves(f"{title or ''}\n{summary_text}")
            articles.append(
                Article(
                    url=entry.get("link") or url,
                    title=title,
                    author=entry.get("author"),
                    published_date=_feed_entry_date(entry),
                    site_name=feed_site,
                    content=summary_text,
                    cves=cves,
                )
            )
        return articles

    def _fetch_json_api(self, url: str) -> list[Article]:
        raw = self.downloader.fetch(url)
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("JSON API at %s did not return valid JSON", url)
            return []

        text = " ".join(_walk_json_strings(data))
        cves = self.extractor.extract_cves(text)
        if not cves:
            return []
        return [
            Article(
                url=url,
                title=_json_title(data) or urlparse(url).netloc,
                site_name=urlparse(url).netloc,
                content=text[:5000],
                cves=cves,
            )
        ]


def test_connection(url: str, source_type: str, timeout: int, user_agent: str) -> dict:
    """Best-effort reachability + format check for the 'Test Connection' UI
    action. Never raises -- always returns a structured result so the route
    handler can just jsonify it."""
    result = {"ok": False, "message": "", "detail": "", "articles_detected": 0, "cves_detected": 0}

    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": user_agent, "Accept": "*/*"})
    except requests.exceptions.Timeout:
        result["message"] = "Unable to Reach URL"
        result["detail"] = "The request timed out."
        return result
    except requests.exceptions.SSLError as exc:
        result["message"] = "Unable to Reach URL"
        result["detail"] = f"TLS/SSL error: {exc}"
        return result
    except requests.exceptions.RequestException as exc:
        result["message"] = "Unable to Reach URL"
        result["detail"] = str(exc)
        return result

    if resp.status_code in (401, 403):
        result["message"] = "Authentication Failed"
        result["detail"] = f"Server responded with HTTP {resp.status_code}."
        return result
    if resp.status_code >= 400:
        result["message"] = "Unable to Reach URL"
        result["detail"] = f"Server responded with HTTP {resp.status_code}."
        return result

    extractor = ArticleExtractor()

    if source_type in _FEED_TYPES:
        parsed = feedparser.parse(resp.content)
        if not parsed.entries:
            result["message"] = "Invalid Feed Format"
            result["detail"] = "No feed items were found at this URL."
            return result
        sample = parsed.entries[:_MAX_FEED_ITEMS]
        text = " ".join(f"{e.get('title', '')} {e.get('summary', '')}" for e in sample)
        cves = extractor.extract_cves(text)
        result.update(
            ok=True,
            message="RSS Feed Detected" if source_type == "rss_feed" else "XML Feed Detected",
            detail=f"Found {len(parsed.entries)} item(s), {len(cves)} CVE ID(s) in the latest {len(sample)}.",
            articles_detected=len(parsed.entries),
            cves_detected=len(cves),
        )
        return result

    if source_type == "json_api":
        try:
            data = resp.json()
        except ValueError:
            result["message"] = "Invalid Feed Format"
            result["detail"] = "Response is not valid JSON."
            return result
        text = " ".join(_walk_json_strings(data))
        cves = extractor.extract_cves(text)
        result.update(
            ok=True,
            message="JSON API Valid",
            detail=(
                f"Response parsed successfully; found {len(cves)} CVE ID(s)."
                if cves
                else "Valid JSON, but no CVE IDs were detected in it."
            ),
            articles_detected=1,
            cves_detected=len(cves),
        )
        return result

    # security_blog / vendor_advisory: a generic HTML page.
    content_type = resp.headers.get("Content-Type", "")
    if content_type and "html" not in content_type and "xml" not in content_type:
        result["message"] = "Invalid Feed Format"
        result["detail"] = f"Expected an HTML page, got Content-Type: {content_type}."
        return result
    soup = BeautifulSoup(resp.text, "lxml")
    text = soup.get_text(" ", strip=True)
    cves = extractor.extract_cves(text)
    result.update(
        ok=True,
        message="Connection Successful",
        detail=(
            f"Page parsed successfully; found {len(cves)} CVE ID(s) on this page."
            if cves
            else "Page parsed successfully; no CVE IDs found on this page yet."
        ),
        articles_detected=1,
        cves_detected=len(cves),
    )
    return result


def _feed_entry_date(entry) -> str | None:
    parsed_time = entry.get("published_parsed") or entry.get("updated_parsed")
    if not parsed_time:
        return None
    try:
        return datetime(*parsed_time[:6], tzinfo=timezone.utc).isoformat()
    except (TypeError, ValueError):
        return None


def _strip_html(html_fragment: str) -> str:
    if not html_fragment:
        return ""
    return BeautifulSoup(html_fragment, "lxml").get_text(" ", strip=True)


def _walk_json_strings(node, depth: int = 0) -> list[str]:
    """Collect every string leaf in a parsed JSON document so CVE IDs can be
    regex-matched regardless of the API's particular schema."""
    if depth > _MAX_JSON_DEPTH:
        return []
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        strings = []
        for value in node.values():
            strings.extend(_walk_json_strings(value, depth + 1))
        return strings
    if isinstance(node, list):
        strings = []
        for item in node[:_MAX_JSON_LIST_ITEMS]:
            strings.extend(_walk_json_strings(item, depth + 1))
        return strings
    return []


def _json_title(data) -> str | None:
    if isinstance(data, dict):
        for key in ("title", "name", "summary"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None
