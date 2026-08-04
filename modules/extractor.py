"""Article metadata/content extraction and CVE-ID extraction."""
from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from dateutil import parser as date_parser

from modules.models import Article

logger = logging.getLogger("vuln_intel.extractor")

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

_META_DATE_KEYS = [
    ("meta", {"property": "article:published_time"}),
    ("meta", {"name": "article:published_time"}),
    ("meta", {"name": "publish-date"}),
    ("meta", {"name": "date"}),
    ("meta", {"itemprop": "datePublished"}),
]
_META_AUTHOR_KEYS = [
    ("meta", {"name": "author"}),
    ("meta", {"property": "article:author"}),
]


class ArticleExtractor:
    """Extracts title/author/date/site name/content and CVE mentions from
    downloaded HTML. Never raises on malformed HTML: BeautifulSoup with the
    lxml parser degrades gracefully."""

    def extract(self, url: str, html: str) -> Article:
        soup = BeautifulSoup(html, "lxml")
        # Strip script/style/nav/footer noise before pulling text content (sanitization).
        for tag in soup(["script", "style", "noscript", "iframe", "svg"]):
            tag.decompose()

        title = self._extract_title(soup)
        author = self._extract_author(soup)
        published_date = self._extract_date(soup)
        site_name = self._extract_site_name(soup, url)
        content = self._extract_content(soup)

        # CVE mentions often live in headline/teaser anchor text or URL slugs
        # on listing pages, not inside the curated <p>/<li> body content, so
        # scan the whole visible page plus every link's text and href/slug.
        link_text = " ".join(
            f"{a.get_text(' ', strip=True)} {a.get('href', '')}" for a in soup.find_all("a")
        )
        full_text = soup.get_text(" ", strip=True)
        cves = self.extract_cves(f"{title or ''}\n{content}\n{full_text}\n{link_text}")

        return Article(
            url=url,
            title=title,
            author=author,
            published_date=published_date,
            site_name=site_name,
            content=content,
            cves=cves,
        )

    @staticmethod
    def extract_cves(text: str) -> list[str]:
        if not text:
            return []
        found = {m.upper() for m in CVE_PATTERN.findall(text)}
        return sorted(found)

    @staticmethod
    def _extract_title(soup: BeautifulSoup) -> str | None:
        og = soup.find("meta", {"property": "og:title"})
        if og and og.get("content"):
            return og["content"].strip()
        if soup.title and soup.title.string:
            return soup.title.string.strip()
        h1 = soup.find("h1")
        if h1:
            return h1.get_text(strip=True)
        return None

    @staticmethod
    def _extract_author(soup: BeautifulSoup) -> str | None:
        for tag, attrs in _META_AUTHOR_KEYS:
            el = soup.find(tag, attrs)
            if el and el.get("content"):
                return el["content"].strip()
        byline = soup.find(class_=re.compile(r"(author|byline)", re.IGNORECASE))
        if byline:
            text = byline.get_text(strip=True)
            if text and len(text) < 100:
                return text
        return None

    @staticmethod
    def _extract_date(soup: BeautifulSoup) -> str | None:
        for tag, attrs in _META_DATE_KEYS:
            el = soup.find(tag, attrs)
            if el and el.get("content"):
                return ArticleExtractor._normalize_date(el["content"])
        time_el = soup.find("time")
        if time_el:
            raw = time_el.get("datetime") or time_el.get_text(strip=True)
            normalized = ArticleExtractor._normalize_date(raw)
            if normalized:
                return normalized
        return None

    @staticmethod
    def _normalize_date(raw: str | None) -> str | None:
        if not raw:
            return None
        try:
            return date_parser.parse(raw, fuzzy=True).isoformat()
        except (ValueError, OverflowError, TypeError):
            logger.debug("Could not parse date string: %s", raw)
            return None

    @staticmethod
    def _extract_site_name(soup: BeautifulSoup, url: str) -> str | None:
        og_site = soup.find("meta", {"property": "og:site_name"})
        if og_site and og_site.get("content"):
            return og_site["content"].strip()
        return urlparse(url).netloc.replace("www.", "")

    @staticmethod
    def _extract_content(soup: BeautifulSoup) -> str:
        article_tag = soup.find("article")
        container = article_tag if article_tag else soup.find("body")
        if container is None:
            return soup.get_text(separator=" ", strip=True)
        paragraphs = container.find_all(["p", "li", "h2", "h3"])
        if paragraphs:
            text = "\n".join(p.get_text(" ", strip=True) for p in paragraphs)
        else:
            text = container.get_text(separator=" ", strip=True)
        return re.sub(r"\n{3,}", "\n\n", text).strip()
