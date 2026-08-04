"""Resilient HTTP downloader for security advisory articles."""
from __future__ import annotations

import logging
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("vuln_intel.downloader")


class DownloadError(Exception):
    """Raised when a URL cannot be downloaded after all retries."""


class Downloader:
    """Downloads web pages with retries, exponential backoff, redirect
    handling, gzip support (native to requests) and per-run URL dedup."""

    def __init__(self, timeout: int, max_retries: int, backoff_factor: float, user_agent: str):
        self.timeout = timeout
        self._seen_urls: set[str] = set()
        self.session = requests.Session()
        retry = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept-Encoding": "gzip, deflate",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )

    @staticmethod
    def is_valid_url(url: str) -> bool:
        try:
            parsed = urlparse(url)
            return parsed.scheme in ("http", "https") and bool(parsed.netloc)
        except ValueError:
            return False

    def fetch(self, url: str) -> str | None:
        """Fetch a URL's HTML. Returns None (and logs) on any failure or
        duplicate, never raises, so a single bad URL cannot halt the batch."""
        if not self.is_valid_url(url):
            logger.warning("Skipping invalid URL: %s", url)
            return None
        if url in self._seen_urls:
            logger.info("Skipping duplicate URL in this run: %s", url)
            return None
        self._seen_urls.add(url)

        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            response.raise_for_status()
            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type and content_type:
                logger.warning("Unexpected content-type for %s: %s", url, content_type)
            return response.text
        except requests.exceptions.Timeout:
            logger.error("Timeout downloading %s", url)
        except requests.exceptions.SSLError as exc:
            logger.error("SSL error downloading %s: %s", url, exc)
        except requests.exceptions.TooManyRedirects:
            logger.error("Too many redirects for %s", url)
        except requests.exceptions.HTTPError as exc:
            logger.error("HTTP error downloading %s: %s", url, exc)
        except requests.exceptions.RequestException as exc:
            logger.error("Failed to download %s: %s", url, exc)
        return None
