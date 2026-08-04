"""End-to-end orchestration: download articles -> extract CVEs -> enrich ->
normalize -> summarize -> score -> persist to the SQLite cache."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from config import Config
from modules.cache import VulnCache
from modules.downloader import Downloader
from modules.epss import EPSSClient
from modules.extractor import ArticleExtractor
from modules.kev import KEVClient
from modules.mitre import MitreClient
from modules.models import Article, EnrichedCVE
from modules.nvd import NVDClient
from modules.risk import RiskScorer
from modules.summarizer import TemplateSummarizer
from modules.vendors import VendorIdentifier

logger = logging.getLogger("vuln_intel.pipeline")


class Pipeline:
    def __init__(self, config: Config):
        self.config = config
        self.cache = VulnCache(config.cache_db_path, ttl_hours=config.cache_ttl_hours)
        self.downloader = Downloader(
            timeout=config.request_timeout,
            max_retries=config.max_retries,
            backoff_factor=config.backoff_factor,
            user_agent=config.user_agent,
        )
        self.extractor = ArticleExtractor()
        self.nvd = NVDClient(
            api_key=config.nvd_api_key,
            timeout=config.request_timeout,
            max_retries=config.max_retries,
            backoff_factor=config.backoff_factor,
            rate_limit_delay=config.nvd_rate_limit_delay,
        )
        self.mitre = MitreClient(config.request_timeout, config.max_retries, config.backoff_factor)
        self.epss = EPSSClient(config.request_timeout, config.max_retries, config.backoff_factor)
        self.kev = KEVClient(config.cache_folder, config.request_timeout, config.max_retries, config.backoff_factor)
        self.vendor_identifier = VendorIdentifier()
        self.summarizer = TemplateSummarizer()
        self.risk_scorer = RiskScorer()

    def read_urls(self) -> list[str]:
        path = Path(self.config.urls_file)
        if not path.exists():
            logger.error("URLs file not found: %s", path)
            return []
        urls: list[str] = []
        seen: set[str] = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            url = line.strip()
            if not url or url in seen:
                continue
            seen.add(url)
            urls.append(url)
        return urls

    def run(self) -> dict:
        urls = self.read_urls()
        logger.info("Loaded %d unique URLs from %s", len(urls), self.config.urls_file)

        articles = self._download_and_extract(urls)
        logger.info("Successfully extracted %d articles", len(articles))

        cve_to_articles: dict[str, list[str]] = {}
        for article in articles:
            self.cache.save_article(article)
            for cve_id in article.cves:
                cve_to_articles.setdefault(cve_id, []).append(article.url)

        logger.info("Found %d unique CVEs across all articles", len(cve_to_articles))

        enriched_count = 0
        cached_count = 0
        for cve_id, source_articles in cve_to_articles.items():
            cached = self.cache.get_cached_cve(cve_id)
            if cached:
                cached.source_articles = sorted(set(cached.source_articles) | set(source_articles))
                self.cache.save_cve(cached)
                cached_count += 1
                continue
            try:
                enriched = self._enrich_cve(cve_id, source_articles)
                self.cache.save_cve(enriched)
                enriched_count += 1
            except Exception:
                logger.exception("Unhandled error enriching %s; skipping", cve_id)

        logger.info(
            "Pipeline complete: %d articles, %d CVEs (%d freshly enriched, %d served from cache)",
            len(articles),
            len(cve_to_articles),
            enriched_count,
            cached_count,
        )
        return {
            "articles": len(articles),
            "cves": len(cve_to_articles),
            "enriched": enriched_count,
            "cached": cached_count,
        }

    def _download_and_extract(self, urls: list[str]) -> list[Article]:
        articles: list[Article] = []
        with ThreadPoolExecutor(max_workers=self.config.concurrency) as pool:
            futures = {pool.submit(self._download_one, url): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    article = future.result()
                    if article:
                        articles.append(article)
                except Exception:
                    logger.exception("Unhandled error processing %s", url)
        return articles

    def _download_one(self, url: str) -> Article | None:
        html = self.downloader.fetch(url)
        if not html:
            return None
        try:
            return self.extractor.extract(url, html)
        except Exception:
            logger.exception("Failed to extract article content from %s", url)
            return None

    def _enrich_cve(self, cve_id: str, source_articles: list[str]) -> EnrichedCVE:
        logger.info("Enriching %s", cve_id)
        cve = EnrichedCVE(cve_id=cve_id, source_articles=sorted(set(source_articles)))

        configurations = self.nvd.enrich(cve_id, cve)
        self.mitre.enrich(cve_id, cve)
        self.epss.enrich(cve_id, cve)
        self.kev.enrich(cve_id, cve)
        self.vendor_identifier.enrich(cve, configurations)

        cve.summary = self.summarizer.summarize(cve)
        self.risk_scorer.score(cve)
        return cve
