"""End-to-end orchestration: scan configured sources -> extract CVEs ->
enrich -> normalize -> summarize -> score -> persist to the SQLite cache.

Sources are entirely database-driven (see modules.cache / modules.source_parsers)
-- there is no hardcoded source list. security_urls.txt is only consulted
once, to seed the database the first time it's empty, for backward
compatibility with existing installs.
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

from config import Config
from modules.action1 import Action1Client
from modules.cache import DuplicateSourceError, VulnCache
from modules.downloader import Downloader
from modules.epss import EPSSClient
from modules.kev import KEVClient
from modules.mitre import MitreClient
from modules.models import Article, EnrichedCVE
from modules.nvd import NVDClient
from modules.risk import RiskScorer
from modules.rt import RTClient
from modules.rt_drafts import create_draft_for_cve
from modules.source_parsers import SourceFetcher
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
        self.fetcher = SourceFetcher(self.downloader)
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
        self.action1 = (
            Action1Client(
                client_id=config.action1_client_id,
                client_secret=config.action1_client_secret,
                org_id=config.action1_org_id,
                base_url=config.action1_base_url,
                timeout=config.request_timeout,
                max_retries=config.max_retries,
                backoff_factor=config.backoff_factor,
            )
            if config.action1_configured
            else None
        )
        self.rt = (
            RTClient(
                url=config.rt_url,
                username=config.rt_username,
                password=config.rt_password,
                queue=config.rt_queue,
                timeout=config.request_timeout,
                max_retries=config.max_retries,
                backoff_factor=config.backoff_factor,
            )
            if config.rt_configured
            else None
        )
        self.vendor_identifier = VendorIdentifier()
        self.summarizer = TemplateSummarizer()
        self.risk_scorer = RiskScorer()
        self._seed_sources_from_file()

    def _seed_sources_from_file(self) -> None:
        """One-time migration: if the sources table is empty and a legacy
        security_urls.txt exists, import it as security_blog sources so
        existing installs don't lose their configured sources. Once seeded,
        the pipeline never reads the file again -- sources live in the DB."""
        if self.cache.get_all_sources():
            return
        path = Path(self.config.urls_file)
        if not path.exists():
            return
        seeded = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            url = line.strip()
            if not url:
                continue
            try:
                self.cache.add_source(
                    url,
                    name=urlparse(url).netloc.replace("www.", ""),
                    source_type="security_blog",
                    enabled=True,
                )
                seeded += 1
            except DuplicateSourceError:
                pass
        if seeded:
            logger.info("Seeded %d source(s) from %s", seeded, path)

    def run(self) -> dict:
        """Scan every enabled source and enrich whatever CVEs turn up."""
        self.downloader.reset_seen_urls()
        sources = self.cache.get_enabled_sources()
        logger.info("Scanning %d enabled source(s)", len(sources))

        all_articles: list[Article] = []
        with ThreadPoolExecutor(max_workers=self.config.concurrency) as pool:
            futures = [pool.submit(self._scan_source, source) for source in sources]
            for future in as_completed(futures):
                all_articles.extend(future.result())

        cve_to_articles = self._save_articles_and_index_cves(all_articles)
        logger.info("Found %d unique CVEs across %d articles", len(cve_to_articles), len(all_articles))

        enriched_count, cached_count = self._enrich_cves(cve_to_articles)
        logger.info(
            "Pipeline complete: %d sources, %d articles, %d CVEs (%d freshly enriched, %d served from cache)",
            len(sources),
            len(all_articles),
            len(cve_to_articles),
            enriched_count,
            cached_count,
        )
        return {
            "sources": len(sources),
            "articles": len(all_articles),
            "cves": len(cve_to_articles),
            "enriched": enriched_count,
            "cached": cached_count,
        }

    def run_single(self, source_id: int) -> dict:
        """Scan exactly one source end-to-end. Used for the dashboard's
        per-source 'Run Scan' action and to process a newly added source
        without waiting for the next full run(). Refuses disabled sources,
        same as a scheduled/full run would skip them."""
        source = self.cache.get_source(source_id)
        if source is None or not source["enabled"]:
            return {"sources": 0, "articles": 0, "cves": 0, "enriched": 0, "cached": 0}

        self.downloader.reset_seen_urls()
        articles = self._scan_source(source)
        cve_to_articles = self._save_articles_and_index_cves(articles)
        enriched_count, cached_count = self._enrich_cves(cve_to_articles)
        return {
            "sources": 1,
            "articles": len(articles),
            "cves": len(cve_to_articles),
            "enriched": enriched_count,
            "cached": cached_count,
        }

    def _scan_source(self, source: dict) -> list[Article]:
        """Fetch one source and record the outcome to scan_history,
        regardless of success or failure -- a source that errors out must
        never stop the rest of the scan."""
        source_id = source["id"]
        label = source.get("name") or source["url"]
        self.cache.mark_source_scanning(source_id)
        started = time.monotonic()
        try:
            articles = self.fetcher.fetch(source)
        except Exception as exc:
            logger.exception("Unhandled error scanning source %r (id=%s)", label, source_id)
            self.cache.record_scan(
                source_id,
                status="Failed",
                duration_seconds=time.monotonic() - started,
                articles_processed=0,
                cves_found=0,
                error_message=str(exc),
            )
            return []

        duration = time.monotonic() - started
        cves_found = len({cve_id for article in articles for cve_id in article.cves})
        if articles:
            self.cache.record_scan(
                source_id,
                status="Processed",
                duration_seconds=duration,
                articles_processed=len(articles),
                cves_found=cves_found,
            )
        else:
            self.cache.record_scan(
                source_id,
                status="Failed",
                duration_seconds=duration,
                articles_processed=0,
                cves_found=0,
                error_message="No articles or feed items could be retrieved.",
            )
        return articles

    def _save_articles_and_index_cves(self, articles: list[Article]) -> dict[str, list[str]]:
        cve_to_articles: dict[str, list[str]] = {}
        for article in articles:
            self.cache.save_article(article)
            for cve_id in article.cves:
                cve_to_articles.setdefault(cve_id, []).append(article.url)
        return cve_to_articles

    def _enrich_cves(self, cve_to_articles: dict[str, list[str]]) -> tuple[int, int]:
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
        return enriched_count, cached_count

    def enrich_single_cve(self, cve_id: str) -> EnrichedCVE | None:
        """Look up and enrich one CVE ID on demand, regardless of whether any
        scanned source ever mentioned it. Used for direct CVE search so users
        aren't limited to what's already been scanned. Returns None if neither
        NVD nor CVE.org/MITRE has any record of the ID."""
        cve_id = cve_id.strip().upper()
        cached = self.cache.get_cached_cve(cve_id)
        if cached:
            return cached
        enriched = self._enrich_cve(cve_id, source_articles=[])
        if not enriched.published_date and not enriched.description:
            return None
        self.cache.save_cve(enriched)
        return enriched

    def _enrich_cve(self, cve_id: str, source_articles: list[str]) -> EnrichedCVE:
        logger.info("Enriching %s", cve_id)
        cve = EnrichedCVE(cve_id=cve_id, source_articles=sorted(set(source_articles)))

        configurations = self.nvd.enrich(cve_id, cve)
        self.mitre.enrich(cve_id, cve)
        self.epss.enrich(cve_id, cve)
        self.kev.enrich(cve_id, cve)
        self.vendor_identifier.enrich(cve, configurations)
        if self.action1:
            self.action1.match_exposure(cve, self.cache)

        cve.summary = self.summarizer.summarize(cve)
        self.risk_scorer.score(cve)

        if self.rt and (cve.kev_listed or cve.risk_level == "Critical") and not self.cache.get_rt_draft_for_cve(cve.cve_id):
            # Never creates a real RT ticket here -- only a local draft an
            # analyst must review and approve (see modules.rt_drafts).
            try:
                create_draft_for_cve(cve, self.cache, self.rt)
            except Exception:
                # An RT outage must never block CVE enrichment -- log and move on.
                logger.exception("Failed to create RT draft for %s", cve.cve_id)

        return cve
