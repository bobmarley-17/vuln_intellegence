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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from config import Config
from modules.action1 import Action1Client
from modules.cache import DuplicateSourceError, VulnCache
from modules.downloader import Downloader
from modules.epss import EPSSClient
from modules.job_control import CancellationToken, JobCancelled
from modules.kev import KEVClient
from modules.mitre import MitreClient
from modules.models import Article, EnrichedCVE
from modules.normalizer import match_cve_to_product
from modules.nvd import NVD_BASE_URL, NVDClient
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
        self._seed_nvd_discovery_source()

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

    def _seed_nvd_discovery_source(self) -> None:
        """One-time creation of the system-managed 'NVD CVE Discovery'
        source row (see modules.nvd.fetch_published_between /
        self.discover_from_nvd). After this it's controlled from the
        Sources UI like any other source -- config.nvd_discovery_enabled/
        interval_hours are seed-time defaults only, not live overrides."""
        try:
            self.cache.add_source(
                NVD_BASE_URL,
                name="NVD CVE Discovery",
                source_type="nvd_discovery",
                polling_interval_minutes=self.config.nvd_discovery_interval_hours * 60,
                enabled=self.config.nvd_discovery_enabled,
            )
            logger.info("Seeded NVD CVE Discovery system source")
        except DuplicateSourceError:
            pass

    def run(self, token: CancellationToken | None = None) -> dict:
        """Scan every enabled source and enrich whatever CVEs turn up."""
        self.downloader.reset_seen_urls()
        sources = self.cache.get_enabled_sources()
        logger.info("Scanning %d enabled source(s)", len(sources))

        # Regular article sources fetch quickly (bounded by request_timeout)
        # so they're allowed to finish once dispatched -- Python threads
        # can't be safely force-killed anyway. The token is still passed
        # through so the NVD discovery source (which can run long) checks
        # it between candidates even inside a full run().
        all_articles: list[Article] = []
        with ThreadPoolExecutor(max_workers=self.config.concurrency) as pool:
            futures = [pool.submit(self._scan_source, source, token) for source in sources]
            for future in as_completed(futures):
                all_articles.extend(future.result())
        if token:
            token.checkpoint()

        cve_to_articles = self._save_articles_and_index_cves(all_articles)
        logger.info("Found %d unique CVEs across %d articles", len(cve_to_articles), len(all_articles))

        enriched_count, cached_count = self._enrich_cves(cve_to_articles, token=token)
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

    def run_single(self, source_id: int, token: CancellationToken | None = None) -> dict:
        """Scan exactly one source end-to-end. Used for the dashboard's
        per-source 'Run Scan' action and to process a newly added source
        without waiting for the next full run(). Refuses disabled sources,
        same as a scheduled/full run would skip them."""
        source = self.cache.get_source(source_id)
        if source is None or not source["enabled"]:
            return {"sources": 0, "articles": 0, "cves": 0, "enriched": 0, "cached": 0}

        self.downloader.reset_seen_urls()
        articles = self._scan_source(source, token=token)
        cve_to_articles = self._save_articles_and_index_cves(articles)
        enriched_count, cached_count = self._enrich_cves(cve_to_articles, token=token)
        return {
            "sources": 1,
            "articles": len(articles),
            "cves": len(cve_to_articles),
            "enriched": enriched_count,
            "cached": cached_count,
        }

    def _run_nvd_discovery(self, source: dict, token: CancellationToken | None = None) -> None:
        """Runs discover_from_nvd() for the system NVD source and records
        the outcome via the same record_scan() every article source uses,
        so Scan History / the Sources table display it with no new UI."""
        source_id = source["id"]
        self.cache.mark_source_scanning(source_id)
        started = time.monotonic()
        try:
            result = self.discover_from_nvd(token=token)
        except JobCancelled:
            logger.info("NVD discovery cancelled")
            self.cache.record_scan(
                source_id,
                status="Cancelled",
                duration_seconds=time.monotonic() - started,
                articles_processed=0,
                cves_found=0,
                error_message="Cancelled by user",
            )
            return
        except Exception as exc:
            logger.exception("NVD discovery failed")
            self.cache.record_scan(
                source_id,
                status="Failed",
                duration_seconds=time.monotonic() - started,
                articles_processed=0,
                cves_found=0,
                error_message=str(exc),
            )
            return

        self.cache.record_scan(
            source_id,
            status="Processed",
            duration_seconds=time.monotonic() - started,
            articles_processed=0,
            cves_found=result["relevant"],
        )

    def discover_from_nvd(self, token: CancellationToken | None = None) -> dict:
        """Pulls recently-published CVEs directly from NVD (rather than
        waiting for a blog to mention them) and enriches the ones that are
        actually relevant -- KEV-listed, Critical severity, or matched
        against the Action1 inventory -- through the exact same
        _enrich_cve() every other discovery path uses. CVEs judged
        irrelevant are recorded (so they're never re-evaluated on a later
        overlapping window) but never saved to the cves table, so NVD's
        global CVE stream doesn't flood the database."""
        now = datetime.now(timezone.utc)
        safety_floor = now - timedelta(hours=self.config.nvd_discovery_lookback_hours)
        state = self.cache.get_nvd_discovery_state()
        if state and state.get("last_success_window_end"):
            last_end = datetime.fromisoformat(state["last_success_window_end"])
            if last_end.tzinfo is None:
                last_end = last_end.replace(tzinfo=timezone.utc)
            window_start = max(last_end, safety_floor)
        else:
            window_start = safety_floor
        window_end = now

        logger.info("NVD discovery window: %s to %s", window_start.isoformat(), window_end.isoformat())
        candidates = self.nvd.fetch_published_between(window_start, window_end)
        logger.info("NVD discovery: %d record(s) received", len(candidates))

        relevant_count = 0
        kev_count = 0
        for cve_id in candidates:
            if token:
                token.checkpoint()  # outside the try/except below so JobCancelled isn't swallowed
            if self.cache.get_cve(cve_id) is not None or self.cache.is_nvd_cve_evaluated(cve_id):
                continue
            try:
                cve = self._enrich_cve(cve_id, source_articles=[], discovered_via="nvd")
            except Exception:
                logger.exception("Failed to enrich NVD-discovered %s; skipping", cve_id)
                continue

            has_exposure = bool(self.cache.get_action1_exposures_for_cve(cve_id))
            relevant, reason = self._classify_relevance(cve, has_exposure)
            self.cache.record_nvd_cve_evaluated(cve_id, relevant=relevant, reason=reason)

            if relevant:
                self.cache.save_cve(cve)
                relevant_count += 1
                if cve.kev_listed:
                    kev_count += 1

        self.cache.set_nvd_discovery_state(window_end.isoformat())
        logger.info(
            "NVD discovery completed: %d received, %d relevant (%d KEV)",
            len(candidates), relevant_count, kev_count,
        )
        return {"received": len(candidates), "relevant": relevant_count, "kev": kev_count}

    def _scan_source(self, source: dict, token: CancellationToken | None = None) -> list[Article]:
        """Fetch one source and record the outcome to scan_history,
        regardless of success or failure -- a source that errors out must
        never stop the rest of the scan. The NVD discovery system source
        doesn't produce Articles at all, so it's handled separately and
        always reports back an empty article list here."""
        if source["source_type"] == "nvd_discovery":
            self._run_nvd_discovery(source, token=token)
            return []

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

    def _enrich_cves(
        self, cve_to_articles: dict[str, list[str]], token: CancellationToken | None = None
    ) -> tuple[int, int]:
        enriched_count = 0
        cached_count = 0
        for cve_id, source_articles in cve_to_articles.items():
            if token:
                token.checkpoint()  # outside the try/except below so JobCancelled isn't swallowed
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
        enriched = self._enrich_cve(cve_id, source_articles=[], discovered_via="manual")
        if not enriched.published_date and not enriched.description:
            return None
        self.cache.save_cve(enriched)
        return enriched

    def _compute_enrichment(self, cve: EnrichedCVE) -> None:
        """Every enrichment step that only mutates `cve` in memory -- NVD,
        MITRE, EPSS, KEV, vendor identification, summary, risk score. No
        cache writes, no external side effects beyond read-only API calls.
        Shared by _enrich_cve() (which goes on to persist Action1 exposure
        and possibly create an RT draft) and preview_nvd_discovery() (which
        deliberately does neither, so it's safe to run repeatedly)."""
        configurations = self.nvd.enrich(cve.cve_id, cve)
        self.mitre.enrich(cve.cve_id, cve)
        self.epss.enrich(cve.cve_id, cve)
        self.kev.enrich(cve.cve_id, cve)
        self.vendor_identifier.enrich(cve, configurations)
        cve.summary = self.summarizer.summarize(cve)
        self.risk_scorer.score(cve)

    @staticmethod
    def _classify_relevance(cve: EnrichedCVE, has_action1_exposure: bool) -> tuple[bool, str]:
        """The one 'is this CVE worth keeping' rule, shared by real
        discovery and the preview so they can never disagree. KEV/Critical
        are included (not just an Action1 match) specifically so a CVE that
        would trigger an RT auto-draft (KEV-or-Critical, see _enrich_cve)
        is never the one discarded -- that would leave the draft pointing
        at a CVE the rest of the app can't display."""
        if cve.kev_listed:
            return True, "kev"
        if cve.risk_level == "Critical":
            return True, "critical"
        if has_action1_exposure:
            return True, "action1_exposure"
        return False, "not_relevant"

    def _enrich_cve(self, cve_id: str, source_articles: list[str], discovered_via: str = "article") -> EnrichedCVE:
        logger.info("Enriching %s", cve_id)
        # A CVE's original discovery channel/date is set once and carried
        # forward across re-enrichment -- it should never flip to "nvd" (or
        # reset first_seen_at) just because NVD discovery happened to see it
        # again after an article already found it first.
        existing = self.cache.get_cve(cve_id)
        cve = EnrichedCVE(
            cve_id=cve_id,
            source_articles=sorted(set(source_articles)),
            discovered_via=existing.discovered_via if existing else discovered_via,
            first_seen_at=existing.first_seen_at if existing else datetime.now(timezone.utc).isoformat(),
        )

        self._compute_enrichment(cve)
        if self.action1:
            self.action1.match_exposure(cve, self.cache)

        if self.rt and (cve.kev_listed or cve.risk_level == "Critical") and not self.cache.get_rt_draft_for_cve(cve.cve_id):
            # Never creates a real RT ticket here -- only a local draft an
            # analyst must review and approve (see modules.rt_drafts).
            try:
                create_draft_for_cve(cve, self.cache, self.rt)
            except Exception:
                # An RT outage must never block CVE enrichment -- log and move on.
                logger.exception("Failed to create RT draft for %s", cve.cve_id)

        return cve

    def _action1_match_preview(self, cve: EnrichedCVE) -> bool:
        """Read-only equivalent of Action1Client.match_exposure -- same
        match_cve_to_product logic, but returns a bool instead of writing
        to action1_exposures. Used only by preview_nvd_discovery()."""
        if not self.action1:
            return False
        for row in self.cache.get_action1_software():
            if not row.get("product"):
                continue
            result = match_cve_to_product(cve, row.get("vendor") or "", row["product"], row.get("version"))
            if result is not None and result["version_status"] != "not_affected":
                return True
        return False

    def preview_nvd_discovery(self, days_back: int, max_candidates: int = 50) -> dict:
        """Shows what discover_from_nvd() would do over the last
        `days_back` days WITHOUT saving anything, creating RT drafts,
        writing Action1 exposure rows, or touching the discovery
        watermark/evaluated log -- safe to run repeatedly to sanity-check
        the relevance filter against real NVD data. Already-known CVEs
        (cached or already evaluated) are reported from what's already on
        file rather than re-fetched, so only genuinely new candidates cost
        a live NVD/MITRE/EPSS lookup; `max_candidates` bounds worst-case
        runtime for a large window since this runs synchronously."""
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days_back)
        candidates = self.nvd.fetch_published_between(start, end)

        truncated = len(candidates) > max_candidates
        results = []
        for cve_id in candidates[:max_candidates]:
            cached = self.cache.get_cve(cve_id)
            evaluated = self.cache.is_nvd_cve_evaluated(cve_id)

            if cached is not None:
                cve = cached
                has_exposure = bool(self.cache.get_action1_exposures_for_cve(cve_id))
            else:
                cve = EnrichedCVE(cve_id=cve_id)
                try:
                    self._compute_enrichment(cve)
                except Exception as exc:
                    results.append({"cve_id": cve_id, "error": str(exc)})
                    continue
                has_exposure = self._action1_match_preview(cve)

            relevant, reason = self._classify_relevance(cve, has_exposure)
            results.append(
                {
                    "cve_id": cve_id,
                    "already_known": cached is not None,
                    "already_evaluated": evaluated,
                    "would_keep": relevant,
                    "reason": reason,
                    "severity": cve.risk_level,
                    "cvss": cve.cvss_v4_score if cve.cvss_v4_score is not None else cve.cvss_v3_score,
                    "kev_listed": cve.kev_listed,
                    "vendor": cve.vendor,
                    "product": cve.product,
                    "published_date": cve.published_date,
                }
            )

        return {
            "window_start": start.isoformat(),
            "window_end": end.isoformat(),
            "total_candidates": len(candidates),
            "truncated": truncated,
            "results": results,
        }
