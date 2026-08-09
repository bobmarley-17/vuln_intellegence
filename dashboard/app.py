"""Flask web dashboard: search, filter, sort, paginate and chart the
enriched CVE data collected by the pipeline."""
from __future__ import annotations

import dataclasses
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request

from config import Config
from modules.cache import DuplicateSourceError, VulnCache
from modules.downloader import Downloader
from modules.models import AffectedProduct, EnrichedCVE
from modules.normalizer import product_version_affected
from modules.pipeline import Pipeline
from modules.source_parsers import DEFAULT_SOURCE_TYPE, SOURCE_TYPES, test_connection as test_source_connection

logger = logging.getLogger("vuln_intel.dashboard")

DASHBOARD_DIR = Path(__file__).resolve().parent
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class PipelineRunner:
    """Runs pipeline jobs (full runs, single-source enrichments) on a
    background thread, one at a time, and exposes their status for the
    dashboard to poll."""

    def __init__(self, pipeline: Pipeline):
        self.pipeline = pipeline
        self._run_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._state = {
            "running": False,
            "job": None,
            "started_at": None,
            "last_finished_at": None,
            "last_result": None,
            "last_error": None,
        }

    def status(self) -> dict:
        with self._state_lock:
            return dict(self._state)

    def start(self, job_name: str, fn, wait_if_busy: bool = True, on_done=None) -> bool:
        """Start `fn` on a background thread under the run lock. If another
        job is already running and `wait_if_busy` is False, returns False
        without queuing. Otherwise the job is queued (or run immediately)
        and this always returns True. `on_done`, if given, always runs after
        the job finishes (success or failure) -- used by the scheduler to
        clear its own pending-source bookkeeping."""
        if not wait_if_busy and self._run_lock.locked():
            return False

        def target():
            with self._run_lock:
                with self._state_lock:
                    self._state.update(
                        running=True,
                        job=job_name,
                        started_at=datetime.now(timezone.utc).isoformat(),
                        last_error=None,
                    )
                try:
                    result = fn()
                    with self._state_lock:
                        self._state["last_result"] = result
                except Exception as exc:
                    logger.exception("Background job '%s' failed", job_name)
                    with self._state_lock:
                        self._state["last_error"] = str(exc)
                finally:
                    with self._state_lock:
                        self._state.update(
                            running=False,
                            job=None,
                            last_finished_at=datetime.now(timezone.utc).isoformat(),
                        )
                    if on_done:
                        try:
                            on_done()
                        except Exception:
                            logger.exception("on_done callback failed for job '%s'", job_name)

        threading.Thread(target=target, daemon=True).start()
        return True


class SourceScheduler:
    """Background thread that fires a scan for any enabled source whose
    polling_interval_minutes has elapsed since its last scan.

    This only runs while the dashboard process is alive -- it is an
    in-process convenience, not an OS-level cron. If the dashboard isn't
    running, sources simply wait for the next manual scan or process start."""

    def __init__(self, cache: VulnCache, runner: PipelineRunner, check_interval_seconds: int = 60):
        self.cache = cache
        self.runner = runner
        self.check_interval_seconds = check_interval_seconds
        self._pending: set[int] = set()
        self._pending_lock = threading.Lock()
        self._stop_event = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self) -> None:
        self._stop_event.set()

    def _loop(self) -> None:
        while not self._stop_event.wait(self.check_interval_seconds):
            try:
                self._tick()
            except Exception:
                logger.exception("Source scheduler tick failed")

    def _tick(self) -> None:
        now = datetime.now(timezone.utc)
        for source in self.cache.get_enabled_sources():
            interval = source.get("polling_interval_minutes")
            if not interval or not self._is_due(source, now, interval):
                continue
            self._schedule(source)

    @staticmethod
    def _is_due(source: dict, now: datetime, interval_minutes: int) -> bool:
        last_checked = source.get("last_checked")
        if not last_checked:
            return True
        try:
            last = datetime.fromisoformat(last_checked)
        except ValueError:
            return True
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return now - last >= timedelta(minutes=interval_minutes)

    def _schedule(self, source: dict) -> None:
        source_id = source["id"]
        with self._pending_lock:
            if source_id in self._pending:
                return  # already queued/running from a previous tick
            self._pending.add(source_id)

        def clear_pending():
            with self._pending_lock:
                self._pending.discard(source_id)

        label = source.get("name") or source["url"]
        self.runner.start(
            f"Scheduled scan: {label}",
            lambda: self.runner.pipeline.run_single(source_id),
            wait_if_busy=True,
            on_done=clear_pending,
        )


def create_app(config: Config, debug: bool = False) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(DASHBOARD_DIR / "templates"),
        static_folder=str(DASHBOARD_DIR / "static"),
    )
    cache = VulnCache(config.cache_db_path, ttl_hours=config.cache_ttl_hours)
    runner = PipelineRunner(Pipeline(config))
    scheduler = SourceScheduler(cache, runner)
    # Under the Werkzeug debug reloader, this module is imported once in the
    # watcher process and once in the actual worker (WERKZEUG_RUN_MAIN=true);
    # only start the background scheduler in the process that will serve
    # requests, or it ends up running twice.
    if not debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        scheduler.start()

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/cves")
    def api_cves():
        cves = cache.get_all_cves()
        cves = _apply_filters(cves, request.args)
        cves = _apply_search(cves, request.args.get("q", "").strip())
        cves = _apply_sort(cves, request.args.get("sort_by", "risk_score"), request.args.get("sort_dir", "desc"))

        page = max(request.args.get("page", 1, type=int) or 1, 1)
        page_size = min(max(request.args.get("page_size", 25, type=int) or 25, 1), 200)
        total = len(cves)
        start = (page - 1) * page_size
        page_items = cves[start : start + page_size]

        return jsonify(
            {
                "total": total,
                "page": page,
                "page_size": page_size,
                "items": [_serialize(c) for c in page_items],
            }
        )

    @app.route("/api/stats")
    def api_stats():
        cves = cache.get_all_cves()
        articles = cache.get_articles()

        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        vendor_counts: dict[str, int] = {}
        product_counts: dict[str, int] = {}
        kev_count = 0
        recent_cves_7d = 0

        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        for c in cves:
            level = c.risk_level or "Low"
            if level in severity_counts:
                severity_counts[level] += 1
            if c.vendor:
                vendor_counts[c.vendor] = vendor_counts.get(c.vendor, 0) + 1
            if c.product:
                product_counts[c.product] = product_counts.get(c.product, 0) + 1
            if c.kev_listed:
                kev_count += 1
            published = _parse_iso_date(c.published_date)
            if published and published >= cutoff:
                recent_cves_7d += 1

        recent_articles_7d = sum(1 for a in articles if (_parse_iso_date(a.get("fetched_at")) or cutoff) >= cutoff)

        top_vendors = sorted(vendor_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
        top_vendor = {"name": top_vendors[0][0], "count": top_vendors[0][1]} if top_vendors else None
        top_products = sorted(product_counts.items(), key=lambda kv: kv[1], reverse=True)[:1]
        top_product = {"name": top_products[0][0], "count": top_products[0][1]} if top_products else None

        return jsonify(
            {
                "total_articles": len(articles),
                "total_cves": len(cves),
                "severity_counts": severity_counts,
                "kev_count": kev_count,
                "vendor_count": len(vendor_counts),
                "product_count": len(product_counts),
                "top_vendors": [{"vendor": v, "count": n} for v, n in top_vendors],
                "recent_cves_7d": recent_cves_7d,
                "recent_articles_7d": recent_articles_7d,
                "top_vendor": top_vendor,
                "top_product": top_product,
            }
        )

    @app.route("/api/analytics")
    def api_analytics():
        """Aggregate chart data for the Analytics page. Computed on demand
        from the same cached CVE set /api/stats and /api/vendors use --
        no separate storage, so it's always consistent with the rest of
        the dashboard."""
        cves = cache.get_all_cves()
        articles = cache.get_articles()

        monthly_counts: dict[str, int] = {}
        for c in cves:
            published = _parse_iso_date(c.published_date)
            if not published:
                continue
            key = f"{published.year:04d}-{published.month:02d}"
            monthly_counts[key] = monthly_counts.get(key, 0) + 1
        monthly_trend = [{"month": k, "count": monthly_counts[k]} for k in sorted(monthly_counts)[-12:]]

        article_monthly_counts: dict[str, int] = {}
        for a in articles:
            fetched = _parse_iso_date(a.get("fetched_at"))
            if not fetched:
                continue
            key = f"{fetched.year:04d}-{fetched.month:02d}"
            article_monthly_counts[key] = article_monthly_counts.get(key, 0) + 1
        articles_trend = [
            {"month": k, "count": article_monthly_counts[k]} for k in sorted(article_monthly_counts)[-12:]
        ]

        vendor_counts: dict[str, int] = {}
        product_counts: dict[str, int] = {}
        kev_count = 0
        for c in cves:
            if c.vendor:
                vendor_counts[c.vendor] = vendor_counts.get(c.vendor, 0) + 1
            if c.product:
                product_counts[c.product] = product_counts.get(c.product, 0) + 1
            if c.kev_listed:
                kev_count += 1

        top_vendors = sorted(vendor_counts.items(), key=lambda kv: kv[1], reverse=True)[:8]
        top_products = sorted(product_counts.items(), key=lambda kv: kv[1], reverse=True)[:8]

        recent = sorted(cves, key=lambda c: c.published_date or "", reverse=True)[:8]

        return jsonify(
            {
                "monthly_trend": monthly_trend,
                "articles_trend": articles_trend,
                "vendor_bar": [{"vendor": v, "count": n} for v, n in top_vendors],
                "product_bar": [{"product": p, "count": n} for p, n in top_products],
                "kev_vs_non_kev": {"kev": kev_count, "non_kev": len(cves) - kev_count},
                "recent_cves": [
                    {
                        "cve_id": c.cve_id,
                        "vendor": c.vendor,
                        "product": c.product,
                        "risk_level": c.risk_level,
                        "published_date": c.published_date,
                        "kev_listed": c.kev_listed,
                    }
                    for c in recent
                ],
            }
        )

    @app.route("/api/settings")
    def api_settings():
        """Read-only view of the active (non-secret) configuration. There is
        no settings-editing UI: these values come from environment
        variables / config.yaml, so surfacing them read-only avoids a
        Settings page with controls that don't actually do anything."""
        return jsonify(
            {
                "request_timeout_seconds": config.request_timeout,
                "max_retries": config.max_retries,
                "backoff_factor": config.backoff_factor,
                "concurrency": config.concurrency,
                "cache_ttl_hours": config.cache_ttl_hours,
                "nvd_api_key_configured": bool(config.nvd_api_key),
                "nvd_rate_limit_delay_seconds": config.nvd_rate_limit_delay,
                "urls_file": config.urls_file,
                "output_folder": config.output_folder,
                "cache_folder": config.cache_folder,
                "log_folder": config.log_folder,
            }
        )

    @app.route("/api/cve/<cve_id>")
    def api_cve_detail(cve_id):
        cve = cache.get_cve(cve_id.strip().upper())
        if cve is None:
            return jsonify({"error": "CVE not found"}), 404
        return jsonify(_serialize(cve))

    @app.route("/api/check")
    def api_check():
        """Vulnerability checker: given a product (and optionally a vendor
        and a version), return every known CVE affecting that product, with
        a per-CVE vulnerable/not-affected verdict when a version is given."""
        vendor = (request.args.get("vendor") or "").strip()
        product = (request.args.get("product") or "").strip()
        version = (request.args.get("version") or "").strip()
        if not product:
            return jsonify({"error": "A product is required"}), 400

        cves = cache.get_all_cves()
        results = []
        for cve in cves:
            candidates = cve.affected_products or (
                [AffectedProduct(vendor=cve.vendor or "", product=cve.product)] if cve.product else []
            )
            match = next(
                (
                    ap
                    for ap in candidates
                    if product.lower() in (ap.product or "").lower()
                    and (not vendor or vendor.lower() in (ap.vendor or "").lower())
                ),
                None,
            )
            if match is None:
                continue

            if version and match.affected_range:
                status = "vulnerable" if product_version_affected(match.affected_range, version) else "not_affected"
            else:
                status = "unknown"

            results.append(
                {
                    "cve": _serialize(cve),
                    "matched_vendor": match.vendor,
                    "matched_product": match.product,
                    "affected_range": match.affected_range,
                    "fixed_version": match.fixed_version,
                    "version_status": status,
                }
            )

        results.sort(key=lambda r: r["cve"]["risk_score"] or 0, reverse=True)
        return jsonify(
            {
                "query": {"vendor": vendor or None, "product": product, "version": version or None},
                "total": len(results),
                "vulnerable_count": sum(1 for r in results if r["version_status"] == "vulnerable"),
                "results": results,
            }
        )

    @app.route("/api/filters")
    def api_filters():
        """Distinct values for populating filter dropdowns."""
        cves = cache.get_all_cves()
        vendors = sorted({c.vendor for c in cves if c.vendor})
        products = sorted({c.product for c in cves if c.product})
        sources: set[str] = set()
        for c in cves:
            sources.update(_source_sites(c))
        return jsonify({"vendors": vendors, "products": products, "sources": sorted(sources)})

    @app.route("/api/articles")
    def api_articles():
        articles = cache.get_articles()

        # Articles don't carry their own severity -- derive "highest severity
        # among the CVEs this article mentions" from the CVE cache so the
        # Security Intelligence cards can show something meaningful.
        severity_by_cve = {c.cve_id: (c.risk_level or "").upper() for c in cache.get_all_cves()}
        for a in articles:
            levels = [severity_by_cve.get(cve_id) for cve_id in a.get("cves") or []]
            levels = [lvl for lvl in levels if lvl in SEVERITY_ORDER]
            a["highest_severity"] = min(levels, key=lambda lvl: SEVERITY_ORDER[lvl]).title() if levels else None

        q = (request.args.get("q") or "").strip().lower()
        if q:
            articles = [
                a
                for a in articles
                if q in (a.get("title") or "").lower()
                or q in (a.get("site_name") or "").lower()
                or q in (a.get("url") or "").lower()
            ]

        sort_by = request.args.get("sort_by", "fetched_at")
        reverse = request.args.get("sort_dir", "desc") != "asc"
        key_funcs = {
            "fetched_at": lambda a: a.get("fetched_at") or "",
            "published_date": lambda a: a.get("published_date") or "",
            "title": lambda a: (a.get("title") or "").lower(),
            "site_name": lambda a: (a.get("site_name") or "").lower(),
            "cve_count": lambda a: len(a.get("cves") or []),
        }
        articles = sorted(articles, key=key_funcs.get(sort_by, key_funcs["fetched_at"]), reverse=reverse)

        page = max(request.args.get("page", 1, type=int) or 1, 1)
        page_size = min(max(request.args.get("page_size", 25, type=int) or 25, 1), 200)
        total = len(articles)
        start = (page - 1) * page_size
        # The article body isn't needed for a list view; drop it to keep the payload light.
        page_items = [{k: v for k, v in a.items() if k != "content"} for a in articles[start : start + page_size]]

        return jsonify({"total": total, "page": page, "page_size": page_size, "items": page_items})

    @app.route("/api/vendors")
    def api_vendors_list():
        """Per-vendor CVE rollup for the Vendors page."""
        cves = cache.get_all_cves()
        agg: dict[str, dict] = {}
        for c in cves:
            if not c.vendor:
                continue
            entry = agg.setdefault(
                c.vendor,
                {"vendor": c.vendor, "cve_count": 0, "kev_count": 0, "critical_count": 0, "high_count": 0, "_products": set()},
            )
            entry["cve_count"] += 1
            entry["kev_count"] += int(c.kev_listed)
            if c.risk_level == "Critical":
                entry["critical_count"] += 1
            elif c.risk_level == "High":
                entry["high_count"] += 1
            if c.product:
                entry["_products"].add(c.product)

        results = []
        for entry in agg.values():
            entry["product_count"] = len(entry.pop("_products"))
            results.append(entry)
        results.sort(key=lambda v: v["cve_count"], reverse=True)
        return jsonify({"total": len(results), "items": results})

    @app.route("/api/products")
    def api_products_list():
        """Per-product CVE rollup for the Products page."""
        cves = cache.get_all_cves()
        agg: dict[tuple[str, str], dict] = {}
        for c in cves:
            if not c.product:
                continue
            key = (c.vendor or "", c.product)
            entry = agg.setdefault(
                key,
                {"vendor": c.vendor, "product": c.product, "cve_count": 0, "kev_count": 0, "critical_count": 0, "high_count": 0},
            )
            entry["cve_count"] += 1
            entry["kev_count"] += int(c.kev_listed)
            if c.risk_level == "Critical":
                entry["critical_count"] += 1
            elif c.risk_level == "High":
                entry["high_count"] += 1

        results = sorted(agg.values(), key=lambda v: v["cve_count"], reverse=True)
        return jsonify({"total": len(results), "items": results})

    @app.route("/api/source-types")
    def api_source_types():
        return jsonify({"source_types": list(SOURCE_TYPES)})

    @app.route("/api/sources", methods=["GET"])
    def api_get_sources():
        return jsonify(cache.get_all_sources())

    @app.route("/api/sources", methods=["POST"])
    def api_add_source():
        data = request.get_json(silent=True) or {}
        url = str(data.get("url", "")).strip()
        name = (str(data.get("name") or "")).strip() or None
        source_type = (str(data.get("source_type") or DEFAULT_SOURCE_TYPE)).strip()
        vendor = (str(data.get("vendor") or "")).strip() or None
        enabled = bool(data.get("enabled", True))

        if not Downloader.is_valid_url(url):
            return jsonify({"error": "Invalid URL provided"}), 400
        if source_type not in SOURCE_TYPES:
            return jsonify({"error": f"source_type must be one of: {', '.join(SOURCE_TYPES)}"}), 400
        ok, polling_interval_minutes = _parse_polling_interval(data.get("polling_interval_minutes"))
        if not ok:
            return jsonify({"error": "polling_interval_minutes must be a positive number of minutes"}), 400

        try:
            source_id = cache.add_source(
                url,
                name=name,
                source_type=source_type,
                vendor=vendor,
                polling_interval_minutes=polling_interval_minutes,
                enabled=enabled,
            )
        except DuplicateSourceError:
            return jsonify({"error": "A source with this URL already exists"}), 409

        if enabled:
            runner.start(f"Processing source: {name or url}", lambda: runner.pipeline.run_single(source_id))
        return jsonify({"message": "Source added; processing in the background", "id": source_id, "source": cache.get_source(source_id)}), 201

    @app.route("/api/sources/<int:source_id>", methods=["GET"])
    def api_get_source(source_id):
        source = cache.get_source(source_id)
        if source is None:
            return jsonify({"error": "Source not found"}), 404
        return jsonify(source)

    @app.route("/api/sources/<int:source_id>", methods=["PUT"])
    def api_update_source(source_id):
        if cache.get_source(source_id) is None:
            return jsonify({"error": "Source not found"}), 404

        data = request.get_json(silent=True) or {}
        updates: dict = {}

        if "name" in data:
            updates["name"] = (str(data.get("name") or "")).strip() or None
        if "url" in data:
            url = str(data.get("url", "")).strip()
            if not Downloader.is_valid_url(url):
                return jsonify({"error": "Invalid URL provided"}), 400
            updates["url"] = url
        if "source_type" in data:
            source_type = (str(data.get("source_type") or "")).strip()
            if source_type not in SOURCE_TYPES:
                return jsonify({"error": f"source_type must be one of: {', '.join(SOURCE_TYPES)}"}), 400
            updates["source_type"] = source_type
        if "vendor" in data:
            updates["vendor"] = (str(data.get("vendor") or "")).strip() or None
        if "polling_interval_minutes" in data:
            ok, polling_interval_minutes = _parse_polling_interval(data.get("polling_interval_minutes"))
            if not ok:
                return jsonify({"error": "polling_interval_minutes must be a positive number of minutes"}), 400
            updates["polling_interval_minutes"] = polling_interval_minutes
        if "enabled" in data:
            updates["enabled"] = bool(data.get("enabled"))

        try:
            cache.update_source(source_id, **updates)
        except DuplicateSourceError:
            return jsonify({"error": "A source with this URL already exists"}), 409
        return jsonify({"message": "Source updated", "source": cache.get_source(source_id)})

    @app.route("/api/sources/<int:source_id>", methods=["DELETE"])
    def api_delete_source(source_id):
        cache.delete_source(source_id)
        return jsonify({"message": "Source deleted successfully"}), 200

    @app.route("/api/sources/<int:source_id>/enable", methods=["POST"])
    def api_enable_source(source_id):
        if not cache.set_source_enabled(source_id, True):
            return jsonify({"error": "Source not found"}), 404
        return jsonify({"message": "Source enabled", "source": cache.get_source(source_id)})

    @app.route("/api/sources/<int:source_id>/disable", methods=["POST"])
    def api_disable_source(source_id):
        if not cache.set_source_enabled(source_id, False):
            return jsonify({"error": "Source not found"}), 404
        return jsonify({"message": "Source disabled", "source": cache.get_source(source_id)})

    @app.route("/api/sources/<int:source_id>/scan", methods=["POST"])
    def api_scan_source(source_id):
        source = cache.get_source(source_id)
        if source is None:
            return jsonify({"error": "Source not found"}), 404
        if not source["enabled"]:
            return jsonify({"error": "Source is disabled; enable it before scanning"}), 400

        label = source.get("name") or source["url"]
        started = runner.start(f"Scanning: {label}", lambda: runner.pipeline.run_single(source_id), wait_if_busy=False)
        if not started:
            return jsonify({"error": "A scan or pipeline job is already running"}), 409
        return jsonify({"message": "Scan started"}), 202

    @app.route("/api/sources/<int:source_id>/history")
    def api_source_history(source_id):
        if cache.get_source(source_id) is None:
            return jsonify({"error": "Source not found"}), 404
        return jsonify(cache.get_scan_history(source_id))

    @app.route("/api/scan-history")
    def api_scan_history():
        """Scan history across every source, for the dedicated Scan History
        page. Optionally scoped to one source via ?source_id=."""
        source_id = request.args.get("source_id", type=int)
        return jsonify(cache.get_all_scan_history(source_id=source_id))

    @app.route("/api/sources/test", methods=["POST"])
    def api_test_source():
        """Connection test usable both before a source is saved (Add modal)
        and against an already-saved one (Edit modal)."""
        data = request.get_json(silent=True) or {}
        url = str(data.get("url", "")).strip()
        source_type = (str(data.get("source_type") or DEFAULT_SOURCE_TYPE)).strip()
        if not Downloader.is_valid_url(url):
            return jsonify({"ok": False, "message": "Unable to Reach URL", "detail": "That is not a valid http(s) URL."})
        if source_type not in SOURCE_TYPES:
            return jsonify({"error": f"source_type must be one of: {', '.join(SOURCE_TYPES)}"}), 400
        result = test_source_connection(url, source_type, timeout=config.request_timeout, user_agent=config.user_agent)
        return jsonify(result)

    @app.route("/api/pipeline/status")
    def api_pipeline_status():
        return jsonify(runner.status())

    @app.route("/api/pipeline/run", methods=["POST"])
    def api_pipeline_run():
        started = runner.start("Full pipeline run", runner.pipeline.run, wait_if_busy=False)
        if not started:
            return jsonify({"error": "A pipeline job is already running"}), 409
        return jsonify({"message": "Pipeline run started"}), 202

    return app


def _parse_iso_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _parse_polling_interval(raw) -> tuple[bool, int | None]:
    """Returns (ok, value). `raw` may be missing/None/'' (no auto-scan) or a
    positive integer number of minutes."""
    if raw in (None, ""):
        return True, None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return False, None
    if value <= 0:
        return False, None
    return True, value


def _apply_filters(cves: list[EnrichedCVE], args) -> list[EnrichedCVE]:
    severity = args.get("severity")
    vendor = args.get("vendor")
    product = args.get("product")
    min_cvss = args.get("min_cvss", type=float)
    max_cvss = args.get("max_cvss", type=float)
    min_epss = args.get("min_epss", type=float)
    kev_only = args.get("kev_only") == "true"
    published_after = args.get("published_after")
    source_site = args.get("source_site")

    result = cves
    if severity:
        result = [c for c in result if (c.risk_level or "").lower() == severity.lower()]
    if vendor:
        result = [c for c in result if (c.vendor or "").lower() == vendor.lower()]
    if product:
        result = [c for c in result if (c.product or "").lower() == product.lower()]
    if min_cvss is not None:
        result = [c for c in result if (_cvss_score(c) or 0) >= min_cvss]
    if max_cvss is not None:
        result = [c for c in result if (_cvss_score(c) or 0) <= max_cvss]
    if min_epss is not None:
        result = [c for c in result if (c.epss_score or 0) >= min_epss]
    if kev_only:
        result = [c for c in result if c.kev_listed]
    if published_after:
        result = [c for c in result if (c.published_date or "") >= published_after]
    if source_site:
        result = [c for c in result if source_site.lower() in {s.lower() for s in _source_sites(c)}]
    return result


def _source_sites(cve: EnrichedCVE) -> list[str]:
    return sorted({urlparse(u).netloc.replace("www.", "") for u in cve.source_articles if u})


def _apply_search(cves: list[EnrichedCVE], query: str) -> list[EnrichedCVE]:
    if not query:
        return cves
    q = query.lower()

    def matches(c: EnrichedCVE) -> bool:
        haystack = [
            c.cve_id,
            c.vendor or "",
            c.product or "",
            c.summary or "",
            c.description or "",
            " ".join(c.cwe),
            c.affected_versions_display or "",
        ]
        return any(q in field.lower() for field in haystack)

    return [c for c in cves if matches(c)]


def _apply_sort(cves: list[EnrichedCVE], sort_by: str, sort_dir: str) -> list[EnrichedCVE]:
    reverse = sort_dir != "asc"
    key_funcs = {
        "risk_score": lambda c: c.risk_score or 0,
        "cvss": lambda c: _cvss_score(c) or 0,
        "epss": lambda c: c.epss_score or 0,
        "published": lambda c: c.published_date or "",
        "modified": lambda c: c.modified_date or "",
        "cve_id": lambda c: c.cve_id,
        "vendor": lambda c: c.vendor or "",
    }
    key_func = key_funcs.get(sort_by, key_funcs["risk_score"])
    return sorted(cves, key=key_func, reverse=reverse)


def _serialize(cve: EnrichedCVE) -> dict:
    d = dataclasses.asdict(cve)
    d["cvss_score"] = _cvss_score(cve)
    d["cvss_version"] = "4.0" if cve.cvss_v4_score is not None else ("3.x" if cve.cvss_v3_score is not None else None)
    d["source_sites"] = _source_sites(cve)
    return d


def _cvss_score(cve: EnrichedCVE) -> float | None:
    """Use the same CVSS preference as the risk scorer."""
    return cve.cvss_v4_score if cve.cvss_v4_score is not None else cve.cvss_v3_score
