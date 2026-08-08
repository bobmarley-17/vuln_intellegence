"""Flask web dashboard: search, filter, sort, paginate and chart the
enriched CVE data collected by the pipeline."""
from __future__ import annotations

import dataclasses
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request

from config import Config
from modules.cache import VulnCache
from modules.downloader import Downloader
from modules.models import AffectedProduct, EnrichedCVE
from modules.normalizer import product_version_affected
from modules.pipeline import Pipeline

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

    def start(self, job_name: str, fn, wait_if_busy: bool = True) -> bool:
        """Start `fn` on a background thread under the run lock. If another
        job is already running and `wait_if_busy` is False, returns False
        without queuing. Otherwise the job is queued (or run immediately)
        and this always returns True."""
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

        threading.Thread(target=target, daemon=True).start()
        return True


def create_app(config: Config) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(DASHBOARD_DIR / "templates"),
        static_folder=str(DASHBOARD_DIR / "static"),
    )
    cache = VulnCache(config.cache_db_path, ttl_hours=config.cache_ttl_hours)
    runner = PipelineRunner(Pipeline(config))

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

        top_vendors = sorted(vendor_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]

        return jsonify(
            {
                "total_articles": len(articles),
                "total_cves": len(cves),
                "severity_counts": severity_counts,
                "kev_count": kev_count,
                "vendor_count": len(vendor_counts),
                "product_count": len(product_counts),
                "top_vendors": [{"vendor": v, "count": n} for v, n in top_vendors],
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

    @app.route("/api/sources", methods=["GET"])
    def api_get_sources():
        sources = cache.get_all_sources()
        return jsonify(sources)

    @app.route("/api/sources", methods=["POST"])
    def api_add_source():
        data = request.get_json(silent=True) or {}
        url = str(data.get("url", "")).strip()
        if not Downloader.is_valid_url(url):
            return jsonify({"error": "Invalid URL provided"}), 400

        source_id = cache.add_source_url(url)
        if source_id is None:
            return jsonify({"error": "URL already exists"}), 409

        runner.start(f"Processing source: {url}", lambda: runner.pipeline.run_single(url))
        return jsonify({"message": "Source URL added; processing in the background", "id": source_id}), 201

    @app.route("/api/sources/<int:source_id>", methods=["DELETE"])
    def api_delete_source(source_id):
        cache.delete_source(source_id)
        return jsonify({"message": "Source deleted successfully"}), 200

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


def _apply_filters(cves: list[EnrichedCVE], args) -> list[EnrichedCVE]:
    severity = args.get("severity")
    vendor = args.get("vendor")
    product = args.get("product")
    min_cvss = args.get("min_cvss", type=float)
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
