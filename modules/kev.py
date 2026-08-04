"""CISA Known Exploited Vulnerabilities (KEV) catalog client.

The KEV catalog is a single JSON feed (~1400 entries), not a per-CVE API,
so we download it once per TTL window and do membership lookups locally
instead of hitting CISA once per CVE.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from modules.models import EnrichedCVE

logger = logging.getLogger("vuln_intel.kev")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVClient:
    def __init__(self, cache_folder: str, timeout: int, max_retries: int, backoff_factor: float, ttl_hours: int = 6):
        self.cache_path = Path(cache_folder) / "kev_catalog.json"
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.ttl_hours = ttl_hours
        self._catalog: dict[str, dict] | None = None

    def _load_catalog(self) -> dict[str, dict]:
        if self._catalog is not None:
            return self._catalog

        if self._cache_is_fresh():
            try:
                with open(self.cache_path, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
                self._catalog = self._index_by_cve(raw)
                return self._catalog
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("KEV cache unreadable, refetching: %s", exc)

        raw = self._download()
        if raw is None:
            # Fall back to a stale cache rather than treating everything as "not KEV".
            if self.cache_path.exists():
                logger.warning("Using stale KEV cache after failed refresh")
                with open(self.cache_path, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
            else:
                raw = {"vulnerabilities": []}
        self._catalog = self._index_by_cve(raw)
        return self._catalog

    def _cache_is_fresh(self) -> bool:
        if not self.cache_path.exists():
            return False
        age = datetime.now(timezone.utc) - datetime.fromtimestamp(
            self.cache_path.stat().st_mtime, tz=timezone.utc
        )
        return age < timedelta(hours=self.ttl_hours)

    def _download(self) -> dict | None:
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = requests.get(KEV_URL, timeout=self.timeout)
                resp.raise_for_status()
                data = resp.json()
                self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.cache_path, "w", encoding="utf-8") as fh:
                    json.dump(data, fh)
                logger.info("Refreshed CISA KEV catalog (%d entries)", len(data.get("vulnerabilities", [])))
                return data
            except requests.exceptions.RequestException as exc:
                logger.error("KEV download error (attempt %d/%d): %s", attempt, self.max_retries, exc)
            except json.JSONDecodeError as exc:
                logger.error("KEV feed returned malformed JSON: %s", exc)
                return None
            time.sleep(self.backoff_factor**attempt)
        logger.error("KEV catalog download failed after %d attempts", self.max_retries)
        return None

    @staticmethod
    def _index_by_cve(raw: dict) -> dict[str, dict]:
        return {v["cveID"]: v for v in raw.get("vulnerabilities", []) if v.get("cveID")}

    def enrich(self, cve_id: str, target: EnrichedCVE) -> None:
        catalog = self._load_catalog()
        entry = catalog.get(cve_id)
        if not entry:
            target.kev_listed = False
            return
        target.kev_listed = True
        target.kev_date_added = entry.get("dateAdded")
        target.kev_due_date = entry.get("dueDate")
