"""FIRST.org EPSS (Exploit Prediction Scoring System) client."""
from __future__ import annotations

import logging
import time

import requests

from modules.models import EnrichedCVE

logger = logging.getLogger("vuln_intel.epss")

EPSS_BASE_URL = "https://api.first.org/data/v1/epss"


class EPSSClient:
    """Fetches EPSS score and percentile for a CVE. No API key required."""

    def __init__(self, timeout: int, max_retries: int, backoff_factor: float):
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.session = requests.Session()

    def enrich(self, cve_id: str, target: EnrichedCVE) -> None:
        data = self._fetch(cve_id)
        if not data:
            return
        results = data.get("data", [])
        if not results:
            logger.info("No EPSS score available for %s", cve_id)
            return
        entry = results[0]
        try:
            target.epss_score = float(entry.get("epss")) if entry.get("epss") is not None else None
            target.epss_percentile = float(entry.get("percentile")) if entry.get("percentile") is not None else None
        except (TypeError, ValueError):
            logger.warning("Malformed EPSS data for %s: %s", cve_id, entry)

    def _fetch(self, cve_id: str) -> dict | None:
        params = {"cve": cve_id}
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self.session.get(EPSS_BASE_URL, params=params, timeout=self.timeout)
                if resp.status_code == 429:
                    wait = self.backoff_factor**attempt
                    logger.warning("EPSS rate-limited on %s, backing off %.1fs", cve_id, wait)
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.Timeout:
                logger.error("EPSS timeout for %s (attempt %d/%d)", cve_id, attempt, self.max_retries)
            except requests.exceptions.RequestException as exc:
                logger.error("EPSS error for %s (attempt %d/%d): %s", cve_id, attempt, self.max_retries, exc)
            time.sleep(self.backoff_factor**attempt)
        logger.error("EPSS lookup failed for %s after %d attempts", cve_id, self.max_retries)
        return None
