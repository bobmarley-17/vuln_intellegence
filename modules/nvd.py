"""NVD (National Vulnerability Database) REST API v2.0 client."""
from __future__ import annotations

import logging
import time

import requests

from modules.models import EnrichedCVE

logger = logging.getLogger("vuln_intel.nvd")

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDClient:
    """Fetches CVSS v3/v4, severity, vector components, CWE, CPEs, dates and
    references for a given CVE ID. Respects NVD's published rate limits:
    5 req/30s without an API key, 50 req/30s with one."""

    def __init__(self, api_key: str | None, timeout: int, max_retries: int, backoff_factor: float, rate_limit_delay: float):
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.rate_limit_delay = rate_limit_delay
        self.session = requests.Session()
        if api_key:
            self.session.headers["apiKey"] = api_key

    def enrich(self, cve_id: str, target: EnrichedCVE) -> list[dict]:
        """Populate `target` in place with NVD data. Logs and returns an
        empty list on failure so downstream enrichment steps still run.
        Returns the raw `configurations` block so callers (e.g. vendor
        identification) can reuse it without a second API call."""
        data = self._fetch(cve_id)
        if not data:
            return []
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            logger.warning("NVD returned no data for %s", cve_id)
            return []
        cve = vulnerabilities[0].get("cve", {})

        target.published_date = cve.get("published")
        target.modified_date = cve.get("lastModified")

        descriptions = cve.get("descriptions", [])
        en_desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)
        if en_desc and not target.description:
            target.description = en_desc

        self._parse_metrics(cve.get("metrics", {}), target)
        target.cwe = self._parse_cwe(cve.get("weaknesses", []))
        configurations = cve.get("configurations", [])
        target.cpes = self._parse_cpes(configurations)
        # Merge and deduplicate with any existing references (e.g., from Mitre)
        new_refs = {r["url"] for r in cve.get("references", []) if r.get("url")}
        target.references = sorted(list(set(target.references) | new_refs))
        return configurations

    def _fetch(self, cve_id: str) -> dict | None:
        params = {"cveId": cve_id}
        delay = self.rate_limit_delay
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self.session.get(NVD_BASE_URL, params=params, timeout=self.timeout)
                if resp.status_code == 429:
                    wait = self.backoff_factor**attempt
                    logger.warning("NVD rate-limited on %s, backing off %.1fs", cve_id, wait)
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                time.sleep(delay)  # stay under the rate limit for the *next* call
                return resp.json()
            except requests.exceptions.Timeout:
                logger.error("NVD timeout for %s (attempt %d/%d)", cve_id, attempt, self.max_retries)
            except requests.exceptions.RequestException as exc:
                logger.error("NVD error for %s (attempt %d/%d): %s", cve_id, attempt, self.max_retries, exc)
            time.sleep(self.backoff_factor**attempt)
        logger.error("NVD lookup failed for %s after %d attempts", cve_id, self.max_retries)
        return None

    @staticmethod
    def _parse_metrics(metrics: dict, target: EnrichedCVE) -> None:
        # CVSS v4 (newest, prefer if present)
        for entry in metrics.get("cvssMetricV40", []):
            d = entry.get("cvssData", {})
            target.cvss_v4_score = d.get("baseScore")
            target.cvss_v4_vector = d.get("vectorString")
            break

        # CVSS v3.1 then v3.0
        v3_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
        for entry in v3_list:
            d = entry.get("cvssData", {})
            target.cvss_v3_score = d.get("baseScore")
            target.cvss_v3_vector = d.get("vectorString")
            target.severity = d.get("baseSeverity")
            target.attack_vector = d.get("attackVector")
            target.attack_complexity = d.get("attackComplexity")
            target.privileges_required = d.get("privilegesRequired")
            target.user_interaction = d.get("userInteraction")
            target.scope = d.get("scope")
            target.confidentiality_impact = d.get("confidentialityImpact")
            target.integrity_impact = d.get("integrityImpact")
            target.availability_impact = d.get("availabilityImpact")
            break

        if not target.severity:
            for entry in metrics.get("cvssMetricV2", []):
                target.severity = entry.get("baseSeverity")
                break

    @staticmethod
    def _parse_cwe(weaknesses: list[dict]) -> list[str]:
        cwes: list[str] = []
        for w in weaknesses:
            for desc in w.get("description", []):
                value = desc.get("value")
                if value and value.startswith("CWE-") and value not in cwes:
                    cwes.append(value)
        return cwes

    @staticmethod
    def _parse_cpes(configurations: list[dict]) -> list[str]:
        cpes: list[str] = []
        for config_node in configurations:
            for node in config_node.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria")
                    if criteria and criteria not in cpes:
                        cpes.append(criteria)
        return cpes

    @staticmethod
    def parse_version_ranges(configurations: list[dict]) -> list[dict]:
        """Return raw cpeMatch entries (criteria + version bounds) for the
        normalizer to turn into human-readable ranges."""
        matches: list[dict] = []
        for config_node in configurations:
            for node in config_node.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    matches.append(
                        {
                            "criteria": match.get("criteria"),
                            "vulnerable": match.get("vulnerable", True),
                            "versionStartIncluding": match.get("versionStartIncluding"),
                            "versionStartExcluding": match.get("versionStartExcluding"),
                            "versionEndIncluding": match.get("versionEndIncluding"),
                            "versionEndExcluding": match.get("versionEndExcluding"),
                        }
                    )
        return matches
