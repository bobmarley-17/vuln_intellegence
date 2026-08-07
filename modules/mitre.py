"""CVE.org (MITRE CVE Services / CVE JSON 5.0) client."""
from __future__ import annotations

import logging
import time

import requests

from modules.models import AffectedProduct, EnrichedCVE

logger = logging.getLogger("vuln_intel.mitre")

CVE_ORG_BASE_URL = "https://cveawg.mitre.org/api/cve"


class MitreClient:
    """Fetches the official CVE.org record: description, CNA, vendor,
    product, affected/fixed versions and references."""

    def __init__(self, timeout: int, max_retries: int, backoff_factor: float):
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.session = requests.Session()

    def enrich(self, cve_id: str, target: EnrichedCVE) -> None:
        data = self._fetch(cve_id)
        if not data:
            return

        cna = data.get("containers", {}).get("cna", {})
        provider = cna.get("providerMetadata", {})
        target.cna = provider.get("shortName")

        descriptions = cna.get("descriptions", [])
        en_desc = next((d["value"] for d in descriptions if d.get("lang", "en").startswith("en")), None)
        if en_desc:
            target.description = en_desc  # CVE.org description takes precedence: it's the authoritative record

        affected = cna.get("affected", [])
        for entry in affected:
            vendor = entry.get("vendor") or "Unknown"
            product = entry.get("product") or "Unknown"
            if not target.vendor and vendor != "Unknown":
                target.vendor = vendor
            if not target.product and product != "Unknown":
                target.product = product

            for version_entry in entry.get("versions", []):
                status = version_entry.get("status", "affected")
                if status != "affected":
                    continue  # "unaffected"/"unknown" rows aren't patch-relevant here
                version = version_entry.get("version")
                fixed = version_entry.get("lessThan") or version_entry.get("lessThanOrEqual")
                # "0"/"*" are CVE JSON 5 sentinels for "no explicit lower bound",
                # not real version numbers - don't surface them as an affected version.
                affected_range = version if version not in (None, "0", "*", "") else None
                target.affected_products.append(
                    AffectedProduct(
                        vendor=vendor,
                        product=product,
                        affected_range=affected_range,
                        fixed_version=fixed,
                        status=status,
                    )
                )

        refs = cna.get("references", [])
        # Use a set for efficient addition and deduplication
        all_refs = set(target.references)
        for r in refs:
            if url := r.get("url"):
                all_refs.add(url)
        target.references = sorted(list(all_refs))

    def _fetch(self, cve_id: str) -> dict | None:
        url = f"{CVE_ORG_BASE_URL}/{cve_id}"
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 404:
                    logger.warning("CVE.org has no record for %s", cve_id)
                    return None
                if resp.status_code == 429:
                    wait = self.backoff_factor**attempt
                    logger.warning("CVE.org rate-limited on %s, backing off %.1fs", cve_id, wait)
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.Timeout:
                logger.error("CVE.org timeout for %s (attempt %d/%d)", cve_id, attempt, self.max_retries)
            except requests.exceptions.RequestException as exc:
                logger.error("CVE.org error for %s (attempt %d/%d): %s", cve_id, attempt, self.max_retries, exc)
            time.sleep(self.backoff_factor**attempt)
        logger.error("CVE.org lookup failed for %s after %d attempts", cve_id, self.max_retries)
        return None
