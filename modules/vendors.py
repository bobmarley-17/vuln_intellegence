"""Best-effort vendor/product identification and affected-version rollup.

Uses data already fetched from NVD (CPE configurations) and CVE.org
(structured `affected` blocks) — no extra scraping or network calls.
"""
from __future__ import annotations

import logging

from modules.models import EnrichedCVE
from modules.normalizer import (
    collapse_affected_products,
    display_product,
    display_vendor,
    normalize_cpe_matches,
    summarize_affected_products,
)
from modules.nvd import NVDClient

logger = logging.getLogger("vuln_intel.vendors")


class VendorIdentifier:
    """Fills in vendor/product/affected_products/display strings on an
    EnrichedCVE using whatever configuration data NVD returned plus any
    structured affected-version data CVE.org already contributed."""

    def enrich(self, target: EnrichedCVE, nvd_configurations: list[dict]) -> None:
        cpe_matches = NVDClient.parse_version_ranges(nvd_configurations)
        cpe_products = normalize_cpe_matches(cpe_matches)

        # Pool CVE.org's raw per-version rows (set in mitre.py) with NVD's
        # CPE-derived rows, then collapse the whole pool into one compact
        # row per distinct vendor+product (Step 4: normalize versions).
        target.affected_products = collapse_affected_products(target.affected_products + cpe_products)

        # The collapsed list picks the cleanest (shortest) product string per
        # group, which is always at least as good as mitre.py's raw first-seen
        # value - so it takes precedence here rather than only filling gaps.
        if target.affected_products:
            target.vendor = target.affected_products[0].vendor
            target.product = target.affected_products[0].product

        if target.vendor:
            target.vendor = display_vendor(target.vendor)
        if target.product:
            target.product = display_product(target.product)

        affected_display, fixed_display = summarize_affected_products(target.affected_products)
        target.affected_versions_display = affected_display
        target.fixed_versions_display = fixed_display
