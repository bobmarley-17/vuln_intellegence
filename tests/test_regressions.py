"""Regression tests for data-integrity behavior in the enrichment pipeline."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from modules.cache import VulnCache
from modules.models import Article, EnrichedCVE
from modules.normalizer import (
    collapse_affected_products,
    normalize_cpe_matches,
    product_version_affected,
    version_in_range,
)
from modules.models import AffectedProduct
from modules.nvd import NVDClient


class RegressionTests(unittest.TestCase):
    def test_nested_nvd_nodes_are_parsed(self):
        configurations = [{"nodes": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}]}]}]}]
        self.assertEqual(
            NVDClient._parse_cpes(configurations),
            ["cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"],
        )

    def test_exclusive_range_and_distinct_branches_are_preserved(self):
        products = normalize_cpe_matches(
            [{
                "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                "versionStartExcluding": "1.0",
                "versionEndIncluding": "1.2",
            }]
        )
        self.assertEqual(products[0].affected_range, "> 1.0, <= 1.2")
        collapsed = collapse_affected_products([
            AffectedProduct("Acme", "Widget", "1.0 - 1.2"),
            AffectedProduct("Acme", "Widget", "3.0 - 3.2"),
        ])
        self.assertEqual(collapsed[0].affected_range, "1.0 - 1.2; 3.0 - 3.2")

    def test_article_cve_links_are_replaced_on_refetch(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = VulnCache(str(Path(directory) / "cache.db"))
            cache.save_article(Article(url="https://example.test/a", cves=["CVE-2024-0001"]))
            cache.save_article(Article(url="https://example.test/a", cves=["CVE-2024-0002"]))
            self.assertEqual(cache.get_articles()[0]["cves"], ["CVE-2024-0002"])

    def test_preferred_cvss_uses_v4_when_available(self):
        cve = EnrichedCVE(cve_id="CVE-2024-0001", cvss_v3_score=7.5, cvss_v4_score=8.2)
        from dashboard.app import _cvss_score
        self.assertEqual(_cvss_score(cve), 8.2)

    def test_version_in_range_bounds(self):
        self.assertTrue(version_in_range("9.0.94", "< 9.0.95"))
        self.assertFalse(version_in_range("9.0.95", "< 9.0.95"))
        self.assertTrue(version_in_range("9.0.95", "<= 9.0.95"))
        self.assertTrue(version_in_range("1.1", ">= 1.0, <= 1.2"))
        self.assertFalse(version_in_range("1.3", ">= 1.0, <= 1.2"))
        self.assertFalse(version_in_range("1.0", "> 1.0, <= 1.2"))
        self.assertTrue(version_in_range("9.9.9", "all versions"))

    def test_version_in_range_pinned_exact_match(self):
        self.assertTrue(version_in_range("1.0", "1.0"))
        self.assertFalse(version_in_range("1.0.0", "1.1"))

    def test_product_version_affected_across_branches(self):
        affected_range = ">= 1.0, <= 1.2; >= 3.0, <= 3.2"
        self.assertTrue(product_version_affected(affected_range, "3.1"))
        self.assertFalse(product_version_affected(affected_range, "2.0"))
        self.assertFalse(product_version_affected(None, "1.0"))


if __name__ == "__main__":
    unittest.main()
