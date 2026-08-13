"""Tests for the Action1 integration: client auth/sync against a fake HTTP
transport (never the real network), and CVE exposure matching against the
locally cached inventory snapshot."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.action1 import Action1Client
from modules.cache import VulnCache
from modules.models import AffectedProduct, EnrichedCVE


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


class FakeAction1Session:
    """Stands in for requests.Session so Action1Client tests never hit the
    network -- returns canned responses keyed by (method, url)."""

    def __init__(self, responses: dict):
        self.responses = responses
        self.calls: list[tuple] = []

    def post(self, url, headers=None, timeout=None, json=None, **kwargs):
        self.calls.append(("post", url))
        return self.responses[("post", url)]

    def get(self, url, headers=None, timeout=None, params=None, **kwargs):
        self.calls.append(("get", url))
        return self.responses[("get", url)]


def make_client(session):
    return Action1Client(
        client_id="test-id",
        client_secret="test-secret",
        org_id="org-1",
        base_url="https://app.action1.test/api/3.0",
        timeout=5,
        max_retries=1,
        backoff_factor=1.0,
        session=session,
    )


@patch("modules.action1.time.sleep", new=lambda *_: None)
class Action1ClientTests(unittest.TestCase):
    def test_token_is_fetched_once_and_cached(self):
        session = FakeAction1Session(
            {("post", "https://app.action1.test/api/3.0/oauth2/token"): FakeResponse({"access_token": "tok", "expires_in": 3600})}
        )
        client = make_client(session)
        self.assertEqual(client._get_token(), "tok")
        self.assertEqual(client._get_token(), "tok")
        self.assertEqual(len([c for c in session.calls if c[0] == "post"]), 1)

    def test_get_managed_endpoints_follows_next_page_url_as_is(self):
        """Action1's next_page is a full URL with its own query string --
        it must be requested directly, not re-wrapped as a `next_page=`
        parameter on the original endpoint URL (that bug caused a 403 from
        an ever-growing, doubly-encoded URL against a real tenant)."""
        base = "https://app.action1.test/api/3.0"
        page2_url = f"{base}/endpoints/managed/org-1?fields=%2A&from=1&limit=1"
        session = FakeAction1Session(
            {
                ("post", f"{base}/oauth2/token"): FakeResponse({"access_token": "tok", "expires_in": 3600}),
                ("get", f"{base}/endpoints/managed/org-1"): FakeResponse(
                    {"data": [{"id": 1, "name": "host-a"}], "next_page": page2_url}
                ),
                ("get", page2_url): FakeResponse({"data": [{"id": 2, "name": "host-b"}], "next_page": None}),
            }
        )
        client = make_client(session)
        endpoints = client.get_managed_endpoints()
        self.assertEqual([e["name"] for e in endpoints], ["host-a", "host-b"])
        # The second call must hit page2_url verbatim -- no extra params merged in.
        second_get = [c for c in session.calls if c[0] == "get"][1]
        self.assertEqual(second_get[1], page2_url)

    def test_resolves_root_relative_next_page_against_the_api_origin(self):
        """Action1's own docs show next_page as a root-relative path (e.g.
        '/API/...?limit=60&from=10') even though we've observed absolute
        URLs in practice -- handle both so a documented-but-unobserved
        format doesn't break pagination."""
        base = "https://app.action1.test/api/3.0"
        session = FakeAction1Session(
            {
                ("post", f"{base}/oauth2/token"): FakeResponse({"access_token": "tok", "expires_in": 3600}),
                ("get", f"{base}/endpoints/managed/org-1"): FakeResponse(
                    {"items": [{"id": 1, "name": "host-a"}], "next_page": "/api/3.0/endpoints/managed/org-1?from=1"}
                ),
                ("get", f"{base}/endpoints/managed/org-1?from=1"): FakeResponse(
                    {"items": [{"id": 2, "name": "host-b"}], "next_page": None}
                ),
            }
        )
        client = make_client(session)
        endpoints = client.get_managed_endpoints()
        self.assertEqual([e["name"] for e in endpoints], ["host-a", "host-b"])

    def test_fetch_installed_software_reads_report_style_fields(self):
        """Installed-software rows are Action1's generic report format:
        real data lives under each row's `fields` dict (Name/Vendor/Version),
        not as top-level keys -- and the path needs both org_id and
        endpoint_id, confirmed against a real tenant's Swagger reference."""
        base = "https://app.action1.test/api/3.0"
        session = FakeAction1Session(
            {
                ("post", f"{base}/oauth2/token"): FakeResponse({"access_token": "tok", "expires_in": 3600}),
                ("get", f"{base}/installed-software/org-1/data/1"): FakeResponse(
                    {
                        "items": [
                            {"fields": {"Name": "Widget", "Vendor": "Acme", "Version": "1.0"}},
                            {"fields": {"Name": "", "Vendor": "Acme", "Version": "2.0"}},  # no name -> skipped
                        ]
                    }
                ),
            }
        )
        client = make_client(session)
        software = client._fetch_installed_software("1")
        self.assertEqual(software, [{"name": "Widget", "vendor": "Acme", "version": "1.0"}])

    def test_sync_inventory_populates_cache(self):
        base = "https://app.action1.test/api/3.0"
        session = FakeAction1Session(
            {
                ("post", f"{base}/oauth2/token"): FakeResponse({"access_token": "tok", "expires_in": 3600}),
                ("get", f"{base}/endpoints/managed/org-1"): FakeResponse(
                    {"items": [{"id": 1, "name": "host-a", "os_name": "Windows"}], "next_page": None}
                ),
                ("get", f"{base}/installed-software/org-1/data/1"): FakeResponse(
                    {"items": [{"fields": {"Name": "Widget", "Vendor": "Acme", "Version": "1.0"}}]}
                ),
            }
        )
        client = make_client(session)
        with tempfile.TemporaryDirectory() as directory:
            cache = VulnCache(str(Path(directory) / "cache.db"))
            result = client.sync_inventory(cache)
            self.assertEqual(result, {"endpoints": 1, "software_rows": 1, "cves_matched": 0})

            software = cache.get_action1_software()
            self.assertEqual(len(software), 1)
            self.assertEqual(software[0]["product"], "Widget")
            self.assertEqual(software[0]["hostname"], "host-a")

            status = cache.get_action1_sync_status()
            self.assertEqual(status["endpoint_count"], 1)
            self.assertEqual(status["software_count"], 1)

    def test_sync_inventory_rematches_cves_that_predate_the_sync(self):
        """The bug this guards against: a CVE enriched before Action1 was
        ever configured/synced only ever gets matched against inventory
        during its own (re-)enrichment -- which, for most CVEs, may never
        happen again. A sync must proactively re-check every already-known
        CVE, not just ones enriched after the fact."""
        base = "https://app.action1.test/api/3.0"
        session = FakeAction1Session(
            {
                ("post", f"{base}/oauth2/token"): FakeResponse({"access_token": "tok", "expires_in": 3600}),
                ("get", f"{base}/endpoints/managed/org-1"): FakeResponse(
                    {"items": [{"id": 1, "name": "host-a"}], "next_page": None}
                ),
                ("get", f"{base}/installed-software/org-1/data/1"): FakeResponse(
                    {"items": [{"fields": {"Name": "Widget", "Vendor": "Acme", "Version": "1.0"}}]}
                ),
            }
        )
        client = make_client(session)
        with tempfile.TemporaryDirectory() as directory:
            cache = VulnCache(str(Path(directory) / "cache.db"))
            pre_existing_cve = EnrichedCVE(
                cve_id="CVE-2024-0001",
                affected_products=[AffectedProduct(vendor="Acme", product="Widget", affected_range="< 2.0")],
            )
            cache.save_cve(pre_existing_cve)
            self.assertEqual(cache.get_all_action1_exposures(), [])  # nothing matched yet

            result = client.sync_inventory(cache)
            self.assertEqual(result["cves_matched"], 1)

            exposures = cache.get_all_action1_exposures()
            self.assertEqual(len(exposures), 1)
            self.assertEqual(exposures[0]["cve_id"], "CVE-2024-0001")
            self.assertEqual(exposures[0]["version_status"], "vulnerable")

    def test_zero_endpoints_refuses_to_overwrite_existing_inventory(self):
        """A real org that previously synced 156 endpoints does not
        suddenly have zero -- a sync that comes back empty must raise
        instead of silently wiping the last known-good snapshot (this
        happened for real: a transient empty response destroyed a good
        156-endpoint / 6448-row inventory with no error surfaced)."""
        base = "https://app.action1.test/api/3.0"
        good_session = FakeAction1Session(
            {
                ("post", f"{base}/oauth2/token"): FakeResponse({"access_token": "tok", "expires_in": 3600}),
                ("get", f"{base}/endpoints/managed/org-1"): FakeResponse(
                    {"items": [{"id": 1, "name": "host-a", "os_name": "Windows"}], "next_page": None}
                ),
                ("get", f"{base}/installed-software/org-1/data/1"): FakeResponse(
                    {"items": [{"fields": {"Name": "Widget", "Vendor": "Acme", "Version": "1.0"}}]}
                ),
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            cache = VulnCache(str(Path(directory) / "cache.db"))
            make_client(good_session).sync_inventory(cache)
            self.assertEqual(cache.get_action1_sync_status()["endpoint_count"], 1)

            empty_session = FakeAction1Session(
                {
                    ("post", f"{base}/oauth2/token"): FakeResponse({"access_token": "tok", "expires_in": 3600}),
                    ("get", f"{base}/endpoints/managed/org-1"): FakeResponse({"items": [], "next_page": None}),
                }
            )
            with self.assertRaises(RuntimeError):
                make_client(empty_session).sync_inventory(cache)

            # The previous good inventory must still be intact.
            status = cache.get_action1_sync_status()
            self.assertEqual(status["endpoint_count"], 1)
            self.assertEqual(status["software_count"], 1)


class Action1ExposureMatchingTests(unittest.TestCase):
    """match_exposure only reads the locally cached inventory (no network),
    so these tests don't need a fake session."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.cache = VulnCache(str(Path(self._tmpdir.name) / "cache.db"))
        self.client = make_client(session=FakeAction1Session({}))

    def tearDown(self):
        self._tmpdir.cleanup()

    def _seed_inventory(self, version: str) -> None:
        self.cache.replace_action1_inventory(
            endpoints=[{"id": "ep-1", "hostname": "host-a", "os": "Windows", "org_id": "org-1", "raw_json": None}],
            software=[{"endpoint_id": "ep-1", "vendor": "Acme", "product": "Widget", "version": version}],
        )

    @staticmethod
    def _make_cve() -> EnrichedCVE:
        return EnrichedCVE(
            cve_id="CVE-2024-0001",
            affected_products=[AffectedProduct(vendor="Acme", product="Widget", affected_range="< 2.0")],
        )

    def test_vulnerable_version_produces_exposure_row(self):
        self._seed_inventory(version="1.0")
        self.client.match_exposure(self._make_cve(), self.cache)
        exposures = self.cache.get_all_action1_exposures()
        self.assertEqual(len(exposures), 1)
        self.assertEqual(exposures[0]["version_status"], "vulnerable")
        self.assertEqual(exposures[0]["hostname"], "host-a")

    def test_not_affected_version_produces_no_exposure_row(self):
        self._seed_inventory(version="3.0")
        self.client.match_exposure(self._make_cve(), self.cache)
        self.assertEqual(self.cache.get_all_action1_exposures(), [])

    def test_rematching_replaces_prior_exposure_rows(self):
        self._seed_inventory(version="1.0")
        self.client.match_exposure(self._make_cve(), self.cache)
        self._seed_inventory(version="3.0")
        self.client.match_exposure(self._make_cve(), self.cache)
        self.assertEqual(self.cache.get_all_action1_exposures(), [])


if __name__ == "__main__":
    unittest.main()
