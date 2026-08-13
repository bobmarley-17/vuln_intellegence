"""Action1 RMM API client: syncs the org's managed-endpoint software
inventory and matches it against enriched CVEs so the dashboard can show
which real assets are affected.

Action1 uses OAuth2-style client-credential auth (exchange a client
id/secret for a bearer JWT) against a REST API under /api/3.0. Endpoint
listing and installed-software paths are confirmed against a real tenant's
Swagger reference. Installed-software rows require the API client's role to
have the `view_installed_software` permission -- without it every call to
SOFTWARE_PATH returns 403, independent of whether the path is correct.

Both endpoints return Action1's generic paginated "ResultPage" envelope
(`items`, `next_page`) -- `next_page` is a complete next-page reference
(observed as an absolute URL in practice; Action1's own docs show a
root-relative path) to fetch as-is, never a token to re-wrap as a new query
parameter. `_get_paginated` is the one place that walks it.
"""
from __future__ import annotations

import logging
import time
from urllib.parse import urlparse

import requests

from modules.cache import VulnCache
from modules.models import EnrichedCVE
from modules.normalizer import match_cve_to_product

logger = logging.getLogger("vuln_intel.action1")

TOKEN_PATH = "/oauth2/token"  # unverified -- console/Swagger access hasn't confirmed this one yet
ENDPOINTS_PATH = "/endpoints/managed/{org_id}"
SOFTWARE_PATH = "/installed-software/{org_id}/data/{endpoint_id}"

_MIN_REQUEST_INTERVAL_SECONDS = 2.0  # keep comfortably under Action1's ~30 req/min cap


class Action1Client:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        org_id: str,
        base_url: str,
        timeout: int,
        max_retries: int,
        backoff_factor: float,
        session: requests.Session | None = None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.org_id = org_id
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.session = session or requests.Session()
        self._token: str | None = None
        self._token_expires_at: float = 0.0
        self._last_request_at: float = 0.0

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------
    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expires_at:
            return self._token
        resp = self._request(
            "post",
            f"{self.base_url}{TOKEN_PATH}",
            authenticated=False,
            json={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )
        data = resp.json()
        self._token = data["access_token"]
        # Refresh a minute early so a near-expiry token is never used mid-request.
        self._token_expires_at = time.time() + max(int(data.get("expires_in", 3600)) - 60, 60)
        return self._token

    # ------------------------------------------------------------------
    # HTTP plumbing shared by every call: bearer auth, rate limiting, retry/backoff
    # ------------------------------------------------------------------
    def _request(self, method: str, url: str, authenticated: bool = True, **kwargs) -> requests.Response:
        headers = kwargs.pop("headers", {})
        if authenticated:
            headers["Authorization"] = f"Bearer {self._get_token()}"

        last_exc: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            self._throttle()
            try:
                resp = getattr(self.session, method)(url, headers=headers, timeout=self.timeout, **kwargs)
                resp.raise_for_status()
                return resp
            except requests.exceptions.RequestException as exc:
                last_exc = exc
                logger.error(
                    "Action1 %s %s failed (attempt %d/%d): %s", method.upper(), url, attempt, self.max_retries, exc
                )
                if attempt < self.max_retries:
                    time.sleep(self.backoff_factor**attempt)
        raise last_exc

    def _throttle(self) -> None:
        elapsed = time.time() - self._last_request_at
        if elapsed < _MIN_REQUEST_INTERVAL_SECONDS:
            time.sleep(_MIN_REQUEST_INTERVAL_SECONDS - elapsed)
        self._last_request_at = time.time()

    # ------------------------------------------------------------------
    # Pagination (shared by every "ResultPage"-shaped endpoint)
    # ------------------------------------------------------------------
    def _get_paginated(self, url: str, params: dict | None = None) -> list[dict]:
        results: list[dict] = []
        next_url: str | None = url
        while next_url:
            resp = self._request("get", next_url, params=params)
            data = resp.json()
            results.extend(data.get("items") or data.get("data") or [])
            next_page = data.get("next_page")
            next_url = self._resolve_next_page(next_page) if next_page else None
            params = None  # next_page already carries its own complete query string
        return results

    def _resolve_next_page(self, next_page: str) -> str:
        if next_page.startswith("http://") or next_page.startswith("https://"):
            return next_page
        origin = urlparse(self.base_url)
        return f"{origin.scheme}://{origin.netloc}{next_page}"

    # ------------------------------------------------------------------
    # Inventory sync
    # ------------------------------------------------------------------
    def get_managed_endpoints(self) -> list[dict]:
        """All endpoints in the org."""
        url = f"{self.base_url}{ENDPOINTS_PATH.format(org_id=self.org_id)}"
        return self._get_paginated(url, params={"fields": "*"})

    def _fetch_installed_software(self, endpoint_id: str) -> list[dict]:
        """Installed software for one endpoint. Requires the API client's
        role to have the `view_installed_software` permission, or every
        call here 403s regardless of the path being correct. Rows come back
        as Action1's generic report format -- the actual name/vendor/version
        live under each row's `fields` dict, not as top-level keys."""
        url = f"{self.base_url}{SOFTWARE_PATH.format(org_id=self.org_id, endpoint_id=endpoint_id)}"
        rows = self._get_paginated(url)
        software = []
        for row in rows:
            fields = row.get("fields") or {}
            name = fields.get("Name")
            if not name:
                continue
            software.append({"name": name, "vendor": fields.get("Vendor"), "version": fields.get("Version")})
        return software

    def sync_inventory(self, cache: VulnCache) -> dict:
        """Pull the org's managed endpoints and their installed software from
        Action1, overwrite the locally cached snapshot, and immediately
        re-match every already-known CVE against it. The pipeline only calls
        match_exposure() while freshly enriching a CVE (see
        Pipeline._enrich_cve), which by itself would leave every CVE that
        existed *before* this sync unmatched indefinitely -- most cached
        CVEs are never touched again unless they resurface in a newly
        scanned article, so a sync would otherwise silently produce zero
        exposure rows despite a populated inventory."""
        raw_endpoints = self.get_managed_endpoints()
        if not raw_endpoints:
            # A real org with a previously-synced fleet does not suddenly
            # have zero endpoints -- this is almost certainly a transient
            # failure (auth hiccup, rate limit, empty page). Refuse to let
            # it silently wipe the last known-good inventory snapshot.
            raise RuntimeError(
                "Action1 returned zero managed endpoints; refusing to overwrite the existing "
                "inventory snapshot. Retry the sync -- if this keeps happening, check the API "
                "client's credentials/permissions rather than assuming the org is actually empty."
            )
        endpoints = [
            {
                "id": str(ep["id"]),
                "hostname": ep.get("name") or ep.get("hostname"),
                "os": ep.get("os_name") or ep.get("os"),
                "org_id": self.org_id,
                "raw_json": None,
            }
            for ep in raw_endpoints
            if ep.get("id")
        ]

        software: list[dict] = []
        for ep in endpoints:
            for item in self._fetch_installed_software(ep["id"]):
                software.append(
                    {
                        "endpoint_id": ep["id"],
                        "vendor": item.get("vendor"),
                        "product": item["name"],
                        "version": item.get("version"),
                    }
                )

        cache.replace_action1_inventory(endpoints, software)

        all_cves = cache.get_all_cves()
        for cve in all_cves:
            self.match_exposure(cve, cache)

        logger.info(
            "Action1 sync complete: %d endpoints, %d software rows, %d CVEs re-matched",
            len(endpoints), len(software), len(all_cves),
        )
        return {"endpoints": len(endpoints), "software_rows": len(software), "cves_matched": len(all_cves)}

    # ------------------------------------------------------------------
    # Exposure matching (reads the local cache only -- no Action1 API calls)
    # ------------------------------------------------------------------
    def match_exposure(self, cve: EnrichedCVE, cache: VulnCache) -> None:
        """Check the cached Action1 software inventory against `cve` and
        store the result. Called automatically for every freshly-enriched
        CVE, so exposure is always current as of the last inventory sync
        without hitting Action1's API per CVE. Keeps 'vulnerable' rows
        (version confirmed in the affected range) and 'unknown' rows (the
        product matches but there's no version data to compare) since both
        represent assets worth a human look; drops confirmed 'not_affected'
        matches."""
        matches = []
        for row in cache.get_action1_software():
            if not row.get("product"):
                continue
            result = match_cve_to_product(cve, row.get("vendor") or "", row["product"], row.get("version"))
            if result is None or result["version_status"] == "not_affected":
                continue
            matches.append(
                {
                    "endpoint_id": row["endpoint_id"],
                    "hostname": row.get("hostname"),
                    "vendor": result["matched_vendor"],
                    "product": result["matched_product"],
                    "installed_version": row.get("version"),
                    "affected_range": result["affected_range"],
                    "fixed_version": result["fixed_version"],
                    "version_status": result["version_status"],
                }
            )
        cache.replace_action1_exposures(cve.cve_id, matches)
