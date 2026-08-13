"""Action1 RMM API client: syncs the org's managed-endpoint software
inventory and matches it against enriched CVEs so the dashboard can show
which real assets are affected.

Action1 uses OAuth2-style client-credential auth (exchange a client
id/secret for a bearer JWT) against a REST API under /api/3.0. Only the
managed-endpoints listing is confirmed from Action1's public docs
(GET /endpoints/managed/{org_id}); the token exchange path and the
per-endpoint installed-software path are not publicly documented -- their
interactive Swagger UI is behind console login. Both are isolated below
(TOKEN_PATH, _fetch_installed_software) so they're a one-place fix once
real credentials and console access are available to confirm them.
"""
from __future__ import annotations

import logging
import time

import requests

from modules.cache import VulnCache
from modules.models import EnrichedCVE
from modules.normalizer import match_cve_to_product

logger = logging.getLogger("vuln_intel.action1")

TOKEN_PATH = "/oauth2/token"  # unverified, see module docstring
ENDPOINTS_PATH = "/endpoints/managed/{org_id}"
SOFTWARE_PATH = "/endpoints/{endpoint_id}/software"  # unverified, see module docstring

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
    # Inventory sync
    # ------------------------------------------------------------------
    def get_managed_endpoints(self) -> list[dict]:
        """All endpoints in the org, following Action1's next_page cursor."""
        endpoints: list[dict] = []
        path = ENDPOINTS_PATH.format(org_id=self.org_id)
        params: dict | None = {"fields": "*"}
        next_page: str | None = None
        while True:
            url = f"{self.base_url}{path}"
            request_params = params if next_page is None else {"next_page": next_page}
            resp = self._request("get", url, params=request_params)
            data = resp.json()
            endpoints.extend(data.get("data") or data.get("items") or [])
            next_page = data.get("next_page")
            if not next_page:
                break
        return endpoints

    def _fetch_installed_software(self, endpoint_id: str) -> list[dict]:
        """Installed software for one endpoint. UNVERIFIED against Action1's
        real API -- confirm this path/shape once console/Swagger access is
        available (see module docstring)."""
        url = f"{self.base_url}{SOFTWARE_PATH.format(endpoint_id=endpoint_id)}"
        resp = self._request("get", url)
        data = resp.json()
        return data.get("data") or data.get("items") or []

    def sync_inventory(self, cache: VulnCache) -> dict:
        """Pull the org's managed endpoints and their installed software from
        Action1 and overwrite the locally cached snapshot that new CVEs are
        automatically matched against during enrichment."""
        raw_endpoints = self.get_managed_endpoints()
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
                if not item.get("name"):
                    continue
                software.append(
                    {
                        "endpoint_id": ep["id"],
                        "vendor": item.get("vendor") or item.get("publisher"),
                        "product": item["name"],
                        "version": item.get("version"),
                    }
                )

        cache.replace_action1_inventory(endpoints, software)
        logger.info("Action1 sync complete: %d endpoints, %d software rows", len(endpoints), len(software))
        return {"endpoints": len(endpoints), "software_rows": len(software)}

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
