"""Request Tracker (RT) REST 1.0 transport client: session-cookie auth,
ticket creation, and ticket search.

This module is a pure transport layer -- it has no opinion about *when* a
ticket should be created. `create_ticket` must only ever be called from
`modules.rt_drafts.approve_draft`, after an analyst has explicitly approved
a draft; nothing in the CVE enrichment pipeline calls it directly.

RT's REST 1.0 API is a simple text protocol, stable since RT 3.4 (~2005):
POST user/pass to the REST root for a session cookie, then GET/POST plain
'Key: value' blocks. Every response starts with a header line like
'RT/3.4.5 200 Ok', a blank line, then the body.
"""
from __future__ import annotations

import logging
import re
import time

import requests

logger = logging.getLogger("vuln_intel.rt")

_TICKET_CREATED_RE = re.compile(r"Ticket (\d+) created")
_STATUS_LINE_RE = re.compile(r"^RT/\S+\s+(\d+)\s")


class RTError(RuntimeError):
    """Raised when RT rejects a request or returns something we can't parse."""


class RTClient:
    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        queue: str,
        timeout: int,
        max_retries: int,
        backoff_factor: float,
        session: requests.Session | None = None,
    ):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.queue = queue
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.session = session or requests.Session()
        self._logged_in = False

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------
    def _ensure_login(self) -> None:
        """RT REST 1.0 sessions are cookie-based -- log in once per client
        instance and let the session's cookie jar carry it on every
        subsequent request."""
        if self._logged_in:
            return
        text = self._request("post", f"{self.url}/REST/1.0/", data={"user": self.username, "pass": self.password})
        if self._status_code(text) != 200:
            raise RTError(f"RT login failed: {text.splitlines()[0] if text else 'no response'}")
        self._logged_in = True

    # ------------------------------------------------------------------
    # HTTP plumbing shared by every call: retry/backoff
    # ------------------------------------------------------------------
    def _request(self, method: str, url: str, **kwargs) -> str:
        last_exc: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = getattr(self.session, method)(url, timeout=self.timeout, **kwargs)
                resp.raise_for_status()
                return resp.text
            except requests.exceptions.RequestException as exc:
                last_exc = exc
                logger.error(
                    "RT %s %s failed (attempt %d/%d): %s", method.upper(), url, attempt, self.max_retries, exc
                )
                if attempt < self.max_retries:
                    time.sleep(self.backoff_factor**attempt)
        raise last_exc

    @staticmethod
    def _status_code(text: str) -> int | None:
        if not text:
            return None
        match = _STATUS_LINE_RE.match(text.splitlines()[0])
        return int(match.group(1)) if match else None

    @staticmethod
    def _strip_header(text: str) -> str:
        """Drop the 'RT/x.y.z NNN ...' status line and the blank line that
        follows it, leaving just the body."""
        lines = text.splitlines()
        if lines and _STATUS_LINE_RE.match(lines[0]):
            lines = lines[1:]
        while lines and not lines[0].strip():
            lines = lines[1:]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Ticket creation
    # ------------------------------------------------------------------
    def create_ticket(
        self,
        subject: str,
        body: str,
        queue: str | None = None,
        priority: str | None = None,
        owner: str | None = None,
    ) -> int:
        """Creates a real RT ticket from already-finalized content. This is
        the only method in the codebase that is allowed to call RT's
        ticket/new endpoint -- callers must never invoke this without
        explicit analyst approval (see modules.rt_drafts.approve_draft)."""
        self._ensure_login()

        lines = ["id: ticket/new", f"Queue: {queue or self.queue}", f"Subject: {subject}"]
        if priority:
            lines.append(f"Priority: {priority}")
        if owner:
            lines.append(f"Owner: {owner}")
        # RT REST 1.0 multi-line field values need each continuation line
        # indented, or the parser reads them as new fields.
        lines.append("Text: " + body.replace("\n", "\n "))
        content = "\n".join(lines)

        text = self._request("post", f"{self.url}/REST/1.0/ticket/new", data={"content": content})
        match = _TICKET_CREATED_RE.search(text)
        if not match:
            raise RTError(f"Could not parse ticket id from RT response: {self._strip_header(text)[:200]!r}")
        ticket_id = int(match.group(1))
        logger.info("Created RT ticket #%d", ticket_id)
        return ticket_id

    # ------------------------------------------------------------------
    # Ticket search
    # ------------------------------------------------------------------
    def search_tickets_for_cve(self, cve_id: str) -> list[dict]:
        self._ensure_login()
        params = {"query": f"Subject LIKE '{cve_id}'", "format": "l", "fields": "id,Subject,Status,Queue"}
        text = self._request("get", f"{self.url}/REST/1.0/search/ticket", params=params)
        return self._parse_ticket_blocks(text)

    def _parse_ticket_blocks(self, text: str) -> list[dict]:
        body = self._strip_header(text)
        tickets = []
        for block in re.split(r"^--\s*$", body, flags=re.MULTILINE):
            fields = self._parse_kv_block(block)
            raw_id = fields.get("id")  # e.g. "ticket/123"
            if not raw_id:
                continue
            ticket_id = raw_id.rsplit("/", 1)[-1]
            if not ticket_id.isdigit():
                continue
            tickets.append(
                {
                    "id": int(ticket_id),
                    "subject": fields.get("subject"),
                    "status": fields.get("status"),
                    "queue": fields.get("queue"),
                    "url": f"{self.url}/Ticket/Display.html?id={ticket_id}",
                }
            )
        return tickets

    @staticmethod
    def _parse_kv_block(block: str) -> dict:
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            fields[key.strip().lower()] = value.strip()
        return fields
