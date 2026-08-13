"""Tests for the Request Tracker (RT) REST 1.0 transport client (against a
fake HTTP transport) and the local rt_tickets cache table. The draft ->
review -> approve workflow that decides *when* create_ticket gets called
lives in modules.rt_drafts and is tested in tests/test_rt_drafts.py."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from modules.cache import VulnCache
from modules.rt import RTClient, RTError


class FakeResponse:
    def __init__(self, text: str):
        self.text = text

    def raise_for_status(self):
        pass


class FakeRTSession:
    """Stands in for requests.Session so RTClient tests never hit the
    network -- returns canned responses keyed by (method, url)."""

    def __init__(self, responses: dict):
        self.responses = responses
        self.calls: list[tuple] = []

    def post(self, url, data=None, timeout=None, **kwargs):
        self.calls.append(("post", url, data))
        return self.responses[("post", url)]

    def get(self, url, params=None, timeout=None, **kwargs):
        self.calls.append(("get", url, params))
        return self.responses[("get", url)]


LOGIN_OK = FakeResponse("RT/3.4.5 200 Ok\n\n")

SEARCH_RESPONSE = FakeResponse(
    "RT/3.4.5 200 Ok\n"
    "\n"
    "id: ticket/1\n"
    "Subject: CVE-2024-0001: Something bad\n"
    "Status: open\n"
    "Queue: General\n"
    "\n"
    "--\n"
    "\n"
    "id: ticket/2\n"
    "Subject: CVE-2024-0001 follow-up\n"
    "Status: resolved\n"
    "Queue: General\n"
)


def make_client(session):
    return RTClient(
        url="https://rt.test",
        username="user",
        password="pass",
        queue="General",
        timeout=5,
        max_retries=1,
        backoff_factor=1.0,
        session=session,
    )


class RTClientTests(unittest.TestCase):
    def test_login_happens_once(self):
        session = FakeRTSession({("post", "https://rt.test/REST/1.0/"): LOGIN_OK})
        client = make_client(session)
        client._ensure_login()
        client._ensure_login()
        self.assertEqual(len([c for c in session.calls if c[1] == "https://rt.test/REST/1.0/"]), 1)

    def test_create_ticket_parses_ticket_id(self):
        session = FakeRTSession(
            {
                ("post", "https://rt.test/REST/1.0/"): LOGIN_OK,
                ("post", "https://rt.test/REST/1.0/ticket/new"): FakeResponse(
                    "RT/3.4.5 200 Ok\n\n# Ticket 42 created.\n"
                ),
            }
        )
        client = make_client(session)
        ticket_id = client.create_ticket(
            subject="[CRITICAL][KEV] CVE-2024-0001 - Acme Widget",
            body="Vulnerability Intelligence Alert",
            priority="High",
            owner="analyst1",
        )
        self.assertEqual(ticket_id, 42)

        create_call = next(c for c in session.calls if c[1] == "https://rt.test/REST/1.0/ticket/new")
        content = create_call[2]["content"]
        self.assertIn("Queue: General", content)  # falls back to the client's default queue
        self.assertIn("CVE-2024-0001", content)
        self.assertIn("Priority: High", content)
        self.assertIn("Owner: analyst1", content)

    def test_create_ticket_uses_explicit_queue_over_default(self):
        session = FakeRTSession(
            {
                ("post", "https://rt.test/REST/1.0/"): LOGIN_OK,
                ("post", "https://rt.test/REST/1.0/ticket/new"): FakeResponse(
                    "RT/3.4.5 200 Ok\n\n# Ticket 1 created.\n"
                ),
            }
        )
        client = make_client(session)
        client.create_ticket(subject="Subject", body="Body", queue="Security")
        create_call = next(c for c in session.calls if c[1] == "https://rt.test/REST/1.0/ticket/new")
        self.assertIn("Queue: Security", create_call[2]["content"])

    def test_create_ticket_raises_on_unparseable_response(self):
        session = FakeRTSession(
            {
                ("post", "https://rt.test/REST/1.0/"): LOGIN_OK,
                ("post", "https://rt.test/REST/1.0/ticket/new"): FakeResponse("RT/3.4.5 400 Bad Request\n\n# Error\n"),
            }
        )
        client = make_client(session)
        with self.assertRaises(RTError):
            client.create_ticket(subject="Subject", body="Body")

    def test_search_tickets_parses_long_format_blocks(self):
        session = FakeRTSession(
            {
                ("post", "https://rt.test/REST/1.0/"): LOGIN_OK,
                ("get", "https://rt.test/REST/1.0/search/ticket"): SEARCH_RESPONSE,
            }
        )
        client = make_client(session)
        tickets = client.search_tickets_for_cve("CVE-2024-0001")
        self.assertEqual(len(tickets), 2)
        self.assertEqual(tickets[0]["id"], 1)
        self.assertEqual(tickets[0]["subject"], "CVE-2024-0001: Something bad")
        self.assertEqual(tickets[0]["status"], "open")
        self.assertEqual(tickets[0]["url"], "https://rt.test/Ticket/Display.html?id=1")
        self.assertEqual(tickets[1]["id"], 2)


class RTCacheTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.cache = VulnCache(str(Path(self._tmpdir.name) / "cache.db"))

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_has_rt_ticket_round_trip(self):
        self.assertFalse(self.cache.has_rt_ticket("CVE-2024-0001"))
        self.cache.record_rt_ticket("CVE-2024-0001", 42, source="draft_approved")
        self.assertTrue(self.cache.has_rt_ticket("CVE-2024-0001"))

    def test_get_rt_ticket_cve_ids_is_a_bulk_set(self):
        self.cache.record_rt_ticket("CVE-2024-0001", 1, source="draft_approved")
        self.cache.record_rt_ticket("CVE-2024-0002", 2, source="associated_existing")
        self.assertEqual(self.cache.get_rt_ticket_cve_ids(), {"CVE-2024-0001", "CVE-2024-0002"})

    def test_record_rt_ticket_ignores_duplicate_pair(self):
        self.cache.record_rt_ticket("CVE-2024-0001", 1, source="draft_approved")
        self.cache.record_rt_ticket("CVE-2024-0001", 1, source="draft_approved")  # should not raise


if __name__ == "__main__":
    unittest.main()
