"""Tests for the RT ticket draft workflow: content generation, the
create -> review -> approve/reject state machine, and the pipeline hook
that generates drafts (never real tickets) for Critical/KEV CVEs."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from config import Config
from modules.cache import VulnCache
from modules.models import EnrichedCVE
from modules.pipeline import Pipeline
from modules.rt_drafts import (
    RTDraftError,
    approve_draft,
    build_draft_body,
    build_draft_subject,
    create_draft_for_cve,
    reject_draft,
    update_draft,
)
from tests.test_rt import LOGIN_OK, FakeResponse, FakeRTSession, make_client

EMPTY_SEARCH = FakeResponse("RT/3.4.5 200 Ok\n\n")


def kev_cve(**overrides) -> EnrichedCVE:
    fields = dict(
        cve_id="CVE-2024-0001",
        risk_level="Critical",
        risk_score=95.0,
        kev_listed=True,
        vendor="Acme",
        product="Widget",
        description="A critical remote code execution flaw.",
        risk_recommendation="Patch Immediately",
        epss_score=0.9,
        cvss_v3_score=9.8,
        source_articles=["https://example.test/article"],
    )
    fields.update(overrides)
    return EnrichedCVE(**fields)


class DraftContentTests(unittest.TestCase):
    def test_subject_includes_severity_kev_and_product_tags(self):
        subject = build_draft_subject(kev_cve())
        self.assertEqual(subject, "[CRITICAL][KEV] CVE-2024-0001 - Acme Widget")

    def test_subject_omits_kev_tag_when_not_listed(self):
        subject = build_draft_subject(kev_cve(kev_listed=False, risk_level="High"))
        self.assertEqual(subject, "[HIGH] CVE-2024-0001 - Acme Widget")

    def test_body_does_not_invent_missing_fields(self):
        cve = kev_cve(description=None, risk_recommendation=None, kev_listed=False)
        body = build_draft_body(cve, affected_endpoint_count=None)
        self.assertNotIn("Affected endpoints", body)
        self.assertIn("No description available.", body)
        self.assertIn("Review and remediate according to your organization's vulnerability management policy.", body)
        self.assertNotIn("cisa.gov", body)

    def test_body_includes_affected_endpoint_count_when_known(self):
        body = build_draft_body(kev_cve(), affected_endpoint_count=12)
        self.assertIn("Affected endpoints detected by Action1:", body)
        self.assertIn("12", body)


class CreateDraftForCveTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.cache = VulnCache(str(Path(self._tmpdir.name) / "cache.db"))

    def tearDown(self):
        self._tmpdir.cleanup()

    def _client(self):
        session = FakeRTSession(
            {
                ("post", "https://rt.test/REST/1.0/"): LOGIN_OK,
                ("get", "https://rt.test/REST/1.0/search/ticket"): EMPTY_SEARCH,
            }
        )
        return make_client(session)

    def test_creates_pending_draft_and_never_calls_ticket_new(self):
        rt_client = self._client()
        draft_id = create_draft_for_cve(kev_cve(), self.cache, rt_client)
        self.assertIsNotNone(draft_id)

        draft = self.cache.get_rt_draft(draft_id)
        self.assertEqual(draft["status"], "Pending Approval")
        self.assertEqual(draft["trigger_reason"], "Critical+KEV")
        self.assertIsNone(draft["rt_ticket_id"])
        self.assertFalse(any(c[1].endswith("/ticket/new") for c in rt_client.session.calls))

        audit = self.cache.get_rt_draft_audit(draft_id)
        self.assertEqual(audit[0]["event"], "draft_created")
        self.assertEqual(audit[0]["actor"], "System")

    def test_skips_a_second_draft_for_the_same_cve(self):
        rt_client = self._client()
        first = create_draft_for_cve(kev_cve(), self.cache, rt_client)
        second = create_draft_for_cve(kev_cve(), self.cache, rt_client)
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        self.assertEqual(len(self.cache.get_all_rt_drafts()), 1)

    def test_non_qualifying_cve_produces_no_draft_unless_forced(self):
        rt_client = self._client()
        cve = kev_cve(kev_listed=False, risk_level="Medium")
        self.assertIsNone(create_draft_for_cve(cve, self.cache, rt_client))
        self.assertIsNotNone(create_draft_for_cve(cve, self.cache, rt_client, force=True))

    def test_associates_existing_ticket_found_via_search_instead_of_drafting(self):
        session = FakeRTSession(
            {
                ("post", "https://rt.test/REST/1.0/"): LOGIN_OK,
                ("get", "https://rt.test/REST/1.0/search/ticket"): FakeResponse(
                    "RT/3.4.5 200 Ok\n\nid: ticket/99\nSubject: Manually filed\nStatus: open\nQueue: General\n"
                ),
            }
        )
        rt_client = make_client(session)
        draft_id = create_draft_for_cve(kev_cve(), self.cache, rt_client)
        draft = self.cache.get_rt_draft(draft_id)
        self.assertEqual(draft["status"], "Created")
        self.assertEqual(draft["ticket_origin"], "associated_existing")
        self.assertEqual(draft["rt_ticket_id"], 99)
        self.assertTrue(self.cache.has_rt_ticket("CVE-2024-0001"))
        self.assertFalse(any(c[1].endswith("/ticket/new") for c in session.calls))


class ApproveRejectDraftTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.cache = VulnCache(str(Path(self._tmpdir.name) / "cache.db"))
        session = FakeRTSession(
            {
                ("post", "https://rt.test/REST/1.0/"): LOGIN_OK,
                ("get", "https://rt.test/REST/1.0/search/ticket"): EMPTY_SEARCH,
            }
        )
        self.rt_client = make_client(session)
        self.draft_id = create_draft_for_cve(kev_cve(), self.cache, self.rt_client)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_approve_creates_ticket_and_records_it(self):
        self.rt_client.session.responses[("post", "https://rt.test/REST/1.0/ticket/new")] = FakeResponse(
            "RT/3.4.5 200 Ok\n\n# Ticket 55 created.\n"
        )
        result = approve_draft(self.draft_id, self.cache, self.rt_client, actor="analyst1")
        self.assertEqual(result["ticket_id"], 55)

        draft = self.cache.get_rt_draft(self.draft_id)
        self.assertEqual(draft["status"], "Created")
        self.assertEqual(draft["rt_ticket_id"], 55)
        self.assertTrue(self.cache.has_rt_ticket("CVE-2024-0001"))

        events = [a["event"] for a in self.cache.get_rt_draft_audit(self.draft_id)]
        self.assertIn("draft_approved", events)
        self.assertIn("ticket_created", events)

    def test_approve_retry_adopts_ticket_found_via_safety_search_instead_of_duplicating(self):
        draft = self.cache.get_rt_draft(self.draft_id)
        # Simulate: a prior approval actually reached RT, but the response
        # was lost before we saw it. The safety search finds it by subject.
        self.rt_client.session.responses[("get", "https://rt.test/REST/1.0/search/ticket")] = FakeResponse(
            f"RT/3.4.5 200 Ok\n\nid: ticket/77\nSubject: {draft['proposed_subject']}\nStatus: open\nQueue: General\n"
        )
        result = approve_draft(self.draft_id, self.cache, self.rt_client, actor="analyst1")
        self.assertEqual(result["ticket_id"], 77)
        self.assertFalse(any(c[1].endswith("/ticket/new") for c in self.rt_client.session.calls))

    def test_approve_failure_marks_creation_failed_not_created(self):
        class BrokenSession(FakeRTSession):
            def post(self, url, data=None, timeout=None, **kwargs):
                if url.endswith("/ticket/new"):
                    raise RuntimeError("RT unreachable")
                return super().post(url, data=data, timeout=timeout, **kwargs)

        broken = BrokenSession(
            {
                ("post", "https://rt.test/REST/1.0/"): LOGIN_OK,
                ("get", "https://rt.test/REST/1.0/search/ticket"): EMPTY_SEARCH,
            }
        )
        self.rt_client.session = broken

        with self.assertRaises(RuntimeError):
            approve_draft(self.draft_id, self.cache, self.rt_client, actor="analyst1")

        draft = self.cache.get_rt_draft(self.draft_id)
        self.assertEqual(draft["status"], "Creation Failed")
        self.assertIsNotNone(draft["failure_reason"])
        self.assertFalse(self.cache.has_rt_ticket("CVE-2024-0001"))

    def test_reject_sets_rejected_and_blocks_future_approval(self):
        reject_draft(self.draft_id, self.cache, actor="analyst1", reason="Not applicable")
        draft = self.cache.get_rt_draft(self.draft_id)
        self.assertEqual(draft["status"], "Rejected")
        self.assertEqual(draft["rejection_reason"], "Not applicable")

        with self.assertRaises(RTDraftError):
            approve_draft(self.draft_id, self.cache, self.rt_client, actor="analyst1")
        self.assertFalse(any(c[1].endswith("/ticket/new") for c in self.rt_client.session.calls))

    def test_update_draft_edits_content_and_logs_audit(self):
        update_draft(self.draft_id, self.cache, actor="analyst1", proposed_subject="Edited subject")
        draft = self.cache.get_rt_draft(self.draft_id)
        self.assertEqual(draft["proposed_subject"], "Edited subject")
        events = [a["event"] for a in self.cache.get_rt_draft_audit(self.draft_id)]
        self.assertIn("draft_edited", events)


class PipelineDraftHookTests(unittest.TestCase):
    """Confirms the pipeline hook only ever creates a *draft*, never a real
    RT ticket -- the whole point of this workflow."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        cfg = Config(cache_folder=str(Path(self._tmpdir.name)))
        cfg.ensure_folders()
        self.pipeline = Pipeline(cfg)

        self.pipeline.nvd.enrich = lambda cve_id, cve: []
        self.pipeline.mitre.enrich = lambda cve_id, cve: None
        self.pipeline.epss.enrich = lambda cve_id, cve: None
        self.pipeline.action1 = None

        self.rt_session = FakeRTSession(
            {
                ("post", "https://rt.test/REST/1.0/"): LOGIN_OK,
                ("get", "https://rt.test/REST/1.0/search/ticket"): EMPTY_SEARCH,
            }
        )
        self.pipeline.rt = make_client(self.rt_session)

    def tearDown(self):
        self._tmpdir.cleanup()

    def _ticket_create_calls(self):
        return [c for c in self.rt_session.calls if c[1].endswith("/ticket/new")]

    def test_kev_cve_gets_a_draft_not_a_ticket(self):
        self.pipeline.kev.enrich = lambda cve_id, cve: setattr(cve, "kev_listed", True)
        self.pipeline._enrich_cve("CVE-2024-0001", [])
        self.assertEqual(len(self._ticket_create_calls()), 0)

        draft = self.pipeline.cache.get_rt_draft_for_cve("CVE-2024-0001")
        self.assertIsNotNone(draft)
        self.assertEqual(draft["status"], "Pending Approval")

    def test_reenrichment_does_not_create_a_second_draft(self):
        self.pipeline.kev.enrich = lambda cve_id, cve: setattr(cve, "kev_listed", True)
        self.pipeline._enrich_cve("CVE-2024-0001", [])
        self.pipeline._enrich_cve("CVE-2024-0001", [])
        self.assertEqual(len(self.pipeline.cache.get_all_rt_drafts()), 1)

    def test_non_kev_non_critical_cve_gets_no_draft(self):
        self.pipeline.kev.enrich = lambda cve_id, cve: setattr(cve, "kev_listed", False)
        self.pipeline._enrich_cve("CVE-2024-0002", [])
        self.assertIsNone(self.pipeline.cache.get_rt_draft_for_cve("CVE-2024-0002"))


if __name__ == "__main__":
    unittest.main()
