"""Request Tracker draft workflow: turns a qualifying CVE into a local,
editable ticket draft instead of ever calling RT directly. A real RT ticket
is only ever created by `approve_draft`, after an analyst has reviewed and
explicitly approved the draft -- nothing else in this codebase is allowed
to call `RTClient.create_ticket`.
"""
from __future__ import annotations

from modules.cache import VulnCache
from modules.models import EnrichedCVE
from modules.rt import RTClient

_APPROVABLE_STATUSES = {"Pending Approval", "Creation Failed"}
_EDITABLE_FIELDS = {"proposed_subject", "proposed_body", "proposed_queue", "proposed_priority", "proposed_owner"}


class RTDraftError(RuntimeError):
    """Raised for invalid draft-workflow transitions (not RT/network errors,
    which propagate as-is so callers can distinguish 'bad request' from
    'RT is unreachable')."""


def _trigger_reason(cve: EnrichedCVE) -> str | None:
    reasons = []
    if cve.risk_level == "Critical":
        reasons.append("Critical")
    if cve.kev_listed:
        reasons.append("KEV")
    return "+".join(reasons) if reasons else None


def build_draft_subject(cve: EnrichedCVE) -> str:
    tags = "".join(f"[{tag.upper()}]" for tag in filter(None, [cve.risk_level, "KEV" if cve.kev_listed else None]))
    label = " ".join(filter(None, [cve.vendor, cve.product])) or "Unknown Product"
    return f"{tags} {cve.cve_id} - {label}".strip()


def build_draft_body(cve: EnrichedCVE, affected_endpoint_count: int | None) -> str:
    cvss = cve.cvss_v4_score if cve.cvss_v4_score is not None else cve.cvss_v3_score
    lines = [
        "Vulnerability Intelligence Alert",
        "",
        f"CVE: {cve.cve_id}",
        f"Severity: {cve.risk_level or 'Unknown'}",
        f"CVSS: {cvss if cvss is not None else 'N/A'}",
        f"EPSS: {cve.epss_score if cve.epss_score is not None else 'N/A'}",
        f"KEV: {'Yes' if cve.kev_listed else 'No'}",
        f"Vendor: {cve.vendor or 'Unknown'}",
        f"Product: {cve.product or 'Unknown'}",
        "",
        "Description:",
        cve.description or cve.summary or "No description available.",
        "",
    ]
    if affected_endpoint_count is not None:
        lines += ["Affected endpoints detected by Action1:", str(affected_endpoint_count), ""]
    lines += [
        "Risk:",
        cve.risk_recommendation or "Review and remediate according to your organization's vulnerability management policy.",
        "",
        "Sources:",
    ]
    sources = list(cve.source_articles or [])
    sources.append(f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}")
    if cve.kev_listed:
        sources.append("https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
    lines += sources
    lines += ["", "This ticket was drafted by Vuln Intel and requires analyst approval before creation."]
    return "\n".join(lines)


def _count_affected_endpoints(cve_id: str, cache: VulnCache) -> int | None:
    """None when there's no Action1 exposure data at all for this CVE (either
    Action1 isn't configured, or nothing matched) -- omitted from the draft
    body rather than claiming a count we don't actually have."""
    endpoint_ids = {e["endpoint_id"] for e in cache.get_all_action1_exposures() if e["cve_id"] == cve_id}
    return len(endpoint_ids) if endpoint_ids else None


def create_draft_for_cve(cve: EnrichedCVE, cache: VulnCache, rt_client: RTClient, force: bool = False) -> int | None:
    """Generates a draft for `cve` if it doesn't already have one. Returns
    the new draft id, or None if a draft already exists or (when `force` is
    False) the CVE doesn't meet the KEV/Critical trigger. `force=True` is
    for the analyst-initiated 'Create Ticket Draft' action, which bypasses
    the trigger check but still respects the one-draft-per-CVE guard."""
    if cache.get_rt_draft_for_cve(cve.cve_id) is not None:
        return None

    reason = _trigger_reason(cve)
    if reason is None and not force:
        return None

    affected_endpoint_count = _count_affected_endpoints(cve.cve_id, cache)
    subject = build_draft_subject(cve)
    body = build_draft_body(cve, affected_endpoint_count)

    common = dict(
        cve_id=cve.cve_id,
        trigger_reason=reason,
        severity=cve.risk_level,
        cvss_score=cve.cvss_v4_score if cve.cvss_v4_score is not None else cve.cvss_v3_score,
        epss_score=cve.epss_score,
        kev_listed=cve.kev_listed,
        vendor=cve.vendor,
        product=cve.product,
        affected_endpoint_count=affected_endpoint_count,
        description=cve.description,
        recommendation=cve.risk_recommendation,
        source_articles=list(cve.source_articles or []),
        proposed_queue=rt_client.queue,
        proposed_priority=None,
        proposed_owner=None,
        proposed_subject=subject,
        proposed_body=body,
    )

    # Someone may have already filed a ticket for this CVE directly in RT --
    # associate it instead of drafting a duplicate for approval.
    existing_tickets = rt_client.search_tickets_for_cve(cve.cve_id)
    if existing_tickets:
        ticket = existing_tickets[0]
        draft_id = cache.create_rt_draft(status="Created", ticket_origin="associated_existing", rt_ticket_id=ticket["id"], **common)
        cache.record_rt_ticket(cve.cve_id, ticket["id"], source="associated_existing")
        cache.record_rt_draft_audit(
            draft_id, "draft_created", "System", detail=f"Associated existing RT ticket #{ticket['id']} found via search."
        )
        return draft_id

    draft_id = cache.create_rt_draft(status="Pending Approval", ticket_origin=None, **common)
    cache.record_rt_draft_audit(draft_id, "draft_created", "System", detail=f"Triggered by: {reason or 'manual request'}")
    return draft_id


def update_draft(draft_id: int, cache: VulnCache, actor: str, **fields) -> None:
    editable = {k: v for k, v in fields.items() if k in _EDITABLE_FIELDS and v is not None}
    if not editable:
        return
    cache.update_rt_draft(draft_id, **editable)
    cache.record_rt_draft_audit(draft_id, "draft_edited", actor)


def approve_draft(draft_id: int, cache: VulnCache, rt_client: RTClient, actor: str) -> dict:
    draft = cache.get_rt_draft(draft_id)
    if draft is None:
        raise RTDraftError(f"No such draft: {draft_id}")
    if draft["status"] not in _APPROVABLE_STATUSES:
        raise RTDraftError(f"Draft {draft_id} is '{draft['status']}' and cannot be approved.")

    # Retry-safety: if a prior approval actually reached RT but the response
    # was lost (e.g. a timeout on our end after RT already created the
    # ticket), adopt that ticket instead of creating a second one.
    try:
        existing = rt_client.search_tickets_for_cve(draft["cve_id"])
    except Exception:
        existing = []
    match = next((t for t in existing if t.get("subject") == draft["proposed_subject"]), None)

    if match:
        ticket_id = match["id"]
    else:
        try:
            ticket_id = rt_client.create_ticket(
                subject=draft["proposed_subject"],
                body=draft["proposed_body"],
                queue=draft["proposed_queue"],
                priority=draft["proposed_priority"],
                owner=draft["proposed_owner"],
            )
        except Exception as exc:
            cache.update_rt_draft(draft_id, status="Creation Failed", failure_reason=str(exc))
            cache.record_rt_draft_audit(draft_id, "ticket_creation_failed", actor, detail=str(exc))
            raise

    cache.update_rt_draft(
        draft_id,
        status="Created",
        rt_ticket_id=ticket_id,
        ticket_origin="associated_existing" if match else "analyst_approved",
    )
    cache.record_rt_ticket(draft["cve_id"], ticket_id, source="draft_approved")
    cache.record_rt_draft_audit(draft_id, "draft_approved", actor)
    detail = f"Adopted existing ticket #{ticket_id} found via retry-safety search." if match else f"Created RT ticket #{ticket_id}."
    cache.record_rt_draft_audit(draft_id, "ticket_created", "System", detail=detail)
    return {"ticket_id": ticket_id, "url": f"{rt_client.url}/Ticket/Display.html?id={ticket_id}"}


def reject_draft(draft_id: int, cache: VulnCache, actor: str, reason: str | None) -> None:
    draft = cache.get_rt_draft(draft_id)
    if draft is None:
        raise RTDraftError(f"No such draft: {draft_id}")
    if draft["status"] not in _APPROVABLE_STATUSES:
        raise RTDraftError(f"Draft {draft_id} is '{draft['status']}' and cannot be rejected.")
    cache.update_rt_draft(draft_id, status="Rejected", rejection_reason=reason)
    cache.record_rt_draft_audit(draft_id, "draft_rejected", actor, detail=reason)
