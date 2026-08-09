"""Shared dataclasses used across the pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Article:
    """A downloaded and parsed security news article."""

    url: str
    title: str | None = None
    author: str | None = None
    published_date: str | None = None
    site_name: str | None = None
    content: str = ""
    fetched_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    cves: list[str] = field(default_factory=list)
    source_id: int | None = None


@dataclass
class AffectedProduct:
    """A single vendor/product/version-range entry derived from CPE or CVE.org data."""

    vendor: str
    product: str
    affected_range: str | None = None
    fixed_version: str | None = None
    status: str = "affected"  # affected | fixed | unaffected


@dataclass
class EnrichedCVE:
    """Fully enriched CVE record aggregating all intelligence sources."""

    cve_id: str

    # NVD
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    cvss_v4_score: float | None = None
    cvss_v4_vector: str | None = None
    severity: str | None = None
    attack_vector: str | None = None
    attack_complexity: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    scope: str | None = None
    confidentiality_impact: str | None = None
    integrity_impact: str | None = None
    availability_impact: str | None = None
    published_date: str | None = None
    modified_date: str | None = None
    cwe: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    # CVE.org / MITRE
    description: str | None = None
    cna: str | None = None

    # Vendor / product / normalized versions
    vendor: str | None = None
    product: str | None = None
    affected_products: list[AffectedProduct] = field(default_factory=list)
    affected_versions_display: str | None = None
    fixed_versions_display: str | None = None

    # EPSS
    epss_score: float | None = None
    epss_percentile: float | None = None

    # CISA KEV
    kev_listed: bool = False
    kev_date_added: str | None = None
    kev_due_date: str | None = None

    # Derived
    summary: str | None = None
    risk_score: float | None = None
    risk_level: str | None = None
    risk_recommendation: str | None = None

    # Provenance
    source_articles: list[str] = field(default_factory=list)
    last_enriched_at: str | None = None
