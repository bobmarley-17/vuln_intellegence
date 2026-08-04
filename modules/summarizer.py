"""Template-based analyst summary generator (no external LLM calls).

Builds an original technical sentence from structured fields already
collected (NVD/CVE.org/EPSS/KEV) rather than copying the NVD description.
"""
from __future__ import annotations

from modules.models import EnrichedCVE

_VULN_CLASS_BY_CWE = {
    "CWE-79": "a cross-site scripting (XSS)",
    "CWE-89": "a SQL injection",
    "CWE-78": "an OS command injection",
    "CWE-77": "a command injection",
    "CWE-94": "a code injection",
    "CWE-502": "an insecure deserialization",
    "CWE-22": "a path traversal",
    "CWE-434": "an arbitrary file upload",
    "CWE-269": "a privilege escalation",
    "CWE-287": "an authentication bypass",
    "CWE-352": "a cross-site request forgery (CSRF)",
    "CWE-190": "an integer overflow",
    "CWE-120": "a buffer overflow",
    "CWE-787": "an out-of-bounds write",
    "CWE-125": "an out-of-bounds read",
    "CWE-416": "a use-after-free",
    "CWE-918": "a server-side request forgery (SSRF)",
    "CWE-611": "an XML external entity (XXE)",
}

_AV_PHRASES = {
    "NETWORK": "remotely over the network",
    "ADJACENT_NETWORK": "from an adjacent network",
    "LOCAL": "with local access",
    "PHYSICAL": "with physical access to the device",
}

_UI_PHRASES = {
    "NONE": "without user interaction",
    "REQUIRED": "but requires user interaction (e.g. opening a file or link)",
}

_PR_PHRASES = {
    "NONE": "without authentication",
    "LOW": "with low-privileged credentials",
    "HIGH": "with high-privileged credentials",
}


class TemplateSummarizer:
    """Deterministic sentence generator producing an analyst-style summary
    for each CVE from its structured fields."""

    def summarize(self, cve: EnrichedCVE) -> str:
        vuln_class = self._vuln_class(cve)
        subject = self._subject(cve)
        severity_word = (cve.severity or "unrated").lower()

        sentence_1 = f"{cve.cve_id} is {vuln_class} vulnerability affecting {subject}."

        exploit_bits = []
        if cve.attack_vector and cve.attack_vector.upper() in _AV_PHRASES:
            exploit_bits.append(_AV_PHRASES[cve.attack_vector.upper()])
        if cve.privileges_required and cve.privileges_required.upper() in _PR_PHRASES:
            exploit_bits.append(_PR_PHRASES[cve.privileges_required.upper()])
        if cve.user_interaction and cve.user_interaction.upper() in _UI_PHRASES:
            exploit_bits.append(_UI_PHRASES[cve.user_interaction.upper()])

        sentence_2 = ""
        if exploit_bits:
            sentence_2 = f"It can be exploited {', '.join(exploit_bits)}."

        sentence_3 = ""
        if cve.fixed_versions_display:
            vendor = cve.vendor or "The vendor"
            sentence_3 = f"{vendor} addressed the issue in version {cve.fixed_versions_display}."
        elif cve.affected_versions_display:
            sentence_3 = "No fixed version has been published at this time; mitigating controls are recommended."

        score_bits = []
        if cve.cvss_v3_score is not None:
            score_bits.append(f"a CVSS score of {cve.cvss_v3_score}")
        if cve.epss_score is not None:
            score_bits.append(f"an EPSS exploitation probability of {cve.epss_score * 100:.1f}%")
        sentence_4 = ""
        if score_bits:
            sentence_4 = f"The vulnerability has {' and '.join(score_bits)}."

        sentence_5 = ""
        if cve.kev_listed:
            sentence_5 = "It is listed in CISA's Known Exploited Vulnerabilities catalog and is confirmed to be actively exploited in the wild."
        elif severity_word in ("critical", "high"):
            sentence_5 = "It should be prioritized for immediate patching given its severity."

        parts = [s for s in (sentence_1, sentence_2, sentence_3, sentence_4, sentence_5) if s]
        return " ".join(parts)

    @staticmethod
    def _vuln_class(cve: EnrichedCVE) -> str:
        for cwe in cve.cwe:
            if cwe in _VULN_CLASS_BY_CWE:
                return _VULN_CLASS_BY_CWE[cwe]
        return "a"

    _MAX_INLINE_VERSION_LEN = 60

    @staticmethod
    def _subject(cve: EnrichedCVE) -> str:
        if cve.vendor and cve.product:
            subject = cve.product if cve.product.lower().startswith(cve.vendor.lower()) else f"{cve.vendor} {cve.product}"
        elif cve.product:
            subject = cve.product
        else:
            subject = "the affected product"

        versions = cve.affected_versions_display
        # Only inline an actual version range (contains "product: range"); a
        # multi-product rollup, or a display string with no range at all,
        # belongs in the dedicated table column, not prose.
        if (
            versions
            and ": " in versions
            and "; " not in versions
            and len(versions) <= TemplateSummarizer._MAX_INLINE_VERSION_LEN
        ):
            subject = f"{subject} versions {versions.split(': ', 1)[-1]}"
        return subject
