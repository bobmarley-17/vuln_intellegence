"""Custom risk scoring engine combining CVSS, EPSS, KEV status and exposure.

Produces a single 0-100 risk_score, a risk_level bucket, and a short
patch-priority recommendation for each CVE.
"""
from __future__ import annotations

from modules.models import EnrichedCVE

_EXPOSURE_BY_ATTACK_VECTOR = {
    "NETWORK": 1.0,
    "ADJACENT_NETWORK": 0.6,
    "LOCAL": 0.3,
    "PHYSICAL": 0.1,
}

# Component weights; only components with available data are used, and the
# remaining weights are renormalized so missing data doesn't silently zero
# out the score.
_WEIGHTS = {
    "cvss": 0.45,
    "epss": 0.30,
    "kev": 0.15,
    "exposure": 0.10,
}


class RiskScorer:
    """Computes a normalized 0-100 risk score from whatever intelligence is
    available for a CVE, tolerating missing sources gracefully."""

    def score(self, cve: EnrichedCVE) -> None:
        components: dict[str, float] = {}

        cvss = cve.cvss_v4_score if cve.cvss_v4_score is not None else cve.cvss_v3_score
        if cvss is not None:
            components["cvss"] = min(cvss / 10.0, 1.0)

        if cve.epss_score is not None:
            components["epss"] = min(cve.epss_score, 1.0)

        components["kev"] = 1.0 if cve.kev_listed else 0.0

        exposure = self._exposure_factor(cve)
        if exposure is not None:
            components["exposure"] = exposure

        total_weight = sum(_WEIGHTS[name] for name in components)
        if total_weight == 0:
            cve.risk_score = 0.0
        else:
            weighted_sum = sum(components[name] * _WEIGHTS[name] for name in components)
            cve.risk_score = round((weighted_sum / total_weight) * 100, 1)

        cve.risk_level = self._risk_level(cve.risk_score)
        cve.risk_recommendation = self._recommendation(cve.risk_level, cve.kev_listed)

    @staticmethod
    def _exposure_factor(cve: EnrichedCVE) -> float | None:
        if not cve.attack_vector:
            return None
        base = _EXPOSURE_BY_ATTACK_VECTOR.get(cve.attack_vector.upper(), 0.3)
        if cve.privileges_required and cve.privileges_required.upper() == "NONE":
            base = min(base + 0.15, 1.0)
        if cve.user_interaction and cve.user_interaction.upper() == "NONE":
            base = min(base + 0.15, 1.0)
        return base

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 35:
            return "Medium"
        return "Low"

    @staticmethod
    def _recommendation(level: str, kev_listed: bool) -> str:
        if kev_listed or level == "Critical":
            return "Patch Immediately"
        if level == "High":
            return "Patch Within 7 Days"
        if level == "Medium":
            return "Schedule Patch"
        return "Monitor"
