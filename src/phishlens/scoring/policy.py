from __future__ import annotations

from ..models.evidence import AnalysisCompleteness, EvidenceItem
from ..models.scoring import ScoringResult
from ..models.verdict import VerdictResult

# These are local observations that warrant analyst review when they are
# sufficiently correlated. None of them is a hard malicious indicator.
MATERIAL_SIGNAL_IDS = {
    "reply_to_mismatch",
    "return_path_mismatch",
    "message_id_domain_mismatch",
    "spf_fail",
    "dkim_fail",
    "dmarc_fail",
    "authenticated_domain_mismatch",
    "dkim_signing_domain_mismatch",
    "ip_literal_url",
    "display_href_mismatch",
    "url_userinfo",
    "suspicious_url_encoding",
    "url_shortener",
    "attachment_type_mismatch",
    "attachment_double_extension",
    "credential_urgency_combination",
    "payment_urgency_combination",
}


def material_suspicious_evidence(
    scoring: ScoringResult,
    evidence: list[EvidenceItem],
) -> bool:
    """Return whether local evidence supports SUSPICIOUS, not MALICIOUS.

    A material result requires one high-severity local finding, two medium-
    severity findings, or a score of at least ten together with a material
    signal. Score alone is never enough. Explicit hard indicators are handled
    separately by the policy engine.
    """
    material = [
        item for item in evidence
        if item.signal_id in MATERIAL_SIGNAL_IDS
        and (item.source.startswith("local_") or item.source == "authentication_results")
    ]
    if any(item.severity in {"high", "critical"} for item in material):
        return True
    if sum(item.severity == "medium" for item in material) >= 2:
        return True
    return scoring.total_score >= 10 and bool(material)


def apply_policy(
    scoring: ScoringResult,
    completeness: AnalysisCompleteness,
    evidence: list[EvidenceItem],
) -> VerdictResult:
    status = completeness.overall_status

    if scoring.hard_indicators:
        return VerdictResult(
            "MALICIOUS",
            "A high-confidence hard indicator was identified.",
            status,
            "high",
            scoring.hard_indicators,
        )

    if material_suspicious_evidence(scoring, evidence):
        return VerdictResult(
            "SUSPICIOUS",
            "Material local indicators require analyst review; no hard malicious indicator was established.",
            status,
            _risk_band(scoring.total_score),
        )

    if status != "complete":
        return VerdictResult(
            "UNRESOLVED",
            "Required local analysis was incomplete or unavailable, so a clean conclusion is not supported.",
            status,
            _risk_band(scoring.total_score),
        )

    return VerdictResult(
        "CLEAN",
        "Supported local analysis completed without material suspicious evidence; this does not prove global safety.",
        status,
        _risk_band(scoring.total_score),
    )


def _risk_band(score: int) -> str:
    if score >= 30:
        return "high"
    if score >= 10:
        return "medium"
    return "low"
