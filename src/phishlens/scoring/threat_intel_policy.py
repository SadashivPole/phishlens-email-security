from __future__ import annotations

from ..models.evidence import EvidenceItem
from ..models.threat_intel import ThreatIntelResult

_FAILURE_STATES = {"timeout", "rate_limited", "error", "unavailable", "partial"}


def threat_intel_evidence(results: list[ThreatIntelResult]) -> list[EvidenceItem]:
    """Convert provider observations into bounded, deterministic evidence.

    One observation per provider/IOC is scored. Provider observations are never
    hard indicators and therefore cannot directly produce MALICIOUS.
    """
    evidence: list[EvidenceItem] = []
    seen: set[tuple[str, str, str]] = set()
    remaining_points = 10
    for result in results:
        if result.status == "not_attempted":
            continue
        key = (result.provider, result.ioc_type, result.ioc_value)
        if key in seen:
            continue
        seen.add(key)
        signal_id, severity, points, explanation = _policy_for(result)
        bounded_points = min(points, remaining_points)
        remaining_points -= bounded_points
        evidence.append(EvidenceItem(
            signal_id=signal_id,
            category="threat_intelligence",
            severity=severity,
            evidence={
                "provider": result.provider,
                "ioc_type": result.ioc_type,
                "ioc_value": result.ioc_value,
                "status": result.status,
                "disposition": result.disposition,
                "confidence": result.confidence,
            },
            explanation=explanation,
            source="threat_intelligence_policy",
            reliability="high" if result.status in {"match", "no_match"} else "low",
            points=bounded_points,
            hard_indicator=False,
        ))
    return evidence


def has_provider_failure(results: list[ThreatIntelResult]) -> bool:
    return any(result.status in _FAILURE_STATES for result in results)


def _policy_for(result: ThreatIntelResult) -> tuple[str, str, int, str]:
    if result.status == "match" and result.disposition == "malicious":
        return "ti_match_malicious", "high", 5, "A provider reported a malicious disposition; local review remains required."
    if result.status == "match" and result.disposition == "suspicious":
        return "ti_match_suspicious", "medium", 3, "A provider reported a suspicious disposition; local review remains required."
    if result.status == "match":
        return "ti_match", "medium", 2, "A provider reported a matching indicator."
    if result.status == "no_match":
        return "ti_no_match", "info", 0, "A provider reported no matching threat-intelligence record."
    if result.status == "not_attempted":
        return "ti_not_attempted", "info", 0, "Threat-intelligence lookup was not attempted."
    if result.status == "partial":
        return "ti_partial", "low", 0, "Threat-intelligence lookup returned incomplete evidence."
    return f"ti_{result.status}", "low", 0, f"Threat-intelligence lookup state was {result.status}."
