from __future__ import annotations

from src.phishlens.models.evidence import AnalysisAreaStatus, AnalysisCompleteness
from src.phishlens.models.scoring import ScoringResult
from src.phishlens.models.threat_intel import ThreatIntelResult
from src.phishlens.scoring.policy import apply_policy
from src.phishlens.scoring.threat_intel_policy import threat_intel_evidence


def ti(status, disposition=None, provider="mock", value="192.0.2.1"):
    return ThreatIntelResult(provider, "ip", value, status, disposition=disposition, confidence="high")


def verdict(results, parser_status="complete"):
    evidence = threat_intel_evidence(results)
    scoring = ScoringResult()
    completeness = AnalysisCompleteness({"parser": AnalysisAreaStatus(parser_status)})
    return apply_policy(scoring, completeness, evidence, results)


def test_policy_defines_all_provider_states_without_provider_verdict_override():
    cases = {
        "match": ("malicious", "CLEAN"),
        "no_match": (None, "CLEAN"),
        "partial": (None, "CLEAN"),
        "timeout": (None, "CLEAN"),
        "rate_limited": (None, "CLEAN"),
        "error": (None, "CLEAN"),
        "unavailable": (None, "CLEAN"),
        "not_attempted": (None, "CLEAN"),
    }
    for status, (disposition, expected) in cases.items():
        assert verdict([ti(status, disposition)]).final == expected


def test_suspicious_provider_match_is_evidence_not_verdict_override():
    result = verdict([ti("match", "suspicious")])
    assert result.final == "CLEAN"
    assert result.final != "MALICIOUS"


def test_repeated_provider_ioc_results_do_not_double_count():
    results = [ti("match", "malicious"), ti("match", "malicious")]
    evidence = threat_intel_evidence(results)
    assert len(evidence) == 1
    assert evidence[0].evidence["provider"] == "mock"
    assert evidence[0].evidence["ioc_type"] == "ip"
    assert evidence[0].evidence["ioc_value"] == "192.0.2.1"
    assert evidence[0].evidence["status"] == "match"


def test_distinct_iocs_are_bounded_by_policy_and_not_hard_indicators():
    results = [ti("match", "malicious", value=f"192.0.2.{index}") for index in range(1, 20)]
    evidence = threat_intel_evidence(results)
    assert len(evidence) == 19
    assert sum(item.points for item in evidence) <= 10
    assert all(not item.hard_indicator for item in evidence)


def test_each_provider_failure_preserves_normal_local_verdict():
    for status in ("timeout", "rate_limited", "error", "unavailable", "partial"):
        assert verdict([ti(status)]).final == "CLEAN"


def test_partial_does_not_mask_an_existing_required_unresolved_state():
    assert verdict([ti("partial")], parser_status="not_evaluable").final == "UNRESOLVED"


def test_no_threat_intel_evidence_preserves_previous_verdict():
    assert verdict([]).final == "CLEAN"
