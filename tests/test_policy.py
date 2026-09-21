from src.phishlens.models.evidence import AnalysisAreaStatus, AnalysisCompleteness, EvidenceItem
from src.phishlens.models.scoring import ScoringResult
from src.phishlens.scoring.policy import apply_policy


def complete():
    return AnalysisCompleteness({
        "parser": AnalysisAreaStatus("complete", required=True),
        "identity": AnalysisAreaStatus("complete", required=True),
        "authentication": AnalysisAreaStatus("complete", required=True),
        "url": AnalysisAreaStatus("complete", required=True),
        "attachment": AnalysisAreaStatus("complete", required=True),
        "reputation": AnalysisAreaStatus("unavailable", required=False),
    })


def test_zero_findings_with_optional_provider_unavailable_is_clean():
    verdict = apply_policy(ScoringResult(), complete(), [])
    assert verdict.final == "CLEAN"
    assert verdict.analysis_status == "complete"


def test_heuristic_alone_does_not_force_malicious():
    evidence = [EvidenceItem("ip_literal_url", "url", "medium", {}, "", "local_url_analysis", "medium", 4)]
    verdict = apply_policy(ScoringResult({"url": 4}, 4, []), complete(), evidence)
    assert verdict.final == "CLEAN"


def test_two_medium_findings_are_suspicious_not_malicious():
    evidence = [
        EvidenceItem("spf_fail", "authentication", "medium", {}, "", "authentication_results", "medium", 4),
        EvidenceItem("reply_to_mismatch", "identity", "medium", {}, "", "local_header_analysis", "medium", 4),
    ]
    verdict = apply_policy(ScoringResult({"authentication": 4, "identity": 4}, 8, []), complete(), evidence)
    assert verdict.final == "SUSPICIOUS"


def test_hard_indicator_produces_malicious():
    evidence = [EvidenceItem("known_malicious_hash", "attachment", "critical", {}, "", "local_attachment_analysis", "high", 15, True)]
    verdict = apply_policy(ScoringResult({"attachment": 15}, 15, ["known_malicious_hash"]), complete(), evidence)
    assert verdict.final == "MALICIOUS"


def test_required_incomplete_analysis_is_unresolved_without_material_evidence():
    incomplete = AnalysisCompleteness({
        "parser": AnalysisAreaStatus("complete", required=True),
        "authentication": AnalysisAreaStatus("not_evaluable", required=True),
        "reputation": AnalysisAreaStatus("unavailable", required=False),
    })
    verdict = apply_policy(ScoringResult(), incomplete, [])
    assert verdict.final == "UNRESOLVED"


def test_material_evidence_precedes_incomplete_optional_or_required_area():
    incomplete = AnalysisCompleteness({
        "parser": AnalysisAreaStatus("complete", required=True),
        "authentication": AnalysisAreaStatus("not_evaluable", required=True),
        "attachment": AnalysisAreaStatus("complete", required=True),
    })
    evidence = [EvidenceItem("attachment_type_mismatch", "attachment", "high", {}, "", "local_attachment_analysis", "high", 7)]
    verdict = apply_policy(ScoringResult({"attachment": 7}, 7, []), incomplete, evidence)
    assert verdict.final == "SUSPICIOUS"
