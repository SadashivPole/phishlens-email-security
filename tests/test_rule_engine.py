from src.phishlens.models.evidence import EvidenceItem
from src.phishlens.models.scoring import CATEGORY_CAPS, MAX_TOTAL_SCORE
from src.phishlens.scoring.rule_engine import score_evidence


def test_scores_are_bounded_and_duplicate_signals_do_not_inflate():
    findings = [EvidenceItem("ip_literal_url", "url", "medium", {}, "", "test", "medium", 4) for _ in range(20)]
    result = score_evidence(findings)
    assert result.category_scores["url"] == 4
    assert result.total_score <= MAX_TOTAL_SCORE


def test_maximum_score_is_derived_from_category_caps():
    result = score_evidence([])
    assert MAX_TOTAL_SCORE == sum(CATEGORY_CAPS.values()) == 70
    assert result.to_dict()["maximum_score"] == MAX_TOTAL_SCORE


def test_hard_indicator_is_explicit_only():
    heuristic = EvidenceItem("reply_to_mismatch", "identity", "medium", {}, "", "test", "medium", 4)
    hard = EvidenceItem("known_malicious_hash", "attachment", "critical", {}, "", "test", "high", 15, True)
    result = score_evidence([heuristic, hard])
    assert result.hard_indicators == ["known_malicious_hash"]


def test_authenticated_domain_mismatch_is_deduplicated():
    findings = [
        EvidenceItem("authenticated_domain_mismatch", "identity", "medium", {"mechanism": "spf"}, "", "authentication_results", "medium", 3),
        EvidenceItem("authenticated_domain_mismatch", "identity", "medium", {"mechanism": "spf"}, "", "authentication_results", "medium", 3),
    ]
    result = score_evidence(findings)
    assert result.category_scores["identity"] == 3
