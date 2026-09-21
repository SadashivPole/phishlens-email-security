from src.phishlens.models.evidence import EvidenceItem
from src.phishlens.models.scoring import CATEGORY_CAPS
from src.phishlens.scoring.rule_engine import score_evidence


def test_scores_are_bounded_and_duplicate_signals_do_not_inflate():
    findings = [EvidenceItem("ip_literal_url", "url", "medium", {}, "", "test", "medium", 4) for _ in range(20)]
    result = score_evidence(findings)
    assert result.category_scores["url"] == 4
    assert result.total_score <= sum(CATEGORY_CAPS.values())


def test_hard_indicator_is_explicit_only():
    heuristic = EvidenceItem("reply_to_mismatch", "identity", "medium", {}, "", "test", "medium", 4)
    hard = EvidenceItem("known_malicious_hash", "attachment", "critical", {}, "", "test", "high", 15, True)
    result = score_evidence([heuristic, hard])
    assert result.hard_indicators == ["known_malicious_hash"]
