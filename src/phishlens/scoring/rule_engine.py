from __future__ import annotations

from collections import defaultdict

from ..models.evidence import EvidenceItem
from ..models.scoring import CATEGORY_CAPS, MAX_TOTAL_SCORE, ScoringResult


def score_evidence(evidence: list[EvidenceItem]) -> ScoringResult:
    category_scores: dict[str, int] = defaultdict(int)
    seen_signals: set[tuple[str, str]] = set()
    hard_indicators: list[str] = []

    for item in evidence:
        key = (item.category, item.signal_id)
        if key in seen_signals:
            continue
        seen_signals.add(key)
        category_scores[item.category] += max(0, item.points)
        if item.hard_indicator and item.signal_id not in hard_indicators:
            hard_indicators.append(item.signal_id)

    bounded = {
        category: min(category_scores.get(category, 0), cap)
        for category, cap in CATEGORY_CAPS.items()
    }
    return ScoringResult(
        category_scores=bounded,
        total_score=min(sum(bounded.values()), MAX_TOTAL_SCORE),
        hard_indicators=hard_indicators,
    )
