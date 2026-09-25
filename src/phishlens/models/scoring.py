from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


CATEGORY_CAPS: dict[str, int] = {
    "authentication": 20,
    "identity": 10,
    "url": 20,
    "attachment": 15,
    "content": 5,
}
MAX_TOTAL_SCORE = sum(CATEGORY_CAPS.values())


@dataclass
class ScoringResult:
    category_scores: dict[str, int] = field(default_factory=dict)
    total_score: int = 0
    hard_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category_scores": self.category_scores,
            "category_caps": CATEGORY_CAPS,
            "total_score": self.total_score,
            "maximum_score": MAX_TOTAL_SCORE,
            "hard_indicators": self.hard_indicators,
        }
