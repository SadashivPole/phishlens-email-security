from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Verdict = Literal["CLEAN", "SUSPICIOUS", "MALICIOUS", "UNRESOLVED"]


@dataclass
class VerdictResult:
    final: Verdict
    reason: str
    analysis_status: str
    risk_band: str
    hard_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "final": self.final,
            "reason": self.reason,
            "analysis_status": self.analysis_status,
            "risk_band": self.risk_band,
            "hard_indicators": self.hard_indicators,
        }
