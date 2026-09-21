from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Category = Literal["authentication", "identity", "url", "attachment", "content"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Reliability = Literal["low", "medium", "high"]
Completeness = Literal["complete", "partial", "unavailable", "not_evaluable"]


@dataclass
class EvidenceItem:
    signal_id: str
    category: Category
    severity: Severity
    evidence: dict[str, Any]
    explanation: str
    source: str
    reliability: Reliability
    points: int = 0
    hard_indicator: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisAreaStatus:
    status: Completeness
    note: str = ""
    required: bool = True

    def to_dict(self) -> dict[str, str | bool]:
        return {"status": self.status, "note": self.note, "required": self.required}


@dataclass
class AnalysisCompleteness:
    areas: dict[str, AnalysisAreaStatus] = field(default_factory=dict)

    @property
    def overall_status(self) -> str:
        # Optional capabilities such as reputation and content analysis remain
        # visible, but cannot invalidate a completed local analysis.
        required_areas = [item for item in self.areas.values() if item.required]
        statuses = {item.status for item in required_areas}
        if "unavailable" in statuses:
            return "unavailable"
        if "not_evaluable" in statuses or "partial" in statuses:
            return "partial"
        return "complete"

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_status": self.overall_status,
            "areas": {key: value.to_dict() for key, value in self.areas.items()},
        }
