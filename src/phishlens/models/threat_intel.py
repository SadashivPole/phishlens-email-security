from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

ProviderState = Literal[
    "not_attempted",
    "budget_exhausted",
    "unavailable",
    "timeout",
    "rate_limited",
    "error",
    "no_match",
    "match",
    "partial",
]


@dataclass
class ThreatIntelResult:
    provider: str
    ioc_type: str
    ioc_value: str
    status: ProviderState
    disposition: str | None = None
    confidence: str | None = None
    reputation: str | None = None
    source: str = ""
    observed_indicators: list[str] = field(default_factory=list)
    error: str | None = None
    timestamp: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_safe_dict(self) -> dict[str, Any]:
        result = self.to_dict()
        if self.ioc_type == "url":
            result["ioc_value"] = "[REDACTED_URL]"
        return result
