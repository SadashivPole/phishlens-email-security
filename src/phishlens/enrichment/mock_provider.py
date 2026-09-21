from __future__ import annotations

from datetime import datetime, timezone
from typing import Mapping

from ..models.ioc import IOC
from ..models.threat_intel import ProviderState, ThreatIntelResult


class MockThreatIntelProvider:
    """Deterministic local provider for tests and offline demonstrations."""

    name = "mock"

    def __init__(self, outcomes: Mapping[tuple[str, str], ProviderState | ThreatIntelResult] | None = None) -> None:
        self.outcomes = dict(outcomes or {})
        self.calls: list[tuple[str, str]] = []

    def lookup_ip(self, ioc: IOC) -> ThreatIntelResult:
        return self._lookup(ioc)

    def lookup_domain(self, ioc: IOC) -> ThreatIntelResult:
        return self._lookup(ioc)

    def lookup_url(self, ioc: IOC) -> ThreatIntelResult:
        return self._lookup(ioc)

    def lookup_hash(self, ioc: IOC) -> ThreatIntelResult:
        return self._lookup(ioc)

    def _lookup(self, ioc: IOC) -> ThreatIntelResult:
        self.calls.append(ioc.key())
        outcome = self.outcomes.get(ioc.key(), "no_match")
        if isinstance(outcome, ThreatIntelResult):
            return outcome
        status = outcome
        disposition = "malicious" if status == "match" else None
        confidence = "high" if status == "match" else None
        return ThreatIntelResult(
            provider=self.name,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.normalized_value,
            status=status,
            disposition=disposition,
            confidence=confidence,
            reputation=disposition,
            source="mock_local_provider",
            observed_indicators=[ioc.normalized_value] if status == "match" else [],
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
