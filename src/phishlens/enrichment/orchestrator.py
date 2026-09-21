from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from ..models.ioc import IOC
from ..models.threat_intel import ThreatIntelResult
from .base import ThreatIntelProvider


class EnrichmentOrchestrator:
    def __init__(self, providers: Iterable[ThreatIntelProvider] | None = None) -> None:
        self.providers = list(providers or [])

    def enrich(self, iocs: list[IOC]) -> list[ThreatIntelResult]:
        if not self.providers:
            return [self._not_attempted(ioc) for ioc in iocs]

        results: list[ThreatIntelResult] = []
        for provider in self.providers:
            for ioc in iocs:
                results.append(self._safe_lookup(provider, ioc))
        return results

    def _safe_lookup(self, provider: ThreatIntelProvider, ioc: IOC) -> ThreatIntelResult:
        try:
            method = getattr(provider, f"lookup_{ioc.ioc_type}")
            result = method(ioc)
            if result.timestamp is None:
                result.timestamp = datetime.now(timezone.utc).isoformat()
            return result
        except TimeoutError:
            return self._failure(provider.name, ioc, "timeout")
        except PermissionError:
            return self._failure(provider.name, ioc, "rate_limited")
        except NotImplementedError:
            return self._failure(provider.name, ioc, "unavailable")
        except Exception as exc:
            return self._failure(provider.name, ioc, "error", type(exc).__name__)

    @staticmethod
    def _not_attempted(ioc: IOC) -> ThreatIntelResult:
        return ThreatIntelResult(
            provider="none",
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.normalized_value,
            status="not_attempted",
            source="enrichment_disabled",
        )

    @staticmethod
    def _failure(provider: str, ioc: IOC, status: str, error: str | None = None) -> ThreatIntelResult:
        return ThreatIntelResult(
            provider=provider,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.normalized_value,
            status=status,  # type: ignore[arg-type]
            source="provider_adapter",
            error=error,
        )
