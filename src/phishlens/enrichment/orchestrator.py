from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from ..models.ioc import IOC
from ..models.threat_intel import ThreatIntelResult
from .base import ThreatIntelProvider


class EnrichmentOrchestrator:
    def __init__(
        self,
        providers: Iterable[ThreatIntelProvider] | None = None,
        *,
        max_requests: int | None = None,
    ) -> None:
        if max_requests is not None and (
            not isinstance(max_requests, int) or max_requests <= 0
        ):
            raise ValueError("max_requests must be a positive integer or None")

        self.providers = list(providers or [])
        self.max_requests = max_requests

    def enrich(self, iocs: list[IOC]) -> list[ThreatIntelResult]:
        if not self.providers:
            return [self._not_attempted(ioc) for ioc in iocs]

        remaining = self.max_requests
        results: list[ThreatIntelResult] = []

        for provider in self.providers:
            for ioc in iocs:
                if remaining is not None and remaining <= 0:
                    results.append(self._budget_exhausted(provider, ioc))
                    continue

                if remaining is not None:
                    remaining -= 1

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
    def _budget_exhausted(
        provider: ThreatIntelProvider,
        ioc: IOC,
    ) -> ThreatIntelResult:
        return ThreatIntelResult(
            provider=provider.name,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.normalized_value,
            status="budget_exhausted",
            source="enrichment_budget",
            error="request_budget_exhausted",
        )

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
