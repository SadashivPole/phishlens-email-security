from __future__ import annotations

from ..config import ThreatIntelProviderConfig
from ..models.ioc import IOC
from ..models.threat_intel import ThreatIntelResult
from .abuseipdb import AbuseIPDBProvider
from .virustotal import VirusTotalProvider


class ConfiguredThreatIntelProvider:
    """Configured, offline-only provider placeholder.

    Phase 3B.1 deliberately performs no HTTP/API operation. Enabled provider
    configuration is represented through the existing provider abstraction and
    returns ``unavailable`` until a later phase adds an API adapter.
    """

    def __init__(self, config: ThreatIntelProviderConfig) -> None:
        if not config.enabled:
            raise ValueError("provider configuration is disabled")
        self.name = config.name
        self.timeout_seconds = config.timeout_seconds
        self._api_key = config.api_key

    def lookup_ip(self, ioc: IOC) -> ThreatIntelResult:
        return self._unavailable(ioc)

    def lookup_domain(self, ioc: IOC) -> ThreatIntelResult:
        return self._unavailable(ioc)

    def lookup_url(self, ioc: IOC) -> ThreatIntelResult:
        return self._unavailable(ioc)

    def lookup_hash(self, ioc: IOC) -> ThreatIntelResult:
        return self._unavailable(ioc)

    def _unavailable(self, ioc: IOC) -> ThreatIntelResult:
        return ThreatIntelResult(
            provider=self.name,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.normalized_value,
            status="unavailable",
            source="provider_adapter_not_implemented",
        )


def providers_from_config(config, *, include_api_adapters: bool = False) -> list[object]:
    """Build configured providers without changing the Phase 3B.1 default.

    The compatibility default remains offline-only. The Analyzer explicitly
    opts into the implemented API adapters for enabled providers.
    """
    providers: list[object] = []
    for item in config.enabled_provider_configs():
        if include_api_adapters:
            if item.name == "virustotal":
                providers.append(VirusTotalProvider(item))
            elif item.name == "abuseipdb":
                providers.append(AbuseIPDBProvider(item))
        else:
            providers.append(ConfiguredThreatIntelProvider(item))
    return providers
