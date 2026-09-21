from __future__ import annotations

from typing import Protocol

from ..models.ioc import IOC
from ..models.threat_intel import ThreatIntelResult


class ThreatIntelProvider(Protocol):
    name: str

    def lookup_ip(self, ioc: IOC) -> ThreatIntelResult: ...
    def lookup_domain(self, ioc: IOC) -> ThreatIntelResult: ...
    def lookup_url(self, ioc: IOC) -> ThreatIntelResult: ...
    def lookup_hash(self, ioc: IOC) -> ThreatIntelResult: ...
