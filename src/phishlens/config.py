from __future__ import annotations

import math
import os
from dataclasses import dataclass, field


DEFAULT_TI_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class ThreatIntelProviderConfig:
    """Offline configuration metadata for one optional TI provider.

    The key is intentionally excluded from repr, equality, and safe export.
    This phase only configures providers; it does not perform requests.
    """

    name: str
    api_key: str | None = field(default=None, repr=False, compare=False)
    timeout_seconds: float = DEFAULT_TI_TIMEOUT_SECONDS

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def safe_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass(frozen=True)
class VirusTotalConfig(ThreatIntelProviderConfig):
    name: str = "virustotal"


@dataclass(frozen=True)
class AbuseIPDBConfig(ThreatIntelProviderConfig):
    name: str = "abuseipdb"


@dataclass(frozen=True)
class ThreatIntelConfig:
    """Safe environment-backed TI configuration; no network behavior."""

    virustotal: VirusTotalConfig = field(default_factory=VirusTotalConfig)
    abuseipdb: AbuseIPDBConfig = field(default_factory=AbuseIPDBConfig)
    timeout_seconds: float = DEFAULT_TI_TIMEOUT_SECONDS

    @classmethod
    def from_environment(cls) -> "ThreatIntelConfig":
        timeout = _env_float(
            "PHISHLENS_TI_TIMEOUT_SECONDS",
            DEFAULT_TI_TIMEOUT_SECONDS,
        )
        return cls(
            virustotal=VirusTotalConfig(
                api_key=_optional_secret("PHISHLENS_VT_API_KEY"),
                timeout_seconds=timeout,
            ),
            abuseipdb=AbuseIPDBConfig(
                api_key=_optional_secret("PHISHLENS_ABUSEIPDB_API_KEY"),
                timeout_seconds=timeout,
            ),
            timeout_seconds=timeout,
        )

    def safe_dict(self) -> dict[str, object]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "providers": {
                "virustotal": self.virustotal.safe_dict(),
                "abuseipdb": self.abuseipdb.safe_dict(),
            },
        }

    def enabled_provider_configs(self) -> list[ThreatIntelProviderConfig]:
        return [config for config in (self.virustotal, self.abuseipdb) if config.enabled]


@dataclass(frozen=True)
class Settings:
    max_email_bytes: int = 10 * 1024 * 1024
    max_attachment_bytes: int = 5 * 1024 * 1024
    max_mime_parts: int = 100
    threat_intelligence: ThreatIntelConfig = field(default_factory=ThreatIntelConfig.from_environment)

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_email_bytes", _env_int("PHISHLENS_MAX_EMAIL_BYTES", self.max_email_bytes))
        object.__setattr__(self, "max_attachment_bytes", _env_int("PHISHLENS_MAX_ATTACHMENT_BYTES", self.max_attachment_bytes))


def _optional_secret(name: str) -> str | None:
    value = os.getenv(name)
    value = value.strip() if value is not None else ""
    return value or None


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return parsed if parsed > 0 else default


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError:
        return default
    return parsed if parsed > 0 and math.isfinite(parsed) else default
