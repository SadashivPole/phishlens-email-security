from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from typing import Literal


DEFAULT_TI_TIMEOUT_SECONDS = 10.0
DEFAULT_TI_MAX_REQUESTS_PER_EMAIL = 50
DEFAULT_MAX_IOCS_PER_EMAIL = 50_000


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
    max_requests_per_email: int = DEFAULT_TI_MAX_REQUESTS_PER_EMAIL

    @classmethod
    def from_environment(cls) -> "ThreatIntelConfig":
        timeout = _env_float(
            "PHISHLENS_TI_TIMEOUT_SECONDS",
            DEFAULT_TI_TIMEOUT_SECONDS,
        )
        max_requests = _env_int(
            "PHISHLENS_TI_MAX_REQUESTS_PER_EMAIL",
            DEFAULT_TI_MAX_REQUESTS_PER_EMAIL,
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
            max_requests_per_email=max_requests,
        )

    def safe_dict(self) -> dict[str, object]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "max_requests_per_email": self.max_requests_per_email,
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
    max_iocs_per_email: int = DEFAULT_MAX_IOCS_PER_EMAIL
    auth_results_mode: Literal["raw", "trusted_ingress"] = "raw"
    trusted_authserv_id: str | None = None
    threat_intelligence: ThreatIntelConfig = field(default_factory=ThreatIntelConfig.from_environment)

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_email_bytes", _env_int("PHISHLENS_MAX_EMAIL_BYTES", self.max_email_bytes))
        object.__setattr__(self, "max_attachment_bytes", _env_int("PHISHLENS_MAX_ATTACHMENT_BYTES", self.max_attachment_bytes))
        object.__setattr__(self, "max_iocs_per_email", _env_int("PHISHLENS_MAX_IOCS_PER_EMAIL", self.max_iocs_per_email))
        object.__setattr__(self, "auth_results_mode", _auth_results_mode(self.auth_results_mode))
        object.__setattr__(self, "trusted_authserv_id", _optional_value("PHISHLENS_TRUSTED_AUTHSERV_ID", self.trusted_authserv_id))


def _optional_secret(name: str) -> str | None:
    value = os.getenv(name)
    value = value.strip() if value is not None else ""
    return value or None


def _optional_value(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name, default)
    value = value.strip() if value is not None else ""
    return value or None


def _auth_results_mode(default: str) -> Literal["raw", "trusted_ingress"]:
    value = os.getenv("PHISHLENS_AUTH_RESULTS_MODE", default).strip().lower()
    return "trusted_ingress" if value == "trusted_ingress" else "raw"


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
