from __future__ import annotations

import json
from collections.abc import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ..config import AbuseIPDBConfig
from ..models.ioc import IOC
from ..models.threat_intel import ThreatIntelResult

HTTPGetter = Callable[[Request, float], tuple[int, bytes]]


class AbuseIPDBProvider:
    """Small offline-testable AbuseIPDB IP-check adapter; never uploads data."""

    name = "abuseipdb"
    _endpoint = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, config: AbuseIPDBConfig, http_get: HTTPGetter | None = None) -> None:
        self.timeout_seconds = config.timeout_seconds
        self._api_key = config.api_key
        self._http_get = http_get or _http_get

    def lookup_ip(self, ioc: IOC) -> ThreatIntelResult:
        if ioc.ioc_type != "ip":
            return self._result(ioc, "unavailable", error="unsupported_ioc_type")
        if not self._api_key:
            return self._result(ioc, "unavailable", error="missing_api_key")

        query = urlencode({"ipAddress": ioc.normalized_value, "maxAgeInDays": "90"})
        request = Request(
            f"{self._endpoint}?{query}",
            headers={"Key": self._api_key, "Accept": "application/json"},
            method="GET",
        )
        try:
            status_code, payload = self._http_get(request, self.timeout_seconds)
        except TimeoutError:
            return self._result(ioc, "timeout")
        except HTTPError as exc:
            return self._http_failure(ioc, exc.code)
        except URLError:
            return self._result(ioc, "error", error="network_error")
        except Exception as exc:
            return self._result(ioc, "error", error=type(exc).__name__)

        if status_code == 404:
            return self._result(ioc, "no_match")
        if status_code == 429:
            return self._result(ioc, "rate_limited")
        if status_code in {401, 403}:
            return self._result(ioc, "unavailable", error="authentication_failed")
        if status_code < 200 or status_code >= 300:
            return self._result(ioc, "error", error=f"http_{status_code}")

        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._result(ioc, "error", error="malformed_json")
        return self._normalize(ioc, document)

    def lookup_domain(self, ioc: IOC) -> ThreatIntelResult:
        return self._unsupported(ioc)

    def lookup_url(self, ioc: IOC) -> ThreatIntelResult:
        return self._unsupported(ioc)

    def lookup_hash(self, ioc: IOC) -> ThreatIntelResult:
        return self._unsupported(ioc)

    def _normalize(self, ioc: IOC, document: object) -> ThreatIntelResult:
        if not isinstance(document, dict):
            return self._result(ioc, "error", error="malformed_response")
        data = document.get("data")
        if not isinstance(data, dict):
            return self._result(ioc, "partial", error="missing_data")
        score = data.get("abuseConfidenceScore")
        reports = data.get("totalReports")
        if not isinstance(score, int) or not isinstance(reports, int):
            return self._result(ioc, "partial", error="missing_reputation_fields")

        observed = []
        if score > 0:
            observed.append("abuseConfidenceScore")
        if reports > 0:
            observed.append("totalReports")
        if score >= 80:
            disposition, confidence = "malicious", "high"
            status = "match"
        elif score > 0 or reports > 0:
            disposition, confidence = "suspicious", "medium"
            status = "match"
        else:
            disposition, confidence = "clean", "low"
            status = "no_match"
        return self._result(
            ioc,
            status,
            disposition=disposition,
            confidence=confidence,
            reputation=disposition,
            observed_indicators=observed,
        )

    def _http_failure(self, ioc: IOC, status_code: int) -> ThreatIntelResult:
        if status_code == 429:
            return self._result(ioc, "rate_limited")
        if status_code in {401, 403}:
            return self._result(ioc, "unavailable", error="authentication_failed")
        if status_code == 404:
            return self._result(ioc, "no_match")
        return self._result(ioc, "error", error=f"http_{status_code}")

    def _unsupported(self, ioc: IOC) -> ThreatIntelResult:
        return self._result(ioc, "unavailable", error="unsupported_ioc_type")

    def _result(self, ioc: IOC, status: str, **fields: object) -> ThreatIntelResult:
        return ThreatIntelResult(
            provider=self.name,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.normalized_value,
            status=status,  # type: ignore[arg-type]
            source="abuseipdb_api",
            **fields,
        )


def _http_get(request: Request, timeout: float) -> tuple[int, bytes]:
    with urlopen(request, timeout=timeout) as response:  # nosec B310 - fixed AbuseIPDB API host
        return int(response.status), response.read()
