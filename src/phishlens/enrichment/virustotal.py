from __future__ import annotations

import base64
import json
from collections.abc import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from ..config import VirusTotalConfig
from ..models.indicators import SENSITIVE_QUERY_PARAMS
from ..models.ioc import IOC
from ..models.threat_intel import ThreatIntelResult

HTTPGetter = Callable[[Request, float], tuple[int, bytes]]


class VirusTotalProvider:
    """Small VirusTotal v3 adapter with no upload or arbitrary-fetch behavior."""

    name = "virustotal"
    _base_url = "https://www.virustotal.com/api/v3"

    def __init__(self, config: VirusTotalConfig, http_get: HTTPGetter | None = None) -> None:
        self.timeout_seconds = config.timeout_seconds
        self._api_key = config.api_key
        self._http_get = http_get or _http_get

    def lookup_ip(self, ioc: IOC) -> ThreatIntelResult:
        return self._lookup(ioc, "ip_addresses")

    def lookup_domain(self, ioc: IOC) -> ThreatIntelResult:
        return self._lookup(ioc, "domains")

    def lookup_url(self, ioc: IOC) -> ThreatIntelResult:
        if ioc.ioc_type != "url":
            return self._unsupported(ioc)
        try:
            provider_url = _sanitize_url_for_lookup(ioc.normalized_value)
        except (TypeError, ValueError, UnicodeError):
            return self._result(ioc, "unavailable", error="url_sanitization_failed")
        url_id = base64.urlsafe_b64encode(provider_url.encode("utf-8")).decode("ascii").rstrip("=")
        return self._lookup(ioc, "urls", url_id)

    def lookup_hash(self, ioc: IOC) -> ThreatIntelResult:
        return self._lookup(ioc, "files")

    def _lookup(self, ioc: IOC, resource: str, identifier: str | None = None) -> ThreatIntelResult:
        if not self._api_key:
            return self._result(ioc, "unavailable", error="missing_api_key")
        if ioc.ioc_type not in {"ip", "domain", "url", "hash"}:
            return self._unsupported(ioc)

        value = identifier or ioc.normalized_value
        encoded_value = quote(value, safe="")
        endpoint = f"{self._base_url}/{resource}/{encoded_value}"  # noqa: S310
        request = Request(endpoint, headers={"x-apikey": self._api_key, "accept": "application/json"}, method="GET")
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

    def _http_failure(self, ioc: IOC, status_code: int) -> ThreatIntelResult:
        if status_code == 429:
            return self._result(ioc, "rate_limited")
        if status_code in {401, 403}:
            return self._result(ioc, "unavailable", error="authentication_failed")
        if status_code == 404:
            return self._result(ioc, "no_match")
        return self._result(ioc, "error", error=f"http_{status_code}")

    def _normalize(self, ioc: IOC, document: object) -> ThreatIntelResult:
        if not isinstance(document, dict):
            return self._result(ioc, "error", error="malformed_response")
        data = document.get("data")
        attributes = data.get("attributes") if isinstance(data, dict) else None
        stats = attributes.get("last_analysis_stats") if isinstance(attributes, dict) else None
        if not isinstance(stats, dict):
            return self._result(ioc, "partial", error="missing_analysis_stats")

        observed = [str(key) for key, value in stats.items() if isinstance(value, int) and value > 0]
        malicious = _count(stats, "malicious")
        suspicious = _count(stats, "suspicious")
        if malicious:
            status, disposition, confidence = "match", "malicious", "high"
        elif suspicious:
            status, disposition, confidence = "match", "suspicious", "medium"
        elif all(isinstance(value, int) for value in stats.values()):
            status, disposition, confidence = "no_match", "clean", "low"
        else:
            status, disposition, confidence = "partial", None, None
        return self._result(ioc, status, disposition=disposition, confidence=confidence, reputation=disposition, observed_indicators=observed)

    def _unsupported(self, ioc: IOC) -> ThreatIntelResult:
        return self._result(ioc, "unavailable", error="unsupported_ioc_type")

    def _result(self, ioc: IOC, status: str, **fields: object) -> ThreatIntelResult:
        return ThreatIntelResult(
            provider=self.name,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.normalized_value,
            status=status,  # type: ignore[arg-type]
            source="virustotal_api",
            **fields,
        )


_PROVIDER_SENSITIVE_QUERY_PARAMS = SENSITIVE_QUERY_PARAMS | {"email"}


def _sanitize_url_for_lookup(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("unsupported provider URL")
    # Accessing port validates malformed port values before any request is made.
    parsed.port
    query = [
        (key, item)
        for key, item in parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        if key.lower() not in _PROVIDER_SENSITIVE_QUERY_PARAMS
    ]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def _count(stats: dict[object, object], key: str) -> int:
    value = stats.get(key, 0)
    return value if isinstance(value, int) and value > 0 else 0


def _http_get(request: Request, timeout: float) -> tuple[int, bytes]:
    with urlopen(request, timeout=timeout) as response:  # nosec B310 - fixed VirusTotal API host
        return int(response.status), response.read()
