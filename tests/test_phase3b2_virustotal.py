from __future__ import annotations

import base64
import json
from urllib.error import HTTPError
from urllib.parse import unquote, urlsplit

from src.phishlens.config import VirusTotalConfig
from src.phishlens.enrichment.virustotal import VirusTotalProvider
from src.phishlens.models.ioc import IOC
from src.phishlens.pipeline.analyzer import Analyzer


SECRET = "offline-test-vt-key"


def ioc(kind: str, value: str) -> IOC:
    return IOC(kind, value, value, "test")


def provider(http_get):
    return VirusTotalProvider(VirusTotalConfig(api_key=SECRET), http_get=http_get)


def response(stats: dict[str, int]) -> bytes:
    return json.dumps({"data": {"attributes": {"last_analysis_stats": stats}}}).encode()


def requested_url_value(request) -> str:
    encoded = unquote(urlsplit(request.full_url).path.rsplit("/", 1)[-1])
    return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode()


def test_missing_api_key_is_unavailable_without_http():
    calls = []
    adapter = VirusTotalProvider(VirusTotalConfig(), http_get=lambda *args: calls.append(args))
    result = adapter.lookup_ip(ioc("ip", "192.0.2.1"))
    assert result.status == "unavailable"
    assert result.error == "missing_api_key"
    assert calls == []


def test_successful_no_match():
    adapter = provider(lambda request, timeout: (200, response({"harmless": 10, "malicious": 0, "suspicious": 0})))
    result = adapter.lookup_ip(ioc("ip", "192.0.2.1"))
    assert result.status == "no_match"
    assert result.reputation == "clean"


def test_successful_match():
    adapter = provider(lambda request, timeout: (200, response({"harmless": 2, "malicious": 3, "suspicious": 1})))
    result = adapter.lookup_domain(ioc("domain", "bad.example"))
    assert result.status == "match"
    assert result.disposition == "malicious"
    assert result.confidence == "high"
    assert "malicious" in result.observed_indicators


def test_timeout():
    def timeout(request, seconds):
        raise TimeoutError()
    result = provider(timeout).lookup_hash(ioc("hash", "a" * 64))
    assert result.status == "timeout"


def test_http_429_is_rate_limited():
    result = provider(lambda request, timeout: (429, b"{}")).lookup_ip(ioc("ip", "192.0.2.1"))
    assert result.status == "rate_limited"


def test_http_401_and_403_are_authentication_unavailable():
    for status in (401, 403):
        result = provider(lambda request, timeout, status=status: (status, b"{}" )).lookup_ip(ioc("ip", "192.0.2.1"))
        assert result.status == "unavailable"
        assert result.error == "authentication_failed"


def test_other_http_error_is_error():
    result = provider(lambda request, timeout: (500, b"{}" )).lookup_ip(ioc("ip", "192.0.2.1"))
    assert result.status == "error"
    assert result.error == "http_500"


def test_http_exception_statuses_are_normalized():
    def denied(request, timeout):
        raise HTTPError(request.full_url, 429, "rate", {}, None)
    assert provider(denied).lookup_ip(ioc("ip", "192.0.2.1")).status == "rate_limited"


def test_malformed_json_is_error():
    result = provider(lambda request, timeout: (200, b"not-json")).lookup_ip(ioc("ip", "192.0.2.1"))
    assert result.status == "error"
    assert result.error == "malformed_json"


def test_unsupported_ioc_type_is_not_requested():
    calls = []
    adapter = provider(lambda request, timeout: calls.append(request))
    result = adapter.lookup_ip(ioc("attachment", "file.bin"))
    assert result.status == "unavailable"
    assert result.error == "unsupported_ioc_type"
    assert calls == []


def test_secret_redaction():
    adapter = provider(lambda request, timeout: (200, response({"malicious": 0})))
    result = adapter.lookup_ip(ioc("ip", "192.0.2.1"))
    assert SECRET not in repr(adapter)
    assert SECRET not in repr(result)
    assert SECRET not in json.dumps(result.to_safe_dict())


def test_deterministic_scoring_is_unchanged():
    raw = b"From: sender@example.com\n\nVisit http://192.0.2.1/login"
    baseline = Analyzer().analyze(raw)
    adapter = provider(lambda request, timeout: (200, response({"malicious": 1})))
    with_provider = Analyzer(providers=[adapter]).analyze(raw)
    assert with_provider.scoring.to_dict() == baseline.scoring.to_dict()
    assert with_provider.verdict.to_dict() == baseline.verdict.to_dict()


def test_hash_lookup_does_not_upload_attachment():
    requests = []
    adapter = provider(lambda request, timeout: (404, requests.append(request) or b"{}"))
    result = adapter.lookup_hash(ioc("hash", "a" * 64))
    assert result.status == "no_match"
    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert requests[0].data is None
    assert "/files/" in requests[0].full_url


def test_url_lookup_sanitizes_sensitive_query_values_for_virustotal():
    requests = []
    adapter = provider(lambda request, timeout: (404, requests.append(request) or b"{}"))
    target = "https://example.test/path?token=top-secret&email=user@example.com&campaign=spring"
    result = adapter.lookup_url(ioc("url", target))

    assert result.status == "no_match"
    assert result.ioc_value == target
    assert len(requests) == 1
    request = requests[0]
    provider_url = requested_url_value(request)
    assert request.full_url.startswith("https://www.virustotal.com/api/v3/urls/")
    assert provider_url == "https://example.test/path?campaign=spring"
    assert "top-secret" not in request.full_url
    assert "user@example.com" not in request.full_url
    assert "top-secret" not in provider_url
    assert "user@example.com" not in provider_url


def test_pipeline_keeps_local_url_ioc_while_provider_receives_sanitized_url():
    requests = []
    adapter = provider(lambda request, timeout: (404, requests.append(request) or b"{}"))
    target = "https://example.test/reset?token=local-secret&email=analyst@example.com&source=mail"
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n"
        + target.encode()
    )

    result = Analyzer(providers=[adapter]).analyze(raw)
    local_url = next(item for item in result.iocs if item.ioc_type == "url")
    url_request = next(request for request in requests if "/urls/" in request.full_url)

    assert local_url.normalized_value == target
    assert requested_url_value(url_request) == "https://example.test/reset?source=mail"
    assert "local-secret" not in url_request.full_url
    assert "analyst@example.com" not in url_request.full_url


def test_url_sanitization_failure_prevents_http(monkeypatch):
    calls = []
    adapter = provider(lambda request, timeout: calls.append(request))

    def fail_sanitization(value):
        raise ValueError("unsafe URL")

    monkeypatch.setattr("src.phishlens.enrichment.virustotal._sanitize_url_for_lookup", fail_sanitization)
    target = "https://example.test/reset?token=must-not-leave"
    result = adapter.lookup_url(ioc("url", target))

    assert result.status == "unavailable"
    assert result.error == "url_sanitization_failed"
    assert result.ioc_value == target
    assert calls == []
