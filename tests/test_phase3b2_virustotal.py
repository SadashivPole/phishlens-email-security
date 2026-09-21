from __future__ import annotations

import base64
import json
from urllib.error import HTTPError

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


def test_url_lookup_uses_fixed_virustotal_api_not_arbitrary_url():
    requests = []
    adapter = provider(lambda request, timeout: (404, requests.append(request) or b"{}"))
    target = "https://example.test/path?token=do-not-fetch"
    result = adapter.lookup_url(ioc("url", target))
    assert result.status == "no_match"
    request = requests[0]
    expected_id = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
    assert request.full_url.startswith("https://www.virustotal.com/api/v3/urls/")
    assert expected_id in request.full_url
    assert target not in request.full_url
