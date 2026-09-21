from __future__ import annotations

import json
from urllib.error import HTTPError

from src.phishlens.config import AbuseIPDBConfig
from src.phishlens.enrichment.abuseipdb import AbuseIPDBProvider
from src.phishlens.models.ioc import IOC
from src.phishlens.pipeline.analyzer import Analyzer


SECRET = "offline-abuseipdb-key"


def ip_ioc(value="192.0.2.1"):
    return IOC("ip", value, value, "test")


def provider(http_get):
    return AbuseIPDBProvider(AbuseIPDBConfig(api_key=SECRET), http_get=http_get)


def payload(score=0, reports=0):
    return json.dumps({"data": {"ipAddress": "192.0.2.1", "abuseConfidenceScore": score, "totalReports": reports}}).encode()


def test_missing_api_key_is_unavailable_without_http():
    calls = []
    adapter = AbuseIPDBProvider(AbuseIPDBConfig(), http_get=lambda *args: calls.append(args))
    result = adapter.lookup_ip(ip_ioc())
    assert result.status == "unavailable"
    assert result.error == "missing_api_key"
    assert calls == []


def test_successful_no_match():
    result = provider(lambda request, timeout: (200, payload())).lookup_ip(ip_ioc())
    assert result.status == "no_match"
    assert result.disposition == "clean"
    assert result.reputation == "clean"


def test_successful_match_is_malicious_when_confidence_is_high():
    result = provider(lambda request, timeout: (200, payload(score=95, reports=4))).lookup_ip(ip_ioc())
    assert result.status == "match"
    assert result.disposition == "malicious"
    assert result.confidence == "high"
    assert "abuseConfidenceScore" in result.observed_indicators


def test_suspicious_abusive_result_normalization():
    result = provider(lambda request, timeout: (200, payload(score=25, reports=1))).lookup_ip(ip_ioc())
    assert result.status == "match"
    assert result.disposition == "suspicious"
    assert result.confidence == "medium"


def test_timeout():
    def timeout(request, seconds):
        raise TimeoutError()
    assert provider(timeout).lookup_ip(ip_ioc()).status == "timeout"


def test_http_429_is_rate_limited():
    result = provider(lambda request, timeout: (429, b"{}")).lookup_ip(ip_ioc())
    assert result.status == "rate_limited"


def test_http_401_and_403_are_authentication_unavailable():
    for status in (401, 403):
        result = provider(lambda request, timeout, status=status: (status, b"{}")).lookup_ip(ip_ioc())
        assert result.status == "unavailable"
        assert result.error == "authentication_failed"


def test_other_http_error_is_error():
    result = provider(lambda request, timeout: (500, b"{}")).lookup_ip(ip_ioc())
    assert result.status == "error"
    assert result.error == "http_500"


def test_http_exception_429_is_rate_limited():
    def limited(request, timeout):
        raise HTTPError(request.full_url, 429, "rate", {}, None)
    assert provider(limited).lookup_ip(ip_ioc()).status == "rate_limited"


def test_malformed_response_is_explicit():
    malformed = provider(lambda request, timeout: (200, b"not-json")).lookup_ip(ip_ioc())
    assert malformed.status == "error"
    assert malformed.error == "malformed_json"
    incomplete = provider(lambda request, timeout: (200, b'{"data": {}}')).lookup_ip(ip_ioc())
    assert incomplete.status == "partial"


def test_unsupported_ioc_types_make_no_http_request():
    calls = []
    adapter = provider(lambda request, timeout: calls.append(request))
    for kind in ("domain", "url", "hash"):
        result = getattr(adapter, f"lookup_{kind}")(IOC(kind, "value", "value", "test"))
        assert result.status == "unavailable"
        assert result.error == "unsupported_ioc_type"
    assert calls == []


def test_secret_redaction():
    adapter = provider(lambda request, timeout: (200, payload()))
    result = adapter.lookup_ip(ip_ioc())
    assert SECRET not in repr(adapter)
    assert SECRET not in repr(result)
    assert SECRET not in json.dumps(result.to_safe_dict())


def test_configured_abuseipdb_provider_is_selected_and_offline_mocked(monkeypatch):
    monkeypatch.setenv("PHISHLENS_ABUSEIPDB_API_KEY", SECRET)
    monkeypatch.delenv("PHISHLENS_VT_API_KEY", raising=False)
    monkeypatch.setattr(
        "src.phishlens.enrichment.abuseipdb._http_get",
        lambda request, timeout: (200, payload(score=1, reports=1)),
    )
    analyzer = Analyzer()
    assert [provider.name for provider in analyzer.enrichment.providers] == ["abuseipdb"]
    result = analyzer.analyze(b"From: sender@example.com\n\nHello")
    assert len(result.threat_intelligence) == 1
    assert result.threat_intelligence[0].status == "unavailable"
    assert result.threat_intelligence[0].error == "unsupported_ioc_type"
    # The message has no extracted IP, so no AbuseIPDB IP request is made.
    # Existing missing-authentication semantics still produce UNRESOLVED.
    assert result.verdict.final == "UNRESOLVED"


def test_abuseipdb_evidence_does_not_change_deterministic_verdict(monkeypatch):
    raw = b"From: sender@example.com\n\nVisit http://192.0.2.1/login"
    baseline = Analyzer().analyze(raw)
    adapter = provider(lambda request, timeout: (200, payload(score=95, reports=10)))
    configured = Analyzer(providers=[adapter]).analyze(raw)
    assert configured.scoring.to_dict() == baseline.scoring.to_dict()
    assert configured.verdict.to_dict() == baseline.verdict.to_dict()
    assert configured.verdict.final != "MALICIOUS"
