from __future__ import annotations

import json

from src.phishlens.enrichment.virustotal import VirusTotalProvider
from src.phishlens.pipeline.analyzer import Analyzer


VT_ENV = "PHISHLENS_VT_API_KEY"
RAW = b"From: sender@example.com\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nVisit http://192.0.2.1/login"


def vt_response(stats: dict[str, int]) -> bytes:
    return json.dumps({"data": {"attributes": {"last_analysis_stats": stats}}}).encode()


def test_no_api_key_keeps_provider_path_disabled(monkeypatch):
    monkeypatch.delenv(VT_ENV, raising=False)
    analyzer = Analyzer()
    assert analyzer.enrichment.providers == []
    result = analyzer.analyze(RAW)
    assert all(item.status == "not_attempted" for item in result.threat_intelligence)


def test_api_key_selects_virustotal_provider(monkeypatch):
    monkeypatch.setenv(VT_ENV, "offline-test-key")
    monkeypatch.setattr(
        "src.phishlens.enrichment.virustotal._http_get",
        lambda request, timeout: (200, vt_response({"malicious": 0, "harmless": 1})),
    )
    analyzer = Analyzer()
    assert len(analyzer.enrichment.providers) == 1
    assert isinstance(analyzer.enrichment.providers[0], VirusTotalProvider)


def test_provider_result_is_in_analysis_result(monkeypatch):
    monkeypatch.setenv(VT_ENV, "offline-test-key")
    monkeypatch.setattr(
        "src.phishlens.enrichment.virustotal._http_get",
        lambda request, timeout: (200, vt_response({"malicious": 1})),
    )
    result = Analyzer().analyze(RAW)
    assert len(result.threat_intelligence) == len(result.iocs) == 3
    assert {item.status for item in result.threat_intelligence} == {"match"}
    assert any(item.provider == "virustotal" and item.status == "match" for item in result.threat_intelligence)


def test_provider_does_not_change_deterministic_scoring_or_verdict(monkeypatch):
    monkeypatch.delenv(VT_ENV, raising=False)
    baseline = Analyzer().analyze(RAW)
    monkeypatch.setenv(VT_ENV, "offline-test-key")
    monkeypatch.setattr(
        "src.phishlens.enrichment.virustotal._http_get",
        lambda request, timeout: (200, vt_response({"malicious": 100})),
    )
    configured = Analyzer().analyze(RAW)
    assert configured.scoring.to_dict() == baseline.scoring.to_dict()
    assert configured.verdict.to_dict() == baseline.verdict.to_dict()


def test_provider_failure_states_remain_explicit(monkeypatch):
    cases = [
        ("timeout", lambda request, timeout: (_ for _ in ()).throw(TimeoutError())),
        ("rate_limited", lambda request, timeout: (429, b"{}")),
        ("error", lambda request, timeout: (500, b"{}")),
    ]
    for expected, http_get in cases:
        monkeypatch.setenv(VT_ENV, "offline-test-key")
        monkeypatch.setattr("src.phishlens.enrichment.virustotal._http_get", http_get)
        result = Analyzer().analyze(RAW)
        assert {item.status for item in result.threat_intelligence} == {expected}


def test_api_key_is_not_in_analysis_result_or_safe_json(monkeypatch):
    secret = "offline-secret-value"
    monkeypatch.setenv(VT_ENV, secret)
    monkeypatch.setattr(
        "src.phishlens.enrichment.virustotal._http_get",
        lambda request, timeout: (200, vt_response({"harmless": 1})),
    )
    result = Analyzer().analyze(RAW)
    assert secret not in repr(result)
    assert secret not in json.dumps(result.to_safe_dict())
    assert all(secret not in item.ioc_value for item in result.threat_intelligence)


def test_only_virustotal_is_auto_selected(monkeypatch):
    monkeypatch.setenv(VT_ENV, "offline-test-key")
    monkeypatch.setenv("PHISHLENS_ABUSEIPDB_API_KEY", "abuse-key-not-auto-enabled")
    monkeypatch.setattr(
        "src.phishlens.enrichment.virustotal._http_get",
        lambda request, timeout: (404, b"{}"),
    )
    analyzer = Analyzer()
    assert {provider.name for provider in analyzer.enrichment.providers} == {"virustotal", "abuseipdb"}
