from __future__ import annotations

import json

from src.phishlens.enrichment.mock_provider import MockThreatIntelProvider
from src.phishlens.models.ioc import IOC
from src.phishlens.pipeline.analyzer import Analyzer


def test_pipeline_extracts_normalized_deduplicated_iocs_and_disabled_states():
    raw = (
        b"From: Alice <ALICE@Example.COM>\n"
        b"To: bob@example.com\n"
        b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
        b"Received: from Mail.Example.COM [2001:0db8:0:0:0:0:0:1] by mx.example.com; Mon, 01 Jan 2026 10:00:00 +0000\n\n"
        b"Visit https://EXAMPLE.com/path?token=secret and https://example.com/path?token=other"
    )
    result = Analyzer().analyze(raw)
    keys = {(ioc.ioc_type, ioc.normalized_value) for ioc in result.iocs}
    assert ("url", "https://example.com/path?token=secret") in keys
    assert ("domain", "example.com") in keys
    assert ("ip", "2001:db8::1") in keys
    assert len(keys) == len(result.iocs)
    assert result.threat_intelligence
    assert {item.status for item in result.threat_intelligence} == {"not_attempted"}
    assert result.completeness.areas["threat_intelligence"].status == "not_evaluable"
    json.dumps(result.to_safe_dict())
    assert "secret" not in json.dumps(result.to_safe_dict())


def test_mock_provider_match_and_no_match_are_normalized():
    iocs = [IOC("ip", "192.0.2.1", "192.0.2.1", "test")]
    provider = MockThreatIntelProvider({("ip", "192.0.2.1"): "match"})
    results = __import__("src.phishlens.enrichment.orchestrator", fromlist=["EnrichmentOrchestrator"]).EnrichmentOrchestrator([provider]).enrich(iocs)
    assert results[0].status == "match"
    assert results[0].disposition == "malicious"
    assert results[0].provider == "mock"
    assert provider.calls == [("ip", "192.0.2.1")]

    no_match = MockThreatIntelProvider()
    result = __import__("src.phishlens.enrichment.orchestrator", fromlist=["EnrichmentOrchestrator"]).EnrichmentOrchestrator([no_match]).enrich(iocs)[0]
    assert result.status == "no_match"


def test_provider_failures_become_explicit_states():
    class Failing:
        name = "failing"
        def lookup_ip(self, ioc): raise TimeoutError()
        def lookup_domain(self, ioc): raise PermissionError()
        def lookup_url(self, ioc): raise NotImplementedError()
        def lookup_hash(self, ioc): raise ValueError("bad input")

    from src.phishlens.enrichment.orchestrator import EnrichmentOrchestrator
    iocs = [
        IOC("ip", "1.1.1.1", "1.1.1.1", "test"),
        IOC("domain", "example.com", "example.com", "test"),
        IOC("url", "https://example.com", "https://example.com", "test"),
        IOC("hash", "a" * 64, "a" * 64, "test"),
    ]
    results = EnrichmentOrchestrator([Failing()]).enrich(iocs)
    assert [item.status for item in results] == ["timeout", "rate_limited", "unavailable", "error"]
    assert all(item.ioc_value == ioc.normalized_value for item, ioc in zip(results, iocs))


def test_enrichment_does_not_change_deterministic_score():
    raw = b"From: sender@example.com\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nHello"
    disabled = Analyzer().analyze(raw)
    provider = MockThreatIntelProvider()
    enabled = Analyzer(providers=[provider]).analyze(raw)
    assert disabled.scoring.to_dict() == enabled.scoring.to_dict()
    assert enabled.completeness.areas["threat_intelligence"].status == "complete"
