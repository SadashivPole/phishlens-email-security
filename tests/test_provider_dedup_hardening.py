from src.phishlens.enrichment.mock_provider import MockThreatIntelProvider
from src.phishlens.enrichment.orchestrator import EnrichmentOrchestrator
from src.phishlens.models.ioc import IOC
from src.phishlens.pipeline.analyzer import Analyzer


def test_duplicate_raw_occurrences_deduplicate_before_provider_lookup():
    raw = (
        b"From: sender@example.com\n"
        b"To: victim@example.net\n"
        b"\n"
        + b"\n".join(
            [b"https://example.com/p/0"] * 1000
        )
    )

    provider = MockThreatIntelProvider()
    result = Analyzer(providers=[provider]).analyze(raw)

    keys = {
        (ioc.ioc_type, ioc.normalized_value)
        for ioc in result.iocs
    }

    calls = set(provider.calls)

    assert ("url", "https://example.com/p/0") in keys
    assert ("domain", "example.com") in keys

    assert len(calls) == len(keys)
    assert len([
        call for call in provider.calls
        if call == ("url", "https://example.com/p/0")
    ]) == 1


def test_equivalent_url_representations_follow_documented_normalization():
    raw = (
        b"From: sender@example.com\n"
        b"\n"
        b"https://example.com/?a=1&b=2\n"
        b"https://example.com/?b=2&a=1\n"
        b"https://example.com/Login\n"
        b"https://example.com/login\n"
        b"https://example.com/%6Cogin\n"
        b"https://example.com./\n"
    )

    provider = MockThreatIntelProvider()
    result = Analyzer(providers=[provider]).analyze(raw)

    url_iocs = {
        ioc.normalized_value
        for ioc in result.iocs
        if ioc.ioc_type == "url"
    }

    assert "https://example.com/?a=1&b=2" in url_iocs
    assert "https://example.com/?b=2&a=1" in url_iocs
    assert "https://example.com/Login" in url_iocs
    assert "https://example.com/login" in url_iocs
    assert "https://example.com/%6Cogin" in url_iocs
    assert "https://example.com./" in url_iocs

    url_calls = [
        call for call in provider.calls
        if call[0] == "url"
    ]

    assert len(url_calls) == len(url_iocs)


def test_duplicate_received_occurrences_deduplicate_before_provider_lookup():
    received = (
        b"Received: from mail.example.com "
        b"[192.0.2.10] by mx.example.net; "
        b"Thu, 25 Sep 2025 10:00:00 +0000\n"
    )

    raw = (
        b"From: sender@example.com\n"
        b"To: victim@example.net\n"
        + received * 1000
        + b"\n"
        + b"body"
    )

    provider = MockThreatIntelProvider()
    result = Analyzer(providers=[provider]).analyze(raw)

    keys = {
        (ioc.ioc_type, ioc.normalized_value)
        for ioc in result.iocs
    }

    calls = set(provider.calls)

    assert len(calls) == len(keys)
    assert len(provider.calls) == len(calls)

