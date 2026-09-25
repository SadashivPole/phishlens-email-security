import pytest

from src.phishlens.enrichment.mock_provider import MockThreatIntelProvider
from src.phishlens.enrichment.orchestrator import EnrichmentOrchestrator
from src.phishlens.models.ioc import IOC
from src.phishlens.pipeline.analyzer import Analyzer


def _domains(count: int):
    return [
        IOC(
            "domain",
            f"bad{i:04d}.example",
            f"bad{i:04d}.example",
            "test",
        )
        for i in range(count)
    ]


def test_1000_iocs_one_provider_capped_at_budget():
    provider = MockThreatIntelProvider()
    iocs = _domains(1000)

    results = EnrichmentOrchestrator(
        [provider],
        max_requests=50,
    ).enrich(iocs)

    assert len(provider.calls) == 50
    assert len(results) == 1000
    assert sum(r.status == "no_match" for r in results) == 50
    assert sum(r.status == "budget_exhausted" for r in results) == 950
    assert results[50].status == "budget_exhausted"


def test_two_providers_share_one_global_budget():
    provider1 = MockThreatIntelProvider()
    provider2 = MockThreatIntelProvider()

    results = EnrichmentOrchestrator(
        [provider1, provider2],
        max_requests=3,
    ).enrich(_domains(3))

    assert len(provider1.calls) + len(provider2.calls) == 3
    assert len(results) == 6
    assert sum(r.status == "budget_exhausted" for r in results) == 3


def test_budget_exactly_exhausted_has_no_budget_exhausted_results():
    provider = MockThreatIntelProvider()

    results = EnrichmentOrchestrator(
        [provider],
        max_requests=4,
    ).enrich(_domains(4))

    assert len(provider.calls) == 4
    assert all(r.status == "no_match" for r in results)


def test_one_request_beyond_budget_never_calls_provider():
    provider = MockThreatIntelProvider()
    iocs = _domains(5)

    results = EnrichmentOrchestrator(
        [provider],
        max_requests=4,
    ).enrich(iocs)

    assert len(provider.calls) == 4
    assert all(r.status == "no_match" for r in results[:4])
    assert results[4].status == "budget_exhausted"
    assert results[4].ioc_value == iocs[4].normalized_value
    assert iocs[4].key() not in provider.calls


def test_failed_lookup_consumes_budget_and_is_not_refunded():
    class FailingProvider:
        name = "failing"

        def lookup_domain(self, ioc):
            raise TimeoutError()

    provider = FailingProvider()
    results = EnrichmentOrchestrator(
        [provider],
        max_requests=2,
    ).enrich(_domains(3))

    assert [r.status for r in results] == [
        "timeout",
        "timeout",
        "budget_exhausted",
    ]


def test_no_providers_preserves_not_attempted_behavior(monkeypatch):
    monkeypatch.setenv("PHISHLENS_TI_MAX_REQUESTS_PER_EMAIL", "5")
    monkeypatch.delenv("PHISHLENS_VT_API_KEY", raising=False)
    monkeypatch.delenv("PHISHLENS_ABUSEIPDB_API_KEY", raising=False)

    iocs = _domains(3)

    results = EnrichmentOrchestrator(
        [],
        max_requests=5,
    ).enrich(iocs)

    assert all(
        result.status == "not_attempted"
        and result.provider == "none"
        and result.source == "enrichment_disabled"
        for result in results
    )

    raw = (
        b"From: sender@example.com\n"
        b"To: victim@example.net\n"
        b"\n"
        b"body"
    )

    analyzer = Analyzer(providers=[])
    result = analyzer.analyze(raw)

    assert analyzer.enrichment.providers == []
    assert all(item.status == "not_attempted" for item in result.threat_intelligence)
    assert result.completeness.areas["threat_intelligence"].status == "not_evaluable"

def test_extractor_dedup_means_duplicate_urls_cost_one_request():
    raw = (
        b"From: sender@example.com\n"
        b"\n"
        + b"\n".join([b"https://example.com/p/0"] * 100)
    )

    provider = MockThreatIntelProvider()
    result = Analyzer(providers=[provider]).analyze(raw)

    url_iocs = [
        ioc for ioc in result.iocs
        if ioc.ioc_type == "url"
        and ioc.normalized_value == "https://example.com/p/0"
    ]

    url_calls = [
        call for call in provider.calls
        if call[0] == "url"
        and call[1] == "https://example.com/p/0"
    ]

    assert len(url_iocs) == 1
    assert len(url_calls) == 1


def test_budget_configuration_boundaries(monkeypatch):
    from src.phishlens.config import (
        DEFAULT_TI_MAX_REQUESTS_PER_EMAIL,
        ThreatIntelConfig,
    )

    env_name = "PHISHLENS_TI_MAX_REQUESTS_PER_EMAIL"

    for raw, expected in [
        ("1", 1),
        ("50", 50),
        ("1000", 1000),
    ]:
        monkeypatch.setenv(env_name, raw)
        assert (
            ThreatIntelConfig.from_environment().max_requests_per_email
            == expected
        )

    for raw in ["0", "-5", "abc", "2.5", " ", ""]:
        monkeypatch.setenv(env_name, raw)
        assert (
            ThreatIntelConfig.from_environment().max_requests_per_email
            == DEFAULT_TI_MAX_REQUESTS_PER_EMAIL
        )

    monkeypatch.delenv(env_name, raising=False)

    assert (
        ThreatIntelConfig.from_environment().max_requests_per_email
        == DEFAULT_TI_MAX_REQUESTS_PER_EMAIL
    )
    assert DEFAULT_TI_MAX_REQUESTS_PER_EMAIL == 50
    assert (
        ThreatIntelConfig().safe_dict()["max_requests_per_email"] == 50
    )


def test_constructor_rejects_invalid_max_requests():
    for bad in [0, -1, 2.5, "10"]:
        with pytest.raises(ValueError):
            EnrichmentOrchestrator([], max_requests=bad)

    assert EnrichmentOrchestrator([]).max_requests is None


def test_budget_resets_for_each_email(monkeypatch):
    monkeypatch.setenv(
        "PHISHLENS_TI_MAX_REQUESTS_PER_EMAIL",
        "50",
    )

    def make_email(count: int) -> bytes:
        body = "\n".join(
            f"https://example.com/p/{i}"
            for i in range(count)
        )
        return (
            b"From: sender@example.com\n"
            b"To: victim@example.net\n"
            b"\n"
            + body.encode()
        )

    provider = MockThreatIntelProvider()
    analyzer = Analyzer(providers=[provider])

    first = analyzer.analyze(make_email(100))

    assert len(provider.calls) == 50
    assert any(
        item.status == "budget_exhausted"
        for item in first.threat_intelligence
    )

    provider.calls.clear()

    second = analyzer.analyze(make_email(10))

    assert 10 <= len(provider.calls) <= 50
    assert all(
        item.status != "budget_exhausted"
        for item in second.threat_intelligence
    )


def test_offline_mode_preserves_no_provider_behavior(monkeypatch):
    monkeypatch.delenv("PHISHLENS_VT_API_KEY", raising=False)
    monkeypatch.delenv("PHISHLENS_ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setenv(
        "PHISHLENS_TI_MAX_REQUESTS_PER_EMAIL",
        "1",
    )

    analyzer = Analyzer()
    result = analyzer.analyze(
        b"From: sender@example.com\n"
        b"To: victim@example.net\n"
        b"\n"
        b"https://example.com/a\n"
        b"https://example.com/b\n"
    )

    assert analyzer.enrichment.providers == []
    assert all(
        item.status == "not_attempted"
        for item in result.threat_intelligence
    )
    assert (
        result.completeness.areas["threat_intelligence"].status
        == "not_evaluable"
    )

def test_budget_exhaustion_preserves_score_verdict_and_completeness(monkeypatch):
    def make_email(count: int) -> bytes:
        body = "\n".join(
            f"https://example.com/p/{i}"
            for i in range(count)
        )
        return (
            b"From: sender@example.com\n"
            b"To: victim@example.net\n"
            b"\n"
            + body.encode()
        )

    raw = make_email(200)

    monkeypatch.setenv(
        "PHISHLENS_TI_MAX_REQUESTS_PER_EMAIL",
        "10000",
    )
    unlimited = Analyzer(
        providers=[MockThreatIntelProvider()]
    ).analyze(raw)

    monkeypatch.setenv(
        "PHISHLENS_TI_MAX_REQUESTS_PER_EMAIL",
        "50",
    )
    budget_provider = MockThreatIntelProvider()
    budgeted = Analyzer(
        providers=[budget_provider]
    ).analyze(raw)

    assert len(budget_provider.calls) == 50
    assert any(
        item.status == "budget_exhausted"
        for item in budgeted.threat_intelligence
    )

    assert (
        budgeted.scoring.to_dict()
        == unlimited.scoring.to_dict()
    )
    assert (
        budgeted.verdict.to_dict()
        == unlimited.verdict.to_dict()
    )
    assert (
        budgeted.completeness.to_dict()
        == unlimited.completeness.to_dict()
    )


def test_match_within_budget_preserves_score_and_verdict(monkeypatch):
    def make_email(count: int) -> bytes:
        body = "\n".join(
            f"https://example.com/p/{i}"
            for i in range(count)
        )
        return (
            b"From: sender@example.com\n"
            b"To: victim@example.net\n"
            b"\n"
            + body.encode()
        )

    raw = make_email(100)

    outcomes = {
        ("domain", "example.com"): "match",
    }

    monkeypatch.setenv(
        "PHISHLENS_TI_MAX_REQUESTS_PER_EMAIL",
        "10000",
    )
    unlimited = Analyzer(
        providers=[MockThreatIntelProvider(outcomes)]
    ).analyze(raw)

    monkeypatch.setenv(
        "PHISHLENS_TI_MAX_REQUESTS_PER_EMAIL",
        "50",
    )
    budgeted = Analyzer(
        providers=[MockThreatIntelProvider(outcomes)]
    ).analyze(raw)

    assert (
        budgeted.scoring.to_dict()
        == unlimited.scoring.to_dict()
    )
    assert (
        budgeted.verdict.to_dict()
        == unlimited.verdict.to_dict()
    )

def test_real_virustotal_adapter_respects_global_http_budget(monkeypatch):
    import src.phishlens.enrichment.virustotal as vt_module

    monkeypatch.setenv(
        "PHISHLENS_VT_API_KEY",
        "offline-test-key",
    )
    monkeypatch.delenv(
        "PHISHLENS_ABUSEIPDB_API_KEY",
        raising=False,
    )
    monkeypatch.setenv(
        "PHISHLENS_TI_MAX_REQUESTS_PER_EMAIL",
        "2",
    )

    http_calls = []

    def fake_http_get(request, timeout):
        http_calls.append(request.full_url)
        return 404, b"{}"

    monkeypatch.setattr(
        vt_module,
        "_http_get",
        fake_http_get,
    )

    raw = (
        b"From: sender@example.com\n"
        b"To: victim@example.net\n"
        b"\n"
        b"https://example.com/a\n"
        b"https://example.com/b\n"
        b"https://example.com/c\n"
    )

    result = Analyzer().analyze(raw)

    assert len(http_calls) == 2
    assert all(
        url.startswith(
            "https://www.virustotal.com/api/v3/"
        )
        for url in http_calls
    )
    assert any(
        item.status == "budget_exhausted"
        for item in result.threat_intelligence
    )
    assert len(result.threat_intelligence) == len(result.iocs)

def test_budget_preserves_multi_provider_result_cardinality():
    provider1 = MockThreatIntelProvider()
    provider2 = MockThreatIntelProvider()

    iocs = _domains(4)

    results = EnrichmentOrchestrator(
        [provider1, provider2],
        max_requests=3,
    ).enrich(iocs)

    assert len(results) == 8
    assert len(provider1.calls) + len(provider2.calls) == 3
    assert sum(
        result.status == "budget_exhausted"
        for result in results
    ) == 5
