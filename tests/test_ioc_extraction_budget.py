from __future__ import annotations

import pytest

from src.phishlens.config import Settings, ThreatIntelConfig
from src.phishlens.enrichment.mock_provider import MockThreatIntelProvider
from src.phishlens.extractor.ioc_extractor import IOCExtractionLimits, extract_iocs
from src.phishlens.models.ioc import IOC
from src.phishlens.parsing.eml_parser import parse_eml_bytes
from src.phishlens.analysis.url_analysis import extract_urls
from src.phishlens.pipeline.analyzer import Analyzer


def urls_email(count: int) -> bytes:
    urls = "\n".join(
        f"https://host{i:05d}.example.com/p{i}"
        for i in range(count)
    )

    return (
        b"From: sender@example.com\n"
        b"To: victim@example.com\n"
        b"\n"
        + urls.encode()
    )


def clean_trusted_email(count: int = 3) -> bytes:
    urls = "\n".join(
        f"https://host{i:05d}.example.com/path"
        for i in range(count)
    )

    return (
        b"From: sender@example.com\n"
        b"To: victim@example.com\n"
        b"Authentication-Results: mx.example.com; "
        b"spf=pass smtp.mailfrom=example.com; "
        b"dkim=pass header.d=example.com; "
        b"dmarc=pass header.from=example.com\n"
        b"\n"
        + urls.encode()
    )


def test_extract_iocs_below_limit_returns_all_keys():
    email = parse_eml_bytes(urls_email(2))

    limits = IOCExtractionLimits(max_iocs=10)
    iocs = extract_iocs(email, extract_urls(email), limits=limits)

    assert len(iocs) == 5
    assert limits.truncated is False


def test_extract_iocs_exact_limit_is_not_truncated():
    email = parse_eml_bytes(urls_email(2))

    limits = IOCExtractionLimits(max_iocs=5)
    iocs = extract_iocs(email, extract_urls(email), limits=limits)

    assert len(iocs) == 5
    assert limits.truncated is False


def test_extract_iocs_above_limit_truncates_in_extraction_order():
    email = parse_eml_bytes(urls_email(3))

    limits = IOCExtractionLimits(max_iocs=5)
    iocs = extract_iocs(email, extract_urls(email), limits=limits)

    assert [(ioc.ioc_type, ioc.normalized_value) for ioc in iocs] == [
        ("url", "https://host00000.example.com/p0"),
        ("domain", "host00000.example.com"),
        ("url", "https://host00001.example.com/p1"),
        ("domain", "host00001.example.com"),
        ("url", "https://host00002.example.com/p2"),
    ]
    assert limits.truncated is True


def test_truncation_is_partial_and_prevents_clean_but_high_cap_stays_clean():
    raw = clean_trusted_email()

    full = Analyzer(
        Settings(
            auth_results_mode="trusted_ingress",
            trusted_authserv_id="mx.example.com",
        )
    ).analyze(raw)

    capped = Analyzer(
        Settings(
            max_iocs_per_email=5,
            auth_results_mode="trusted_ingress",
            trusted_authserv_id="mx.example.com",
        )
    ).analyze(raw)

    assert full.verdict.final == "CLEAN"
    assert full.completeness.areas["ioc_extraction"].status == "complete"

    assert capped.completeness.areas["ioc_extraction"].status == "partial"
    assert capped.completeness.areas["ioc_extraction"].required is True
    assert capped.completeness.areas["url"].status == "complete"
    assert capped.completeness.overall_status == "partial"
    assert capped.verdict.final == "UNRESOLVED"


def test_unparsed_email_reports_ioc_extraction_not_evaluable():
    result = Analyzer(Settings(max_email_bytes=32)).analyze(
        b"From: sender@example.com\n\n" + b"A" * 100
    )

    assert result.completeness.areas["ioc_extraction"].status == "not_evaluable"
    assert result.verdict.final == "UNRESOLVED"


def test_provider_enrichment_bounded_after_ioc_truncation():
    provider = MockThreatIntelProvider()

    result = Analyzer(
        Settings(max_iocs_per_email=4),
        providers=[provider],
    ).analyze(urls_email(7))

    assert len(result.iocs) == 4
    assert len(provider.calls) == 4
    assert len(result.threat_intelligence) == 4
    assert result.completeness.areas["ioc_extraction"].status == "partial"


def test_ioc_truncation_and_ti_request_budget_compose():
    provider = MockThreatIntelProvider()

    settings = Settings(
        max_iocs_per_email=4,
        threat_intelligence=ThreatIntelConfig(
            max_requests_per_email=3,
        ),
    )

    result = Analyzer(settings, providers=[provider]).analyze(urls_email(7))

    assert len(result.iocs) == 4
    assert len(provider.calls) == 3
    assert len(result.threat_intelligence) == 4
    assert sum(
        item.status == "budget_exhausted"
        for item in result.threat_intelligence
    ) == 1


def test_extract_iocs_return_contract_is_unchanged_for_direct_callers():
    email = parse_eml_bytes(urls_email(1))

    iocs = extract_iocs(email, extract_urls(email))

    assert isinstance(iocs, list)
    assert all(isinstance(ioc, IOC) for ioc in iocs)


def test_extract_iocs_without_limits_keeps_unbounded_legacy_behavior():
    email = parse_eml_bytes(urls_email(3))

    without_limits = extract_iocs(email, extract_urls(email))
    with_empty_limits = extract_iocs(
        email,
        extract_urls(email),
        limits=IOCExtractionLimits(),
    )

    assert len(without_limits) == 7
    assert len(with_empty_limits) == 7


def test_duplicates_after_limit_still_merge_provenance():
    raw = (
        b"From: sender@example.com\n"
        b"To: victim@example.net\n"
        b"\n"
        b"https://example.com/one\n"
        b"https://host2.example.com/two\n"
    )

    email = parse_eml_bytes(raw)
    limits = IOCExtractionLimits(max_iocs=3)

    iocs = extract_iocs(email, extract_urls(email), limits=limits)

    example_domain = next(
        ioc for ioc in iocs
        if ioc.ioc_type == "domain"
        and ioc.normalized_value == "example.com"
    )

    assert "from_address" in example_domain.provenance.get("sources", [])
    assert limits.truncated is True
    assert len(iocs) == 3


@pytest.mark.parametrize("value", [0, -1, "3", 1.5, True])
def test_ioc_extraction_limits_rejects_invalid_values(value):
    with pytest.raises(ValueError):
        IOCExtractionLimits(max_iocs=value)


@pytest.mark.parametrize("value", [1, None])
def test_ioc_extraction_limits_accepts_valid_values(value):
    limits = IOCExtractionLimits(max_iocs=value)
    assert limits.max_iocs == value


def test_settings_max_iocs_uses_env_with_house_fallback(monkeypatch):
    monkeypatch.delenv("PHISHLENS_MAX_IOCS_PER_EMAIL", raising=False)
    assert Settings().max_iocs_per_email == 50_000

    monkeypatch.setenv("PHISHLENS_MAX_IOCS_PER_EMAIL", "7")
    assert Settings().max_iocs_per_email == 7

    for value in ("0", "-3", "abc", "1.5", ""):
        monkeypatch.setenv("PHISHLENS_MAX_IOCS_PER_EMAIL", value)
        assert Settings().max_iocs_per_email == 50_000

    monkeypatch.delenv("PHISHLENS_MAX_IOCS_PER_EMAIL", raising=False)
    assert Settings(max_iocs_per_email=9).max_iocs_per_email == 9

    monkeypatch.setenv("PHISHLENS_MAX_IOCS_PER_EMAIL", "7")
    assert Settings(max_iocs_per_email=9).max_iocs_per_email == 7


def test_default_limit_bounds_hostile_email():
    raw = urls_email(60_000)

    result = Analyzer().analyze(raw)

    assert len(result.iocs) == 50_000
    assert result.completeness.areas["ioc_extraction"].status == "partial"
    assert result.completeness.areas["url"].status == "partial"
    assert result.verdict.final != "CLEAN"

