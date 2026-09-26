from src.phishlens.analysis.url_analysis import URLExtractionLimits, extract_urls
from src.phishlens.models.email import ParsedEmail


def email_with_urls(count: int) -> ParsedEmail:
    urls = "\n".join(f"https://host{i}.example/path" for i in range(count))
    return ParsedEmail(raw_size_bytes=len(urls), body_text=urls)


def test_below_limit_returns_all_urls():
    email = email_with_urls(5)

    limits = URLExtractionLimits(max_urls=10)
    urls = extract_urls(email, limits=limits)

    assert len(urls) == 5
    assert limits.truncated is False


def test_exact_limit_is_not_truncated():
    email = email_with_urls(5)

    limits = URLExtractionLimits(max_urls=5)
    urls = extract_urls(email, limits=limits)

    assert len(urls) == 5
    assert limits.truncated is False


def test_above_limit_truncates_in_extraction_order():
    email = email_with_urls(8)

    limits = URLExtractionLimits(max_urls=5)
    urls = extract_urls(email, limits=limits)

    assert len(urls) == 5
    assert limits.truncated is True
    assert [item.normalized_url for item in urls] == [
        "https://host0.example/path",
        "https://host1.example/path",
        "https://host2.example/path",
        "https://host3.example/path",
        "https://host4.example/path",
    ]


def test_duplicate_urls_do_not_consume_limit():
    email = ParsedEmail(
        raw_size_bytes=200,
        body_text=(
            "https://same.example/path "
            "https://same.example/path "
            "https://other.example/path "
            "https://third.example/path"
        ),
    )

    limits = URLExtractionLimits(max_urls=3)
    urls = extract_urls(email, limits=limits)

    assert len(urls) == 3
    assert limits.truncated is False


def test_duplicate_anchor_can_still_update_existing_indicator():
    email = ParsedEmail(
        raw_size_bytes=200,
        body_text="https://same.example/path",
        body_html=(
            '<a href="https://same.example/path">'
            "https://same.example/path"
            "</a>"
        ),
    )

    urls = extract_urls(email, limits=URLExtractionLimits(max_urls=1))

    assert len(urls) == 1
    assert urls[0].context == "html_anchor"
    assert urls[0].display_text == "https://same.example/path"


def test_without_limits_keeps_legacy_unbounded_behavior():
    email = email_with_urls(20)

    without_limits = extract_urls(email)
    with_empty_limits = extract_urls(email, limits=URLExtractionLimits())

    assert len(without_limits) == 20
    assert len(with_empty_limits) == 20


def test_invalid_url_limits_fail_closed():
    for value in (0, -1, True, False, 1.5, "5"):
        try:
            URLExtractionLimits(max_urls=value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Expected ValueError for {value!r}")


def test_analyzer_marks_url_area_partial_when_url_cap_is_hit():
    raw = (
        b"From: sender@example.com\r\n"
        b"To: victim@example.net\r\n"
        b"Subject: URL stress\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        + "\n".join(f"https://host{i}.example/path" for i in range(6)).encode()
    )

    from src.phishlens.config import Settings
    from src.phishlens.pipeline.analyzer import Analyzer

    result = Analyzer(Settings(max_urls_per_email=5)).analyze(raw)

    assert result.completeness.areas["url"].status == "partial"
    assert "capped" in result.completeness.areas["url"].note.lower()
    assert result.verdict.final != "CLEAN"


def test_url_evidence_only_covers_retained_urls():
    from src.phishlens.analysis.url_analysis import url_evidence

    email = ParsedEmail(
        raw_size_bytes=300,
        body_text="\n".join(
            f"https://10.0.0.{i}/path"
            for i in range(6)
        ),
    )

    limits = URLExtractionLimits(max_urls=3)
    urls = extract_urls(email, limits=limits)
    evidence = url_evidence(urls)

    assert len(urls) == 3
    assert limits.truncated is True
    assert len(evidence) == 3
    assert all(item.signal_id == "ip_literal_url" for item in evidence)


def test_none_limit_preserves_existing_api():
    email = email_with_urls(3)

    urls = extract_urls(email, limits=None)

    assert isinstance(urls, list)
    assert len(urls) == 3
