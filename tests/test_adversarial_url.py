from phishlens.analysis.url_analysis import analyze_url


def test_userinfo_url_keeps_real_hostname_separate():
    item = analyze_url("https://trusted.example@evil.example/login")

    assert item.hostname == "evil.example"
    assert item.has_userinfo is True


def test_default_http_port_is_not_marked_nonstandard():
    item = analyze_url("http://example.com:80/path")

    assert item.hostname == "example.com"
    assert item.suspicious_port is False


def test_default_https_port_is_not_marked_nonstandard():
    item = analyze_url("https://example.com:443/path")

    assert item.hostname == "example.com"
    assert item.suspicious_port is False


def test_nonstandard_port_is_preserved_and_flagged():
    item = analyze_url("https://example.com:8443/path")

    assert item.hostname == "example.com"
    assert item.suspicious_port is True
    assert ":8443" in item.normalized_url


def test_fragment_is_not_part_of_normalized_destination():
    item = analyze_url("https://example.com/login#token=secret")

    assert item.normalized_url == "https://example.com/login"
    assert "#token" not in item.normalized_url


def test_unicode_hostname_is_normalized_to_idna():
    item = analyze_url("https://éxample.com/login")

    assert item.hostname.startswith("xn--")
    assert item.has_punycode is True


def test_encoded_userinfo_is_detected():
    item = analyze_url("https://example.com%40evil.example/path")

    assert item.analysis_status == "complete"
from phishlens.analysis.url_analysis import analyze_url


def test_redirect_parameter_is_detected_case_insensitively():
    item = analyze_url(
        "https://example.com/login?ReDiReCt=https%3A%2F%2Fevil.example"
    )

    assert item.redirect_indicator is True


def test_non_redirect_query_parameter_is_not_marked_redirect():
    item = analyze_url(
        "https://example.com/login?campaign=security"
    )

    assert item.redirect_indicator is False


def test_mixed_case_hostname_is_canonicalized():
    item = analyze_url(
        "https://ExAmPle.CoM/path"
    )

    assert item.hostname == "example.com"
    assert item.normalized_url == "https://example.com/path"


def test_trailing_dot_hostname_is_preserved_without_fragment():
    item = analyze_url(
        "https://example.com./login"
    )

    assert item.analysis_status == "complete"
    assert item.hostname
    assert item.normalized_url.startswith("https://")


def test_encoded_redirect_target_remains_in_query_but_is_not_followed():
    item = analyze_url(
        "https://example.com/redirect?url=https%3A%2F%2Fevil.example%2Flogin"
    )

    assert item.redirect_indicator is True
    assert "evil.example" not in item.hostname


def test_multiple_redirect_parameters_do_not_change_single_url_indicator():
    item = analyze_url(
        "https://example.com/?url=https%3A%2F%2Fevil.example&next=https%3A%2F%2Fother.example"
    )

    assert item.redirect_indicator is True
    assert item.analysis_status == "complete"


def test_malformed_port_results_in_partial_url_analysis():
    item = analyze_url(
        "https://example.com:notaport/path"
    )

    assert item.analysis_status == "partial"
from phishlens.analysis.url_analysis import extract_urls
from phishlens.config import Settings
from phishlens.parsing.eml_parser import parse_eml_bytes
from phishlens.pipeline.analyzer import Analyzer


def test_ipv6_url_is_extracted_from_plain_text_email():
    raw = b"""From: sender@example.com
To: analyst@example.net
Subject: ipv6 URL test

Visit https://[2001:db8::1]/login
"""

    email = parse_eml_bytes(raw)
    urls = extract_urls(email)

    assert len(urls) == 1
    assert urls[0].hostname == "2001:db8::1"
    assert urls[0].is_ip_literal is True


def test_ipv6_url_is_extracted_from_html_email():
    raw = b"""From: sender@example.com
To: analyst@example.net
Subject: ipv6 HTML URL test
Content-Type: text/html; charset="utf-8"

<a href="https://[2001:db8::1]/login">IPv6 link</a>
"""

    email = parse_eml_bytes(raw)
    urls = extract_urls(email)

    assert len(urls) == 1
    assert urls[0].hostname == "2001:db8::1"
    assert urls[0].is_ip_literal is True


def test_malformed_url_makes_pipeline_url_analysis_partial():
    raw = b"""From: sender@example.com
To: analyst@example.net
Subject: malformed URL test

Visit https://example.com:notaport/path
"""

    result = Analyzer(Settings()).analyze(raw)

    assert result.completeness.areas["url"].status == "partial"
    assert result.completeness.overall_status == "partial"
    assert result.verdict.final == "UNRESOLVED"
