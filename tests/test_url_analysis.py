from src.phishlens.analysis.url_analysis import analyze_url, extract_urls, normalize_url, url_evidence
from src.phishlens.parsing.eml_parser import parse_eml_bytes


def test_url_extraction_and_display_mismatch(fixture_dir):
    email = parse_eml_bytes((fixture_dir / "html.eml").read_bytes())
    urls = extract_urls(email)
    assert any(item.display_mismatch for item in urls)
    assert any(item.original_url == "https://evil.example/path" for item in urls)


def test_ip_literal_and_userinfo_are_detected():
    item = analyze_url("http://user:pass@192.0.2.10/login")
    assert item.is_ip_literal is True
    assert item.has_userinfo is True
    ids = {finding.signal_id for finding in url_evidence([item])}
    assert "ip_literal_url" in ids
    assert "url_userinfo" in ids


def test_normalization_preserves_scheme_host_and_removes_fragment():
    normalized = normalize_url("HTTPS://Example.COM:443/path#fragment")
    assert normalized == "https://example.com/path"


def test_suspicious_encoding_is_flagged_without_double_decoding():
    item = analyze_url("https://example.com/%252fsecret")
    assert item.suspicious_encoding is True
    assert "%252f" in item.original_url


def test_idn_port_and_redirect_structure_are_detected_without_fetching():
    item = analyze_url("https://xn--pple-43d.example:8080/login?redirect=https%3A%2F%2Fexample.com")
    assert item.has_punycode is True
    assert item.suspicious_port is True
    assert item.redirect_indicator is True
    ids = {finding.signal_id for finding in url_evidence([item])}
    assert {"idn_punycode_url", "nonstandard_url_port", "redirect_structure"} <= ids


def test_malformed_url_is_represented_as_partial_indicator():
    item = analyze_url("https://example.com:invalid/")
    assert item.analysis_status == "partial"
    assert item.normalized_url == ""
    assert item.analysis_error
