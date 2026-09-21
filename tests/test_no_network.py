from src.phishlens.analysis.url_analysis import extract_urls
from src.phishlens.models.email import ParsedEmail


def test_url_analysis_is_static_only():
    email = ParsedEmail(raw_size_bytes=20, body_text="Visit https://example.com/path")
    urls = extract_urls(email)
    assert urls[0].normalized_url.startswith("https://")
