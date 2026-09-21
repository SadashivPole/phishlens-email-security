from __future__ import annotations

from src.phishlens.config import Settings
from src.phishlens.parsing.eml_parser import parse_eml_bytes


def test_plain_text_email_parses(fixture_dir):
    email = parse_eml_bytes((fixture_dir / "clean.eml").read_bytes())
    assert email.subject == "Monthly report"
    assert "monthly report" in email.body_text
    assert email.from_address == "notifications@example.com"


def test_html_email_parses(fixture_dir):
    email = parse_eml_bytes((fixture_dir / "html.eml").read_bytes())
    assert "trusted.example" in email.body_html


def test_multipart_email_parses_both_bodies(fixture_dir):
    email = parse_eml_bytes((fixture_dir / "multipart.eml").read_bytes())
    assert "Plain body" in email.body_text
    assert "HTML body" in email.body_html


def test_attachment_metadata_hash_and_limits(fixture_dir):
    email = parse_eml_bytes((fixture_dir / "attachment.eml").read_bytes())
    assert len(email.attachments) == 1
    attachment = email.attachments[0]
    assert attachment.sha256
    assert attachment.double_extension is True
    assert attachment.detected_type == "PE executable"
    assert attachment.extension_mismatch is True


def test_size_limit_is_enforced():
    try:
        parse_eml_bytes(b"x" * 20, Settings(max_email_bytes=10))
    except ValueError as exc:
        assert "maximum size" in str(exc)
    else:
        raise AssertionError("expected size limit failure")


def test_malformed_email_is_safe(fixture_dir):
    email = parse_eml_bytes((fixture_dir / "malformed.eml").read_bytes())
    assert email.raw_size_bytes > 0
