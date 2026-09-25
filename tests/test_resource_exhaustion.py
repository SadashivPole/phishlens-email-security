from __future__ import annotations

from phishlens.config import Settings
from phishlens.parsing.eml_parser import parse_eml_bytes
from phishlens.pipeline.analyzer import Analyzer


def test_pipeline_rejects_email_above_configured_size_limit():
    settings = Settings(max_email_bytes=1024)

    raw = (
        b"From: sender@example.com\n"
        b"To: analyst@example.net\n"
        b"Subject: oversized email\n\n"
        + b"A" * 2048
    )

    result = Analyzer(settings).analyze(raw)

    assert result.completeness.areas["parser"].status == "unavailable"
    assert result.verdict.final == "UNRESOLVED"
    assert result.errors
    assert "2048" not in result.errors[0]


def test_parser_rejects_attachment_above_configured_size_limit():
    settings = Settings(max_attachment_bytes=1024)

    raw = b"""From: sender@example.com
To: analyst@example.net
Subject: oversized attachment
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="limit"

--limit
Content-Type: text/plain

Attachment follows.
--limit
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="large.bin"

""" + (b"A" * 2048) + b"""
--limit--
"""

    result = Analyzer(settings).analyze(raw)

    assert result.completeness.areas["parser"].status == "unavailable"
    assert result.verdict.final == "UNRESOLVED"
    assert result.errors
    assert "2048" not in result.errors[0]


def test_many_duplicate_identity_headers_remain_bounded_and_unresolved():
    headers = b"".join(
        f"From: sender-{index}@example.com\n".encode("ascii")
        for index in range(1000)
    )

    raw = (
        headers
        + b"To: analyst@example.net\n"
        + b"Subject: duplicate header stress\n\n"
        + b"Normal body.\n"
    )

    result = Analyzer().analyze(raw)
    safe = result.to_safe_dict()

    assert len(result.email.headers["from"]) == 1000
    assert result.completeness.areas["identity"].status == "partial"
    assert result.verdict.final == "UNRESOLVED"
    assert safe["email"]["identity_header_conflicts"]["from"] == 1000
    assert safe["email"]["from_address"] is None


def test_large_but_allowed_body_does_not_trigger_parser_failure():
    body = b"A" * (1024 * 1024)

    raw = (
        b"From: sender@example.com\n"
        b"To: analyst@example.net\n"
        b"Subject: large body\n"
        b"Content-Type: text/plain; charset=utf-8\n\n"
        + body
    )

    result = Analyzer().analyze(raw)

    assert result.completeness.areas["parser"].status == "complete"
    assert result.email.raw_size_bytes > 1024 * 1024
    assert result.verdict.final in {"CLEAN", "UNRESOLVED", "SUSPICIOUS"}


def test_long_url_does_not_crash_analysis():
    path = "a" * 200_000

    raw = (
        b"From: sender@example.com\n"
        b"To: analyst@example.net\n"
        b"Subject: long URL stress\n\n"
        + f"https://example.com/{path}\n".encode("ascii")
    )

    result = Analyzer().analyze(raw)

    assert result.completeness.areas["parser"].status == "complete"
    assert result.verdict.final in {"CLEAN", "UNRESOLVED", "SUSPICIOUS"}
from email.message import EmailMessage

from phishlens.config import Settings
from phishlens.parsing.eml_parser import parse_eml_bytes


def _attachment_email(payload: bytes) -> bytes:
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "analyst@example.net"
    message["Subject"] = "attachment boundary test"
    message.set_content("Attachment boundary.")
    message.add_attachment(
        payload,
        maintype="application",
        subtype="octet-stream",
        filename="boundary.bin",
    )
    return message.as_bytes()


def test_email_size_exact_limit_is_accepted():
    settings = Settings(max_email_bytes=1024)
    raw = b"A" * 1024

    parsed = parse_eml_bytes(raw, settings)

    assert parsed.raw_size_bytes == 1024


def test_email_size_one_byte_over_limit_is_rejected():
    settings = Settings(max_email_bytes=1024)
    raw = b"A" * 1025

    try:
        parse_eml_bytes(raw, settings)
    except ValueError as exc:
        assert "maximum size" in str(exc)
    else:
        raise AssertionError("expected email size limit failure")


def test_attachment_size_exact_limit_is_accepted():
    settings = Settings(max_attachment_bytes=1024)
    raw = _attachment_email(b"A" * 1024)

    parsed = parse_eml_bytes(raw, settings)

    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].size_bytes == 1024


def test_attachment_size_one_byte_over_limit_is_rejected():
    settings = Settings(max_attachment_bytes=1024)
    raw = _attachment_email(b"A" * 1025)

    try:
        parse_eml_bytes(raw, settings)
    except ValueError as exc:
        assert "attachment exceeds maximum size" in str(exc)
    else:
        raise AssertionError("expected attachment size limit failure")
def test_many_authentication_results_headers_remain_untrusted_and_bounded():
    headers = b"".join(
        b"Authentication-Results: attacker.invalid; spf=pass; dkim=pass; dmarc=pass\n"
        for _ in range(1000)
    )

    raw = (
        b"From: sender@example.com\n"
        + headers
        + b"To: analyst@example.net\n"
        + b"Subject: authentication header stress\n\n"
        + b"Normal body.\n"
    )

    result = Analyzer().analyze(raw)

    assert len(result.email.authentication_results) == 1000
    assert result.completeness.areas["authentication"].status == "not_evaluable"
    assert result.scoring.category_scores["authentication"] == 0
    assert result.verdict.final == "UNRESOLVED"


def test_many_received_headers_do_not_crash_analysis():
    headers = b"".join(
        (
            b"Received: from mail.example [203.0.113.5] "
            b"by mx.example; Mon, 01 Jan 2026 10:00:00 +0000\n"
        )
        for _ in range(1000)
    )

    raw = (
        b"From: sender@example.com\n"
        + headers
        + b"To: analyst@example.net\n"
        + b"Subject: received header stress\n\n"
        + b"Normal body.\n"
    )

    result = Analyzer().analyze(raw)

    assert len(result.email.received_hops) == 1000
    assert result.completeness.areas["mail_flow"].status == "complete"
    assert result.verdict.final == "UNRESOLVED"


def test_repeated_identical_urls_do_not_multiply_url_score():
    url = b"https://example.com/login?redirect=https%3A%2F%2Fevil.example\n"

    raw = (
        b"From: sender@example.com\n"
        b"To: analyst@example.net\n"
        b"Subject: repeated URL stress\n\n"
        + url * 1000
    )

    result = Analyzer().analyze(raw)

    assert result.scoring.category_scores["url"] <= 20
    assert result.verdict.final != "MALICIOUS"
