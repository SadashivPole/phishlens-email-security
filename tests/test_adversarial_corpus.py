from __future__ import annotations

import base64
import json
from email.message import EmailMessage
from urllib.parse import unquote, urlsplit

from src.phishlens.config import Settings, VirusTotalConfig
from src.phishlens.enrichment.virustotal import VirusTotalProvider
from src.phishlens.pipeline.analyzer import Analyzer


def _requested_url_value(request) -> str:
    encoded = unquote(urlsplit(request.full_url).path.rsplit("/", 1)[-1])
    return base64.urlsafe_b64decode(
        encoded + "=" * (-len(encoded) % 4)
    ).decode()


def test_adversarial_duplicate_trusted_auth_headers_fail_closed_at_pipeline():
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\n"
        b"Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail\n"
        b"\n"
        b"Normal message body.\n"
    )

    settings = Settings(
        auth_results_mode="trusted_ingress",
        trusted_authserv_id="mx.example",
    )

    result = Analyzer(settings, providers=[]).analyze(raw)

    assert result.completeness.areas["authentication"].status == "not_evaluable"
    assert result.completeness.overall_status != "complete"
    assert result.scoring.category_scores["authentication"] == 0
    assert result.verdict.final == "UNRESOLVED"


def test_adversarial_vt_sanitization_handles_mixed_case_sensitive_parameters():
    requests = []

    adapter = VirusTotalProvider(
        VirusTotalConfig(api_key="offline-adversarial-test-key"),
        http_get=lambda request, timeout: (
            404,
            requests.append(request) or b"{}",
        ),
    )

    target = (
        "https://example.test/reset"
        "?ToKeN=TOP-SECRET"
        "&EMAIL=analyst@example.com"
        "&campaign=spring"
        "#fragment-secret"
    )

    result = adapter.lookup_url(
        __import__("src.phishlens.models.ioc", fromlist=["IOC"]).IOC(
            "url",
            target,
            target,
            "adversarial-test",
        )
    )

    assert result.status == "no_match"
    assert result.ioc_value == target
    assert len(requests) == 1

    provider_value = _requested_url_value(requests[0])

    assert provider_value == "https://example.test/reset?campaign=spring"
    assert "TOP-SECRET" not in provider_value
    assert "analyst@example.com" not in provider_value
    assert "fragment-secret" not in provider_value


def test_adversarial_safe_report_does_not_leak_multiple_sensitive_query_values():
    raw = (
        b"From: sender@example.com\n"
        b"Subject: Sensitive URL test\n"
        b"\n"
        b"https://example.test/reset?"
        b"token=TOP-SECRET&"
        b"email=analyst@example.com&"
        b"campaign=spring\n"
    )

    result = Analyzer().analyze(raw)
    serialized = json.dumps(result.to_safe_dict())

    assert "TOP-SECRET" not in serialized
    assert "analyst@example.com" not in serialized
    assert "campaign=spring" in serialized
    assert "%5BREDACTED%5D" in serialized

def test_adversarial_attachment_size_boundary_is_enforced():
    settings = Settings(
        max_attachment_bytes=10,
        auth_results_mode="trusted_ingress",
        trusted_authserv_id="mx",
    )

    within_limit = EmailMessage()
    within_limit["From"] = "sender@example.com"
    within_limit["Authentication-Results"] = "mx; spf=pass; dkim=pass; dmarc=pass"
    within_limit["Subject"] = "Attachment boundary"
    within_limit.set_content("Normal body")
    within_limit.add_attachment(
        b"1234567890",
        maintype="application",
        subtype="octet-stream",
        filename="boundary.bin",
    )

    result = Analyzer(settings, providers=[]).analyze(within_limit.as_bytes())

    assert result.completeness.areas["parser"].status == "complete"
    assert result.completeness.areas["attachment"].status == "complete"
    assert len(result.email.attachments) == 1
    assert result.email.attachments[0].size_bytes == 10
    assert result.verdict.final == "CLEAN"

    over_limit = EmailMessage()
    over_limit["From"] = "sender@example.com"
    over_limit["Authentication-Results"] = "mx; spf=pass; dkim=pass; dmarc=pass"
    over_limit["Subject"] = "Attachment boundary overflow"
    over_limit.set_content("Normal body")
    over_limit.add_attachment(
        b"12345678901",
        maintype="application",
        subtype="octet-stream",
        filename="too-large.bin",
    )

    result = Analyzer(settings, providers=[]).analyze(over_limit.as_bytes())

    assert result.verdict.final == "UNRESOLVED"
    assert result.completeness.areas["parser"].status == "unavailable"
    assert result.email.parse_warnings


def test_adversarial_nested_mime_preserves_body_and_attachment_analysis():
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["Authentication-Results"] = "mx; spf=pass; dkim=pass; dmarc=pass"
    message["Subject"] = "Nested MIME test"

    message.set_content("Plain body")
    message.add_alternative("<html><body>HTML body</body></html>", subtype="html")
    message.add_attachment(
        b"normal attachment",
        maintype="application",
        subtype="octet-stream",
        filename="document.bin",
    )

    settings = Settings(
        auth_results_mode="trusted_ingress",
        trusted_authserv_id="mx",
    )

    result = Analyzer(settings, providers=[]).analyze(message.as_bytes())

    assert result.completeness.areas["parser"].status == "complete"
    assert result.completeness.areas["attachment"].status == "complete"
    assert result.completeness.areas["content"].status == "complete"
    assert "Plain body" in result.email.body_text
    assert "HTML body" in result.email.body_html
    assert len(result.email.attachments) == 1
    assert result.email.attachments[0].filename == "document.bin"
    assert result.verdict.final == "CLEAN"


def test_adversarial_malformed_received_hop_is_partial_but_not_required():
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
        b"Received: from mail.example [203.0.113.10] by mx.example; Mon, 01 Jan 2026 10:00:00 +0000\n"
        b"Received: from broken.example [999.999.999.999] by mx.example; Mon, 01 Jan 2026 09:59:00 +0000\n"
        b"\n"
        b"Normal message body.\n"
    )

    settings = Settings(
        auth_results_mode="trusted_ingress",
        trusted_authserv_id="mx",
    )

    result = Analyzer(settings, providers=[]).analyze(raw)

    assert result.completeness.areas["mail_flow"].status == "partial"
    assert result.completeness.areas["mail_flow"].required is False
    assert result.completeness.overall_status == "complete"
    assert any(
        item.signal_id == "received_hop_malformed"
        for item in result.evidence
    )
    assert result.verdict.final == "CLEAN"
