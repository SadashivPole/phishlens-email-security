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
