from __future__ import annotations
from email.message import EmailMessage

import json
import subprocess
import sys

from src.phishlens.analysis.url_analysis import extract_urls, url_evidence
from src.phishlens.config import Settings
from src.phishlens.models.result import AnalysisResult
from src.phishlens.parsing.eml_parser import parse_eml_bytes
from src.phishlens.pipeline.analyzer import Analyzer


def test_pipeline_returns_stable_analysis_result(fixture_dir):
    result = Analyzer().analyze((fixture_dir / "phishing.eml").read_bytes())
    assert isinstance(result, AnalysisResult)
    payload = result.to_dict()
    assert payload["schema_version"] == "1.0"
    assert set(payload) == {"schema_version", "email", "urls", "evidence", "scoring", "completeness", "verdict", "errors", "iocs", "threat_intelligence"}
    json.dumps(payload)


def test_exact_fixture_verdicts(fixture_dir):
    analyzer = Analyzer()
    assert analyzer.analyze((fixture_dir / "clean.eml").read_bytes()).verdict.final == "UNRESOLVED"
    assert analyzer.analyze((fixture_dir / "phishing.eml").read_bytes()).verdict.final == "SUSPICIOUS"
    assert analyzer.analyze((fixture_dir / "attachment.eml").read_bytes()).verdict.final == "SUSPICIOUS"
    assert analyzer.analyze((fixture_dir / "malformed.eml").read_bytes()).verdict.final == "UNRESOLVED"


def test_local_pipeline_does_not_require_network(fixture_dir, monkeypatch):
    def fail_network(*args, **kwargs):
        raise AssertionError("network access was attempted")

    monkeypatch.setattr("socket.socket", fail_network)
    result = Analyzer().analyze((fixture_dir / "clean.eml").read_bytes())
    assert result.verdict.final == "UNRESOLVED"


def test_optional_reputation_unavailable_does_not_poison_clean_status(fixture_dir):
    settings = Settings(auth_results_mode="trusted_ingress", trusted_authserv_id="mx.example.net")
    result = Analyzer(settings).analyze((fixture_dir / "clean.eml").read_bytes())
    assert result.completeness.areas["reputation"].status == "unavailable"
    assert result.completeness.areas["reputation"].required is False
    assert result.completeness.overall_status == "complete"
    assert result.verdict.final == "CLEAN"


def test_missing_authentication_is_not_clean_by_default():
    result = Analyzer().analyze(b"From: sender@example.com\nSubject: Test\n\nA normal body.")
    assert result.completeness.areas["authentication"].status == "not_evaluable"
    assert result.verdict.final == "UNRESOLVED"


def test_authentication_failure_is_not_malicious_by_itself():
    raw = b"From: sender@example.com\nAuthentication-Results: mx; spf=fail; dmarc=fail\n\nBody"
    result = Analyzer().analyze(raw)
    assert result.completeness.areas["authentication"].status == "not_evaluable"
    assert result.scoring.category_scores["authentication"] == 0
    assert result.verdict.final == "UNRESOLVED"


def test_trusted_ingress_authentication_can_complete_pipeline():
    raw = b"From: sender@example.com\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nBody"
    settings = Settings(auth_results_mode="trusted_ingress", trusted_authserv_id="mx")
    result = Analyzer(settings, providers=[]).analyze(raw)
    assert result.completeness.areas["authentication"].status == "complete"
    assert result.completeness.overall_status == "complete"
    assert result.verdict.final == "CLEAN"


def test_duplicate_html_destination_produces_one_indicator(fixture_dir):
    email = parse_eml_bytes((fixture_dir / "phishing.eml").read_bytes())
    urls = extract_urls(email)
    ip_urls = [item for item in urls if item.is_ip_literal]
    findings = url_evidence(urls)
    ip_findings = [item for item in findings if item.signal_id == "ip_literal_url"]
    assert len(ip_urls) == 1
    assert len(ip_findings) == 1


def test_duplicate_scoring_is_bounded():
    result = Analyzer().analyze(b"From: sender@example.com\n\nVisit http://192.0.2.1/a and http://192.0.2.1/a")
    assert result.scoring.category_scores["url"] <= 20
    assert result.verdict.final != "MALICIOUS"


def test_pipeline_applies_content_analysis_without_external_services():
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n"
        b"Verify your password immediately within 24 hours."
    )
    result = Analyzer().analyze(raw)
    ids = {item.signal_id for item in result.evidence}
    assert "credential_request" in ids
    assert "urgency_language" in ids
    assert result.completeness.areas["content"].status == "complete"
    assert result.verdict.final != "MALICIOUS"


def test_pipeline_includes_received_hops_without_external_lookup():
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
        b"Received: from mail.example [203.0.113.5] by mx.example; Mon, 01 Jan 2026 10:00:00 +0000\n\nbody"
    )
    result = Analyzer().analyze(raw)
    assert len(result.email.received_hops) == 1
    assert result.email.received_hops[0].source_ips == ["203.0.113.5"]
    assert result.completeness.areas["mail_flow"].status == "complete"
    assert result.completeness.areas["authentication"].status == "not_evaluable"
    assert result.verdict.final == "UNRESOLVED"


def test_required_parser_failure_is_unresolved():
    result = Analyzer().analyze(b"This is not a recognizable email message.")
    assert result.completeness.areas["parser"].status == "unavailable"
    assert result.verdict.final == "UNRESOLVED"


def test_malformed_urls_do_not_abort_and_valid_evidence_is_preserved():
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
        b"Content-Type: text/plain; charset=utf-8\n\n"
        b"Bad: https://example.com:invalid/\n"
        b"Bad IPv6: http://[::1\n"
        b"Valid: http://192.0.2.1/login\n"
    )
    result = Analyzer().analyze(raw)
    assert result.completeness.areas["url"].status == "partial"
    assert result.verdict.final == "UNRESOLVED"
    assert any(item.signal_id == "malformed_url" for item in result.evidence)
    assert any(item.signal_id == "ip_literal_url" for item in result.evidence)


def test_default_cli_json_is_a_safe_report(fixture_dir):
    completed = subprocess.run(
        [sys.executable, "analyze.py", str(fixture_dir / "phishing.eml"), "--json"],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)
    serialized = completed.stdout
    assert "body_text" not in payload["email"]
    assert "body_html" not in payload["email"]
    assert "Verify your password immediately" not in serialized
    assert "token=" not in serialized
    assert "verdict" in payload
    assert "scoring" in payload
    assert payload["scoring"]["maximum_score"] == sum(payload["scoring"]["category_caps"].values()) == 70
    assert "evidence" in payload
    assert "authentication" in payload


def test_sensitive_query_values_are_redacted_in_safe_report():
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n"
        b"https://example.com/reset?token=secret-value&email=user@example.com"
    )
    result = Analyzer().analyze(raw)
    serialized = json.dumps(result.to_safe_dict())
    assert "secret-value" not in serialized
    assert "%5BREDACTED%5D" in serialized
def test_pipeline_marks_content_not_evaluable_when_body_is_empty():
    raw = (
        b"From: sender@example.com\n"
        b"Subject: No body\n\n"
    )
    result = Analyzer().analyze(raw)
    assert result.completeness.areas["content"].status == "not_evaluable"

def _build_mime_truncated_email(
    *,
    suspicious_body: bool = False,
    dangerous_tail: bool = False,
) -> bytes:
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "recipient@example.com"
    message["Subject"] = "MIME truncation regression"
    message["Authentication-Results"] = "mx.example; spf=pass; dkim=pass; dmarc=pass"

    body = (
        "Verify your password immediately within 24 hours. "
        "Open http://192.0.2.1/login to continue."
        if suspicious_body
        else "Normal message body."
    )
    message.set_content(body)

    for index in range(99):
        message.add_attachment(
            b"benign attachment",
            maintype="application",
            subtype="octet-stream",
            filename=f"benign-{index}.bin",
        )

    if dangerous_tail:
        message.add_attachment(
            b"MZ" + b"\x00" * 128,
            maintype="application",
            subtype="pdf",
            filename="final-document.pdf",
        )

    return message.as_bytes()


def test_mime_truncation_makes_clean_analysis_unresolved():
    raw = _build_mime_truncated_email()
    result = Analyzer().analyze(raw)

    assert "maximum MIME part count exceeded" in result.email.parse_warnings
    assert result.completeness.areas["parser"].status == "partial"
    assert result.completeness.areas["attachment"].status == "partial"
    assert result.completeness.overall_status != "complete"
    assert result.verdict.final == "UNRESOLVED"


def test_mime_truncation_does_not_hide_suspicious_evidence_seen_before_limit():
    raw = _build_mime_truncated_email(suspicious_body=True)
    result = Analyzer().analyze(raw)

    assert "maximum MIME part count exceeded" in result.email.parse_warnings
    assert result.completeness.areas["parser"].status == "partial"
    assert result.completeness.areas["attachment"].status == "partial"
    assert result.verdict.final == "SUSPICIOUS"


def test_mime_truncation_does_not_claim_complete_attachment_analysis():
    raw = _build_mime_truncated_email()
    result = Analyzer().analyze(raw)

    assert len(result.email.attachments) == 98
    assert result.completeness.areas["attachment"].status == "partial"
    assert result.completeness.areas["parser"].status == "partial"


def test_mime_truncation_does_not_analyze_attachment_after_limit():
    raw = _build_mime_truncated_email(dangerous_tail=True)
    result = Analyzer().analyze(raw)

    assert "maximum MIME part count exceeded" in result.email.parse_warnings
    assert not any(
        attachment.filename == "final-document.pdf"
        for attachment in result.email.attachments
    )
    assert result.completeness.areas["attachment"].status == "partial"
    assert result.completeness.overall_status != "complete"
    assert result.verdict.final == "UNRESOLVED"
