from __future__ import annotations

import json
import subprocess
import sys

from src.phishlens.analysis.url_analysis import extract_urls, url_evidence
from src.phishlens.models.result import AnalysisResult
from src.phishlens.parsing.eml_parser import parse_eml_bytes
from src.phishlens.pipeline.analyzer import Analyzer


def test_pipeline_returns_stable_analysis_result(fixture_dir):
    result = Analyzer().analyze((fixture_dir / "phishing.eml").read_bytes())
    assert isinstance(result, AnalysisResult)
    payload = result.to_dict()
    assert payload["schema_version"] == "1.0"
    assert set(payload) == {"schema_version", "email", "urls", "evidence", "scoring", "completeness", "verdict", "errors"}
    json.dumps(payload)


def test_exact_fixture_verdicts(fixture_dir):
    analyzer = Analyzer()
    assert analyzer.analyze((fixture_dir / "clean.eml").read_bytes()).verdict.final == "CLEAN"
    assert analyzer.analyze((fixture_dir / "phishing.eml").read_bytes()).verdict.final == "SUSPICIOUS"
    assert analyzer.analyze((fixture_dir / "attachment.eml").read_bytes()).verdict.final == "SUSPICIOUS"
    assert analyzer.analyze((fixture_dir / "malformed.eml").read_bytes()).verdict.final == "UNRESOLVED"


def test_local_pipeline_does_not_require_network(fixture_dir, monkeypatch):
    def fail_network(*args, **kwargs):
        raise AssertionError("network access was attempted")

    monkeypatch.setattr("socket.socket", fail_network)
    result = Analyzer().analyze((fixture_dir / "clean.eml").read_bytes())
    assert result.verdict.final == "CLEAN"


def test_optional_reputation_unavailable_does_not_poison_clean_status(fixture_dir):
    result = Analyzer().analyze((fixture_dir / "clean.eml").read_bytes())
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
    assert result.verdict.final != "MALICIOUS"
    assert result.verdict.final in {"CLEAN", "SUSPICIOUS"}


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
    assert result.verdict.final == "CLEAN"


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
