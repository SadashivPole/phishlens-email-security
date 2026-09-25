from __future__ import annotations

import json

from src.phishlens.config import Settings
from src.phishlens.parsing.authentication import parse_authentication_results
from src.phishlens.parsing.domain_alignment import compare_domains, normalize_domain, organizational_domain
from src.phishlens.parsing.eml_parser import parse_eml_bytes
from src.phishlens.parsing.headers import header_evidence
from src.phishlens.pipeline.analyzer import Analyzer


def _alignment(findings, method):
    return next(
        item for item in findings
        if item.signal_id in {f"{method}_alignment", f"{method}_alignment_not_evaluable"}
    )


def test_spf_and_dkim_aligned_evidence_is_deterministic_and_not_hard():
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: mx; spf=pass smtp.mailfrom=example.com; "
        b"dkim=pass header.d=example.com header.s=s1; dmarc=pass header.from=example.com\n\n"
        b"Routine message body."
    )
    email = parse_eml_bytes(raw)
    auth = parse_authentication_results(email)
    findings = header_evidence(email, auth)
    spf = _alignment(findings, "spf")
    dkim = _alignment(findings, "dkim")
    assert spf.evidence["alignment"] == "aligned"
    assert dkim.evidence["alignment"] == "aligned"
    assert spf.evidence["from_domain"] == "example.com"
    assert spf.evidence["observations"][0]["authenticated_domain"] == "example.com"
    assert dkim.evidence["observations"][0]["selector"] == "s1"
    assert all(not item.hard_indicator for item in (spf, dkim))
    assert all(item.points == 0 for item in (spf, dkim))
    assert all(item.evidence["trust"] == "untrusted_assertion" for item in (spf, dkim))
    assert all(item.evidence["decision_eligible"] is False for item in (spf, dkim))
    assert all(item.reliability == "low" for item in (spf, dkim))


def test_misaligned_spf_and_dkim_evidence_has_provenance_without_direct_malicious_verdict():
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: mx; spf=pass smtp.mailfrom=other.example.net; "
        b"dkim=pass header.d=signer.example.org header.s=sel; dmarc=pass header.from=example.com\n\n"
        b"Routine message body."
    )
    result = Analyzer().analyze(raw)
    spf = _alignment(result.evidence, "spf")
    dkim = _alignment(result.evidence, "dkim")
    assert spf.evidence["alignment"] == "misaligned"
    assert dkim.evidence["alignment"] == "misaligned"
    assert spf.evidence["observations"][0]["provenance"]["source"] == "Authentication-Results"
    assert dkim.evidence["observations"][0]["provenance"]["method"] == "dkim"
    assert result.verdict.final != "MALICIOUS"


def test_missing_authentication_domains_are_not_evaluable():
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n"
        b"Body"
    )
    email = parse_eml_bytes(raw)
    auth = parse_authentication_results(email)
    findings = header_evidence(email, auth)
    assert _alignment(findings, "spf").evidence["alignment"] == "not_evaluable"
    assert _alignment(findings, "dkim").evidence["alignment"] == "not_evaluable"
    assert _alignment(findings, "spf").points == 0


def test_multiple_authentication_results_are_retained_and_alignment_is_partial():
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: primary; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com header.s=a\n"
        b"Authentication-Results: backup; spf=pass smtp.mailfrom=other.example; dkim=pass header.d=signer.example header.s=b\n\n"
        b"Body"
    )
    email = parse_eml_bytes(raw)
    auth = parse_authentication_results(email)
    findings = header_evidence(email, auth)
    assert len(auth.spf) == 2
    assert len(auth.dkim) == 2
    assert _alignment(findings, "spf").evidence["alignment"] == "partial"
    assert _alignment(findings, "dkim").evidence["alignment"] == "partial"
    assert len(_alignment(findings, "spf").evidence["observations"]) == 2


def test_malformed_authentication_properties_are_safe_and_explicit():
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: mx; spf=pass smtp.mailfrom=example.com; broken; "
        b"dkim=pass header.s=selector-without-domain\n\nBody"
    )
    email = parse_eml_bytes(raw)
    auth = parse_authentication_results(email, mode="trusted_ingress", trusted_authserv_id="mx")
    findings = header_evidence(email, auth)
    assert auth.status.status == "partial"
    assert _alignment(findings, "spf").evidence["alignment"] == "aligned"
    assert _alignment(findings, "dkim").evidence["alignment"] == "not_evaluable"


def test_alignment_explicitly_does_not_claim_spf_or_dkim_verification():
    raw = b"From: sender@example.com\nAuthentication-Results: mx; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com\n\nBody"
    result = Analyzer().analyze(raw)
    alignment_items = [item for item in result.evidence if item.signal_id in {"spf_alignment", "dkim_alignment"}]
    assert alignment_items
    assert all("does not independently verify" in item.explanation for item in alignment_items)
    assert all("verification_scope" in item.evidence for item in alignment_items)


def test_alignment_safe_json_keeps_provenance_without_raw_headers():
    raw = b"From: sender@example.com\nAuthentication-Results: mx; spf=pass smtp.mailfrom=other.example; dkim=pass header.d=signer.example\n\nBody"
    result = Analyzer().analyze(raw)
    safe = json.dumps(result.to_safe_dict())
    assert "spf_alignment" in safe
    assert "dkim_alignment" in safe
    assert "authentication_results" in safe
    assert "mx; spf=pass smtp.mailfrom=other.example" not in safe
    assert "Body" not in safe


def test_alignment_does_not_change_clean_verdict_for_aligned_message():
    raw = b"From: sender@example.com\nAuthentication-Results: mx; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com\n\nRoutine body"
    settings = Settings(auth_results_mode="trusted_ingress", trusted_authserv_id="mx")
    result = Analyzer(settings, providers=[]).analyze(raw)
    assert result.verdict.final == "CLEAN"
    assert result.completeness.areas["authentication"].status == "complete"
