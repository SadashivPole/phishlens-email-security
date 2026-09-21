from src.phishlens.parsing.authentication import authentication_evidence_items, parse_authentication_results
from src.phishlens.parsing.eml_parser import parse_eml_bytes


def test_authentication_states_are_parsed(fixture_dir):
    email = parse_eml_bytes((fixture_dir / "clean.eml").read_bytes())
    auth = parse_authentication_results(email)
    assert auth.spf[0].result == "pass"
    assert auth.dkim[0].result == "pass"
    assert auth.dmarc[0].result == "pass"
    assert auth.status.status == "complete"


def test_multiple_authentication_results_values_are_retained():
    raw = b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\nAuthentication-Results: backup; spf=fail; dkim=none; dmarc=fail\n\nbody"
    auth = parse_authentication_results(parse_eml_bytes(raw))
    assert len(auth.spf) == 2
    assert {item.result for item in auth.spf} == {"pass", "fail"}


def test_missing_authentication_results_is_not_evaluable():
    email = parse_eml_bytes(b"From: a@example.com\n\nbody")
    auth = parse_authentication_results(email)
    assert auth.status.status == "not_evaluable"
    assert auth.spf == []


def test_dns_context_is_not_claimed_by_parser():
    email = parse_eml_bytes(b"From: a@example.com\n\nbody")
    auth = parse_authentication_results(email)
    assert auth.status.note and "DNS" in auth.status.note
    assert auth.status.status != "complete"
    assert auth.header_state == "absent"


def test_authentication_properties_capture_domains_and_selector():
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: mx; spf=pass smtp.mailfrom=mailer.example.net; "
        b"dkim=pass header.d=signer.example.net header.s=selector1; "
        b"dmarc=pass header.from=example.com\n\nbody"
    )
    auth = parse_authentication_results(parse_eml_bytes(raw))
    assert auth.spf[0].domain == "mailer.example.net"
    assert auth.dkim[0].domain == "signer.example.net"
    assert auth.dkim[0].selector == "selector1"
    assert auth.dmarc[0].domain == "example.com"


def test_unsupported_authentication_header_is_not_evaluable():
    raw = b"Authentication-Results: mx; futuremethod=pass\n\nbody"
    auth = parse_authentication_results(parse_eml_bytes(raw))
    assert auth.header_state == "present"
    assert auth.status.status == "not_evaluable"


def test_authentication_failure_evidence_is_not_hard():
    raw = b"Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\n\nbody"
    auth = parse_authentication_results(parse_eml_bytes(raw))
    findings = authentication_evidence_items(auth)
    assert {item.signal_id for item in findings} == {"spf_fail", "dkim_fail", "dmarc_fail"}
    assert all(not item.hard_indicator for item in findings)
