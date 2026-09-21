from src.phishlens.parsing.eml_parser import parse_eml_bytes
from src.phishlens.parsing.authentication import parse_authentication_results
from src.phishlens.parsing.headers import header_evidence, parse_received_headers, received_evidence


def test_identity_mismatches_are_evidence_not_hard_proof(fixture_dir):
    email = parse_eml_bytes((fixture_dir / "phishing.eml").read_bytes())
    findings = header_evidence(email)
    ids = {item.signal_id for item in findings}
    assert "reply_to_mismatch" in ids
    assert all(not item.hard_indicator for item in findings)


def test_missing_headers_are_tolerated():
    email = parse_eml_bytes(b"Subject: Minimal\n\nbody")
    assert email.from_address is None
    assert header_evidence(email) == []


def test_received_headers_are_ordered_and_extract_safe_hops():
    raw = (
        b"Received: from mail.sender.example (mail.sender.example [203.0.113.10]) "
        b"by mx.example.net; Mon, 01 Jan 2026 10:00:00 +0000\n"
        b"Received: from [10.0.0.5] by mail.sender.example; Mon, 01 Jan 2026 09:59:00 +0000\n\nbody"
    )
    email = parse_eml_bytes(raw)
    hops = parse_received_headers(email.received_headers)
    assert [hop.order for hop in hops] == [0, 1]
    assert hops[0].source_hostname == "mail.sender.example"
    assert "203.0.113.10" in hops[0].source_ips
    assert "10.0.0.5" in hops[1].source_ips
    assert all(not hop.malformed for hop in hops)


def test_malformed_received_header_creates_low_confidence_evidence():
    email = parse_eml_bytes(b"Received: from mail.example [bad]\n\nbody")
    email.received_hops = parse_received_headers(email.received_headers)
    assert email.received_hops[0].malformed is True
    findings = received_evidence(email)
    assert len(findings) == 1
    assert findings[0].signal_id == "received_hop_malformed"
    assert findings[0].points == 0


def test_authenticated_and_dkim_domain_mismatches_are_distinct_and_not_hard():
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: mx; spf=pass smtp.mailfrom=other.example; "
        b"dkim=pass header.d=signer.example header.s=s1; dmarc=pass header.from=example.com\n\nbody"
    )
    email = parse_eml_bytes(raw)
    auth = parse_authentication_results(email)
    findings = header_evidence(email, auth)
    ids = {item.signal_id for item in findings}
    assert "authenticated_domain_mismatch" in ids
    assert "dkim_signing_domain_mismatch" in ids
    assert all(not item.hard_indicator for item in findings)
