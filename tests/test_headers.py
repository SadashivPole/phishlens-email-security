from src.phishlens.parsing.eml_parser import parse_eml_bytes
from src.phishlens.parsing.headers import header_evidence


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
