from src.phishlens.parsing.authentication import parse_authentication_results
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
