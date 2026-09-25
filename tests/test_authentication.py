from src.phishlens.parsing.authentication import authentication_evidence_items, parse_authentication_results
from src.phishlens.parsing.eml_parser import parse_eml_bytes


def _parse(raw: bytes, *, mode="raw", trusted_authserv_id=None):
    return parse_authentication_results(
        parse_eml_bytes(raw),
        mode=mode,
        trusted_authserv_id=trusted_authserv_id,
    )


def test_forged_authentication_results_is_untrusted_by_default():
    raw = b"Authentication-Results: attacker-controlled.invalid; spf=pass; dkim=pass; dmarc=pass\n\nbody"
    auth = _parse(raw)
    assert auth.status.status == "not_evaluable"
    assert auth.trust == "untrusted_assertion"
    assert auth.decision_eligible is False
    assert auth.spf[0].result == "pass"
    assert authentication_evidence_items(auth) == []


def test_authserv_id_does_not_activate_trust_in_raw_mode():
    raw = b"Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\n\nbody"
    auth = _parse(raw, trusted_authserv_id="mx.example")
    assert auth.status.status == "not_evaluable"
    assert auth.decision_eligible is False


def test_invalid_mode_behaves_as_untrusted():
    raw = b"Authentication-Results: mx.example; spf=pass\n\nbody"
    auth = _parse(raw, mode="invalid", trusted_authserv_id="mx.example")
    assert auth.status.status == "not_evaluable"
    assert auth.decision_eligible is False


def test_trusted_ingress_without_authserv_id_fails_closed():
    raw = b"Authentication-Results: mx.example; spf=pass\n\nbody"
    auth = _parse(raw, mode="trusted_ingress")
    assert auth.status.status == "not_evaluable"
    assert auth.decision_eligible is False


def test_trusted_ingress_exact_authserv_id_is_decision_eligible():
    raw = b"Authentication-Results: MX.Example; spf=pass; dkim=pass; dmarc=pass\n\nbody"
    auth = _parse(raw, mode="trusted_ingress", trusted_authserv_id="mx.example")
    assert auth.status.status == "complete"
    assert auth.trust == "trusted_ingress_assertion"
    assert auth.decision_eligible is True
    assert auth.spf[0].result == "pass"


def test_trusted_ingress_nonmatching_authserv_id_fails_closed():
    raw = b"Authentication-Results: attacker.invalid; spf=pass\n\nbody"
    auth = _parse(raw, mode="trusted_ingress", trusted_authserv_id="mx.example")
    assert auth.status.status == "not_evaluable"
    assert auth.decision_eligible is False
    assert auth.spf == []


def test_duplicate_matching_authserv_id_headers_fail_closed():
    raw = (
        b"Authentication-Results: mx.example; spf=pass\n"
        b"Authentication-Results: mx.example; spf=fail\n\nbody"
    )
    auth = _parse(raw, mode="trusted_ingress", trusted_authserv_id="mx.example")
    assert auth.status.status == "not_evaluable"
    assert auth.decision_eligible is False
    assert authentication_evidence_items(auth) == []


def test_mixed_headers_use_only_exact_trusted_match():
    raw = (
        b"Authentication-Results: attacker.invalid; spf=pass; dkim=pass; dmarc=pass\n"
        b"Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail\n\nbody"
    )
    auth = _parse(raw, mode="trusted_ingress", trusted_authserv_id="mx.example")
    assert auth.decision_eligible is True
    assert [item.result for item in auth.spf] == ["fail"]
    assert {item.signal_id for item in authentication_evidence_items(auth)} == {
        "spf_fail",
        "dkim_fail",
        "dmarc_fail",
    }


def test_missing_authentication_results_is_not_evaluable():
    auth = _parse(b"From: a@example.com\n\nbody")
    assert auth.status.status == "not_evaluable"
    assert auth.header_state == "absent"
    assert auth.decision_eligible is False
    assert auth.spf == []


def test_authentication_properties_remain_visible_in_raw_mode():
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: mx; spf=pass smtp.mailfrom=mailer.example.net; "
        b"dkim=pass header.d=signer.example.net header.s=selector1; "
        b"dmarc=pass header.from=example.com\n\nbody"
    )
    auth = _parse(raw)
    assert auth.spf[0].domain == "mailer.example.net"
    assert auth.dkim[0].domain == "signer.example.net"
    assert auth.dkim[0].selector == "selector1"
    assert auth.dmarc[0].domain == "example.com"
    assert auth.decision_eligible is False


def test_unsupported_trusted_authentication_header_is_not_evaluable():
    raw = b"Authentication-Results: mx; futuremethod=pass\n\nbody"
    auth = _parse(raw, mode="trusted_ingress", trusted_authserv_id="mx")
    assert auth.header_state == "present"
    assert auth.status.status == "not_evaluable"
    assert auth.decision_eligible is False


def test_trusted_authentication_failure_evidence_is_not_hard():
    raw = b"Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\n\nbody"
    auth = _parse(raw, mode="trusted_ingress", trusted_authserv_id="mx")
    findings = authentication_evidence_items(auth)
    assert {item.signal_id for item in findings} == {"spf_fail", "dkim_fail", "dmarc_fail"}
    assert all(not item.hard_indicator for item in findings)
