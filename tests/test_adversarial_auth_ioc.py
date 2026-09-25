from src.phishlens.extractor.ioc_extractor import extract_iocs
from src.phishlens.parsing.eml_parser import parse_eml_bytes


def test_raw_authentication_results_domains_are_not_provider_eligible_iocs():
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: attacker.invalid; "
        b"spf=pass smtp.mailfrom=attacker-controlled.example; "
        b"dkim=pass header.d=forged-signer.example; "
        b"dmarc=pass header.from=forged-from.example\n"
        b"\n"
        b"body"
    )

    email = parse_eml_bytes(raw)
    iocs = extract_iocs(email, [])

    auth_domains = {
        ioc.normalized_value
        for ioc in iocs
        if ioc.ioc_type == "domain"
        and ioc.source == "authentication_results"
    }

    assert auth_domains == set()


def test_raw_authentication_results_remain_visible_to_auth_parser():
    from src.phishlens.parsing.authentication import parse_authentication_results

    raw = (
        b"Authentication-Results: attacker.invalid; "
        b"spf=pass smtp.mailfrom=attacker-controlled.example; "
        b"dkim=pass header.d=forged-signer.example\n"
        b"\n"
        b"body"
    )

    email = parse_eml_bytes(raw)
    auth = parse_authentication_results(email)

    assert auth.trust == "untrusted_assertion"
    assert auth.decision_eligible is False
    assert auth.spf[0].domain == "attacker-controlled.example"
    assert auth.dkim[0].domain == "forged-signer.example"

def test_trusted_authentication_results_domains_are_allowed_when_decision_eligible():
    from src.phishlens.parsing.authentication import parse_authentication_results

    raw = (
        b"Authentication-Results: mx.example; "
        b"spf=pass smtp.mailfrom=trusted-sender.example; "
        b"dkim=pass header.d=trusted-signer.example; "
        b"dmarc=pass header.from=trusted-sender.example\n"
        b"\n"
        b"body"
    )

    email = parse_eml_bytes(raw)
    auth = parse_authentication_results(
        email,
        mode="trusted_ingress",
        trusted_authserv_id="mx.example",
    )

    assert auth.decision_eligible is True

    iocs = extract_iocs(email, [], authentication=auth)

    auth_domains = {
        ioc.normalized_value
        for ioc in iocs
        if ioc.ioc_type == "domain"
        and ioc.source == "authentication_results"
    }

    assert auth_domains == {
        "trusted-sender.example",
        "trusted-signer.example",
    }
