from src.phishlens.analysis.content_analysis import content_evidence
from src.phishlens.models.email import ParsedEmail


def test_content_signals_capture_credential_urgency_and_payment_language():
    email = ParsedEmail(
        raw_size_bytes=100,
        body_text="Verify your password immediately. Payment overdue; change bank details now.",
    )
    findings = content_evidence(email)
    ids = {item.signal_id for item in findings}
    assert "credential_request" in ids
    assert "urgency_language" in ids
    assert "payment_request" in ids
    assert "credential_urgency_combination" in ids
    assert all(not item.hard_indicator for item in findings)


def test_content_heuristics_do_not_treat_generic_newsletter_language_as_malicious():
    email = ParsedEmail(
        raw_size_bytes=100,
        body_text="Read our monthly newsletter and review the latest product news.",
    )
    findings = content_evidence(email)
    assert all(item.signal_id != "credential_request" for item in findings)
    assert all(not item.hard_indicator for item in findings)
def test_generic_password_discussion_is_not_a_credential_request():
    email = ParsedEmail(
        raw_size_bytes=100,
        body_text="Our password policy was updated last quarter."
    )
    findings = content_evidence(email)
    assert all(item.signal_id != "credential_request" for item in findings)


def test_explicit_password_request_is_detected():
    email = ParsedEmail(
        raw_size_bytes=100,
        body_text="Please enter your password to verify your account."
    )
    findings = content_evidence(email)
    ids = {item.signal_id for item in findings}
    assert "credential_request" in ids
    assert all(not item.hard_indicator for item in findings)
