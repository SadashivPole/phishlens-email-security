import pytest

from phishlens.config import Settings
from phishlens.pipeline.analyzer import Analyzer


def analyze(raw: str):
    settings = Settings()
    return Analyzer(settings).analyze(raw.encode("utf-8"))


def test_duplicate_from_headers_are_not_silently_trusted():
    raw = """From: attacker@example.com
From: trusted-looking@example.org
To: victim@example.net
Subject: duplicate from test
Message-ID: <test@example.com>

Hello
"""

    result = analyze(raw)

    assert len(result.email.headers.get("from", [])) == 2


def test_duplicate_reply_to_headers_are_visible():
    raw = """From: sender@example.com
Reply-To: first@example.com
Reply-To: second@example.org
To: victim@example.net
Subject: duplicate reply-to test

Hello
"""

    result = analyze(raw)

    assert len(result.email.headers.get("reply-to", [])) == 2


def test_duplicate_return_path_headers_are_visible():
    raw = """From: sender@example.com
Return-Path: first@example.com
Return-Path: second@example.org
To: victim@example.net
Subject: duplicate return-path test

Hello
"""

    result = analyze(raw)

    assert len(result.email.headers.get("return-path", [])) == 2


def test_conflicting_identity_domains_are_preserved_in_safe_analysis():
    raw = """From: sender@evil.example
Reply-To: victim@trusted.example
Return-Path: bounce@other.example
To: victim@example.net
Subject: conflicting identity test
Message-ID: <abc@evil.example>

Hello
"""

    result = analyze(raw)

    assert result.email.from_address == "sender@evil.example"
    assert result.email.reply_to == "victim@trusted.example"
    assert result.email.return_path == "bounce@other.example"
def test_duplicate_from_makes_identity_analysis_partial():
    raw = """From: attacker@example.com
From: trusted-looking@example.org
To: victim@example.net
Subject: duplicate identity test

Hello
"""

    result = analyze(raw)

    assert result.completeness.areas["identity"].status == "partial"
    assert result.completeness.overall_status == "partial"
    assert result.verdict.final == "UNRESOLVED"
def test_duplicate_reply_to_makes_identity_analysis_partial():
    raw = """From: sender@example.com
Reply-To: first@example.com
Reply-To: second@example.org
To: victim@example.net
Subject: duplicate reply-to test

Hello
"""

    result = analyze(raw)

    assert result.completeness.areas["identity"].status == "partial"
    assert result.completeness.overall_status == "partial"
    assert result.verdict.final == "UNRESOLVED"


def test_duplicate_return_path_makes_identity_analysis_partial():
    raw = """From: sender@example.com
Return-Path: first@example.com
Return-Path: second@example.org
To: victim@example.net
Subject: duplicate return-path test

Hello
"""

    result = analyze(raw)

    assert result.completeness.areas["identity"].status == "partial"
    assert result.completeness.overall_status == "partial"
    assert result.verdict.final == "UNRESOLVED"


def test_duplicate_message_id_makes_identity_analysis_partial():
    raw = """From: sender@example.com
Message-ID: <first@example.com>
Message-ID: <second@example.org>
To: victim@example.net
Subject: duplicate message-id test

Hello
"""

    result = analyze(raw)

    assert result.completeness.areas["identity"].status == "partial"
    assert result.completeness.overall_status == "partial"
    assert result.verdict.final == "UNRESOLVED"
def test_safe_report_does_not_silently_select_duplicate_from():
    raw = """From: attacker@example.com
From: trusted-looking@example.org
To: victim@example.net
Subject: safe report ambiguity test

Hello
"""

    result = analyze(raw)
    safe = result.to_safe_dict()

    assert safe["completeness"]["areas"]["identity"]["status"] == "partial"
    assert safe["verdict"]["final"] == "UNRESOLVED"
    assert safe["email"]["from_address"] is None
    assert "from" in safe["email"]["identity_header_conflicts"]
def test_safe_report_does_not_silently_select_duplicate_reply_to():
    raw = """From: sender@example.com
Reply-To: first@example.com
Reply-To: second@example.org
To: victim@example.net
Subject: safe reply-to ambiguity test

Hello
"""

    result = analyze(raw)
    safe = result.to_safe_dict()

    assert safe["completeness"]["areas"]["identity"]["status"] == "partial"
    assert safe["verdict"]["final"] == "UNRESOLVED"
    assert safe["email"]["reply_to"] is None
    assert safe["email"]["identity_header_conflicts"]["reply-to"] == 2


def test_safe_report_records_duplicate_return_path_without_exposing_value():
    raw = """From: sender@example.com
Return-Path: first@example.com
Return-Path: second@example.org
To: victim@example.net
Subject: safe return-path ambiguity test

Hello
"""

    result = analyze(raw)
    safe = result.to_safe_dict()

    assert safe["completeness"]["areas"]["identity"]["status"] == "partial"
    assert safe["verdict"]["final"] == "UNRESOLVED"
    assert safe["email"]["identity_header_conflicts"]["return-path"] == 2
    assert "return_path" not in safe["email"]


def test_safe_report_does_not_silently_select_duplicate_message_id():
    raw = """From: sender@example.com
Message-ID: <first@example.com>
Message-ID: <second@example.org>
To: victim@example.net
Subject: safe message-id ambiguity test

Hello
"""

    result = analyze(raw)
    safe = result.to_safe_dict()

    assert safe["completeness"]["areas"]["identity"]["status"] == "partial"
    assert safe["verdict"]["final"] == "UNRESOLVED"
    assert safe["email"]["message_id"] is None
    assert safe["email"]["identity_header_conflicts"]["message-id"] == 2
