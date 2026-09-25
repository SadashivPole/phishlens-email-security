from __future__ import annotations

import json
import base64

from phishlens.config import Settings
from phishlens.pipeline.analyzer import Analyzer


def analyze(raw: bytes):
    return Analyzer(Settings()).analyze(raw)


def safe_json(raw: bytes) -> str:
    return json.dumps(analyze(raw).to_safe_dict(), sort_keys=True)


def test_safe_report_excludes_body_html_and_full_headers():
    secret_body = "BODY-CANARY-9f3a"
    secret_html = "HTML-CANARY-7b2d"
    secret_header = "HEADER-CANARY-4c8e"

    raw = f"""From: sender@example.com
To: analyst@example.net
X-Debug-Secret: {secret_header}
Subject: safe output test
Content-Type: multipart/alternative; boundary="safe"

--safe
Content-Type: text/plain; charset="utf-8"

{secret_body}
--safe
Content-Type: text/html; charset="utf-8"

<html><body>{secret_html}</body></html>
--safe--
""".encode("utf-8")

    output = safe_json(raw)

    assert secret_body not in output
    assert secret_html not in output
    assert secret_header not in output
    assert "X-Debug-Secret" not in output


def test_safe_report_redacts_sensitive_url_query_values():
    token = "TOKEN-CANARY-123"
    password = "PASSWORD-CANARY-456"
    email = "EMAIL-CANARY-789"

    raw = f"""From: sender@example.com
To: analyst@example.net
Subject: URL privacy test

https://example.com/reset?token={token}&password={password}&email={email}&campaign=spring
""".encode("utf-8")

    output = safe_json(raw)

    assert token not in output
    assert password not in output
    assert email not in output
    assert "%5BREDACTED%5D" in output
    assert "campaign=spring" in output


def test_safe_report_removes_url_userinfo_credentials():
    username = "user-canary"
    password = "PASS-CANARY-321"

    raw = f"""From: sender@example.com
To: analyst@example.net
Subject: userinfo privacy test

https://{username}:{password}@evil.example/login
""".encode("utf-8")

    output = safe_json(raw)

    assert username not in output
    assert password not in output
    assert "evil.example" in output


def test_safe_report_excludes_attachment_payload():
    payload = b"ATTACHMENT-PAYLOAD-CANARY-9876"
    encoded = base64.b64encode(payload).decode("ascii")

    raw = f"""From: sender@example.com
To: analyst@example.net
Subject: attachment privacy test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="attach"

--attach
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="document.bin"
Content-Transfer-Encoding: base64

{encoded}
--attach--
""".encode("utf-8")

    output = safe_json(raw)

    assert payload.decode("ascii") not in output
    assert encoded not in output
    assert "document.bin" in output


def test_safe_report_does_not_echo_malformed_input_in_errors():
    canary = "MALFORMED-INPUT-CANARY-2468"

    raw = (
        f"From: sender@example.com\n"
        f"X-Canary: {canary}\n"
        f"\n"
        f"https://example.com:notaport/{canary}\n"
    ).encode("utf-8")

    result = analyze(raw)
    output = json.dumps(result.to_safe_dict(), sort_keys=True)

    assert result.completeness.areas["url"].status == "partial"
    assert canary not in output
def test_safe_report_redacts_userinfo_from_ipv6_url():
    username = "ipv6-user-canary"
    password = "ipv6-pass-canary"

    raw = f"""From: sender@example.com
To: analyst@example.net
Subject: IPv6 userinfo privacy test

https://{username}:{password}@[2001:db8::10]:8443/login
""".encode("utf-8")

    output = safe_json(raw)

    assert username not in output
    assert password not in output
    assert "[2001:db8::10]:8443" in output
