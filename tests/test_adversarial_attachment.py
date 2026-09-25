from __future__ import annotations

import base64

from phishlens.config import Settings
from phishlens.parsing.eml_parser import parse_eml_bytes
from phishlens.pipeline.analyzer import Analyzer


def make_attachment_email(
    filename: str,
    content_type: str,
    payload: bytes,
) -> bytes:
    encoded = base64.b64encode(payload).decode("ascii")
    raw = f"""From: sender@example.com
To: analyst@example.net
Subject: attachment adversarial test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="test-boundary"

--test-boundary
Content-Type: text/plain; charset="utf-8"

Please review the attachment.
--test-boundary
Content-Type: {content_type}
Content-Disposition: attachment; filename="{filename}"
Content-Transfer-Encoding: base64

{encoded}
--test-boundary--
"""
    return raw.encode("utf-8")


def test_pe_magic_bytes_override_pdf_declaration():
    raw = make_attachment_email(
        "invoice.pdf",
        "application/pdf",
        b"MZ" + b"\x00" * 16,
    )

    email = parse_eml_bytes(raw)

    attachment = email.attachments[0]
    assert attachment.detected_type == "PE executable"
    assert attachment.extension_mismatch is True


def test_pdf_magic_bytes_do_not_trust_executable_extension():
    raw = make_attachment_email(
        "invoice.exe",
        "application/octet-stream",
        b"%PDF-1.7\n" + b"0" * 16,
    )

    email = parse_eml_bytes(raw)

    attachment = email.attachments[0]
    assert attachment.detected_type == "PDF"
    assert attachment.extension_mismatch is True


def test_zip_magic_bytes_conflict_with_pdf_mime_type():
    raw = make_attachment_email(
        "document.pdf",
        "application/pdf",
        b"PK\x03\x04" + b"\x00" * 16,
    )

    email = parse_eml_bytes(raw)

    attachment = email.attachments[0]
    assert attachment.detected_type == "ZIP/archive"
    assert attachment.extension_mismatch is True


def test_ole_magic_bytes_conflict_with_pdf_mime_type():
    raw = make_attachment_email(
        "document.pdf",
        "application/pdf",
        b"\xd0\xcf\x11\xe0" + b"\x00" * 16,
    )

    email = parse_eml_bytes(raw)

    attachment = email.attachments[0]
    assert attachment.detected_type == "OLE compound document"
    assert attachment.extension_mismatch is True


def test_multiple_attachment_signals_do_not_exceed_attachment_cap():
    first = base64.b64encode(b"MZ" + b"\x00" * 16).decode("ascii")
    second = base64.b64encode(b"benign-looking content").decode("ascii")

    raw = f"""From: sender@example.com
To: analyst@example.net
Subject: multiple attachment scoring test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="multi"

--multi
Content-Type: text/plain; charset="utf-8"

Multiple attachments.
--multi
Content-Type: application/pdf
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

{first}
--multi
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="report.pdf.exe"
Content-Transfer-Encoding: base64

{second}
--multi--
""".encode("utf-8")

    result = Analyzer(Settings()).analyze(raw)

    assert len(result.email.attachments) == 2
    assert result.scoring.category_scores["attachment"] == 11
    assert result.scoring.category_scores["attachment"] <= 15
def test_zip_magic_bytes_with_executable_extension_are_flagged():
    raw = make_attachment_email(
        "invoice.exe",
        "application/octet-stream",
        b"PK\x03\x04" + b"\x00" * 16,
    )

    email = parse_eml_bytes(raw)

    attachment = email.attachments[0]
    assert attachment.detected_type == "ZIP/archive"
    assert attachment.extension_mismatch is True


def test_ole_magic_bytes_with_executable_extension_are_flagged():
    raw = make_attachment_email(
        "document.exe",
        "application/octet-stream",
        b"\xd0\xcf\x11\xe0" + b"\x00" * 16,
    )

    email = parse_eml_bytes(raw)

    attachment = email.attachments[0]
    assert attachment.detected_type == "OLE compound document"
    assert attachment.extension_mismatch is True
def test_zip_archive_with_zip_extension_is_not_flagged():
    raw = make_attachment_email(
        "archive.zip",
        "application/zip",
        b"PK\x03\x04" + b"\x00" * 16,
    )

    email = parse_eml_bytes(raw)

    attachment = email.attachments[0]
    assert attachment.detected_type == "ZIP/archive"
    assert attachment.extension_mismatch is False


def test_ole_document_with_doc_extension_is_not_flagged():
    raw = make_attachment_email(
        "document.doc",
        "application/msword",
        b"\xd0\xcf\x11\xe0" + b"\x00" * 16,
    )

    email = parse_eml_bytes(raw)

    attachment = email.attachments[0]
    assert attachment.detected_type == "OLE compound document"
    assert attachment.extension_mismatch is False
