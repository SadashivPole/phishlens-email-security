from __future__ import annotations

import hashlib
import re
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path

from ..config import Settings
from ..models.email import Attachment, ParsedEmail

MAGIC_TYPES: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "PE executable"),
    (b"%PDF", "PDF"),
    (b"PK\x03\x04", "ZIP/archive"),
    (b"\xd0\xcf\x11\xe0", "OLE compound document"),
)


def parse_eml_bytes(raw: bytes, settings: Settings | None = None) -> ParsedEmail:
    settings = settings or Settings()
    if len(raw) > settings.max_email_bytes:
        raise ValueError(f"email exceeds maximum size of {settings.max_email_bytes} bytes")

    message = BytesParser(policy=policy.default).parsebytes(raw)
    result = ParsedEmail(raw_size_bytes=len(raw), source_message=message)
    _extract_headers(message, result)
    _extract_parts(message, result, settings)
    return result


def parse_eml_file(path: str | Path, settings: Settings | None = None) -> ParsedEmail:
    return parse_eml_bytes(Path(path).read_bytes(), settings=settings)


def _extract_headers(message: Message, result: ParsedEmail) -> None:
    for name, value in message.raw_items():
        result.headers.setdefault(name.lower(), []).append(str(value))

    result.from_address = message.get("From")
    result.to_addresses = _split_addresses(message.get_all("To", []))
    result.cc_addresses = _split_addresses(message.get_all("Cc", []))
    result.reply_to = message.get("Reply-To")
    result.return_path = message.get("Return-Path")
    result.subject = str(message.get("Subject", ""))
    result.date = message.get("Date")
    result.message_id = message.get("Message-ID")
    result.received_headers = [str(item) for item in message.get_all("Received", [])]
    result.authentication_results = [str(item) for item in message.get_all("Authentication-Results", [])]
    result.dkim_signatures = [str(item) for item in message.get_all("DKIM-Signature", [])]


def _split_addresses(values: list[str]) -> list[str]:
    # Keep parsing conservative; full address normalization belongs in a later phase.
    return [value.strip() for value in values if value.strip()]


def _extract_parts(message: Message, result: ParsedEmail, settings: Settings) -> None:
    part_count = 0
    for part in message.walk():
        part_count += 1
        if part_count > settings.max_mime_parts:
            result.parse_warnings.append("maximum MIME part count exceeded")
            break
        if part.is_multipart():
            continue

        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        payload = part.get_payload(decode=True)
        if payload is None:
            payload = b""

        if disposition == "attachment" or filename:
            result.attachments.append(_attachment_from_part(part, payload, settings))
            continue

        if content_type == "text/plain":
            result.body_text += _decode_text_part(part, payload)
        elif content_type == "text/html":
            result.body_html += _decode_text_part(part, payload)


def _decode_text_part(part: Message, payload: bytes) -> str:
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _attachment_from_part(part: Message, payload: bytes, settings: Settings) -> Attachment:
    if len(payload) > settings.max_attachment_bytes:
        raise ValueError(f"attachment exceeds maximum size of {settings.max_attachment_bytes} bytes")

    filename = part.get_filename()
    detected_type = detect_file_type(payload)
    declared_type = part.get_content_type()
    extension_mismatch = _extension_mismatch(filename, declared_type, detected_type)
    double_extension = bool(filename and re.search(r"\.[^.]+\.[^.]+$", filename))
    return Attachment(
        filename=filename,
        content_type=declared_type,
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        detected_type=detected_type,
        extension_mismatch=extension_mismatch,
        double_extension=double_extension,
    )


def detect_file_type(payload: bytes) -> str:
    for magic, description in MAGIC_TYPES:
        if payload.startswith(magic):
            return description
    return "unknown"


def _extension_mismatch(filename: str | None, declared_type: str, detected_type: str) -> bool:
    if detected_type == "unknown":
        return False
    lowered = (filename or "").lower()
    executable_extensions = (".exe", ".dll", ".scr", ".com")
    if detected_type == "PE executable":
        return declared_type == "application/pdf" or not lowered.endswith((".exe", ".dll", ".scr", ".com"))
    if detected_type == "PDF":
        return declared_type not in {"application/pdf", "application/octet-stream"} or not lowered.endswith(".pdf")
    if detected_type == "ZIP/archive":
        return (
            declared_type in {"application/pdf", "image/png", "image/jpeg"}
            or lowered.endswith(executable_extensions)
        )
    if detected_type == "OLE compound document":
        return (
            declared_type in {"application/pdf", "text/plain"}
            or lowered.endswith(executable_extensions)
        )
    return False
