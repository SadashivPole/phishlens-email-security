from __future__ import annotations

from dataclasses import dataclass, field
from email.message import Message
from typing import Any


@dataclass
class Attachment:
    filename: str | None
    content_type: str
    size_bytes: int
    sha256: str
    detected_type: str = "unknown"
    extension_mismatch: bool = False
    double_extension: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "detected_type": self.detected_type,
            "extension_mismatch": self.extension_mismatch,
            "double_extension": self.double_extension,
        }


@dataclass
class ParsedEmail:
    raw_size_bytes: int
    headers: dict[str, list[str]] = field(default_factory=dict)
    from_address: str | None = None
    to_addresses: list[str] = field(default_factory=list)
    cc_addresses: list[str] = field(default_factory=list)
    reply_to: str | None = None
    return_path: str | None = None
    subject: str = ""
    date: str | None = None
    message_id: str | None = None
    received_headers: list[str] = field(default_factory=list)
    authentication_results: list[str] = field(default_factory=list)
    dkim_signatures: list[str] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)
    source_message: Message | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_size_bytes": self.raw_size_bytes,
            "headers": self.headers,
            "from_address": self.from_address,
            "to_addresses": self.to_addresses,
            "cc_addresses": self.cc_addresses,
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "subject": self.subject,
            "date": self.date,
            "message_id": self.message_id,
            "received_headers": self.received_headers,
            "authentication_results": self.authentication_results,
            "dkim_signatures": self.dkim_signatures,
            "body_text": self.body_text,
            "body_html": self.body_html,
            "attachments": [item.to_dict() for item in self.attachments],
            "parse_warnings": self.parse_warnings,
        }
