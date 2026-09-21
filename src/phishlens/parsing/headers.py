from __future__ import annotations

import re
from email.utils import parseaddr

from ..models.email import ParsedEmail
from ..models.evidence import EvidenceItem


def address_domain(value: str | None) -> str | None:
    if not value:
        return None
    _, address = parseaddr(value)
    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower().strip().rstrip(">")


def header_evidence(email: ParsedEmail) -> list[EvidenceItem]:
    findings: list[EvidenceItem] = []
    from_domain = address_domain(email.from_address)
    reply_domain = address_domain(email.reply_to)
    return_domain = address_domain(email.return_path)

    if from_domain and reply_domain and from_domain != reply_domain:
        findings.append(EvidenceItem(
            signal_id="reply_to_mismatch",
            category="identity",
            severity="medium",
            evidence={"from_domain": from_domain, "reply_to_domain": reply_domain},
            explanation="The Reply-To domain differs from the visible From domain.",
            source="local_header_analysis",
            reliability="medium",
            points=4,
        ))

    if from_domain and return_domain and from_domain != return_domain:
        findings.append(EvidenceItem(
            signal_id="return_path_mismatch",
            category="identity",
            severity="low",
            evidence={"from_domain": from_domain, "return_path_domain": return_domain},
            explanation="The Return-Path domain differs from the visible From domain.",
            source="local_header_analysis",
            reliability="low",
            points=2,
        ))

    message_id_domain = _message_id_domain(email.message_id)
    if from_domain and message_id_domain and from_domain != message_id_domain:
        findings.append(EvidenceItem(
            signal_id="message_id_domain_mismatch",
            category="identity",
            severity="low",
            evidence={"from_domain": from_domain, "message_id_domain": message_id_domain},
            explanation="The Message-ID domain differs from the visible From domain; this is an anomaly, not proof of phishing.",
            source="local_header_analysis",
            reliability="low",
            points=1,
        ))
    return findings


def _message_id_domain(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"@([^>\s]+)", value)
    return match.group(1).lower().rstrip(">") if match else None
