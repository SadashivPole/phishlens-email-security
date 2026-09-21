from __future__ import annotations

from ..models.email import ParsedEmail
from ..models.evidence import EvidenceItem


def attachment_evidence(email: ParsedEmail) -> list[EvidenceItem]:
    findings: list[EvidenceItem] = []
    for attachment in email.attachments:
        if attachment.extension_mismatch:
            findings.append(EvidenceItem(
                "attachment_type_mismatch", "attachment", "high", attachment.to_dict(),
                "The detected file type does not match the filename extension.",
                "local_attachment_analysis", "high", 7,
            ))
        if attachment.double_extension:
            findings.append(EvidenceItem(
                "attachment_double_extension", "attachment", "medium", attachment.to_dict(),
                "The attachment filename contains multiple extensions and warrants review.",
                "local_attachment_analysis", "medium", 4,
            ))
    return findings
