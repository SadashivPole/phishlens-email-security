from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any

from .email import ParsedEmail
from .evidence import AnalysisCompleteness, EvidenceItem
from .indicators import UrlIndicator, _redact_url
from .ioc import IOC
from .scoring import ScoringResult
from .threat_intel import ThreatIntelResult
from .verdict import VerdictResult


@dataclass
class AnalysisResult:
    schema_version: str
    email: ParsedEmail
    urls: list[UrlIndicator]
    evidence: list[EvidenceItem]
    scoring: ScoringResult
    completeness: AnalysisCompleteness
    verdict: VerdictResult
    errors: list[str] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    threat_intelligence: list[ThreatIntelResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "email": self.email.to_dict(),
            "urls": [item.to_dict() for item in self.urls],
            "evidence": [item.to_dict() for item in self.evidence],
            "scoring": self.scoring.to_dict(),
            "completeness": self.completeness.to_dict(),
            "verdict": self.verdict.to_dict(),
            "errors": self.errors,
            "iocs": [item.to_dict() for item in self.iocs],
            "threat_intelligence": [item.to_dict() for item in self.threat_intelligence],
        }

    def to_safe_dict(self) -> dict[str, Any]:
        """Return the default report representation without message bodies."""
        return {
            "schema_version": self.schema_version,
            "email": {
                "from_address": self.email.from_address,
                "to_addresses": self.email.to_addresses,
                "cc_addresses": self.email.cc_addresses,
                "reply_to": self.email.reply_to,
                "subject": self.email.subject,
                "date": self.email.date,
                "message_id": self.email.message_id,
                "raw_size_bytes": self.email.raw_size_bytes,
                "attachment_count": len(self.email.attachments),
            },
            "authentication": _safe_authentication_summary(self.email.authentication_results),
            "urls": [item.to_safe_dict() for item in self.urls],
            "attachments": [item.to_dict() for item in self.email.attachments],
            "evidence": [_safe_evidence(item.to_dict()) for item in self.evidence],
            "scoring": self.scoring.to_dict(),
            "completeness": self.completeness.to_dict(),
            "verdict": self.verdict.to_dict(),
            "errors": self.errors,
            "iocs": [item.to_safe_dict() for item in self.iocs],
            "threat_intelligence": [item.to_safe_dict() for item in self.threat_intelligence],
        }


def _safe_evidence(item: dict[str, Any]) -> dict[str, Any]:
    evidence = item.get("evidence")
    if isinstance(evidence, dict) and "original_url" in evidence:
        safe_evidence = dict(evidence)
        safe_evidence.pop("original_url", None)
        normalized = safe_evidence.get("normalized_url")
        safe_evidence["normalized_url"] = _redact_url(normalized) if normalized else None
        safe_evidence.pop("display_text", None)
        item = dict(item)
        item["evidence"] = safe_evidence
    return item


def _safe_authentication_summary(headers: list[str]) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    pattern = re.compile(r"\b(spf|dkim|dmarc|arc)=([A-Za-z]+)", re.IGNORECASE)
    for header in headers:
        for match in pattern.finditer(header):
            results.append({"method": match.group(1).lower(), "result": match.group(2).lower()})
    return results
