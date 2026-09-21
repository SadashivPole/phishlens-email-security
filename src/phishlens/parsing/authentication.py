from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..models.email import ParsedEmail
from ..models.evidence import AnalysisAreaStatus, EvidenceItem

_ALLOWED = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}


@dataclass
class AuthResult:
    result: str
    source: str
    method: str
    domain: str | None = None
    selector: str | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "source": self.source,
            "method": self.method,
            "domain": self.domain,
            "selector": self.selector,
            "note": self.note,
        }


@dataclass
class AuthenticationEvidence:
    spf: list[AuthResult] = field(default_factory=list)
    dkim: list[AuthResult] = field(default_factory=list)
    dmarc: list[AuthResult] = field(default_factory=list)
    arc: list[AuthResult] = field(default_factory=list)
    status: AnalysisAreaStatus = field(default_factory=lambda: AnalysisAreaStatus("not_evaluable"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "spf": [item.to_dict() for item in self.spf],
            "dkim": [item.to_dict() for item in self.dkim],
            "dmarc": [item.to_dict() for item in self.dmarc],
            "arc": [item.to_dict() for item in self.arc],
            "status": self.status.to_dict(),
        }


def parse_authentication_results(email: ParsedEmail) -> AuthenticationEvidence:
    evidence = AuthenticationEvidence()
    if not email.authentication_results:
        evidence.status = AnalysisAreaStatus(
            "not_evaluable",
            "Authentication-Results header is absent; DNS policy existence cannot prove message authentication.",
        )
        return evidence

    for header in email.authentication_results:
        for method, result, domain, selector in _parse_header(header):
            target = getattr(evidence, method, None)
            if target is not None:
                target.append(AuthResult(result, "authentication_results", method, domain, selector))

    evidence.status = AnalysisAreaStatus("complete", "Authentication-Results assertions were observed and parsed.")
    return evidence


def _parse_header(header: str) -> list[tuple[str, str, str | None, str | None]]:
    results: list[tuple[str, str, str | None, str | None]] = []
    # Authentication-Results uses semicolon-separated method=result tokens.
    for match in re.finditer(r"\b(spf|dkim|dmarc|arc)=([A-Za-z]+)([^;]*)", header, flags=re.IGNORECASE):
        method = match.group(1).lower()
        raw_result = match.group(2).lower()
        result = raw_result if raw_result in _ALLOWED else "unavailable"
        tail = match.group(3)
        domain_match = re.search(r"\bd=([^\s;]+)", tail, flags=re.IGNORECASE)
        selector_match = re.search(r"\bs=([^\s;]+)", tail, flags=re.IGNORECASE)
        results.append((method, result, domain_match.group(1) if domain_match else None, selector_match.group(1) if selector_match else None))
    return results


def authentication_evidence_items(auth: AuthenticationEvidence) -> list[EvidenceItem]:
    findings: list[EvidenceItem] = []
    for method in ("spf", "dkim", "dmarc"):
        for item in getattr(auth, method):
            if item.result == "fail":
                findings.append(EvidenceItem(
                    signal_id=f"{method}_fail",
                    category="authentication",
                    severity="medium",
                    evidence=item.to_dict(),
                    explanation=f"Authentication-Results reports {method.upper()} failure; this is an anomaly but not standalone proof of phishing.",
                    source="authentication_results",
                    reliability="medium",
                    points=4,
                ))
    return findings
