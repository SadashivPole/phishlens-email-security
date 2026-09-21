from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..models.email import ParsedEmail
from ..models.evidence import AnalysisAreaStatus, EvidenceItem

# Authentication-Results permits additional method-specific result values. The
# requested primary values are preserved exactly; other known receiver states
# remain representable without being converted into pass/fail.
COMMON_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}
PRIMARY_METHODS = {"spf", "dkim", "dmarc", "arc"}
METHOD_RE = re.compile(r"^\s*(spf|dkim|dmarc|arc)\s*=\s*([^\s;]+)(.*)$", re.IGNORECASE)
PROPERTY_RE = re.compile(r"(?:^|\s)([A-Za-z][A-Za-z0-9_.-]*)\s*=\s*([^\s;]+)")


@dataclass
class AuthResult:
    result: str
    source: str
    method: str
    domain: str | None = None
    selector: str | None = None
    note: str = ""
    raw_result: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "source": self.source,
            "method": self.method,
            "domain": self.domain,
            "selector": self.selector,
            "note": self.note,
            "raw_result": self.raw_result,
        }


@dataclass
class AuthenticationEvidence:
    spf: list[AuthResult] = field(default_factory=list)
    dkim: list[AuthResult] = field(default_factory=list)
    dmarc: list[AuthResult] = field(default_factory=list)
    arc: list[AuthResult] = field(default_factory=list)
    status: AnalysisAreaStatus = field(default_factory=lambda: AnalysisAreaStatus("not_evaluable"))
    header_state: str = "absent"

    def to_dict(self) -> dict[str, Any]:
        return {
            "spf": [item.to_dict() for item in self.spf],
            "dkim": [item.to_dict() for item in self.dkim],
            "dmarc": [item.to_dict() for item in self.dmarc],
            "arc": [item.to_dict() for item in self.arc],
            "status": self.status.to_dict(),
            "header_state": self.header_state,
        }


def parse_authentication_results(email: ParsedEmail) -> AuthenticationEvidence:
    evidence = AuthenticationEvidence()
    if not email.authentication_results:
        evidence.status = AnalysisAreaStatus(
            "not_evaluable",
            "Authentication-Results header is absent; DNS policy existence cannot prove message authentication.",
        )
        return evidence

    evidence.header_state = "present"
    recognized = 0
    malformed_segments = 0
    for header in email.authentication_results:
        parsed, malformed = _parse_header(header)
        recognized += len(parsed)
        malformed_segments += malformed
        for method, result, domain, selector, raw_result in parsed:
            target = getattr(evidence, method, None)
            if target is not None:
                target.append(AuthResult(
                    result=result,
                    source="authentication_results",
                    method=method,
                    domain=domain,
                    selector=selector,
                    raw_result=raw_result,
                ))

    if recognized == 0:
        evidence.status = AnalysisAreaStatus(
            "not_evaluable",
            "Authentication-Results headers were present but no supported authentication result was parsed.",
        )
    elif malformed_segments:
        evidence.status = AnalysisAreaStatus(
            "partial",
            "Some Authentication-Results segments were malformed or unsupported.",
        )
    else:
        evidence.status = AnalysisAreaStatus(
            "complete",
            "Authentication-Results assertions were observed and parsed.",
        )
    return evidence


def _parse_header(header: str) -> tuple[list[tuple[str, str, str | None, str | None, str]], int]:
    results: list[tuple[str, str, str | None, str | None, str]] = []
    malformed = 0
    # Semicolons delimit methods in Authentication-Results. Property values
    # within a method are space-separated and are parsed separately.
    for segment in header.split(";")[1:]:
        match = METHOD_RE.match(segment)
        if not match:
            if segment.strip():
                malformed += 1
            continue
        method = match.group(1).lower()
        raw_result = match.group(2).lower()
        result = raw_result if raw_result in COMMON_RESULTS else "unavailable"
        properties = {key.lower(): value for key, value in PROPERTY_RE.findall(match.group(3))}
        domain = properties.get("header.d") or properties.get("d")
        if method == "spf":
            domain = properties.get("smtp.mailfrom") or domain
        if method == "dmarc":
            domain = properties.get("header.from") or domain
        selector = properties.get("header.s") or properties.get("s")
        results.append((method, result, domain, selector, raw_result))
    return results, malformed


def authentication_evidence_items(auth: AuthenticationEvidence) -> list[EvidenceItem]:
    findings: list[EvidenceItem] = []
    for method in ("spf", "dkim", "dmarc"):
        seen: set[str] = set()
        for item in getattr(auth, method):
            if item.result == "fail" and item.result not in seen:
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
            elif method == "spf" and item.result == "softfail" and item.result not in seen:
                findings.append(EvidenceItem(
                    signal_id="spf_softfail",
                    category="authentication",
                    severity="low",
                    evidence=item.to_dict(),
                    explanation="Authentication-Results reports SPF softfail; forwarding and policy configuration can cause legitimate softfails.",
                    source="authentication_results",
                    reliability="low",
                    points=1,
                ))
            seen.add(item.result)
    return findings
