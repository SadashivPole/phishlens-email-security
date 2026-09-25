from __future__ import annotations

import ipaddress
import re
from email.utils import parseaddr

from ..models.email import ParsedEmail, ReceivedHop
from ..models.evidence import EvidenceItem
from .authentication import AuthenticationEvidence
from .domain_alignment import compare_domains

_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:.]+(?![\w:])")
_BRACKET_RE = re.compile(r"\[([^\]]+)\]")
_FROM_RE = re.compile(r"\bfrom\s+([^\s(;,]+)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+([^\s(;,]+)", re.IGNORECASE)


def address_domain(value: str | None) -> str | None:
    if not value:
        return None
    _, address = parseaddr(value)
    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower().strip().rstrip(">")


def header_evidence(email: ParsedEmail, auth: AuthenticationEvidence | None = None) -> list[EvidenceItem]:
    findings: list[EvidenceItem] = []

    for header_name in ("from", "reply-to", "return-path", "message-id"):
        values = email.headers.get(header_name, [])
        if len(values) > 1:
            findings.append(EvidenceItem(
                signal_id="duplicate_identity_header",
                category="identity",
                severity="medium",
                evidence={
                    "header": header_name,
                    "value_count": len(values),
                },
                explanation=(
                    f"The {header_name} header appears multiple times; "
                    "identity analysis is incomplete because no single value "
                    "should be treated as authoritative."
                ),
                source="local_header_analysis",
                reliability="high",
                points=0,
            ))
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

    if auth and from_domain:
        if auth.decision_eligible:
            findings.extend(_authenticated_domain_evidence(from_domain, auth))
        findings.extend(_alignment_evidence(from_domain, auth))
    return findings


def parse_received_headers(headers: list[str]) -> list[ReceivedHop]:
    hops: list[ReceivedHop] = []
    for order, raw in enumerate(headers):
        source_match = _FROM_RE.search(raw)
        by_match = _BY_RE.search(raw)
        source_hostname = source_match.group(1).strip("[]") if source_match else None
        by_hostname = by_match.group(1).strip("[]") if by_match else None
        source_ips: list[str] = []
        reasons: list[str] = []

        for candidate in _ip_candidates(raw):
            if candidate not in source_ips:
                source_ips.append(candidate)

        if source_match is None or by_match is None:
            reasons.append("missing from or by clause")
        if raw.count("[") != raw.count("]"):
            reasons.append("unbalanced brackets")
        for bracketed in _BRACKET_RE.findall(raw):
            if _looks_like_ip(bracketed) and not _valid_ip(bracketed):
                reasons.append("invalid bracketed IP literal")

        hops.append(ReceivedHop(
            order=order,
            raw=raw,
            source_hostname=source_hostname,
            source_ips=source_ips,
            by_hostname=by_hostname,
            malformed=bool(reasons),
            suspicious_reasons=sorted(set(reasons)),
        ))
    return hops


def received_evidence(email: ParsedEmail) -> list[EvidenceItem]:
    findings: list[EvidenceItem] = []
    for hop in email.received_hops:
        if hop.malformed:
            findings.append(EvidenceItem(
                signal_id="received_hop_malformed",
                category="identity",
                severity="low",
                evidence=hop.to_dict(),
                explanation="A Received header could not be fully interpreted; mail-flow conclusions are limited.",
                source="local_received_header_analysis",
                reliability="low",
                points=0,
            ))
    return findings


def _alignment_evidence(from_domain: str, auth: AuthenticationEvidence) -> list[EvidenceItem]:
    """Compare asserted authentication domains with the visible From domain.

    This is standards-aware domain comparison only. It does not evaluate the
    effective DMARC policy mode, SPF DNS policy, or DKIM cryptographic validity.
    """
    findings: list[EvidenceItem] = []
    for method, label in (("spf", "SPF"), ("dkim", "DKIM")):
        records = [
            item for item in getattr(auth, method)
            if item.domain and item.result != "unavailable"
        ]
        if not records:
            findings.append(EvidenceItem(
                signal_id=f"{method}_alignment_not_evaluable",
                category="identity",
                severity="info",
                evidence={
                    "mechanism": method,
                    "alignment": "not_evaluable",
                    "from_domain": from_domain,
                    "authenticated_domains": [],
                    "effective_alignment": "unknown",
                    "trust": auth.trust,
                    "decision_eligible": auth.decision_eligible,
                    "provenance": {
                        "source": "Authentication-Results",
                        "analysis": "domain comparison only",
                        "verification": "no independent SPF DNS or DKIM cryptographic verification",
                        "policy_mode": "unknown",
                    },
                },
                explanation=f"{label} alignment could not be evaluated from the available Authentication-Results properties; effective DMARC alignment is unknown and this is not independent {label} verification.",
                source="authentication_results",
                reliability="low",
                points=0,
            ))
            continue

        observations = []
        for item in records:
            comparison = compare_domains(from_domain, item.domain)
            details = comparison.to_dict()
            if comparison.strict_alignment is True or comparison.relaxed_alignment is True:
                details["alignment"] = "aligned"
            elif comparison.strict_alignment is False and comparison.relaxed_alignment is False:
                details["alignment"] = "misaligned"
            else:
                details["alignment"] = "not_evaluable"
            details["authentication_result"] = item.result
            details["selector"] = item.selector
            details["provenance"]["method"] = item.method
            details["provenance"]["authentication_source"] = item.source
            observations.append(details)

        states = {item["alignment"] for item in observations}
        alignment = states.pop() if len(states) == 1 else "partial"
        findings.append(EvidenceItem(
            signal_id=f"{method}_alignment",
            category="identity",
            severity="info" if alignment == "aligned" else "low",
            evidence={
                "mechanism": method,
                "alignment": alignment,
                "from_domain": observations[0]["from_domain"],
                "observations": observations,
                "effective_alignment": "unknown",
                "trust": auth.trust,
                "decision_eligible": auth.decision_eligible,
                "verification_scope": "strict/relaxed domain comparison only; effective DMARC policy mode is unavailable; no independent cryptographic or DNS verification",
            },
            explanation=(
                f"{label} strict and relaxed domain alignment were compared from "
                f"{'configured trusted-ingress' if auth.decision_eligible else 'untrusted message'} "
                f"Authentication-Results assertions; effective DMARC alignment is unknown and this does not independently verify {label}."
            ),
            source="authentication_results",
            reliability="medium" if auth.decision_eligible else "low",
            points=0,
        ))
    return findings

def _authenticated_domain_evidence(from_domain: str, auth: AuthenticationEvidence) -> list[EvidenceItem]:
    # Aggregate mechanism results into at most one finding per underlying
    # mismatch type, preventing repeated Authentication-Results headers from
    # multiplying the score.
    spf_domains = sorted({item.domain for item in auth.spf if item.domain and item.result in {"pass", "fail", "softfail", "neutral", "none"}})
    dkim_domains = sorted({item.domain for item in auth.dkim if item.domain and item.result in {"pass", "fail", "none"}})
    findings: list[EvidenceItem] = []
    if any(domain != from_domain for domain in spf_domains):
        findings.append(EvidenceItem(
            signal_id="authenticated_domain_mismatch",
            category="identity",
            severity="medium",
            evidence={"from_domain": from_domain, "authenticated_domains": spf_domains, "mechanism": "spf"},
            explanation="The visible From domain differs from the domain reported for SPF authentication.",
            source="authentication_results",
            reliability="medium",
            points=3,
        ))
    if any(domain != from_domain for domain in dkim_domains):
        findings.append(EvidenceItem(
            signal_id="dkim_signing_domain_mismatch",
            category="identity",
            severity="medium",
            evidence={"from_domain": from_domain, "signing_domains": dkim_domains, "mechanism": "dkim"},
            explanation="The DKIM signing domain differs from the visible From domain; alignment is not independently verified here.",
            source="authentication_results",
            reliability="medium",
            points=3,
        ))
    return findings


def _ip_candidates(value: str) -> list[str]:
    candidates = _BRACKET_RE.findall(value)
    candidates += _IPV4_RE.findall(value)
    candidates += _IPV6_RE.findall(value)
    return [candidate for candidate in candidates if _valid_ip(candidate)]


def _looks_like_ip(value: str) -> bool:
    return ":" in value or bool(_IPV4_RE.fullmatch(value))


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _message_id_domain(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"@([^>\s]+)", value)
    return match.group(1).lower().rstrip(">") if match else None
