from __future__ import annotations

import html
import re

from ..models.email import ParsedEmail
from ..models.evidence import EvidenceItem

PATTERNS: dict[str, tuple[tuple[str, ...], str, str, int]] = {
    "credential_request": (
        (r"\b(?:enter|provide|submit|share|send|type|confirm|verify)\s+(?:your\s+)?(?:password|passcode|one[- ]time code|verification code|credentials?)\b",),
        "medium",
        "The message contains language requesting or handling credentials or verification secrets.",
        2,
    ),
    "urgency_language": (
        (r"\b(?:urgent|immediately|act now|within\s+\d+\s+(?:hours?|minutes?)|account will be suspended|expires? today)\b",),
        "low",
        "The message uses urgency or consequence language.",
        1,
    ),
    "payment_request": (
        (r"\b(?:payment|wire transfer|gift card|invoice|payment overdue|bank details|bank account|change\s+(?:the\s+)?bank)\b",),
        "medium",
        "The message contains payment, invoice, or bank-detail language.",
        2,
    ),
    "account_verification": (
        (r"\b(?:verify|confirm)\s+(?:your\s+)?(?:account|identity|email|login)\b|\bpassword reset\b|\bsecurity alert\b",),
        "medium",
        "The message requests account verification or password-reset action.",
        2,
    ),
    "suspicious_call_to_action": (
        (r"\b(?:click|tap|open|review|sign\s*in|log\s*in|login)\b.{0,50}\b(?:here|now|below|link|portal|account)\b",),
        "low",
        "The message contains a direct call to action that may require review in context.",
        1,
    ),
    "bec_language": (
        (r"\b(?:keep this confidential|are you available|need this handled|do not discuss|quick favor|on my behalf)\b",),
        "medium",
        "The message contains language commonly seen in business-email-compromise scenarios.",
        2,
    ),
}


def content_evidence(email: ParsedEmail) -> list[EvidenceItem]:
    text = _plain_content(email)
    findings: list[EvidenceItem] = []
    matched: set[str] = set()
    for signal_id, (patterns, severity, explanation, points) in PATTERNS.items():
        matches: list[str] = []
        for pattern in patterns:
            matches.extend(match.group(0) for match in re.finditer(pattern, text, re.IGNORECASE | re.DOTALL))
        if matches and signal_id not in matched:
            matched.add(signal_id)
            findings.append(EvidenceItem(
                signal_id=signal_id,
                category="content",
                severity=severity,  # type: ignore[arg-type]
                evidence={"matches": sorted(set(matches))[:5]},
                explanation=explanation,
                source="local_content_analysis",
                reliability="low" if severity == "low" else "medium",
                points=points,
            ))

    if "credential_request" in matched and "urgency_language" in matched:
        findings.append(EvidenceItem(
            signal_id="credential_urgency_combination",
            category="content",
            severity="medium",
            evidence={"signals": ["credential_request", "urgency_language"]},
            explanation="Credential-related language is combined with urgency or consequences.",
            source="local_content_analysis",
            reliability="medium",
            points=2,
        ))
    if "payment_request" in matched and "urgency_language" in matched:
        findings.append(EvidenceItem(
            signal_id="payment_urgency_combination",
            category="content",
            severity="medium",
            evidence={"signals": ["payment_request", "urgency_language"]},
            explanation="Payment or invoice language is combined with urgency or consequences.",
            source="local_content_analysis",
            reliability="medium",
            points=2,
        ))
    return findings


def _plain_content(email: ParsedEmail) -> str:
    html_text = re.sub(r"<[^>]*>", " ", email.body_html or "")
    return html.unescape(f"{email.body_text}\n{html_text}")
