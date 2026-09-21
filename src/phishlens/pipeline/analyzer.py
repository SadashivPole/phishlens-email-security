from __future__ import annotations

from ..analysis.attachment_analysis import attachment_evidence
from ..analysis.content_analysis import content_evidence
from ..analysis.url_analysis import extract_urls, url_evidence
from ..config import Settings
from ..models.evidence import AnalysisAreaStatus, AnalysisCompleteness
from ..models.result import AnalysisResult
from ..parsing.authentication import authentication_evidence_items, parse_authentication_results
from ..parsing.eml_parser import parse_eml_bytes
from ..parsing.headers import header_evidence, parse_received_headers, received_evidence
from ..scoring.policy import apply_policy
from ..scoring.rule_engine import score_evidence


class Analyzer:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()

    def analyze(self, raw: bytes) -> AnalysisResult:
        errors: list[str] = []
        try:
            email = parse_eml_bytes(raw, self.settings)
        except Exception as exc:
            # Do not expose raw input or secrets in the error string.
            return self._unresolved_result(raw, f"email parsing failed: {type(exc).__name__}")

        # The stdlib parser is intentionally permissive. Treat input with no
        # recognizable headers as a materially malformed message rather than a
        # successfully completed email analysis.
        if not email.headers:
            return self._unresolved_result(raw, "email has no recognizable message headers")

        evidence = []
        auth = parse_authentication_results(email)
        email.received_hops = parse_received_headers(email.received_headers)
        evidence.extend(header_evidence(email, auth))
        evidence.extend(authentication_evidence_items(auth))
        evidence.extend(received_evidence(email))
        urls = extract_urls(email)
        evidence.extend(url_evidence(urls))
        evidence.extend(attachment_evidence(email))
        content_findings = content_evidence(email)
        evidence.extend(content_findings)

        content_available = bool(
            (email.body_text or "").strip()
            or (email.body_html or "").strip()
        )
        content_status = "complete" if content_available else "not_evaluable"
        content_note = (
            "Deterministic local content heuristics were applied."
            if content_available
            else "No usable message body was available for content analysis."
        )
        url_status = "partial" if any(item.analysis_status != "complete" for item in urls) else "complete"
        url_note = "One or more URL candidates could not be safely normalized." if url_status == "partial" else "URLs were inspected without fetching them."
        mail_flow_status = "partial" if any(hop.malformed for hop in email.received_hops) else "complete"
        mail_flow_note = "One or more Received headers were malformed." if mail_flow_status == "partial" else "Received headers were inspected where available."

        completeness = AnalysisCompleteness({
            "parser": AnalysisAreaStatus("complete", "Email was parsed locally.", required=True),
            "identity": AnalysisAreaStatus("complete", "Available identity headers were inspected.", required=True),
            "authentication": AnalysisAreaStatus(auth.status.status, auth.status.note, required=True),
            "url": AnalysisAreaStatus(url_status, url_note, required=True),
            "attachment": AnalysisAreaStatus("complete", "Attachment metadata and hashes were generated locally.", required=True),
            "mail_flow": AnalysisAreaStatus(mail_flow_status, mail_flow_note, required=False),
            "content": AnalysisAreaStatus(content_status, content_note, required=False),
            "reputation": AnalysisAreaStatus("unavailable", "No external reputation provider is enabled.", required=False),
        })
        scoring = score_evidence(evidence)
        verdict = apply_policy(scoring, completeness, evidence)
        return AnalysisResult("1.0", email, urls, evidence, scoring, completeness, verdict, errors)

    def _unresolved_result(self, raw: bytes, error: str) -> AnalysisResult:
        from ..models.email import ParsedEmail
        from ..models.scoring import ScoringResult
        from ..models.verdict import VerdictResult

        email = ParsedEmail(raw_size_bytes=len(raw), parse_warnings=[error])
        completeness = AnalysisCompleteness({
            "parser": AnalysisAreaStatus("unavailable", error, required=True),
            "identity": AnalysisAreaStatus("not_evaluable", "Parsing did not complete.", required=True),
            "authentication": AnalysisAreaStatus("not_evaluable", "Parsing did not complete.", required=True),
            "url": AnalysisAreaStatus("not_evaluable", "Parsing did not complete.", required=True),
            "attachment": AnalysisAreaStatus("not_evaluable", "Parsing did not complete.", required=True),
            "mail_flow": AnalysisAreaStatus("not_evaluable", "Parsing did not complete.", required=False),
            "content": AnalysisAreaStatus("not_evaluable", "Parsing did not complete.", required=False),
            "reputation": AnalysisAreaStatus("unavailable", "No external reputation provider is enabled.", required=False),
        })
        verdict = VerdictResult("UNRESOLVED", "The email could not be safely parsed.", completeness.overall_status, "low")
        return AnalysisResult("1.0", email, [], [], ScoringResult(), completeness, verdict, [error])
