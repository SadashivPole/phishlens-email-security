from __future__ import annotations

from ..analysis.attachment_analysis import attachment_evidence
from ..analysis.url_analysis import extract_urls, url_evidence
from ..config import Settings
from ..models.evidence import AnalysisAreaStatus, AnalysisCompleteness
from ..models.result import AnalysisResult
from ..parsing.authentication import authentication_evidence_items, parse_authentication_results
from ..parsing.eml_parser import parse_eml_bytes
from ..parsing.headers import header_evidence
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
        evidence.extend(header_evidence(email))
        auth = parse_authentication_results(email)
        evidence.extend(authentication_evidence_items(auth))
        urls = extract_urls(email)
        evidence.extend(url_evidence(urls))
        evidence.extend(attachment_evidence(email))
        url_status = "partial" if any(item.analysis_status != "complete" for item in urls) else "complete"
        url_note = "One or more URL candidates could not be safely normalized." if url_status == "partial" else "URLs were inspected without fetching them."

        completeness = AnalysisCompleteness({
            "parser": AnalysisAreaStatus("complete", "Email was parsed locally.", required=True),
            "identity": AnalysisAreaStatus("complete", "Available identity headers were inspected.", required=True),
            "authentication": AnalysisAreaStatus(auth.status.status, auth.status.note, required=True),
            "url": AnalysisAreaStatus(url_status, url_note, required=True),
            "attachment": AnalysisAreaStatus("complete", "Attachment metadata and hashes were generated locally.", required=True),
            "content": AnalysisAreaStatus("not_evaluable", "Content classification is not implemented in this foundation phase.", required=False),
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
            "content": AnalysisAreaStatus("not_evaluable", "Parsing did not complete.", required=False),
            "reputation": AnalysisAreaStatus("unavailable", "No external reputation provider is enabled.", required=False),
        })
        verdict = VerdictResult("UNRESOLVED", "The email could not be safely parsed.", completeness.overall_status, "low")
        return AnalysisResult("1.0", email, [], [], ScoringResult(), completeness, verdict, [error])
