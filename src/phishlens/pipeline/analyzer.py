from __future__ import annotations

from ..analysis.attachment_analysis import attachment_evidence
from ..analysis.content_analysis import content_evidence
from ..analysis.url_analysis import extract_urls, url_evidence
from ..config import Settings
from ..extractor.ioc_extractor import extract_iocs
from ..enrichment.configured import providers_from_config
from ..enrichment.orchestrator import EnrichmentOrchestrator
from ..models.evidence import AnalysisAreaStatus, AnalysisCompleteness
from ..models.result import AnalysisResult
from ..parsing.authentication import authentication_evidence_items, parse_authentication_results
from ..parsing.eml_parser import parse_eml_bytes
from ..parsing.headers import header_evidence, parse_received_headers, received_evidence
from ..scoring.policy import apply_policy
from ..scoring.rule_engine import score_evidence
from ..scoring.threat_intel_policy import has_provider_failure, threat_intel_evidence


class Analyzer:
    def __init__(self, settings: Settings | None = None, providers=None) -> None:
        self.settings = settings or Settings()
        configured = (
            providers_from_config(self.settings.threat_intelligence, include_api_adapters=True)
            if providers is None
            else providers
        )
        self.enrichment = EnrichmentOrchestrator(configured)

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
        auth = parse_authentication_results(
            email,
            mode=self.settings.auth_results_mode,
            trusted_authserv_id=self.settings.trusted_authserv_id,
        )
        email.received_hops = parse_received_headers(email.received_headers)
        header_findings = header_evidence(email, auth)
        evidence.extend(header_findings)
        evidence.extend(authentication_evidence_items(auth))
        evidence.extend(received_evidence(email))
        urls = extract_urls(email)
        evidence.extend(url_evidence(urls))
        evidence.extend(attachment_evidence(email))
        content_findings = content_evidence(email)
        evidence.extend(content_findings)
        iocs = extract_iocs(email, urls, evidence)
        threat_intelligence = self.enrichment.enrich(iocs)
        evidence.extend(threat_intel_evidence(threat_intelligence))
        url_status = "partial" if any(item.analysis_status != "complete" for item in urls) else "complete"
        url_note = "One or more URL candidates could not be safely normalized." if url_status == "partial" else "URLs were inspected without fetching them."
        mail_flow_status = "partial" if any(hop.malformed for hop in email.received_hops) else "complete"
        mail_flow_note = "One or more Received headers were malformed." if mail_flow_status == "partial" else "Received headers were inspected where available."
        content_status = "complete" if (email.body_text or email.body_html).strip() else "not_evaluable"
        content_note = (
            "Deterministic local content heuristics were applied."
            if content_status == "complete"
            else "No usable email body was available for content analysis."
        )
        ti_status = "not_evaluable" if not self.enrichment.providers else ("partial" if has_provider_failure(threat_intelligence) else "complete")
        ti_note = (
            "Threat-intelligence enrichment was not attempted."
            if not self.enrichment.providers
            else "One or more threat-intelligence lookups were incomplete or unavailable."
            if has_provider_failure(threat_intelligence)
            else "Threat-intelligence provider results were collected."
        )

        mime_parts_truncated = "maximum MIME part count exceeded" in email.parse_warnings

        parser_status = "partial" if mime_parts_truncated else "complete"
        parser_note = (
            "MIME part limit was reached; later MIME parts were not inspected."
            if mime_parts_truncated
            else "Email was parsed locally."
        )

        attachment_status = "partial" if mime_parts_truncated else "complete"
        attachment_note = (
            "Attachment analysis is incomplete because the MIME part limit was reached."
            if mime_parts_truncated
            else "Attachment metadata and hashes were generated locally."
        )

        duplicate_identity_headers = sorted({
            str(item.evidence.get("header"))
            for item in header_findings
            if item.signal_id == "duplicate_identity_header"
            and item.evidence.get("header")
        })
        identity_status = "partial" if duplicate_identity_headers else "complete"
        identity_note = (
            "Duplicate singleton identity headers were detected; no single value was treated as authoritative."
            if duplicate_identity_headers
            else "Available identity headers were inspected."
        )

        completeness = AnalysisCompleteness({
            "parser": AnalysisAreaStatus(parser_status, parser_note, required=True),
            "identity": AnalysisAreaStatus(identity_status, identity_note, required=True),
            "authentication": AnalysisAreaStatus(auth.status.status, auth.status.note, required=True),
            "url": AnalysisAreaStatus(url_status, url_note, required=True),
            "attachment": AnalysisAreaStatus(attachment_status, attachment_note, required=True),
            "mail_flow": AnalysisAreaStatus(mail_flow_status, mail_flow_note, required=False),
            "content": AnalysisAreaStatus(content_status, content_note, required=False),
            "reputation": AnalysisAreaStatus("unavailable", "No external reputation provider is enabled.", required=False),
            "threat_intelligence": AnalysisAreaStatus(ti_status, ti_note, required=False),
        })
        scoring = score_evidence(evidence)
        verdict = apply_policy(scoring, completeness, evidence, threat_intelligence)
        return AnalysisResult("1.0", email, urls, evidence, scoring, completeness, verdict, errors, iocs, threat_intelligence)

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
            "threat_intelligence": AnalysisAreaStatus("not_evaluable", "Parsing did not complete.", required=False),
        })
        verdict = VerdictResult("UNRESOLVED", "The email could not be safely parsed.", completeness.overall_status, "low")
        return AnalysisResult("1.0", email, [], [], ScoringResult(), completeness, verdict, [error])
