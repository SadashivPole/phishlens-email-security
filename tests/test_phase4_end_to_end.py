from __future__ import annotations

import json
import sys
from pathlib import Path

from src.phishlens.enrichment.abuseipdb import AbuseIPDBProvider
from src.phishlens.enrichment.virustotal import VirusTotalProvider
from src.phishlens.models.ioc import IOC
from src.phishlens.models.threat_intel import ThreatIntelResult
from src.phishlens.pipeline.analyzer import Analyzer


FIXTURES = Path(__file__).parent / "fixtures"
VT_KEY = "phase4-offline-vt-key"
ABUSE_KEY = "phase4-offline-abuse-key"


def vt_payload(stats):
    return json.dumps({"data": {"attributes": {"last_analysis_stats": stats}}}).encode()


def abuse_payload(score=0, reports=0):
    return json.dumps({"data": {"abuseConfidenceScore": score, "totalReports": reports}}).encode()


def test_realistic_phase4_fixtures_cover_end_to_end_inputs():
    clean = Analyzer().analyze((FIXTURES / "phase4_clean.eml").read_bytes())
    phishing = Analyzer().analyze((FIXTURES / "phase4_phishing.eml").read_bytes())
    ip_result = Analyzer().analyze((FIXTURES / "phase4_ip_ioc.eml").read_bytes())
    attachment = Analyzer().analyze((FIXTURES / "phase4_attachment.eml").read_bytes())
    malformed = Analyzer().analyze((FIXTURES / "phase4_malformed.eml").read_bytes())

    assert clean.verdict.final == "CLEAN"
    assert phishing.verdict.final == "SUSPICIOUS"
    assert any(ioc.ioc_type == "ip" for ioc in ip_result.iocs)
    assert any(ioc.ioc_type == "hash" for ioc in attachment.iocs)
    assert malformed.verdict.final == "UNRESOLVED"
    assert malformed.completeness.areas["parser"].status == "unavailable"


def test_both_configured_providers_contribute_evidence_offline(monkeypatch):
    monkeypatch.setenv("PHISHLENS_VT_API_KEY", VT_KEY)
    monkeypatch.setenv("PHISHLENS_ABUSEIPDB_API_KEY", ABUSE_KEY)
    monkeypatch.setattr(
        "src.phishlens.enrichment.virustotal._http_get",
        lambda request, timeout: (200, vt_payload({"malicious": 1})),
    )
    monkeypatch.setattr(
        "src.phishlens.enrichment.abuseipdb._http_get",
        lambda request, timeout: (200, abuse_payload(score=90, reports=3)),
    )
    result = Analyzer().analyze((FIXTURES / "phase4_combined_ti.eml").read_bytes())
    providers = {item.provider for item in result.threat_intelligence}
    assert providers == {"virustotal", "abuseipdb"}
    assert any(item.provider == "virustotal" and item.status == "match" for item in result.threat_intelligence)
    assert any(item.provider == "abuseipdb" and item.status == "match" for item in result.threat_intelligence)
    ti_evidence = [item for item in result.evidence if item.source == "threat_intelligence_policy"]
    assert all("provider" in item.evidence and "ioc_type" in item.evidence for item in ti_evidence)
    assert ti_evidence
    assert sum(item.points for item in ti_evidence) <= 10
    assert all(not item.hard_indicator for item in ti_evidence)


def test_duplicate_provider_ioc_evidence_is_not_double_counted():
    from src.phishlens.scoring.threat_intel_policy import threat_intel_evidence

    repeated = [
        ThreatIntelResult("virustotal", "ip", "203.0.113.44", "match", disposition="malicious"),
        ThreatIntelResult("virustotal", "ip", "203.0.113.44", "match", disposition="malicious"),
        ThreatIntelResult("abuseipdb", "ip", "203.0.113.44", "match", disposition="suspicious"),
    ]
    evidence = threat_intel_evidence(repeated)
    assert len(evidence) == 2
    assert sum(item.points for item in evidence) <= 10


def test_provider_failure_preserves_complete_local_verdict():
    class TimeoutProvider:
        name = "offline-timeout"

        def lookup_ip(self, ioc):
            return ThreatIntelResult(self.name, ioc.ioc_type, ioc.normalized_value, "timeout")

        def lookup_domain(self, ioc):
            return ThreatIntelResult(self.name, ioc.ioc_type, ioc.normalized_value, "timeout")

        def lookup_url(self, ioc):
            return ThreatIntelResult(self.name, ioc.ioc_type, ioc.normalized_value, "timeout")

        def lookup_hash(self, ioc):
            return ThreatIntelResult(self.name, ioc.ioc_type, ioc.normalized_value, "timeout")

    result = Analyzer(providers=[TimeoutProvider()]).analyze((FIXTURES / "phase4_timeout.eml").read_bytes())
    assert result.iocs
    assert result.threat_intelligence
    assert all(item.status == "timeout" for item in result.threat_intelligence)
    assert result.completeness.areas["threat_intelligence"].status == "partial"
    assert result.verdict.final == "CLEAN"


def test_provider_failure_executes_on_valid_ioc_message():
    class ErrorProvider:
        name = "offline-error"

        def lookup_ip(self, ioc):
            raise RuntimeError("offline failure")

        lookup_domain = lookup_ip
        lookup_url = lookup_ip
        lookup_hash = lookup_ip

    result = Analyzer(providers=[ErrorProvider()]).analyze((FIXTURES / "phase4_timeout.eml").read_bytes())
    assert result.iocs
    assert result.threat_intelligence
    assert all(item.status == "error" for item in result.threat_intelligence)
    assert result.verdict.final == "CLEAN"


def test_required_parser_failure_remains_unresolved_independently():
    result = Analyzer().analyze((FIXTURES / "phase4_malformed.eml").read_bytes())
    assert result.verdict.final == "UNRESOLVED"
    assert result.completeness.areas["parser"].status == "unavailable"


def test_malicious_provider_evidence_cannot_directly_force_malicious():
    provider = VirusTotalProvider(
        __import__("src.phishlens.config", fromlist=["VirusTotalConfig"]).VirusTotalConfig(api_key=VT_KEY),
        http_get=lambda request, timeout: (200, vt_payload({"malicious": 20})),
    )
    result = Analyzer(providers=[provider]).analyze((FIXTURES / "phase4_ip_ioc.eml").read_bytes())
    assert result.iocs
    assert any(ioc.ioc_type == "ip" for ioc in result.iocs)
    assert any(item.provider == "virustotal" and item.status == "match" for item in result.threat_intelligence)
    assert any(
        item.source == "threat_intelligence_policy"
        and item.evidence["provider"] == "virustotal"
        and item.evidence["status"] == "match"
        for item in result.evidence
    )
    assert result.verdict.final != "MALICIOUS"


def test_no_match_does_not_make_email_suspicious():
    provider = AbuseIPDBProvider(
        __import__("src.phishlens.config", fromlist=["AbuseIPDBConfig"]).AbuseIPDBConfig(api_key=ABUSE_KEY),
        http_get=lambda request, timeout: (200, abuse_payload()),
    )
    result = Analyzer(providers=[provider]).analyze((FIXTURES / "phase4_ip_ioc.eml").read_bytes())
    assert any(item.status == "no_match" for item in result.threat_intelligence)
    assert result.verdict.final == "CLEAN"


def test_safe_cli_json_has_no_secrets_or_raw_payloads(monkeypatch, capsys):
    monkeypatch.delenv("PHISHLENS_VT_API_KEY", raising=False)
    monkeypatch.delenv("PHISHLENS_ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setattr(sys, "argv", ["analyze.py", str(FIXTURES / "phase4_phishing.eml"), "--json"])
    from analyze import main

    assert main() == 0
    output = capsys.readouterr().out
    assert VT_KEY not in output
    assert ABUSE_KEY not in output
    assert "Verify your password immediately" not in output
    assert "mx.example.net; spf=fail; dkim=none; dmarc=fail" not in output
    assert "body_text" not in output
    assert "ioc_value" in output
    assert "[REDACTED_URL]" in output

    attachment_result = Analyzer().analyze((FIXTURES / "phase4_attachment.eml").read_bytes())
    attachment_safe = json.dumps(attachment_result.to_safe_dict())
    assert "safe-fixture-attachment" not in attachment_safe
    assert "c2FmZS1maXh0dXJlLWF0dGFjaG1lbnQ=" not in attachment_safe


def test_cli_provider_modes_are_selectable_without_live_http(monkeypatch, capsys):
    monkeypatch.setattr(
        "src.phishlens.enrichment.virustotal._http_get",
        lambda request, timeout: (404, b"{}"),
    )
    monkeypatch.setattr(
        "src.phishlens.enrichment.abuseipdb._http_get",
        lambda request, timeout: (404, b"{}"),
    )
    from analyze import main

    modes = (
        (None, None, set()),
        (VT_KEY, None, {"virustotal"}),
        (None, ABUSE_KEY, {"abuseipdb"}),
        (VT_KEY, ABUSE_KEY, {"virustotal", "abuseipdb"}),
    )
    for vt_key, abuse_key, expected_providers in modes:
        if vt_key is None:
            monkeypatch.delenv("PHISHLENS_VT_API_KEY", raising=False)
        else:
            monkeypatch.setenv("PHISHLENS_VT_API_KEY", vt_key)
        if abuse_key is None:
            monkeypatch.delenv("PHISHLENS_ABUSEIPDB_API_KEY", raising=False)
        else:
            monkeypatch.setenv("PHISHLENS_ABUSEIPDB_API_KEY", abuse_key)
        selected = {provider.name for provider in Analyzer().enrichment.providers}
        assert selected == expected_providers
        monkeypatch.setattr(sys, "argv", ["analyze.py", str(FIXTURES / "phase4_combined_ti.eml"), "--json"])
        assert main() == 0
        capsys.readouterr()
