from __future__ import annotations

import json

from src.phishlens.config import DEFAULT_TI_TIMEOUT_SECONDS, ThreatIntelConfig
from src.phishlens.enrichment.configured import providers_from_config
from src.phishlens.models.ioc import IOC
from src.phishlens.pipeline.analyzer import Analyzer


VT_ENV = "PHISHLENS_VT_API_KEY"
ABUSE_ENV = "PHISHLENS_ABUSEIPDB_API_KEY"
TIMEOUT_ENV = "PHISHLENS_TI_TIMEOUT_SECONDS"


def clear_ti_env(monkeypatch):
    for name in (VT_ENV, ABUSE_ENV, TIMEOUT_ENV):
        monkeypatch.delenv(name, raising=False)


def test_both_providers_disabled(monkeypatch):
    clear_ti_env(monkeypatch)
    config = ThreatIntelConfig.from_environment()
    assert not config.virustotal.enabled
    assert not config.abuseipdb.enabled
    assert providers_from_config(config) == []


def test_virustotal_enabled_without_exposing_key(monkeypatch):
    clear_ti_env(monkeypatch)
    secret = "vt-test-secret"
    monkeypatch.setenv(VT_ENV, secret)
    config = ThreatIntelConfig.from_environment()
    providers = providers_from_config(config)
    assert [provider.name for provider in providers] == ["virustotal"]
    assert config.safe_dict()["providers"]["virustotal"]["enabled"] is True
    assert secret not in repr(config)
    assert secret not in json.dumps(config.safe_dict())


def test_abuseipdb_enabled(monkeypatch):
    clear_ti_env(monkeypatch)
    monkeypatch.setenv(ABUSE_ENV, "abuse-test-secret")
    config = ThreatIntelConfig.from_environment()
    assert [provider.name for provider in providers_from_config(config)] == ["abuseipdb"]


def test_both_enabled(monkeypatch):
    clear_ti_env(monkeypatch)
    monkeypatch.setenv(VT_ENV, "vt-secret")
    monkeypatch.setenv(ABUSE_ENV, "abuse-secret")
    config = ThreatIntelConfig.from_environment()
    assert [provider.name for provider in providers_from_config(config)] == ["virustotal", "abuseipdb"]


def test_missing_environment_variables_disable_providers(monkeypatch):
    clear_ti_env(monkeypatch)
    config = ThreatIntelConfig.from_environment()
    assert config.enabled_provider_configs() == []


def test_blank_environment_variables_disable_providers(monkeypatch):
    clear_ti_env(monkeypatch)
    monkeypatch.setenv(VT_ENV, "   ")
    monkeypatch.setenv(ABUSE_ENV, "")
    config = ThreatIntelConfig.from_environment()
    assert config.enabled_provider_configs() == []


def test_default_timeout_is_ten_seconds(monkeypatch):
    clear_ti_env(monkeypatch)
    config = ThreatIntelConfig.from_environment()
    assert config.timeout_seconds == 10
    assert config.timeout_seconds == DEFAULT_TI_TIMEOUT_SECONDS


def test_configured_timeout_applies_to_both_providers(monkeypatch):
    clear_ti_env(monkeypatch)
    monkeypatch.setenv(TIMEOUT_ENV, "3.5")
    config = ThreatIntelConfig.from_environment()
    assert config.timeout_seconds == 3.5
    assert config.virustotal.timeout_seconds == 3.5
    assert config.abuseipdb.timeout_seconds == 3.5


def test_invalid_timeout_uses_deterministic_default(monkeypatch):
    clear_ti_env(monkeypatch)
    for value in ("not-a-number", "0", "-1", "nan", "inf"):
        monkeypatch.setenv(TIMEOUT_ENV, value)
        assert ThreatIntelConfig.from_environment().timeout_seconds == DEFAULT_TI_TIMEOUT_SECONDS


def test_secret_redaction_from_config_and_analysis(monkeypatch):
    clear_ti_env(monkeypatch)
    secret = "super-secret-vt-key"
    monkeypatch.setenv(VT_ENV, secret)
    config = ThreatIntelConfig.from_environment()
    result = Analyzer().analyze(b"From: sender@example.com\n\nHello")
    assert secret not in repr(config)
    assert secret not in json.dumps(config.safe_dict())
    assert secret not in repr(result)
    assert secret not in json.dumps(result.to_safe_dict())
    assert all(item.provider != secret for item in result.threat_intelligence)


def test_configured_provider_is_unavailable_and_offline(monkeypatch):
    clear_ti_env(monkeypatch)
    monkeypatch.setenv(VT_ENV, "offline-test-key")
    provider = providers_from_config(ThreatIntelConfig.from_environment())[0]
    ioc = IOC("ip", "192.0.2.1", "192.0.2.1", "test")

    def fail_network(*args, **kwargs):
        raise AssertionError("network access was attempted")

    monkeypatch.setattr("socket.socket", fail_network)
    result = provider.lookup_ip(ioc)
    assert result.status == "unavailable"
    assert result.provider == "virustotal"
    assert result.ioc_value == ioc.normalized_value


def test_provider_configuration_does_not_change_phase1_phase2_verdict(monkeypatch):
    clear_ti_env(monkeypatch)
    raw = (
        b"From: sender@example.com\n"
        b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n"
        b"Hello"
    )
    baseline = Analyzer().analyze(raw)
    monkeypatch.setenv(VT_ENV, "offline-test-key")
    configured = Analyzer().analyze(raw)
    assert configured.verdict.to_dict() == baseline.verdict.to_dict()
    assert configured.scoring.to_dict() == baseline.scoring.to_dict()
