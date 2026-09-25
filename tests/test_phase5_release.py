from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_cli_missing_file_returns_meaningful_nonzero_error():
    completed = subprocess.run(
        [sys.executable, "analyze.py", str(ROOT / "does-not-exist.eml")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert "unable to read input file" in completed.stderr
    assert "Traceback" not in completed.stderr


def test_cli_displays_score_with_derived_maximum():
    completed = subprocess.run(
        [sys.executable, "analyze.py", str(ROOT / "tests" / "fixtures" / "clean.eml")],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "RISK SCORE: 0/70" in completed.stdout
    assert "/100" not in completed.stdout


def test_sample_safe_output_is_structured_and_payload_free():
    payload = json.loads((ROOT / "docs" / "sample-safe-output.json").read_text())
    assert payload["verdict"]["final"] in {"CLEAN", "SUSPICIOUS", "MALICIOUS", "UNRESOLVED"}
    assert "total_score" in payload["scoring"]
    assert payload["scoring"]["maximum_score"] == sum(payload["scoring"]["category_caps"].values()) == 70
    assert "areas" in payload["completeness"]
    assert payload["iocs"]
    assert payload["threat_intelligence"]
    serialized = json.dumps(payload)
    for forbidden in ("body_text", "body_html", "source_message", "api_key", "PHISHLENS_VT_API_KEY"):
        assert forbidden not in serialized
    assert "token=secret" not in serialized


def test_readme_covers_release_contract():
    readme = (ROOT / "README.md").read_text()
    for section in (
        "Architecture",
        "Verdicts",
        "Threat intelligence",
        "Configuration",
        "Safe output",
        "Testing and CI",
        "Limitations and non-goals",
    ):
        assert section in readme
    assert "does not fetch arbitrary URLs" in readme
    assert "does not execute attachments" in readme
    assert "does not perform automatic remediation" in readme


def test_ci_workflow_is_offline_and_secret_free():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "push:" in workflow
    assert "pull_request:" in workflow
    assert "pytest -q" in workflow
    assert "pip install -e '.[dev]'" in workflow
    assert "PHISHLENS_VT_API_KEY: \"\"" in workflow
    assert "PHISHLENS_ABUSEIPDB_API_KEY: \"\"" in workflow
    assert "secrets." not in workflow
