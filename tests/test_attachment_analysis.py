from src.phishlens.analysis.attachment_analysis import attachment_evidence
from src.phishlens.parsing.eml_parser import parse_eml_bytes


def test_attachment_findings_include_mismatch_and_double_extension(fixture_dir):
    email = parse_eml_bytes((fixture_dir / "attachment.eml").read_bytes())
    findings = attachment_evidence(email)
    ids = {item.signal_id for item in findings}
    assert "attachment_type_mismatch" in ids
    assert "attachment_double_extension" in ids
