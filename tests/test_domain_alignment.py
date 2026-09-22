from __future__ import annotations

from src.phishlens.parsing.domain_alignment import compare_domains, normalize_domain, organizational_domain


def test_normalize_domain_handles_case_trailing_dot_and_idna():
    assert normalize_domain("  Mail.Example.COM. ") == "mail.example.com"
    assert normalize_domain("bücher.example") == "xn--bcher-kva.example"


def test_normalize_domain_rejects_malformed_domains_and_ips():
    for value in (None, "", "localhost", "example..com", "-bad.example", "bad-.example", "192.0.2.1"):
        assert normalize_domain(value) is None


def test_strict_alignment_requires_exact_fqdn_equality():
    comparison = compare_domains("sender.example.com", "example.com")
    assert comparison.strict_alignment is False
    assert comparison.relaxed_alignment is True
    assert comparison.from_organizational_domain == "example.com"
    assert comparison.authenticated_organizational_domain == "example.com"
    assert comparison.effective_alignment == "unknown"


def test_exact_domains_are_strict_and_relaxed_aligned():
    comparison = compare_domains("example.com", "example.com.")
    assert comparison.strict_alignment is True
    assert comparison.relaxed_alignment is True


def test_public_suffix_list_handles_multi_label_suffixes_without_naive_suffix_matching():
    assert organizational_domain("a.example.co.uk") == "example.co.uk"
    assert organizational_domain("b.example.co.uk") == "example.co.uk"
    assert compare_domains("a.example.co.uk", "b.example.co.uk").strict_alignment is False
    assert compare_domains("a.example.co.uk", "b.example.co.uk").relaxed_alignment is True
    assert compare_domains("a.example.co.uk", "attacker.co.uk").relaxed_alignment is False


def test_public_suffix_edge_cases_and_unknown_suffixes_are_not_invented():
    assert organizational_domain("co.uk") is None
    assert organizational_domain("localhost") is None
    assert organizational_domain("example.invalid") is None
    comparison = compare_domains("a.example.invalid", "b.example.invalid")
    assert comparison.strict_alignment is False
    assert comparison.relaxed_alignment is None
    assert comparison.effective_alignment == "unknown"


def test_missing_domains_are_not_evaluable_and_provenance_is_explicit():
    comparison = compare_domains("example.com", None)
    assert comparison.strict_alignment is None
    assert comparison.relaxed_alignment is None
    assert comparison.from_organizational_domain == "example.com"
    assert comparison.authenticated_organizational_domain is None
    assert comparison.provenance["source"] == "Authentication-Results"
    assert comparison.provenance["policy_mode"] == "unknown"


def test_multiple_observations_keep_each_domain_comparison():
    first = compare_domains("sender.example.com", "example.com")
    second = compare_domains("sender.example.com", "other.example.net")
    assert first.relaxed_alignment is True
    assert second.relaxed_alignment is False
