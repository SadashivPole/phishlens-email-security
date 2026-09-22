from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from publicsuffix2 import get_sld, get_tld

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True)
class DomainAlignment:
    from_domain: str | None
    authenticated_domain: str | None
    strict_alignment: bool | None
    relaxed_alignment: bool | None
    from_organizational_domain: str | None
    authenticated_organizational_domain: str | None
    effective_alignment: str
    provenance: dict[str, str]

    def to_dict(self) -> dict[str, object]:
        return {
            "from_domain": self.from_domain,
            "authenticated_domain": self.authenticated_domain,
            "strict_alignment": self.strict_alignment,
            "relaxed_alignment": self.relaxed_alignment,
            "from_organizational_domain": self.from_organizational_domain,
            "authenticated_organizational_domain": self.authenticated_organizational_domain,
            "effective_alignment": self.effective_alignment,
            "provenance": self.provenance,
        }


def normalize_domain(value: str | None) -> str | None:
    """Return a canonical DNS name, or None for malformed/non-DNS input."""
    if not value:
        return None
    candidate = value.strip().lower().rstrip(".")
    if not candidate or len(candidate) > 253:
        return None
    try:
        if ipaddress.ip_address(candidate):
            return None
    except ValueError:
        pass
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = candidate.split(".")
    if len(labels) < 2 or any(not _LABEL_RE.fullmatch(label) for label in labels):
        return None
    return candidate


def organizational_domain(value: str | None) -> str | None:
    normalized = normalize_domain(value)
    if not normalized:
        return None
    # publicsuffix2 ships a Public Suffix List implementation and data. Strict
    # mode avoids inventing a suffix for unknown TLDs.
    suffix = get_tld(normalized, strict=True)
    result = get_sld(normalized, strict=True)
    if not suffix or not result or result == suffix:
        return None
    return result


def compare_domains(from_domain: str | None, authenticated_domain: str | None) -> DomainAlignment:
    normalized_from = normalize_domain(from_domain)
    normalized_authenticated = normalize_domain(authenticated_domain)
    from_org = organizational_domain(normalized_from)
    authenticated_org = organizational_domain(normalized_authenticated)
    strict = (
        normalized_from == normalized_authenticated
        if normalized_from is not None and normalized_authenticated is not None
        else None
    )
    relaxed = (
        from_org == authenticated_org
        if from_org is not None and authenticated_org is not None
        else None
    )
    return DomainAlignment(
        from_domain=normalized_from,
        authenticated_domain=normalized_authenticated,
        strict_alignment=strict,
        relaxed_alignment=relaxed,
        from_organizational_domain=from_org,
        authenticated_organizational_domain=authenticated_org,
        # DMARC mode/policy is not present in Authentication-Results parsing.
        effective_alignment="unknown",
        provenance={
            "source": "Authentication-Results",
            "analysis": "domain comparison only",
            "verification": "no independent SPF DNS or DKIM cryptographic verification",
            "policy_mode": "unknown",
        },
    )
