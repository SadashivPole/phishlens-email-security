from __future__ import annotations

import ipaddress
import re
from email.utils import parseaddr
from urllib.parse import urlsplit

from ..models.email import ParsedEmail
from ..parsing.authentication import AuthenticationEvidence
from ..models.evidence import EvidenceItem
from ..models.ioc import IOC
from ..models.indicators import UrlIndicator

HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:.]+(?![\w:])")
DOMAIN_RE = re.compile(r"(?<![@\w])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?")


def extract_iocs(
    email: ParsedEmail,
    urls: list[UrlIndicator],
    evidence: list[EvidenceItem] | None = None,
    authentication: AuthenticationEvidence | None = None,
) -> list[IOC]:
    found: dict[tuple[str, str], IOC] = {}

    def add(ioc: IOC) -> None:
        if ioc.normalized_value and ioc.key() not in found:
            found[ioc.key()] = ioc
        elif ioc.normalized_value and ioc.key() in found:
            existing = found[ioc.key()]
            existing.provenance.setdefault("sources", [])
            source = ioc.source
            if source not in existing.provenance["sources"]:
                existing.provenance["sources"].append(source)

    for item in urls:
        if item.analysis_status == "complete" and item.normalized_url:
            add(IOC("url", item.original_url, item.normalized_url, "local_url_analysis", {"context": item.context}))
            if item.hostname:
                _add_host_ioc(add, item.hostname, "local_url_analysis", {"url": item.normalized_url})

    for value, source in _email_address_values(email):
        domain = _domain(value)
        if domain:
            add(IOC("domain", domain, domain, source, {"field": source}))

    # Authentication-Results domains are provider-eligible only when the
    # authentication parser explicitly accepted the header under the
    # configured trust boundary.
    if authentication is not None and authentication.decision_eligible:
        for method in ("spf", "dkim", "dmarc", "arc"):
            for item in getattr(authentication, method):
                domain = _normalize_domain(item.domain) if item.domain else None
                if domain:
                    add(
                        IOC(
                            "domain",
                            item.domain or domain,
                            domain,
                            "authentication_results",
                            {"method": method},
                        )
                    )

    for hop in email.received_hops:
        for ip in hop.source_ips:
            normalized = _normalize_ip(ip)
            if normalized:
                add(IOC("ip", ip, normalized, "local_received_header_analysis", {"hop": hop.order}))
        if hop.source_hostname:
            domain = _normalize_domain(hop.source_hostname)
            if domain:
                add(IOC("domain", hop.source_hostname, domain, "local_received_header_analysis", {"hop": hop.order}))

    for item in email.attachments:
        if _is_sha256(item.sha256):
            add(IOC("hash", item.sha256, item.sha256.lower(), "local_attachment_analysis", {"filename": item.filename}))

    # Evidence is intentionally used only as a source of additional structured
    # indicators, never as a reason to trust arbitrary raw text.
    for item in evidence or []:
        _extract_from_evidence(add, item)

    return list(found.values())


def _extract_from_evidence(add, item: EvidenceItem) -> None:
    evidence = item.evidence
    if not isinstance(evidence, dict):
        return
    for key, value in evidence.items():
        if not isinstance(value, str):
            continue
        for match in HASH_RE.findall(value):
            add(IOC("hash", match, match.lower(), item.source, {"signal_id": item.signal_id}))
        for match in IP_RE.findall(value):
            normalized = _normalize_ip(match)
            if normalized:
                add(IOC("ip", match, normalized, item.source, {"signal_id": item.signal_id, "field": key}))
        for match in DOMAIN_RE.findall(value):
            normalized = _normalize_domain(match)
            if normalized:
                add(IOC("domain", match, normalized, item.source, {"signal_id": item.signal_id, "field": key}))


def _email_address_values(email: ParsedEmail):
    values = [(email.from_address, "from_address"), (email.reply_to, "reply_to"), (email.return_path, "return_path"), (email.message_id, "message_id")]
    values.extend((item, "recipient") for item in email.to_addresses + email.cc_addresses)
    for value, source in values:
        if value:
            yield value, source
    # Raw Authentication-Results are intentionally excluded here.
    # Trust-aware authentication domains are added only from parsed,
    # decision-eligible AuthenticationEvidence above.


def _add_host_ioc(add, hostname: str, source: str, provenance: dict[str, object]) -> None:
    ip = _normalize_ip(hostname)
    if ip:
        add(IOC("ip", hostname, ip, source, provenance))
    else:
        domain = _normalize_domain(hostname)
        if domain:
            add(IOC("domain", hostname, domain, source, provenance))


def _domain(value: str) -> str | None:
    _, address = parseaddr(value)
    candidate = address.rsplit("@", 1)[-1] if "@" in address else address.strip("<>")
    return _normalize_domain(candidate)


def _normalize_ip(value: str) -> str | None:
    try:
        return ipaddress.ip_address(value.strip("[]")).compressed
    except ValueError:
        return None


def _normalize_domain(value: str) -> str | None:
    candidate = value.strip().lower().rstrip(".")
    if not candidate or "@" in candidate or "/" in candidate:
        return None
    try:
        return candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _is_sha256(value: str) -> bool:
    return bool(value and HASH_RE.fullmatch(value.strip()))
