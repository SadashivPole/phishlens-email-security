from __future__ import annotations

import html
import ipaddress
import re
from urllib.parse import SplitResult, urlsplit, urlunsplit

from ..models.email import ParsedEmail
from ..models.evidence import EvidenceItem
from ..models.indicators import UrlIndicator

URL_RE = re.compile(r"https?://[^\s<>\"'{}|\\^`\[\]]+", re.IGNORECASE)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "lnkd.in"}


def extract_urls(email: ParsedEmail) -> list[UrlIndicator]:
    indicators: list[UrlIndicator] = []
    positions: dict[str, int] = {}

    def add_or_prefer(item: UrlIndicator) -> None:
        # Deduplicate by normalized destination. If an anchor-aware item is
        # available, prefer it because it preserves display text and mismatch
        # context that generic HTML scanning cannot reliably provide.
        key = item.normalized_url or f"malformed:{item.original_url}"
        existing_position = positions.get(key)
        if existing_position is None:
            positions[key] = len(indicators)
            indicators.append(item)
            return
        existing = indicators[existing_position]
        if item.display_text and not existing.display_text:
            indicators[existing_position] = item

    for value, context in ((email.body_text, "text"), (email.body_html, "html")):
        decoded = html.unescape(value or "")
        for match in URL_RE.finditer(decoded):
            original = match.group(0).rstrip(".,;:!?)]")
            add_or_prefer(analyze_url(original, context=context))

    for match in re.finditer(r"<a\b[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", html.unescape(email.body_html or ""), re.IGNORECASE | re.DOTALL):
        href = match.group(1).strip()
        if not href.lower().startswith(("http://", "https://")):
            continue
        display = re.sub(r"<[^>]+>", " ", match.group(2)).strip()
        add_or_prefer(analyze_url(href, context="html_anchor", display_text=display))
    return indicators


def analyze_url(url: str, context: str = "unknown", display_text: str | None = None) -> UrlIndicator:
    try:
        normalized = normalize_url(url)
        parsed = urlsplit(normalized)
        hostname = parsed.hostname.lower() if parsed.hostname else None
        if not hostname:
            raise ValueError("URL has no hostname")
        is_ip = _is_ip_literal(hostname)
        domain = hostname
        has_userinfo = bool(parsed.username or parsed.password)
        suspicious_encoding = bool(re.search(r"%(?:25|2f|5c|40|3a|3f|23)", url, re.IGNORECASE))
        display_mismatch = _display_mismatch(display_text, hostname)
        return UrlIndicator(
            original_url=url,
            normalized_url=normalized,
            hostname=hostname,
            domain=domain,
            display_text=display_text,
            context=context,
            is_ip_literal=is_ip,
            is_shortened=hostname in SHORTENERS,
            display_mismatch=display_mismatch,
            has_userinfo=has_userinfo,
            suspicious_encoding=suspicious_encoding,
        )
    except (ValueError, UnicodeError) as exc:
        # URL content is attacker-controlled. Preserve the candidate and let
        # the pipeline continue with a partial URL-analysis status.
        return UrlIndicator(
            original_url=url,
            normalized_url="",
            display_text=display_text,
            context=context,
            analysis_status="partial",
            analysis_error=type(exc).__name__,
        )


def normalize_url(url: str) -> str:
    value = html.unescape(url.strip())
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower() if parsed.hostname else ""
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        pass

    userinfo = ""
    if parsed.username is not None:
        userinfo = parsed.username
        if parsed.password is not None:
            userinfo += f":{parsed.password}"
        userinfo += "@"

    host_port = hostname
    if ":" in hostname and not hostname.startswith("["):
        host_port = f"[{hostname}]"
    if parsed.port is not None and not ((scheme == "http" and parsed.port == 80) or (scheme == "https" and parsed.port == 443)):
        host_port += f":{parsed.port}"

    rebuilt = SplitResult(scheme, f"{userinfo}{host_port}", parsed.path or "/", parsed.query, "")
    return urlunsplit(rebuilt)


def url_evidence(urls: list[UrlIndicator]) -> list[EvidenceItem]:
    findings: list[EvidenceItem] = []
    for item in urls:
        if item.analysis_status != "complete":
            findings.append(EvidenceItem(
                "malformed_url", "url", "low", item.to_dict(),
                "A URL candidate could not be safely normalized; URL analysis is incomplete for this indicator.",
                "local_url_analysis", "medium", 0,
            ))
            continue
        if item.is_ip_literal:
            findings.append(EvidenceItem("ip_literal_url", "url", "medium", item.to_dict(), "The URL destination is an IP literal rather than a hostname; this is suspicious but not proof of maliciousness.", "local_url_analysis", "medium", 4))
        if item.display_mismatch:
            findings.append(EvidenceItem("display_href_mismatch", "url", "medium", item.to_dict(), "Displayed link text does not match the URL destination.", "local_url_analysis", "medium", 5))
        if item.is_shortened:
            findings.append(EvidenceItem("url_shortener", "url", "low", item.to_dict(), "The URL uses a common shortening service, which obscures the final destination.", "local_url_analysis", "low", 1))
        if item.has_userinfo:
            findings.append(EvidenceItem("url_userinfo", "url", "medium", item.to_dict(), "The URL contains userinfo before the host, a technique sometimes used to disguise the real destination.", "local_url_analysis", "medium", 3))
        if item.suspicious_encoding:
            findings.append(EvidenceItem("suspicious_url_encoding", "url", "low", item.to_dict(), "The URL contains encoding patterns that warrant review.", "local_url_analysis", "low", 1))
    return findings


def _is_ip_literal(hostname: str | None) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _display_mismatch(display_text: str | None, hostname: str | None) -> bool:
    if not display_text or not hostname:
        return False
    display_match = re.search(r"https?://([^/\s<>]+)", display_text, re.IGNORECASE)
    if not display_match:
        return False
    shown_host = display_match.group(1).split("@")[-1].split(":")[0].lower().rstrip(".")
    return shown_host != hostname.rstrip(".")
