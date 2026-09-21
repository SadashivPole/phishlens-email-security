from __future__ import annotations

from dataclasses import asdict, dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from typing import Any

SENSITIVE_QUERY_PARAMS = {
    "token", "access_token", "id_token", "code", "password", "key",
    "secret", "signature", "session", "auth", "credential",
}


@dataclass
class UrlIndicator:
    original_url: str
    normalized_url: str
    hostname: str | None = None
    domain: str | None = None
    display_text: str | None = None
    context: str = "unknown"
    is_ip_literal: bool = False
    is_shortened: bool = False
    display_mismatch: bool = False
    has_userinfo: bool = False
    suspicious_encoding: bool = False
    has_punycode: bool = False
    suspicious_port: bool = False
    redirect_indicator: bool = False
    analysis_status: str = "complete"
    analysis_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_safe_dict(self) -> dict[str, Any]:
        safe_url = _redact_url(self.normalized_url) if self.normalized_url else None
        return {
            "normalized_url": safe_url,
            "hostname": self.hostname,
            "domain": self.domain,
            "context": self.context,
            "is_ip_literal": self.is_ip_literal,
            "is_shortened": self.is_shortened,
            "display_mismatch": self.display_mismatch,
            "has_userinfo": self.has_userinfo,
            "suspicious_encoding": self.suspicious_encoding,
            "has_punycode": self.has_punycode,
            "suspicious_port": self.suspicious_port,
            "redirect_indicator": self.redirect_indicator,
            "analysis_status": self.analysis_status,
            "analysis_error": self.analysis_error,
        }


def _redact_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        safe_query = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            safe_query.append((key, "[REDACTED]" if key.lower() in SENSITIVE_QUERY_PARAMS else value))
        # Do not expose credentials embedded in URL userinfo in the safe report.
        hostname = parsed.hostname or ""
        netloc = hostname
        if parsed.port is not None:
            netloc = f"{hostname}:{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(safe_query), ""))
    except (ValueError, UnicodeError):
        return "[REDACTED_INVALID_URL]"
