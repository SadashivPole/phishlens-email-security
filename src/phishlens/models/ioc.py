from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .indicators import SENSITIVE_QUERY_PARAMS

IOCType = Literal["ip", "domain", "url", "hash"]


@dataclass
class IOC:
    ioc_type: IOCType
    original_value: str
    normalized_value: str
    source: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str]:
        return self.ioc_type, self.normalized_value

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_safe_dict(self) -> dict[str, Any]:
        result = self.to_dict()
        if self.ioc_type == "url":
            result["original_value"] = None
            result["normalized_value"] = _redact_url(self.normalized_value)
        result["provenance"] = _safe_provenance(result.get("provenance", {}))
        return result


def _safe_provenance(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {name: _safe_provenance(item, name.lower()) for name, item in value.items()}
    if isinstance(value, list):
        return [_safe_provenance(item, key) for item in value]
    if isinstance(value, str) and (key in {"url", "original_url", "normalized_url"} or value.startswith(("http://", "https://"))):
        return _redact_url(value)
    return value


def _redact_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        query = [
            (key, "[REDACTED]" if key.lower() in SENSITIVE_QUERY_PARAMS else value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]

        # Never expose URL userinfo credentials in safe output.
        hostname = parsed.hostname or ""
        netloc = hostname
        if ":" in hostname and not hostname.startswith("["):
            netloc = f"[{hostname}]"
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"

        return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(query), ""))
    except (ValueError, UnicodeError):
        return "[REDACTED_INVALID_URL]"
