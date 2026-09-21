from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    max_email_bytes: int = 10 * 1024 * 1024
    max_attachment_bytes: int = 5 * 1024 * 1024
    max_mime_parts: int = 100

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_email_bytes", _env_int("PHISHLENS_MAX_EMAIL_BYTES", self.max_email_bytes))
        object.__setattr__(self, "max_attachment_bytes", _env_int("PHISHLENS_MAX_ATTACHMENT_BYTES", self.max_attachment_bytes))


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return parsed if parsed > 0 else default
