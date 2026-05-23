"""Redaction helpers for logs, reports, and dashboard payloads."""

from __future__ import annotations

import re
from typing import Any

SENSITIVE_KEY_PARTS = ("token", "secret", "password", "private", "apikey", "api_key", "authorization")
SECRET_LIKE = re.compile(r"(?i)(sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{20,}|Bearer\s+[A-Za-z0-9._-]{16,})")


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, nested in value.items():
            if any(part in str(key).lower() for part in SENSITIVE_KEY_PARTS):
                result[key] = "[redacted]"
            else:
                result[key] = redact_value(nested)
        return result
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return SECRET_LIKE.sub("[redacted]", value)
    return value

