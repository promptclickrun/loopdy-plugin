"""Shared fail-closed patterns for content that must not leave the Hermes host."""

from __future__ import annotations

import re


SECRET_PATH_SOURCE = (
    r"(^|/)(?:\.env(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)|.*\.(?:pem|p12|pfx|key|keystore))$"
)
SENSITIVE_CREDENTIAL_SOURCE = (
    r"(?:BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|"
    r"(?:api[_-]?key|secret|token|password|credential)\s*[:=]\s*[^\s]{8,}|"
    r"https?://[^\s:@]+:[^\s@]+@|"
    r"github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"xox[baprs]-[A-Za-z0-9-]{20,}|"
    r"sk-(?:proj-)?[A-Za-z0-9_-]{16,}|"
    r"[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|"
    r"[A-Za-z][A-Za-z0-9_-]{1,40}\s*[:=]\s*"
    r"(?=[^\s]{24,}(?:\s|$))(?=[^\s]*[A-Za-z])(?=[^\s]*[0-9])"
    r"[A-Za-z0-9_./+=-]{24,})"
)

SECRET_PATH_RE = re.compile(SECRET_PATH_SOURCE, re.IGNORECASE)
SENSITIVE_CREDENTIAL_RE = re.compile(SENSITIVE_CREDENTIAL_SOURCE, re.IGNORECASE)
SENSITIVE_CREDENTIAL_BYTES_RE = re.compile(
    SENSITIVE_CREDENTIAL_SOURCE.encode("ascii"),
    re.IGNORECASE,
)


def contains_sensitive_credential(value: str) -> bool:
    return bool(SENSITIVE_CREDENTIAL_RE.search(value))


__all__ = [
    "SECRET_PATH_RE",
    "SENSITIVE_CREDENTIAL_BYTES_RE",
    "contains_sensitive_credential",
]
