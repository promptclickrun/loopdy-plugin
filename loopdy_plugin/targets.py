"""Native Loopdy channel target parsing."""

from __future__ import annotations

import re


_TARGET = re.compile(r"^(device|group):([A-Za-z0-9][A-Za-z0-9._-]{0,127})$")


def parse_target(raw: str) -> tuple[str, None] | None:
    value = str(raw or "").strip()
    if value == "all":
        return value, None
    match = _TARGET.fullmatch(value)
    if match is None or ".." in match.group(2):
        return None
    return value, None


def validate_target(target: str) -> bool | str:
    if parse_target(target) is not None:
        return True
    return "use all, device:<id>, or group:<id>"
