"""Normalized Loopdy event records and privacy-minimal push payloads."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping
from urllib.parse import quote


EVENT_TYPES = frozenset(
    {
        "attention.required",
        "approval.required",
        "session.completed",
        "session.failed",
        "delegation.started",
        "delegation.updated",
        "delegation.completed",
        "task.updated",
        "job.completed",
        "job.failed",
        "channel.message",
    }
)


@dataclass(frozen=True)
class LoopdyEvent:
    event_id: str
    type: str
    profile: str
    session_id: str = ""
    job_id: str = ""
    task_id: str = ""
    approval_id: str = ""
    delegation_id: str = ""
    detail: Mapping[str, Any] = field(default_factory=dict)

    @property
    def deep_link(self) -> str:
        return f"loopdy:///dashboard?eventId={quote(self.event_id, safe='')}"

    @property
    def push_payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "event_id": self.event_id,
            "type": self.type,
            "deep_link": self.deep_link,
        }


def build_event(
    kind: str,
    *,
    correlation: Iterable[Any] = (),
    profile: str = "default",
    session_id: str = "",
    job_id: str = "",
    task_id: str = "",
    approval_id: str = "",
    delegation_id: str = "",
    detail: Mapping[str, Any] | None = None,
) -> LoopdyEvent:
    if kind not in EVENT_TYPES:
        raise ValueError(f"Unsupported Loopdy event type: {kind}")
    return LoopdyEvent(
        event_id=_event_id(kind, correlation),
        type=kind,
        profile=_text(profile, 80) or "default",
        session_id=_text(session_id, 180),
        job_id=_text(job_id, 180),
        task_id=_text(task_id, 180),
        approval_id=_text(approval_id, 180),
        delegation_id=_text(delegation_id, 180),
        detail=dict(detail or {}),
    )


def _event_id(kind: str, correlation: Iterable[Any]) -> str:
    values = [str(value).strip() for value in correlation if str(value or "").strip()]
    if not values:
        return f"{kind}:{uuid.uuid4().hex}"
    encoded = json.dumps(values, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return f"{kind}:{hashlib.sha256(encoded).hexdigest()[:32]}"


def _text(value: Any, maximum: int) -> str:
    return " ".join(value.split())[:maximum] if isinstance(value, str) else ""
