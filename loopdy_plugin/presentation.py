"""Adaptive, bounded notification copy for Loopdy events."""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Mapping

from .events import LoopdyEvent
from .provider import PushMessage
from .sensitive import contains_sensitive_credential


_COPY = {
    "approval.required": ("Needs your approval", "Open Loopdy to review the request."),
    "attention.required": ("Session update", "Open Loopdy to continue."),
    "session.completed": (
        "Completion alert",
        "Open Loopdy to view the finished response.",
    ),
    "session.failed": ("Session update", "Open Loopdy to review what happened."),
    "delegation.started": (
        "Delegation started",
        "Open Loopdy to view the new delegation.",
    ),
    "delegation.updated": (
        "Session update",
        "Open Loopdy to view the latest activity.",
    ),
    "delegation.completed": (
        "Delegation complete",
        "Open Loopdy to view the completed delegation.",
    ),
    "task.updated": ("Session update", "Open Loopdy to view the task."),
    "job.completed": (
        "Completion alert",
        "Open Loopdy to view the scheduled task result.",
    ),
    "job.failed": ("Session update", "Open Loopdy to review the scheduled task."),
    "channel.message": (
        "Hermes just messaged you!",
        "Open Loopdy to view the message.",
    ),
}

_EVENT_LABELS = {
    "session.completed": "Session complete",
    "session.failed": "Session failed",
    "delegation.started": "Delegation started",
    "delegation.updated": "Delegation updated",
    "delegation.completed": "Delegation complete",
    "task.updated": "Task update",
    "job.completed": "Scheduled task complete",
    "job.failed": "Scheduled task failed",
    "channel.message": "Message",
}

_DETAIL_KEYS = {
    "attention.required": ("question", "summary", "message"),
    "session.completed": ("summary", "result", "message"),
    "session.failed": ("summary", "reason", "message"),
    "delegation.started": ("summary", "status", "message"),
    "delegation.updated": ("summary", "status", "message"),
    "delegation.completed": ("summary", "status", "message"),
    "task.updated": ("summary", "status", "message"),
    "job.completed": ("summary", "result", "message"),
    "job.failed": ("summary", "reason", "message"),
    "channel.message": ("message", "summary"),
}


def shape_notification(
    event: LoopdyEvent,
    preferences: Mapping[str, Any] | None = None,
) -> PushMessage:
    values = dict(preferences or {})
    requested_mode = str(values.get("detail_mode") or "automatic").strip().lower()
    mode = (
        requested_mode
        if requested_mode in {"automatic", "minimal", "detailed"}
        else "automatic"
    )
    if values.get("lock_screen_previews") is False:
        mode = "minimal"
    title, generic_body = _COPY.get(
        event.type,
        ("Session update", "Open Loopdy to view it."),
    )
    detail = event.detail if isinstance(event.detail, Mapping) else {}
    agent_name = _text(detail.get("agent_name") or detail.get("sender_name"), 80)
    session_title = _text(detail.get("session_title"), 100)
    if mode != "minimal":
        if session_title:
            title = f"{session_title} · {agent_name}" if agent_name else session_title
        elif event.type == "channel.message":
            title = f"{agent_name or 'Hermes'} just messaged you!"
        elif event.type in {
            "approval.required",
            "session.completed",
            "session.failed",
            "attention.required",
        }:
            title = _text(detail.get("title"), 100) or title
            if agent_name and not _text(detail.get("title"), 100):
                title = {
                    "approval.required": f"{agent_name} needs approval",
                    "attention.required": f"{agent_name} has a question",
                    "session.completed": f"{agent_name} finished",
                    "session.failed": f"{agent_name} session needs attention",
                }[event.type]
        elif event.type in {
            "delegation.started",
            "delegation.updated",
            "delegation.completed",
        } and agent_name:
            title = {
                "delegation.started": f"{agent_name} started a delegation",
                "delegation.updated": f"{agent_name} delegation updated",
                "delegation.completed": f"{agent_name} completed a delegation",
            }[event.type]
        elif event.type in {"task.updated", "job.completed", "job.failed"}:
            title = (
                _text(
                    detail.get("title")
                    or detail.get("task_title")
                    or detail.get("job_title"),
                    100,
                )
                or title
            )
    body = generic_body if mode == "minimal" else _event_body(event, generic_body)
    if mode != "minimal" and event.type not in {"approval.required", "attention.required"}:
        label = _EVENT_LABELS.get(event.type)
        if label:
            body = f"{label}: {body}"
    envelope = dict(event.push_payload)
    if event.approval_id:
        envelope["approval_id"] = event.approval_id
    return PushMessage(
        event_id=event.event_id,
        event_type=event.type,
        title=_text(title, 100),
        body=_text(body, 800),
        data={"loopdy": envelope},
        sound=values.get("priority_sound") is not False,
    )


def _event_body(event: LoopdyEvent, fallback: str) -> str:
    detail = event.detail if isinstance(event.detail, Mapping) else {}
    if event.type == "approval.required":
        raw_description = detail.get("description")
        raw_summary = detail.get("summary")
        description = _safe_approval_description(raw_description)
        summary = _safe_approval_description(raw_summary)
        if description or summary:
            return description or summary
        if not _text(raw_description, 400) and not _text(raw_summary, 400):
            command = _safe_approval_description(detail.get("command"))
            if command:
                return command
        if _text(detail.get("command"), 800):
            return "Review the requested command in Loopdy."
        return fallback
    for key in _DETAIL_KEYS.get(event.type, ()):
        value = (
            _safe_approval_description(detail.get(key))
            if event.type == "attention.required"
            else _text(detail.get(key), 800)
        )
        if value:
            return value
    return fallback


def _text(value: Any, maximum: int) -> str:
    if not isinstance(value, str):
        return ""
    normalized = unicodedata.normalize("NFC", " ".join(value.split()))
    budget = max(0, int(maximum))
    encoded = normalized.encode("utf-8")
    if len(encoded) <= budget:
        return normalized
    # Slice bytes only at a valid UTF-8 boundary. This keeps emoji and
    # combining sequences deterministic across APNs and relay providers.
    return encoded[:budget].decode("utf-8", errors="ignore")


_PRIVATE_DETAIL = re.compile(
    r"(?:^|[\s(\"'=])(?:[/\\]|~[/\\]|\.\.?[/\\]|[A-Za-z]:[/\\]|"
    r"(?:[A-Za-z0-9_.-]+[/\\])+(?:[A-Za-z0-9_.-]+))|"
    r"\b(?:https?|ssh|file)://|"
    r"(?:^|\s)-{1,2}[A-Za-z0-9]|"
    r"\b(?:api[_-]?key|secret|token|password|credential|authorization|bearer|"
    r"arguments?|prompt|pattern(?:_keys?)?|regex|glob)\b|"
    r"(?:gh[pousr]_|github_pat_|xox[baprs]-|eyJ[A-Za-z0-9_-]{8,}\.)",
    re.IGNORECASE,
)


def _safe_approval_description(value: Any) -> str:
    normalized = _text(value, 400)
    if (
        not normalized
        or _PRIVATE_DETAIL.search(normalized)
        or contains_sensitive_credential(normalized)
    ):
        return ""
    return normalized


__all__ = ["shape_notification"]
