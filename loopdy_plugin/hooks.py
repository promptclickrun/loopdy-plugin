"""Hermes lifecycle hook normalization for Loopdy notifications."""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from .events import LoopdyEvent, build_event
from .sensitive import contains_sensitive_credential


_CRON_SESSION = re.compile(r"^cron_(.+)_\d{8}_\d{6}$")


def normalize_hook(hook: str, *, profile: str, **payload: Any) -> LoopdyEvent | None:
    profile = _text(payload.get("profile_name"), 80) or profile

    if hook == "pre_tool_call":
        # Hermes creates the actionable clarify_id later, inside the gateway
        # callback. LoopdyAdapter.send_clarify owns the durable attention event
        # so Home never receives a duplicate card bound to the tool_call_id.
        return None

    if hook == "on_session_end":
        completed = payload.get("completed") is True
        failed = payload.get("failed") is True
        if payload.get("interrupted") is True or not (completed or failed):
            return None
        platform = _text(payload.get("platform"), 40).lower()
        # A turn is not a permanent session closure. Never guess its owner
        # from task_id or truncate coordinates into another run's identity.
        session_id = _identity(payload.get("session_id"))
        turn_id = _identity(payload.get("turn_id"))
        if not session_id:
            return None
        if platform == "cron":
            job_id = _cron_job_id(session_id)
            detail = {"status": "failed" if failed else "completed"}
            if turn_id:
                detail["turn_id"] = turn_id
            if failed:
                detail["reason"] = _text(payload.get("turn_exit_reason"), 120)
            return build_event(
                "job.failed" if failed else "job.completed",
                correlation=("job", profile, session_id, turn_id),
                profile=profile,
                session_id=session_id,
                job_id=job_id,
                task_id=job_id,
                detail=detail,
            )
        if completed and not failed:
            # The parent-owned subagent_stop record represents delegated work.
            # A second user completion for the child would duplicate that run.
            if not turn_id or platform == "subagent" or payload.get("parent_session_id"):
                return None
            return build_event(
                "session.completed",
                correlation=("session", profile, session_id, turn_id),
                profile=profile,
                session_id=session_id,
                detail={"status": "completed", "turn_id": turn_id},
            )
        return build_event(
            "session.failed",
            correlation=("session", profile, session_id, turn_id),
            profile=profile,
            session_id=session_id,
            detail={"reason": _text(payload.get("turn_exit_reason"), 120) or None},
        )

    if hook in {"subagent_start", "subagent_stop"}:
        parent_session = _identity(payload.get("parent_session_id"))
        child_session = _identity(payload.get("child_session_id"))
        delegation_id = _identity(payload.get("child_subagent_id")) or child_session
        if not parent_session or not delegation_id:
            return None
        status = "running" if hook == "subagent_start" else (
            _text(payload.get("child_status"), 40) or "unknown"
        )
        event_type = (
            "delegation.started"
            if hook == "subagent_start"
            else "delegation.completed"
            if status == "completed"
            else "delegation.updated"
        )
        detail = {
            "status": status,
            "parent_session_id": parent_session,
            "delegation_id": delegation_id,
        }
        if child_session:
            detail["child_session_id"] = child_session
        parent_turn = _identity(payload.get("parent_turn_id"))
        if parent_turn:
            detail["turn_id"] = parent_turn
        title = _goal_title(payload.get("child_goal"))
        if title:
            detail["title"] = title
        # Stop need not repeat the goal or subagent ID. The child session is
        # the shared run coordinate; registration restores start metadata.
        return build_event(
            event_type,
            correlation=(
                "delegation", profile, parent_session,
                child_session or delegation_id, status,
            ),
            profile=profile,
            session_id=parent_session,
            delegation_id=delegation_id,
            detail=detail,
        )

    if hook in {"kanban_task_claimed", "kanban_task_completed", "kanban_task_blocked"}:
        task_id = _text(payload.get("task_id"), 180)
        status = {
            "kanban_task_claimed": "running",
            "kanban_task_completed": "completed",
            "kanban_task_blocked": "blocked",
        }[hook]
        return build_event(
            "task.updated",
            correlation=("task", task_id, status, payload.get("run_id")),
            profile=profile,
            task_id=task_id,
            delegation_id=task_id,
            detail={
                "entity": "task",
                "status": status,
                "board": _text(payload.get("board"), 180) or None,
                "assignee": _text(payload.get("assignee"), 180) or None,
                "run_id": payload.get("run_id"),
                "summary": _text(payload.get("summary"), 2000) or None,
                "reason": _text(payload.get("reason"), 500) or None,
            },
        )

    return None


def _cron_job_id(session_id: str) -> str:
    match = _CRON_SESSION.fullmatch(session_id)
    return match.group(1) if match else ""


def _identity(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 180:
        return ""
    if any(
        character.isspace() or unicodedata.category(character).startswith("C")
        for character in value
    ):
        return ""
    return value


def _goal_title(value: Any) -> str:
    # Store only a short purpose label, never the child reply, tool history,
    # or the rest of a multi-line delegation brief.
    if not isinstance(value, str):
        return ""
    first_line = next((line.strip() for line in value.splitlines() if line.strip()), "")
    title = (
        " ".join(first_line.split()).encode("utf-8")[:200]
        .decode("utf-8", errors="ignore")
    )
    if contains_sensitive_credential(first_line) or any(
        unicodedata.category(character).startswith("C") for character in title
    ):
        return ""
    return title


def _text(value: Any, maximum: int) -> str:
    return " ".join(value.split())[:maximum] if isinstance(value, str) else ""
