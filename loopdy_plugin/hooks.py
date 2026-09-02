"""Hermes lifecycle hook normalization for Loopdy notifications."""

from __future__ import annotations

import re
from typing import Any

from .events import LoopdyEvent, build_event


_CRON_SESSION = re.compile(r"^cron_(.+)_\d{8}_\d{6}$")


def normalize_hook(hook: str, *, profile: str, **payload: Any) -> LoopdyEvent | None:
    profile = _text(payload.get("profile_name"), 80) or profile
    session_id = _text(payload.get("session_id") or payload.get("task_id"), 180)
    turn_id = _text(payload.get("turn_id"), 180)

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
        if completed and not failed:
            if platform != "cron":
                return None
            job_id = _cron_job_id(session_id)
            return build_event(
                "job.completed",
                correlation=("job", job_id or session_id, turn_id),
                profile=profile,
                session_id=session_id,
                job_id=job_id,
                task_id=job_id,
                detail={"status": "completed"},
            )
        if platform == "cron":
            job_id = _cron_job_id(session_id)
            return build_event(
                "job.failed",
                correlation=("job", job_id or session_id, turn_id),
                profile=profile,
                session_id=session_id,
                job_id=job_id,
                task_id=job_id,
                detail={
                    "status": "failed",
                    "reason": _text(payload.get("turn_exit_reason"), 120) or None,
                },
            )
        return build_event(
            "session.failed",
            correlation=("session", session_id, turn_id),
            profile=profile,
            session_id=session_id,
            detail={"reason": _text(payload.get("turn_exit_reason"), 120) or None},
        )

    if hook in {"subagent_start", "subagent_stop"}:
        parent_session = _text(payload.get("parent_session_id"), 180)
        delegation_id = _text(
            payload.get("child_subagent_id") or payload.get("child_session_id"), 180
        )
        status = "running" if hook == "subagent_start" else (
            _text(payload.get("child_status"), 40) or "completed"
        )
        event_type = (
            "delegation.started"
            if hook == "subagent_start"
            else "delegation.completed"
            if status == "completed"
            else "delegation.updated"
        )
        return build_event(
            event_type,
            correlation=("delegation", parent_session, delegation_id, status),
            profile=profile,
            session_id=parent_session,
            delegation_id=delegation_id,
            detail={"status": status},
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


def _text(value: Any, maximum: int) -> str:
    return " ".join(value.split())[:maximum] if isinstance(value, str) else ""
