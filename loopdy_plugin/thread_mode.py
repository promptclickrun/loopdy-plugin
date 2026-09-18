"""Loopdy thread mode: coordinator/worker threads (plugin side).

Implements PROTOCOL.md: four ``loopdy``-toolset tools (thread_spawn,
thread_status, thread_collect, thread_note), the pre_llm_call injection for
coordinator/worker turns, and subagent_start/subagent_stop observers. All
state lives in Hermes PluginState (profile-scoped JSON KV) under
``threadmode:<coordinator_session_id>`` and ``threadmode:worker:<id>`` keys.

NO Hermes core changes. Workers are launched via ctx.subagent_lifecycle
(in-process subagents) or created out-of-turn by the Loopdy app as real
sessions (registered via the native REST surface). REST session.fork is
never used for workers.
"""
from __future__ import annotations

import json
import logging
import re
import time
from enum import Enum
from typing import Any

logger = logging.getLogger("hermes.plugins.loopdy.thread_mode")

THREAD_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
MAX_NOTES_PER_THREAD = 50
MAX_NOTE_CHARS = 2000
MAX_RESULT_CHARS = 20000
MAX_BRIEF_CHARS = 4000

STATUS_VALUES = (
    "spawning", "running", "succeeded", "failed",
    "cancelled", "interrupted", "unknown",
)
TERMINAL_STATUSES = {"succeeded", "failed", "cancelled", "interrupted"}

#: Maps Hermes SubagentState values onto the thread-mode status vocabulary.
_SUBAGENT_STATUS_MAP = {
    "PENDING": "spawning",
    "STARTING": "spawning",
    "RUNNING": "running",
    "CANCEL_REQUESTED": "running",
    "SUCCEEDED": "succeeded",
    "FAILED": "failed",
    "INTERRUPTED": "interrupted",
    "CANCELLED": "cancelled",
    "UNKNOWN": "unknown",
}

#: Maps subagent_stop hook child_status values onto our vocabulary.
_CHILD_STATUS_MAP = {
    "completed": "succeeded",
    "interrupted": "interrupted",
    "failed": "failed",
}

#: Clean error returned when thread_spawn is called without a live turn.
NO_LIVE_TURN_ERROR = (
    "thread_spawn needs a live coordinator turn (no active Hermes parent "
    "session). Create the worker from the Loopdy thread view instead."
)

_RESULT_HEADING_RE = re.compile(r"^##\s+Result\s*$", re.MULTILINE)
_NEXT_SECTION_RE = re.compile(r"^#{1,2}\s", re.MULTILINE)


def coordinator_key(coordinator_session_id: str) -> str:
    return f"threadmode:{coordinator_session_id}"


def worker_key(worker_session_id: str) -> str:
    return f"threadmode:worker:{worker_session_id}"


def _utcnow() -> float:
    return time.time()


def _new_coordinator_record(coordinator_session_id: str, enabled: bool = True) -> dict:
    return {
        "version": 1,
        "enabled": bool(enabled),
        "coordinator_session_id": coordinator_session_id,
        "updated_at": _utcnow(),
        "notes": [],
        "threads": {},
    }


def _load_coordinator(state: Any, coordinator_session_id: str) -> dict | None:
    if not isinstance(coordinator_session_id, str) or not coordinator_session_id:
        return None
    record = state.get(coordinator_key(coordinator_session_id))
    if not isinstance(record, dict):
        return None
    threads = record.get("threads")
    if not isinstance(threads, dict):
        record["threads"] = {}
    if not isinstance(record.get("notes"), list):
        record["notes"] = []
    return record


def _save_coordinator(state: Any, record: dict) -> None:
    record["updated_at"] = _utcnow()
    state.set(coordinator_key(record["coordinator_session_id"]), record)


def _ensure_coordinator(state: Any, coordinator_session_id: str) -> dict:
    record = _load_coordinator(state, coordinator_session_id)
    if record is None:
        record = _new_coordinator_record(coordinator_session_id, enabled=True)
    return record


def _new_thread_record(name: str, brief: str, kind: str) -> dict:
    now = _utcnow()
    return {
        "name": name,
        "brief": brief,
        "kind": kind,
        "status": "spawning",
        "subagent_id": None,
        "subagent_session_id": None,
        "handle": None,
        "worker_session_id": None,
        "notes": [],
        "result": None,
        "created_at": now,
        "updated_at": now,
    }


def public_thread(entry: dict) -> dict:
    """Roster projection: everything except the raw subagent handle dict."""
    ids = {}
    for key in ("subagent_id", "subagent_session_id", "worker_session_id"):
        value = entry.get(key)
        if value:
            ids[key] = value
    return {
        "name": entry.get("name"),
        "kind": entry.get("kind"),
        "status": entry.get("status"),
        "brief": entry.get("brief"),
        "ids": ids,
        "notes": list(entry.get("notes") or []),
        "result": entry.get("result"),
        "updated_at": entry.get("updated_at"),
    }


def parse_result_section(text: Any) -> str:
    """Return the first ``## Result`` heading section; fallback = full text."""
    if not isinstance(text, str) or not text:
        return ""
    match = _RESULT_HEADING_RE.search(text)
    if match is None:
        return text
    rest = text[match.end():]
    following = _NEXT_SECTION_RE.search(rest)
    section = rest[: following.start()] if following else rest
    return section.strip() or text


def worker_discipline(name: str, brief: str, extra_context: str = "") -> str:
    """The §8 worker discipline, injected via launch context / prompt."""
    lines = [
        f"You are worker thread `{name}` in a Loopdy thread-mode session. "
        "Do ONLY the scoped brief below. Do not expand scope.",
        "",
        "## Your assignment",
        brief,
    ]
    if extra_context and extra_context.strip():
        lines += ["", extra_context.strip()]
    lines += [
        "",
        "End your FINAL message with a `## Result` section containing the complete deliverable.",
        "NEVER write to global/profile memory (`MEMORY.md`). Scratch notes go via the "
        "`thread_note` tool (available in your toolset) — or just include them in your result.",
        "Sibling threads exist and work in parallel; shared context for you is injected above. "
        "Do not wait on them.",
    ]
    return "\n".join(lines)


def _tool_json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _map_subagent_state(state_value: Any) -> str:
    name = state_value.name if isinstance(state_value, Enum) else str(state_value)
    return _SUBAGENT_STATUS_MAP.get(name, "unknown")


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

def _thread_spawn_handler(ctx: Any):
    def handle(payload: Any, **kwargs: Any) -> str:
        coordinator_session_id = str(kwargs.get("session_id") or "")
        if not isinstance(payload, dict):
            return _tool_json({"ok": False, "error": "thread_spawn expects a JSON object payload."})
        specs = payload.get("threads")
        if not isinstance(specs, list) or not specs:
            return _tool_json({"ok": False, "error": "thread_spawn needs at least one thread."})
        if not coordinator_session_id:
            return _tool_json({"ok": False, "error": "thread_spawn needs a coordinator session."})
        state = ctx.state
        record = _ensure_coordinator(state, coordinator_session_id)
        results = [
            _spawn_one(ctx, state, record, coordinator_session_id, spec)
            for spec in specs
        ]
        _save_coordinator(state, record)
        return _tool_json({"ok": True, "threads": results})

    return handle


def _spawn_one(
    ctx: Any, state: Any, record: dict, coordinator_session_id: str, spec: Any,
) -> dict:
    name = spec.get("name") if isinstance(spec, dict) else None
    brief = spec.get("brief") if isinstance(spec, dict) else None
    extra = spec.get("context") if isinstance(spec, dict) else None
    if not isinstance(name, str) or THREAD_NAME_RE.fullmatch(name) is None:
        return {
            "name": name if isinstance(name, str) else None,
            "ok": False, "kind": "subagent",
            "error": f"Invalid thread name {name!r}: must match ^[a-z0-9][a-z0-9_-]{{0,63}}$.",
        }
    if name in record["threads"]:
        return {
            "name": name, "ok": False, "kind": "subagent",
            "error": f"A thread named '{name}' already exists for this coordinator.",
        }
    if not isinstance(brief, str) or not brief.strip():
        return {
            "name": name, "ok": False, "kind": "subagent",
            "error": f"Thread '{name}' needs a non-empty brief.",
        }
    brief = brief.strip()[:MAX_BRIEF_CHARS]

    # Persist the spawning record BEFORE launch: this closes the race where
    # the child's first pre_llm_call fires before the tool persists anything.
    entry = _new_thread_record(name, brief, "subagent")
    record["threads"][name] = entry
    _save_coordinator(state, record)

    from agent.subagent_lifecycle import SubagentLaunchRequest, SubagentLifecycleError

    try:
        request = SubagentLaunchRequest(
            goal=brief,
            context=worker_discipline(name, brief, extra if isinstance(extra, str) else ""),
            role="leaf",
            correlation_id=name,
            metadata={"threadmode": coordinator_session_id, "thread": name},
        )
        handle = ctx.subagent_lifecycle.launch(request)
    except SubagentLifecycleError as exc:
        entry["status"] = "failed"
        entry["updated_at"] = _utcnow()
        _save_coordinator(state, record)
        message = str(exc)
        if "No active Hermes parent session" in message:
            error = NO_LIVE_TURN_ERROR
        elif "Duplicate correlation_id" in message:
            error = f"A worker for thread '{name}' is already launching in this coordinator turn."
        else:
            error = f"thread_spawn failed for '{name}': {message[:400]}"
        return {"name": name, "ok": False, "kind": "subagent", "error": error}
    except Exception as exc:  # never leak a traceback to the model
        entry["status"] = "failed"
        entry["updated_at"] = _utcnow()
        _save_coordinator(state, record)
        return {
            "name": name, "ok": False, "kind": "subagent",
            "error": f"thread_spawn failed for '{name}': {type(exc).__name__}.",
        }
    entry["subagent_id"] = handle.subagent_id
    entry["handle"] = handle.to_dict()
    entry["status"] = "running"
    entry["updated_at"] = _utcnow()
    _save_coordinator(state, record)
    return {"name": name, "ok": True, "kind": "subagent", "subagent_id": handle.subagent_id}


def _refresh_subagent_status(ctx: Any, entry: dict) -> str | None:
    """Best-effort refresh of a subagent-kind thread's status; None on failure."""
    handle_dict = entry.get("handle")
    if not isinstance(handle_dict, dict):
        return None
    try:
        from agent.subagent_lifecycle import SubagentHandle
        handle = SubagentHandle.from_dict(handle_dict)
        status = ctx.subagent_lifecycle.status(handle)
    except Exception:
        logger.warning("Thread-mode subagent status refresh failed", exc_info=True)
        return None
    return _map_subagent_state(getattr(status, "state", "UNKNOWN"))


def _thread_status_handler(ctx: Any):
    def handle(payload: Any, **kwargs: Any) -> str:
        coordinator_session_id = str(kwargs.get("session_id") or "")
        record = _load_coordinator(ctx.state, coordinator_session_id)
        if record is None:
            return _tool_json({"ok": True, "threads": []})
        changed = False
        for entry in record["threads"].values():
            if (
                entry.get("kind") == "subagent"
                and entry.get("status") not in TERMINAL_STATUSES
            ):
                refreshed = _refresh_subagent_status(ctx, entry)
                if refreshed is not None and refreshed != entry.get("status"):
                    entry["status"] = refreshed
                    entry["updated_at"] = _utcnow()
                    changed = True
        if changed:
            _save_coordinator(ctx.state, record)
        return _tool_json(
            {"ok": True, "threads": [public_thread(e) for e in record["threads"].values()]}
        )

    return handle


def _read_worker_session_text(ctx: Any, worker_session_id: Any) -> str | None:
    """Best-effort control-plane read of a session-kind worker's last text.

    Returns the last assistant message's text, or None when unavailable.
    """
    if not isinstance(worker_session_id, str) or not worker_session_id:
        return None
    try:
        from hermes_state import SessionDB
        from hermes_cli.profiles import get_profile_dir
        profile = str(getattr(ctx, "profile_name", "default") or "default")
        db = SessionDB(db_path=get_profile_dir(profile) / "state.db", read_only=True)
        try:
            messages = db.get_messages(worker_session_id, latest=True, limit=50)
        finally:
            db.close()
    except Exception:
        logger.warning("Thread-mode worker session read failed", exc_info=True)
        return None
    for message in reversed(messages or []):
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            return content
    return None


def _thread_collect_handler(ctx: Any):
    def handle(payload: Any, **kwargs: Any) -> str:
        coordinator_session_id = str(kwargs.get("session_id") or "")
        name = payload.get("thread_name") if isinstance(payload, dict) else None
        record = _load_coordinator(ctx.state, coordinator_session_id)
        entry = record["threads"].get(name) if record and isinstance(name, str) else None
        if entry is None:
            return _tool_json({"collected": False, "error": f"Unknown thread '{name}'."})
        if entry.get("kind") == "session":
            text = _read_worker_session_text(ctx, entry.get("worker_session_id"))
            if text is None:
                return _tool_json({
                    "collected": False,
                    "thread_name": name,
                    "worker_session_id": entry.get("worker_session_id"),
                    "hint": "Read the worker session directly.",
                })
            result = parse_result_section(text)[:MAX_RESULT_CHARS]
            entry["result"] = result
            entry["updated_at"] = _utcnow()
            _save_coordinator(ctx.state, record)
            return _tool_json({"collected": True, "thread_name": name, "result": result})
        handle_dict = entry.get("handle")
        if not isinstance(handle_dict, dict):
            return _tool_json({"collected": False, "thread_name": name,
                               "status": entry.get("status"),
                               "error": "Subagent handle is missing."})
        try:
            from agent.subagent_lifecycle import SubagentHandle
            handle = SubagentHandle.from_dict(handle_dict)
            outcome = ctx.subagent_lifecycle.result(handle)
        except Exception:
            logger.warning("Thread-mode subagent result read failed", exc_info=True)
            return _tool_json({"collected": False, "thread_name": name,
                               "status": entry.get("status")})
        if not getattr(outcome, "ready", False):
            return _tool_json({"collected": False, "thread_name": name,
                               "status": entry.get("status")})
        # Never block: no wait() with a timeout here.
        summary = getattr(outcome, "summary", None)
        result = parse_result_section(summary)[:MAX_RESULT_CHARS]
        entry["result"] = result
        entry["updated_at"] = _utcnow()
        _save_coordinator(ctx.state, record)
        return _tool_json({"collected": True, "thread_name": name, "result": result})

    return handle


def _thread_note_handler(ctx: Any):
    def handle(payload: Any, **kwargs: Any) -> str:
        coordinator_session_id = str(kwargs.get("session_id") or "")
        if not isinstance(payload, dict):
            return _tool_json({"ok": False, "error": "thread_note expects a JSON object payload."})
        note = payload.get("note")
        if not isinstance(note, str) or not note.strip():
            return _tool_json({"ok": False, "error": "thread_note needs a non-empty note."})
        note = note.strip()[:MAX_NOTE_CHARS]
        name = payload.get("thread_name")
        record = _ensure_coordinator(ctx.state, coordinator_session_id)
        if name is None:
            notes = record.setdefault("notes", [])
        else:
            entry = record["threads"].get(name) if isinstance(name, str) else None
            if entry is None:
                return _tool_json({"ok": False, "error": f"Unknown thread '{name}'."})
            notes = entry.setdefault("notes", [])
        notes.append(note)
        del notes[: max(0, len(notes) - MAX_NOTES_PER_THREAD)]
        _save_coordinator(ctx.state, record)
        return _tool_json({"ok": True, "note_count": len(notes)})

    return handle


# ---------------------------------------------------------------------------
# pre_llm_call injection
# ---------------------------------------------------------------------------

def _coordinator_section(record: dict) -> str:
    threads = record.get("threads") or {}
    rows = ["| name | kind | status | brief |", "| --- | --- | --- | --- |"]
    for entry in threads.values():
        rows.append(
            f"| {entry.get('name')} | {entry.get('kind')} | {entry.get('status')} "
            f"| {(entry.get('brief') or '')[:120]} |"
        )
    roster = "\n".join(rows) if threads else "No threads yet."
    return (
        "## Thread mode — coordinator\n"
        "You are the coordinator of a Loopdy thread-mode session. "
        f"{len(threads)} worker thread(s) run in parallel.\n"
        f"{roster}\n"
        "Treat this current coordinator chat as the user's single project conversation: "
        "the user speaks naturally, and you automatically decide whether a request benefits "
        "from parallel scoped worker threads. Answer simple requests directly. When parallel "
        "work helps, choose thread names and briefs yourself and call `thread_spawn` during "
        "the live turn, without asking the user to create or name threads. Monitor progress "
        "with `thread_status`, gather finished work with `thread_collect`, and return the "
        "assembled final answer in this current coordinator chat — never ask a worker to "
        "assemble it. The Loopdy thread view's manual thread creation is an optional fallback "
        "for session-backed workers, never the primary workflow.\n"
        "Memory discipline: ONLY you write durable profile memory (`MEMORY.md`). "
        "Workers never do; all cross-thread scratch lives in thread-mode plugin state "
        "and is injected into turns."
    )


def _worker_section(entry: dict, siblings: list[dict]) -> str:
    notes = entry.get("notes") or []
    sibling_lines = [
        f"- {s.get('name')}: {s.get('status')}"
        for s in siblings if s.get("name") != entry.get("name")
    ]
    lines = [
        "## Your thread assignment",
        f"You are worker thread `{entry.get('name')}` in a Loopdy thread-mode session.",
        "",
        "Scoped brief:",
        str(entry.get("brief") or ""),
        "",
        "Scratch notes for this thread:",
    ]
    lines += [f"- {note}" for note in notes] if notes else ["(none)"]
    lines += ["", "Sibling threads (names + statuses only):"]
    lines += sibling_lines if sibling_lines else ["(none)"]
    lines += ["", worker_discipline(str(entry.get("name")), str(entry.get("brief") or ""))]
    return "\n".join(lines)


def _resolve_worker_entry(record: dict, worker_session_id: str) -> dict | None:
    """Match a worker turn's session id to its thread record."""
    threads = record.get("threads") or {}
    for entry in threads.values():
        if entry.get("subagent_session_id") == worker_session_id:
            return entry
    # Fallback: the single spawning/running thread for that coordinator.
    candidates = [
        entry for entry in threads.values()
        if entry.get("status") in ("spawning", "running")
    ]
    if len(candidates) == 1:
        return candidates[0]
    return None


def pre_llm_call(state: Any, **payload: Any) -> dict | None:
    """Additive thread-mode context injection. Never breaks the turn: fails silent."""
    try:
        session_id = str(payload.get("session_id") or "")
        parent_session_id = str(payload.get("parent_session_id") or "")
        if not session_id:
            return None
        if parent_session_id:
            # Subagent-kind worker turn.
            record = _load_coordinator(state, parent_session_id)
            if record is None or not record.get("enabled"):
                return None
            entry = _resolve_worker_entry(record, session_id)
            if entry is None:
                return None
            siblings = list((record.get("threads") or {}).values())
            return {"context": _worker_section(entry, siblings)}
        record = _load_coordinator(state, session_id)
        if record is not None and record.get("enabled"):
            return {"context": _coordinator_section(record)}
        index = state.get(worker_key(session_id))
        if isinstance(index, dict):
            coordinator_session_id = index.get("coordinator_session_id")
            thread_name = index.get("thread")
            record = _load_coordinator(state, coordinator_session_id)
            if record is not None and record.get("enabled"):
                entry = (record.get("threads") or {}).get(thread_name)
                if entry is not None:
                    siblings = list((record.get("threads") or {}).values())
                    return {"context": _worker_section(entry, siblings)}
        return None
    except Exception:
        logger.warning("Thread-mode pre_llm_call injection failed", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# subagent_start / subagent_stop observers
# ---------------------------------------------------------------------------

def subagent_start(state: Any, **payload: Any) -> None:
    """Record child_session_id and write the worker index at subagent_start."""
    try:
        parent_session_id = str(payload.get("parent_session_id") or "")
        child_subagent_id = str(payload.get("child_subagent_id") or "")
        child_session_id = str(payload.get("child_session_id") or "")
        if not parent_session_id or not child_subagent_id or not child_session_id:
            return
        record = _load_coordinator(state, parent_session_id)
        if record is None or not record.get("enabled"):
            return
        for name, entry in (record.get("threads") or {}).items():
            if entry.get("kind") == "subagent" and entry.get("subagent_id") == child_subagent_id:
                entry["subagent_session_id"] = child_session_id
                if entry.get("status") not in TERMINAL_STATUSES:
                    entry["status"] = "running"
                entry["updated_at"] = _utcnow()
                _save_coordinator(state, record)
                state.set(worker_key(child_session_id), {
                    "coordinator_session_id": parent_session_id,
                    "thread": name,
                })
                return
    except Exception:
        logger.warning("Thread-mode subagent_start observation failed", exc_info=True)


def subagent_stop(state: Any, **payload: Any) -> None:
    """Map the child's terminal status onto the thread record."""
    try:
        parent_session_id = str(payload.get("parent_session_id") or "")
        child_session_id = str(payload.get("child_session_id") or "")
        if not parent_session_id or not child_session_id:
            return
        record = _load_coordinator(state, parent_session_id)
        if record is None or not record.get("enabled"):
            return
        mapped = _CHILD_STATUS_MAP.get(str(payload.get("child_status") or ""))
        if mapped is None:
            return
        for entry in (record.get("threads") or {}).values():
            if (
                entry.get("kind") == "subagent"
                and entry.get("subagent_session_id") == child_session_id
            ):
                entry["status"] = mapped
                entry["updated_at"] = _utcnow()
                _save_coordinator(state, record)
                return
    except Exception:
        logger.warning("Thread-mode subagent_stop observation failed", exc_info=True)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

THREAD_TOOLS = (
    (
        "thread_spawn",
        "Launch one or more parallel worker threads (Hermes in-process subagents) from a live "
        "coordinator turn. Each thread needs a unique name matching ^[a-z0-9][a-z0-9_-]{0,63}$ "
        "and a scoped brief. The scoped brief becomes the worker's assignment; thread_spawn "
        "needs a live coordinator turn. Requires thread mode enabled for this conversation.",
        {
            "type": "object",
            "properties": {
                "threads": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$"},
                            "brief": {"type": "string", "minLength": 1, "maxLength": 4000},
                            "context": {"type": "string", "maxLength": 4000},
                        },
                        "required": ["name", "brief"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["threads"],
            "additionalProperties": False,
        },
    ),
    (
        "thread_status",
        "Report the current roster of thread-mode worker threads: name, kind, status, brief, "
        "ids, and timestamps. Subagent-kind statuses refresh from the Hermes subagent lifecycle.",
        {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    (
        "thread_collect",
        "Collect a worker thread's finished deliverable. Parses the worker's `## Result` "
        "section (falls back to the full final text). Never blocks. For session-backed "
        "threads the result comes from the worker session's recent messages when available.",
        {
            "type": "object",
            "properties": {
                "thread_name": {"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$"},
            },
            "required": ["thread_name"],
            "additionalProperties": False,
        },
    ),
    (
        "thread_note",
        "Append a scratch note to a worker thread (max 50 notes, 2000 chars each). Omit "
        "thread_name to write a coordinator-level note. Only the coordinator writes "
        "durable profile memory; thread notes are cross-thread scratch.",
        {
            "type": "object",
            "properties": {
                "thread_name": {"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$"},
                "note": {"type": "string", "minLength": 1, "maxLength": 2000},
            },
            "required": ["note"],
            "additionalProperties": False,
        },
    ),
)


def register(ctx: Any) -> None:
    """Register thread-mode tools and additive hooks. Closes over ctx."""
    handlers = {
        "thread_spawn": _thread_spawn_handler(ctx),
        "thread_status": _thread_status_handler(ctx),
        "thread_collect": _thread_collect_handler(ctx),
        "thread_note": _thread_note_handler(ctx),
    }
    for name, description, parameters in THREAD_TOOLS:
        ctx.register_tool(
            name=name,
            toolset="loopdy",
            schema={"name": name, "description": description, "parameters": parameters},
            handler=handlers[name],
        )
    # Additive hooks: registered alongside the existing ones; fail silent.
    # ctx.state resolves lazily at fire time so registration never assumes
    # a state facade the host may not provide.
    ctx.register_hook("pre_llm_call", lambda **payload: pre_llm_call(ctx.state, **payload))
    ctx.register_hook("subagent_start", lambda **payload: subagent_start(ctx.state, **payload))
    ctx.register_hook("subagent_stop", lambda **payload: subagent_stop(ctx.state, **payload))
    # Expose the profile's PluginState to the out-of-turn REST surface
    # (native_threads scans sys.modules for the loader-owned module).
    from .native_threads import register_state_resolver
    register_state_resolver(str(getattr(ctx, "profile_name", "default") or "default"),
                            _LazyState(ctx))


class _LazyState:
    """Defers to ctx.state so registration works without an eager facade."""

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def get(self, key: str, default: Any = None) -> Any:
        return self._ctx.state.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._ctx.state.set(key, value)
