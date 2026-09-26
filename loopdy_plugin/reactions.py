"""Supported SessionDB-backed reactions for Loopdy conversations.

The plugin uses Hermes' public session context/state registry. It never imports a
private TUI handler or patches the runtime. The typed result lets native Loopdy
paint the write immediately while ordinary history remains authoritative.
"""
from __future__ import annotations

import json
import unicodedata
from typing import Any

REACTION_SCHEMA = "loopdy.message-reaction"


def supported() -> bool:
    try:
        from gateway.session_context import get_session_env  # noqa: F401
        from hermes_state_registry import acquire, release_or_close  # noqa: F401
    except (ImportError, AttributeError):
        return False
    return True


def _error(code: str) -> str:
    return json.dumps(
        {"schema": REACTION_SCHEMA, "version": 1, "success": False, "error": code},
        separators=(",", ":"), sort_keys=True,
    )


def _emoji(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("reaction_invalid")
    candidate = value.strip()
    if not candidate:
        return ""
    if len(candidate.encode("utf-8")) > 32 or any(
        character.isspace() or unicodedata.category(character).startswith("C")
        for character in candidate
    ):
        raise ValueError("reaction_invalid")
    return candidate


def react(emoji: Any, message_row_id: Any = None, messages_back: Any = None) -> str:
    try:
        normalized = _emoji(emoji)
        back = 0 if messages_back is None else int(messages_back)
        if back < 0 or back > 100:
            raise ValueError("reaction_offset_invalid")
        row_id = None if message_row_id is None else int(message_row_id)
        if row_id is not None and row_id <= 0:
            raise ValueError("reaction_message_invalid")
    except (TypeError, ValueError) as error:
        return _error(str(error) if str(error).startswith("reaction_") else "reaction_invalid")

    from gateway.session_context import get_session_env
    from hermes_state_registry import acquire, release_or_close

    session_key = (get_session_env("HERMES_SESSION_KEY", "")
                   or get_session_env("HERMES_SESSION_ID", ""))
    if not session_key:
        return _error("reaction_session_unavailable")
    try:
        database = acquire()
    except Exception:
        return _error("reaction_storage_unavailable")
    try:
        if row_id is None:
            row_id = database.latest_message_row_id(session_key, role="user", offset=back)
            if row_id is None:
                return _error("reaction_message_unavailable")
        else:
            role = database.get_message_role(session_key, row_id)
            if role != "user":
                return _error("reaction_target_not_human")
        reactions = database.set_message_reaction(
            session_key, row_id, normalized or None, author="agent"
        )
        if reactions is None:
            return _error("reaction_message_unavailable")
        # Paint it live in app chats, as Hermes' own react tool does; without
        # a UI bridge the stored reaction still shows on the next history read.
        try:
            from tools import desktop_ui
            desktop_ui.emit("message.reaction", {"row_id": int(row_id), "reactions": reactions, "role": "user"})
        except Exception:
            pass
        return json.dumps({
            "schema": REACTION_SCHEMA,
            "version": 1,
            "success": True,
            "rowId": row_id,
            "targetRole": "user",
            "reactions": reactions,
        }, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    except Exception:
        return _error("reaction_write_failed")
    finally:
        try:
            release_or_close(database)
        except Exception:
            pass


PARAMETERS = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "emoji": {
            "type": "string",
            "maxLength": 16,
            "description": "One emoji reaction, or an empty string to remove the agent reaction.",
        },
        "message_row_id": {
            "type": "integer",
            "minimum": 1,
            "description": "Optional durable Hermes row ID for a human message.",
        },
        "messages_back": {
            "type": "integer",
            "minimum": 0,
            "maximum": 100,
            "description": "When no row ID is supplied, 0 is the latest human message and 1 is the previous one.",
        },
    },
    "required": ["emoji"],
}


def register(ctx: Any) -> bool:
    if not supported():
        return False
    ctx.register_tool(
        name="loopdy_react_to_message",
        toolset="loopdy",
        schema={
            "name": "loopdy_react_to_message",
            "description": (
                "React to the person's message in the bighelp app with one emoji, the way "
                "you'd tapback in iMessage: something funny gets a 😂, good news or warmth a "
                "❤️, a plan you're on board with a 👍. If a reaction says it all it can be the "
                "whole reply; otherwise react and carry on. Use it like a person would, now and "
                "then when it's felt, not on every message and never as a status signal. Never "
                "narrate or explain the reaction. Omit message_row_id for their latest message; "
                "a different emoji replaces yours and an empty string removes it."
            ),
            "parameters": PARAMETERS,
        },
        handler=lambda args, **_: react(
            args.get("emoji", ""),
            args.get("message_row_id"),
            args.get("messages_back"),
        ),
        emoji="💛",
    )
    return True
