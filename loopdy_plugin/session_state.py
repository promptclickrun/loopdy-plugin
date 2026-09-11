"""Bounded display pages from Hermes' canonical session store.

No transcript is cached here. Hermes owns display ordering, compaction and row
identity. Continuations tolerate verified appends; rewind/replacement requires a
new snapshot. Call through the profile-scoped opener, off the gateway event loop.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any


class SessionStateResetRequired(ValueError):
    """The saved coordinate no longer describes this Hermes transcript."""


class SessionStateUnavailable(ValueError):
    """The installed Hermes store cannot provide bounded display history."""


_RICH_FIELDS = (
    "tool_call_id", "tool_calls", "tool_name", "effect_disposition", "timestamp",
    "token_count", "finish_reason", "reasoning", "reasoning_content",
    "reasoning_details", "codex_reasoning_items", "codex_message_items",
    "platform_message_id", "_compressed_summary", "display_kind", "display_metadata", "compacted",
)


def _json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")


def _integer(value: Any, maximum: int = 10_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError("Invalid session state coordinate")
    return value


def _scope(value: Any, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(c) < 32 for c in value):
        raise ValueError("Invalid session state scope")
    return value


def _revision(db: Any, stored_id: str) -> dict[str, int]:
    session = db.get_session(stored_id)
    if not session:
        raise SessionStateResetRequired("Session is no longer available")
    return {
        "count": int(session.get("message_count") or 0),
        "rewind": int(session.get("rewind_count") or 0),
        "head": int(db.get_active_message_watermark(stored_id)),
    }


def _parse_revision(value: Any) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != {"count", "rewind", "head"}:
        raise ValueError("Invalid session state revision")
    return {key: _integer(number, 2**63 - 1) for key, number in value.items()}


def _message(row: dict[str, Any]) -> dict[str, Any]:
    from hermes_cli.web_routers.sessions import _project_for_display

    projected = _project_for_display([row])[0]
    content = projected.get("display_content")
    if content is None or content == "":
        content = projected.get("content")
    result = {"id": str(row["id"]), "row_id": int(row["id"]), "role": row["role"], "content": content}
    result.update({key: projected[key] for key in _RICH_FIELDS if projected.get(key) is not None})
    # get_messages_around preserves the raw 0 flag; get_messages omits it.
    if not result.get("_compressed_summary"):
        result.pop("_compressed_summary", None)
    return result


class SessionStateReader:
    def __init__(self, *, maximum_rows: int = 24, maximum_bytes: int = 131_072,
                 maximum_row_bytes: int = 8_192):
        if not 1 <= maximum_rows <= 64 or not 4_096 <= maximum_bytes <= 262_144:
            raise ValueError("Invalid session page limits")
        if not 1_024 <= maximum_row_bytes <= maximum_bytes // 2:
            raise ValueError("Invalid session row limit")
        self.maximum_rows = maximum_rows
        self.maximum_bytes = maximum_bytes
        self.maximum_row_bytes = maximum_row_bytes

    async def read_profile(self, *, agent_id: str, stored_id: str,
                           cursor: dict[str, Any] | None = None) -> dict[str, Any]:
        from hermes_cli.web_routers.sessions import _with_db

        # The official opener validates/resolves the profile; no filesystem or
        # default-profile fallback is inferred from a requested identifier.
        return await asyncio.to_thread(
            _with_db, agent_id,
            lambda db: self.read(db, agent_id=agent_id, stored_id=stored_id, cursor=cursor),
            read_only=True,
        )

    def _coordinate(self, value: Any, *, agent_id: str, stored_id: str, kind: str) -> dict[str, Any]:
        extra = {"offset"} if kind == "cursor" else {"rowId", "sha256"}
        if (not isinstance(value, dict) or set(value) != {"version", "agentId", "storedId", "revision", *extra}
                or type(value["version"]) is not int or value["version"] != 1
                or value["agentId"] != agent_id or value["storedId"] != stored_id):
            raise ValueError("Session coordinate does not match its scope")
        _parse_revision(value["revision"])
        if kind == "cursor":
            _integer(value["offset"])
        else:
            _integer(value["rowId"], 2**63 - 1)
            digest = value["sha256"]
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("Invalid session content digest")
        return value

    @staticmethod
    def _append_count(db: Any, stored_id: str, previous: dict[str, int], current: dict[str, int]) -> int:
        if current == previous:
            return 0
        if current["rewind"] != previous["rewind"] or current["head"] <= previous["head"]:
            raise SessionStateResetRequired("Session history changed")
        # Bound catch-up work. Compaction archives old rows, so it cannot satisfy
        # the active-count equality even when its replacement rows have new IDs.
        # Hermes' public projection omits display_order. Inspect only these two
        # indexed coordinates, using the same SessionDB read connection helper;
        # leave all transcript selection/deduplication to get_messages below.
        rows = db._read_all(
            "SELECT id, display_order FROM messages WHERE session_id = ? AND active = 1 AND id > ? ORDER BY id LIMIT 257",
            (stored_id, previous["head"]),
        )
        if (len(rows) > 256 or not rows or rows[-1]["id"] != current["head"]
                or previous["count"] + len(rows) != current["count"]
                or any(row["display_order"] is None or row["display_order"] <= previous["head"] for row in rows)):
            raise SessionStateResetRequired("Session history needs reconciliation")
        return len(rows)

    def read(self, db: Any, *, agent_id: str, stored_id: str,
             cursor: dict[str, Any] | None = None) -> dict[str, Any]:
        _scope(agent_id, 96)
        _scope(stored_id, 160)
        if cursor is not None:
            self._coordinate(cursor, agent_id=agent_id, stored_id=stored_id, kind="cursor")
        # Exact stored IDs only. The caller may use Hermes' official catalog to
        # resolve a visible chat alias before requesting this reader.
        if db.get_session(stored_id) is None:
            raise SessionStateResetRequired("Session is no longer available")
        ensure_index = getattr(db, "_ensure_display_order", None)
        for _ in range(3):
            resolved = db.resolve_resume_session_id(stored_id)
            if resolved != stored_id:
                if cursor is not None:
                    raise SessionStateResetRequired("Session continuation moved")
                stored_id = resolved
            if not callable(ensure_index) or not ensure_index(stored_id):
                # Hermes' legacy read-only fallback scans the entire transcript.
                # Require its indexed display reader instead of silently taking it.
                raise SessionStateUnavailable("Hermes display history index is not ready")
            before = _revision(db, stored_id)
            offset = 0 if cursor is None else cursor["offset"] + self._append_count(db, stored_id, cursor["revision"], before)
            rows = db.get_messages(stored_id, latest=True, offset=offset,
                                   limit=self.maximum_rows + 1, include_compacted=True)
            after = _revision(db, stored_id)
            if before != after or db.resolve_resume_session_id(stored_id) != stored_id:
                continue
            result: dict[str, Any] = {"version": 1, "storedId": stored_id, "agentId": agent_id,
                                      "revision": after, "messages": []}
            selected: list[dict[str, Any]] = []
            consumed = 0
            # Reserve space for a continuation even on a full page. Each row is
            # serialized once; no repeated serialization of a growing transcript.
            used = len(_json(result)) + 1_024
            for row in reversed(rows[-self.maximum_rows:]):
                if row.get("role") not in {"user", "assistant", "tool"}:
                    consumed += 1
                    continue
                message = _message(row)
                encoded = _json(message)
                if len(encoded) > self.maximum_row_bytes:
                    reference = {"version": 1, "storedId": stored_id, "agentId": agent_id,
                                 "revision": after, "rowId": int(row["id"]),
                                 "sha256": hashlib.sha256(encoded).hexdigest()}
                    content = message["content"]
                    preview = (content if isinstance(content, str) else json.dumps(content, ensure_ascii=False))
                    message = {"id": message["id"], "row_id": message["row_id"], "role": message["role"],
                               "content": preview.encode("utf-8")[:512].decode("utf-8", errors="ignore"),
                               "contentComplete": False, "contentReference": reference}
                    encoded = _json(message)
                    while len(encoded) > self.maximum_row_bytes and message["content"]:
                        message["content"] = message["content"][:len(message["content"]) // 2]
                        encoded = _json(message)
                    for key in ("tool_call_id", "tool_name", "timestamp", "display_kind"):
                        value = row.get(key)
                        if value is not None and len(_json(value)) <= 200:
                            candidate = {**message, key: value}
                            if len(_json(candidate)) <= self.maximum_row_bytes:
                                message = candidate
                    encoded = _json(message)
                if used + len(encoded) + 1 > self.maximum_bytes:
                    break
                used += len(encoded) + 1
                selected.append(message)
                consumed += 1
            result["messages"] = list(reversed(selected))
            if consumed < len(rows):
                result["nextCursor"] = {"version": 1, "storedId": stored_id, "agentId": agent_id,
                                        "revision": after, "offset": offset + consumed}
            return result
        raise SessionStateResetRequired("Session changed during the snapshot")

    def content(self, db: Any, *, agent_id: str, stored_id: str,
                reference: dict[str, Any], offset: int = 0) -> dict[str, Any]:
        self._coordinate(reference, agent_id=agent_id, stored_id=stored_id, kind="content")
        _integer(offset, 2**63 - 1)
        current = _revision(db, stored_id)
        self._append_count(db, stored_id, reference["revision"], current)
        rows = db.get_messages_around(stored_id, reference["rowId"], window=0)["window"]
        if len(rows) != 1 or not (rows[0].get("active") or rows[0].get("compacted")):
            raise SessionStateResetRequired("Session content is no longer visible")
        encoded = _json(_message(rows[0]))
        if hashlib.sha256(encoded).hexdigest() != reference["sha256"] or current != _revision(db, stored_id):
            raise SessionStateResetRequired("Session content changed")
        if offset > len(encoded):
            raise ValueError("Invalid session content offset")
        try:
            # Ignore an incomplete trailing scalar only; its bytes remain at the
            # next offset. A caller-supplied offset inside a scalar is rejected.
            encoded[offset:].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Invalid session content offset") from exc
        text = encoded[offset:offset + 65_536].decode("utf-8", errors="ignore")
        end = offset + len(text.encode("utf-8"))
        result = {"text": text, "offset": offset, "sha256": reference["sha256"]}
        if end < len(encoded):
            result["nextOffset"] = end
        return result
