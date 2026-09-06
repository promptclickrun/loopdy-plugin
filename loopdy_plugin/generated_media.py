"""Exact-coordinate generated media projection for Loopdy Link.

The client never supplies a path or URL. Resolution starts from a real stored
Hermes tool result, then reuses the existing platform delivery policy and
profile-scoped attachment cache.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from hermes_constants import get_hermes_home  # type: ignore[import-not-found]

from .link_contracts import MAX_AGENT_ATTACHMENT_BYTES


CANONICAL_GENERATION_TOOLS = {
    "image_generate": "image",
    "video_generate": "video",
    "xai_video_edit": "video",
    "xai_video_extend": "video",
}
MAX_GENERATED_ARTIFACTS = 8
MAX_GENERATED_TOTAL_BYTES = 32 * 1024 * 1024
MAX_NATIVE_ARTIFACT_BYTES = MAX_AGENT_ATTACHMENT_BYTES


def effective_generation_kind(tool_name: Any, arguments: Any) -> str | None:
    if isinstance(tool_name, str) and tool_name in CANONICAL_GENERATION_TOOLS:
        return CANONICAL_GENERATION_TOOLS[tool_name]
    if tool_name != "tool_call":
        return None
    values = arguments
    if isinstance(values, str):
        try:
            values = json.loads(values)
        except (TypeError, json.JSONDecodeError):
            return None
    if not isinstance(values, dict):
        return None
    inner_name = values.get("name")
    return CANONICAL_GENERATION_TOOLS.get(inner_name) if isinstance(inner_name, str) else None


def record_generated_media_call(
    *,
    profile: str,
    stored_id: str,
    turn_id: str,
    tool_call_id: str,
    tool_name: str,
    arguments: Any,
    link_session_id: str | None = None,
) -> None:
    """Persist only identity; media bytes still come from stored history."""

    profile = "default" if profile == "hermes" else profile
    kind = effective_generation_kind(tool_name, arguments)
    if kind is None:
        return
    external_turn = _external_turn_id(link_session_id or stored_id, turn_id)
    path = _ledger_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=2) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS generated_media_calls (
                profile TEXT NOT NULL,
                stored_id TEXT NOT NULL,
                turn_id TEXT NOT NULL,
                tool_call_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (profile, stored_id, turn_id, tool_call_id)
            )
            """
        )
        connection.execute(
            """
            INSERT INTO generated_media_calls
                (profile, stored_id, turn_id, tool_call_id, kind, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(profile, stored_id, turn_id, tool_call_id) DO UPDATE SET
                kind = excluded.kind,
                created_at = excluded.created_at
            """,
            (profile, stored_id, external_turn, tool_call_id, kind, int(time.time())),
        )
        connection.execute(
            """
            DELETE FROM generated_media_calls
            WHERE rowid IN (
                SELECT rowid FROM generated_media_calls
                ORDER BY created_at DESC, rowid DESC
                LIMIT -1 OFFSET 512
            )
            """
        )


def resolve_generated_media(
    *,
    profile: str,
    stored_id: str,
    turn_id: str,
    tool_call_id: str,
    rows: list[dict[str, Any]],
    attachment_store: Any,
) -> dict[str, Any]:
    request, result, history_turn = _exact_tool_result(rows, tool_call_id)
    kind = effective_generation_kind(request["name"], request["arguments"])
    if kind is None or not _turn_matches(
        profile=profile,
        stored_id=stored_id,
        requested_turn=turn_id,
        history_turn=history_turn,
        tool_call_id=tool_call_id,
        kind=kind,
    ):
        return _response(stored_id, turn_id, tool_call_id, "unavailable")

    # The tool call was proven unique in this stored session before reaching the
    # cache. Live and hydrated turn IDs are different projections of that call.
    item_id = "generated_" + hashlib.sha256(
        "\0".join((stored_id, tool_call_id)).encode("utf-8")
    ).hexdigest()[:32]
    resolved = attachment_store.resolve(
        profile=profile,
        session_id=stored_id,
        items=[{"id": item_id, "text": result}],
    )
    raw_attachments = resolved[0]["attachments"] if resolved else []
    accepted: list[dict[str, Any]] = []
    total = 0
    oversized_types = resolved[0].get("oversized_mime_types", []) if resolved else []
    omitted = sum(
        1 for mime_type in oversized_types
        if isinstance(mime_type, str) and mime_type.startswith(kind + "/")
    )
    has_oversized_artifact = omitted > 0
    for attachment in raw_attachments:
        size = attachment.get("size")
        mime_type = attachment.get("mime_type")
        media_matches = (
            isinstance(mime_type, str)
            and (
                (kind == "image" and mime_type.startswith("image/"))
                or (kind == "video" and mime_type.startswith("video/"))
            )
        )
        if (
            not media_matches
            or not isinstance(size, int)
            or size <= 0
            or size > MAX_NATIVE_ARTIFACT_BYTES
            or len(accepted) >= MAX_GENERATED_ARTIFACTS
            or total + size > MAX_GENERATED_TOTAL_BYTES
        ):
            if media_matches and isinstance(size, int) and size > MAX_NATIVE_ARTIFACT_BYTES:
                has_oversized_artifact = True
            omitted += 1
            continue
        total += size
        accepted.append(
            {
                "id": attachment["id"],
                "fileName": attachment["name"],
                "mimeType": mime_type,
                "byteCount": size,
            }
        )
    if accepted:
        return _response(
            stored_id,
            turn_id,
            tool_call_id,
            "ready",
            attachments=accepted,
            omitted_count=omitted,
        )
    state = "oversized" if has_oversized_artifact else "unavailable"
    return _response(stored_id, turn_id, tool_call_id, state, omitted_count=omitted)


def _exact_tool_result(
    rows: list[dict[str, Any]], tool_call_id: str
) -> tuple[dict[str, Any], str, str]:
    requests: list[tuple[dict[str, Any], str]] = []
    results: list[str] = []
    current_turn: str | None = None
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        row_id = row.get("id", index + 1)
        row_coordinate = str(row_id)
        if row.get("role") == "user" or current_turn is None:
            current_turn = f"history-turn-{row_coordinate}"
        for call in _tool_calls(row.get("tool_calls")):
            if call["id"] == tool_call_id:
                requests.append((call, current_turn))
        if row.get("role") == "tool" and row.get("tool_call_id") == tool_call_id:
            content = row.get("content")
            if isinstance(content, str):
                results.append(content)
    if len(requests) != 1 or len(results) != 1:
        raise ValueError("Generated media tool coordinate is unavailable")
    return requests[0][0], results[0], requests[0][1]


def _tool_calls(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return []
    if not isinstance(value, list) or len(value) > 64:
        return []
    calls: list[dict[str, Any]] = []
    for raw in value:
        if not isinstance(raw, dict):
            continue
        raw_function = raw.get("function")
        function: dict[str, Any] = raw_function if isinstance(raw_function, dict) else {}
        call_id = raw.get("id") or raw.get("call_id") or raw.get("tool_call_id")
        name = raw.get("name") or function.get("name")
        arguments = raw.get("arguments", function.get("arguments"))
        if isinstance(call_id, str) and isinstance(name, str):
            calls.append({"id": call_id, "name": name, "arguments": arguments})
    return calls


def _turn_matches(
    *,
    profile: str,
    stored_id: str,
    requested_turn: str,
    history_turn: str,
    tool_call_id: str,
    kind: str,
) -> bool:
    if requested_turn == history_turn:
        return True
    path = _ledger_path()
    if not path.exists():
        return False
    with sqlite3.connect(path, timeout=2) as connection:
        try:
            row = connection.execute(
                """
                SELECT kind FROM generated_media_calls
                WHERE profile = ? AND stored_id = ? AND turn_id = ? AND tool_call_id = ?
                """,
                (profile, stored_id, requested_turn, tool_call_id),
            ).fetchone()
        except sqlite3.OperationalError:
            return False
    return row is not None and row[0] == kind


def _response(
    stored_id: str,
    turn_id: str,
    tool_call_id: str,
    state: str,
    *,
    attachments: list[dict[str, Any]] | None = None,
    omitted_count: int = 0,
) -> dict[str, Any]:
    return {
        "storedId": stored_id,
        "turnId": turn_id,
        "toolCallId": tool_call_id,
        "state": state,
        "omittedCount": omitted_count,
        "attachments": attachments or [],
    }


def _external_turn_id(stored_id: str, turn_id: str) -> str:
    digest = hashlib.sha256(f"{stored_id}\x1f{turn_id}".encode("utf-8")).digest()[:18]
    import base64

    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"turn_{encoded}"


def _ledger_path() -> Path:
    return get_hermes_home() / "plugin-data" / "loopdy" / "generated-media.sqlite3"
