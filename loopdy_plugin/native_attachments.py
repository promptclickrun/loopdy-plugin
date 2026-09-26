"""Native agent-attachment resolution for Direct Loopdy clients.

Agents deliver files with ``MEDIA:<path>`` directives. Stock Hermes only lets a
phone read images below its media cache and files below ``terminal.cwd``, so a
PDF in ``~/Downloads`` or a video in a project folder used to render as raw
text. This route applies the gateway's own delivery policy
(``extract_media`` + ``validate_media_delivery_path``), the same one every
messaging platform uses, and adds a provenance bound: a path is served only
when an assistant message stored in the requested session (or its compaction
ancestors) actually emitted it. The phone never names a path directly; it
receives opaque attachment IDs and pulls bytes in bounded chunks.
"""
from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from starlette.concurrency import run_in_threadpool

from .native_context import NativeAPIError, NativeContext, PROFILE_ID, native_context

CAPABILITY = "native-agent-attachments-v1"
# The app's Media page: pictures and videos the agent sent or generated lately.
MEDIA_CAPABILITY = "native-agent-media-v1"
MAX_RECENT_MEDIA = 36
_RECENT_SCAN_ROWS = 400
_GENERATOR_TOOLS = ("image_generate", "video_generate")
MAX_ITEMS = 50
MAX_TEXT_BYTES = 100_000
MAX_LINEAGE = 16
# 3 MiB raw -> 4 MiB base64, inside the client's 4 MiB message response budget.
MAX_CHUNK_BYTES = 3 * 1024 * 1024 - 64 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

_store = None


class _Item(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    itemId: str = Field(min_length=1, max_length=200)
    text: str = Field(max_length=MAX_TEXT_BYTES)


class _Resolve(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    agentId: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    storedId: str = Field(min_length=1, max_length=180)
    items: list[_Item] = Field(min_length=1, max_length=MAX_ITEMS)


class _Fetch(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    agentId: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    attachmentId: str = Field(min_length=16, max_length=128)
    offset: StrictInt = Field(ge=0, le=25 * 1024 * 1024)


class _Recent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    agentId: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    limit: StrictInt = Field(ge=1, le=MAX_RECENT_MEDIA)


def available() -> bool:
    try:
        from gateway.platforms.base import BasePlatformAdapter  # noqa: F401
        from hermes_cli.profiles import get_profile_dir, profile_exists  # noqa: F401
    except ImportError:
        return False
    return True


def attachment_store():
    global _store
    if _store is None:
        from hermes_constants import get_process_hermes_home
        from .attachments import AttachmentStore
        _store = AttachmentStore(
            get_process_hermes_home() / "plugin-data" / "loopdy" / "agent-attachments.sqlite3"
        )
    return _store


def _state_db(profile: str) -> Path:
    from hermes_cli.profiles import get_profile_dir, profile_exists
    if not profile_exists(profile):
        raise NativeAPIError(404, "profile_not_found", "The selected profile no longer exists.")
    return get_profile_dir(profile) / "state.db"


def _session_lineage(connection: sqlite3.Connection, stored_id: str) -> list[str]:
    lineage: list[str] = []
    current: str | None = stored_id
    while current and current not in lineage and len(lineage) < MAX_LINEAGE:
        row = connection.execute(
            "SELECT id, parent_session_id FROM sessions WHERE id = ?", (current,)
        ).fetchone()
        if row is None:
            break
        lineage.append(row[0])
        current = row[1]
    return lineage


def emitted_by_session(db_path: Path, stored_id: str, raw_paths: list[str]) -> set[str]:
    """Return the raw paths that an assistant message in this session emitted."""
    if not raw_paths or not db_path.is_file():
        return set()
    uri = db_path.resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=5) as connection:
        lineage = _session_lineage(connection, stored_id)
        if not lineage:
            return set()
        marks = ",".join("?" for _ in lineage)
        found: set[str] = set()
        for path in raw_paths:
            row = connection.execute(
                f"SELECT 1 FROM messages WHERE session_id IN ({marks}) "
                "AND role = 'assistant' AND instr(content, ?) > 0 LIMIT 1",
                (*lineage, path),
            ).fetchone()
            if row is not None:
                found.add(path)
        return found


def _media_paths(text: str) -> list[str]:
    from gateway.platforms.base import BasePlatformAdapter
    media, _cleaned = BasePlatformAdapter.extract_media(text)
    paths: list[str] = []
    for raw, _voice in media:
        # Agents often write ``MEDIA://abs/path``; the gateway treats it as ``/abs/path``.
        path = _canonical(raw)
        if path not in paths:
            paths.append(path)
    return paths


def _canonical(path: str) -> str:
    return "/" + path.lstrip("/") if path.startswith("/") else path


def resolve(body: _Resolve) -> dict[str, Any]:
    db_path = _state_db(body.agentId)
    wanted = []
    for item in body.items:
        wanted.extend(p for p in _media_paths(item.text) if p not in wanted)
    allowed = emitted_by_session(db_path, body.storedId, wanted)
    store = attachment_store()
    projected = []
    for item in body.items:
        paths = [p for p in _media_paths(item.text) if p in allowed]
        if not paths:
            projected.append({"itemId": item.itemId, "text": item.text, "attachments": []})
            continue
        [result] = store.resolve(
            profile=body.agentId, session_id=body.storedId,
            items=[{"id": item.itemId, "text": _only(item.text, paths)}],
        )
        projected.append({
            "itemId": item.itemId,
            "text": result["text"] if result["attachments"] else item.text,
            "attachments": [
                {"id": a["id"], "fileName": a["name"], "mimeType": a["mime_type"], "byteCount": a["size"]}
                for a in result["attachments"]
            ],
        })
    return {"items": projected}


def _only(text: str, allowed: list[str]) -> str:
    """Neutralize MEDIA directives whose path failed provenance.

    ``AttachmentStore`` would otherwise resolve every policy-valid directive in
    the text, including ones the phone injected into its own copy.
    """
    from gateway.platforms.base import MEDIA_TAG_CLEANUP_RE, _normalize_media_tag_path
    import os

    def keep(match):
        path = _canonical(os.path.expanduser(_normalize_media_tag_path(match.group("path"))))
        return match.group(0) if path in allowed else match.group(0).replace("MEDIA:", "MEDIA\u200b:")

    return MEDIA_TAG_CLEANUP_RE.sub(keep, text)


def _is_media(path: str) -> bool:
    import mimetypes
    kind = mimetypes.guess_type(path)[0] or ""
    return kind.startswith("image/") or kind.startswith("video/")


def _generated_path(content: str | None) -> str | None:
    """The host-deliverable file a stock image or video tool reported."""
    try:
        value = json.loads(content or "")
    except (TypeError, ValueError):
        return None
    if not isinstance(value, dict) or value.get("success") is not True:
        return None
    for key in ("image", "video"):
        path = value.get(key)
        if isinstance(path, str) and path.startswith("/"):
            return path
    return None


def recent(body: _Recent) -> dict[str, Any]:
    """Newest pictures and videos this agent delivered (``MEDIA:``) or generated.

    Every path comes from the agent's own stored messages and goes through the
    same gateway delivery policy and attachment store as chat attachments, so
    the phone still only receives opaque IDs.
    """
    db_path = _state_db(body.agentId)
    if not db_path.is_file():
        return {"items": []}
    uri = db_path.resolve().as_uri() + "?mode=ro"
    marks = ",".join("?" for _ in _GENERATOR_TOOLS)
    with sqlite3.connect(uri, uri=True, timeout=5) as connection:
        delivered = connection.execute(
            "SELECT id, session_id, timestamp, content FROM messages WHERE role = 'assistant' "
            "AND instr(content, 'MEDIA:') > 0 ORDER BY timestamp DESC LIMIT ?", (_RECENT_SCAN_ROWS,)
        ).fetchall()
        generated = connection.execute(
            f"SELECT id, session_id, timestamp, content FROM messages WHERE role = 'tool' "
            f"AND tool_name IN ({marks}) ORDER BY timestamp DESC LIMIT ?", (*_GENERATOR_TOOLS, _RECENT_SCAN_ROWS)
        ).fetchall()
    candidates: list[tuple[float, int, str, str]] = []
    for row_id, session_id, timestamp, content in delivered:
        for path in _media_paths(content or ""):
            candidates.append((float(timestamp), int(row_id), str(session_id), path))
    for row_id, session_id, timestamp, content in generated:
        path = _generated_path(content)
        if path is not None:
            candidates.append((float(timestamp), int(row_id), str(session_id), path))
    candidates.sort(key=lambda row: (row[0], row[1]), reverse=True)
    store = attachment_store()
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for timestamp, row_id, session_id, path in candidates:
        if len(items) >= body.limit:
            break
        if path in seen or not _is_media(path):
            continue
        seen.add(path)
        try:
            [result] = store.resolve(
                profile=body.agentId, session_id=session_id,
                items=[{"id": f"media-{row_id}", "text": "MEDIA:" + path}],
            )
        except ValueError:
            continue
        for attachment in result["attachments"]:
            if not str(attachment["mime_type"]).startswith(("image/", "video/")):
                continue
            items.append({
                "id": attachment["id"], "fileName": attachment["name"], "mimeType": attachment["mime_type"],
                "byteCount": attachment["size"], "storedId": session_id, "createdAt": timestamp,
            })
    return {"items": items}


def fetch(body: _Fetch) -> dict[str, Any]:
    attachment = attachment_store().read(profile=body.agentId, attachment_id=body.attachmentId)
    if attachment is None:
        raise NativeAPIError(404, "attachment_unavailable", "The attachment is unavailable.")
    content = attachment["content"]
    if not isinstance(content, bytes) or body.offset >= len(content):
        raise NativeAPIError(404, "attachment_unavailable", "The attachment is unavailable.")
    chunk = content[body.offset: body.offset + MAX_CHUNK_BYTES]
    end = body.offset + len(chunk)
    return {
        "attachmentId": body.attachmentId,
        "offset": body.offset,
        "byteCount": len(content),
        "mimeType": attachment["mime_type"],
        "data": base64.b64encode(chunk).decode("ascii"),
        "nextOffset": end if end < len(content) else None,
    }


async def request(operation: str, http_request: Request, *, auth_module) -> Response:
    owner: NativeContext = native_context(http_request)
    request_id = auth_module._precondition(http_request, owner)
    if CAPABILITY not in owner.features:
        raise NativeAPIError(503, "attachments_unavailable", "Native attachments are unavailable.")
    model = {"resolve": _Resolve, "fetch": _Fetch, "recent": _Recent}.get(operation)
    if model is None:
        raise NativeAPIError(404, "unknown_operation", "The attachment operation is unknown.")
    body = await auth_module._body(http_request, model)
    if PROFILE_ID.fullmatch(body.agentId) is None:
        raise NativeAPIError(422, "invalid_request", "The profile is invalid.")
    if operation == "recent" and MEDIA_CAPABILITY not in owner.features:
        raise NativeAPIError(503, "media_unavailable", "Recent agent media is unavailable.")
    worker = {"resolve": resolve, "fetch": fetch, "recent": recent}[operation]
    try:
        result = await run_in_threadpool(worker, body)
    except (ValueError, sqlite3.Error):
        raise NativeAPIError(422, "invalid_request", "The attachment request is invalid.") from None
    if native_context(http_request) != owner:
        raise NativeAPIError(412, "context_changed", "The native context changed; refresh before retrying.")
    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise NativeAPIError(413, "payload_too_large", "The response exceeds the byte limit.")
    return Response(encoded, media_type="application/json", headers=auth_module._headers(owner, request_id))
