"""Policy-backed, durable outgoing attachments for Loopdy chat history."""

from __future__ import annotations

import hashlib
import mimetypes
import os
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any, Iterable

from gateway.platforms.base import BasePlatformAdapter

from .link_contracts import MAX_AGENT_ATTACHMENT_BYTES


MAX_ITEMS = 200
MAX_TEXT_BYTES = 100_000
MAX_ATTACHMENTS_PER_ITEM = 20
MAX_ARTIFACT_BYTES = MAX_AGENT_ATTACHMENT_BYTES
MAX_FILENAME_BYTES = 240
MAX_CACHE_BYTES_PER_PROFILE = 250 * 1024 * 1024
MAX_CACHE_ITEMS_PER_PROFILE = 500
IMAGE_MIME_PREFIX = "image/"


class _OversizedAttachment(Exception):
    def __init__(self, mime_type: str):
        self.mime_type = mime_type
        super().__init__("Attachment exceeds the agent media size limit")


class AttachmentStore:
    """Resolve Hermes media directives into opaque, profile-scoped blobs."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._initialize()

    def resolve(
        self,
        *,
        profile: str,
        session_id: str,
        items: Iterable[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        safe_profile = _bounded_identifier(profile, 80, "profile")
        safe_session = _bounded_identifier(session_id, 180, "session_id")
        bounded_items = list(items)
        if len(bounded_items) > MAX_ITEMS:
            raise ValueError(f"items may contain at most {MAX_ITEMS} entries")

        total_text_bytes = 0
        resolved_items: list[dict[str, Any]] = []
        for item in bounded_items:
            item_id = _bounded_identifier(item.get("id"), 180, "item id")
            text = item.get("text")
            if not isinstance(text, str):
                raise ValueError("item text must be a string")
            total_text_bytes += len(text.encode("utf-8"))
            if total_text_bytes > MAX_TEXT_BYTES:
                raise ValueError(f"item text may contain at most {MAX_TEXT_BYTES} bytes")
            resolved_items.append(
                self._resolve_item(
                    profile=safe_profile,
                    session_id=safe_session,
                    item_id=item_id,
                    text=text,
                )
            )
        return resolved_items

    def read(self, *, profile: str, attachment_id: str) -> dict[str, Any] | None:
        safe_profile = _bounded_identifier(profile, 80, "profile")
        if not isinstance(attachment_id, str) or not _is_attachment_id(attachment_id):
            return None
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT name, mime_type, size, content
                FROM agent_attachments
                WHERE profile = ? AND attachment_id = ?
                """,
                (safe_profile, attachment_id),
            ).fetchone()
        if row is None:
            return None
        return {
            "id": attachment_id,
            "name": row[0],
            "mime_type": row[1],
            "size": row[2],
            "content": row[3],
        }

    def _resolve_item(
        self,
        *,
        profile: str,
        session_id: str,
        item_id: str,
        text: str,
    ) -> dict[str, Any]:
        text_digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        cached = self._cached_item(profile, session_id, item_id, text_digest)
        if cached is not None:
            return cached

        media, cleaned = BasePlatformAdapter.extract_media(text)
        validated_media = [
            (safe_path, is_voice)
            for path, is_voice in media
            if (safe_path := BasePlatformAdapter.validate_media_delivery_path(path))
        ]
        safe_media = BasePlatformAdapter.filter_media_delivery_paths(validated_media)
        local_files, cleaned = BasePlatformAdapter.extract_local_files(cleaned)
        validated_local_files = [
            safe_path
            for path in local_files
            if (safe_path := BasePlatformAdapter.validate_media_delivery_path(path))
        ]
        safe_local_files = BasePlatformAdapter.filter_local_delivery_paths(validated_local_files)

        paths: list[str] = []
        seen: set[str] = set()
        for path, _is_voice in safe_media:
            if path not in seen:
                seen.add(path)
                paths.append(path)
        for path in safe_local_files:
            if path not in seen:
                seen.add(path)
                paths.append(path)

        attachments = []
        oversized_mime_types = []
        for source_path in paths[:MAX_ATTACHMENTS_PER_ITEM]:
            try:
                attachment = self._cache_file(profile, session_id, item_id, source_path)
            except _OversizedAttachment as error:
                oversized_mime_types.append(error.mime_type)
                continue
            if attachment is not None:
                attachments.append(attachment)

        display_text = _remove_unresolved_directive_lines(
            BasePlatformAdapter.strip_media_directives_for_display(cleaned)
        )
        result = {"id": item_id, "text": display_text, "attachments": attachments}
        if oversized_mime_types:
            # Internal diagnostics only; workspace projections never expose local paths.
            result["oversized_mime_types"] = oversized_mime_types
        if attachments:
            self._cache_item(profile, session_id, item_id, text_digest, display_text, attachments)
        return result

    def _cache_file(
        self,
        profile: str,
        session_id: str,
        item_id: str,
        source_path: str,
    ) -> dict[str, Any] | None:
        source_key = hashlib.sha256(
            "\0".join((profile, session_id, item_id, source_path)).encode("utf-8")
        ).hexdigest()
        with self._connect() as connection:
            existing = connection.execute(
                """
                SELECT attachment_id, name, mime_type, size
                FROM agent_attachments
                WHERE profile = ? AND source_key = ?
                """,
                (profile, source_key),
            ).fetchone()
        if existing is not None:
            with self._lock, self._connect() as connection:
                self._enforce_profile_limits(connection, profile)
                existing = connection.execute(
                    """
                    SELECT attachment_id, name, mime_type, size
                    FROM agent_attachments
                    WHERE profile = ? AND source_key = ?
                    """,
                    (profile, source_key),
                ).fetchone()
            if existing is not None:
                return _public_attachment(*existing)

        try:
            path = Path(source_path)
            size = path.stat().st_size
            if size > MAX_ARTIFACT_BYTES:
                mime_type = mimetypes.guess_type(_safe_filename(path.name))[0] or "application/octet-stream"
                raise _OversizedAttachment(mime_type)
            if size < 0:
                return None
            with path.open("rb") as source:
                content = source.read(MAX_ARTIFACT_BYTES + 1)
        except OSError:
            return None
        if len(content) != size or len(content) > MAX_ARTIFACT_BYTES:
            return None

        name = _safe_filename(path.name)
        mime_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        attachment_id = uuid.uuid4().hex
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO agent_attachments (
                    attachment_id, profile, session_id, item_id, source_key,
                    name, mime_type, size, content
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attachment_id,
                    profile,
                    session_id,
                    item_id,
                    source_key,
                    name,
                    mime_type,
                    size,
                    content,
                ),
            )
            self._enforce_profile_limits(connection, profile)
            row = connection.execute(
                """
                SELECT attachment_id, name, mime_type, size
                FROM agent_attachments
                WHERE profile = ? AND source_key = ?
                """,
                (profile, source_key),
            ).fetchone()
        return _public_attachment(*row) if row is not None else None

    def _enforce_profile_limits(
        self,
        connection: sqlite3.Connection,
        profile: str,
    ) -> None:
        while True:
            count, total_bytes = connection.execute(
                """
                SELECT COUNT(*), COALESCE(SUM(size), 0)
                FROM agent_attachments
                WHERE profile = ?
                """,
                (profile,),
            ).fetchone()
            if (
                count <= MAX_CACHE_ITEMS_PER_PROFILE
                and total_bytes <= MAX_CACHE_BYTES_PER_PROFILE
            ):
                return
            victim = connection.execute(
                """
                SELECT attachment_id
                FROM agent_attachments
                WHERE profile = ?
                ORDER BY created_at ASC, rowid ASC
                LIMIT 1
                """,
                (profile,),
            ).fetchone()
            if victim is None:
                return
            affected_messages = connection.execute(
                """
                SELECT DISTINCT session_id, item_id
                FROM agent_attachment_message_items
                WHERE profile = ? AND attachment_id = ?
                """,
                (profile, victim[0]),
            ).fetchall()
            for session_id, item_id in affected_messages:
                connection.execute(
                    """
                    DELETE FROM agent_attachment_message_items
                    WHERE profile = ? AND session_id = ? AND item_id = ?
                    """,
                    (profile, session_id, item_id),
                )
                connection.execute(
                    """
                    DELETE FROM agent_attachment_messages
                    WHERE profile = ? AND session_id = ? AND item_id = ?
                    """,
                    (profile, session_id, item_id),
                )
            connection.execute(
                """
                DELETE FROM agent_attachments
                WHERE profile = ? AND attachment_id = ?
                """,
                (profile, victim[0]),
            )

    def _cached_item(
        self,
        profile: str,
        session_id: str,
        item_id: str,
        text_digest: str,
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT display_text
                FROM agent_attachment_messages
                WHERE profile = ? AND session_id = ? AND item_id = ? AND text_digest = ?
                """,
                (profile, session_id, item_id, text_digest),
            ).fetchone()
            if row is None:
                return None
            attachments = connection.execute(
                """
                SELECT a.attachment_id, a.name, a.mime_type, a.size
                FROM agent_attachment_message_items AS m
                JOIN agent_attachments AS a
                  ON a.profile = m.profile AND a.attachment_id = m.attachment_id
                WHERE m.profile = ? AND m.session_id = ? AND m.item_id = ?
                ORDER BY m.position
                """,
                (profile, session_id, item_id),
            ).fetchall()
        return {
            "id": item_id,
            "text": row[0],
            "attachments": [_public_attachment(*attachment) for attachment in attachments],
        }

    def _cache_item(
        self,
        profile: str,
        session_id: str,
        item_id: str,
        text_digest: str,
        display_text: str,
        attachments: list[dict[str, Any]],
    ) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO agent_attachment_messages (
                    profile, session_id, item_id, text_digest, display_text
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(profile, session_id, item_id) DO UPDATE SET
                    text_digest = excluded.text_digest,
                    display_text = excluded.display_text
                """,
                (profile, session_id, item_id, text_digest, display_text),
            )
            connection.execute(
                """
                DELETE FROM agent_attachment_message_items
                WHERE profile = ? AND session_id = ? AND item_id = ?
                """,
                (profile, session_id, item_id),
            )
            connection.executemany(
                """
                INSERT INTO agent_attachment_message_items (
                    profile, session_id, item_id, position, attachment_id
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (profile, session_id, item_id, position, value["id"])
                    for position, value in enumerate(attachments)
                ],
            )

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS agent_attachments (
                    attachment_id TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    source_key TEXT NOT NULL,
                    name TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content BLOB NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (profile, attachment_id),
                    UNIQUE (profile, source_key)
                );
                CREATE TABLE IF NOT EXISTS agent_attachment_messages (
                    profile TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    text_digest TEXT NOT NULL,
                    display_text TEXT NOT NULL,
                    PRIMARY KEY (profile, session_id, item_id)
                );
                CREATE TABLE IF NOT EXISTS agent_attachment_message_items (
                    profile TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    attachment_id TEXT NOT NULL,
                    PRIMARY KEY (profile, session_id, item_id, position)
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection


def _public_attachment(
    attachment_id: str,
    name: str,
    mime_type: str,
    size: int,
) -> dict[str, Any]:
    return {
        "id": attachment_id,
        "kind": "image" if mime_type.startswith(IMAGE_MIME_PREFIX) else "file",
        "name": name,
        "mime_type": mime_type,
        "size": size,
    }


def _bounded_identifier(value: Any, maximum: int, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized.encode("utf-8")) > maximum:
        raise ValueError(f"{label} is invalid")
    return normalized


def _safe_filename(value: str) -> str:
    name = "".join(
        character if 32 <= ord(character) != 127 else "_"
        for character in os.path.basename(value)
    ).strip(" .")
    if not name:
        name = "attachment"
    encoded = name.encode("utf-8")
    if len(encoded) <= MAX_FILENAME_BYTES:
        return name
    suffix = Path(name).suffix.encode("utf-8")[:32].decode("utf-8", "ignore")
    budget = MAX_FILENAME_BYTES - len(suffix.encode("utf-8"))
    stem = Path(name).stem.encode("utf-8")[:budget].decode("utf-8", "ignore")
    return f"{stem}{suffix}" or "attachment"


def _is_attachment_id(value: str) -> bool:
    return len(value) == 32 and all(character in "0123456789abcdef" for character in value)


def _remove_unresolved_directive_lines(value: str) -> str:
    lines = [line for line in value.splitlines() if "media:" not in line.lower()]
    return "\n".join(lines).strip()


__all__ = [
    "AttachmentStore",
    "MAX_ARTIFACT_BYTES",
    "MAX_ATTACHMENTS_PER_ITEM",
    "MAX_CACHE_BYTES_PER_PROFILE",
    "MAX_CACHE_ITEMS_PER_PROFILE",
    "MAX_ITEMS",
    "MAX_TEXT_BYTES",
]
