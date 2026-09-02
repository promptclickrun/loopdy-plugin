"""Bounded, restart-safe inbound attachment assembly for Loopdy Link."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Iterable

from .link_contracts import (
    MAX_ATTACHMENT_CHUNK_BYTES,
    AttachmentChunk,
    AttachmentReference,
)


_SAFE_EXTENSION = re.compile(r"^\.[A-Za-z0-9]{1,10}$")
_STALE_SECONDS = 24 * 60 * 60


class LinkAttachmentInbox:
    """Assembles authenticated chunks without using sender-controlled paths."""

    def __init__(self, root: Path):
        self.root = Path(root).expanduser().resolve()
        self.partial_root = self.root / "partial"
        self.ready_root = self.root / "ready"
        self._purge_stale()

    def accept(self, *, sender_device_id: str, chunk: AttachmentChunk) -> None:
        # Account/device lifecycle cleanup can remove the bounded inbox while
        # this long-lived Link client is still running. Re-establish its
        # private directories before accepting a replayed durable frame so one
        # missing cache directory cannot poison the shared transport.
        if chunk.index == 0:
            self._purge_stale()
        else:
            self._ensure_roots()
        key = self._partial_key(sender_device_id, chunk.upload_id)
        partial = self.partial_root / f"{key}.part"
        manifest_path = self.partial_root / f"{key}.json"
        ready = self._ready_path(
            sender_device_id=sender_device_id,
            session_id=chunk.session_id,
            agent_id=chunk.agent_id,
            reference=chunk.reference,
        )
        if ready.is_file():
            self._verify_ready(ready, chunk.reference)
            return

        expected_manifest = self._manifest_value(sender_device_id, chunk)
        next_index = 0
        if manifest_path.is_file():
            try:
                stored = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError("Loopdy Link attachment manifest is invalid") from exc
            next_index = stored.pop("nextIndex", None)
            if stored != expected_manifest or not isinstance(next_index, int):
                raise ValueError("Loopdy Link attachment metadata changed during upload")
        if next_index not in {chunk.index, chunk.index + 1}:
            raise ValueError("Loopdy Link attachment chunks are out of order")

        expected_offset = chunk.index * MAX_ATTACHMENT_CHUNK_BYTES
        size = partial.stat().st_size if partial.is_file() else 0
        if next_index == chunk.index:
            if size == expected_offset:
                with partial.open("ab") as stream:
                    stream.write(chunk.data)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    partial.chmod(0o600)
                except OSError:
                    pass
            elif size == expected_offset + len(chunk.data):
                with partial.open("rb") as stream:
                    stream.seek(expected_offset)
                    if stream.read() != chunk.data:
                        raise ValueError("Loopdy Link attachment replay does not match")
            else:
                raise ValueError("Loopdy Link attachment size is invalid")
            next_index = chunk.index + 1

        if chunk.index + 1 < chunk.count:
            self._write_manifest(
                manifest_path,
                {**expected_manifest, "nextIndex": next_index},
            )
            return

        self._verify_ready(partial, chunk.reference)
        ready.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.replace(partial, ready)
        manifest_path.unlink(missing_ok=True)

    def resolve(
        self,
        *,
        sender_device_id: str,
        session_id: str,
        agent_id: str,
        references: Iterable[AttachmentReference],
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        self._ensure_roots()
        paths: list[str] = []
        mime_types: list[str] = []
        for reference in references:
            path = self._ready_path(
                sender_device_id=sender_device_id,
                session_id=session_id,
                agent_id=agent_id,
                reference=reference,
            )
            self._verify_ready(path, reference)
            paths.append(str(path))
            mime_types.append(reference.mime_type)
        return tuple(paths), tuple(mime_types)

    def discard(self, paths: Iterable[str]) -> None:
        for raw_path in paths:
            path = Path(raw_path).resolve()
            if path.parent == self.ready_root:
                path.unlink(missing_ok=True)

    @staticmethod
    def _partial_key(sender_device_id: str, upload_id: str) -> str:
        return hashlib.sha256(
            f"{sender_device_id}\0{upload_id}".encode("utf-8")
        ).hexdigest()

    def _ready_path(
        self,
        *,
        sender_device_id: str,
        session_id: str,
        agent_id: str,
        reference: AttachmentReference,
    ) -> Path:
        key = hashlib.sha256(
            (
                f"{sender_device_id}\0{session_id}\0{agent_id}\0"
                f"{reference.attachment_id}\0{reference.sha256}"
            ).encode("utf-8")
        ).hexdigest()
        extension = Path(reference.file_name).suffix
        if not _SAFE_EXTENSION.fullmatch(extension):
            extension = ".bin"
        return self.ready_root / f"{key}{extension.lower()}"

    @staticmethod
    def _manifest_value(sender_device_id: str, chunk: AttachmentChunk) -> dict[str, object]:
        reference = chunk.reference
        return {
            "senderDeviceId": sender_device_id,
            "uploadId": chunk.upload_id,
            "sessionId": chunk.session_id,
            "agentId": chunk.agent_id,
            "attachmentId": reference.attachment_id,
            "fileName": reference.file_name,
            "mimeType": reference.mime_type,
            "totalBytes": reference.total_bytes,
            "sha256": reference.sha256,
            "count": chunk.count,
        }

    @staticmethod
    def _write_manifest(path: Path, value: dict[str, object]) -> None:
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        os.replace(temporary, path)

    @staticmethod
    def _verify_ready(path: Path, reference: AttachmentReference) -> None:
        if not path.is_file() or path.stat().st_size != reference.total_bytes:
            raise ValueError("Loopdy Link attachment is incomplete")
        digest = hashlib.sha256(path.read_bytes()).digest()
        encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        if encoded != reference.sha256:
            raise ValueError("Loopdy Link attachment digest does not match")

    def _purge_stale(self) -> None:
        self._ensure_roots()
        cutoff = time.time() - _STALE_SECONDS
        for root in (self.partial_root, self.ready_root):
            for path in root.iterdir():
                try:
                    if path.is_file() and path.stat().st_mtime < cutoff:
                        path.unlink(missing_ok=True)
                except OSError:
                    continue

    def _ensure_roots(self) -> None:
        self.partial_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.ready_root.mkdir(parents=True, exist_ok=True, mode=0o700)


__all__ = ["LinkAttachmentInbox"]
