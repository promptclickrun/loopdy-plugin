"""Durable bounded upload admission on the Wiki service's single process lock.

The staging table lives in the same private database outside all Wiki roots.
No expiry/eviction removes unresolved drafts. A submitted upload without a save
journal is indeterminate; status never initiates or repeats a replacement.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from .wiki_contract import validate_payload, chunk_bytes
from .wiki_service import WikiService, WikiServiceError, _Reader, _markdown, _creation_revision, _request_digest, _sha

MAX_UPLOADS = 128
MAX_STAGED_BYTES = 32 * 1024 * 1024


class WikiUploads:
    def __init__(self, service: WikiService):
        self.service = service

    @staticmethod
    def _schema(connection):
        from .wiki_schema import SCHEMA_VERSION
        if connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
            raise WikiServiceError("STATE_UNAVAILABLE", "Wiki upload schema is unavailable")

    @staticmethod
    def _binding(row):
        values = tuple(row[k] for k in (
            "authority_id", "profile_id", "device_id", "wiki_id", "generation",
            "path", "base_revision", "total_bytes", "sha256",
        ))
        return _request_digest(values if row["owner_kind"] == "link_device"
                               else ("native_principal", row["principal_id"], *values))

    def _load(self, connection, operation_id, profile_id, device_id, *, write=False):
        row = connection.execute("SELECT * FROM wiki_uploads WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None or not self.service._matches_owner(row, profile_id, device_id):
            raise WikiServiceError("OPERATION_NOT_FOUND", "Save operation was not found")
        grant = self.service._authorize(connection, row["wiki_id"], profile_id, device_id, write=write)
        if grant["generation"] != row["generation"]:
            raise WikiServiceError("WIKI_NOT_ALLOWED", "Save belongs to an obsolete Wiki grant")
        if (self._binding(row) != row["binding"] or type(row["content"]) is not bytes
                or not 0 <= len(row["content"]) <= row["total_bytes"] <= 1024 * 1024):
            raise WikiServiceError("STATE_UNAVAILABLE", "Wiki upload integrity check failed")
        return row

    @staticmethod
    def _receiving(row):
        return {"operationId": row["operation_id"], "status": "receiving",
                "nextOffset": len(row["content"]), "totalBytes": row["total_bytes"]}

    def _outcome(self, connection, row):
        operation = self.service._operation(connection, row["operation_id"], row["profile_id"], row["device_id"])
        if operation is not None:
            expected = self.service._digest((row["authority_id"], row["profile_id"], row["device_id"],
                                        row["wiki_id"], row["generation"], row["path"],
                                        row["base_revision"], row["sha256"]))
            if operation["request_digest"] != expected:
                raise WikiServiceError("OPERATION_CONFLICT", "Save operation binding differs")
            return self.service._recover(connection, operation)
        if row["submitted"]:
            return self.service._outcome(row["operation_id"], "indeterminate", None, "SAVE_INTERRUPTED")
        return self._receiving(row)

    def begin(self, payload: dict, *, device_id: str | None) -> dict:
        p = validate_payload("wiki.save.begin", payload)
        profile = p["agentId"]
        with self.service._locked() as connection:
            self._schema(connection)
            grant = self.service._authorize(connection, p["wikiId"], profile, device_id, write=True)
            creating = _creation_revision(p["baseRevision"], grant["generation"])
            if Path(p["path"]).suffix.casefold() not in {".md", ".markdown"}:
                raise WikiServiceError("UNSUPPORTED_CONTENT", "Only Markdown files can be edited")
            binding = self.service._digest((self.service._authority_id, profile, device_id, p["wikiId"],
                                       grant["generation"], p["path"], p["baseRevision"], p["totalBytes"], p["sha256"]))
            existing = connection.execute("SELECT 1 FROM wiki_uploads WHERE operation_id=?", (p["operationId"],)).fetchone()
            if existing is not None:
                row = self._load(connection, p["operationId"], profile, device_id, write=True)
                if row["binding"] != binding:
                    raise WikiServiceError("OPERATION_CONFLICT", "operationId was already used for a different upload")
                # Begin's DTO stays receiving even after commit; status is authoritative.
                return self._receiving(row)
            if connection.execute("SELECT 1 FROM wiki_operations WHERE operation_id=?", (p["operationId"],)).fetchone():
                raise WikiServiceError("OPERATION_CONFLICT", "operationId was already used for a save")
            # Admission refuses inaccessible, oversized, ACL/xattr or non-plain files
            # before accepting a draft. A changed revision remains commit's conflict.
            reader = _Reader(self.service, connection, grant)
            root = reader._open_grant_root(reader._load_grant(p["wikiId"]))
            try:
                observed, _ = (self.service._creation_snapshot(reader, root, p["path"]) if creating
                               else self.service._snapshot(reader, root, p["path"]))
                _markdown(observed)
            finally:
                os.close(root)
            count, used = connection.execute("SELECT COUNT(*),COALESCE(SUM(total_bytes),0) FROM wiki_uploads").fetchone()
            if count >= MAX_UPLOADS or used + p["totalBytes"] > MAX_STAGED_BYTES:
                raise WikiServiceError("QUOTA_EXCEEDED", "Wiki upload storage requires host-local maintenance")
            self.service._revalidate(connection, grant)
            with connection:
                connection.execute(
                    "INSERT INTO wiki_uploads(operation_id,authority_id,profile_id,device_id,wiki_id,generation,"
                    "path,base_revision,total_bytes,sha256,binding,content,submitted,created_at,owner_kind,principal_id) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                    p["operationId"], self.service._authority_id, profile, device_id, p["wikiId"],
                    grant["generation"], p["path"], p["baseRevision"], p["totalBytes"], p["sha256"],
                    binding, b"", 0, time.time_ns(), self.service._owner_kind, self.service._principal_id,
                ))
            return self._receiving(self._load(connection, p["operationId"], profile, device_id))

    def chunk(self, payload: dict, *, device_id: str | None) -> dict:
        p = validate_payload("wiki.save.chunk", payload)
        data = chunk_bytes(p["data"])
        with self.service._locked() as connection:
            self._schema(connection)
            row = self._load(connection, p["operationId"], p["agentId"], device_id, write=True)
            content, offset = row["content"], p["offset"]
            end = offset + len(data)
            if offset < len(content) and end <= len(content) and content[offset:end] == data:
                return self._receiving(row)
            if row["submitted"] or offset != len(content) or end > row["total_bytes"]:
                raise WikiServiceError("OPERATION_CONFLICT", "Upload chunk does not match the next offset")
            with connection:
                connection.execute("UPDATE wiki_uploads SET content=? WHERE operation_id=?", (content + data, p["operationId"]))
            return self._receiving(self._load(connection, p["operationId"], p["agentId"], device_id))

    def status(self, payload: dict, *, device_id: str | None) -> dict:
        p = validate_payload("wiki.save.status", payload)
        with self.service._locked() as connection:
            self._schema(connection)
            row = self._load(connection, p["operationId"], p["agentId"], device_id)
            return self._outcome(connection, row)

    def commit(self, payload: dict, *, device_id: str | None) -> dict:
        p = validate_payload("wiki.save.commit", payload)
        with self.service._locked() as connection:
            self._schema(connection)
            row = self._load(connection, p["operationId"], p["agentId"], device_id, write=True)
            outcome = self._outcome(connection, row)
            if outcome["status"] != "receiving":
                return outcome
            if len(row["content"]) != row["total_bytes"]:
                raise WikiServiceError("UPLOAD_INCOMPLETE", "Upload is not complete")
            if _sha(row["content"]) != row["sha256"]:
                raise WikiServiceError("DIGEST_MISMATCH", "Upload content digest differs")
            _markdown(row["content"])
            self.service.check_owner()
            # Persist before calling save: a crash in the admission gap must never
            # cause a later commit/status request to perform a surprise replacement.
            with connection:
                connection.execute("UPDATE wiki_uploads SET submitted=1 WHERE operation_id=?", (p["operationId"],))
            return self.service._save_file_locked(
                connection, row["wiki_id"], profile_id=p["agentId"], device_id=device_id,
                path=row["path"], base_revision=row["base_revision"], content=row["content"],
                operation_id=p["operationId"],
            )
