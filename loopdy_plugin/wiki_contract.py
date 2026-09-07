"""Finite Wiki v1 schemas; validation never grants authority or touches disk."""
from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

from .workspace_files import (
    WorkspaceFilesError, WorkspaceFilesService, _valid_relative_path,
    _valid_workspace_id, _valid_query,
)

WIKI_OPERATIONS = frozenset({
    "wiki.roots", "wiki.resolve", "wiki.connect", "wiki.list", "wiki.read", "wiki.search",
    "wiki.image", "wiki.save.begin", "wiki.save.chunk", "wiki.save.commit", "wiki.save.status",
})
REVISION = re.compile(r"wiki-v1:[0-9a-f]{32}:[0-9a-f]{64}\Z")
OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
MAX_PAYLOAD_BYTES = 120_000  # Reserve JSON, capability metadata and AES/base64 expansion.


def available_wiki_operations() -> frozenset[str]:
    """Advertise Wiki only where descriptor-relative traversal is enforceable."""
    try:
        WorkspaceFilesService._require_secure_platform()
    except WorkspaceFilesError:
        return frozenset()
    return WIKI_OPERATIONS


def _invalid() -> ValueError:
    return ValueError("Wiki request is invalid")


def integer(value: Any, maximum: int, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _invalid()
    return value


def chunk_bytes(value: Any) -> bytes:
    if not isinstance(value, str) or not 1 <= len(value) <= 87_384:
        raise _invalid()
    try:
        content = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise _invalid() from None
    if not 1 <= len(content) <= 65_536 or base64.b64encode(content).decode("ascii") != value:
        raise _invalid()
    return content


def exact_folder(value: Any) -> str:
    if (not isinstance(value, str) or not value.startswith("/") or value == "/"
            or len(value.encode("utf-8")) > 4096 or "\\" in value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(p in {"", ".", ".."} for p in value.split("/")[1:])):
        raise _invalid()
    return value


def validate_payload(operation: str, value: Any) -> dict:
    fields = {
        "wiki.roots": set(), "wiki.resolve": {"folderPath"}, "wiki.connect": {"folderPath"},
        "wiki.list": {"wikiId", "path", "offset", "limit", "query"},
        "wiki.read": {"wikiId", "path", "offset", "limit"},
        "wiki.image": {"wikiId", "path", "offset", "limit"},
        "wiki.search": {"wikiId", "query", "mode", "offset", "limit"},
        "wiki.save.begin": {"wikiId", "path", "baseRevision", "operationId", "totalBytes", "sha256"},
        "wiki.save.chunk": {"operationId", "offset", "data"},
        "wiki.save.commit": {"operationId"}, "wiki.save.status": {"operationId"},
    }
    if operation not in fields or not isinstance(value, dict):
        raise _invalid()
    required = fields[operation] | {"agentId"}
    optional = {"revision"} if operation in {"wiki.list", "wiki.read", "wiki.image"} else set()
    if not required <= value.keys() or not value.keys() <= required | optional:
        raise _invalid()
    if (not isinstance(value["agentId"], str)
            or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value["agentId"]) is None):
        raise _invalid()
    try:
        if "wikiId" in value:
            _valid_workspace_id(value["wikiId"])
        if "path" in value:
            _valid_relative_path(value["path"], allow_root=operation == "wiki.list")
        if "query" in value:
            _valid_query(value["query"])
        if "folderPath" in value:
            exact_folder(value["folderPath"])
        for field in ("revision", "baseRevision"):
            if field in value and (value[field] is not None or field == "baseRevision"):
                token = value[field]
                creation = (operation == "wiki.save.begin" and field == "baseRevision"
                            and isinstance(token, str)
                            and re.fullmatch(r"wiki-new-v1:[0-9a-f]{32}", token) is not None)
                if not creation and (not isinstance(token, str) or REVISION.fullmatch(token) is None):
                    raise _invalid()
        if "operationId" in value:
            if not isinstance(value["operationId"], str) or OPERATION_ID.fullmatch(value["operationId"]) is None:
                raise _invalid()
        if "offset" in value:
            integer(value["offset"], 8 * 1024 * 1024)
        if "limit" in value:
            integer(value["limit"], 100 if operation in {"wiki.list", "wiki.search"} else 65_536, 1)
        if "mode" in value and value["mode"] not in ("name", "content"):
            raise _invalid()
        if "totalBytes" in value:
            integer(value["totalBytes"], 1024 * 1024)
            if not isinstance(value["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None:
                raise _invalid()
        if "data" in value:
            chunk_bytes(value["data"])
        if len(json.dumps(value, ensure_ascii=True, allow_nan=False).encode("ascii")) > MAX_PAYLOAD_BYTES:
            raise _invalid()
    except (WorkspaceFilesError, UnicodeError, TypeError):
        raise _invalid() from None
    return dict(value)


def bounded_result(value: dict) -> dict:
    """Keep authoritative file bytes; shorten only explicitly paginated lists."""
    result = dict(value)
    text = result.get("text")
    if isinstance(text, str) and any(ord(c) < 32 and c not in "\n\r\t" for c in text):
        result["text"] = None
    def size():
        return len(json.dumps(result, ensure_ascii=True, allow_nan=False).encode("ascii"))
    if size() > MAX_PAYLOAD_BYTES and "text" in result:
        result["text"] = None
    if "entries" in result:
        result["entries"] = list(result["entries"])
        while size() > MAX_PAYLOAD_BYTES and len(result["entries"]) > 1:
            result["entries"].pop()
            result["nextOffset"] = result["offset"] + len(result["entries"])
    if size() > MAX_PAYLOAD_BYTES:
        raise ValueError("Wiki response exceeds the transfer limit")
    return result
