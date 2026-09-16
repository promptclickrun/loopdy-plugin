"""Profile-derived, workspace-local agent templates for native Loopdy."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import stat
import time
import unicodedata
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Literal, TypeVar
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, StrictBool, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from .native_context import NativeAPIError, NativeContext, PROFILE_ID, native_context
from .sensitive import contains_sensitive_credential


try:
    import fcntl
except ImportError:  # Windows has no process-safe flock equivalent.
    fcntl = None


logger = logging.getLogger(__name__)
CAPABILITY = "native-agent-templates-v1"
SCHEMA_VERSION = 1
MAX_BODY_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 1_048_576
MAX_SKILLS = 128
MAX_SKILL_BYTES = 100_000
MAX_TEMPLATE_BYTES = 1_000_000
MAX_TEMPLATES = 256
_TEMPLATE_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_REVISION = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ENV_REFERENCE = re.compile(r"\$\{(?:env:)?[A-Za-z_][A-Za-z0-9_]*\}\Z")
_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}\Z")
_BodyT = TypeVar("_BodyT", bound=BaseModel)


class AgentTemplateError(Exception):
    def __init__(self, status: int, code: str, message: str, *, retryable: bool = False):
        self.status, self.code, self.message, self.retryable = status, code, message, retryable
        super().__init__(message)


class _TemplateRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def guarded(request: Request) -> Response:
            try:
                return await handler(request)
            except (NativeAPIError, AgentTemplateError) as error:
                logger.warning("Loopdy agent-template request rejected: %s", error.code)
                return _error_response(error, request)
            except ClientDisconnect:
                return _error_response(
                    AgentTemplateError(400, "request_disconnected", "The request was disconnected."),
                    request,
                )
            except Exception:
                # Profile configuration, skill readers, and filesystem exceptions can
                # carry private paths or values. Never reflect or log their details.
                logger.error("Loopdy agent-template request failed: template_service_unavailable")
                return _error_response(
                    AgentTemplateError(
                        503,
                        "template_service_unavailable",
                        "Agent templates are unavailable on this host.",
                        retryable=True,
                    ),
                    request,
                )

        return guarded


router = APIRouter(prefix="/native/agent-templates", route_class=_TemplateRoute)


class _StrictBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _OwnerBody(_StrictBody):
    agentId: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")


class _TemplateBody(_OwnerBody):
    templateId: str = Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class _SaveBody(_OwnerBody):
    template: dict[str, Any]
    expectedRevision: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")


class _Skill(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(min_length=1, max_length=160)
    enabled: StrictBool
    content: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class _MCPServer(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=160)
    transport: Literal["stdio", "http", "sse", "unknown"]
    url: str | None = Field(default=None, max_length=4_096)
    command: str | None = Field(default=None, max_length=2_048)
    arguments: list[str] = Field(default_factory=list, max_length=128)
    auth: str | None = Field(default=None, max_length=32)
    enabled: StrictBool
    environmentKeys: list[str] = Field(default_factory=list, max_length=64)
    headerNames: list[str] = Field(default_factory=list, max_length=64)
    tools: list[str] = Field(default_factory=list, max_length=2_048)


class _Toolset(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(min_length=1, max_length=160)
    name: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=8_192)
    platform: str = Field(min_length=1, max_length=80)
    enabled: StrictBool
    tools: list[str] = Field(default_factory=list, max_length=2_048)


class _Source(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    profileId: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    snapshotRevision: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    derivedAt: int = Field(ge=1, le=9_999_999_999)


class _Document(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schemaVersion: Literal[1]
    id: str = Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    title: str = Field(min_length=1, max_length=120)
    source: _Source
    soul: str = Field(max_length=256_000)
    skills: list[_Skill] = Field(max_length=MAX_SKILLS)
    mcpServers: list[_MCPServer] = Field(max_length=256)
    tools: list[_Toolset] = Field(max_length=512)
    config: dict[str, Any]
    omissions: list[str] = Field(default_factory=list, max_length=256)


_SAFE_CONFIG_FIELDS: dict[str, set[str] | None] = {
    "_config_version": None,
    "model": None,
    "model_context_length": None,
    "reasoning_effort": None,
    "timezone": None,
    "agent": {"max_turns", "tool_use_enforcement", "reasoning_effort"},
    "compression": {"enabled", "threshold", "target_ratio"},
    "display": {"skin", "language", "personality", "show_reasoning", "show_cost", "tool_progress"},
    "delegation": {"model", "provider", "reasoning_effort", "max_iterations", "max_concurrent"},
    "cron": {"model", "model_provider"},
    "memory": {"memory_enabled", "user_profile_enabled", "provider"},
    "terminal": {"backend", "timeout", "home_mode"},
    "approvals": {"mode"},
    "privacy": {"redact_pii"},
    "security": {"tirith_enabled", "website_blocklist", "redact_secrets"},
    "checkpoints": {"enabled", "max_snapshots"},
}
_SECRET_KEY = re.compile(r"(?:api.?key|token|secret|password|credential|authorization|cookie|headers?|cert|private.?key|env)", re.I)


def available() -> bool:
    if fcntl is None or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        return False
    try:
        from hermes_cli.config import read_user_config_raw
        from hermes_cli.profiles import get_profile_dir, profile_exists
    except ImportError:
        return False
    return all(callable(value) for value in (
        read_user_config_raw, get_profile_dir,
        profile_exists,
    ))


def capability() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "feature": CAPABILITY,
        "available": available(),
        "folder": ".loopdy/agent-templates/<profile-id>",
        "operations": ["list", "derive", "read", "save"],
        "maximum_template_bytes": MAX_TEMPLATE_BYTES,
        "source_profile_mutation": False,
    }


def _error_response(error: NativeAPIError | AgentTemplateError, request: Request) -> JSONResponse:
    request_id = request.headers.get("x-loopdy-request-id", "")
    headers = {"Cache-Control": "no-store"}
    if len(request.headers.getlist("x-loopdy-request-id")) == 1 and _TEMPLATE_ID.fullmatch(request_id):
        headers["X-Loopdy-Request-ID"] = request_id
    retryable = getattr(error, "retryable", False) or error.status == 503
    return JSONResponse(
        status_code=error.status,
        content={"error": {"code": error.code, "message": error.message, "retryable": retryable, "details": {}}},
        headers=headers,
    )


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _invalid_number(_value):
    raise ValueError("Non-finite JSON number")


async def _body(request: Request, model: type[_BodyT]) -> _BodyT:
    if request.query_params:
        raise AgentTemplateError(422, "invalid_request", "Query fields are not supported.")
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise AgentTemplateError(422, "invalid_request", "A JSON request is required.")
    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > MAX_BODY_BYTES:
            raise AgentTemplateError(413, "payload_too_large", "The request exceeds the byte limit.")
        content.extend(chunk)
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_invalid_number)
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 24:
                raise ValueError("JSON nesting limit")
            if isinstance(item, dict):
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
        return model.model_validate(value)
    except (ValueError, UnicodeError, RecursionError, ValidationError):
        raise AgentTemplateError(422, "invalid_request", "The agent-template request is invalid.") from None


def _precondition(request: Request, context: NativeContext) -> str:
    if request.headers.get("if-match") is None:
        raise AgentTemplateError(428, "context_required", "Load native context before this request.")
    if len(request.headers.getlist("if-match")) != 1 or request.headers["if-match"] != context.etag:
        raise AgentTemplateError(412, "context_changed", "The native context changed; refresh before retrying.")
    request_id = request.headers.get("x-loopdy-request-id", "")
    if len(request.headers.getlist("x-loopdy-request-id")) != 1 or _TEMPLATE_ID.fullmatch(request_id) is None:
        raise AgentTemplateError(422, "invalid_request", "A canonical request ID is required.")
    return request_id


def _response(value: dict[str, Any], context: NativeContext, request_id: str) -> Response:
    encoded = _canonical(value)
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise AgentTemplateError(413, "payload_too_large", "The response exceeds the byte limit.")
    return Response(
        encoded,
        media_type="application/json",
        headers={"Cache-Control": "no-store", "ETag": context.etag, "X-Loopdy-Request-ID": request_id},
    )


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, maximum: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value) or len(value.encode("utf-8")) > maximum:
        raise AgentTemplateError(422, "invalid_template", "The template contains invalid text.")
    if value != unicodedata.normalize("NFC", value) or any(
        unicodedata.category(character).startswith("C") and character not in "\n\r\t" for character in value
    ):
        raise AgentTemplateError(422, "invalid_template", "The template contains unsupported text.")
    return value


def _identifier(value: Any, maximum: int = 256) -> str:
    value = _text(value, maximum)
    if _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise AgentTemplateError(422, "invalid_template", "The template contains an invalid identifier.")
    return value


def _secret_free(value: str) -> str:
    if contains_sensitive_credential(value):
        raise AgentTemplateError(422, "secret_scan_blocked", "Template content requires host-local credential review.")
    return value


def _safe_url(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = _secret_free(_text(value, 4_096))
    parsed = urlsplit(text)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise AgentTemplateError(422, "unsafe_mcp_configuration", "An MCP URL cannot be represented without credentials.")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _safe_argument(value: Any, maximum: int = 4_096) -> str:
    text = _text(value, maximum)
    if _ENV_REFERENCE.fullmatch(text):
        return text
    return _secret_free(text)


def _json_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 8:
        raise AgentTemplateError(422, "invalid_template", "The safe config projection is too deeply nested.")
    if value is None or type(value) in {bool, int, float}:
        if isinstance(value, float) and not (-1_000_000 <= value <= 1_000_000):
            raise AgentTemplateError(422, "invalid_template", "The safe config projection is invalid.")
        return value
    if isinstance(value, str):
        return _secret_free(_text(value, 8_192, allow_empty=True))
    if isinstance(value, list):
        if len(value) > 256:
            raise AgentTemplateError(413, "payload_too_large", "The safe config projection is too large.")
        return [_json_value(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > 256:
            raise AgentTemplateError(413, "payload_too_large", "The safe config projection is too large.")
        result = {}
        for raw_key, item in value.items():
            key = _identifier(raw_key, 128)
            if _SECRET_KEY.search(key):
                raise AgentTemplateError(422, "secret_scan_blocked", "Credential fields cannot be saved in templates.")
            result[key] = _json_value(item, depth=depth + 1)
        return result
    raise AgentTemplateError(422, "invalid_template", "The safe config projection contains an unsupported value.")


def _safe_config(raw: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    result: dict[str, Any] = {}
    omissions: list[str] = []
    for key, fields in _SAFE_CONFIG_FIELDS.items():
        if key not in raw:
            continue
        value = raw[key]
        if fields is None:
            try:
                result[key] = _json_value(value)
            except AgentTemplateError:
                omissions.append(f"config:{key}")
            continue
        if not isinstance(value, dict):
            omissions.append(f"config:{key}")
            continue
        section = {}
        for field in sorted(fields):
            if field not in value:
                continue
            try:
                section[field] = _json_value(value[field])
            except AgentTemplateError:
                omissions.append(f"config:{key}.{field}")
        if section:
            result[key] = section
    return result, omissions


def _workspace_and_config(agent_id: str) -> tuple[Path, dict[str, Any]]:
    from hermes_cli.config import read_user_config_raw
    from hermes_cli.profiles import get_profile_dir, profile_exists

    if not profile_exists(agent_id):
        raise AgentTemplateError(404, "profile_not_found", "The selected profile no longer exists.")
    try:
        # Exact raw read: no defaults merge, environment expansion, migration,
        # parse-failure backup, or source-profile write.
        raw = read_user_config_raw(get_profile_dir(agent_id) / "config.yaml")
    except (OSError, UnicodeError, ValueError, TypeError):
        raise AgentTemplateError(409, "profile_config_invalid", "The selected profile configuration must be repaired locally.") from None
    terminal = raw.get("terminal")
    cwd = terminal.get("cwd") if isinstance(terminal, dict) else None
    if not isinstance(cwd, str) or not cwd.strip() or cwd.strip() in {".", "auto", "cwd"}:
        raise AgentTemplateError(
            409,
            "workspace_not_configured",
            "Set an absolute terminal.cwd for this profile before using agent templates.",
        )
    try:
        candidate = Path(cwd).expanduser()
    except (OSError, RuntimeError, ValueError):
        raise AgentTemplateError(409, "workspace_not_configured", "The selected profile requires an absolute terminal.cwd.") from None
    if not candidate.is_absolute():
        raise AgentTemplateError(409, "workspace_not_configured", "The selected profile requires an absolute terminal.cwd.")
    try:
        root = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        raise AgentTemplateError(409, "workspace_unavailable", "The selected profile workspace is unavailable.") from None
    if not root.is_dir():
        raise AgentTemplateError(409, "workspace_unavailable", "The selected profile workspace is unavailable.")
    # This comparison proves the public profile helper still resolves the same
    # profile while the separately configured workspace remains its own boundary.
    if get_profile_dir(agent_id).name == "" or PROFILE_ID.fullmatch(agent_id) is None:
        raise AgentTemplateError(404, "profile_not_found", "The selected profile no longer exists.")
    return root, raw


@contextmanager
def _template_directory(agent_id: str, *, create: bool) -> Iterator[int]:
    root, _ = _workspace_and_config(agent_id)
    required = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise AgentTemplateError(501, "secure_traversal_unavailable", "Secure template storage is unavailable on this host.")
    descriptors: list[int] = []
    try:
        try:
            descriptors.append(os.open(root, required))
        except OSError:
            raise AgentTemplateError(409, "workspace_unavailable", "The selected profile workspace is unavailable.") from None
        parent = descriptors[-1]
        for index, component in enumerate((".loopdy", "agent-templates", agent_id)):
            created = False
            if create:
                try:
                    os.mkdir(component, 0o700, dir_fd=parent)
                    created = True
                except FileExistsError:
                    pass
            try:
                descriptor = os.open(component, required, dir_fd=parent)
            except FileNotFoundError:
                raise AgentTemplateError(404, "template_not_found", "No saved templates were found for this profile.") from None
            except OSError:
                raise AgentTemplateError(409, "storage_conflict", "The template folder requires host-local review.") from None
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                raise AgentTemplateError(409, "storage_conflict", "The template folder requires host-local review.")
            # Do not alter a pre-existing workspace-wide .loopdy directory;
            # only this feature's private descendants are ours to harden.
            if created or index > 0:
                try:
                    os.fchmod(descriptor, 0o700)
                except OSError:
                    pass
            descriptors.append(descriptor)
            parent = descriptor
        yield descriptors[-1]
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


@contextmanager
def _locked(directory: int, *, exclusive: bool) -> Iterator[None]:
    if fcntl is None:
        raise AgentTemplateError(501, "secure_traversal_unavailable", "Secure template storage is unavailable on this host.")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(".lock", flags, 0o600, dir_fd=directory)
    except OSError:
        raise AgentTemplateError(409, "storage_conflict", "The template folder requires host-local review.") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AgentTemplateError(409, "storage_conflict", "The template folder requires host-local review.")
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _read_file(directory: int, template_id: str) -> tuple[dict[str, Any], str]:
    name = template_id + ".json"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory)
    except FileNotFoundError:
        raise AgentTemplateError(404, "template_not_found", "The selected template no longer exists.") from None
    except OSError:
        raise AgentTemplateError(409, "storage_conflict", "The template file requires host-local review.") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_TEMPLATE_BYTES:
            raise AgentTemplateError(409, "storage_conflict", "The template file requires host-local review.")
        chunks = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1_024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) != info.st_size:
            raise AgentTemplateError(409, "template_changed", "The template changed while it was being read.")
    finally:
        os.close(descriptor)
    try:
        raw = json.loads(content.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_invalid_number)
    except (ValueError, UnicodeError, RecursionError):
        raise AgentTemplateError(409, "storage_conflict", "The template file requires host-local review.") from None
    document = _normalize_document(raw)
    canonical = _canonical(document)
    if not hmac.compare_digest(content, canonical):
        raise AgentTemplateError(409, "storage_conflict", "The template file is not in canonical form.")
    return document, _digest(document)


def _write_file(directory: int, document: dict[str, Any], expected_revision: str | None) -> tuple[dict[str, Any], str]:
    name = document["id"] + ".json"
    exists = True
    try:
        current, revision = _read_file(directory, document["id"])
    except AgentTemplateError as error:
        if error.code != "template_not_found":
            raise
        current, revision, exists = None, None, False
    if exists:
        if expected_revision is None or revision is None or not hmac.compare_digest(expected_revision, revision):
            raise AgentTemplateError(409, "template_conflict", "The template changed. Reopen it before saving.")
        if current is not None and current["source"] != document["source"]:
            raise AgentTemplateError(409, "template_conflict", "Template provenance cannot be changed.")
    elif expected_revision is not None:
        raise AgentTemplateError(409, "template_conflict", "The selected template no longer exists.")
    encoded = _canonical(document)
    if len(encoded) > MAX_TEMPLATE_BYTES:
        raise AgentTemplateError(413, "payload_too_large", "The template exceeds the byte limit.")
    temporary = ".tmp-" + uuid.uuid4().hex
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
    except OSError:
        raise AgentTemplateError(409, "storage_conflict", "The template folder requires host-local review.") from None
    try:
        try:
            written = 0
            while written < len(encoded):
                count = os.write(descriptor, encoded[written:])
                if count <= 0:
                    raise OSError("Template write made no progress")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
    readback, revision = _read_file(directory, document["id"])
    if readback != document:
        raise AgentTemplateError(409, "template_changed", "The saved template did not match exact readback.")
    return readback, revision


def _normalize_document(raw: Any, *, expected_agent: str | None = None) -> dict[str, Any]:
    try:
        model = _Document.model_validate(raw)
    except ValidationError:
        raise AgentTemplateError(422, "invalid_template", "The template document is invalid.") from None
    document = model.model_dump()
    document["title"] = _secret_free(_text(document["title"], 120))
    source = document["source"]
    if expected_agent is not None and source["profileId"] != expected_agent:
        raise AgentTemplateError(422, "profile_mismatch", "The template belongs to another profile workspace.")
    if _TEMPLATE_ID.fullmatch(document["id"]) is None or _REVISION.fullmatch(source["snapshotRevision"]) is None:
        raise AgentTemplateError(422, "invalid_template", "The template identity is invalid.")
    seen_skills = set()
    for skill in document["skills"]:
        skill["id"] = _identifier(skill["id"], 160)
        skill["content"] = _secret_free(_text(skill["content"], MAX_SKILL_BYTES))
        actual = hashlib.sha256(skill["content"].encode("utf-8")).hexdigest()
        if not hmac.compare_digest(actual, skill["sha256"]) or skill["id"] in seen_skills:
            raise AgentTemplateError(422, "invalid_template", "The skill template content is invalid.")
        seen_skills.add(skill["id"])
    seen_mcp = set()
    for server in document["mcpServers"]:
        server["name"] = _identifier(server["name"], 160)
        if server["name"] in seen_mcp:
            raise AgentTemplateError(422, "invalid_template", "The MCP template contains duplicate servers.")
        seen_mcp.add(server["name"])
        server["url"] = _safe_url(server["url"])
        server["command"] = None if server["command"] is None else _safe_argument(server["command"], 2_048)
        server["arguments"] = [_safe_argument(item) for item in server["arguments"]]
        server["environmentKeys"] = sorted({_identifier(item, 128) for item in server["environmentKeys"]})
        server["headerNames"] = sorted({_identifier(item, 128) for item in server["headerNames"]})
        server["tools"] = sorted({_identifier(item) for item in server["tools"]})
    seen_tools = set()
    for tool in document["tools"]:
        tool["id"] = _identifier(tool["id"], 160)
        if tool["id"] in seen_tools:
            raise AgentTemplateError(422, "invalid_template", "The tool template contains duplicate toolsets.")
        seen_tools.add(tool["id"])
        tool["name"] = _secret_free(_text(tool["name"], 256))
        tool["description"] = _secret_free(_text(tool["description"], 8_192, allow_empty=True))
        tool["platform"] = _identifier(tool["platform"], 80)
        tool["tools"] = sorted({_identifier(item) for item in tool["tools"]})
    document["soul"] = _secret_free(_text(document["soul"], 256_000, allow_empty=True))
    if not set(document["config"]).issubset(_SAFE_CONFIG_FIELDS):
        raise AgentTemplateError(422, "invalid_template", "The config template contains unsupported fields.")
    config, config_omissions = _safe_config(document["config"])
    if config_omissions:
        raise AgentTemplateError(422, "invalid_template", "The config template contains unsupported fields.")
    document["config"] = config
    document["omissions"] = sorted({_identifier(item, 256) for item in document["omissions"]})
    # The typed source revision is a validated SHA-256 digest, not free-form
    # content. Scanning its literal "sha256:<hex>" label as a credential rejects
    # every generated template. Keep scanning every editable field unchanged.
    scan_document = {**document, "source": {**source, "snapshotRevision": None}}
    if contains_sensitive_credential(_canonical(scan_document).decode("utf-8")):
        raise AgentTemplateError(422, "secret_scan_blocked", "Template content requires host-local credential review.")
    if len(_canonical(document)) > MAX_TEMPLATE_BYTES:
        raise AgentTemplateError(413, "payload_too_large", "The template exceeds the byte limit.")
    return document


def _profile_skills(profile_home: Path, raw_config: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    root = profile_home / "skills"
    if not root.exists():
        return [], []
    if root.is_symlink() or not root.is_dir():
        raise AgentTemplateError(409, "source_projection_unavailable", "The profile skill folder requires host-local review.")
    skills_config = raw_config.get("skills")
    raw_disabled = skills_config.get("disabled", []) if isinstance(skills_config, dict) else []
    disabled = {item for item in raw_disabled if isinstance(item, str)}
    skills: list[dict[str, Any]] = []
    omissions: list[str] = []
    visited = 0
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        visited += 1
        if visited > 1_024:
            raise AgentTemplateError(413, "catalog_too_large", "The profile skill catalog exceeds the scan limit.")
        current = Path(directory)
        safe_directories = []
        for name in sorted(directory_names):
            child = current / name
            if name.startswith(".") or child.is_symlink():
                continue
            safe_directories.append(name)
        directory_names[:] = safe_directories
        if "SKILL.md" not in file_names:
            continue
        relative = current.relative_to(root).as_posix()
        if relative == ".":
            raise AgentTemplateError(409, "source_projection_unavailable", "The profile skill folder is invalid.")
        skill_id = _identifier(relative, 160)
        path = current / "SKILL.md"
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            omissions.append("skill:" + skill_id)
            continue
        if info.st_size > MAX_SKILL_BYTES:
            raise AgentTemplateError(413, "catalog_too_large", "A profile skill exceeds the template limit.")
        try:
            content = path.read_text(encoding="utf-8")
            content = _secret_free(_text(content, MAX_SKILL_BYTES))
        except AgentTemplateError as error:
            if error.code != "secret_scan_blocked":
                raise
            omissions.append("skill:" + skill_id)
            continue
        except (OSError, UnicodeError):
            raise AgentTemplateError(409, "source_projection_unavailable", "A profile skill could not be read safely.") from None
        skills.append({
            "id": skill_id,
            "enabled": skill_id not in disabled and current.name not in disabled,
            "content": content,
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        })
        if len(skills) > MAX_SKILLS:
            raise AgentTemplateError(413, "catalog_too_large", "The profile skill catalog exceeds the template limit.")
    return sorted(skills, key=lambda item: item["id"]), omissions


def _profile_mcp(raw_config: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    source = raw_config.get("mcp_servers")
    if source in (None, {}):
        return [], []
    if not isinstance(source, dict) or len(source) > 256:
        raise AgentTemplateError(409, "source_projection_unavailable", "The profile MCP configuration is invalid.")
    servers: list[dict[str, Any]] = []
    omissions: list[str] = []
    for raw_name in sorted(source):
        name = _identifier(raw_name, 160)
        config = source[raw_name]
        if not isinstance(config, dict):
            raise AgentTemplateError(409, "source_projection_unavailable", "The profile MCP configuration is invalid.")
        environment = config.get("env") if isinstance(config.get("env"), dict) else {}
        headers = config.get("headers") if isinstance(config.get("headers"), dict) else {}
        raw_tools_config = config.get("tools")
        tools_config: dict[str, Any] = raw_tools_config if isinstance(raw_tools_config, dict) else {}
        raw_included = tools_config.get("include")
        included: list[Any] = raw_included if isinstance(raw_included, list) else []
        if tools_config.get("exclude"):
            omissions.append("mcp:" + name + ":excluded-tools")
        transport = "http" if config.get("url") else "stdio" if config.get("command") else "unknown"
        try:
            servers.append({
                "name": name,
                "transport": transport,
                "url": _safe_url(config.get("url")),
                "command": None if config.get("command") in (None, "") else _safe_argument(config.get("command"), 2_048),
                "arguments": [_safe_argument(item) for item in config.get("args", [])]
                if isinstance(config.get("args"), list) else [],
                "auth": None if config.get("auth") in (None, "") else _identifier(config.get("auth"), 32),
                "enabled": config.get("enabled") is not False,
                "environmentKeys": sorted(_identifier(key, 128) for key in environment),
                "headerNames": sorted(_identifier(key, 128) for key in headers),
                "tools": sorted(_identifier(item) for item in included),
            })
        except AgentTemplateError as error:
            if error.code not in {"secret_scan_blocked", "unsafe_mcp_configuration"}:
                raise
            omissions.append("mcp:" + name)
    return servers, omissions


def _profile_tools(raw_config: dict[str, Any]) -> list[dict[str, Any]]:
    configured: list[tuple[str, str]] = []
    platforms = raw_config.get("platform_toolsets")
    if isinstance(platforms, dict):
        for raw_platform, values in sorted(platforms.items()):
            platform = _identifier(raw_platform, 80)
            if not isinstance(values, list) or len(values) > 512:
                raise AgentTemplateError(409, "source_projection_unavailable", "The profile toolset configuration is invalid.")
            configured.extend((platform, _identifier(item, 160)) for item in values)
    legacy = raw_config.get("toolsets")
    if isinstance(legacy, list):
        if len(legacy) > 512:
            raise AgentTemplateError(413, "catalog_too_large", "The profile toolset catalog exceeds the template limit.")
        configured.extend(("cli", _identifier(item, 160)) for item in legacy)
    configured = sorted(set(configured))
    if len(configured) > 512:
        raise AgentTemplateError(413, "catalog_too_large", "The profile toolset catalog exceeds the template limit.")
    return [{
        "id": platform + ":" + name,
        "name": name,
        "description": "",
        "platform": platform,
        "enabled": True,
        "tools": [],
    } for platform, name in configured]


def _derive(agent_id: str, template_id: str) -> dict[str, Any]:
    from hermes_cli.profiles import get_profile_dir, profile_exists

    if not profile_exists(agent_id):
        raise AgentTemplateError(404, "profile_not_found", "The selected profile no longer exists.")
    _, raw_config = _workspace_and_config(agent_id)
    profile_home = get_profile_dir(agent_id)
    skills, skill_omissions = _profile_skills(profile_home, raw_config)
    mcp_servers, mcp_omissions = _profile_mcp(raw_config)
    tools = _profile_tools(raw_config)
    soul_path = profile_home / "SOUL.md"
    try:
        if soul_path.exists():
            info = soul_path.lstat()
            if soul_path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 256_000:
                raise AgentTemplateError(409, "source_projection_unavailable", "The profile SOUL requires host-local review.")
            soul = soul_path.read_text(encoding="utf-8")
        else:
            soul = ""
    except AgentTemplateError:
        raise
    except (OSError, UnicodeError):
        raise AgentTemplateError(503, "source_projection_unavailable", "The profile SOUL could not be read safely.") from None
    soul = _secret_free(_text(soul, 256_000, allow_empty=True))
    config, config_omissions = _safe_config(raw_config)
    omissions = skill_omissions + mcp_omissions + config_omissions
    snapshot = {
        "soul": soul,
        "skills": skills,
        "mcpServers": mcp_servers,
        "tools": tools,
        "config": config,
    }
    document = {
        "schemaVersion": SCHEMA_VERSION,
        "id": template_id,
        "title": "Untitled agent template",
        "source": {
            "profileId": agent_id,
            "snapshotRevision": _digest(snapshot),
            "derivedAt": int(time.time()),
        },
        **snapshot,
        "omissions": sorted(set(omissions)),
    }
    return _normalize_document(document, expected_agent=agent_id)


def _catalog(agent_id: str) -> dict[str, Any]:
    try:
        with _template_directory(agent_id, create=False) as directory, _locked(directory, exclusive=False):
            names = sorted(name for name in os.listdir(directory) if _TEMPLATE_ID.fullmatch(name.removesuffix(".json")) and name.endswith(".json"))
            if len(names) > MAX_TEMPLATES:
                raise AgentTemplateError(413, "catalog_too_large", "The template catalog exceeds the row limit.")
            templates = []
            for name in names:
                document, revision = _read_file(directory, name[:-5])
                if document["source"]["profileId"] != agent_id:
                    raise AgentTemplateError(409, "storage_conflict", "The template folder requires host-local review.")
                templates.append({
                    "id": document["id"],
                    "title": document["title"],
                    "revision": revision,
                    "derivedAt": document["source"]["derivedAt"],
                    "omissionCount": len(document["omissions"]),
                })
    except AgentTemplateError as error:
        if error.code == "template_not_found":
            templates = []
        else:
            raise
    return {"agentId": agent_id, "templates": templates, "storageFolder": f".loopdy/agent-templates/{agent_id}"}


def _read(agent_id: str, template_id: str) -> dict[str, Any]:
    with _template_directory(agent_id, create=False) as directory, _locked(directory, exclusive=False):
        document, revision = _read_file(directory, template_id)
    if document["source"]["profileId"] != agent_id:
        raise AgentTemplateError(409, "profile_mismatch", "The template belongs to another profile workspace.")
    return {
        "agentId": agent_id,
        "template": document,
        "revision": revision,
        "storageFolder": f".loopdy/agent-templates/{agent_id}",
    }


def _save(agent_id: str, raw: dict[str, Any], expected_revision: str | None) -> dict[str, Any]:
    document = _normalize_document(raw, expected_agent=agent_id)
    with _template_directory(agent_id, create=True) as directory, _locked(directory, exclusive=True):
        saved, revision = _write_file(directory, document, expected_revision)
    return {
        "agentId": agent_id,
        "template": saved,
        "revision": revision,
        "storageFolder": f".loopdy/agent-templates/{agent_id}",
    }


async def _request(request: Request, model: type[_BodyT], operation: str) -> Response:
    owner = native_context(request)
    request_id = _precondition(request, owner)
    if not available():
        raise AgentTemplateError(501, "templates_unavailable", "This Hermes host cannot safely project agent templates.")
    body = await _body(request, model)
    if not isinstance(body, _OwnerBody):
        raise AgentTemplateError(422, "invalid_request", "The agent-template operation is invalid.")
    if PROFILE_ID.fullmatch(body.agentId) is None:
        raise AgentTemplateError(422, "invalid_request", "The profile is invalid.")
    if native_context(request) != owner:
        raise AgentTemplateError(412, "context_changed", "The native context changed; refresh before retrying.")
    if operation == "derive" and isinstance(body, _TemplateBody):
        result = {
            "agentId": body.agentId,
            "template": await run_in_threadpool(_derive, body.agentId, body.templateId),
            "revision": None,
        }
    elif operation == "list":
        result = await run_in_threadpool(_catalog, body.agentId)
    elif operation == "read" and isinstance(body, _TemplateBody):
        result = await run_in_threadpool(_read, body.agentId, body.templateId)
    elif operation == "save" and isinstance(body, _SaveBody):
        result = await run_in_threadpool(_save, body.agentId, body.template, body.expectedRevision)
    else:
        raise AgentTemplateError(422, "invalid_request", "The agent-template operation is invalid.")
    if native_context(request) != owner:
        raise AgentTemplateError(
            412,
            "context_changed",
            "The native context changed; reconcile the template before retrying.",
        )
    return _response(result, owner, request_id)


@router.post("/list")
async def list_templates(request: Request) -> Response:
    return await _request(request, _OwnerBody, "list")


@router.post("/derive")
async def derive_template(request: Request) -> Response:
    return await _request(request, _TemplateBody, "derive")


@router.post("/read")
async def read_template(request: Request) -> Response:
    return await _request(request, _TemplateBody, "read")


@router.post("/save")
async def save_template(request: Request) -> Response:
    return await _request(request, _SaveBody, "save")
