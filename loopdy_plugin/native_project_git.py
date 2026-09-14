"""Read-only Git for a publicly registered Project and exact native stored session."""
from __future__ import annotations

from dataclasses import dataclass
import inspect
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any, Literal
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from starlette.concurrency import run_in_threadpool

from .native_api import _NativeRoute, _body, _precondition, _response
from .native_context import NativeAPIError, NativeContext, PROFILE_ID, native_context
from .workspace_control import _project_git_wire
from .workspace_files import (
    WorkspaceFilesError, _sanitize_git_status, _valid_relative_path, validate_workspace_root,
)
from .workspace_git import WorkspaceGitError, WorkspaceGitService, _workspace_lstat


CAPABILITY = "native-project-git-read-v1"
router = APIRouter(prefix="/native/projects/git", route_class=_NativeRoute)
_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_BLOCKED_SOURCES = {"bot_room", "tool", "subagent", "worker", "kanban", "cron", "delegate"}


class ProjectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    agentId: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    sessionId: str = Field(pattern=_ID)
    workspaceId: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")


class DiffRequest(ProjectRequest):
    path: str = Field(min_length=1, max_length=4096)
    side: Literal["staged", "worktree"]
    statusToken: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    offset: StrictInt = Field(ge=0, le=100_000)
    limit: StrictInt = Field(ge=1, le=500)


def supported() -> bool:
    try:
        from hermes_state import SessionDB
        from hermes_cli import profiles
        from hermes_constants import get_process_hermes_home
    except ImportError:
        return False
    return (
        "read_only" in inspect.signature(SessionDB).parameters
        and all(callable(getattr(SessionDB, name, None)) for name in
                ("get_session", "get_session_by_title", "get_compression_tip", "close"))
        and all(callable(getattr(profiles, name, None)) for name in
                ("normalize_profile_name", "validate_profile_name", "get_profile_dir", "profile_exists"))
        and callable(get_process_hermes_home)
        and os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW")
    )


def _unavailable_session() -> NativeAPIError:
    return NativeAPIError(404, "session_unavailable", "The selected session cannot be reviewed for this Project.")


def _safe_text(value: Any, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ValueError("Invalid metadata")
    if any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value):
        raise ValueError("Invalid metadata")
    return value


def _session_stamp(row: Any, profile: str) -> tuple:
    if not isinstance(row, dict):
        raise _unavailable_session()
    source = row.get("source")
    if (not isinstance(source, str) or not source or len(source) > 64
            or source in _BLOCKED_SOURCES or source.startswith(("worker_", "kanban_", "subagent_", "delegate_"))
            or row.get("archived") not in (False, 0, None)
            or row.get("profile_name") not in (None, profile)):
        raise _unavailable_session()
    config = row.get("model_config")
    if isinstance(config, str):
        if len(config.encode("utf-8")) > 65_536:
            raise _unavailable_session()
        try:
            config = json.loads(config)
        except (ValueError, RecursionError):
            raise _unavailable_session() from None
    if config is not None and not isinstance(config, dict):
        raise _unavailable_session()
    if any(row.get(key) or (config or {}).get(key) for key in ("room_plumbing", "_delegate_from")):
        raise _unavailable_session()
    return (row.get("id"), row.get("cwd"), source, bool(row.get("hidden")),
            row.get("parent_session_id"), row.get("end_reason"))


def _read_session(profile: str, profile_home: Path, session_id: str) -> tuple[dict, tuple]:
    from hermes_state import SessionDB

    path = profile_home / "state.db"
    if path.is_symlink() or not path.is_file():
        raise _unavailable_session()
    try:
        db = SessionDB(db_path=path, read_only=True)
        try:
            row = db.get_session(session_id)
            stamp = _session_stamp(row, profile)
            if row["id"] != session_id:
                raise _unavailable_session()
            witness = ()
            if row.get("hidden"):
                canonical = db.get_session_by_title("Bot Chat")
                canonical_stamp = _session_stamp(canonical, profile)
                if canonical.get("title") != "Bot Chat":
                    raise _unavailable_session()
                tip_id = db.get_compression_tip(canonical["id"])
                tip = db.get_session(tip_id) if isinstance(tip_id, str) else None
                tip_stamp = _session_stamp(tip, profile)
                if session_id not in {canonical["id"], tip["id"]}:
                    raise _unavailable_session()
                witness = (canonical_stamp, tip_stamp)
            return row, (stamp, witness)
        finally:
            db.close()
    except (OSError, sqlite3.Error):
        raise NativeAPIError(503, "session_metadata_unavailable", "Existing session metadata is unavailable.") from None


def _read_project(profile: str, project_id: str) -> dict:
    from tui_gateway.server import handle_request

    request_id = "loopdy-native-project-" + uuid.uuid4().hex
    response = handle_request({"jsonrpc": "2.0", "id": request_id, "method": "projects.get",
                               "params": {"profile": profile, "id": project_id}})
    if not isinstance(response, dict) or response.get("id") != request_id:
        raise NativeAPIError(503, "project_metadata_unavailable", "Project metadata is unavailable.")
    error = response.get("error")
    if error is not None:
        if isinstance(error, dict) and error.get("code") == 5062:
            raise NativeAPIError(404, "project_unavailable", "The selected Project is unavailable.")
        raise NativeAPIError(503, "project_metadata_unavailable", "Project metadata is unavailable.")
    result = response.get("result")
    project = result.get("project") if isinstance(result, dict) else None
    if not isinstance(project, dict) or project.get("id") != project_id or project.get("archived") is not False:
        raise NativeAPIError(404, "project_unavailable", "The selected Project is unavailable.")
    return project


@dataclass(frozen=True)
class Association:
    profile: str
    project_id: str
    label: str
    root: Path
    root_identity: tuple[int, int]
    folders: tuple
    session: tuple


def association(body: ProjectRequest) -> Association:
    from hermes_cli.profiles import (
        normalize_profile_name, validate_profile_name, get_profile_dir, profile_exists,
    )
    from hermes_constants import get_process_hermes_home

    profile = normalize_profile_name(body.agentId)
    try:
        validate_profile_name(profile)
    except ValueError:
        raise NativeAPIError(404, "profile_not_found", "The selected profile is unavailable.") from None
    profile_home = get_profile_dir(profile)
    if (profile != body.agentId or not profile_exists(profile) or not profile_home.is_dir()
            or profile_home.resolve() != Path(os.path.abspath(profile_home))):
        raise NativeAPIError(404, "profile_not_found", "The selected profile is unavailable.")
    row, session = _read_session(profile, profile_home, body.sessionId)
    project = _read_project(profile, body.workspaceId)
    try:
        label = _safe_text(project.get("name"), 120)
        root_path = _safe_text(project.get("primary_path"), 4096)
        folders = project.get("folders")
        if not isinstance(folders, list) or not 1 <= len(folders) <= 64:
            raise ValueError("Invalid Project folders")
        registered = tuple(sorted((_safe_text(folder.get("path"), 4096), folder.get("is_primary"))
                                  for folder in folders if isinstance(folder, dict)))
        if len(registered) != len(folders) or any(type(primary) is not bool for _, primary in registered):
            raise ValueError("Invalid Project folders")
        if sum(path == root_path and primary for path, primary in registered) != 1:
            raise ValueError("Project has no exact registered primary root")
        root = validate_workspace_root(Path(root_path), state_dir=get_process_hermes_home())
        cwd = Path(_safe_text(row.get("cwd"), 4096))
        if not cwd.is_absolute() or cwd.resolve(strict=True) != Path(os.path.abspath(cwd)) or not cwd.samefile(root):
            raise ValueError("Session is not anchored to the exact Project root")
        info = root.stat()
    except (OSError, RuntimeError, ValueError, WorkspaceFilesError):
        raise NativeAPIError(404, "project_unavailable", "The session and Project root could not be verified.") from None
    return Association(profile, body.workspaceId, label, root, (info.st_dev, info.st_ino), registered, session)


def _status(service: WorkspaceGitService, workspace_id: str) -> dict:
    result = _sanitize_git_status(service.status(workspace_id))
    if result.pop("hidden_files", 0):
        raise NativeAPIError(422, "sensitive_data_blocked", "Protected Project paths require local review.")
    return result


def _execute(request: Request, owner: NativeContext, body: ProjectRequest, operation: str) -> dict:
    from hermes_constants import (
        get_process_hermes_home, set_hermes_home_override, reset_hermes_home_override,
    )

    def check_owner():
        if native_context(request) != owner:
            raise NativeAPIError(412, "context_changed", "The native context changed; refresh Project changes.")

    check_owner()
    token = set_hermes_home_override(get_process_hermes_home())
    try:
        before = association(body)
        service = WorkspaceGitService([{
            "workspace_id": before.project_id, "label": before.label, "root": str(before.root),
            "visibility": "private", "operations": ["status"], "remotes": [], "branches": [],
            "mutations_enabled": False,
        }], read_only=True)
        current = _status(service, before.project_id)
        if operation == "capabilities":
            result = service.capabilities()
        elif operation == "status":
            result = current
        elif operation == "diff" and isinstance(body, DiffRequest):
            path = _valid_relative_path(body.path)
            entry = _workspace_lstat(before.root, path)
            if entry is not None and (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1):
                raise NativeAPIError(422, "diff_unsupported", "This Project entry cannot be reviewed safely.")
            result = service.diff(before.project_id, path=path, side=body.side,
                expected_status_token=body.statusToken, offset=body.offset, limit=body.limit,
                reject_sensitive_content=True)
        else:
            raise NativeAPIError(422, "invalid_request", "The Project Git request is invalid.")
        try:
            root_info = before.root.stat()
            root_unchanged = (before.root.resolve(strict=True) == before.root
                              and (root_info.st_dev, root_info.st_ino) == before.root_identity)
        except OSError:
            root_unchanged = False
        if not root_unchanged:
            raise NativeAPIError(409, "scope_changed", "The Project root changed; refresh before reviewing.")
        final = _status(service, before.project_id)
        if current["status_token"] != final["status_token"]:
            raise NativeAPIError(409, "status_changed", "Project changes changed; refresh before reviewing.")
        try:
            after = association(body)
        except NativeAPIError as error:
            if error.status == 404:
                raise NativeAPIError(409, "scope_changed", "The Project or session changed; refresh before reviewing.") from None
            raise
        if after != before:
            raise NativeAPIError(409, "scope_changed", "The Project or session changed; refresh before reviewing.")
        check_owner()
        return _project_git_wire(result)
    finally:
        reset_hermes_home_override(token)


def _domain_error(error: WorkspaceGitError | WorkspaceFilesError) -> NativeAPIError:
    mapping = {
        "GIT_STATUS_OVERSIZED": (413, "status_oversized", "The complete Project status exceeds the review limit."),
        "STATUS_STALE": (409, "status_changed", "Project changes changed; refresh before reviewing."),
        "DIFF_UNSUPPORTED": (422, "diff_unsupported", "Combined conflict diffs are not supported."),
        "SECRET_SCAN_BLOCKED": (422, "sensitive_data_blocked", "Project content requires local review."),
        "PATH_PROTECTED": (422, "sensitive_data_blocked", "Protected Project paths require local review."),
        "INVALID_PATH": (422, "invalid_path", "The selected Project path is invalid."),
        "INVALID_REQUEST": (422, "invalid_request", "The Project Git request is invalid."),
        "WORKSPACE_NOT_ALLOWED": (409, "scope_changed", "The Project root changed; refresh before reviewing."),
        "PROJECT_NOT_REPOSITORY": (422, "project_not_repository", "The Project root is not a Git repository."),
        "UNSUPPORTED_PATH_ENCODING": (422, "diff_unsupported", "A Project path cannot be safely displayed."),
        "GIT_TIMEOUT": (504, "git_timeout", "Git did not complete within the review time limit."),
    }
    return NativeAPIError(*mapping.get(error.code, (503, "git_unavailable", "Project Git is unavailable.")))


async def _perform(request: Request, operation: str) -> Response:
    owner = native_context(request)
    request_id = _precondition(request, owner)
    if CAPABILITY not in owner.features:
        raise NativeAPIError(501, "project_git_unavailable", "Native Project Git requires supported public metadata APIs.")
    body = await _body(request, DiffRequest if operation == "diff" else ProjectRequest)
    if PROFILE_ID.fullmatch(body.agentId) is None:
        raise NativeAPIError(422, "invalid_request", "The profile is invalid.")
    try:
        result = await run_in_threadpool(_execute, request, owner, body, operation)
    except (WorkspaceGitError, WorkspaceFilesError) as error:
        raise _domain_error(error) from None
    if native_context(request) != owner:
        raise NativeAPIError(412, "context_changed", "The native context changed; discard Project changes.")
    return _response(result, owner, request_id)


@router.post("/capabilities")
async def capabilities(request: Request) -> Response:
    return await _perform(request, "capabilities")


@router.post("/status")
async def status(request: Request) -> Response:
    return await _perform(request, "status")


@router.post("/diff")
async def diff(request: Request) -> Response:
    return await _perform(request, "diff")
