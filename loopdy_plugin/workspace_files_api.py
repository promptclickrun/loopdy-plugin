"""Authenticated read-only workspace Files routes for the Loopdy plugin."""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Literal, TypeVar

from fastapi import APIRouter, Body, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError

from hermes_constants import get_hermes_home
from loopdy_plugin.workspace_files import WorkspaceFilesError, WorkspaceFilesService


router = APIRouter(prefix="/workspace-files", tags=["workspace-files"])
_REVISION_PATTERN = r"^sha256:[0-9a-f]{64}$"
_STATUS_TOKEN_PATTERN = r"^sha256:[0-9a-f]{64}$"
_BodyT = TypeVar("_BodyT", bound=BaseModel)


class _StrictBody(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _WorkspaceBody(_StrictBody):
    workspace_id: str = Field(
        min_length=1,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$",
    )


class _ListBody(_WorkspaceBody):
    path: str = Field(default="", max_length=4096)
    offset: StrictInt = Field(default=0, ge=0, le=8_388_608)
    limit: StrictInt = Field(default=100, ge=1, le=500)
    query: str = Field(default="", max_length=256)
    revision: str | None = Field(default=None, pattern=_REVISION_PATTERN)


class _ReadBody(_WorkspaceBody):
    path: str = Field(min_length=1, max_length=4096)
    offset: StrictInt = Field(default=0, ge=0, le=8_388_608)
    limit: StrictInt = Field(default=65_536, ge=1, le=65_536)
    revision: str | None = Field(default=None, pattern=_REVISION_PATTERN)


class _DiffBody(_WorkspaceBody):
    path: str = Field(min_length=1, max_length=4096)
    side: Literal["staged", "worktree"]
    expected_status_token: str = Field(pattern=_STATUS_TOKEN_PATTERN)
    offset: StrictInt = Field(default=0, ge=0, le=8_388_608)
    limit: StrictInt = Field(default=300, ge=1, le=500)


@lru_cache(maxsize=8)
def _default_service(state_dir: str) -> WorkspaceFilesService:
    return WorkspaceFilesService(state_dir)


def get_workspace_files_service() -> WorkspaceFilesService:
    """Keep cached services separated by the current profile's plugin data root."""
    try:
        return _default_service(str(get_hermes_home() / "plugin-data" / "loopdy" / "workspace-files"))
    except WorkspaceFilesError as error:
        response = _error_response(error)
        raise HTTPException(status_code=response.status_code, detail=error.envelope()) from error


@router.get("/capabilities", response_model=None)
def capabilities(
    service: WorkspaceFilesService = Depends(get_workspace_files_service),
) -> dict[str, Any] | JSONResponse:
    return _call(service.capabilities)


@router.post("/list", response_model=None)
def list_directory(
    value: Any = Body(...),
    service: WorkspaceFilesService = Depends(get_workspace_files_service),
) -> dict[str, Any] | JSONResponse:
    body = _validated(_ListBody, value)
    if isinstance(body, JSONResponse):
        return body
    return _call(
        service.list_directory,
        body.workspace_id,
        path=body.path,
        offset=body.offset,
        limit=body.limit,
        query=body.query,
        revision=body.revision,
    )


@router.post("/read", response_model=None)
def read_file(
    value: Any = Body(...),
    service: WorkspaceFilesService = Depends(get_workspace_files_service),
) -> dict[str, Any] | JSONResponse:
    body = _validated(_ReadBody, value)
    if isinstance(body, JSONResponse):
        return body
    return _call(
        service.read_file,
        body.workspace_id,
        path=body.path,
        offset=body.offset,
        limit=body.limit,
        revision=body.revision,
    )


@router.post("/status", response_model=None)
def git_status(
    value: Any = Body(...),
    service: WorkspaceFilesService = Depends(get_workspace_files_service),
) -> dict[str, Any] | JSONResponse:
    body = _validated(_WorkspaceBody, value)
    if isinstance(body, JSONResponse):
        return body
    return _call(service.git_status, body.workspace_id)


@router.post("/diff", response_model=None)
def git_diff(
    value: Any = Body(...),
    service: WorkspaceFilesService = Depends(get_workspace_files_service),
) -> dict[str, Any] | JSONResponse:
    body = _validated(_DiffBody, value)
    if isinstance(body, JSONResponse):
        return body
    return _call(
        service.git_diff,
        body.workspace_id,
        path=body.path,
        side=body.side,
        expected_status_token=body.expected_status_token,
        offset=body.offset,
        limit=body.limit,
    )


def _validated(
    body_type: type[_BodyT], value: Any
) -> _BodyT | JSONResponse:
    try:
        return body_type.model_validate(value)
    except ValidationError:
        return JSONResponse(status_code=422, content=WorkspaceFilesError(
            "INVALID_REQUEST", "Workspace Files request is invalid"
        ).envelope())


def _call(function: Any, *args: Any, **kwargs: Any) -> dict[str, Any] | JSONResponse:
    try:
        return function(*args, **kwargs)
    except WorkspaceFilesError as error:
        return _error_response(error)
    except Exception:
        error = WorkspaceFilesError(
            "FILES_UNAVAILABLE", "Workspace Files request failed"
        )
        return _error_response(error)


def _error_response(error: WorkspaceFilesError) -> JSONResponse:
    mapping = {
        "INVALID_REQUEST": status.HTTP_400_BAD_REQUEST,
        "INVALID_PATH": status.HTTP_400_BAD_REQUEST,
        "INVALID_GRANT": status.HTTP_400_BAD_REQUEST,
        "REVISION_REQUIRED": status.HTTP_400_BAD_REQUEST,
        "PATH_PROTECTED": status.HTTP_404_NOT_FOUND,
        "PATH_NOT_FOUND": status.HTTP_404_NOT_FOUND,
        "WORKSPACE_NOT_ALLOWED": status.HTTP_404_NOT_FOUND,
        "GRANT_CONFLICT": status.HTTP_409_CONFLICT,
        "REVISION_STALE": status.HTTP_409_CONFLICT,
        "STATUS_STALE": status.HTTP_409_CONFLICT,
        "HARD_LINK_UNSAFE": 422,
        "SECRET_SCAN_BLOCKED": 422,
        "DIRECTORY_OVERSIZED": 413,
        "CAPABILITY_UNSUPPORTED": status.HTTP_501_NOT_IMPLEMENTED,
        "STATE_UNAVAILABLE": status.HTTP_503_SERVICE_UNAVAILABLE,
        "FILES_UNAVAILABLE": status.HTTP_503_SERVICE_UNAVAILABLE,
        "GIT_UNAVAILABLE": status.HTTP_503_SERVICE_UNAVAILABLE,
        "GIT_STATUS_OVERSIZED": 413,
        "GIT_TIMEOUT": status.HTTP_504_GATEWAY_TIMEOUT,
    }
    return JSONResponse(
        status_code=mapping.get(error.code, status.HTTP_500_INTERNAL_SERVER_ERROR),
        content=error.envelope(),
    )


__all__ = ["router", "get_workspace_files_service"]
