"""Fixed authenticated endpoints for disposable hosted-room tool observations."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from .native_api import _NativeRoute, _body, _precondition, _response
from .native_context import NativeAPIError, native_context
from .room_activity import CAPABILITY, RoomScope, activity_hub


router = APIRouter(prefix="/groups/activity", route_class=_NativeRoute)


class _Room(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    roomId: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class _Stream(_Room):
    streamId: str = Field(pattern=r"^[0-9a-f]{32}$")


class _Poll(_Stream):
    after: StrictInt = Field(ge=0, le=9_007_199_254_740_991)
    limit: StrictInt = Field(ge=1, le=8)


async def read_room_scope(room_id: str) -> RoomScope:
    from hermes_constants import (
        get_process_hermes_home, set_hermes_home_override, reset_hermes_home_override,
    )
    from .adapter import get_service
    from .workspace_control import HermesWorkspaceBackend, WorkspaceControlError
    token = set_hermes_home_override(get_process_hermes_home())
    try:
        backend = HermesWorkspaceBackend(service=get_service())
        try:
            state = await backend.groups_state({"room_id": room_id})
        except WorkspaceControlError:
            raise NativeAPIError(503, "room_unavailable", "The native room could not be verified.") from None
        return RoomScope.from_state(state, room_id)
    finally:
        reset_hermes_home_override(token)


def _same_owner(request: Request, owner) -> None:
    if native_context(request) != owner:
        raise NativeAPIError(412, "context_changed", "The native context changed; discard the observation feed.")


@router.post("/open")
async def open_feed(request: Request) -> Response:
    owner = native_context(request)
    request_id = _precondition(request, owner)
    if CAPABILITY not in owner.features:
        raise NativeAPIError(503, "activity_unavailable", "The public room observer is unavailable.")
    body = await _body(request, _Room)
    _same_owner(request, owner)
    scope = await read_room_scope(body.roomId)
    _same_owner(request, owner)
    page = activity_hub().open(owner, scope)
    return _response(page, owner, request_id)


@router.post("/poll")
async def poll_feed(request: Request) -> Response:
    owner = native_context(request)
    request_id = _precondition(request, owner)
    body = await _body(request, _Poll)
    _same_owner(request, owner)
    hub = activity_hub()
    hub.check(body.streamId, owner, body.roomId)
    scope = await read_room_scope(body.roomId)
    _same_owner(request, owner)
    page = hub.poll(body.streamId, owner, scope, body.after, body.limit)
    return _response(page, owner, request_id)


@router.post("/close")
async def close_feed(request: Request) -> Response:
    owner = native_context(request)
    request_id = _precondition(request, owner)
    body = await _body(request, _Stream)
    _same_owner(request, owner)
    return _response(activity_hub().close(body.streamId, owner, body.roomId), owner, request_id)
