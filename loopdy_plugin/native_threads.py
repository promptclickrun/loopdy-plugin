"""App -> plugin REST channel for thread mode (out-of-turn).

The iOS app manages thread-mode conversations without a live coordinator turn:
it flags a session as thread-mode, registers session-backed worker threads it
created itself (``session.create`` + ``prompt.submit``), and reads the roster.
All state lives in the same PluginState the in-turn tools use, so the roster
stays consistent across both channels.
"""
from __future__ import annotations

import logging
import sys
import time
from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from .native_api import _NativeRoute, _body, _precondition, _response
from .native_context import NativeAPIError, native_context
from . import thread_mode as _thread_mode


logger = logging.getLogger("hermes.plugins.loopdy.thread_mode.rest")
router = APIRouter(prefix="/native/threads", route_class=_NativeRoute)

# State resolver wiring. The dashboard mounts the bare ``loopdy_plugin``
# package while Hermes loads the plugin under a profile-safe namespace; the
# plugin registration records its PluginState resolver in the loader-owned
# module and this module scans sys.modules for the matching generation, the
# same pattern native_device_tools uses for its hub.
_registered_profile: str | None = None
_registered_state: Any = None


def register_state_resolver(profile: str, state: Any) -> None:
    """Called from plugin registration: expose the profile's PluginState."""
    global _registered_profile, _registered_state
    _registered_profile = profile
    _registered_state = state


def _state_for_profile(profile: str) -> Any:
    if not isinstance(profile, str) or not profile:
        raise NativeAPIError(503, "threads_unavailable", "Thread mode is unavailable.")
    for name, module in tuple(sys.modules.items()):
        if not name.endswith(".native_threads"):
            continue
        resolver_profile = getattr(module, "_registered_profile", None)
        state = getattr(module, "_registered_state", None)
        if resolver_profile == profile and state is not None:
            return state
    raise NativeAPIError(503, "threads_unavailable", "Thread mode is unavailable.")


def _clean_id(value: Any, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise NativeAPIError(422, "invalid_request", f"The {label} is invalid.")
    if len(value) > maximum or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
        raise NativeAPIError(422, "invalid_request", f"The {label} is invalid.")
    return value


class _FlagBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    session_id: str = Field(min_length=1, max_length=256)
    enabled: bool


class _RegisterBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    coordinator_session_id: str = Field(min_length=1, max_length=256)
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    worker_session_id: str = Field(min_length=1, max_length=256)
    brief: str = Field(min_length=1, max_length=4000)


def _profile_state(request: Request, owner: Any) -> Any:
    profile = str(getattr(owner, "serving_profile_id", "") or "")
    if not profile:
        raise NativeAPIError(503, "threads_unavailable", "Thread mode is unavailable.")
    state = _state_for_profile(profile)
    if native_context(request) != owner:
        raise NativeAPIError(412, "context_changed", "The native context changed; refresh before retrying.")
    return state


@router.post("/flag")
async def flag(request: Request) -> Response:
    owner = native_context(request)
    request_id = _precondition(request, owner)
    body = await _body(request, _FlagBody)
    session_id = _clean_id(body.session_id, "session id")
    state = _profile_state(request, owner)
    record = _thread_mode._load_coordinator(state, session_id)
    if record is None:
        record = _thread_mode._new_coordinator_record(session_id, enabled=body.enabled)
    else:
        record["enabled"] = bool(body.enabled)
    _thread_mode._save_coordinator(state, record)
    if native_context(request) != owner:
        raise NativeAPIError(412, "context_changed", "The native context changed; reconcile the outcome.")
    return _response({"ok": True, "session_id": session_id, "enabled": bool(body.enabled)},
                     owner, request_id)


@router.post("/register")
async def register(request: Request) -> Response:
    owner = native_context(request)
    request_id = _precondition(request, owner)
    body = await _body(request, _RegisterBody)
    coordinator_session_id = _clean_id(body.coordinator_session_id, "coordinator session id")
    worker_session_id = _clean_id(body.worker_session_id, "worker session id")
    state = _profile_state(request, owner)
    record = _thread_mode._ensure_coordinator(state, coordinator_session_id)
    if body.name in (record.get("threads") or {}):
        raise NativeAPIError(409, "thread_name_conflict",
                             f"A thread named '{body.name}' already exists for this coordinator.")
    entry = _thread_mode._new_thread_record(body.name, body.brief.strip(), "session")
    entry["worker_session_id"] = worker_session_id
    # The app created a real session and submitted the brief already: the
    # worker is live from the plugin's point of view.
    entry["status"] = "running"
    entry["updated_at"] = time.time()
    record["threads"][body.name] = entry
    _thread_mode._save_coordinator(state, record)
    state.set(_thread_mode.worker_key(worker_session_id), {
        "coordinator_session_id": coordinator_session_id,
        "thread": body.name,
    })
    if native_context(request) != owner:
        raise NativeAPIError(412, "context_changed", "The native context changed; reconcile the outcome.")
    return _response({"ok": True, "thread": _thread_mode.public_thread(entry)}, owner, request_id)


@router.get("/roster")
async def roster(request: Request) -> Response:
    owner = native_context(request)
    request_id = _precondition(request, owner)
    coordinator_session_id = _clean_id(
        request.query_params.get("coordinator_session_id"), "coordinator session id")
    state = _profile_state(request, owner)
    record = _thread_mode._load_coordinator(state, coordinator_session_id)
    if record is None:
        raise NativeAPIError(404, "coordinator_not_found",
                             "No thread-mode record exists for this session.")
    if native_context(request) != owner:
        raise NativeAPIError(412, "context_changed", "The native context changed; reconcile the outcome.")
    return _response({
        "coordinator_session_id": coordinator_session_id,
        "enabled": bool(record.get("enabled")),
        "updated_at": record.get("updated_at"),
        "notes": list(record.get("notes") or []),
        "threads": [_thread_mode.public_thread(entry)
                    for entry in (record.get("threads") or {}).values()],
    }, owner, request_id)
