"""Bounded native phone transport for Hermes device tools.

Hermes owns the tool execution lifecycle.  This module only holds an ephemeral,
authenticated phone lease and forwards the already validated ``device.tool``
wire contracts to that phone.  The execution middleware receives the real
session, turn, and tool call coordinates from Hermes; none of those identities
are accepted from model arguments.
"""

from __future__ import annotations

import asyncio
from collections import deque
from concurrent.futures import Future, InvalidStateError
from dataclasses import dataclass, field
import hashlib
import json
import sqlite3
import sys
import threading
import time
from typing import Any, Callable, Literal
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator

from .link_contracts import device_tool_request, parse_device_tool_result


CAPABILITY = "native-device-tools-v1"
LEASE_SECONDS = 30
MAX_CHANNELS = 64
MAX_QUEUE = 128
MAX_COMPLETED = 256
MAX_POLL_ITEMS = 8
_UUID = r"\A[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z"
_SESSION = r"\A[A-Za-z0-9_-]{1,180}\z"
_PROFILE = r"\A[a-z0-9][a-z0-9_-]{0,63}\z"
_HOST = r"\A[A-Za-z0-9_-]{1,96}\z"
_TOOL_NAMES = frozenset({"iphone_health", "iphone_calendar", "iphone_reminders"})


class NativeDeviceToolError(ValueError):
    """A bounded native channel rejection safe to return to the phone."""

    def __init__(self, code: str, message: str = "The native iPhone tool channel is unavailable.",
                 status: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass
class _Pending:
    request: dict[str, Any]
    fingerprint: str
    future: Future[dict[str, Any]]
    waiters: int = 1


@dataclass
class _Channel:
    owner: Any
    channel_id: str
    device_id: str
    host_id: str
    authorization_epoch: int
    profile: str
    session_id: str
    enabled: frozenset[str]
    lease_expires: float
    sequence: int = 0
    requests: deque[tuple[int, dict[str, Any]]] = field(default_factory=deque)
    pending: dict[str, _Pending] = field(default_factory=dict)
    completed: set[str] = field(default_factory=set)
    completed_order: deque[str] = field(default_factory=deque)
    closed: bool = False


def _failed_result(request_id: str | None, code: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "version": 1,
        "type": "device.tool.result",
        "status": "failed",
        "code": code,
        "payload": {},
    }
    if request_id:
        result["requestId"] = request_id
    return result


def _fingerprint(operation: str, arguments: dict[str, Any]) -> str:
    encoded = json.dumps(
        {"operation": operation, "arguments": arguments},
        ensure_ascii=False, separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _request_id(channel: _Channel, session_id: str, turn_id: str, tool_call_id: str) -> str:
    # The authentic Hermes call identity is the idempotency key.  Arguments are
    # deliberately excluded so a duplicate invocation coalesces, while its
    # fingerprint below rejects a reused call ID with changed work.
    value = json.dumps(
        [channel.channel_id, channel.device_id, channel.host_id,
         channel.authorization_epoch, session_id, turn_id, tool_call_id,
        ],
        ensure_ascii=False, separators=(",", ":"), sort_keys=True,
    )
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _owner_profile(owner: Any) -> str:
    return str(getattr(owner, "serving_profile_id", "") or "")


def _owner_key(owner: Any) -> tuple[Any, ...]:
    return (
        getattr(owner, "provider", None),
        getattr(owner, "user_id", None),
        getattr(owner, "serving_profile_id", None),
        getattr(owner, "runtime_id", None),
    )


def _set_future(pending: _Pending, result: dict[str, Any]) -> None:
    try:
        pending.future.set_result(result)
    except InvalidStateError:
        return


def _mark_completed(channel: _Channel, request_id: str) -> None:
    """Keep the newest bounded result tombstones in insertion order."""
    if request_id in channel.completed:
        return
    channel.completed.add(request_id)
    channel.completed_order.append(request_id)
    while len(channel.completed_order) > MAX_COMPLETED:
        channel.completed.discard(channel.completed_order.popleft())


def _default_profile_session_validator(profile: str, session_id: str) -> bool:
    """Verify a stored or currently live Hermes session with official helpers."""
    try:
        from hermes_cli.profiles import get_profile_dir, profile_exists
        from hermes_constants import (
            get_process_hermes_home,
            reset_hermes_home_override,
            set_hermes_home_override,
        )
        from hermes_state import SessionDB
    except ImportError:
        return False
    try:
        if not profile_exists(profile):
            return False
        token = set_hermes_home_override(get_process_hermes_home())
        try:
            db_path = get_profile_dir(profile) / "state.db"
            with SessionDB(db_path=db_path, read_only=True) as db:
                if db.get_session(session_id) is not None:
                    return True
        finally:
            reset_hermes_home_override(token)
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return False

    # A live gateway may have a runtime UI ID before its durable session row is
    # visible to a reader.  Hermes' own session gateway map is the only allowed
    # runtime-to-stored resolution here; do not accept arbitrary prefixes.
    try:
        # ``methods_session`` bodies are rebound onto the running gateway
        # module. Read that canonical live map instead of guessing a runtime
        # ID from a prefix or from arbitrary request data.
        sessions = _live_sessions_snapshot()
        row = sessions.get(session_id)
        if isinstance(row, dict) and isinstance(row.get("session_key"), str) and _live_profile_matches(row, profile):
            return True
        return any(
            isinstance(row, dict)
            and row.get("session_key") == session_id
            and _live_profile_matches(row, profile)
            for row in sessions.values()
        )
    except (AttributeError, RuntimeError, TypeError, ValueError):
        pass
    return False


def _live_profile_matches(row: dict[str, Any], profile: str) -> bool:
    """Require a live runtime row to belong to the requested Hermes profile."""
    try:
        from hermes_constants import get_process_hermes_home, profile_name_for_home
        profile_home = row.get("profile_home")
        home = Path(profile_home) if isinstance(profile_home, str) and profile_home else get_process_hermes_home()
        return profile_name_for_home(home) == profile
    except (ImportError, OSError, TypeError, ValueError):
        return False


def _live_sessions_snapshot() -> dict[str, Any]:
    """Read Hermes' live runtime map under its own lock when available."""
    try:
        # Do not import the gateway lazily.  Hermes' gateway module performs
        # startup/config work at import time; the native plugin may be loaded
        # by the dashboard before that module exists.  A live runtime map is
        # usable only when the official gateway has already published it.
        gateway_server = sys.modules.get("tui_gateway.server")
        if gateway_server is None:
            return {}
        sessions = getattr(gateway_server, "_sessions", {})
        if not isinstance(sessions, dict):
            return {}
        lock = getattr(gateway_server, "_sessions_lock", None)
        if lock is None:
            return dict(sessions)
        with lock:
            return dict(sessions)
    except (ImportError, AttributeError, RuntimeError, TypeError):
        return {}


def _same_live_session(left: str, right: str) -> bool:
    """Match Hermes' runtime sid to its durable session key using its live map."""
    if left == right:
        return True
    for runtime_id, row in _live_sessions_snapshot().items():
        if not isinstance(row, dict):
            continue
        stored_id = row.get("session_key")
        if not isinstance(runtime_id, str) or not isinstance(stored_id, str):
            continue
        if (runtime_id == left and stored_id == right) or (runtime_id == right and stored_id == left):
            return True
    return False


class NativeDeviceToolHub:
    """Own native device leases, queued requests, and one-shot results."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] | None = None,
        lease_seconds: int = LEASE_SECONDS,
        profile_session_validator: Callable[[str, str], bool] | None = None,
    ) -> None:
        self.clock = clock or time.time
        self.lease_seconds = max(20, min(LEASE_SECONDS, int(lease_seconds)))
        self.profile_session_validator = profile_session_validator or _default_profile_session_validator
        self.channels: dict[str, _Channel] = {}
        self._retired_ids: deque[str] = deque(maxlen=MAX_COMPLETED)
        self._lock = threading.RLock()

    def _expired(self, channel: _Channel) -> bool:
        return channel.closed or self.clock() >= channel.lease_expires

    def _purge_expired(self) -> None:
        for channel_id, channel in tuple(self.channels.items()):
            if self._expired(channel):
                self._retire(channel)
                self.channels.pop(channel_id, None)

    def _retire(self, channel: _Channel) -> None:
        if channel.closed:
            return
        channel.closed = True
        self._retired_ids.append(channel.channel_id)
        channel.requests.clear()
        for request_id, pending in tuple(channel.pending.items()):
            _mark_completed(channel, request_id)
            _set_future(pending, _failed_result(request_id, "phone_unavailable"))
        channel.pending.clear()

    def _get(self, owner: Any, channel_id: str) -> _Channel:
        channel = self.channels.get(channel_id)
        if channel is None:
            if channel_id in self._retired_ids:
                raise NativeDeviceToolError("phone_unavailable")
            raise NativeDeviceToolError("channel_not_found")
        if _owner_key(channel.owner) != _owner_key(owner):
            raise NativeDeviceToolError("channel_owner_changed", status=403)
        if self._expired(channel):
            self._retire(channel)
            raise NativeDeviceToolError("phone_unavailable")
        return channel

    def connect(self, owner: Any, fields: dict[str, Any]) -> dict[str, Any]:
        channel_id = fields["channelId"]
        profile = fields["agentId"]
        session_id = fields["sessionId"]
        if _owner_profile(owner) != profile:
            raise NativeDeviceToolError("profile_not_served", status=403)
        try:
            verified = self.profile_session_validator(profile, session_id)
        except Exception:
            verified = False
        if not verified:
            raise NativeDeviceToolError("session_not_found", status=404)
        with self._lock:
            if channel_id in self.channels or channel_id in self._retired_ids:
                raise NativeDeviceToolError("channel_id_consumed")
            self._purge_expired()
            if len(self.channels) >= MAX_CHANNELS:
                raise NativeDeviceToolError("channel_capacity", status=503)
            # A second phone for one live Hermes session is ambiguous.  It is
            # never selected by recency or by whichever request polls first.
            for channel in tuple(self.channels.values()):
                if channel.profile == profile and _same_live_session(channel.session_id, session_id):
                    raise NativeDeviceToolError("channel_ambiguous")
            channel = _Channel(
                owner=owner,
                channel_id=channel_id,
                device_id=fields["deviceId"],
                host_id=fields["hostId"],
                authorization_epoch=fields["authorizationEpoch"],
                profile=profile,
                session_id=session_id,
                enabled=frozenset(fields["enabled"]),
                lease_expires=self.clock() + self.lease_seconds,
            )
            self.channels[channel_id] = channel
        return {"channelId": channel_id, "connected": True}

    def _matching(self, profile: str, session_id: str) -> list[_Channel]:
        matches: list[_Channel] = []
        with self._lock:
            for channel in tuple(self.channels.values()):
                if self._expired(channel):
                    self._retire(channel)
                    self.channels.pop(channel.channel_id, None)
                    continue
                if channel.profile == profile and _same_live_session(channel.session_id, session_id):
                    matches.append(channel)
        return matches

    def native_channel_count(self, profile: str, session_id: str) -> int:
        """Return the active native-channel count for middleware fallback routing."""
        return len(self._matching(profile, session_id))

    def poll(self, owner: Any, fields: dict[str, Any], *, after: int | None = None) -> dict[str, Any]:
        with self._lock:
            channel = self._get(owner, fields["channelId"])
            if after is None:
                after = fields["after"]
            if after > channel.sequence or (
                channel.requests and after < channel.requests[0][0] - 1
            ):
                raise NativeDeviceToolError("feed_gap")
            while channel.requests and channel.requests[0][0] <= after:
                channel.requests.popleft()
            rows = list(channel.requests)[:MAX_POLL_ITEMS]
            channel.lease_expires = self.clock() + self.lease_seconds
            return {
                "channelId": channel.channel_id,
                "next": rows[-1][0] if rows else after,
                "requests": [
                    {"sequence": sequence, "request": request}
                    for sequence, request in rows
                ],
            }

    def accept_result(self, owner: Any, fields: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            channel = self._get(owner, fields["channelId"])
            request_id = result.get("requestId") if isinstance(result, dict) else None
            if request_id in channel.completed:
                raise NativeDeviceToolError("result_replay")
            pending = channel.pending.get(request_id)
            if pending is None:
                raise NativeDeviceToolError("result_unknown")
            try:
                parsed = parse_device_tool_result(
                    result,
                    sender_device_id=channel.device_id,
                    sender_epoch=channel.authorization_epoch,
                )
            except ValueError as exc:
                raise NativeDeviceToolError("result_invalid") from exc
            if any(
                parsed.get(key) != pending.request.get(key)
                for key in (
                    "requestId", "deviceId", "hostId", "authorizationEpoch", "sessionId",
                    "agentId", "turnId", "operation",
                )
            ):
                raise NativeDeviceToolError("result_coordinates_mismatch")
            if parsed["operation"].split(".", 1)[0] not in channel.enabled:
                raise NativeDeviceToolError("authorization_required")
            if parsed["sentAt"] < pending.request["sentAt"]:
                raise NativeDeviceToolError("result_timestamp_invalid")
            if self.clock() >= pending.request["expiresAt"]:
                _mark_completed(channel, request_id)
                _set_future(pending, _failed_result(request_id, "phone_unavailable"))
                raise NativeDeviceToolError("result_expired")
            _mark_completed(channel, request_id)
            _set_future(pending, parsed)
            channel.lease_expires = self.clock() + self.lease_seconds
        return {"accepted": True}

    def close(self, owner: Any, fields: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            channel = self._get(owner, fields["channelId"])
            self._retire(channel)
            self.channels.pop(channel.channel_id, None)
        return {"closed": True}

    def close_all(self) -> None:
        """Retire every phone lease when Hermes unloads this plugin generation."""
        with self._lock:
            for channel_id, channel in tuple(self.channels.items()):
                self._retire(channel)
                self.channels.pop(channel_id, None)

    async def execute(
        self,
        *,
        profile: str,
        session_id: str,
        turn_id: str,
        tool_call_id: str,
        operation: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        if not all(isinstance(value, str) and value for value in (profile, session_id, turn_id, tool_call_id)):
            return _failed_result(None, "call_identity_missing")
        try:
            if not self.profile_session_validator(profile, session_id):
                return _failed_result(None, "phone_unavailable")
        except Exception:
            return _failed_result(None, "phone_unavailable")
        matches = self._matching(profile, session_id)
        if not matches:
            return _failed_result(None, "phone_unavailable")
        if len(matches) != 1:
            return _failed_result(None, "channel_ambiguous")
        channel = matches[0]
        capability = operation.split(".", 1)[0]
        if capability not in channel.enabled:
            return _failed_result(None, "authorization_required")
        try:
            if not isinstance(arguments, dict):
                raise ValueError
            request_id = _request_id(channel, session_id, turn_id, tool_call_id)
            fingerprint = _fingerprint(operation, arguments)
            with self._lock:
                if self._expired(channel):
                    self._retire(channel)
                    return _failed_result(None, "phone_unavailable")
                existing = channel.pending.get(request_id)
                if existing is not None:
                    if existing.fingerprint != fingerprint:
                        return _failed_result(request_id, "request_conflict")
                    existing.waiters += 1
                    pending = existing
                elif request_id in channel.completed:
                    return _failed_result(request_id, "result_replay")
                else:
                    sent_at = int(self.clock())
                    request = device_tool_request(
                        request_id=request_id,
                        device_id=channel.device_id,
                        host_id=channel.host_id,
                        authorization_epoch=channel.authorization_epoch,
                        # Echo the channel's validated coordinate.  If the
                        # phone connected with Hermes' runtime sid, the
                        # middleware's durable sid is used only for matching.
                        session_id=channel.session_id,
                        agent_id=profile,
                        turn_id=turn_id,
                        operation=operation,
                        arguments=arguments,
                        sent_at=sent_at,
                        expires_at=sent_at + self.lease_seconds,
                    )
                    if len(channel.pending) >= MAX_QUEUE:
                        return _failed_result(request_id, "busy")
                    pending = _Pending(request, fingerprint, Future())
                    channel.pending[request_id] = pending
                    channel.sequence += 1
                    channel.requests.append((channel.sequence, request))
                    while len(channel.requests) > MAX_QUEUE:
                        channel.requests.popleft()
                deadline = pending.request["expiresAt"]
            remaining = max(0.001, min(float(deadline - int(self.clock())), self.lease_seconds))
            try:
                # A middleware call may run through Hermes' persistent main
                # loop or a per-worker loop.  Wrap the thread-safe shared
                # future on this caller's loop so duplicates can coalesce
                # across either execution path without cross-loop awaits.
                shared_result = asyncio.wrap_future(pending.future, loop=asyncio.get_running_loop())
                return await asyncio.wait_for(asyncio.shield(shared_result), timeout=remaining)
            except asyncio.TimeoutError:
                result = _failed_result(request_id, "phone_unavailable")
                with self._lock:
                    _mark_completed(channel, request_id)
                    _set_future(pending, result)
                return result
            finally:
                with self._lock:
                    if channel.pending.get(request_id) is pending:
                        pending.waiters -= 1
                        if pending.waiters <= 0 or pending.future.done():
                            channel.pending.pop(request_id, None)
        except NativeDeviceToolError as exc:
            return _failed_result(None, exc.code)
        except (TypeError, ValueError, KeyError):
            return _failed_result(None, "invalid_arguments")


def _operation_for_tool(tool_name: str, args: Any) -> tuple[str, dict[str, Any]]:
    # These coordinates belong to the authenticated channel and Hermes
    # middleware.  A model supplied value is discarded before the existing
    # device-tool contract validates the operation arguments.
    reserved = {
        "channelId", "deviceId", "hostId", "authorizationEpoch", "sessionId",
        "agentId", "turnId", "toolCallId", "requestId",
    }
    if tool_name == "iphone_health":
        if not isinstance(args, dict):
            raise NativeDeviceToolError("invalid_arguments", status=422)
        return "health.read", {key: value for key, value in args.items() if key not in reserved}
    if tool_name not in _TOOL_NAMES or not isinstance(args, dict):
        raise NativeDeviceToolError("invalid_arguments", status=422)
    values = {key: value for key, value in args.items() if key not in reserved}
    selected = values.pop("operation", None)
    if selected not in {"list", "create", "update", "delete"}:
        raise NativeDeviceToolError("invalid_arguments", status=422)
    return f"{tool_name.removeprefix('iphone_')}.{selected}", values


def register_middleware(
    ctx: Any,
    *,
    hub: NativeDeviceToolHub | None = None,
    fallback_to_link: bool = False,
) -> bool:
    """Register native tool execution on Hermes' public middleware surface.

    Hermes invokes execution middleware from synchronous tool dispatch.  The
    callback therefore resolves the native hub coroutine through Hermes'
    supported ``model_tools._run_async`` bridge before returning a JSON tool
    result.  On hosts that still expose the old Link context, an absent native
    lease falls through exactly once to the downstream Link handler.

    Hermes capability probes may expose middleware registration without the
    host-owned ``on_unload`` lifecycle.  Those probes can inspect the callback,
    but native availability remains false until cleanup ownership is present.
    """
    register = getattr(ctx, "register_middleware", None)
    if not callable(register):
        return False
    try:
        from hermes_cli.middleware import TOOL_EXECUTION_MIDDLEWARE, VALID_MIDDLEWARE
    except ImportError:
        return False
    if TOOL_EXECUTION_MIDDLEWARE not in VALID_MIDDLEWARE:
        return False
    selected_hub = hub or _HUB
    profile = str(getattr(ctx, "profile_name", "") or "")

    def execute(**kwargs: Any) -> str | None:
        tool_name = kwargs.get("tool_name")
        if tool_name not in _TOOL_NAMES:
            return None
        session_id = kwargs.get("session_id", "")
        # Native is authoritative whenever a phone lease is selected.  A
        # missing lease may use the old Link bridge on compatible Hermes
        # versions; ambiguity and native authorization failures never reroute.
        if selected_hub.native_channel_count(profile, session_id) == 0 and fallback_to_link:
            next_call = kwargs.get("next_call")
            if callable(next_call):
                return next_call()
        try:
            operation, arguments = _operation_for_tool(tool_name, kwargs.get("args"))
            import model_tools
            result = model_tools._run_async(selected_hub.execute(
                profile=profile,
                session_id=session_id,
                turn_id=kwargs.get("turn_id", ""),
                tool_call_id=kwargs.get("tool_call_id", ""),
                operation=operation,
                arguments=arguments,
            ))
        except NativeDeviceToolError as exc:
            result = _failed_result(None, exc.code)
        except (TypeError, ValueError, KeyError):
            result = _failed_result(None, "invalid_arguments")
        except Exception:
            # Hermes' execution chain falls through when a middleware callback
            # raises.  An active native lease must never silently reroute into
            # the legacy handler after its async bridge fails.
            result = _failed_result(None, "phone_unavailable")
        return json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    try:
        register(TOOL_EXECUTION_MIDDLEWARE, execute)
    except (AttributeError, TypeError, ValueError):
        return False
    on_unload = getattr(ctx, "on_unload", None)
    if callable(on_unload):
        _set_registered(True, profile)

        def unload() -> None:
            retire = getattr(selected_hub, "close_all", None)
            try:
                if callable(retire):
                    retire()
            finally:
                _set_registered(False, profile)

        on_unload(unload)
    # A host without lifecycle cleanup is deliberately unsupported for native
    # phone leases; ``available()`` remains false and the HTTP gate will fail
    # closed.  Keep the callback registration result true for probe contexts.
    return True


_HUB = NativeDeviceToolHub()
_registered = False
_registered_profile: str | None = None
_MODULE_ORIGIN = Path(__file__).resolve()


def _set_registered(value: bool, profile: str | None = None) -> None:
    global _registered, _registered_profile
    _registered = bool(value)
    _registered_profile = profile if _registered else None


def _implementation_for_profile(profile: str | None) -> Any | None:
    """Find the middleware module owned by the active Hermes plugin loader.

    Hermes intentionally imports directory plugins under a profile-safe
    ``hermes_plugins.<slug>`` namespace.  Dashboard API modules are mounted
    from disk and import the same package under its bare name.  Keep the
    dashboard side pointed at the loader-owned implementation so its requests
    use the middleware's hub, while matching the serving profile to prevent a
    multiplexed process from crossing profile state.  Multiple matching
    generations are treated as unavailable until Hermes retires the stale one.
    """
    if not isinstance(profile, str) or not profile:
        return None
    current = sys.modules.get(__name__)
    candidates: list[Any] = []
    if (
        current is not None
        and _registered
        and _registered_profile == profile
    ):
        candidates.append(current)
    for name, module in tuple(sys.modules.items()):
        if module is current or not name.endswith(".native_device_tools"):
            continue
        try:
            origin = Path(getattr(module, "__file__", "")).resolve()
        except (OSError, RuntimeError, TypeError, ValueError):
            continue
        if origin != _MODULE_ORIGIN:
            continue
        if getattr(module, "_registered", False) is not True:
            continue
        if getattr(module, "_registered_profile", None) != profile:
            continue
        candidates.append(module)
    # A forced reload can briefly leave two registered generations in one
    # process.  Refuse to route by import order until the host's lifecycle has
    # retired one of them.
    return candidates[0] if len(candidates) == 1 else None


def available(profile: str | None = None) -> bool:
    """Whether registration installed a working native middleware path.

    With a profile, resolve the loader-owned namespace used by the current
    dashboard process.  The no-argument form remains a local registration
    probe for compatibility with focused tests and host feature probes.
    """
    if profile is None:
        return _registered
    return _implementation_for_profile(profile) is not None


class _Scope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    channelId: str = Field(pattern=_UUID)


class _Connect(_Scope):
    deviceId: str = Field(pattern=_UUID)
    hostId: str = Field(pattern=_HOST)
    authorizationEpoch: StrictInt = Field(ge=1, le=1)
    agentId: str = Field(pattern=_PROFILE)
    sessionId: str = Field(pattern=_SESSION)
    enabled: list[Literal["health", "calendar", "reminders"]] = Field(min_length=0, max_length=3)

    @field_validator("enabled")
    @classmethod
    def unique_enabled(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("enabled capabilities must be unique")
        return value


class _Poll(_Scope):
    after: StrictInt = Field(ge=0, le=9_007_199_254_740_991)


class _Result(_Scope):
    result: dict[str, Any]


async def request(operation: str, request: Any) -> Any:
    """Serve one native device-tool operation through the shared native auth gate."""
    from .native_api import _body, _precondition, _response
    from .native_context import NativeAPIError, native_context

    models: dict[str, type[BaseModel]] = {
        "connect": _Connect,
        "poll": _Poll,
        "result": _Result,
        "close": _Scope,
    }
    if operation not in models:
        raise NativeAPIError(404, "unknown_device_tool_operation", "The device-tool operation is unknown.")
    owner = native_context(request)
    request_id = _precondition(request, owner)
    if CAPABILITY not in owner.features or not available():
        raise NativeAPIError(503, "device_tools_unavailable", "Native device tools are unavailable.")
    body = await _body(request, models[operation])
    if native_context(request) != owner:
        raise NativeAPIError(412, "context_changed", "The native context changed; reconnect before retrying.")
    fields = body.model_dump()
    try:
        if operation == "connect":
            value = _HUB.connect(owner, fields)
        elif operation == "poll":
            value = _HUB.poll(owner, fields)
        elif operation == "result":
            value = _HUB.accept_result(owner, fields, fields["result"])
        else:
            value = _HUB.close(owner, fields)
    except NativeDeviceToolError as error:
        raise NativeAPIError(error.status, error.code, str(error)) from None
    if native_context(request) != owner:
        raise NativeAPIError(412, "context_changed", "The native context changed; reconcile the outcome.")
    return _response(value, owner, request_id)


__all__ = [
    "CAPABILITY", "NativeDeviceToolError", "NativeDeviceToolHub", "available",
    "register_middleware", "request",
]
