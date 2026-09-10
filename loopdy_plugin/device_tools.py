"""Authenticated Loopdy iPhone Health, Calendar and Reminders tool bridge."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections.abc import Mapping
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable

from .link_contracts import (
    DEVICE_TOOL_OPERATIONS,
    DIRECTED_FRAMES_CAPABILITY,
    HEALTH_TYPES,
    MAX_DEVICE_TOOL_ARGUMENT_BYTES,
    MAX_DEVICE_TOOL_PAYLOAD_BYTES,
    device_tool_request,
    parse_device_tool_result,
    parse_device_tool_status,
)


CAPABILITIES = ("health", "calendar", "reminders")
MAX_PENDING_DEVICE_TOOLS = 128
MAX_DEVICE_TOOL_OUTCOMES = 256
MAX_STATUS_ENTRIES = 32
STATUS_MAX_AGE_SECONDS = 120
STATUS_MAX_FUTURE_SECONDS = 30
DEVICE_TOOL_TIMEOUT_SECONDS = 30


class DeviceToolError(ValueError):
    """A bounded, user-safe device tool failure."""

    def __init__(self, code: str, message: str = "The iPhone tool is unavailable.") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class _Pending:
    request: dict[str, Any]
    context_key: tuple[Any, ...]
    fingerprint: str
    future: asyncio.Future[dict[str, Any]]


@dataclass
class _Outcome:
    fingerprint: str
    result: dict[str, Any]


class DeviceToolBridge:
    """Correlate one authenticated Hermes tool call with one selected iPhone."""

    def __init__(
        self,
        link_client: Any | None = None,
        *,
        clock: Callable[[], float] | None = None,
        timeout: float = DEVICE_TOOL_TIMEOUT_SECONDS,
    ) -> None:
        self.link_client = link_client
        self.clock = clock or time.time
        self.timeout = max(20.0, min(60.0, float(timeout)))
        self._pending: dict[str, _Pending] = {}
        self._outcomes: OrderedDict[str, _Outcome] = OrderedDict()
        self._status: OrderedDict[tuple[str, str, int], dict[str, Any]] = OrderedDict()

    def bind_link_client(self, link_client: Any | None) -> None:
        if link_client is not self.link_client:
            self._status.clear()
            for pending in self._pending.values():
                if not pending.future.done():
                    pending.future.set_exception(DeviceToolError("owner_changed"))
        self.link_client = link_client

    def accept_status(
        self,
        status: dict[str, Any],
        *,
        sender_device_id: str,
        sender_epoch: int,
        target_device_id: str,
    ) -> bool:
        try:
            parsed = parse_device_tool_status(
                status,
                sender_device_id=sender_device_id,
                sender_epoch=sender_epoch,
            )
        except ValueError:
            return False
        client = self.link_client
        config = getattr(client, "config", None)
        host_id = getattr(config, "device_id", None)
        now = int(self.clock())
        if (
            not _nonempty_string(host_id)
            or target_device_id != host_id
            or parsed["hostId"] != host_id
            or parsed["sentAt"] < now - STATUS_MAX_AGE_SECONDS
            or parsed["sentAt"] > now + STATUS_MAX_FUTURE_SECONDS
        ):
            return False
        key = (parsed["deviceId"], parsed["hostId"], parsed["authorizationEpoch"])
        previous = self._status.get(key)
        if previous is not None and (
            parsed["sentAt"] < previous["sentAt"] or parsed == previous
        ):
            return False
        self._status[key] = parsed
        self._status.move_to_end(key)
        while len(self._status) > MAX_STATUS_ENTRIES:
            self._status.popitem(last=False)
        if not parsed["available"]:
            self._cancel_pending_for_status(key, reason="authorization_required")
        else:
            enabled = set(parsed["enabled"])
            self._cancel_pending_for_status(
                key,
                reason="authorization_required",
                enabled=enabled,
            )
        return True

    def _cancel_pending_for_status(
        self,
        key: tuple[str, str, int],
        *,
        reason: str,
        enabled: set[str] | None = None,
    ) -> None:
        device_id, host_id, epoch = key
        for pending in self._pending.values():
            request = pending.request
            capability = str(request.get("operation", "")).split(".", 1)[0]
            if (
                request.get("deviceId") == device_id
                and request.get("hostId") == host_id
                and request.get("authorizationEpoch") == epoch
                and (enabled is None or capability not in enabled)
                and not pending.future.done()
            ):
                pending.future.set_exception(DeviceToolError(reason))

    def accept_result(
        self,
        result: dict[str, Any],
        *,
        sender_device_id: str,
        sender_epoch: int,
        target_device_id: str,
    ) -> bool:
        try:
            parsed = parse_device_tool_result(
                result,
                sender_device_id=sender_device_id,
                sender_epoch=sender_epoch,
            )
        except ValueError:
            return False
        client = self.link_client
        config = getattr(client, "config", None)
        host_id = getattr(config, "device_id", None)
        if (
            not _nonempty_string(host_id)
            or target_device_id != host_id
            or parsed["hostId"] != host_id
        ):
            return False
        pending = self._pending.get(parsed["requestId"])
        if pending is None or not _same_coordinates(pending.request, parsed):
            return False
        if not pending.future.done():
            pending.future.set_result(parsed)
        return True

    async def execute(
        self,
        *,
        context: Any,
        device_id: str,
        host_id: str,
        authorization_epoch: int,
        session_id: str,
        agent_id: str,
        turn_id: str,
        tool_call_id: str,
        operation: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            self._assert_context(
                context,
                device_id=device_id,
                host_id=host_id,
                authorization_epoch=authorization_epoch,
                session_id=session_id,
                agent_id=agent_id,
                turn_id=turn_id,
            )
            if not isinstance(tool_call_id, str) or not tool_call_id:
                raise DeviceToolError("call_identity_missing")
            client = self.link_client
            if client is None or not bool(getattr(client, "connected", False)):
                raise DeviceToolError("unavailable")
            config = getattr(client, "config", None)
            config_host_id = getattr(config, "device_id", None)
            if (
                config is None
                or not _nonempty_string(config_host_id)
                or config_host_id != host_id
            ):
                raise DeviceToolError("owner_changed")
            status = self._status.get((device_id, host_id, authorization_epoch))
            capability = operation.split(".", 1)[0]
            if status is None or not status.get("available") or capability not in status.get("enabled", []):
                raise DeviceToolError("authorization_required")
            if DIRECTED_FRAMES_CAPABILITY not in set(getattr(client, "peer_capabilities", ())):
                raise DeviceToolError("directed_frames_unavailable")
            request_id = _stable_request_id(
                device_id, authorization_epoch, session_id, agent_id, turn_id, tool_call_id,
            )
            fingerprint = _request_fingerprint(operation, arguments)
            existing = self._pending.get(request_id)
            if existing is not None:
                if existing.fingerprint != fingerprint:
                    raise DeviceToolError("request_conflict")
                return await self._await_pending(
                    existing,
                    context=context,
                    client=client,
                    device_id=device_id,
                    host_id=host_id,
                    authorization_epoch=authorization_epoch,
                    session_id=session_id,
                    agent_id=agent_id,
                    turn_id=turn_id,
                    capability=capability,
                )
            outcome = self._outcomes.get(request_id)
            if outcome is not None:
                if outcome.fingerprint != fingerprint:
                    raise DeviceToolError("request_conflict")
                self._outcomes.move_to_end(request_id)
                return dict(outcome.result)
            sent_at = int(self.clock())
            expires_at = sent_at + int(self.timeout)
            request = device_tool_request(
                request_id=request_id,
                device_id=device_id,
                host_id=host_id,
                authorization_epoch=authorization_epoch,
                session_id=session_id,
                agent_id=agent_id,
                turn_id=turn_id,
                operation=operation,
                arguments=arguments,
                sent_at=sent_at,
                expires_at=expires_at,
            )
            encoded_size = len(json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            if encoded_size > MAX_DEVICE_TOOL_PAYLOAD_BYTES:
                raise DeviceToolError("request_too_large")
            if len(json.dumps(request["arguments"], ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_DEVICE_TOOL_ARGUMENT_BYTES:
                raise DeviceToolError("request_too_large")
            if len(self._pending) >= MAX_PENDING_DEVICE_TOOLS:
                raise DeviceToolError("busy")
            loop = asyncio.get_running_loop()
            pending = _Pending(
                request=request,
                context_key=_context_key(context),
                fingerprint=fingerprint,
                future=loop.create_future(),
            )
            self._pending[request_id] = pending
            try:
                self._assert_context(
                    context,
                    device_id=device_id,
                    host_id=host_id,
                    authorization_epoch=authorization_epoch,
                    session_id=session_id,
                    agent_id=agent_id,
                    turn_id=turn_id,
                )
                if self.link_client is not client:
                    raise DeviceToolError("owner_changed")
                # This is one send. A timeout or uncertain write is returned to the
                # model for reconciliation; this bridge never submits a second request.
                await client.send_payload(
                    request,
                    target_device_id=device_id,
                    preserve_pending_on_failure=True,
                )
                return await self._await_pending(
                    pending,
                    context=context,
                    client=client,
                    device_id=device_id,
                    host_id=host_id,
                    authorization_epoch=authorization_epoch,
                    session_id=session_id,
                    agent_id=agent_id,
                    turn_id=turn_id,
                    capability=capability,
                )
            except DeviceToolError as exc:
                result = _failed_result(request_id, exc.code)
                self._record_outcome(request_id, fingerprint, result, operation)
                return result
            except Exception:
                # Sending may have crossed the transport boundary. Keep the
                # request identity tombstoned and never submit an uncertain
                # write a second time.
                uncertain = _failed_result(request_id, "delivery_uncertain")
                self._record_outcome(request_id, fingerprint, uncertain, operation)
                return uncertain
            finally:
                if self._pending.get(request_id) is pending:
                    self._pending.pop(request_id, None)
        except DeviceToolError as exc:
            return _failed_result(None, exc.code)
        except (TypeError, ValueError):
            return _failed_result(None, "invalid_arguments")

    async def _await_pending(
        self,
        pending: _Pending,
        *,
        context: Any,
        client: Any,
        device_id: str,
        host_id: str,
        authorization_epoch: int,
        session_id: str,
        agent_id: str,
        turn_id: str,
        capability: str,
    ) -> dict[str, Any]:
        request_id = pending.request["requestId"]
        try:
            remaining = max(
                0.001,
                min(float(pending.request["expiresAt"] - int(self.clock())), self.timeout),
            )
            result = await asyncio.wait_for(asyncio.shield(pending.future), timeout=remaining)
            self._assert_context(
                context,
                device_id=device_id,
                host_id=host_id,
                authorization_epoch=authorization_epoch,
                session_id=session_id,
                agent_id=agent_id,
                turn_id=turn_id,
            )
            if self.link_client is not client:
                raise DeviceToolError("owner_changed")
            current_status = self._status.get((device_id, host_id, authorization_epoch))
            if current_status is None or not current_status.get("available") or capability not in current_status.get("enabled", []):
                raise DeviceToolError("authorization_required")
            self._record_outcome(request_id, pending.fingerprint, result, pending.request["operation"])
            return result
        except asyncio.TimeoutError:
            result = _failed_result(request_id, "timeout")
            self._record_outcome(request_id, pending.fingerprint, result, pending.request["operation"])
            return result
        except DeviceToolError as exc:
            result = _failed_result(request_id, exc.code)
            self._record_outcome(request_id, pending.fingerprint, result, pending.request["operation"])
            return result
        except Exception:
            result = _failed_result(request_id, "delivery_uncertain")
            self._record_outcome(request_id, pending.fingerprint, result, pending.request["operation"])
            return result
        finally:
            if self._pending.get(request_id) is pending:
                self._pending.pop(request_id, None)

    def _record_outcome(
        self,
        request_id: str,
        fingerprint: str,
        result: dict[str, Any],
        operation: str,
    ) -> None:
        # Reads may contain private health, calendar, or reminder values. They
        # are returned to the active caller only and never retained for a
        # later retry. Mutation replay retains only reconciliation metadata.
        if operation.endswith(".read") or operation.endswith(".list"):
            return
        safe = dict(result)
        payload = result.get("payload")
        if isinstance(payload, dict):
            safe["payload"] = {
                key: payload[key]
                for key in ("id", "revision", "deleted")
                if key in payload
            }
        else:
            safe["payload"] = {}
        self._outcomes[request_id] = _Outcome(fingerprint=fingerprint, result=safe)
        self._outcomes.move_to_end(request_id)
        while len(self._outcomes) > MAX_DEVICE_TOOL_OUTCOMES:
            self._outcomes.popitem(last=False)

    @staticmethod
    def _assert_context(
        context: Any,
        *,
        device_id: str,
        host_id: str,
        authorization_epoch: int,
        session_id: str,
        agent_id: str,
        turn_id: str,
    ) -> None:
        attributes = getattr(context, "attributes", None)
        if (
            getattr(context, "source", None) != "loopdy_link"
            or not _nonempty_string(device_id)
            or not _nonempty_string(getattr(context, "owner_id", None))
            or getattr(context, "owner_id", None) != device_id
            or not _nonempty_string(agent_id)
            or not _nonempty_string(getattr(context, "scope_id", None))
            or getattr(context, "scope_id", None) != agent_id
            or type(authorization_epoch) is not int
            or authorization_epoch < 1
            or type(getattr(context, "authorization_epoch", None)) is not int
            or getattr(context, "authorization_epoch", None) < 1
            or getattr(context, "authorization_epoch", None) != authorization_epoch
            or not _nonempty_string(host_id)
            or not isinstance(attributes, Mapping)
            or set(attributes) != {"host_id"}
            or attributes.get("host_id") != host_id
            or not _nonempty_string(session_id)
            or not _nonempty_string(turn_id)
        ):
            raise DeviceToolError("owner_changed")


def _context_key(context: Any) -> tuple[Any, ...]:
    return tuple(getattr(context, "owner_key", (getattr(context, "owner_id", ""),)))


def _same_coordinates(request: dict[str, Any], result: dict[str, Any]) -> bool:
    return all(request.get(key) == result.get(key) for key in (
        "requestId", "deviceId", "hostId", "authorizationEpoch", "sessionId", "agentId", "turnId", "operation",
    ))


def _stable_request_id(*parts: Any) -> str:
    canonical = json.dumps(parts, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _request_fingerprint(operation: str, arguments: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"operation": operation, "arguments": arguments},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _failed_result(request_id: str | None, code: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "version": 1,
        "type": "device.tool.result",
        "status": "failed",
        "code": code,
        "payload": {},
    }
    if request_id is not None:
        result["requestId"] = request_id
    return result


def _strict_object(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


def _list_properties(ids_name: str) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "operation": {"type": "string", "enum": ["list", "create", "update", "delete"]},
        "start": {"type": "string", "format": "date-time"},
        "end": {"type": "string", "format": "date-time"},
        "timeZone": {"type": "string", "minLength": 1, "maxLength": 128},
        "limit": {"type": "integer", "minimum": 1, "maximum": 200},
        "completed": {"type": "boolean"},
        "includeUndated": {"type": "boolean"},
        ids_name: {"type": "array", "minItems": 1, "maxItems": 50, "items": {"type": "string", "minLength": 1, "maxLength": 512}},
    }
    properties.update(_mutation_properties())
    if ids_name == "calendarIDs":
        for field in ("dueDate", "startDate", "listID", "priority", "completed", "includeUndated"):
            properties.pop(field, None)
    else:
        for field in ("calendarID", "location", "url", "span", "occurrenceStart"):
            properties.pop(field, None)
    return properties


def _mutation_properties() -> dict[str, Any]:
    return {
        "title": {"type": "string", "minLength": 1, "maxLength": 4_000},
        "id": {"type": "string", "minLength": 1, "maxLength": 512},
        "expectedRevision": {"type": "string", "minLength": 1, "maxLength": 512},
        "start": {"type": "string", "format": "date-time"},
        "end": {"type": "string", "format": "date-time"},
        "dueDate": {"type": "string", "format": "date-time"},
        "startDate": {"type": "string", "format": "date-time"},
        "calendarID": {"type": "string", "minLength": 1, "maxLength": 512},
        "listID": {"type": "string", "minLength": 1, "maxLength": 512},
        "location": {"type": "string", "maxLength": 4_000},
        "notes": {"type": "string", "maxLength": 4_000},
        "url": {"type": "string", "maxLength": 4_000},
        "priority": {"type": "integer", "minimum": 0, "maximum": 9},
        "completed": {"type": "boolean"},
        "span": {"type": "string", "enum": ["thisEvent"]},
        "occurrenceStart": {"type": "string", "format": "date-time"},
    }


def _handler(*, bridge: DeviceToolBridge | None, fixed_operation: str | None = None, tool_prefix: str | None = None):
    async def handle(payload: Any, **kwargs: Any) -> str:
        if bridge is None:
            raise ValueError("verified iPhone tool context is unavailable")
        if not isinstance(payload, dict):
            raise ValueError("iPhone tool arguments must be an object")
        context = kwargs.get("tool_execution_context")
        if context is None:
            raise ValueError("verified iPhone tool context is unavailable")
        operation = fixed_operation
        arguments = dict(payload)
        if operation is None:
            selected = arguments.pop("operation", None)
            if not isinstance(selected, str) or selected not in {"list", "create", "update", "delete"}:
                raise ValueError("iPhone tool operation is invalid")
            operation = selected
        elif "operation" in arguments:
            raise ValueError("iPhone tool operation is invalid")
        prefix = "health" if fixed_operation == "health.read" else tool_prefix or kwargs.get("tool_name", "iphone_calendar").removeprefix("iphone_")
        if fixed_operation is None:
            operation = f"{prefix}.{operation}"
        attributes = getattr(context, "attributes", None)
        session_id = kwargs.get("session_id")
        turn_id = kwargs.get("turn_id")
        agent_id = getattr(context, "scope_id", "")
        device_id = getattr(context, "owner_id", "")
        host_id = attributes.get("host_id") if isinstance(attributes, Mapping) else None
        tool_call_id = kwargs.get("tool_call_id")
        if not all(
            _nonempty_string(value)
            for value in (session_id, turn_id, agent_id, device_id, host_id, tool_call_id)
        ):
            raise ValueError("verified iPhone tool context is incomplete")
        result = await bridge.execute(
            context=context,
            device_id=device_id,
            host_id=host_id,
            authorization_epoch=getattr(context, "authorization_epoch", None),
            session_id=session_id,
            agent_id=agent_id,
            turn_id=turn_id,
            tool_call_id=tool_call_id,
            operation=operation,
            arguments=arguments,
        )
        return json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return handle


def register(ctx: Any, *, bridge: DeviceToolBridge | None = None) -> None:
    health_schema = _strict_object(
        {
            "start": {"type": "string", "format": "date-time"},
            "end": {"type": "string", "format": "date-time"},
            "timeZone": {"type": "string", "minLength": 1, "maxLength": 128},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            "types": {"type": "array", "minItems": 1, "maxItems": len(HEALTH_TYPES), "items": {"type": "string", "enum": list(HEALTH_TYPES)}},
        },
        ["start", "end", "timeZone"],
    )
    calendar_schema = _strict_object(_list_properties("calendarIDs"), ["operation"])
    reminder_schema = _strict_object(_list_properties("listIDs"), ["operation"])
    definitions = (
        (
            "iphone_health",
            "Read bounded raw HealthKit samples from an authenticated iPhone with Health permissions enabled and the phone available in the foreground. Inspect coverage and truncation; an empty or denied result does not prove zero values or full-period totals.",
            health_schema,
            _handler(bridge=bridge, fixed_operation="health.read"),
        ),
        (
            "iphone_calendar",
            "List calendar items on an authenticated iPhone with Calendar permission enabled, then use an exact returned id and expectedRevision for changes. For one recurring event, preserve occurrenceStart and span=thisEvent. If a write is uncertain, reconcile by reading before retrying and never blindly repeat it.",
            calendar_schema,
            _handler(bridge=bridge, tool_prefix="calendar"),
        ),
        (
            "iphone_reminders",
            "List reminders on an authenticated iPhone with Reminders permission enabled, then use an exact returned id and expectedRevision for changes. If a write is uncertain, reconcile by reading before retrying and never blindly repeat it.",
            reminder_schema,
            _handler(bridge=bridge, tool_prefix="reminders"),
        ),
    )
    for name, description, schema, handler in definitions:
        ctx.register_tool(name=name, toolset="loopdy", schema={"name": name, "description": description, "parameters": schema}, handler=handler, is_async=True)



def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


__all__ = ["DeviceToolBridge", "DeviceToolError", "register"]
