"""Bounded transient presentation feeds for authenticated Link sessions.

The hub keeps no history of its own. Each active subscription retains only the
events published after it subscribed, within its private event and byte limits.
Callers must reload authoritative session state after ``StreamResetRequired``.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Any


# These are the presentation payloads built by link_contracts.py. Command,
# acknowledgement, approval, attachment, and device-operation envelopes are
# deliberately absent because they require reliable delivery semantics.
PRESENTATION_EVENT_TYPES = frozenset(
    {
        "assistant.message",
        "activity.event",
        "session.context",
        "session.todos",
        "session.subagents",
        "generative.ui",
    }
)

_SCOPE = re.compile(r"^[A-Za-z0-9_-]+$")


class StreamResetRequired(RuntimeError):
    """The subscription overflowed and must reload authoritative session state."""

    def __init__(self, *, process_epoch: str, cursor: int) -> None:
        self.process_epoch = process_epoch
        self.cursor = cursor
        super().__init__(
            f"session stream overflowed at {process_epoch}:{cursor}; state reset required"
        )


class StreamClosed(RuntimeError):
    """The session stream subscription has been explicitly closed."""


@dataclass(frozen=True)
class _EncodedEvent:
    process_epoch: str
    cursor: int
    payload: bytes

    def wire_value(self) -> dict[str, Any]:
        # Decode for every receiver so callers never share mutable payload data.
        return {
            "processEpoch": self.process_epoch,
            "cursor": self.cursor,
            "payload": json.loads(self.payload),
        }


class SessionStreamSubscription:
    """One independently bounded view of a single agent/session live feed."""

    def __init__(
        self,
        *,
        hub: SessionStreamHub,
        identifier: int,
        agent_id: str,
        session_id: str,
        cursor: int,
    ) -> None:
        self._hub = hub
        self._identifier = identifier
        self._agent_id = agent_id
        self._session_id = session_id
        self._cursor = cursor
        self._events: deque[_EncodedEvent] = deque()
        self._retained_bytes = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._event: asyncio.Event | None = None
        self._wake_scheduled = False
        self._notification_set = False
        self._closed = False
        self._reset_cursor: int | None = None

    @property
    def cursor(self) -> int:
        with self._hub._lock:
            return self._cursor

    async def receive(self) -> dict[str, Any]:
        """Wait for and return the next event, or raise the terminal feed state.

        Cancelling this coroutine does not close or poison the subscription; a
        later receive can consume the same buffered event or continue waiting.
        """

        loop = asyncio.get_running_loop()
        while True:
            encoded: _EncodedEvent | None = None
            with self._hub._lock:
                self._bind_loop_locked(loop)
                if self._reset_cursor is not None:
                    raise StreamResetRequired(
                        process_epoch=self._hub.process_epoch,
                        cursor=self._reset_cursor,
                    )
                if self._closed:
                    raise StreamClosed("session stream subscription is closed")
                if self._events:
                    encoded = self._events.popleft()
                    self._retained_bytes -= len(encoded.payload)
                    self._cursor = encoded.cursor
                    if not self._events:
                        self._clear_notification_locked()
                else:
                    self._clear_notification_locked()
                    assert self._event is not None
                    notification = self._event
            if encoded is not None:
                return encoded.wire_value()
            await notification.wait()

    def close(self) -> None:
        """Close this subscription, discard retained events, and wake receivers."""

        self._hub._close(self)

    def _bind_loop_locked(self, loop: asyncio.AbstractEventLoop) -> None:
        if self._loop is None:
            self._loop = loop
            self._event = asyncio.Event()
        elif self._loop is not loop:
            raise RuntimeError("session stream subscription belongs to another event loop")

    def _clear_notification_locked(self) -> None:
        if self._event is not None:
            self._event.clear()
        self._notification_set = False


class SessionStreamHub:
    """Thread-safe publisher for bounded, disposable presentation subscriptions."""

    def __init__(
        self,
        *,
        maximum_events: int = 128,
        maximum_bytes: int = 262_144,
        maximum_subscriptions: int = 64,
    ) -> None:
        for name, value in (
            ("maximum_events", maximum_events),
            ("maximum_bytes", maximum_bytes),
            ("maximum_subscriptions", maximum_subscriptions),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self.maximum_events = maximum_events
        self.maximum_bytes = maximum_bytes
        self.maximum_subscriptions = maximum_subscriptions
        self.process_epoch = uuid.uuid4().hex
        self._lock = threading.RLock()
        self._cursor = 0
        self._next_identifier = 0
        self._subscriptions: dict[int, SessionStreamSubscription] = {}

    @property
    def subscription_count(self) -> int:
        with self._lock:
            return len(self._subscriptions)

    def subscribe(
        self, *, agent_id: str, session_id: str
    ) -> SessionStreamSubscription:
        agent_id = _scope(agent_id, "agent_id", maximum=96)
        session_id = _scope(session_id, "session_id", maximum=180)
        with self._lock:
            if len(self._subscriptions) >= self.maximum_subscriptions:
                raise RuntimeError("session stream subscription limit reached")
            self._next_identifier += 1
            subscription = SessionStreamSubscription(
                hub=self,
                identifier=self._next_identifier,
                agent_id=agent_id,
                session_id=session_id,
                cursor=self._cursor,
            )
            self._subscriptions[subscription._identifier] = subscription
            return subscription

    def publish(
        self, *, agent_id: str, session_id: str, payload: dict[str, Any]
    ) -> int:
        """Publish one validated presentation event and return its process cursor.

        The payload is encoded exactly once before taking the publication lock.
        Every matching subscriber retains the same immutable byte string and
        receives a separately decoded value. A slow subscriber is reset and
        removed without affecting any other subscriber.
        """

        agent_id = _scope(agent_id, "agent_id", maximum=96)
        session_id = _scope(session_id, "session_id", maximum=180)
        encoded_payload = self._encode_payload(
            agent_id=agent_id, session_id=session_id, payload=payload
        )
        with self._lock:
            self._cursor += 1
            encoded = _EncodedEvent(
                process_epoch=self.process_epoch,
                cursor=self._cursor,
                payload=encoded_payload,
            )
            for subscription in tuple(self._subscriptions.values()):
                if (
                    subscription._agent_id != agent_id
                    or subscription._session_id != session_id
                ):
                    continue
                if (
                    len(subscription._events) >= self.maximum_events
                    or subscription._retained_bytes + len(encoded_payload)
                    > self.maximum_bytes
                ):
                    self._reset_locked(subscription, cursor=encoded.cursor)
                    continue
                subscription._events.append(encoded)
                subscription._retained_bytes += len(encoded_payload)
                self._schedule_wake_locked(subscription)
            return encoded.cursor

    def _encode_payload(
        self, *, agent_id: str, session_id: str, payload: dict[str, Any]
    ) -> bytes:
        if type(payload) is not dict:
            raise ValueError("session stream payload must be a JSON object")
        event_type = payload.get("type")
        if not isinstance(event_type, str) or event_type not in PRESENTATION_EVENT_TYPES:
            raise ValueError("session stream payload type is not transient presentation")
        if "agentId" in payload and payload["agentId"] != agent_id:
            raise ValueError("session stream payload agentId does not match its scope")
        if "sessionId" in payload and payload["sessionId"] != session_id:
            raise ValueError("session stream payload sessionId does not match its scope")
        try:
            encoded = json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("session stream payload is not valid JSON") from exc
        if len(encoded) > self.maximum_bytes:
            raise ValueError("session stream payload exceeds maximum_bytes")
        return encoded

    def _reset_locked(
        self, subscription: SessionStreamSubscription, *, cursor: int
    ) -> None:
        self._subscriptions.pop(subscription._identifier, None)
        subscription._events.clear()
        subscription._retained_bytes = 0
        subscription._reset_cursor = cursor
        subscription._closed = True
        self._schedule_wake_locked(subscription)

    def _close(self, subscription: SessionStreamSubscription) -> None:
        with self._lock:
            if subscription._closed:
                return
            self._subscriptions.pop(subscription._identifier, None)
            subscription._events.clear()
            subscription._retained_bytes = 0
            subscription._closed = True
            self._schedule_wake_locked(subscription)

    def _schedule_wake_locked(self, subscription: SessionStreamSubscription) -> None:
        loop = subscription._loop
        if (
            loop is None
            or subscription._event is None
            or subscription._notification_set
            or subscription._wake_scheduled
        ):
            return
        subscription._wake_scheduled = True
        try:
            loop.call_soon_threadsafe(self._deliver_wake, subscription)
        except RuntimeError:
            subscription._wake_scheduled = False

    def _deliver_wake(self, subscription: SessionStreamSubscription) -> None:
        with self._lock:
            subscription._wake_scheduled = False
            notification = subscription._event
            if notification is None or subscription._notification_set:
                return
            if (
                subscription._events
                or subscription._closed
                or subscription._reset_cursor is not None
            ):
                subscription._notification_set = True
                notification.set()


def _scope(value: Any, name: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or not _SCOPE.fullmatch(value)
    ):
        raise ValueError(f"session stream {name} is invalid")
    return value


__all__ = [
    "PRESENTATION_EVENT_TYPES",
    "SessionStreamHub",
    "SessionStreamSubscription",
    "StreamClosed",
    "StreamResetRequired",
]
