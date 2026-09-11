"""Disposable current presentation, separate from canonical Hermes history.

Only explicit profile/session coordinates are accepted. No filesystem, network,
private Hermes handles, or transcript identity heuristics live in this cache.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import json
import threading
from typing import Any

from .session_stream import SessionStreamHub


@dataclass
class _Snapshot:
    cursor: int = 0
    size: int = 0
    complete: bool = True
    events: OrderedDict[str, bytes] = field(default_factory=OrderedDict)


class SessionPresentationStore:
    def __init__(self, hub: SessionStreamHub, *, maximum_sessions: int = 64,
                 maximum_events: int = 128, maximum_bytes: int = 262_144):
        if any(type(v) is not int or v <= 0 for v in (maximum_sessions, maximum_events, maximum_bytes)):
            raise ValueError("Invalid presentation bounds")
        self.hub = hub
        self.maximum_sessions = maximum_sessions
        self.maximum_events = maximum_events
        self.maximum_bytes = min(maximum_bytes, hub.maximum_bytes)
        self._lock = threading.RLock()
        self._sessions: OrderedDict[tuple[str, str], _Snapshot] = OrderedDict()
        self._closed = False

    @staticmethod
    def _key(payload: dict[str, Any]) -> str:
        kind = payload.get("type")
        identifier = payload.get("messageId") if kind == "assistant.message" else payload.get("eventId")
        if kind in {"assistant.message", "activity.event"}:
            if not isinstance(identifier, str) or not identifier or len(identifier) > 180:
                raise ValueError("Presentation has no stable identity")
            return f"{kind}:{identifier}"
        # Latest scoped context/roster/todo/card state replaces the same slot.
        if kind == "generative.ui":
            identifier = payload.get("id") or payload.get("cardId")
            if not isinstance(identifier, str) or not identifier or len(identifier) > 180:
                raise ValueError("Presentation card has no stable identity")
            return f"{kind}:{identifier}"
        return str(kind)

    def publish(self, *, agent_id: str, payload: dict[str, Any]) -> int:
        session_id = payload.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("Presentation has no session coordinate")
        key = self._key(payload)
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"),
                             sort_keys=True, allow_nan=False).encode("utf-8")
        if len(encoded) > self.maximum_bytes:
            with self._lock:
                scope = (agent_id, session_id)
                if scope not in self._sessions and len(self._sessions) >= self.maximum_sessions:
                    self._sessions.popitem(last=False)
                snapshot = self._sessions.setdefault(scope, _Snapshot())
                previous = snapshot.events.pop(key, None)
                if previous is not None:
                    snapshot.size -= len(previous)
                snapshot.complete = False
                snapshot.cursor = self.hub.reset(agent_id=agent_id, session_id=session_id)
            raise ValueError("Current presentation exceeds its bounded snapshot")
        with self._lock:
            if self._closed:
                raise RuntimeError("Presentation owner retired")
            # Publish and snapshot install share one short lock. A returned
            # coverage cursor therefore cannot get ahead of snapshot contents.
            cursor = self.hub.publish(agent_id=agent_id, session_id=session_id, payload=payload)
            scope = (agent_id, session_id)
            snapshot = self._sessions.get(scope)
            if snapshot is None:
                if len(self._sessions) >= self.maximum_sessions:
                    self._sessions.popitem(last=False)
                snapshot = _Snapshot()
                self._sessions[scope] = snapshot
            self._sessions.move_to_end(scope)
            previous = snapshot.events.get(key)
            if previous is not None:
                snapshot.size -= len(previous)
            snapshot.events[key] = encoded
            snapshot.size += len(encoded)
            while len(snapshot.events) > self.maximum_events or snapshot.size > self.maximum_bytes:
                _, retired = snapshot.events.popitem(last=False)
                snapshot.size -= len(retired)
                snapshot.complete = False
            snapshot.cursor = cursor
            return cursor

    def snapshot(self, *, agent_id: str, session_id: str) -> dict[str, Any]:
        with self._lock:
            value = self._sessions.get((agent_id, session_id))
            if value is None:
                return {"coverageCursor": 0, "events": [], "complete": True}
            return {"coverageCursor": value.cursor,
                    "events": [json.loads(event) for event in value.events.values()],
                    "complete": value.complete}

    def retire(self, *, agent_id: str, session_id: str) -> None:
        with self._lock:
            self._sessions.pop((agent_id, session_id), None)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._sessions.clear()
