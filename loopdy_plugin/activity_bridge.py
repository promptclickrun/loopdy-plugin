"""Thread-safe Hermes lifecycle projection onto the existing Loopdy Link socket."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import shlex
import sqlite3
import threading
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from typing import Any

from .generated_media import record_generated_media_call
from .link_contracts import (
    activity_event,
    session_context,
    session_subagents,
    session_todos,
)


logger = logging.getLogger("hermes.plugins.loopdy.activity")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]+$")
_INTERNAL_TURN = re.compile(r"^[A-Za-z0-9_:-]+$")

_TOOL_TITLES = {
    "browser": "Using the browser",
    "clarify": "Waiting for your answer",
    "delegate": "Starting a subagent",
    "read_file": "Reading a file",
    "terminal": "Running a command",
    "web_search": "Searching the web",
    "weather": "Checking weather",
    "write_file": "Editing a file",
}


class LinkActivityBroker:
    """Moves synchronous hook events onto one bounded Link sender task."""

    maximum_queue_size = 256
    maximum_active_turns = 128
    maximum_bound_sessions = 256
    context_poll_interval_seconds = 1.0

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._queue: asyncio.Queue[dict[str, Any]] | None = None
        self._sender: Callable[[dict[str, Any]], Awaitable[Any]] | None = None
        self._live_activity_sender: Callable[[dict[str, Any]], Awaitable[Any]] | None = None
        self._drain_task: asyncio.Task[None] | None = None
        self._context_task: asyncio.Task[None] | None = None
        self._active: OrderedDict[tuple[str, str], str] = OrderedDict()
        self._bound_sessions: OrderedDict[str, str] = OrderedDict()
        self._api_usage: OrderedDict[tuple[str, str], dict[str, int]] = OrderedDict()
        self._api_usage_order: dict[tuple[str, str], dict[str, Any]] = {}
        self._child_routes: OrderedDict[str, tuple[str, str, str]] = OrderedDict()
        self._handoffs_by_process: OrderedDict[str, tuple[str, str, str]] = OrderedDict()

        self._session_resolver: Callable[[str], Any] | None = None
        self._context_provider: Callable[[str], dict[str, Any] | None] | None = None
        self._context_signatures: dict[tuple[str, str], tuple[Any, ...]] = {}
        self._context_updated_at: dict[tuple[str, str], int] = {}
        self._status_lock = threading.Lock()
        self._goal_provider: Callable[[str], dict[str, Any] | None] | None = None
        self._goal_snapshots: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._goal_published_at: dict[str, float] = {}
        self._todo_signatures: OrderedDict[str, str] = OrderedDict()
        self._subagent_rosters: OrderedDict[
            str, OrderedDict[str, dict[str, Any]]
        ] = OrderedDict()
        self._subagent_signatures: OrderedDict[str, str] = OrderedDict()
        self._live_state: dict[str, dict[str, Any]] = {}

    async def attach(
        self,
        sender: Callable[[dict[str, Any]], Awaitable[Any]],
        *,
        live_activity_sender: Callable[[dict[str, Any]], Awaitable[Any]] | None = None,
    ) -> None:
        loop = asyncio.get_running_loop()
        with self._lock:
            if self._loop is loop and self._drain_task is not None:
                self._sender = sender
                self._live_activity_sender = live_activity_sender
                return
            self._loop = loop
            self._queue = asyncio.Queue(maxsize=self.maximum_queue_size)
            self._sender = sender
            self._live_activity_sender = live_activity_sender
            self._drain_task = loop.create_task(
                self._drain(), name="loopdy-link-activity"
            )
            self._context_task = loop.create_task(
                self._poll_context_windows(), name="loopdy-link-context"
            )

    async def detach(self) -> None:
        with self._status_lock:
            with self._lock:
                task = self._drain_task
                context_task = self._context_task
                self._loop = None
                self._queue = None
                self._sender = None
                self._live_activity_sender = None
                self._drain_task = None
                self._context_task = None
                self._active.clear()
                self._bound_sessions.clear()
                self._api_usage.clear()
                self._api_usage_order.clear()
                self._child_routes.clear()
                self._handoffs_by_process.clear()

                self._context_signatures.clear()
                self._context_updated_at.clear()
                self._live_state.clear()
            self._todo_signatures.clear()
            self._goal_snapshots.clear()
            self._goal_published_at.clear()
            self._subagent_rosters.clear()
            self._subagent_signatures.clear()
        tasks = tuple(item for item in (task, context_task) if item is not None)
        for active_task in tasks:
            active_task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def activate(
        self,
        session_id: str,
        turn_id: str,
        *,
        link_session_id: str,
    ) -> None:
        coordinate = (session_id, turn_id)
        self.bind_link_session(session_id, link_session_id)
        with self._lock:
            self._active.pop(coordinate, None)
            self._active[coordinate] = link_session_id
            while len(self._active) > self.maximum_active_turns:
                self._active.popitem(last=False)

    def bind_link_session(self, session_id: str, link_session_id: str) -> None:
        """Bind one verified Link chat to its canonical Hermes conversation."""

        hermes_session = _coordinate(session_id, 128)
        link_session = _coordinate(link_session_id, 128)
        if not hermes_session or not link_session:
            return
        with self._lock:
            previous_route = self._bound_sessions.get(hermes_session)
            if previous_route is not None and previous_route != link_session:
                self._clear_api_usage_locked(hermes_session)
            self._bound_sessions.pop(hermes_session, None)
            self._bound_sessions[hermes_session] = link_session
            while len(self._bound_sessions) > self.maximum_bound_sessions:
                evicted_session, _ = self._bound_sessions.popitem(last=False)
                self._clear_api_usage_locked(evicted_session)

    def record_api_usage(self, **payload: Any) -> None:
        """Retain only the latest public usage snapshot for a bound session/model."""

        session_id = _coordinate(payload.get("session_id"), 128)
        model = _model_coordinate(payload.get("model"))
        usage = _api_usage_projection(payload.get("usage"))
        if not session_id or not model:
            return
        key = (session_id, model)
        order = _api_usage_event_order(payload)
        turn_id = payload.get("turn_id")
        with self._lock:
            if session_id not in self._bound_sessions:
                return
            previous_order = self._api_usage_order.get(key)
            if previous_order is not None and _api_usage_is_stale(
                previous_order, order
            ):
                return
            self._api_usage.pop(key, None)
            # An unavailable or rejected latest snapshot deliberately replaces
            # older numbers with absence; an empty dict is the bounded marker.
            self._api_usage[key] = usage or {}
            self._api_usage_order[key] = order
            while len(self._api_usage) > self.maximum_bound_sessions:
                evicted_key, _ = self._api_usage.popitem(last=False)
                self._api_usage_order.pop(evicted_key, None)
            active_turn = (
                turn_id.strip()
                if isinstance(turn_id, str) and turn_id.strip()
                else ""
            )
            should_publish = bool(
                active_turn and (session_id, active_turn) in self._active
            )
        if should_publish:
            self.publish_context_window(session_id, active_turn, force=True)

    def usage_snapshot(self, session_id: Any, model: Any) -> dict[str, int] | None:
        """Return a copy only for the exact currently bound session and model."""

        session = _coordinate(session_id, 128)
        canonical_model = _model_coordinate(model)
        if not session or not canonical_model:
            return None
        key = (session, canonical_model)
        with self._lock:
            if session not in self._bound_sessions:
                return None
            usage = self._api_usage.get(key)
            if not usage:
                return None
            self._api_usage.move_to_end(key)
            return dict(usage)

    def reset_api_usage(
        self,
        session_id: Any = None,
        *,
        old_session_id: Any = None,
        new_session_id: Any = None,
        **_payload: Any,
    ) -> None:
        """Clear usage at a public boundary without changing existing chat routes."""

        old_session = _coordinate(old_session_id, 128) or _coordinate(session_id, 128)
        new_session = _coordinate(new_session_id, 128)
        with self._lock:
            if old_session:
                self._clear_api_usage_locked(old_session)
            if new_session and new_session != old_session:
                self._clear_api_usage_locked(new_session)

    def _clear_api_usage_locked(self, session_id: str) -> None:
        for key in tuple(self._api_usage):
            if key[0] == session_id:
                self._api_usage.pop(key, None)
                self._api_usage_order.pop(key, None)

    def register_child_route(
        self, child_session_id: str, parent_link_session_id: str, parent_turn_id: str
    ) -> None:
        child = _coordinate(child_session_id, 180)
        parent = _coordinate(parent_link_session_id, 128)
        turn = _turn_coordinate(parent_turn_id)
        if not child or not parent or not turn:
            return
        with self._lock:
            self._child_routes.pop(child, None)
            self._child_routes[child] = (parent, child, turn)
            while len(self._child_routes) > self.maximum_bound_sessions:
                self._child_routes.popitem(last=False)

    def child_route(self, session_id: str) -> tuple[str, str, str] | None:
        child = _coordinate(session_id, 180)
        if not child:
            return None
        with self._lock:
            route = self._child_routes.get(child)
            if route is not None:
                self._child_routes.move_to_end(child)
            return route

    def remove_child_route(self, session_id: str) -> None:
        child = _coordinate(session_id, 180)
        if child:
            with self._lock:
                self._child_routes.pop(child, None)

    def bind_handoff_process(
        self,
        process_id: str,
        link_session_id: str,
        target: str,
        sender: str,
    ) -> None:
        process = _coordinate(process_id, 180)
        link_session = _coordinate(link_session_id, 128)
        target_member = _coordinate(target, 96)
        sender_member = _coordinate(sender, 96)
        if not all((process, link_session, target_member, sender_member)):
            return
        with self._lock:
            self._handoffs_by_process.pop(process, None)
            self._handoffs_by_process[process] = (
                link_session,
                target_member,
                sender_member,
            )
            while len(self._handoffs_by_process) > self.maximum_bound_sessions:
                self._handoffs_by_process.popitem(last=False)


    def take_handoff_process(
        self,
        process_id: str,
        link_session_id: str,
    ) -> tuple[str, str] | None:
        process = _coordinate(process_id, 180)
        link_session = _coordinate(link_session_id, 128)
        if not process or not link_session:
            return None
        with self._lock:
            handoff = self._handoffs_by_process.get(process)
            if handoff is None or handoff[0] != link_session:
                return None
            self._handoffs_by_process.pop(process, None)
        return handoff[1], handoff[2]

    def attach_session_store(self, session_store: Any) -> None:
        """Use Hermes' official session index for lifecycle-to-chat routing."""

        resolver = getattr(session_store, "lookup_by_session_id", None)
        with self._lock:
            self._session_resolver = resolver if callable(resolver) else None

    def attach_context_provider(
        self,
        provider: Callable[[str], dict[str, Any] | None],
    ) -> None:
        """Attach the adapter's read-only view of Hermes gateway session state."""

        with self._lock:
            self._context_provider = provider if callable(provider) else None

    def bound_link_session(self, session_id: str) -> str | None:
        hermes_session = _coordinate(session_id, 128)
        if not hermes_session:
            return None
        with self._lock:
            link_session = self._bound_sessions.get(hermes_session)
            if link_session is not None:
                self._bound_sessions.move_to_end(hermes_session)
                return link_session
            resolver = self._session_resolver
        if resolver is None:
            return None
        try:
            entry = resolver(hermes_session)
        except Exception as exc:
            logger.warning(
                "Loopdy Link session lookup failed (%s)", type(exc).__name__
            )
            return None
        origin = getattr(entry, "origin", None)
        entry_platform = getattr(getattr(entry, "platform", None), "value", None)
        origin_platform = getattr(getattr(origin, "platform", None), "value", None)
        if entry_platform != "loopdy" or origin_platform != "loopdy":
            return None
        return _coordinate(getattr(origin, "chat_id", None), 128)

    def attach_goal_provider(
        self, provider: Callable[[str], dict[str, Any] | None]
    ) -> None:
        with self._status_lock:
            self._goal_provider = provider if callable(provider) else None

    def goal_snapshot(self, session_id: str) -> dict[str, Any] | None:
        """Read a goal under the same lock that orders its observations.

        None means unavailable, not no goal. The provider must prove the
        current Hermes-to-Link route and explicitly return status=none for a
        successful absent-row read. Old/foreign session hooks cannot supply
        their own state or get a new timestamp for an old read.
        """
        with self._status_lock:
            return self._goal_snapshot_locked(session_id)

    def _goal_snapshot_locked(self, session_id: str) -> dict[str, Any] | None:
        if self._goal_provider is None:
            return None
        try:
            state = self._goal_provider(session_id)
        except Exception as exc:
            logger.warning("Loopdy goal snapshot failed (%s)", type(exc).__name__)
            return None
        if not isinstance(state, dict):
            return None
        link_session_id = _coordinate(state.get("sessionId"), 128)
        stored_session_id = _coordinate(state.get("storedSessionId"), 128)
        if not link_session_id or stored_session_id != session_id:
            return None
        status = state.get("status")
        if not isinstance(status, str) or status not in {"active", "paused", "done", "cleared", "none"}:
            return None
        summary = state.get("summary")
        if status in {"active", "paused"}:
            if not isinstance(summary, str) or not summary.strip():
                return None
            summary = _safe_text(summary, 2_000)
            if not summary:
                return None
        else:
            summary = None
        previous = self._goal_snapshots.get(link_session_id)
        if previous and (
            previous["storedSessionId"], previous["status"], previous["summary"]
        ) == (stored_session_id, status, summary):
            self._goal_snapshots.move_to_end(link_session_id)
            return dict(previous)
        payload = {
            "version": 1,
            "type": "session.goal",
            "sessionId": link_session_id,
            "storedSessionId": stored_session_id,
            "status": status,
            "summary": summary,
            "updatedAt": max(
                time.time_ns() // 1_000_000,
                (previous["updatedAt"] + 1) if previous else 1,
            ),
        }
        self._goal_snapshots[link_session_id] = payload
        self._goal_snapshots.move_to_end(link_session_id)
        self._goal_published_at.pop(link_session_id, None)
        while len(self._goal_snapshots) > self.maximum_bound_sessions:
            evicted, _ = self._goal_snapshots.popitem(last=False)
            self._goal_published_at.pop(evicted, None)
        return dict(payload)

    def publish_goal_snapshot(self, session_id: str, *, force: bool = False) -> bool:
        with self._status_lock:
            payload = self._goal_snapshot_locked(session_id)
            if payload is None:
                return False
            route = payload["sessionId"]
            now = time.monotonic()
            last = self._goal_published_at.get(route)
            # Periodic retransmission heals bounded-queue drops and reconnects,
            # even when no subsequent turn or goal mutation occurs.
            if not force and last is not None and now - last < 30:
                return False
            delivered = self.publish(payload)
            if delivered:
                self._goal_published_at[route] = now
            return delivered

    def is_active(self, session_id: str, turn_id: str) -> bool:
        with self._lock:
            return (session_id, turn_id) in self._active

    def resolved_session_id(self, session_id: str, turn_id: str) -> str | None:
        with self._lock:
            return self._active.get((session_id, turn_id))

    def deactivate(self, session_id: str, turn_id: str) -> None:
        with self._lock:
            self._active.pop((session_id, turn_id), None)
            self._context_signatures.pop((session_id, turn_id), None)
            self._context_updated_at.pop((session_id, turn_id), None)

    def publish_context_window(
        self,
        session_id: str,
        turn_id: str,
        *,
        force: bool = False,
        occurred_at: int | None = None,
    ) -> bool:
        coordinate = (session_id, turn_id)
        with self._lock:
            link_session_id = self._active.get(coordinate)
            provider = self._context_provider
        if not link_session_id or provider is None:
            return False
        try:
            snapshot = provider(session_id)
        except Exception as exc:
            logger.warning(
                "Loopdy context snapshot failed (%s)", type(exc).__name__
            )
            return False
        if not isinstance(snapshot, dict):
            return False
        snapshot = dict(snapshot)
        usage = self.usage_snapshot(session_id, snapshot.get("model"))
        if usage is not None:
            _merge_context_usage(snapshot, usage)
        signature = (
            snapshot.get("title"),
            snapshot.get("model"),
            snapshot.get("contextUsed"),
            snapshot.get("contextMax"),
            snapshot.get("contextPercent"),
            snapshot.get("compressions"),
            snapshot.get("isCompacting"),
            snapshot.get("inputTokens"),
            snapshot.get("outputTokens"),
            snapshot.get("cachedTokens"),
            snapshot.get("totalTokens"),
        )
        with self._lock:
            if not force and self._context_signatures.get(coordinate) == signature:
                return False
            self._context_signatures[coordinate] = signature
            updated_at = int(occurred_at if occurred_at is not None else time.time())
            updated_at = max(
                updated_at,
                self._context_updated_at.get(coordinate, updated_at - 1) + 1,
            )
            self._context_updated_at[coordinate] = updated_at
        try:
            payload = session_context(
                session_id=link_session_id,
                title=snapshot.get("title"),
                model=snapshot.get("model"),
                context_used=snapshot.get("contextUsed"),
                context_max=snapshot.get("contextMax"),
                context_percent=snapshot.get("contextPercent"),
                compressions=snapshot.get("compressions"),
                is_compacting=snapshot.get("isCompacting"),
                updated_at=updated_at,
                input_tokens=snapshot.get("inputTokens"),
                output_tokens=snapshot.get("outputTokens"),
                cached_tokens=snapshot.get("cachedTokens"),
                total_tokens=snapshot.get("totalTokens"),
            )
        except (TypeError, ValueError):
            with self._lock:
                if self._context_signatures.get(coordinate) == signature:
                    self._context_signatures.pop(coordinate, None)
                    self._context_updated_at.pop(coordinate, None)
            logger.warning("Hermes context snapshot was invalid")
            return False
        return self.publish(payload)

    def publish_todo_snapshot(
        self,
        link_session_id: str,
        snapshot: dict[str, Any],
        *,
        occurred_at: int,
    ) -> bool:
        """Publish one official TodoStore snapshot when its state changed."""

        try:
            payload = session_todos(
                session_id=link_session_id,
                revision=snapshot.get("revision"),
                todos=snapshot.get("todos"),
                updated_at=occurred_at,
            )
            signature = json.dumps(
                {"revision": payload["revision"], "todos": payload["todos"]},
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        except (TypeError, ValueError):
            logger.warning("Hermes todo snapshot was invalid")
            return False
        with self._status_lock:
            if self._todo_signatures.get(link_session_id) == signature:
                return False
            delivered = self.publish(payload)
            if delivered:
                self._todo_signatures[link_session_id] = signature
                self._todo_signatures.move_to_end(link_session_id)
                while len(self._todo_signatures) > self.maximum_bound_sessions:
                    self._todo_signatures.popitem(last=False)
            return delivered

    def publish_subagent_lifecycle(
        self,
        hook_name: str,
        link_session_id: str,
        snapshot: dict[str, Any],
        *,
        occurred_at: int,
    ) -> bool:
        """Reduce official child hooks into a bounded active-roster snapshot."""

        child_session_id = _coordinate(snapshot.get("child_session_id"), 180)
        if not child_session_id or hook_name not in {"subagent_start", "subagent_stop"}:
            return False
        with self._status_lock:
            parent_turn = _turn_coordinate(snapshot.get("parent_turn_id"))
            parent_route = self.bound_link_session(
                str(snapshot.get("parent_session_id") or "")
            )
            if hook_name == "subagent_start" and parent_route and parent_turn:
                self.register_child_route(child_session_id, child_session_id, parent_turn)
            roster = self._subagent_rosters.setdefault(
                link_session_id, OrderedDict()
            )
            self._subagent_rosters.move_to_end(link_session_id)
            if hook_name == "subagent_start":
                subagent_id = (
                    _coordinate(snapshot.get("child_subagent_id"), 180)
                    or child_session_id
                )
                role = _safe_text(snapshot.get("child_role"), 80) or "Subagent"
                goal = (
                    _safe_text(snapshot.get("child_goal"), 2_000)
                    or "Delegated work"
                )
                item: dict[str, Any] = {
                    "id": subagent_id,
                    "sessionId": child_session_id,
                    "role": role,
                    "goal": goal,
                    "startedAt": occurred_at,
                }
                parent_id = _coordinate(snapshot.get("parent_subagent_id"), 180)
                if parent_id:
                    item["parentId"] = parent_id
                existing = roster.get(child_session_id)
                if existing is not None:
                    item["startedAt"] = existing["startedAt"]
                roster[child_session_id] = item
                roster.move_to_end(child_session_id)
                while len(roster) > 256:
                    roster.popitem(last=False)
            elif roster.pop(child_session_id, None) is None:
                return False
            if hook_name == "subagent_stop":
                self.remove_child_route(child_session_id)
            while len(self._subagent_rosters) > self.maximum_bound_sessions:
                expired_session, _ = self._subagent_rosters.popitem(last=False)
                self._subagent_signatures.pop(expired_session, None)
            try:
                payload = session_subagents(
                    session_id=link_session_id,
                    subagents=list(roster.values()),
                    updated_at=occurred_at,
                )
                signature = json.dumps(
                    payload["subagents"],
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            except (TypeError, ValueError):
                logger.warning("Hermes subagent roster was invalid")
                return False
            if self._subagent_signatures.get(link_session_id) == signature:
                return False
            delivered = self.publish(payload)
            if delivered:
                self._subagent_signatures[link_session_id] = signature
                self._subagent_signatures.move_to_end(link_session_id)
            if parent_turn:
                lifecycle = "running" if hook_name == "subagent_start" else _subagent_lifecycle(
                    snapshot.get("child_status")
                )
                _publish(
                    self,
                    _event_id("delegate", child_session_id, parent_turn),
                    child_session_id,
                    parent_turn,
                    "subagent",
                    lifecycle,
                    _safe_text(snapshot.get("child_role"), 80) or "Subagent",
                    _safe_text(
                        snapshot.get("child_goal")
                        if hook_name == "subagent_start"
                        else snapshot.get("child_summary"),
                        500,
                    ) or "Delegated work",
                    None,
                    occurred_at,
                    subagent_id=_coordinate(
                        snapshot.get("child_subagent_id"), 180
                    ) or child_session_id,
                )
            return delivered

    def publish(self, payload: dict[str, Any]) -> bool:
        with self._lock:
            loop = self._loop
            queue = self._queue
        if loop is None or queue is None or loop.is_closed():
            return False
        try:
            loop.call_soon_threadsafe(self._enqueue, queue, dict(payload))
        except RuntimeError:
            return False
        return True

    async def complete(
        self,
        session_id: str,
        *,
        agent_name: str,
        succeeded: bool = True,
        occurred_at: int | None = None,
    ) -> bool:
        with self._lock:
            sender = self._live_activity_sender
        if sender is None:
            return False
        session = _coordinate(session_id, 128)
        if not session:
            return False
        state = self._live_state.setdefault(session, _new_live_state())
        if state.get("ended"):
            return True
        timestamp = _next_live_timestamp(state, occurred_at)
        state["ended"] = True
        name = _safe_text(agent_name, 60) or "Your agent"
        phase = "completed" if succeeded else "failed"
        action = (
            f"{name} finished the response"
            if succeeded
            else f"{name} could not finish the response"
        )[:96]
        update = _live_activity_wire(
            session_id=session,
            identity=f"final\x1f{phase}\x1f{timestamp}",
            phase=phase,
            current_action=action,
            progress=100,
            completed_steps=int(state.get("completed_steps") or 0),
            active_subagent_count=0,
            latest_tool=state.get("latest_tool"),
            timestamp=timestamp,
        )
        await sender(update)
        return True

    def _enqueue(
        self,
        queue: asyncio.Queue[dict[str, Any]],
        payload: dict[str, Any],
    ) -> None:
        if queue.full():
            try:
                queue.get_nowait()
                queue.task_done()
            except asyncio.QueueEmpty:
                pass
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            logger.warning("Loopdy Link activity queue remained full")

    async def _drain(self) -> None:
        while True:
            with self._lock:
                queue = self._queue
                sender = self._sender
                live_activity_sender = self._live_activity_sender
            if queue is None or sender is None:
                return
            payload = await queue.get()
            try:
                await sender(payload)
                if live_activity_sender is not None:
                    live_update = self._project_live_activity(payload)
                    if live_update is not None:
                        await live_activity_sender(live_update)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "Loopdy Link activity delivery failed (%s)", type(exc).__name__
                )
            finally:
                queue.task_done()

    async def _poll_context_windows(self) -> None:
        while True:
            await asyncio.sleep(max(0.01, self.context_poll_interval_seconds))
            with self._lock:
                active = tuple(self._active)
                bound = tuple(self._bound_sessions)
            for session_id, turn_id in active:
                self.publish_context_window(session_id, turn_id)
            # The goal judge runs AFTER post_llm_call deactivates a turn. A
            # standing goal must therefore remain observed while the chat is
            # idle; terminal/tool events are refresh triggers, not verdicts.
            for session_id in bound:
                await asyncio.to_thread(self.publish_goal_snapshot, session_id)

    def _project_live_activity(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        if payload.get("version") != 1 or payload.get("type") != "activity.event":
            return None
        session_id = _coordinate(payload.get("sessionId"), 128)
        event_id = _coordinate(payload.get("eventId"), 128)
        kind = str(payload.get("kind") or "")
        lifecycle = str(payload.get("lifecycle") or "")
        title = _safe_text(payload.get("title"), 80)
        occurred_at = _positive_timestamp(payload.get("occurredAt"))
        if (
            not session_id
            or not event_id
            or kind not in {"reasoning", "tool", "subagent", "bot_handoff"}
            or lifecycle not in {"running", "succeeded", "failed", "cancelled"}
            or not title
            or occurred_at is None
            or occurred_at < 1
        ):
            return None
        state = self._live_state.setdefault(session_id, _new_live_state())
        if state.get("ended"):
            return None
        settled = state["settled"]
        if lifecycle != "running" and event_id not in settled:
            settled.add(event_id)
            state["completed_steps"] = min(999, int(state["completed_steps"]) + 1)
        subagents = state["subagents"]
        if kind == "subagent":
            subagent_id = _coordinate(payload.get("subagentId"), 180) or event_id
            if lifecycle == "running":
                subagents.add(subagent_id)
            else:
                subagents.discard(subagent_id)

        if kind == "reasoning":
            if lifecycle == "running":
                phase, action, progress = "thinking", "Preparing a response", 12
            elif lifecycle == "succeeded":
                phase, action, progress = "responding", "Writing the response", 85
            else:
                phase, action, progress = "failed", "The response could not be completed", 100
        elif kind == "tool":
            state["latest_tool"] = title[:64]
            if lifecycle == "running":
                waiting = title.lower().startswith("waiting")
                phase = "waiting" if waiting else "using_tool"
                action = title
                progress = 35 if waiting else 48
            else:
                phase, action, progress = "thinking", "Continuing with the result", 62
        elif kind == "subagent":
            if lifecycle == "running":
                phase, action, progress = "delegating", title, 55
            else:
                phase, action, progress = "thinking", "Reviewing delegated work", 68
        else:
            if lifecycle == "running":
                phase, action, progress = "delegating", title, 58
            else:
                phase, action, progress = "thinking", "Continuing the conversation", 70
        timestamp = _next_live_timestamp(state, occurred_at)
        return _live_activity_wire(
            session_id=session_id,
            identity=(
                f"{event_id}\x1f{lifecycle}\x1f{timestamp}\x1f"
                f"{state['completed_steps']}\x1f{len(subagents)}"
            ),
            phase=phase,
            current_action=action[:96],
            progress=progress,
            completed_steps=int(state["completed_steps"]),
            active_subagent_count=len(subagents),
            latest_tool=state.get("latest_tool"),
            timestamp=timestamp,
        )


def publish_hook_activity(
    hook_name: str,
    *,
    broker: LinkActivityBroker | Any,
    profile: str,
    payload: dict[str, Any],
    occurred_at: int | None = None,
) -> None:
    """Normalize one official Hermes hook without exposing raw tool payloads."""

    timestamp = int(occurred_at if occurred_at is not None else time.time())
    child_route: tuple[str, str, str] | None = None
    if hook_name in {"pre_llm_call", "post_llm_call", "pre_tool_call", "post_tool_call"}:
        session_id = _coordinate(payload.get("session_id"), 128)
        turn_id = _turn_coordinate(payload.get("turn_id"))
        route_resolver = getattr(broker, "child_route", None)
        if session_id and callable(route_resolver):
            candidate = route_resolver(session_id)
            if isinstance(candidate, tuple) and len(candidate) == 3 and all(
                isinstance(item, str) for item in candidate
            ):
                child_route = candidate
    else:
        session_id = _coordinate(payload.get("parent_session_id"), 128)
        turn_id = _turn_coordinate(payload.get("parent_turn_id"))
    if not session_id:
        return

    if hook_name == "pre_llm_call":
        if not turn_id:
            return
        if (
            str(payload.get("platform") or "").strip().lower() != "loopdy"
            and child_route is None
        ):
            return
        link_session_id = child_route[1] if child_route else broker.bound_link_session(session_id)
        if not link_session_id:
            return
        broker.activate(session_id, turn_id, link_session_id=link_session_id)
        completion = _background_handoff_completion(payload.get("user_message"))
        resolver = getattr(broker, "take_handoff_process", None)
        handoff = (
            resolver(completion[0], link_session_id)
            if completion is not None and callable(resolver)
            else None
        )
        if (
            completion is not None
            and isinstance(handoff, tuple)
            and len(handoff) == 2
            and all(isinstance(item, str) for item in handoff)
        ):
            process_id, output, succeeded = completion
            target, sender = handoff
            _publish(
                broker,
                _event_id("handoff_return", link_session_id, process_id),
                link_session_id,
                turn_id,
                "bot_handoff",
                "succeeded" if succeeded else "failed",
                "Agent reply",
                f"@{target} replied" if succeeded else f"@{target} could not reply",
                None,
                timestamp,
                result=output or None,
                bot_run_id=process_id,
                member_id=sender,
                from_member_id=target,
            )
        publish_context = getattr(broker, "publish_context_window", None)
        if callable(publish_context):
            publish_context(session_id, turn_id, occurred_at=timestamp)
        _publish(
            broker,
            _event_id("reason", link_session_id, turn_id),
            link_session_id,
            turn_id,
            "reasoning",
            "running",
            "Reasoning",
            "Preparing a response",
            None,
            timestamp,
        )
        return

    link_session_id = (
        broker.resolved_session_id(session_id, turn_id) if turn_id else None
    )
    if child_route is not None:
        link_session_id = child_route[1]
    bound_session_id = link_session_id
    if not bound_session_id:
        bound_resolver = getattr(broker, "bound_link_session", None)
        if callable(bound_resolver):
            bound_session_id = _coordinate(bound_resolver(session_id), 128) or None
    if not link_session_id:
        link_session_id = bound_session_id

    if hook_name == "post_tool_call" and bound_session_id:
        publish_goal = getattr(broker, "publish_goal_snapshot", None)
        if callable(publish_goal):
            # A terminal tool can mutate goal state; its arguments/results
            # cannot prove it did. Re-read Hermes instead of parsing either.
            publish_goal(session_id)
        if (
            _coordinate(payload.get("tool_name"), 80) == "todo"
            and _tool_lifecycle(payload.get("status")) == "succeeded"
        ):
            snapshot = _todo_snapshot(payload.get("result"))
            publisher = getattr(broker, "publish_todo_snapshot", None)
            if snapshot is not None and callable(publisher):
                publisher(bound_session_id, snapshot, occurred_at=timestamp)

    if hook_name in {"subagent_start", "subagent_stop"} and bound_session_id:
        publisher = getattr(broker, "publish_subagent_lifecycle", None)
        if callable(publisher):
            publisher(
                hook_name,
                bound_session_id,
                payload,
                occurred_at=timestamp,
            )

    if not link_session_id or not turn_id:
        return

    if hook_name == "post_llm_call":
        publish_context = getattr(broker, "publish_context_window", None)
        if callable(publish_context):
            publish_context(
                session_id,
                turn_id,
                force=True,
                occurred_at=timestamp,
            )
        _publish(
            broker,
            _event_id("reason", link_session_id, turn_id),
            link_session_id,
            turn_id,
            "reasoning",
            "succeeded",
            "Reasoning",
            "Response ready",
            None,
            timestamp,
        )
        broker.deactivate(session_id, turn_id)
        return

    if hook_name == "pre_tool_call":
        tool_name = _coordinate(payload.get("tool_name"), 80)
        tool_call_id = _coordinate(payload.get("tool_call_id"), 180)
        if not tool_name or not tool_call_id:
            return
        if tool_name in {"message_agent", "terminal"}:
            request = _collaboration_request(tool_name, payload.get("args"))
            if request is not None:
                target, message = request
                _publish(
                    broker,
                    _event_id("handoff", link_session_id, turn_id, tool_call_id),
                    link_session_id,
                    turn_id,
                    "bot_handoff",
                    "running",
                    f"Contacting @{target}",
                    f"Message sent to @{target}",
                    None,
                    timestamp,
                    arguments=message,
                    bot_run_id=tool_call_id,
                    member_id=target,
                    from_member_id=_profile_member_id(profile),
                )
                return
        _publish(
            broker,
            _event_id("tool", link_session_id, turn_id, tool_call_id),
            link_session_id,
            turn_id,
            "tool",
            "running",
            _tool_title(tool_name),
            _argument_summary(payload.get("args")),
            None,
            timestamp,
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            arguments=_tool_detail(payload.get("args")),
        )
        return

    if hook_name == "post_tool_call":
        tool_name = _coordinate(payload.get("tool_name"), 80)
        tool_call_id = _coordinate(payload.get("tool_call_id"), 180)
        if not tool_name or not tool_call_id:
            return
        lifecycle = _tool_lifecycle(payload.get("status"))
        duration = _duration(payload.get("duration_ms"))
        if lifecycle == "succeeded":
            try:
                record_generated_media_call(
                    profile=profile,
                    stored_id=session_id,
                    turn_id=turn_id,
                    tool_call_id=tool_call_id,
                    tool_name=tool_name,
                    arguments=payload.get("args"),
                    link_session_id=link_session_id,
                )
            except (OSError, sqlite3.Error, ValueError):
                logger.warning("Generated media identity could not be retained")
        if tool_name in {"message_agent", "terminal"}:
            request = _collaboration_request(tool_name, payload.get("args"))
            if request is not None:
                target, message = request
                process_id = (
                    _agent_message_process_id(
                        payload.get("result"),
                        accepts_legacy_terminal_result=tool_name == "terminal",
                    )
                    if lifecycle == "succeeded"
                    else None
                )
                binder = getattr(broker, "bind_handoff_process", None)
                sender = _profile_member_id(profile)
                if process_id is not None and callable(binder):
                    binder(process_id, link_session_id, target, sender)

                _publish(
                    broker,
                    _event_id("handoff", link_session_id, turn_id, tool_call_id),
                    link_session_id,
                    turn_id,
                    "bot_handoff",
                    lifecycle,
                    f"Contacting @{target}",
                    "Message accepted" if lifecycle == "succeeded" else "Message was not sent",
                    _duration_label(duration),
                    timestamp,
                    arguments=message,
                    result=(None if lifecycle == "succeeded" else _tool_detail(payload.get("result"))),
                    duration_ms=duration,
                    bot_run_id=tool_call_id,
                    member_id=target,
                    from_member_id=sender,
                )
                return
        _publish(
            broker,
            _event_id("tool", link_session_id, turn_id, tool_call_id),
            link_session_id,
            turn_id,
            "tool",
            lifecycle,
            _tool_title(tool_name),
            "Completed" if lifecycle == "succeeded" else "Tool did not complete",
            _duration_label(duration),
            timestamp,
            duration_ms=duration,
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            arguments=_tool_detail(payload.get("args")),
            result=_tool_detail(payload.get("result")),
        )
        return

    if hook_name in {"subagent_start", "subagent_stop"}:
        child_session_id = _coordinate(payload.get("child_session_id"), 180)
        if not child_session_id:
            return
        role = _safe_text(payload.get("child_role"), 60) or "Subagent"
        title = role if role.lower().endswith("agent") else f"{role} agent"
        if hook_name == "subagent_start":
            lifecycle = "running"
            summary = _safe_text(payload.get("child_goal"), 500) or "Delegated work started"
            duration = None
        else:
            lifecycle = _subagent_lifecycle(payload.get("child_status"))
            summary = _safe_text(payload.get("child_summary"), 500) or "Delegated work finished"
            duration = _duration(payload.get("duration_ms"))
        _publish(
            broker,
            _event_id("delegate", link_session_id, turn_id, child_session_id),
            link_session_id,
            turn_id,
            "subagent",
            lifecycle,
            title,
            summary,
            _duration_label(duration),
            timestamp,
            duration_ms=duration,
            subagent_id=child_session_id,
        )


def finish_failed_turn_activity(
    *,
    broker: LinkActivityBroker | Any,
    payload: dict[str, Any],
    occurred_at: int | None = None,
) -> None:
    session_id = _coordinate(payload.get("session_id"), 128)
    turn_id = _turn_coordinate(payload.get("turn_id"))
    if not session_id or not turn_id:
        return
    link_session_id = broker.resolved_session_id(session_id, turn_id)
    if not link_session_id:
        return
    failed = bool(payload.get("failed") or payload.get("interrupted"))
    lifecycle = "failed" if failed else "succeeded"
    _publish(
        broker,
        _event_id("reason", link_session_id, turn_id),
        link_session_id,
        turn_id,
        "reasoning",
        lifecycle,
        "Reasoning",
        "Response stopped" if failed else "Response ready",
        None,
        int(occurred_at if occurred_at is not None else time.time()),
    )
    broker.deactivate(session_id, turn_id)


def _publish(
    broker: LinkActivityBroker | Any,
    event_id: str,
    session_id: str,
    turn_id: str,
    kind: str,
    lifecycle: str,
    title: str,
    summary: str | None,
    detail: str | None,
    occurred_at: int,
    **coordinates: Any,
) -> None:
    try:
        payload = activity_event(
            event_id=event_id,
            session_id=session_id,
            turn_id=external_turn_id(session_id, turn_id),
            kind=kind,
            lifecycle=lifecycle,
            title=title,
            summary=summary,
            detail=detail,
            occurred_at=occurred_at,
            **coordinates,
        )
    except (TypeError, ValueError):
        logger.warning("Hermes activity coordinates were invalid")
        return
    if not broker.publish(payload):
        logger.debug("Loopdy Link activity has no attached socket")


def _event_id(prefix: str, *coordinates: str) -> str:
    digest = hashlib.sha256("\x1f".join(coordinates).encode("utf-8")).digest()[:18]
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"{prefix}_{encoded}"


def external_turn_id(session_id: str, turn_id: str) -> str:
    """Project an internal Hermes turn coordinate into the opaque Link contract."""

    return _event_id("turn", session_id, turn_id)


def _profile_member_id(profile: str) -> str:
    member_id = _coordinate(profile, 96)
    return "default" if member_id in {"", "hermes"} else member_id



def _agent_message_process_id(
    value: Any,
    *,
    accepts_legacy_terminal_result: bool,
) -> str | None:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return None
    if not isinstance(value, dict):
        return None
    status = value.get("status")
    process_id = value.get("process_id") or value.get("session_id")
    if status != "sent" and not (
        accepts_legacy_terminal_result and status == "running"
    ):
        return None
    return _coordinate(process_id, 180) or None


def _background_handoff_completion(
    value: Any,
) -> tuple[str, str, bool] | None:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 1_065_000:
        return None
    marker = "Background process "
    start = value.find(marker)
    if start < 0:
        return None
    tail = value[start + len(marker):]
    raw_process = tail.split(maxsplit=1)[0] if tail else ""
    process_id = _coordinate(raw_process, 180)
    if not process_id:
        return None
    output_marker = "\nOutput:\n"
    output = value.split(output_marker, 1)[1].strip() if output_marker in value else ""
    if len(output.encode("utf-8")) > 64_000:
        return None
    succeeded = "completed normally (exit code 0)" in value
    return process_id, output, succeeded


def _agent_message_request(value: Any) -> tuple[str, str] | None:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return None
    if not isinstance(value, dict):
        return None
    raw_target = value.get("target")
    message = value.get("message")
    if not isinstance(raw_target, str) or not isinstance(message, str):
        return None
    target = raw_target.strip().removeprefix("@")
    if target == "hermes":
        target = "default"
    target = _coordinate(target, 96)
    if not target or not message.strip() or len(message.encode("utf-8")) > 64_000:
        return None
    return target, message


def _collaboration_request(tool_name: str, value: Any) -> tuple[str, str] | None:
    if tool_name == "message_agent":
        return _agent_message_request(value)
    return _legacy_agent_message_request(value) if tool_name == "terminal" else None


def _legacy_agent_message_request(value: Any) -> tuple[str, str] | None:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return None
    if not isinstance(value, dict) or not isinstance(value.get("command"), str):
        return None
    if "\n" in value["command"] or "\r" in value["command"]:
        return None
    lexer = shlex.shlex(value["command"], posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        words = list(lexer)
    except ValueError:
        return None
    if any(word and set(word) <= set(";&|") for word in words):
        return None
    if len(words) < 4 or words[0].rsplit("/", 1)[-1] != "hermes":
        return None
    if words[1] != "-p" or words[3] != "chat":
        return None

    def argument(flag: str) -> str | None:
        try:
            index = words.index(flag)
        except ValueError:
            return None
        return words[index + 1] if index + 1 < len(words) else None

    if argument("-c") != "Bot Chat":
        return None
    message = argument("-q") or argument("--query")
    if message is None:
        return None
    return _agent_message_request({"target": words[2], "message": message})


def _coordinate(value: Any, maximum: int) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip()
    if not 1 <= len(normalized) <= maximum or not _IDENTIFIER.fullmatch(normalized):
        return ""
    return normalized


def _model_coordinate(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip()
    if (
        not 1 <= len(normalized) <= 160
        or not normalized.isprintable()
        or any(character.isspace() for character in normalized)
    ):
        return ""
    return normalized


def _api_usage_projection(value: Any) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    projected: dict[str, int] = {}
    fields = {
        "prompt_tokens": "inputTokens",
        "output_tokens": "outputTokens",
        "cache_read_tokens": "cachedTokens",
        "total_tokens": "totalTokens",
    }
    for source in (
        "prompt_tokens",
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
        "reasoning_tokens",
        "total_tokens",
    ):
        if source not in value or value[source] is None:
            continue
        count = value[source]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            return None
        target = fields.get(source)
        if target is not None:
            projected[target] = count
    return projected or None


def _api_usage_event_order(payload: dict[str, Any]) -> dict[str, Any]:
    def identifier(value: Any) -> str:
        if not isinstance(value, str):
            return ""
        candidate = value.strip()
        return (
            candidate
            if 1 <= len(candidate) <= 180 and candidate.isprintable()
            else ""
        )

    def count(value: Any) -> int | None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return None
        return value

    def timestamp(value: Any) -> float | None:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        candidate = float(value)
        return candidate if 0 <= candidate <= 100_000_000_000 else None

    return {
        "request_id": identifier(payload.get("api_request_id")),
        "turn_id": identifier(payload.get("turn_id")),
        "api_call_count": count(payload.get("api_call_count")),
        "started_at": timestamp(payload.get("started_at")),
        "ended_at": timestamp(payload.get("ended_at")),
    }


def _api_usage_is_stale(
    previous: dict[str, Any], candidate: dict[str, Any]
) -> bool:
    request_id = candidate.get("request_id")
    if request_id and request_id == previous.get("request_id"):
        return True
    previous_ended = previous.get("ended_at")
    candidate_ended = candidate.get("ended_at")
    if previous_ended is not None and candidate_ended is not None:
        if candidate_ended < previous_ended:
            return True
        if candidate_ended > previous_ended:
            return False
    turn_id = candidate.get("turn_id")
    if turn_id and turn_id == previous.get("turn_id"):
        previous_count = previous.get("api_call_count")
        candidate_count = candidate.get("api_call_count")
        if previous_count is not None and candidate_count is not None:
            return candidate_count < previous_count
        previous_started = previous.get("started_at")
        candidate_started = candidate.get("started_at")
        if previous_started is not None and candidate_started is not None:
            return candidate_started < previous_started
    return False


def _merge_context_usage(
    snapshot: dict[str, Any], usage: dict[str, int]
) -> None:
    snapshot.update(usage)
    prompt_tokens = usage.get("inputTokens")
    if prompt_tokens is None:
        return
    snapshot["contextUsed"] = prompt_tokens
    maximum = snapshot.get("contextMax")
    if isinstance(maximum, int) and not isinstance(maximum, bool) and maximum > 0:
        snapshot["contextPercent"] = min(
            100, round((prompt_tokens / maximum) * 100)
        )


def _turn_coordinate(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip()
    if not 8 <= len(normalized) <= 180 or not _INTERNAL_TURN.fullmatch(normalized):
        return ""
    return normalized


def _safe_text(value: Any, maximum: int) -> str:
    if not isinstance(value, str):
        return ""
    normalized = " ".join(value.split())[:maximum]
    return normalized if normalized and normalized.isprintable() else ""


def _argument_summary(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    keys = sorted(
        _safe_text(str(key).replace("_", " "), 40)
        for key in value
        if _coordinate(str(key), 80)
    )[:4]
    keys = [key for key in keys if key]
    if not keys:
        return None
    return "Inputs: " + ", ".join(keys)


def _tool_detail(value: Any, maximum: int = 65_536) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        rendered = value
    else:
        try:
            rendered = json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
        except (TypeError, ValueError, OverflowError):
            return None
    rendered = rendered.replace("\r\n", "\n").replace("\r", "\n")
    rendered = "".join(
        character
        if character.isprintable() or character in "\n\t"
        else "\N{REPLACEMENT CHARACTER}"
        for character in rendered
    )
    if not rendered:
        return None
    if len(rendered) > maximum:
        marker = "\n… [truncated]"
        rendered = rendered[: maximum - len(marker)] + marker
    return rendered


def _todo_snapshot(value: Any) -> dict[str, Any] | None:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return None
    if not isinstance(value, dict):
        return None
    if not isinstance(value.get("todos"), list):
        return None
    revision = value.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        return None
    return {"todos": value["todos"], "revision": revision}


def _tool_title(tool_name: str) -> str:
    return _TOOL_TITLES.get(tool_name, "Using " + tool_name.replace("_", " "))


def _tool_lifecycle(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"ok", "success", "succeeded", "completed"}:
        return "succeeded"
    if normalized in {"cancelled", "canceled", "interrupted"}:
        return "cancelled"
    return "failed"


def _subagent_lifecycle(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"completed", "succeeded", "success", "ok"}:
        return "succeeded"
    if normalized in {"cancelled", "canceled", "interrupted"}:
        return "cancelled"
    if normalized == "running":
        return "running"
    return "failed"


def _duration(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return min(max(value, 0), 86_400_000)


def _duration_label(value: int | None) -> str | None:
    if value is None:
        return None
    if value < 1_000:
        return f"{value} ms"
    return f"{value / 1_000:.1f} s"


def _new_live_state() -> dict[str, Any]:
    return {
        "completed_steps": 0,
        "subagents": set(),
        "settled": set(),
        "latest_tool": None,
        "last_timestamp": 0,
        "ended": False,
    }


def _positive_timestamp(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 1 <= value <= 9_999_999_999 else None


def _next_live_timestamp(state: dict[str, Any], value: int | None) -> int:
    candidate = _positive_timestamp(value)
    if candidate is None:
        candidate = int(time.time())
    timestamp = max(candidate, int(state.get("last_timestamp") or 0) + 1)
    state["last_timestamp"] = timestamp
    return timestamp


def _live_activity_wire(
    *,
    session_id: str,
    identity: str,
    phase: str,
    current_action: str,
    progress: int,
    completed_steps: int,
    active_subagent_count: int,
    latest_tool: Any,
    timestamp: int,
) -> dict[str, Any]:
    session_reference = base64.urlsafe_b64encode(
        hashlib.sha256(session_id.encode("utf-8")).digest()
    ).decode("ascii").rstrip("=")
    update_id = "live_" + base64.urlsafe_b64encode(
        hashlib.sha256(f"{session_id}\x1f{identity}".encode("utf-8")).digest()[:18]
    ).decode("ascii").rstrip("=")
    tool = _safe_text(latest_tool, 64) or None
    return {
        "version": 1,
        "type": "live_activity.update",
        "updateId": update_id,
        "sessionReference": session_reference,
        "phase": phase,
        "currentAction": _safe_text(current_action, 96) or "Working on your request",
        "progress": min(max(int(progress), 0), 100),
        "completedSteps": min(max(int(completed_steps), 0), 999),
        "activeSubagentCount": min(max(int(active_subagent_count), 0), 99),
        "latestTool": tool,
        "timestamp": timestamp,
        "expires": timestamp + 120,
    }


__all__ = [
    "LinkActivityBroker",
    "finish_failed_turn_activity",
    "publish_hook_activity",
]
