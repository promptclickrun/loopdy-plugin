"""Thread-safe Hermes lifecycle projection onto the existing Loopdy Link socket."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from typing import Any

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
        self._child_routes: OrderedDict[str, tuple[str, str, str]] = OrderedDict()
        self._session_resolver: Callable[[str], Any] | None = None
        self._context_provider: Callable[[str], dict[str, Any] | None] | None = None
        self._context_signatures: dict[tuple[str, str], tuple[Any, ...]] = {}
        self._status_lock = threading.Lock()
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
                self._child_routes.clear()
                self._context_signatures.clear()
                self._live_state.clear()
            self._todo_signatures.clear()
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
            self._bound_sessions.pop(hermes_session, None)
            self._bound_sessions[hermes_session] = link_session
            while len(self._bound_sessions) > self.maximum_bound_sessions:
                self._bound_sessions.popitem(last=False)

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
        signature = (
            snapshot.get("title"),
            snapshot.get("model"),
            snapshot.get("contextUsed"),
            snapshot.get("contextMax"),
            snapshot.get("contextPercent"),
            snapshot.get("compressions"),
            snapshot.get("isCompacting"),
        )
        with self._lock:
            if not force and self._context_signatures.get(coordinate) == signature:
                return False
            self._context_signatures[coordinate] = signature
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
                updated_at=int(occurred_at if occurred_at is not None else time.time()),
            )
        except (TypeError, ValueError):
            with self._lock:
                if self._context_signatures.get(coordinate) == signature:
                    self._context_signatures.pop(coordinate, None)
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
            for session_id, turn_id in active:
                self.publish_context_window(session_id, turn_id)

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
            bound_session_id = bound_resolver(session_id)

    if hook_name == "post_tool_call" and bound_session_id:
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


def _coordinate(value: Any, maximum: int) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip()
    if not 1 <= len(normalized) <= maximum or not _IDENTIFIER.fullmatch(normalized):
        return ""
    return normalized


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
