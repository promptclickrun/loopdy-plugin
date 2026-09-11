from __future__ import annotations

import asyncio
import json
import threading
import unittest
from unittest.mock import patch
from types import SimpleNamespace


class ActivityBridgeTests(unittest.IsolatedAsyncioTestCase):
    async def test_hook_burst_schedules_one_bounded_event_loop_wakeup(self):
        from loopdy_plugin.activity_bridge import LinkActivityBroker
        broker = LinkActivityBroker()
        release = asyncio.Event()
        delivered = asyncio.Event()
        received = []

        async def stalled_sender(payload):
            await release.wait()
            received.append(payload["eventId"])
            if payload["eventId"] == "1999":
                delivered.set()

        await broker.attach(stalled_sender)
        loop = asyncio.get_running_loop()
        try:
            with patch.object(loop, "call_soon_threadsafe", wraps=loop.call_soon_threadsafe) as schedule:
                producer = threading.Thread(target=lambda: [broker.publish({"type": "activity.event", "eventId": str(index)})
                                                            for index in range(2_000)])
                producer.start()
                producer.join(timeout=2)
                self.assertFalse(producer.is_alive())
                self.assertEqual(schedule.call_count, 1, "A burst must not leave one pending callback per tool event")
            await asyncio.sleep(0)
            self.assertLessEqual(broker._queue.qsize(), broker.maximum_queue_size)
            release.set()
            await asyncio.wait_for(delivered.wait(), timeout=1)
            self.assertEqual(received, [str(index) for index in range(2_000 - broker.maximum_queue_size, 2_000)])
        finally:
            release.set()
            await broker.detach()

    async def test_old_publication_wakeup_cannot_drain_a_reattached_broker(self):
        from loopdy_plugin.activity_bridge import LinkActivityBroker
        broker = LinkActivityBroker()
        received = []
        delivered = asyncio.Event()

        async def sender(payload):
            received.append(payload["eventId"])
            delivered.set()

        await broker.attach(sender)
        callbacks = []
        loop = asyncio.get_running_loop()
        try:
            with patch.object(loop, "call_soon_threadsafe", side_effect=lambda fn, *args: callbacks.append((fn, args))):
                broker.publish({"type": "activity.event", "eventId": "old"})
                await broker.detach()
                await broker.attach(sender)
                broker.publish({"type": "activity.event", "eventId": "new"})
            for callback, args in callbacks:
                callback(*args)
            await asyncio.wait_for(delivered.wait(), timeout=1)
            self.assertEqual(received, ["new"])
        finally:
            await broker.detach()

    async def test_detached_children_keep_parent_owned_roster_until_last_stop(self):
        from loopdy_plugin.activity_bridge import LinkActivityBroker
        broker = LinkActivityBroker()
        for child in ('child-a', 'child-b'):
            broker.publish_subagent_lifecycle('subagent_start', None,
                {'parent_session_id': 'parent', 'parent_turn_id': 'turn-a',
                 'child_session_id': child, 'child_goal': 'Work', 'child_role': 'worker'},
                occurred_at=1, profile='default')
        first = broker.subagent_snapshot('default', 'parent', 'visible')
        self.assertEqual(len(first['subagents']), 2)
        self.assertEqual(broker.subagent_snapshot('other', 'parent', 'visible')['subagents'], [])
        for remaining, child in ((1, 'child-a'), (0, 'child-b')):
            broker.publish_subagent_lifecycle('subagent_stop', None,
                {'parent_session_id': 'parent', 'parent_turn_id': 'turn-b',
                 'child_session_id': child, 'child_status': 'failed'},
                occurred_at=2, profile='default')
            current = broker.subagent_snapshot('default', 'parent', 'visible')
            self.assertEqual(len(current['subagents']), remaining)
            self.assertGreater(current['updatedAt'], first['updatedAt'])


    async def test_goal_observations_preserve_tombstones_and_unavailable_is_not_absence(self):
        from loopdy_plugin.activity_bridge import LinkActivityBroker
        broker = LinkActivityBroker()
        state = {"sessionId": "visible-goal", "storedSessionId": "stored-goal", "status": "active", "summary": "Finish work"}
        broker.attach_goal_provider(lambda _: state)
        active = broker.goal_snapshot("stored-goal")
        self.assertEqual(active["status"], "active")
        state = dict(state, status="done", summary=None)
        done = broker.goal_snapshot("stored-goal")
        self.assertGreater(done["updatedAt"], active["updatedAt"])
        self.assertIsNone(done["summary"])
        self.assertEqual(broker.goal_snapshot("stored-goal"), done)
        broker.attach_goal_provider(lambda _: None)
        self.assertIsNone(broker.goal_snapshot("stored-goal"))
        self.assertIsNone(broker.goal_snapshot("foreign-goal"))

    async def test_resolves_verified_loopdy_chat_from_the_official_session_store(
        self,
    ) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker

        broker = LinkActivityBroker()
        link_source = SimpleNamespace(
            platform=SimpleNamespace(value="loopdy"),
            chat_id="link-chat-coordinate-0001",
        )
        entry = SimpleNamespace(
            platform=SimpleNamespace(value="loopdy"),
            origin=link_source,
        )
        store = SimpleNamespace(
            lookup_by_session_id=lambda session_id: (
                entry if session_id == "hermes-session-coordinate-0001" else None
            )
        )

        broker.attach_session_store(store)

        self.assertEqual(
            broker.bound_link_session("hermes-session-coordinate-0001"),
            "link-chat-coordinate-0001",
        )

    async def test_rejects_non_loopdy_session_store_origins(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker

        broker = LinkActivityBroker()
        entry = SimpleNamespace(
            platform=SimpleNamespace(value="telegram"),
            origin=SimpleNamespace(
                platform=SimpleNamespace(value="telegram"),
                chat_id="link-chat-coordinate-0001",
            ),
        )
        broker.attach_session_store(
            SimpleNamespace(lookup_by_session_id=lambda _session_id: entry)
        )

        self.assertIsNone(
            broker.bound_link_session("hermes-session-coordinate-0001")
        )

    async def test_hook_thread_crosses_onto_one_bounded_async_sender(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker

        broker = LinkActivityBroker()
        received = []
        delivered = asyncio.Event()

        async def sender(payload):
            received.append(payload)
            delivered.set()

        await broker.attach(sender)
        thread = threading.Thread(
            target=lambda: broker.publish(
                {
                    "version": 1,
                    "type": "activity.event",
                    "eventId": "tool_event_fixture_0001",
                }
            )
        )
        thread.start()
        thread.join(timeout=1)
        await asyncio.wait_for(delivered.wait(), timeout=1)

        self.assertFalse(thread.is_alive())
        self.assertEqual(received[0]["eventId"], "tool_event_fixture_0001")
        await broker.detach()

    async def test_detached_broker_rejects_new_activity_without_queueing(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker

        broker = LinkActivityBroker()
        await broker.attach(lambda payload: asyncio.sleep(0))
        await broker.detach()

        self.assertFalse(broker.publish({"type": "activity.event"}))

    async def test_projects_sanitized_live_activity_while_encrypted_event_keeps_tool_details(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker

        broker = LinkActivityBroker()
        encrypted = []
        live = []
        delivered = asyncio.Event()

        async def event_sender(payload):
            encrypted.append(payload)

        async def live_sender(payload):
            live.append(payload)
            delivered.set()

        await broker.attach(event_sender, live_activity_sender=live_sender)
        broker.publish(
            {
                "version": 1,
                "type": "activity.event",
                "eventId": "tool_event_fixture_0002",
                "sessionId": "session_coordinate_0001",
                "turnId": "turn_coordinate_0001",
                "kind": "tool",
                "lifecycle": "running",
                "title": "Checking weather",
                "summary": "private location and API token",
                "arguments": '{"api_token":"private token","city":"Chicago"}',
                "result": "private forecast output",
                "occurredAt": 1_788_000_000,
                "toolCallId": "tool_call_fixture_0001",
            }
        )
        await asyncio.wait_for(delivered.wait(), timeout=1)

        self.assertEqual(encrypted[0]["summary"], "private location and API token")
        self.assertEqual(
            encrypted[0]["arguments"],
            '{"api_token":"private token","city":"Chicago"}',
        )
        self.assertEqual(encrypted[0]["result"], "private forecast output")
        self.assertEqual(live[0]["type"], "live_activity.update")
        self.assertEqual(live[0]["phase"], "using_tool")
        self.assertEqual(live[0]["currentAction"], "Checking weather")
        self.assertEqual(live[0]["latestTool"], "Checking weather")
        self.assertEqual(len(live[0]["sessionReference"]), 43)
        self.assertNotIn("private location", repr(live[0]))
        self.assertNotIn("API token", repr(live[0]))
        self.assertNotIn("private token", repr(live[0]))
        self.assertNotIn("private forecast output", repr(live[0]))
        await broker.detach()

    async def test_message_agent_hooks_publish_live_collaboration_identity(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker, publish_hook_activity

        class CapturingBroker(LinkActivityBroker):
            def __init__(self):
                super().__init__()
                self.payloads = []

            def publish(self, payload):
                self.payloads.append(payload)
                return True

        broker = CapturingBroker()
        session_id = "hermes_session_coordinate_0001"
        turn_id = "hermes_session_coordinate_0001:turn:handoff01"
        broker.activate(
            session_id,
            turn_id,
            link_session_id="link_session_coordinate_0001",
        )
        base = {
            "session_id": session_id,
            "turn_id": turn_id,
            "tool_name": "message_agent",
            "tool_call_id": "agent_message_call_0001",
            "args": {"target": "nova", "message": "Review this."},
        }

        publish_hook_activity(
            "pre_tool_call",
            broker=broker,
            profile="default",
            payload=base,
            occurred_at=1_788_000_030,
        )
        publish_hook_activity(
            "post_tool_call",
            broker=broker,
            profile="default",
            payload={**base, "status": "ok", "duration_ms": 125},
            occurred_at=1_788_000_031,
        )

        self.assertEqual(len(broker.payloads), 2)
        started, completed = broker.payloads
        self.assertEqual(started["eventId"], completed["eventId"])
        self.assertEqual(started["kind"], "bot_handoff")
        self.assertEqual(started["lifecycle"], "running")
        self.assertEqual(completed["lifecycle"], "succeeded")
        self.assertEqual(started["fromMemberId"], "default")
        self.assertEqual(started["memberId"], "nova")
        self.assertEqual(started["arguments"], "Review this.")
        self.assertEqual(started["botRunId"], "agent_message_call_0001")
        self.assertNotIn("toolCallId", started)

    async def test_legacy_hermes_profile_chat_hook_publishes_live_collaboration_identity(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker, publish_hook_activity

        class CapturingBroker(LinkActivityBroker):
            def __init__(self):
                super().__init__()
                self.payloads = []

            def publish(self, payload):
                self.payloads.append(payload)
                return True

        broker = CapturingBroker()
        session_id = "hermes_session_coordinate_0001"
        turn_id = "hermes_session_coordinate_0001:turn:legacy01"
        broker.activate(session_id, turn_id, link_session_id="link_session_coordinate_0001")
        publish_hook_activity(
            "pre_tool_call",
            broker=broker,
            profile="default",
            payload={
                "session_id": session_id,
                "turn_id": turn_id,
                "tool_name": "terminal",
                "tool_call_id": "legacy_agent_call_0001",
                "args": {
                    "command": 'hermes -p nova chat --in ~ -c "Bot Chat" -q "Review this."',
                    "background": True,
                },
            },
            occurred_at=1_788_000_032,
        )

        self.assertEqual(len(broker.payloads), 1)
        self.assertEqual(broker.payloads[0]["kind"], "bot_handoff")
        self.assertEqual(broker.payloads[0]["fromMemberId"], "default")
        self.assertEqual(broker.payloads[0]["memberId"], "nova")
        self.assertEqual(broker.payloads[0]["arguments"], "Review this.")

    async def test_bound_link_session_publishes_profile_chat_without_active_turn_entry(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker, publish_hook_activity

        class CapturingBroker(LinkActivityBroker):
            def __init__(self):
                super().__init__()
                self.payloads = []

            def publish(self, payload):
                self.payloads.append(payload)
                return True

        broker = CapturingBroker()
        session_id = "hermes_session_coordinate_0001"
        turn_id = "hermes_session_coordinate_0001:turn:handoff02"
        broker.bind_link_session(session_id, "link_session_coordinate_0001")

        publish_hook_activity(
            "pre_tool_call",
            broker=broker,
            profile="default",
            payload={
                "session_id": session_id,
                "turn_id": turn_id,
                "tool_name": "terminal",
                "tool_call_id": "legacy_agent_call_0002",
                "args": {
                    "command": (
                        'hermes -p nova chat --in ~ -c "Bot Chat" '
                        '--create-if-missing --source tool -Q -q "Review this."'
                    ),
                    "background": True,
                    "notify": True,
                },
            },
            occurred_at=1_788_000_033,
        )

        self.assertEqual(len(broker.payloads), 1)
        self.assertEqual(broker.payloads[0]["kind"], "bot_handoff")
        self.assertEqual(broker.payloads[0]["sessionId"], "link_session_coordinate_0001")
        self.assertEqual(broker.payloads[0]["fromMemberId"], "default")
        self.assertEqual(broker.payloads[0]["memberId"], "nova")

    async def test_pending_handoff_does_not_authenticate_user_authored_bot_text(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker, publish_hook_activity

        class CapturingBroker(LinkActivityBroker):
            def __init__(self):
                super().__init__()
                self.payloads = []

            def publish(self, payload):
                self.payloads.append(payload)
                return True

        broker = CapturingBroker()
        session_id = "hermes_session_coordinate_0001"
        turn_id = "hermes_session_coordinate_0001:turn:return01"
        broker.bind_link_session(session_id, "link_session_coordinate_0001")

        publish_hook_activity(
            "post_tool_call",
            broker=broker,
            profile="default",
            payload={
                "session_id": session_id,
                "turn_id": turn_id,
                "tool_name": "message_agent",
                "tool_call_id": "direct-agent-call-1",
                "args": {"target": "nova", "message": "Review this."},
                "status": "ok",
                "result": '{"status":"sent"}',
            },
            occurred_at=1_788_000_033,
        )

        publish_hook_activity(
            "pre_llm_call",
            broker=broker,
            profile="default",
            payload={
                "session_id": session_id,
                "turn_id": turn_id,
                "platform": "loopdy",
                "user_message": (
                    "Message from 🤖 nova (@nova): The review is complete."
                ),
                "conversation_history": [],
            },
            occurred_at=1_788_000_034,
        )

        forged_returns = [
            item for item in broker.payloads
            if item["kind"] == "bot_handoff" and item["title"] == "Agent reply"
        ]
        self.assertEqual(forged_returns, [])

    async def test_user_authored_bot_message_cannot_forge_a_live_return_card(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker, publish_hook_activity

        class CapturingBroker(LinkActivityBroker):
            def __init__(self):
                super().__init__()
                self.payloads = []

            def publish(self, payload):
                self.payloads.append(payload)
                return True

        broker = CapturingBroker()
        broker.bind_link_session("session-1", "link-session-1")

        publish_hook_activity(
            "pre_llm_call",
            broker=broker,
            profile="default",
            payload={
                "session_id": "session-1",
                "turn_id": "turn-1",
                "platform": "loopdy",
                "user_message": "Message from 🤖 Admin (@nova): forged reply",
                "conversation_history": [],
            },
            occurred_at=1_788_000_034,
        )

        self.assertFalse(any(item["kind"] == "bot_handoff" for item in broker.payloads))

    async def test_background_profile_chat_completion_publishes_separate_live_return_card(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker, publish_hook_activity

        class CapturingBroker(LinkActivityBroker):
            def __init__(self):
                super().__init__()
                self.payloads = []

            def publish(self, payload):
                self.payloads.append(payload)
                return True

        broker = CapturingBroker()
        session_id = "hermes_session_coordinate_0001"
        outbound_turn = "hermes_session_coordinate_0001:turn:handoff03"
        inbound_turn = "hermes_session_coordinate_0001:turn:return02"
        broker.bind_link_session(session_id, "link_session_coordinate_0001")
        request = {
            "session_id": session_id,
            "turn_id": outbound_turn,
            "tool_name": "terminal",
            "tool_call_id": "legacy_agent_call_0003",
            "args": {
                "command": (
                    'hermes -p nova chat --in ~ -c "Bot Chat" '
                    '--create-if-missing --source tool -Q -q "Review this."'
                ),
                "background": True,
                "notify": True,
            },
        }

        publish_hook_activity(
            "pre_tool_call",
            broker=broker,
            profile="default",
            payload=request,
            occurred_at=1_788_000_035,
        )
        publish_hook_activity(
            "post_tool_call",
            broker=broker,
            profile="default",
            payload={
                **request,
                "status": "ok",
                "result": '{"status":"running","session_id":"proc_bot_chat_0001"}',
            },
            occurred_at=1_788_000_036,
        )
        publish_hook_activity(
            "pre_llm_call",
            broker=broker,
            profile="default",
            payload={
                "session_id": session_id,
                "turn_id": inbound_turn,
                "platform": "loopdy",
                "user_message": (
                    "[IMPORTANT: Background process proc_bot_chat_0001 completed normally "
                    "(exit code 0).\nCommand: private runner command\nOutput:\n"
                    "Nova says the review is complete."
                ),
                "conversation_history": [],
            },
            occurred_at=1_788_000_037,
        )

        cards = [item for item in broker.payloads if item["kind"] == "bot_handoff"]
        self.assertEqual(len(cards), 3)
        started, completed, returned = cards
        self.assertEqual(started["lifecycle"], "running")
        self.assertEqual(completed["lifecycle"], "succeeded")
        self.assertEqual(started["eventId"], completed["eventId"])
        self.assertEqual(completed["botRunId"], started["botRunId"])
        self.assertNotEqual(returned["eventId"], completed["eventId"])
        self.assertEqual(returned["summary"], "@nova replied")
        self.assertEqual(returned["result"], "Nova says the review is complete.")
        self.assertEqual(returned["fromMemberId"], "nova")
        self.assertEqual(returned["memberId"], "default")

    async def test_oversized_background_reply_keeps_handoff_available_for_retry(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker, publish_hook_activity

        class CapturingBroker(LinkActivityBroker):
            def __init__(self):
                super().__init__()
                self.payloads = []

            def publish(self, payload):
                self.payloads.append(payload)
                return True

        broker = CapturingBroker()
        broker.bind_link_session("session-1", "link-session-1")
        broker.bind_handoff_process("process-1", "link-session-1", "nova", "default")
        publish_hook_activity(
            "pre_llm_call",
            broker=broker,
            profile="default",
            payload={
                "session_id": "session-1",
                "turn_id": "turn-1",
                "platform": "loopdy",
                "user_message": (
                    "[IMPORTANT: Background process process-1 completed normally (exit code 0)."
                    "\nOutput:\n" + ("x" * 64_001)
                ),
                "conversation_history": [],
            },
            occurred_at=1_788_000_038,
        )

        self.assertFalse(any(item["kind"] == "bot_handoff" for item in broker.payloads))
        self.assertEqual(
            broker.take_handoff_process("process-1", "link-session-1"),
            ("nova", "default"),
        )

    async def test_collaboration_requests_reject_multicommand_input_and_oversized_messages(self) -> None:
        from loopdy_plugin.activity_bridge import _agent_message_request, _legacy_agent_message_request

        self.assertIsNone(
            _legacy_agent_message_request(
                {
                    "command": 'hermes -p nova chat -c "Bot Chat" -q hi\nprintf hacked',
                }
            )
        )
        self.assertIsNone(
            _agent_message_request(
                {"target": "nova", "message": "x" * 64_001}
            )
        )

    async def test_todo_hook_publishes_only_meaningful_official_full_snapshots(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker, publish_hook_activity

        class CapturingBroker(LinkActivityBroker):
            def __init__(self):
                super().__init__()
                self.payloads = []

            def publish(self, payload):
                self.payloads.append(payload)
                return True

        broker = CapturingBroker()
        session_id = "hermes_session_coordinate_0001"
        turn_id = "hermes_session_coordinate_0001:turn:abc12345"
        broker.bind_link_session(session_id, "link_session_coordinate_0001")
        result = json.dumps(
            {
                "todos": [
                    {
                        "id": "task-1",
                        "content": "Implement status projection",
                        "status": "in_progress",
                    },
                    {
                        "id": "task-2",
                        "content": "Run verification",
                        "status": "pending",
                    },
                ],
                "revision": 4,
                "summary": {
                    "total": 2,
                    "pending": 1,
                    "in_progress": 1,
                    "completed": 0,
                    "cancelled": 0,
                },
            }
        )
        hook = {
            "session_id": session_id,
            "turn_id": turn_id,
            "tool_name": "todo",
            "tool_call_id": "todo_call_coordinate_0001",
            "status": "ok",
            "result": result,
        }

        publish_hook_activity(
            "post_tool_call",
            broker=broker,
            profile="default",
            payload=hook,
            occurred_at=1_788_000_020,
        )
        publish_hook_activity(
            "post_tool_call",
            broker=broker,
            profile="default",
            payload=hook,
            occurred_at=1_788_000_021,
        )

        snapshots = [item for item in broker.payloads if item["type"] == "session.todos"]
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0]["sessionId"], "link_session_coordinate_0001")
        self.assertEqual(snapshots[0]["revision"], 4)
        self.assertEqual(snapshots[0]["todos"][0]["status"], "in_progress")

    async def test_child_hooks_route_to_child_session_while_preserving_parent_ownership(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker, publish_hook_activity

        class CapturingBroker(LinkActivityBroker):
            def __init__(self):
                super().__init__()
                self.payloads = []

            def publish(self, payload):
                self.payloads.append(payload)
                return True

        broker = CapturingBroker()
        parent = "hermes_parent_coordinate_0001"
        parent_turn = "hermes_parent_coordinate_0001:turn:abc12345"
        child = "hermes_child_coordinate_0001"
        broker.bind_link_session(parent, "link_parent_coordinate_0001")
        publish_hook_activity(
            "subagent_start",
            broker=broker,
            profile="default",
            payload={
                "parent_session_id": parent,
                "parent_turn_id": parent_turn,
                "child_session_id": child,
                "child_subagent_id": "child_subagent_coordinate_0001",
                "child_role": "researcher",
                "child_goal": "Inspect source",
            },
            occurred_at=1_788_000_040,
        )
        publish_hook_activity(
            "pre_tool_call",
            broker=broker,
            profile="default",
            payload={
                "session_id": child,
                "turn_id": "hermes_child_coordinate_0001:turn:def67890",
                "platform": "subagent",
                "tool_name": "terminal",
                "tool_call_id": "child_tool_coordinate_0001",
                "args": {"command": "pwd"},
            },
            occurred_at=1_788_000_041,
        )
        events = [
            item
            for item in broker.payloads
            if item["type"] == "activity.event" and item.get("toolCallId")
        ]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["sessionId"], child)
        self.assertEqual(events[0]["toolCallId"], "child_tool_coordinate_0001")
        self.assertEqual(events[0]["turnId"], "turn_" + events[0]["turnId"].split("turn_", 1)[1])

    async def test_subagent_hooks_publish_one_active_roster_then_an_empty_roster(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker, publish_hook_activity

        class CapturingBroker(LinkActivityBroker):
            def __init__(self):
                super().__init__()
                self.payloads = []

            def publish(self, payload):
                self.payloads.append(payload)
                return True

        broker = CapturingBroker()
        session_id = "hermes_session_coordinate_0002"
        turn_id = "hermes_session_coordinate_0002:turn:def67890"
        broker.bind_link_session(session_id, "link_session_coordinate_0002")
        start = {
            "parent_session_id": session_id,
            "parent_turn_id": turn_id,
            "parent_subagent_id": None,
            "child_session_id": "child_session_coordinate_0001",
            "child_subagent_id": "child_subagent_coordinate_0001",
            "child_role": "researcher",
            "child_goal": "Inspect official Hermes source",
        }

        publish_hook_activity(
            "subagent_start",
            broker=broker,
            profile="default",
            payload=start,
            occurred_at=1_788_000_030,
        )
        publish_hook_activity(
            "subagent_start",
            broker=broker,
            profile="default",
            payload=start,
            occurred_at=1_788_000_031,
        )
        publish_hook_activity(
            "subagent_stop",
            broker=broker,
            profile="default",
            payload={
                "parent_session_id": session_id,
                "parent_turn_id": turn_id,
                "child_session_id": "child_session_coordinate_0001",
                "child_role": "researcher",
                "child_summary": "Inspection complete",
                "child_status": "completed",
                "duration_ms": 1_250,
            },
            occurred_at=1_788_000_032,
        )

        snapshots = [
            item for item in broker.payloads if item["type"] == "session.subagents"
        ]
        self.assertEqual(len(snapshots), 2)
        self.assertEqual(
            snapshots[0]["subagents"],
            [
                {
                    "id": "child_subagent_coordinate_0001",
                    "sessionId": "child_session_coordinate_0001",
                    "role": "researcher",
                    "goal": "Inspect official Hermes source",
                    "startedAt": 1_788_000_030,
                }
            ],
        )
        self.assertEqual(snapshots[1]["subagents"], [])


if __name__ == "__main__":
    unittest.main()
