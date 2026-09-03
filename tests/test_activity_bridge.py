from __future__ import annotations

import asyncio
import json
import threading
import unittest
from types import SimpleNamespace


class ActivityBridgeTests(unittest.IsolatedAsyncioTestCase):
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
