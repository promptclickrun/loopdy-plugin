"""Link steering uses stock Hermes dispatch without completing its active turn."""
from __future__ import annotations

import asyncio
import json
import time
import unittest
from dataclasses import replace
from types import SimpleNamespace

from gateway.config import PlatformConfig
from gateway.run import GatewayRunner
from loopdy_plugin.adapter import LoopdyAdapter
from loopdy_plugin.link_client import InboundLinkTurn, LoopdyLinkClient
from loopdy_plugin.link_contracts import UserMessage
# Hermes also has a tests package. Resolve fixtures within this suite.
if __package__:
    from . import test_adapter as adapter_fixtures
    from . import test_link_client as link_fixtures
    from .test_adapter import _ActivityBroker, _LinkClient, _Service
    from .test_link_client import _State
else:
    import test_adapter as adapter_fixtures
    import test_link_client as link_fixtures
    from test_adapter import _ActivityBroker, _LinkClient, _Service
    from test_link_client import _State


class SteeringLifecycleTests(unittest.TestCase):
    setUp = adapter_fixtures.AdapterTests.setUp

    def make_fixture(self, *, link=None, handler=None):
        link = link or _LinkClient()
        broker = _ActivityBroker()
        adapter = LoopdyAdapter(PlatformConfig(enabled=True), service=_Service(),
                                link_client=link, activity_broker=broker)
        session = "session-steer-lifecycle-0001"
        # No provider, credentials, or model request: exercise the real stock
        # steer queue and tool-boundary drain on an uninitialized agent fixture.
        from run_agent import AIAgent
        agent = object.__new__(AIAgent)
        runner = object.__new__(GatewayRunner)
        runner._peek_session_state = lambda key: SimpleNamespace(
            turn=SimpleNamespace(agent=agent))
        # Match the ownership a real active Link turn receives from the runner.
        host_id = getattr(getattr(link, "config", None), "device_id", None)
        if host_id:
            try:
                from tool_execution_context import ToolExecutionContext
            except ImportError:
                ToolExecutionContext = None
            if ToolExecutionContext is not None:
                agent._tool_execution_context = ToolExecutionContext(
                    source="loopdy_link", owner_id="mobile-device-1", scope_id="default",
                    authorization_epoch=1, attributes={"host_id": host_id})
        async def dispatch(event):
            return await GatewayRunner._busy_steer_command(runner, event, "fixture-key", event.source)
        adapter.set_message_handler(handler or dispatch)
        source = adapter.build_source(chat_id=session, chat_type="dm", user_id="fixture_sender")
        source.profile = "default"
        key = adapter._link_session_key(source)
        guard = asyncio.Event()
        adapter._active_sessions[key] = guard
        adapter._remember_verified_link_profile(session, "default")
        turn = InboundLinkTurn(
            message=UserMessage(message_id="message-steer-lifecycle-0001",
                session_id=session, agent_id="default", actor_id="actor-fixture",
                actor_name="Alex", device_name="iPhone", text="Use the second option",
                behavior="steer", sent_at=int(time.time())),
            sender_id="fixture_sender", sender_device_id="mobile-device-1",
            sender_epoch=1, attachment_paths=(), attachment_types=())
        return adapter, link, broker, agent, key, guard, turn

    def test_steer_ack_keeps_live_draft_and_run_active(self):
        async def scenario():
            adapter, link, broker, agent, key, guard, turn = self.make_fixture()
            session = turn.message.session_id
            await adapter.send_draft(session, 41, "Working on the original request")
            original_id = link.payloads[-1]["messageId"]
            await adapter.receive_link_turn(turn)
            self.assertIn("Use the second option", agent._pending_steer)
            self.assertIs(adapter._active_sessions.get(key), guard)
            self.assertFalse(guard.is_set())
            self.assertEqual(broker.completions, [], "Steer acknowledgment completed the active run")
            self.assertFalse(any(p.get("delivery") == "final" for p in link.payloads),
                             "Steer acknowledgment finalized the pending assistant")
            # A second steer is admitted without replacing the first or owner.
            await adapter.receive_link_turn(replace(turn, message=replace(turn.message,
                message_id="message-steer-lifecycle-0002", text="Keep the original scope")))
            from agent.agent_runtime_helpers import apply_pending_steer_to_tool_results
            messages = [{"role": "tool", "tool_call_id": "fixture-tool", "content": "Tool finished"}]
            apply_pending_steer_to_tool_results(agent, messages, 1)
            self.assertIn("Use the second option", messages[-1]["content"])
            self.assertIn("Keep the original scope", messages[-1]["content"])
            self.assertIsNone(agent._drain_pending_steer())
            self.assertEqual([message["role"] for message in messages], ["tool", "user"])
            self.assertEqual(messages[0]["content"], "Tool finished")
            await adapter.send(session, "Original task completed with your correction")
            self.assertEqual(link.payloads[-1]["messageId"], original_id)
            self.assertEqual(link.payloads[-1]["delivery"], "final")
            self.assertEqual(len(broker.completions), 1)
        asyncio.run(scenario())

    def test_only_owned_successful_control_replies_are_consumed(self):
        async def scenario(reply, behavior="steer", explicit=False):
            async def handler(event):
                return reply
            adapter, link, broker, _, _, _, turn = self.make_fixture(handler=handler)
            text = "/steer Use the second option" if explicit else turn.message.text
            turn = replace(turn, message=replace(turn.message, behavior=behavior, text=text))
            await adapter.receive_link_turn(turn)
            self.assertEqual(link.payloads, [])
            self.assertEqual(broker.completions, [])
        for reply, behavior, explicit in [
            ("⏩ Steer queued — arrives after the next tool call: 'Use the second option'", "steer", False),
            ("Agent still starting — /steer queued for the next turn.", "steer", False),
            ("No active agent — /steer queued for the next turn.", "steer", False),
            ("Queued for the next turn. (2 queued)", "queue", False),
            ("⏩ Steer queued — arrives after the next tool call: 'Use the second option'", None, True),
        ]:
            with self.subTest(reply=reply):
                asyncio.run(scenario(reply, behavior, explicit))
        for reply in ["Steer rejected (empty payload).", "⚠️ Steer failed: fixture failure", "Unrecognized response"]:
            with self.subTest(reply=reply), self.assertRaisesRegex(
                RuntimeError, "Hermes could not confirm this control request"
            ):
                asyncio.run(scenario(reply))

    def test_delayed_control_reply_does_not_capture_concurrent_final(self):
        async def scenario():
            entered, release = asyncio.Event(), asyncio.Event()
            async def handler(event):
                entered.set()
                await release.wait()
                return "⏩ Steer queued — arrives after the next tool call: 'Use the second option'"
            adapter, link, broker, _, _, _, turn = self.make_fixture(handler=handler)
            pending = asyncio.create_task(adapter.receive_link_turn(turn))
            await entered.wait()
            await adapter.send(turn.message.session_id, "The real final while the acknowledgment waits")
            release.set()
            await pending
            self.assertEqual(len(link.payloads), 1)
            self.assertEqual(link.payloads[0]["delivery"], "final")
            self.assertEqual(len(broker.completions), 1)
        asyncio.run(scenario())

    def test_idle_steer_keeps_background_final_even_with_inherited_context(self):
        async def scenario():
            ended = asyncio.Event()
            async def handler(event):
                ended.set()
                return "Idle request completed"
            adapter, link, broker, _, key, _, turn = self.make_fixture(handler=handler)
            adapter._active_sessions.pop(key)
            await adapter.receive_link_turn(turn)
            await ended.wait()
            await asyncio.gather(*tuple(adapter._background_tasks))
            self.assertEqual(len(link.payloads), 1)
            self.assertEqual(link.payloads[0]["text"], "Idle request completed")
            self.assertEqual(link.payloads[0]["delivery"], "final")
            self.assertEqual(len(broker.completions), 1)
        asyncio.run(scenario())

    def test_encrypted_deferred_steer_gets_receipt_without_waiting_for_task_final(self):
        async def scenario():
            _, config = link_fixtures.LinkClientTests()._configuration()
            client = LoopdyLinkClient(config, state=_State())
            outgoing = []
            class Socket:
                async def send(self, raw):
                    message = json.loads(raw)
                    outgoing.append(message)
                    if message.get("type") == "frame":
                        client._accept_outbound({"version": 1, "type": "accepted",
                            "id": message["id"], "sequence": message["sequence"]})
            client._socket = Socket()
            client._connected.set()
            adapter, _, broker, agent, key, guard, turn = self.make_fixture(link=client)
            payload = {"version": 1, "type": "user.message",
                "messageId": turn.message.message_id, "sessionId": turn.message.session_id,
                "agentId": "default", "actorId": "actor-fixture", "actorName": "Alex",
                "deviceName": "iPhone", "text": turn.message.text, "behavior": "steer",
                "attachments": [], "sentAt": int(time.time())}
            wire = json.dumps({"version": 1, "type": "frame", "id": "frame-steer-lifecycle-0001",
                "senderDeviceId": "mobile-device-1", "senderEpoch": 1, "sequence": 1,
                "ack": 0, "ciphertext": client.cipher.seal(payload)})
            try:
                await client.handle_wire_message(wire, adapter.receive_link_turn, defer_callbacks=True)
                await asyncio.wait_for(client._inbound_callback_queue.join(), 2)
                responses = [client.cipher.open(frame["ciphertext"]) for frame in outgoing
                             if frame.get("type") == "frame"]
                self.assertEqual([r["type"] for r in responses], ["user.message.result"])
                self.assertEqual(responses[0]["status"], "accepted")
                self.assertEqual(responses[0]["requestId"], turn.message.message_id)
                self.assertIn(turn.message.text, agent._pending_steer)
                self.assertIs(adapter._active_sessions.get(key), guard)
                self.assertEqual(broker.completions, [])
                self.assertEqual([f["sequence"] for f in outgoing if f.get("type") == "receipt"], [1])
            finally:
                await client._stop_inbound_callback_dispatcher()
        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
