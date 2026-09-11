"""Optional host capability must not become a mandatory chat dependency."""
from __future__ import annotations

import asyncio
import sys
import unittest
from contextlib import contextmanager
from dataclasses import field, make_dataclass
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, patch

from gateway.config import PlatformConfig
from gateway.platform_registry import PlatformEntry, platform_registry
from loopdy_plugin.adapter import LoopdyAdapter, MessageEvent
from loopdy_plugin.link_client import InboundLinkTurn
from loopdy_plugin.link_contracts import UserMessage
from loopdy_plugin.registration import _device_tools_supported
from test_adapter import _LinkClient, _Service


@contextmanager
def supported_context_host():
    """Test-only host contract fixture; never installed in a Hermes runtime."""
    event_type = make_dataclass("ContextMessageEvent",
        [("tool_execution_context", object, field(default=None, repr=False))],
        bases=(MessageEvent,))
    context_type = make_dataclass("FixtureToolExecutionContext", [
        ("source", str), ("owner_id", str), ("scope_id", str),
        ("authorization_epoch", int), ("attributes", dict),
    ], frozen=True)
    module = ModuleType("tool_execution_context")
    module.ToolExecutionContext = context_type
    with (
        patch("loopdy_plugin.adapter.MessageEvent", event_type),
        patch.dict(sys.modules, {"tool_execution_context": module}),
    ):
        yield context_type


class OptionalDeviceContextTests(unittest.TestCase):
    def setUp(self):
        platform_registry.register(PlatformEntry(name="loopdy", label="Loopdy",
            adapter_factory=lambda config: None, check_fn=lambda: True))

    def test_stock_host_admits_verified_chat_without_optional_context(self):
        completed = asyncio.Event()

        class ObservedAdapter(LoopdyAdapter):
            async def on_processing_complete(self, event, outcome):
                await super().on_processing_complete(event, outcome)
                completed.set()

        link = _LinkClient()
        link.config = SimpleNamespace(device_id="host-fixture")
        adapter = ObservedAdapter(PlatformConfig(enabled=True), service=_Service(), link_client=link)
        handler = AsyncMock(return_value=None)
        adapter.set_message_handler(handler)
        turn = InboundLinkTurn(
            message=UserMessage(message_id="message-fixture", session_id="session-coordinate-fixture",
                agent_id="default", actor_id="actor-fixture", actor_name="Alex",
                device_name="Fixture phone", text="hello", attachments=(), sent_at=1788000000),
            sender_id="sender-fixture", sender_device_id="private-phone-fixture", sender_epoch=3,
        )
        async def exercise():
            await adapter.receive_link_turn(turn)
            await asyncio.wait_for(completed.wait(), timeout=3)

        with patch.dict(sys.modules, {"tool_execution_context": None}):
            asyncio.run(exercise())
            self.assertFalse(_device_tools_supported())
        handler.assert_awaited_once()
        event = handler.await_args.args[0]
        self.assertEqual(event.text, "hello")
        self.assertEqual(event.source.chat_id, "session-coordinate-fixture")
        self.assertEqual(event.source.profile, "default")
        self.assertIsNone(getattr(event, "tool_execution_context", None))
        self.assertNotIn("private-phone-fixture", repr(event))

    def test_importable_context_without_event_support_does_not_enable_phone_tools(self):
        module = ModuleType("tool_execution_context")
        module.ToolExecutionContext = SimpleNamespace
        with patch.dict(sys.modules, {"tool_execution_context": module}):
            self.assertFalse(_device_tools_supported())

    def test_phone_tool_gate_requires_both_host_contract_parts(self):
        with supported_context_host():
            self.assertTrue(_device_tools_supported())
            with patch.dict(sys.modules, {"tool_execution_context": None}):
                self.assertFalse(_device_tools_supported())


if __name__ == "__main__":
    unittest.main()
