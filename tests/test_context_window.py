from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace

from gateway.config import PlatformConfig
from gateway.platform_registry import PlatformEntry, platform_registry

from loopdy_plugin.activity_bridge import LinkActivityBroker, publish_hook_activity
from loopdy_plugin.adapter import LoopdyAdapter


class _Service:
    def health(self):
        return {"configured": True}


class _ContextProviderBroker:
    def __init__(self) -> None:
        self.provider = None
        self.session_store = None

    def attach_context_provider(self, provider) -> None:
        self.provider = provider

    def attach_session_store(self, session_store) -> None:
        self.session_store = session_store


async def _wait_until(predicate, *, timeout: float = 1.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() >= deadline:
            raise AssertionError("Timed out waiting for context-window payload")
        await asyncio.sleep(0.005)


class ContextWindowTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        platform_registry.register(
            PlatformEntry(
                name="loopdy",
                label="Loopdy",
                adapter_factory=lambda config: None,
                check_fn=lambda: True,
            )
        )

    async def test_adapter_reads_context_from_the_official_running_agent(self) -> None:
        broker = _ContextProviderBroker()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=SimpleNamespace(),
            activity_broker=broker,
        )
        entry = SimpleNamespace(
            session_id="hermes-session-1",
            session_key="agent:main:loopdy:chat-1",
            last_prompt_tokens=12_000,
        )
        store = SimpleNamespace(
            lookup_by_session_id=lambda session_id: (
                entry if session_id == entry.session_id else None
            )
        )
        compressor = SimpleNamespace(
            last_prompt_tokens=154_200,
            context_length=272_000,
            compression_count=2,
        )
        agent = SimpleNamespace(
            model="anthropic/claude-fable-5",
            context_compressor=compressor,
            _active_compression_lock_holder=None,
        )
        adapter.gateway_runner = SimpleNamespace(
            _running_agents={entry.session_key: agent},
            _agent_cache={},
            _agent_cache_lock=None,
        )

        adapter.set_session_store(store)

        self.assertIs(broker.session_store, store)
        self.assertIsNotNone(broker.provider)
        self.assertEqual(
            broker.provider(entry.session_id),
            {
                "model": "anthropic/claude-fable-5",
                "contextUsed": 154_200,
                "contextMax": 272_000,
                "contextPercent": 57,
                "compressions": 2,
                "isCompacting": False,
            },
        )

    async def test_active_turn_pushes_pre_active_and_final_compaction_context(self) -> None:
        broker = LinkActivityBroker()
        broker.context_poll_interval_seconds = 0.01
        received: list[dict] = []
        delivered = asyncio.Event()
        state = {
            "model": "anthropic/claude-fable-5",
            "contextUsed": 164_444,
            "contextMax": 272_000,
            "contextPercent": 60,
            "compressions": 0,
            "isCompacting": False,
        }

        async def sender(payload):
            if payload.get("type") == "session.context":
                received.append(payload)
                delivered.set()

        broker.attach_context_provider(lambda _session_id: dict(state))
        broker.bind_link_session("hermes-session-2", "link-chat-2")
        await broker.attach(sender)

        publish_hook_activity(
            "pre_llm_call",
            broker=broker,
            profile="default",
            payload={
                "session_id": "hermes-session-2",
                "turn_id": "turn-coordinate-2",
                "platform": "loopdy",
            },
            occurred_at=1_788_000_000,
        )
        await _wait_until(lambda: len(received) == 1)
        self.assertEqual(
            received[0],
            {
                "version": 1,
                "type": "session.context",
                "sessionId": "link-chat-2",
                "model": "anthropic/claude-fable-5",
                "contextUsed": 164_444,
                "contextMax": 272_000,
                "contextPercent": 60,
                "compressions": 0,
                "isCompacting": False,
                "updatedAt": received[0]["updatedAt"],
            },
        )

        delivered.clear()
        state["isCompacting"] = True
        await _wait_until(lambda: len(received) == 2)
        self.assertTrue(received[1]["isCompacting"])
        self.assertEqual(received[1]["contextUsed"], 164_444)

        state.update(
            contextUsed=64_128,
            contextPercent=24,
            compressions=1,
            isCompacting=False,
        )
        publish_hook_activity(
            "post_llm_call",
            broker=broker,
            profile="default",
            payload={
                "session_id": "hermes-session-2",
                "turn_id": "turn-coordinate-2",
                "platform": "loopdy",
            },
            occurred_at=1_788_000_005,
        )
        await _wait_until(lambda: len(received) == 3)

        self.assertEqual(received[2]["contextUsed"], 64_128)
        self.assertEqual(received[2]["contextPercent"], 24)
        self.assertEqual(received[2]["compressions"], 1)
        self.assertFalse(received[2]["isCompacting"])
        self.assertFalse(broker.is_active("hermes-session-2", "turn-coordinate-2"))
        await broker.detach()

    async def test_unchanged_periodic_context_is_not_republished(self) -> None:
        broker = LinkActivityBroker()
        broker.context_poll_interval_seconds = 0.01
        received: list[dict] = []
        broker.attach_context_provider(
            lambda _session_id: {
                "model": "gpt-5.6-sol",
                "contextUsed": 80_000,
                "contextMax": 272_000,
                "contextPercent": 29,
                "compressions": 0,
                "isCompacting": False,
            }
        )
        broker.bind_link_session("hermes-session-3", "link-chat-3")

        async def sender(payload):
            if payload.get("type") == "session.context":
                received.append(payload)

        await broker.attach(sender)
        publish_hook_activity(
            "pre_llm_call",
            broker=broker,
            profile="default",
            payload={
                "session_id": "hermes-session-3",
                "turn_id": "turn-coordinate-3",
                "platform": "loopdy",
            },
        )
        await _wait_until(lambda: len(received) == 1)
        await asyncio.sleep(0.05)

        self.assertEqual(len(received), 1)
        await broker.detach()


if __name__ == "__main__":
    unittest.main()
