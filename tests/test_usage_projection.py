"""Usage projection consumes public API-request hooks, not agent internals."""
import asyncio
import unittest

from loopdy_plugin.activity_bridge import LinkActivityBroker


class UsageProjectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_duplicates_stale_requests_and_reset_preserve_session_boundaries(self):
        broker = LinkActivityBroker()
        broker.bind_link_session("canonical-session", "visible-link")
        broker.bind_link_session("retained-alias", "visible-link")
        broker.record_api_usage(session_id="canonical-session", model="model",
            turn_id="turn", api_request_id="request-2", api_call_count=2,
            usage={"prompt_tokens":100,"cache_read_tokens":80})
        for request_id, count in (("request-2", 2), ("request-1", 1)):
            broker.record_api_usage(session_id="canonical-session", model="model",
                turn_id="turn", api_request_id=request_id, api_call_count=count,
                usage={"prompt_tokens":999,"cache_read_tokens":999})
        self.assertEqual(broker.usage_snapshot("canonical-session", "model")["cachedTokens"], 80)
        self.assertEqual(broker.bound_link_session("canonical-session"), "visible-link")
        broker.record_api_usage(session_id="canonical-session", model="model",
            turn_id="turn", api_request_id="request-3", api_call_count=3, usage=None)
        self.assertIsNone(broker.usage_snapshot("canonical-session", "model"))
        broker.record_api_usage(session_id="canonical-session", model="model",
            api_request_id="request-4", usage={"prompt_tokens":True})
        self.assertIsNone(broker.usage_snapshot("canonical-session", "model"))
        broker.reset_api_usage(session_id="canonical-session")
        self.assertIsNone(broker.usage_snapshot("canonical-session", "model"))
        self.assertEqual(broker.bound_link_session("retained-alias"), "visible-link")

    async def test_hook_usage_reaches_existing_context_wire_fields(self):
        broker = LinkActivityBroker()
        received = []

        async def sender(payload):
            received.append(payload)

        broker.attach_context_provider(lambda _: {
            "model": "fixture-model", "contextUsed": 0, "contextMax": 10000,
            "contextPercent": 0, "compressions": 0, "isCompacting": False,
        })
        await broker.attach(sender)
        try:
            broker.activate("hermes-session", "turn-1", link_session_id="link-session")
            broker.record_api_usage(session_id="hermes-session", turn_id="turn-1",
                api_request_id="request-1", api_call_count=1, model="fixture-model",
                usage={"input_tokens":11, "output_tokens":7, "cache_read_tokens":200,
                       "cache_write_tokens":300, "reasoning_tokens":2,
                       "prompt_tokens":511, "total_tokens":518},
                response={"private": "MUST-NOT-LEAK"})
            broker.publish_context_window("hermes-session", "turn-1", force=True)
            await asyncio.sleep(0.05)
            payload = [x for x in received if x.get("type") == "session.context"][-1]
            self.assertEqual(payload["contextUsed"], 511)
            self.assertEqual(payload["inputTokens"], 511)
            self.assertEqual(payload["outputTokens"], 7)
            self.assertEqual(payload["cachedTokens"], 200)
            self.assertEqual(payload["totalTokens"], 518)
            self.assertNotIn("MUST-NOT-LEAK", str(received))
        finally:
            await broker.detach()

    async def test_usage_absence_and_other_session_cannot_invent_counters(self):
        broker = LinkActivityBroker()
        broker.bind_link_session("session-one", "link-one")
        broker.record_api_usage(session_id="session-one", model="fixture-model",
                               api_request_id="request-one", usage=None)
        self.assertIsNone(broker.usage_snapshot("session-one", "fixture-model"))
        broker.record_api_usage(session_id="session-one", model="fixture-model",
                               api_request_id="request-two", usage={
                                   "prompt_tokens":12,"output_tokens":2,"total_tokens":14,
                                   "cache_read_tokens":0})
        self.assertIsNone(broker.usage_snapshot("session-two", "fixture-model"))
        self.assertIsNone(broker.usage_snapshot("session-one", "different-model"))
        self.assertEqual(broker.usage_snapshot("session-one", "fixture-model")["cachedTokens"],0)


if __name__ == "__main__":
    unittest.main()
