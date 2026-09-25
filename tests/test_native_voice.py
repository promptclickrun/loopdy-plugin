"""Native media ownership and at-most-once boundaries; no real provider calls."""
import asyncio
from dataclasses import replace
import json
import unittest

from loopdy_plugin.live_voice_provider import LiveProviderError
from loopdy_plugin.native_context import NativeContext, NativeAPIError
from loopdy_plugin.native_voice import NativeVoiceHub

SDP = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"


class Provider:
    def __init__(self, **kwargs):
        self.event = kwargs["on_event"]
        self.creates = 0
        self.results = []
        self.closed = False
        self.provider_event_types = {}
        self.schema_mismatches = 0

    async def create(self, sdp, **kwargs):
        self.creates += 1
        await self.event({"kind": "started"})
        return SDP

    async def append_result(self, identifier, text, **kwargs):
        self.results.append((identifier, text))

    async def close(self):
        self.closed = True


class NativeVoiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.providers = []
        def factory(**kwargs):
            provider = Provider(**kwargs)
            self.providers.append(provider)
            return provider
        self.hub = NativeVoiceHub(provider_factory=factory, lease_seconds=30)
        self.owner = NativeContext("fixture", "alice", None, "default", ("native-voice-v1",), "runtime")
        self.fields = {"agentId": "default", "sessionId": "stored", "voiceId": "voice_fixture",
                       "provider": "codex_subscription", "voice": "cove", "sdp": SDP}

    async def asyncTearDown(self):
        await self.hub.shutdown()

    async def offer(self):
        return await self.hub.offer(self.owner, self.fields)

    async def test_provider_is_reused_without_cloud_and_repeat_offer_never_allocates(self):
        self.assertEqual((await self.offer())["sdp"], SDP)
        with self.assertRaises(NativeAPIError):
            await self.offer()
        self.assertEqual(len(self.providers), 1)
        self.assertEqual(self.providers[0].creates, 1)
        page = self.hub.poll(self.owner, self.fields, after=0)
        self.assertEqual(page["events"][0]["event"]["kind"], "started")

    async def test_owner_profile_session_and_runtime_cannot_adopt_call(self):
        await self.offer()
        for owner, fields in [
            (replace(self.owner, user_id="bob"), self.fields),
            (replace(self.owner, runtime_id="replacement"), self.fields),
            (self.owner, dict(self.fields, agentId="other")),
            (self.owner, dict(self.fields, sessionId="other")),
        ]:
            with self.assertRaises(NativeAPIError):
                self.hub.poll(owner, fields, after=0)
            with self.assertRaises(NativeAPIError):
                await self.hub.close(owner, fields)

    async def test_close_winning_offer_race_consumes_id_without_allocating(self):
        await self.hub.close(self.owner, self.fields)
        with self.assertRaises(NativeAPIError):
            await self.offer()
        self.assertEqual(self.providers, [])

    async def test_nonfatal_error_does_not_hang_up_and_result_cannot_replay(self):
        await self.offer()
        provider = self.providers[0]
        await provider.event({"kind": "provider_error", "fatal": False, "code": "upstream_error"})
        self.assertFalse(provider.closed)
        await provider.event({"kind": "delegation", "id": "item-one", "text": "Check tomorrow's calendar"})
        fields = dict(self.fields, delegationId="item-one", text="Hermes returned three events.")
        await self.hub.result(self.owner, fields)
        with self.assertRaises(NativeAPIError):
            await self.hub.result(self.owner, fields)
        self.assertEqual(provider.results, [("item-one", "Hermes returned three events.")])
        with self.assertRaises(NativeAPIError):
            await self.hub.result(self.owner, dict(fields, delegationId="unseen"))

    async def test_poll_reports_payload_free_provider_diagnostics_and_turn_counters(self):
        await self.offer()
        provider = self.providers[0]
        provider.provider_event_types = {
            "session.started": 1,
            "delegation.created": 1,
            "private_text": "must not escape",
            "\ud800": 99,
        }
        provider.schema_mismatches = 2
        await provider.event({"kind": "delegation", "id": "item", "text": "Check calendar"})
        await self.hub.result(self.owner, dict(self.fields, delegationId="item", text="Two events."))

        diagnostics = self.hub.poll(self.owner, self.fields, after=0)["diagnostics"]
        self.assertEqual(set(diagnostics), {
            "providerEventTypes", "schemaMismatches", "admittedDelegations", "appendedResults",
        })
        self.assertEqual(diagnostics["providerEventTypes"], {
            "session.started": 1, "delegation.created": 1,
        })
        self.assertEqual(diagnostics["schemaMismatches"], 2)
        self.assertEqual(diagnostics["admittedDelegations"], 1)
        self.assertEqual(diagnostics["appendedResults"], 1)
        encoded = json.dumps(diagnostics)
        self.assertNotIn("Check calendar", encoded)
        self.assertNotIn("Two events", encoded)
        self.assertNotIn("must not escape", encoded)

    async def test_lost_append_receipt_is_not_retried(self):
        await self.offer()
        provider = self.providers[0]
        await provider.event({"kind": "delegation", "id": "item", "text": "Hello"})
        async def uncertain(*args):
            provider.results.append(args)
            raise OSError("lost receipt")
        provider.append_result = uncertain
        fields = dict(self.fields, delegationId="item", text="Verified reply")
        with self.assertRaises(OSError):
            await self.hub.result(self.owner, fields)
        with self.assertRaises(NativeAPIError):
            await self.hub.result(self.owner, fields)
        self.assertEqual(len(provider.results), 1)

    async def test_expired_media_does_not_submit_or_cancel_a_hermes_turn(self):
        self.hub.lease_seconds = 0.01
        await self.offer()
        await asyncio.sleep(0.03)
        self.assertTrue(self.providers[0].closed)
        self.assertTrue(self.hub.poll(self.owner, self.fields, after=0)["closed"])


class NativeVoiceProviderFailureTests(unittest.IsolatedAsyncioTestCase):
    """Setup failures carry the provider's fixed reason, never a generic outage."""

    async def asyncSetUp(self):
        self.providers = []
        self.failure = None
        outer = self

        class Failing(Provider):
            async def create(self, sdp, **kwargs):
                self.creates += 1
                if outer.failure == "hang":
                    await asyncio.sleep(1)
                raise outer.failure

        def factory(**kwargs):
            provider = Failing(**kwargs)
            self.providers.append(provider)
            return provider
        self.hub = NativeVoiceHub(provider_factory=factory, lease_seconds=30, setup_seconds=0.05)
        self.owner = NativeContext("fixture", "alice", None, "default", ("native-voice-v1",), "runtime")
        self.fields = {"agentId": "default", "sessionId": "stored", "voiceId": "voice_fixture",
                       "provider": "codex_subscription", "voice": "cove", "sdp": SDP}

    async def asyncTearDown(self):
        await self.hub.shutdown()

    async def test_provider_refusal_reports_its_code_and_closes_the_call(self):
        self.failure = LiveProviderError("rate_limited", stage="create", allocation_state="rejected", http_status=429)
        with self.assertLogs("loopdy_plugin.native_voice", level="WARNING") as logs:
            with self.assertRaises(NativeAPIError) as caught:
                await self.hub.offer(self.owner, self.fields)
        self.assertEqual((caught.exception.status, caught.exception.code), (409, "voice_provider_rate_limited"))
        self.assertTrue(self.providers[0].closed)
        self.assertTrue(self.hub.calls["voice_fixture"].closed)
        self.assertIn("code=rate_limited stage=create http_status=429", logs.output[0])

    async def test_setup_timeout_is_named(self):
        self.failure = "hang"
        with self.assertRaises(NativeAPIError) as caught:
            await self.hub.offer(self.owner, self.fields)
        self.assertEqual(caught.exception.code, "voice_provider_setup_timeout")
        self.assertTrue(self.providers[0].closed)

    async def test_invalid_offer_is_rejected_before_any_allocation(self):
        with self.assertRaises(NativeAPIError) as caught:
            await self.hub.offer(self.owner, dict(self.fields, sdp="v=0\r\nm=video 9 RTP/AVP 96\r\n"))
        self.assertEqual(caught.exception.code, "voice_provider_audio_only_required")
        self.assertEqual(self.providers, [])

    async def test_unexpected_code_shape_never_leaves_the_host(self):
        self.failure = LiveProviderError("Bearer sk-secret/leak", stage="create")
        with self.assertRaises(NativeAPIError) as caught:
            await self.hub.offer(self.owner, self.fields)
        self.assertEqual(caught.exception.code, "voice_provider_failed")
        self.assertNotIn("secret", caught.exception.message)
