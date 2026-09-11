"""Primary subscription wire contract. Fixtures contain no credentials."""
import unittest
import asyncio
import json
import secrets
import httpx

from loopdy_plugin.live_voice_auth import LiveCredentials


class _Auth:
    async def resolve(self):
        return LiveCredentials(secrets.token_urlsafe(24), "fixture-account")


class _Socket:
    def __init__(self):
        self.incoming = asyncio.Queue()
        self.incoming.put_nowait(json.dumps({"type":"session.started","session":{}}))
        self.sent = []
        self.closed = False
    async def recv(self):
        return await self.incoming.get()
    async def send(self, text):
        self.sent.append(json.loads(text))
    async def close(self, **_kwargs):
        self.closed = True


class LiveVoiceTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_http_serializer_attaches_sideband_once_before_returning_sdp(self):
        from loopdy_plugin.live_voice_provider import CodexLiveProvider, CODEX_CALL_URL
        sdp = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
        requests, sockets, events = [], [], []
        async def handle(request):
            requests.append(request)
            self.assertEqual(str(request.url), CODEX_CALL_URL)
            self.assertEqual(json.loads(request.content)["session"]["model"], "gpt-live-1-codex")
            self.assertEqual(request.headers["OpenAI-Alpha"], "quicksilver=v2")
            return httpx.Response(201, headers={"Location":"/v1/live/rtc_fixture"}, text=sdp)
        ws = _Socket()
        async def connect(url, **options):
            sockets.append(url)
            self.assertEqual(url,"wss://api.openai.com/v1/live/rtc_fixture")
            self.assertEqual(options["additional_headers"]["session-id"], requests[0].headers["session-id"])
            return ws
        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
            provider = CodexLiveProvider(auth=_Auth(), http_client=client, websocket_connect=connect, on_event=events.append)
            try:
                self.assertEqual(await provider.create(sdp), sdp)
                await provider.wait_started()
                await provider.append_result("delegation_a", "First result")
                await provider.append_result("delegation_b", "Second result")
                self.assertEqual([x["delegation_item_id"] for x in ws.sent], ["delegation_a", "delegation_b"])
                with self.assertRaises(Exception):
                    await provider.create(sdp)
                self.assertEqual(len(requests),1)
                self.assertEqual(len(sockets),1)
            finally:
                await provider.close()
            self.assertTrue(ws.closed)
            self.assertEqual(ws.sent[-1]["type"], "session.close")

    async def test_subscription_denial_never_falls_back_or_reposts(self):
        from loopdy_plugin.live_voice_provider import CodexLiveProvider, LiveProviderError
        called=[]
        async def handler(request):
            called.append(str(request.url))
            return httpx.Response(403, text="untrusted provider body must not escape")
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            provider=CodexLiveProvider(auth=_Auth(),http_client=client)
            with self.assertRaises(LiveProviderError) as error:
                await provider.create("v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n")
            self.assertEqual(error.exception.code,"access_denied")
            self.assertNotIn("untrusted",str(error.exception))
            self.assertEqual(len(called),1)


class LiveVoiceProviderTests(unittest.TestCase):
    def test_subscription_delegation_preserves_opaque_identity_and_task(self):
        from loopdy_plugin.live_voice_provider import CodexLiveProvider
        event = CodexLiveProvider.decode_event({
            "type": "delegation.created", "item": {
                "type": "delegation", "target": "client", "id": "delegation_fixture_a",
                "content": [{"type": "input_text", "text": "Inspect the project."}],
            },
        })
        self.assertEqual(event, {"kind": "delegation", "id": "delegation_fixture_a", "text": "Inspect the project."})
        self.assertIsNone(CodexLiveProvider.decode_event({
            "type": "session.delegation.created", "id": "public-api-shape-must-not-be-adopted",
        }))

    def test_audio_interruption_is_not_task_cancellation(self):
        from loopdy_plugin.live_voice_provider import CodexLiveProvider
        self.assertEqual(CodexLiveProvider.decode_event({"type": "output_audio_buffer.cleared"}),
                         {"kind": "audio_cleared"})

    def test_results_use_speakable_quicksilver_channel(self):
        from loopdy_plugin.live_voice_provider import CodexLiveProvider
        frames = CodexLiveProvider.result_frames("delegation_fixture_a", "Finished: " + "🧑🏾‍💻" * 150)
        self.assertGreater(len(frames), 1)
        self.assertEqual("".join(x["content"][0]["text"] for x in frames), "Finished: " + "🧑🏾‍💻" * 150)
        for frame in frames:
            self.assertEqual(frame["type"], "delegation.context.append")
            self.assertEqual(frame["delegation_item_id"], "delegation_fixture_a")
            self.assertEqual(frame["channel"], "speakable")
            self.assertLessEqual(len(frame["content"][0]["text"].encode()), 500)
