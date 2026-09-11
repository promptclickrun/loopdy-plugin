"""Actual Loopdy adapter and stock BasePlatformAdapter; synthetic external provider."""
import asyncio
import secrets
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from cryptography.hazmat.primitives.asymmetric import ec
from gateway.config import PlatformConfig
from gateway.platform_registry import PlatformEntry, platform_registry
from loopdy_plugin.adapter import LoopdyAdapter
from loopdy_plugin.link_client import LinkRuntimeConfig
from test_adapter import _LinkClient, _Service


def signing_fixture(device_id="host-fixture"):
    return LinkRuntimeConfig("https://link.example",device_id,1,ec.generate_private_key(ec.SECP256R1()),secrets.token_bytes(32))


class LiveRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_gateway_jobs_finish_in_reverse_order_and_voice_close_does_not_cancel(self):
        platform_registry.register(PlatformEntry(name="loopdy",label="Loopdy",adapter_factory=lambda _:None,check_fn=lambda:True))
        class Client(_LinkClient):
            async def send_payload(self,payload,**kwargs):
                self.payloads.append(payload)
                return "frame_fixture"
        class Provider:
            def __init__(self,**kwargs): self.callback=kwargs["on_event"];self.results=[];self.closed=False
            async def create(self,sdp,**kwargs):
                await self.callback({"kind":"started"})
                return sdp
            async def append_result(self,id,text): self.results.append((id,text))
            async def close(self): self.closed=True;return {"cleanup_confirmed":True}
        class Workspace:
            async def execute(self,request,**kwargs):
                if request.operation=="agents.list": return {"agents":[{"id":"default"}]}
                raise ValueError("unexpected fixture operation")
        link=Client();link.config=signing_fixture();link.peer_capabilities={"directed-frames-v1"}
        link.identity_registry=SimpleNamespace(remember=lambda **kwargs:"verified_fixture_sender")
        providers=[]
        def factory(**kwargs):
            item=Provider(**kwargs);providers.append(item);return item
        gates={"First task":asyncio.Event(),"Second task":asyncio.Event()}
        seen=[]
        with tempfile.TemporaryDirectory() as directory:
            adapter=LoopdyAdapter(PlatformConfig(enabled=True),service=_Service(),link_client=link,
                workspace_controller=Workspace(),live_voice_provider_factory=factory,live_voice_storage_root=Path(directory))
            async def handler(event):
                seen.append((event.source.chat_id,event.text))
                await gates[event.text].wait()
                return event.text+" completed"
            adapter.set_message_handler(handler)
            runtime=adapter._ensure_live_voice_runtime()
            route=adapter._link_reply_route("phone-fixture",1)
            base={"agentId":"default","sessionId":"session_voice_fixture","voiceId":"voice_fixture"}
            try:
                await runtime.dispatch(None,{**base,"type":"voice.live.offer","sdp":"v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"},route)
                provider=providers[0]
                for id,text in (("delegation_first","First task"),("delegation_second","Second task")):
                    await provider.callback({"kind":"delegation","id":id,"text":text})
                async with asyncio.timeout(3):
                    while len(seen)<2: await asyncio.sleep(.01)
                self.assertNotEqual(seen[0][0],seen[1][0])
                gates["Second task"].set()
                async with asyncio.timeout(3):
                    while not provider.results: await asyncio.sleep(.01)
                self.assertEqual(provider.results[0],("delegation_second","Second task completed"))
                await runtime.dispatch(None,{**base,"type":"voice.live.close"},route)
                self.assertTrue(provider.closed)
                gates["First task"].set()
                async with asyncio.timeout(3):
                    while True:
                        rows=await runtime.dispatch(None,{**base,"type":"voice.live.jobs"},route)
                        if all(row["state"]=="completed" for row in rows["jobs"]):break
                        await asyncio.sleep(.01)
                self.assertEqual(len(rows["jobs"]),2)
                self.assertEqual(len(seen),2)
            finally:
                for gate in gates.values(): gate.set()
                await runtime.shutdown()
