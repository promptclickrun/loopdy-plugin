import asyncio
import json
import secrets
import socket
import tempfile
import time
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from loopdy_plugin.adapter import LoopdyAdapter
from loopdy_plugin.direct_runtime import DirectRuntime, DirectSettings
from loopdy_plugin.link_client import LinkRuntimeConfig
from loopdy_plugin.direct_connection import canonical_enrollment_transcript
from loopdy_plugin.link_crypto import sign_p256_raw, encode_base64url
from gateway.config import PlatformConfig
from gateway.platform_registry import PlatformEntry, platform_registry
from test_adapter import _Service, _LinkClient
from test_direct_server import _State, _device, _spki
import test_direct_server as server_fixtures


class DirectAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_authenticated_listener_reaches_adapter_workspace_and_retires_revoked_peer(self):
        platform_registry.register(PlatformEntry(name="loopdy",label="Loopdy",adapter_factory=lambda _:None,check_fn=lambda:True))
        state=_State();host_key=ec.generate_private_key(ec.SECP256R1());self.phone_key=ec.generate_private_key(ec.SECP256R1())
        config=LinkRuntimeConfig("https://account.example","host_1",7,host_key,secrets.token_bytes(32))
        link=_LinkClient();link.config=config;link.state=state
        class Workspace:
            async def execute(self,request,**kwargs):
                return {"agents":[{"id":"default","name":"Fixture"}]}
        adapter=LoopdyAdapter(PlatformConfig(enabled=True),service=_Service(),link_client=link,workspace_controller=Workspace())
        catalog={"version":1,"devices":[_device("host_1",role="host",epoch=7),_device("phone_1",role="mobile",epoch=11)]}
        with tempfile.TemporaryDirectory() as root:
            with socket.socket() as bound:
                bound.bind(("127.0.0.1",0));port=bound.getsockname()[1]
            runtime=DirectRuntime(settings=DirectSettings(True,"https://direct.example:8443",port),config=config,state=state,
                journal_path=Path(root).resolve()/"journal.sqlite3",dispatch=adapter.dispatch_direct,catalog_fetcher=lambda _:catalog)
            adapter.direct_runtime=runtime
            public=_spki(self.phone_key)
            envelope={"version":1,"exchangeId":"exchange_1","phoneNonce":"phone_nonce_1","phonePublicKey":public}
            transcript=canonical_enrollment_transcript(account_origin=config.base_url,direct_origin=runtime.settings.origin,
                host_device_id="host_1",host_epoch=7,phone_device_id="phone_1",phone_epoch=11,
                exchange_id="exchange_1",phone_nonce="phone_nonce_1",phone_public_key=public)
            envelope["phoneProof"]=encode_base64url(sign_p256_raw(self.phone_key,transcript))
            await runtime.start()
            try:
                await runtime.enroll(envelope,sender_device_id="phone_1",sender_epoch=11)
                ws,_=await server_fixtures.DirectServerTests._connect(self,runtime.server)
                async with ws:
                    request={"version":1,"type":"direct.query","requestID":"query_fixture_0001",
                        "payload":{"version":1,"type":"workspace.request","requestId":"query_fixture_0001",
                            "operation":"agents.list","payload":{},"sentAt":int(time.time())}}
                    await ws.send(json.dumps(request));result=json.loads(await asyncio.wait_for(ws.recv(),3))
                    self.assertEqual(result["result"]["type"],"workspace.result")
                    self.assertEqual(result["result"]["payload"]["agents"][0]["id"],"default")
                    catalog["devices"][1].update(lifecycle="revoked",authorizationEpoch=12,revokedAt=2,revision=2)
                    await runtime.refresh()
                    await asyncio.wait_for(ws.wait_closed(),3)
            finally:
                await runtime.stop()
            self.assertFalse(runtime.available)
