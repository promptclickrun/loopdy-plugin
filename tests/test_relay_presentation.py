import unittest
from types import SimpleNamespace
from gateway.config import PlatformConfig
from gateway.platform_registry import PlatformEntry, platform_registry
from loopdy_plugin.adapter import LoopdyAdapter
from test_adapter import _Service, _LinkClient
from test_live_voice_runtime import signing_fixture

class RelayPresentationTests(unittest.TestCase):
    def test_completed_turn_retires_transient_finals_before_saved_state_recovery(self):
        platform_registry.register(PlatformEntry(name="loopdy",label="Loopdy",adapter_factory=lambda _:None,check_fn=lambda:True))
        link=_LinkClient();link.config=signing_fixture()
        adapter=LoopdyAdapter(PlatformConfig(enabled=True),service=_Service(),link_client=link)
        route=adapter._link_reply_route("phone-fixture",1)
        lease=adapter._turn_replies.register("default","session_fixture_live","message_fixture_turn",route)
        adapter._observe_presentation("processing_start",event=None,lease=lease)
        payload={"type":"assistant.message","sessionId":"session_fixture_live","agentId":"default","messageId":"final_fixture","delivery":"final","text":"Complete"}
        adapter._observe_presentation("assistant_message",payload=payload,profile="default",lease=lease,final=True)
        adapter._observe_presentation("processing_complete",event=None,outcome="success",lease=lease)
        self.assertEqual(adapter.session_presentation_snapshot("default","session_fixture_live")["events"],[])

    def test_relay_only_host_has_current_partial_snapshot_without_direct_listener(self):
        platform_registry.register(PlatformEntry(name="loopdy",label="Loopdy",adapter_factory=lambda _:None,check_fn=lambda:True))
        link=_LinkClient();link.config=signing_fixture()
        adapter=LoopdyAdapter(PlatformConfig(enabled=True),service=_Service(),link_client=link)
        payload={"version":1,"type":"assistant.message","sessionId":"session_fixture_live","agentId":"default",
                 "messageId":"message_fixture_live","delivery":"draft","text":"currently streaming"}
        adapter._observe_presentation("assistant_message",payload=payload,profile="default",session_id="session_fixture_live",lease=None,reply_to=None,final=False)
        snapshot=adapter.session_presentation_snapshot("default","session_fixture_live")
        self.assertEqual(snapshot["events"],[payload])
        self.assertTrue(snapshot["complete"])
        self.assertIsNone(adapter.direct_runtime)
