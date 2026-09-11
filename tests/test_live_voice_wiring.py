import unittest
from loopdy_plugin.link_contracts import parse_workspace_request, workspace_capabilities


class LiveVoiceWiringTests(unittest.TestCase):
    def test_live_voice_uses_the_authenticated_workspace_contract(self):
        operations = ("voice.live.status", "voice.live.offer", "voice.live.close", "voice.live.jobs", "voice.live.control")
        for operation in operations:
            request = parse_workspace_request({"version": 1, "type": "workspace.request",
                "requestId": "voice-fixture-request-001", "operation": operation,
                "payload": {"agentId": "default", "sessionId": "link-fixture-session"}, "sentAt": 1})
            self.assertEqual(request.operation, operation)
        capabilities = workspace_capabilities()
        self.assertIn("live-voice-v1", capabilities["features"])
        self.assertTrue(set(operations) <= set(capabilities["operations"]))
