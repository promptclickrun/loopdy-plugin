from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from loopdy_plugin.link_client import LinkRuntimeConfig, LoopdyLinkClient
from loopdy_plugin.link_contracts import WORKSPACE_OPERATIONS, parse_workspace_request, workspace_capabilities
# Support both unittest's top-level discovery and package-addressed runs.
# Do not resolve the ambiguous global `tests` package from Hermes' checkout.
if __package__:
    from .test_link_request_isolation import _Socket, _State
else:
    from test_link_request_isolation import _Socket, _State


class LinkRecoveryContractTests(unittest.IsolatedAsyncioTestCase):
    def test_only_explicit_revocation_stops_automatic_reconnect(self) -> None:
        from websockets.datastructures import Headers
        from websockets.exceptions import ConnectionClosedError, InvalidStatus
        from websockets.frames import Close
        from websockets.http11 import Response
        from loopdy_plugin.link_client import _connection_authentication_failed

        temporary = InvalidStatus(Response(
            status_code=403, reason_phrase="Forbidden", headers=Headers(),
            body=b'{"version":1,"error":"nonce_replayed"}',
        ))
        revoked = InvalidStatus(Response(
            status_code=403, reason_phrase="Forbidden", headers=Headers(),
            body=b'{"version":1,"error":"device_revoked"}',
        ))
        self.assertFalse(_connection_authentication_failed(temporary))
        self.assertTrue(_connection_authentication_failed(revoked))
        self.assertTrue(_connection_authentication_failed(
            ConnectionClosedError(Close(4003, "authorization revoked"), None)
        ))
        self.assertFalse(_connection_authentication_failed(
            ConnectionClosedError(Close(1008, "temporary policy rejection"), None)
        ))

    def test_advertised_capabilities_match_actual_supported_operations(self) -> None:
        capabilities = workspace_capabilities()
        assert isinstance(capabilities, dict), "Workspace result lacks capability metadata"
        self.assertEqual(capabilities["protocolVersion"], 1)
        self.assertEqual(capabilities["operations"], sorted(WORKSPACE_OPERATIONS))
        self.assertIn("workspace-rejected-v1", capabilities["features"])
        self.assertIn("backpressure-v1", capabilities["features"])

    def test_new_app_operations_are_in_the_installable_plugin_contract(self) -> None:
        for operation in (
            "sessions.update", "sessions.delete", "skills_tools.get",
            "skills_tools.create", "skills_tools.update", "skills_tools.import",
        ):
            with self.subTest(operation=operation):
                value = {"version": 1, "type": "workspace.request", "requestId": "request-capability-check-0001",
                         "operation": operation, "payload": {}, "sentAt": 1_788_000_000}
                if operation == "skills_tools.import":
                    value["payload"] = {"dataBase64": "AA=="}
                try:
                    parsed = parse_workspace_request(value)
                except ValueError as error:
                    self.fail(f"Required app operation is rejected: {operation}: {error}")
                self.assertEqual(parsed.operation, operation)

    async def test_backpressure_does_not_advance_or_discard_the_exact_pending_frame(self) -> None:
        with tempfile.TemporaryDirectory(prefix="loopdy-backpressure-") as directory:
            root = Path(directory)
            client = LoopdyLinkClient(
                LinkRuntimeConfig("https://link.example.invalid", "host-pressure-fixture", 1,
                                  ec.generate_private_key(ec.SECP256R1()), b"k" * 32),
                state=_State(root), attachment_root=root / "attachments",
            )
            socket = _Socket()
            client._socket = socket
            client._connected.set()
            pending = {"version": 1, "type": "frame", "id": "frame-pressure-fixture-0001",
                       "senderDeviceId": "host-pressure-fixture", "senderEpoch": 1,
                       "sequence": 1, "ack": 0,
                       "ciphertext": client.cipher.seal({"fixture": "durable"})}
            client._transport_set("pending_frame", pending)
            try:
                try:
                    await client.handle_wire_message(json.dumps({
                        "version": 1, "type": "backpressure", "id": pending["id"],
                        "sequence": 1, "retryAfterMs": 1000, "reason": "storage_limit",
                    }), lambda value: None, defer_callbacks=True)
                except ValueError as error:
                    self.fail(f"Negotiated backpressure is treated as a bad frame: {error}")
                self.assertEqual(client._transport_get("pending_frame"), pending)
                self.assertEqual(client._transport_get("outbound_sequence", 0), 0)
                self.assertTrue(client._connected.is_set())
                self.assertEqual(socket.closes, [])
            finally:
                await client.stop()


if __name__ == "__main__":
    unittest.main()
