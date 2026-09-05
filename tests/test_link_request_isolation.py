from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from loopdy_plugin.link_client import LinkRuntimeConfig, LoopdyLinkClient


class _State:
    def __init__(self, directory: Path) -> None:
        self.data_dir = directory
        self.values: dict[str, object] = {}

    def get(self, key: str, default=None):
        return self.values.get(key, default)

    def set(self, key: str, value) -> None:
        self.values[key] = value


class _Socket:
    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.closes: list[dict] = []

    async def send(self, value: str) -> None:
        self.sent.append(json.loads(value))

    async def close(self, **kwargs) -> None:
        self.closes.append(kwargs)


class LinkRequestIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def test_unknown_operation_does_not_poison_the_next_valid_request(self) -> None:
        """An authenticated application error must not poison shared delivery."""
        with tempfile.TemporaryDirectory(prefix="loopdy-request-isolation-") as directory:
            root = Path(directory)
            config = LinkRuntimeConfig(
                "https://link.example.invalid",
                "host-isolation-fixture",
                1,
                ec.generate_private_key(ec.SECP256R1()),
                b"k" * 32,
            )
            state = _State(root)
            client = LoopdyLinkClient(config, state=state, attachment_root=root / "attachments")
            socket = _Socket()
            client._socket = socket
            received = []

            def wire(sequence: int, operation: str) -> str:
                payload = {
                    "version": 1,
                    "type": "workspace.request",
                    "requestId": f"request-isolation-{sequence:04d}",
                    "operation": operation,
                    "payload": {},
                    "sentAt": 1_788_000_000,
                }
                return json.dumps({
                    "version": 1,
                    "type": "frame",
                    "id": f"frame-isolation-{sequence:04d}",
                    "senderDeviceId": "mobile-isolation-fixture",
                    "senderEpoch": 1,
                    "sequence": sequence,
                    "ack": 0,
                    "ciphertext": client.cipher.seal(payload),
                })

            try:
                try:
                    await client.handle_wire_message(
                        wire(1, "unsupported.fixture.operation"),
                        received.append,
                        defer_callbacks=True,
                    )
                except ValueError as error:
                    self.fail(f"Authenticated request escaped per-request isolation: {error}")

                await client.handle_wire_message(
                    wire(2, "sessions.list"), received.append, defer_callbacks=True
                )
                if client._inbound_callback_queue is not None:
                    await client._inbound_callback_queue.join()
                self.assertEqual(len(received), 1)
                self.assertEqual(received[0].request.operation, "sessions.list")
                receipts = [message for message in socket.sent if message.get("type") == "receipt"]
                self.assertEqual([message["frameId"] for message in receipts], [
                    "frame-isolation-0001", "frame-isolation-0002"
                ])
                self.assertEqual(socket.closes, [])
                self.assertEqual(
                    client._transport_get("received_sequences"),
                    {"mobile-isolation-fixture": 2},
                )
            finally:
                await client._stop_inbound_callback_dispatcher()


    async def test_rejected_request_cannot_overtake_an_earlier_valid_request(self) -> None:
        with tempfile.TemporaryDirectory(prefix="loopdy-request-order-") as directory:
            root = Path(directory)
            config = LinkRuntimeConfig(
                "https://link.example.invalid", "host-isolation-fixture", 1,
                ec.generate_private_key(ec.SECP256R1()), b"k" * 32,
            )
            client = LoopdyLinkClient(
                config, state=_State(root), attachment_root=root / "attachments"
            )
            socket = _Socket()
            client._socket = socket
            received = []
            operations = ["sessions.list", "unsupported.fixture.operation", "sessions.list"]
            try:
                for sequence, operation in enumerate(operations, 1):
                    payload = {
                        "version": 1, "type": "workspace.request",
                        "requestId": f"request-ordered-{sequence:04d}",
                        "operation": operation, "payload": {}, "sentAt": 1_788_000_000,
                    }
                    wire = json.dumps({
                        "version": 1, "type": "frame", "id": f"frame-ordered-{sequence:04d}",
                        "senderDeviceId": "mobile-isolation-fixture", "senderEpoch": 1,
                        "sequence": sequence, "ack": 0,
                        "ciphertext": client.cipher.seal(payload),
                    })
                    await client.handle_wire_message(wire, received.append, defer_callbacks=True)
                await client._inbound_callback_queue.join()
                self.assertEqual(
                    [item.request.request_id for item in received],
                    ["request-ordered-0001", "request-ordered-0003"],
                )
                self.assertEqual(
                    [item["frameId"] for item in socket.sent if item.get("type") == "receipt"],
                    ["frame-ordered-0001", "frame-ordered-0002", "frame-ordered-0003"],
                )
                self.assertEqual(socket.closes, [])
            finally:
                await client._stop_inbound_callback_dispatcher()


if __name__ == "__main__":
    unittest.main()
