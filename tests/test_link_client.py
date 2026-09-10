from __future__ import annotations

import asyncio
import base64
import json
import os
import hashlib
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class _State:
    def __init__(self):
        self.values = {}

    def get(self, key, default=None):
        return self.values.get(key, default)

    def set(self, key, value):
        self.values[key] = value


class _DiskState(_State):
    def __init__(self, data_dir: Path):
        super().__init__()
        self.data_dir = data_dir


class _Socket:
    def __init__(self):
        self.sent = []

    async def send(self, value):
        self.sent.append(json.loads(value))


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _relay_ready_wire(client, *, sequence: int) -> str:
    plaintext = {
        "version": 1,
        "type": "relay.ready",
        "deviceId": "mobile-device-1",
        "enrollmentRevision": 4,
        "acknowledgementRevision": 5,
        "leaseExpires": int(time.time()) + 2_000,
        "recipientPublicKey": "B" + "A" * 86,
        "recipientKeyId": "A" * 43,
        "senderKeyRevision": 2,
        "acknowledgedSenderKeyIds": ["A" * 43],
        "environment": "production",
        "topic": ".".join(("app", "loopdy", "mobile")),
        "deviceName": "Alex's iPhone",
        "sentAt": int(time.time()),
    }
    return json.dumps(
        {
            "version": 1,
            "type": "frame",
            "id": f"frame-control-coordinate-{sequence:04d}",
            "senderDeviceId": "mobile-device-1",
            "senderEpoch": 1,
            "sequence": sequence,
            "ack": 0,
            "ciphertext": client.cipher.seal(plaintext),
        }
    )


class LinkClientTests(unittest.TestCase):
    def _configuration(self):
        from loopdy_plugin.link_client import LinkRuntimeConfig

        signing = ec.generate_private_key(ec.SECP256R1())
        return signing, LinkRuntimeConfig.from_mapping(
            {
                "LOOPDY_LINK_BASE_URL": "https://link.loopdy.example",
                "LOOPDY_LINK_DEVICE_ID": "host-device-fixture",
                "LOOPDY_LINK_AUTHORIZATION_EPOCH": "3",
                "LOOPDY_LINK_SIGNING_PRIVATE_KEY": _b64(
                    signing.private_bytes(
                        serialization.Encoding.DER,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                ),
                "LOOPDY_LINK_ACCOUNT_KEY": _b64(b"k" * 32),
            }
        )

    def test_competing_host_receipts_targeted_request_without_dispatching_it(self):
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        received = []
        payload = {
            "version": 1,
            "type": "workspace.request",
            "requestId": "request-targeted-0001",
            "operation": "sessions.list",
            "payload": {},
            "sentAt": int(time.time()),
            "targetHostId": "different-host-device",
        }
        wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-targeted-request-0001",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 1,
                "ack": 0,
                "ciphertext": client.cipher.seal(payload),
            }
        )

        asyncio.run(client.handle_wire_message(wire, received.append))

        self.assertEqual(received, [])
        self.assertEqual(
            state.get("link.transport.host-device-fixture.received_sequences"),
            {"mobile-device-1": 1},
        )
        self.assertEqual(socket.sent[-1]["type"], "receipt")
        self.assertEqual(socket.sent[-1]["frameId"], "frame-targeted-request-0001")

    def test_assembles_attachment_frames_before_exposing_a_bound_hermes_turn(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        content = b"PNG!"
        digest = _b64(hashlib.sha256(content).digest())
        reference = {
            "attachmentId": "attachment-coordinate-0001",
            "fileName": "forecast.png",
            "mimeType": "image/png",
            "totalBytes": len(content),
            "sha256": digest,
        }
        with tempfile.TemporaryDirectory() as directory:
            client = LoopdyLinkClient(
                config,
                state=_State(),
                attachment_root=Path(directory),
            )
            socket = _Socket()
            client._socket = socket
            received = []

            def receive(turn):
                received.append(
                    (
                        turn,
                        Path(turn.attachment_paths[0]).read_bytes(),
                    )
                )

            for sequence, plaintext in enumerate(
                (
                    {
                        "version": 1,
                        "type": "attachment.chunk",
                        "uploadId": "upload-coordinate-0001",
                        "sessionId": "session-coordinate-0001",
                        "agentId": "finance",
                        **reference,
                        "index": 0,
                        "count": 1,
                        "data": _b64(content),
                        "sentAt": int(time.time()),
                    },
                    {
                        "version": 1,
                        "type": "user.message",
                        "messageId": "message-coordinate-0001",
                        "sessionId": "session-coordinate-0001",
                        "agentId": "finance",
                        "actorId": "family-member-1",
                        "actorName": "Alex",
                        "deviceName": "Kitchen iPad",
                        "text": "Read this",
                        "attachments": [reference],
                        "sentAt": int(time.time()),
                    },
                ),
                start=1,
            ):
                wire = json.dumps(
                    {
                        "version": 1,
                        "type": "frame",
                        "id": f"frame-coordinate-000{sequence}",
                        "senderDeviceId": "mobile-device-1",
                        "senderEpoch": 1,
                        "sequence": sequence,
                        "ack": 0,
                        "ciphertext": client.cipher.seal(plaintext),
                    }
                )
                asyncio.run(client.handle_wire_message(wire, receive))

            self.assertEqual(len(received), 1)
            turn, observed_content = received[0]
            self.assertEqual(turn.attachment_types, ("image/png",))
            self.assertEqual(observed_content, content)
            # BasePlatformAdapter.handle_message() only schedules Hermes'
            # background turn. The media path must remain readable after the
            # Link callback returns so that background ingestion can own it.
            attachment_path = Path(turn.attachment_paths[0])
            self.assertTrue(attachment_path.exists())
            client.release_attachment_paths(turn.attachment_paths)
            self.assertFalse(attachment_path.exists())

    def test_recreates_removed_attachment_inbox_before_accepting_a_pending_frame(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        content = b"PNG!"
        digest = _b64(hashlib.sha256(content).digest())
        reference = {
            "attachmentId": "attachment-coordinate-recovery-0001",
            "fileName": "forecast.png",
            "mimeType": "image/png",
            "totalBytes": len(content),
            "sha256": digest,
        }
        with tempfile.TemporaryDirectory() as directory:
            attachment_root = Path(directory) / "link-inbound"
            client = LoopdyLinkClient(
                config,
                state=_State(),
                attachment_root=attachment_root,
            )
            shutil.rmtree(attachment_root)
            socket = _Socket()
            client._socket = socket
            received = []

            def receive(turn):
                received.append(Path(turn.attachment_paths[0]).read_bytes())

            payloads = (
                {
                    "version": 1,
                    "type": "attachment.chunk",
                    "uploadId": "upload-coordinate-recovery-0001",
                    "sessionId": "session-coordinate-recovery-0001",
                    "agentId": "finance",
                    **reference,
                    "index": 0,
                    "count": 1,
                    "data": _b64(content),
                    "sentAt": int(time.time()),
                },
                {
                    "version": 1,
                    "type": "user.message",
                    "messageId": "message-coordinate-recovery-0001",
                    "sessionId": "session-coordinate-recovery-0001",
                    "agentId": "finance",
                    "actorId": "family-member-1",
                    "actorName": "Alex",
                    "deviceName": "Kitchen iPad",
                    "text": "Read this",
                    "attachments": [reference],
                    "sentAt": int(time.time()),
                },
            )
            for sequence, plaintext in enumerate(payloads, start=1):
                wire = json.dumps(
                    {
                        "version": 1,
                        "type": "frame",
                        "id": f"frame-recovery-coordinate-{sequence:04d}",
                        "senderDeviceId": "mobile-device-1",
                        "senderEpoch": 1,
                        "sequence": sequence,
                        "ack": 0,
                        "ciphertext": client.cipher.seal(plaintext),
                    }
                )
                asyncio.run(client.handle_wire_message(wire, receive))

            self.assertEqual(received, [content])
            self.assertEqual(
                [message["sequence"] for message in socket.sent],
                [1, 2],
            )


    def test_signed_socket_headers_match_the_worker_canonical_contract(self) -> None:
        from loopdy_plugin.link_client import canonical_device_request
        from loopdy_plugin.link_crypto import decode_base64url, raw_p256_to_der

        signing, config = self._configuration()
        headers = config.signed_headers(
            method="GET",
            path="/v1/socket",
            body="",
            timestamp=1788000000,
            nonce="bm9uY2UtZml4dHVyZS12YWx1ZS0wMDAx",
        )
        canonical = canonical_device_request(
            method="GET",
            path="/v1/socket",
            device_id="host-device-fixture",
            timestamp=1788000000,
            nonce="bm9uY2UtZml4dHVyZS12YWx1ZS0wMDAx",
            authorization_epoch=3,
            body="",
        )
        signing.public_key().verify(
            raw_p256_to_der(decode_base64url(headers["x-loopdy-signature"])),
            canonical.encode(),
            ec.ECDSA(hashes.SHA256()),
        )
        self.assertEqual(headers["x-loopdy-device-id"], "host-device-fixture")
        self.assertNotIn("account", json.dumps(headers).lower())

    def test_sends_a_plaintext_sanitized_live_activity_control_and_waits_for_acceptance(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        client._connected.set()
        update = {
            "version": 1,
            "type": "live_activity.update",
            "updateId": "activity-update-fixture-0001",
            "sessionReference": "A" * 43,
            "phase": "using_tool",
            "currentAction": "Checking weather",
            "progress": 48,
            "completedSteps": 2,
            "activeSubagentCount": 1,
            "latestTool": "weather",
            "timestamp": 1_788_000_000,
            "expires": 1_788_000_120,
        }

        async def scenario() -> str:
            pending = asyncio.create_task(client.send_live_activity_update(update))
            while not socket.sent:
                await asyncio.sleep(0)
            self.assertEqual(socket.sent[0], update)
            await client.handle_wire_message(
                json.dumps(
                    {
                        "version": 1,
                        "type": "live_activity.accepted",
                        "updateId": update["updateId"],
                        "activityCount": 1,
                    }
                ),
                lambda _value: None,
            )
            return await pending

        self.assertEqual(asyncio.run(scenario()), update["updateId"])

    def test_reader_processes_outbound_ack_while_inbound_callback_is_waiting(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)

        class ReaderSocket(_Socket):
            def __init__(self):
                super().__init__()
                self.incoming = asyncio.Queue()

            async def send(self, value):
                message = json.loads(value)
                self.sent.append(message)
                if (
                    message.get("type") == "frame"
                    and message.get("senderDeviceId") == config.device_id
                ):
                    await self.incoming.put(
                        json.dumps(
                            {
                                "version": 1,
                                "type": "accepted",
                                "id": message["id"],
                                "sequence": message["sequence"],
                            }
                        )
                    )

        socket = ReaderSocket()
        client._socket = socket
        client._connected.set()
        inbound = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-mobile-callback-0001",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 1,
                "ack": 0,
                "ciphertext": client.cipher.seal(
                    {
                        "version": 1,
                        "type": "workspace.request",
                        "requestId": "request-callback-0001",
                        "operation": "sessions.list",
                        "payload": {},
                        "sentAt": int(time.time()),
                    }
                ),
            }
        )
        callback_started = asyncio.Event()
        callback_release = asyncio.Event()
        callback_finished = asyncio.Event()

        async def callback(_payload):
            callback_started.set()
            await client.send_payload(
                {
                    "version": 1,
                    "type": "workspace.result",
                    "requestId": "request-callback-0001",
                }
            )
            await callback_release.wait()
            callback_finished.set()

        async def reader():
            await client.handle_wire_message(inbound, callback, defer_callbacks=True)
            await asyncio.wait_for(callback_started.wait(), timeout=0.5)
            self.assertNotIn(
                "mobile-device-1",
                state.get("link.transport.host-device-fixture.received_sequences", {}),
            )
            await client.handle_wire_message(
                await socket.incoming.get(), callback, defer_callbacks=True
            )
            self.assertNotIn(
                "mobile-device-1",
                state.get("link.transport.host-device-fixture.received_sequences", {}),
            )
            callback_release.set()
            await asyncio.wait_for(callback_finished.wait(), timeout=0.5)
            self.assertEqual(
                state.get("link.transport.host-device-fixture.received_sequences"),
                {"mobile-device-1": 1},
            )
            self.assertTrue(
                any(
                    message.get("type") == "receipt"
                    and message.get("sourceDeviceId") == "mobile-device-1"
                    for message in socket.sent
                )
            )

        asyncio.run(asyncio.wait_for(reader(), timeout=0.5))
        self.assertTrue(
            any(
                message.get("type") == "frame"
                and message.get("senderDeviceId") == config.device_id
                for message in socket.sent
            )
        )

    def test_new_host_identity_does_not_reuse_the_previous_hosts_outbound_sequence(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        state.values.update(
            {
                "link.outbound_sequence": 27,
                "link.runtime_status": {
                    "device_id": "host-device-previous",
                    "authorization_epoch": 1,
                },
            }
        )
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        client._connected.set()

        async def send() -> dict:
            pending = asyncio.create_task(
                client.send_payload(
                    {
                        "version": 1,
                        "type": "assistant.message",
                        "messageId": "message-coordinate-0001",
                    }
                )
            )
            while not socket.sent:
                await asyncio.sleep(0)
            frame = socket.sent[0]
            client._accept_outbound(
                {
                    "version": 1,
                    "type": "accepted",
                    "id": frame["id"],
                    "sequence": frame["sequence"],
                }
            )
            await pending
            return frame

        frame = asyncio.run(send())

        self.assertEqual(frame["senderDeviceId"], "host-device-fixture")
        self.assertEqual(frame["sequence"], 1)

    def test_existing_host_identity_migrates_its_legacy_outbound_sequence(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        state.values.update(
            {
                "link.outbound_sequence": 27,
                "link.runtime_status": {
                    "device_id": config.device_id,
                    "authorization_epoch": config.authorization_epoch,
                },
            }
        )
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        client._connected.set()

        async def send() -> dict:
            pending = asyncio.create_task(
                client.send_payload(
                    {
                        "version": 1,
                        "type": "assistant.message",
                        "messageId": "message-coordinate-0002",
                    }
                )
            )
            while not socket.sent:
                await asyncio.sleep(0)
            frame = socket.sent[0]
            client._accept_outbound(
                {
                    "version": 1,
                    "type": "accepted",
                    "id": frame["id"],
                    "sequence": frame["sequence"],
                }
            )
            await pending
            return frame

        frame = asyncio.run(send())

        self.assertEqual(frame["sequence"], 28)

    def test_socket_ready_exact_pending_frame_is_committed_after_lost_acceptance(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        client._connected.set()

        async def scenario() -> dict:
            pending = asyncio.create_task(
                client.send_payload(
                    {
                        "version": 1,
                        "type": "assistant.message",
                        "messageId": "message-coordinate-ready-0001",
                    }
                )
            )
            while not socket.sent:
                await asyncio.sleep(0)
            frame = socket.sent[0]
            client._reconcile_socket_ready(
                {
                    "version": 1,
                    "type": "socket.ready",
                    "deviceId": config.device_id,
                    "authorizationEpoch": config.authorization_epoch,
                    "lastInboundSequence": frame["sequence"],
                    "lastInboundFrameId": frame["id"],
                    "lastAcknowledgedSequence": 4,
                }
            )
            await pending
            return frame

        frame = asyncio.run(scenario())
        self.assertEqual(state.get("link.transport.host-device-fixture.pending_frame"), None)
        self.assertEqual(state.get("link.transport.host-device-fixture.outbound_sequence"), frame["sequence"])

    def test_pending_payload_identity_exposes_the_exact_durable_outbox_frame(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        client._connected.set()
        payload = {
            "version": 1,
            "type": "notification.event",
            "eventId": "attention.required:clarify-timeout-0001",
        }

        async def scenario() -> tuple[str | None, str]:
            sending = asyncio.create_task(client.send_payload(payload))
            while not socket.sent:
                await asyncio.sleep(0)
            frame = socket.sent[0]
            lookup = getattr(client, "pending_payload_frame_id", lambda _: None)
            pending_frame_id = lookup(payload)
            sending.cancel()
            await asyncio.gather(sending, return_exceptions=True)
            return pending_frame_id, frame["id"]

        pending_frame_id, frame_id = asyncio.run(scenario())

        self.assertEqual(pending_frame_id, frame_id)

    def test_socket_ready_conflict_rebases_pending_payload_to_server_high_water(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        client._connected.set()

        async def scenario() -> tuple[dict, dict]:
            pending = asyncio.create_task(
                client.send_payload(
                    {
                        "version": 1,
                        "type": "assistant.message",
                        "messageId": "message-coordinate-ready-0002",
                    }
                )
            )
            while not socket.sent:
                await asyncio.sleep(0)
            original = socket.sent[0]
            client._reconcile_socket_ready(
                {
                    "version": 1,
                    "type": "socket.ready",
                    "deviceId": config.device_id,
                    "authorizationEpoch": config.authorization_epoch,
                    "lastInboundSequence": 4,
                    "lastInboundFrameId": "frame-server-high-water-0004",
                    "lastAcknowledgedSequence": 7,
                }
            )
            rebased = state.get("link.transport.host-device-fixture.pending_frame")
            self.assertIsInstance(rebased, dict)
            client._accept_outbound(
                {
                    "version": 1,
                    "type": "accepted",
                    "id": rebased["id"],
                    "sequence": rebased["sequence"],
                }
            )
            await pending
            return original, rebased

        original, rebased = asyncio.run(scenario())
        self.assertEqual(rebased["sequence"], 5)
        self.assertEqual(rebased["ack"], 7)
        self.assertNotEqual(rebased["id"], original["id"])
        self.assertNotEqual(rebased["ciphertext"], original["ciphertext"])

    def test_socket_ready_next_sequence_retains_pending_frame_identity(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        client._connected.set()

        async def scenario() -> dict:
            pending = asyncio.create_task(
                client.send_payload(
                    {
                        "version": 1,
                        "type": "assistant.message",
                        "messageId": "message-coordinate-ready-0003",
                    }
                )
            )
            while not socket.sent:
                await asyncio.sleep(0)
            original = socket.sent[0]
            client._reconcile_socket_ready(
                {
                    "version": 1,
                    "type": "socket.ready",
                    "deviceId": config.device_id,
                    "authorizationEpoch": config.authorization_epoch,
                    "lastInboundSequence": 0,
                    "lastInboundFrameId": None,
                    "lastAcknowledgedSequence": 2,
                }
            )
            client._accept_outbound(
                {
                    "version": 1,
                    "type": "accepted",
                    "id": original["id"],
                    "sequence": original["sequence"],
                }
            )
            await pending
            return original

        original = asyncio.run(scenario())
        self.assertEqual(
            state.get("link.transport.host-device-fixture.pending_frame"), None
        )
        self.assertEqual(
            state.get("link.transport.host-device-fixture.outbound_sequence"),
            original["sequence"],
        )

    def test_legacy_socket_ready_retires_persisted_directed_tool_without_replay(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient
        from loopdy_plugin.link_contracts import EncryptedFrame

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        pending = EncryptedFrame(
            frame_id="frame-directed-tool-legacy-0001",
            sender_device_id=config.device_id,
            sender_epoch=config.authorization_epoch,
            sequence=1,
            ack=0,
            ciphertext=client.cipher.seal(
                {
                    "version": 1,
                    "type": "device.tool.request",
                    "requestId": "request-directed-tool-legacy-0001",
                }
            ),
            target_device_id="phone-device-1",
        ).wire_value()
        state.set("link.transport.host-device-fixture.pending_frame", pending)

        class LegacyConnection:
            def __init__(self) -> None:
                self.sent: list[dict] = []

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                client._stopping.set()
                return False

            async def recv(self):
                return json.dumps(
                    {
                        "version": 1,
                        "type": "socket.ready",
                        "deviceId": config.device_id,
                        "authorizationEpoch": config.authorization_epoch,
                        "lastInboundSequence": 0,
                        "lastInboundFrameId": None,
                        "lastAcknowledgedSequence": 0,
                    }
                )

            def __aiter__(self):
                return self

            async def __anext__(self):
                raise StopAsyncIteration

            async def send(self, value):
                self.sent.append(json.loads(value))

        connection = LegacyConnection()

        def connect(*_args, **_kwargs):
            return connection

        async def scenario() -> None:
            with patch("websockets.asyncio.client.connect", new=connect):
                await client._run(lambda _payload: None)

        asyncio.run(scenario())

        self.assertEqual(connection.sent, [])
        self.assertIsNone(
            state.get("link.transport.host-device-fixture.pending_frame")
        )

    def test_two_clients_for_one_host_serialize_their_durable_outbound_sequence(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        with tempfile.TemporaryDirectory() as directory:
            state = _DiskState(Path(directory))
            first = LoopdyLinkClient(config, state=state)
            second = LoopdyLinkClient(config, state=state)
            first_socket = _Socket()
            second_socket = _Socket()
            first._socket = first_socket
            second._socket = second_socket
            first._connected.set()
            second._connected.set()

            async def scenario() -> list[int]:
                first_send = asyncio.create_task(
                    first.send_payload(
                        {
                            "version": 1,
                            "type": "assistant.message",
                            "messageId": "message-coordinate-serial-0001",
                        }
                    )
                )
                second_send = asyncio.create_task(
                    second.send_payload(
                        {
                            "version": 1,
                            "type": "assistant.message",
                            "messageId": "message-coordinate-serial-0002",
                        }
                    )
                )
                while len(first_socket.sent) + len(second_socket.sent) < 1:
                    await asyncio.sleep(0)
                for _ in range(20):
                    await asyncio.sleep(0)
                self.assertEqual(
                    len(first_socket.sent) + len(second_socket.sent),
                    1,
                    "a second process must not allocate the same host sequence while the first is pending",
                )

                first_client, first_frame = (
                    (first, first_socket.sent[0])
                    if first_socket.sent
                    else (second, second_socket.sent[0])
                )
                first_client._accept_outbound(
                    {
                        "version": 1,
                        "type": "accepted",
                        "id": first_frame["id"],
                        "sequence": first_frame["sequence"],
                    }
                )
                while len(first_socket.sent) + len(second_socket.sent) < 2:
                    await asyncio.sleep(0)
                second_client, second_frame = (
                    (second, second_socket.sent[0])
                    if first_client is first
                    else (first, first_socket.sent[0])
                )
                second_client._accept_outbound(
                    {
                        "version": 1,
                        "type": "accepted",
                        "id": second_frame["id"],
                        "sequence": second_frame["sequence"],
                    }
                )
                await asyncio.gather(first_send, second_send)
                return sorted([first_frame["sequence"], second_frame["sequence"]])

            self.assertEqual(asyncio.run(scenario()), [1, 2])

    def test_transport_lock_serializes_independent_clients_for_one_host_device(self) -> None:
        from loopdy_plugin.link_client import _LoopdyLinkTransportLock

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "host-device.lock"
            first = _LoopdyLinkTransportLock(path)
            second = _LoopdyLinkTransportLock(path)

            async def scenario() -> int:
                active = 0
                maximum_active = 0
                first_entered = asyncio.Event()
                release_first = asyncio.Event()

                async def hold_first() -> None:
                    nonlocal active, maximum_active
                    async with first:
                        active += 1
                        maximum_active = max(maximum_active, active)
                        first_entered.set()
                        await release_first.wait()
                        active -= 1

                async def enter_second() -> None:
                    nonlocal active, maximum_active
                    await first_entered.wait()
                    async with second:
                        active += 1
                        maximum_active = max(maximum_active, active)
                        active -= 1

                first_task = asyncio.create_task(hold_first())
                second_task = asyncio.create_task(enter_second())
                await first_entered.wait()
                for _ in range(20):
                    await asyncio.sleep(0)
                self.assertFalse(second_task.done())
                release_first.set()
                await asyncio.gather(first_task, second_task)
                return maximum_active

            self.assertEqual(asyncio.run(scenario()), 1)

    def test_decrypts_a_verified_sender_message_and_records_identity(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        received = []
        plaintext = {
            "version": 1,
            "type": "user.message",
            "messageId": "message-coordinate-0001",
            "sessionId": "session-coordinate-0001",
            "agentId": "finance",
            "actorId": "family-member-1",
            "actorName": "Alex",
            "deviceName": "Kitchen iPad",
            "text": "Hello from Loopdy",
            "behavior": "steer",
            "sentAt": int(time.time()),
        }
        wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-coordinate-0001",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 1,
                "ack": 0,
                "ciphertext": client.cipher.seal(plaintext),
            }
        )

        asyncio.run(client.handle_wire_message(wire, received.append))

        self.assertEqual(received[0].message.text, "Hello from Loopdy")
        self.assertEqual(received[0].message.agent_id, "finance")
        self.assertEqual(received[0].message.behavior, "steer")
        self.assertTrue(received[0].sender_id.startswith("link_"))
        context = client.identity_registry.pre_llm_context(
            platform="loopdy", sender_id=received[0].sender_id
        )
        self.assertIn("Kitchen iPad", context["context"])
        self.assertEqual(
            state.values["link.transport.host-device-fixture.last_received_sequence"],
            1,
        )
        self.assertEqual(
            socket.sent,
            [
                {
                    "version": 1,
                    "type": "receipt",
                    "deviceId": "host-device-fixture",
                    "frameId": "frame-coordinate-0001",
                    "sourceDeviceId": "mobile-device-1",
                    "sequence": 1,
                }
            ],
        )

        asyncio.run(client.handle_wire_message(wire, received.append))
        self.assertEqual(len(received), 1)
        self.assertEqual(len(socket.sent), 2)

    def test_decrypts_a_verified_voice_request_without_creating_a_chat_identity(self) -> None:
        from loopdy_plugin.link_client import InboundLinkVoiceSpeak, LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        received = []
        plaintext = {
            "version": 1,
            "type": "voice.speak.request",
            "requestId": "voice_request_fixture_0001",
            "sessionId": "session-coordinate-0001",
            "agentId": "finance",
            "text": "Read this aloud.",
            "speed": 1.0,
            "sentAt": int(time.time()),
        }
        wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-voice-coordinate-0001",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 1,
                "ack": 0,
                "ciphertext": client.cipher.seal(plaintext),
            }
        )

        asyncio.run(client.handle_wire_message(wire, received.append))

        self.assertIsInstance(received[0], InboundLinkVoiceSpeak)
        self.assertEqual(received[0].request.agent_id, "finance")
        self.assertEqual(received[0].sender_device_id, "mobile-device-1")
        self.assertNotIn("link.identities", state.values)

    def test_decrypts_verified_picker_control_messages_without_creating_chat_identity(self) -> None:
        from loopdy_plugin.link_client import (
            InboundLinkPickerOpen,
            InboundLinkPickerSelection,
            LoopdyLinkClient,
        )

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        received = []

        async def receive(sequence: int, payload: dict) -> None:
            wire = json.dumps(
                {
                    "version": 1,
                    "type": "frame",
                    "id": f"frame-picker-coordinate-{sequence:04d}",
                    "senderDeviceId": "mobile-device-1",
                    "senderEpoch": 1,
                    "sequence": sequence,
                    "ack": 0,
                    "ciphertext": client.cipher.seal(payload),
                }
            )
            await client.handle_wire_message(wire, received.append)

        asyncio.run(
            receive(
                1,
                {
                    "version": 1,
                    "type": "picker.open",
                    "requestId": "picker_request_fixture_0001",
                    "sessionId": "session-coordinate-0001",
                    "agentId": "finance",
                    "kind": "reasoning",
                    "sentAt": int(time.time()),
                },
            )
        )
        asyncio.run(
            receive(
                2,
                {
                    "version": 1,
                    "type": "picker.select",
                    "pickerId": "picker_request_fixture_0001",
                    "sessionId": "session-coordinate-0001",
                    "kind": "reasoning",
                    "value": "high",
                    "sentAt": int(time.time()),
                },
            )
        )

        self.assertIsInstance(received[0], InboundLinkPickerOpen)
        self.assertEqual(received[0].request.agent_id, "finance")
        self.assertIsInstance(received[1], InboundLinkPickerSelection)
        self.assertEqual(received[1].selection.value, "high")
        self.assertEqual(received[1].sender_device_id, "mobile-device-1")
        self.assertNotIn("link.identities", state.values)

    def test_decrypts_a_verified_session_fork_and_binds_the_sender_identity(self) -> None:
        import hashlib

        from loopdy_plugin.link_client import InboundLinkSessionFork, LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        received = []
        plaintext = {
            "version": 1,
            "type": "session.fork.request",
            "requestId": "fork_request_fixture_0001",
            "sourceSessionId": "source_session_fixture_0001",
            "forkSessionId": "fork_session_fixture_000001",
            "agentId": "finance",
            "actorId": "family-member-1",
            "actorName": "Alex",
            "deviceName": "Kitchen iPad",
            "userTurn": 2,
            "checkpointRole": "assistant",
            "checkpointDigest": _b64(hashlib.sha256(b"Second answer").digest()),
            "title": "Budget review · Fork",
            "sentAt": int(time.time()),
        }
        wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-fork-coordinate-0001",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 1,
                "ack": 0,
                "ciphertext": client.cipher.seal(plaintext),
            }
        )

        asyncio.run(client.handle_wire_message(wire, received.append))

        self.assertIsInstance(received[0], InboundLinkSessionFork)
        self.assertEqual(received[0].request.source_session_id, plaintext["sourceSessionId"])
        self.assertEqual(received[0].request.fork_session_id, plaintext["forkSessionId"])
        self.assertEqual(received[0].request.user_turn, 2)
        self.assertTrue(received[0].sender_id.startswith("link_"))
        context = client.identity_registry.pre_llm_context(
            platform="loopdy", sender_id=received[0].sender_id
        )
        self.assertIn("Kitchen iPad", context["context"])
        self.assertEqual(socket.sent[0]["frameId"], "frame-fork-coordinate-0001")

    def test_decrypts_a_verified_slash_command_catalog_request_as_control(self) -> None:
        from loopdy_plugin.link_client import (
            InboundLinkCommandCatalog,
            LoopdyLinkClient,
        )

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        received = []
        plaintext = {
            "version": 1,
            "type": "commands.catalog.request",
            "requestId": "commands_request_fixture_0001",
            "sessionId": "session_fixture_0001",
            "agentId": "gordie",
            "sentAt": int(time.time()),
        }
        wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-commands-coordinate-0001",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 1,
                "ack": 0,
                "ciphertext": client.cipher.seal(plaintext),
            }
        )

        asyncio.run(client.handle_wire_message(wire, received.append))

        self.assertIsInstance(received[0], InboundLinkCommandCatalog)
        self.assertEqual(received[0].request.agent_id, "gordie")
        self.assertEqual(received[0].sender_device_id, "mobile-device-1")
        self.assertNotIn("link.identities", state.values)

    def test_decrypts_a_personality_catalog_request_as_account_control(self) -> None:
        from loopdy_plugin.link_client import (
            InboundLinkPersonalityRequest,
            LoopdyLinkClient,
        )

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        received = []
        plaintext = {
            "version": 1,
            "type": "personalities.catalog.request",
            "requestId": "personality-request-0001",
            "sentAt": int(time.time()),
        }
        wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-personality-coordinate-0001",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 1,
                "ack": 0,
                "ciphertext": client.cipher.seal(plaintext),
            }
        )

        asyncio.run(client.handle_wire_message(wire, received.append))

        self.assertIsInstance(received[0], InboundLinkPersonalityRequest)
        self.assertEqual(received[0].request.action, "catalog")
        self.assertNotIn("link.identities", state.values)

    def test_decrypts_a_generative_ui_form_submission_as_bound_control(self) -> None:
        from loopdy_plugin.link_client import (
            InboundLinkGenerativeUIFormSubmission,
            LoopdyLinkClient,
        )

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        received = []
        plaintext = {
            "version": 1,
            "type": "generative.ui.form.submit",
            "requestId": "a" * 32,
            "sessionId": "session-coordinate-0001",
            "profile": "personal",
            "idempotencyKey": "123e4567-e89b-42d3-a456-426614174000",
            "values": {"departure_day": "friday", "bags": 2},
            "submittedAt": int(time.time()),
        }
        wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-form-coordinate-0001",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 1,
                "ack": 0,
                "ciphertext": client.cipher.seal(plaintext),
            }
        )

        asyncio.run(client.handle_wire_message(wire, received.append))

        self.assertIsInstance(received[0], InboundLinkGenerativeUIFormSubmission)
        self.assertEqual(received[0].request.values["bags"], 2)
        self.assertEqual(received[0].sender_device_id, "mobile-device-1")
        self.assertNotIn("link.identities", state.values)

    def test_decrypts_an_explicit_workspace_request_without_creating_identity_state(self) -> None:
        from loopdy_plugin.link_client import (
            InboundLinkWorkspaceRequest,
            LoopdyLinkClient,
        )

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        received = []
        plaintext = {
            "version": 1,
            "type": "workspace.request",
            "requestId": "workspace_request_0001",
            "operation": "sessions.list",
            "payload": {"limit": 50},
            "sentAt": int(time.time()),
        }
        wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-workspace-coordinate-0001",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 1,
                "ack": 0,
                "ciphertext": client.cipher.seal(plaintext),
            }
        )

        asyncio.run(client.handle_wire_message(wire, received.append))

        self.assertIsInstance(received[0], InboundLinkWorkspaceRequest)
        self.assertEqual(received[0].request.operation, "sessions.list")
        self.assertEqual(received[0].sender_device_id, "mobile-device-1")
        self.assertNotIn("link.identities", state.values)

    def test_new_host_accepts_the_first_cloud_ordered_frame_at_its_current_sequence(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        received = []
        plaintext = {
            "version": 1,
            "type": "user.message",
            "messageId": "message-coordinate-0016",
            "sessionId": "session-coordinate-0001",
            "agentId": "default",
            "actorId": "family-member-1",
            "actorName": "Alex",
            "deviceName": "Kitchen iPad",
            "text": "First message observed by this newly paired host",
            "sentAt": int(time.time()),
        }
        wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-coordinate-0016",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 16,
                "ack": 0,
                "ciphertext": client.cipher.seal(plaintext),
            }
        )

        asyncio.run(client.handle_wire_message(wire, received.append))

        self.assertEqual([item.message.text for item in received], [plaintext["text"]])
        self.assertEqual(socket.sent[0]["sequence"], 16)

    def test_existing_host_accepts_a_higher_sequence_after_missing_other_host_traffic(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        state.set(
            "link.transport.host-device-fixture.received_sequences",
            {"mobile-device-1": 10},
        )
        state.set("link.transport.host-device-fixture.last_received_sequence", 10)
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        received = []
        plaintext = {
            "version": 1,
            "type": "workspace.request",
            "requestId": "request-after-host-gap-0021",
            "operation": "sessions.list",
            "payload": {},
            "sentAt": int(time.time()),
            "targetHostId": config.device_id,
        }
        wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-after-host-gap-0021",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 21,
                "ack": 0,
                "ciphertext": client.cipher.seal(plaintext),
            }
        )

        asyncio.run(client.handle_wire_message(wire, received.append))

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].request.operation, "sessions.list")
        self.assertEqual(
            state.get("link.transport.host-device-fixture.received_sequences"),
            {"mobile-device-1": 21},
        )
        self.assertEqual(socket.sent[-1]["type"], "receipt")

        # Replaying the accepted coordinate remains idempotent and is never
        # dispatched to Hermes a second time.
        asyncio.run(client.handle_wire_message(wire, received.append))
        self.assertEqual(len(received), 1)
        self.assertEqual(socket.sent[-1]["type"], "receipt")

    def test_existing_host_rejects_a_lower_sequence_as_replay_after_a_gap(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        state.set(
            "link.transport.host-device-fixture.received_sequences",
            {"mobile-device-1": 21},
        )
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        received = []
        payload = {
            "version": 1,
            "type": "workspace.request",
            "requestId": "replayed-request-0019",
            "operation": "sessions.list",
            "payload": {},
            "sentAt": int(time.time()),
            "targetHostId": config.device_id,
        }
        wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "replayed-frame-0019",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 19,
                "ack": 0,
                "ciphertext": client.cipher.seal(payload),
            }
        )

        asyncio.run(client.handle_wire_message(wire, received.append))

        self.assertEqual(received, [])
        self.assertEqual(
            state.get("link.transport.host-device-fixture.received_sequences"),
            {"mobile-device-1": 21},
        )
        self.assertEqual(socket.sent[-1]["type"], "receipt")

    def test_public_status_never_contains_runtime_secrets(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        status = LoopdyLinkClient(config, state=_State()).status()
        serialized = json.dumps(status)
        self.assertEqual(status["state"], "disconnected")
        self.assertIn("host-device-fixture", serialized)
        self.assertNotIn(_b64(b"k" * 32), serialized)
        self.assertNotIn("PRIVATE KEY", serialized)

    def test_stop_stays_inside_the_gateway_deadline_when_peer_ignores_close(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        client = LoopdyLinkClient(config, state=_State())

        class HangingSocket:
            async def close(self, **_kwargs):
                await asyncio.Event().wait()

        async def scenario() -> float:
            client._socket = HangingSocket()
            client._task = asyncio.create_task(asyncio.Event().wait())
            started = time.monotonic()
            await asyncio.wait_for(client.stop(), timeout=0.75)
            return time.monotonic() - started

        elapsed = asyncio.run(scenario())

        self.assertLess(elapsed, 0.6)
        self.assertIsNone(client._socket)
        self.assertIsNone(client._task)

    def test_runtime_status_is_persisted_for_other_hermes_processes(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)

        with patch("loopdy_plugin.link_client.time.time", return_value=1_788_000_123):
            client._record_runtime_status("connected")

        self.assertEqual(
            state.values["link.runtime_status"],
            {
                "state": "connected",
                "observed_at": 1_788_000_123,
                "last_connected_at": 1_788_000_123,
                "base_url": "https://link.loopdy.example",
                "device_id": "host-device-fixture",
                "authorization_epoch": 3,
                "reconnect_attempt": 0,
                "detail": "",
            },
        )
        self.assertNotIn(_b64(b"k" * 32), json.dumps(state.values))

    def test_connection_error_detail_is_single_line_and_bounded(self) -> None:
        from loopdy_plugin.link_client import _connection_error_detail

        detail = _connection_error_detail(ValueError("relay readiness\nwas rejected" + "!" * 300))

        self.assertTrue(detail.startswith("ValueError: relay readiness was rejected"))
        self.assertNotIn("\n", detail)
        self.assertLessEqual(len(detail), 160)

    def test_connection_replacement_close_stops_the_superseded_runtime(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        attempts = 0

        class CloseFrame:
            code = 4_000

        class ConnectionReplaced(Exception):
            rcvd = CloseFrame()
            sent = CloseFrame()

        class ReplacedConnection:
            async def __aenter__(self):
                raise ConnectionReplaced("private close detail must not be persisted")

            async def __aexit__(self, *_args):
                return False

        def connect(*_args, **_kwargs):
            nonlocal attempts
            attempts += 1
            return ReplacedConnection()

        async def scenario() -> None:
            with patch("websockets.asyncio.client.connect", new=connect):
                await asyncio.wait_for(client._run(lambda _payload: None), timeout=0.1)
                client.start(lambda _payload: None)
                await asyncio.sleep(0)
                self.assertIsNone(client._task)

        asyncio.run(scenario())

        self.assertEqual(attempts, 1)
        self.assertEqual(state.values["link.runtime_status"]["state"], "superseded")
        self.assertEqual(
            state.values["link.runtime_status"]["detail"],
            "connection replaced by newer runtime",
        )
        self.assertNotIn("private close detail", json.dumps(state.values))

    def test_missing_socket_ready_times_out_instead_of_hanging_connecting(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state, readiness_timeout=0.005)
        attempts = 0

        async def scenario() -> None:
            receive_started = asyncio.Event()
            never_ready = asyncio.Event()

            class ConnectionWithoutReadiness:
                async def __aenter__(self):
                    return self

                async def __aexit__(self, *_args):
                    return False

                async def recv(self):
                    receive_started.set()
                    await never_ready.wait()

            def connect(*_args, **_kwargs):
                nonlocal attempts
                attempts += 1
                return ConnectionWithoutReadiness()

            with patch("websockets.asyncio.client.connect", new=connect):
                task = asyncio.create_task(client._run(lambda _payload: None))
                await asyncio.wait_for(receive_started.wait(), timeout=0.1)
                await asyncio.sleep(0.02)
                client._stopping.set()
                await asyncio.wait_for(task, timeout=0.1)

        asyncio.run(scenario())

        self.assertEqual(attempts, 1)
        self.assertEqual(state.values["link.runtime_status"]["state"], "reconnecting")
        self.assertIn("TimeoutError", state.values["link.runtime_status"]["detail"])

    def test_dispatches_relay_ready_control_without_creating_a_chat_identity(self) -> None:
        from loopdy_plugin.link_client import InboundLinkRelayReady, LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        socket = _Socket()
        client._socket = socket
        received = []
        plaintext = {
            "version": 1,
            "type": "relay.ready",
            "deviceId": "mobile-device-1",
            "enrollmentRevision": 4,
            "acknowledgementRevision": 5,
            "leaseExpires": int(time.time()) + 2_000,
            "recipientPublicKey": "B" + "A" * 86,
            "recipientKeyId": "A" * 43,
            "senderKeyRevision": 2,
            "acknowledgedSenderKeyIds": ["A" * 43],
            "environment": "production",
            "topic": ".".join(("app", "loopdy", "mobile")),
            "deviceName": "Alex's iPhone",
            "sentAt": int(time.time()),
        }
        wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-control-coordinate-0001",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 1,
                "ack": 0,
                "ciphertext": client.cipher.seal(plaintext),
            }
        )

        asyncio.run(client.handle_wire_message(wire, received.append))

        self.assertIsInstance(received[0], InboundLinkRelayReady)
        self.assertEqual(received[0].registration.device_id, "mobile-device-1")
        self.assertNotIn("link.identities", state.values)
        self.assertEqual(
            state.values["link.transport.host-device-fixture.last_received_sequence"],
            1,
        )

    def test_relay_ready_callback_failure_marks_link_unready_and_reconnectable(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)

        class ObservableSocket(_Socket):
            def __init__(self):
                super().__init__()
                self.closed = False

            async def close(self, **_kwargs):
                self.closed = True

        socket = ObservableSocket()
        client._socket = socket
        wire = _relay_ready_wire(client, sequence=1)

        async def scenario() -> None:
            def callback(_payload):
                raise ValueError("Loopdy Link relay sender-key acknowledgement is invalid")

            await client.handle_wire_message(wire, callback, defer_callbacks=True)
            await client._inbound_callback_queue.join()

        asyncio.run(scenario())

        self.assertTrue(socket.closed)
        self.assertEqual(state.values["link.runtime_status"]["state"], "unready")
        self.assertEqual(
            state.values.get("link.transport.host-device-fixture.received_sequences", {}),
            {},
        )
        self.assertFalse(any(message.get("type") == "receipt" for message in socket.sent))

    def test_wait_until_connected_reports_socket_ready_without_claiming_it_early(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        client = LoopdyLinkClient(config, state=_State())

        async def scenario() -> None:
            self.assertFalse(await client.wait_until_connected(timeout=0.001))
            client._connected.set()
            self.assertTrue(await client.wait_until_connected(timeout=0.001))

        asyncio.run(scenario())

    def test_user_callback_failure_returns_correlated_failure_before_followup_dispatch(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)

        ordering: list[str] = []

        class ObservableSocket(_Socket):
            def __init__(self):
                super().__init__()
                self.closed = False

            async def send(self, value):
                message = json.loads(value)
                self.sent.append(message)
                if message.get("type") == "frame" and message.get("senderDeviceId") == config.device_id:
                    payload = client.cipher.open(message["ciphertext"])
                    ordering.append(f"outbound:{payload['type']}")
                    client._accept_outbound(
                        {
                            "version": 1,
                            "type": "accepted",
                            "id": message["id"],
                            "sequence": message["sequence"],
                        }
                    )
                elif message.get("type") == "receipt":
                    ordering.append(f"receipt:{message['sequence']}")

            async def close(self, **_kwargs):
                self.closed = True

        socket = ObservableSocket()
        client._socket = socket
        client._connected.set()
        first_wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-user-failure-coordinate",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 1,
                "ack": 0,
                "ciphertext": client.cipher.seal(
                    {
                        "version": 1,
                        "type": "user.message",
                        "messageId": "message-user-failure-coordinate",
                        "sessionId": "session-user-failure-coordinate",
                        "agentId": "gordie",
                        "actorId": "actor-fixture",
                        "actorName": "Alex",
                        "deviceName": "iPhone",
                        "text": "Fail this request",
                        "attachments": [],
                        "behavior": "steer",
                        "sentAt": int(time.time()),
                    }
                ),
            }
        )

        second_wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-user-recovery-coordinate",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 2,
                "ack": 0,
                "ciphertext": client.cipher.seal(
                    {
                        "version": 1,
                        "type": "user.message",
                        "messageId": "message-user-recovery-coordinate",
                        "sessionId": "session-user-failure-coordinate",
                        "agentId": "gordie",
                        "actorId": "actor-fixture",
                        "actorName": "Alex",
                        "deviceName": "iPhone",
                        "text": "This request must follow",
                        "attachments": [],
                        "behavior": "queue",
                        "sentAt": int(time.time()),
                    }
                ),
            }
        )
        async def scenario() -> None:
            def callback(payload):
                ordering.append(f"callback:{payload.message.message_id}")
                if payload.message.message_id == "message-user-failure-coordinate":
                    raise ValueError("Hermes callback failed")

            await client.handle_wire_message(
                first_wire, callback, defer_callbacks=True
            )
            await client.handle_wire_message(
                second_wire, callback, defer_callbacks=True
            )
            await client._inbound_callback_queue.join()

        asyncio.run(scenario())

        self.assertFalse(socket.closed)
        self.assertEqual(
            state.values["link.transport.host-device-fixture.received_sequences"],
            {"mobile-device-1": 2},
        )
        self.assertEqual(
            [message["sequence"] for message in socket.sent if message.get("type") == "receipt"],
            [1, 2],
        )
        failure_frame = next(
            message
            for message in socket.sent
            if message.get("type") == "frame"
            and message.get("senderDeviceId") == config.device_id
        )
        self.assertEqual(
            client.cipher.open(failure_frame["ciphertext"]),
            {
                "version": 1,
                "type": "user.message.result",
                "requestId": "message-user-failure-coordinate",
                "sessionId": "session-user-failure-coordinate",
                "agentId": "gordie",
                "status": "failed",
                "code": "hermes_request_failed",
                "message": "Hermes could not accept this message.",
                "sentAt": unittest.mock.ANY,
            },
        )
        self.assertEqual(
            ordering,
            [
                "callback:message-user-failure-coordinate",
                "outbound:user.message.result",
                "receipt:1",
                "callback:message-user-recovery-coordinate",
                "outbound:user.message.result",
                "receipt:2",
            ],
        )
        success_frame = [
            message
            for message in socket.sent
            if message.get("type") == "frame"
            and message.get("senderDeviceId") == config.device_id
        ][1]
        self.assertEqual(
            client.cipher.open(success_frame["ciphertext"]),
            {
                "version": 1,
                "type": "user.message.result",
                "requestId": "message-user-recovery-coordinate",
                "sessionId": "session-user-failure-coordinate",
                "agentId": "gordie",
                "status": "accepted",
                "sentAt": unittest.mock.ANY,
            },
        )

    def test_success_result_transport_failure_does_not_masquerade_as_hermes_rejection(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)
        attempted_statuses: list[str] = []

        class FailingSocket(_Socket):
            def __init__(self):
                super().__init__()
                self.closed = False

            async def send(self, value):
                message = json.loads(value)
                self.sent.append(message)
                if message.get("type") == "frame" and message.get("senderDeviceId") == config.device_id:
                    attempted_statuses.append(
                        client.cipher.open(message["ciphertext"])["status"]
                    )
                    raise ConnectionError("socket failed while returning acceptance")

            async def close(self, **_kwargs):
                self.closed = True

        socket = FailingSocket()
        client._socket = socket
        client._connected.set()
        wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-success-result-transport-failure",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 1,
                "ack": 0,
                "ciphertext": client.cipher.seal(
                    {
                        "version": 1,
                        "type": "user.message",
                        "messageId": "message-success-result-failure-0001",
                        "sessionId": "session-success-result-failure-0001",
                        "agentId": "gordie",
                        "actorId": "actor-fixture",
                        "actorName": "Alex",
                        "deviceName": "iPhone",
                        "text": "Hermes accepts this",
                        "attachments": [],
                        "sentAt": int(time.time()),
                    }
                ),
            }
        )

        async def scenario() -> None:
            started = asyncio.get_running_loop().time()
            await client.handle_wire_message(
                wire, lambda _payload: None, defer_callbacks=True
            )
            await client._inbound_callback_queue.join()
            self.assertLess(asyncio.get_running_loop().time() - started, 0.2)

        asyncio.run(scenario())

        self.assertEqual(attempted_statuses, ["accepted"])
        self.assertTrue(socket.closed)
        self.assertNotIn(
            "mobile-device-1",
            state.get("link.transport.host-device-fixture.received_sequences", {}),
        )
        self.assertFalse(any(message.get("type") == "receipt" for message in socket.sent))

    def test_outbound_timeout_marks_exact_frame_and_fresh_ready_unblocks_later_payload(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state, delivery_timeout=0.01)

        class ObservableSocket(_Socket):
            def __init__(self):
                super().__init__()
                self.closed = False

            async def close(self, **_kwargs):
                self.closed = True

        first = ObservableSocket()
        client._socket = first
        client._connected.set()
        failed_payload = {
            "version": 1,
            "type": "notification.event",
            "eventId": "notification-timeout-fixture-0001",
        }
        later_payload = {
            "version": 1,
            "type": "notification.event",
            "eventId": "notification-recovered-fixture-0001",
        }

        async def scenario() -> str:
            with self.assertRaises(asyncio.TimeoutError):
                await client.send_payload(failed_payload)
            failed = state.get("link.transport.host-device-fixture.pending_frame")
            self.assertIsInstance(failed, dict)
            self.assertEqual(
                state.get("link.transport.host-device-fixture.failed_pending_frame_id"),
                failed["id"],
            )
            self.assertTrue(first.closed)

            second = ObservableSocket()
            client._socket = second
            client._reconcile_socket_ready(
                {
                    "version": 1,
                    "type": "socket.ready",
                    "deviceId": config.device_id,
                    "authorizationEpoch": config.authorization_epoch,
                    "lastInboundSequence": 0,
                    "lastInboundFrameId": None,
                    "lastAcknowledgedSequence": 0,
                }
            )
            client._connected.set()
            sending = asyncio.create_task(client.send_payload(later_payload))
            while not second.sent:
                await asyncio.sleep(0)
            later = second.sent[0]
            client._accept_outbound(
                {
                    "version": 1,
                    "type": "accepted",
                    "id": later["id"],
                    "sequence": later["sequence"],
                }
            )
            return await sending

        later_id = asyncio.run(scenario())

        self.assertTrue(later_id.startswith("frame_"))
        self.assertIsNone(state.get("link.transport.host-device-fixture.pending_frame"))
        self.assertIsNone(
            state.get("link.transport.host-device-fixture.failed_pending_frame_id")
        )

    def test_failed_outbound_frame_reanchors_to_contradictory_authenticated_ready_state(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        for server_sequence, server_frame_id in [
            (3, "frame_unrelated_older_coordinate"),
            (6, "frame_unrelated_ahead_coordinate"),
        ]:
            with self.subTest(server_sequence=server_sequence):
                state = _State()
                client = LoopdyLinkClient(config, state=state)
                pending = {
                    "version": 1,
                    "type": "frame",
                    "id": "frame_failed_ready_coordinate",
                    "senderDeviceId": config.device_id,
                    "senderEpoch": config.authorization_epoch,
                    "sequence": 5,
                    "ack": 0,
                    "ciphertext": client.cipher.seal(
                        {"version": 1, "type": "notification.event"}
                    ),
                }
                state.set("link.transport.host-device-fixture.pending_frame", pending)
                state.set(
                    "link.transport.host-device-fixture.failed_pending_frame_id",
                    pending["id"],
                )

                client._reconcile_socket_ready(
                    {
                        "version": 1,
                        "type": "socket.ready",
                        "deviceId": config.device_id,
                        "authorizationEpoch": config.authorization_epoch,
                        "lastInboundSequence": server_sequence,
                        "lastInboundFrameId": server_frame_id,
                        "lastAcknowledgedSequence": 0,
                    }
                )

                self.assertIsNone(
                    state.get("link.transport.host-device-fixture.pending_frame")
                )
                self.assertIsNone(
                    state.get("link.transport.host-device-fixture.failed_pending_frame_id")
                )
                self.assertEqual(
                    state.get("link.transport.host-device-fixture.outbound_sequence"),
                    server_sequence,
                )

    def test_attachment_storage_failure_is_quarantined_without_reconnecting(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)

        class ObservableSocket(_Socket):
            def __init__(self):
                super().__init__()
                self.closed = False

            async def close(self, **_kwargs):
                self.closed = True

        socket = ObservableSocket()
        client._socket = socket
        content = b"image bytes"
        digest = _b64(hashlib.sha256(content).digest())
        attachment_wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-attachment-storage-failure",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 1,
                "ack": 0,
                "ciphertext": client.cipher.seal(
                    {
                        "version": 1,
                        "type": "attachment.chunk",
                        "uploadId": "upload-storage-failure-0001",
                        "sessionId": "session-storage-failure-0001",
                        "agentId": "finance",
                        "attachmentId": "attachment-storage-failure-0001",
                        "fileName": "photo.jpg",
                        "mimeType": "image/jpeg",
                        "totalBytes": len(content),
                        "sha256": digest,
                        "index": 0,
                        "count": 1,
                        "data": _b64(content),
                        "sentAt": int(time.time()),
                    }
                ),
            }
        )
        oversized_chunk_wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-oversized-chunk-coordinate",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 2,
                "ack": 0,
                "ciphertext": client.cipher.seal(
                    {
                        "version": 1,
                        "type": "attachment.chunk",
                        "uploadId": "upload-oversized-coordinate-0001",
                        "sessionId": "session-storage-failure-0001",
                        "agentId": "finance",
                        "attachmentId": "attachment-oversized-coordinate-0001",
                        "fileName": "photo.jpg",
                        "mimeType": "image/jpeg",
                        "totalBytes": len(content),
                        "sha256": digest,
                        "index": 0,
                        "count": 129,
                        "data": _b64(content),
                        "sentAt": int(time.time()),
                    }
                ),
            }
        )
        workspace_wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-after-attachment-failure",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 3,
                "ack": 0,
                "ciphertext": client.cipher.seal(
                    {
                        "version": 1,
                        "type": "workspace.request",
                        "requestId": "request-after-attachment-failure",
                        "operation": "sessions.list",
                        "payload": {},
                        "sentAt": int(time.time()),
                    }
                ),
            }
        )
        observed = []

        async def scenario() -> None:
            with patch.object(
                client.attachment_inbox,
                "accept",
                side_effect=OSError("simulated protected-data failure"),
            ):
                await client.handle_wire_message(
                    attachment_wire, observed.append, defer_callbacks=True
                )
            await client.handle_wire_message(
                oversized_chunk_wire, observed.append, defer_callbacks=True
            )
            await client.handle_wire_message(
                workspace_wire, observed.append, defer_callbacks=True
            )
            await client._inbound_callback_queue.join()

        asyncio.run(scenario())

        self.assertFalse(socket.closed)
        self.assertEqual(len(observed), 1)
        self.assertEqual(
            state.values["link.transport.host-device-fixture.received_sequences"],
            {"mobile-device-1": 3},
        )
        self.assertEqual(
            [message["sequence"] for message in socket.sent if message.get("type") == "receipt"],
            [1, 2, 3],
        )

    def test_missing_message_attachment_returns_correlated_failure_instead_of_hanging_turn(self) -> None:
        from loopdy_plugin.link_client import LoopdyLinkClient

        _, config = self._configuration()
        state = _State()
        client = LoopdyLinkClient(config, state=state)

        socket = _Socket()
        client._socket = socket
        client._connected.set()
        wire = json.dumps(
            {
                "version": 1,
                "type": "frame",
                "id": "frame-missing-message-attachment",
                "senderDeviceId": "mobile-device-1",
                "senderEpoch": 1,
                "sequence": 1,
                "ack": 0,
                "ciphertext": client.cipher.seal(
                    {
                        "version": 1,
                        "type": "user.message",
                        "messageId": "message-missing-attachment-0001",
                        "sessionId": "session-missing-attachment-0001",
                        "agentId": "gordie",
                        "actorId": "actor-fixture",
                        "actorName": "Alex",
                        "deviceName": "iPhone",
                        "text": "Read the missing image",
                        "attachments": [
                            {
                                "attachmentId": "attachment-missing-fixture-0001",
                                "fileName": "photo.jpg",
                                "mimeType": "image/jpeg",
                                "totalBytes": 3,
                                "sha256": _b64(hashlib.sha256(b"abc").digest()),
                            }
                        ],
                        "sentAt": int(time.time()),
                    }
                ),
            }
        )

        async def scenario() -> None:
            # The socket reader must return before the correlated failure is
            # accepted, otherwise it cannot consume that acceptance in
            # production and both peers wait until their delivery watchdogs.
            await asyncio.wait_for(
                client.handle_wire_message(
                    wire, lambda _payload: None, defer_callbacks=True
                ),
                timeout=0.05,
            )
            while not any(message.get("type") == "frame" for message in socket.sent):
                await asyncio.sleep(0)
            failure = next(
                message for message in socket.sent if message.get("type") == "frame"
            )
            client._accept_outbound(
                {
                    "version": 1,
                    "type": "accepted",
                    "id": failure["id"],
                    "sequence": failure["sequence"],
                }
            )
            await client._inbound_callback_queue.join()

        asyncio.run(scenario())

        failure_frames = [
            message
            for message in socket.sent
            if message.get("type") == "frame"
            and message.get("senderDeviceId") == config.device_id
        ]
        self.assertEqual(len(failure_frames), 1)
        self.assertEqual(
            client.cipher.open(failure_frames[0]["ciphertext"]),
            {
                "version": 1,
                "type": "user.message.result",
                "requestId": "message-missing-attachment-0001",
                "sessionId": "session-missing-attachment-0001",
                "agentId": "gordie",
                "status": "failed",
                "code": "attachment_unavailable",
                "message": "The attached file is unavailable. Attach it again and retry.",
                "sentAt": unittest.mock.ANY,
            },
        )
        self.assertEqual(
            state.get("link.transport.host-device-fixture.received_sequences"),
            {"mobile-device-1": 1},
        )


if __name__ == "__main__":
    unittest.main()
