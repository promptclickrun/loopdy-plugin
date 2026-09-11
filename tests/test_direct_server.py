from __future__ import annotations

import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path

import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatus
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from loopdy_plugin.direct_commands import DirectCommandJournal
from loopdy_plugin.direct_connection import (
    DirectConnectionAuthority,
    canonical_enrollment_transcript,
    canonical_session_transcript,
)
from loopdy_plugin.link_crypto import encode_base64url, sign_p256_raw
from loopdy_plugin.session_stream import SessionStreamHub


class _State:
    def __init__(self) -> None:
        self.values: dict[str, object] = {}

    def get(self, key: str, default=None):
        return self.values.get(key, default)

    def set(self, key: str, value: object) -> None:
        self.values[key] = value


def _spki(key: ec.EllipticCurvePrivateKey) -> str:
    return encode_base64url(
        key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _device(device_id: str, *, role: str, epoch: int) -> dict[str, object]:
    return {
        "deviceId": device_id,
        "encryptedName": "synthetic",
        "role": role,
        "kind": "hermes_host" if role == "host" else "phone",
        "lifecycle": "active",
        "revision": 1,
        "authorizationEpoch": epoch,
        "connection": "online",
        "pushState": None if role == "host" else "ready",
        "pushRevision": 0 if role == "host" else 1,
        "createdAt": 1,
        "revokedAt": None,
        "lastSeenBucket": 1,
    }


class DirectServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.host_key = ec.generate_private_key(ec.SECP256R1())
        self.phone_key = ec.generate_private_key(ec.SECP256R1())
        state = _State()
        self.authority = DirectConnectionAuthority(
            account_origin="https://account.example",
            direct_origin="https://direct.example:8443",
            host_device_id="host_1",
            host_epoch=7,
            host_private_key=self.host_key,
            state=state,
        )
        phone_public_key = _spki(self.phone_key)
        enrollment = {
            "version": 1,
            "exchangeId": "exchange_1",
            "phoneNonce": "phone_nonce_1",
            "phonePublicKey": phone_public_key,
        }
        transcript = canonical_enrollment_transcript(
            account_origin="https://account.example",
            direct_origin="https://direct.example:8443",
            host_device_id="host_1",
            host_epoch=7,
            phone_device_id="phone_1",
            phone_epoch=11,
            exchange_id="exchange_1",
            phone_nonce="phone_nonce_1",
            phone_public_key=phone_public_key,
        )
        enrollment["phoneProof"] = encode_base64url(
            sign_p256_raw(self.phone_key, transcript)
        )
        self.authority._enroll_from_link(
            enrollment,
            trusted_sender_device_id="phone_1",
            trusted_sender_epoch=11,
        )
        self.authority._refresh_lifecycle_catalog(
            {
                "version": 1,
                "devices": [
                    _device("host_1", role="host", epoch=7),
                    _device("phone_1", role="mobile", epoch=11),
                ],
            }
        )
        self.journal = DirectCommandJournal(
            Path(self.temporary.name).resolve() / "direct.sqlite3"
        )
        self.servers = []

    async def asyncTearDown(self) -> None:
        for server in self.servers:
            await server.stop()
        self.journal.close()
        self.temporary.cleanup()

    async def _connect(self, server):
        socket = await websockets.connect(
            f"ws://127.0.0.1:{server.port}/loopdy/direct/v1",
            compression=None,
        )
        client_nonce = encode_base64url(bytes(range(32)))
        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "direct.hello",
                    "deviceId": "phone_1",
                    "authorizationEpoch": 11,
                    "clientNonce": client_nonce,
                }
            )
        )
        challenge_envelope = json.loads(await socket.recv())
        challenge = challenge_envelope["challenge"]
        proof_transcript = canonical_session_transcript(
            account_origin="https://account.example",
            direct_origin="https://direct.example:8443",
            host_device_id="host_1",
            host_epoch=7,
            peer_device_id="phone_1",
            peer_epoch=11,
            connection_id=challenge["connectionID"],
            nonce=challenge["nonce"],
            client_nonce=client_nonce,
        )
        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "direct.proof",
                    "nonce": challenge["nonce"],
                    "peerProof": encode_base64url(
                        sign_p256_raw(self.phone_key, proof_transcript)
                    ),
                }
            )
        )
        ready = json.loads(await socket.recv())
        self.assertEqual(ready["type"], "direct.ready")
        return socket, ready["connectionID"]

    async def _hello(self, server, *, client_nonce: str | None = None):
        socket = await websockets.connect(
            f"ws://127.0.0.1:{server.port}/loopdy/direct/v1", compression=None
        )
        nonce = client_nonce or encode_base64url(bytes(range(32)))
        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "direct.hello",
                    "deviceId": "phone_1",
                    "authorizationEpoch": 11,
                    "clientNonce": nonce,
                }
            )
        )
        return socket, nonce, json.loads(await socket.recv())["challenge"]

    def _proof(self, challenge, client_nonce, *, key=None, connection_id=None):
        transcript = canonical_session_transcript(
            account_origin="https://account.example",
            direct_origin="https://direct.example:8443",
            host_device_id="host_1",
            host_epoch=7,
            peer_device_id="phone_1",
            peer_epoch=11,
            connection_id=connection_id or challenge["connectionID"],
            nonce=challenge["nonce"],
            client_nonce=client_nonce,
        )
        return encode_base64url(sign_p256_raw(key or self.phone_key, transcript))

    async def _send_proof(self, socket, challenge, proof):
        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "direct.proof",
                    "nonce": challenge["nonce"],
                    "peerProof": proof,
                }
            )
        )

    async def test_valid_handshake_and_command_dispatch_real_loopback(self) -> None:
        try:
            from loopdy_plugin.direct_server import DirectServer
        except ModuleNotFoundError as error:
            self.fail(f"DirectServer is missing: {error.name}")

        calls = []

        async def dispatch(context, payload):
            calls.append((context, payload))
            return {"accepted": True}

        server = DirectServer(self.authority, self.journal, dispatch)
        self.servers.append(server)
        await server.start(0)
        socket, connection_id = await self._connect(server)
        issued_at = int(time.time())
        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "direct.command",
                    "commandID": "command_basic_0001",
                    "issuedAt": issued_at,
                    "payload": {"kind": "synthetic"},
                }
            )
        )

        receipt = json.loads(await socket.recv())
        self.assertEqual(
            receipt,
            {
                "version": 1,
                "type": "direct.receipt",
                "commandID": "command_basic_0001",
                "state": "completed",
                "result": {"accepted": True},
            },
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0].connection_id, connection_id)
        self.assertEqual(calls[0][0].peer.peer_device_id, "phone_1")
        self.assertEqual(calls[0][1], {"kind": "synthetic"})
        await socket.close()

    async def test_proofs_are_single_use_nonce_and_connection_bound(self) -> None:
        from loopdy_plugin.direct_server import DirectServer

        server = DirectServer(self.authority, self.journal, lambda *_: None)
        self.servers.append(server)
        await server.start()

        wrong_socket, nonce, challenge = await self._hello(server)
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        await self._send_proof(
            wrong_socket, challenge, self._proof(challenge, nonce, key=wrong_key)
        )
        with self.assertRaises(ConnectionClosed):
            await wrong_socket.recv()

        first, first_nonce, first_challenge = await self._hello(server)
        second, _, second_challenge = await self._hello(server)
        cross = self._proof(
            first_challenge,
            first_nonce,
            connection_id=first_challenge["connectionID"],
        )
        await self._send_proof(second, second_challenge, cross)
        with self.assertRaises(ConnectionClosed):
            await second.recv()
        await first.close()

        replay, replay_nonce, replay_challenge = await self._hello(server)
        proof = self._proof(replay_challenge, replay_nonce)
        await self._send_proof(replay, replay_challenge, proof)
        await replay.recv()
        await self._send_proof(replay, replay_challenge, proof)
        with self.assertRaises(ConnectionClosed):
            await replay.recv()

    async def test_pre_auth_command_and_client_nonce_tamper_never_dispatch(self) -> None:
        from loopdy_plugin.direct_server import DirectServer

        calls = []

        async def dispatch(*args):
            calls.append(args)
            return {"accepted": True}

        server = DirectServer(self.authority, self.journal, dispatch)
        self.servers.append(server)
        await server.start()
        socket = await websockets.connect(
            f"ws://127.0.0.1:{server.port}/loopdy/direct/v1", compression=None
        )
        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "direct.command",
                    "commandID": "command_too_early",
                    "issuedAt": int(time.time()),
                    "payload": {},
                }
            )
        )
        with self.assertRaises(ConnectionClosed):
            await socket.recv()

        tampered, nonce, challenge = await self._hello(server)
        other_nonce = encode_base64url(bytes(reversed(range(32))))
        await self._send_proof(tampered, challenge, self._proof(challenge, other_nonce))
        with self.assertRaises(ConnectionClosed):
            await tampered.recv()
        self.assertEqual(calls, [])

    async def test_revoked_peer_is_closed_while_idle(self) -> None:
        from loopdy_plugin.direct_server import DirectServer

        async def dispatch(_context, _payload):
            return {"accepted": True}

        server = DirectServer(self.authority, self.journal, dispatch)
        self.servers.append(server)
        await server.start()
        socket, _ = await self._connect(server)
        self.authority._refresh_lifecycle_catalog(
            {"version": 1, "devices": [_device("host_1", role="host", epoch=7)]}
        )
        with self.assertRaises(ConnectionClosed):
            await asyncio.wait_for(socket.recv(), 1.5)

    async def test_disconnect_does_not_cancel_admitted_action_or_rerun_duplicate(self) -> None:
        from loopdy_plugin.direct_server import DirectServer

        entered = asyncio.Event()
        release = asyncio.Event()
        calls = 0

        async def dispatch(_context, _payload):
            nonlocal calls
            calls += 1
            entered.set()
            await release.wait()
            return {"accepted": True, "count": calls}

        server = DirectServer(self.authority, self.journal, dispatch)
        self.servers.append(server)
        await server.start()
        issued_at = int(time.time())
        command = {
            "version": 1,
            "type": "direct.command",
            "commandID": "command_disconnect_1",
            "issuedAt": issued_at,
            "payload": {"action": "synthetic"},
        }
        socket, _ = await self._connect(server)
        await socket.send(json.dumps(command))
        await asyncio.wait_for(entered.wait(), 1)
        await socket.close()
        release.set()

        replay, _ = await self._connect(server)
        for _ in range(20):
            await replay.send(json.dumps(command))
            receipt = json.loads(await replay.recv())
            if receipt["state"] == "completed":
                break
            await asyncio.sleep(0.01)
        self.assertEqual(receipt["result"], {"accepted": True, "count": 1})
        self.assertEqual(calls, 1)
        await replay.close()

    async def test_context_send_remains_bound_to_original_connection(self) -> None:
        from loopdy_plugin.direct_server import DirectServer

        contexts = []

        async def dispatch(context, _payload):
            contexts.append(context)
            return {"accepted": True}

        server = DirectServer(self.authority, self.journal, dispatch)
        self.servers.append(server)
        await server.start()
        first, _ = await self._connect(server)
        await first.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "direct.command",
                    "commandID": "command_context_001",
                    "issuedAt": int(time.time()),
                    "payload": {},
                }
            )
        )
        await first.recv()
        await first.close()
        newer, _ = await self._connect(server)

        with self.assertRaises(ConnectionError):
            await contexts[0].send({"version": 1, "type": "synthetic.output"})
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(newer.recv(), 0.1)
        await newer.close()

    async def test_post_admission_exception_returns_uncertain_receipt_not_rejection(self) -> None:
        from loopdy_plugin.direct_server import DirectServer

        async def dispatch(_context, _payload):
            raise RuntimeError("private exception text and payload must not escape")

        server = DirectServer(self.authority, self.journal, dispatch)
        self.servers.append(server)
        await server.start()
        socket, _ = await self._connect(server)
        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "direct.command",
                    "commandID": "command_uncertain_1",
                    "issuedAt": int(time.time()),
                    "payload": {"private": "do-not-echo"},
                }
            )
        )
        receipt = json.loads(await socket.recv())
        self.assertEqual(receipt["type"], "direct.receipt")
        self.assertEqual(receipt["state"], "completed")
        self.assertEqual(
            receipt["result"], {"accepted": False, "code": "uncertain"}
        )
        self.assertNotIn("private exception", json.dumps(receipt))
        self.assertNotIn("do-not-echo", json.dumps(receipt))
        await socket.close()

    async def test_connection_and_authenticated_peer_capacity_are_bounded(self) -> None:
        from loopdy_plugin.direct_server import DirectServer

        async def dispatch(_context, _payload):
            return {"accepted": True}

        server = DirectServer(self.authority, self.journal, dispatch)
        self.servers.append(server)
        await server.start()
        waiting = [
            await websockets.connect(
                f"ws://127.0.0.1:{server.port}/loopdy/direct/v1", compression=None
            )
            for _ in range(16)
        ]
        excess = await websockets.connect(
            f"ws://127.0.0.1:{server.port}/loopdy/direct/v1", compression=None
        )
        with self.assertRaises(ConnectionClosed):
            await excess.recv()
        await asyncio.gather(*(socket.close() for socket in waiting))

        first, _ = await self._connect(server)
        second, _ = await self._connect(server)
        third, nonce, challenge = await self._hello(server)
        await self._send_proof(third, challenge, self._proof(challenge, nonce))
        with self.assertRaises(ConnectionClosed):
            await third.recv()
        await first.close()
        await second.close()

    async def test_command_capacity_rejects_without_entering_dispatch(self) -> None:
        from loopdy_plugin.direct_server import DirectServer

        release = asyncio.Event()
        entered = 0

        async def dispatch(_context, _payload):
            nonlocal entered
            entered += 1
            await release.wait()
            return {"accepted": True}

        server = DirectServer(self.authority, self.journal, dispatch)
        self.servers.append(server)
        await server.start()
        socket, _ = await self._connect(server)
        issued_at = int(time.time())
        for index in range(9):
            await socket.send(
                json.dumps(
                    {
                        "version": 1,
                        "type": "direct.command",
                        "commandID": f"command_capacity_{index:02d}",
                        "issuedAt": issued_at,
                        "payload": {"index": index},
                    }
                )
            )
        rejected = json.loads(await asyncio.wait_for(socket.recv(), 1))
        self.assertEqual(rejected["type"], "direct.rejected")
        self.assertEqual(rejected["commandID"], "command_capacity_08")
        self.assertEqual(rejected["code"], "capacity")
        for _ in range(100):
            if entered == 8:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(entered, 8)
        release.set()
        await socket.close()

    async def test_read_only_queries_are_ephemeral_and_do_not_consume_journal(self) -> None:
        from loopdy_plugin.direct_server import DirectServer

        query_calls = 0

        async def dispatch(_context, payload):
            nonlocal query_calls
            if payload.get("type") == "workspace.request":
                query_calls += 1
                return {"profiles": []}
            return {"accepted": True}

        self.journal.close()
        self.journal = DirectCommandJournal(
            Path(self.temporary.name).resolve() / "bounded.sqlite3",
            maximum_entries=1,
        )
        server = DirectServer(self.authority, self.journal, dispatch)
        self.servers.append(server)
        await server.start()
        socket, _ = await self._connect(server)
        sent_at = int(time.time())
        for index in range(20):
            request_id = f"direct_query_{index:04d}"
            await socket.send(
                json.dumps(
                    {
                        "version": 1,
                        "type": "direct.query",
                        "requestID": request_id,
                        "payload": {
                            "version": 1,
                            "type": "workspace.request",
                            "requestId": f"workspace_query_{index:04d}",
                            "operation": "agents.list",
                            "payload": {},
                            "sentAt": sent_at,
                        },
                    }
                )
            )
            response = json.loads(await socket.recv())
            self.assertEqual(
                response,
                {
                    "version": 1,
                    "type": "direct.query.result",
                    "requestID": request_id,
                    "result": {"profiles": []},
                },
            )
        self.assertEqual(query_calls, 20)

        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "direct.command",
                    "commandID": "command_after_queries",
                    "issuedAt": sent_at,
                    "payload": {"kind": "synthetic"},
                }
            )
        )
        receipt = json.loads(await socket.recv())
        self.assertEqual(receipt["state"], "completed")
        await socket.close()

    async def test_query_lane_rejects_mutations_before_dispatch(self) -> None:
        from loopdy_plugin.direct_server import DirectServer

        calls = []

        async def dispatch(_context, payload):
            calls.append(payload)
            return {"changed": True}

        server = DirectServer(self.authority, self.journal, dispatch)
        self.servers.append(server)
        await server.start()
        socket, _ = await self._connect(server)
        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "direct.query",
                    "requestID": "direct_query_mutation",
                    "payload": {
                        "version": 1,
                        "type": "workspace.request",
                        "requestId": "workspace_query_mutation",
                        "operation": "voice_settings.set",
                        "payload": {
                            "agentId": "default",
                            "expectedRevision": "a" * 64,
                            "providerId": "openai",
                            "voiceId": "alloy",
                            "confirmed": True,
                        },
                        "sentAt": int(time.time()),
                    },
                }
            )
        )
        response = json.loads(await socket.recv())
        self.assertEqual(
            response,
            {
                "version": 1,
                "type": "direct.query.result",
                "requestID": "direct_query_mutation",
                "result": {"status": "failed", "code": "invalid"},
            },
        )
        self.assertEqual(calls, [])
        await socket.close()

    async def test_query_result_is_bounded_with_a_safe_failure(self) -> None:
        from loopdy_plugin.direct_server import DirectServer

        async def dispatch(_context, _payload):
            return {"data": "x" * (512 * 1024 - 28)}

        server = DirectServer(self.authority, self.journal, dispatch)
        self.servers.append(server)
        await server.start()
        socket, _ = await self._connect(server)
        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "direct.query",
                    "requestID": "direct_query_oversize",
                    "payload": {
                        "version": 1,
                        "type": "workspace.request",
                        "requestId": "workspace_query_oversize",
                        "operation": "agents.list",
                        "payload": {},
                        "sentAt": int(time.time()),
                    },
                }
            )
        )
        response = json.loads(await socket.recv())
        self.assertEqual(
            response["result"], {"status": "failed", "code": "query_failed"}
        )
        await socket.close()

    async def test_session_snapshot_precedes_buffered_event_and_unsubscribe_closes(self) -> None:
        from loopdy_plugin.direct_server import DirectServer, DirectSessionView

        hub = SessionStreamHub(maximum_events=4)
        subscriptions = []

        async def open_session(_context, agent_id, session_id):
            subscription = hub.subscribe(agent_id=agent_id, session_id=session_id)
            subscriptions.append(subscription)
            hub.publish(
                agent_id=agent_id,
                session_id=session_id,
                payload={"type": "assistant.message", "text": "buffered"},
            )
            return DirectSessionView(
                snapshot={"messages": []},
                subscription=subscription,
                process_epoch=hub.process_epoch,
                start_cursor=0,
            )

        async def dispatch(_context, _payload):
            return {"accepted": True}

        server = DirectServer(
            self.authority, self.journal, dispatch, open_session=open_session
        )
        self.servers.append(server)
        await server.start()
        socket, _ = await self._connect(server)
        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "session.subscribe",
                    "subscriptionID": "subscription_0001",
                    "agentId": "agent_1",
                    "sessionId": "session_1",
                }
            )
        )
        snapshot = json.loads(await socket.recv())
        event = json.loads(await socket.recv())
        self.assertEqual(snapshot["type"], "session.snapshot")
        self.assertEqual(snapshot["cursor"], 0)
        self.assertEqual(event["type"], "session.event")
        self.assertEqual(event["cursor"], 1)
        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "session.unsubscribe",
                    "subscriptionID": "subscription_0001",
                }
            )
        )
        for _ in range(20):
            if hub.subscription_count == 0:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(hub.subscription_count, 0)
        await socket.close()

    async def test_slow_snapshot_does_not_block_command_receipt(self) -> None:
        from loopdy_plugin.direct_server import DirectServer, DirectSessionView

        hub = SessionStreamHub()
        release = asyncio.Event()

        async def open_session(_context, agent_id, session_id):
            subscription = hub.subscribe(agent_id=agent_id, session_id=session_id)
            try:
                await release.wait()
                return DirectSessionView({}, subscription, hub.process_epoch, 0)
            except BaseException:
                subscription.close()
                raise

        async def dispatch(_context, _payload):
            return {"accepted": True}

        server = DirectServer(
            self.authority, self.journal, dispatch, open_session=open_session
        )
        self.servers.append(server)
        await server.start()
        socket, _ = await self._connect(server)
        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "session.subscribe",
                    "subscriptionID": "subscription_wait",
                    "agentId": "agent_1",
                    "sessionId": "session_1",
                }
            )
        )
        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "direct.command",
                    "commandID": "command_during_wait",
                    "issuedAt": int(time.time()),
                    "payload": {},
                }
            )
        )
        receipt = json.loads(await asyncio.wait_for(socket.recv(), 1))
        self.assertEqual(receipt["type"], "direct.receipt")
        release.set()
        snapshot = json.loads(await socket.recv())
        self.assertEqual(snapshot["type"], "session.snapshot")
        await socket.close()

    async def test_overflow_resets_only_the_affected_subscription(self) -> None:
        from loopdy_plugin.direct_server import DirectServer, DirectSessionView

        overflow_hub = SessionStreamHub(maximum_events=1)
        healthy_hub = SessionStreamHub(maximum_events=4)

        async def open_session(_context, agent_id, session_id):
            hub = overflow_hub if session_id == "slow" else healthy_hub
            subscription = hub.subscribe(agent_id=agent_id, session_id=session_id)
            if session_id == "slow":
                for text in ("one", "two"):
                    hub.publish(
                        agent_id=agent_id,
                        session_id=session_id,
                        payload={"type": "assistant.message", "text": text},
                    )
            return DirectSessionView({}, subscription, hub.process_epoch, 0)

        async def dispatch(_context, _payload):
            return {"accepted": True}

        server = DirectServer(
            self.authority, self.journal, dispatch, open_session=open_session
        )
        self.servers.append(server)
        await server.start()
        socket, _ = await self._connect(server)
        for subscription_id, session_id in (
            ("subscription_slow", "slow"),
            ("subscription_healthy", "healthy"),
        ):
            await socket.send(
                json.dumps(
                    {
                        "version": 1,
                        "type": "session.subscribe",
                        "subscriptionID": subscription_id,
                        "agentId": "agent_1",
                        "sessionId": session_id,
                    }
                )
            )
        received = [json.loads(await socket.recv()) for _ in range(3)]
        self.assertIn("session.reset", {item["type"] for item in received})
        healthy_hub.publish(
            agent_id="agent_1",
            session_id="healthy",
            payload={"type": "assistant.message", "text": "still-live"},
        )
        healthy = json.loads(await socket.recv())
        self.assertEqual(healthy["type"], "session.event")
        self.assertEqual(healthy["subscriptionID"], "subscription_healthy")
        await socket.close()

    async def test_disconnect_cancels_session_setup_and_closes_created_feed(self) -> None:
        from loopdy_plugin.direct_server import DirectServer

        hub = SessionStreamHub()
        subscribed = asyncio.Event()
        cancelled = asyncio.Event()

        async def open_session(_context, agent_id, session_id):
            subscription = hub.subscribe(agent_id=agent_id, session_id=session_id)
            subscribed.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                subscription.close()
                cancelled.set()
                raise

        async def dispatch(_context, _payload):
            return {"accepted": True}

        server = DirectServer(
            self.authority, self.journal, dispatch, open_session=open_session
        )
        self.servers.append(server)
        await server.start()
        socket, _ = await self._connect(server)
        await socket.send(
            json.dumps(
                {
                    "version": 1,
                    "type": "session.subscribe",
                    "subscriptionID": "subscription_cancel",
                    "agentId": "agent_1",
                    "sessionId": "session_1",
                }
            )
        )
        await asyncio.wait_for(subscribed.wait(), 1)
        await socket.close()
        await asyncio.wait_for(cancelled.wait(), 1)
        self.assertEqual(hub.subscription_count, 0)

    async def test_replacement_does_not_wait_for_or_leak_stale_snapshot(self) -> None:
        from loopdy_plugin.direct_server import DirectServer, DirectSessionView

        stale_hub = SessionStreamHub()
        replacement_hub = SessionStreamHub()
        stale_started = asyncio.Event()
        release_stale = asyncio.Event()
        calls = 0

        async def open_session(_context, agent_id, session_id):
            nonlocal calls
            calls += 1
            if calls == 1:
                subscription = stale_hub.subscribe(
                    agent_id=agent_id, session_id=session_id
                )
                stale_started.set()
                try:
                    await asyncio.Future()
                except asyncio.CancelledError:
                    await release_stale.wait()
                    subscription.close()
                    return DirectSessionView(
                        {"source": "stale"},
                        subscription,
                        stale_hub.process_epoch,
                        0,
                    )
            subscription = replacement_hub.subscribe(
                agent_id=agent_id, session_id=session_id
            )
            return DirectSessionView(
                {"source": "replacement"},
                subscription,
                replacement_hub.process_epoch,
                0,
            )

        async def dispatch(_context, _payload):
            return {"accepted": True}

        server = DirectServer(
            self.authority, self.journal, dispatch, open_session=open_session
        )
        self.servers.append(server)
        await server.start()
        socket, _ = await self._connect(server)
        subscribe = {
            "version": 1,
            "type": "session.subscribe",
            "subscriptionID": "subscription_replace",
            "agentId": "agent_1",
            "sessionId": "session_1",
        }
        await socket.send(json.dumps(subscribe))
        await asyncio.wait_for(stale_started.wait(), 1)
        await socket.send(json.dumps(subscribe))
        asyncio.get_running_loop().call_later(0.5, release_stale.set)

        snapshot = json.loads(await asyncio.wait_for(socket.recv(), 0.25))
        self.assertEqual(snapshot["payload"], {"source": "replacement"})
        release_stale.set()
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(socket.recv(), 0.1)
        self.assertEqual(replacement_hub.subscription_count, 1)
        await socket.close()

    async def test_route_origin_and_malformed_inputs_are_rejected(self) -> None:
        from loopdy_plugin.direct_server import DirectServer

        async def dispatch(_context, _payload):
            return {"accepted": True}

        server = DirectServer(self.authority, self.journal, dispatch)
        self.servers.append(server)
        await server.start()
        for path, origin in (
            ("/wrong", None),
            ("/loopdy/direct/v1?query=1", None),
            ("/loopdy/direct/v1", "https://browser.example"),
        ):
            with self.subTest(path=path, origin=origin), self.assertRaises(InvalidStatus):
                await websockets.connect(
                    f"ws://127.0.0.1:{server.port}{path}",
                    origin=origin,
                    compression=None,
                )

        deeply_nested: object = 0
        for _ in range(25):
            deeply_nested = [deeply_nested]
        malformed_cases = (
            b"binary",
            json.dumps(
                {
                    "version": 1,
                    "type": "direct.hello",
                    "deviceId": "phone_1",
                    "authorizationEpoch": 11,
                    "clientNonce": encode_base64url(bytes(range(32))),
                    "extra": True,
                }
            ),
            "[1]",
            json.dumps({"version": 1, "type": "unknown", "nested": deeply_nested}),
            '{"version":1,"type":"direct.hello","type":"direct.hello"}',
            '{"version":1,"type":"direct.hello","authorizationEpoch":NaN}',
        )
        for value in malformed_cases:
            socket = await websockets.connect(
                f"ws://127.0.0.1:{server.port}/loopdy/direct/v1", compression=None
            )
            await socket.send(value)
            with self.assertRaises(ConnectionClosed):
                await socket.recv()

        oversized = await websockets.connect(
            f"ws://127.0.0.1:{server.port}/loopdy/direct/v1",
            compression=None,
            max_size=None,
        )
        await oversized.send("x" * (512 * 1024 + 1))
        with self.assertRaises(ConnectionClosed):
            await oversized.recv()


if __name__ == "__main__":
    unittest.main()
