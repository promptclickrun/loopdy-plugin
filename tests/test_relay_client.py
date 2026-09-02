from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from loopdy_plugin.provider import LiveActivityState, PushMessage
from loopdy_plugin.relay_crypto import (
    alert_aad,
    alert_signature_input,
    b64url_decode,
    b64url_encode,
    request_signing_input,
    verify_p1363,
)
from loopdy_plugin.relay_client import (
    RelayClient,
    RelayConfig,
    RelayHttpResponse,
    RelayOutcomeUnknown,
    delivery_coordinates,
    live_activity_delivery_coordinates,
    resolve_secret_reference,
)


FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "contracts"
    / "relay-v1-vector.json"
)
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def private_pem(scalar: int) -> bytes:
    return ec.derive_private_key(scalar, ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def signing_keyring_secret() -> bytes:
    return json.dumps(
        {
            "version": 1,
            "revision": 1,
            "current": {
                "pem": private_pem(4).decode("ascii"),
                "not_before": FIXTURE["issued"] - 300,
                "not_after": FIXTURE["issued"] + 2_678_100,
            },
            "previous": None,
        },
        separators=(",", ":"),
    ).encode("utf-8")


class _Transport:
    def __init__(self, outcomes=None):
        self.outcomes = list(outcomes or [])
        self.requests = []

    def request(self, *, method, url, headers, body, timeout, follow_redirects):
        self.requests.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": bytes(body),
                "timeout": timeout,
                "follow_redirects": follow_redirects,
            }
        )
        if self.outcomes:
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        if url.endswith("/v1/devices/register"):
            registration = json.loads(body)
            response = {
                "version": 1,
                "status": "accepted",
                "tenant_id": FIXTURE["tenant_id"],
                "device_id": registration["device_id"],
                "recipient_key_id": registration["recipient_key_id"],
                "revision": registration["revision"],
                "lease_expires": registration["lease_expires"],
                "sender_key_revision": 1,
                "current_sender_key": {
                    "key_id": FIXTURE["sender"]["key_id"],
                    "public_key": FIXTURE["sender"]["public_key_b64url"],
                    "state": "current",
                    "not_before": FIXTURE["issued"] - 300,
                    "not_after": FIXTURE["issued"] + 2_678_100,
                },
                "previous_sender_key": None,
            }
            return RelayHttpResponse(202, json.dumps(response, separators=(",", ":")).encode())
        request = json.loads(body) if body else {}
        if url.endswith("/v1/deliveries"):
            response_id = request.get("envelope", {}).get("delivery_id", FIXTURE["delivery_id"])
            response_revision = 1
        elif "/v1/devices/" in url:
            response_id = request["device_id"]
            response_revision = request["revision"]
        elif "/v1/tenants/" in url:
            response_id = request["tenant_id"]
            response_revision = request["revision"]
        elif "/v1/live-activities/" in url:
            response_id = request["activity_id"]
            response_revision = request["revision"]
        else:
            response_id = FIXTURE["delivery_id"]
            response_revision = 1
        response = {
            "id": response_id,
            "revision": response_revision,
            "status": (
                "deleted" if url.endswith("/v1/tenants/delete")
                else "revoked" if url.endswith("/revoke")
                else "accepted"
            ),
            "version": 1,
        }
        return RelayHttpResponse(202, json.dumps(response, separators=(",", ":")).encode())


class RelayClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = RelayConfig(
            base_url="https://relay.example.invalid",
            tenant_id=FIXTURE["tenant_id"],
            credential_key_id=FIXTURE["credential_key_id"],
            hmac_secret_reference="env:LOOPDY_RELAY_HMAC",
            signing_key_secret_reference="file:/private/loopdy-signing-key.pem",
        )
        secrets = {
            self.config.hmac_secret_reference: bytes.fromhex(FIXTURE["hmac_key_hex"]),
            self.config.signing_key_secret_reference: signing_keyring_secret(),
        }
        self.secret_resolver = secrets.__getitem__

    def client(self, transport, request_nonces=None) -> RelayClient:
        nonces = list(request_nonces or [bytes.fromhex(FIXTURE["request_nonce_hex"])])

        def random_bytes(count: int) -> bytes:
            if nonces and len(nonces[0]) == count:
                return nonces.pop(0)
            return bytes(index % 256 for index in range(count))

        return RelayClient(
            self.config,
            transport=transport,
            secret_resolver=self.secret_resolver,
            now=lambda: FIXTURE["issued"],
            random_bytes=random_bytes,
        )

    def test_delivers_ciphertext_only_alert_with_exact_authenticated_request(self) -> None:
        transport = _Transport()
        result = self.client(transport).deliver_alert(
            device={
                "device_id": FIXTURE["device_id"],
                "recipient_public_key": FIXTURE["recipient"]["public_key_b64url"],
                "recipient_key_id": FIXTURE["recipient"]["key_id"],
                "revision": 1,
                "acknowledged_sender_key_ids": [FIXTURE["sender"]["key_id"]],
            },
            message=PushMessage(
                event_id=FIXTURE["event_id"],
                event_type=FIXTURE["event_type"],
                title=FIXTURE["title"],
                body=FIXTURE["body"],
                data={"loopdy": {"detail": "must never be serialized"}},
                sound=True,
            ),
            delivery_id=FIXTURE["delivery_id"],
            idempotency_key=FIXTURE["idempotency_key"],
            ephemeral_private_key=ec.derive_private_key(3, ec.SECP256R1()),
            salt=bytes.fromhex(FIXTURE["salt_hex"]),
            nonce=bytes.fromhex(FIXTURE["nonce_hex"]),
        )
        self.assertEqual(result.delivery_id, FIXTURE["delivery_id"])
        request = transport.requests[0]
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["url"], "https://relay.example.invalid/v1/deliveries")
        self.assertFalse(request["follow_redirects"])
        self.assertLessEqual(request["timeout"], 10)
        actual = json.loads(request["body"])
        expected = json.loads(FIXTURE["canonical_delivery_body"])
        signature = actual["envelope"].pop("signature")
        expected["envelope"].pop("signature")
        self.assertEqual(actual, expected)
        envelope = json.loads(request["body"])["envelope"]
        aad = alert_aad(
            tenant_id=FIXTURE["tenant_id"],
            device_id=FIXTURE["device_id"],
            delivery_id=FIXTURE["delivery_id"],
            event_ref=envelope["event_ref"],
            recipient_key_id=envelope["recipient_key_id"],
            sender_key_id=envelope["sender_key_id"],
            issued=envelope["issued"],
            expires=envelope["expires"],
        )
        verify_p1363(
            ec.derive_private_key(4, ec.SECP256R1()).public_key(),
            b64url_decode(signature),
            alert_signature_input(
                aad=aad,
                ephemeral_public_key=b64url_decode(envelope["ephemeral_public_key"]),
                salt=b64url_decode(envelope["salt"]),
                nonce=b64url_decode(envelope["nonce"]),
                ciphertext=b64url_decode(envelope["ciphertext"]),
                tag=b64url_decode(envelope["tag"]),
            ),
        )
        signed_request = request_signing_input(
            method="POST",
            path="/v1/deliveries",
            tenant_id=FIXTURE["tenant_id"],
            credential_key_id=FIXTURE["credential_key_id"],
            timestamp=FIXTURE["issued"],
            nonce=FIXTURE["request_nonce_b64url"],
            body=request["body"],
        )
        expected_hmac = b64url_encode(
            hmac.new(bytes.fromhex(FIXTURE["hmac_key_hex"]), signed_request, hashlib.sha256).digest()
        )
        self.assertEqual(request["headers"]["x-loopdy-signature"], expected_hmac)
        serialized = request["body"].decode()
        self.assertNotIn(FIXTURE["event_id"], serialized)
        self.assertNotIn(FIXTURE["event_type"], serialized)
        self.assertNotIn(FIXTURE["title"], serialized)
        self.assertNotIn(FIXTURE["body"], serialized)
        self.assertNotIn("must never be serialized", serialized)

    def test_unknown_outcome_retries_identical_body_and_idempotency_with_fresh_hmac_nonce(self) -> None:
        device = {
            "device_id": FIXTURE["device_id"],
            "recipient_public_key": FIXTURE["recipient"]["public_key_b64url"],
            "recipient_key_id": FIXTURE["recipient"]["key_id"],
            "revision": 1,
            "acknowledged_sender_key_ids": [FIXTURE["sender"]["key_id"]],
        }
        message = PushMessage(
            FIXTURE["event_id"], FIXTURE["event_type"], FIXTURE["title"], FIXTURE["body"], {}, True
        )
        transport = _Transport(
            [
                RelayOutcomeUnknown("transport_error"),
                RelayHttpResponse(
                    202,
                    b'{"id":"delivery_fixture_0001","revision":1,"status":"duplicate","version":1}',
                ),
            ]
        )
        result = self.client(
            transport,
            [bytes.fromhex(FIXTURE["request_nonce_hex"]), bytes(range(16))],
        ).deliver_alert(
            device={
                "device_id": FIXTURE["device_id"],
                "recipient_public_key": FIXTURE["recipient"]["public_key_b64url"],
                "recipient_key_id": FIXTURE["recipient"]["key_id"],
                "revision": 1,
                "acknowledged_sender_key_ids": [FIXTURE["sender"]["key_id"]],
            },
            message=PushMessage(
                FIXTURE["event_id"],
                FIXTURE["event_type"],
                FIXTURE["title"],
                FIXTURE["body"],
                {},
                True,
            ),
            delivery_id=FIXTURE["delivery_id"],
            idempotency_key=FIXTURE["idempotency_key"],
            ephemeral_private_key=ec.derive_private_key(3, ec.SECP256R1()),
            salt=bytes.fromhex(FIXTURE["salt_hex"]),
            nonce=bytes.fromhex(FIXTURE["nonce_hex"]),
        )
        self.assertEqual(result.delivery_id, FIXTURE["delivery_id"])
        self.assertEqual(transport.requests[0]["body"], transport.requests[1]["body"])

        for status_code in (501, 599):
            retry_transport = _Transport(
                [
                    RelayHttpResponse(status_code, b'{"status":"temporarily_unavailable"}'),
                    RelayHttpResponse(
                        202,
                        b'{"id":"delivery_fixture_0001","revision":1,"status":"accepted","version":1}',
                    ),
                ]
            )
            self.client(retry_transport).deliver_alert(
                device=device,
                message=message,
                delivery_id=FIXTURE["delivery_id"],
                idempotency_key=FIXTURE["idempotency_key"],
                ephemeral_private_key=ec.derive_private_key(3, ec.SECP256R1()),
                salt=bytes.fromhex(FIXTURE["salt_hex"]),
                nonce=bytes.fromhex(FIXTURE["nonce_hex"]),
            )
            self.assertEqual(retry_transport.requests[0]["body"], retry_transport.requests[1]["body"])
        self.assertNotEqual(
            transport.requests[0]["headers"]["x-loopdy-nonce"],
            transport.requests[1]["headers"]["x-loopdy-nonce"],
        )

        with self.assertRaises(RelayOutcomeUnknown):
            self.client(
                _Transport([httpx.RemoteProtocolError("connection reset")]),
            ).health()

        server_error = _Transport(
            [
                RelayHttpResponse(503, b'{"status":"temporarily_unavailable"}'),
                RelayHttpResponse(
                    202,
                    b'{"id":"delivery_fixture_0001","revision":1,"status":"duplicate","version":1}',
                ),
            ]
        )
        self.client(server_error).deliver_alert(
            device={
                "device_id": FIXTURE["device_id"],
                "recipient_public_key": FIXTURE["recipient"]["public_key_b64url"],
                "recipient_key_id": FIXTURE["recipient"]["key_id"],
                "revision": 1,
                "acknowledged_sender_key_ids": [FIXTURE["sender"]["key_id"]],
            },
            message=PushMessage(
                FIXTURE["event_id"], FIXTURE["event_type"], FIXTURE["title"], FIXTURE["body"], {}, True
            ),
            delivery_id=FIXTURE["delivery_id"],
            idempotency_key=FIXTURE["idempotency_key"],
            ephemeral_private_key=ec.derive_private_key(3, ec.SECP256R1()),
            salt=bytes.fromhex(FIXTURE["salt_hex"]),
            nonce=bytes.fromhex(FIXTURE["nonce_hex"]),
        )
        self.assertEqual(server_error.requests[0]["body"], server_error.requests[1]["body"])

    def test_httpx_remote_protocol_error_is_unknown_and_retried_with_fresh_nonce(self) -> None:
        transport = _Transport(
            [
                __import__("httpx").RemoteProtocolError("connection ended before headers"),
                RelayHttpResponse(
                    202,
                    b'{"id":"delivery_fixture_0001","revision":1,"status":"accepted","version":1}',
                ),
            ]
        )
        self.client(
            transport,
            [bytes.fromhex(FIXTURE["request_nonce_hex"]), bytes(range(16))],
        ).deliver_alert(
            device={
                "device_id": FIXTURE["device_id"],
                "recipient_public_key": FIXTURE["recipient"]["public_key_b64url"],
                "recipient_key_id": FIXTURE["recipient"]["key_id"],
                "revision": 1,
                "acknowledged_sender_key_ids": [FIXTURE["sender"]["key_id"]],
            },
            message=PushMessage(
                FIXTURE["event_id"], FIXTURE["event_type"], FIXTURE["title"], FIXTURE["body"], {}, True
            ),
            delivery_id=FIXTURE["delivery_id"],
            idempotency_key=FIXTURE["idempotency_key"],
            ephemeral_private_key=ec.derive_private_key(3, ec.SECP256R1()),
            salt=bytes.fromhex(FIXTURE["salt_hex"]),
            nonce=bytes.fromhex(FIXTURE["nonce_hex"]),
        )
        self.assertEqual(len(transport.requests), 2)
        self.assertEqual(transport.requests[0]["body"], transport.requests[1]["body"])
        self.assertNotEqual(
            transport.requests[0]["headers"]["x-loopdy-nonce"],
            transport.requests[1]["headers"]["x-loopdy-nonce"],
        )

    def test_frozen_alert_body_is_reused_without_reencryption(self) -> None:
        transport = _Transport(
            [
                RelayOutcomeUnknown("before_acceptance"),
                RelayHttpResponse(
                    202,
                    b'{"id":"delivery_fixture_0001","revision":1,"status":"accepted","version":1}',
                ),
            ]
        )
        client = self.client(transport, [bytes.fromhex(FIXTURE["request_nonce_hex"]), bytes(range(16))])
        device = {
            "device_id": FIXTURE["device_id"],
            "recipient_public_key": FIXTURE["recipient"]["public_key_b64url"],
            "recipient_key_id": FIXTURE["recipient"]["key_id"],
            "revision": 1,
            "acknowledged_sender_key_ids": [FIXTURE["sender"]["key_id"]],
        }
        message = PushMessage(
            FIXTURE["event_id"], FIXTURE["event_type"], FIXTURE["title"], FIXTURE["body"], {}, True
        )
        frozen = client.prepare_alert(
            device=device,
            message=message,
            delivery_id=FIXTURE["delivery_id"],
            idempotency_key=FIXTURE["idempotency_key"],
            ephemeral_private_key=ec.derive_private_key(3, ec.SECP256R1()),
            salt=bytes.fromhex(FIXTURE["salt_hex"]),
            nonce=bytes.fromhex(FIXTURE["nonce_hex"]),
        )
        client.deliver_alert(
            device=device,
            message=message,
            delivery_id=FIXTURE["delivery_id"],
            idempotency_key=FIXTURE["idempotency_key"],
            request_body=frozen,
        )
        self.assertEqual(transport.requests[0]["body"], transport.requests[1]["body"])

        tampered = json.loads(json.dumps(frozen))
        tampered["envelope"]["delivery_id"] = "different-delivery"
        with self.assertRaisesRegex(ValueError, "Frozen alert"):
            client.deliver_alert(
                device=device,
                message=message,
                delivery_id=FIXTURE["delivery_id"],
                idempotency_key=FIXTURE["idempotency_key"],
                request_body=tampered,
            )

        with self.assertRaisesRegex(ValueError, "Frozen alert"):
            client.deliver_alert(
                device=device,
                message=message,
                delivery_id=FIXTURE["delivery_id"],
                idempotency_key=FIXTURE["idempotency_key"],
                request_body={},
            )

    def test_response_status_is_bound_to_each_operation(self) -> None:
        operations = (
            ("delivery", lambda client: client.deliver_alert(
                device={
                    "device_id": FIXTURE["device_id"],
                    "recipient_public_key": FIXTURE["recipient"]["public_key_b64url"],
                    "recipient_key_id": FIXTURE["recipient"]["key_id"],
                    "revision": 1,
                    "acknowledged_sender_key_ids": [FIXTURE["sender"]["key_id"]],
                },
                message=PushMessage(
                    FIXTURE["event_id"], FIXTURE["event_type"], FIXTURE["title"], FIXTURE["body"], {}, True
                ),
                delivery_id=FIXTURE["delivery_id"],
                idempotency_key=FIXTURE["idempotency_key"],
                ephemeral_private_key=ec.derive_private_key(3, ec.SECP256R1()),
                salt=bytes.fromhex(FIXTURE["salt_hex"]),
                nonce=bytes.fromhex(FIXTURE["nonce_hex"]),
            ), {"accepted", "duplicate"}),
            ("revoke", lambda client: client.revoke_device({
                "version": 1, "device_id": FIXTURE["device_id"], "revision": 8,
                "idempotency_key": FIXTURE["idempotency_key"],
            }), {"revoked", "duplicate"}),
            ("delete", lambda client: client.delete_tenant({
                "version": 1, "tenant_id": FIXTURE["tenant_id"], "revision": 8,
                "confirmation": "delete", "idempotency_key": FIXTURE["idempotency_key"],
            }), {"deleted", "duplicate"}),
        )
        for name, operation, allowed in operations:
            with self.subTest(name=name):
                response = {"id": FIXTURE["delivery_id"] if name == "delivery" else (FIXTURE["device_id"] if name == "revoke" else FIXTURE["tenant_id"]), "revision": 8 if name != "delivery" else 1, "status": "revoked" if name == "delivery" else "accepted", "version": 1}
                transport = _Transport([RelayHttpResponse(202, json.dumps(response).encode())])
                with self.assertRaisesRegex(ValueError, "status"):
                    operation(self.client(transport))

    def test_rejects_alert_and_revisioned_responses_with_mismatched_coordinates(self) -> None:
        wrong_alert = _Transport(
            [
                RelayHttpResponse(
                    202,
                    b'{"id":"wrong_delivery","revision":2,"status":"accepted","version":1}',
                )
            ]
        )
        with self.assertRaisesRegex(ValueError, "coordinates"):
            self.client(wrong_alert).deliver_alert(
                device={
                    "device_id": FIXTURE["device_id"],
                    "recipient_public_key": FIXTURE["recipient"]["public_key_b64url"],
                    "recipient_key_id": FIXTURE["recipient"]["key_id"],
                    "revision": 1,
                    "acknowledged_sender_key_ids": [FIXTURE["sender"]["key_id"]],
                },
                message=PushMessage(
                    FIXTURE["event_id"],
                    FIXTURE["event_type"],
                    FIXTURE["title"],
                    FIXTURE["body"],
                    {},
                    True,
                ),
                delivery_id=FIXTURE["delivery_id"],
                idempotency_key=FIXTURE["idempotency_key"],
            )

        wrong_revoke = _Transport(
            [
                RelayHttpResponse(
                    202,
                    b'{"id":"another_device","revision":8,"status":"revoked","version":1}',
                )
            ]
        )
        with self.assertRaisesRegex(ValueError, "coordinates"):
            self.client(wrong_revoke).revoke_device(
                {
                    "version": 1,
                    "device_id": FIXTURE["device_id"],
                    "revision": 8,
                    "idempotency_key": FIXTURE["idempotency_key"],
                }
            )

        common = {"version": 1, "idempotency_key": FIXTURE["idempotency_key"]}
        activity = FIXTURE["live_activity"]["activity_id"]
        operations = (
            lambda client: client.acknowledge_sender_keys(
                {
                    **common,
                    "device_id": FIXTURE["device_id"],
                    "revision": 2,
                    "sender_key_revision": 1,
                    "acknowledged_sender_key_ids": [FIXTURE["sender"]["key_id"]],
                }
            ),
            lambda client: client.revoke_tenant(
                {**common, "tenant_id": FIXTURE["tenant_id"], "revision": 3}
            ),
            lambda client: client.delete_tenant(
                {
                    **common,
                    "tenant_id": FIXTURE["tenant_id"],
                    "revision": 4,
                    "confirmation": "delete",
                }
            ),
            lambda client: client.register_live_activity(
                {
                    **common,
                    "activity_id": activity,
                    "device_id": FIXTURE["device_id"],
                    "session_ref": FIXTURE["live_activity"]["session_ref"],
                    "push_token": "bb",
                    "environment": "production",
                    "topic": "com.example.loopdy",
                    "revision": 5,
                    "timestamp": FIXTURE["live_activity"]["timestamp"],
                    "lease_expires": FIXTURE["live_activity"]["timestamp"] + 28_800,
                }
            ),
            lambda client: client.revoke_live_activity(
                {
                    **common,
                    "activity_id": activity,
                    "revision": 6,
                    "timestamp": FIXTURE["live_activity"]["timestamp"] + 1,
                }
            ),
        )
        for operation in operations:
            with self.subTest(operation=operation):
                transport = _Transport(
                    [
                        RelayHttpResponse(
                            202,
                            b'{"id":"wrong_coordinate","revision":99,"status":"accepted","version":1}',
                        )
                    ]
                )
                with self.assertRaisesRegex(ValueError, "coordinates"):
                    operation(self.client(transport))

    def test_relay_delivery_preserves_silent_preference_without_changing_default_fixture(self) -> None:
        transport = _Transport()
        self.client(transport).deliver_alert(
            device={
                "device_id": FIXTURE["device_id"],
                "recipient_public_key": FIXTURE["recipient"]["public_key_b64url"],
                "recipient_key_id": FIXTURE["recipient"]["key_id"],
                "revision": 1,
                "acknowledged_sender_key_ids": [FIXTURE["sender"]["key_id"]],
            },
            message=PushMessage(
                FIXTURE["event_id"], FIXTURE["event_type"], FIXTURE["title"], FIXTURE["body"], {}, False
            ),
            delivery_id=FIXTURE["delivery_id"],
            idempotency_key=FIXTURE["idempotency_key"],
        )
        self.assertIs(json.loads(transport.requests[0]["body"])["sound"], False)

    def test_posts_strict_device_tenant_and_live_activity_operations(self) -> None:
        transport = _Transport()
        client = self.client(transport, [bytes([index]) * 16 for index in range(8)])
        common = {"version": 1, "idempotency_key": FIXTURE["idempotency_key"]}
        client.register_device(
            {
                **common,
                "device_id": FIXTURE["device_id"],
                "revision": 1,
                "issued": FIXTURE["issued"],
                "lease_expires": FIXTURE["issued"] + 2_592_000,
                "provider": "relay",
                "recipient_public_key": FIXTURE["recipient"]["public_key_b64url"],
                "recipient_key_id": FIXTURE["recipient"]["key_id"],
                "push_token": "a" * 64,
                "environment": "production",
                "topic": "com.example.loopdy",
                "label": "Phone",
                "groups": [],
            }
        )
        client.acknowledge_sender_keys(
            {
                **common,
                "device_id": FIXTURE["device_id"],
                "revision": 2,
                "sender_key_revision": 1,
                "acknowledged_sender_key_ids": [FIXTURE["sender"]["key_id"]],
            }
        )
        client.revoke_device({**common, "device_id": FIXTURE["device_id"], "revision": 2})
        client.revoke_tenant({**common, "tenant_id": FIXTURE["tenant_id"], "revision": 3})
        client.delete_tenant(
            {
                **common,
                "tenant_id": FIXTURE["tenant_id"],
                "revision": 4,
                "confirmation": "delete",
            }
        )
        client.register_live_activity(
            {
                **common,
                "activity_id": FIXTURE["live_activity"]["activity_id"],
                "device_id": FIXTURE["device_id"],
                "session_ref": FIXTURE["live_activity"]["session_ref"],
                "push_token": "b" * 64,
                "environment": "production",
                "topic": "com.example.loopdy",
                "revision": 1,
                "timestamp": FIXTURE["live_activity"]["timestamp"],
                "lease_expires": FIXTURE["live_activity"]["timestamp"] + 28_800,
            }
        )
        client.revoke_live_activity(
            {
                **common,
                "activity_id": FIXTURE["live_activity"]["activity_id"],
                "revision": 2,
                "timestamp": FIXTURE["live_activity"]["timestamp"] + 1,
            }
        )

        with self.assertRaisesRegex(ValueError, "bundle topic"):
            client.register_live_activity(
                {
                    **common,
                    "activity_id": FIXTURE["live_activity"]["activity_id"],
                    "device_id": FIXTURE["device_id"],
                    "session_ref": FIXTURE["live_activity"]["session_ref"],
                    "push_token": "b" * 64,
                    "environment": "production",
                    "topic": "com.example.loopdy.push-type.liveactivity",
                    "revision": 1,
                    "timestamp": FIXTURE["live_activity"]["timestamp"],
                    "lease_expires": FIXTURE["live_activity"]["timestamp"] + 28_800,
                }
            )
        self.assertEqual(
            [request["url"].removeprefix(self.config.base_url) for request in transport.requests],
            [
                "/v1/devices/register",
                "/v1/devices/ack-sender-keys",
                "/v1/devices/revoke",
                "/v1/tenants/revoke",
                "/v1/tenants/delete",
                "/v1/live-activities/register",
                "/v1/live-activities/revoke",
            ],
        )
        for request in transport.requests:
            self.assertEqual(request["headers"]["x-loopdy-tenant-id"], FIXTURE["tenant_id"])
            self.assertNotIn(bytes.fromhex(FIXTURE["hmac_key_hex"]), request["body"])
            self.assertNotIn(b"PRIVATE KEY", request["body"])

    def test_sends_sanitized_live_activity_with_deterministic_bound_coordinates(self) -> None:
        state = LiveActivityState(**FIXTURE["live_activity"])
        delivery_id, idempotency_key = live_activity_delivery_coordinates(
            state,
            FIXTURE["device_id"],
            7,
        )
        response = {
            "version": 1,
            "status": "accepted",
            "id": delivery_id,
            "revision": 7,
        }
        transport = _Transport(
            [RelayHttpResponse(202, json.dumps(response, separators=(",", ":")).encode())]
        )

        receipt = self.client(transport).send_live_activity(
            device_id=FIXTURE["device_id"],
            state=state,
            delivery_id=delivery_id,
            target_revision=7,
            idempotency_key=idempotency_key,
        )

        self.assertEqual(receipt.delivery_id, delivery_id)
        request = transport.requests[0]
        self.assertTrue(request["url"].endswith("/v1/deliveries"))
        self.assertEqual(
            json.loads(request["body"]),
            {
                "device_id": FIXTURE["device_id"],
                "delivery_id": delivery_id,
                "state": FIXTURE["live_activity"],
                "idempotency_key": idempotency_key,
            },
        )
        serialized = request["body"].decode()
        for forbidden in ("detail", "tool", "title", "profile", "transcript"):
            self.assertNotIn(forbidden, serialized)

        mismatch = self.client(
            _Transport(
                [
                    RelayHttpResponse(
                        202,
                        b'{"id":"wrong_delivery","revision":7,"status":"accepted","version":1}',
                    )
                ]
            )
        )
        with self.assertRaisesRegex(ValueError, "does not match"):
            mismatch.send_live_activity(
                device_id=FIXTURE["device_id"],
                state=state,
                delivery_id=delivery_id,
                target_revision=7,
                idempotency_key=idempotency_key,
            )

    def test_delivery_coordinates_reject_noncanonical_ids_and_revisions(self) -> None:
        for event_id in (True, "event\nunsafe", "évent"):
            with self.subTest(event_id=event_id):
                with self.assertRaisesRegex(ValueError, "event_id"):
                    delivery_coordinates(event_id, FIXTURE["device_id"], 1)
        for revision in (True, 1.5, 0, 9_007_199_254_740_992):
            with self.subTest(revision=revision):
                with self.assertRaisesRegex(ValueError, "revision"):
                    delivery_coordinates(FIXTURE["event_id"], FIXTURE["device_id"], revision)

    def test_health_is_authenticated_and_rejects_oversized_or_secret_bearing_errors(self) -> None:
        transport = _Transport(
            [RelayHttpResponse(200, b'{"status":"ok","version":1}')]
        )
        self.assertEqual(self.client(transport).health(), {"status": "ok", "version": 1})
        request = transport.requests[0]
        self.assertEqual(request["url"], "https://relay.example.invalid/health")
        self.assertIn("x-loopdy-signature", request["headers"])

        oversized = _Transport([RelayHttpResponse(500, b"x" * 65_537)])
        with self.assertRaisesRegex(ValueError, "response"):
            self.client(oversized).health()

    def test_config_rejects_non_https_credentials_queries_fragments_and_long_urls(self) -> None:
        bad_urls = (
            "http://relay.example.invalid",
            "https://user@relay.example.invalid",
            "https://relay.example.invalid/path?token=fake",
            "https://relay.example.invalid/#fragment",
            "https://" + "a" * 500 + ".invalid",
        )
        for base_url in bad_urls:
            with self.subTest(base_url=base_url), self.assertRaises(ValueError):
                RelayConfig(
                    base_url=base_url,
                    tenant_id=FIXTURE["tenant_id"],
                    credential_key_id=FIXTURE["credential_key_id"],
                    hmac_secret_reference="env:LOOPDY_RELAY_HMAC",
                    signing_key_secret_reference="env:LOOPDY_RELAY_SIGNING_KEY",
                )

    def test_registration_accepts_opaque_lowercase_even_hex_tokens_only(self) -> None:
        base = {
            "version": 1,
            "device_id": FIXTURE["device_id"],
            "revision": 1,
            "issued": FIXTURE["issued"],
            "lease_expires": FIXTURE["issued"] + 2_592_000,
            "provider": "relay",
            "recipient_public_key": FIXTURE["recipient"]["public_key_b64url"],
            "recipient_key_id": FIXTURE["recipient"]["key_id"],
            "push_token": "0a",
            "environment": "production",
            "topic": "com.example.loopdy",
            "label": "Café",
            "groups": [],
            "idempotency_key": FIXTURE["idempotency_key"],
        }
        transport = _Transport()
        self.client(transport).register_device(base)
        self.assertIn(b'"label":"Caf\xc3\xa9"', transport.requests[0]["body"])
        for push_token in ("", "a", "AA", "aa" * 257):
            with self.subTest(push_token=push_token), self.assertRaises(ValueError):
                self.client(_Transport()).register_device({**base, "push_token": push_token})
        for change in (
            {"version": True},
            {"device_id": 123},
            {"label": "Cafe\u0301"},
            {"label": "é" * 61},
            {"groups": ["bad group"]},
            {"groups": [f"group_{index}" for index in range(51)]},
            {"revision": True},
            {"revision": 1.5},
            {"revision": 9_007_199_254_740_992},
            {"issued": False},
            {"issued": 1.5},
            {"lease_expires": True},
            {"lease_expires": 1.5},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.client(_Transport()).register_device({**base, **change})

        live = {
            "version": 1,
            "activity_id": FIXTURE["live_activity"]["activity_id"],
            "device_id": FIXTURE["device_id"],
            "session_ref": FIXTURE["live_activity"]["session_ref"],
            "push_token": "bb",
            "environment": "production",
            "topic": "com.example.loopdy",
            "revision": 1,
            "timestamp": FIXTURE["live_activity"]["timestamp"],
            "lease_expires": FIXTURE["live_activity"]["timestamp"] + 28_800,
            "idempotency_key": FIXTURE["idempotency_key"],
        }
        for change in (
            {"session_ref": b64url_encode(b"x" * 65)},
            {"revision": True},
            {"timestamp": 1.5},
            {"lease_expires": False},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.client(_Transport()).register_live_activity({**live, **change})

        ack = {
            "version": 1,
            "device_id": FIXTURE["device_id"],
            "revision": 2,
            "sender_key_revision": 1,
            "acknowledged_sender_key_ids": [FIXTURE["sender"]["key_id"]],
            "idempotency_key": FIXTURE["idempotency_key"],
        }
        with self.assertRaises(ValueError):
            self.client(_Transport()).acknowledge_sender_keys({**ack, "sender_key_revision": True})

    def test_secret_references_resolve_from_named_environment_or_private_file_only(self) -> None:
        self.assertEqual(
            resolve_secret_reference("env:FIXTURE_SECRET", environ={"FIXTURE_SECRET": "fake-value"}),
            b"fake-value",
        )
        with tempfile.TemporaryDirectory() as directory:
            secret_path = Path(directory) / "relay-secret"
            secret_path.write_bytes(b"fake-file-value")
            secret_path.chmod(0o600)
            self.assertEqual(
                resolve_secret_reference(f"file:{secret_path}", environ={}),
                b"fake-file-value",
            )
            secret_path.chmod(0o640)
            with self.assertRaisesRegex(ValueError, "owner-only"):
                resolve_secret_reference(f"file:{secret_path}", environ={})
        for reference in ("fake-value", "env:", "file:relative", "command:echo fake"):
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                resolve_secret_reference(reference, environ={})

    def test_signing_pin_metadata_is_stable_and_raw_pem_is_rejected(self) -> None:
        first = self.client(_Transport()).sender_key_set()
        secrets = {
            self.config.hmac_secret_reference: bytes.fromhex(FIXTURE["hmac_key_hex"]),
            self.config.signing_key_secret_reference: signing_keyring_secret(),
        }
        later = RelayClient(
            self.config,
            transport=_Transport(),
            secret_resolver=secrets.__getitem__,
            now=lambda: FIXTURE["issued"] + 600,
            random_bytes=lambda count: b"x" * count,
        ).sender_key_set()
        self.assertEqual(first, later)

        malformed = {
            self.config.hmac_secret_reference: bytes.fromhex(FIXTURE["hmac_key_hex"]),
            self.config.signing_key_secret_reference: private_pem(4),
        }
        raw = RelayClient(
            self.config,
            transport=_Transport(),
            secret_resolver=malformed.__getitem__,
            now=lambda: FIXTURE["issued"],
        )
        with self.assertRaisesRegex(ValueError, "versioned keyring"):
            raw.sender_key_set()


if __name__ == "__main__":
    unittest.main()
