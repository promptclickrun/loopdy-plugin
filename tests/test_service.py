from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from loopdy_plugin.events import build_event
from loopdy_plugin.provider import DeliveryError, DeliveryReceipt, LiveActivityState, ProviderReceipt
from loopdy_plugin.providers.apns import ApnsPushProvider
from loopdy_plugin.relay_client import RelayConfig, RelayOutcomeUnknown, RelayPushProvider
from loopdy_plugin.relay_crypto import b64url_encode, key_id, public_key_bytes
from loopdy_plugin.service import LoopdyService, _session_reference
from loopdy_plugin.store import LoopdyStore


@dataclass
class _Call:
    token: str
    message: object
    environment: str


class _Provider:
    def __init__(self, *, outcomes: dict[str, list[object]] | None = None):
        self.calls: list[_Call] = []
        self.outcomes = outcomes or {}
        self.receipt_results: dict[str, ProviderReceipt] = {}
        self.receipt_queries: list[list[str]] = []

    def send(self, token, message, *, environment=""):
        self.calls.append(_Call(token, message, environment))
        outcomes = self.outcomes.get(token, [])
        if outcomes:
            result = outcomes.pop(0)
            if isinstance(result, Exception):
                raise result
            return result
        suffix = token[-8:].replace("]", "")
        return DeliveryReceipt(delivery_id=f"delivery-{suffix}")

    def receipts(self, receipt_ids):
        ids = list(receipt_ids)
        self.receipt_queries.append(ids)
        return {value: self.receipt_results[value] for value in ids if value in self.receipt_results}


class _LiveProvider(ApnsPushProvider):
    def __init__(self, outcomes: list[DeliveryReceipt | Exception] | None = None):
        self.outcomes = list(outcomes or [])
        self.live_calls: list[str] = []
        self.live_updates: list[dict[str, object]] = []
        self.closed = False

    def send_live_activity(self, token, **kwargs) -> DeliveryReceipt:
        self.live_calls.append(kwargs["phase"])
        self.live_updates.append(dict(kwargs))
        if self.outcomes:
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        return DeliveryReceipt(delivery_id="live-delivery")

    def close(self):
        self.closed = True


class _BlockingLiveProvider(_LiveProvider):
    def __init__(self, *, fail_if_closed: bool = False):
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls_after_close: list[bool] = []
        self.fail_if_closed = fail_if_closed

    def send_live_activity(self, token, **kwargs) -> DeliveryReceipt:
        self.live_calls.append(kwargs["phase"])
        self.calls_after_close.append(self.closed)
        if len(self.live_calls) == 1:
            self.started.set()
            self.release.wait(timeout=5)
        if self.fail_if_closed and self.closed:
            raise RuntimeError("Cannot send with a closed client")
        return DeliveryReceipt(delivery_id="live-delivery")


class ServiceTests(unittest.TestCase):
    def _store(self, directory: str) -> LoopdyStore:
        return LoopdyStore(Path(directory) / "loopdy.sqlite3")

    def _configure_apns(self, store: LoopdyStore, directory: str) -> None:
        key_path = Path(directory) / "AuthKey_FIXTURE01.p8"
        key_path.write_bytes(
            ec.generate_private_key(ec.SECP256R1()).private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
        store.save_apns_config(
            {
                "team_id": "TEAM123456",
                "key_id": "KEY1234567",
                "topic": "com.example.loopdyai",
                "environment": "production",
                "key_path": str(key_path),
            }
        )

    def _relay_registration_body(
        self,
        *,
        device_id: str = "relay-phone",
        revision: int = 10,
        issued: int = 1_700_000_000,
        lease_expires: int = 1_702_592_000,
        recipient_private_key: ec.EllipticCurvePrivateKey | None = None,
        push_token: str = "ab" * 32,
        environment: str = "production",
        topic: str = "com.example.loopdy",
        label: str = "iPhone",
        groups: list[str] | None = None,
        idempotency_key: str = "00000000-0000-5000-8000-000000000010",
    ) -> dict[str, object]:
        private_key = recipient_private_key or ec.derive_private_key(19, ec.SECP256R1())
        public_key = public_key_bytes(private_key.public_key())
        return {
            "version": 1,
            "device_id": device_id,
            "revision": revision,
            "issued": issued,
            "lease_expires": lease_expires,
            "provider": "relay",
            "recipient_public_key": b64url_encode(public_key),
            "recipient_key_id": key_id(public_key),
            "push_token": push_token,
            "environment": environment,
            "topic": topic,
            "label": label,
            "groups": list(groups or []),
            "idempotency_key": idempotency_key,
        }

    def test_adopts_verified_link_relay_readiness_as_a_compatible_local_device(self) -> None:
        from loopdy_plugin.link_contracts import RelayReady

        sender_key_id = "A" * 43

        class RelayProvider:
            def sender_key_set(self):
                return {
                    "version": 1,
                    "revision": 7,
                    "current": {"key_id": sender_key_id},
                    "previous": None,
                }

            def select_sender_key_id(self, acknowledged_sender_key_ids):
                if acknowledged_sender_key_ids != [sender_key_id]:
                    raise ValueError("unexpected sender key acknowledgement")
                return sender_key_id

        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            service = LoopdyService(
                store,
                providers={"relay": RelayProvider()},
                timestamp_fn=lambda: 1_788_000_100,
            )
            ready = RelayReady(
                device_id="mobile-private-coordinate",
                enrollment_revision=4,
                acknowledgement_revision=5,
                lease_expires=1_789_000_000,
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="A" * 43,
                sender_key_revision=7,
                acknowledged_sender_key_ids=(sender_key_id,),
                environment="production",
                topic=".".join(("app", "loopdy", "mobile")),
                device_name="Alex's iPhone",
                sent_at=1_788_000_000,
                scope="host_relay",
            )

            first = service.adopt_link_relay_device(
                ready,
                sender_device_id="mobile-private-coordinate",
            )
            second = service.adopt_link_relay_device(
                ready,
                sender_device_id="mobile-private-coordinate",
            )

            self.assertTrue(first["ready"])
            self.assertFalse(second["changed"])
            device = store.get_device("mobile-private-coordinate")
            self.assertEqual(device["provider"], "relay")
            self.assertEqual(device["revision"], 5)
            self.assertEqual(device["sender_key_revision"], 7)
            self.assertEqual(device["acknowledged_sender_key_ids"], [sender_key_id])
            self.assertEqual(
                [item["device_id"] for item in store.resolve_devices("all", "relay", now=1_788_000_100)],
                ["mobile-private-coordinate"],
            )

            with self.assertRaisesRegex(ValueError, "verified sender"):
                service.adopt_link_relay_device(
                    ready,
                    sender_device_id="different-device",
                )
            service.close()

    def test_relay_registration_retry_resumes_the_original_journal_request_for_a_newer_same_scope_body(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            issued = int(time.time())
            first_body = self._relay_registration_body(
                issued=issued,
                lease_expires=issued + 2_592_000,
            )
            retry_body = self._relay_registration_body(
                revision=11,
                issued=issued + 1,
                lease_expires=issued + 2_592_001,
                idempotency_key="00000000-0000-5000-8000-000000000011",
            )

            class RelayClient:
                def __init__(self) -> None:
                    self.calls: list[dict[str, object]] = []

                def register_device(self, body: dict[str, object]) -> dict[str, object]:
                    self.calls.append(dict(body))
                    if len(self.calls) == 1:
                        raise RelayOutcomeUnknown("relay transport outcome unknown")
                    return {
                        "version": 1,
                        "status": "accepted",
                        "tenant_id": "TENANT_EXAMPLE",
                        "device_id": body["device_id"],
                        "recipient_key_id": body["recipient_key_id"],
                        "revision": body["revision"],
                        "lease_expires": body["lease_expires"],
                    }

            client = RelayClient()
            service = LoopdyService(store, providers={"relay": RelayPushProvider(client)})

            with self.assertRaises(RelayOutcomeUnknown):
                service.relay_operation("register_device", first_body)

            result = service.relay_operation("register_device", retry_body)

            self.assertEqual(client.calls, [first_body, first_body])
            self.assertEqual(result["revision"], first_body["revision"])
            self.assertIsNone(store.pending_relay_operation("register_device", "relay-phone"))
            self.assertEqual(store.get_device("relay-phone")["revision"], first_body["revision"])
            service.close()

    def test_accepted_relay_registration_replaces_an_existing_direct_device(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_device(
                device_id="relay-phone",
                endpoint_id="ab" * 32,
                provider="direct",
                preferences={"notifications_enabled": True},
            )
            issued = int(time.time())
            body = self._relay_registration_body(
                issued=issued,
                lease_expires=issued + 2_592_000,
            )

            class RelayClient:
                def register_device(self, request: dict[str, object]) -> dict[str, object]:
                    return {
                        "version": 1,
                        "status": "accepted",
                        "tenant_id": "TENANT_EXAMPLE",
                        "device_id": request["device_id"],
                        "recipient_key_id": request["recipient_key_id"],
                        "revision": request["revision"],
                        "lease_expires": request["lease_expires"],
                    }

            service = LoopdyService(store, providers={"relay": RelayPushProvider(RelayClient())})

            result = service.relay_operation("register_device", body)

            self.assertEqual(result["status"], "accepted")
            self.assertIsNone(store.pending_relay_operation("register_device", "relay-phone"))
            device = store.get_device("relay-phone")
            self.assertEqual(device["provider"], "relay")
            self.assertEqual(device["revision"], body["revision"])
            self.assertEqual(device["preferences"], {"notifications_enabled": True})
            service.close()

    def test_accepted_relay_registration_cancels_stale_direct_delivery_and_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_device(
                device_id="relay-phone",
                endpoint_id="ab" * 32,
                provider="direct",
            )
            event = build_event("channel.message", correlation=("provider-transition",))
            store.record_event(event, target="all")
            store.record_device_delivery(
                event_id=event.event_id,
                device_id="relay-phone",
                provider="direct",
                status="queued",
            )
            store.record_provider_receipt(
                receipt_id="direct-receipt",
                event_id=event.event_id,
                device_id="relay-phone",
                provider="direct",
            )
            issued = int(time.time())
            body = self._relay_registration_body(
                issued=issued,
                lease_expires=issued + 2_592_000,
            )

            class RelayClient:
                def register_device(self, request: dict[str, object]) -> dict[str, object]:
                    return {
                        "version": 1,
                        "status": "accepted",
                        "tenant_id": "TENANT_EXAMPLE",
                        "device_id": request["device_id"],
                        "recipient_key_id": request["recipient_key_id"],
                        "revision": request["revision"],
                        "lease_expires": request["lease_expires"],
                    }

            direct = _Provider()
            direct.receipt_results = {
                "direct-receipt": ProviderReceipt(
                    status="failed",
                    error_code="DeviceNotRegistered",
                    invalid_token=True,
                )
            }
            service = LoopdyService(
                store,
                providers={"direct": direct, "relay": RelayPushProvider(RelayClient())},
            )

            service.relay_operation("register_device", body)
            service.reconcile_receipts()

            delivery = store.list_event_deliveries(event.event_id)[0]
            self.assertEqual((delivery["status"], delivery["failure"]), ("failed", "relay_target_changed"))
            self.assertEqual(direct.receipt_queries, [])
            device = store.get_device("relay-phone")
            self.assertEqual(device["provider"], "relay")
            self.assertFalse(device["revoked"])
            service.close()

    def test_relay_registration_prevents_a_previously_loaded_direct_receipt_from_revoking_it(self) -> None:
        class BlockingReceiptProvider(_Provider):
            def __init__(self) -> None:
                super().__init__()
                self.started = threading.Event()
                self.release = threading.Event()

            def receipts(self, receipt_ids):
                self.started.set()
                self.release.wait(timeout=2)
                return super().receipts(receipt_ids)

        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_device(
                device_id="relay-phone",
                endpoint_id="ab" * 32,
                provider="direct",
            )
            event = build_event("channel.message", correlation=("receipt-race",))
            store.record_event(event, target="all")
            store.record_provider_receipt(
                receipt_id="direct-receipt",
                event_id=event.event_id,
                device_id="relay-phone",
                provider="direct",
            )
            issued = int(time.time())
            body = self._relay_registration_body(
                issued=issued,
                lease_expires=issued + 2_592_000,
            )

            class RelayClient:
                def register_device(self, request: dict[str, object]) -> dict[str, object]:
                    return {
                        "version": 1,
                        "status": "accepted",
                        "tenant_id": "TENANT_EXAMPLE",
                        "device_id": request["device_id"],
                        "recipient_key_id": request["recipient_key_id"],
                        "revision": request["revision"],
                        "lease_expires": request["lease_expires"],
                    }

            direct = BlockingReceiptProvider()
            direct.receipt_results = {
                "direct-receipt": ProviderReceipt(
                    status="failed",
                    error_code="DeviceNotRegistered",
                    invalid_token=True,
                )
            }
            service = LoopdyService(
                store,
                providers={"direct": direct, "relay": RelayPushProvider(RelayClient())},
            )
            reconcile = threading.Thread(target=service.reconcile_receipts)

            reconcile.start()
            self.assertTrue(direct.started.wait(timeout=2))
            service.relay_operation("register_device", body)
            direct.release.set()
            reconcile.join(timeout=3)

            self.assertFalse(reconcile.is_alive())
            device = store.get_device("relay-phone")
            self.assertEqual(device["provider"], "relay")
            self.assertFalse(device["revoked"])
            self.assertEqual(store.pending_provider_receipts("direct"), [])
            service.close()

    def test_terminal_provider_conflict_registration_recovers_stored_response_without_remote_call(self) -> None:
        class RejectingRelayClient:
            def __init__(self) -> None:
                self.calls = 0

            def register_device(self, _body: dict[str, object]) -> dict[str, object]:
                self.calls += 1
                raise AssertionError("stored-response recovery must not call the relay")

        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            sender_private_key = ec.derive_private_key(29, ec.SECP256R1())
            sender_pem = sender_private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii")
            sender_now = int(time.time())
            sender_key = {
                "key_id": key_id(public_key_bytes(sender_private_key.public_key())),
                "public_key": b64url_encode(public_key_bytes(sender_private_key.public_key())),
                "state": "current",
                "not_before": sender_now - 60,
                "not_after": sender_now + 86_400,
            }
            signing_path = Path(directory) / "relay-signing-keyring"
            signing_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "revision": 1,
                        "current": {
                            "pem": sender_pem,
                            "not_before": sender_key["not_before"],
                            "not_after": sender_key["not_after"],
                        },
                        "previous": None,
                    }
                ),
                encoding="utf-8",
            )
            signing_path.chmod(0o600)
            store.save_relay_config(
                {
                    "base_url": "https://relay.example.invalid",
                    "tenant_id": "TENANT_EXAMPLE",
                    "credential_key_id": "credential_fixture_01",
                    "hmac_secret_reference": "env:LOOPDY_RELAY_HMAC",
                    "signing_key_secret_reference": f"file:{signing_path}",
                }
            )
            store.upsert_device(
                device_id="relay-phone",
                endpoint_id="ab" * 32,
                provider="direct",
                preferences={"notifications_enabled": True},
            )
            issued = int(time.time())
            body = self._relay_registration_body(
                issued=issued,
                lease_expires=issued + 2_592_000,
            )
            generation = store.relay_config_generation()
            store.save_pending_relay_operation(
                operation="register_device",
                device_id="relay-phone",
                revision=body["revision"],
                idempotency_key=body["idempotency_key"],
                body=body,
                relay_generation=generation,
            )
            response = {
                "version": 1,
                "status": "accepted",
                "tenant_id": "TENANT_EXAMPLE",
                "device_id": "relay-phone",
                "recipient_key_id": body["recipient_key_id"],
                "revision": body["revision"],
                "lease_expires": body["lease_expires"],
                "sender_key_revision": 1,
                "current_sender_key": sender_key,
                "previous_sender_key": None,
            }
            store.record_relay_operation_response(
                operation="register_device",
                device_id="relay-phone",
                response=response,
            )
            store.quarantine_relay_operation(
                "register_device",
                "relay-phone",
                error="Device is already registered with another provider",
            )
            client = RejectingRelayClient()
            service = LoopdyService(store, providers={"relay": RelayPushProvider(client)})

            validate_response = service._validate_stored_relay_registration_response

            def reset_after_recovery_claim(
                stored_response: dict[str, object], normalized_body: dict[str, object]
            ) -> None:
                validate_response(stored_response, normalized_body)
                claimed = store.pending_relay_operation("register_device", "relay-phone")
                self.assertIsNotNone(claimed)
                assert claimed is not None
                self.assertNotEqual(claimed["claim_token"], "")
                with mock.patch(
                    "loopdy_plugin.store.time.time",
                    return_value=int(claimed["claim_expires"]),
                ):
                    self.assertTrue(
                        store.reset_relay_operation(
                            "register_device",
                            "relay-phone",
                            request_digest=str(claimed["request_digest"]),
                        )
                    )

            with mock.patch.object(
                service,
                "_validate_stored_relay_registration_response",
                side_effect=reset_after_recovery_claim,
            ):
                raced = service.recover_terminal_relay_registrations()

            self.assertEqual(raced, {"claimed": 1, "applied": 0, "skipped": 1, "remote_calls": 0})
            self.assertEqual(store.get_device("relay-phone")["provider"], "direct")
            reset = store.pending_relay_operation("register_device", "relay-phone")
            self.assertIsNotNone(reset)
            assert reset is not None
            self.assertEqual(reset["terminal"], 0)
            store.record_relay_operation_response(
                operation="register_device",
                device_id="relay-phone",
                response=response,
            )
            store.quarantine_relay_operation(
                "register_device",
                "relay-phone",
                error="Device is already registered with another provider",
            )

            result = service.recover_terminal_relay_registrations()

            self.assertEqual(result, {"claimed": 1, "applied": 1, "skipped": 0, "remote_calls": 0})
            self.assertEqual(client.calls, 0)
            self.assertIsNone(store.pending_relay_operation("register_device", "relay-phone"))
            device = store.get_device("relay-phone")
            self.assertEqual(device["provider"], "relay")
            self.assertEqual(device["preferences"], {"notifications_enabled": True})

            invalid_body = self._relay_registration_body(
                revision=11,
                issued=issued + 1,
                lease_expires=issued + 2_592_001,
                idempotency_key="00000000-0000-5000-8000-000000000099",
            )
            store.save_pending_relay_operation(
                operation="register_device",
                device_id="relay-phone",
                revision=invalid_body["revision"],
                idempotency_key=invalid_body["idempotency_key"],
                body=invalid_body,
                relay_generation=generation,
            )
            mismatched_response = {**response, "revision": invalid_body["revision"]}
            store.record_relay_operation_response(
                operation="register_device",
                device_id="relay-phone",
                response=mismatched_response,
            )
            store.quarantine_relay_operation(
                "register_device",
                "relay-phone",
                error="Device is already registered with another provider",
            )

            rejected = service.recover_terminal_relay_registrations()

            self.assertEqual(
                rejected,
                {"claimed": 1, "applied": 0, "skipped": 1, "remote_calls": 0},
            )
            self.assertEqual(client.calls, 0)
            self.assertIsNotNone(store.pending_relay_operation("register_device", "relay-phone"))
            self.assertEqual(store.get_device("relay-phone")["revision"], body["revision"])
            service.close()

    def test_relay_registration_retry_preserves_conflicts_for_changed_scope_or_non_newer_revision(self) -> None:
        scope_changes = (
            {"push_token": "cd" * 32},
            {"recipient_private_key": ec.derive_private_key(23, ec.SECP256R1())},
            {"topic": "com.example.other"},
            {"label": "Other iPhone"},
            {"groups": ["work"]},
            {"environment": "sandbox"},
        )
        for change in (*scope_changes, {"revision": 10}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                store = self._store(directory)
                issued = int(time.time())
                first_body = self._relay_registration_body(
                    issued=issued,
                    lease_expires=issued + 2_592_000,
                )
                retry_body = self._relay_registration_body(
                    revision=int(change.get("revision", 11)),
                    issued=issued + 1,
                    lease_expires=issued + 2_592_001,
                    recipient_private_key=change.get("recipient_private_key"),
                    idempotency_key="00000000-0000-5000-8000-000000000011",
                    push_token=str(change.get("push_token", first_body["push_token"])),
                    environment=str(change.get("environment", first_body["environment"])),
                    topic=str(change.get("topic", first_body["topic"])),
                    label=str(change.get("label", first_body["label"])),
                    groups=list(change.get("groups", first_body["groups"])),
                )

                class RelayClient:
                    def register_device(self, _body: dict[str, object]) -> dict[str, object]:
                        raise RelayOutcomeUnknown("relay transport outcome unknown")

                service = LoopdyService(
                    store,
                    providers={"relay": RelayPushProvider(RelayClient())},
                )
                with self.assertRaises(RelayOutcomeUnknown):
                    service.relay_operation("register_device", first_body)
                with self.assertRaisesRegex(ValueError, "conflict"):
                    service.relay_operation("register_device", retry_body)
                pending = store.pending_relay_operation("register_device", "relay-phone")
                self.assertIsNotNone(pending)
                assert pending is not None
                self.assertEqual(json.loads(pending["body_json"]), first_body)
                service.close()

    def test_proactive_channel_message_reaches_all_eligible_devices(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_device(
                device_id="phone-1",
                endpoint_id="ExponentPushToken[fixture-phone-1]",
                provider="managed",
                preferences={"detail_mode": "automatic", "notifications_enabled": True},
            )
            store.upsert_device(
                device_id="phone-2",
                endpoint_id="ExponentPushToken[fixture-phone-2]",
                provider="managed",
                groups=["personal"],
                preferences={"detail_mode": "minimal", "notifications_enabled": True},
            )
            store.upsert_device(
                device_id="direct-phone",
                endpoint_id="a" * 64,
                provider="direct",
            )
            provider = _Provider()
            service = LoopdyService(store, providers={"managed": provider})
            event = build_event(
                "channel.message",
                correlation=("proactive-message",),
                detail={"message": "Deployment complete"},
            )

            first = service.deliver(event, target="all")
            second = service.deliver(event, target="all")

            self.assertTrue(first["success"])
            self.assertTrue(second["success"])
            self.assertEqual(
                [call.token for call in provider.calls],
                [
                    "ExponentPushToken[fixture-phone-1]",
                    "ExponentPushToken[fixture-phone-2]",
                ],
            )
            self.assertEqual(provider.calls[0].message.body, "Message: Deployment complete")
            self.assertNotEqual(provider.calls[1].message.body, "Deployment complete")
            self.assertEqual(
                [item["status"] for item in store.list_event_deliveries(event.event_id)],
                ["failed", "sent", "sent"],
            )
            self.assertEqual(first["failed"], 1)
            self.assertEqual(store.get_event(event.event_id)["status"], "sent")

    def test_each_delegation_lifecycle_preference_filters_independently(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            event_types = (
                "delegation.started",
                "delegation.updated",
                "delegation.completed",
            )
            for index, event_type in enumerate(event_types):
                store.upsert_device(
                    device_id=f"device-{index}",
                    endpoint_id=f"ExponentPushToken[fixture-device-{index}]",
                    provider="managed",
                    preferences={"enabled_types": [event_type]},
                )
            provider = _Provider()
            service = LoopdyService(store, providers={"managed": provider})

            for event_type in event_types:
                before = len(provider.calls)
                service.deliver(
                    build_event(event_type, correlation=(event_type,)),
                    target="all",
                )
                self.assertEqual(len(provider.calls), before + 1)
                self.assertEqual(provider.calls[-1].message.event_type, event_type)

    def test_targets_preferences_quiet_hours_and_mixed_outcomes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            for device_id, preferences in (
                ("enabled", {"notifications_enabled": True}),
                ("disabled", {"notifications_enabled": False}),
                ("filtered", {"enabled_types": ["approval.required"]}),
                ("quiet", {"quiet_hours": {"start": "22:00", "end": "07:00"}}),
            ):
                store.upsert_device(
                    device_id=device_id,
                    endpoint_id=f"ExponentPushToken[fixture-{device_id}]",
                    provider="managed",
                    groups=["personal"],
                    preferences=preferences,
                )
            provider = _Provider()
            service = LoopdyService(
                store,
                providers={"managed": provider},
                now_fn=lambda: datetime(2026, 8, 15, 23, 0),
            )

            result = service.deliver(
                build_event("channel.message", correlation=("preferences",)),
                target="group:personal",
            )

            self.assertTrue(result["success"])
            self.assertEqual([call.token for call in provider.calls], ["ExponentPushToken[fixture-enabled]"])
            statuses = {
                item["device_id"]: item["status"]
                for item in store.list_event_deliveries(result["event_id"])
            }
            self.assertEqual(
                statuses,
                {"disabled": "suppressed", "enabled": "sent", "filtered": "suppressed", "quiet": "suppressed"},
            )

    def test_quiet_hours_use_each_devices_configured_timezone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_device(
                device_id="tokyo-phone",
                endpoint_id="ExponentPushToken[fixture-tokyo]",
                provider="managed",
                preferences={
                    "notifications_enabled": True,
                    "timezone": "Asia/Tokyo",
                    "quiet_hours": {"start": "22:00", "end": "07:00"},
                },
            )
            provider = _Provider()
            service = LoopdyService(
                store,
                providers={"managed": provider},
                now_fn=lambda: datetime(2026, 8, 15, 15, 0, tzinfo=timezone.utc),
            )

            result = service.deliver(
                build_event("channel.message", correlation=("timezone-quiet-hours",)),
                target="all",
            )

            self.assertTrue(result["success"])
            self.assertEqual(result["suppressed"], 1)
            self.assertEqual(provider.calls, [])

    def test_retries_temporary_failures_and_revokes_only_invalid_device(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            retry_token = "ExponentPushToken[fixture-retry]"
            invalid_token = "ExponentPushToken[fixture-invalid]"
            store.upsert_device(device_id="retry", endpoint_id=retry_token, provider="managed")
            store.upsert_device(device_id="invalid", endpoint_id=invalid_token, provider="managed")
            provider = _Provider(
                outcomes={
                    retry_token: [
                        DeliveryError("provider_unavailable", status=503),
                        DeliveryReceipt(delivery_id="delivery-after-retry"),
                    ],
                    invalid_token: [
                        DeliveryError("DeviceNotRegistered", status=400, invalid_token=True)
                    ],
                }
            )
            sleeps: list[float] = []
            service = LoopdyService(
                store,
                providers={"managed": provider},
                sleep_fn=sleeps.append,
                jitter_fn=lambda: 0,
            )

            result = service.deliver(
                build_event("session.failed", correlation=("mixed-failures",)),
                target="all",
            )

            self.assertTrue(result["success"])
            self.assertEqual(sleeps, [0.25])
            devices = {item["device_id"]: item for item in store.list_devices()}
            self.assertFalse(devices["retry"]["revoked"])
            self.assertTrue(devices["invalid"]["revoked"])
            self.assertEqual(result["failed"], 1)
            self.assertEqual(result["delivered"], 1)

    def test_pending_expo_receipts_are_reconciled_and_revoke_only_terminal_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            for device_id in ("healthy", "gone"):
                store.upsert_device(
                    device_id=device_id,
                    endpoint_id=f"ExponentPushToken[fixture-{device_id}]",
                    provider="managed",
                )
            provider = _Provider(
                outcomes={
                    "ExponentPushToken[fixture-healthy]": [
                        DeliveryReceipt("delivery-healthy", "receipt-healthy")
                    ],
                    "ExponentPushToken[fixture-gone]": [
                        DeliveryReceipt("delivery-gone", "receipt-gone")
                    ],
                }
            )
            service = LoopdyService(store, providers={"managed": provider})
            service.deliver(
                build_event("channel.message", correlation=("receipts",)),
                target="all",
            )
            provider.receipt_results = {
                "receipt-healthy": ProviderReceipt(status="delivered"),
                "receipt-gone": ProviderReceipt(
                    status="failed",
                    error_code="DeviceNotRegistered",
                    invalid_token=True,
                ),
            }

            result = service.reconcile_receipts()

            self.assertEqual(result, {"checked": 2, "delivered": 1, "failed": 1})
            self.assertEqual(len(provider.receipt_queries), 1)
            self.assertCountEqual(
                provider.receipt_queries[0],
                ["receipt-healthy", "receipt-gone"],
            )
            devices = {item["device_id"]: item for item in store.list_devices()}
            self.assertFalse(devices["healthy"]["revoked"])
            self.assertTrue(devices["gone"]["revoked"])
            self.assertEqual(store.pending_provider_receipts("managed"), [])

    def test_device_lifecycle_provider_switching_and_health_are_local(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.set_provider_mode("managed")
            provider = _Provider()
            service = LoopdyService(store, providers={"managed": provider})

            self.assertFalse(service.health()["ready"])
            registered = service.register_device(
                device_id="phone-123",
                endpoint_id="ExponentPushToken[fixture-phone-123]",
                provider="managed",
                token_environment="production",
                label="Phone",
                groups=["personal"],
                preferences={"notifications_enabled": True},
            )
            self.assertTrue(registered["registered"])
            self.assertTrue(service.health()["ready"])
            self.assertTrue(service.update_device_preferences("phone-123", {"detail_mode": "minimal"})["updated"])
            self.assertTrue(service.revoke_device("phone-123")["revoked"])
            self.assertFalse(service.health()["ready"])
            with self.assertRaisesRegex(ValueError, "Configure APNs"):
                service.set_provider_mode("direct")

    def test_relay_reconfiguration_replaces_cached_credentials_and_removal_disables_stale_client(self) -> None:
        class CachedRelay:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            previous = CachedRelay()
            service = LoopdyService(store, providers={"relay": previous})
            hmac_path = Path(directory) / "relay-hmac"
            hmac_path.write_bytes(bytes(range(32)))
            hmac_path.chmod(0o600)
            private_key = ec.derive_private_key(19, ec.SECP256R1())
            pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii")
            signing_path = Path(directory) / "relay-signing-keyring"
            keyring_now = int(time.time())
            signing_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "revision": 2,
                        "current": {
                            "pem": pem,
                            "not_before": keyring_now - 60,
                            "not_after": keyring_now + 86_400,
                        },
                        "previous": None,
                    }
                ),
                encoding="utf-8",
            )
            signing_path.chmod(0o600)
            config = RelayConfig(
                base_url="https://relay.example.invalid",
                tenant_id="TENANT_EXAMPLE",
                credential_key_id="credential_key_02",
                hmac_secret_reference=f"file:{hmac_path}",
                signing_key_secret_reference=f"file:{signing_path}",
            )

            health = service.configure_relay(config)

            self.assertTrue(previous.closed)
            replacement = service._providers["relay"]
            self.assertIsInstance(replacement, RelayPushProvider)
            self.assertEqual(replacement.client.config, config)
            self.assertEqual(store.provider_mode(), "relay")
            self.assertEqual(store.load_relay_config(), config.stored_values())

            with self.assertRaisesRegex(ValueError, "unavailable"):
                service.configure_relay(
                    RelayConfig(
                        base_url="https://new-relay.example.invalid",
                        tenant_id="TENANT_EXAMPLE",
                        credential_key_id="credential_key_03",
                        hmac_secret_reference=f"file:{Path(directory) / 'missing-hmac'}",
                        signing_key_secret_reference=f"file:{signing_path}",
                    )
                )
            self.assertIs(service._providers["relay"], replacement)
            self.assertEqual(store.provider_mode(), "relay")
            self.assertEqual(store.load_relay_config(), config.stored_values())

            service.remove_relay_configuration()

            self.assertNotIn("relay", service._providers)
            self.assertIsNone(store.load_relay_config())
            self.assertEqual(store.provider_mode(), "managed")
            with self.assertRaisesRegex(ValueError, "configuration is missing"):
                service._provider("relay")

            missing_config = RelayConfig(
                base_url="https://relay.example.invalid",
                tenant_id="TENANT_EXAMPLE",
                credential_key_id="credential_key_04",
                hmac_secret_reference=f"file:{Path(directory) / 'missing-after-restart'}",
                signing_key_secret_reference=f"file:{signing_path}",
            )
            store.save_relay_config(missing_config.stored_values())
            store.set_provider_mode("relay")
            restarted = LoopdyService(store)
            restarted_health = restarted.health()
            self.assertFalse(restarted_health["configured"])
            self.assertFalse(restarted_health["ready"])
            self.assertNotIn("missing-after-restart", restarted_health["detail"])
            self.assertNotIn("relay", restarted._providers)

    def test_explicit_device_providers_coexist_with_managed_legacy_device(self) -> None:
        class RelayProvider:
            def __init__(self):
                self.calls = []

            def select_sender_key_id(self, acknowledged_sender_key_ids):
                self.asserted_acknowledgements = list(acknowledged_sender_key_ids)
                return "z_current_sender_key"

            def send_device(self, device, message, *, delivery_id, idempotency_key):
                self.calls.append((dict(device), message, delivery_id, idempotency_key))
                return DeliveryReceipt(delivery_id=delivery_id)

        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.set_provider_mode("managed")
            self._configure_apns(store, directory)
            managed = _Provider()
            direct = _Provider()
            relay = RelayProvider()
            service = LoopdyService(
                store,
                providers={"managed": managed, "direct": direct, "relay": relay},
            )
            service.register_device(
                device_id="managed-phone",
                endpoint_id="ExponentPushToken[fixture-managed]",
                provider="managed",
            )
            service.register_device(
                device_id="direct-phone",
                endpoint_id="a" * 64,
                provider="direct",
            )
            store.register_relay_device(
                device_id="relay-phone",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=1,
                lease_expires=int(time.time()) + 2_592_000,
                normalized_body={"device_id": "relay-phone", "revision": 1},
            )
            store.acknowledge_relay_sender_keys(
                device_id="relay-phone",
                revision=2,
                sender_key_revision=1,
                acknowledged_sender_key_ids=["a_previous_sender_key", "z_current_sender_key"],
                normalized_body={"device_id": "relay-phone", "revision": 2},
            )

            result = service.deliver(
                build_event("approval.required", correlation=("coexisting-providers",)),
                target="all",
            )

            self.assertTrue(result["success"])
            self.assertEqual(result["delivered"], 3)
            self.assertEqual(len(managed.calls), 1)
            self.assertEqual(len(direct.calls), 1)
            self.assertEqual(len(relay.calls), 1)
            relay_device, relay_message, delivery_id, idempotency_key = relay.calls[0]
            self.assertEqual(relay_device["revision"], 2)
            self.assertEqual(relay_device["recipient_key_id"], "key_fixture_01")
            self.assertEqual(
                relay.asserted_acknowledgements,
                ["a_previous_sender_key", "z_current_sender_key"],
            )
            self.assertEqual(
                relay_device["acknowledged_sender_key_ids"],
                ["z_current_sender_key"],
            )
            self.assertEqual(relay_message.event_type, "approval.required")
            self.assertTrue(delivery_id)
            self.assertRegex(
                idempotency_key,
                r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            )
            deliveries = store.list_event_deliveries(result["event_id"])
            relay_delivery = next(item for item in deliveries if item["provider"] == "relay")
            self.assertEqual(relay_delivery["target_revision"], 2)
            self.assertEqual(relay_delivery["target_key_id"], "key_fixture_01")
            self.assertEqual(relay_delivery["target_sender_key_id"], "z_current_sender_key")

    def test_live_activity_registration_requires_direct_apns_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = LoopdyService(self._store(directory))
            with self.assertRaisesRegex(ValueError, "Configure direct APNs"):
                service.register_live_activity(
                    session_id="stored",
                    live_session_id="live",
                    profile="default",
                    activity_id="activity",
                    push_token="a" * 64,
                    token_environment="production",
                )
            self.assertEqual(service.store.active_live_activities("live", "default"), [])

    def test_live_activity_phase_reaches_direct_and_relay_with_identical_sanitized_state(self) -> None:
        class RelayLiveProvider:
            def __init__(self):
                self.calls = []

            def send_live_activity(
                self,
                *,
                device_id,
                state,
                delivery_id,
                target_revision,
                idempotency_key,
            ):
                self.calls.append(
                    {
                        "device_id": device_id,
                        "state": state,
                        "delivery_id": delivery_id,
                        "target_revision": target_revision,
                        "idempotency_key": idempotency_key,
                    }
                )
                return DeliveryReceipt(delivery_id=delivery_id)

        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            direct = _LiveProvider()
            relay = RelayLiveProvider()
            session_id = "session-parity"
            activity_id = "activity-parity"
            update_timestamp = int(time.time()) + 10
            store.upsert_live_activity(
                session_id=session_id,
                live_session_id=session_id,
                profile="default",
                activity_id=activity_id,
                push_token="a" * 64,
                token_environment="production",
            )
            store.register_relay_device(
                device_id="relay-phone",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="recipient_key_fixture_01",
                revision=1,
                lease_expires=int(time.time()) + 2_592_000,
                normalized_body={"device_id": "relay-phone", "revision": 1},
            )
            store.acknowledge_relay_sender_keys(
                device_id="relay-phone",
                revision=2,
                sender_key_revision=1,
                acknowledged_sender_key_ids=["sender_key_fixture_01"],
                normalized_body={"device_id": "relay-phone", "revision": 2},
            )
            store.register_relay_live_activity(
                activity_id=activity_id,
                device_id="relay-phone",
                session_ref=_session_reference(session_id),
                revision=1,
                timestamp=update_timestamp - 1,
                lease_expires=update_timestamp + 28_799,
                normalized_body={"activity_id": activity_id, "revision": 1},
            )
            service = LoopdyService(
                store,
                providers={"direct": direct, "relay": relay},
                timestamp_fn=lambda: update_timestamp,
            )

            result = service.update_live_activities(
                session_id=session_id,
                profile="default",
                phase="running",
                detail="private detail",
                tool_name="private tool",
                active_session_count=0,
            )

            self.assertEqual(result, {"matched": 2, "delivered": 2, "failed": 0})
            direct_update = dict(direct.live_updates[0])
            direct_update.pop("environment")
            direct_state = LiveActivityState(version=1, kind="live_activity", **direct_update)
            relay_state = relay.calls[0]["state"]
            self.assertEqual(relay_state.as_payload(), direct_state.as_payload())
            serialized = str(relay_state.as_payload())
            self.assertNotIn("private detail", serialized)
            self.assertNotIn("private tool", serialized)
            self.assertNotIn("title", serialized)
            self.assertRegex(relay.calls[0]["idempotency_key"], r"^[0-9a-f-]{36}$")

            terminal = service.update_live_activities(
                session_id=session_id,
                profile="default",
                phase="completed",
                detail="must stay local",
                tool_name="must stay local",
                active_session_count=0,
            )
            self.assertEqual(terminal, {"matched": 2, "delivered": 2, "failed": 0})
            self.assertEqual(store.active_live_activities(session_id, "default"), [])
            self.assertEqual(
                store.active_relay_live_activities(_session_reference(session_id)),
                [],
            )

    def test_relay_live_activity_reregistration_cannot_cross_session_ownership(self) -> None:
        class RacingStore(LoopdyStore):
            raced = False

            def active_relay_live_activity(self, activity_id, **expected):
                if expected.get("expected_session_ref") and not self.raced:
                    self.raced = True
                    current = super().active_relay_live_activity(activity_id)
                    assert current is not None
                    self.register_relay_live_activity(
                        activity_id=activity_id,
                        device_id=current["device_id"],
                        session_ref=_session_reference("new-session"),
                        revision=current["revision"] + 1,
                        timestamp=current["source_timestamp"] + 1,
                        lease_expires=current["source_timestamp"] + 28_800,
                        normalized_body={"activity_id": activity_id, "revision": 2},
                    )
                return super().active_relay_live_activity(activity_id, **expected)

        class RelayLiveProvider:
            def __init__(self):
                self.calls = []

            def send_live_activity(self, **update):
                self.calls.append(update)
                return DeliveryReceipt(delivery_id=update["delivery_id"])

        with tempfile.TemporaryDirectory() as directory:
            store = RacingStore(Path(directory) / "loopdy.sqlite3")
            now = int(time.time())
            store.register_relay_device(
                device_id="relay-phone",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="recipient_key_fixture_01",
                revision=1,
                lease_expires=now + 2_592_000,
                normalized_body={"device_id": "relay-phone", "revision": 1},
            )
            store.acknowledge_relay_sender_keys(
                device_id="relay-phone",
                revision=2,
                sender_key_revision=1,
                acknowledged_sender_key_ids=["sender_key_fixture_01"],
                normalized_body={"device_id": "relay-phone", "revision": 2},
            )
            store.register_relay_live_activity(
                activity_id="activity-race",
                device_id="relay-phone",
                session_ref=_session_reference("old-session"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": "activity-race", "revision": 1},
            )
            relay = RelayLiveProvider()
            service = LoopdyService(
                store,
                providers={"relay": relay},
                timestamp_fn=lambda: now + 2,
            )

            result = service.update_live_activities(
                session_id="old-session",
                profile="default",
                phase="running",
            )

            self.assertEqual(result, {"matched": 1, "delivered": 0, "failed": 0})
            self.assertEqual(relay.calls, [])
            self.assertEqual(
                len(store.active_relay_live_activities(_session_reference("new-session"))),
                1,
            )

    def test_direct_live_activity_reregistration_cannot_cross_session_ownership(self) -> None:
        class RacingStore(LoopdyStore):
            raced = False

            def active_live_activity(self, activity_id, **expected):
                if expected.get("expected_session_id") and not self.raced:
                    self.raced = True
                    self.upsert_live_activity(
                        session_id="new-session",
                        live_session_id="new-session",
                        profile="default",
                        activity_id=activity_id,
                        push_token="b" * 64,
                        token_environment="production",
                    )
                return super().active_live_activity(activity_id, **expected)

        with tempfile.TemporaryDirectory() as directory:
            store = RacingStore(Path(directory) / "loopdy.sqlite3")
            store.upsert_live_activity(
                session_id="old-session",
                live_session_id="old-session",
                profile="default",
                activity_id="activity-race",
                push_token="a" * 64,
                token_environment="production",
            )
            direct = _LiveProvider()
            service = LoopdyService(store, providers={"direct": direct})

            result = service.update_live_activities(
                session_id="old-session",
                profile="default",
                phase="running",
            )

            self.assertEqual(result, {"matched": 1, "delivered": 0, "failed": 0})
            self.assertEqual(direct.live_updates, [])
            self.assertEqual(len(store.active_live_activities("new-session", "default")), 1)

            self._configure_apns(service.store, directory)
            configured = LoopdyService(
                service.store,
                providers={"direct": _LiveProvider()},
            )
            result = configured.register_live_activity(
                session_id="stored",
                live_session_id="live",
                profile="default",
                activity_id="activity",
                push_token="a" * 64,
                token_environment="production",
            )
            self.assertTrue(result["registered"])
            self.assertEqual(
                configured.store.active_live_activities("live", "default")[0]["activity_id"],
                "activity",
            )

    def test_live_activity_registration_rechecks_config_after_provider_is_cached(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            self._configure_apns(store, directory)
            service = LoopdyService(store, providers={"direct": _LiveProvider()})
            self.assertIsInstance(service._provider("direct"), ApnsPushProvider)
            store.clear_apns_config()

            with self.assertRaisesRegex(ValueError, "Configure direct APNs"):
                service.register_live_activity(
                    session_id="stored",
                    live_session_id="live",
                    profile="default",
                    activity_id="activity",
                    push_token="a" * 64,
                    token_environment="production",
                )
            self.assertEqual(store.active_live_activities("live", "default"), [])

    def test_switching_to_managed_closes_and_removes_cached_direct_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            provider = _LiveProvider()
            service = LoopdyService(store, providers={"direct": provider})

            service.set_provider_mode("managed")

            self.assertTrue(provider.closed)
            self.assertNotIn("direct", service._providers)

    def test_repeated_provider_rotation_does_not_retain_closed_identity_bookkeeping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            service = LoopdyService(store, providers={"managed": _Provider()})

            for _ in range(8):
                with service._provider_lock:
                    previous = service._providers["managed"]
                    service._providers["managed"] = _Provider()
                service._retire_provider(previous)

            self.assertEqual(service._provider_closed, set())
            self.assertEqual(service._provider_retired, set())
            self.assertEqual(service._provider_close_events, {})
            service.close()

    def test_receipt_ledger_read_failure_does_not_block_provider_retirement(self) -> None:
        class RaisingStore(LoopdyStore):
            def __init__(self, path):
                super().__init__(path)
                self.receipt_reads = 0

            def pending_provider_receipts(self, provider, *, limit=1000):
                self.receipt_reads += 1
                if self.receipt_reads > 1:
                    raise RuntimeError("receipt ledger unavailable")
                return [{"receipt_id": "receipt-fixture"}]

        class ReceiptProvider(_Provider):
            def __init__(self):
                super().__init__()
                self.close_count = 0

            def receipts(self, _receipt_ids):
                # This second ledger read occurs while reconcile_receipts holds
                # the provider lease, exercising the exception/finally path.
                store.pending_provider_receipts("managed")
                return {}

            def close(self):
                self.close_count += 1

        with tempfile.TemporaryDirectory() as directory:
            store = RaisingStore(Path(directory) / "loopdy.sqlite3")
            provider = ReceiptProvider()
            service = LoopdyService(store, providers={"managed": provider})

            service.reconcile_receipts()
            service.close()

            self.assertEqual(store.receipt_reads, 2)
            self.assertEqual(provider.close_count, 1)
            self.assertEqual(service._provider_inflight, {})

    def test_completed_live_activity_is_retained_after_retryable_delivery_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_live_activity(
                session_id="stored",
                live_session_id="live",
                profile="default",
                activity_id="activity",
                push_token="a" * 64,
                token_environment="production",
            )
            provider = _LiveProvider(
                [
                    DeliveryError("transport_error", retryable=True),
                    DeliveryError("transport_error", retryable=True),
                    DeliveryError("transport_error", retryable=True),
                ]
            )
            service = LoopdyService(
                store,
                providers={"direct": provider},
                sleep_fn=lambda _delay: None,
                jitter_fn=lambda: 0,
            )

            result = service.update_live_activities(
                session_id="live",
                profile="default",
                status="completed",
                detail="Response ready",
                active_session_count=0,
            )

            self.assertEqual(result, {"matched": 1, "delivered": 0, "failed": 1})
            self.assertEqual(len(provider.live_calls), 3)
            self.assertEqual(len(store.active_live_activities("live", "default")), 1)
            self.assertEqual(len(store.pending_live_activity_updates()), 1)
            service.close()

    def test_close_defers_provider_close_until_blocking_ordinary_delivery_finishes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_device(
                device_id="phone-123",
                endpoint_id="ExponentPushToken[fixture-phone-123]",
                provider="managed",
            )
            started = threading.Event()
            release = threading.Event()

            class BlockingProvider(_Provider):
                def __init__(self):
                    super().__init__()
                    self.closed = False

                def send(self, token, message, *, environment=""):
                    started.set()
                    if not release.wait(timeout=2):
                        raise AssertionError("ordinary send was not released")
                    return super().send(token, message, environment=environment)

                def close(self):
                    self.closed = True

            provider = BlockingProvider()
            service = LoopdyService(store, providers={"managed": provider})
            event = build_event("channel.message", correlation=("ordinary-close",))
            delivery = threading.Thread(target=lambda: service.deliver(event, target="all"))
            delivery.start()
            self.assertTrue(started.wait(timeout=1))
            closing = threading.Thread(target=service.close)
            closing.start()
            time.sleep(0.05)
            self.assertTrue(closing.is_alive())
            self.assertFalse(provider.closed)
            release.set()
            delivery.join(timeout=2)
            closing.join(timeout=2)
            self.assertFalse(delivery.is_alive())
            self.assertFalse(closing.is_alive())
            self.assertTrue(provider.closed)

    def test_provider_retirement_owns_close_exactly_once(self) -> None:
        class CountingProvider(_Provider):
            def __init__(self):
                super().__init__()
                self.close_count = 0

            def close(self):
                self.close_count += 1

        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            provider = CountingProvider()
            service = LoopdyService(store, providers={"managed": provider})
            with service._provider_lock:
                service._providers.pop("managed")

            service._retire_provider(provider)
            service._retire_provider(provider)

            self.assertEqual(provider.close_count, 1)

    def test_delivery_releases_provider_lease_when_sent_ledger_write_fails(self) -> None:
        class RaisingStore(LoopdyStore):
            def record_device_delivery(self, **kwargs):
                if kwargs.get("status") == "sent":
                    raise RuntimeError("ledger unavailable")
                return super().record_device_delivery(**kwargs)

        with tempfile.TemporaryDirectory() as directory:
            store = RaisingStore(Path(directory) / "loopdy.sqlite3")
            store.upsert_device(
                device_id="phone-123",
                endpoint_id="ExponentPushToken[fixture-phone-123]",
                provider="managed",
            )
            provider = _Provider()
            service = LoopdyService(store, providers={"managed": provider})
            event = build_event("channel.message", correlation=("ledger-failure",))

            with self.assertRaisesRegex(RuntimeError, "ledger unavailable"):
                service.deliver(event, target="all")

            self.assertEqual(service._provider_inflight, {})

    def test_closed_service_rejects_provider_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            service = LoopdyService(store)
            service.close()

            with self.assertRaisesRegex(DeliveryError, "service_closed"):
                service._provider("managed")

    def test_relay_tenant_revoke_evicts_cached_provider_and_disables_old_client(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.save_relay_config(
                {
                    "base_url": "https://relay.example.invalid",
                    "tenant_id": "TENANT_EXAMPLE",
                    "credential_key_id": "credential_fixture_01",
                    "hmac_secret_reference": "env:LOOPDY_RELAY_HMAC",
                    "signing_key_secret_reference": "env:LOOPDY_RELAY_SIGNING_KEY",
                }
            )

            class RelayClient:
                def revoke_tenant(self, body):
                    return {
                        "version": 1,
                        "status": "revoked",
                        "id": "TENANT_EXAMPLE",
                        "revision": body["revision"],
                    }

            class RelayProvider(RelayPushProvider):
                def __init__(self):
                    self.client = RelayClient()
                    self.closed = False

                def close(self):
                    self.closed = True

            provider = RelayProvider()
            service = LoopdyService(store, providers={"relay": provider})
            response = service.relay_operation(
                "revoke_tenant",
                {
                    "version": 1,
                    "tenant_id": "TENANT_EXAMPLE",
                    "revision": 1,
                    "idempotency_key": "00000000-0000-5000-8000-000000000001",
                },
            )

            self.assertEqual(response["status"], "revoked")
            self.assertTrue(provider.closed)
            self.assertNotIn("relay", service._providers)
            with self.assertRaisesRegex(ValueError, "disabled"):
                service._provider("relay")

    def test_startup_replays_queued_relay_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            now = int(time.time())
            store.save_relay_config(
                {
                    "base_url": "https://relay.example.invalid",
                    "tenant_id": "TENANT_EXAMPLE",
                    "credential_key_id": "credential_fixture_01",
                    "hmac_secret_reference": "env:LOOPDY_RELAY_HMAC",
                    "signing_key_secret_reference": "env:LOOPDY_RELAY_SIGNING_KEY",
                }
            )
            store.register_relay_device(
                device_id="relay-phone",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=1,
                lease_expires=now + 2_592_000,
                normalized_body={"device_id": "relay-phone", "revision": 1},
                now=now,
            )
            store.acknowledge_relay_sender_keys(
                device_id="relay-phone",
                revision=2,
                sender_key_revision=1,
                acknowledged_sender_key_ids=["sender_key_fixture_01"],
                normalized_body={"device_id": "relay-phone", "revision": 2},
                now=now,
            )
            event = build_event("channel.message", correlation=("startup-retry",))
            store.record_event(event, target="all")
            store.record_device_delivery(
                event_id=event.event_id,
                device_id="relay-phone",
                provider="relay",
                status="queued",
                target_revision=1,
                target_key_id="key_fixture_01",
                target_sender_key_id="sender_key_fixture_01",
            )

            class RelayProvider:
                def __init__(self):
                    self.calls = []

                def select_sender_key_id(self, values):
                    return values[0]

                def send_device(self, device, message, *, delivery_id, idempotency_key):
                    self.calls.append((device["device_id"], delivery_id, idempotency_key))
                    return DeliveryReceipt(delivery_id="startup-delivery")

                def close(self):
                    return None

            provider = RelayProvider()
            service = LoopdyService(store, providers={"relay": provider})
            service._queue.join()

            self.assertEqual(len(provider.calls), 1)
            self.assertEqual(store.list_event_deliveries(event.event_id)[0]["status"], "sent")
            service.close()

    def test_retryable_nonterminal_relay_live_activity_update_remains_pending(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            now = int(time.time())
            store.register_relay_device(
                device_id="relay-phone",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=1,
                lease_expires=now + 2_592_000,
                normalized_body={"device_id": "relay-phone", "revision": 1},
                now=now,
            )
            store.acknowledge_relay_sender_keys(
                device_id="relay-phone",
                revision=2,
                sender_key_revision=1,
                acknowledged_sender_key_ids=["sender_key_fixture_01"],
                normalized_body={"device_id": "relay-phone", "revision": 2},
                now=now,
            )
            store.register_relay_live_activity(
                activity_id="activity-running",
                device_id="relay-phone",
                session_ref=_session_reference("session-running"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": "activity-running", "revision": 1},
            )

            class RelayProvider:
                def send_live_activity(self, **_kwargs):
                    raise DeliveryError("relay_unavailable", status=503)

                def close(self):
                    return None

            service = LoopdyService(store, providers={"relay": RelayProvider()})
            result = service.update_live_activities(
                session_id="session-running",
                profile="default",
                status="running",
                active_session_count=1,
            )

            self.assertEqual(result, {"matched": 1, "delivered": 0, "failed": 1})
            self.assertIsNotNone(store.pending_relay_live_activity_update("activity-running"))
            service.close()

    def test_retryable_relay_delivery_remains_queued_and_retries_exact_coordinate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.register_relay_device(
                device_id="relay-phone",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=1,
                lease_expires=int(time.time()) + 2_592_000,
                normalized_body={"device_id": "relay-phone", "revision": 1},
                now=int(time.time()),
            )
            store.acknowledge_relay_sender_keys(
                device_id="relay-phone",
                revision=2,
                sender_key_revision=1,
                acknowledged_sender_key_ids=["sender_key_fixture_01"],
                normalized_body={"device_id": "relay-phone", "revision": 2},
                now=int(time.time()),
            )

            class RelayProvider:
                def __init__(self):
                    self.calls = []
                    self.outcomes = [RelayOutcomeUnknown("before_acceptance"), DeliveryReceipt(delivery_id="accepted")]

                def select_sender_key_id(self, values):
                    return values[0]

                def send_device(self, device, message, *, delivery_id, idempotency_key):
                    self.calls.append((delivery_id, idempotency_key))
                    result = self.outcomes.pop(0)
                    if isinstance(result, Exception):
                        raise result
                    return result

            provider = RelayProvider()
            service = LoopdyService(store, providers={"relay": provider})
            event = build_event("channel.message", correlation=("relay-retry",))
            first = service.deliver(event, target="all")
            self.assertEqual(first["delivered"], 0)
            self.assertEqual(store.list_event_deliveries(event.event_id)[0]["status"], "queued")
            pending = store.list_event_deliveries(event.event_id)[0]
            self.assertGreater(pending["next_attempt_at"], int(time.time()))
            second = service.deliver(event, target="all")
            self.assertEqual(second["delivered"], 0)
            self.assertEqual(len(provider.calls), 1)
            with store._connect() as connection:
                connection.execute(
                    "UPDATE event_deliveries SET next_attempt_at=0 WHERE event_id=? AND device_id=?",
                    (event.event_id, "relay-phone"),
                )
            third = service.deliver(event, target="all")
            self.assertEqual(third["delivered"], 1)
            self.assertEqual(provider.calls[0], provider.calls[1])
            service.close()

    def test_relay_terminal_live_activity_retry_freezes_request_across_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            now = int(time.time())
            store.register_relay_device(
                device_id="relay-phone",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=1,
                lease_expires=now + 2_592_000,
                normalized_body={"device_id": "relay-phone", "revision": 1},
                now=now,
            )
            store.acknowledge_relay_sender_keys(
                device_id="relay-phone",
                revision=2,
                sender_key_revision=1,
                acknowledged_sender_key_ids=["sender_key_fixture_01"],
                normalized_body={"device_id": "relay-phone", "revision": 2},
                now=now,
            )
            store.register_relay_live_activity(
                activity_id="activity-retry",
                device_id="relay-phone",
                session_ref=_session_reference("session-retry"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": "activity-retry", "revision": 1},
            )

            class RelayLiveProvider:
                def __init__(self, outcome):
                    self.outcome = outcome
                    self.calls = []

                def send_live_activity(self, **update):
                    self.calls.append(dict(update))
                    if isinstance(self.outcome, Exception):
                        raise self.outcome
                    return self.outcome

                def close(self):
                    return None

            first_provider = RelayLiveProvider(RelayOutcomeUnknown("before_acceptance"))
            first_service = LoopdyService(
                store,
                providers={"relay": first_provider},
                timestamp_fn=lambda: now + 1,
            )
            first_service.update_live_activities(
                session_id="session-retry",
                profile="default",
                phase="completed",
                active_session_count=0,
            )
            first_service.close()
            pending = store.pending_relay_live_activity_update("activity-retry")
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertGreater(int(pending["timestamp"]), 0)
            self.assertTrue(pending["delivery_id"])
            self.assertTrue(pending["idempotency_key"])
            self.assertTrue(pending["request_body_json"])

            with store._connect() as connection:
                connection.execute(
                    "UPDATE pending_relay_live_activity_updates SET next_attempt_at=0 "
                    "WHERE activity_id=?",
                    ("activity-retry",),
                )
            second_provider = RelayLiveProvider(DeliveryReceipt(delivery_id="relay-live"))
            second_service = LoopdyService(store, providers={"relay": second_provider})
            second_service._reconcile_relay_live_activity_updates()
            second_service.close()
            self.assertEqual(len(second_provider.calls), 1)
            self.assertEqual(
                second_provider.calls[0]["delivery_id"], first_provider.calls[0]["delivery_id"]
            )
            self.assertEqual(
                second_provider.calls[0]["idempotency_key"], first_provider.calls[0]["idempotency_key"]
            )
            self.assertEqual(
                second_provider.calls[0]["state"].timestamp,
                first_provider.calls[0]["state"].timestamp,
            )

    def test_relay_device_revoke_retries_same_pending_request_after_unknown_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            now = int(time.time())
            store.register_relay_device(
                device_id="relay-phone",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=1,
                lease_expires=now + 2_592_000,
                normalized_body={"device_id": "relay-phone", "revision": 1},
                now=now,
            )

            class RelayClient:
                def __init__(self):
                    self.calls = []
                    self.outcomes = [
                        RelayOutcomeUnknown("before_acceptance"),
                        {"version": 1, "status": "revoked", "id": "relay-phone", "revision": 2},
                    ]

                def revoke_device(self, body):
                    self.calls.append(dict(body))
                    outcome = self.outcomes.pop(0)
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome

            client = RelayClient()

            class RelayProvider:
                def __init__(self):
                    self.client = client

                def close(self):
                    return None

            service = LoopdyService(store, providers={"relay": RelayProvider()})
            with self.assertRaises(RelayOutcomeUnknown):
                service.revoke_device("relay-phone")
            pending = store.pending_relay_operation("device_revoke", "relay-phone")
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertTrue(pending["body_json"])
            service.close()
            service = LoopdyService(store, providers={"relay": RelayProvider()})
            service.revoke_device("relay-phone")
            self.assertEqual(client.calls[0], client.calls[1])
            self.assertTrue(store.get_device("relay-phone")["revoked"])
            self.assertIsNone(store.pending_relay_operation("device_revoke", "relay-phone"))
            service.close()

    def test_relay_tenant_journal_response_reconciles_revoke_and_delete_after_restart(self) -> None:
        for operation, response_status, should_purge in (
            ("revoke_tenant", "revoked", False),
            ("delete_tenant", "deleted", True),
        ):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                store = self._store(directory)
                store.save_relay_config(
                    {
                        "base_url": "https://relay.example.invalid",
                        "tenant_id": "TENANT_EXAMPLE",
                        "credential_key_id": "credential_fixture_01",
                        "hmac_secret_reference": "env:LOOPDY_RELAY_HMAC",
                        "signing_key_secret_reference": "env:LOOPDY_RELAY_SIGNING_KEY",
                    }
                )
                now = int(time.time())
                store.register_relay_device(
                    device_id="relay-phone",
                    recipient_public_key="B" + "A" * 86,
                    recipient_key_id="key_fixture_01",
                    revision=1,
                    lease_expires=now + 2_592_000,
                    normalized_body={"device_id": "relay-phone", "revision": 1},
                    now=now,
                )
                body = {
                    "version": 1,
                    "tenant_id": "TENANT_EXAMPLE",
                    "revision": 2,
                    "idempotency_key": "00000000-0000-5000-8000-000000000002",
                }
                if operation == "delete_tenant":
                    body["confirmation"] = "delete"
                generation = store.relay_config_generation()
                store.save_pending_relay_operation(
                    operation=operation,
                    device_id="TENANT_EXAMPLE",
                    revision=2,
                    idempotency_key=body["idempotency_key"],
                    body=body,
                    relay_generation=generation,
                )
                store.record_relay_operation_response(
                    operation=operation,
                    device_id="TENANT_EXAMPLE",
                    response={
                        "version": 1,
                        "status": response_status,
                        "id": "TENANT_EXAMPLE",
                        "revision": 2,
                    },
                )

                class RelayClient:
                    def close(self):
                        return None

                provider = RelayPushProvider(RelayClient())
                first_service = LoopdyService(store, providers={"relay": provider})
                first_service.close()
                service = LoopdyService(store, providers={"relay": RelayPushProvider(RelayClient())})
                self.assertEqual(service.reconcile_relay_operations(), 1)

                self.assertIsNone(store.pending_relay_operation(operation, "TENANT_EXAMPLE"))
                self.assertEqual(store.provider_mode(), "managed")
                if should_purge:
                    self.assertEqual(store.list_devices(), [])
                    self.assertIsNone(store.load_relay_config())
                else:
                    self.assertTrue(store.get_device("relay-phone")["revoked"])
                service.close()

    def test_relay_alert_retry_reuses_exact_frozen_request_body(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            now = int(time.time())
            store.register_relay_device(
                device_id="relay-phone",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=1,
                lease_expires=now + 2_592_000,
                normalized_body={"device_id": "relay-phone", "revision": 1},
                now=now,
            )
            store.acknowledge_relay_sender_keys(
                device_id="relay-phone",
                revision=2,
                sender_key_revision=1,
                acknowledged_sender_key_ids=["sender_key_fixture_01"],
                normalized_body={"device_id": "relay-phone", "revision": 2},
                now=now,
            )

            class RelayClient:
                def __init__(self):
                    self.prepare_count = 0
                    self.bodies = []

                def select_sender_key_id(self, values):
                    return values[0]

                def prepare_alert(self, **_kwargs):
                    self.prepare_count += 1
                    return {
                        "device_id": "relay-phone",
                        "envelope": {"delivery_id": "frozen-delivery", "ciphertext": "fixture"},
                        "idempotency_key": "00000000-0000-5000-8000-000000000001",
                    }

                def deliver_alert(self, *, request_body=None, **_kwargs):
                    self.bodies.append(json.dumps(request_body, sort_keys=True, separators=(",", ":")).encode())
                    if len(self.bodies) == 1:
                        raise RelayOutcomeUnknown("before_acceptance")
                    return DeliveryReceipt(delivery_id="frozen-delivery")

                def close(self):
                    return None

            client = RelayClient()
            service = LoopdyService(store, providers={"relay": RelayPushProvider(client)})
            event = build_event("channel.message", correlation=("relay-body-retry",))
            service.deliver(event, target="all")
            pending = store.list_event_deliveries(event.event_id)[0]
            self.assertGreater(pending["next_attempt_at"], int(time.time()))
            service.deliver(event, target="all")
            self.assertEqual(len(client.bodies), 1)
            with store._connect() as connection:
                connection.execute(
                    "UPDATE event_deliveries SET next_attempt_at=0 WHERE event_id=? AND device_id=?",
                    (event.event_id, "relay-phone"),
                )
            service.deliver(event, target="all")
            self.assertEqual(client.prepare_count, 1)
            self.assertEqual(client.bodies[0], client.bodies[1])
            service.close()

    def test_live_activity_queue_preserves_lifecycle_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_live_activity(
                session_id="stored",
                live_session_id="live",
                profile="default",
                activity_id="activity",
                push_token="a" * 64,
                token_environment="production",
            )
            provider = _LiveProvider()
            service = LoopdyService(store, providers={"direct": provider})
            self.assertTrue(
                service.enqueue_live_activity_update(
                    session_id="live",
                    profile="default",
                    status="reasoning",
                    detail="Working",
                )
            )
            self.assertTrue(
                service.enqueue_live_activity_update(
                    session_id="live",
                    profile="default",
                    status="completed",
                    detail="Response ready",
                    active_session_count=0,
                )
            )
            service._live_activity_queue.join()
            service.close()
            self.assertEqual(provider.live_calls, ["thinking", "completed"])
            self.assertEqual(store.active_live_activities("live", "default"), [])

    def test_followup_cannot_supersede_pending_terminal_update(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_live_activity(
                session_id="stored",
                live_session_id="live",
                profile="default",
                activity_id="activity",
                push_token="a" * 64,
                token_environment="production",
            )
            provider = _LiveProvider(
                [DeliveryError("transport_error", retryable=True) for _ in range(3)]
            )
            service = LoopdyService(
                store,
                providers={"direct": provider},
                sleep_fn=lambda _delay: None,
                jitter_fn=lambda: 0,
            )
            service.update_live_activities(
                session_id="live",
                profile="default",
                status="completed",
                detail="Response ready",
                active_session_count=0,
            )
            self.assertEqual(len(store.pending_live_activity_updates()), 1)

            result = service.update_live_activities(
                session_id="live",
                profile="default",
                status="reasoning",
                detail="Working again",
            )

            self.assertEqual(result, {"matched": 1, "delivered": 0, "failed": 0})
            self.assertEqual(
                provider.live_calls,
                ["completed", "completed", "completed"],
            )
            self.assertEqual(len(store.pending_live_activity_updates()), 1)
            self.assertEqual(len(store.active_live_activities("live", "default")), 1)
            service.close()

    def test_later_terminal_update_does_not_replace_pending_terminal_update(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_live_activity(
                session_id="stored",
                live_session_id="live",
                profile="default",
                activity_id="activity",
                push_token="a" * 64,
                token_environment="production",
            )
            provider = _LiveProvider(
                [DeliveryError("transport_error", retryable=True) for _ in range(3)]
            )
            service = LoopdyService(
                store,
                providers={"direct": provider},
                sleep_fn=lambda _delay: None,
                jitter_fn=lambda: 0,
            )
            service.update_live_activities(
                session_id="live",
                profile="default",
                status="completed",
                detail="Response ready",
                active_session_count=0,
            )

            result = service.update_live_activities(
                session_id="live",
                profile="default",
                status="failed",
                detail="Late terminal update",
                active_session_count=0,
            )

            self.assertEqual(result, {"matched": 1, "delivered": 0, "failed": 0})
            self.assertEqual(
                provider.live_calls,
                ["completed", "completed", "completed"],
            )
            self.assertEqual(len(store.pending_live_activity_updates()), 1)
            self.assertEqual(len(store.active_live_activities("live", "default")), 1)
            service.close()

    def test_live_activity_timestamp_remains_monotonic_after_service_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_live_activity(
                session_id="stored",
                live_session_id="live",
                profile="default",
                activity_id="activity",
                push_token="a" * 64,
                token_environment="production",
            )
            first_provider = _LiveProvider()
            first = LoopdyService(
                store,
                providers={"direct": first_provider},
                timestamp_fn=lambda: 1_700_000_000,
            )
            first.update_live_activities(
                session_id="live",
                profile="default",
                status="reasoning",
                detail="Working",
            )
            first.close()

            second_provider = _LiveProvider()
            second = LoopdyService(
                self._store(directory),
                providers={"direct": second_provider},
                timestamp_fn=lambda: 1_700_000_000,
            )
            second.update_live_activities(
                session_id="live",
                profile="default",
                status="failed",
                detail="The agent stopped with an error",
                active_session_count=0,
            )

            self.assertEqual(first_provider.live_updates[0]["timestamp"], 1_700_000_000)
            self.assertEqual(second_provider.live_updates[0]["timestamp"], 1_700_000_001)
            self.assertEqual(second.store.active_live_activities("live", "default"), [])
            second.close()

    def test_terminal_live_activity_send_serializes_across_service_instances(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_live_activity(
                session_id="stored",
                live_session_id="live",
                profile="default",
                activity_id="activity",
                push_token="a" * 64,
                token_environment="production",
            )
            terminal_started = threading.Event()
            release_terminal = threading.Event()
            network_sends: list[tuple[str, int]] = []

            class _BlockingTerminalProvider(_LiveProvider):
                def send_live_activity(self, token, **kwargs) -> DeliveryReceipt:
                    terminal_started.set()
                    self.assert_release(release_terminal)
                    network_sends.append((str(kwargs["phase"]), int(kwargs["timestamp"])))
                    return DeliveryReceipt(delivery_id="terminal")

                @staticmethod
                def assert_release(event: threading.Event) -> None:
                    if not event.wait(timeout=2):
                        raise AssertionError("terminal send was not released")

            class _RecordingProvider(_LiveProvider):
                def send_live_activity(self, token, **kwargs) -> DeliveryReceipt:
                    network_sends.append((str(kwargs["phase"]), int(kwargs["timestamp"])))
                    return DeliveryReceipt(delivery_id="newer")

            terminal_service = LoopdyService(
                store,
                providers={"direct": _BlockingTerminalProvider()},
                timestamp_fn=lambda: 100,
            )
            newer_service = LoopdyService(
                self._store(directory),
                providers={"direct": _RecordingProvider()},
                timestamp_fn=lambda: 100,
            )
            terminal_result: list[dict[str, int]] = []
            newer_result: list[dict[str, int]] = []
            terminal_thread = threading.Thread(
                target=lambda: terminal_result.append(
                    terminal_service.update_live_activities(
                        session_id="live",
                        profile="default",
                        status="failed",
                        detail="The agent stopped with an error",
                        active_session_count=0,
                    )
                )
            )
            newer_thread = threading.Thread(
                target=lambda: newer_result.append(
                    newer_service.update_live_activities(
                        session_id="live",
                        profile="default",
                        status="reasoning",
                        detail="Working",
                    )
                )
            )

            terminal_thread.start()
            self.assertTrue(terminal_started.wait(timeout=1))
            newer_thread.start()
            time.sleep(0.05)
            self.assertEqual(network_sends, [])
            release_terminal.set()
            terminal_thread.join(timeout=2)
            newer_thread.join(timeout=2)

            self.assertEqual(network_sends, [("failed", 100)])
            self.assertEqual(terminal_result, [{"matched": 1, "delivered": 1, "failed": 0}])
            self.assertEqual(newer_result, [{"matched": 1, "delivered": 0, "failed": 0}])
            terminal_service.close()
            newer_service.close()

    def test_deferred_completion_serializes_with_live_followup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_live_activity(
                session_id="stored",
                live_session_id="live",
                profile="default",
                activity_id="activity",
                push_token="a" * 64,
                token_environment="production",
            )
            completion_started = threading.Event()
            release_completion = threading.Event()
            network_sends: list[tuple[str, int]] = []

            class _BlockingCompletionProvider(_LiveProvider):
                def send_live_activity(self, token, **kwargs) -> DeliveryReceipt:
                    completion_started.set()
                    if not release_completion.wait(timeout=2):
                        raise AssertionError("deferred completion was not released")
                    network_sends.append((str(kwargs["phase"]), int(kwargs["timestamp"])))
                    return DeliveryReceipt(delivery_id="completed")

            class _FollowupProvider(_LiveProvider):
                def send_live_activity(self, token, **kwargs) -> DeliveryReceipt:
                    network_sends.append((str(kwargs["phase"]), int(kwargs["timestamp"])))
                    return DeliveryReceipt(delivery_id="followup")

            completion_service = LoopdyService(
                store,
                providers={"direct": _BlockingCompletionProvider()},
                timestamp_fn=lambda: 100,
            )
            followup_service = LoopdyService(
                self._store(directory),
                providers={"direct": _FollowupProvider()},
                timestamp_fn=lambda: 100,
            )
            store.defer_live_activity_update(
                activity_id="activity",
                status="completed",
                detail="Response ready",
                tool_name="",
                active_session_count=0,
                delay_seconds=0,
                failure="transport_error",
            )
            completion_thread = threading.Thread(
                target=completion_service._reconcile_live_activity_updates
            )
            followup_result: list[dict[str, int]] = []
            followup_thread = threading.Thread(
                target=lambda: followup_result.append(
                    followup_service.update_live_activities(
                        session_id="live",
                        profile="default",
                        status="reasoning",
                        detail="Working again",
                    )
                )
            )

            completion_thread.start()
            self.assertTrue(completion_started.wait(timeout=1))
            followup_thread.start()
            time.sleep(0.05)
            sends_before_release = list(network_sends)
            release_completion.set()
            completion_thread.join(timeout=2)
            followup_thread.join(timeout=2)

            self.assertEqual(sends_before_release, [])
            self.assertEqual(network_sends, [("completed", 100)])
            self.assertEqual(followup_result, [{"matched": 1, "delivered": 0, "failed": 0}])
            self.assertIsNone(store.pending_live_activity_update("activity"))
            self.assertEqual(store.active_live_activities("live", "default"), [])
            completion_service.close()
            followup_service.close()

    def test_provider_switch_waits_for_inflight_terminal_send(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_live_activity(
                session_id="stored",
                live_session_id="live",
                profile="default",
                activity_id="activity",
                push_token="a" * 64,
                token_environment="production",
            )
            provider = _BlockingLiveProvider(fail_if_closed=True)
            service = LoopdyService(store, providers={"direct": provider})
            delivery_result: dict[str, object] = {}

            def deliver() -> None:
                delivery_result.update(
                    service.update_live_activities(
                        session_id="live",
                        profile="default",
                        status="completed",
                        detail="Response ready",
                        active_session_count=0,
                    )
                )

            delivery_thread = threading.Thread(target=deliver)
            delivery_thread.start()
            self.assertTrue(provider.started.wait(timeout=2))
            switch_thread = threading.Thread(target=lambda: service.set_provider_mode("managed"))
            switch_thread.start()
            time.sleep(0.1)
            switch_waited = switch_thread.is_alive()
            provider_was_open = not provider.closed
            provider.release.set()
            delivery_thread.join(timeout=3)
            switch_thread.join(timeout=3)

            self.assertTrue(switch_waited)
            self.assertTrue(provider_was_open)
            self.assertFalse(delivery_thread.is_alive())
            self.assertFalse(switch_thread.is_alive())
            self.assertEqual(delivery_result.get("delivered"), 1)
            self.assertTrue(provider.closed)
            self.assertEqual(store.pending_live_activity_updates(), [])
            self.assertEqual(store.active_live_activities("live", "default"), [])

    def test_terminal_live_activity_retry_survives_service_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_live_activity(
                session_id="stored",
                live_session_id="live",
                profile="default",
                activity_id="activity",
                push_token="a" * 64,
                token_environment="production",
            )
            failing = _LiveProvider(
                [DeliveryError("transport_error", retryable=True) for _ in range(3)]
            )
            first = LoopdyService(
                store,
                providers={"direct": failing},
                sleep_fn=lambda _delay: None,
                jitter_fn=lambda: 0,
            )
            first.update_live_activities(
                session_id="live",
                profile="default",
                status="completed",
                detail="Response ready",
                active_session_count=0,
            )
            first.close()
            self.assertEqual(len(store.pending_live_activity_updates()), 1)

            recovered = _LiveProvider()
            second = LoopdyService(store, providers={"direct": recovered})
            deadline = time.monotonic() + 3
            while store.pending_live_activity_updates() and time.monotonic() < deadline:
                time.sleep(0.05)
            second.close()

            self.assertEqual(recovered.live_calls, ["completed"])
            self.assertEqual(store.pending_live_activity_updates(), [])
            self.assertEqual(store.active_live_activities("live", "default"), [])

    def test_live_activity_close_waits_for_full_queue_before_closing_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_live_activity(
                session_id="stored",
                live_session_id="live",
                profile="default",
                activity_id="activity",
                push_token="a" * 64,
                token_environment="production",
            )
            provider = _BlockingLiveProvider()
            service = LoopdyService(store, providers={"direct": provider}, queue_size=1)
            self.assertTrue(
                service.enqueue_live_activity_update(
                    session_id="live", profile="default", status="reasoning", detail="Working"
                )
            )
            self.assertTrue(provider.started.wait(timeout=2))
            self.assertTrue(
                service.enqueue_live_activity_update(
                    session_id="live", profile="default", status="replying", detail="Writing"
                )
            )

            close_thread = threading.Thread(target=service.close)
            close_thread.start()
            time.sleep(0.1)
            self.assertTrue(close_thread.is_alive())
            self.assertFalse(provider.closed)
            self.assertFalse(
                service.enqueue_live_activity_update(
                    session_id="live", profile="default", status="failed", detail="Late"
                )
            )
            provider.release.set()
            close_thread.join(timeout=3)

            self.assertFalse(close_thread.is_alive())
            worker = service._live_activity_worker
            self.assertIsNotNone(worker)
            assert worker is not None
            self.assertFalse(worker.is_alive())
            self.assertTrue(provider.closed)
            self.assertEqual(provider.live_calls, ["thinking", "running"])
            self.assertEqual(provider.calls_after_close, [False, False])

    def test_terminal_live_activity_ends_only_after_successful_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.upsert_live_activity(
                session_id="stored",
                live_session_id="live",
                profile="default",
                activity_id="activity",
                push_token="a" * 64,
                token_environment="production",
            )
            provider = _LiveProvider()
            service = LoopdyService(store, providers={"direct": provider})
            result = service.update_live_activities(
                session_id="live",
                profile="default",
                status="failed",
                detail="The agent stopped with an error",
                active_session_count=0,
            )
            self.assertEqual(result["delivered"], 1)
            self.assertEqual(store.active_live_activities("live", "default"), [])


if __name__ == "__main__":
    unittest.main()
