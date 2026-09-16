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



    def test_supported_device_providers_coexist_without_relay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            self._configure_apns(store, directory)
            managed, direct = _Provider(), _Provider()
            service = LoopdyService(store, providers={"managed": managed, "direct": direct})
            self.addCleanup(service.close)
            service.register_device(device_id="managed-phone", endpoint_id="ExponentPushToken[fixture-managed]", provider="managed")
            service.register_device(device_id="direct-phone", endpoint_id="a" * 64, provider="direct")
            result = service.deliver(build_event("approval.required", correlation=("supported-providers",)), target="all")
            self.assertTrue(result["success"])
            self.assertEqual(result["delivered"], 2)
            self.assertEqual(len(managed.calls), 1)
            self.assertEqual(len(direct.calls), 1)
            self.assertEqual({item["provider"] for item in store.list_event_deliveries(result["event_id"])}, {"managed", "direct"})

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

    def test_direct_live_activity_phase_preserves_sanitized_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            direct = _LiveProvider()
            session_id = "session-sanitized"
            store.upsert_live_activity(session_id=session_id, live_session_id=session_id, profile="default", activity_id="activity-sanitized", push_token="a" * 64, token_environment="production")
            service = LoopdyService(store, providers={"direct": direct}, timestamp_fn=lambda: int(time.time()) + 10)
            self.addCleanup(service.close)
            result = service.update_live_activities(session_id=session_id, profile="default", phase="running", detail="private detail", tool_name="private tool", active_session_count=0)
            self.assertEqual(result, {"matched": 1, "delivered": 1, "failed": 0})
            serialized = str(direct.live_updates[0])
            self.assertNotIn("private detail", serialized)
            self.assertNotIn("private tool", serialized)
            terminal = service.update_live_activities(session_id=session_id, profile="default", phase="completed", detail="must stay local", tool_name="must stay local", active_session_count=0)
            self.assertEqual(terminal, {"matched": 1, "delivered": 1, "failed": 0})
            self.assertEqual(store.active_live_activities(session_id, "default"), [])



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
