from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from loopdy_plugin.events import build_event
from loopdy_plugin.presentation import shape_notification
from loopdy_plugin.provider import DeliveryError, DeliveryReceipt, LiveActivityState
from loopdy_plugin.relay_client import RelayOutcomeUnknown, RelayPushProvider
from loopdy_plugin.service import LoopdyService, _session_reference
from loopdy_plugin.store import LoopdyStore


CONFIG = {
    "base_url": "https://relay.example.invalid",
    "tenant_id": "TENANT_EXAMPLE",
    "credential_key_id": "credential_fixture_01",
    "hmac_secret_reference": "env:LOOPDY_RELAY_HMAC",
    "signing_key_secret_reference": "env:LOOPDY_RELAY_SIGNING_KEY",
}


def _seed_relay(store: LoopdyStore, *, device_id: str = "relay-phone") -> None:
    now = int(time.time())
    store.save_relay_config(CONFIG)
    store.register_relay_device(
        device_id=device_id,
        recipient_public_key="B" + "A" * 86,
        recipient_key_id="key_fixture_01",
        revision=1,
        lease_expires=now + 2_592_000,
        normalized_body={"device_id": device_id, "revision": 1},
        now=now,
    )
    store.acknowledge_relay_sender_keys(
        device_id=device_id,
        revision=2,
        sender_key_revision=1,
        acknowledged_sender_key_ids=["sender_key_fixture_01"],
        normalized_body={"device_id": device_id, "revision": 2},
        now=now,
    )


class Task5Round3Tests(unittest.TestCase):
    def test_operation_journal_rejects_different_request_for_same_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            first = {
                "version": 1,
                "device_id": "relay-phone",
                "revision": 1,
                "idempotency_key": "00000000-0000-5000-8000-000000000001",
            }
            store.save_pending_relay_operation(
                operation="device_revoke",
                device_id="relay-phone",
                revision=1,
                idempotency_key=first["idempotency_key"],
                body=first,
            )

            with self.assertRaisesRegex(ValueError, "conflict"):
                store.save_pending_relay_operation(
                    operation="device_revoke",
                    device_id="relay-phone",
                    revision=2,
                    idempotency_key="00000000-0000-5000-8000-000000000002",
                    body={**first, "revision": 2},
                )

    def test_concurrent_operation_reconcilers_claim_one_remote_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            body = {
                "version": 1,
                "device_id": "relay-phone",
                "revision": 3,
                "idempotency_key": "00000000-0000-5000-8000-000000000003",
            }
            store.save_pending_relay_operation(
                operation="device_revoke",
                device_id="relay-phone",
                revision=3,
                idempotency_key=body["idempotency_key"],
                body=body,
                relay_generation=store.relay_config_generation(),
            )

            class Client:
                def __init__(self) -> None:
                    self.calls = 0
                    self.lock = threading.Lock()

                def revoke_device(self, request):
                    with self.lock:
                        self.calls += 1
                    time.sleep(0.15)
                    return {
                        "version": 1,
                        "status": "revoked",
                        "id": request["device_id"],
                        "revision": request["revision"],
                    }

            client = Client()
            provider = RelayPushProvider(client)
            service = LoopdyService(store, providers={"relay": provider})
            failures: list[BaseException] = []

            def reconcile() -> None:
                try:
                    service.reconcile_relay_operations()
                except BaseException as error:
                    failures.append(error)

            first = threading.Thread(target=reconcile)
            second = threading.Thread(target=reconcile)
            first.start()
            second.start()
            first.join(timeout=3)
            second.join(timeout=3)

            self.assertEqual(failures, [])
            self.assertEqual(client.calls, 1)
            self.assertIsNone(store.pending_relay_operation("device_revoke", "relay-phone"))
            service.close()

    def test_synchronous_operation_claim_does_not_lease_unrelated_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store, device_id="relay-phone-a")
            now = int(time.time())
            store.register_relay_device(
                device_id="relay-phone-b", recipient_public_key="C" + "A" * 86,
                recipient_key_id="key_fixture_02", revision=1,
                lease_expires=now + 2_592_000,
                normalized_body={"device_id": "relay-phone-b", "revision": 1}, now=now,
            )
            store.acknowledge_relay_sender_keys(
                device_id="relay-phone-b", revision=2, sender_key_revision=1,
                acknowledged_sender_key_ids=["sender_key_fixture_01"],
                normalized_body={"device_id": "relay-phone-b", "revision": 2}, now=now,
            )
            body = lambda device, revision: {
                "version": 1,
                "device_id": device,
                "revision": revision,
                "idempotency_key": f"00000000-0000-5000-8000-{revision:012d}",
            }
            for device, revision in (("relay-phone-a", 3), ("relay-phone-b", 3)):
                request = body(device, revision)
                store.save_pending_relay_operation(
                    operation="revoke_device", device_id=device, revision=revision,
                    idempotency_key=request["idempotency_key"], body=request,
                    relay_generation=store.relay_config_generation(),
                )

            class Client:
                calls = 0

                def revoke_device(self, request):
                    self.calls += 1
                    return {"version": 1, "status": "revoked", "id": request["device_id"], "revision": request["revision"]}

            client = Client()
            service = LoopdyService(store, providers={"relay": RelayPushProvider(client)})
            self.assertEqual(service.reconcile_relay_operations(), 2)
            self.assertEqual(client.calls, 2)
            self.assertEqual(store.pending_relay_operations(), [])
            service.close()

    def test_response_ready_operation_claim_is_held_through_local_apply(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            body = {
                "version": 1,
                "device_id": "relay-phone",
                "revision": 3,
                "idempotency_key": "00000000-0000-5000-8000-000000000007",
            }
            store.save_pending_relay_operation(
                operation="device_revoke",
                device_id="relay-phone",
                revision=3,
                idempotency_key=body["idempotency_key"],
                body=body,
                relay_generation=store.relay_config_generation(),
            )
            store.record_relay_operation_response(
                operation="device_revoke",
                device_id="relay-phone",
                response={"version": 1, "status": "revoked", "id": "relay-phone", "revision": 3},
            )
            service = LoopdyService(store)
            started = threading.Event()
            release = threading.Event()
            applies = 0
            original_apply = service._apply_relay_operation

            def apply_once(*args, **kwargs):
                nonlocal applies
                applies += 1
                started.set()
                release.wait(timeout=2)
                return original_apply(*args, **kwargs)

            service._apply_relay_operation = apply_once
            result: list[dict] = []
            errors: list[BaseException] = []

            def finish() -> None:
                try:
                    result.append(service.relay_operation("device_revoke", body))
                except BaseException as error:
                    errors.append(error)

            worker = threading.Thread(target=finish)
            worker.start()
            self.assertTrue(started.wait(timeout=2))
            with self.assertRaisesRegex(DeliveryError, "relay_operation_pending"):
                service.relay_operation("device_revoke", body)
            release.set()
            worker.join(timeout=3)
            self.assertEqual(errors, [])
            self.assertEqual(applies, 1)
            self.assertEqual(result[0]["status"], "revoked")
            self.assertIsNone(store.pending_relay_operation("device_revoke", "relay-phone"))
            service.close()

    def test_invalid_route_is_rejected_before_operation_journal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            now = int(time.time())
            body = {
                "version": 1,
                "activity_id": "activity-invalid-route",
                "device_id": "relay-phone",
                "session_ref": "c2Vzc2lvbg",
                "push_token": "aa",
                "environment": "production",
                "topic": "com.example.app.push-type.liveactivity",
                "revision": 1,
                "timestamp": now,
                "lease_expires": now + 60,
                "idempotency_key": "00000000-0000-5000-8000-000000000008",
            }
            service = LoopdyService(store)
            with self.assertRaisesRegex(ValueError, "topic"):
                service.relay_operation("register_live_activity", body)
            self.assertIsNone(
                store.pending_relay_operation("register_live_activity", "activity-invalid-route")
            )
            service.close()

    def test_retryable_operation_is_due_later_and_4xx_becomes_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            body = {
                "version": 1,
                "device_id": "relay-phone",
                "revision": 3,
                "idempotency_key": "00000000-0000-5000-8000-000000000004",
            }
            store.save_pending_relay_operation(
                operation="device_revoke",
                device_id="relay-phone",
                revision=3,
                idempotency_key=body["idempotency_key"],
                body=body,
                relay_generation=store.relay_config_generation(),
            )

            class Client:
                calls = 0

                def revoke_device(self, _request):
                    self.calls += 1
                    raise DeliveryError("relay_rejected", status=400)

            client = Client()
            service = LoopdyService(store, providers={"relay": RelayPushProvider(client)})
            service.reconcile_relay_operations()
            service.reconcile_relay_operations()
            pending = store.pending_relay_operation("device_revoke", "relay-phone")
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertTrue(pending["terminal"])
            self.assertEqual(client.calls, 1)
            service.close()

    def test_retryable_relay_operation_wakes_idle_recovery_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)

            class Client:
                calls = 0

                def revoke_device(self, request):
                    self.calls += 1
                    if self.calls == 1:
                        raise RelayOutcomeUnknown("before_acceptance")
                    return {
                        "version": 1,
                        "status": "revoked",
                        "id": request["device_id"],
                        "revision": request["revision"],
                    }

            client = Client()
            service = LoopdyService(store, providers={"relay": RelayPushProvider(client)})
            body = {
                "version": 1,
                "device_id": "relay-phone",
                "revision": 3,
                "idempotency_key": "00000000-0000-5000-8000-000000000005",
            }
            with self.assertRaises(RelayOutcomeUnknown):
                service.relay_operation("device_revoke", body)

            deadline = time.time() + 3
            while time.time() < deadline and store.pending_relay_operation(
                "device_revoke", "relay-phone"
            ) is not None:
                time.sleep(0.05)
            self.assertIsNone(store.pending_relay_operation("device_revoke", "relay-phone"))
            self.assertEqual(client.calls, 2)
            service.close()

    def test_config_replacement_quarantines_pending_operation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.save_relay_config(CONFIG)
            body = {
                "version": 1,
                "device_id": "relay-phone",
                "revision": 1,
                "idempotency_key": "00000000-0000-5000-8000-000000000006",
            }
            store.save_pending_relay_operation(
                operation="device_revoke",
                device_id="relay-phone",
                revision=1,
                idempotency_key=body["idempotency_key"],
                body=body,
                relay_generation=store.relay_config_generation(),
            )
            store.save_relay_config({**CONFIG, "credential_key_id": "credential_fixture_02"})
            self.assertIsNone(store.pending_relay_operation("device_revoke", "relay-phone"))

    def test_startup_recovery_drains_more_than_one_hundred_queued_alerts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            for index in range(101):
                event = build_event("channel.message", correlation=("round3", index))
                store.record_event(event, target="all")
                store.record_device_delivery(
                    event_id=event.event_id,
                    device_id="relay-phone",
                    provider="relay",
                    status="queued",
                    target_revision=2,
                    target_generation=store.relay_config_generation(),
                    target_key_id="key_fixture_01",
                    target_sender_key_id="sender_key_fixture_01",
                )

            class Provider:
                def __init__(self) -> None:
                    self.calls = 0
                    self.lock = threading.Lock()

                def select_sender_key_id(self, values):
                    return values[0]

                def send_device(self, **kwargs):
                    with self.lock:
                        self.calls += 1
                    return DeliveryReceipt(delivery_id=kwargs["delivery_id"])

                def close(self):
                    return None

            provider = Provider()
            service = LoopdyService(store, providers={"relay": provider})
            deadline = time.time() + 5
            while time.time() < deadline and provider.calls < 101:
                time.sleep(0.05)
            self.assertEqual(provider.calls, 101)
            service.close()

    def test_queued_alert_retries_unknown_outcome_while_service_stays_alive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            event = build_event("channel.message", correlation=("live-retry",))
            store.record_event(event, target="all")
            store.record_device_delivery(
                event_id=event.event_id,
                device_id="relay-phone",
                provider="relay",
                status="queued",
                target_revision=2,
                target_generation=store.relay_config_generation(),
            )

            class Provider:
                def __init__(self) -> None:
                    self.calls = 0

                def select_sender_key_id(self, values):
                    return values[0]

                def send_device(self, **kwargs):
                    self.calls += 1
                    if self.calls == 1:
                        raise RelayOutcomeUnknown("before_acceptance")
                    return DeliveryReceipt(delivery_id=kwargs["delivery_id"])

                def close(self):
                    return None

            provider = Provider()
            service = LoopdyService(store, providers={"relay": provider})
            deadline = time.time() + 5
            while time.time() < deadline and provider.calls < 2:
                time.sleep(0.05)
            self.assertGreaterEqual(provider.calls, 2)
            self.assertEqual(store.list_event_deliveries(event.event_id)[0]["status"], "sent")
            service.close()

    def test_concurrent_first_alert_admission_preserves_one_frozen_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            event = build_event("channel.message", correlation=("first-admission",))
            barrier = threading.Barrier(2)
            send_started = threading.Event()
            send_release = threading.Event()
            seen: list[dict] = []
            seen_lock = threading.Lock()

            class Provider(RelayPushProvider):
                def __init__(self, marker: str) -> None:
                    super().__init__(object())
                    self.marker = marker
                    self.calls = 0

                def select_sender_key_id(self, values):
                    return values[0]

                def prepare_device(self, device, message, *, delivery_id, idempotency_key):
                    barrier.wait(timeout=2)
                    return {
                        "device_id": device["device_id"],
                        "envelope": {"marker": self.marker},
                        "idempotency_key": idempotency_key,
                    }

                def send_device(self, device, message, *, delivery_id, idempotency_key, request_body=None):
                    self.calls += 1
                    with seen_lock:
                        seen.append(dict(request_body or {}))
                    send_started.set()
                    send_release.wait(timeout=2)
                    return DeliveryReceipt(delivery_id=delivery_id)

            first = Provider("first")
            second = Provider("second")
            services = [
                LoopdyService(store, providers={"relay": first}),
                LoopdyService(store, providers={"relay": second}),
            ]
            failures: list[BaseException] = []

            def deliver(service: LoopdyService) -> None:
                try:
                    service.deliver(event, target="all")
                except BaseException as error:
                    failures.append(error)

            threads = [threading.Thread(target=deliver, args=(service,)) for service in services]
            for thread in threads:
                thread.start()
            self.assertTrue(send_started.wait(timeout=2))
            in_flight = store.list_event_deliveries(event.event_id)[0]
            self.assertEqual(
                in_flight["relay_request_body_json"],
                json.dumps(seen[0], sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            )
            send_release.set()
            for thread in threads:
                thread.join(timeout=3)

            self.assertEqual(failures, [])
            self.assertEqual(first.calls + second.calls, 1)
            self.assertEqual(len(seen), 1)
            self.assertIn(seen[0]["envelope"]["marker"], {"first", "second"})
            row = store.list_event_deliveries(event.event_id)[0]
            self.assertEqual(row["status"], "sent")
            self.assertEqual(row["attempts"], 1)
            for service in services:
                service.close()

    def test_old_relay_send_cannot_resurrect_sent_after_reregistration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            started = threading.Event()
            release = threading.Event()

            class Provider:
                def select_sender_key_id(self, values):
                    return values[0]

                def send_device(self, **kwargs):
                    started.set()
                    release.wait(timeout=3)
                    return DeliveryReceipt(delivery_id=kwargs["delivery_id"])

                def close(self):
                    return None

            service = LoopdyService(store, providers={"relay": Provider()})
            event = build_event("channel.message", correlation=("old-send",))
            thread = threading.Thread(target=lambda: service.deliver(event, target="all"))
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            now = int(time.time())
            store.register_relay_device(
                device_id="relay-phone",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=3,
                lease_expires=now + 2_592_000,
                normalized_body={"device_id": "relay-phone", "revision": 3},
                now=now,
            )
            store.acknowledge_relay_sender_keys(
                device_id="relay-phone",
                revision=4,
                sender_key_revision=1,
                acknowledged_sender_key_ids=["sender_key_fixture_01"],
                normalized_body={"device_id": "relay-phone", "revision": 4},
                now=now,
            )
            release.set()
            thread.join(timeout=3)
            row = store.list_event_deliveries(event.event_id)[0]
            self.assertNotEqual(row["status"], "sent")
            self.assertEqual(row["failure"], "relay_target_changed")
            service.close()

    def test_closing_service_rejects_provider_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = LoopdyService(LoopdyStore(Path(directory) / "loopdy.sqlite3"))
            service._closing = True
            with self.assertRaisesRegex(DeliveryError, "service_closing"):
                service._provider("managed")
            self.assertNotIn("managed", service._providers)
            service._closing = False
            service.close()

    def test_stale_live_activity_clear_cannot_delete_new_owner_pending_row(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            now = int(time.time())
            store.register_relay_live_activity(
                activity_id="activity-round3",
                device_id="relay-phone",
                session_ref=_session_reference("session-round3"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": "activity-round3", "revision": 1},
            )
            store.defer_relay_live_activity_update(
                activity_id="activity-round3",
                status="running",
                detail="",
                tool_name="",
                active_session_count=1,
                delay_seconds=0,
                failure="",
                timestamp=now + 1,
                delivery_id="old-delivery",
                idempotency_key="old-key",
                request_body={"device_id": "relay-phone", "state": {"timestamp": now + 1}},
                expected_device_id="relay-phone",
                expected_session_ref=_session_reference("session-round3"),
                expected_revision=1,
                expected_lease_expires=now + 28_800,
                expected_relay_generation=store.relay_config_generation(),
            )
            store.register_relay_live_activity(
                activity_id="activity-round3",
                device_id="relay-phone",
                session_ref=_session_reference("session-round3-new"),
                revision=2,
                timestamp=now + 2,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": "activity-round3", "revision": 2},
            )
            store.defer_relay_live_activity_update(
                activity_id="activity-round3",
                status="running",
                detail="",
                tool_name="",
                active_session_count=1,
                delay_seconds=0,
                failure="",
                timestamp=now + 3,
                delivery_id="new-delivery",
                idempotency_key="new-key",
                request_body={"device_id": "relay-phone", "state": {"timestamp": now + 3}},
                expected_device_id="relay-phone",
                expected_session_ref=_session_reference("session-round3-new"),
                expected_revision=2,
                expected_lease_expires=now + 28_800,
                expected_relay_generation=store.relay_config_generation(),
            )

            removed = store.clear_pending_relay_live_activity_update(
                "activity-round3",
                expected_device_id="relay-phone",
                expected_session_ref=_session_reference("session-round3"),
                expected_revision=1,
                expected_lease_expires=now + 28_800,
                expected_relay_generation=store.relay_config_generation(),
            )
            self.assertFalse(removed)
            self.assertEqual(
                store.pending_relay_live_activity_update("activity-round3")["delivery_id"],
                "new-delivery",
            )

    def test_relay_device_revoke_cancels_alert_and_live_activity_work(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            now = int(time.time())
            event = build_event("channel.message", correlation=("revoke-cancel",))
            store.record_event(event, target="all")
            store.record_device_delivery(
                event_id=event.event_id,
                device_id="relay-phone",
                provider="relay",
                status="queued",
                target_revision=2,
                target_generation=store.relay_config_generation(),
            )
            store.register_relay_live_activity(
                activity_id="activity-revoke",
                device_id="relay-phone",
                session_ref=_session_reference("session-revoke"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": "activity-revoke", "revision": 1},
            )
            store.defer_relay_live_activity_update(
                activity_id="activity-revoke",
                status="running",
                detail="",
                tool_name="",
                active_session_count=1,
                delay_seconds=0,
                failure="",
                timestamp=now + 1,
                delivery_id="revoke-delivery",
                idempotency_key="revoke-key",
                request_body={"device_id": "relay-phone"},
            )
            store.revoke_relay_device(
                device_id="relay-phone",
                revision=3,
                normalized_body={"device_id": "relay-phone", "revision": 3},
                now=now + 2,
            )
            self.assertEqual(store.list_event_deliveries(event.event_id)[0]["status"], "failed")
            self.assertIsNone(store.pending_relay_live_activity_update("activity-revoke"))
            self.assertEqual(store.active_relay_live_activities(_session_reference("session-revoke")), [])

    def test_relay_live_activity_revoke_terminalizes_pending_row(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            now = int(time.time())
            store.register_relay_live_activity(
                activity_id="activity-revoke-row",
                device_id="relay-phone",
                session_ref=_session_reference("session-revoke-row"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": "activity-revoke-row", "revision": 1},
            )
            store.defer_relay_live_activity_update(
                activity_id="activity-revoke-row",
                status="running",
                detail="",
                tool_name="",
                active_session_count=1,
                delay_seconds=0,
                failure="",
                timestamp=now + 1,
                delivery_id="row-delivery",
                idempotency_key="row-key",
                request_body={"device_id": "relay-phone"},
            )
            store.revoke_relay_live_activity(
                activity_id="activity-revoke-row",
                revision=2,
                timestamp=now + 2,
                normalized_body={"activity_id": "activity-revoke-row", "revision": 2},
            )
            self.assertIsNone(store.pending_relay_live_activity_update("activity-revoke-row"))

    def test_live_activity_pending_attempts_become_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            now = int(time.time())
            store.register_relay_live_activity(
                activity_id="activity-attempts",
                device_id="relay-phone",
                session_ref=_session_reference("session-attempts"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": "activity-attempts", "revision": 1},
            )
            for attempt in range(6):
                store.defer_relay_live_activity_update(
                    activity_id="activity-attempts",
                    status="running",
                    detail="",
                    tool_name="",
                    active_session_count=1,
                    delay_seconds=0,
                    failure="relay unavailable",
                    timestamp=now + 1,
                    delivery_id="attempt-delivery",
                    idempotency_key="attempt-key",
                    request_body={"device_id": "relay-phone"},
                )
            row = store.pending_relay_live_activity_update("activity-attempts")
            self.assertIsNotNone(row)
            assert row is not None
            self.assertTrue(row["terminal"])

    def test_live_activity_startup_pending_scan_is_bounded(self) -> None:
        class BoundedStore(LoopdyStore):
            def __init__(self, path):
                self.pending_limits = []
                super().__init__(path)

            def has_pending_relay_live_activity_updates(self):
                self.pending_limits.append(1)
                return super().has_pending_relay_live_activity_updates()

        with tempfile.TemporaryDirectory() as directory:
            store = BoundedStore(Path(directory) / "loopdy.sqlite3")
            service = LoopdyService(store)
            self.assertEqual(store.pending_limits, [1])
            service.close()

    def test_startup_pending_existence_checks_are_bounded(self) -> None:
        class BoundedStore(LoopdyStore):
            def __init__(self, path):
                self.calls = []
                super().__init__(path)

            def has_pending_live_activity_updates(self):
                self.calls.append(("direct", 1))
                return super().has_pending_live_activity_updates()

            def has_pending_relay_live_activity_updates(self):
                self.calls.append(("relay", 1))
                return super().has_pending_relay_live_activity_updates()

            def has_pending_relay_operations(self):
                self.calls.append(("operations", 1))
                return super().has_pending_relay_operations()

        with tempfile.TemporaryDirectory() as directory:
            store = BoundedStore(Path(directory) / "loopdy.sqlite3")
            service = LoopdyService(store)
            self.assertEqual(
                store.calls,
                [("direct", 1), ("relay", 1), ("operations", 1)],
            )
            service.close()

    def test_relay_to_managed_switch_cancels_old_work_before_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            now = int(time.time())
            event = build_event("channel.message", correlation=("switch-provider",))
            store.record_event(event, target="all")
            store.record_device_delivery(
                event_id=event.event_id,
                device_id="relay-phone",
                provider="relay",
                status="queued",
                target_revision=2,
                target_generation=store.relay_config_generation(),
            )
            store.register_relay_live_activity(
                activity_id="activity-switch",
                device_id="relay-phone",
                session_ref=_session_reference("session-switch"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": "activity-switch", "revision": 1},
            )
            store.defer_relay_live_activity_update(
                activity_id="activity-switch",
                status="running",
                detail="",
                tool_name="",
                active_session_count=1,
                delay_seconds=0,
                failure="",
                timestamp=now + 1,
                delivery_id="switch-delivery",
                idempotency_key="switch-key",
                request_body={"device_id": "relay-phone"},
            )

            store.upsert_device(
                device_id="relay-phone",
                endpoint_id="ExponentPushToken[managed-switch]",
                provider="managed",
            )

            self.assertEqual(store.list_event_deliveries(event.event_id)[0]["status"], "failed")
            self.assertIsNone(store.pending_relay_live_activity_update("activity-switch"))
            self.assertEqual(store.active_relay_live_activities(_session_reference("session-switch")), [])
            restarted = LoopdyService(store)
            self.assertFalse(restarted._worker and restarted._worker.is_alive())
            self.assertFalse(restarted._live_activity_worker and restarted._live_activity_worker.is_alive())
            restarted.close()

    def test_operation_journal_rejects_nonfinite_request_before_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            with self.assertRaisesRegex(ValueError, "canonical|finite"):
                store.save_pending_relay_operation(
                    operation="device_revoke",
                    device_id="relay-phone",
                    revision=1,
                    idempotency_key="00000000-0000-5000-8000-000000000007",
                    body={
                        "version": 1,
                        "device_id": "relay-phone",
                        "revision": 1,
                        "idempotency_key": "00000000-0000-5000-8000-000000000007",
                        "unsafe": float("nan"),
                    },
                )
            self.assertEqual(store.pending_relay_operations(), [])

    def test_malformed_legacy_operation_is_quarantined_without_remote_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.save_relay_config(CONFIG)
            with store._connect() as connection:
                connection.execute(
                    "INSERT INTO pending_relay_operations "
                    "(operation, device_id, revision, idempotency_key, body_json, response_json, "
                    "relay_generation, attempts, updated_at) VALUES (?, ?, ?, ?, ?, '', ?, 1, ?)",
                    (
                        "device_revoke",
                        "relay-phone",
                        1,
                        "00000000-0000-5000-8000-000000000008",
                        '{"device_id":"relay-phone","revision":NaN}',
                        store.relay_config_generation(),
                        int(time.time()),
                    ),
                )

            class Client:
                calls = 0

                def revoke_device(self, _body):
                    self.calls += 1
                    raise AssertionError("malformed legacy request must not reach relay")

            client = Client()
            service = LoopdyService(store, providers={"relay": RelayPushProvider(client)})
            service.reconcile_relay_operations()
            pending = store.pending_relay_operation("device_revoke", "relay-phone")
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertTrue(pending["terminal"])
            self.assertEqual(client.calls, 0)
            service.close()

    def test_notification_copy_normalizes_nfc_and_truncates_utf8_safely(self) -> None:
        event = build_event(
            "channel.message",
            correlation=("nfc-round3",),
            detail={"agent_name": "Cafe\u0301", "message": "😀" * 500},
        )
        message = shape_notification(event, {"detail_mode": "detailed"})
        self.assertEqual(message.title, "Café just messaged you!")
        self.assertEqual(message.body, "Message: " + "😀" * 197)
        self.assertLessEqual(len(message.title.encode("utf-8")), 120)
        self.assertLessEqual(len(message.body.encode("utf-8")), 800)


if __name__ == "__main__":
    unittest.main()
