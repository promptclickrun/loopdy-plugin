from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import loopdy_plugin.service as service_module
from loopdy_plugin.events import build_event
from loopdy_plugin.provider import DeliveryError, DeliveryReceipt
from loopdy_plugin.relay_client import RelayPushProvider
from loopdy_plugin.service import LoopdyService, _session_reference
from loopdy_plugin.store import LoopdyStore

from test_task5_round3 import CONFIG, _seed_relay


class _TraceBarrierStore(LoopdyStore):
    def __init__(self, path: Path, select_seen: threading.Event, release_select: threading.Event):
        self._select_seen = select_seen
        self._release_select = release_select
        self._in_transaction: list[bool] = []
        super().__init__(path)

    @contextmanager
    def _connect(self, *, initialize: bool = True):
        with super()._connect(initialize=initialize) as connection:
            armed = True

            def trace(sql: str) -> None:
                nonlocal armed
                if armed and "SELECT body_json, request_digest" in sql:
                    armed = False
                    self._in_transaction.append(connection.in_transaction)
                    self._select_seen.set()
                    if not self._release_select.wait(timeout=3):
                        raise AssertionError("admission SELECT was not released")

            connection.set_trace_callback(trace)
            yield connection


class Task5Round4Tests(unittest.TestCase):
    def test_concurrent_identical_operation_admission_is_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            select_seen = threading.Event()
            release_select = threading.Event()
            store = _TraceBarrierStore(
                Path(directory) / "loopdy.sqlite3", select_seen, release_select
            )
            body = {
                "version": 1,
                "device_id": "relay-phone",
                "revision": 1,
                "idempotency_key": "00000000-0000-5000-8000-000000000101",
            }
            errors: list[BaseException] = []
            outcomes: list[str] = []

            def save() -> None:
                try:
                    store.save_pending_relay_operation(
                        operation="device_revoke",
                        device_id="relay-phone",
                        revision=1,
                        idempotency_key=body["idempotency_key"],
                        body=body,
                    )
                    outcomes.append("inserted")
                except BaseException as error:
                    errors.append(error)

            threads = [threading.Thread(target=save) for _ in range(2)]
            threads[0].start()
            self.assertTrue(select_seen.wait(timeout=2))
            self.assertEqual(store._in_transaction, [True])
            threads[1].start()
            time.sleep(0.05)
            self.assertTrue(threads[0].is_alive())
            release_select.set()
            for thread in threads:
                thread.join(timeout=4)
                self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(sorted(outcomes), ["inserted", "inserted"])
            rows = store.pending_relay_operations()
            self.assertEqual(len(rows), 1)
            self.assertEqual(json.loads(rows[0]["body_json"]), body)

    def test_operation_reconciliation_leases_one_row_before_network_work(self) -> None:
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
            first_started = threading.Event()
            release = threading.Event()
            calls: list[str] = []

            class Client:
                def revoke_device(self, request):
                    calls.append(str(request["device_id"]))
                    if len(calls) == 1:
                        first_started.set()
                        self.assert_release(release)
                    return {
                        "version": 1,
                        "status": "revoked",
                        "id": request["device_id"],
                        "revision": request["revision"],
                    }

                @staticmethod
                def assert_release(event: threading.Event) -> None:
                    if not event.wait(timeout=3):
                        raise AssertionError("network operation was not released")

            service = LoopdyService(store, providers={"relay": RelayPushProvider(Client())})
            for index, device in enumerate(("relay-phone-a", "relay-phone-b"), start=1):
                body = {
                    "version": 1,
                    "device_id": device,
                    "revision": 3,
                    "idempotency_key": f"00000000-0000-5000-8000-{100 + index:012d}",
                }
                store.save_pending_relay_operation(
                    operation="device_revoke", device_id=device, revision=3,
                    idempotency_key=body["idempotency_key"], body=body,
                    relay_generation=store.relay_config_generation(),
                )
            failures: list[BaseException] = []
            thread = threading.Thread(
                target=lambda: self._capture(
                    lambda: service.reconcile_relay_operations(), failures
                )
            )
            thread.start()
            self.assertTrue(first_started.wait(timeout=2))
            rows = {
                row["device_id"]: row for row in store.pending_relay_operations()
            }
            other = "relay-phone-b" if calls[0] == "relay-phone-a" else "relay-phone-a"
            self.assertEqual(rows[other]["attempts"], 0)
            self.assertEqual(rows[other]["claim_token"], "")
            release.set()
            thread.join(timeout=4)
            self.assertEqual(failures, [])
            self.assertEqual(calls, ["relay-phone-a", "relay-phone-b"])
            service.close()

    def test_existing_queued_alert_respects_future_retry_time(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)

            calls: list[str] = []

            class Provider:
                def select_sender_key_id(self, values):
                    return values[0]

                def send_device(self, **kwargs):
                    calls.append(str(kwargs["device"]["device_id"]))
                    return DeliveryReceipt(delivery_id=str(kwargs["delivery_id"]))

                def close(self):
                    return None

            service = LoopdyService(store, providers={"relay": Provider()})
            event = build_event("channel.message", correlation=("future-retry",))
            store.record_event(event, target="all")
            store.record_device_delivery(
                event_id=event.event_id,
                device_id="relay-phone",
                provider="relay",
                status="queued",
                target_revision=2,
                target_generation=store.relay_config_generation(),
            )
            future = int(time.time()) + 300
            with store._connect() as connection:
                connection.execute(
                    "UPDATE event_deliveries SET next_attempt_at=? WHERE event_id=? AND device_id=?",
                    (future, event.event_id, "relay-phone"),
                )
            service.deliver(event, target="all")
            row = store.list_event_deliveries(event.event_id)[0]
            self.assertEqual(calls, [])
            self.assertEqual(row["status"], "queued")
            self.assertEqual(row["attempts"], 0)
            self.assertGreaterEqual(row["next_attempt_at"], future)
            service.close()

    def test_relay_live_activity_rechecks_due_time_after_send_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "loopdy.sqlite3"
            seed = LoopdyStore(path)
            _seed_relay(seed)
            now = int(time.time())
            seed.register_relay_live_activity(
                activity_id="activity-due-race",
                device_id="relay-phone",
                session_ref=_session_reference("session-due-race"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": "activity-due-race", "revision": 1},
            )

            class HoldingStore(LoopdyStore):
                def __init__(self, path: Path):
                    self.due_returned = threading.Event()
                    self.allow_return = threading.Event()
                    super().__init__(path)

                def due_relay_live_activity_updates(self, *, limit: int = 100):
                    rows = super().due_relay_live_activity_updates(limit=limit)
                    self.due_returned.set()
                    self.allow_return.wait(timeout=4)
                    return rows

            store_b = HoldingStore(path)
            store_a = LoopdyStore(path)
            class Failing(RelayPushProvider):
                def __init__(self):
                    super().__init__(object())
                    self.calls = 0

                def send_live_activity(self, **_kwargs):
                    self.calls += 1
                    raise DeliveryError("temporary", retryable=True)

            class Recording(RelayPushProvider):
                def __init__(self):
                    super().__init__(object())
                    self.calls = 0

                def send_live_activity(self, **_kwargs):
                    self.calls += 1
                    return DeliveryReceipt(delivery_id="recorded")

            failing = Failing()
            recording = Recording()
            service_a = LoopdyService(store_a, providers={"relay": failing})
            service_b = LoopdyService(store_b, providers={"relay": recording})
            store_a.defer_relay_live_activity_update(
                activity_id="activity-due-race", status="running", detail="", tool_name="",
                active_session_count=1, delay_seconds=0, failure="", timestamp=0,
                delivery_id="", idempotency_key="", request_body=None,
            )
            b_thread = threading.Thread(target=service_b._reconcile_relay_live_activity_updates)
            b_thread.start()
            self.assertTrue(store_b.due_returned.wait(timeout=2))
            service_a._reconcile_relay_live_activity_updates()
            store_b.allow_return.set()
            b_thread.join(timeout=4)
            self.assertFalse(b_thread.is_alive())
            self.assertEqual(failing.calls, 1)
            self.assertEqual(recording.calls, 0)
            pending = seed.pending_relay_live_activity_update("activity-due-race")
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertGreater(pending["next_attempt_at"], int(time.time()))
            service_a.close()
            service_b.close()

    def test_recovery_wake_uses_one_earliest_timer_and_cancels_on_close(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = LoopdyService(LoopdyStore(Path(directory) / "loopdy.sqlite3"))
            created = []

            class FakeTimer:
                def __init__(self, delay, callback):
                    self.delay = delay
                    self.callback = callback
                    self.cancelled = False
                    created.append(self)

                def start(self):
                    return None

                def cancel(self):
                    self.cancelled = True

            with patch.object(service_module.threading, "Timer", FakeTimer):
                service._wake_recovery_owner(5)
                service._wake_recovery_owner(2)
                service._wake_recovery_owner(10)
                active = [timer for timer in created if not timer.cancelled]
                self.assertEqual(len(active), 1)
                self.assertEqual(active[0].delay, 2)
            service.close()
            self.assertTrue(active[0].cancelled)

    def test_exhausted_routine_live_activity_allows_waiting_and_coalesces_lower_phases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            now = int(time.time())
            store.register_relay_live_activity(
                activity_id="activity-priority",
                device_id="relay-phone",
                session_ref=_session_reference("session-priority"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": "activity-priority", "revision": 1},
            )
            owner = {
                "expected_device_id": "relay-phone",
                "expected_session_ref": _session_reference("session-priority"),
                "expected_revision": 1,
                "expected_lease_expires": now + 28_800,
                "expected_relay_generation": store.relay_config_generation(),
            }
            for attempt in range(5):
                store.defer_relay_live_activity_update(
                    activity_id="activity-priority", status="running", detail="", tool_name="",
                    active_session_count=1, delay_seconds=0, failure="retry", timestamp=now + attempt + 1,
                    delivery_id=f"routine-{attempt}", idempotency_key=f"routine-key-{attempt}",
                    request_body={"device_id": "relay-phone"}, **owner,
                )
            exhausted = store.pending_relay_live_activity_update("activity-priority")
            self.assertTrue(exhausted["terminal"])
            store.defer_relay_live_activity_update(
                activity_id="activity-priority", status="waiting", detail="Approve", tool_name="",
                active_session_count=1, delay_seconds=0, failure="", timestamp=now + 10,
                delivery_id="waiting", idempotency_key="waiting-key",
                request_body={"device_id": "relay-phone"}, **owner,
            )
            waiting = store.pending_relay_live_activity_update("activity-priority")
            self.assertEqual(waiting["status"], "waiting")
            self.assertFalse(waiting["terminal"])
            store.defer_relay_live_activity_update(
                activity_id="activity-priority", status="running", detail="", tool_name="",
                active_session_count=1, delay_seconds=0, failure="", timestamp=now + 11,
                delivery_id="running", idempotency_key="running-key",
                request_body={"device_id": "relay-phone"}, **owner,
            )
            self.assertEqual(
                store.pending_relay_live_activity_update("activity-priority")["status"],
                "waiting",
            )
            store.defer_relay_live_activity_update(
                activity_id="activity-priority", status="completed", detail="Done", tool_name="",
                active_session_count=0, delay_seconds=0, failure="", timestamp=now + 12,
                delivery_id="completed", idempotency_key="completed-key",
                request_body={"device_id": "relay-phone"}, **owner,
            )
            self.assertEqual(
                store.pending_relay_live_activity_update("activity-priority")["status"],
                "completed",
            )
            store.defer_relay_live_activity_update(
                activity_id="activity-priority", status="completed", detail="Done", tool_name="",
                active_session_count=0, delay_seconds=0, failure="retry", timestamp=now + 12,
                delivery_id="completed", idempotency_key="completed-key",
                request_body={"device_id": "relay-phone"}, **owner,
            )
            self.assertEqual(
                store.pending_relay_live_activity_update("activity-priority")["attempts"],
                3,
            )
            store.defer_relay_live_activity_update(
                activity_id="activity-priority", status="failed", detail="Late", tool_name="",
                active_session_count=0, delay_seconds=0, failure="", timestamp=now + 13,
                delivery_id="failed", idempotency_key="failed-key",
                request_body={"device_id": "relay-phone"}, **owner,
            )
            terminal = store.pending_relay_live_activity_update("activity-priority")
            self.assertEqual(terminal["status"], "completed")

    def test_direct_live_activity_retry_attempts_become_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.upsert_live_activity(
                session_id="stored", live_session_id="live", profile="default",
                activity_id="direct-attempts", push_token="a" * 64,
                token_environment="production",
            )
            for _ in range(6):
                store.defer_live_activity_update(
                    activity_id="direct-attempts", status="running", detail="", tool_name="",
                    active_session_count=1, delay_seconds=0, failure="temporary",
                )
            row = store.pending_live_activity_update("direct-attempts")
            self.assertIsNotNone(row)
            assert row is not None
            self.assertTrue(row["terminal"])
            self.assertEqual(store.due_live_activity_updates(), [])

    def test_direct_end_cannot_end_activity_after_new_same_owner_request_is_inserted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.upsert_live_activity(
                session_id="stored", live_session_id="live", profile="default",
                activity_id="direct-end-request-race", push_token="a" * 64,
                token_environment="production",
            )
            store.defer_live_activity_update(
                activity_id="direct-end-request-race", status="running", detail="old",
                tool_name="", active_session_count=1, delay_seconds=0, failure="",
            )
            old = store.pending_live_activity_update("direct-end-request-race")
            self.assertIsNotNone(old)
            assert old is not None
            store.defer_live_activity_update(
                activity_id="direct-end-request-race", status="waiting", detail="new",
                tool_name="", active_session_count=1, delay_seconds=0, failure="",
                expected_session_id="stored",
                expected_live_session_id="live",
                expected_profile="default",
                expected_push_token="a" * 64,
                expected_owner_generation=int(old["owner_generation"]),
                expected_request_id=str(old["request_id"]),
            )
            result = store.end_live_activity(
                "direct-end-request-race",
                expected_session_id="stored",
                expected_live_session_id="live",
                expected_profile="default",
                expected_push_token="a" * 64,
                expected_owner_generation=int(old["owner_generation"]),
                expected_request_id=str(old["request_id"]),
            )
            self.assertFalse(result)
            self.assertIsNotNone(store.active_live_activity("direct-end-request-race"))
            pending = store.pending_live_activity_update("direct-end-request-race")
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertEqual(pending["status"], "waiting")
            self.assertNotEqual(pending["request_id"], old["request_id"])

    def test_relay_immediate_invalid_token_cannot_end_after_new_request_is_inserted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            now = int(time.time())
            activity_id = "relay-immediate-request-race"
            store.register_relay_live_activity(
                activity_id=activity_id,
                device_id="relay-phone",
                session_ref=_session_reference("relay-immediate-session"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": activity_id, "revision": 1},
            )
            started = threading.Event()
            release = threading.Event()

            def send(_activity, **_kwargs):
                started.set()
                release.wait(timeout=3)
                raise DeliveryError("BadDeviceToken", status=400, invalid_token=True)

            service = LoopdyService(store, timestamp_fn=lambda: now + 1)
            service._send_live_activity_update = send
            thread = threading.Thread(
                target=lambda: service.update_live_activities(
                    session_id="relay-immediate-session",
                    profile="default",
                    phase="completed",
                    active_session_count=0,
                )
            )
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            activity = store.active_relay_live_activity(
                activity_id,
                expected_session_ref=_session_reference("relay-immediate-session"),
                expected_device_id="relay-phone",
                expected_revision=1,
                expected_lease_expires=now + 28_800,
            )
            self.assertIsNotNone(activity)
            assert activity is not None
            old = store.pending_relay_live_activity_update(activity_id)
            self.assertIsNotNone(old)
            assert old is not None
            new_request = service._prepare_relay_live_activity_request(
                activity,
                status="completed",
                active_session_count=0,
            )
            store.defer_relay_live_activity_update(
                activity_id=activity_id,
                status="completed",
                detail="new",
                tool_name="",
                active_session_count=0,
                delay_seconds=0,
                failure="",
                timestamp=int(new_request["timestamp"]),
                delivery_id=str(new_request["delivery_id"]),
                idempotency_key=str(new_request["idempotency_key"]),
                request_body=new_request["request_body"],
                **service._relay_activity_owner(activity),
            )
            release.set()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertIsNotNone(store.active_relay_live_activity(activity_id))
            pending = store.pending_relay_live_activity_update(activity_id)
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertEqual(pending["status"], "completed")
            self.assertNotEqual(pending["delivery_id"], old["delivery_id"])
            self.assertNotEqual(pending["idempotency_key"], old["idempotency_key"])
            service.close()

    def test_relay_immediate_nonterminal_cannot_clear_new_request_when_local_pending_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            now = int(time.time())
            activity_id = "relay-immediate-nonterminal-request-race"
            store.register_relay_live_activity(
                activity_id=activity_id,
                device_id="relay-phone",
                session_ref=_session_reference("relay-immediate-nonterminal-session"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": activity_id, "revision": 1},
            )
            started = threading.Event()
            release = threading.Event()

            def send(_activity, **_kwargs):
                started.set()
                release.wait(timeout=3)
                return DeliveryReceipt(delivery_id="accepted")

            service = LoopdyService(store, timestamp_fn=lambda: now + 1)
            service._send_live_activity_update = send
            thread = threading.Thread(
                target=lambda: service.update_live_activities(
                    session_id="relay-immediate-nonterminal-session",
                    profile="default",
                    phase="running",
                    active_session_count=1,
                )
            )
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            activity = store.active_relay_live_activity(activity_id)
            self.assertIsNotNone(activity)
            assert activity is not None
            old = store.pending_relay_live_activity_update(activity_id)
            self.assertIsNotNone(old)
            assert old is not None
            new_request = service._prepare_relay_live_activity_request(
                activity,
                status="waiting",
                active_session_count=1,
            )
            store.defer_relay_live_activity_update(
                activity_id=activity_id,
                status="waiting",
                detail="new",
                tool_name="",
                active_session_count=1,
                delay_seconds=0,
                failure="",
                timestamp=int(new_request["timestamp"]),
                delivery_id=str(new_request["delivery_id"]),
                idempotency_key=str(new_request["idempotency_key"]),
                request_body=new_request["request_body"],
                **service._relay_activity_owner(activity),
            )
            release.set()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            pending = store.pending_relay_live_activity_update(activity_id)
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertEqual(pending["status"], "waiting")
            self.assertNotEqual(pending["delivery_id"], old["delivery_id"])
            self.assertNotEqual(pending["idempotency_key"], old["idempotency_key"])
            service.close()

    def test_relay_immediate_retry_cannot_overwrite_new_same_owner_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            now = int(time.time())
            activity_id = "relay-immediate-retry-request-race"
            store.register_relay_live_activity(
                activity_id=activity_id,
                device_id="relay-phone",
                session_ref=_session_reference("relay-immediate-retry-session"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": activity_id, "revision": 1},
            )
            started = threading.Event()
            release = threading.Event()

            def send(_activity, **_kwargs):
                started.set()
                release.wait(timeout=3)
                raise DeliveryError("relay_unavailable", status=503)

            service = LoopdyService(store, timestamp_fn=lambda: now + 1)
            service._send_live_activity_update = send
            thread = threading.Thread(
                target=lambda: service.update_live_activities(
                    session_id="relay-immediate-retry-session",
                    profile="default",
                    phase="running",
                    active_session_count=1,
                )
            )
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            activity = store.active_relay_live_activity(activity_id)
            self.assertIsNotNone(activity)
            assert activity is not None
            old = store.pending_relay_live_activity_update(activity_id)
            self.assertIsNotNone(old)
            assert old is not None
            new_request = service._prepare_relay_live_activity_request(
                activity,
                status="running",
                active_session_count=2,
            )
            store.defer_relay_live_activity_update(
                activity_id=activity_id,
                status="running",
                detail="new request",
                tool_name="new-tool",
                active_session_count=2,
                delay_seconds=0,
                failure="new failure",
                timestamp=int(new_request["timestamp"]),
                delivery_id=str(new_request["delivery_id"]),
                idempotency_key=str(new_request["idempotency_key"]),
                request_body=new_request["request_body"],
                **service._relay_activity_owner(activity),
            )
            expected = store.pending_relay_live_activity_update(activity_id)
            self.assertIsNotNone(expected)
            assert expected is not None
            release.set()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            actual = store.pending_relay_live_activity_update(activity_id)
            self.assertEqual(actual, expected)
            self.assertNotEqual(actual["delivery_id"], old["delivery_id"])
            self.assertNotEqual(actual["idempotency_key"], old["idempotency_key"])
            service.close()

    def test_queued_relay_retry_cannot_overwrite_new_same_owner_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            now = int(time.time())
            activity_id = "relay-queued-retry-request-race"
            store.register_relay_live_activity(
                activity_id=activity_id,
                device_id="relay-phone",
                session_ref=_session_reference("relay-queued-retry-session"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": activity_id, "revision": 1},
            )
            service = LoopdyService(store, timestamp_fn=lambda: now + 1)
            activity = store.active_relay_live_activity(activity_id)
            self.assertIsNotNone(activity)
            assert activity is not None
            old_request = service._prepare_relay_live_activity_request(
                activity,
                status="running",
                active_session_count=1,
            )
            store.defer_relay_live_activity_update(
                activity_id=activity_id,
                status="running",
                detail="old request",
                tool_name="old-tool",
                active_session_count=1,
                delay_seconds=0,
                failure="old failure",
                timestamp=int(old_request["timestamp"]),
                delivery_id=str(old_request["delivery_id"]),
                idempotency_key=str(old_request["idempotency_key"]),
                request_body=old_request["request_body"],
                **service._relay_activity_owner(activity),
            )
            started = threading.Event()
            release = threading.Event()

            def send(_activity, **_kwargs):
                started.set()
                release.wait(timeout=3)
                raise DeliveryError("relay_unavailable", status=503)

            service._send_live_activity_update = send
            thread = threading.Thread(target=service._reconcile_relay_live_activity_updates)
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            new_request = service._prepare_relay_live_activity_request(
                activity,
                status="running",
                active_session_count=2,
            )
            store.defer_relay_live_activity_update(
                activity_id=activity_id,
                status="running",
                detail="new request",
                tool_name="new-tool",
                active_session_count=2,
                delay_seconds=0,
                failure="new failure",
                timestamp=int(new_request["timestamp"]),
                delivery_id=str(new_request["delivery_id"]),
                idempotency_key=str(new_request["idempotency_key"]),
                request_body=new_request["request_body"],
                **service._relay_activity_owner(activity),
            )
            expected = store.pending_relay_live_activity_update(activity_id)
            self.assertIsNotNone(expected)
            assert expected is not None
            release.set()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            actual = store.pending_relay_live_activity_update(activity_id)
            self.assertEqual(actual, expected)
            self.assertNotEqual(actual["delivery_id"], old_request["delivery_id"])
            self.assertNotEqual(actual["idempotency_key"], old_request["idempotency_key"])
            service.close()

    def test_queued_relay_legacy_blank_terminal_refreshes_coordinates_before_settlement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            now = int(time.time())
            activity_id = "relay-legacy-terminal-request-race"
            store.register_relay_live_activity(
                activity_id=activity_id,
                device_id="relay-phone",
                session_ref=_session_reference("relay-legacy-terminal-session"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": activity_id, "revision": 1},
            )
            store.defer_relay_live_activity_update(
                activity_id=activity_id,
                status="completed",
                detail="legacy request",
                tool_name="",
                active_session_count=0,
                delay_seconds=0,
                failure="",
            )
            with store._connect() as connection:
                connection.execute(
                    "UPDATE pending_relay_live_activity_updates SET timestamp=0, "
                    "delivery_id='', idempotency_key='', request_body_json='' "
                    "WHERE activity_id=?",
                    (activity_id,),
                )
            service = LoopdyService(store, timestamp_fn=lambda: now + 1)
            started = threading.Event()
            release = threading.Event()

            def send(_activity, **_kwargs):
                materialized = store.pending_relay_live_activity_update(activity_id)
                self.assertIsNotNone(materialized)
                assert materialized is not None
                self.assertTrue(materialized["delivery_id"])
                self.assertTrue(materialized["idempotency_key"])
                activity = store.active_relay_live_activity(activity_id)
                self.assertIsNotNone(activity)
                assert activity is not None
                new_request = service._prepare_relay_live_activity_request(
                    activity,
                    status="completed",
                    active_session_count=0,
                )
                store.defer_relay_live_activity_update(
                    activity_id=activity_id,
                    status="completed",
                    detail="new request",
                    tool_name="",
                    active_session_count=0,
                    delay_seconds=0,
                    failure="",
                    timestamp=int(new_request["timestamp"]),
                    delivery_id=str(new_request["delivery_id"]),
                    idempotency_key=str(new_request["idempotency_key"]),
                    request_body=new_request["request_body"],
                    **service._relay_activity_owner(activity),
                )
                started.set()
                release.wait(timeout=3)
                return DeliveryReceipt(delivery_id="accepted")

            service._send_live_activity_update = send
            thread = threading.Thread(target=service._reconcile_relay_live_activity_updates)
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            expected = store.pending_relay_live_activity_update(activity_id)
            self.assertIsNotNone(expected)
            assert expected is not None
            release.set()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertIsNotNone(store.active_relay_live_activity(activity_id))
            actual = store.pending_relay_live_activity_update(activity_id)
            self.assertEqual(actual, expected)
            service.close()

    def test_queued_relay_terminal_cannot_end_after_new_request_replaces_old_coordinates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            now = int(time.time())
            activity_id = "relay-queued-request-race"
            store.register_relay_live_activity(
                activity_id=activity_id,
                device_id="relay-phone",
                session_ref=_session_reference("relay-queued-session"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": activity_id, "revision": 1},
            )
            service = LoopdyService(store, timestamp_fn=lambda: now + 1)
            activity = store.active_relay_live_activity(activity_id)
            self.assertIsNotNone(activity)
            assert activity is not None
            old_request = service._prepare_relay_live_activity_request(
                activity,
                status="completed",
                active_session_count=0,
            )
            store.defer_relay_live_activity_update(
                activity_id=activity_id,
                status="completed",
                detail="old",
                tool_name="",
                active_session_count=0,
                delay_seconds=0,
                failure="",
                timestamp=int(old_request["timestamp"]),
                delivery_id=str(old_request["delivery_id"]),
                idempotency_key=str(old_request["idempotency_key"]),
                request_body=old_request["request_body"],
                **service._relay_activity_owner(activity),
            )
            started = threading.Event()
            release = threading.Event()

            def send(_activity, **_kwargs):
                started.set()
                release.wait(timeout=3)
                return DeliveryReceipt(delivery_id="accepted")

            service._send_live_activity_update = send
            thread = threading.Thread(target=service._reconcile_relay_live_activity_updates)
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            new_request = service._prepare_relay_live_activity_request(
                activity,
                status="completed",
                active_session_count=0,
            )
            store.defer_relay_live_activity_update(
                activity_id=activity_id,
                status="completed",
                detail="new",
                tool_name="",
                active_session_count=0,
                delay_seconds=0,
                failure="",
                timestamp=int(new_request["timestamp"]),
                delivery_id=str(new_request["delivery_id"]),
                idempotency_key=str(new_request["idempotency_key"]),
                request_body=new_request["request_body"],
                **service._relay_activity_owner(activity),
            )
            release.set()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertIsNotNone(store.active_relay_live_activity(activity_id))
            pending = store.pending_relay_live_activity_update(activity_id)
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertEqual(pending["status"], "completed")
            self.assertNotEqual(pending["delivery_id"], old_request["delivery_id"])
            self.assertNotEqual(pending["idempotency_key"], old_request["idempotency_key"])
            service.close()

    def test_old_direct_live_activity_send_cannot_clear_new_owner_pending_row(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.upsert_live_activity(
                session_id="stored-old", live_session_id="live-old", profile="default",
                activity_id="direct-owner-race", push_token="a" * 64,
                token_environment="production",
            )
            service = LoopdyService(store)
            store.defer_live_activity_update(
                activity_id="direct-owner-race", status="running", detail="", tool_name="",
                active_session_count=1, delay_seconds=0, failure="temporary",
            )
            started = threading.Event()
            release = threading.Event()

            def send(_activity, **_kwargs):
                started.set()
                release.wait(timeout=3)
                return DeliveryReceipt(delivery_id="old")

            service._send_live_activity_update = send
            thread = threading.Thread(
                target=service._reconcile_live_activity_updates
            )
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            store.upsert_live_activity(
                session_id="stored-new", live_session_id="live-new", profile="default",
                activity_id="direct-owner-race", push_token="b" * 64,
                token_environment="production",
            )
            store.defer_live_activity_update(
                activity_id="direct-owner-race", status="waiting", detail="Approve", tool_name="",
                active_session_count=1, delay_seconds=0, failure="",
            )
            release.set()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            pending = store.pending_live_activity_update("direct-owner-race")
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertEqual(pending["status"], "waiting")
            service.close()

    def test_old_direct_terminal_send_cannot_end_exact_same_owner_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.upsert_live_activity(
                session_id="stored", live_session_id="live", profile="default",
                activity_id="direct-same-owner", push_token="a" * 64,
                token_environment="production",
            )
            store.defer_live_activity_update(
                activity_id="direct-same-owner", status="completed", detail="old", tool_name="",
                active_session_count=0, delay_seconds=0, failure="temporary",
            )
            started = threading.Event()
            release = threading.Event()

            def send(_activity, **_kwargs):
                started.set()
                release.wait(timeout=3)
                return DeliveryReceipt(delivery_id="old")

            service = LoopdyService(store)
            service._send_live_activity_update = send
            thread = threading.Thread(target=service._reconcile_live_activity_updates)
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            store.upsert_live_activity(
                session_id="stored", live_session_id="live", profile="default",
                activity_id="direct-same-owner", push_token="a" * 64,
                token_environment="production",
            )
            store.defer_live_activity_update(
                activity_id="direct-same-owner", status="waiting", detail="new", tool_name="",
                active_session_count=1, delay_seconds=0, failure="",
            )
            release.set()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            active = store.active_live_activity("direct-same-owner")
            self.assertIsNotNone(active)
            pending = store.pending_live_activity_update("direct-same-owner")
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertEqual(pending["status"], "waiting")
            service.close()

    def test_old_direct_retryable_send_cannot_defer_changed_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.upsert_live_activity(
                session_id="stored-old", live_session_id="live-old", profile="default",
                activity_id="direct-retry-owner", push_token="a" * 64,
                token_environment="production",
            )
            store.defer_live_activity_update(
                activity_id="direct-retry-owner", status="running", detail="old", tool_name="",
                active_session_count=1, delay_seconds=0, failure="temporary",
            )
            started = threading.Event()
            release = threading.Event()

            def send(_activity, **_kwargs):
                started.set()
                release.wait(timeout=3)
                raise DeliveryError("temporary", retryable=True)

            service = LoopdyService(store)
            service._send_live_activity_update = send
            thread = threading.Thread(target=service._reconcile_live_activity_updates)
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            store.upsert_live_activity(
                session_id="stored-new", live_session_id="live-new", profile="default",
                activity_id="direct-retry-owner", push_token="b" * 64,
                token_environment="production",
            )
            release.set()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertIsNone(store.pending_live_activity_update("direct-retry-owner"))
            self.assertIsNotNone(store.active_live_activity("direct-retry-owner"))
            service.close()

    def test_old_direct_retryable_send_cannot_defer_exact_same_owner_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.upsert_live_activity(
                session_id="stored", live_session_id="live", profile="default",
                activity_id="direct-retry-same-owner", push_token="a" * 64,
                token_environment="production",
            )
            store.defer_live_activity_update(
                activity_id="direct-retry-same-owner", status="running", detail="old", tool_name="",
                active_session_count=1, delay_seconds=0, failure="temporary",
            )
            started = threading.Event()
            release = threading.Event()

            def send(_activity, **_kwargs):
                started.set()
                release.wait(timeout=3)
                raise DeliveryError("temporary", retryable=True)

            service = LoopdyService(store)
            service._send_live_activity_update = send
            thread = threading.Thread(target=service._reconcile_live_activity_updates)
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            store.upsert_live_activity(
                session_id="stored", live_session_id="live", profile="default",
                activity_id="direct-retry-same-owner", push_token="a" * 64,
                token_environment="production",
            )
            release.set()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertIsNone(store.pending_live_activity_update("direct-retry-same-owner"))
            self.assertIsNotNone(store.active_live_activity("direct-retry-same-owner"))
            service.close()

    def test_revoke_device_cancels_inflight_live_activity_registration_operation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            started = threading.Event()
            release = threading.Event()

            class Client:
                def register_live_activity(self, _body):
                    started.set()
                    release.wait(timeout=3)
                    return {"version": 1, "status": "registered"}

            service = LoopdyService(store, providers={"relay": RelayPushProvider(Client())})
            body = {
                "version": 1,
                "activity_id": "stale-activity",
                "device_id": "relay-phone",
                "session_ref": _session_reference("stale-session"),
                "push_token": "aa",
                "environment": "production",
                "topic": "com.example.app",
                "revision": 1,
                "timestamp": int(time.time()),
                "lease_expires": int(time.time()) + 60,
                "idempotency_key": "00000000-0000-5000-8000-000000000109",
            }
            store.save_pending_relay_operation(
                operation="register_live_activity", device_id=body["device_id"],
                revision=1, idempotency_key=body["idempotency_key"], body=body,
                relay_generation=store.relay_config_generation(),
            )
            thread = threading.Thread(target=service.reconcile_relay_operations)
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            now = int(time.time())
            store.revoke_relay_device(
                device_id="relay-phone", revision=3,
                normalized_body={"device_id": "relay-phone", "revision": 3}, now=now,
            )
            store.register_relay_device(
                device_id="relay-phone", recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01", revision=4,
                lease_expires=now + 2_592_000,
                normalized_body={"device_id": "relay-phone", "revision": 4}, now=now + 1,
            )
            store.acknowledge_relay_sender_keys(
                device_id="relay-phone", revision=5, sender_key_revision=1,
                acknowledged_sender_key_ids=["sender_key_fixture_01"],
                normalized_body={"device_id": "relay-phone", "revision": 5}, now=now + 1,
            )
            release.set()
            thread.join(timeout=4)
            self.assertFalse(thread.is_alive())
            self.assertEqual(store.active_relay_live_activities(_session_reference("stale-session")), [])
            row = store.pending_relay_operation("register_live_activity", "relay-phone")
            self.assertIsNotNone(row)
            assert row is not None
            self.assertTrue(row["terminal"])
            service.close()

    def test_revoke_device_terminalizes_activity_revoke_operation_without_device_in_body(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            now = int(time.time())
            activity_id = "activity-revoke-owned"
            store.register_relay_live_activity(
                activity_id=activity_id,
                device_id="relay-phone",
                session_ref=_session_reference("revoke-owned"),
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": activity_id, "revision": 1},
            )
            body = {
                "version": 1,
                "activity_id": activity_id,
                "revision": 2,
                "timestamp": now + 1,
                "idempotency_key": "00000000-0000-5000-8000-000000000110",
            }
            store.save_pending_relay_operation(
                operation="revoke_live_activity",
                device_id=activity_id,
                revision=2,
                idempotency_key=body["idempotency_key"],
                body=body,
                relay_generation=store.relay_config_generation(),
            )
            store.revoke_relay_device(
                device_id="relay-phone", revision=3,
                normalized_body={"device_id": "relay-phone", "revision": 3}, now=now + 2,
            )
            pending = store.pending_relay_operation("revoke_live_activity", activity_id)
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertTrue(pending["terminal"])

    def test_new_relay_device_registration_invalidates_stale_live_activity_operation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            _seed_relay(store)
            started = threading.Event()
            release = threading.Event()

            class Client:
                def register_live_activity(self, _body):
                    started.set()
                    release.wait(timeout=3)
                    return {"version": 1, "status": "registered"}

            service = LoopdyService(store, providers={"relay": RelayPushProvider(Client())})
            now = int(time.time())
            body = {
                "version": 1,
                "activity_id": "stale-registration",
                "device_id": "relay-phone",
                "session_ref": _session_reference("stale-registration"),
                "push_token": "aa",
                "environment": "production",
                "topic": "com.example.app",
                "revision": 1,
                "timestamp": now,
                "lease_expires": now + 60,
                "idempotency_key": "00000000-0000-5000-8000-000000000111",
            }
            store.save_pending_relay_operation(
                operation="register_live_activity", device_id=body["device_id"],
                revision=1, idempotency_key=body["idempotency_key"], body=body,
                relay_generation=store.relay_config_generation(),
            )
            thread = threading.Thread(target=service.reconcile_relay_operations)
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            store.register_relay_device(
                device_id="relay-phone",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=3,
                lease_expires=now + 2_592_000,
                normalized_body={"device_id": "relay-phone", "revision": 3},
                now=now + 1,
            )
            release.set()
            thread.join(timeout=4)
            self.assertFalse(thread.is_alive())
            self.assertEqual(store.active_relay_live_activities(_session_reference("stale-registration")), [])
            pending = store.pending_relay_operation("register_live_activity", "relay-phone")
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertTrue(pending["terminal"])
            service.close()

    def test_worker_contains_one_delivery_exception_and_processes_the_next(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = LoopdyService(LoopdyStore(Path(directory) / "loopdy.sqlite3"))
            first = build_event("channel.message", correlation=("worker", "first"))
            second = build_event("channel.message", correlation=("worker", "second"))
            calls: list[str] = []

            def deliver(event, *, target):
                if event.event_id == first.event_id:
                    raise RuntimeError("unexpected delivery bug")
                calls.append(event.event_id)
                return {"delivered": 1}

            service.deliver = deliver
            self.assertTrue(service.enqueue(first, target="all"))
            self.assertTrue(service.enqueue(second, target="all"))
            service._queue.join()
            self.assertEqual(calls, [second.event_id])
            self.assertIsNotNone(service._worker)
            assert service._worker is not None
            self.assertTrue(service._worker.is_alive())
            service.close()

    @staticmethod
    def _capture(function, failures: list[BaseException]) -> None:
        try:
            function()
        except BaseException as error:
            failures.append(error)


if __name__ == "__main__":
    unittest.main()
