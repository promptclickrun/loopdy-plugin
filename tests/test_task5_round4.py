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
