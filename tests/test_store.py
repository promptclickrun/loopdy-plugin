from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from loopdy_plugin.events import build_event
from loopdy_plugin.store import LoopdyStore


class StoreTests(unittest.TestCase):
    def test_fresh_store_defaults_to_relay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")

            self.assertEqual(store.provider_mode(), "relay")

    def test_device_reconciliation_preserves_preferences_when_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.db")
            store.upsert_device(
                device_id="device-1",
                endpoint_id="token-1",
                preferences={"enabled_types": ["approval.required"]},
            )
            store.upsert_device(device_id="device-1", endpoint_id="token-2")
            device = next(item for item in store.list_devices() if item["device_id"] == "device-1")
            self.assertEqual(device["preferences"], {"enabled_types": ["approval.required"]})

    def test_concurrent_partial_preference_updates_preserve_both_writers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.db")
            store.upsert_device(
                device_id="device-1",
                endpoint_id="token-1",
                preferences={"notifications_enabled": True},
            )
            writer_a_selected = threading.Event()
            writer_b_selected = threading.Event()
            writer_a_updated = threading.Event()
            original_connect = sqlite3.connect

            class SynchronizedConnection(sqlite3.Connection):
                def execute(self, sql, parameters=()):
                    cursor = super().execute(sql, parameters)
                    thread_name = threading.current_thread().name
                    if "SELECT preferences_json FROM devices" in sql:
                        if thread_name == "preference-writer-a":
                            writer_a_selected.set()
                            writer_b_selected.wait(timeout=0.5)
                        elif thread_name == "preference-writer-b":
                            writer_b_selected.set()
                            writer_a_updated.wait(timeout=2)
                    elif thread_name == "preference-writer-a" and sql.startswith(
                        "UPDATE devices SET preferences_json="
                    ):
                        writer_a_updated.set()
                    return cursor

            def synchronized_connect(*args, **kwargs):
                return original_connect(*args, factory=SynchronizedConnection, **kwargs)

            results: list[bool] = []
            failures: list[BaseException] = []

            def update(preferences: dict[str, object]) -> None:
                try:
                    results.append(store.update_preferences("device-1", preferences))
                except BaseException as exc:
                    failures.append(exc)

            with mock.patch.object(sqlite3, "connect", side_effect=synchronized_connect):
                writer_a = threading.Thread(
                    target=update,
                    args=({"priority_sound": False},),
                    name="preference-writer-a",
                )
                writer_b = threading.Thread(
                    target=update,
                    args=({"detail_mode": "full"},),
                    name="preference-writer-b",
                )
                writer_a.start()
                self.assertTrue(writer_a_selected.wait(timeout=2))
                writer_b.start()
                writer_a.join(timeout=5)
                writer_b.join(timeout=5)

            self.assertFalse(writer_a.is_alive())
            self.assertFalse(writer_b.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(results, [True, True])
            self.assertEqual(
                store.list_devices()[0]["preferences"],
                {
                    "notifications_enabled": True,
                    "priority_sound": False,
                    "detail_mode": "full",
                },
            )

    def test_explicit_delegation_choices_survive_reopen_reconciliation_and_partial_updates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "loopdy.db"
            store = LoopdyStore(path)
            store.upsert_device(
                device_id="device-1",
                endpoint_id="token-1",
                preferences={"enabled_types": ["delegation.updated"]},
            )

            reopened = LoopdyStore(path)
            reopened.upsert_device(device_id="device-1", endpoint_id="token-2")
            reopened.update_preferences("device-1", {"priority_sound": False})

            device = reopened.list_devices()[0]
            self.assertEqual(
                device["preferences"],
                {
                    "enabled_types": ["delegation.updated"],
                    "priority_sound": False,
                },
            )

    def test_devices_preferences_and_event_ledger_are_durable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "loopdy.sqlite3"
            store = LoopdyStore(path)
            store.upsert_device(
                device_id="phone_123",
                endpoint_id="endpoint_456",
                provider="managed",
                token_environment="production",
                label="My phone",
                groups=["personal"],
            )
            store.update_preferences(
                "phone_123",
                {
                    "enabled_types": ["approval.required"],
                    "quiet_hours": {"start": "22:00", "end": "07:00"},
                },
            )
            event = build_event(
                "approval.required",
                correlation=("approval", "request-1"),
                approval_id="request-1",
            )
            store.record_event(event, target="device:phone_123")
            store.record_event(event, target="device:phone_123")

            reopened = LoopdyStore(path)
            self.assertEqual(
                reopened.list_devices(),
                [
                    {
                        "device_id": "phone_123",
                        "endpoint_id": "endpoint_456",
                        "provider": "managed",
                        "token_environment": "production",
                        "label": "My phone",
                        "groups": ["personal"],
                        "preferences": {
                            "enabled_types": ["approval.required"],
                            "quiet_hours": {"start": "22:00", "end": "07:00"},
                        },
                        "revoked": False,
                    }
                ],
            )
            self.assertEqual(len(reopened.list_events()), 1)
            self.assertEqual(reopened.get_event(event.event_id)["status"], "queued")

            self.assertTrue(reopened.revoke_device("phone_123"))
            self.assertFalse(reopened.revoke_device("missing"))
            self.assertTrue(reopened.list_devices()[0]["revoked"])

    def test_list_events_pages_in_stable_newest_first_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.db")
            events = [
                build_event(
                    "channel.message",
                    correlation=("channel", f"message-{index}"),
                    detail={"message": f"Message {index}"},
                )
                for index in range(3)
            ]
            for event in events:
                store.record_event(event)

            first_page = store.list_events(limit=2, offset=0)
            second_page = store.list_events(limit=2, offset=2)

            self.assertEqual(
                [event["event_id"] for event in first_page + second_page],
                [events[2].event_id, events[1].event_id, events[0].event_id],
            )

    def test_clarify_link_prompt_and_pending_frame_states_are_durable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "loopdy.db"
            store = LoopdyStore(path)
            event = build_event(
                "attention.required",
                correlation=("clarify", "request-pending-1"),
                session_id="opaque-link-chat-pending-1",
                detail={"request_id": "request-pending-1"},
            )

            self.assertTrue(store.record_event(event))
            self.assertTrue(store.mark_event_prompted(event.event_id))
            self.assertEqual(store.get_event(event.event_id)["status"], "prompted")
            self.assertTrue(
                store.mark_event_pending(event.event_id, "frame-pending-coordinate-0001")
            )

            reopened = LoopdyStore(path)
            row = reopened.get_event(event.event_id)
            self.assertEqual(row["status"], "pending")
            self.assertEqual(row["delivery_id"], "frame-pending-coordinate-0001")

    def test_event_read_and_pin_state_is_durable_and_pins_sort_first(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "loopdy.db"
            store = LoopdyStore(path)
            older = build_event(
                "channel.message",
                correlation=("channel", "older"),
                detail={"message": "Older update"},
            )
            newer = build_event(
                "channel.message",
                correlation=("channel", "newer"),
                detail={"message": "Newer update"},
            )
            store.record_event(older)
            store.record_event(newer)
            with sqlite3.connect(path) as connection:
                connection.execute(
                    "UPDATE events SET created_at=? WHERE event_id=?",
                    (100, older.event_id),
                )
                connection.execute(
                    "UPDATE events SET created_at=? WHERE event_id=?",
                    (200, newer.event_id),
                )

            self.assertTrue(
                store.set_event_state(
                    older.event_id,
                    is_read=True,
                    is_pinned=True,
                    changed_at=300,
                )
            )

            reopened = LoopdyStore(path)
            rows = reopened.list_events()
            self.assertEqual([row["event_id"] for row in rows], [older.event_id, newer.event_id])
            self.assertTrue(rows[0]["is_read"])
            self.assertTrue(rows[0]["is_pinned"])
            self.assertFalse(rows[1]["is_read"])
            self.assertFalse(rows[1]["is_pinned"])
            self.assertTrue(
                reopened.set_event_state(
                    older.event_id,
                    is_read=False,
                    is_pinned=False,
                    changed_at=400,
                )
            )
            self.assertFalse(reopened.get_event(older.event_id)["is_read"])
            self.assertFalse(reopened.get_event(older.event_id)["is_pinned"])
            self.assertFalse(
                reopened.set_event_state(
                    "missing-event",
                    is_read=True,
                    is_pinned=False,
                    changed_at=500,
                )
            )

    def test_dismissed_events_leave_the_audit_ledger_but_not_the_inbox_projection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.db")
            events = [
                build_event(
                    "channel.message",
                    correlation=("channel", f"message-{index}"),
                    detail={"message": f"Message {index}"},
                )
                for index in range(3)
            ]
            for event in events:
                store.record_event(event)

            self.assertTrue(store.dismiss_event(events[0].event_id, dismissed_at=100))
            self.assertTrue(store.dismiss_event(events[0].event_id, dismissed_at=101))
            self.assertFalse(store.dismiss_event("missing-event", dismissed_at=101))
            self.assertEqual(
                store.dismiss_events(
                    event_types=["channel.message"],
                    created_before=9_999_999_999,
                    dismissed_at=102,
                ),
                2,
            )

            self.assertEqual(store.list_events(), [])
            self.assertEqual(store.get_event(events[0].event_id)["dismissed_at"], 100)

    def test_attention_events_can_be_resolved_by_request_session_or_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.db")
            events = [
                build_event(
                    "attention.required",
                    correlation=("clarify", request_id),
                    session_id=session_id,
                    detail={"request_id": request_id, "question": "Choose one"},
                )
                for request_id, session_id in (
                    ("request-1", "session-1"),
                    ("request-2", "session-1"),
                    ("request-3", "session-2"),
                )
            ]
            for event in events:
                store.record_event(event)
            with sqlite3.connect(store.path) as connection:
                connection.execute(
                    "UPDATE events SET created_at=10 WHERE event_id=?",
                    (events[2].event_id,),
                )

            self.assertEqual(
                store.dismiss_attention_request(
                    "request-1",
                    session_id="session-1",
                    dismissed_at=20,
                ),
                1,
            )
            self.assertEqual(
                store.dismiss_attention_for_session("session-1", dismissed_at=21),
                1,
            )
            self.assertEqual(store.dismiss_expired_attention(10, dismissed_at=22), 1)
            self.assertEqual(store.list_events(), [])

    def test_absolute_deadline_clarify_remains_projectable_after_expiry_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.db")
            clarify = build_event(
                "attention.required",
                correlation=("clarify", "clarify-1"),
                session_id="session-key-1",
                detail={
                    "kind": "clarify",
                    "request_id": "clarify-1",
                    "question": "Choose one",
                    "expires_at": "20",
                    "interaction": {"type": "clarify"},
                },
            )
            generic = build_event(
                "attention.required",
                correlation=("legacy", "request-2"),
                session_id="session-key-2",
                detail={"request_id": "request-2", "question": "Legacy attention"},
            )
            store.record_event(clarify)
            store.record_event(generic)
            with sqlite3.connect(store.path) as connection:
                connection.execute("UPDATE events SET created_at=10")

            self.assertEqual(store.dismiss_expired_attention(10, dismissed_at=22), 1)
            remaining = store.list_events()
            self.assertEqual([row["event_id"] for row in remaining], [clarify.event_id])
            self.assertEqual(
                store.dismiss_attention_for_session(
                    "session-key-1", dismissed_at=22
                ),
                0,
            )
            self.assertEqual(
                [row["event_id"] for row in store.list_events()],
                [clarify.event_id],
            )

    def test_known_gateway_lifecycle_messages_are_dismissed_without_hiding_chat(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.db")
            restart = build_event(
                "channel.message",
                correlation=("channel", "restart"),
                detail={"message": "⚠️ Gateway restarting — current work will pause."},
            )
            ordinary = build_event(
                "channel.message",
                correlation=("channel", "ordinary"),
                detail={"message": "The gateway restart is complete in staging."},
            )
            store.record_event(restart)
            store.record_event(ordinary)

            self.assertEqual(store.dismiss_gateway_lifecycle_events(dismissed_at=50), 1)
            self.assertEqual(
                [event["event_id"] for event in store.list_events()],
                [ordinary.event_id],
            )

    def test_legacy_relay_state_is_removed_without_losing_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "loopdy.sqlite3"
            event = build_event("session.completed", correlation=("turn", "turn-1"))
            _create_legacy_database(path, event)

            migrated = LoopdyStore(path)

            self.assertEqual(migrated.provider_mode(), "managed")
            self.assertEqual(migrated.provider_mode(), "managed")
            self.assertEqual(migrated.get_event(event.event_id)["status"], "sent")
            self.assertTrue(migrated.list_devices()[0]["revoked"])
            self.assertEqual(migrated.list_devices()[0]["provider"], "legacy_relay")

    def test_provider_state_target_resolution_and_receipts_are_durable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "loopdy.sqlite3"
            store = LoopdyStore(path)
            store.set_provider_mode("direct")
            store.save_apns_config(
                {
                    "team_id": "TEAM123456",
                    "key_id": "KEY1234567",
                    "topic": "app.loopdy.personal",
                    "environment": "production",
                    "key_path": "/private/config/AuthKey.p8",
                }
            )
            store.upsert_device(
                device_id="phone_123",
                endpoint_id="a" * 64,
                provider="direct",
                token_environment="production",
                groups=["personal"],
                preferences={"detail_mode": "automatic", "notifications_enabled": True},
            )
            event = build_event("session.completed", correlation=("turn", "turn-2"))
            store.record_event(event, target="group:personal")
            store.record_device_delivery(
                event_id=event.event_id,
                device_id="phone_123",
                provider="direct",
                status="sent",
                delivery_id="delivery-1",
            )
            store.record_provider_receipt(
                receipt_id="receipt-1",
                event_id=event.event_id,
                device_id="phone_123",
                provider="direct",
            )

            reopened = LoopdyStore(path)

            self.assertEqual(reopened.provider_mode(), "direct")
            self.assertEqual(reopened.load_apns_config()["topic"], "app.loopdy.personal")
            self.assertEqual(
                [device["device_id"] for device in reopened.resolve_devices("group:personal", "direct")],
                ["phone_123"],
            )
            self.assertEqual(
                reopened.pending_provider_receipts("direct")[0]["receipt_id"],
                "receipt-1",
            )
            self.assertTrue(
                reopened.complete_provider_receipt(
                    "receipt-1",
                    status="failed",
                    error="DeviceNotRegistered",
                )
            )
            self.assertEqual(reopened.pending_provider_receipts("direct"), [])

    def test_provider_mode_accepts_relay_and_rejects_legacy_or_unknown_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.set_provider_mode("relay")
            self.assertEqual(store.provider_mode(), "relay")
            for invalid in ("legacy_relay", "unknown"):
                with self.subTest(invalid=invalid):
                    with self.assertRaisesRegex(ValueError, "managed, direct, or relay"):
                        store.set_provider_mode(invalid)

    def test_relay_device_registration_is_monotonic_idempotent_leased_and_tombstoned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            body = {
                "version": 1,
                "device_id": "relay_phone_01",
                "revision": 7,
                "recipient_key_id": "key_fixture_01",
            }
            first = store.register_relay_device(
                device_id="relay_phone_01",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=7,
                lease_expires=2_692_000,
                normalized_body=body,
                label="Phone",
                groups=["personal"],
                now=100_000,
            )
            duplicate = store.register_relay_device(
                device_id="relay_phone_01",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=7,
                lease_expires=2_692_000,
                normalized_body=body,
                label="Phone",
                groups=["personal"],
                now=100_001,
            )
            self.assertTrue(first["changed"])
            self.assertFalse(duplicate["changed"])
            self.assertEqual(store.resolve_devices("all", "relay", now=100_003), [])
            with self.assertRaisesRegex(ValueError, "revision"):
                store.register_relay_device(
                    device_id="relay_phone_01",
                    recipient_public_key="B" + "A" * 86,
                    recipient_key_id="key_fixture_01",
                    revision=6,
                    lease_expires=2_692_000,
                    normalized_body={**body, "revision": 6},
                    now=100_002,
                )
            with self.assertRaisesRegex(ValueError, "idempotency"):
                store.register_relay_device(
                    device_id="relay_phone_01",
                    recipient_public_key="B" + "A" * 86,
                    recipient_key_id="key_fixture_01",
                    revision=7,
                    lease_expires=2_692_000,
                    normalized_body={**body, "label": "Different"},
                    now=100_003,
                )

            acknowledged = store.acknowledge_relay_sender_keys(
                device_id="relay_phone_01",
                revision=8,
                sender_key_revision=1,
                acknowledged_sender_key_ids=["sender_key_fixture_01"],
                normalized_body={
                    "version": 1,
                    "device_id": "relay_phone_01",
                    "revision": 8,
                    "sender_key_revision": 1,
                    "acknowledged_sender_key_ids": ["sender_key_fixture_01"],
                },
                now=100_004,
            )
            self.assertTrue(acknowledged["changed"])
            self.assertEqual(
                [
                    device["device_id"]
                    for device in store.resolve_devices("all", "relay", now=100_005)
                ],
                ["relay_phone_01"],
            )

            revoked = store.revoke_relay_device(
                device_id="relay_phone_01",
                revision=9,
                normalized_body={"version": 1, "device_id": "relay_phone_01", "revision": 9},
                now=100_005,
            )
            self.assertTrue(revoked["changed"])
            self.assertTrue(store.list_devices()[0]["revoked"])
            with self.assertRaisesRegex(ValueError, "higher revision"):
                store.register_relay_device(
                    device_id="relay_phone_01",
                    recipient_public_key="B" + "A" * 86,
                    recipient_key_id="key_fixture_01",
                    revision=9,
                    lease_expires=2_692_000,
                    normalized_body={**body, "revision": 9},
                    now=100_006,
                )
            reactivated = store.register_relay_device(
                device_id="relay_phone_01",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_02",
                revision=10,
                lease_expires=2_692_000,
                normalized_body={**body, "revision": 10, "recipient_key_id": "key_fixture_02"},
                now=100_007,
            )
            self.assertTrue(reactivated["changed"])
            self.assertFalse(store.list_devices()[0]["revoked"])

    def test_relay_recipient_key_change_clears_sender_ack_but_same_key_renewal_preserves_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            first_body = {"device_id": "relay_phone_01", "revision": 1}
            store.register_relay_device(
                device_id="relay_phone_01",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="recipient_key_fixture_01",
                revision=1,
                lease_expires=2_692_000,
                normalized_body=first_body,
                token_environment="sandbox",
                now=100_000,
            )
            store.acknowledge_relay_sender_keys(
                device_id="relay_phone_01",
                revision=2,
                sender_key_revision=4,
                acknowledged_sender_key_ids=["sender_key_fixture_01"],
                normalized_body={"device_id": "relay_phone_01", "revision": 2},
                now=100_001,
            )
            store.register_relay_device(
                device_id="relay_phone_01",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="recipient_key_fixture_01",
                revision=3,
                lease_expires=2_692_001,
                normalized_body={"device_id": "relay_phone_01", "revision": 3},
                token_environment="sandbox",
                now=100_002,
            )
            renewed = store.list_devices()[0]
            self.assertEqual(renewed["token_environment"], "sandbox")
            self.assertEqual(renewed["sender_key_revision"], 4)
            self.assertEqual(renewed["acknowledged_sender_key_ids"], ["sender_key_fixture_01"])

            store.register_relay_device(
                device_id="relay_phone_01",
                recipient_public_key="B" + "C" * 86,
                recipient_key_id="recipient_key_fixture_02",
                revision=4,
                lease_expires=2_692_002,
                normalized_body={"device_id": "relay_phone_01", "revision": 4},
                token_environment="production",
                now=100_003,
            )
            replaced = store.list_devices()[0]
            self.assertEqual(replaced["token_environment"], "production")
            self.assertEqual(replaced["sender_key_revision"], 0)
            self.assertEqual(replaced["acknowledged_sender_key_ids"], [])
            self.assertEqual(store.resolve_devices("all", "relay", now=100_004), [])

            for invalid in (True, 1.5):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    store.register_relay_device(
                        device_id="relay_phone_02",
                        recipient_public_key="B" + "A" * 86,
                        recipient_key_id="recipient_key_fixture_03",
                        revision=invalid,
                        lease_expires=2_692_003,
                        normalized_body={"device_id": "relay_phone_02"},
                        now=100_004,
                    )

    def test_relay_config_generation_invalidates_old_devices_without_remote_revoke(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            old_config = {
                "base_url": "https://relay.example.invalid",
                "tenant_id": "TENANT_EXAMPLE",
                "credential_key_id": "credential_fixture_01",
                "hmac_secret_reference": "env:LOOPDY_RELAY_HMAC",
                "signing_key_secret_reference": "env:LOOPDY_RELAY_SIGNING_KEY",
            }
            store.save_relay_config(old_config)
            store.register_relay_device(
                device_id="relay_phone_01",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=1,
                lease_expires=2_692_000,
                normalized_body={"device_id": "relay_phone_01", "revision": 1},
                now=100_000,
            )
            store.acknowledge_relay_sender_keys(
                device_id="relay_phone_01",
                revision=2,
                sender_key_revision=1,
                acknowledged_sender_key_ids=["sender_key_fixture_01"],
                normalized_body={"device_id": "relay_phone_01", "revision": 2},
                now=100_000,
            )
            self.assertEqual(len(store.resolve_devices("all", "relay", now=100_001)), 1)
            store.save_relay_config({**old_config, "credential_key_id": "credential_fixture_02"})
            self.assertEqual(store.resolve_devices("all", "relay", now=100_001), [])
            self.assertFalse(store.list_devices()[0]["revoked"])
            store.register_relay_device(
                device_id="relay_phone_01",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=3,
                lease_expires=2_691_000,
                normalized_body={"device_id": "relay_phone_01", "revision": 3},
                now=100_001,
            )
            self.assertEqual(store.list_devices()[0]["relay_generation"], store.relay_config_generation())

    def test_removed_relay_config_exposes_disabled_rows_as_revoked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
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
                device_id="relay_phone_01",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=1,
                lease_expires=2_692_000,
                normalized_body={"device_id": "relay_phone_01", "revision": 1},
                now=100_000,
            )

            store.clear_relay_config()

            self.assertTrue(store.list_devices()[0]["revoked"])
            self.assertTrue(store.get_device("relay_phone_01")["revoked"])

    def test_relay_tenant_tombstone_cancels_activities_and_pending_updates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.save_relay_config({
                "base_url": "https://relay.example.invalid",
                "tenant_id": "TENANT_EXAMPLE",
                "credential_key_id": "credential_fixture_01",
                "hmac_secret_reference": "env:LOOPDY_RELAY_HMAC",
                "signing_key_secret_reference": "env:LOOPDY_RELAY_SIGNING_KEY",
            })
            store.register_relay_device(
                device_id="relay_phone_01", recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01", revision=1, lease_expires=2_692_000,
                normalized_body={"device_id": "relay_phone_01", "revision": 1}, now=100_000,
            )
            store.register_relay_live_activity(
                activity_id="activity_fixture_01", device_id="relay_phone_01",
                session_ref="Q0RFRkdISUpLTE1OT1A", revision=1, timestamp=1_000,
                lease_expires=29_800,
                normalized_body={"activity_id": "activity_fixture_01", "revision": 1},
            )
            store.defer_relay_live_activity_update(
                activity_id="activity_fixture_01", status="completed", detail="",
                tool_name="", active_session_count=0, delay_seconds=0, failure="offline",
            )
            store.revoke_relay_tenant()
            self.assertEqual(store.resolve_devices("all", "relay", now=100_001), [])
            self.assertEqual(store.active_relay_live_activities("Q0RFRkdISUpLTE1OT1A", now=100_001), [])
            self.assertEqual(store.pending_relay_live_activity_updates(), [])

    def test_relay_tenant_delete_purges_only_relay_local_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.register_relay_device(
                device_id="relay_phone_01", recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01", revision=1, lease_expires=2_692_000,
                normalized_body={"device_id": "relay_phone_01", "revision": 1}, now=100_000,
            )
            store.upsert_device(
                device_id="managed_phone_01",
                endpoint_id="ExponentPushToken[fixture-managed]",
                provider="managed",
            )
            store.register_relay_live_activity(
                activity_id="relay_activity_01", device_id="relay_phone_01",
                session_ref="Q0RFRkdISUpLTE1OT1A", revision=1, timestamp=1_000,
                lease_expires=29_800,
                normalized_body={"activity_id": "relay_activity_01", "revision": 1},
            )
            store.record_device_delivery(
                event_id="event_relay", device_id="relay_phone_01", provider="relay", status="sent",
                delivery_id="delivery_relay",
            )
            store.record_device_delivery(
                event_id="event_managed", device_id="managed_phone_01", provider="managed", status="sent",
                delivery_id="delivery_managed",
            )
            store.record_provider_receipt(
                receipt_id="receipt_relay", event_id="event_relay", device_id="relay_phone_01", provider="relay",
            )
            store.record_provider_receipt(
                receipt_id="receipt_managed", event_id="event_managed", device_id="managed_phone_01", provider="managed",
            )
            store.revoke_relay_tenant(clear_config=True)

            self.assertEqual([item["device_id"] for item in store.list_devices()], ["managed_phone_01"])
            self.assertEqual(store.active_relay_live_activities("Q0RFRkdISUpLTE1OT1A"), [])
            self.assertIsNone(store.load_relay_config())
            self.assertEqual(store.list_event_deliveries("event_relay"), [])
            self.assertEqual(len(store.list_event_deliveries("event_managed")), 1)
            self.assertEqual(store.pending_provider_receipts("relay"), [])
            self.assertEqual(len(store.pending_provider_receipts("managed")), 1)

    def test_relay_live_activity_reregistration_clears_frozen_pending_update(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            now = 100_000
            store.register_relay_device(
                device_id="relay_phone_01",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=1,
                lease_expires=now + 2_592_000,
                normalized_body={"device_id": "relay_phone_01", "revision": 1},
                now=now,
            )
            store.register_relay_live_activity(
                activity_id="relay_activity_01",
                device_id="relay_phone_01",
                session_ref="Q0RFRkdISUpLTE1OT1A",
                revision=1,
                timestamp=now,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": "relay_activity_01", "revision": 1},
            )
            store.defer_relay_live_activity_update(
                activity_id="relay_activity_01",
                status="running",
                detail="",
                tool_name="",
                active_session_count=1,
                delay_seconds=0,
                failure="offline",
                timestamp=now + 1,
                delivery_id="old-delivery",
                idempotency_key="00000000-0000-5000-8000-000000000001",
                request_body={"device_id": "relay_phone_01", "delivery_id": "old-delivery"},
            )

            store.register_relay_live_activity(
                activity_id="relay_activity_01",
                device_id="relay_phone_01",
                session_ref="Q0RFRkdISUpLTE1OT1A",
                revision=2,
                timestamp=now + 2,
                lease_expires=now + 28_800,
                normalized_body={"activity_id": "relay_activity_01", "revision": 2},
            )

            with self.assertRaisesRegex(ValueError, "owner"):
                store.defer_relay_live_activity_update(
                    activity_id="relay_activity_01",
                    status="running",
                    detail="",
                    tool_name="",
                    active_session_count=1,
                    delay_seconds=0,
                    failure="offline",
                    timestamp=now + 3,
                    delivery_id="stale-delivery",
                    idempotency_key="00000000-0000-5000-8000-000000000003",
                    request_body={"device_id": "relay_phone_01", "delivery_id": "stale-delivery"},
                    expected_device_id="relay_phone_01",
                    expected_session_ref="Q0RFRkdISUpLTE1OT1A",
                    expected_revision=1,
                    expected_lease_expires=now + 28_800,
                    expected_relay_generation=store.relay_config_generation(),
                )

            self.assertIsNone(store.pending_relay_live_activity_update("relay_activity_01"))

    def test_relay_config_and_reregistration_cancel_queued_ciphertext(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            config = {
                "base_url": "https://relay.example.invalid",
                "tenant_id": "TENANT_EXAMPLE",
                "credential_key_id": "credential_fixture_01",
                "hmac_secret_reference": "env:LOOPDY_RELAY_HMAC",
                "signing_key_secret_reference": "env:LOOPDY_RELAY_SIGNING_KEY",
            }
            store.save_relay_config(config)
            now = 100_000
            store.register_relay_device(
                device_id="relay_phone_01",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=1,
                lease_expires=now + 2_592_000,
                normalized_body={"device_id": "relay_phone_01", "revision": 1},
                now=now,
            )
            event = build_event("channel.message", correlation=("queued-ciphertext",))
            store.record_event(event, target="all")
            store.record_device_delivery(
                event_id=event.event_id,
                device_id="relay_phone_01",
                provider="relay",
                status="queued",
                target_revision=1,
                target_generation=store.relay_config_generation(),
                relay_request_body={"device_id": "relay_phone_01", "ciphertext": "old"},
            )

            store.save_relay_config({**config, "credential_key_id": "credential_fixture_02"})
            canceled = store.list_event_deliveries(event.event_id)[0]
            self.assertEqual(canceled["status"], "failed")
            self.assertEqual(canceled["failure"], "relay_target_changed")
            self.assertEqual(canceled["relay_request_body_json"], "")

            store.register_relay_device(
                device_id="relay_phone_01",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=2,
                lease_expires=now + 2_592_000,
                normalized_body={"device_id": "relay_phone_01", "revision": 2},
                now=now + 1,
            )
            self.assertEqual(store.list_event_deliveries(event.event_id)[0]["relay_request_body_json"], "")

    def test_relay_operation_journal_persists_response_for_restart_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            body = {
                "version": 1,
                "device_id": "relay_phone_01",
                "revision": 1,
                "idempotency_key": "00000000-0000-5000-8000-000000000001",
            }
            store.save_pending_relay_operation(
                operation="register_device",
                device_id="relay_phone_01",
                revision=1,
                idempotency_key=body["idempotency_key"],
                body=body,
                relay_generation=store.relay_config_generation(),
            )
            store.record_relay_operation_response(
                operation="register_device",
                device_id="relay_phone_01",
                response={"version": 1, "status": "accepted", "device_id": "relay_phone_01"},
            )

            pending = store.pending_relay_operation("register_device", "relay_phone_01")
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertEqual(json.loads(pending["response_json"])["status"], "accepted")
            self.assertEqual(pending["relay_generation"], store.relay_config_generation())

    def test_terminal_relay_operation_can_be_reset_without_active_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            body = {
                "version": 1,
                "device_id": "relay_phone_01",
                "revision": 1,
                "idempotency_key": "00000000-0000-5000-8000-000000000001",
            }
            store.save_pending_relay_operation(
                operation="register_device",
                device_id="relay_phone_01",
                revision=1,
                idempotency_key=body["idempotency_key"],
                body=body,
                relay_generation=store.relay_config_generation(),
            )
            pending = store.pending_relay_operation("register_device", "relay_phone_01")
            self.assertIsNotNone(pending)
            assert pending is not None
            request_digest = str(pending["request_digest"])
            self.assertTrue(
                store.quarantine_relay_operation(
                    "register_device",
                    "relay_phone_01",
                    error="terminal fixture",
                    request_digest=request_digest,
                )
            )

            self.assertTrue(
                store.reset_relay_operation(
                    "register_device",
                    "relay_phone_01",
                    request_digest=request_digest,
                )
            )
            reset = store.pending_relay_operation("register_device", "relay_phone_01")
            self.assertIsNotNone(reset)
            assert reset is not None
            self.assertEqual(reset["terminal"], 0)
            self.assertEqual(reset["last_error"], "")
            self.assertEqual(reset["attempts"], 0)

    def test_active_terminal_recovery_claim_blocks_reset_until_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            body = {
                "version": 1,
                "device_id": "relay_phone_01",
                "revision": 1,
                "idempotency_key": "00000000-0000-5000-8000-000000000001",
            }
            store.save_pending_relay_operation(
                operation="register_device",
                device_id="relay_phone_01",
                revision=1,
                idempotency_key=body["idempotency_key"],
                body=body,
                relay_generation=store.relay_config_generation(),
            )
            store.record_relay_operation_response(
                operation="register_device",
                device_id="relay_phone_01",
                response={"version": 1, "status": "accepted"},
            )
            pending = store.pending_relay_operation("register_device", "relay_phone_01")
            self.assertIsNotNone(pending)
            assert pending is not None
            request_digest = str(pending["request_digest"])
            self.assertTrue(
                store.quarantine_relay_operation(
                    "register_device",
                    "relay_phone_01",
                    error="Device is already registered with another provider",
                    request_digest=request_digest,
                )
            )
            claims = store.claim_terminal_provider_conflict_registrations()
            self.assertEqual(len(claims), 1)
            claim = claims[0]

            self.assertFalse(
                store.reset_relay_operation(
                    "register_device",
                    "relay_phone_01",
                    request_digest=request_digest,
                )
            )
            with mock.patch(
                "loopdy_plugin.store.time.time",
                return_value=int(claim["claim_expires"]),
            ):
                self.assertTrue(
                    store.reset_relay_operation(
                        "register_device",
                        "relay_phone_01",
                        request_digest=request_digest,
                    )
                )

    def test_relay_registration_cas_rejects_generation_changed_during_remote_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            config = {
                "base_url": "https://relay.example.invalid",
                "tenant_id": "TENANT_EXAMPLE",
                "credential_key_id": "credential_fixture_01",
                "hmac_secret_reference": "env:LOOPDY_RELAY_HMAC",
                "signing_key_secret_reference": "env:LOOPDY_RELAY_SIGNING_KEY",
            }
            store.save_relay_config(config)
            expected = store.relay_config_generation()
            store.save_relay_config({**config, "credential_key_id": "credential_fixture_02"})

            with self.assertRaisesRegex(ValueError, "generation"):
                store.register_relay_device(
                    device_id="relay_phone_01",
                    recipient_public_key="B" + "A" * 86,
                    recipient_key_id="key_fixture_01",
                    revision=1,
                    lease_expires=2_692_000,
                    normalized_body={"device_id": "relay_phone_01", "revision": 1},
                    expected_relay_generation=expected,
                    now=100_000,
                )

    def test_pending_delivery_retains_original_relay_revision_and_recipient_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.register_relay_device(
                device_id="relay_phone_01",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_01",
                revision=1,
                lease_expires=2_692_000,
                normalized_body={"device_id": "relay_phone_01", "revision": 1},
                now=100_000,
            )
            store.acknowledge_relay_sender_keys(
                device_id="relay_phone_01",
                revision=2,
                sender_key_revision=1,
                acknowledged_sender_key_ids=["sender_key_fixture_01"],
                normalized_body={"device_id": "relay_phone_01", "revision": 2},
                now=100_000,
            )
            event = build_event("approval.required", correlation=("relay-snapshot",))
            store.record_event(event, target="device:relay_phone_01")
            store.record_device_delivery(
                event_id=event.event_id,
                device_id="relay_phone_01",
                provider="relay",
                status="queued",
                target_revision=1,
                target_key_id="key_fixture_01",
                target_sender_key_id="sender_key_fixture_01",
            )
            store.register_relay_device(
                device_id="relay_phone_01",
                recipient_public_key="B" + "A" * 86,
                recipient_key_id="key_fixture_02",
                revision=3,
                lease_expires=2_692_001,
                normalized_body={"device_id": "relay_phone_01", "revision": 3},
                now=100_001,
            )
            pending = store.list_event_deliveries(event.event_id)[0]
            self.assertEqual(pending["target_revision"], 1)
            self.assertEqual(pending["target_key_id"], "key_fixture_01")
            self.assertEqual(pending["target_sender_key_id"], "sender_key_fixture_01")

    def test_relay_live_activity_rejects_nonincreasing_watermarks_and_reactivates_higher_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            first = store.register_relay_live_activity(
                activity_id="activity_fixture_01",
                device_id="relay_phone_01",
                session_ref="Q0RFRkdISUpLTE1OT1A",
                revision=1,
                timestamp=1_000,
                lease_expires=29_800,
                normalized_body={"activity_id": "activity_fixture_01", "revision": 1, "timestamp": 1_000},
            )
            self.assertTrue(first["changed"])
            for timestamp in (999, 1_000):
                with self.subTest(timestamp=timestamp), self.assertRaisesRegex(
                    ValueError, "timestamp"
                ):
                    store.register_relay_live_activity(
                        activity_id="activity_fixture_01",
                        device_id="relay_phone_01",
                        session_ref="Q0RFRkdISUpLTE1OT1A",
                        revision=2,
                        timestamp=timestamp,
                        lease_expires=timestamp + 28_800,
                        normalized_body={"activity_id": "activity_fixture_01", "revision": 2, "timestamp": timestamp},
                    )
            store.revoke_relay_live_activity(
                activity_id="activity_fixture_01",
                revision=2,
                timestamp=1_001,
                normalized_body={"activity_id": "activity_fixture_01", "revision": 2, "timestamp": 1_001},
            )
            with self.assertRaisesRegex(ValueError, "higher revision"):
                store.register_relay_live_activity(
                    activity_id="activity_fixture_01",
                    device_id="relay_phone_01",
                    session_ref="Q0RFRkdISUpLTE1OT1A",
                    revision=2,
                    timestamp=1_002,
                    lease_expires=29_802,
                    normalized_body={"activity_id": "activity_fixture_01", "revision": 2, "timestamp": 1_002},
                )

    def test_live_activity_tokens_match_stored_or_live_session_and_can_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.upsert_live_activity(
                session_id="stored-session",
                live_session_id="live-session",
                profile="default",
                activity_id="activity-1",
                push_token="f" * 64,
                token_environment="production",
            )

            self.assertEqual(
                store.active_live_activities("stored-session", "default")[0]["activity_id"],
                "activity-1",
            )
            self.assertEqual(
                store.active_live_activities("live-session", "default")[0]["push_token"],
                "f" * 64,
            )
            self.assertEqual(store.active_live_activities("live-session", "other"), [])
            store.end_live_activity("activity-1")
            self.assertEqual(store.active_live_activities("live-session", "default"), [])

    def test_schema_three_live_activities_gain_persisted_push_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "loopdy.sqlite3"
            with sqlite3.connect(path) as connection:
                connection.executescript(
                    """
                    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO metadata(key, value) VALUES ('schema_version', '3');
                    CREATE TABLE live_activities (
                        activity_id TEXT PRIMARY KEY,
                        session_id TEXT NOT NULL,
                        live_session_id TEXT NOT NULL,
                        profile TEXT NOT NULL,
                        push_token TEXT NOT NULL,
                        token_environment TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        ended_at INTEGER
                    );
                    INSERT INTO live_activities VALUES (
                        'activity-1', 'stored-session', 'live-session', 'default',
                        'token', 'production', 1, 1, NULL
                    );
                    """
                )

            store = LoopdyStore(path)

            self.assertEqual(store.allocate_live_activity_timestamp("activity-1", 100), 100)
            self.assertEqual(store.allocate_live_activity_timestamp("activity-1", 100), 101)
            with sqlite3.connect(path) as connection:
                version = connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()
            self.assertEqual(version, ("8",))

    def test_live_activity_send_lock_serializes_across_processes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "loopdy.sqlite3"
            ready = Path(directory) / "ready"
            acquired = Path(directory) / "acquired"
            store = LoopdyStore(path)
            child_code = """
from pathlib import Path
import sys
from loopdy_plugin.store import LoopdyStore

store = LoopdyStore(Path(sys.argv[1]))
Path(sys.argv[2]).write_text("ready")
with store.live_activity_send_lock("activity-1"):
    Path(sys.argv[3]).write_text("acquired")
"""

            with store.live_activity_send_lock("activity-1"):
                child = subprocess.Popen(
                    [sys.executable, "-c", child_code, str(path), str(ready), str(acquired)],
                    env=os.environ.copy(),
                )
                deadline = time.monotonic() + 2
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                time.sleep(0.05)
                self.assertFalse(acquired.exists())

            self.assertEqual(child.wait(timeout=2), 0)
            self.assertTrue(acquired.exists())

    def test_approval_responses_preserve_every_hermes_scope_and_are_first_writer_wins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.create_approval(
                approval_id="approval_123",
                request_digest="digest_456",
                allowed_choices=["once", "session", "always", "deny"],
                event_id="event_789",
                expires_at=9_999_999_999,
            )

            self.assertTrue(store.respond_approval("approval_123", "always"))
            self.assertFalse(store.respond_approval("approval_123", "deny"))
            self.assertEqual(
                store.get_approval("approval_123"),
                {
                    "approval_id": "approval_123",
                    "request_digest": "digest_456",
                    "allowed_choices": ["once", "session", "always", "deny"],
                    "event_id": "event_789",
                    "status": "responded",
                    "choice": "always",
                    "expires_at": 9_999_999_999,
                },
            )


def _create_legacy_database(path: Path, event) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE devices (
                device_id TEXT PRIMARY KEY,
                endpoint_id TEXT NOT NULL UNIQUE,
                label TEXT NOT NULL,
                groups_json TEXT NOT NULL,
                preferences_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                revoked_at INTEGER
            );
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                status TEXT NOT NULL,
                target TEXT NOT NULL,
                profile TEXT NOT NULL,
                session_id TEXT NOT NULL,
                job_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                approval_id TEXT NOT NULL,
                delegation_id TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                push_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                delivered_at INTEGER,
                delivery_id TEXT,
                failure TEXT
            );
            """
        )
        connection.executemany(
            "INSERT INTO metadata(key, value) VALUES (?, ?)",
            [
                ("relay_url", "https://relay.example.test"),
                ("credential", "legacy-credential"),
                ("installation_id", "legacy-installation"),
            ],
        )
        connection.execute(
            "INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
            ("old-phone", "old-endpoint", "Old phone", "[]", "{}", 1, 1),
        )
        connection.execute(
            "INSERT INTO events VALUES (?, ?, 'sent', 'all', ?, '', '', '', '', '', ?, ?, 1, 2, ?, NULL)",
            (
                event.event_id,
                event.type,
                event.profile,
                json.dumps(dict(event.detail)),
                json.dumps(event.push_payload),
                "legacy-delivery",
            ),
        )
        connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    unittest.main()
