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























    def test_closing_service_rejects_provider_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = LoopdyService(LoopdyStore(Path(directory) / "loopdy.sqlite3"))
            service._closing = True
            with self.assertRaisesRegex(DeliveryError, "service_closing"):
                service._provider("managed")
            self.assertNotIn("managed", service._providers)
            service._closing = False
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
                [("direct", 1)],
            )
            service.close()



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
