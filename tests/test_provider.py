from __future__ import annotations

import unittest

from loopdy_plugin.provider import (
    DeliveryError,
    DeliveryReceipt,
    LiveActivityState,
    ProviderStatus,
    PushMessage,
)


class ProviderContractTests(unittest.TestCase):
    def test_delivery_error_classifies_retry_and_invalid_token(self) -> None:
        invalid = DeliveryError(
            "DeviceNotRegistered",
            status=400,
            invalid_token=True,
        )
        temporary = DeliveryError("provider_unavailable", status=503)

        self.assertFalse(invalid.retryable)
        self.assertTrue(invalid.invalid_token)
        self.assertTrue(temporary.retryable)
        self.assertFalse(temporary.invalid_token)

    def test_provider_values_are_immutable_and_explicit(self) -> None:
        message = PushMessage(
            event_id="event-1",
            event_type="channel.message",
            title="Hermes just messaged you!",
            body="Deployment complete",
            data={"loopdy": {"event_id": "event-1"}},
            sound=True,
        )
        receipt = DeliveryReceipt(delivery_id="delivery-1", pending_receipt_id="receipt-1")
        status = ProviderStatus(mode="managed", configured=True, ready=True, detail="Ready")

        self.assertEqual(message.event_type, "channel.message")
        self.assertEqual(receipt.pending_receipt_id, "receipt-1")
        self.assertEqual(status.mode, "managed")
        with self.assertRaises(AttributeError):
            message.title = "Changed"

    def test_live_activity_state_is_sanitized_bounded_and_immutable(self) -> None:
        state = LiveActivityState(
            version=1,
            kind="live_activity",
            activity_id="activity_01",
            session_ref="Q0RFRkdISUpLTE1OT1A",
            phase="running",
            progress=42,
            active_session_count=2,
            timestamp=1_735_689_842,
            expires=1_735_689_962,
        )
        self.assertEqual(state.phase, "running")
        self.assertEqual(
            set(state.as_payload()),
            {
                "version",
                "kind",
                "activity_id",
                "session_ref",
                "phase",
                "progress",
                "active_session_count",
                "timestamp",
                "expires",
            },
        )
        with self.assertRaises(ValueError):
            LiveActivityState(**{**state.as_payload(), "phase": "callingTool"})
        with self.assertRaises(ValueError):
            LiveActivityState(**{**state.as_payload(), "expires": state.timestamp + 121})
        with self.assertRaises(AttributeError):
            state.phase = "failed"
        with self.assertRaises(ValueError):
            LiveActivityState(**{**state.as_payload(), "session_ref": "A" * 87})
        for activity_id in ("bad id", "bad\n", "bad\r", "évent", "\x00bad"):
            with self.subTest(activity_id=activity_id), self.assertRaises(ValueError):
                LiveActivityState(**{**state.as_payload(), "activity_id": activity_id})
        for field, value in (
            ("version", True),
            ("progress", True),
            ("progress", 1.5),
            ("active_session_count", False),
            ("active_session_count", 1.5),
            ("timestamp", True),
            ("timestamp", 1.5),
            ("expires", False),
            ("expires", 1.5),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                LiveActivityState(**{**state.as_payload(), field: value})


if __name__ == "__main__":
    unittest.main()
