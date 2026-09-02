from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from loopdy_plugin.approval import LoopdyApprovalTransport
from loopdy_plugin.store import LoopdyStore


@dataclass(frozen=True)
class _Decision:
    request_id: str
    request_digest: str
    choice: str


@dataclass(frozen=True)
class _Request:
    request_id: str = "approval-123"
    digest: str = "digest-456"
    command: str = "cat /private/file"
    description: str = "Read private file"
    pattern_key: str = "cat"
    pattern_keys: tuple[str, ...] = ("cat",)
    surface: str = "gateway"
    timeout_seconds: float = 1
    allowed_choices: tuple[str, ...] = ("once", "session", "always", "deny")

    def respond(self, choice: str) -> _Decision:
        return _Decision(self.request_id, self.digest, choice)


class _Service:
    def __init__(self, store: LoopdyStore):
        self.store = store
        self.events = []

    def deliver(self, event, *, target):
        self.events.append((event, target))
        self.store.respond_approval(event.approval_id, "session")
        return {"success": True, "message_id": "delivery-1"}


class _FailedService:
    def deliver(self, event, *, target):
        return {"error": "offline"}


class ApprovalTransportTests(unittest.TestCase):
    def test_returns_only_the_request_bound_human_decision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            service = _Service(store)
            transport = LoopdyApprovalTransport(
                store,
                service,
                target="all",
                agent_name="Atlas",
                poll_interval=0.001,
            )

            decision = transport.present(_Request())

            self.assertEqual(decision, _Decision("approval-123", "digest-456", "session"))
            event = service.events[0][0]
            self.assertEqual(event.type, "approval.required")
            self.assertNotIn("private", str(event.push_payload))
            self.assertEqual(
                event.detail["allowed_choices"],
                ["once", "session", "always", "deny"],
            )
            self.assertEqual(event.detail["interaction"], {
                "schemaVersion": 1,
                "type": "approval",
                "requestId": "approval-123",
                "expiresAt": event.detail["expires_at"],
                "allowedChoices": ["once", "session", "always", "deny"],
            })
            self.assertEqual(event.detail["agent_name"], "Atlas")
            self.assertEqual(
                store.get_approval("approval-123")["allowed_choices"],
                ["once", "session", "always", "deny"],
            )
            self.assertEqual(store.get_approval("approval-123")["status"], "responded")

    def test_delivery_failure_denies_without_waiting_for_the_host_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            transport = LoopdyApprovalTransport(
                store,
                _FailedService(),
                poll_interval=0.001,
            )

            started = __import__("time").monotonic()
            decision = transport.present(_Request(timeout_seconds=30))

            self.assertEqual(decision.choice, "deny")
            self.assertLess(__import__("time").monotonic() - started, 1)


if __name__ == "__main__":
    unittest.main()
