from __future__ import annotations

import json
import sqlite3
import unittest
import uuid

from typing import Any
from loopdy_plugin.managed_notifications import ManagedNotifications
from tests import test_managed_notifications as fixtures


class ManagedApprovalNotificationTests(unittest.TestCase):
    service: ManagedNotifications
    grant: dict[str, Any]
    calls: list[tuple[str, str, bytes, dict[str, str]]]
    now: int
    setUp = fixtures.ManagedNotificationTests.setUp
    tearDown = fixtures.ManagedNotificationTests.tearDown
    get_session = fixtures.ManagedNotificationTests.get_session
    transport = fixtures.ManagedNotificationTests.transport

    def enroll_approval(self):
        self.grant_id = str(uuid.uuid4())
        self.grant = dict(self.grant, grantId=self.grant_id,
                          eventTypes=["session.completed", "session.failed", "approval.required"])
        self.service.enroll(self.grant_id, str(uuid.uuid4()))
        self.service.subscribe(self.grant_id, "default", "native-session", True)
        self.calls.clear()

    def approval(self, hook: str = "pre_approval_request", **changes: Any):
        payload = dict(profile="default", session_id="native-session", session_key="runtime-session",
                       turn_id="turn-a", tool_call_id="tool-a", surface="gateway",
                       command="PRIVATE command arguments", description="PRIVATE description")
        payload.update(changes)
        self.service.observe(hook, **payload)

    def pending(self):
        with sqlite3.connect(self.service.db_path) as db:
            return [json.loads(row[0]) for row in db.execute(
                "SELECT raw FROM pending WHERE state='pending' AND grant_id=? AND path='/events'",
                (self.grant_id,))]

    def test_human_approval_queues_one_exact_grant_owned_generic_alert(self):
        self.enroll_approval()
        self.service.observe("pre_llm_call", profile="default", session_id="native-session",
                             turn_id="turn-a", platform="desktop")
        self.approval()
        self.approval()
        rows = self.pending()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["eventType"], "approval.required")
        self.assertTrue(rows[0]["eventId"].startswith(self.grant_id + ":"))
        detail = self.service.event(self.grant_id, rows[0]["eventId"])["event"]
        self.assertEqual(detail["turnId"], "turn-a")
        self.assertEqual(detail["sessionId"], "native-session")
        self.assertNotIn("PRIVATE", json.dumps(detail))
        self.assertNotIn("requestId", detail, "The observer did not supply a native request ID")

    def test_old_completion_only_grant_does_not_authorize_approval(self):
        self.approval()
        self.assertEqual(self.pending(), [])

    def test_smart_coalesced_or_unowned_approval_never_queues(self):
        self.enroll_approval()
        for change in ({"surface": "smart"}, {"coalesced": True}, {"session_id": "other"},
                       {"profile": "other"}, {"session_id": ""}, {"tool_call_id": ""},
                       {"turn_id": ""}, {"surface": "cli"}):
            with self.subTest(change=change):
                self.approval(**dict[str, Any](change))
                self.assertEqual(self.pending(), [])

    def test_response_retires_unsent_tool_scoped_attention(self):
        self.enroll_approval()
        self.approval()
        self.assertEqual(len(self.pending()), 1)
        self.approval("post_approval_response", choice="notify_failed")
        self.assertEqual(self.pending(), [])
        self.now += 10
        self.service.drain_pending()
        self.assertFalse(any(path.endswith("/events") for _, path, _, _ in self.calls))

    def test_revocation_refuses_queued_approval(self):
        self.enroll_approval()
        self.approval()
        self.service.remove(self.grant_id)
        self.now += 10
        self.service.drain_pending()
        self.assertFalse(any(path.endswith("/events") for _, path, _, _ in self.calls))

    def event_calls(self):
        return [call for call in self.calls if call[1].endswith("/events")]

    def test_grace_then_frozen_retry_preserves_exact_ciphertext(self):
        self.enroll_approval()
        self.approval()
        self.service.drain_pending()
        self.assertEqual(self.event_calls(), [])
        self.now += 3
        self.fail_send = True
        self.service.drain_pending()
        self.assertEqual(len(self.event_calls()), 1)
        first = self.event_calls()[0]
        self.now += 3
        self.fail_send = False
        self.service.drain_pending()
        second = self.event_calls()[1]
        self.assertEqual(first[2], second[2])
        self.assertNotEqual(first[3]["x-loopdy-nonce"], second[3]["x-loopdy-nonce"])
        self.assertEqual(self.pending(), [])

    def test_response_before_pre_and_late_pre_cannot_resurrect(self):
        self.enroll_approval()
        self.approval("post_approval_response", choice="deny")
        self.approval()
        self.assertEqual(self.pending(), [])
        self.approval(tool_call_id="tool-b")
        self.assertEqual(len(self.pending()), 1)
        self.service.observe("on_session_end", profile="default", session_id="native-session",
                             turn_id="turn-a", interrupted=True)
        self.approval(tool_call_id="tool-c")
        self.assertEqual(self.pending(), [])

    def test_tool_end_retires_only_its_exact_attention(self):
        self.enroll_approval()
        self.approval()
        self.approval(tool_call_id="tool-b")
        self.service.observe("post_tool_call", profile="default", session_id="native-session",
                             turn_id="turn-a", tool_call_id="tool-a")
        self.approval()
        self.assertEqual(len(self.pending()), 1)
        self.now += 4
        self.service.drain_pending()
        self.assertEqual(len(self.event_calls()), 1)

    def test_new_process_drops_stale_attention_without_sending(self):
        self.enroll_approval()
        self.approval()
        self.service.close()
        self.service = ManagedNotifications(self.service.directory, transport=self.transport,
            clock=lambda: self.now, session_opener=lambda profile, read, read_only: read(self))
        self.now += 4
        self.service.drain_pending()
        self.assertEqual(self.event_calls(), [])
        self.approval()
        self.assertEqual(self.pending(), [])

    def test_api_reader_does_not_retire_live_producer_attention(self):
        self.enroll_approval()
        self.approval()
        reader = ManagedNotifications(self.service.directory, transport=self.transport,
            clock=lambda: self.now, session_opener=lambda profile, read, read_only: read(self))
        try:
            self.assertEqual(len(self.pending()), 1)
            self.now += 4
            self.service.drain_pending()
            self.assertEqual(len(self.event_calls()), 1)
        finally:
            reader.close()

    def test_expired_attention_is_never_sent(self):
        self.enroll_approval()
        self.approval()
        self.now += 61
        self.service.drain_pending()
        self.assertEqual(self.event_calls(), [])
        self.assertEqual(self.pending(), [])

    def test_response_during_final_session_check_prevents_transport(self):
        self.enroll_approval()
        self.approval()
        def opener(profile, read, read_only):
            self.approval("post_approval_response", choice="once")
            return read(self)
        self.service.session_opener = opener
        self.now += 4
        self.service.drain_pending()
        self.assertEqual(self.event_calls(), [])
        self.assertEqual(self.pending(), [])

    def test_inflight_error_cannot_resurrect_answered_approval(self):
        from loopdy_plugin.managed_notifications import ManagedNotificationError
        self.enroll_approval()
        self.approval()
        def transport(method, path, raw, headers):
            self.calls.append((method, path, raw, headers))
            self.approval("post_approval_response", choice="deny")
            raise ManagedNotificationError("synthetic_timeout", 503)
        self.service.transport = transport
        self.now += 4
        self.service.drain_pending()
        self.assertEqual(self.pending(), [])
        self.now += 20
        self.service.drain_pending()
        self.assertEqual(len(self.event_calls()), 1)

    def test_unsubscribe_fences_delayed_attention(self):
        self.enroll_approval()
        self.approval()
        self.service.subscribe(self.grant_id, "default", "native-session", False)
        self.now += 4
        self.service.drain_pending()
        self.assertEqual(self.event_calls(), [])


if __name__ == "__main__":
    unittest.main()
