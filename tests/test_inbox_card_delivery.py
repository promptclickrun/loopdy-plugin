"""Exercise the composed cron-final -> inbox -> workspace response contract."""
from __future__ import annotations

import asyncio
import copy
import json
import tempfile
import unittest
from types import SimpleNamespace
from datetime import datetime, timezone
from pathlib import Path

from loopdy_plugin.adapter import _channel_event
from loopdy_plugin.link_contracts import WorkspaceRequest, workspace_result
from loopdy_plugin.loopdy_cards import render_card
from loopdy_plugin.workspace_control import _event_projection

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/loopdy_card_v1/static-metrics.json"
NOW = 1_788_000_000


def rendered_card():
    return render_card(json.loads(FIXTURE.read_text()), now=datetime.fromtimestamp(NOW, timezone.utc))


def projected_event(card):
    # Hermes sends only the final response through the scheduler-owned adapter.
    text = ("Cronjob Response: Briefing\n(job_id: fixture-job)\n-------------\n\n"
            + json.dumps(card)
            + "\n\nTo stop or manage this job, send me a new message asking to pause it.")
    event = _channel_event(text, metadata={"job_id": "fixture-job", "profile": "default"})
    return _event_projection({
        "event_id": "channel.message:briefing", "type": "channel.message", "profile": "default",
        "session_id": None, "approval_id": None, "created_at": NOW,
        "detail": event.detail, "is_read": False, "is_pinned": False,
    })


class InboxCardDeliveryTests(unittest.TestCase):
    def test_renderer_card_survives_cron_final_and_both_dashboard_versions(self):
        card = rendered_card()
        event = projected_event(card)
        self.assertEqual(event["detail"]["generative_ui"], card)
        for request_payload in ({}, {"schemaVersion": 2}):
            with self.subTest(request_payload=request_payload):
                result = workspace_result(
                    request=WorkspaceRequest(request_id="fixture-request", operation="dashboard.load",
                                             payload=request_payload, sent_at=NOW),
                    status="completed", payload={"events": [event]}, sent_at=NOW,
                )
                self.assertEqual(result["payload"]["events"][0]["detail"]["generative_ui"], card)


    def result(self, payload, operation="dashboard.load", status="completed"):
        return workspace_result(
            request=WorkspaceRequest(request_id="fixture-request", operation=operation, payload={}, sent_at=NOW),
            status=status, payload=payload, sent_at=NOW,
        )

    def test_persisted_card_and_ordinary_event_survive_backend_and_encryption(self):
        from loopdy_plugin.link_crypto import AccountCipher
        from loopdy_plugin.store import LoopdyStore
        from loopdy_plugin.workspace_control import HermesWorkspaceBackend

        card = rendered_card()
        with tempfile.TemporaryDirectory() as folder:
            store = LoopdyStore(Path(folder) / "loopdy.sqlite3")
            event = _channel_event(json.dumps(card), metadata={"job_id": "fixture-job", "profile": "default"})
            store.record_event(event, target="all")
            store.record_event(_channel_event("Ordinary update", metadata={"profile": "default"}), target="all")
            for options in ({}, {"schemaVersion": 2}):
                # Reopen the actual store, as a later dashboard refresh would.
                reopened = LoopdyStore(store.path)
                backend = HermesWorkspaceBackend(service=SimpleNamespace(store=reopened))
                payload = asyncio.run(backend.dashboard_load(options))
                result = self.result(payload)
                cipher = AccountCipher(bytes(range(32)))
                decoded = cipher.open(cipher.seal(result))
                self.assertEqual(decoded, result)
                self.assertEqual(len(decoded["payload"]["events"]), 2)
                cards = [e["detail"]["generative_ui"] for e in decoded["payload"]["events"]
                         if "generative_ui" in e["detail"]]
                self.assertEqual(cards, [card])

    def test_bad_optional_card_preserves_base_and_neighbor_without_mutating_source(self):
        valid = projected_event(rendered_card())
        for invalid in ({"schema": "unsupported"}, {"secret": "fixture"}, ["invalid"]):
            damaged = copy.deepcopy(valid)
            damaged["detail"]["generative_ui"] = invalid
            original = copy.deepcopy(damaged)
            result = self.result({"events": [damaged, valid]})
            self.assertNotIn("generative_ui", result["payload"]["events"][0]["detail"])
            self.assertEqual(result["payload"]["events"][1], valid)
            self.assertEqual(damaged, original)

    def test_optional_cards_do_not_relax_generic_secret_or_depth_guards(self):
        event = projected_event(rendered_card())
        for key in ("password", "gatewayToken", "authorization", "cookie", "credential", "secret"):
            broken = copy.deepcopy(event)
            broken["detail"][key] = "fixture"
            with self.assertRaises(ValueError):
                self.result({"events": [broken]})
        deep = "value"
        for _ in range(10):
            deep = {"child": deep}
        with self.assertRaises(ValueError):
            self.result({"events": [event], "unrelated": deep})
        with self.assertRaises(ValueError):
            self.result({"events": [event]}, operation="sessions.list")
        with self.assertRaises(ValueError):
            self.result({"events": [event]}, status="failed")

    def test_legacy_card_is_unchanged(self):
        legacy = {"schema": "loopdy.generative_ui", "version": 1, "component": "summary",
                  "title": "Legacy briefing", "body": "Ordinary update"}
        event = projected_event(legacy)
        self.assertEqual(self.result({"events": [event]})["payload"]["events"][0], event)

    def test_swift_fixture_matches_real_serialized_and_encrypted_bytes(self):
        from loopdy_plugin.link_crypto import AccountCipher
        fixture = Path(__file__).resolve().parents[1] / "fixtures/inbox-card-workspace.json"
        result = self.result({"events": [projected_event(rendered_card())]})
        cipher = AccountCipher(bytes(range(32)))
        self.assertEqual(json.loads(fixture.read_text()), cipher.open(cipher.seal(result)))

    def test_aggregate_limit_drops_only_cards_that_do_not_fit(self):
        event = projected_event(rendered_card())
        events = [{**copy.deepcopy(event), "eventId": f"channel.message:fixture-{i}"} for i in range(180)]
        result = self.result({"events": events})
        payload = result["payload"]
        self.assertEqual(len(payload["events"]), 180)
        self.assertLessEqual(len(json.dumps(payload, ensure_ascii=False, separators=(",", ":"),
                                            sort_keys=True).encode()), 196_608)
        from loopdy_plugin.link_crypto import AccountCipher
        cipher = AccountCipher(bytes(range(32)))
        self.assertEqual(cipher.open(cipher.seal(result)), result)
        count = sum("generative_ui" in row["detail"] for row in payload["events"])
        self.assertGreater(count, 0)
        self.assertLess(count, 180)
        self.assertTrue(all("generative_ui" in row["detail"] for row in events))


if __name__ == "__main__":
    unittest.main()
