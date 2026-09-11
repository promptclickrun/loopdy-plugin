"""Retry identity at the scheduled and standalone notification boundary."""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from gateway.config import PlatformConfig
from gateway.platform_registry import PlatformEntry, platform_registry
from loopdy_plugin.adapter import LoopdyAdapter, _channel_event, standalone_send
from loopdy_plugin.generative_ui import render_v2_envelope
from loopdy_plugin.loopdy_cards import render_card
from loopdy_plugin.store import LoopdyStore


class NotificationCardIdentityTests(unittest.TestCase):
    def setUp(self):
        platform_registry.register(PlatformEntry(name="loopdy", label="Loopdy",
            adapter_factory=lambda config: None, check_fn=lambda: True))
        fixture = Path(__file__).resolve().parents[1] / "fixtures/loopdy_card_v1/static-metrics.json"
        self.payload = json.loads(fixture.read_text())
        self.now = datetime(2026, 1, 5, 12, tzinfo=timezone.utc)
        self.card = render_card(self.payload, now=self.now)
        self.raw = json.dumps(self.card)

    def test_timeout_then_metadata_free_fallback_keeps_one_persisted_card(self):
        async def exercise(path, card):
            raw = json.dumps(card)
            class TimeoutLink:
                connected = True

                async def send_payload(self, payload):
                    raise TimeoutError("synthetic acknowledgement timeout")

            store = LoopdyStore(path)
            service = SimpleNamespace(store=store)
            with patch("loopdy_plugin.adapter.load_runtime_config", return_value=None):
                first = LoopdyAdapter(PlatformConfig(enabled=True), service=service,
                                      workspace_controller=SimpleNamespace())
            first.link_client = TimeoutLink()
            result = await first.send("all", raw,
                                      metadata={"job_id": "fixture-brief", "profile": "default"})
            self.assertFalse(result.success)
            first_id = store.list_events()[0]["event_id"]
            # The real standalone path drops scheduler metadata and reconstructs
            # the adapter. Reopen storage to prove identity survives that boundary.
            reopened = LoopdyStore(path)
            with patch("loopdy_plugin.adapter.load_runtime_config", return_value=None):
                fallback = LoopdyAdapter(PlatformConfig(enabled=True),
                    service=SimpleNamespace(store=reopened), workspace_controller=SimpleNamespace())
            fallback.link_client = TimeoutLink()
            with (
                patch("loopdy_plugin.adapter._active_profile_id", return_value="default"),
                patch.object(fallback, "connect", new=AsyncMock(return_value=True)),
                patch.object(fallback, "disconnect", new=AsyncMock()),
            ):
                result = await standalone_send(PlatformConfig(enabled=True), "all", raw,
                    service=service, adapter_factory=lambda *args, **kwargs: fallback)
            self.assertIn("error", result)
            rows = reopened.list_events()
            self.assertEqual(len(rows), 1, "fallback must not create a second Inbox card")
            self.assertEqual(rows[0]["event_id"], first_id)
            self.assertEqual(rows[0]["job_id"], "fixture-brief")
            self.assertEqual(rows[0]["detail"]["generative_ui"], card)

        stock_fixture = Path(__file__).resolve().parents[1] / "fixtures/generative_ui_v2/valid-stock.json"
        stock = render_v2_envelope("loopdy_render_stock_quote", json.loads(stock_fixture.read_text()),
                                  now=datetime(2026, 8, 22, tzinfo=timezone.utc))
        for card in (self.card, stock):
            with self.subTest(schema=card["schema"]), tempfile.TemporaryDirectory() as folder:
                asyncio.run(exercise(Path(folder) / "events.sqlite3", card))

    def test_card_identity_preserves_instance_and_audience_boundaries(self):
        meta = {"job_id": "fixture-brief", "profile": "default"}
        original = _channel_event(self.raw, metadata=meta)
        wrapped = ("Cronjob Response: Brief\n(job_id: fixture-brief)\n-------------\n\n"
                   + json.dumps(self.card, sort_keys=True, indent=2)
                   + "\n\nTo stop or manage this job, send me a new message asking to pause it.")
        self.assertEqual(_channel_event(wrapped, metadata=meta).event_id, original.event_id)
        later = render_card(self.payload, now=self.now + timedelta(days=1))
        self.assertNotEqual(_channel_event(json.dumps(later), metadata=meta).event_id,
                            original.event_id)
        self.assertNotEqual(_channel_event(self.raw, metadata={"profile": "other"}).event_id,
                            original.event_id)
        self.assertNotEqual(_channel_event(self.raw, metadata=meta, target="other").event_id,
                            original.event_id)
        for text in ("Ordinary repeatable message", '{"schema":"loopdy.card","version":1}'):
            with self.subTest(text=text):
                self.assertNotEqual(_channel_event(text, metadata=meta).event_id,
                                    _channel_event(text, metadata=meta).event_id)


if __name__ == "__main__":
    unittest.main()
