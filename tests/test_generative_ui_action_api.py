from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from loopdy_plugin.generative_ui import render_v2_envelope
from loopdy_plugin.store import LoopdyStore


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PLUGIN_ROOT / "fixtures" / "generative_ui_v2" / "valid-form.json"
REQUEST_ID = "a" * 32
KEY = "123e4567-e89b-42d3-a456-426614174000"


class _Service:
    def __init__(self, store):
        self.store = store

    def health(self):
        return {"mode": "managed", "configured": True, "ready": True}


class GenerativeUiActionApiTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = LoopdyStore(Path(temporary.name) / "api.sqlite3")
        module_name = f"loopdy_dashboard_action_api_{id(self)}"
        spec = importlib.util.spec_from_file_location(module_name, PLUGIN_ROOT / "dashboard" / "plugin_api.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        assert spec.loader is not None
        spec.loader.exec_module(module)
        module._service = _Service(self.store)
        module._clock = lambda: 1787356810
        app = FastAPI()
        app.include_router(module.router)
        self.client = TestClient(app)

        payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
        from datetime import datetime, timezone
        now = datetime(2026, 8, 22, 0, 0, tzinfo=timezone.utc)
        card = render_v2_envelope(
            "loopdy_render_form",
            payload,
            now=now,
            profile="personal",
            session_id="stored-session",
            request_id_factory=lambda: REQUEST_ID,
        )
        self.store.create_form_request(
            request_id=REQUEST_ID,
            profile="personal",
            session_id="stored-session",
            form_schema=card["data"],
            content_hash=card["content_hash"],
            created_at=int(now.timestamp()),
            expires_at=int(now.timestamp()) + 300,
        )

    def body(self, **updates):
        value = {
            "schema": "loopdy.generative_ui.action_request",
            "version": 2,
            "kind": "submit_form",
            "idempotency_key": KEY,
            "owner": {"profile": "personal", "session_id": "stored-session"},
            "submitted_at": "2026-08-22T00:00:10Z",
            "values": {"departure_day": "friday", "bags": 2},
        }
        value.update(updates)
        return value

    def test_capabilities_advertise_exact_v1_v2_contract(self) -> None:
        value = self.client.get("/capabilities").json()["generative_ui"]
        self.assertEqual(value["schema"], "loopdy.generative_ui")
        self.assertEqual(value["supported_versions"], [1, 2])
        self.assertEqual(value["preferred_version"], 2)
        self.assertEqual(value["components"]["2"], ["weather_forecast", "sports_game", "stock_quote", "chart", "dashboard", "form"])
        self.assertEqual(value["actions"], {"2": ["submit_form"]})
        self.assertEqual(value["max_payload_bytes"], {"1": 16384, "2": 32768})
        self.assertEqual(value["max_action_bytes"], 8192)

    def test_fixed_submit_and_status_routes_validate_and_never_return_values_from_status(self) -> None:
        accepted = self.client.post(f"/generative-ui/v2/forms/{REQUEST_ID}/submit", json=self.body())
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual((accepted.json()["state"], accepted.json()["code"]), ("success", "accepted"))
        replay = self.client.post(f"/generative-ui/v2/forms/{REQUEST_ID}/submit", json=self.body())
        self.assertEqual(replay.json(), accepted.json())
        status = self.client.get(
            f"/generative-ui/v2/forms/{REQUEST_ID}/status",
            params={"profile": "personal", "session_id": "stored-session"},
        )
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["state"], "success")
        self.assertNotIn("values", status.json())

    def test_wrong_owner_unknown_fields_invalid_values_and_path_mismatch_fail_closed(self) -> None:
        wrong = self.client.post(
            f"/generative-ui/v2/forms/{REQUEST_ID}/submit",
            json=self.body(owner={"profile": "personal", "session_id": "wrong"}),
        )
        self.assertEqual(wrong.json()["code"], "owner_mismatch")
        invalid = self.client.post(
            f"/generative-ui/v2/forms/{REQUEST_ID}/submit",
            json=self.body(values={"departure_day": "sunday"}),
        )
        self.assertEqual(invalid.json()["code"], "invalid_value")
        extra = self.client.post(
            f"/generative-ui/v2/forms/{REQUEST_ID}/submit",
            json={**self.body(), "endpoint": "/unsafe"},
        )
        self.assertEqual(extra.status_code, 422)
        mismatch = self.client.post(
            f"/generative-ui/v2/forms/{'b' * 32}/submit",
            json=self.body(),
        )
        self.assertEqual(mismatch.json()["code"], "request_not_found")
        malformed = self.client.post(
            "/generative-ui/v2/forms/not-a-request/submit",
            json=self.body(),
        )
        self.assertEqual((malformed.status_code, malformed.json()["code"]), (200, "request_not_found"))
        oversized = self.client.post(
            f"/generative-ui/v2/forms/{REQUEST_ID}/submit",
            json=self.body(values={"departure_day": "friday", "padding": "é" * 5000}),
        )
        self.assertEqual(oversized.json()["code"], "payload_too_large")
        self.assertEqual(self.client.post("/generative-ui/v2/actions", json=self.body()).status_code, 404)


if __name__ == "__main__":
    unittest.main()
