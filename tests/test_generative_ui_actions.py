from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from loopdy_plugin.generative_ui import canonical_json, validate_submission_values
from loopdy_plugin.store import LoopdyStore
from loopdy_plugin.tools import register


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "generative_ui_v2"
NOW = datetime(2026, 8, 22, 0, 0, tzinfo=timezone.utc)
NOW_SECONDS = int(NOW.timestamp())
REQUEST_ID = "a" * 32
KEY_ONE = "123e4567-e89b-42d3-a456-426614174000"
KEY_TWO = "123e4567-e89b-42d3-a456-426614174001"


class _Context:
    profile_name = "personal"

    def __init__(self) -> None:
        self.tools = {}
        self.schemas = {}

    def register_tool(self, *, name, handler, schema, **_kwargs):
        self.tools[name] = handler
        self.schemas[name] = schema


def form_fixture() -> dict:
    return json.loads((FIXTURES / "valid-form.json").read_text(encoding="utf-8"))


class GenerativeUiActionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = LoopdyStore(Path(self.temporary.name) / "loopdy.sqlite3")
        self.context = _Context()
        register(
            self.context,
            store=self.store,
            profile="personal",
            now=lambda: NOW,
            request_id_factory=lambda: REQUEST_ID,
        )

    def render_form(self, session_id: str = "stored-session") -> dict:
        return json.loads(
            self.context.tools["loopdy_render_form"](
                form_fixture(),
                session_id=session_id,
                task_id="task-1",
            )
        )

    def submit(self, *, key: str = KEY_ONE, values: dict | None = None, session_id: str = "stored-session", now: int = NOW_SECONDS + 10) -> dict:
        values = values or {"departure_day": "friday", "bags": 2}
        schema = self.store.get_form_request(REQUEST_ID)["form_schema"]
        normalized = validate_submission_values(schema, values)
        return self.store.submit_form_request(
            request_id=REQUEST_ID,
            profile="personal",
            session_id=session_id,
            idempotency_key=key,
            values=normalized,
            now=now,
        )

    def test_catalog_registers_exact_legacy_and_card_tools_with_strict_schemas(self) -> None:
        self.assertEqual(
            set(self.context.tools),
            {
                "loopdy_render_summary", "loopdy_render_metrics", "loopdy_render_list", "loopdy_render_timeline",
                "loopdy_render_weather_forecast", "loopdy_render_sports_game", "loopdy_render_stock_quote",
                "loopdy_render_chart", "loopdy_render_dashboard", "loopdy_render_form",
                "loopdy_render_card",
                "loopdy_search_card_templates", "loopdy_get_card_template", "loopdy_render_card_template",
                "loopdy_await_form_response", "loopdy_marketplace_prepare_upload",
            },
        )
        for name, schema in self.context.schemas.items():
            self.assertFalse(schema["parameters"]["additionalProperties"], name)
        self.assertEqual(set(self.context.schemas["loopdy_await_form_response"]["parameters"]["properties"]), {"request_id"})

    def test_render_form_transactionally_stores_exact_profile_session_and_schema(self) -> None:
        card = self.render_form()
        stored = self.store.get_form_request(REQUEST_ID)
        self.assertEqual(stored["profile"], "personal")
        self.assertEqual(stored["session_id"], "stored-session")
        self.assertEqual(stored["state"], "pending")
        self.assertEqual(stored["expires_at"], NOW_SECONDS + 300)
        self.assertEqual(stored["content_hash"], card["content_hash"])
        self.assertEqual(canonical_json(stored["form_schema"]), canonical_json(card["data"]))
        with self.assertRaises(ValueError):
            self.render_form(session_id="")

    def test_submit_is_single_use_idempotent_and_exact_owner_bound(self) -> None:
        self.render_form()
        wrong = self.submit(session_id="another-session")
        self.assertEqual((wrong["state"], wrong["code"]), ("error", "owner_mismatch"))
        wrong_profile = self.store.submit_form_request(
            request_id=REQUEST_ID,
            profile="another-profile",
            session_id="stored-session",
            idempotency_key=KEY_ONE,
            values={"departure_day": "friday", "bags": 2},
            now=NOW_SECONDS + 10,
        )
        self.assertEqual(wrong_profile["code"], "owner_mismatch")
        accepted = self.submit()
        self.assertEqual((accepted["state"], accepted["code"]), ("success", "accepted"))
        replay = self.submit()
        self.assertEqual(replay, accepted)
        conflict = self.submit(values={"departure_day": "saturday", "bags": 2})
        self.assertEqual(conflict["code"], "idempotency_conflict")
        other_key = self.submit(key=KEY_TWO)
        self.assertEqual(other_key["code"], "already_submitted")

    def test_await_is_the_only_exact_session_consumer_and_erases_values(self) -> None:
        self.render_form()
        self.submit()
        wrong = json.loads(self.context.tools["loopdy_await_form_response"]({"request_id": REQUEST_ID}, session_id="wrong"))
        self.assertEqual(wrong["code"], "owner_mismatch")
        consumed = json.loads(self.context.tools["loopdy_await_form_response"]({"request_id": REQUEST_ID}, session_id="stored-session"))
        self.assertEqual(consumed["state"], "success")
        self.assertEqual(consumed["values"], {"bags": 2, "departure_day": "friday"})
        self.assertIsNone(self.store.get_form_request(REQUEST_ID)["values"])
        second = json.loads(self.context.tools["loopdy_await_form_response"]({"request_id": REQUEST_ID}, session_id="stored-session"))
        self.assertEqual(second["code"], "already_consumed")
        malformed = json.loads(self.context.tools["loopdy_await_form_response"]({"request_id": "not-a-request"}, session_id="stored-session"))
        self.assertEqual(malformed["code"], "request_not_found")

    def test_pending_expiry_status_and_concurrent_claims_are_deterministic(self) -> None:
        self.render_form()
        status = self.store.form_request_status(REQUEST_ID, profile="personal", session_id="stored-session", now=NOW_SECONDS + 1)
        self.assertEqual((status["state"], status["code"]), ("pending", "accepted"))
        self.assertNotIn("values", status)
        expired = self.store.submit_form_request(
            request_id=REQUEST_ID,
            profile="personal",
            session_id="stored-session",
            idempotency_key=KEY_ONE,
            values={"departure_day": "friday", "bags": 2},
            now=NOW_SECONDS + 301,
        )
        self.assertEqual(expired["code"], "request_expired")

        self.store = LoopdyStore(Path(self.temporary.name) / "concurrent.sqlite3")
        self.context = _Context()
        register(self.context, store=self.store, profile="personal", now=lambda: NOW, request_id_factory=lambda: REQUEST_ID)
        self.render_form()
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda key: self.submit(key=key), (KEY_ONE, KEY_TWO)))
        self.assertEqual(sorted(result["code"] for result in results), ["accepted", "already_submitted"])


if __name__ == "__main__":
    unittest.main()
