from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from loopdy_plugin.loopdy_cards import LoopdyCardError
from loopdy_plugin.tools import register


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PLUGIN_ROOT / "fixtures" / "loopdy_card_v1" / "static-metrics.json"
LIVE_FIXTURE = PLUGIN_ROOT / "fixtures" / "loopdy_card_v1" / "live-weather.json"
SCHEMA = PLUGIN_ROOT / "spec" / "loopdy-card-v1.schema.json"
NOW = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)
LEGACY_RENDERERS = [
    "loopdy_render_summary",
    "loopdy_render_metrics",
    "loopdy_render_list",
    "loopdy_render_timeline",
    "loopdy_render_weather_forecast",
    "loopdy_render_sports_game",
    "loopdy_render_stock_quote",
    "loopdy_render_chart",
    "loopdy_render_dashboard",
    "loopdy_render_form",
]


class _Context:
    profile_name = "personal"

    def __init__(self) -> None:
        self.names: list[str] = []
        self.handlers: dict[str, object] = {}
        self.schemas: dict[str, dict[str, object]] = {}

    def register_tool(self, *, name, handler, schema, **_kwargs) -> None:
        self.names.append(name)
        self.handlers[name] = handler
        self.schemas[name] = schema


class LoopdyCardToolTests(unittest.TestCase):
    def context(self) -> _Context:
        context = _Context()
        register(context, now=lambda: NOW)
        return context

    def test_exactly_one_generic_renderer_is_registered_in_the_stable_order(self) -> None:
        context = self.context()

        self.assertEqual(1, context.names.count("loopdy_render_card"))
        self.assertEqual(
            [*LEGACY_RENDERERS, "loopdy_render_card", "loopdy_await_form_response"],
            context.names,
        )

    def test_generic_renderer_parameters_match_the_canonical_input_schema(self) -> None:
        context = self.context()
        portable = json.loads(SCHEMA.read_text(encoding="utf-8"))
        expected = {
            "type": portable["type"],
            "properties": portable["properties"],
            "required": portable["required"],
            "additionalProperties": portable["additionalProperties"],
            "$defs": portable["$defs"],
        }

        schema = context.schemas["loopdy_render_card"]
        self.assertEqual("loopdy_render_card", schema["name"])
        self.assertEqual(expected, schema["parameters"])
        description = str(schema["description"])
        self.assertIn("native Loopdy Card", description)
        self.assertIn("progressively disclosed", description)
        self.assertIn("data_sources must be empty", description)
        self.assertIn("live Card data refresh is unavailable", description)
        self.assertNotIn("optional public HTTPS GET", description)

    def test_generic_handler_returns_one_validated_renderer_owned_document(self) -> None:
        context = self.context()
        payload = json.loads(FIXTURE.read_text(encoding="utf-8"))

        result = json.loads(context.handlers["loopdy_render_card"](payload))

        self.assertEqual("loopdy.card", result["schema"])
        self.assertEqual(1, result["version"])
        self.assertEqual("2026-09-02T12:00:00Z", result["created_at"])
        self.assertEqual(
            "bf3cc2d664a5e7d1067c5e50173d5e643642e41e8a0f6f9c2703e962ad43563a",
            result["content_hash"],
        )

    def test_generic_handler_rejects_an_unsafe_document_before_returning_json(self) -> None:
        context = self.context()
        payload = json.loads(
            (
                PLUGIN_ROOT
                / "fixtures"
                / "loopdy_card_v1"
                / "invalid-private-url.json"
            ).read_text(encoding="utf-8")
        )

        with self.assertRaises(LoopdyCardError) as caught:
            context.handlers["loopdy_render_card"](payload)

        self.assertEqual("invalid_url", caught.exception.code)

    def test_generic_handler_rejects_live_data_sources_for_build_three(self) -> None:
        context = self.context()
        payload = json.loads(LIVE_FIXTURE.read_text(encoding="utf-8"))

        with self.assertRaises(LoopdyCardError) as caught:
            context.handlers["loopdy_render_card"](payload)

        self.assertEqual("live_data_unavailable", caught.exception.code)

    def test_legacy_renderer_names_and_contract_versions_are_unchanged(self) -> None:
        context = self.context()

        for name in LEGACY_RENDERERS[:4]:
            parameters = context.schemas[name]["parameters"]
            self.assertEqual(1, parameters["properties"]["version"]["const"])
            self.assertNotIn("spoken_summary", parameters["properties"])
        for name in LEGACY_RENDERERS[4:]:
            parameters = context.schemas[name]["parameters"]
            self.assertEqual("loopdy.generative_ui", parameters["properties"]["schema"]["const"])
            self.assertEqual(2, parameters["properties"]["version"]["const"])


if __name__ == "__main__":
    unittest.main()
