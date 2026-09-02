from __future__ import annotations

import copy
import json
import math
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from loopdy_plugin.generative_ui import (
    GenerativeUIError,
    canonical_json,
    parse_v2_json,
    render_v2_envelope,
    validate_rendered_envelope,
    validate_submission_values,
)
from loopdy_plugin.tools import _v2_handler


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "generative_ui_v2"
NOW = datetime(2026, 8, 22, 0, 0, tzinfo=timezone.utc)


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def assert_code(test: unittest.TestCase, code: str, fn) -> None:
    with test.assertRaises(GenerativeUIError) as caught:
        fn()
    test.assertEqual(caught.exception.code, code)


class GenerativeUiV2ContractTests(unittest.TestCase):
    def render(self, name: str, *, session_id: str = "stored-session") -> dict:
        payload = fixture(name)
        return render_v2_envelope(
            f"loopdy_render_{payload['component']}",
            payload,
            now=NOW,
            profile="personal",
            session_id=session_id,
            request_id_factory=lambda: "a" * 32,
        )

    def test_shared_manifest_accepts_every_v2_component_deterministically(self) -> None:
        manifest = fixture("manifest.json")
        components = set()
        for item in manifest["fixtures"]:
            payload = fixture(item["file"])
            if not item["accepted"]:
                assert_code(
                    self,
                    item["code"],
                    lambda payload=payload: render_v2_envelope(
                        f"loopdy_render_{payload['component']}",
                        payload,
                        now=NOW,
                        profile="personal",
                        session_id="stored-session",
                    ),
                )
                continue
            first = self.render(item["file"])
            second = self.render(item["file"])
            self.assertEqual(first, second)
            self.assertEqual(first["schema"], "loopdy.generative_ui")
            self.assertEqual(first["version"], 2)
            self.assertEqual(first["component"], item["component"])
            self.assertEqual(first["created_at"], manifest["fixed_created_at"])
            self.assertEqual(first["origin"], "live")
            self.assertRegex(first["card_id"], r"^[0-9a-f]{32}$")
            self.assertRegex(first["content_hash"], r"^[0-9a-f]{64}$")
            self.assertLessEqual(len(canonical_json(first).encode("utf-8")), 32_768)
            components.add(item["component"])
        self.assertEqual(
            components,
            {"weather_forecast", "sports_game", "stock_quote", "chart", "dashboard", "form"},
        )

    def test_form_action_is_server_owned_and_requires_host_session(self) -> None:
        value = self.render("valid-form.json")
        self.assertNotIn("provenance", value)
        self.assertEqual(
            value["action"],
            {
                "kind": "submit_form",
                "request_id": "a" * 32,
                "owner": {"profile": "personal", "session_id": "stored-session"},
                "expires_at": "2026-08-22T00:05:00Z",
            },
        )
        self.assertEqual(value["card_id"], "a" * 32)
        assert_code(self, "owner_required", lambda: self.render("valid-form.json", session_id=""))
        payload = fixture("valid-form.json")
        payload["action"] = {"kind": "submit_form"}
        assert_code(
            self,
            "unknown_field",
            lambda: render_v2_envelope(
                "loopdy_render_form", payload, now=NOW, profile="personal", session_id="stored-session"
            ),
        )

    def test_unknown_version_component_fields_duplicate_keys_and_executable_keys_fail_closed(self) -> None:
        payload = fixture("valid-stock.json")
        cases = []
        version = copy.deepcopy(payload)
        version["version"] = 3
        cases.append(("unsupported_version", version))
        component = copy.deepcopy(payload)
        component["component"] = "html"
        cases.append(("unsupported_component", component))
        unknown = copy.deepcopy(payload)
        unknown["data"]["mystery"] = True
        cases.append(("unknown_field", unknown))
        for key in (
            "URL", "uri", "href", "style", "styles", "css", "html", "javascript", "js",
            "route", "routes", "module", "native", "command", "shell", "rpc", "method",
            "endpoint", "headers", "token", "secret", "password", "script", "eval", "actions",
        ):
            forbidden = copy.deepcopy(payload)
            forbidden["data"][key] = "literal text only"
            cases.append(("forbidden_field", forbidden))
        for expected, value in cases:
            assert_code(
                self,
                expected,
                lambda value=value: render_v2_envelope(
                    "loopdy_render_stock_quote", value, now=NOW, profile="personal", session_id="s"
                ),
            )
        assert_code(
            self,
            "duplicate_key",
            lambda: parse_v2_json('{"schema":"loopdy.generative_ui","version":2,"version":2}'),
        )

    def test_global_limits_normalization_and_numeric_rules_are_enforced(self) -> None:
        payload = fixture("valid-stock.json")
        payload["title"] = "Cafe\u0301"
        value = render_v2_envelope(
            "loopdy_render_stock_quote", payload, now=NOW, profile="personal", session_id="s"
        )
        self.assertEqual(value["title"], "Café")
        integer_price = fixture("valid-stock.json")
        integer_price["data"]["price"] = 125
        decimal_price = fixture("valid-stock.json")
        decimal_price["data"]["price"] = 125.0
        first = render_v2_envelope("loopdy_render_stock_quote", integer_price, now=NOW, profile="p", session_id="s")
        second = render_v2_envelope("loopdy_render_stock_quote", decimal_price, now=NOW, profile="p", session_id="s")
        self.assertEqual(first["content_hash"], second["content_hash"])

        for number in (math.nan, math.inf, 1_000_000_000_001, 1.1234567):
            invalid = fixture("valid-stock.json")
            invalid["data"]["price"] = number
            assert_code(
                self,
                "invalid_number",
                lambda invalid=invalid: render_v2_envelope(
                    "loopdy_render_stock_quote", invalid, now=NOW, profile="personal", session_id="s"
                ),
            )
        control = fixture("valid-stock.json")
        control["title"] = "bad\u0000control"
        assert_code(
            self,
            "invalid_string",
            lambda: render_v2_envelope(
                "loopdy_render_stock_quote", control, now=NOW, profile="personal", session_id="s"
            ),
        )
        huge = fixture("valid-stock.json")
        huge["subtitle"] = "é" * 20_000
        assert_code(
            self,
            "payload_too_large",
            lambda: render_v2_envelope(
                "loopdy_render_stock_quote", huge, now=NOW, profile="personal", session_id="s"
            ),
        )

    def test_weather_sports_stock_and_provenance_invariants(self) -> None:
        weather = fixture("valid-weather.json")
        weather["data"]["periods"] *= 15
        assert_code(self, "limit_exceeded", lambda: render_v2_envelope("loopdy_render_weather_forecast", weather, now=NOW, profile="p", session_id="s"))
        weather = fixture("valid-weather.json")
        weather["data"]["periods"][0]["high"] = 60
        weather["data"]["periods"][0]["low"] = 66
        assert_code(self, "invalid_value", lambda: render_v2_envelope("loopdy_render_weather_forecast", weather, now=NOW, profile="p", session_id="s"))

        sports = fixture("valid-sports-live.json")
        sports["data"]["teams"][0]["home"] = True
        assert_code(self, "invalid_value", lambda: render_v2_envelope("loopdy_render_sports_game", sports, now=NOW, profile="p", session_id="s"))
        sports = fixture("valid-sports-live.json")
        sports["data"]["teams"][0]["score"] = None
        assert_code(self, "invalid_value", lambda: render_v2_envelope("loopdy_render_sports_game", sports, now=NOW, profile="p", session_id="s"))

        stock = fixture("valid-stock.json")
        stock["data"]["symbol"] = "lower"
        assert_code(self, "invalid_value", lambda: render_v2_envelope("loopdy_render_stock_quote", stock, now=NOW, profile="p", session_id="s"))
        provenance = fixture("valid-stock.json")
        provenance["provenance"]["age_seconds"] = 260
        normalized = render_v2_envelope(
            "loopdy_render_stock_quote",
            provenance,
            now=NOW,
            profile="p",
            session_id="s",
        )
        self.assertEqual(normalized["provenance"]["age_seconds"], 300)

    def test_weather_provenance_age_is_derived_at_render_time(self) -> None:
        weather = fixture("valid-weather.json")

        # The source and retrieval timestamps are the provenance facts. Age
        # is presentation metadata and must be recalculated when the payload
        # reaches the renderer, regardless of time spent in model/tool work.
        delayed = render_v2_envelope(
            "loopdy_render_weather_forecast",
            weather,
            now=NOW + timedelta(minutes=3),
            profile="p",
            session_id="s",
        )
        self.assertEqual(delayed["provenance"]["age_seconds"], 480)

        # A source outside the supported one-year freshness window remains
        # invalid even though the client-supplied age is never trusted.
        unsupported_age = fixture("valid-weather.json")
        unsupported_age["provenance"]["source_timestamp"] = "2025-08-21T23:54:59Z"
        assert_code(
            self,
            "invalid_freshness",
            lambda: render_v2_envelope(
                "loopdy_render_weather_forecast",
                unsupported_age,
                now=NOW,
                profile="p",
                session_id="s",
            ),
        )

    def test_provenance_valid_until_is_hashed_ordered_and_round_trips(self) -> None:
        weather = fixture("valid-weather-valid-until.json")

        rendered = render_v2_envelope(
            "loopdy_render_weather_forecast",
            weather,
            now=NOW,
            profile="p",
            session_id="s",
        )
        without_valid_until = render_v2_envelope(
            "loopdy_render_weather_forecast",
            fixture("valid-weather.json"),
            now=NOW,
            profile="p",
            session_id="s",
        )

        self.assertEqual(
            rendered["provenance"]["valid_until"],
            "2026-08-22T01:00:00Z",
        )
        self.assertEqual(rendered["provenance"]["age_seconds"], 300)
        self.assertNotEqual(rendered["content_hash"], without_valid_until["content_hash"])
        self.assertEqual(validate_rendered_envelope(rendered), rendered)

        for invalid in (
            "2026-08-21T23:54:59Z",
            "2026-08-21T23:55:30Z",
        ):
            payload = fixture("valid-weather.json")
            payload["provenance"]["valid_until"] = invalid
            assert_code(
                self,
                "invalid_freshness",
                lambda payload=payload: render_v2_envelope(
                    "loopdy_render_weather_forecast",
                    payload,
                    now=NOW,
                    profile="p",
                    session_id="s",
                ),
            )

        malformed = fixture("valid-weather.json")
        malformed["provenance"]["valid_until"] = "tomorrow"
        assert_code(
            self,
            "invalid_value",
            lambda: render_v2_envelope(
                "loopdy_render_weather_forecast",
                malformed,
                now=NOW,
                profile="p",
                session_id="s",
            ),
        )

    def test_weather_tool_handler_derives_age_when_model_age_is_stale_or_missing(self) -> None:
        payload = fixture("valid-weather.json")
        payload["provenance"]["age_seconds"] = 0
        handler = _v2_handler(
            "loopdy_render_weather_forecast",
            store=None,
            profile="p",
            now=lambda: NOW + timedelta(minutes=3),
            request_id_factory=None,
        )

        stale = json.loads(handler(payload))
        self.assertEqual(stale["provenance"]["age_seconds"], 480)

        del payload["provenance"]["age_seconds"]
        missing = json.loads(handler(payload))
        self.assertEqual(missing["provenance"]["age_seconds"], 480)

    def test_rendered_envelope_recanonicalizes_a_mutated_age(self) -> None:
        rendered = self.render("valid-weather.json")
        rendered["provenance"]["age_seconds"] -= 1

        normalized = validate_rendered_envelope(rendered)

        self.assertEqual(normalized["provenance"]["age_seconds"], 300)

    def test_rendered_envelope_recanonicalizes_a_delayed_model_age(self) -> None:
        rendered = render_v2_envelope(
            "loopdy_render_weather_forecast",
            fixture("valid-weather.json"),
            now=NOW + timedelta(minutes=3),
            profile="p",
            session_id="s",
        )
        # The model/tool result can carry an age measured before the renderer
        # result crosses the host boundary. Timestamps are authoritative; the
        # stale age must not turn a valid weather card into a tool error.
        rendered["provenance"]["age_seconds"] -= 180

        normalized = validate_rendered_envelope(rendered)

        self.assertEqual(normalized["provenance"]["age_seconds"], 480)

    def test_chart_and_dashboard_aggregate_limits_and_accessibility_fields(self) -> None:
        chart = fixture("valid-chart.json")
        chart["data"]["series"] *= 7
        assert_code(self, "limit_exceeded", lambda: render_v2_envelope("loopdy_render_chart", chart, now=NOW, profile="p", session_id="s"))
        chart = fixture("valid-chart.json")
        chart["data"]["series"][0]["points"] = [
            {"x": f"2026-08-21T00:{index:02d}:00Z", "y": index} for index in range(61)
        ]
        assert_code(self, "limit_exceeded", lambda: render_v2_envelope("loopdy_render_chart", chart, now=NOW, profile="p", session_id="s"))
        chart = fixture("valid-chart.json")
        chart["data"]["series"][0]["points"].reverse()
        assert_code(self, "invalid_order", lambda: render_v2_envelope("loopdy_render_chart", chart, now=NOW, profile="p", session_id="s"))

        dashboard = fixture("valid-dashboard.json")
        dashboard["data"]["metrics"] *= 13
        assert_code(self, "limit_exceeded", lambda: render_v2_envelope("loopdy_render_dashboard", dashboard, now=NOW, profile="p", session_id="s"))
        dashboard = fixture("valid-dashboard.json")
        dashboard["data"]["charts"] *= 3
        assert_code(self, "limit_exceeded", lambda: render_v2_envelope("loopdy_render_dashboard", dashboard, now=NOW, profile="p", session_id="s"))

    def test_form_schema_and_submission_values_are_strict_and_bounded(self) -> None:
        form = fixture("valid-form.json")
        form["data"]["fields"][0]["kind"] = "password"
        assert_code(self, "invalid_value", lambda: render_v2_envelope("loopdy_render_form", form, now=NOW, profile="p", session_id="s"))
        form = fixture("valid-form.json")
        form["data"]["fields"] *= 13
        assert_code(self, "limit_exceeded", lambda: render_v2_envelope("loopdy_render_form", form, now=NOW, profile="p", session_id="s"))

        schema = fixture("valid-form.json")["data"]
        self.assertEqual(validate_submission_values(schema, {"departure_day": "friday", "bags": 2}), {"bags": 2, "departure_day": "friday"})
        for values in (
            {"bags": 2},
            {"departure_day": "sunday"},
            {"departure_day": "friday", "unknown": True},
            {"departure_day": "friday", "bags": 6},
        ):
            assert_code(self, "invalid_value", lambda values=values: validate_submission_values(schema, values))
        assert_code(
            self,
            "payload_too_large",
            lambda: validate_submission_values(schema, {"departure_day": "friday", "bags": 2, "padding": "é" * 5000}),
        )

    def test_every_allowlisted_form_field_kind_round_trips_through_server_validation(self) -> None:
        form = fixture("valid-form.json")
        form["data"]["fields"] = [
            {"id": "name", "kind": "text", "label": "Name", "required": True, "min_length": 1, "max_length": 20},
            {"id": "notes", "kind": "textarea", "label": "Notes", "required": False, "max_length": 100},
            {"id": "choice", "kind": "select", "label": "Choice", "required": True, "options": [{"id": "one", "label": "One"}]},
            {"id": "many", "kind": "multi_select", "label": "Many", "required": False, "options": [{"id": "one", "label": "One"}, {"id": "two", "label": "Two"}], "max_selected": 2},
            {"id": "enabled", "kind": "toggle", "label": "Enabled", "required": True},
            {"id": "count", "kind": "integer", "label": "Count", "required": True, "min": 0, "max": 10, "step": 2},
            {"id": "amount", "kind": "decimal", "label": "Amount", "required": True, "min": 0, "max": 2, "step": 0.25},
            {"id": "tenths", "kind": "decimal", "label": "Tenths", "required": True, "min": 0.1, "max": 1, "step": 0.1},
            {"id": "day", "kind": "date", "label": "Day", "required": True, "min": "2026-08-01", "max": "2026-08-31"},
        ]
        card = render_v2_envelope(
            "loopdy_render_form",
            form,
            now=NOW,
            profile="personal",
            session_id="stored-session",
            request_id_factory=lambda: "b" * 32,
        )
        values = {
            "name": "Fixture",
            "notes": "Line one\nLine two",
            "choice": "one",
            "many": ["one", "two"],
            "enabled": True,
            "count": 4,
            "amount": 1.25,
            "tenths": 0.3,
            "day": "2026-08-22",
        }
        self.assertEqual(validate_submission_values(card["data"], values), dict(sorted(values.items())))


if __name__ == "__main__":
    unittest.main()
