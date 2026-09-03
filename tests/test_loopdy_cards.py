from __future__ import annotations

import copy
import json
import math
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from loopdy_plugin.loopdy_cards import (
    LoopdyCardError,
    canonical_json,
    render_card,
    validate_card_input,
    validate_card_result,
)


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "loopdy_card_v1"
NOW = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)
VALID_FIXTURES = (
    "static-metrics.json",
    "live-bitcoin.json",
    "live-earthquakes.json",
    "live-weather.json",
)


def fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def assert_code(test: unittest.TestCase, code: str, operation) -> None:
    with test.assertRaises(LoopdyCardError) as caught:
        operation()
    test.assertEqual(code, caught.exception.code)


class LoopdyCardValidationTests(unittest.TestCase):
    def validate(self, value: object) -> dict[str, object]:
        return validate_card_input(value, now=NOW, allow_live_data_for_testing=True)

    def test_static_and_live_fixture_matrix_is_accepted_deterministically(self) -> None:
        for name in VALID_FIXTURES:
            with self.subTest(fixture=name):
                payload = fixture(name)
                self.assertEqual(payload, self.validate(payload))
                self.assertEqual(
                    canonical_json(payload),
                    canonical_json(self.validate(copy.deepcopy(payload))),
                )

    def test_optional_ranking_metadata_is_generic_and_bounded(self) -> None:
        payload = fixture("static-metrics.json")
        self.assertEqual(payload, self.validate(payload))

        for importance in ("normal", "important", "urgent"):
            ranked = copy.deepcopy(payload)
            ranked["importance"] = importance
            self.assertEqual(importance, self.validate(ranked)["importance"])

        invalid_importance = copy.deepcopy(payload)
        invalid_importance["importance"] = "emergency"
        assert_code(
            self,
            "invalid_importance",
            lambda: self.validate(invalid_importance),
        )

        for valid_until in (NOW, NOW + timedelta(days=30, seconds=1)):
            invalid_validity = copy.deepcopy(payload)
            invalid_validity["valid_until"] = valid_until.isoformat().replace("+00:00", "Z")
            assert_code(
                self,
                "invalid_valid_until",
                lambda invalid_validity=invalid_validity: self.validate(invalid_validity),
            )

    def test_renderer_adds_exact_deterministic_identity_and_utc_creation(self) -> None:
        rendered = render_card(fixture("static-metrics.json"), now=NOW)

        self.assertEqual(
            "bf3cc2d664a5e7d1067c5e50173d5e643642e41e8a0f6f9c2703e962ad43563a",
            rendered["content_hash"],
        )
        self.assertEqual("bf3cc2d664a5e7d1067c5e50173d5e64", rendered["card_id"])
        self.assertEqual("2026-09-02T12:00:00Z", rendered["created_at"])
        self.assertEqual("live", rendered["origin"])
        self.assertEqual(rendered, validate_card_result(rendered, now=NOW))

    def test_renderer_owned_fields_are_exact_and_hash_protected(self) -> None:
        rendered = render_card(fixture("static-metrics.json"), now=NOW)
        cases = {
            "invalid_content_hash": ("content_hash", "0" * 64),
            "invalid_card_id": ("card_id", "0" * 32),
            "invalid_created_at": ("created_at", "tomorrow"),
            "invalid_origin": ("origin", "catalog"),
        }
        for expected, (key, value) in cases.items():
            with self.subTest(field=key):
                invalid = copy.deepcopy(rendered)
                invalid[key] = value
                assert_code(
                    self,
                    expected,
                    lambda invalid=invalid: validate_card_result(invalid, now=NOW),
                )

    def test_unknown_root_key_and_missing_required_root_fail_closed(self) -> None:
        unknown = fixture("static-metrics.json")
        unknown["action"] = {"kind": "open_url"}
        assert_code(self, "unknown_field", lambda: self.validate(unknown))

        missing = fixture("static-metrics.json")
        missing.pop("root")
        assert_code(self, "missing_field", lambda: self.validate(missing))

    def test_duplicate_source_and_element_references_fail_closed(self) -> None:
        duplicate_source = fixture("live-bitcoin.json")
        duplicate_source["data_sources"].append(
            copy.deepcopy(duplicate_source["data_sources"][0])
        )
        assert_code(
            self, "duplicate_source", lambda: self.validate(duplicate_source)
        )

        duplicate_element = fixture("static-metrics.json")
        duplicate_element["elements"]["card"]["children"].append("metrics")
        assert_code(
            self, "duplicate_element", lambda: self.validate(duplicate_element)
        )

    def test_missing_root_unreachable_node_and_cycle_fail_closed(self) -> None:
        missing_root = fixture("static-metrics.json")
        missing_root["root"] = "not_present"
        assert_code(self, "missing_root", lambda: self.validate(missing_root))

        unreachable = fixture("static-metrics.json")
        unreachable["elements"]["orphan"] = {
            "type": "text",
            "props": {"value": {"literal": "orphan"}},
            "children": [],
        }
        assert_code(self, "unreachable_element", lambda: self.validate(unreachable))

        cycle = fixture("static-metrics.json")
        cycle["elements"]["metrics"]["children"].append("card")
        assert_code(self, "cycle", lambda: self.validate(cycle))

    def test_tree_depth_element_count_and_children_count_are_bounded(self) -> None:
        excessive_depth = fixture("static-metrics.json")
        elements = {
            "card": {
                "type": "card",
                "props": {"title": "Deep"},
                "children": ["level_1"],
            }
        }
        for index in range(1, 13):
            elements[f"level_{index}"] = {
                "type": "vstack",
                "props": {},
                "children": [f"level_{index + 1}"],
            }
        elements["level_13"] = {
            "type": "text",
            "props": {"value": {"literal": "too deep"}},
            "children": [],
        }
        excessive_depth["elements"] = elements
        assert_code(self, "limit_exceeded", lambda: self.validate(excessive_depth))

        excessive_count = fixture("static-metrics.json")
        for index in range(81):
            excessive_count["elements"][f"extra_{index}"] = {
                "type": "divider",
                "props": {},
                "children": [],
            }
        assert_code(self, "limit_exceeded", lambda: self.validate(excessive_count))

        excessive_children = fixture("static-metrics.json")
        excessive_children["elements"]["card"]["children"] = [
            "status" for _ in range(21)
        ]
        assert_code(self, "limit_exceeded", lambda: self.validate(excessive_children))

    def test_unknown_type_illegal_children_and_unknown_props_fail_closed(self) -> None:
        unknown_type = fixture("static-metrics.json")
        unknown_type["elements"]["status"]["type"] = "webview"
        assert_code(
            self, "unsupported_element", lambda: self.validate(unknown_type)
        )

        illegal_child = fixture("static-metrics.json")
        illegal_child["elements"]["status"]["children"] = ["passed"]
        assert_code(self, "invalid_children", lambda: self.validate(illegal_child))

        unknown_prop = fixture("static-metrics.json")
        unknown_prop["elements"]["passed"]["props"]["font_name"] = "Comic Sans"
        assert_code(self, "unknown_field", lambda: self.validate(unknown_prop))

    def test_private_http_credentials_fragment_and_nonstandard_port_urls_fail(self) -> None:
        assert_code(
            self,
            "invalid_url",
            lambda: self.validate(fixture("invalid-private-url.json")),
        )
        for url in (
            "http://api.coinbase.com/v2/prices/BTC-USD/spot",
            "https://user:secret@api.coinbase.com/value",
            "https://api.coinbase.com/value#fragment",
            "https://api.coinbase.com:8443/value",
        ):
            with self.subTest(url=url):
                payload = fixture("live-bitcoin.json")
                payload["data_sources"][0]["request"]["url"] = url
                assert_code(self, "invalid_url", lambda payload=payload: self.validate(payload))

    def test_refresh_staleness_and_expiration_bounds_are_enforced(self) -> None:
        for interval in (59, 3601):
            payload = fixture("live-bitcoin.json")
            payload["data_sources"][0]["refresh"]["minimum_interval_seconds"] = interval
            assert_code(
                self, "invalid_refresh", lambda payload=payload: self.validate(payload)
            )

        for stale in (59, 86_401):
            payload = fixture("live-bitcoin.json")
            payload["data_sources"][0]["refresh"]["stale_after_seconds"] = stale
            assert_code(
                self, "invalid_refresh", lambda payload=payload: self.validate(payload)
            )

        for expiration in (NOW, NOW + timedelta(days=7, seconds=1)):
            payload = fixture("live-bitcoin.json")
            payload["data_sources"][0]["refresh"]["expires_at"] = (
                expiration.isoformat().replace("+00:00", "Z")
            )
            assert_code(
                self,
                "invalid_expiration",
                lambda payload=payload: self.validate(payload),
            )

    def test_expression_depth_is_bounded_but_division_by_zero_is_deferred(self) -> None:
        accepted = fixture("static-metrics.json")
        accepted["elements"]["passed"]["props"]["value"] = {
            "expression": {
                "op": "divide",
                "arguments": [{"literal": 10}, {"literal": 0}],
            }
        }
        self.validate(accepted)

        binding: dict[str, object] = {"literal": True}
        for _ in range(9):
            binding = {
                "expression": {"op": "not", "arguments": [binding]}
            }
        excessive = fixture("static-metrics.json")
        excessive["elements"]["passed"]["props"]["value"] = binding
        assert_code(
            self, "limit_exceeded", lambda: self.validate(excessive)
        )

    def test_binding_sources_and_finite_numbers_are_validated(self) -> None:
        unknown_source = fixture("live-bitcoin.json")
        unknown_source["elements"]["price"]["props"]["value"]["source"] = "missing"
        assert_code(
            self, "unknown_source", lambda: self.validate(unknown_source)
        )

        non_finite = fixture("static-metrics.json")
        non_finite["elements"]["passed"]["props"]["value"] = {
            "literal": math.inf
        }
        assert_code(self, "invalid_number", lambda: self.validate(non_finite))

    def test_document_text_table_chart_and_list_limits_are_enforced(self) -> None:
        text = fixture("static-metrics.json")
        text["spoken_summary"] = "a" * 2001
        assert_code(self, "limit_exceeded", lambda: self.validate(text))

        table = fixture("static-metrics.json")
        table["elements"]["status"] = {
            "type": "table",
            "props": {
                "columns": [{"label": str(index)} for index in range(9)],
                "rows": [],
            },
            "children": [],
        }
        assert_code(self, "limit_exceeded", lambda: self.validate(table))

        chart = fixture("static-metrics.json")
        chart["elements"]["status"] = {
            "type": "chart",
            "props": {
                "kind": "line",
                "description": "Oversized chart",
                "series": [
                    {
                        "id": f"series_{index}",
                        "label": f"Series {index}",
                        "semantic": "accent",
                        "points": [{"x": {"literal": "x"}, "y": {"literal": 1}}],
                    }
                    for index in range(7)
                ],
            },
            "children": [],
        }
        assert_code(self, "limit_exceeded", lambda: self.validate(chart))

        invalid_list = fixture("live-earthquakes.json")
        invalid_list["elements"]["quakes"]["children"] = [
            "quake_row",
            "quake_place",
        ]
        assert_code(self, "invalid_children", lambda: self.validate(invalid_list))

    def test_encoded_document_is_limited_to_sixty_four_kibibytes(self) -> None:
        payload = fixture("static-metrics.json")
        payload["elements"] = {
            "card": {
                "type": "card",
                "props": {"title": "Large"},
                "children": ["chart"],
            },
            "chart": {
                "type": "chart",
                "props": {
                    "kind": "line",
                    "description": "Large but structurally bounded",
                    "series": [
                        {
                            "id": f"series_{series}",
                            "label": f"Series {series}",
                            "semantic": "accent",
                            "points": [
                                {
                                    "x": {"literal": f"{point}-" + "x" * 100},
                                    "y": {"literal": point},
                                }
                                for point in range(120)
                            ],
                        }
                        for series in range(6)
                    ],
                },
                "children": [],
            },
        }
        self.assertGreater(len(canonical_json(payload).encode("utf-8")), 65_536)
        assert_code(self, "payload_too_large", lambda: self.validate(payload))


if __name__ == "__main__":
    unittest.main()
