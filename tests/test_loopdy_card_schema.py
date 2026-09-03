from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PLUGIN_ROOT / "spec" / "loopdy-card-v1.schema.json"
FIXTURE_ROOT = PLUGIN_ROOT / "fixtures" / "loopdy_card_v1"
VALID_FIXTURES = (
    "static-metrics.json",
)
LIVE_FIXTURES = ("live-bitcoin.json", "live-earthquakes.json", "live-weather.json")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


class LoopdyCardSchemaTests(unittest.TestCase):
    def validator(self) -> Draft202012Validator:
        schema = load_json(SCHEMA_PATH)
        Draft202012Validator.check_schema(schema)
        return Draft202012Validator(schema)

    def test_positive_fixture_matrix_matches_the_portable_contract(self) -> None:
        validator = self.validator()

        for name in VALID_FIXTURES:
            with self.subTest(fixture=name):
                errors = sorted(
                    validator.iter_errors(load_json(FIXTURE_ROOT / name)),
                    key=lambda error: list(error.absolute_path),
                )
                self.assertEqual([], errors, [error.message for error in errors])

    def test_private_url_fixture_fails_closed(self) -> None:
        validator = self.validator()
        errors = list(
            validator.iter_errors(load_json(FIXTURE_ROOT / "invalid-private-url.json"))
        )

        self.assertTrue(errors, "private URL fixture unexpectedly validated")

    def test_live_data_fixtures_are_not_part_of_the_build_three_contract(self) -> None:
        validator = self.validator()

        for name in LIVE_FIXTURES:
            with self.subTest(fixture=name):
                self.assertTrue(list(validator.iter_errors(load_json(FIXTURE_ROOT / name))))


if __name__ == "__main__":
    unittest.main()
