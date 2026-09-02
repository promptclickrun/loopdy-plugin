import json
import unittest

from loopdy_plugin.generative_ui import validate_render_payload, render_envelope


class GenerativeUiContractTests(unittest.TestCase):
    def test_summary_is_versioned_and_bounded(self):
        payload = {"component": "summary", "version": 1, "title": "Status", "body": "Ready"}
        value = render_envelope("loopdy_render_summary", payload)
        self.assertEqual(value["version"], 1)
        self.assertEqual(value["component"], "summary")

    def test_unknown_component_and_oversize_are_rejected(self):
        with self.assertRaises(ValueError):
            validate_render_payload({"component": "html", "version": 1})
        with self.assertRaises(ValueError):
            validate_render_payload({"component": "summary", "version": 1, "body": "x" * 20000})

    def test_component_fields_and_nested_safety_are_strict(self):
        with self.assertRaises(ValueError):
            validate_render_payload({"component": "summary", "version": 1, "html": "x"})
        with self.assertRaises(ValueError):
            validate_render_payload({"component": "summary", "version": 1, "extra": True})
        with self.assertRaises(ValueError):
            validate_render_payload({"component": "summary", "version": 1, "body": {"style": "x"}})
        with self.assertRaises(ValueError):
            validate_render_payload({"component": "list", "version": 1, "items": list(range(21))})


if __name__ == "__main__":
    unittest.main()
