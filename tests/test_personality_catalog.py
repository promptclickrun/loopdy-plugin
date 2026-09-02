from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


class PersonalityCatalogTests(unittest.TestCase):
    def test_builtin_catalog_snapshot_fits_the_link_wire_contract(self) -> None:
        from loopdy_plugin.link_contracts import personality_catalog_payload
        from loopdy_plugin.personality_catalog import PersonalityCatalogManager

        with tempfile.TemporaryDirectory() as directory:
            manager = PersonalityCatalogManager(
                config_path=Path(directory) / "config.yaml",
                persist_selection=lambda value: None,
            )
            snapshot = manager.snapshot()

            payload = personality_catalog_payload(
                request_id="personality-request-wire-0001",
                catalog=snapshot,
                sent_at=1788000050,
            )

            self.assertEqual(
                len(payload["personalities"]),
                len(snapshot["personalities"]),
            )

    def test_uses_hermes_personality_owner_for_builtins_overrides_and_selection(self) -> None:
        from loopdy_plugin.link_contracts import parse_personality_request
        from loopdy_plugin.personality_catalog import PersonalityCatalogManager

        selected = []
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            manager = PersonalityCatalogManager(
                config_path=config_path,
                persist_selection=selected.append,
            )
            initial = manager.snapshot()
            self.assertIn("helpful", [item["name"] for item in initial["personalities"]])

            save = parse_personality_request(
                {
                    "version": 1,
                    "type": "personalities.mutate",
                    "requestId": "personality-request-0001",
                    "action": "save",
                    "expectedRevision": initial["revision"],
                    "name": "focused",
                    "definition": {
                        "name": "focused",
                        "description": "Quietly deliberate",
                        "systemPrompt": "Work carefully.",
                        "tone": "Calm",
                        "style": "Structured",
                    },
                    "sentAt": 1788000050,
                }
            )
            saved = manager.mutate(save)
            focused = next(item for item in saved["personalities"] if item["name"] == "focused")
            self.assertFalse(focused["builtIn"])
            self.assertTrue(focused["customized"])

            activate = parse_personality_request(
                {
                    "version": 1,
                    "type": "personalities.mutate",
                    "requestId": "personality-request-0002",
                    "action": "activate",
                    "expectedRevision": saved["revision"],
                    "name": "focused",
                    "sentAt": 1788000051,
                }
            )
            manager.mutate(activate)
            self.assertEqual(selected, ["focused"])

    def test_rejects_stale_mutations_and_never_deletes_an_unmodified_builtin(self) -> None:
        from loopdy_plugin.link_contracts import parse_personality_request
        from loopdy_plugin.personality_catalog import PersonalityCatalogManager

        with tempfile.TemporaryDirectory() as directory:
            manager = PersonalityCatalogManager(
                config_path=Path(directory) / "config.yaml",
                persist_selection=lambda value: None,
            )
            request = parse_personality_request(
                {
                    "version": 1,
                    "type": "personalities.mutate",
                    "requestId": "personality-request-0003",
                    "action": "delete",
                    "expectedRevision": manager.snapshot()["revision"] + 1,
                    "name": "helpful",
                    "sentAt": 1788000052,
                }
            )
            with self.assertRaises(ValueError):
                manager.mutate(request)
