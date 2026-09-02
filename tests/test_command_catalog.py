import unittest
from types import SimpleNamespace

from loopdy_plugin.command_catalog import build_command_catalog


class CommandCatalogTests(unittest.TestCase):
    def test_catalog_matches_hermes_dispatch_precedence_without_handlers_or_secrets(self) -> None:
        registry = [
            SimpleNamespace(
                name="help",
                description="Show commands",
                category="Help",
                aliases=("commands",),
                args_hint="[query]",
                argument_mode="text",
            ),
            SimpleNamespace(
                name="stop",
                description="Stop the current turn",
                category="Session",
                aliases=(),
                args_hint="",
                argument_mode=None,
            ),
        ]
        rows = build_command_catalog(
            registry=registry,
            gateway_names=frozenset({"help", "commands", "stop"}),
            quick_commands={
                "help": {"description": "Must lose to core", "command": "secret"},
                "daily": {"description": "Run the daily briefing", "command": "secret"},
            },
            plugin_commands={
                "daily": {"description": "Must lose to user", "handler": object()},
                "parcel": {"description": "Show parcels", "handler": object()},
            },
            skill_commands={
                "/parcel": {"name": "parcel", "description": "Must lose to plugin"},
                "/weather": {"name": "weather", "description": "Look up weather"},
            },
        )

        self.assertEqual(
            [(row["name"], row["source"]) for row in rows],
            [
                ("help", "core"),
                ("stop", "core"),
                ("daily", "user"),
                ("parcel", "plugin"),
                ("weather", "skill"),
            ],
        )
        self.assertEqual(rows[0]["aliases"], ["commands"])
        self.assertEqual(rows[1]["argumentMode"], "none")
        self.assertEqual(rows[1]["argsHint"], "")
        self.assertNotIn("handler", repr(rows))
        self.assertNotIn("secret", repr(rows))


if __name__ == "__main__":
    unittest.main()
