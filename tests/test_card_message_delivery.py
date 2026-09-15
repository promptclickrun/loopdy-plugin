"""Renderer delivery must survive ordinary assistant-message history."""
import json
import unittest

from loopdy_plugin.tools import register


class ToolRegistry:
    profile_name = "default"

    def __init__(self):
        self.tools = {}

    def register_tool(self, **tool):
        self.tools[tool["name"]] = tool


class CardMessageDeliveryTests(unittest.TestCase):
    def test_registered_summary_returns_exact_assistant_fence(self):
        registry = ToolRegistry()
        register(registry)
        tool = registry.tools["loopdy_render_summary"]
        result = json.loads(tool["handler"]({
            "component": "summary", "version": 1,
            "title": "Fixture", "body": "Persist this card with its answer.",
        }))
        self.assertIn("display_markdown", result)
        block = result["display_markdown"]
        self.assertTrue(block.startswith("```loopdy-card\n"))
        self.assertTrue(block.endswith("\n```"))
        card = json.loads(block[len("```loopdy-card\n"):-len("\n```")])
        self.assertEqual(card, result["card"])
        self.assertEqual(card["schema"], "loopdy.generative_ui")
        self.assertEqual(card["body"], "Persist this card with its answer.")
        self.assertIn("display_markdown", tool["schema"]["description"])


if __name__ == "__main__":
    unittest.main()
