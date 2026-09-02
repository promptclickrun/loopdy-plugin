import json
import unittest
from pathlib import Path

from loopdy_plugin.registration import register


class _Service:
    def __init__(self):
        self.store = type("Store", (), {})()


class _Context:
    profile_name = "default"

    def __init__(self):
        self.tools = {}
        self.schemas = {}

    def register_tool(self, *, name, handler, schema, **_kwargs):
        self.tools[name] = handler
        self.schemas[name] = schema

    def register_platform(self, **_kwargs): pass
    def register_approval_transport(self, *_args): pass
    def register_hook(self, *_args): pass
    def register_skill(self, *_args, **_kwargs): pass
    def register_cli_command(self, **_kwargs): pass
    def on_unload(self, *_args): pass


class ToolRegistrationTests(unittest.TestCase):
    def test_generative_ui_skill_supports_hermes_progressive_tool_disclosure(self):
        skill = (
            Path(__file__).resolve().parents[1]
            / "skills"
            / "generative-ui"
            / "SKILL.md"
        ).read_text(encoding="utf-8")

        self.assertIn("progressively disclose", skill)
        self.assertIn("`tool_search`, `tool_describe`, and `tool_call`", skill)
        self.assertIn("invoke that exact renderer", skill)
        self.assertIn("loopdy_render_weather_forecast", skill)
        self.assertIn("Do not stop at a prose-only forecast", skill)
        self.assertIn("complete final channel-delivery payload", skill)
        self.assertIn("no Markdown fence", skill)
        self.assertIn("delivered to `loopdy`", skill)
        self.assertIn("hermes send --to loopdy:all", skill)

    def test_install_guidance_matches_progressive_renderer_disclosure(self):
        guidance = (
            Path(__file__).resolve().parents[1] / "after-install.md"
        ).read_text(encoding="utf-8")

        self.assertIn("progressively disclosed", guidance)
        self.assertIn("official tool bridge", guidance)
        self.assertNotIn("never through deferred-tool", guidance)

    def test_skill_and_plugin_docs_keep_inline_and_proactive_cards_distinct(self):
        root = Path(__file__).resolve().parents[1]
        skill = (root / "skills" / "generative-ui" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        readme = (root / "README.md").read_text(encoding="utf-8")

        for document in (skill, readme):
            self.assertIn("Inline card in the active chat", document)
            self.assertIn("Proactive or scheduled card", document)
            self.assertIn("Do not use the notification channel just to answer the current chat", document)
            self.assertIn("does not auto-forward", document)
            self.assertIn("Never script or reconstruct", document)
        self.assertNotIn("must not be sent through `tool_search`", readme)
        self.assertIn("visible in the current tool list", readme)
        self.assertIn("official progressive-disclosure bridge", readme)

    def test_root_entrypoint_registers_model_schema_and_json_result(self):
        context = _Context()
        register(context, service=_Service())
        schema = context.schemas["loopdy_render_summary"]
        self.assertEqual(schema["name"], "loopdy_render_summary")
        self.assertFalse(schema["parameters"]["additionalProperties"])
        self.assertNotIn("function", schema)
        weather_provenance = context.schemas[
            "loopdy_render_weather_forecast"
        ]["parameters"]["properties"]["provenance"]
        self.assertEqual(
            weather_provenance["properties"]["valid_until"],
            {"type": "string", "format": "date-time"},
        )
        self.assertNotIn("valid_until", weather_provenance["required"])
        for tool_name, renderer_schema in context.schemas.items():
            description = renderer_schema["description"]
            if tool_name == "loopdy_await_form_response":
                self.assertNotIn("renderer", description)
                self.assertIn("exact-session", description)
                continue
            self.assertIn("direct callable native Loopdy renderer", description)
            self.assertIn("visible in the current tool list", description)
            self.assertIn("tool_search", description)
            self.assertIn("tool_describe", description)
            self.assertIn("tool_call", description)
            self.assertIn("progressively disclosed", description)

        result = context.tools["loopdy_render_summary"]({
            "version": 1,
            "component": "summary",
            "title": "Ready",
            "body": "Connected",
        }, task_id="test-task")
        self.assertIsInstance(result, str)
        self.assertEqual(json.loads(result)["schema"], "loopdy.generative_ui")
        self.assertEqual(
            result,
            '{"schema": "loopdy.generative_ui", "version": 1, "component": "summary", "title": "Ready", "body": "Connected"}',
        )


if __name__ == "__main__":
    unittest.main()
