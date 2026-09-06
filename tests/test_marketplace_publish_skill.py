from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


class MarketplacePublishSkillTests(unittest.TestCase):
    def test_real_plugin_context_registers_namespaced_read_only_skill(self) -> None:
        from hermes_cli import plugins as plugins_module
        from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
        from loopdy_plugin.registration import register_marketplace_publish_skill
        from tools.skills_tool import skill_view

        manager = PluginManager()
        manifest = PluginManifest(
            name="loopdy",
            version="2.3.0",
            description="Loopdy plugin test",
            source="user",
            portable=True,
        )
        context = PluginContext(manifest, manager)
        flat_skills = Path(os.environ["HERMES_HOME"]) / "skills"
        before = (
            {path.relative_to(flat_skills) for path in flat_skills.rglob("*")}
            if flat_skills.exists()
            else set()
        )

        with mock.patch.object(plugins_module, "_plugin_manager", manager):
            register_marketplace_publish_skill(context)
            registered = manager.find_plugin_skill(
                "loopdy:loopdy-marketplace-publish"
            )
            self.assertEqual(
                registered,
                PLUGIN_ROOT
                / "skills"
                / "loopdy-marketplace-publish"
                / "SKILL.md",
            )
            viewed = json.loads(skill_view("loopdy:loopdy-marketplace-publish"))

        self.assertTrue(viewed["success"])
        self.assertIn("validateOnly: true", viewed["content"])
        self.assertIn("private draft", viewed["content"])
        self.assertIn("Never submit", viewed["content"])
        after = (
            {path.relative_to(flat_skills) for path in flat_skills.rglob("*")}
            if flat_skills.exists()
            else set()
        )
        self.assertEqual(after, before)
        self.assertFalse((flat_skills / "loopdy-marketplace-publish").exists())


if __name__ == "__main__":
    unittest.main()
