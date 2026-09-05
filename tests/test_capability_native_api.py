"""Exercise public Hermes settings APIs in an isolated home, never live config."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class NativeCapabilityAPITests(unittest.TestCase):
    def test_mcp_and_skill_enablement_roundtrip_through_real_hermes_services(self):
        script = r'''
import asyncio, json, os
from pathlib import Path
import yaml
from hermes_constants import get_hermes_home
from loopdy_plugin.workspace_capabilities import profile_scope, set_enabled
home = Path(os.environ["HERMES_HOME"])
assert get_hermes_home().resolve() == home.resolve()
with profile_scope("default"):
    assert get_hermes_home().resolve() == home.resolve()
(home / "skills" / "fixture-capability").mkdir(parents=True)
(home / "skills" / "fixture-capability" / "SKILL.md").write_text("---\nname: fixture-capability\ndescription: Use for isolated verification.\n---\n\nA local test fixture.\n")
(home / "config.yaml").write_text(yaml.safe_dump({"mcp_servers": {"fixture-mcp": {"command": "false", "enabled": True}}}))
async def check():
    from hermes_cli.web_routers.mcp import list_mcp_servers
    from hermes_cli.web_routers.skills import get_skills
    await set_enabled("default", "mcpServer", "fixture-mcp", False)
    state = yaml.safe_load((home / "config.yaml").read_text())
    assert state["mcp_servers"]["fixture-mcp"]["enabled"] is False
    await set_enabled("default", "mcpServer", "fixture-mcp", True)
    assert yaml.safe_load((home / "config.yaml").read_text())["mcp_servers"]["fixture-mcp"]["enabled"] is True
    await set_enabled("default", "skill", "fixture-capability", False)
    rows = await get_skills(profile="default")
    row = next(row for row in rows if row["name"] == "fixture-capability")
    assert row["enabled"] is False
    await set_enabled("default", "skill", "fixture-capability", True)
    rows = await get_skills(profile="default")
    assert next(row for row in rows if row["name"] == "fixture-capability")["enabled"] is True
    print(json.dumps({"mcp_roundtrip": True, "skill_roundtrip": True, "isolated": True}))
asyncio.run(check())
'''
        with tempfile.TemporaryDirectory(prefix="loopdy-capability-test-") as directory:
            home = Path(directory) / ".hermes"
            home.mkdir()
            environment = dict(os.environ, HOME=directory, HERMES_HOME=str(home))
            # Resolve the already-selected import roots before changing cwd.
            environment["PYTHONPATH"] = os.pathsep.join(str(Path(p).resolve()) for p in sys.path if p)
            result = subprocess.run([sys.executable, "-c", script], env=environment,
                                    cwd=directory, capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('"mcp_roundtrip": true', result.stdout)
            self.assertIn('"skill_roundtrip": true', result.stdout)


if __name__ == "__main__":
    unittest.main()
