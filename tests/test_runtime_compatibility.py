"""Run against each supported Hermes checkout, without bypassing Plugin Doctor."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from loopdy_plugin import room_activity, room_activity_api
import test_native_api as native_fixtures


class RuntimeCompatibilityTests(unittest.TestCase):
    def test_real_runtime_doctor_loads_plugin_and_keeps_core_registrations(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="loopdy-runtime-compat-") as home:
            env = {**os.environ, "HERMES_HOME": home}
            result = subprocess.run(
                [sys.executable, "-c", """
import json, sys
from unittest.mock import patch
from hermes_cli.plugin_dev import doctor_plugin
from hermes_cli.plugins import VALID_HOOKS
# Exercise the runtime's actual post-migration loader, not a scanner bypass.
with patch("hermes_cli.plugin_compat.removal_in_effect", return_value=True):
    report = doctor_plugin(sys.argv[1])
print(json.dumps({"ok": report.ok, "report": report.format_text(),
    "hooks": report.registered_hooks, "tools": report.registered_tools,
    "supports_room_activity": "on_room_member_activity" in VALID_HOOKS}))
""", str(source)], env=env, capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(result.returncode, 0, result.stderr[-3000:])
        report = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertTrue(report["ok"], report["report"])
        self.assertIn("pre_approval_request", report["hooks"])
        self.assertIn("post_tool_call", report["hooks"])
        self.assertIn("loopdy_render_summary", report["tools"])
        self.assertEqual("on_room_member_activity" in report["hooks"], report["supports_room_activity"])

    def test_missing_room_hook_omits_only_room_activity_and_returns_unavailable(self):
        fixture = native_fixtures.NativeAPITests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.client.app.include_router(room_activity_api.router, prefix=native_fixtures.PREFIX)
        from hermes_cli.plugins import VALID_HOOKS
        with patch("hermes_cli.plugins.VALID_HOOKS", VALID_HOOKS - {"on_room_member_activity"}):
            stop = room_activity.register_room_activity(SimpleNamespace(
                register_hook=lambda *_args: self.fail("Cannot register a hook the host does not provide")))
        self.addCleanup(stop)
        context = fixture.context()
        self.assertEqual(context.status_code, 200)
        self.assertIn("native-card-templates-v1", context.json()["features"])
        self.assertNotIn(room_activity.CAPABILITY, context.json()["features"])
        response = fixture.client.post(native_fixtures.PREFIX + "/groups/activity/open",
            json={"roomId": "room-fixture"}, headers=fixture.headers())
        self.assertEqual(response.status_code, 503, response.text)


if __name__ == "__main__":
    unittest.main()
