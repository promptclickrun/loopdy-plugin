"""Self-update regressions. Always run with a temporary HERMES_HOME."""
import argparse
import contextlib
import io
import unittest
from pathlib import Path

from loopdy_plugin import registration


class PluginUpdateCLITests(unittest.TestCase):
    def test_update_command_accepts_explicit_restart(self):
        self.assertEqual(Path(registration.__file__).resolve().parents[1], Path(__file__).resolve().parents[1])
        parser = argparse.ArgumentParser()
        registration.setup_cli(parser)
        with contextlib.redirect_stderr(io.StringIO()):
            try:
                args = parser.parse_args(["update", "--restart"])
            except SystemExit:
                self.fail("Loopdy CLI must expose update --restart")
        self.assertEqual(args.loopdy_action, "update")
        self.assertTrue(args.restart)

    def test_update_status_is_read_only_command(self):
        parser = argparse.ArgumentParser()
        registration.setup_cli(parser)
        with contextlib.redirect_stderr(io.StringIO()):
            try:
                args = parser.parse_args(["update-status"])
            except SystemExit:
                self.fail("Loopdy CLI must expose update-status")
        self.assertEqual(args.loopdy_action, "update-status")


class PluginUpdateJournalTests(unittest.TestCase):
    def test_duplicate_start_launches_one_durable_operation(self):
        import importlib.util
        import tempfile
        self.assertIsNotNone(importlib.util.find_spec("loopdy_plugin.plugin_update"), "Durable updater is missing")
        from loopdy_plugin.plugin_update import PluginUpdateManager
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugin = root / "plugins" / "loopdy"
            plugin.mkdir(parents=True)
            (plugin / "plugin.yaml").write_text('name: loopdy\nversion: "2.3.0"\n')
            launched = []
            manager = PluginUpdateManager(data_root=root / "data", plugin_root=plugin, profile="default", launch_worker=launched.append)
            first = manager.start(operation_id="update_0123456789abcdef", device_id="device_1234567890", restart=True)
            second = manager.start(operation_id="update_0123456789abcdef", device_id="device_1234567890", restart=True)
            self.assertEqual(first["operation_id"], second["operation_id"])
            self.assertEqual(len(launched), 1)
            restored = PluginUpdateManager(data_root=root / "data", plugin_root=plugin, profile="default", launch_worker=launched.append)
            self.assertEqual(restored.status(operation_id=first["operation_id"], device_id="device_1234567890")["operation_id"], first["operation_id"])
            with self.assertRaises(ValueError):
                restored.status(operation_id=first["operation_id"], device_id="other_device_1234")
            self.assertEqual(len(launched), 1)


if __name__ == "__main__":
    unittest.main()
