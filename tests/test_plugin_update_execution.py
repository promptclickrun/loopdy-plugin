"""Execution boundaries for self-update; no production service mutations."""
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from loopdy_plugin import plugin_update as api
with patch.dict(sys.modules, {"plugin_update": api}):
    worker = importlib.import_module("loopdy_plugin.plugin_update_worker")


class PluginUpdateExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.plugin = self.root / "plugins" / "loopdy"
        self.plugin.mkdir(parents=True)
        (self.plugin / "plugin.yaml").write_text('name: loopdy\nversion: "2.4.0"\n')
        self.manager = api.PluginUpdateManager(self.root / "plugin-data" / "loopdy" / "plugin-update", self.plugin, "default", launch_worker=lambda _: None)
        self.operation_id = "update_0123456789abcdef"
        self.device = "device_0123456789"

    def begin(self):
        return self.manager.start(self.operation_id, self.device, True)

    def test_public_status_is_decodable_by_native_contract(self):
        idle = self.manager.status(device_id=self.device)
        self.assertIsNone(idle["operation_id"])
        self.assertIsNone(idle["target_revision"])
        self.assertIsNone(idle["active_revision"])
        self.assertEqual(self.begin()["phase"], "accepted")
        expected = {
            "resolved": "resolving", "validating_installation": "validating",
            "staging": "validating", "backing_up": "validating", "installed": "installing",
            "restart_requested": "restarting", "awaiting_activation": "waiting_for_activation",
            "reconnecting": "waiting_for_activation",
        }
        for internal, external in expected.items():
            self.manager._worker_transition(self.operation_id, internal, "Status")
            self.assertEqual(self.manager.status(self.operation_id, self.device)["phase"], external)

    def test_ambiguous_timeout_does_not_authorize_a_second_update(self):
        self.begin()
        self.manager._worker_transition(self.operation_id, "timed_out", "Waiting", restart_requested_at=1)
        with self.assertRaises(ValueError):
            self.manager.start("update_second_0123456789", self.device, True)

    def test_completion_requires_fresh_revision_and_authenticated_owner_response(self):
        revision = "a" * 40
        with patch.object(api, "LOADED_REVISION", revision), patch.object(api, "RUNTIME_ID", "runtime_old"):
            self.manager.record_runtime_loaded()
            self.begin()
            self.manager._worker_transition(self.operation_id, "awaiting_activation", "Waiting", target_revision=revision)
            self.manager.record_link_response(self.device, self.operation_id)
            self.assertNotEqual(self.manager.status(self.operation_id, self.device)["phase"], "complete")
        with patch.object(api, "LOADED_REVISION", "b" * 40), patch.object(api, "RUNTIME_ID", "runtime_wrong"):
            self.manager.record_runtime_loaded()
            self.manager.record_link_response(self.device, self.operation_id)
            self.assertNotEqual(self.manager.status(self.operation_id, self.device)["phase"], "complete")
        with patch.object(api, "LOADED_REVISION", revision), patch.object(api, "RUNTIME_ID", "runtime_fresh"):
            self.manager.record_runtime_loaded()
            self.manager.record_link_response("other_device", self.operation_id)
            self.assertNotEqual(self.manager.status(self.operation_id, self.device)["phase"], "complete")
            self.manager.record_link_response(self.device, self.operation_id)
            self.assertEqual(self.manager.status(self.operation_id, self.device)["phase"], "complete")

    def test_launcher_preserves_virtual_environment_interpreter(self):
        interpreter = self.root / "venv" / "bin" / "python"
        interpreter.parent.mkdir(parents=True)
        interpreter.symlink_to(sys.executable)
        commands = []
        def capture(command, **kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0)
        original_which = api.shutil.which
        with patch.object(api.sys, "executable", str(interpreter)), patch.object(api.platform, "system", return_value="Darwin"), patch.object(api.shutil, "which", side_effect=lambda name: "/bin/launchctl" if name == "launchctl" else original_which(name)), patch.object(api.subprocess, "run", side_effect=capture):
            self.manager._launch_detached_worker(self.operation_id)
        self.assertEqual(commands[0][1], "submit")
        self.assertIn(str(interpreter), commands[0])
        self.assertNotIn("KeepAlive", commands[0])
        self.assertIn("--service-label", commands[0])

    def test_production_manager_refuses_a_shared_other_profile_installation(self):
        import hermes_constants
        another_home = self.root / "other-profile"
        with patch.object(api, "_PLUGIN_ROOT", self.plugin), patch.object(hermes_constants, "get_hermes_home", return_value=another_home), patch.object(api.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
            manager = api.production_manager("other")
            with self.assertRaises(api.PluginUpdateError):
                manager._launch_detached_worker(self.operation_id)

    def test_new_privileged_capability_blocks_before_installer(self):
        staged = self.root / "staged"
        staged.mkdir()
        (staged / "plugin.yaml").write_text('name: loopdy\ncapabilities: [tools.override]\n')
        with patch.object(worker, "_run_quiet", return_value=0):
            with self.assertRaises(worker.UpdateBlocked):
                worker._validate_staged_plugin(staged, self.root)

    def test_dirty_installation_is_checked_before_up_to_date(self):
        revision = "a" * 40
        with patch.object(api, "LOADED_REVISION", revision), patch.object(api, "RUNTIME_ID", "runtime_active"):
            self.manager.record_runtime_loaded()
        self.begin()
        self.manager._worker_transition(self.operation_id, "resolved", "Resolved", target_revision=revision)
        with patch.object(worker, "_metadata_revision", return_value=revision), patch.object(worker, "_recognized_installation", side_effect=worker.UpdateBlocked("dirty")):
            with self.assertRaises(worker.UpdateBlocked):
                worker._run_operation(self.manager, self.operation_id)

    def test_cli_restart_can_confirm_through_an_authenticated_link_response(self):
        revision = "a" * 40
        cli_device = api.local_cli_device_id("default")
        with patch.object(api, "LOADED_REVISION", revision), patch.object(api, "RUNTIME_ID", "runtime_old"):
            self.manager.record_runtime_loaded()
            self.manager.start(self.operation_id, cli_device, True)
        self.manager._worker_transition(self.operation_id, "awaiting_activation", "Waiting", target_revision=revision)
        with patch.object(api, "LOADED_REVISION", revision), patch.object(api, "RUNTIME_ID", "runtime_fresh"):
            self.manager.record_runtime_loaded()
            self.manager.record_link_response(self.device, self.operation_id)
            self.assertEqual(self.manager.status(self.operation_id)["phase"], "complete")

    def test_restart_timeout_is_observation_only(self):
        with patch.object(worker.subprocess, "run", side_effect=subprocess.TimeoutExpired(["hermes"], 1)) as runner:
            self.assertEqual(worker._restart_gateway(self.manager), "reconnecting")
            self.assertEqual(runner.call_count, 1)

    def test_workspace_rejects_forged_owner_and_requires_consent(self):
        import asyncio
        from loopdy_plugin.workspace_control import HermesWorkspaceBackend, WorkspaceController
        from loopdy_plugin.link_contracts import WorkspaceRequest
        backend = HermesWorkspaceBackend(service=object(), plugin_update_manager=self.manager, connection_id_getter=lambda: self.device)
        async def check():
            with self.assertRaises(Exception):
                await backend.plugin_update_start({"operation_id": self.operation_id, "confirm_restart": False})
            with self.assertRaises(Exception):
                await backend.plugin_update_start({"operation_id": self.operation_id, "confirm_restart": True, "device_id": "forged"})
            result = await backend.plugin_update_start({"operation_id": self.operation_id, "confirm_restart": True})
            self.assertEqual(result["operation_id"], self.operation_id)
            with self.assertRaises(ValueError):
                self.manager.status(self.operation_id, "forged")
        asyncio.run(check())


if __name__ == "__main__":
    unittest.main()
