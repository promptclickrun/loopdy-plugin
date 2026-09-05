"""Real Git + supported Hermes installer in a disposable profile, never live."""
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from loopdy_plugin import plugin_update as api
with patch.dict(sys.modules, {"plugin_update": api}):
    worker = importlib.import_module("loopdy_plugin.plugin_update_worker")


class PluginUpdateInstallationTests(unittest.TestCase):
    def test_real_packaged_install_preserves_data_and_updates_exact_revision(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="loopdy-install-proof-") as directory:
            root = Path(directory)
            home = root / "home"
            repo = root / "source"
            shutil.copytree(source, repo, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".pytest_cache"))
            env = worker._process_env(home)
            def command(argv):
                result = subprocess.run(argv, env=env, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=90)
                self.assertEqual(result.returncode, 0, result.stdout[-3000:])
                return result.stdout.strip()
            command(["git", "init", "-q", "-b", "main", str(repo)])
            command(["git", "-C", str(repo), "add", "."])
            commit = ["git", "-C", str(repo), "-c", "user.name=Loopdy Test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m"]
            command(commit + ["baseline fixture"])
            old = command(["git", "-C", str(repo), "rev-parse", "HEAD"])
            home.mkdir(parents=True, exist_ok=True)
            config = home / "config.yaml"
            config.write_text('plugins:\n  enabled: [loopdy]\n  disabled: []\n')
            command([sys.executable, "-m", "hermes_cli.main", "plugins", "install", repo.as_uri(), "--ref", old, "--force", "--no-enable"])
            installed = home / "plugins" / "loopdy"
            self.assertTrue((installed / "plugin.yaml").is_file())
            # Model the app's archive-style package, while retaining installer metadata.
            if (installed / ".git").exists():
                shutil.rmtree(installed / ".git")
            metadata_path = home / "plugins" / ".install-metadata.json"
            metadata = json.loads(metadata_path.read_text())
            metadata["loopdy"]["source"] = "https://github.com/promptclickrun/loopdy-plugin"
            metadata_path.write_text(json.dumps(metadata))
            data = home / "plugin-data" / "loopdy" / "pairing-sentinel.json"
            data.parent.mkdir(parents=True, exist_ok=True)
            data.write_text('{"fixture":"preserve-this-pairing"}')
            config_before, pairing_before = config.read_bytes(), data.read_bytes()
            (repo / "update-proof.txt").write_text("new revision installed through the actual Hermes installer\n")
            command(["git", "-C", str(repo), "add", "update-proof.txt"])
            command(commit + ["updated fixture"])
            target = command(["git", "-C", str(repo), "rev-parse", "HEAD"])
            manager = api.PluginUpdateManager(home / "plugin-data" / "loopdy" / "plugin-update", installed, "default", launch_worker=lambda _: None)
            operation = "update_real_install_0123456789"
            manager.start(operation, "device_fixture", False)
            # Only the remote address is redirected to a real local Git fixture.
            # Fetch, revision pinning, scan, doctor, backup, installer and readback are real.
            with patch.object(worker, "SOURCE_URL", repo.as_uri()):
                worker._run_operation(manager, operation)
            result = manager.status(operation, "device_fixture")
            self.assertEqual(result["phase"], "installed_restart_required")
            self.assertEqual(result["target_revision"], target)
            self.assertEqual(api._metadata_revision(installed), target)
            self.assertEqual((installed / "update-proof.txt").read_text(), (repo / "update-proof.txt").read_text())
            self.assertEqual(config.read_bytes(), config_before)
            self.assertEqual(data.read_bytes(), pairing_before)
            self.assertTrue((manager.data_root / "backups" / operation / "plugin" / "plugin.yaml").exists())


if __name__ == "__main__":
    unittest.main()
