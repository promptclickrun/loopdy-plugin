"""Exercise the production launcher across a disposable launchd parent's exit."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from loopdy_plugin import plugin_update as api


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("launchctl"), "launchd lifecycle proof is macOS-only")
class PluginUpdateLaunchdTests(unittest.TestCase):
    def test_production_launcher_survives_its_parent_job_being_removed(self):
        with tempfile.TemporaryDirectory(prefix="loopdy-coalition-proof-") as directory:
            root = Path(directory)
            plugin = root / "plugins" / "loopdy"
            plugin.mkdir(parents=True)
            fake_source = root / "controlled-worker"
            fake_source.mkdir()
            (fake_source / "plugin_update.py").write_text("# Controlled worker fixture, not runtime code.\n")
            # Only worker business logic is replaced. The production launchctl
            # submission, clean environment and copied-worker paths are exercised.
            (fake_source / "plugin_update_worker.py").write_text('''import argparse, json, os, pathlib, subprocess, time
p = argparse.ArgumentParser()
p.add_argument('--data-root'); p.add_argument('--plugin-root'); p.add_argument('--profile'); p.add_argument('--operation-id'); p.add_argument('--service-label')
a = p.parse_args()
r = pathlib.Path(a.data_root)
(r / 'child-started.json').write_text(json.dumps({'pid': os.getpid()}))
end = time.monotonic() + 20
while not (r / 'parent-removed').exists() and time.monotonic() < end:
    time.sleep(.05)
if (r / 'parent-removed').exists():
    (r / 'child-survived').write_text('survived actual parent launchd job removal')
subprocess.run(['/bin/launchctl', 'remove', a.service_label], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
''')
            data = root / "data"
            operation = "update_probe_" + uuid.uuid4().hex
            digest = hashlib.sha256(operation.encode()).hexdigest()[:20]
            child_label = f"app.loopdy.plugin-update.{os.getuid()}.{digest}"
            parent_label = "app.loopdy.test-parent." + uuid.uuid4().hex
            parent = root / "parent.py"
            parent.write_text('''import json, os, pathlib, time
from loopdy_plugin import plugin_update as api
r = pathlib.Path(__file__).parent
api.__file__ = str(r / 'controlled-worker' / 'plugin_update.py')
m = api.PluginUpdateManager(r / 'data', r / 'plugins' / 'loopdy', 'default')
m.start(OPERATION, 'fixture_device', False)
(r / 'data' / 'parent-started.json').write_text(json.dumps({'pid': os.getpid()}))
time.sleep(30)
'''.replace("OPERATION", repr(operation)))
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(Path.home()), "HERMES_HOME": str(root), "PYTHONPATH": str(Path(api.__file__).resolve().parents[1])}
            command = ["/bin/launchctl", "submit", "-l", parent_label, "-o", "/dev/null", "-e", "/dev/null", "--", "/usr/bin/env", "-i", *[f"{key}={value}" for key, value in env.items()], sys.executable, str(parent)]
            try:
                subprocess.run(command, check=True, timeout=10)
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline and not (data / "child-started.json").exists():
                    time.sleep(.05)
                self.assertTrue((data / "child-started.json").exists(), "Production launcher did not start its independent job")
                subprocess.run(["/bin/launchctl", "remove", parent_label], check=True, timeout=10)
                self.assertNotEqual(subprocess.run(["/bin/launchctl", "list", parent_label], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode, 0)
                (data / "parent-removed").write_text("removed")
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline and not (data / "child-survived").exists():
                    time.sleep(.05)
                self.assertTrue((data / "child-survived").exists(), "Updater child died with its parent coalition")
            finally:
                for label in [parent_label, child_label]:
                    subprocess.run(["/bin/launchctl", "remove", label], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)


if __name__ == "__main__":
    unittest.main()
