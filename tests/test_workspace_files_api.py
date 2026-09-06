from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]


class WorkspaceFilesApiTests(unittest.TestCase):
    def test_real_plugin_router_includes_strict_read_only_files_routes(self):
        from loopdy_plugin.workspace_files import WorkspaceFilesService
        from loopdy_plugin import workspace_files_api

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "workspace"
            root.mkdir()
            (root / "unchanged.md").write_text("# Hello\n")
            service = WorkspaceFilesService(Path(directory) / "state")
            service.grant("demo", root=root, label="Demo")
            spec = importlib.util.spec_from_file_location("files_plugin_api_candidate", ROOT / "dashboard/plugin_api.py")
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            self.addCleanup(sys.modules.pop, spec.name, None)
            spec.loader.exec_module(module)
            app = FastAPI()
            app.include_router(module.router)
            app.dependency_overrides[workspace_files_api.get_workspace_files_service] = lambda: service
            with TestClient(app) as client:
                response = client.get("/workspace-files/capabilities")
                self.assertEqual(response.status_code, 200, response.text)
                self.assertNotIn(str(root), response.text)
                page = client.post("/workspace-files/list", json={"workspace_id":"demo", "path":"", "offset":0, "limit":100, "query":""})
                self.assertEqual(page.status_code, 200, page.text)
                self.assertEqual(page.json()["entries"][0]["name"], "unchanged.md")
                data = client.post("/workspace-files/read", json={"workspace_id":"demo", "path":"unchanged.md", "offset":0, "limit":65536})
                self.assertEqual(data.status_code, 200, data.text)
                self.assertEqual(data.json()["text"], "# Hello\n")
                for path in ("../outside", "/etc/passwd", ".git/config"):
                    bad = client.post("/workspace-files/read", json={"workspace_id":"demo", "path":path})
                    self.assertGreaterEqual(bad.status_code, 400)
                    self.assertNotIn(str(root), bad.text)
                for extra in ({"root":"/etc"}, {"command":"arbitrary"}, {"offset":True}, {"limit":65537}):
                    bad = client.post("/workspace-files/read", json={"workspace_id":"demo", "path":"unchanged.md", **extra})
                    self.assertEqual(bad.status_code, 422, bad.text)
                self.assertEqual(client.post("/workspace-files/grant", json={}).status_code, 404)
                self.assertEqual(client.post("/workspace-files/revoke", json={}).status_code, 404)
                self.assertEqual(client.post("/workspace-files/commit", json={}).status_code, 404)


    def test_stock_hermes_mount_auth_and_disable_gate(self):
        script = r'''
import json, os, sys
from pathlib import Path
from fastapi.testclient import TestClient
# Stock plugin discovery must establish imports in this clean subprocess.
from hermes_cli.web_server import app
from loopdy_plugin.workspace_files import WorkspaceFilesService
home = Path(os.environ["HERMES_HOME"])
root = home.parent / "project"
root.mkdir()
(root / "visible.txt").write_text("Fixture only.\n")
service = WorkspaceFilesService(home / "plugin-data/loopdy/workspace-files")
service.grant("demo", root=root, label="Demo")
from loopdy_plugin import workspace_files
assert Path(workspace_files.__file__).resolve().parent.parent == Path(os.environ["CANDIDATE_ROOT"])
mounted = sys.modules["hermes_dashboard_plugin_loopdy"]
assert Path(mounted.__file__).resolve() == Path(os.environ["CANDIDATE_ROOT"]) / "dashboard/plugin_api.py"
client = TestClient(app, base_url="http://localhost")
url = "/api/plugins/loopdy/workspace-files/capabilities"
assert client.get(url).status_code == 401
assert client.get(url, headers={"X-Hermes-Session-Token":"wrong-fixture"}).status_code == 401
headers={"X-Hermes-Session-Token":os.environ["HERMES_DASHBOARD_SESSION_TOKEN"]}
r = client.get(url, headers=headers)
assert r.status_code == 200, (r.status_code, r.text)
r = client.post("/api/plugins/loopdy/workspace-files/read", headers=headers,
    json={"workspace_id":"demo", "path":"visible.txt"})
assert r.status_code == 200, (r.status_code, r.text)
assert r.json()["text"] == "Fixture only.\n"
(home / "config.yaml").write_text("plugins:\n  enabled: []\n  disabled: [loopdy]\n")
assert client.get(url, headers=headers).status_code == 404
print("stock mount, exact source, unauthorized denial, file read, disable gate verified")
'''
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve() / "hermes-home"
            (home / "plugins").mkdir(parents=True)
            (home / "plugins/loopdy").symlink_to(ROOT, target_is_directory=True)
            (home / "config.yaml").write_text("plugins:\n  enabled: [loopdy]\n")
            env = {k:v for k,v in os.environ.items() if not any(word in k.upper() for word in ("TOKEN", "SECRET", "PASSWORD", "API_KEY"))}
            env.update(HERMES_HOME=str(home), HERMES_DASHBOARD_SESSION_TOKEN="workspace-files-auth-fixture",
                       CANDIDATE_ROOT=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
            result = subprocess.run([sys.executable, "-c", script], env=env, cwd=directory,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("disable gate verified", result.stdout)


    def test_registered_cli_grant_read_and_revoke(self):
        script = "from hermes_cli.main import main; main()"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            home = base / "hermes-home"
            root = base / "workspace"
            root.mkdir()
            (root / "file.txt").write_text("CLI fixture\n")
            (home / "plugins").mkdir(parents=True)
            (home / "plugins/loopdy").symlink_to(ROOT, target_is_directory=True)
            (home / "config.yaml").write_text("plugins:\n  enabled: [loopdy]\n")
            env = {k:v for k,v in os.environ.items() if not any(word in k.upper() for word in ("TOKEN", "SECRET", "PASSWORD", "API_KEY"))}
            env.update(HERMES_HOME=str(home), PYTHONDONTWRITEBYTECODE="1")
            def cli(*args, code=0):
                result = subprocess.run([sys.executable, "-c", script, "loopdy", "files", *args], env=env, cwd=directory,
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                return json.loads(result.stdout)
            self.assertEqual(cli("roots")["roots"], [])
            self.assertTrue(cli("grant", "demo", "--root", str(root), "--label", "Demo")["granted"])
            self.assertEqual(cli("read", "demo", "file.txt")["text"], "CLI fixture\n")
            cli("revoke", "demo", code=1)
            self.assertTrue(cli("revoke", "demo", "--yes")["revoked"])
            self.assertEqual(cli("read", "demo", "file.txt", code=1)["error"]["code"], "WORKSPACE_NOT_ALLOWED")


if __name__ == "__main__":
    unittest.main()
