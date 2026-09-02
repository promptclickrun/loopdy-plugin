from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from loopdy_plugin.workspace_git import WorkspaceGitService


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "Loopdy Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.test", "GIT_COMMITTER_NAME": "Loopdy Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.test"},
    )


class WorkspaceGitApiTests(unittest.TestCase):
    def test_fixed_routes_are_strict_and_return_structured_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            git(root, "init", "-b", "main")
            (root / "tracked.txt").write_text("one\n", encoding="utf-8")
            git(root, "add", "--", "tracked.txt")
            git(root, "commit", "-m", "initial")
            (root / "tracked.txt").write_text("two\n", encoding="utf-8")
            service = WorkspaceGitService(
                [
                    {
                        "workspace_id": "fixture",
                        "label": "Fixture",
                        "root": str(root),
                        "visibility": "public",
                        "operations": ["status", "stage", "commit", "push", "fetch", "pull"],
                        "remotes": ["origin"],
                        "branches": ["main"],
                        "mutations_enabled": True,
                    }
                ],
                state_path=Path(directory) / "state.sqlite3",
            )
            module_name = "loopdy_workspace_git_api_for_test"
            spec = importlib.util.spec_from_file_location(module_name, PLUGIN_ROOT / "dashboard" / "plugin_api.py")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            assert spec.loader is not None
            spec.loader.exec_module(module)
            module._workspace_git_service = service
            app = FastAPI()
            app.include_router(module.router)
            client = TestClient(app)

            capabilities = client.get("/workspace-git/capabilities")
            self.assertEqual(capabilities.status_code, 200)
            self.assertFalse(capabilities.json()["capabilities"]["arbitrary_command"])
            self.assertNotIn(str(root), capabilities.text)

            status = client.post("/workspace-git/status", json={"workspace_id": "fixture"})
            self.assertEqual(status.status_code, 200)
            token = status.json()["status_token"]
            self.assertEqual(status.json()["changes"]["files"], 1)

            escape = client.post(
                "/workspace-git/prepare",
                json={
                    "workspace_id": "fixture",
                    "operation": "stage",
                    "input": {"mode": "stage", "paths": ["../outside"]},
                    "expected_status_token": token,
                },
                headers={"x-loopdy-connection-id": "fixture-connection"},
            )
            self.assertEqual(escape.status_code, 400)
            self.assertEqual(escape.json()["error"]["code"], "INVALID_PATH")

            arbitrary = client.post(
                "/workspace-git/stage",
                json={
                    "workspace_id": "fixture",
                    "mode": "stage",
                    "paths": ["tracked.txt"],
                    "expected_status_token": token,
                    "confirmation_token": "no",
                    "idempotency_key": "11111111-1111-4111-8111-111111111111",
                    "command": "git reset --hard",
                },
            )
            self.assertEqual(arbitrary.status_code, 422)


if __name__ == "__main__":
    unittest.main()
