from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hermes_state import SessionDB
from hermes_cli import projects_db
from loopdy_plugin import native_project_git, native_context
from loopdy_plugin.workspace_git import WorkspaceGitService
import test_native_api as native_fixtures


SESSION = "native-full-session-0001"


def git(root, *args, check=True):
    return subprocess.run(["git", *args], cwd=root, capture_output=True, check=check,
        env={**os.environ, "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
             "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"})


class NativeProjectGitTests(unittest.TestCase):
    def setUp(self):
        self.fixture = native_fixtures.NativeAPITests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.home = self.fixture.home
        self.root = self.home / "project"
        self.root.mkdir()
        git(self.root, "init", "-b", "main")
        (self.root / "file.txt").write_text("original\n")
        git(self.root, "add", "--", "file.txt")
        git(self.root, "commit", "-m", "Synthetic baseline")
        self.db = SessionDB(db_path=self.home / "state.db")
        self.db.create_session(SESSION, "cli", cwd=str(self.root), profile_name="default")
        self.db.close()
        with projects_db.connect_closing() as connection:
            self.project = projects_db.create_project(connection, name="Fixture", folders=[str(self.root)],
                                                      primary_path=str(self.root))
        self.client = self.fixture.client
        self.client.app.include_router(native_project_git.router, prefix="/api/plugins/loopdy")

    def call(self, suffix, fields=None, headers=None):
        return self.client.post(native_fixtures.PREFIX + "/projects/git/" + suffix,
            headers=self.fixture.headers() if headers is None else headers,
            json={"agentId": "default", "sessionId": SESSION, "workspaceId": self.project, **(fields or {})})

    def status(self):
        result = self.call("status")
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()

    def diff(self, token, **changes):
        return self.call("diff", {"path": "file.txt", "side": "worktree", "statusToken": token,
                                  "offset": 0, "limit": 500, **changes})

    def test_real_project_session_status_codec_and_readonly_caps_ignore_mutation_config(self):
        (self.root / "file.txt").write_text("changed\n")
        index = self.root / ".git/index"
        before = (index.read_bytes(), index.stat().st_mtime_ns, (self.root / "file.txt").read_bytes())
        with patch.dict(os.environ, {"LOOPDY_WORKSPACE_GIT_CONFIG": json.dumps([{
            "workspace_id": self.project, "root": str(self.root), "operations": ["status", "commit"],
            "remotes": ["origin"], "branches": ["main"], "mutations_enabled": True,
        }])}):
            caps = self.call("capabilities")
        self.assertEqual(caps.status_code, 200, caps.text)
        self.assertEqual(caps.json()["capabilities"], {"status": True, "stage": False, "commit": False,
            "push": False, "fetch": False, "pull": False, "arbitraryCommand": False})
        self.assertEqual(caps.json()["workspaces"][0]["operations"], ["status"])
        state = self.status()
        self.assertEqual(state["workspaceId"], self.project)
        self.assertEqual(state["head"]["branch"], "main")
        self.assertTrue(state["filesPage"]["complete"])
        self.assertNotIn("hidden_files", state)
        self.assertNotIn(str(self.root), json.dumps(state))
        self.assertEqual(before, (index.read_bytes(), index.stat().st_mtime_ns, (self.root / "file.txt").read_bytes()))
        self.assertFalse((self.home / "plugin-data/loopdy/workspace-git.sqlite3").exists())
        self.assertFalse((self.home / "plugin-data/loopdy/workspace-files").exists())
        for suffix in ("stage", "commit", "fetch", "push", "pull", "prepare"):
            self.assertEqual(self.call(suffix).status_code, 404)

    def test_distinct_sides_real_paging_exact_previews_and_stale_token(self):
        (self.root / "file.txt").write_text("staged\n")
        git(self.root, "add", "--", "file.txt")
        (self.root / "file.txt").write_text("working\n")
        token = self.status()["statusToken"]
        page = self.diff(token, side="staged", limit=2)
        self.assertEqual(page.status_code, 200, page.text)
        self.assertEqual(page.json()["nextOffset"], 2)
        self.assertEqual(page.json()["previewContent"], "staged\n")
        tail = self.diff(token, side="staged", offset=2).json()
        self.assertTrue(any(line["content"] == "staged" for line in tail["lines"]))
        work = self.diff(token).json()
        self.assertTrue(any(line["content"] == "working" for line in work["lines"]))
        self.assertEqual(work["previewContent"], "working\n")
        (self.root / "file.txt").write_text("again\n")
        rejected = self.diff(token)
        self.assertEqual(rejected.status_code, 409)
        self.assertEqual(rejected.json()["error"]["code"], "status_changed")

    def test_binary_oversize_and_complete_status_limit_are_explicit(self):
        (self.root / "binary.dat").write_bytes(b"x\0y")
        (self.root / "large.txt").write_bytes(b"x" * 2_000_001)
        token = self.status()["statusToken"]
        self.assertEqual(self.diff(token, path="binary.dat").json()["availability"], "binary")
        oversized = self.diff(token, path="large.txt").json()
        self.assertEqual(oversized["availability"], "oversized")
        self.assertEqual(oversized["lines"], [])
        self.assertIsNone(oversized["nextOffset"])
        for index in range(501):
            (self.root / f"many-{index}.txt").write_text("small\n")
        result = self.call("status")
        self.assertEqual(result.status_code, 413)
        self.assertEqual(result.json()["error"]["code"], "status_oversized")
        self.assertNotIn("files", result.json())

    def test_unmerged_conflict_is_not_available_empty_diff(self):
        git(self.root, "checkout", "-b", "conflict")
        (self.root / "file.txt").write_text("branch\n")
        git(self.root, "add", "--", "file.txt")
        git(self.root, "commit", "-m", "Branch fixture")
        git(self.root, "checkout", "main")
        (self.root / "file.txt").write_text("main\n")
        git(self.root, "add", "--", "file.txt")
        git(self.root, "commit", "-m", "Main fixture")
        self.assertNotEqual(git(self.root, "merge", "conflict", check=False).returncode, 0)
        token = self.status()["statusToken"]
        for side in ("staged", "worktree"):
            result = self.diff(token, side=side)
            self.assertEqual(result.status_code, 422, result.text)
            self.assertEqual(result.json()["error"]["code"], "diff_unsupported")

    def test_secret_hunks_protected_renames_and_unsafe_paths_fail_closed(self):
        (self.root / "file.txt").write_text("normal\n" * 1000 + "sk-" + "x" * 30)
        token = self.status()["statusToken"]
        result = self.diff(token, limit=1)
        self.assertEqual(result.status_code, 422)
        self.assertEqual(result.json()["error"]["code"], "sensitive_data_blocked")
        (self.root / "file.txt").write_text("safe\n")
        for path in ("../escape", "/etc/passwd", ".git/config"):
            self.assertGreaterEqual(self.diff(self.status()["statusToken"], path=path).status_code, 400)
        (self.root / ".env").write_text("not-a-secret\n")
        result = self.call("status")
        self.assertEqual(result.json()["error"]["code"], "sensitive_data_blocked")

    def test_hidden_canonical_root_and_tip_are_allowed_but_other_hidden_and_plumbing_denied(self):
        db = SessionDB(db_path=self.home / "state.db")
        try:
            db.set_session_title(SESSION, "Bot Chat")
            db.set_session_hidden(SESSION, True)
            self.assertEqual(self.call("status").status_code, 200)
            db.end_session(SESSION, "compression")
            db.create_session("canonical-middle", "cli", cwd=str(self.root), profile_name="default",
                              parent_session_id=SESSION)
            db.set_session_hidden("canonical-middle", True)
            db.end_session("canonical-middle", "compression")
            db.create_session("canonical-tip", "cli", cwd=str(self.root), profile_name="default",
                              parent_session_id="canonical-middle")
            db.set_session_hidden("canonical-tip", True)
            self.assertEqual(self.call("status", {"sessionId": "canonical-tip"}).status_code, 200)
            self.assertEqual(self.call("status", {"sessionId": "canonical-middle"}).status_code, 404)
            db.create_session("unrelated-hidden", "cli", cwd=str(self.root), profile_name="default")
            db.set_session_hidden("unrelated-hidden", True)
            self.assertEqual(self.call("status", {"sessionId": "unrelated-hidden"}).status_code, 404)
            for source in ("bot_room", "tool", "subagent", "worker"):
                db.create_session("internal-" + source, source, cwd=str(self.root), profile_name="default")
                self.assertEqual(self.call("status", {"sessionId": "internal-" + source}).status_code, 404)
        finally:
            db.close()

    def test_exact_profile_full_session_and_project_root_required_without_fallback(self):
        for update in ({"sessionId": SESSION[:-1]}, {"workspaceId": "missing"},
                       {"agentId": "research"}, {"agentId": "missing"}):
            self.assertEqual(self.call("status", update).status_code, 404)
        self.assertFalse((self.home / "profiles/research/state.db").exists())
        db = SessionDB(db_path=self.home / "state.db")
        try:
            db.create_session("wrong-cwd", "cli", cwd=str(self.home), profile_name="default")
            db.create_session("wrong-profile", "cli", cwd=str(self.root), profile_name="research")
            self.assertEqual(self.call("status", {"sessionId": "wrong-cwd"}).status_code, 404)
            self.assertEqual(self.call("status", {"sessionId": "wrong-profile"}).status_code, 404)
        finally:
            db.close()
        with projects_db.connect_closing() as connection:
            projects_db.archive_project(connection, self.project)
        self.assertEqual(self.call("status").status_code, 404)

    def test_project_metadata_change_after_git_read_and_auth_context_change_are_rejected(self):
        original = native_project_git.association
        count = 0
        def moved(body):
            nonlocal count
            count += 1
            value = original(body)
            if count == 2:
                from dataclasses import replace
                return replace(value, label="Changed project")
            return value
        with patch.object(native_project_git, "association", side_effect=moved):
            result = self.call("status")
        self.assertEqual(result.status_code, 409)
        self.assertEqual(result.json()["error"]["code"], "scope_changed")
        old = native_context.RUNTIME_ID
        def switched(body):
            value = original(body)
            native_context.RUNTIME_ID = "new-runtime"
            return value
        try:
            with patch.object(native_project_git, "association", side_effect=switched):
                self.assertEqual(self.call("status").status_code, 412)
        finally:
            native_context.RUNTIME_ID = old

    def test_actual_session_move_and_root_replacement_during_read_fail_closed(self):
        original = WorkspaceGitService.status
        changed = False
        def moved(service, workspace_id):
            nonlocal changed
            result = original(service, workspace_id)
            if not changed:
                changed = True
                with sqlite3.connect(self.home / "state.db") as connection:
                    connection.execute("UPDATE sessions SET cwd=? WHERE id=?", (str(self.home), SESSION))
            return result
        with patch.object(WorkspaceGitService, "status", moved):
            result = self.call("status")
        self.assertEqual(result.status_code, 409, result.text)
        self.assertEqual(result.json()["error"]["code"], "scope_changed")
        with sqlite3.connect(self.home / "state.db") as connection:
            connection.execute("UPDATE sessions SET cwd=? WHERE id=?", (str(self.root), SESSION))
        changed = False
        def replaced(service, workspace_id):
            nonlocal changed
            result = original(service, workspace_id)
            if not changed:
                changed = True
                self.root.rename(self.home / "original-project")
                self.root.mkdir()
            return result
        with patch.object(WorkspaceGitService, "status", replaced):
            result = self.call("status")
        self.assertEqual(result.status_code, 409, result.text)
        self.assertEqual(result.json()["error"]["code"], "scope_changed")

    def test_symlink_primary_root_and_missing_database_are_not_followed_or_created(self):
        original = self.home / "original-project"
        self.root.rename(original)
        self.root.symlink_to(original, target_is_directory=True)
        self.assertEqual(self.call("status").status_code, 404)
        self.root.unlink()
        original.rename(self.root)
        database = self.home / "state.db"
        saved = self.home / "saved-state.db"
        database.rename(saved)
        self.assertEqual(self.call("status").status_code, 404)
        self.assertFalse(database.exists())

    def test_headers_revocation_unknown_fields_and_mutation_policy_fail_closed(self):
        result = self.call("status", headers={"Authorization": "Bearer fixture-alice"})
        self.assertEqual(result.status_code, 428)
        headers = self.fixture.headers()
        for extra in ("root", "command", "remote", "actor", "deviceId", "offset"):
            self.assertEqual(self.call("status", {extra: "untrusted"}).status_code, 422)
        token = self.status()["statusToken"]
        self.assertEqual(self.diff(token, limit=True).status_code, 422)
        other = {**headers, "Authorization": "Bearer fixture-bob"}
        self.assertEqual(self.call("status", headers=other).status_code, 412)
        self.fixture.provider.tokens.pop("fixture-alice")
        self.assertEqual(self.call("status", headers=headers).status_code, 401)
        with self.assertRaises(ValueError):
            WorkspaceGitService([{"workspace_id": "unsafe", "label": "Unsafe", "root": str(self.root),
                "operations": ["status", "commit"], "remotes": [], "branches": [], "mutations_enabled": True}],
                read_only=True)

    def test_hidden_bot_chat_worker_metadata_and_archived_canonical_are_not_admitted(self):
        db = SessionDB(db_path=self.home / "state.db")
        try:
            db.set_session_title(SESSION, "Bot Chat")
            db.set_session_hidden(SESSION, True)
        finally:
            db.close()
        for update in ({"source": "bot_room"}, {"model_config": '{"room_plumbing":true}'},
                       {"model_config": '{"_delegate_from":"parent"}'}, {"archived": 1}):
            with sqlite3.connect(self.home / "state.db") as connection:
                connection.execute("UPDATE sessions SET source='cli',model_config=NULL,archived=0 WHERE id=?", (SESSION,))
                key, value = next(iter(update.items()))
                connection.execute(f"UPDATE sessions SET {key}=? WHERE id=?", (value, SESSION))
            result = self.call("status")
            self.assertEqual(result.status_code, 404, result.text)

    def test_invalid_combined_output_and_missing_support_are_explicit(self):
        (self.root / "file.txt").write_text("changed\n")
        token = self.status()["statusToken"]
        original = WorkspaceGitService._git_bounded
        def combined(service, *args):
            if "--unified=3" in args:
                return b"diff --cc file.txt\n@@@ -1,1 -1,1 +1,1 @@@\n++conflict\n", False
            return original(service, *args)
        with patch.object(WorkspaceGitService, "_git_bounded", combined):
            result = self.diff(token)
            self.assertEqual(result.status_code, 422)
            self.assertEqual(result.json()["error"]["code"], "diff_unsupported")
        with patch.object(native_project_git, "supported", return_value=False):
            result = self.call("status")
            self.assertEqual(result.status_code, 501)
            self.assertNotIn(native_project_git.CAPABILITY, self.fixture.context().json()["features"])


class NativeProjectGitStockTests(unittest.TestCase):
    def test_stock_native_auth_public_metadata_and_real_git_without_pairing(self):
        script = r'''
import os,sys
from pathlib import Path
from fastapi.testclient import TestClient
from hermes_state import SessionDB
from hermes_cli import projects_db
from hermes_cli.web_server import app
from hermes_cli.dashboard_auth.registry import register_provider
from test_native_api import FixtureProvider,PREFIX
from test_native_project_git import git,SESSION
home=Path(os.environ["HERMES_HOME"])
root=Path(os.environ["HOME"])/"project"
root.mkdir()
git(root,"init","-b","main")
(root/"file.txt").write_text("before\n")
git(root,"add","--","file.txt")
git(root,"commit","-m","Fixture")
(root/"file.txt").write_text("after\n")
db=SessionDB(db_path=home/"state.db")
db.create_session(SESSION,"cli",cwd=str(root),profile_name="default")
db.set_session_title(SESSION,"Bot Chat")
db.set_session_hidden(SESSION,True)
db.close()
with projects_db.connect_closing() as connection:
 project=projects_db.create_project(connection,name="Fixture",folders=[str(root)],primary_path=str(root))
provider=FixtureProvider()
register_provider(provider)
app.state.auth_required=True
client=TestClient(app,base_url="http://localhost")
base=PREFIX+"/projects/git/"
body={"agentId":"default","sessionId":SESSION,"workspaceId":project}
assert client.post(base+"status",json=body).status_code==401
headers={"Authorization":"Bearer fixture-alice"}
context=client.get(PREFIX+"/context",headers=headers)
assert "native-project-git-read-v1" in context.json()["features"]
headers.update({"If-Match":context.headers["etag"],"X-Loopdy-Request-ID":"123e4567-e89b-42d3-a456-426614174000"})
before_index=(root/".git/index").read_bytes()
status=client.post(base+"status",headers=headers,json=body)
assert status.status_code==200,(status.status_code,status.text)
diff=client.post(base+"diff",headers=headers,json={**body,"path":"file.txt","side":"worktree",
 "statusToken":status.json()["statusToken"],"offset":0,"limit":500})
assert diff.status_code==200,(diff.status_code,diff.text)
assert any(row["content"]=="after" for row in diff.json()["lines"])
assert (root/".git/index").read_bytes()==before_index
assert not (home/"plugin-data/loopdy/workspace-git.sqlite3").exists()
provider.tokens.pop("fixture-alice")
assert client.post(base+"status",headers=headers,json=body).status_code==401
provider.tokens["fixture-alice"]=provider.alice
(home/"config.yaml").write_text("plugins:\n  enabled: []\n  disabled: [loopdy]\n")
assert client.post(base+"status",headers=headers,json=body).status_code==404
print("stock native Git auth, canonical hidden session, public Project metadata, diff and no-index-write passed",file=sys.__stdout__,flush=True)
'''
        with tempfile.TemporaryDirectory(prefix="loopdy-native-git-http-", dir=Path(tempfile.gettempdir()).resolve()) as directory:
            home = Path(directory) / "hermes-home"
            (home / "plugins").mkdir(parents=True)
            (home / "plugins/loopdy").symlink_to(native_fixtures.ROOT, target_is_directory=True)
            (home / "config.yaml").write_text("plugins:\n  enabled: [loopdy]\n")
            env = {key: os.environ[key] for key in ("PATH", "PYTHONPATH") if key in os.environ}
            env.update(HOME=directory, HERMES_HOME=str(home), TMPDIR=directory, PYTHONDONTWRITEBYTECODE="1")
            result = subprocess.run([sys.executable, "-B", "-c", script], env=env, cwd=directory,
                                    capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("no-index-write passed", result.stdout)
