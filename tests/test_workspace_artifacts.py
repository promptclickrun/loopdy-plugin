"""Authenticated file routes against real temporary files and Hermes config."""
import base64
import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import yaml
import test_native_api as native_fixture

PREFIX = native_fixture.PREFIX
from loopdy_plugin import workspace_artifacts as files


class WorkspaceArtifactRouteTests(unittest.TestCase):
    setUp = native_fixture.NativeAPITests.setUp
    context = native_fixture.NativeAPITests.context
    headers = native_fixture.NativeAPITests.headers

    def configure(self):
        root = self.home / "workspace"
        root.mkdir()
        (self.home / "config.yaml").write_text(yaml.safe_dump({"terminal": {"cwd": str(root)}}))
        return root

    def request(self, operation, path=None, headers=None):
        return self.client.post(PREFIX + "/workspace-files/" + operation,
                                headers=headers if headers is not None else self.headers(),
                                json={"path": path})

    def test_scope_listing_and_read_use_configured_root_and_true_birth_time(self):
        root = self.configure()
        target = root / "sample.txt"
        target.write_text("isolated fixture")
        modified = target.stat().st_mtime + 3600
        os.utime(target, (modified, modified))
        scope = self.request("scope")
        self.assertEqual(scope.status_code, 200, scope.text)
        self.assertEqual(scope.json()["workspace"]["source"], "terminal.cwd")
        self.assertEqual(scope.json()["workspace"]["root"], str(root))
        listing = self.request("list")
        self.assertEqual(listing.status_code, 200, listing.text)
        row = next(row for row in listing.json()["entries"] if row["name"] == "sample.txt")
        self.assertAlmostEqual(row["mtime"], modified, places=3)
        birth = getattr(target.stat(), "st_birthtime", None)
        if birth is not None:
            self.assertAlmostEqual(row["created"], birth, places=3)
            self.assertNotEqual(row["created"], row["mtime"])
        read = self.request("read", str(target))
        self.assertEqual(read.status_code, 200, read.text)
        self.assertEqual(base64.b64decode(read.json()["data_url"].split(",", 1)[1]), b"isolated fixture")
        self.assertEqual(read.headers["cache-control"], "no-store")
        self.assertIn("x-loopdy-request-id", read.headers)

    def history(self, rows):
        import sqlite3
        with sqlite3.connect(self.home / "state.db") as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, session_id TEXT, "
                               "role TEXT, content TEXT, tool_calls TEXT, timestamp REAL)")
            connection.executemany("INSERT INTO messages (session_id, role, content, tool_calls, timestamp) "
                                   "VALUES ('s', 'assistant', ?, ?, ?)", rows)

    @staticmethod
    def wrote(path, tool="write_file"):
        return json.dumps([{"id": "c", "type": "function",
                            "function": {"name": tool, "arguments": json.dumps({"path": str(path)})}}])

    def test_recent_lists_what_the_agent_made_newest_first_inside_the_workspace_only(self):
        root = self.configure()
        (root / "deep" / "er" / "still").mkdir(parents=True)
        made = root / "deep" / "er" / "still" / "report.md"
        patched = root / "app.swift"
        sent = root / "clip.mp4"
        for path in (made, patched, sent):
            path.write_text(path.name)
        outside = self.home / "outside.txt"
        outside.write_text("outside")
        (root / "linked.txt").symlink_to(outside)
        (root / ".secret").write_text("hidden")
        self.history([
            (None, self.wrote(made), 300.0),
            (None, self.wrote(patched, "patch"), 200.0),
            (f"Here it is\nMEDIA:{sent}", None, 250.0),
            (None, self.wrote(outside), 400.0),
            (None, self.wrote(root / "linked.txt"), 410.0),
            (None, self.wrote(root / ".secret"), 420.0),
            (None, self.wrote(root / "deleted.txt"), 430.0),
            (None, self.wrote("relative.txt"), 440.0),
        ])
        response = self.request("recent")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        agent_rows = [row["name"] for row in body["entries"] if row["name"] in {"report.md", "clip.mp4", "app.swift"}]
        self.assertEqual(agent_rows, ["report.md", "clip.mp4", "app.swift"])
        self.assertNotIn("outside", response.text)
        self.assertNotIn(".secret", response.text)
        self.assertEqual(body["workspace"]["root"], str(root))
        self.assertEqual(self.request("recent", str(root)).status_code, 422)

    def test_recent_adds_new_top_level_files_and_skips_housekeeping(self):
        root = self.configure()
        (root / "project" / "node_modules" / "pkg").mkdir(parents=True)
        (root / "cloned" / ".git").mkdir(parents=True)
        (root / "cloned" / "README.md").write_text("fresh clone")
        files = {
            root / "notes.md": 1_000,
            root / "project" / "summary.pdf": 2_000,
            root / "project" / "debug.log": 9_000,
            root / "project" / "node_modules" / "pkg" / "index.js": 9_000,
        }
        for path, stamp in files.items():
            path.write_text(path.name)
            os.utime(path, (stamp, stamp))
        response = self.request("recent")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual({row["name"] for row in response.json()["entries"]}, {"notes.md", "summary.pdf"})

    def test_missing_and_relative_config_never_fall_back_to_process_cwd(self):
        for cwd in [None, ".", "auto", "relative/folder"]:
            config = {} if cwd is None else {"terminal": {"cwd": cwd}}
            (self.home / "config.yaml").write_text(yaml.safe_dump(config))
            response = self.request("scope")
            self.assertEqual(response.status_code, 409, response.text)
            self.assertEqual(response.json()["error"]["code"], "workspace_not_configured")

    def test_outside_traversal_symlink_and_special_files_are_not_readable(self):
        root = self.configure()
        outside = self.home / "outside.txt"
        outside.write_text("not authorized by workspace")
        (root / "alias.txt").symlink_to(outside)
        os.mkfifo(root / "pipe")
        for path in [outside, root / ".." / "outside.txt", root / "alias.txt", root / "pipe"]:
            response = self.request("read", str(path))
            self.assertNotEqual(response.status_code, 200, response.text)
            self.assertNotIn("not authorized by workspace", response.text)
        listing = self.request("list")
        self.assertEqual(listing.status_code, 200, listing.text)
        self.assertEqual(listing.json()["entries"], [])

    def test_auth_etag_and_request_id_are_required_before_file_access(self):
        self.configure()
        for headers, expected in [({}, 401), ({"Authorization": "Bearer fixture-alice"}, 428)]:
            self.assertEqual(self.request("scope", headers=headers).status_code, expected)
        headers = self.headers()
        headers["If-Match"] = '"obsolete-context"'
        self.assertEqual(self.request("scope", headers=headers).status_code, 412)
        headers = self.headers()
        self.provider.tokens.pop("fixture-alice")
        self.assertEqual(self.request("scope", headers=headers).status_code, 401)

    def test_duplicate_body_keys_and_oversized_file_fail_closed(self):
        root = self.configure()
        duplicate = self.client.post(PREFIX + "/workspace-files/list", headers=self.headers(),
                                     content='{"path":null,"path":null}')
        self.assertEqual(duplicate.status_code, 422, duplicate.text)
        target = root / "large.bin"
        with target.open("wb") as output:
            output.truncate(files.MAX_FILE_BYTES + 1)
        response = self.request("read", str(target))
        self.assertEqual(response.status_code, 413, response.text)

    def test_no_birth_time_never_substitutes_mtime_or_ctime(self):
        self.assertIsNone(files._birthtime(SimpleNamespace(st_mtime=100, st_ctime=200)))
        with patch.object(files, "_linux_birthtime", return_value=None):
            self.assertIsNone(files._birthtime(SimpleNamespace(st_mtime=100, st_ctime=200), 123))

    def test_workspace_change_during_read_discards_result(self):
        root = self.configure()
        target = root / "sample.txt"
        target.write_text("must not escape stale scope")
        other = self.home / "other"
        other.mkdir()
        original = files._read
        def read_then_change(*args, **kwargs):
            result = original(*args, **kwargs)
            (self.home / "config.yaml").write_text(yaml.safe_dump({"terminal": {"cwd": str(other)}}))
            return result
        with patch.object(files, "_read", side_effect=read_then_change):
            response = self.request("read", str(target))
        self.assertEqual(response.status_code, 409, response.text)
        self.assertNotIn("data_url", response.text)
