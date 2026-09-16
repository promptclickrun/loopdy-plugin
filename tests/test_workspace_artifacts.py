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
