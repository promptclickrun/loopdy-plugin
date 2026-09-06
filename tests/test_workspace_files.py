from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class WorkspaceFilesTests(unittest.TestCase):
    def test_explicit_grant_lists_unchanged_files_and_confines_reads(self):
        module = importlib.util.find_spec("loopdy_plugin.workspace_files")
        self.assertIsNotNone(module, "Workspace Files service must exist before clients can browse")
        from loopdy_plugin.workspace_files import WorkspaceFilesService, WorkspaceFilesError

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "workspace"
            root.mkdir()
            (root / "notes").mkdir()
            (root / "notes" / "unchanged.txt").write_text("Full unchanged file.\n", encoding="utf-8")
            (root / "README.md").write_text("# Workspace\n", encoding="utf-8")
            service = WorkspaceFilesService(base / "state")
            with self.assertRaises(WorkspaceFilesError):
                service.list_directory("demo", path="", offset=0, limit=100, query="")
            service.grant("demo", root=root, label="Demo")
            page = service.list_directory("demo", path="", offset=0, limit=100, query="")
            self.assertEqual([entry["name"] for entry in page["entries"]], ["notes", "README.md"])
            self.assertIsNone(page["parent"])
            self.assertNotIn(str(root), repr(page))
            nested = service.list_directory("demo", path="notes", offset=0, limit=100, query="")
            self.assertEqual(nested["parent"], "")
            result = service.read_file("demo", path="notes/unchanged.txt", offset=0, limit=65536)
            self.assertEqual(result["availability"], "available")
            self.assertEqual(result["text"], "Full unchanged file.\n")
            with self.assertRaises(WorkspaceFilesError):
                service.read_file("demo", path="../outside.txt", offset=0, limit=65536)
            service.revoke("demo")
            with self.assertRaises(WorkspaceFilesError):
                service.read_file("demo", path="notes/unchanged.txt", offset=0, limit=65536)


    def fixture(self, base):
        from loopdy_plugin.workspace_files import WorkspaceFilesService
        root = Path(base).resolve() / "project"
        root.mkdir()
        service = WorkspaceFilesService(Path(base) / "state")
        service.grant("demo", root=root, label="Demo")
        return root, service

    def test_directory_pages_are_complete_and_revision_bound(self):
        from loopdy_plugin.workspace_files import WorkspaceFilesError
        with tempfile.TemporaryDirectory() as base:
            root, service = self.fixture(base)
            for name in ("alpha.txt", "beta.txt", "charlie.txt", ".notes"):
                (root / name).write_text(name)
            first = service.list_directory("demo", path="", offset=0, limit=2, query="")
            second = service.list_directory("demo", path="", offset=2, limit=2, query="", revision=first["revision"])
            names = [e["name"] for e in first["entries"] + second["entries"]]
            self.assertEqual(sorted(names), sorted(["alpha.txt", "beta.txt", "charlie.txt", ".notes"]))
            filtered = service.list_directory("demo", path="", offset=0, limit=10, query="BETA")
            self.assertEqual([e["name"] for e in filtered["entries"]], ["beta.txt"])
            (root / "delta.txt").write_text("new")
            with self.assertRaises(WorkspaceFilesError):
                service.list_directory("demo", path="", offset=2, limit=2, query="", revision=first["revision"])

    def test_paths_links_special_files_and_credentials_do_not_escape(self):
        from loopdy_plugin.workspace_files import WorkspaceFilesError
        with tempfile.TemporaryDirectory() as base:
            root, service = self.fixture(base)
            (root / "safe.txt").write_text("ordinary content")
            (root / ".env").write_text("fixture content")
            (root / ".git").mkdir()
            (root / ".git" / "config").write_text("fixture content")
            (root / "secret.txt").write_text("password=" + "synthetic" * 5)
            (root / "link.txt").symlink_to(root / "safe.txt")
            (root / "escape").symlink_to(Path(base))
            os.link(root / "safe.txt", root / "hard.txt")
            os.mkfifo(root / "pipe")
            for path in ("../out", "/etc/passwd", "./safe.txt", "folder//safe", "C:\\safe", ".env", ".git/config", "secret.txt", "link.txt", "escape/file", "pipe", "hard.txt"):
                with self.subTest(path=path), self.assertRaises(WorkspaceFilesError):
                    service.read_file("demo", path=path, offset=0, limit=65536)
            listing = service.list_directory("demo", path="", offset=0, limit=100, query="")
            names = {e["name"] for e in listing["entries"]}
            self.assertFalse(names & {".env", ".git", "link.txt", "escape", "pipe", "hard.txt"})
            with self.assertRaises(WorkspaceFilesError):
                service.read_file("demo", path="safe.txt", offset=True, limit=100)

    def test_revocation_and_root_replacement_invalidate_existing_instances(self):
        from loopdy_plugin.workspace_files import WorkspaceFilesService, WorkspaceFilesError
        with tempfile.TemporaryDirectory() as base:
            root, service = self.fixture(base)
            (root / "a.txt").write_text("old")
            other = WorkspaceFilesService(Path(base) / "state")
            other.revoke("demo")
            with self.assertRaises(WorkspaceFilesError):
                service.list_directory("demo", path="", offset=0, limit=10, query="")
            other.grant("demo", root=root, label="Demo")
            root.rename(root.with_name("old"))
            root.mkdir()
            (root / "a.txt").write_text("replacement must not be read")
            with self.assertRaises(WorkspaceFilesError):
                service.read_file("demo", path="a.txt", offset=0, limit=100)

    def test_file_pages_use_exact_bytes_and_refuse_stale_or_secret_chunks(self):
        from loopdy_plugin.workspace_files import WorkspaceFilesError
        with tempfile.TemporaryDirectory() as base:
            root, service = self.fixture(base)
            content = ("Long content with unicode café.\n" * 2500).encode()
            (root / "long.txt").write_bytes(content)
            first = service.read_file("demo", path="long.txt", offset=0, limit=65536)
            second = service.read_file("demo", path="long.txt", offset=65536, limit=65536, revision=first["revision"])
            actual = base64.b64decode(first["data"]) + base64.b64decode(second["data"])
            self.assertEqual(actual, content)
            self.assertIn(hashlib.sha256(content).hexdigest(), first["revision"])
            (root / "long.txt").write_bytes(content + b"changed")
            with self.assertRaises(WorkspaceFilesError):
                service.read_file("demo", path="long.txt", offset=65536, limit=65536, revision=first["revision"])
            (root / "later-secret.txt").write_bytes(b"a" * 65530 + b"\npassword=" + b"synthetic" * 4)
            with self.assertRaises(WorkspaceFilesError):
                service.read_file("demo", path="later-secret.txt", offset=0, limit=32)
            (root / "large.bin").write_bytes(b"a" * (8 * 1024 * 1024 + 1))
            large = service.read_file("demo", path="large.bin", offset=0, limit=65536)
            self.assertEqual(large["availability"], "oversized")
            self.assertFalse(large.get("data"))
            (root / "binary.bin").write_bytes(b"\x00\x01\xff\x02")
            binary = service.read_file("demo", path="binary.bin", offset=0, limit=65536)
            self.assertEqual(base64.b64decode(binary["data"]), b"\x00\x01\xff\x02")
            self.assertIsNone(binary.get("text"))

    def test_git_status_and_staged_worktree_diffs_are_read_only(self):
        from loopdy_plugin.workspace_files import WorkspaceFilesError
        with tempfile.TemporaryDirectory() as base:
            root, service = self.fixture(base)
            def git(*args):
                return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True,
                    env={**os.environ, "GIT_AUTHOR_NAME":"Fixture", "GIT_AUTHOR_EMAIL":"fixture@example.test",
                    "GIT_COMMITTER_NAME":"Fixture", "GIT_COMMITTER_EMAIL":"fixture@example.test"}).stdout
            git("init", "-b", "main")
            (root / "file.txt").write_text("one\n")
            git("add", "file.txt")
            git("commit", "-m", "initial")
            (root / "file.txt").write_text("one\nstaged\n")
            git("add", "file.txt")
            (root / "file.txt").write_text("one\nstaged\nworking\n")
            (root / "new.txt").write_text("new\n")
            before = git("status", "--porcelain")
            status = service.git_status("demo")
            self.assertEqual({f["path"] for f in status["files"]}, {"file.txt", "new.txt"})
            for side, marker in (("staged", "staged"), ("worktree", "working")):
                result = service.git_diff("demo", path="file.txt", side=side, expected_status_token=status["status_token"], offset=0, limit=300)
                self.assertTrue(any(row["content"] == marker for row in result["lines"]))
            self.assertEqual(before, git("status", "--porcelain"))
            with self.assertRaises(WorkspaceFilesError):
                service.git_diff("demo", path="../outside", side="worktree", expected_status_token=status["status_token"], offset=0, limit=300)


    def test_late_pages_and_revocation_during_a_read(self):
        from loopdy_plugin import workspace_files
        with tempfile.TemporaryDirectory() as base:
            root, service = self.fixture(base)
            content = b"ordinary line\n" * 100_000
            (root / "large.txt").write_bytes(content)
            revision = "sha256:" + hashlib.sha256(content).hexdigest()
            result = service.read_file("demo", path="large.txt", offset=1_100_000, limit=65536, revision=revision)
            self.assertEqual(base64.b64decode(result["data"]), content[1_100_000:1_165_536])
            read = workspace_files._read_descriptor
            def revoke_during_read(*args):
                result = read(*args)
                service.revoke("demo")
                service.grant("demo", root=root, label="Regranted")
                return result
            with patch.object(workspace_files, "_read_descriptor", side_effect=revoke_during_read):
                with self.assertRaises(workspace_files.WorkspaceFilesError) as caught:
                    service.read_file("demo", path="large.txt")
                self.assertEqual(caught.exception.code, "WORKSPACE_NOT_ALLOWED")

    def test_git_checks_all_hunks_once_and_refuses_incomplete_status(self):
        from loopdy_plugin.workspace_files import WorkspaceFilesError
        from loopdy_plugin.workspace_git import WorkspaceGitService
        with tempfile.TemporaryDirectory() as base:
            root, service = self.fixture(base)
            subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, capture_output=True)
            content = "ordinary line\n" * 1200
            (root / "new.txt").write_text(content)
            status = service.git_status("demo")
            original = WorkspaceGitService.diff
            calls = []
            def observe(instance, *args, **kwargs):
                calls.append(kwargs)
                return original(instance, *args, **kwargs)
            with patch.object(WorkspaceGitService, "diff", new=observe):
                result = service.git_diff("demo", path="new.txt", side="worktree", expected_status_token=status["status_token"], limit=10)
            self.assertEqual(len(calls), 1)
            self.assertEqual(result["next_offset"], 10)
            (root / "new.txt").write_text(content + "password=" + "synthetic" * 5)
            status = service.git_status("demo")
            with self.assertRaises(WorkspaceFilesError) as caught:
                service.git_diff("demo", path="new.txt", side="worktree", expected_status_token=status["status_token"], limit=10)
            self.assertEqual(caught.exception.code, "SECRET_SCAN_BLOCKED")
            for index in range(501):
                (root / f"file-{index}.txt").write_text("ordinary\n")
            with self.assertRaises(WorkspaceFilesError) as caught:
                service.git_status("demo")
            self.assertEqual(caught.exception.code, "GIT_STATUS_OVERSIZED")


    def test_diff_supports_deleted_nested_files_and_refuses_protected_renames(self):
        from loopdy_plugin.workspace_files import WorkspaceFilesError
        with tempfile.TemporaryDirectory() as base:
            root, service = self.fixture(base)
            env = {**os.environ, "GIT_AUTHOR_NAME":"Fixture", "GIT_AUTHOR_EMAIL":"fixture@example.test",
                   "GIT_COMMITTER_NAME":"Fixture", "GIT_COMMITTER_EMAIL":"fixture@example.test"}
            def git(*args):
                return subprocess.run(["git", *args], cwd=root, env=env, check=True, capture_output=True)
            git("init", "-b", "main")
            (root / "nested").mkdir()
            (root / "nested/gone.txt").write_text("previous content\n")
            (root / ".env").write_text("host-only configuration\n" * 30)
            git("add", "--", "nested/gone.txt", ".env")
            git("commit", "-m", "fixture")
            (root / "nested/gone.txt").unlink()
            (root / "nested").rmdir()
            status = service.git_status("demo")
            diff = service.git_diff("demo", path="nested/gone.txt", side="worktree", expected_status_token=status["status_token"])
            self.assertTrue(any(row["kind"] == "deletion" for row in diff["lines"]))
            git("mv", ".env", "looks-safe.txt")
            status = service.git_status("demo")
            with self.assertRaises(WorkspaceFilesError):
                service.git_diff("demo", path="looks-safe.txt", side="staged", expected_status_token=status["status_token"])


if __name__ == "__main__":
    unittest.main()
