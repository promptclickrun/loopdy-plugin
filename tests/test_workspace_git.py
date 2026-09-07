from __future__ import annotations

import gc
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from loopdy_plugin import workspace_git
from loopdy_plugin.workspace_git import WorkspaceGitError, WorkspaceGitService


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "Loopdy Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.test", "GIT_COMMITTER_NAME": "Loopdy Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.test"},
    )
    return result.stdout.strip()


class WorkspaceGitTests(unittest.TestCase):
    def test_text_preview_crosses_real_backend_with_canonical_field(self) -> None:
        import asyncio
        from loopdy_plugin.workspace_control import HermesWorkspaceBackend

        for suffix in ("md", "markdown", "txt"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                root, service = self.make_repo(directory, visibility="private")
                path = f"preview.{suffix}"
                content = "# Full file\n\n" + "Unchanged context\n" * 15 + "Final marker\n"
                (root / path).write_text(content, encoding="utf-8")
                git(root, "add", "--", path)
                git(root, "commit", "-m", "preview baseline")
                staged = content.replace("Full file", "Staged file")
                worktree = content.replace("Full file", "Worktree file")
                (root / path).write_text(staged, encoding="utf-8")
                git(root, "add", "--", path)
                (root / path).write_text(worktree, encoding="utf-8")

                class Backend(HermesWorkspaceBackend):
                    async def _projects_catalog(self, agent_id):
                        return {"active_id": "fixture", "projects": [{
                            "id": "fixture", "name": "Fixture", "archived": False,
                            "primary_path": str(root),
                            "folders": [{"path": str(root), "is_primary": True}],
                        }]}

                backend = Backend(service=object(), workspace_git=service,
                    session_workspace_getter=lambda _agent, _session: str(root))
                token = service.status("fixture")["status_token"]
                for side, expected in (("staged", staged), ("worktree", worktree)):
                    page = asyncio.run(backend.projects_git_diff({
                        "agentId": "default", "sessionId": "session_preview_0001",
                        "workspaceId": "fixture", "path": path, "side": side,
                        "statusToken": token, "offset": 0, "limit": 200,
                    }))
                    self.assertEqual(page.get("previewContent"), expected)
                    self.assertNotIn("preview_content", page)
                    self.assertEqual(page["availability"], "available")
                    self.assertFalse(any(row["content"] == "Final marker" for row in page["lines"]))

    def test_text_preview_omits_binary_and_control_content(self) -> None:
        from loopdy_plugin.workspace_control import _project_git_wire
        for data in (b"before\x00after", b"before\x1bafter", "before\u0085after".encode()):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as directory:
                root, service = self.make_repo(directory)
                (root / "unsafe.md").write_bytes(data)
                page = service.diff("fixture", path="unsafe.md", side="worktree",
                    expected_status_token=service.status("fixture")["status_token"], offset=0, limit=200)
                self.assertNotIn("preview_content", page)
                self.assertNotIn("previewContent", _project_git_wire(page))

    def test_diff_marks_unsafe_control_text_unavailable_instead_of_failing_native_decode(self) -> None:
        for text in ("before\u007fafter", "before\u0080after"):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as directory:
                root, service = self.make_repo(directory)
                (root / "controls.txt").write_text(text, encoding="utf-8")
                page = service.diff("fixture", path="controls.txt", side="worktree",
                    expected_status_token=service.status("fixture")["status_token"], offset=0, limit=200)
                self.assertEqual(page["availability"], "binary")
                self.assertEqual(page["lines"], [])
                self.assertNotIn("preview_content", page)

    def test_text_preview_keeps_large_diff_pages_inside_wire_budget(self) -> None:
        from loopdy_plugin.workspace_control import _project_git_wire
        from loopdy_plugin.link_contracts import _workspace_json
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            path = "large.md"
            (root / path).write_text(("old" * 3000 + "\n") * 15, encoding="utf-8")
            git(root, "add", "--", path)
            git(root, "commit", "-m", "large previous content")
            content = ("new" * 3000 + "\n") * 7
            (root / path).write_text(content, encoding="utf-8")
            token = service.status("fixture")["status_token"]
            offset = 0
            rows = []
            while True:
                page = service.diff("fixture", path=path, side="worktree",
                    expected_status_token=token, offset=offset, limit=200)
                if offset == 0:
                    self.assertEqual(page.get("preview_content"), content)
                wire = _project_git_wire(page)
                _workspace_json(wire, depth=0)
                self.assertLessEqual(len(json.dumps(wire).encode("utf-8")), 160_000)
                rows.extend(wire["lines"])
                following = wire["nextOffset"]
                if following is None:
                    break
                self.assertGreater(following, offset)
                self.assertEqual(following, offset + len(wire["lines"]))
                offset = following
            additions = [row["content"] for row in rows if row["kind"] == "addition"]
            deletions = [row["content"] for row in rows if row["kind"] == "deletion"]
            self.assertEqual(additions, content.splitlines())
            self.assertEqual(len(deletions), 15)

    def make_repo(self, directory: str, *, visibility: str = "public") -> tuple[Path, WorkspaceGitService]:
        root = Path(directory) / "repo"
        root.mkdir()
        git(root, "init", "-b", "main")
        # Production intentionally ignores global Git config and author env.
        # Give each disposable repository its own synthetic commit identity.
        git(root, "config", "user.name", "Loopdy Fixture")
        git(root, "config", "user.email", "fixture@example.test")
        (root / "tracked.txt").write_text("one\n", encoding="utf-8")
        git(root, "add", "--", "tracked.txt")
        git(root, "commit", "-m", "initial")
        service = WorkspaceGitService(
            [
                {
                    "workspace_id": "fixture",
                    "label": "Fixture",
                    "root": str(root),
                    "visibility": visibility,
                    "operations": ["status", "stage", "commit", "push", "fetch", "pull"],
                    "remotes": ["origin"],
                    "branches": ["main"],
                    "mutations_enabled": True,
                }
            ],
            state_path=Path(directory) / "workspace-git.sqlite3",
        )
        return root, service

    def prepare(self, service: WorkspaceGitService, operation: str, input_: dict, status_token: str) -> dict:
        return service.prepare(
            workspace_id="fixture",
            operation=operation,
            input_=input_,
            expected_status_token=status_token,
            connection_id="test-connection",
        )

    def test_status_is_porcelain_safe_and_summarizes_large_untracked_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            (root / "tracked.txt").write_text("one\ntwo\n", encoding="utf-8")
            (root / "new file.txt").write_text("alpha\nbeta\n", encoding="utf-8")

            status = service.status("fixture")

            self.assertEqual(status["head"]["branch"], "main")
            self.assertIsNone(status["head"]["upstream"])
            self.assertEqual(status["changes"], {"files": 2, "insertions": 3, "deletions": 0})
            self.assertEqual({item["path"] for item in status["files"]}, {"tracked.txt", "new file.txt"})
            self.assertTrue(status["status_token"].startswith("sha256:"))
            self.assertNotIn(str(root), repr(status))

    @unittest.skipUnless(sys.platform == "darwin", "macOS filesystem path behavior")
    def test_service_accepts_case_variant_path_to_git_worktree_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            git(root, "init", "-b", "main")
            variant = root.with_name("REPO")
            if not variant.exists() or not variant.samefile(root):
                self.skipTest("case-sensitive filesystem")

            service = WorkspaceGitService(
                [{
                    "workspace_id": "fixture",
                    "label": "Fixture",
                    "root": str(variant),
                    "visibility": "private",
                    "operations": ["status"],
                    "remotes": [],
                    "branches": [],
                    "mutations_enabled": False,
                }],
                state_path=Path(directory) / "workspace-git.sqlite3",
            )

            status = service.status("fixture")

        self.assertEqual(status["head"]["branch"], "main")

    def test_status_bounds_large_file_lists_and_marks_the_page_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            for index in range(2_000):
                (root / f"untracked-{index:04d}.txt").write_text("line\n", encoding="utf-8")

            status = service.status("fixture")

            self.assertEqual(status["changes"]["files"], 2_000)
            self.assertEqual(status["files_page"]["total"], 2_000)
            self.assertEqual(status["files_page"]["returned"], len(status["files"]))
            self.assertFalse(status["files_page"]["complete"])
            self.assertEqual(status["files_page"]["next_offset"], len(status["files"]))
            self.assertLessEqual(len(json.dumps(status).encode("utf-8")), 160_000)

    def test_status_changes_include_staged_only_totals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            (root / "tracked.txt").write_text("staged replacement\n", encoding="utf-8")
            git(root, "add", "--", "tracked.txt")

            status = service.status("fixture")

            self.assertEqual(status["changes"], {"files": 1, "insertions": 1, "deletions": 1})
            self.assertEqual(status["files"][0]["insertions"], 1)
            self.assertEqual(status["files"][0]["deletions"], 1)

    def test_service_closes_ledger_connections(self) -> None:
        with tempfile.TemporaryDirectory() as directory, warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            root, service = self.make_repo(directory)
            (root / "tracked.txt").write_text("staged\n", encoding="utf-8")
            before = service.status("fixture")
            prepared = self.prepare(
                service,
                "stage",
                {"mode": "stage", "paths": ["tracked.txt"]},
                before["status_token"],
            )
            service.execute(
                "stage",
                {
                    "workspace_id": "fixture",
                    "mode": "stage",
                    "paths": ["tracked.txt"],
                    "expected_status_token": before["status_token"],
                    "confirmation_token": prepared["confirmation_token"],
                    "idempotency_key": "abababab-abab-4bab-8bab-abababababab",
                },
                connection_id="test-connection",
            )
            del service
            gc.collect()

        leaked = [item for item in caught if "unclosed database" in str(item.message)]
        self.assertEqual(leaked, [])

    def test_status_and_diff_project_structured_tracked_and_untracked_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            (root / "tracked.txt").write_text("context\nold\n", encoding="utf-8")
            git(root, "add", "--", "tracked.txt")
            git(root, "commit", "-m", "add diff context")
            (root / "tracked.txt").write_text("context\nnew\n", encoding="utf-8")
            (root / "z-untracked.txt").write_text("alpha\nbeta\n", encoding="utf-8")

            status = service.status("fixture")
            page = service.diff(
                "fixture",
                path="tracked.txt",
                side="worktree",
                expected_status_token=status["status_token"],
                offset=0,
                limit=200,
            )

            self.assertEqual(page["path"], "tracked.txt")
            self.assertEqual(page["side"], "worktree")
            self.assertEqual(page["availability"], "available")
            self.assertEqual(
                [line["kind"] for line in page["lines"]],
                ["header", "context", "deletion", "addition"],
            )
            self.assertEqual(
                [(line["old_line"], line["new_line"]) for line in page["lines"]],
                [(None, None), (1, 1), (2, None), (None, 2)],
            )
            self.assertIsNone(page["next_offset"])
            self.assertGreaterEqual(status["files"][0]["insertions"], 1)
            self.assertGreaterEqual(status["files"][0]["deletions"], 1)
            self.assertFalse(status["files"][0]["is_binary"])

            untracked = service.diff(
                "fixture",
                path="z-untracked.txt",
                side="worktree",
                expected_status_token=status["status_token"],
                offset=0,
                limit=200,
            )
            self.assertEqual([line["kind"] for line in untracked["lines"]], ["addition", "addition"])
            self.assertEqual([line["content"] for line in untracked["lines"]], ["alpha", "beta"])
            self.assertEqual([line["new_line"] for line in untracked["lines"]], [1, 2])

    def test_diff_keeps_staged_and_worktree_sides_distinct_and_pages_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            (root / "tracked.txt").write_text("staged\n", encoding="utf-8")
            git(root, "add", "--", "tracked.txt")
            (root / "tracked.txt").write_text("worktree\n", encoding="utf-8")
            status = service.status("fixture")

            staged = service.diff(
                "fixture",
                path="tracked.txt",
                side="staged",
                expected_status_token=status["status_token"],
                offset=0,
                limit=2,
            )
            worktree = service.diff(
                "fixture",
                path="tracked.txt",
                side="worktree",
                expected_status_token=status["status_token"],
                offset=0,
                limit=20,
            )

            self.assertEqual(staged["next_offset"], 2)
            self.assertNotIn("worktree", [line["content"] for line in staged["lines"]])
            self.assertIn("worktree", [line["content"] for line in worktree["lines"]])
            remainder = service.diff(
                "fixture",
                path="tracked.txt",
                side="staged",
                expected_status_token=status["status_token"],
                offset=staged["next_offset"],
                limit=20,
            )
            self.assertIsNone(remainder["next_offset"])
            self.assertEqual(len(staged["lines"]) + len(remainder["lines"]), 3)

    def test_diff_rejects_stale_unsafe_and_invalid_requests_and_marks_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            (root / "tracked.txt").write_text("changed\n", encoding="utf-8")
            old = service.status("fixture")["status_token"]
            (root / "second.txt").write_text("state changed\n", encoding="utf-8")
            status = service.status("fixture")

            with self.assertRaisesRegex(WorkspaceGitError, "STATUS_STALE"):
                service.diff(
                    "fixture",
                    path="tracked.txt",
                    side="worktree",
                    expected_status_token=old,
                    offset=0,
                    limit=100,
                )
            with self.assertRaisesRegex(WorkspaceGitError, "INVALID_PATH"):
                service.diff(
                    "fixture",
                    path="../outside",
                    side="worktree",
                    expected_status_token=status["status_token"],
                    offset=0,
                    limit=100,
                )
            for side, offset, limit in (("head", 0, 100), ("worktree", -1, 100), ("worktree", 0, 501)):
                with self.subTest(side=side, offset=offset, limit=limit):
                    with self.assertRaisesRegex(WorkspaceGitError, "INVALID_REQUEST"):
                        service.diff(
                            "fixture",
                            path="tracked.txt",
                            side=side,
                            expected_status_token=status["status_token"],
                            offset=offset,
                            limit=limit,
                        )

            outside = Path(directory) / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            (root / "unsafe-link.txt").symlink_to(outside)
            linked_status = service.status("fixture")
            with self.assertRaisesRegex(WorkspaceGitError, "INVALID_PATH"):
                service.diff(
                    "fixture",
                    path="unsafe-link.txt",
                    side="worktree",
                    expected_status_token=linked_status["status_token"],
                    offset=0,
                    limit=100,
                )

            (root / "binary.dat").write_bytes(b"safe-prefix\0safe-suffix")
            binary_status = service.status("fixture")
            binary_page = service.diff(
                "fixture",
                path="binary.dat",
                side="worktree",
                expected_status_token=binary_status["status_token"],
                offset=0,
                limit=100,
            )
            binary_row = next(item for item in binary_status["files"] if item["path"] == "binary.dat")
            self.assertTrue(binary_row["is_binary"])
            self.assertEqual(binary_page["availability"], "binary")
            self.assertEqual(binary_page["lines"], [])

    def test_diff_response_is_bounded_and_reports_the_next_offset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            content = "".join(f"{index:04d} " + ("x" * 1_000) + "\n" for index in range(300))
            (root / "large.txt").write_text(content, encoding="utf-8")
            status = service.status("fixture")

            page = service.diff(
                "fixture",
                path="large.txt",
                side="worktree",
                expected_status_token=status["status_token"],
                offset=0,
                limit=500,
            )

            self.assertEqual(page["availability"], "available")
            self.assertIsNotNone(page["next_offset"])
            self.assertLessEqual(len(json.dumps(page).encode("utf-8")), 160_000)

    def test_diff_includes_complete_markdown_content_for_rendered_preview(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            markdown = "# Build notes\n\nRendered **Markdown** preview.\n"
            (root / "README.md").write_text(markdown, encoding="utf-8")
            status = service.status("fixture")

            page = service.diff(
                "fixture",
                path="README.md",
                side="worktree",
                expected_status_token=status["status_token"],
                offset=0,
                limit=100,
            )

            self.assertEqual(page["preview_content"], markdown)

    def test_diff_rechecks_status_after_a_tracked_file_changes_during_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            (root / "tracked.txt").write_text("reviewed\n", encoding="utf-8")
            status = service.status("fixture")
            structured_diff_page = service._structured_diff_page

            def substitute_before_projection(*args, **kwargs):
                (root / "tracked.txt").write_text("substituted\n", encoding="utf-8")
                return structured_diff_page(*args, **kwargs)

            with patch.object(service, "_structured_diff_page", side_effect=substitute_before_projection):
                with self.assertRaisesRegex(WorkspaceGitError, "STATUS_STALE"):
                    service.diff(
                        "fixture",
                        path="tracked.txt",
                        side="worktree",
                        expected_status_token=status["status_token"],
                        offset=0,
                        limit=100,
                    )

    def test_diff_rejects_a_tracked_path_swapped_to_a_symlink_and_restored_before_recheck(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            selected = root.resolve() / "tracked.txt"
            selected.write_text("reviewed replacement\n", encoding="utf-8")
            reviewed_bytes = selected.read_bytes()
            reviewed_stat = selected.stat()
            outside = Path(directory).resolve() / "external.txt"
            outside.write_text("external secret\n", encoding="utf-8")
            status = service.status("fixture")
            git_bounded = service._git_bounded

            def project_swapped_path(*args, **kwargs):
                selected.unlink()
                selected.symlink_to(outside)
                try:
                    return git_bounded(*args, **kwargs)
                finally:
                    selected.unlink()
                    selected.write_bytes(reviewed_bytes)
                    os.chmod(selected, reviewed_stat.st_mode)
                    os.utime(selected, ns=(reviewed_stat.st_atime_ns, reviewed_stat.st_mtime_ns))

            with patch.object(service, "_git_bounded", side_effect=project_swapped_path):
                with self.assertRaisesRegex(WorkspaceGitError, "STATUS_STALE"):
                    service.diff(
                        "fixture",
                        path="tracked.txt",
                        side="worktree",
                        expected_status_token=status["status_token"],
                        offset=0,
                        limit=100,
                    )

    def test_diff_never_follows_an_untracked_file_swapped_to_an_external_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            selected = root.resolve() / "untracked.txt"
            selected.write_text("inside\n", encoding="utf-8")
            outside = Path(directory) / "outside.txt"
            outside.write_text("external secret\n", encoding="utf-8")
            status = service.status("fixture")
            original_is_symlink = Path.is_symlink
            original_open = os.open
            selected_checks = 0
            selected_opens = 0
            attack_triggered = False

            def swap_after_status(candidate: Path) -> bool:
                nonlocal attack_triggered, selected_checks
                if candidate == selected:
                    selected_checks += 1
                    if selected_checks == 3:
                        selected.unlink()
                        selected.symlink_to(outside)
                        attack_triggered = True
                        return False
                return original_is_symlink(candidate)

            def swap_before_descriptor_open(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal attack_triggered, selected_opens
                if path == "untracked.txt" and dir_fd is not None:
                    selected_opens += 1
                    if selected_opens == 3 and not selected.is_symlink():
                        selected.unlink()
                        selected.symlink_to(outside)
                        attack_triggered = True
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with (
                patch.object(type(selected), "is_symlink", autospec=True, side_effect=swap_after_status),
                patch.object(workspace_git.os, "open", side_effect=swap_before_descriptor_open),
            ):
                try:
                    page = service.diff(
                        "fixture",
                        path="untracked.txt",
                        side="worktree",
                        expected_status_token=status["status_token"],
                        offset=0,
                        limit=100,
                    )
                except WorkspaceGitError as error:
                    self.assertIn(error.code, {"INVALID_PATH", "STATUS_STALE"})
                else:
                    self.assertNotIn("external secret", [line["content"] for line in page["lines"]])
            self.assertTrue(attack_triggered, "symlink swap probe did not reach a vulnerable read boundary")

    def test_diff_reports_a_tracked_projection_over_capture_limit_as_oversized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            (root / "tracked.txt").write_text("x" * 4_100_000 + "\n", encoding="utf-8")
            status = service.status("fixture")

            page = service.diff(
                "fixture",
                path="tracked.txt",
                side="worktree",
                expected_status_token=status["status_token"],
                offset=0,
                limit=100,
            )

            self.assertEqual(page["availability"], "oversized")
            self.assertEqual(page["lines"], [])
            self.assertIsNone(page["next_offset"])

    def test_diff_supports_exact_status_paths_and_deleted_nested_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            paths = [" leading and trailing.txt ", "-leading-dash.txt"]
            for path in paths:
                (root / path).write_text("before\n", encoding="utf-8")
            nested = root / "deleted" / "nested.txt"
            nested.parent.mkdir()
            nested.write_text("deleted\n", encoding="utf-8")
            (root / "rename-source.txt").write_text("rename\n", encoding="utf-8")
            git(root, "add", "--", *paths, "deleted/nested.txt", "rename-source.txt")
            git(root, "commit", "-m", "add unusual paths")
            for path in paths:
                (root / path).write_text("after\n", encoding="utf-8")
            nested.unlink()
            nested.parent.rmdir()
            git(root, "mv", "--", "rename-source.txt", "rename-target.txt")
            status = service.status("fixture")

            for path in [*paths, "deleted/nested.txt"]:
                with self.subTest(path=path):
                    page = service.diff(
                        "fixture",
                        path=path,
                        side="worktree",
                        expected_status_token=status["status_token"],
                        offset=0,
                        limit=100,
                    )
                    self.assertEqual(page["path"], path)
                    self.assertEqual(page["availability"], "available")

            renamed = service.diff(
                "fixture",
                path="rename-target.txt",
                side="staged",
                expected_status_token=status["status_token"],
                offset=0,
                limit=100,
            )
            rename_row = next(item for item in status["files"] if item["path"] == "rename-target.txt")
            self.assertEqual(rename_row["original_path"], "rename-source.txt")
            self.assertEqual(renamed["availability"], "available")

    def test_diff_marks_an_oversized_hunk_header_instead_of_stalling_pagination(self) -> None:
        raw = b"@@ -1 +1 @@ " + (b"x" * 170_000) + b"\n-old\n+new\n\\ No newline at end of file\n"

        availability, rows = workspace_git._parse_unified_diff(raw)
        page = workspace_git._diff_page("tracked.txt", "worktree", availability, rows, 0, 100)

        self.assertEqual(page["availability"], "oversized")
        self.assertEqual(page["lines"], [])
        self.assertIsNone(page["next_offset"])

    def test_stage_is_path_selective_confirmed_idempotent_and_can_unstage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            (root / "tracked.txt").write_text("changed\n", encoding="utf-8")
            (root / "other.txt").write_text("other\n", encoding="utf-8")
            before = service.status("fixture")
            prepared = self.prepare(service, "stage", {"mode": "stage", "paths": ["tracked.txt"]}, before["status_token"])
            request = {
                "workspace_id": "fixture",
                "mode": "stage",
                "paths": ["tracked.txt"],
                "expected_status_token": before["status_token"],
                "confirmation_token": prepared["confirmation_token"],
                "idempotency_key": "11111111-1111-4111-8111-111111111111",
            }

            result = service.execute("stage", request, connection_id="test-connection")
            replay = service.execute("stage", request, connection_id="test-connection")

            self.assertEqual(result, replay)
            by_path = {item["path"]: item for item in result["status"]["files"]}
            self.assertNotEqual(by_path["tracked.txt"]["index"], ".")
            self.assertEqual(by_path["other.txt"]["index"], "?")

            prepared_unstage = self.prepare(
                service,
                "stage",
                {"mode": "unstage", "paths": ["tracked.txt"]},
                result["status"]["status_token"],
            )
            unstaged = service.execute(
                "stage",
                {
                    "workspace_id": "fixture",
                    "mode": "unstage",
                    "paths": ["tracked.txt"],
                    "expected_status_token": result["status"]["status_token"],
                    "confirmation_token": prepared_unstage["confirmation_token"],
                    "idempotency_key": "22222222-2222-4222-8222-222222222222",
                },
                connection_id="test-connection",
            )
            self.assertEqual({item["path"]: item for item in unstaged["status"]["files"]}["tracked.txt"]["index"], ".")

    def test_stage_confirmation_binds_the_reviewed_worktree_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            (root / "tracked.txt").write_text("reviewed A\n", encoding="utf-8")
            status = service.status("fixture")
            prepared = self.prepare(
                service,
                "stage",
                {"mode": "stage", "paths": ["tracked.txt"]},
                status["status_token"],
            )
            (root / "tracked.txt").write_text("substituted B\n", encoding="utf-8")

            with self.assertRaisesRegex(WorkspaceGitError, "STATUS_STALE"):
                service.execute(
                    "stage",
                    {
                        "workspace_id": "fixture",
                        "mode": "stage",
                        "paths": ["tracked.txt"],
                        "expected_status_token": status["status_token"],
                        "confirmation_token": prepared["confirmation_token"],
                        "idempotency_key": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    },
                    connection_id="test-connection",
                )

    def test_rejects_path_escape_stale_confirmation_and_conflicting_idempotency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            (root / "tracked.txt").write_text("changed\n", encoding="utf-8")
            status = service.status("fixture")
            with self.assertRaisesRegex(WorkspaceGitError, "INVALID_PATH"):
                self.prepare(service, "stage", {"mode": "stage", "paths": ["../outside"]}, status["status_token"])

            prepared = self.prepare(service, "stage", {"mode": "stage", "paths": ["tracked.txt"]}, status["status_token"])
            (root / "second.txt").write_text("state changed\n", encoding="utf-8")
            with self.assertRaisesRegex(WorkspaceGitError, "STATUS_STALE"):
                service.execute(
                    "stage",
                    {
                        "workspace_id": "fixture",
                        "mode": "stage",
                        "paths": ["tracked.txt"],
                        "expected_status_token": status["status_token"],
                        "confirmation_token": prepared["confirmation_token"],
                        "idempotency_key": "33333333-3333-4333-8333-333333333333",
                    },
                    connection_id="test-connection",
                )

    def test_public_commit_blocks_secret_like_staged_content_and_detached_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            (root / ".env.production").write_text("TOKEN=" + "fixture-secret\n", encoding="utf-8")
            git(root, "add", "--", ".env.production")
            status = service.status("fixture")
            with self.assertRaisesRegex(WorkspaceGitError, "SECRET_SCAN_BLOCKED"):
                self.prepare(service, "commit", {"message": "Add config"}, status["status_token"])

            git(root, "reset", "--", ".env.production")
            (root / "tracked.txt").write_text("safe\n", encoding="utf-8")
            git(root, "add", "--", "tracked.txt")
            git(root, "checkout", "--detach")
            status = service.status("fixture")
            with self.assertRaisesRegex(WorkspaceGitError, "BRANCH_MISMATCH"):
                self.prepare(service, "commit", {"message": "Safe change"}, status["status_token"])

    def test_public_commit_blocks_common_standalone_provider_tokens_and_jwts(self) -> None:
        fixtures = {
            "github-pat.txt": "github_" + "pat_11AA22BB33CC44DD55EE66FF77GG88HH99II00JJ",
            "github-classic.txt": "gh" + "p_0123456789abcdefghijklmnopqrstuvwxyz",
            "aws.txt": "AKIA" + "IOSFODNN7EXAMPLE",
            "jwt.txt": "eyJhbGciOiJIUzI1NiJ9."
            + "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            + "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "slack.txt": "xox" + "b-123456789012-123456789012-abcdefghijklmnopqrstuvwx",
        }
        for filename, token in fixtures.items():
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root, service = self.make_repo(directory)
                (root / filename).write_text(f"{token}\n", encoding="utf-8")
                git(root, "add", "--", filename)
                status = service.status("fixture")
                with self.assertRaisesRegex(WorkspaceGitError, "SECRET_SCAN_BLOCKED"):
                    self.prepare(service, "commit", {"message": "Unsafe fixture"}, status["status_token"])

    def test_commit_reads_back_effect_and_commit_and_push_can_stop_before_push(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory, visibility="private")
            (root / "tracked.txt").write_text("committed\n", encoding="utf-8")
            git(root, "add", "--", "tracked.txt")
            status = service.status("fixture")
            prepared = self.prepare(service, "commit", {"message": "Update tracked fixture"}, status["status_token"])
            result = service.execute(
                "commit",
                {
                    "workspace_id": "fixture",
                    "message": "Update tracked fixture",
                    "expected_status_token": status["status_token"],
                    "confirmation_token": prepared["confirmation_token"],
                    "idempotency_key": "44444444-4444-4444-8444-444444444444",
                },
                connection_id="test-connection",
            )
            self.assertEqual(result["result"]["commit_oid"], git(root, "rev-parse", "HEAD"))
            self.assertEqual(result["result"]["subject"], "Update tracked fixture")
            self.assertEqual(result["status"]["staged"]["files"], 0)

    def test_commit_message_file_falls_back_when_descriptor_chmod_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory, visibility="private")
            (root / "tracked.txt").write_text("portable commit\n", encoding="utf-8")
            git(root, "add", "--", "tracked.txt")
            status = service.status("fixture")
            prepared = self.prepare(
                service,
                "commit",
                {"message": "Portable commit"},
                status["status_token"],
            )

            with patch.object(
                os,
                "fchmod",
                side_effect=AttributeError("fchmod is unavailable"),
                create=True,
            ):
                result = service.execute(
                    "commit",
                    {
                        "workspace_id": "fixture",
                        "message": "Portable commit",
                        "expected_status_token": status["status_token"],
                        "confirmation_token": prepared["confirmation_token"],
                        "idempotency_key": "45454545-4545-4545-8545-454545454545",
                    },
                    connection_id="test-connection",
                )

            self.assertEqual(result["result"]["subject"], "Portable commit")

    def test_commit_never_executes_repository_commit_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory, visibility="private")
            markers = Path(directory) / "markers"
            hooks = root / ".git" / "hooks"
            hooks.mkdir(parents=True, exist_ok=True)
            for hook in ("pre-commit", "commit-msg", "post-commit"):
                path = hooks / hook
                path.write_text(
                    f"#!/bin/sh\nmkdir -p '{markers}'\ntouch '{markers / hook}'\n",
                    encoding="utf-8",
                )
                path.chmod(0o755)
            (root / "tracked.txt").write_text("safe commit\n", encoding="utf-8")
            git(root, "add", "--", "tracked.txt")
            status = service.status("fixture")
            prepared = self.prepare(service, "commit", {"message": "Safe service commit"}, status["status_token"])

            result = service.execute(
                "commit",
                {
                    "workspace_id": "fixture",
                    "message": "Safe service commit",
                    "expected_status_token": status["status_token"],
                    "confirmation_token": prepared["confirmation_token"],
                    "idempotency_key": "99999999-9999-4999-8999-999999999999",
                },
                connection_id="test-connection",
            )

            self.assertEqual(result["result"]["subject"], "Safe service commit")
            self.assertFalse(markers.exists(), "service-owned commit executed a repository hook")

    def test_stage_neutralizes_configured_filters_textconv_aliases_pagers_and_editors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory, visibility="private")
            marker = Path(directory) / "external-program-fired"
            program = Path(directory) / "external-program"
            program.write_text(f"#!/bin/sh\ntouch '{marker}'\ncat\n", encoding="utf-8")
            program.chmod(0o755)
            for key in ("filter.evil.clean", "filter.evil.smudge", "filter.evil.process"):
                git(root, "config", key, str(program))
            git(root, "config", "filter.evil.required", "true")
            git(root, "config", "diff.evil.textconv", str(program))
            git(root, "config", "credential.helper", f"!{program}")
            git(root, "config", "alias.status", f"!{program}")
            git(root, "config", "core.pager", str(program))
            git(root, "config", "core.editor", str(program))
            (root / ".gitattributes").write_text("tracked.txt filter=evil diff=evil\n", encoding="utf-8")
            (root / "tracked.txt").write_text("safe filtered bytes\n", encoding="utf-8")

            before = service.status("fixture")
            prepared = self.prepare(
                service,
                "stage",
                {"mode": "stage", "paths": ["tracked.txt", ".gitattributes"]},
                before["status_token"],
            )
            result = service.execute(
                "stage",
                {
                    "workspace_id": "fixture",
                    "mode": "stage",
                    "paths": ["tracked.txt", ".gitattributes"],
                    "expected_status_token": before["status_token"],
                    "confirmation_token": prepared["confirmation_token"],
                    "idempotency_key": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                },
                connection_id="test-connection",
            )

            self.assertEqual(result["result"]["paths"], ["tracked.txt", ".gitattributes"])
            self.assertFalse(marker.exists(), "service-owned stage executed a configured helper")

    def test_push_and_pull_require_upstream_and_fetch_does_not_mutate_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory)
            status = service.status("fixture")
            for operation, input_ in (("push", {"remote": "origin", "branch": "main"}), ("pull", {"remote": "origin", "branch": "main", "strategy": "ff-only"})):
                with self.assertRaisesRegex(WorkspaceGitError, "UPSTREAM_REQUIRED"):
                    self.prepare(service, operation, input_, status["status_token"])

            bare = Path(directory) / "remote.git"
            git(Path(directory), "init", "--bare", "-b", "main", str(bare))
            git(root, "remote", "add", "origin", str(bare))
            git(root, "push", "-u", "origin", "main")
            (root / "tracked.txt").write_text("dirty but preserved\n", encoding="utf-8")
            before_bytes = (root / "tracked.txt").read_bytes()
            before = service.status("fixture")
            prepared = self.prepare(service, "fetch", {"remote": "origin"}, before["status_token"])
            result = service.execute(
                "fetch",
                {
                    "workspace_id": "fixture",
                    "remote": "origin",
                    "expected_status_token": before["status_token"],
                    "confirmation_token": prepared["confirmation_token"],
                    "idempotency_key": "55555555-5555-4555-8555-555555555555",
                },
                connection_id="test-connection",
            )
            self.assertEqual((root / "tracked.txt").read_bytes(), before_bytes)
            self.assertEqual(result["operation"], "fetch")

    def test_pull_fast_forwards_after_fetch_and_reads_back_a_clean_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory, visibility="private")
            bare = Path(directory) / "remote.git"
            git(Path(directory), "init", "--bare", "-b", "main", str(bare))
            git(root, "remote", "add", "origin", str(bare))
            git(root, "push", "-u", "origin", "main")
            peer = Path(directory) / "peer"
            git(Path(directory), "clone", str(bare), str(peer))
            (peer / "remote.txt").write_text("remote\n", encoding="utf-8")
            git(peer, "add", "--", "remote.txt")
            git(peer, "commit", "-m", "remote update")
            git(peer, "push", "origin", "main")

            post_merge_marker = Path(directory) / "post-merge-fired"
            post_merge = root / ".git" / "hooks" / "post-merge"
            post_merge.write_text(f"#!/bin/sh\ntouch '{post_merge_marker}'\n", encoding="utf-8")
            post_merge.chmod(0o755)
            fetch_status = service.status("fixture")
            fetch_prepare = self.prepare(service, "fetch", {"remote": "origin"}, fetch_status["status_token"])
            fetched = service.execute(
                "fetch",
                {
                    "workspace_id": "fixture",
                    "remote": "origin",
                    "expected_status_token": fetch_status["status_token"],
                    "confirmation_token": fetch_prepare["confirmation_token"],
                    "idempotency_key": "66666666-6666-4666-8666-666666666666",
                },
                connection_id="test-connection",
            )
            self.assertEqual(fetched["status"]["head"]["behind"], 1)
            pull_prepare = self.prepare(
                service,
                "pull",
                {"remote": "origin", "branch": "main", "strategy": "ff-only"},
                fetched["status"]["status_token"],
            )
            pulled = service.execute(
                "pull",
                {
                    "workspace_id": "fixture",
                    "remote": "origin",
                    "branch": "main",
                    "strategy": "ff-only",
                    "expected_status_token": fetched["status"]["status_token"],
                    "confirmation_token": pull_prepare["confirmation_token"],
                    "idempotency_key": "77777777-7777-4777-8777-777777777777",
                },
                connection_id="test-connection",
            )
            self.assertFalse(pulled["status"]["dirty"])
            self.assertEqual((root / "remote.txt").read_text(encoding="utf-8"), "remote\n")
            self.assertFalse(post_merge_marker.exists(), "service-owned pull executed post-merge")

    def test_https_push_never_executes_a_repository_credential_helper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory, visibility="private")
            bare = Path(directory) / "remote.git"
            git(Path(directory), "init", "--bare", "-b", "main", str(bare))
            git(root, "remote", "add", "origin", str(bare))
            git(root, "push", "-u", "origin", "main")
            (root / "pushed.txt").write_text("service push\n", encoding="utf-8")
            git(root, "add", "--", "pushed.txt")
            git(root, "commit", "-m", "outgoing update")
            marker = Path(directory) / "credential-helper-fired"
            program = Path(directory) / "credential-helper"
            program.write_text(
                f"#!/bin/sh\ntouch '{marker}'\n"
                "if [ \"$1\" = get ]; then\n"
                "  echo username=fixture\n"
                "  echo password=fixture\n"
                "fi\n",
                encoding="utf-8",
            )
            program.chmod(0o755)
            git(root, "config", "credential.helper", f"!{program}")

            class AuthenticationRequired(BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="fixture"')
                    self.end_headers()

                def log_message(self, format: str, *args: object) -> None:
                    pass

            server = ThreadingHTTPServer(("127.0.0.1", 0), AuthenticationRequired)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            remote_url = f"http://127.0.0.1:{server.server_port}/repository.git"
            git(root, "remote", "set-url", "origin", remote_url)

            subprocess.run(
                ["git", "ls-remote", remote_url],
                cwd=root,
                check=False,
                capture_output=True,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
            )
            self.assertTrue(marker.exists(), "HTTPS probe did not reach the configured helper")
            marker.unlink()

            status = service.status("fixture")
            prepared = self.prepare(
                service,
                "push",
                {"remote": "origin", "branch": "main"},
                status["status_token"],
            )
            with self.assertRaises(WorkspaceGitError):
                service.execute(
                    "push",
                    {
                        "workspace_id": "fixture",
                        "remote": "origin",
                        "branch": "main",
                        "expected_status_token": status["status_token"],
                        "confirmation_token": prepared["confirmation_token"],
                        "idempotency_key": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                    },
                    connection_id="test-connection",
                )
            self.assertFalse(marker.exists(), "service-owned HTTPS push executed the credential helper")

    def test_ssh_push_never_executes_a_repository_ssh_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory, visibility="private")
            bare = Path(directory) / "remote.git"
            git(Path(directory), "init", "--bare", "-b", "main", str(bare))
            git(root, "remote", "add", "origin", str(bare))
            git(root, "push", "-u", "origin", "main")
            (root / "pushed.txt").write_text("service push\n", encoding="utf-8")
            git(root, "add", "--", "pushed.txt")
            git(root, "commit", "-m", "outgoing update")
            marker = Path(directory) / "ssh-command-fired"
            program = Path(directory) / "ssh-command"
            program.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n", encoding="utf-8")
            program.chmod(0o755)
            git(root, "config", "core.sshCommand", str(program))
            remote_url = "ssh://fixture@127.0.0.1:9/repository.git"
            git(root, "remote", "set-url", "origin", remote_url)

            subprocess.run(
                ["git", "ls-remote", remote_url],
                cwd=root,
                check=False,
                capture_output=True,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
            )
            self.assertTrue(marker.exists(), "SSH probe did not reach the configured command")
            marker.unlink()

            status = service.status("fixture")
            prepared = self.prepare(
                service,
                "push",
                {"remote": "origin", "branch": "main"},
                status["status_token"],
            )
            with self.assertRaises(WorkspaceGitError):
                service.execute(
                    "push",
                    {
                        "workspace_id": "fixture",
                        "remote": "origin",
                        "branch": "main",
                        "expected_status_token": status["status_token"],
                        "confirmation_token": prepared["confirmation_token"],
                        "idempotency_key": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                    },
                    connection_id="test-connection",
                )
            self.assertFalse(marker.exists(), "service-owned SSH push executed the repository command")

    def test_push_never_executes_a_repository_receive_pack_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory, visibility="private")
            bare = Path(directory) / "remote.git"
            git(Path(directory), "init", "--bare", "-b", "main", str(bare))
            git(root, "remote", "add", "origin", str(bare))
            git(root, "push", "-u", "origin", "main")
            (root / "pushed.txt").write_text("service push\n", encoding="utf-8")
            git(root, "add", "--", "pushed.txt")
            git(root, "commit", "-m", "outgoing update")
            marker = Path(directory) / "receive-pack-fired"
            program = Path(directory) / "receive-pack"
            program.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n", encoding="utf-8")
            program.chmod(0o755)
            git(root, "config", "remote.origin.receivepack", str(program))

            subprocess.run(["git", "push", "origin", "main"], cwd=root, check=False, capture_output=True)
            self.assertTrue(marker.exists(), "push probe did not reach remote.origin.receivepack")
            marker.unlink()

            status = service.status("fixture")
            prepared = self.prepare(
                service,
                "push",
                {"remote": "origin", "branch": "main"},
                status["status_token"],
            )
            result = service.execute(
                "push",
                {
                    "workspace_id": "fixture",
                    "remote": "origin",
                    "branch": "main",
                    "expected_status_token": status["status_token"],
                    "confirmation_token": prepared["confirmation_token"],
                    "idempotency_key": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                },
                connection_id="test-connection",
            )

            self.assertEqual(result["result"]["commit_oid"], git(root, "rev-parse", "HEAD"))
            self.assertFalse(marker.exists(), "service-owned push executed remote.origin.receivepack")

    def test_fetch_never_executes_a_repository_upload_pack_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory, visibility="private")
            bare = Path(directory) / "remote.git"
            git(Path(directory), "init", "--bare", "-b", "main", str(bare))
            git(root, "remote", "add", "origin", str(bare))
            git(root, "push", "-u", "origin", "main")
            marker = Path(directory) / "upload-pack-fired"
            program = Path(directory) / "upload-pack"
            program.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n", encoding="utf-8")
            program.chmod(0o755)
            git(root, "config", "remote.origin.uploadpack", str(program))

            subprocess.run(["git", "fetch", "origin"], cwd=root, check=False, capture_output=True)
            self.assertTrue(marker.exists(), "fetch probe did not reach remote.origin.uploadpack")
            marker.unlink()

            status = service.status("fixture")
            prepared = self.prepare(service, "fetch", {"remote": "origin"}, status["status_token"])
            result = service.execute(
                "fetch",
                {
                    "workspace_id": "fixture",
                    "remote": "origin",
                    "expected_status_token": status["status_token"],
                    "confirmation_token": prepared["confirmation_token"],
                    "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                },
                connection_id="test-connection",
            )

            self.assertEqual(result["operation"], "fetch")
            self.assertFalse(marker.exists(), "service-owned fetch executed remote.origin.uploadpack")

    def test_rejected_push_and_conflicts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, service = self.make_repo(directory, visibility="private")
            bare = Path(directory) / "remote.git"
            git(Path(directory), "init", "--bare", "-b", "main", str(bare))
            git(root, "remote", "add", "origin", str(bare))
            git(root, "push", "-u", "origin", "main")
            peer = Path(directory) / "peer"
            git(Path(directory), "clone", str(bare), str(peer))
            (root / "local.txt").write_text("local\n", encoding="utf-8")
            git(root, "add", "--", "local.txt")
            git(root, "commit", "-m", "local update")
            local_status = service.status("fixture")
            prepared = self.prepare(service, "push", {"remote": "origin", "branch": "main"}, local_status["status_token"])
            (peer / "remote.txt").write_text("remote\n", encoding="utf-8")
            git(peer, "add", "--", "remote.txt")
            git(peer, "commit", "-m", "remote update")
            git(peer, "push", "origin", "main")
            with self.assertRaisesRegex(WorkspaceGitError, "NON_FAST_FORWARD"):
                service.execute(
                    "push",
                    {
                        "workspace_id": "fixture",
                        "remote": "origin",
                        "branch": "main",
                        "expected_status_token": local_status["status_token"],
                        "confirmation_token": prepared["confirmation_token"],
                        "idempotency_key": "88888888-8888-4888-8888-888888888888",
                    },
                    connection_id="test-connection",
                )

            git(root, "checkout", "-b", "conflict-fixture")
            (root / "tracked.txt").write_text("branch\n", encoding="utf-8")
            git(root, "commit", "-am", "branch side")
            git(root, "checkout", "main")
            (root / "tracked.txt").write_text("main\n", encoding="utf-8")
            git(root, "commit", "-am", "main side")
            subprocess.run(["git", "merge", "conflict-fixture"], cwd=root, capture_output=True, check=False)
            conflict_status = service.status("fixture")
            self.assertEqual(conflict_status["conflicts"], ["tracked.txt"])
            with self.assertRaisesRegex(WorkspaceGitError, "WORKTREE_CONFLICTED"):
                self.prepare(service, "commit", {"message": "cannot commit"}, conflict_status["status_token"])


if __name__ == "__main__":
    unittest.main()
