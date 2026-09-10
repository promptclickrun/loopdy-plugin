"""Bounded, workspace-pinned git operations for the authenticated Loopdy API."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import secrets
import selectors
import sqlite3
import stat
import subprocess
import tempfile
import threading
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from .sensitive import SECRET_PATH_RE, SENSITIVE_CREDENTIAL_BYTES_RE


_ALLOWED_OPERATIONS = {"status", "stage", "commit", "push", "fetch", "pull"}
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_BASE_SAFE_GIT_CONFIG = (
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "credential.helper=",
    "-c",
    "core.askPass=false",
    "-c",
    "core.gitProxy=none",
    "-c",
    "protocol.ext.allow=never",
)
_MAX_STATUS_HASH_BYTES_PER_FILE = 64 * 1024 * 1024
_MAX_STATUS_HASH_BYTES_TOTAL = 512 * 1024 * 1024
_MAX_STATUS_FILES = 500
_MAX_STATUS_CONFLICTS = 500
_MAX_STATUS_RESPONSE_BYTES = 160_000
_MAX_DIFF_FILE_BYTES = 2_000_000
_MAX_DIFF_LINES = 100_000
_MAX_DIFF_LINE_BYTES = 16_000
_MAX_DIFF_RESPONSE_BYTES = 160_000
_MAX_TEXT_PREVIEW_BYTES = 65_536
_FIXED_ENV = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_PAGER": "cat",
    "PAGER": "cat",
    "GIT_EDITOR": "false",
    "GIT_SEQUENCE_EDITOR": "false",
    "GIT_ASKPASS": "false",
    "SSH_ASKPASS": "false",
    "GIT_SSH_COMMAND": "false",
    "GIT_PROXY_COMMAND": "false",
    "GIT_ALLOW_PROTOCOL": "file:http:https:ssh:git",
    "GIT_PROTOCOL_FROM_USER": "0",
    "GIT_EXTERNAL_DIFF": "false",
    "GIT_MERGE_AUTOEDIT": "no",
}


class WorkspaceGitError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.retryable = retryable
        self.details = dict(details or {})

    def envelope(self) -> dict[str, Any]:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "retryable": self.retryable,
                "details": self.details,
            }
        }


@dataclass(frozen=True)
class Workspace:
    workspace_id: str
    label: str
    root: Path
    visibility: str
    operations: frozenset[str]
    remotes: frozenset[str]
    branches: frozenset[str]
    mutations_enabled: bool
    identity: str


@dataclass
class Confirmation:
    connection_id: str
    workspace_id: str
    operation: str
    digest: str
    status_token: str
    expires_at: float
    used: bool = False


class WorkspaceGitService:
    """Runs only fixed git argv against host-configured repository roots."""

    def __init__(
        self,
        workspaces: Iterable[Mapping[str, Any]],
        *,
        state_path: Path | str,
        timeout: float = 30.0,
        max_output_bytes: int = 4_000_000,
    ) -> None:
        self._timeout = timeout
        self._max_output_bytes = max_output_bytes
        self._locks: dict[str, threading.RLock] = {}
        self._confirmations: dict[str, Confirmation] = {}
        self._workspaces: dict[str, Workspace] = {}
        self._state_path = Path(state_path)
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        for value in workspaces:
            workspace = self._workspace(value)
            if workspace.workspace_id in self._workspaces:
                raise ValueError("Duplicate workspace_id")
            self._workspaces[workspace.workspace_id] = workspace
            self._locks[workspace.workspace_id] = threading.RLock()
        self._ensure_ledger()

    @classmethod
    def from_environment(cls, *, state_path: Path | str) -> "WorkspaceGitService":
        raw = os.getenv("LOOPDY_WORKSPACE_GIT_CONFIG", "").strip()
        if not raw:
            return cls([], state_path=state_path)
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ValueError("LOOPDY_WORKSPACE_GIT_CONFIG must be valid JSON") from error
        if not isinstance(value, list):
            raise ValueError("LOOPDY_WORKSPACE_GIT_CONFIG must be a workspace list")
        return cls(value, state_path=state_path)

    def capabilities(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "capabilities": {
                "status": bool(self._workspaces),
                "stage": any("stage" in item.operations for item in self._workspaces.values()),
                "commit": any("commit" in item.operations for item in self._workspaces.values()),
                "push": any("push" in item.operations for item in self._workspaces.values()),
                "fetch": any("fetch" in item.operations for item in self._workspaces.values()),
                "pull": any("pull" in item.operations for item in self._workspaces.values()),
                "arbitrary_command": False,
            },
            "workspaces": [
                {
                    "workspace_id": item.workspace_id,
                    "label": item.label,
                    "visibility": item.visibility,
                    "operations": sorted(item.operations),
                    "remotes": sorted(item.remotes),
                    "branches": sorted(item.branches),
                    "mutations_enabled": item.mutations_enabled,
                }
                for item in sorted(self._workspaces.values(), key=lambda item: item.workspace_id)
            ],
        }

    def status(self, workspace_id: str) -> dict[str, Any]:
        workspace = self._get_workspace(workspace_id, "status")
        with self._locks[workspace.workspace_id]:
            self._verify_workspace(workspace)
            raw = self._git(workspace, "status", "--porcelain=v2", "-z", "--branch", "--untracked-files=all")
            files, head = _parse_porcelain(raw)
            staged_by_path = self._diff_stats_by_path(workspace, cached=True)
            worktree_by_path = self._diff_stats_by_path(workspace, cached=False)
            staged_stats = _sum_diff_stats(staged_by_path)
            for item in files:
                staged = staged_by_path.get(item["path"], _empty_diff_stats())
                worktree = worktree_by_path.get(item["path"], _empty_diff_stats())
                if item["kind"] == "untracked":
                    insertions, is_binary = _untracked_status(workspace.root, item["path"])
                    worktree = {"insertions": insertions, "deletions": 0, "is_binary": is_binary}
                item["insertions"] = min(
                    int(staged["insertions"]) + int(worktree["insertions"]),
                    _MAX_DIFF_LINES,
                )
                item["deletions"] = min(
                    int(staged["deletions"]) + int(worktree["deletions"]),
                    _MAX_DIFF_LINES,
                )
                item["is_binary"] = bool(staged["is_binary"] or worktree["is_binary"])
            changes = {
                "files": len(files),
                "insertions": sum(int(item["insertions"]) for item in files),
                "deletions": sum(int(item["deletions"]) for item in files),
            }
            staged_stats["files"] = sum(1 for item in files if item["index"] not in {".", "?"})
            conflicts = [item["path"] for item in files if item["kind"] == "unmerged"]
            token_input = b"\0".join(
                [
                    workspace.identity.encode("utf-8"),
                    str(head.get("oid") or "").encode("ascii", "replace"),
                    self._index_digest(workspace).encode("ascii"),
                    self._worktree_digest(workspace, files).encode("ascii"),
                    raw,
                ]
            )
            response = {
                "workspace_id": workspace.workspace_id,
                "status_token": f"sha256:{hashlib.sha256(token_input).hexdigest()}",
                "head": head,
                "files": files[:_MAX_STATUS_FILES],
                "files_page": _status_page(len(files), min(len(files), _MAX_STATUS_FILES), _MAX_STATUS_FILES),
                "staged": staged_stats,
                "changes": changes,
                "conflicts": conflicts[:_MAX_STATUS_CONFLICTS],
                "conflicts_page": _status_page(
                    len(conflicts),
                    min(len(conflicts), _MAX_STATUS_CONFLICTS),
                    _MAX_STATUS_CONFLICTS,
                ),
                "dirty": bool(files),
            }
            return _bound_status_response(response)

    def diff(
        self,
        workspace_id: str,
        *,
        path: str,
        side: str,
        expected_status_token: str,
        offset: int,
        limit: int,
        reject_sensitive_content: bool = False,
    ) -> dict[str, Any]:
        workspace = self._get_workspace(workspace_id, "status")
        with self._locks[workspace.workspace_id]:
            current = self.status(workspace_id)
            self._require_status(expected_status_token, current)
            selected = self._paths(workspace, [path], current)[0]
            if (
                side not in {"staged", "worktree"}
                or isinstance(offset, bool)
                or not isinstance(offset, int)
                or isinstance(limit, bool)
                or not isinstance(limit, int)
                or not 0 <= offset <= 100_000
                or not 1 <= limit <= 500
            ):
                raise WorkspaceGitError("INVALID_REQUEST", "Diff page is invalid")
            page = self._structured_diff_page(
                workspace, current, selected, side, offset, limit,
                reject_sensitive_content=reject_sensitive_content,
            )
            status_row = next(item for item in current["files"] if item["path"] == selected)
            selected_status = status_row["index" if side == "staged" else "worktree"]
            if offset == 0 and selected_status != "D":
                preview = self._text_preview(workspace, selected, side)
                if preview is not None:
                    if reject_sensitive_content and SENSITIVE_CREDENTIAL_BYTES_RE.search(preview.encode("utf-8")):
                        raise WorkspaceGitError("SECRET_SCAN_BLOCKED", "Diff content requires local review")
                    candidate = {**page, "lines": list(page["lines"]), "preview_content": preview}
                    # Keep the complete preview and defer diff rows to later pages.
                    # A nonempty page must advance; never return next_offset == offset.
                    while True:
                        encoded = json.dumps(
                            candidate, ensure_ascii=False, separators=(",", ":"),
                        ).encode("utf-8")
                        if len(encoded) <= _MAX_DIFF_RESPONSE_BYTES:
                            page = candidate
                            break
                        if len(candidate["lines"]) <= 1:
                            break
                        candidate["lines"].pop()
                        candidate["next_offset"] = offset + len(candidate["lines"])
            final = self.status(workspace_id)
            self._require_status(expected_status_token, final)
            return page

    def prepare(
        self,
        *,
        workspace_id: str,
        operation: str,
        input_: Mapping[str, Any],
        expected_status_token: str,
        connection_id: str,
    ) -> dict[str, Any]:
        workspace = self._get_workspace(workspace_id, operation, mutation=True)
        with self._locks[workspace.workspace_id]:
            current = self.status(workspace_id)
            self._require_status(expected_status_token, current)
            normalized, preview = self._validate_operation(workspace, operation, input_, current)
            digest = _digest({"workspace_id": workspace_id, "operation": operation, "input": normalized})
            token = secrets.token_urlsafe(32)
            expiry = time.time() + 300
            self._confirmations[token] = Confirmation(
                connection_id=connection_id,
                workspace_id=workspace_id,
                operation=operation,
                digest=digest,
                status_token=expected_status_token,
                expires_at=expiry,
            )
            return {
                "confirmation_token": token,
                "operation_digest": digest,
                "expires_at": _iso(expiry),
                "preview": preview,
            }

    def execute(
        self,
        operation: str,
        request: Mapping[str, Any],
        *,
        connection_id: str,
    ) -> dict[str, Any]:
        workspace_id = _required_string(request.get("workspace_id"), "workspace_id", 80)
        workspace = self._get_workspace(workspace_id, operation, mutation=True)
        key = _required_string(request.get("idempotency_key"), "idempotency_key", 64)
        if not _UUID.fullmatch(key):
            raise WorkspaceGitError("INVALID_REQUEST", "idempotency_key must be a lowercase UUID")
        input_ = {
            key_: request[key_]
            for key_ in ("mode", "paths", "message", "remote", "branch", "strategy")
            if key_ in request
        }
        replay = self._ledger_get(workspace_id, key)
        if replay is not None:
            replay_digest = _digest(
                {"workspace_id": workspace_id, "operation": operation, "input": input_}
            )
            if replay["digest"] != replay_digest:
                raise WorkspaceGitError("IDEMPOTENCY_CONFLICT", "Idempotency key was reused for another operation")
            return replay["response"]
        normalized, _ = self._validate_operation(workspace, operation, input_, self.status(workspace_id))
        digest = _digest({"workspace_id": workspace_id, "operation": operation, "input": normalized})
        with self._locks[workspace.workspace_id]:
            current = self.status(workspace_id)
            expected = _required_string(request.get("expected_status_token"), "expected_status_token", 100)
            self._require_status(expected, current)
            token = _required_string(request.get("confirmation_token"), "confirmation_token", 200)
            confirmation = self._confirmations.get(token)
            if (
                confirmation is None
                or confirmation.used
                or confirmation.expires_at < time.time()
                or confirmation.connection_id != connection_id
                or confirmation.workspace_id != workspace_id
                or confirmation.operation != operation
                or confirmation.digest != digest
                or confirmation.status_token != expected
            ):
                raise WorkspaceGitError("CONFIRMATION_INVALID", "Prepare this operation again before continuing")
            confirmation.used = True
            result = self._perform(workspace, operation, normalized, current)
            response = {
                "operation_id": key,
                "workspace_id": workspace_id,
                "operation": operation,
                "result": result,
                "status": self.status(workspace_id),
            }
            self._ledger_put(workspace_id, key, digest, response)
            return response

    def _perform(
        self,
        workspace: Workspace,
        operation: str,
        input_: Mapping[str, Any],
        before: Mapping[str, Any],
    ) -> dict[str, Any]:
        if operation == "stage":
            paths = list(input_["paths"])
            if input_["mode"] == "stage":
                self._git(workspace, "add", "--", *paths)
            else:
                self._git(workspace, "restore", "--staged", "--", *paths)
            after = self.status(workspace.workspace_id)
            by_path = {item["path"]: item for item in after["files"]}
            if input_["mode"] == "stage" and any(by_path.get(path, {}).get("index") in {None, ".", "?"} for path in paths):
                raise WorkspaceGitError("GIT_OUTCOME_UNKNOWN", "Git did not stage every selected path")
            if input_["mode"] == "unstage" and any(by_path.get(path, {}).get("index") not in {None, ".", "?"} for path in paths):
                raise WorkspaceGitError("GIT_OUTCOME_UNKNOWN", "Git did not unstage every selected path")
            return {"mode": input_["mode"], "paths": paths}
        if operation == "commit":
            message = str(input_["message"])
            parent = str(before["head"].get("oid") or "")
            descriptor, name = tempfile.mkstemp(prefix="loopdy-commit-", text=True)
            try:
                try:
                    os.fchmod(descriptor, 0o600)
                except (AttributeError, NotImplementedError):
                    # Native Windows does not expose os.fchmod. Keep the
                    # temporary commit-message file private through the
                    # platform-supported path operation instead.
                    os.chmod(name, 0o600)
                os.write(descriptor, message.encode("utf-8"))
                os.close(descriptor)
                descriptor = -1
                self._git(workspace, "commit", "--file", name)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                Path(name).unlink(missing_ok=True)
            oid = self._git_text(workspace, "rev-parse", "HEAD")
            subject = self._git_text(workspace, "show", "-s", "--format=%s", "HEAD")
            tree = self._git_text(workspace, "show", "-s", "--format=%T", "HEAD")
            actual_parent = self._git_text(workspace, "show", "-s", "--format=%P", "HEAD").split(" ")[0]
            if oid == parent or actual_parent != parent:
                raise WorkspaceGitError("GIT_OUTCOME_UNKNOWN", "Committed revision did not match the prepared parent")
            return {"commit_oid": oid, "parent_oid": actual_parent, "tree_oid": tree, "subject": subject}
        if operation == "fetch":
            remote = str(input_["remote"])
            before_refs = self._remote_tracking_refs(workspace, remote)
            self._git(workspace, "fetch", "--no-tags", "--upload-pack=git-upload-pack", remote)
            after_refs = self._remote_tracking_refs(workspace, remote)
            return {"remote": remote, "updated_refs": _changed_refs(before_refs, after_refs)}
        if operation == "push":
            remote = str(input_["remote"])
            branch = str(input_["branch"])
            local_oid = self._git_text(workspace, "rev-parse", f"refs/heads/{branch}")
            self._git(
                workspace,
                "push",
                "--receive-pack=git-receive-pack",
                remote,
                f"refs/heads/{branch}:refs/heads/{branch}",
            )
            remote_oid = self._ls_remote(workspace, remote, branch)
            if remote_oid != local_oid:
                raise WorkspaceGitError("GIT_OUTCOME_UNKNOWN", "Remote branch did not match the pushed revision")
            return {"remote": remote, "branch": branch, "commit_oid": local_oid}
        if operation == "pull":
            remote = str(input_["remote"])
            branch = str(input_["branch"])
            self._git(workspace, "fetch", "--no-tags", "--upload-pack=git-upload-pack", remote)
            target = self._git_text(workspace, "rev-parse", f"refs/remotes/{remote}/{branch}")
            self._git(workspace, "merge", "--ff-only", target)
            head = self._git_text(workspace, "rev-parse", "HEAD")
            if head != target or self.status(workspace.workspace_id)["dirty"]:
                raise WorkspaceGitError("GIT_OUTCOME_UNKNOWN", "Pulled worktree did not match the fetched target")
            return {"remote": remote, "branch": branch, "commit_oid": head, "strategy": "ff-only"}
        raise WorkspaceGitError("OPERATION_NOT_ALLOWED", "Unsupported workspace operation")

    def _validate_operation(
        self,
        workspace: Workspace,
        operation: str,
        input_: Mapping[str, Any],
        current: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        head = current["head"]
        conflicts = current.get("conflicts") or []
        has_conflicts = int((current.get("conflicts_page") or {}).get("total", len(conflicts))) > 0
        if operation == "stage":
            mode = str(input_.get("mode") or "stage")
            if mode not in {"stage", "unstage"}:
                raise WorkspaceGitError("INVALID_REQUEST", "Stage mode must be stage or unstage")
            paths = self._paths(workspace, input_.get("paths"), current)
            by_path = {item["path"]: item for item in current["files"]}
            eligible = [
                path
                for path in paths
                if (mode == "stage" and by_path[path]["worktree"] not in {".", "!"})
                or (mode == "unstage" and by_path[path]["index"] not in {".", "?"})
            ]
            if len(eligible) != len(paths):
                raise WorkspaceGitError("NOTHING_TO_STAGE", f"One or more selected paths cannot be {mode}d")
            return {"mode": mode, "paths": paths}, {"summary": f"{mode.title()} {len(paths)} selected path(s)", "paths": paths}
        if operation == "commit":
            self._require_attached_allowed_branch(workspace, head)
            if has_conflicts:
                raise WorkspaceGitError("WORKTREE_CONFLICTED", "Resolve conflicts before committing")
            if current["staged"]["files"] < 1:
                raise WorkspaceGitError("NOTHING_TO_COMMIT", "Stage at least one change before committing")
            message = _required_string(input_.get("message"), "message", 10_000)
            if any(ord(character) < 32 and character not in "\n\t" for character in message):
                raise WorkspaceGitError("INVALID_REQUEST", "Commit message contains unsupported control characters")
            findings = self._public_commit_findings(workspace) if workspace.visibility == "public" else []
            if findings:
                raise WorkspaceGitError(
                    "SECRET_SCAN_BLOCKED",
                    "The staged changes need review before they can be committed",
                    details={"findings": findings},
                )
            paths = [item["path"] for item in current["files"] if item["index"] not in {".", "?"}]
            return {"message": message}, {"summary": message.splitlines()[0], "paths": paths}
        if operation == "fetch":
            remote = self._remote(workspace, input_.get("remote"))
            return {"remote": remote}, {"summary": f"Fetch {remote}", "remote": remote}
        if operation in {"push", "pull"}:
            branch = self._require_attached_allowed_branch(workspace, head)
            remote = _required_string(input_.get("remote"), "remote", 180)
            if remote not in workspace.remotes:
                raise WorkspaceGitError("OPERATION_NOT_ALLOWED", "Remote is not allowlisted")
            requested_branch = _required_string(input_.get("branch"), "branch", 180)
            if requested_branch != branch or requested_branch not in workspace.branches:
                raise WorkspaceGitError("BRANCH_MISMATCH", "The selected branch is not allowlisted")
            expected_upstream = f"{remote}/{branch}"
            if head.get("upstream") != expected_upstream:
                raise WorkspaceGitError("UPSTREAM_REQUIRED", "Track the allowlisted upstream before this operation")
            configured = set(self._git_text(workspace, "remote").splitlines())
            if remote not in configured:
                raise WorkspaceGitError(
                    "REMOTE_UNAVAILABLE", "Allowlisted remote is not configured", retryable=True
                )
            if has_conflicts:
                raise WorkspaceGitError("WORKTREE_CONFLICTED", "Resolve conflicts before this operation")
            ahead = int(head.get("ahead") or 0)
            behind = int(head.get("behind") or 0)
            if ahead and behind:
                raise WorkspaceGitError("NON_FAST_FORWARD", "The branch has diverged from its upstream")
            if operation == "push":
                if behind:
                    raise WorkspaceGitError("NON_FAST_FORWARD", "Pull the upstream changes before pushing")
                if ahead < 1:
                    raise WorkspaceGitError("NOTHING_TO_PUSH", "The upstream already has this branch")
                if workspace.visibility == "public" and self._public_push_findings(workspace, expected_upstream):
                    raise WorkspaceGitError("PUBLIC_REPO_SAFETY_BLOCK", "Review pending public-repository findings before pushing")
                return {"remote": remote, "branch": branch}, {"summary": f"Push {ahead} commit(s)", "remote": remote, "branch": branch, "commits": ahead}
            strategy = str(input_.get("strategy") or "")
            if strategy != "ff-only":
                raise WorkspaceGitError("INVALID_REQUEST", "Pull strategy must be ff-only")
            if current["dirty"]:
                raise WorkspaceGitError("WORKTREE_NOT_CLEAN", "Commit or discard local changes before pulling")
            if ahead:
                raise WorkspaceGitError("NON_FAST_FORWARD", "Push local commits before pulling")
            if behind < 1:
                raise WorkspaceGitError("NOTHING_TO_PULL", "The branch is already up to date")
            return {"remote": remote, "branch": branch, "strategy": "ff-only"}, {"summary": f"Fast-forward {behind} commit(s)", "remote": remote, "branch": branch, "commits": behind}
        raise WorkspaceGitError("OPERATION_NOT_ALLOWED", "Unsupported workspace operation")

    def _paths(self, workspace: Workspace, value: Any, current: Mapping[str, Any]) -> list[str]:
        if not isinstance(value, list) or not value:
            raise WorkspaceGitError("INVALID_PATH", "Select at least one changed path")
        available = {item["path"] for item in current["files"]}
        paths: list[str] = []
        for raw in value:
            path = _required_path(raw)
            pure = PurePosixPath(path)
            if pure.is_absolute() or ".." in pure.parts or path not in available:
                raise WorkspaceGitError("INVALID_PATH", "Selected path is outside the current workspace status")
            entry = _workspace_lstat(workspace.root, path)
            if entry is not None and stat.S_ISLNK(entry.st_mode):
                raise WorkspaceGitError("INVALID_PATH", "Selected path is a symbolic link")
            if path not in paths:
                paths.append(path)
        return paths

    def _public_commit_findings(self, workspace: Workspace) -> list[dict[str, str]]:
        names = self._git(workspace, "diff", "--cached", "--name-only", "-z").split(b"\0")
        findings: list[dict[str, str]] = []
        for raw in names:
            if not raw:
                continue
            path = raw.decode("utf-8", "strict")
            if SECRET_PATH_RE.search(path):
                findings.append({"path": path, "rule_id": "secret-path"})
        diff = self._git(workspace, "diff", "--cached", "--binary", "--no-ext-diff", "--no-textconv")
        if SENSITIVE_CREDENTIAL_BYTES_RE.search(diff):
            findings.append({"path": "staged-diff", "rule_id": "secret-pattern"})
        return findings[:50]

    def _public_push_findings(self, workspace: Workspace, upstream: str) -> list[dict[str, str]]:
        pending = self.status(workspace.workspace_id)
        if pending["dirty"]:
            return [{"path": "working-tree", "rule_id": "pending-material"}]
        names = self._git(workspace, "diff", "--name-only", "-z", f"{upstream}..HEAD").split(b"\0")
        findings = [
            {"path": raw.decode("utf-8", "strict"), "rule_id": "secret-path"}
            for raw in names
            if raw and SECRET_PATH_RE.search(raw.decode("utf-8", "strict"))
        ]
        commit_diff = self._git(
            workspace, "diff", "--binary", "--no-ext-diff", "--no-textconv", f"{upstream}..HEAD"
        )
        if SENSITIVE_CREDENTIAL_BYTES_RE.search(commit_diff):
            findings.append({"path": "outgoing-commits", "rule_id": "secret-pattern"})
        return findings[:50]

    def _workspace(self, value: Mapping[str, Any]) -> Workspace:
        workspace_id = _required_string(value.get("workspace_id"), "workspace_id", 80)
        label = _required_string(value.get("label"), "label", 120)
        root = Path(_required_string(value.get("root"), "root", 4_096)).expanduser().resolve(strict=True)
        operations = frozenset(str(item) for item in value.get("operations", []))
        if not operations or not operations <= _ALLOWED_OPERATIONS:
            raise ValueError("Workspace operations must be a non-empty allowlisted set")
        visibility = str(value.get("visibility") or "public")
        if visibility not in {"public", "private"}:
            raise ValueError("Workspace visibility must be public or private")
        identity = self._repository_identity(root)
        return Workspace(
            workspace_id=workspace_id,
            label=label,
            root=root,
            visibility=visibility,
            operations=operations,
            remotes=frozenset(_string_list(value.get("remotes"), "remotes")),
            branches=frozenset(_string_list(value.get("branches"), "branches")),
            mutations_enabled=value.get("mutations_enabled") is True,
            identity=identity,
        )

    def _get_workspace(self, workspace_id: str, operation: str, *, mutation: bool = False) -> Workspace:
        workspace = self._workspaces.get(str(workspace_id or ""))
        if workspace is None:
            raise WorkspaceGitError("WORKSPACE_NOT_ALLOWED", "This workspace is not configured")
        if operation not in workspace.operations:
            raise WorkspaceGitError("OPERATION_NOT_ALLOWED", "This operation is not enabled")
        if mutation and not workspace.mutations_enabled:
            raise WorkspaceGitError("OPERATION_NOT_ALLOWED", "Workspace mutations are disabled")
        return workspace

    def _verify_workspace(self, workspace: Workspace) -> None:
        if workspace.root.resolve(strict=True) != workspace.root or self._repository_identity(workspace.root) != workspace.identity:
            raise WorkspaceGitError("WORKSPACE_NOT_ALLOWED", "Configured workspace identity changed")

    def _repository_identity(self, root: Path) -> str:
        top = _run_git(root, self._timeout, self._max_output_bytes, "rev-parse", "--show-toplevel").decode().strip()
        try:
            is_root = Path(top).samefile(root)
        except OSError:
            is_root = False
        if not is_root:
            raise ValueError("Configured root must be the git worktree root")
        common = _run_git(root, self._timeout, self._max_output_bytes, "rev-parse", "--git-common-dir").decode().strip()
        common_path = (root / common).resolve(strict=True) if not Path(common).is_absolute() else Path(common).resolve(strict=True)
        stat = common_path.stat()
        return hashlib.sha256(f"{root}\0{common_path}\0{stat.st_dev}\0{stat.st_ino}".encode()).hexdigest()

    def _require_attached_allowed_branch(self, workspace: Workspace, head: Mapping[str, Any]) -> str:
        branch = str(head.get("branch") or "")
        if head.get("detached") or not branch or branch not in workspace.branches:
            raise WorkspaceGitError("BRANCH_MISMATCH", "Use an attached allowlisted branch for this operation")
        return branch

    def _remote(self, workspace: Workspace, value: Any) -> str:
        remote = _required_string(value, "remote", 180)
        if remote not in workspace.remotes:
            raise WorkspaceGitError("OPERATION_NOT_ALLOWED", "Remote is not allowlisted")
        configured = set(self._git_text(workspace, "remote").splitlines())
        if remote not in configured:
            raise WorkspaceGitError("REMOTE_UNAVAILABLE", "Allowlisted remote is not configured", retryable=True)
        return remote

    def _require_status(self, expected: str, current: Mapping[str, Any]) -> None:
        if expected != current["status_token"]:
            raise WorkspaceGitError("STATUS_STALE", "Workspace changed; review the latest status and prepare again")

    def _diff_stats_by_path(
        self,
        workspace: Workspace,
        *,
        cached: bool,
    ) -> dict[str, dict[str, int | bool]]:
        args = ["diff", "--numstat", "-z", "--no-ext-diff", "--no-textconv"]
        if cached:
            args.insert(1, "--cached")
        raw = self._git(workspace, *args)
        result: dict[str, dict[str, int | bool]] = {}
        parts = raw.split(b"\0")
        index = 0
        while index < len(parts):
            row = parts[index]
            index += 1
            if not row:
                continue
            fields = row.split(b"\t", 2)
            if len(fields) < 3:
                continue
            path_bytes = fields[2]
            if not fields[2] and index + 1 < len(parts):
                index += 1
                path_bytes = parts[index]
                index += 1
            try:
                path = path_bytes.decode("utf-8", "strict")
            except UnicodeDecodeError as error:
                raise WorkspaceGitError(
                    "UNSUPPORTED_PATH_ENCODING",
                    "Git diff contains a path that is not valid UTF-8",
                ) from error
            result[path] = {
                "insertions": min(int(fields[0]), _MAX_DIFF_LINES) if fields[0].isdigit() else 0,
                "deletions": min(int(fields[1]), _MAX_DIFF_LINES) if fields[1].isdigit() else 0,
                "is_binary": not fields[0].isdigit() or not fields[1].isdigit(),
            }
        return result

    def _structured_diff_page(
        self,
        workspace: Workspace,
        current: Mapping[str, Any],
        path: str,
        side: str,
        offset: int,
        limit: int,
        *,
        reject_sensitive_content: bool = False,
    ) -> dict[str, Any]:
        status_row = next(item for item in current["files"] if item["path"] == path)
        if side == "worktree" and status_row["kind"] == "untracked":
            availability, rows = _untracked_diff_rows(workspace.root, path)
        else:
            args = ["diff", "--no-ext-diff", "--no-textconv", "--unified=3"]
            if side == "staged":
                args.insert(1, "--cached")
            entry = _workspace_lstat(workspace.root, path)
            if entry is not None and stat.S_ISREG(entry.st_mode) and entry.st_size > _MAX_DIFF_FILE_BYTES:
                availability, rows = "oversized", []
            else:
                raw, overflow = self._git_bounded(workspace, _MAX_DIFF_FILE_BYTES, *args, "--", path)
                after = _workspace_lstat(workspace.root, path)
                if not _same_workspace_entry(entry, after):
                    raise WorkspaceGitError("STATUS_STALE", "Workspace changed while projecting the selected path")
                if overflow:
                    availability, rows = "oversized", []
                elif b"Binary files " in raw or b"GIT binary patch" in raw:
                    availability, rows = "binary", []
                else:
                    availability, rows = _parse_unified_diff(raw)
        if reject_sensitive_content and SENSITIVE_CREDENTIAL_BYTES_RE.search(
            "\n".join(row["content"] for row in rows).encode("utf-8")
        ):
            raise WorkspaceGitError("SECRET_SCAN_BLOCKED", "Diff content requires local review")
        return _diff_page(path, side, availability, rows, offset, limit)

    def _text_preview(
        self,
        workspace: Workspace,
        path: str,
        side: str,
    ) -> str | None:
        if PurePosixPath(path).suffix.lower() not in {".md", ".markdown", ".txt"}:
            return None
        if side == "staged":
            try:
                raw, overflow = self._git_bounded(
                    workspace,
                    _MAX_TEXT_PREVIEW_BYTES,
                    "show",
                    f":{path}",
                )
            except WorkspaceGitError:
                return None
        else:
            raw = _read_workspace_file(
                workspace.root,
                path,
                _MAX_TEXT_PREVIEW_BYTES,
            )
            overflow = raw is None
        if raw is None or overflow:
            return None
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return None
        return text if _safe_text_preview(text) else None

    def _index_digest(self, workspace: Workspace) -> str:
        git_dir = Path(self._git_text(workspace, "rev-parse", "--git-dir"))
        if not git_dir.is_absolute():
            git_dir = workspace.root / git_dir
        index = git_dir / "index"
        return hashlib.sha256(index.read_bytes() if index.exists() else b"").hexdigest()

    def _worktree_digest(self, workspace: Workspace, files: Iterable[Mapping[str, Any]]) -> str:
        digest = hashlib.sha256()
        total_bytes = 0
        for item in files:
            if item.get("worktree") in {".", "!"}:
                continue
            relative = str(item["path"])
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            entry = _workspace_lstat(workspace.root, relative)
            if entry is None:
                digest.update(b"missing\0")
                continue
            digest.update(f"{entry.st_mode:o}\0{entry.st_size}\0".encode("ascii"))
            if stat.S_ISLNK(entry.st_mode):
                digest.update(_read_workspace_link(workspace.root, relative).encode("utf-8"))
                digest.update(b"\0")
                continue
            if not stat.S_ISREG(entry.st_mode):
                raise WorkspaceGitError("GIT_UNAVAILABLE", "Git status contains an unsupported path type")
            if entry.st_size > _MAX_STATUS_HASH_BYTES_PER_FILE:
                raise WorkspaceGitError("GIT_UNAVAILABLE", "A changed file exceeds the review safety limit")
            total_bytes += entry.st_size
            if total_bytes > _MAX_STATUS_HASH_BYTES_TOTAL:
                raise WorkspaceGitError("GIT_UNAVAILABLE", "Changed files exceed the review safety limit")
            data = _read_workspace_file(workspace.root, relative, _MAX_STATUS_HASH_BYTES_PER_FILE)
            if data is None:
                raise WorkspaceGitError("GIT_UNAVAILABLE", "A changed file exceeds the review safety limit")
            digest.update(data)
            digest.update(b"\0")
        return digest.hexdigest()

    def _remote_tracking_refs(self, workspace: Workspace, remote: str) -> dict[str, str]:
        raw = self._git_text(workspace, "for-each-ref", "--format=%(refname) %(objectname)", f"refs/remotes/{remote}/")
        return dict(line.split(" ", 1) for line in raw.splitlines() if " " in line)

    def _ls_remote(self, workspace: Workspace, remote: str, branch: str) -> str:
        raw = self._git_text(
            workspace,
            "ls-remote",
            "--upload-pack=git-upload-pack",
            "--heads",
            remote,
            f"refs/heads/{branch}",
        )
        return raw.split()[0] if raw else ""

    def _git(self, workspace: Workspace, *args: str) -> bytes:
        try:
            return _run_git(workspace.root, self._timeout, self._max_output_bytes, *args)
        except subprocess.TimeoutExpired as error:
            raise WorkspaceGitError("GIT_TIMEOUT", "Git operation timed out", retryable=True) from error
        except subprocess.CalledProcessError as error:
            stderr = (error.stderr or b"").decode("utf-8", "replace").lower()
            if "non-fast-forward" in stderr or "fetch first" in stderr:
                raise WorkspaceGitError("NON_FAST_FORWARD", "The remote rejected a non-fast-forward update") from error
            if "could not read" in stderr or "unable to access" in stderr or "could not resolve" in stderr:
                raise WorkspaceGitError("REMOTE_UNAVAILABLE", "Remote is unavailable", retryable=True) from error
            raise WorkspaceGitError("GIT_UNAVAILABLE", "Git could not complete the requested operation") from error

    def _git_bounded(self, workspace: Workspace, limit: int, *args: str) -> tuple[bytes, bool]:
        try:
            return _run_git_bounded(
                workspace.root,
                self._timeout,
                limit,
                self._max_output_bytes,
                *args,
            )
        except subprocess.TimeoutExpired as error:
            raise WorkspaceGitError("GIT_TIMEOUT", "Git operation timed out", retryable=True) from error
        except subprocess.CalledProcessError as error:
            stderr = (error.stderr or b"").decode("utf-8", "replace").lower()
            if "non-fast-forward" in stderr or "fetch first" in stderr:
                raise WorkspaceGitError("NON_FAST_FORWARD", "The remote rejected a non-fast-forward update") from error
            if "could not read" in stderr or "unable to access" in stderr or "could not resolve" in stderr:
                raise WorkspaceGitError("REMOTE_UNAVAILABLE", "Remote is unavailable", retryable=True) from error
            raise WorkspaceGitError("GIT_UNAVAILABLE", "Git could not complete the requested operation") from error

    def _git_text(self, workspace: Workspace, *args: str) -> str:
        return self._git(workspace, *args).decode("utf-8", "strict").strip()

    def _ensure_ledger(self) -> None:
        with closing(sqlite3.connect(self._state_path)) as connection:
            with connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS workspace_git_operations ("
                    "workspace_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, digest TEXT NOT NULL, "
                    "response_json TEXT NOT NULL, created_at INTEGER NOT NULL, "
                    "PRIMARY KEY(workspace_id, idempotency_key))"
                )

    def _ledger_get(self, workspace_id: str, key: str) -> dict[str, Any] | None:
        with closing(sqlite3.connect(self._state_path)) as connection:
            row = connection.execute(
                "SELECT digest, response_json FROM workspace_git_operations WHERE workspace_id=? AND idempotency_key=?",
                (workspace_id, key),
            ).fetchone()
        return None if row is None else {"digest": row[0], "response": json.loads(row[1])}

    def _ledger_put(self, workspace_id: str, key: str, digest: str, response: Mapping[str, Any]) -> None:
        with closing(sqlite3.connect(self._state_path)) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO workspace_git_operations(workspace_id,idempotency_key,digest,response_json,created_at) VALUES(?,?,?,?,?)",
                    (workspace_id, key, digest, json.dumps(response, sort_keys=True, separators=(",", ":")), int(time.time())),
                )


def _run_git(root: Path, timeout: float, max_output_bytes: int, *args: str) -> bytes:
    safe_config = _safe_git_config(root, timeout)
    result = subprocess.run(
        ["git", *safe_config, *args],
        cwd=root,
        env=_FIXED_ENV,
        shell=False,
        check=True,
        capture_output=True,
        timeout=timeout,
    )
    if len(result.stdout) > max_output_bytes or len(result.stderr) > max_output_bytes:
        raise WorkspaceGitError("GIT_UNAVAILABLE", "Git output exceeded the safety limit")
    return result.stdout


def _run_git_bounded(
    root: Path,
    timeout: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    *args: str,
) -> tuple[bytes, bool]:
    safe_config = _safe_git_config(root, timeout)
    argv = ["git", *safe_config, *args]
    process = subprocess.Popen(
        argv,
        cwd=root,
        env=_FIXED_ENV,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        raise WorkspaceGitError("GIT_UNAVAILABLE", "Git output could not be captured")
    stdout = bytearray()
    stderr = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, (stdout, max_stdout_bytes, "stdout"))
    selector.register(process.stderr, selectors.EVENT_READ, (stderr, max_stderr_bytes, "stderr"))
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.communicate()
                raise subprocess.TimeoutExpired(argv, timeout)
            events = selector.select(remaining)
            if not events:
                continue
            for key, _ in events:
                target, limit, stream = key.data
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target.extend(chunk)
                if len(target) <= limit:
                    continue
                process.kill()
                process.communicate()
                if stream == "stdout":
                    return bytes(target[:limit]), True
                raise WorkspaceGitError("GIT_UNAVAILABLE", "Git output exceeded the safety limit")
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    returncode = process.wait()
    if returncode:
        raise subprocess.CalledProcessError(
            returncode,
            argv,
            output=bytes(stdout),
            stderr=bytes(stderr),
        )
    return bytes(stdout), False


def _git_reports_non_repository(output: bytes) -> bool:
    lines = output.decode("utf-8", "replace").lower().splitlines()
    return any(
        line.startswith(prefix)
        for line in lines
        for prefix in (
            "fatal: not a git repository",
            "fatal: --local can only be used inside a git repository",
            "fatal: this operation must be run in a work tree",
        )
    )


def _safe_git_config(root: Path, timeout: float) -> tuple[str, ...]:
    """Neutralize every configured external filter/text converter by its discovered driver name."""
    probe = subprocess.run(
        [
            "git",
            *_BASE_SAFE_GIT_CONFIG,
            "config",
            "--local",
            "--includes",
            "--null",
            "--name-only",
            "--get-regexp",
            r"^(filter\..*\.(clean|smudge|process|required)|diff\..*\.(command|textconv)|remote\..*\.(receivepack|uploadpack|proxy|vcs))$",
        ],
        cwd=root,
        env=_FIXED_ENV,
        shell=False,
        check=False,
        capture_output=True,
        timeout=timeout,
    )
    if probe.returncode not in {0, 1}:
        if _git_reports_non_repository(probe.stderr):
            raise WorkspaceGitError(
                "PROJECT_NOT_REPOSITORY", "Workspace is not a Git repository"
            )
        raise WorkspaceGitError("GIT_UNAVAILABLE", "Git configuration could not be safety-checked")
    filters: set[str] = set()
    diffs: set[str] = set()
    remote_programs: dict[str, str] = {}
    for raw in probe.stdout.split(b"\0"):
        key = raw.decode("utf-8", "strict")
        parts = key.split(".")
        if len(parts) >= 3 and parts[0] == "filter":
            filters.add(".".join(parts[1:-1]))
        elif len(parts) >= 3 and parts[0] == "diff":
            diffs.add(".".join(parts[1:-1]))
        elif len(parts) >= 3 and parts[0] == "remote":
            remote_programs[key] = parts[-1].lower()
    overrides: list[str] = list(_BASE_SAFE_GIT_CONFIG)
    for driver in sorted(filters):
        for suffix, value in (("clean", ""), ("smudge", ""), ("process", ""), ("required", "false")):
            overrides.extend(("-c", f"filter.{driver}.{suffix}={value}"))
    for driver in sorted(diffs):
        overrides.extend(("-c", f"diff.{driver}.command="))
        overrides.extend(("-c", f"diff.{driver}.textconv="))
    for key, selector in sorted(remote_programs.items()):
        if selector in {"receivepack", "uploadpack"}:
            # Fetch/push/ls-remote pass fixed program options that take
            # precedence over repository configuration without creating a
            # second multi-valued selector.
            continue
        overrides.extend(("-c", f"{key}="))
    return tuple(overrides)


def _parse_porcelain(raw: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records = raw.split(b"\0")
    files: list[dict[str, Any]] = []
    head: dict[str, Any] = {"oid": None, "branch": None, "detached": False, "upstream": None, "ahead": 0, "behind": 0}
    index = 0
    while index < len(records):
        raw_record = records[index]
        index += 1
        if not raw_record:
            continue
        try:
            record = raw_record.decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise WorkspaceGitError("UNSUPPORTED_PATH_ENCODING", "Git status contains a path that is not valid UTF-8") from error
        if record.startswith("# branch.oid "):
            oid = record.removeprefix("# branch.oid ")
            head["oid"] = None if oid == "(initial)" else oid
            continue
        if record.startswith("# branch.head "):
            branch = record.removeprefix("# branch.head ")
            head["detached"] = branch == "(detached)"
            head["branch"] = None if branch in {"(detached)", "(unknown)"} else branch
            continue
        if record.startswith("# branch.upstream "):
            head["upstream"] = record.removeprefix("# branch.upstream ")
            continue
        if record.startswith("# branch.ab "):
            match = re.fullmatch(r"# branch\.ab \+(\d+) -(\d+)", record)
            if match:
                head["ahead"], head["behind"] = int(match.group(1)), int(match.group(2))
            continue
        kind = record[:1]
        if kind == "1":
            fields = record.split(" ", 8)
            if len(fields) != 9:
                raise WorkspaceGitError("GIT_UNAVAILABLE", "Git returned malformed status data")
            files.append(_file_status(fields[8], fields[1], "ordinary"))
        elif kind == "2":
            fields = record.split(" ", 9)
            if len(fields) != 10 or index >= len(records):
                raise WorkspaceGitError("GIT_UNAVAILABLE", "Git returned malformed rename data")
            original = records[index].decode("utf-8", "strict")
            index += 1
            item = _file_status(fields[9], fields[1], "renamed")
            item["original_path"] = original
            files.append(item)
        elif kind == "u":
            fields = record.split(" ", 10)
            if len(fields) != 11:
                raise WorkspaceGitError("GIT_UNAVAILABLE", "Git returned malformed conflict data")
            files.append(_file_status(fields[10], fields[1], "unmerged"))
        elif kind == "?":
            files.append(_file_status(record[2:], "??", "untracked"))
        elif kind == "!":
            continue
    files.sort(key=lambda item: item["path"])
    return files, head


def _file_status(path: str, xy: str, kind: str) -> dict[str, Any]:
    return {
        "path": path,
        "original_path": None,
        "index": "?" if xy[0] == "?" else xy[0],
        "worktree": "?" if xy[1] == "?" else xy[1],
        "kind": kind,
    }


def _empty_diff_stats() -> dict[str, int | bool]:
    return {"insertions": 0, "deletions": 0, "is_binary": False}


def _sum_diff_stats(values: Mapping[str, Mapping[str, int | bool]]) -> dict[str, int]:
    return {
        "files": len(values),
        "insertions": sum(int(item["insertions"]) for item in values.values()),
        "deletions": sum(int(item["deletions"]) for item in values.values()),
    }


def _status_page(total: int, returned: int, limit: int) -> dict[str, int | bool | None]:
    return {
        "offset": 0,
        "limit": limit,
        "returned": returned,
        "total": total,
        "next_offset": returned if returned < total else None,
        "complete": returned == total,
    }


def _bound_status_response(response: dict[str, Any]) -> dict[str, Any]:
    while len(json.dumps(response).encode("utf-8")) > _MAX_STATUS_RESPONSE_BYTES:
        if response["conflicts"]:
            response["conflicts"].pop()
            page = response["conflicts_page"]
            response["conflicts_page"] = _status_page(page["total"], len(response["conflicts"]), page["limit"])
            continue
        if response["files"]:
            response["files"].pop()
            page = response["files_page"]
            response["files_page"] = _status_page(page["total"], len(response["files"]), page["limit"])
            continue
        raise WorkspaceGitError("GIT_UNAVAILABLE", "Workspace status exceeded the safety limit")
    return response


def _same_workspace_entry(before: os.stat_result | None, after: os.stat_result | None) -> bool:
    if before is None or after is None:
        return before is after
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _workspace_parent_fd(root: Path, path: str) -> tuple[int | None, str]:
    parts = PurePosixPath(path).parts
    if not parts:
        raise WorkspaceGitError("INVALID_PATH", "Selected path is invalid")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        current = os.open(root, directory_flags)
    except OSError as error:
        raise WorkspaceGitError("WORKSPACE_NOT_ALLOWED", "Configured workspace is unavailable") from error
    try:
        for component in parts[:-1]:
            try:
                following = os.open(component, directory_flags, dir_fd=current)
            except FileNotFoundError:
                os.close(current)
                return None, parts[-1]
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise WorkspaceGitError("INVALID_PATH", "Selected path crosses a symbolic link") from error
                raise WorkspaceGitError("GIT_UNAVAILABLE", "Selected path could not be inspected") from error
            os.close(current)
            current = following
        return current, parts[-1]
    except Exception:
        try:
            os.close(current)
        except OSError:
            pass
        raise


def _workspace_lstat(root: Path, path: str) -> os.stat_result | None:
    parent, name = _workspace_parent_fd(root, path)
    if parent is None:
        return None
    try:
        try:
            return os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise WorkspaceGitError("GIT_UNAVAILABLE", "Selected path could not be inspected") from error
    finally:
        os.close(parent)


def _read_workspace_link(root: Path, path: str) -> str:
    parent, name = _workspace_parent_fd(root, path)
    if parent is None:
        raise WorkspaceGitError("STATUS_STALE", "Workspace changed while reading the selected path")
    try:
        try:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISLNK(before.st_mode):
                raise WorkspaceGitError("STATUS_STALE", "Workspace changed while reading the selected path")
            target = os.readlink(name, dir_fd=parent)
            after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError as error:
            raise WorkspaceGitError("STATUS_STALE", "Workspace changed while reading the selected path") from error
        except OSError as error:
            raise WorkspaceGitError("STATUS_STALE", "Workspace changed while reading the selected path") from error
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if identity_before != identity_after:
            raise WorkspaceGitError("STATUS_STALE", "Workspace changed while reading the selected path")
        return target
    finally:
        os.close(parent)


def _read_workspace_file(root: Path, path: str, limit: int) -> bytes | None:
    parent, name = _workspace_parent_fd(root, path)
    if parent is None:
        raise WorkspaceGitError("STATUS_STALE", "Workspace changed while reading the selected path")
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            descriptor = os.open(name, flags, dir_fd=parent)
        except FileNotFoundError as error:
            raise WorkspaceGitError("STATUS_STALE", "Workspace changed while reading the selected path") from error
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise WorkspaceGitError("INVALID_PATH", "Selected path is a symbolic link") from error
            raise WorkspaceGitError("GIT_UNAVAILABLE", "Selected path could not be opened") from error
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise WorkspaceGitError("INVALID_PATH", "Selected path is not a regular file")
        if before.st_size > limit:
            return None
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(1024 * 1024, limit + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                return None
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if identity_before != identity_after:
            raise WorkspaceGitError("STATUS_STALE", "Workspace changed while reading the selected path")
        return b"".join(chunks)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _untracked_status(root: Path, path: str) -> tuple[int, bool]:
    try:
        data = _read_workspace_file(root, path, _MAX_DIFF_FILE_BYTES)
    except WorkspaceGitError as error:
        if error.code in {"INVALID_PATH", "STATUS_STALE"}:
            return 0, False
        raise
    if data is None:
        return 0, False
    if b"\0" in data:
        return 0, True
    line_count = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
    return min(line_count, _MAX_DIFF_LINES), False


def _untracked_diff_rows(root: Path, path: str) -> tuple[str, list[dict[str, Any]]]:
    data = _read_workspace_file(root, path, _MAX_DIFF_FILE_BYTES)
    if data is None:
        return "oversized", []
    if b"\0" in data:
        return "binary", []
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return "binary", []
    lines = text.splitlines()
    if len(lines) > _MAX_DIFF_LINES:
        return "oversized", []
    rows: list[dict[str, Any]] = []
    for number, content in enumerate(lines, 1):
        if not _safe_diff_content(content):
            return "binary", []
        if len(content.encode("utf-8")) > _MAX_DIFF_LINE_BYTES:
            return "oversized", []
        rows.append(
            {
                "kind": "addition",
                "old_line": None,
                "new_line": number,
                "content": content,
            }
        )
    return "available", rows


def _parse_unified_diff(raw: bytes) -> tuple[str, list[dict[str, Any]]]:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return "binary", []
    rows: list[dict[str, Any]] = []
    old_line = new_line = 0
    in_hunk = False
    hunk_count = 0
    for line in text.splitlines():
        if line.startswith("@@ "):
            match = re.match(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
            if match is None:
                return "oversized", []
            old_line, new_line = int(match.group(1)), int(match.group(2))
            hunk_count += 1
            issue = _append_diff_row(
                rows,
                {
                    "kind": "header" if hunk_count == 1 else "hunk",
                    "old_line": None,
                    "new_line": None,
                    "content": line,
                },
            )
            if issue is not None:
                return issue, []
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line == r"\ No newline at end of file":
            issue = _append_diff_row(
                rows,
                {
                    "kind": "no_newline",
                    "old_line": None,
                    "new_line": None,
                    "content": "No newline at end of file",
                },
            )
            if issue is not None:
                return issue, []
            continue
        if not line or line[0] not in {" ", "+", "-"}:
            continue
        content = line[1:]
        if not _safe_diff_content(content):
            return "binary", []
        if len(content.encode("utf-8")) > _MAX_DIFF_LINE_BYTES:
            return "oversized", []
        if line[0] == " ":
            kind = "context"
            row_old, row_new = old_line, new_line
            old_line += 1
            new_line += 1
        elif line[0] == "-":
            kind = "deletion"
            row_old, row_new = old_line, None
            old_line += 1
        else:
            kind = "addition"
            row_old, row_new = None, new_line
            new_line += 1
        issue = _append_diff_row(
            rows,
            {
                "kind": kind,
                "old_line": row_old,
                "new_line": row_new,
                "content": content,
            },
        )
        if issue is not None:
            return issue, []
    return "available", rows


def _append_diff_row(rows: list[dict[str, Any]], row: dict[str, Any]) -> str | None:
    content = str(row["content"])
    if not _safe_diff_content(content):
        return "binary"
    if len(content.encode("utf-8")) > _MAX_DIFF_LINE_BYTES or len(rows) >= _MAX_DIFF_LINES:
        return "oversized"
    rows.append(row)
    return None


def _safe_diff_content(value: str) -> bool:
    return all(
        character == "\t" or (ord(character) >= 32 and not 127 <= ord(character) <= 159)
        for character in value
    )


def _safe_text_preview(value: str) -> bool:
    return all(
        character in "\n\r\t" or not (ord(character) < 32 or 127 <= ord(character) <= 159)
        for character in value
    )


def _diff_page(
    path: str,
    side: str,
    availability: str,
    rows: list[dict[str, Any]],
    offset: int,
    limit: int,
) -> dict[str, Any]:
    if availability != "available":
        return _unavailable_diff_page(path, side, availability, offset)
    selected = list(rows[offset : offset + limit])
    while True:
        next_offset = offset + len(selected) if offset + len(selected) < len(rows) else None
        page = {
            "path": path,
            "side": side,
            "availability": "available",
            "offset": offset,
            "lines": selected,
            "next_offset": next_offset,
        }
        if len(json.dumps(page).encode("utf-8")) <= _MAX_DIFF_RESPONSE_BYTES:
            return page
        if not selected:
            return _unavailable_diff_page(path, side, "oversized", offset)
        selected.pop()


def _unavailable_diff_page(path: str, side: str, availability: str, offset: int) -> dict[str, Any]:
    return {
        "path": path,
        "side": side,
        "availability": availability,
        "offset": offset,
        "lines": [],
        "next_offset": None,
    }


def _required_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4_096 or "\0" in value:
        raise WorkspaceGitError("INVALID_PATH", "Selected path is invalid")
    return value


def _required_string(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > limit or "\0" in value:
        raise WorkspaceGitError("INVALID_REQUEST", f"{field} is invalid")
    return value.strip()


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    result = []
    for item in value:
        text = str(item or "").strip()
        if not text or text.startswith("-") or any(character.isspace() for character in text):
            raise ValueError(f"{field} contains an invalid value")
        result.append(text)
    return sorted(set(result))


def _digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _iso(timestamp: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))


def _changed_refs(before: Mapping[str, str], after: Mapping[str, str]) -> list[dict[str, Any]]:
    return [
        {"ref": ref, "before": before.get(ref), "after": after.get(ref)}
        for ref in sorted(set(before) | set(after))
        if before.get(ref) != after.get(ref)
    ]
