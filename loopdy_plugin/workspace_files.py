"""Explicitly granted, read-only workspace file and Git projections."""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Mapping

from .sensitive import SECRET_PATH_RE, SENSITIVE_CREDENTIAL_BYTES_RE
from .workspace_git import WorkspaceGitError, WorkspaceGitService

_MAX_FILE_BYTES = 8 * 1024 * 1024
_MAX_CHUNK_BYTES = 64 * 1024
_MAX_DIRECTORY_ENTRIES = 10_000
_MAX_DIRECTORY_LIMIT = 500
_MAX_DIRECTORY_RESPONSE_BYTES = 160_000
_MAX_GRANTS = 256
_WORKSPACE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
_DRIVE_PATH = re.compile(r"^[A-Za-z]:")
_BLOCKED_COMPONENTS = {
    ".git",
    ".hg",
    ".svn",
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".hermes",
    "keychains",
}
_BLOCKED_FILES = {
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "auth.json",
    "credentials",
}
_SYSTEM_ROOTS = {
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/library",
    "/mnt",
    "/opt",
    "/private",
    "/private/tmp",
    "/private/var",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/system",
    "/sys",
    "/usr",
    "/users",
    "/var",
    "/volumes",
}


class WorkspaceFilesError(RuntimeError):
    """A public, path-redacted workspace Files failure."""

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
class _Grant:
    workspace_id: str
    label: str
    root: Path
    device: int
    inode: int
    generation: str

    @property
    def identity(self) -> tuple[str, str, int, int, str]:
        return (self.workspace_id, str(self.root), self.device, self.inode, self.generation)


class WorkspaceFilesService:
    """Browses only host-local roots explicitly granted through the Files CLI."""

    def __init__(self, state_dir: Path | str) -> None:
        self._require_secure_platform()
        self._state_dir = Path(state_dir)
        try:
            self._state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self._state_dir, 0o700)
        except OSError as error:
            raise WorkspaceFilesError(
                "STATE_UNAVAILABLE", "Workspace Files state is unavailable"
            ) from error
        self._state_path = self._state_dir / "grants.sqlite3"
        self._git_state_path = self._state_dir / "workspace-git.sqlite3"
        try:
            self._ensure_store()
        except sqlite3.Error as error:
            raise WorkspaceFilesError(
                "STATE_UNAVAILABLE", "Workspace Files state is unavailable"
            ) from error

    def capabilities(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "read_only": True,
            "host_grants_only": True,
            "remote_grant_mutation": False,
            "secure_traversal": True,
            "max_file_bytes": _MAX_FILE_BYTES,
            "max_chunk_bytes": _MAX_CHUNK_BYTES,
            "max_directory_page": _MAX_DIRECTORY_LIMIT,
            **self.roots(),
        }

    def grant(self, workspace_id: str, *, root: Path, label: str) -> dict[str, Any]:
        workspace_id = _valid_workspace_id(workspace_id)
        label = _valid_label(label)
        candidate = self._valid_grant_root(root)
        try:
            descriptor = self._open_absolute_directory(candidate)
            try:
                root_stat = os.fstat(descriptor)
            finally:
                os.close(descriptor)
        except OSError as error:
            raise WorkspaceFilesError(
                "INVALID_GRANT", "Workspace root is unavailable"
            ) from error
        with self._database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT root, root_dev, root_ino FROM workspace_file_grants WHERE workspace_id=?",
                (workspace_id,),
            ).fetchone()
            if row is not None and (
                row[0] != str(candidate)
                or int(row[1]) != root_stat.st_dev
                or int(row[2]) != root_stat.st_ino
            ):
                connection.rollback()
                raise WorkspaceFilesError(
                    "GRANT_CONFLICT",
                    "Revoke this workspace before granting a different root",
                )
            if row is None and connection.execute("SELECT COUNT(*) FROM workspace_file_grants").fetchone()[0] >= _MAX_GRANTS:
                raise WorkspaceFilesError("INVALID_GRANT", "Workspace grant limit reached")
            connection.execute(
                "INSERT INTO workspace_file_grants(workspace_id,label,root,root_dev,root_ino,updated_at,generation) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(workspace_id) DO UPDATE SET "
                "label=excluded.label, updated_at=excluded.updated_at",
                (
                    workspace_id,
                    label,
                    str(candidate),
                    root_stat.st_dev,
                    root_stat.st_ino,
                    int(time.time()),
                    uuid.uuid4().hex,
                ),
            )
            connection.commit()
        self._load_grant(workspace_id)
        return {"workspace_id": workspace_id, "label": label, "granted": True}

    def revoke(self, workspace_id: str) -> dict[str, Any]:
        workspace_id = _valid_workspace_id(workspace_id)
        with self._database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "DELETE FROM workspace_file_grants WHERE workspace_id=?", (workspace_id,)
            )
            connection.commit()
        return {"workspace_id": workspace_id, "revoked": cursor.rowcount > 0}

    def roots(self) -> dict[str, Any]:
        with self._database() as connection:
            rows = connection.execute(
                "SELECT workspace_id,label FROM workspace_file_grants ORDER BY workspace_id"
            ).fetchall()
        return {
            "roots": [
                {"workspace_id": str(row[0]), "label": str(row[1])} for row in rows
            ]
        }

    def list_directory(
        self,
        workspace_id: str,
        *,
        path: str = "",
        offset: int = 0,
        limit: int = 100,
        query: str = "",
        revision: str | None = None,
    ) -> dict[str, Any]:
        grant = self._load_grant(workspace_id)
        path = _valid_relative_path(path, allow_root=True)
        offset, limit = _valid_page(offset, limit, maximum=_MAX_DIRECTORY_LIMIT)
        query = _valid_query(query)
        if offset and not revision:
            raise WorkspaceFilesError(
                "REVISION_REQUIRED", "Directory revision is required after the first page"
            )
        root_descriptor = self._open_grant_root(grant)
        directory_descriptor = -1
        try:
            directory_descriptor = self._open_directory_from_root(
                root_descriptor, path
            )
            before = os.fstat(directory_descriptor)
            entries: list[dict[str, Any]] = []
            scanned = 0
            with os.scandir(directory_descriptor) as iterator:
                for item in iterator:
                    scanned += 1
                    if scanned > _MAX_DIRECTORY_ENTRIES:
                        raise WorkspaceFilesError(
                            "DIRECTORY_OVERSIZED",
                            "Directory exceeds the workspace browsing safety limit",
                        )
                    name = item.name
                    if not _safe_name(name):
                        continue
                    relative = f"{path}/{name}" if path else name
                    if _protected_path(relative):
                        continue
                    try:
                        entry_stat = item.stat(follow_symlinks=False)
                    except FileNotFoundError as error:
                        raise WorkspaceFilesError(
                            "REVISION_STALE", "Directory changed while it was being listed"
                        ) from error
                    if stat.S_ISDIR(entry_stat.st_mode):
                        kind = "directory"
                        size: int | None = None
                    elif stat.S_ISREG(entry_stat.st_mode) and entry_stat.st_nlink == 1:
                        kind = "file"
                        size = int(entry_stat.st_size)
                    else:
                        continue
                    if query and query.casefold() not in name.casefold():
                        continue
                    entries.append(
                        {
                            "name": name,
                            "path": relative,
                            "kind": kind,
                            "size": size,
                            "_identity": (
                                entry_stat.st_dev,
                                entry_stat.st_ino,
                                entry_stat.st_mode,
                                entry_stat.st_size,
                                entry_stat.st_mtime_ns,
                                entry_stat.st_ctime_ns,
                            ),
                        }
                    )
            after = os.fstat(directory_descriptor)
            if not _same_stat(before, after):
                raise WorkspaceFilesError(
                    "REVISION_STALE", "Directory changed while it was being listed"
                )
            try:
                check_descriptor = self._open_directory_from_root(root_descriptor, path)
                try:
                    if not _same_stat(before, os.fstat(check_descriptor)):
                        raise WorkspaceFilesError(
                            "REVISION_STALE", "Directory changed while it was being listed"
                        )
                finally:
                    os.close(check_descriptor)
            except OSError as error:
                raise WorkspaceFilesError(
                    "REVISION_STALE", "Directory changed while it was being listed"
                ) from error
            entries.sort(
                key=lambda item: (
                    item["kind"] != "directory",
                    str(item["name"]).casefold(),
                    str(item["name"]),
                )
            )
            current_revision = _directory_revision(path, query, before, entries)
            if revision is not None and revision != current_revision:
                raise WorkspaceFilesError(
                    "REVISION_STALE", "Directory changed; request the first page again"
                )
            total = len(entries)
            selected = entries[offset : offset + limit]
            public_entries = [
                {key: value for key, value in item.items() if key != "_identity"}
                for item in selected
            ]
            response = {
                "workspace_id": grant.workspace_id,
                "path": path,
                "parent": _parent_path(path),
                "revision": current_revision,
                "offset": offset,
                "limit": limit,
                "total": total,
                "entries": public_entries,
                "next_offset": (
                    offset + len(public_entries)
                    if offset + len(public_entries) < total
                    else None
                ),
            }
            _bound_directory_response(response)
            self._revalidate_grant(grant)
            return response
        except WorkspaceFilesError:
            raise
        except FileNotFoundError as error:
            raise WorkspaceFilesError(
                "PATH_NOT_FOUND", "Workspace directory was not found"
            ) from error
        except NotADirectoryError as error:
            raise WorkspaceFilesError(
                "INVALID_PATH", "Selected workspace path is not a directory"
            ) from error
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise WorkspaceFilesError(
                    "INVALID_PATH", "Workspace path crosses a symbolic link"
                ) from error
            raise WorkspaceFilesError(
                "FILES_UNAVAILABLE", "Workspace directory could not be listed"
            ) from error
        finally:
            if directory_descriptor >= 0:
                os.close(directory_descriptor)
            os.close(root_descriptor)

    def read_file(
        self,
        workspace_id: str,
        *,
        path: str,
        offset: int = 0,
        limit: int = _MAX_CHUNK_BYTES,
        revision: str | None = None,
    ) -> dict[str, Any]:
        grant = self._load_grant(workspace_id)
        path = _valid_relative_path(path)
        offset, limit = _valid_page(offset, limit, maximum=_MAX_CHUNK_BYTES)
        if offset and not revision:
            raise WorkspaceFilesError(
                "REVISION_REQUIRED", "File revision is required after the first page"
            )
        root_descriptor = self._open_grant_root(grant)
        descriptor = -1
        parent_descriptor = -1
        try:
            parent_descriptor, name = self._open_parent_from_root(root_descriptor, path)
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=parent_descriptor,
                )
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise WorkspaceFilesError(
                        "INVALID_PATH", "Workspace path is a symbolic link"
                    ) from error
                raise
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise WorkspaceFilesError(
                    "INVALID_PATH", "Selected workspace path is not a regular file"
                )
            if before.st_nlink != 1:
                raise WorkspaceFilesError(
                    "HARD_LINK_UNSAFE", "Hard-linked workspace files cannot be read"
                )
            if before.st_size > _MAX_FILE_BYTES:
                self._revalidate_file_path(root_descriptor, path, before)
                response = {
                    "workspace_id": grant.workspace_id,
                    "path": path,
                    "availability": "oversized",
                    "size": int(before.st_size),
                    "max_file_bytes": _MAX_FILE_BYTES,
                    "offset": offset,
                    "data": "",
                    "text": None,
                    "revision": None,
                    "next_offset": None,
                }
                self._revalidate_grant(grant)
                return response
            content = _read_descriptor(descriptor, _MAX_FILE_BYTES)
            after = os.fstat(descriptor)
            if not _same_stat(before, after):
                raise WorkspaceFilesError(
                    "REVISION_STALE", "File changed while it was being read"
                )
            self._revalidate_file_path(root_descriptor, path, before)
            digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
            if revision is not None and revision != digest:
                raise WorkspaceFilesError(
                    "REVISION_STALE", "File changed; request the first page again"
                )
            if SENSITIVE_CREDENTIAL_BYTES_RE.search(content):
                raise WorkspaceFilesError(
                    "SECRET_SCAN_BLOCKED",
                    "File content requires local review before it can be returned",
                )
            selected = content[offset : offset + limit]
            try:
                complete_text = content.decode("utf-8", "strict")
                binary = b"\0" in content
            except UnicodeDecodeError:
                complete_text = ""
                binary = True
            complete = offset == 0 and len(selected) == len(content)
            response = {
                "workspace_id": grant.workspace_id,
                "path": path,
                "availability": "binary" if binary else "available",
                "size": len(content),
                "offset": offset,
                "data": base64.b64encode(selected).decode("ascii"),
                "text": complete_text if complete and not binary else None,
                "revision": digest,
                "next_offset": (
                    offset + len(selected)
                    if offset + len(selected) < len(content)
                    else None
                ),
            }
            if len(json.dumps(response).encode("utf-8")) > 196_608:
                response["text"] = None
            self._revalidate_grant(grant)
            return response
        except WorkspaceFilesError:
            raise
        except FileNotFoundError as error:
            raise WorkspaceFilesError(
                "PATH_NOT_FOUND", "Workspace file was not found"
            ) from error
        except OSError as error:
            raise WorkspaceFilesError(
                "FILES_UNAVAILABLE", "Workspace file could not be read"
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if parent_descriptor >= 0:
                os.close(parent_descriptor)
            os.close(root_descriptor)

    def git_status(self, workspace_id: str) -> dict[str, Any]:
        grant = self._load_grant(workspace_id)
        self._revalidate_grant(grant)
        service = self._git_service(grant)
        try:
            result = service.status(grant.workspace_id)
        except WorkspaceGitError as error:
            raise _files_git_error(error) from error
        result = _sanitize_git_status(result)
        self._revalidate_grant(grant)
        return result

    def git_diff(
        self,
        workspace_id: str,
        *,
        path: str,
        side: str,
        expected_status_token: str,
        offset: int = 0,
        limit: int = 300,
    ) -> dict[str, Any]:
        grant = self._load_grant(workspace_id)
        path = _valid_relative_path(path)
        offset, limit = _valid_page(offset, limit, maximum=500)
        if side not in {"staged", "worktree"}:
            raise WorkspaceFilesError("INVALID_REQUEST", "Diff side is invalid")
        if (
            not isinstance(expected_status_token, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", expected_status_token) is None
        ):
            raise WorkspaceFilesError(
                "INVALID_REQUEST", "Expected status token is invalid"
            )
        self._reject_unsafe_existing_file(grant, path)
        service = self._git_service(grant)
        try:
            visible_status = _sanitize_git_status(service.status(grant.workspace_id))
            if path not in {item["path"] for item in visible_status["files"]}:
                raise WorkspaceFilesError("PATH_PROTECTED", "Path is not available for diff inspection")
            requested = service.diff(
                grant.workspace_id,
                path=path,
                side=side,
                expected_status_token=expected_status_token,
                offset=offset,
                limit=limit,
                reject_sensitive_content=True,
            )
        except WorkspaceGitError as error:
            raise _files_git_error(error) from error
        self._revalidate_grant(grant)
        return requested

    def _git_service(self, grant: _Grant) -> WorkspaceGitService:
        try:
            return WorkspaceGitService(
                [
                    {
                        "workspace_id": grant.workspace_id,
                        "label": grant.label,
                        "root": str(grant.root),
                        "visibility": "private",
                        "operations": ["status"],
                        "remotes": [],
                        "branches": [],
                        "mutations_enabled": False,
                    }
                ],
                state_path=self._git_state_path,
            )
        except (OSError, ValueError, WorkspaceGitError, sqlite3.Error) as error:
            raise WorkspaceFilesError(
                "GIT_UNAVAILABLE", "Workspace is not an available Git repository"
            ) from error

    def _reject_unsafe_existing_file(self, grant: _Grant, path: str) -> None:
        root_descriptor = self._open_grant_root(grant)
        parent_descriptor = -1
        try:
            parent_descriptor, name = self._open_parent_from_root(root_descriptor, path)
            try:
                entry = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return
            if stat.S_ISLNK(entry.st_mode):
                raise WorkspaceFilesError(
                    "INVALID_PATH", "Workspace path is a symbolic link"
                )
            if stat.S_ISREG(entry.st_mode) and entry.st_nlink != 1:
                raise WorkspaceFilesError(
                    "HARD_LINK_UNSAFE", "Hard-linked workspace files cannot be reviewed"
                )
            if not stat.S_ISREG(entry.st_mode):
                raise WorkspaceFilesError(
                    "INVALID_PATH", "Selected workspace path is not a regular file"
                )
        except FileNotFoundError:
            # A tracked deletion may remove its entire parent directory.
            return
        except OSError as error:
            raise WorkspaceFilesError("INVALID_PATH", "Workspace path is unavailable for review") from error
        finally:
            if parent_descriptor >= 0:
                os.close(parent_descriptor)
            os.close(root_descriptor)

    def _revalidate_file_path(
        self,
        root_descriptor: int,
        path: str,
        expected: os.stat_result,
    ) -> None:
        parent_descriptor = -1
        try:
            parent_descriptor, name = self._open_parent_from_root(root_descriptor, path)
            current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except OSError as error:
            raise WorkspaceFilesError(
                "REVISION_STALE", "File changed while it was being read"
            ) from error
        finally:
            if parent_descriptor >= 0:
                os.close(parent_descriptor)
        if not _same_stat(expected, current):
            raise WorkspaceFilesError(
                "REVISION_STALE", "File changed while it was being read"
            )

    def _valid_grant_root(self, root: Path) -> Path:
        if not isinstance(root, Path):
            root = Path(root)
        if not root.is_absolute():
            raise WorkspaceFilesError(
                "INVALID_GRANT", "Workspace root must be an absolute path"
            )
        try:
            resolved = root.resolve(strict=True)
        except OSError as error:
            raise WorkspaceFilesError(
                "INVALID_GRANT", "Workspace root is unavailable"
            ) from error
        if Path(os.path.abspath(os.fspath(root))) != resolved or not resolved.is_dir():
            raise WorkspaceFilesError(
                "INVALID_GRANT", "Workspace root must be a real directory without symbolic links"
            )
        normalized = str(resolved).rstrip("/").casefold() or "/"
        home = Path.home().resolve()
        if normalized in _SYSTEM_ROOTS or resolved == home:
            raise WorkspaceFilesError(
                "INVALID_GRANT", "This directory cannot be granted as a workspace root"
            )
        if _credential_root(resolved, home) or _protected_path(str(resolved)):
            raise WorkspaceFilesError(
                "INVALID_GRANT", "Credential and control directories cannot be granted"
            )
        try:
            self._state_dir.resolve().relative_to(resolved)
        except ValueError:
            pass
        else:
            raise WorkspaceFilesError(
                "INVALID_GRANT", "Workspace Files state cannot be inside a granted root"
            )
        return resolved

    def _load_grant(self, workspace_id: str) -> _Grant:
        workspace_id = _valid_workspace_id(workspace_id)
        with self._database() as connection:
            row = connection.execute(
                "SELECT workspace_id,label,root,root_dev,root_ino,generation "
                "FROM workspace_file_grants WHERE workspace_id=?",
                (workspace_id,),
            ).fetchone()
        if row is None:
            raise WorkspaceFilesError(
                "WORKSPACE_NOT_ALLOWED", "This workspace has no host grant"
            )
        grant = _Grant(
            workspace_id=str(row[0]),
            label=str(row[1]),
            root=Path(str(row[2])),
            device=int(row[3]),
            inode=int(row[4]),
            generation=str(row[5]),
        )
        descriptor = self._open_grant_root(grant)
        os.close(descriptor)
        return grant

    def _revalidate_grant(self, expected: _Grant) -> None:
        current = self._load_grant(expected.workspace_id)
        if current.identity != expected.identity:
            raise WorkspaceFilesError(
                "WORKSPACE_NOT_ALLOWED", "Workspace grant changed during the request"
            )

    def _open_grant_root(self, grant: _Grant) -> int:
        try:
            descriptor = self._open_absolute_directory(grant.root)
            current = os.fstat(descriptor)
        except OSError as error:
            raise WorkspaceFilesError(
                "WORKSPACE_NOT_ALLOWED", "Granted workspace is unavailable"
            ) from error
        if (current.st_dev, current.st_ino) != (grant.device, grant.inode):
            os.close(descriptor)
            raise WorkspaceFilesError(
                "WORKSPACE_NOT_ALLOWED", "Granted workspace identity changed"
            )
        return descriptor

    @staticmethod
    def _open_absolute_directory(path: Path) -> int:
        return os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )

    @staticmethod
    def _open_directory_from_root(root_descriptor: int, path: str) -> int:
        current = os.dup(root_descriptor)
        try:
            for component in PurePosixPath(path).parts if path else ():
                following = os.open(
                    component,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    dir_fd=current,
                )
                os.close(current)
                current = following
            return current
        except Exception:
            os.close(current)
            raise

    @classmethod
    def _open_parent_from_root(
        cls, root_descriptor: int, path: str
    ) -> tuple[int, str]:
        parts = PurePosixPath(path).parts
        parent_path = "/".join(parts[:-1])
        return cls._open_directory_from_root(root_descriptor, parent_path), parts[-1]

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._state_path, timeout=10)
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            with connection:
                yield connection
        except WorkspaceFilesError:
            raise
        except sqlite3.Error as error:
            raise WorkspaceFilesError(
                "STATE_UNAVAILABLE", "Workspace Files state is unavailable"
            ) from error
        finally:
            if connection is not None:
                connection.close()

    def _ensure_store(self) -> None:
        with self._database() as connection:
            with connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS workspace_file_grants ("
                    "workspace_id TEXT PRIMARY KEY, label TEXT NOT NULL, root TEXT NOT NULL, "
                    "root_dev INTEGER NOT NULL, root_ino INTEGER NOT NULL, updated_at INTEGER NOT NULL, "
                    "generation TEXT NOT NULL)"
                )
        try:
            os.chmod(self._state_path, 0o600)
        except OSError as error:
            raise WorkspaceFilesError(
                "STATE_UNAVAILABLE", "Workspace Files state is unavailable"
            ) from error

    @staticmethod
    def _require_secure_platform() -> None:
        required = (
            os.name == "posix"
            and hasattr(os, "O_NOFOLLOW")
            and hasattr(os, "O_DIRECTORY")
            and os.open in os.supports_dir_fd
            and os.stat in os.supports_dir_fd
            and os.stat in os.supports_follow_symlinks
            and os.scandir in os.supports_fd
        )
        if not required:
            raise WorkspaceFilesError(
                "CAPABILITY_UNSUPPORTED",
                "Secure workspace traversal is unavailable on this platform",
            )


def _valid_workspace_id(value: Any) -> str:
    if not isinstance(value, str) or _WORKSPACE_ID.fullmatch(value) is None:
        raise WorkspaceFilesError("INVALID_REQUEST", "workspace_id is invalid")
    return value


def _valid_label(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > 120
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise WorkspaceFilesError("INVALID_REQUEST", "label is invalid")
    return value.strip()


def _valid_relative_path(value: Any, *, allow_root: bool = False) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 4096:
        raise WorkspaceFilesError("INVALID_PATH", "Workspace path is invalid")
    if value == "" and allow_root:
        return value
    if (
        not value
        or value.startswith(("/", "\\"))
        or _DRIVE_PATH.match(value)
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise WorkspaceFilesError("INVALID_PATH", "Workspace path is invalid")
    parts = value.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise WorkspaceFilesError("INVALID_PATH", "Workspace path is invalid")
    if _protected_path(value):
        raise WorkspaceFilesError("PATH_PROTECTED", "Workspace path is protected")
    return value


def _valid_query(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > 256
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise WorkspaceFilesError("INVALID_REQUEST", "Directory query is invalid")
    return value


def _valid_page(offset: Any, limit: Any, *, maximum: int) -> tuple[int, int]:
    if (
        isinstance(offset, bool)
        or not isinstance(offset, int)
        or offset < 0
        or offset > _MAX_FILE_BYTES
        or isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= maximum
    ):
        raise WorkspaceFilesError("INVALID_REQUEST", "Requested page is invalid")
    return offset, limit


def _safe_name(name: str) -> bool:
    try:
        name.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return False
    return bool(name) and "/" not in name and "\\" not in name and all(
        ord(character) >= 32 and ord(character) != 127 for character in name
    )


def _protected_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    parts = [part.casefold() for part in normalized.split("/") if part]
    return (
        any(part in _BLOCKED_COMPONENTS for part in parts)
        or any(part in _BLOCKED_FILES for part in parts)
        or any(SECRET_PATH_RE.search(part) for part in parts)
        or bool(SENSITIVE_CREDENTIAL_BYTES_RE.search(normalized.encode("utf-8")))
    )


def _credential_root(root: Path, home: Path) -> bool:
    for relative in (
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".kube",
        ".docker",
        ".hermes",
        "Library/Keychains",
    ):
        candidate = home / relative
        try:
            root.relative_to(candidate)
            return True
        except ValueError:
            continue
    return False


def _same_stat(before: os.stat_result, after: os.stat_result) -> bool:
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


def _directory_revision(
    path: str,
    query: str,
    directory: os.stat_result,
    entries: list[dict[str, Any]],
) -> str:
    digest = hashlib.sha256()
    digest.update(path.encode("utf-8"))
    digest.update(b"\0")
    digest.update(query.encode("utf-8"))
    digest.update(b"\0")
    digest.update(
        repr(
            (
                directory.st_dev,
                directory.st_ino,
                directory.st_mtime_ns,
                directory.st_ctime_ns,
            )
        ).encode("ascii")
    )
    for item in entries:
        digest.update(str(item["name"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(item["kind"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(repr(item["_identity"]).encode("ascii"))
        digest.update(b"\0")
    return f"sha256:{digest.hexdigest()}"


def _parent_path(path: str) -> str | None:
    if not path:
        return None
    parent = str(PurePosixPath(path).parent)
    return "" if parent == "." else parent


def _bound_directory_response(response: dict[str, Any]) -> None:
    entries = response["entries"]
    while len(json.dumps(response, ensure_ascii=False).encode("utf-8")) > _MAX_DIRECTORY_RESPONSE_BYTES:
        if not entries:
            raise WorkspaceFilesError(
                "DIRECTORY_OVERSIZED", "Directory page exceeds the response safety limit"
            )
        entries.pop()
        response["next_offset"] = response["offset"] + len(entries)


def _read_descriptor(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise WorkspaceFilesError(
                "REVISION_STALE", "File changed while it was being read"
            )


def _sanitize_git_status(result: dict[str, Any]) -> dict[str, Any]:
    if not result.get("files_page", {}).get("complete", True) or not result.get("conflicts_page", {}).get("complete", True):
        raise WorkspaceFilesError("GIT_STATUS_OVERSIZED", "Git status exceeds the workspace inspection limit")
    original_count = len(result.get("files") or [])
    visible = []
    for item in result.get("files") or []:
        path = str(item.get("path") or "")
        original = str(item.get("original_path") or "")
        try:
            _valid_relative_path(path)
            if original:
                _valid_relative_path(original)
        except WorkspaceFilesError:
            continue
        visible.append(item)
    result["files"] = visible
    result["conflicts"] = [
        path
        for path in (result.get("conflicts") or [])
        if isinstance(path, str) and not _protected_path(path) and _safe_status_path(path)
    ]
    result["changes"] = {
        "files": len(visible),
        "insertions": sum(int(item.get("insertions") or 0) for item in visible),
        "deletions": sum(int(item.get("deletions") or 0) for item in visible),
    }
    result["hidden_files"] = original_count - len(visible)
    files_page = dict(result.get("files_page") or {})
    files_page.update(
        {
            "offset": 0,
            "returned": len(visible),
            "total": len(visible),
            "next_offset": None,
            "complete": True,
        }
    )
    result["files_page"] = files_page
    conflicts_page = dict(result.get("conflicts_page") or {})
    conflicts_page.update(
        {
            "offset": 0,
            "returned": len(result["conflicts"]),
            "total": len(result["conflicts"]),
            "next_offset": None,
            "complete": True,
        }
    )
    result["conflicts_page"] = conflicts_page
    return result


def _safe_status_path(path: str) -> bool:
    try:
        _valid_relative_path(path)
        return True
    except WorkspaceFilesError:
        return False


def _files_git_error(error: WorkspaceGitError) -> WorkspaceFilesError:
    code = error.code
    if code == "WORKSPACE_NOT_ALLOWED":
        code = "GIT_UNAVAILABLE"
    return WorkspaceFilesError(code, error.message, retryable=error.retryable)


__all__ = ["WorkspaceFilesError", "WorkspaceFilesService"]
