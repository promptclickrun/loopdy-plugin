"""Owner-scoped Wiki files and explicit account-authorized connection; no runtime dependencies.

All cooperating processes must use the same private state directory. Saves use
an advisory process lock, an append-only SQLite recovery journal, and a durable
same-directory replacement. These are optimistic saves, NOT filesystem CAS:
an unrelated writer can race the last check, rename, or readback. No restart
path retries a replacement. An interrupted committing operation is indeterminate.

Wiki revisions are opaque ``wiki-v1:<grant generation>:<sha256 hex>`` tokens.
Their digest has the Files byte/directory semantics; generation binding prevents
an old draft or page cursor from surviving revoke/regrant at the same path.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
import time
import uuid
import unicodedata
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterator

try:
    import fcntl
except ImportError:  # Read traversal may be available without safe write locking.
    fcntl = None

from .workspace_files import (
    WorkspaceFilesError,
    WorkspaceFilesService,
    _Grant,
    _read_descriptor,
    _same_stat,
    _valid_label,
    _valid_relative_path,
    _valid_workspace_id,
)
from .sensitive import SENSITIVE_CREDENTIAL_BYTES_RE

_MAX_EDIT_BYTES = 1024 * 1024
_MAX_RECOVERY_BYTES = 128 * 1024 * 1024
_MAX_OPERATIONS = 1024
_MAX_GRANTS = 256
_MAX_NATIVE_DISCONNECTS = 1024
_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REVISION = re.compile(r"wiki-v1:([0-9a-f]{32}):([0-9a-f]{64})\Z")
_TERMINAL = {"committed", "conflict", "failed", "indeterminate"}
_SOURCE_KINDS = {"files", "generated", "mirror", "export"}


class WikiServiceError(WorkspaceFilesError):
    """Path-redacted error with code/message/retryable/details and envelope()."""


def _opaque(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > 256
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise WikiServiceError("INVALID_REQUEST", f"{field} is required and must be valid")
    return value  # Do not normalize authority, profile, or device identities.


def _operation_id(value: Any) -> str:
    if not isinstance(value, str) or _OPERATION_ID.fullmatch(value) is None:
        raise WikiServiceError("INVALID_REQUEST", "operationId is invalid")
    return value


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _revision(generation: str, content: bytes) -> str:
    return f"wiki-v1:{generation}:{_sha(content)}"


def _creation_revision(value: str, generation: str) -> bool:
    """An explicit absent-file precondition, bound to the current grant epoch."""
    if isinstance(value, str) and value.startswith("wiki-new-v1:"):
        if value != f"wiki-new-v1:{generation}":
            raise WikiServiceError("REVISION_STALE", "Wiki creation grant changed")
        return True
    _raw_revision(value, generation)
    return False


def _raw_revision(value: Any, generation: str) -> str | None:
    if value is None:
        return None
    match = _REVISION.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise WikiServiceError("INVALID_REQUEST", "revision is invalid")
    if match[1] != generation:
        raise WikiServiceError("REVISION_STALE", "Wiki grant generation changed")
    return f"sha256:{match[2]}"


def _request_digest(values: tuple[Any, ...]) -> str:
    return _sha(json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode("ascii"))


def _markdown(content: bytes) -> None:
    if len(content) > _MAX_EDIT_BYTES:
        raise WikiServiceError("FILE_OVERSIZED", "Editable Markdown is limited to 1 MiB")
    try:
        content.decode("utf-8", "strict")
    except UnicodeError:
        raise WikiServiceError("UNSUPPORTED_CONTENT", "Editing requires UTF-8 Markdown") from None
    if b"\0" in content:
        raise WikiServiceError("UNSUPPORTED_CONTENT", "Binary files cannot be edited")
    if SENSITIVE_CREDENTIAL_BYTES_RE.search(content):
        raise WikiServiceError("SECRET_SCAN_BLOCKED", "Content requires host-local review")


@lru_cache(maxsize=1)
def _darwin_acl_api():
    import ctypes
    library = ctypes.CDLL(None, use_errno=True)
    library.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    library.acl_get_fd_np.restype = ctypes.c_void_p
    library.acl_valid.argtypes = [ctypes.c_void_p]
    library.acl_valid.restype = ctypes.c_int
    library.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    library.acl_get_entry.restype = ctypes.c_int
    library.acl_free.argtypes = [ctypes.c_void_p]
    library.acl_free.restype = ctypes.c_int
    library.flistxattr.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    library.flistxattr.restype = ctypes.c_ssize_t
    return library


def _require_plain_metadata(descriptor: int) -> None:
    """Replacement must not discard ACLs, resource forks or other metadata.

    Refuse rather than weaken permissions until faithful metadata preservation
    is implemented. Linux POSIX ACLs are xattrs; Darwin ACLs need its public API.
    """
    message = "Extended file metadata requires host-local editing"
    try:
        if sys.platform == "darwin":
            import ctypes
            library = _darwin_acl_api()
            # Python exposes os.listxattr on Linux, not on all Darwin builds.
            # Query the public fd-based Darwin API without resolving a path.
            if library.flistxattr(descriptor, None, 0, 0) != 0:
                raise WikiServiceError("READ_ONLY", message)
            ctypes.set_errno(0)
            acl = library.acl_get_fd_np(descriptor, 0x00000100)  # ACL_TYPE_EXTENDED
            if not acl:
                # Darwin reports ENOENT for no extended ACL on a valid open fd.
                # The surrounding snapshot checks file/path identity separately.
                if ctypes.get_errno() == errno.ENOENT:
                    return
                raise WikiServiceError("READ_ONLY", message)
            try:
                if library.acl_valid(acl) != 0:
                    raise WikiServiceError("READ_ONLY", message)
                entry = ctypes.c_void_p()
                ctypes.set_errno(0)
                result = library.acl_get_entry(acl, 0, ctypes.byref(entry))  # ACL_FIRST_ENTRY
                # Darwin returns 0 for an entry and EINVAL when an empty, valid
                # ACL has no first entry. Other results do not prove safety.
                if result != -1 or ctypes.get_errno() != errno.EINVAL:
                    raise WikiServiceError("READ_ONLY", message)
            finally:
                library.acl_free(acl)
        else:
            list_attributes = getattr(os, "listxattr", None)
            if list_attributes is None or list_attributes(descriptor):
                raise WikiServiceError("READ_ONLY", message)
    except (AttributeError, OSError, TypeError, ValueError):
        raise WikiServiceError("READ_ONLY", message) from None


def _absolute_directory(path: Path) -> int:
    """Walk every absolute ancestor, unlike O_NOFOLLOW on the final path only."""
    if not path.is_absolute() or ".." in path.parts:
        raise WikiServiceError("INVALID_PATH", "An absolute, non-traversing directory is required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            following = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = following
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _lexically_contains(parent: Path, child: Path) -> bool:
    """Conservative across case/Unicode-insensitive host filesystems.

    A false positive on a case-sensitive volume denies setup rather than
    allowing an alternate spelling to cross an authority boundary.
    """
    def parts(path):
        return tuple(unicodedata.normalize("NFC", part).casefold() for part in path.parts)
    prefix, candidate = parts(parent), parts(child)
    return candidate[:len(prefix)] == prefix


def _directory_lineage(path: Path) -> tuple[tuple[int, int], ...]:
    """Actual ancestor identities, walking without following symbolic links."""
    if not path.is_absolute() or ".." in path.parts:
        raise WikiServiceError("INVALID_PATH", "An absolute directory is required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    identities = []
    try:
        current = os.fstat(descriptor)
        identities.append((current.st_dev, current.st_ino))
        for part in path.parts[1:]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
            current = os.fstat(descriptor)
            identities.append((current.st_dev, current.st_ino))
        return tuple(identities)
    finally:
        os.close(descriptor)


def _overlaps_root(candidate: Path, lineage: tuple[tuple[int, int], ...], root: Path,
                   pinned: tuple[int, int] | None = None) -> bool:
    if _lexically_contains(root, candidate) or _lexically_contains(candidate, root):
        return True
    # Pinned identity remains protective even when the original grant path was
    # renamed or is unavailable; a spelling/rename must not adopt that inode.
    if pinned is not None and pinned in lineage:
        return True
    try:
        root_lineage = _directory_lineage(root)
    except OSError:
        return False  # Lexical and pinned checks above still apply to stale roots.
    return root_lineage[-1] in lineage or lineage[-1] in root_lineage


class _Reader(WorkspaceFilesService):
    """Reuse Files I/O, not its constructor, grants, database, or Git surface."""

    _open_absolute_directory = staticmethod(_absolute_directory)

    def _include_directory_entry(self, path: str) -> bool:
        # WikiNavigation rejects hidden components and colons in every returned path.
        return ":" not in path and not any(part.startswith(".") for part in path.split("/"))

    def __init__(self, service: WikiService, connection: sqlite3.Connection, row: sqlite3.Row | None):
        self.service = service
        self.connection = connection
        self.row = row
        self._state_dir = service._state_dir

    def _load_grant(self, workspace_id: str) -> _Grant:
        if self.row is None or workspace_id != self.row["wiki_id"]:
            raise WikiServiceError("WIKI_NOT_ALLOWED", "Wiki is not authorized")
        self.service._revalidate(self.connection, self.row)
        return _Grant(
            workspace_id, self.row["label"], Path(self.row["root"]),
            self.row["root_dev"], self.row["root_ino"], self.row["generation"],
        )


class WikiService:
    """Separate Wiki grants and durable, owner-scoped save operations.

    The trusted integration supplies either Link device authority or native
    principal authority and verifies the profile on EVERY request. Host
    grant/revoke is separate from native connect/disconnect. The state directory is private
    host control data; neither a Wiki root nor an existing Files grant store.
    """

    def __init__(self, state_dir: Path, *, authority_id: str,
                 owner_check: Callable[[], None] | None = None,
                 protected_roots: tuple[Path, ...] = (),
                 principal_id: str | None = None):
        self._owner_check = owner_check
        self._protected_roots = protected_roots
        try:
            self._authority_id = _opaque(authority_id, "authorityId")
            self._principal_id = None if principal_id is None else _opaque(principal_id, "principalId")
            self._owner_kind = "link_device" if principal_id is None else "native_principal"
            WorkspaceFilesService._require_secure_platform()
            self._state_dir = Path(state_dir)
            if not self._state_dir.is_absolute() or ".." in self._state_dir.parts:
                raise WikiServiceError("STATE_UNAVAILABLE", "Wiki state requires an absolute directory")
            # Create missing ancestors through descriptors; never follow links or
            # chmod preexisting directories, including a fresh plugin-data tree.
            parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                for part in self._state_dir.parts[1:]:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=parent)
                        os.fsync(parent)
                    except FileExistsError:
                        pass
                    following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                        dir_fd=parent)
                    os.close(parent)
                    parent = following
            finally:
                os.close(parent)
            descriptor = _absolute_directory(self._state_dir)
            try:
                current = os.fstat(descriptor)
                self._private_directory(current)
                self._state_identity = (current.st_dev, current.st_ino)
            finally:
                os.close(descriptor)
            self._state_path = self._state_dir / "wiki.sqlite3"
            self._can_write = bool(
                fcntl is not None
                and os.rename in os.supports_dir_fd
                and os.unlink in os.supports_dir_fd
            )
            with self._locked() as connection:
                self._ensure_store(connection)
        except WorkspaceFilesError as error:
            raise WikiServiceError(error.code, error.message, retryable=error.retryable) from None
        except (OSError, sqlite3.Error):
            raise WikiServiceError("STATE_UNAVAILABLE", "Wiki state is unavailable") from None
        except (TypeError, ValueError, UnicodeError):
            raise WikiServiceError("INVALID_REQUEST", "Wiki configuration is invalid") from None

    @staticmethod
    def _private_directory(current: os.stat_result) -> None:
        if current.st_uid != os.geteuid() or stat.S_IMODE(current.st_mode) & 0o077:
            raise WikiServiceError("STATE_UNAVAILABLE", "Wiki state must be private to the host user")

    @staticmethod
    def _private_file(current: os.stat_result) -> None:
        if (
            not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
            or current.st_uid != os.geteuid() or stat.S_IMODE(current.st_mode) & 0o077
        ):
            raise WikiServiceError("STATE_UNAVAILABLE", "Wiki state file is unsafe")

    @contextmanager
    def _locked(self) -> Iterator[sqlite3.Connection]:
        """One advisory lock across instances/processes sharing this state root.

        SQLite transactions alone cannot serialize the filesystem replacement
        across the separate durable prepared/committing/committed transactions.
        """
        directory = lock = -1
        connection = None
        try:
            directory = _absolute_directory(self._state_dir)
            current = os.fstat(directory)
            self._private_directory(current)
            if (current.st_dev, current.st_ino) != self._state_identity:
                raise WikiServiceError("STATE_UNAVAILABLE", "Wiki state identity changed")
            new_lock = False
            flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            try:
                lock = os.open("wiki.lock", flags, dir_fd=directory)
            except FileNotFoundError:
                if hasattr(self, "_lock_identity"):
                    raise WikiServiceError("STATE_UNAVAILABLE", "Wiki lock is missing") from None
                try:
                    lock = os.open("wiki.lock", flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
                    new_lock = True
                except FileExistsError:
                    lock = os.open("wiki.lock", flags, dir_fd=directory)
            lock_stat = os.fstat(lock)
            self._private_file(lock_stat)
            identity = (lock_stat.st_dev, lock_stat.st_ino)
            if identity != getattr(self, "_lock_identity", identity):
                raise WikiServiceError("STATE_UNAVAILABLE", "Wiki lock identity changed")
            self._lock_identity = identity
            if fcntl is not None:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise WikiServiceError("STATE_BUSY", "Wiki is busy", retryable=True) from None
                        time.sleep(0.025)
            # Never let SQLite follow a pre-existing database/sidecar symlink.
            for name in ("wiki.sqlite3", "wiki.sqlite3-journal", "wiki.sqlite3-wal", "wiki.sqlite3-shm"):
                try:
                    entry = os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    if name != "wiki.sqlite3":
                        continue
                    if not new_lock or hasattr(self, "_database_identity"):
                        raise WikiServiceError("STATE_UNAVAILABLE", "Wiki journal is missing") from None
                    fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                    try:
                        entry = os.fstat(fd)
                    finally:
                        os.close(fd)
                self._private_file(entry)
                if name == "wiki.sqlite3":
                    identity = (entry.st_dev, entry.st_ino)
                    if identity != getattr(self, "_database_identity", identity):
                        raise WikiServiceError("STATE_UNAVAILABLE", "Wiki journal identity changed")
                    self._database_identity = identity
            os.fsync(directory)
            connection = sqlite3.connect(self._state_path, timeout=10)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA fullfsync=ON")
            self.check_owner()
            yield connection
            self.check_owner()
        except WikiServiceError:
            raise
        except WorkspaceFilesError as error:
            code = "WIKI_NOT_ALLOWED" if error.code == "WORKSPACE_NOT_ALLOWED" else error.code
            raise WikiServiceError(code, error.message, retryable=error.retryable) from None
        except (OSError, sqlite3.Error):
            raise WikiServiceError("STATE_UNAVAILABLE", "Wiki operation could not access durable state") from None
        except (TypeError, ValueError, UnicodeError):
            raise WikiServiceError("INVALID_REQUEST", "Wiki request is invalid") from None
        finally:
            if connection is not None:
                connection.close()
            if lock >= 0:
                os.close(lock)
            if directory >= 0:
                os.close(directory)

    @staticmethod
    def _ensure_store(connection: sqlite3.Connection) -> None:
        with connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS wiki_grants (
                    wiki_id TEXT PRIMARY KEY, label TEXT NOT NULL, root TEXT NOT NULL,
                    root_dev INTEGER NOT NULL, root_ino INTEGER NOT NULL,
                    generation TEXT NOT NULL, authority_id TEXT NOT NULL,
                    profile_id TEXT NOT NULL, device_ids TEXT NOT NULL,
                    writable INTEGER NOT NULL CHECK(writable IN (0,1)), source_kind TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS wiki_operations (
                    operation_id TEXT PRIMARY KEY, wiki_id TEXT NOT NULL,
                    generation TEXT NOT NULL, authority_id TEXT NOT NULL,
                    profile_id TEXT NOT NULL, device_id TEXT NOT NULL,
                    path TEXT NOT NULL, base_revision TEXT NOT NULL,
                    request_digest TEXT NOT NULL, proposed BLOB NOT NULL,
                    base BLOB, observed BLOB NOT NULL, temp_name TEXT NOT NULL,
                    reserved_bytes INTEGER NOT NULL, created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS wiki_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id TEXT NOT NULL REFERENCES wiki_operations(operation_id),
                    status TEXT NOT NULL CHECK(status IN
                        ('prepared','committing','committed','conflict','failed','indeterminate')),
                    revision TEXT, error_code TEXT, created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS wiki_event_lookup ON wiki_events(operation_id, sequence);
                CREATE TABLE IF NOT EXISTS wiki_evidence (
                    operation_id TEXT NOT NULL REFERENCES wiki_operations(operation_id),
                    kind TEXT NOT NULL CHECK(kind IN ('late','readback')),
                    content BLOB NOT NULL, PRIMARY KEY(operation_id, kind)
                );
            """)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(wiki_grants)")}
            if "access_scope" not in columns:
                connection.execute("ALTER TABLE wiki_grants ADD COLUMN access_scope TEXT NOT NULL "
                                   "DEFAULT 'device' CHECK(access_scope IN ('device','account'))")
            for table in ("wiki_operations", "wiki_events", "wiki_evidence"):
                for action in ("UPDATE", "DELETE"):
                    connection.execute(
                        f"CREATE TRIGGER IF NOT EXISTS {table}_no_{action.lower()} "
                        f"BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT, 'immutable Wiki recovery'); END"
                    )
        from .wiki_schema import migrate_owner_schema
        migrate_owner_schema(connection)

    def _validate_requester(self, profile_id: str, device_id: str | None) -> None:
        _opaque(profile_id, "profileId")
        if self._owner_kind == "native_principal":
            if device_id is not None:
                raise WikiServiceError("INVALID_REQUEST", "Native Wiki does not accept device identity")
        else:
            _opaque(device_id, "deviceId")

    def _matches_owner(self, row: sqlite3.Row, profile_id: str, device_id: str | None) -> bool:
        return (row["authority_id"], row["profile_id"], row["device_id"], row["owner_kind"], row["principal_id"]) == (
            self._authority_id, profile_id, device_id, self._owner_kind, self._principal_id)

    def _digest(self, values: tuple[Any, ...]) -> str:
        return _request_digest(values if self._principal_id is None
                               else ("native_principal", self._principal_id, *values))

    def _allows_requester(self, row: sqlite3.Row, device_id: str | None) -> bool:
        if row["owner_kind"] != self._owner_kind or row["principal_id"] != self._principal_id:
            return False
        return (device_id is None if self._owner_kind == "native_principal"
                else self._allows_device(row, device_id))

    def grant(self, wiki_id: str, *, root: Path, label: str, profile_id: str,
              device_ids: tuple[str, ...], writable: bool = False,
              source_kind: str = "files") -> dict:
        """Host administration only. Changed policy always rotates generation."""
        if self._principal_id is not None:
            raise WikiServiceError("INVALID_REQUEST", "Use native connect rather than a device grant")
        with self._locked() as connection:
            wiki_id = _valid_workspace_id(wiki_id)
            if connection.execute("SELECT 1 FROM wiki_native_disconnects WHERE wiki_id=?", (wiki_id,)).fetchone():
                raise WikiServiceError("WIKI_NOT_ALLOWED", "This Wiki identity has been retired")
            label = _valid_label(label)
            profile_id = _opaque(profile_id, "profileId")
            if not isinstance(device_ids, tuple) or not 1 <= len(device_ids) <= 128:
                raise WikiServiceError("INVALID_REQUEST", "An explicit nonempty device tuple is required")
            devices = tuple(_opaque(device, "deviceId") for device in device_ids)
            if len(set(devices)) != len(devices) or type(writable) is not bool:
                raise WikiServiceError("INVALID_REQUEST", "Wiki grant policy is invalid")
            if not isinstance(source_kind, str) or source_kind not in _SOURCE_KINDS:
                raise WikiServiceError("INVALID_REQUEST", "sourceKind is unsupported")
            # No generated/mirror/export adapter is authoritative in this service.
            effective_writable = writable and source_kind == "files" and self._can_write
            reader = _Reader(self, connection, None)
            candidate = reader._valid_grant_root(root)
            if candidate == self._state_dir or self._state_dir in candidate.parents:
                raise WikiServiceError("INVALID_GRANT", "Wiki state cannot be granted")
            descriptor = _absolute_directory(candidate)
            try:
                current = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            existing = connection.execute("SELECT * FROM wiki_grants WHERE wiki_id=?", (wiki_id,)).fetchone()
            policy = (label, str(candidate), current.st_dev, current.st_ino, self._authority_id,
                      profile_id, json.dumps(sorted(devices)), int(effective_writable), source_kind)
            columns = ("label", "root", "root_dev", "root_ino", "authority_id", "profile_id",
                       "device_ids", "writable", "source_kind")
            if existing is not None and tuple(existing[key] for key in columns) == policy:
                return self._root_dto(existing)
            if existing is None and connection.execute("SELECT COUNT(*) FROM wiki_grants").fetchone()[0] >= _MAX_GRANTS:
                raise WikiServiceError("QUOTA_EXCEEDED", "Wiki grant limit reached")
            with connection:
                connection.execute(
                    "INSERT OR REPLACE INTO wiki_grants "
                    "(wiki_id,label,root,root_dev,root_ino,authority_id,profile_id,device_ids,writable,source_kind,generation) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (wiki_id, *policy, uuid.uuid4().hex),
                )
            row = connection.execute("SELECT * FROM wiki_grants WHERE wiki_id=?", (wiki_id,)).fetchone()
            self._revalidate(connection, row)
            return self._root_dto(row)

    def connect(self, folder_path: str, *, profile_id: str, device_id: str | None,
                account_authorized: bool = False) -> dict:
        """Explicit folder setup under verified Link or native-principal authority.

        Verified account selection creates/converts an exact grant to account
        read/write. The default retains the legacy host-internal device policy.
        Reads and resolve never call this mutation path.
        """
        from .wiki_contract import exact_folder
        native = self._principal_id is not None
        if native and account_authorized:
            raise WikiServiceError("INVALID_REQUEST", "Native Wiki cannot adopt account authority")
        folder_path = exact_folder(folder_path)
        with self._locked() as connection:
            self._validate_requester(profile_id, device_id)
            try:
                candidate = _Reader(self, connection, None)._valid_grant_root(Path(folder_path))
                lineage = _directory_lineage(candidate)
                self._check_host_control_root(candidate, lineage)
                home = Path.home().resolve()
                if _lexically_contains(candidate, home) or lineage[-1] in _directory_lineage(home):
                    raise WikiServiceError("WIKI_NOT_ALLOWED", "Home directories cannot be connected")
                if _overlaps_root(candidate, lineage, self._state_dir):
                    raise WikiServiceError("WIKI_NOT_ALLOWED", "Host control folders cannot be connected")
                protected = any(_overlaps_root(candidate, lineage, root)
                                for root in self._protected_roots)
                system_trees = ("/etc", "/proc", "/dev", "/sys", "/run", "/boot", "/bin", "/sbin",
                                "/usr", "/lib", "/lib64", "/System", "/Library", "/private/etc", "/private/var")
                if any(_overlaps_root(candidate, lineage, Path(root)) for root in system_trees):
                    raise WikiServiceError("WIKI_NOT_ALLOWED", "System folders cannot be connected")
                descriptor = _absolute_directory(candidate)
            except (WorkspaceFilesError, OSError):
                raise WikiServiceError("WIKI_NOT_ALLOWED", "This folder cannot be connected") from None
            try:
                current = os.fstat(descriptor)
                if (current.st_dev, current.st_ino) != lineage[-1]:
                    raise WikiServiceError("WIKI_NOT_ALLOWED", "Wiki folder identity changed")
            finally:
                os.close(descriptor)
            exact = []
            for row in connection.execute("SELECT * FROM wiki_grants").fetchall():
                registered = Path(row["root"])
                pinned = (row["root_dev"], row["root_ino"])
                if not _overlaps_root(candidate, lineage, registered, pinned):
                    continue
                if native and row["owner_kind"] == "link_device" and candidate == registered and (current.st_dev, current.st_ino) == pinned:
                    raise WikiServiceError("WIKI_AUTHORITY_CONFLICT",
                                           "This folder has a Link connection. Explicitly remove that connection before native reconnect.")
                if (row["authority_id"] != self._authority_id or row["profile_id"] != profile_id
                        or (not account_authorized and not self._allows_requester(row, device_id))):
                    raise WikiServiceError("WIKI_NOT_ALLOWED", "This folder overlaps an existing host grant")
                if candidate == registered and (current.st_dev, current.st_ino) == pinned:
                    exact.append(row)
                elif account_authorized or native:
                    raise WikiServiceError("WIKI_NOT_ALLOWED", "Choose the exact registered Wiki folder")
            if len(exact) > 1:
                raise WikiServiceError("WIKI_AMBIGUOUS", "Choose a named Wiki from the authorized roots")
            if exact:
                row = exact[0]
                self._revalidate(connection, row)
                writable = int(row["source_kind"] == "files" and self._can_write)
                if native and row["writable"] != writable:
                    self.check_owner()
                    with connection:
                        connection.execute("UPDATE wiki_grants SET writable=?, generation=? WHERE wiki_id=?",
                                           (writable, uuid.uuid4().hex, row["wiki_id"]))
                        row = connection.execute("SELECT * FROM wiki_grants WHERE wiki_id=?", (row["wiki_id"],)).fetchone()
                        self._revalidate(connection, row)
                if account_authorized and (row["access_scope"] != "account" or row["writable"] != writable):
                    self.check_owner()
                    with connection:
                        connection.execute("UPDATE wiki_grants SET access_scope='account', device_ids='[]', "
                                           "writable=?, generation=? WHERE wiki_id=?",
                                           (writable, uuid.uuid4().hex, row["wiki_id"]))
                        row = connection.execute("SELECT * FROM wiki_grants WHERE wiki_id=?", (row["wiki_id"],)).fetchone()
                        self._revalidate(connection, row)
                return self._root_dto(row)
            # Explicit account/native selection can register ordinary data under
            # the host home; control roots were unconditionally excluded above.
            if protected and not (account_authorized or native):
                raise WikiServiceError("WIKI_NOT_ALLOWED", "This folder cannot be connected")
            if connection.execute("SELECT COUNT(*) FROM wiki_grants").fetchone()[0] >= _MAX_GRANTS:
                raise WikiServiceError("QUOTA_EXCEEDED", "Wiki grant limit reached")
            wiki_id = self._new_wiki_id(connection)
            label = _valid_label(candidate.name)
            self.check_owner()
            with connection:
                connection.execute(
                    "INSERT INTO wiki_grants "
                    "(wiki_id,label,root,root_dev,root_ino,authority_id,profile_id,device_ids,writable,source_kind,generation,"
                    "owner_kind,principal_id,access_scope) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (wiki_id, label, str(candidate), current.st_dev, current.st_ino, self._authority_id,
                     profile_id, "[]" if native else json.dumps([device_id]), int(native and self._can_write),
                     "files", uuid.uuid4().hex, self._owner_kind, self._principal_id,
                     "native_principal" if native else "device"),
                )
                if account_authorized:
                    connection.execute("UPDATE wiki_grants SET access_scope='account', device_ids='[]', writable=? "
                                       "WHERE wiki_id=?", (int(self._can_write), wiki_id))
                row = connection.execute("SELECT * FROM wiki_grants WHERE wiki_id=?", (wiki_id,)).fetchone()
                self._revalidate(connection, row)
            return self._root_dto(row)

    @staticmethod
    def _new_wiki_id(connection: sqlite3.Connection) -> str:
        for _ in range(8):
            candidate = "wiki-" + uuid.uuid4().hex
            if not connection.execute(
                "SELECT 1 FROM wiki_grants WHERE wiki_id=? UNION ALL "
                "SELECT 1 FROM wiki_native_disconnects WHERE wiki_id=?",
                (candidate, candidate),
            ).fetchone():
                return candidate
        raise WikiServiceError("STATE_UNAVAILABLE", "A new Wiki identity could not be allocated")

    def disconnect(self, wiki_id: str, *, profile_id: str) -> dict:
        """Native-principal registry removal; retain files and all recovery data."""
        if self._principal_id is None:
            raise WikiServiceError("INVALID_REQUEST", "Native principal ownership is required")
        with self._locked() as connection:
            wiki_id = _valid_workspace_id(wiki_id)
            self._validate_requester(profile_id, None)
            expected = (self._authority_id, profile_id, self._principal_id)
            tombstone = connection.execute(
                "SELECT * FROM wiki_native_disconnects WHERE wiki_id=?", (wiki_id,)
            ).fetchone()
            if tombstone is not None:
                if (tombstone["authority_id"], tombstone["profile_id"], tombstone["principal_id"]) != expected:
                    raise WikiServiceError("WIKI_NOT_ALLOWED", "Wiki connection was not found")
                return {"wikiId": wiki_id, "disconnected": True}
            row = connection.execute("SELECT * FROM wiki_grants WHERE wiki_id=?", (wiki_id,)).fetchone()
            if (row is None or (row["authority_id"], row["profile_id"], row["principal_id"]) != expected
                    or row["owner_kind"] != "native_principal"):
                raise WikiServiceError("WIKI_NOT_ALLOWED", "Wiki connection was not found")
            if connection.execute("SELECT COUNT(*) FROM wiki_native_disconnects").fetchone()[0] >= _MAX_NATIVE_DISCONNECTS:
                raise WikiServiceError("QUOTA_EXCEEDED", "Wiki disconnect receipts require host-local maintenance")
            self.check_owner()
            with connection:
                connection.execute(
                    "INSERT INTO wiki_native_disconnects(wiki_id,authority_id,profile_id,principal_id,generation,created_at) "
                    "VALUES(?,?,?,?,?,?)", (wiki_id, *expected, row["generation"], time.time_ns()),
                )
                deleted = connection.execute(
                    "DELETE FROM wiki_grants WHERE wiki_id=? AND authority_id=? AND profile_id=? "
                    "AND principal_id=? AND owner_kind='native_principal'", (wiki_id, *expected),
                )
                if deleted.rowcount != 1:
                    raise WikiServiceError("WIKI_NOT_ALLOWED", "Wiki connection changed during disconnect")
            return {"wikiId": wiki_id, "disconnected": True}

    def _check_host_control_root(self, candidate: Path, lineage: tuple[tuple[int, int], ...]) -> None:
        # A custom Hermes home may also be the persistent user-data volume.
        # Exempt ordinary data folders, never the home or its control subtrees.
        controls = {'plugin-data', 'plugins', 'profiles', 'config', 'credentials',
                    'sessions', 'logs', 'memories', 'skills', 'cache', 'cron',
                    'hooks', 'auth', 'secrets', 'backups', 'hermes-agent',
                    'desktop-plugins', 'tui-widgets', 'skins', 'pets'}
        for home in self._protected_roots:
            if _lexically_contains(candidate, home):
                raise WikiServiceError('WIKI_NOT_ALLOWED', 'Host control folders cannot be connected')
            if _lexically_contains(home, candidate):
                first = unicodedata.normalize('NFC', candidate.parts[len(home.parts)]).casefold()
                if first.startswith('.') or first in controls:
                    raise WikiServiceError('WIKI_NOT_ALLOWED', 'Host control folders cannot be connected')
            # Inode checks also cover case-insensitive aliases of known roots.
            if any(_overlaps_root(candidate, lineage, home / name) for name in controls):
                raise WikiServiceError('WIKI_NOT_ALLOWED', 'Host control folders cannot be connected')

    def revoke(self, wiki_id: str) -> dict:
        """Host administration only; recovery material is deliberately retained."""
        with self._locked() as connection:
            wiki_id = _valid_workspace_id(wiki_id)
            with connection:
                cursor = connection.execute(
                    "DELETE FROM wiki_grants WHERE wiki_id=? AND authority_id=?", (wiki_id, self._authority_id),
                )
            return {"wikiId": wiki_id, "revoked": cursor.rowcount > 0}

    def _root_dto(self, row: sqlite3.Row) -> dict:
        return {"wikiId": row["wiki_id"], "name": row["label"],
                "writable": bool(row["writable"] and self._can_write),
                "sourceKind": row["source_kind"], "generation": row["generation"],
                "folderPath": row["root"], "supportsCreation": self._can_write}

    @staticmethod
    def _allows_device(row: sqlite3.Row, device_id: str) -> bool:
        return (row["access_scope"] == "account" or
                (row["access_scope"] == "device" and device_id in json.loads(row["device_ids"])))

    def _authorize(self, connection: sqlite3.Connection, wiki_id: str,
                   profile_id: str, device_id: str | None, *, write: bool = False) -> sqlite3.Row:
        _valid_workspace_id(wiki_id)
        self._validate_requester(profile_id, device_id)
        row = connection.execute("SELECT * FROM wiki_grants WHERE wiki_id=?", (wiki_id,)).fetchone()
        if (
            row is None or row["authority_id"] != self._authority_id
            or row["profile_id"] != profile_id or not self._allows_requester(row, device_id)
        ):
            message = ("Wiki is not connected for this principal and profile" if self._principal_id is not None
                       else "Wiki is not authorized for this owner and device")
            raise WikiServiceError("WIKI_NOT_ALLOWED", message)
        if write and (not row["writable"] or row["source_kind"] != "files" or not self._can_write):
            raise WikiServiceError("READ_ONLY", "This Wiki does not permit editing")
        self._revalidate(connection, row)
        return row

    def _revalidate(self, connection: sqlite3.Connection, expected: sqlite3.Row) -> None:
        self.check_owner()
        current = connection.execute("SELECT * FROM wiki_grants WHERE wiki_id=?", (expected["wiki_id"],)).fetchone()
        if current is None or dict(current) != dict(expected) or current["authority_id"] != self._authority_id:
            raise WikiServiceError("WIKI_NOT_ALLOWED", "Wiki grant changed during the request")
        descriptor = -1
        try:
            descriptor = _absolute_directory(Path(current["root"]))
            observed = os.fstat(descriptor)
            if (observed.st_dev, observed.st_ino) != (current["root_dev"], current["root_ino"]):
                raise WikiServiceError("WIKI_NOT_ALLOWED", "Wiki root identity changed")
        except OSError:
            raise WikiServiceError("WIKI_NOT_ALLOWED", "Wiki root is unavailable") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def check_owner(self) -> None:
        """Recheck the trusted pairing snapshot, never caller payload authority."""
        if self._owner_check is not None:
            self._owner_check()

    def grant_metadata(self, wiki_id: str, *, profile_id: str, device_id: str | None,
                       write: bool = False) -> dict:
        with self._locked() as connection:
            return self._root_dto(self._authorize(connection, wiki_id, profile_id, device_id, write=write))

    def list_grants(self) -> dict:
        """Host CLI only: policy metadata without file content."""
        with self._locked() as connection:
            rows = connection.execute(
                "SELECT * FROM wiki_grants WHERE authority_id=? ORDER BY wiki_id",
                (self._authority_id,),
            ).fetchall()
            return {"grants": [dict(self._root_dto(row), profileId=row["profile_id"],
                                    deviceIds=json.loads(row["device_ids"]),
                                    accessScope=row["access_scope"]) for row in rows]}

    def resolve(self, folder_path: str, *, profile_id: str, device_id: str | None) -> dict:
        from .wiki_contract import exact_folder
        folder_path = exact_folder(folder_path)
        with self._locked() as connection:
            self._validate_requester(profile_id, device_id)
            rows = connection.execute(
                "SELECT * FROM wiki_grants WHERE authority_id=? AND profile_id=? AND root=? ORDER BY wiki_id",
                (self._authority_id, profile_id, folder_path),
            ).fetchall()
            visible = [row for row in rows if self._allows_requester(row, device_id)]
            if not visible:
                message = ("This folder is not connected for this native principal" if self._principal_id is not None
                           else "This folder requires host approval")
                raise WikiServiceError("WIKI_NOT_ALLOWED", message)
            if len(visible) != 1:
                raise WikiServiceError("WIKI_AMBIGUOUS", "Choose a named Wiki from the authorized roots")
            self._revalidate(connection, visible[0])
            return self._root_dto(visible[0])

    def read_image(self, wiki_id: str, *, profile_id: str, device_id: str | None,
                   path: str, offset: int = 0, limit: int = 65536,
                   revision: str | None = None) -> dict:
        import base64
        suffix = Path(_valid_relative_path(path)).suffix.casefold()
        if suffix not in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
            raise WikiServiceError("UNSUPPORTED_CONTENT", "Only PNG, JPEG, GIF and WebP images are supported")
        with self._locked() as connection:
            row = self._authorize(connection, wiki_id, profile_id, device_id)
            reader = _Reader(self, connection, row)
            first = reader.read_file(wiki_id, path=path, offset=0, limit=32,
                                     revision=_raw_revision(revision, row["generation"]))
            if first["availability"] == "oversized":
                return self._native(first, row["generation"])
            header = base64.b64decode(first["data"], validate=True)
            valid = (
                (suffix == ".png" and header.startswith(b"\x89PNG\r\n\x1a\n"))
                or (suffix in {".jpg", ".jpeg"} and header.startswith(b"\xff\xd8\xff"))
                or (suffix == ".gif" and header[:6] in {b"GIF87a", b"GIF89a"})
                or (suffix == ".webp" and header[:4] == b"RIFF" and header[8:12] == b"WEBP")
            )
            if not valid:
                raise WikiServiceError("UNSUPPORTED_CONTENT", "Image bytes do not match a supported inert image type")
            if offset and revision is None:
                raise WikiServiceError("REVISION_REQUIRED", "Image revision is required after the first page")
            result = reader.read_file(wiki_id, path=path, offset=offset, limit=limit,
                                      revision=first["revision"])
            result["text"] = None
            result["availability"] = "binary"
            self._revalidate(connection, row)
            return self._native(result, row["generation"])

    def roots(self, *, profile_id: str, device_id: str | None) -> dict:
        with self._locked() as connection:
            self._validate_requester(profile_id, device_id)
            rows = connection.execute(
                "SELECT * FROM wiki_grants WHERE authority_id=? AND profile_id=? ORDER BY wiki_id",
                (self._authority_id, profile_id),
            ).fetchall()
            visible = []
            for row in rows:
                if not self._allows_requester(row, device_id):
                    continue
                try:
                    self._revalidate(connection, row)
                except WikiServiceError as error:
                    if error.code != "WIKI_NOT_ALLOWED":
                        raise
                    continue
                visible.append(self._root_dto(row))
            return {"roots": visible}

    @staticmethod
    def _native(result: dict, generation: str) -> dict:
        names = {"workspace_id": "wikiId", "next_offset": "nextOffset", "max_file_bytes": "maxFileBytes"}
        result = {names.get(key, key): value for key, value in result.items()}
        if result.get("revision") is not None:
            result["revision"] = f"wiki-v1:{generation}:{result['revision'].removeprefix('sha256:')}"
        # Adding a longer opaque token must not push a duplicated text/data read
        # past the generic envelope budget. Base64 remains authoritative.
        if "text" in result and len(json.dumps(result).encode("utf-8")) > 180_000:
            result["text"] = None
        if "entries" in result:
            while len(json.dumps(result).encode("utf-8")) > 180_000:
                if not result["entries"]:
                    raise WikiServiceError("DIRECTORY_OVERSIZED", "Wiki directory page exceeds the response limit")
                result["entries"].pop()
                result["nextOffset"] = result["offset"] + len(result["entries"])
        return result

    def list_directory(self, wiki_id: str, *, profile_id: str, device_id: str | None,
                       path: str = "", offset: int = 0, limit: int = 100,
                       query: str = "", revision: str | None = None) -> dict:
        """Directory-local filename filter, not recursive/content Wiki search."""
        with self._locked() as connection:
            row = self._authorize(connection, wiki_id, profile_id, device_id)
            result = _Reader(self, connection, row).list_directory(
                wiki_id, path=path, offset=offset, limit=limit, query=query,
                revision=_raw_revision(revision, row["generation"]),
            )
            return self._native(result, row["generation"])

    def read_file(self, wiki_id: str, *, profile_id: str, device_id: str | None,
                  path: str, offset: int = 0, limit: int = 65536,
                  revision: str | None = None) -> dict:
        with self._locked() as connection:
            row = self._authorize(connection, wiki_id, profile_id, device_id)
            result = _Reader(self, connection, row).read_file(
                wiki_id, path=path, offset=offset, limit=limit,
                revision=_raw_revision(revision, row["generation"]),
            )
            return self._native(result, row["generation"])

    @staticmethod
    def _snapshot(reader: _Reader, root: int, path: str) -> tuple[bytes, os.stat_result]:
        parent = descriptor = -1
        try:
            parent, name = reader._open_parent_from_root(root, path)
            descriptor = os.open(
                name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent,
            )
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise WikiServiceError("INVALID_PATH", "Only existing regular Markdown files can be edited")
            if before.st_nlink != 1:
                raise WikiServiceError("HARD_LINK_UNSAFE", "Hard-linked files cannot be edited")
            if before.st_size > _MAX_EDIT_BYTES:
                raise WikiServiceError("FILE_OVERSIZED", "Editable Markdown is limited to 1 MiB")
            if (
                before.st_uid != os.geteuid() or not before.st_mode & 0o222
                or before.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o111)
                or getattr(before, "st_flags", 0)
            ):
                raise WikiServiceError("READ_ONLY", "File ownership or permissions do not permit Wiki editing")
            _require_plain_metadata(descriptor)
            content = _read_descriptor(descriptor, _MAX_EDIT_BYTES)
            after = os.fstat(descriptor)
            if after.st_nlink != 1 or not _same_stat(before, after):
                raise WikiServiceError("REVISION_STALE", "File changed while preparing the save")
            reader._revalidate_file_path(root, path, before)
            return content, before
        except FileNotFoundError:
            raise WikiServiceError("PATH_NOT_FOUND", "Existing Wiki file was not found") from None
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise WikiServiceError("INVALID_PATH", "Wiki path crosses a symbolic link or non-directory") from None
            raise WikiServiceError("FILES_UNAVAILABLE", "Wiki file is unavailable") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if parent >= 0:
                os.close(parent)

    def _creation_snapshot(self, reader: _Reader, root: int, path: str):
        # Only the final component may be absent. Missing/unsafe parents fail.
        parent, name = reader._open_parent_from_root(root, path)
        try:
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return b"", None
        finally:
            os.close(parent)
        return self._snapshot(reader, root, path)

    @staticmethod
    def _event(connection: sqlite3.Connection, operation_id: str, status: str,
               revision: str | None = None, error_code: str | None = None) -> dict:
        with connection:
            connection.execute(
                "INSERT INTO wiki_events(operation_id,status,revision,error_code,created_at) VALUES(?,?,?,?,?)",
                (operation_id, status, revision, error_code, time.time_ns()),
            )
        return WikiService._outcome(operation_id, status, revision, error_code)

    @staticmethod
    def _outcome(operation_id: str, status: str, revision: str | None, error_code: str | None) -> dict:
        result = {"operationId": operation_id, "status": status, "revision": revision}
        if error_code is not None:
            result["errorCode"] = error_code
        return result

    def _operation(self, connection: sqlite3.Connection, operation_id: str,
                   profile_id: str, device_id: str | None) -> sqlite3.Row | None:
        row = connection.execute("SELECT * FROM wiki_operations WHERE operation_id=?", (operation_id,)).fetchone()
        if row is not None:
            if not self._matches_owner(row, profile_id, device_id):
                raise WikiServiceError("OPERATION_NOT_FOUND", "Save operation was not found")
            expected = self._digest((row["authority_id"], row["profile_id"], row["device_id"],
                                        row["wiki_id"], row["generation"], row["path"],
                                        row["base_revision"], _sha(row["proposed"])))
            if expected != row["request_digest"]:
                raise WikiServiceError("STATE_UNAVAILABLE", "Save journal integrity check failed")
            prepared = connection.execute(
                "SELECT status,revision FROM wiki_events WHERE operation_id=? ORDER BY sequence LIMIT 1",
                (operation_id,),
            ).fetchone()
            if (
                prepared is None or prepared["status"] != "prepared"
                or prepared["revision"] != _revision(row["generation"], row["observed"])
                or (row["base"] is not None and (
                    _revision(row["generation"], row["base"]) != row["base_revision"]
                    or row["base"] != row["observed"]
                ))
            ):
                raise WikiServiceError("STATE_UNAVAILABLE", "Save recovery material is inconsistent")
        return row

    def _recover(self, connection: sqlite3.Connection, operation: sqlite3.Row) -> dict:
        event = connection.execute(
            "SELECT * FROM wiki_events WHERE operation_id=? ORDER BY sequence DESC LIMIT 1",
            (operation["operation_id"],),
        ).fetchone()
        if event is None:
            raise WikiServiceError("STATE_UNAVAILABLE", "Save journal is incomplete")
        if event["status"] not in _TERMINAL:
            if fcntl is None:
                # Read-only platforms without locking cannot prove the writer
                # stopped; report the recorded phase without reconciling it.
                return self._outcome(operation["operation_id"], event["status"], event["revision"], event["error_code"])
            # Holding the process lock proves no cooperating save is still active.
            # Even matching current bytes do not prove this process committed them.
            status = "failed" if event["status"] == "prepared" else "indeterminate"
            return self._event(connection, operation["operation_id"], status, error_code="SAVE_INTERRUPTED")
        return self._outcome(operation["operation_id"], event["status"], event["revision"], event["error_code"])

    def save_status(self, operation_id: str, *, profile_id: str, device_id: str | None) -> dict:
        with self._locked() as connection:
            operation_id = _operation_id(operation_id)
            self._validate_requester(profile_id, device_id)
            operation = self._operation(connection, operation_id, profile_id, device_id)
            if operation is None:
                raise WikiServiceError("OPERATION_NOT_FOUND", "Save operation was not found")
            grant = self._authorize(connection, operation["wiki_id"], profile_id, device_id)
            if grant["generation"] != operation["generation"]:
                raise WikiServiceError("WIKI_NOT_ALLOWED", "Save belongs to an obsolete Wiki grant")
            return self._recover(connection, operation)

    def save_file(self, wiki_id: str, *, profile_id: str, device_id: str | None,
                  path: str, base_revision: str, content: bytes, operation_id: str) -> dict:
        with self._locked() as connection:
            return self._save_file_locked(
                connection, wiki_id, profile_id=profile_id, device_id=device_id,
                path=path, base_revision=base_revision, content=content, operation_id=operation_id,
            )

    def _save_file_locked(self, connection: sqlite3.Connection, wiki_id: str, *,
                          profile_id: str, device_id: str | None, path: str,
                          base_revision: str, content: bytes, operation_id: str) -> dict:
        """Internal staged-save entry; caller holds this service's process lock."""
        row = self._authorize(connection, wiki_id, profile_id, device_id, write=True)
        path = _valid_relative_path(path)
        if Path(path).suffix.casefold() not in {".md", ".markdown"}:
            raise WikiServiceError("UNSUPPORTED_CONTENT", "Only Markdown files can be edited")
        operation_id = _operation_id(operation_id)
        if type(content) is not bytes:
            raise WikiServiceError("INVALID_REQUEST", "Save content must be exact bytes")
        _markdown(content)
        if base_revision is None:
            raise WikiServiceError("REVISION_REQUIRED", "A base revision is required")
        creating = _creation_revision(base_revision, row["generation"])
        digest = self._digest((self._authority_id, profile_id, device_id, wiki_id,
                                  row["generation"], path, base_revision, _sha(content)))
        operation = self._operation(connection, operation_id, profile_id, device_id)
        if operation is not None:
            if operation["request_digest"] != digest:
                raise WikiServiceError("OPERATION_CONFLICT", "operationId was already used for a different save")
            return self._recover(connection, operation)
        reader = _Reader(self, connection, row)
        root = reader._open_grant_root(reader._load_grant(wiki_id))
        try:
            observed, before = (self._creation_snapshot(reader, root, path) if creating
                                else self._snapshot(reader, root, path))
            _markdown(observed)
            current_revision = _revision(row["generation"], observed)
            base = observed if current_revision == base_revision else None
            # Reserve enough for a late preimage AND post-replacement readback.
            # No eviction can destroy unresolved or terminal recovery evidence.
            reserved = len(observed) + len(content) + len(base or b"") + 2 * _MAX_EDIT_BYTES
            count, used = connection.execute("""
                SELECT COUNT(*), COALESCE(SUM(
                    CASE WHEN (SELECT status FROM wiki_events
                        WHERE wiki_events.operation_id=wiki_operations.operation_id
                        ORDER BY sequence DESC LIMIT 1)
                        IN ('committed','conflict','failed','indeterminate')
                    THEN length(proposed) + COALESCE(length(base),0) + length(observed)
                        + COALESCE((SELECT SUM(length(content)) FROM wiki_evidence
                            WHERE wiki_evidence.operation_id=wiki_operations.operation_id),0)
                    ELSE reserved_bytes END
                ),0) FROM wiki_operations
            """).fetchone()
            if count >= _MAX_OPERATIONS or used + reserved > _MAX_RECOVERY_BYTES:
                raise WikiServiceError("QUOTA_EXCEEDED", "Wiki recovery storage requires host-local maintenance")
            # .env.* is intentionally denied/hidden by the shared Files
            # primitives, so an interrupted staging file cannot leak drafts.
            temp_name = f".env.loopdy-wiki-{uuid.uuid4().hex}"
            with connection:
                connection.execute(
                    "INSERT INTO wiki_operations(operation_id,wiki_id,generation,authority_id,profile_id,device_id,"
                    "path,base_revision,request_digest,proposed,base,observed,temp_name,reserved_bytes,created_at,owner_kind,principal_id) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (operation_id, wiki_id, row["generation"], self._authority_id, profile_id, device_id,
                     path, base_revision, digest, content, base, observed, temp_name, reserved, time.time_ns(),
                     self._owner_kind, self._principal_id),
                )
                connection.execute(
                    "INSERT INTO wiki_events(operation_id,status,revision,created_at) VALUES(?,?,?,?)",
                    (operation_id, "prepared", current_revision, time.time_ns()),
                )
            if (creating and before is not None) or (not creating and current_revision != base_revision):
                return self._event(connection, operation_id, "conflict", current_revision, "REVISION_STALE")
            return self._replace(connection, row, reader, root, path, content, observed, before, operation_id, temp_name)
        finally:
            os.close(root)

    def _replace(self, connection: sqlite3.Connection, grant: sqlite3.Row, reader: _Reader,
                 root: int, path: str, content: bytes, observed: bytes, before: os.stat_result | None,
                 operation_id: str, temp_name: str) -> dict:
        parent = temporary = -1
        temp_identity = None
        committing = False
        try:
            parent, name = reader._open_parent_from_root(root, path)
            parent_identity = os.fstat(parent)
            temporary = os.open(
                temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600, dir_fd=parent,
            )
            temp_stat = os.fstat(temporary)
            temp_identity = (temp_stat.st_dev, temp_stat.st_ino)
            remaining = memoryview(content)
            while remaining:
                written = os.write(temporary, remaining)
                if written <= 0:
                    raise OSError("Short Wiki staging write")
                remaining = remaining[written:]
            if before is not None:
                os.fchown(temporary, -1, before.st_gid)
                os.fchmod(temporary, stat.S_IMODE(before.st_mode))
            _require_plain_metadata(temporary)
            os.fsync(temporary)
            os.fsync(parent)
            self._event(connection, operation_id, "committing")
            committing = True
            # Final full-byte/stat/path/owner check, AFTER staging and its journal.
            late, late_stat = (self._creation_snapshot(reader, root, path) if before is None
                               else self._snapshot(reader, root, path))
            with connection:
                connection.execute("INSERT INTO wiki_evidence VALUES(?,?,?)", (operation_id, "late", late))
            changed = (late_stat is not None if before is None
                       else late_stat is None or not _same_stat(before, late_stat))
            if late != observed or changed:
                return self._event(connection, operation_id, "conflict", _revision(grant["generation"], late), "REVISION_STALE")
            self._revalidate(connection, grant)
            check, _ = reader._open_parent_from_root(root, path)
            try:
                check_stat = os.fstat(check)
                if (check_stat.st_dev, check_stat.st_ino) != (parent_identity.st_dev, parent_identity.st_ino):
                    raise WikiServiceError("REVISION_STALE", "Wiki parent directory changed")
            finally:
                os.close(check)
            staged = os.stat(temp_name, dir_fd=parent, follow_symlinks=False)
            if (staged.st_dev, staged.st_ino) != temp_identity or staged.st_nlink != 1:
                raise WikiServiceError("REVISION_STALE", "Wiki staging identity changed")
            # There is deliberately no claim of CAS here: direct external writers
            # can change/remove the destination or move an ancestor after checks.
            if before is None:
                # link is atomic create-if-absent; never overwrite a racing file,
                # directory or symlink. Drop the staging link before readback.
                try:
                    os.link(temp_name, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                except FileExistsError:
                    return self._event(connection, operation_id, "conflict", error_code="REVISION_STALE")
                os.unlink(temp_name, dir_fd=parent)
            else:
                os.replace(temp_name, name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
            actual, after = self._snapshot(reader, root, path)
            with connection:
                connection.execute("INSERT INTO wiki_evidence VALUES(?,?,?)", (operation_id, "readback", actual))
            self._revalidate(connection, grant)
            if actual != content or (after.st_dev, after.st_ino) != temp_identity:
                return self._event(connection, operation_id, "indeterminate", error_code="READBACK_MISMATCH")
            return self._event(connection, operation_id, "committed", _revision(grant["generation"], content))
        except (WorkspaceFilesError, OSError, sqlite3.Error) as error:
            status = "indeterminate" if committing else "failed"
            code = error.code if isinstance(error, WorkspaceFilesError) else "SAVE_IO_ERROR"
            try:
                return self._event(connection, operation_id, status, error_code=code)
            except sqlite3.Error:
                raise WikiServiceError(
                    "STATE_UNAVAILABLE", "Save outcome requires reconciliation",
                    details={"operationId": operation_id, "status": "indeterminate"},
                ) from None
        finally:
            if temporary >= 0:
                os.close(temporary)
            if parent >= 0:
                # Only remove the exact staging inode this call created. Restart
                # recovery never deletes by a stale path or retries a replacement.
                if temp_identity is not None:
                    try:
                        entry = os.stat(temp_name, dir_fd=parent, follow_symlinks=False)
                        if (entry.st_dev, entry.st_ino) == temp_identity and entry.st_nlink == 1:
                            os.unlink(temp_name, dir_fd=parent)
                            os.fsync(parent)
                    except OSError:
                        pass  # Protected orphan + durable proposed bytes survive.
                os.close(parent)


__all__ = ["WikiService", "WikiServiceError"]
