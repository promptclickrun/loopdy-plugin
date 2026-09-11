"""Independent durable voice jobs; no Hermes core or provider dependencies.

A session_id here is a *visible Loopdy chat*, never an invented stored Hermes ID.
The authenticated adapter owns authorization freshness and supplies callbacks. Every
mutation is CAS-fenced by the complete owner, job, run and revision. Reopening a
ledger makes unfinished work uncertain, never eligible for automatic dispatch.
"""
from __future__ import annotations

import asyncio
import fcntl
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Awaitable, Callable, Coroutine, Iterator
from urllib.parse import quote, urlsplit


_IDENTIFIER = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.:-]{0,179}\Z")
_TERMINAL = frozenset({"completed", "failed", "cancelled", "expired"})
_STATES = _TERMINAL | {"admitted", "dispatching", "running", "waiting", "cancel_requested", "uncertain"}
_MAX_TEXT = 65536
_MAX_SUMMARY = 4096
_MAX_PENDING = 8192
_MAX_CONTROL = 4096
_TOMBSTONE_BYTES = 16384


class VoiceJobError(ValueError):
    """Base for safe, payload-free control-plane errors."""


class VoiceJobNotFound(VoiceJobError):
    """Unknown job or wrong owner (deliberately indistinguishable)."""


class VoiceJobConflict(VoiceJobError):
    """Changed duplicate, stale revision, wrong run, or invalid transition."""


class VoiceJobCapacity(VoiceJobError):
    """A bounded ledger fails closed rather than forgetting replay identity."""


class VoiceJobClosed(VoiceJobError):
    pass


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise VoiceJobError(f"invalid {label}")
    return value


def _integer(value: Any, label: str, minimum: int = 1) -> int:
    if type(value) is not int or not minimum <= value <= 2**63 - 1:
        raise VoiceJobError(f"invalid {label}")
    return value


def _text(value: Any, label: str, maximum: int, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value.strip()) or "\x00" in value:
        raise VoiceJobError(f"invalid {label}")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as error:
        raise VoiceJobError(f"invalid {label}") from error
    if size > maximum:
        raise VoiceJobError(f"{label} exceeds byte limit")
    return value


def _json(value: Any, maximum: int) -> str:
    def validate(item: Any, depth: int = 0) -> None:
        if depth > 12:
            raise VoiceJobError("JSON nesting exceeds limit")
        if item is None or type(item) in {str, bool, int}:
            return
        if type(item) is float and math.isfinite(item):
            return
        if type(item) is list:
            for child in item:
                validate(child, depth + 1)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values():
                validate(child, depth + 1)
            return
        raise VoiceJobError("invalid JSON value")
    validate(value)
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        _text(encoded, "JSON", maximum)
    except (TypeError, ValueError, OverflowError) as error:
        raise VoiceJobError("invalid or oversized JSON") from error
    return encoded


@dataclass(frozen=True)
class VoiceJobOwner:
    account_origin: str
    host_id: str
    host_epoch: int
    device_id: str
    device_epoch: int
    agent_id: str

    def __post_init__(self) -> None:
        _text(self.account_origin, "account_origin", 512)
        try:
            origin = urlsplit(self.account_origin)
            port = origin.port
        except ValueError as error:
            raise VoiceJobError("invalid account_origin") from error
        if (origin.scheme != "https" or not origin.hostname or origin.username is not None
                or origin.password is not None or origin.path or origin.query or origin.fragment
                or port == 0 or origin.netloc.endswith(":") or "\\" in self.account_origin or "%" in origin.netloc
                or "?" in self.account_origin or "#" in self.account_origin
                or any(character.isspace() or ord(character) < 32 for character in self.account_origin)):
            raise VoiceJobError("account_origin must be an exact HTTPS origin")
        for name in ("host_id", "device_id", "agent_id"):
            _identifier(getattr(self, name), name)
        _integer(self.host_epoch, "host_epoch")
        _integer(self.device_epoch, "device_epoch")

    def _key(self) -> str:
        # Store the exact tuple, not a normalized URL or an ambiguous concatenation.
        return _json([self.account_origin, self.host_id, self.host_epoch,
                      self.device_id, self.device_epoch, self.agent_id], 2048)


@dataclass(frozen=True)
class VoiceJobPending:
    pending_id: str
    kind: str
    revision: int
    prompt: str


@dataclass(frozen=True)
class VoiceJobRecord:
    owner: VoiceJobOwner
    job_id: str
    voice_id: str
    delegation_id: str
    session_id: str
    message_id: str
    run_id: str
    revision: int
    state: str
    text: str
    stored_session_id: str | None
    pending: VoiceJobPending | None
    summary: str | None
    created_at: float
    updated_at: float
    is_new: bool = False

    @property
    def terminal(self) -> bool:
        return self.state in _TERMINAL

    @property
    def phase(self) -> str:
        return self.state


@dataclass(frozen=True)
class VoiceJobControl:
    """Immutable dispatch envelope. decision returns a fresh JSON value."""
    job: VoiceJobRecord
    request_id: str
    action: str
    expected_revision: int
    text: str | None
    pending_id: str | None
    pending_revision: int | None
    decision_json: str | None
    state: str = "admitted"
    is_new: bool = True

    @property
    def decision(self) -> Any:
        return json.loads(self.decision_json) if self.decision_json is not None else None


@dataclass(frozen=True)
class VoiceJobSubmission:
    """A dispatch receipt, NOT evidence that the Hermes job has completed."""
    stored_session_id: str | None = None


class VoiceJobLedger:
    """Single-live-owner SQLite ledger, with persistent replay tombstones.

    Retention removes terminal content, not delegation identity. Tombstones still
    consume capacity: without issued-at/replay-window input, deleting them would
    make an old delegation executable again. Uncertain work is never evicted.
    The containing directory must not be writable by another user. close() does
    not cancel jobs; all nonterminal records become uncertain on the next open.
    """

    def __init__(self, path: str | os.PathLike[str], *, maximum_entries: int = 1024,
                 maximum_active: int = 64, maximum_bytes: int = 64 * 1024 * 1024,
                 maximum_controls: int = 32, retention_seconds: float = 7 * 86400,
                 clock: Callable[[], float] = time.time) -> None:
        self.maximum_entries = _integer(maximum_entries, "maximum_entries")
        self.maximum_active = _integer(maximum_active, "maximum_active")
        self.maximum_bytes = _integer(maximum_bytes, "maximum_bytes", 65536)
        self.maximum_controls = _integer(maximum_controls, "maximum_controls")
        if (isinstance(retention_seconds, bool) or not isinstance(retention_seconds, (float, int))
                or not math.isfinite(retention_seconds) or retention_seconds < 0 or not callable(clock)):
            raise VoiceJobError("invalid retention or clock")
        self.retention_seconds = retention_seconds
        self.clock = clock
        raw_path = os.fspath(path)
        if not isinstance(raw_path, str) or not raw_path or "\x00" in raw_path or ".." in Path(raw_path).parts:
            raise VoiceJobError("invalid ledger path")
        self.path = Path(os.path.abspath(raw_path))
        # macOS exposes these OS-owned root aliases in tempfile.gettempdir().
        # No user-controlled symlink or final database symlink is resolved.
        for alias, target in (("/var", "/private/var"), ("/tmp", "/private/tmp")):
            if str(self.path).startswith(alias + "/") and os.path.islink(alias):
                if os.lstat(alias).st_uid != 0 or os.path.realpath(alias) != target:
                    raise VoiceJobError("unsafe system temporary-directory alias")
                self.path = Path(target + str(self.path)[len(alias):])
        self._lock = threading.RLock()
        self._closed = False
        self._fd: int | None = None
        self._db: sqlite3.Connection | None = None
        try:
            self._open()
        except BaseException:
            self.close()
            raise

    def _parent(self, create: bool = False) -> int:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open(self.path.anchor, flags)
        try:
            for component in self.path.parent.parts[1:]:
                if create:
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise VoiceJobError("ledger directory must be owned and not group/world writable")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _guard(self, parent: int, name: str) -> tuple[int, int]:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
                raise VoiceJobError("ledger files must be owned regular files without hard links")
            os.fchmod(descriptor, 0o600)
            return info.st_dev, info.st_ino
        finally:
            os.close(descriptor)

    def _check_path(self) -> None:
        parent = self._parent()
        try:
            if self._guard(parent, self.path.name) != self._identity:
                raise VoiceJobError("ledger path changed")
            if self._guard(parent, self.path.name + ".owner-lock") != self._lock_identity:
                raise VoiceJobError("ledger owner lock changed")
            for suffix in ("-journal", "-wal", "-shm"):
                try:
                    self._guard(parent, self.path.name + suffix)
                except FileNotFoundError:
                    pass
        finally:
            os.close(parent)

    def _open(self) -> None:
        parent = self._parent(create=True)
        try:
            # Darwin flock and SQLite's fcntl locks on the same inode conflict.
            # Keep process ownership on a distinct private sidecar, never the DB.
            descriptor = os.open(self.path.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 0o600, dir_fd=parent)
            try:
                self._identity = self._guard(parent, self.path.name)
                opened = os.fstat(descriptor)
                if self._identity != (opened.st_dev, opened.st_ino):
                    raise VoiceJobError("ledger path changed while opening")
            finally:
                os.close(descriptor)
            lock_name = self.path.name + ".owner-lock"
            self._fd = os.open(lock_name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                               0o600, dir_fd=parent)
            self._lock_identity = self._guard(parent, lock_name)
            lock_info = os.fstat(self._fd)
            if self._lock_identity != (lock_info.st_dev, lock_info.st_ino):
                raise VoiceJobError("ledger lock changed while opening")
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise VoiceJobConflict("ledger already has a live owner") from error
        finally:
            os.close(parent)
        self._check_path()
        self._db = sqlite3.connect(f"file:{quote(str(self.path), safe='/')}?mode=rw", uri=True,
                                   timeout=5, isolation_level=None, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._check_path()
        self._db.execute("PRAGMA trusted_schema=OFF")
        self._db.execute("PRAGMA foreign_keys=ON")
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1):
            raise VoiceJobError("unsupported voice ledger schema")
        tables = {row[0] for row in self._db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if tables and tables != {"voice_jobs", "voice_job_controls"}:
            raise VoiceJobError("path contains a different application's database")
        page_size = self._db.execute("PRAGMA page_size").fetchone()[0]
        page_limit = self.maximum_bytes // page_size
        if self._db.execute("PRAGMA page_count").fetchone()[0] > page_limit:
            raise VoiceJobCapacity("existing ledger exceeds the configured byte limit")
        self._db.execute(f"PRAGMA max_page_count={page_limit}")
        self._db.execute("PRAGMA journal_mode=DELETE")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA secure_delete=ON")
        with self._transaction() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS voice_jobs (
                job_id TEXT PRIMARY KEY, owner TEXT NOT NULL, voice_id TEXT NOT NULL,
                delegation_id TEXT NOT NULL, digest TEXT NOT NULL,
                session_id TEXT NOT NULL UNIQUE, message_id TEXT NOT NULL UNIQUE,
                run_id TEXT NOT NULL, revision INTEGER NOT NULL, state TEXT NOT NULL,
                text TEXT NOT NULL, stored_session_id TEXT, pending_json TEXT, summary TEXT,
                created_at REAL NOT NULL, updated_at REAL NOT NULL, terminal_at REAL,
                reserved_bytes INTEGER NOT NULL, control_limit INTEGER NOT NULL,
                UNIQUE(owner, voice_id, delegation_id))""")
            db.execute("""CREATE TABLE IF NOT EXISTS voice_job_controls (
                job_id TEXT NOT NULL REFERENCES voice_jobs(job_id), request_id TEXT NOT NULL,
                body TEXT NOT NULL, state TEXT NOT NULL, dispatch_revision INTEGER NOT NULL,
                PRIMARY KEY(job_id, request_id))""")
            db.execute("CREATE INDEX IF NOT EXISTS voice_jobs_owner ON voice_jobs(owner, voice_id)")
            db.execute("PRAGMA user_version=1")
            reserved = db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM voice_jobs").fetchone()[0]
            if reserved and reserved + 65536 > self.maximum_bytes:
                raise VoiceJobCapacity("existing reservations exceed the configured byte limit")
            now = self._now()
            db.execute("UPDATE voice_jobs SET state='uncertain', revision=revision+1, pending_json=NULL, "
                       "updated_at=? WHERE state NOT IN ('completed','failed','cancelled','expired','uncertain')", (now,))
            db.execute("UPDATE voice_job_controls SET state='uncertain' WHERE state='admitted'")

    def _now(self) -> float:
        value = self.clock()
        if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or value < 0:
            raise VoiceJobError("invalid clock")
        return float(value)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed or self._db is None:
                raise VoiceJobClosed("voice ledger is closed")
            self._check_path()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise

    @staticmethod
    def _record(row: sqlite3.Row, *, is_new: bool = False) -> VoiceJobRecord:
        if row["state"] not in _STATES:
            raise VoiceJobError("invalid stored voice job state")
        owner = VoiceJobOwner(*json.loads(row["owner"]))
        pending = VoiceJobPending(**json.loads(row["pending_json"])) if row["pending_json"] else None
        return VoiceJobRecord(owner=owner, job_id=row["job_id"], voice_id=row["voice_id"],
                              delegation_id=row["delegation_id"], session_id=row["session_id"],
                              message_id=row["message_id"], run_id=row["run_id"], revision=row["revision"],
                              state=row["state"], text=row["text"], stored_session_id=row["stored_session_id"],
                              pending=pending, summary=row["summary"], created_at=row["created_at"],
                              updated_at=row["updated_at"], is_new=is_new)

    @staticmethod
    def _owner(owner: VoiceJobOwner) -> str:
        if type(owner) is not VoiceJobOwner:
            raise VoiceJobError("invalid voice owner")
        return owner._key()

    def _get(self, db: sqlite3.Connection, owner: VoiceJobOwner, job_id: str) -> VoiceJobRecord:
        row = db.execute("SELECT * FROM voice_jobs WHERE owner=? AND job_id=?",
                         (self._owner(owner), _identifier(job_id, "job_id"))).fetchone()
        if row is None:
            raise VoiceJobNotFound("voice job not found")
        return self._record(row)

    def _fenced(self, db: sqlite3.Connection, owner: VoiceJobOwner, job_id: str,
                run_id: str, expected_revision: int) -> VoiceJobRecord:
        current = self._get(db, owner, job_id)
        _integer(expected_revision, "expected_revision")
        _identifier(run_id, "run_id")
        if current.revision != expected_revision or current.run_id != run_id:
            raise VoiceJobConflict("stale voice job revision or run")
        return current

    def get(self, owner: VoiceJobOwner, job_id: str) -> VoiceJobRecord:
        with self._transaction() as db:
            return self._get(db, owner, job_id)

    def list(self, owner: VoiceJobOwner, *, voice_id: str | None = None,
             limit: int = 100, offset: int = 0) -> tuple[VoiceJobRecord, ...]:
        _integer(limit, "limit")
        _integer(offset, "offset", 0)
        if limit > 1000:
            raise VoiceJobError("list limit exceeds 1000")
        query = "SELECT * FROM voice_jobs WHERE owner=?"
        values: list[Any] = [self._owner(owner)]
        if voice_id is not None:
            query += " AND voice_id=?"
            values.append(_identifier(voice_id, "voice_id"))
        with self._transaction() as db:
            rows = db.execute(query + " ORDER BY created_at, job_id LIMIT ? OFFSET ?", (*values, limit, offset)).fetchall()
            return tuple(self._record(row) for row in rows)

    def _prune(self, db: sqlite3.Connection, now: float) -> int:
        # Replay fences survive content expiry. Never forget or dispatch uncertain work.
        criteria = "state IN ('completed','failed','cancelled') AND terminal_at<=?"
        cutoff = now - self.retention_seconds
        db.execute(f"DELETE FROM voice_job_controls WHERE job_id IN (SELECT job_id FROM voice_jobs WHERE {criteria})", (cutoff,))
        return db.execute(f"UPDATE voice_jobs SET text='', summary=NULL, pending_json=NULL, state='expired', "
                          f"revision=revision+1, updated_at=?, reserved_bytes=? WHERE {criteria}",
                          (now, _TOMBSTONE_BYTES, cutoff)).rowcount

    def prune(self) -> int:
        with self._transaction() as db:
            return self._prune(db, self._now())

    def admit(self, owner: VoiceJobOwner, voice_id: str, delegation_id: str, text: str) -> VoiceJobRecord:
        key = self._owner(owner)
        _identifier(voice_id, "voice_id")
        _identifier(delegation_id, "delegation_id")
        _text(text, "text", _MAX_TEXT)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        with self._transaction() as db:
            now = self._now()
            self._prune(db, now)
            row = db.execute("SELECT * FROM voice_jobs WHERE owner=? AND voice_id=? AND delegation_id=?",
                             (key, voice_id, delegation_id)).fetchone()
            if row is not None:
                if row["digest"] != digest:
                    raise VoiceJobConflict("delegation identifier has different text")
                return self._record(row)
            count, active, reserved = db.execute("SELECT COUNT(*), COALESCE(SUM(state NOT IN "
                "('completed','failed','cancelled','expired')),0), COALESCE(SUM(reserved_bytes),0) FROM voice_jobs").fetchone()
            # Reserve overflow/index/row-rewrite headroom as well as payloads,
            # so a terminal update is not crowded out by earlier control bodies.
            budget = (_TOMBSTONE_BYTES + 2 * (len(text.encode("utf-8")) + _MAX_SUMMARY + _MAX_PENDING)
                      + self.maximum_controls * (2 * _MAX_CONTROL + 4096))
            if (count >= self.maximum_entries or active >= self.maximum_active
                    or reserved + budget + 65536 > self.maximum_bytes):
                raise VoiceJobCapacity("voice job ledger capacity exhausted")
            job_id, session_id = "job_" + uuid.uuid4().hex, "voicejob_" + uuid.uuid4().hex
            db.execute("""INSERT INTO voice_jobs (job_id,owner,voice_id,delegation_id,digest,session_id,
                message_id,run_id,revision,state,text,created_at,updated_at,reserved_bytes,control_limit)
                VALUES (?,?,?,?,?,?,?,?,1,'admitted',?,?,?,?,?)""",
                (job_id, key, voice_id, delegation_id, digest, session_id, "message_" + uuid.uuid4().hex,
                 "run_" + uuid.uuid4().hex, text, now, now, budget, self.maximum_controls))
            return replace(self._get(db, owner, job_id), is_new=True)

    def _update(self, db: sqlite3.Connection, current: VoiceJobRecord, **fields: Any) -> VoiceJobRecord:
        fields["revision"] = current.revision + 1
        fields["updated_at"] = self._now()
        assignments = ",".join(f"{name}=?" for name in fields)
        # All column names are internal literals; values are parameterized.
        updated = db.execute(f"UPDATE voice_jobs SET {assignments} WHERE job_id=? AND owner=? AND revision=? AND run_id=?",
                             (*fields.values(), current.job_id, current.owner._key(), current.revision, current.run_id))
        if updated.rowcount != 1:
            raise VoiceJobConflict("voice job changed")
        return self._get(db, current.owner, current.job_id)

    def start(self, owner: VoiceJobOwner, job_id: str, *, run_id: str, expected_revision: int) -> VoiceJobRecord:
        with self._transaction() as db:
            current = self._fenced(db, owner, job_id, run_id, expected_revision)
            if current.state != "admitted":
                raise VoiceJobConflict("voice job is not newly admitted")
            return self._update(db, current, state="dispatching")

    def running(self, owner: VoiceJobOwner, job_id: str, *, run_id: str, expected_revision: int,
                stored_session_id: str | None = None) -> VoiceJobRecord:
        if stored_session_id is not None:
            _identifier(stored_session_id, "stored_session_id")
        with self._transaction() as db:
            current = self._fenced(db, owner, job_id, run_id, expected_revision)
            if current.state != "dispatching":
                raise VoiceJobConflict("voice job is not dispatching")
            return self._update(db, current, state="running", stored_session_id=stored_session_id)

    def bind_stored_session(self, owner: VoiceJobOwner, job_id: str, *, run_id: str,
                            expected_revision: int, stored_session_id: str) -> VoiceJobRecord:
        _identifier(stored_session_id, "stored_session_id")
        with self._transaction() as db:
            current = self._fenced(db, owner, job_id, run_id, expected_revision)
            if current.terminal or current.state == "uncertain":
                raise VoiceJobConflict("voice job cannot bind a stored session")
            if current.stored_session_id is not None:
                if current.stored_session_id != stored_session_id:
                    raise VoiceJobConflict("stored session already bound")
                return current
            return self._update(db, current, stored_session_id=stored_session_id)

    def set_pending(self, owner: VoiceJobOwner, job_id: str, *, run_id: str, expected_revision: int,
                    pending_id: str, kind: str, prompt: str) -> VoiceJobRecord:
        _identifier(pending_id, "pending_id")
        if kind not in {"approval", "clarification"}:
            raise VoiceJobError("invalid pending kind")
        _text(prompt, "pending prompt", _MAX_PENDING - 1024)
        with self._transaction() as db:
            current = self._fenced(db, owner, job_id, run_id, expected_revision)
            if current.state not in {"running", "dispatching", "waiting"}:
                raise VoiceJobConflict("voice job cannot accept a pending request")
            payload = _json(dict(pending_id=pending_id, kind=kind, revision=current.revision + 1, prompt=prompt), _MAX_PENDING)
            return self._update(db, current, state="waiting", pending_json=payload)

    def complete(self, owner: VoiceJobOwner, job_id: str, *, run_id: str, expected_revision: int,
                 state: str = "completed", summary: str | None = None) -> VoiceJobRecord:
        if state not in {"completed", "failed", "cancelled"}:
            raise VoiceJobError("invalid terminal state")
        if summary is not None:
            _text(summary, "summary", _MAX_SUMMARY, empty=True)
        with self._transaction() as db:
            current = self._fenced(db, owner, job_id, run_id, expected_revision)
            if current.terminal or current.state in {"admitted", "uncertain"}:
                raise VoiceJobConflict("voice job cannot accept this completion")
            return self._update(db, current, state=state, summary=summary, pending_json=None, terminal_at=self._now())

    def uncertain(self, owner: VoiceJobOwner, job_id: str, *, run_id: str, expected_revision: int) -> VoiceJobRecord:
        with self._transaction() as db:
            current = self._fenced(db, owner, job_id, run_id, expected_revision)
            if current.terminal:
                raise VoiceJobConflict("terminal voice job cannot become uncertain")
            if current.state == "uncertain":
                return current
            return self._update(db, current, state="uncertain", pending_json=None)

    def reconcile(self, owner: VoiceJobOwner, job_id: str, *, run_id: str, expected_revision: int,
                  state: str, stored_session_id: str, summary: str | None = None) -> VoiceJobRecord:
        """Apply independently observed native state, never submit/resume a prompt.

        This trusted adapter-only seam rotates run_id, retiring pre-restart events.
        A running reconciliation must rebind native observers to the returned run.
        """
        _identifier(stored_session_id, "stored_session_id")
        if state not in {"running", "completed", "failed", "cancelled"}:
            raise VoiceJobError("invalid reconciliation state")
        if summary is not None:
            _text(summary, "summary", _MAX_SUMMARY, empty=True)
        with self._transaction() as db:
            current = self._fenced(db, owner, job_id, run_id, expected_revision)
            if current.state != "uncertain" or current.stored_session_id not in {None, stored_session_id}:
                raise VoiceJobConflict("voice job reconciliation does not match")
            return self._update(db, current, state=state, stored_session_id=stored_session_id,
                                run_id="run_" + uuid.uuid4().hex, summary=summary, pending_json=None,
                                terminal_at=self._now() if state in _TERMINAL else None)

    @staticmethod
    def _control_record(job: VoiceJobRecord, row: sqlite3.Row, *, is_new: bool = False) -> VoiceJobControl:
        body = json.loads(row["body"])
        return VoiceJobControl(job=job, request_id=row["request_id"], action=body["action"],
            expected_revision=body["expected_revision"], text=body["text"],
            pending_id=body["pending_id"], pending_revision=body["pending_revision"],
            decision_json=_json(body["decision"], _MAX_CONTROL) if body["decision"] is not None else None,
            state=row["state"], is_new=is_new)

    def admit_control(self, owner: VoiceJobOwner, job_id: str, *, run_id: str,
                      expected_revision: int, request_id: str, action: str,
                      text: str | None = None, pending_id: str | None = None,
                      pending_revision: int | None = None, decision: Any = None) -> VoiceJobControl:
        """Persist a one-shot control before invoking its external callback.

        Identical request replays return the receipt; changed bodies conflict.
        Approval/clarification decisions require both the current job revision and
        the exact pending ID/revision. queue preserves an outstanding question.
        """
        _identifier(request_id, "request_id")
        _identifier(run_id, "run_id")
        _integer(expected_revision, "expected_revision")
        if action not in {"steer", "queue", "cancel", "approval", "clarification"}:
            raise VoiceJobError("unsupported voice job control")
        if action in {"steer", "queue"}:
            _text(text, "control text", _MAX_CONTROL - 1024)
        elif text is not None:
            raise VoiceJobError("this control does not accept text")
        if action in {"approval", "clarification"}:
            _identifier(pending_id, "pending_id")
            _integer(pending_revision, "pending_revision")
            if decision is None:
                raise VoiceJobError("pending decision must be explicit")
        elif pending_id is not None or pending_revision is not None or decision is not None:
            raise VoiceJobError("unexpected pending decision fields")
        body = _json(dict(run_id=run_id, expected_revision=expected_revision, action=action,
                          text=text, pending_id=pending_id, pending_revision=pending_revision,
                          decision=decision), _MAX_CONTROL)
        with self._transaction() as db:
            current = self._get(db, owner, job_id)
            duplicate = db.execute("SELECT * FROM voice_job_controls WHERE job_id=? AND request_id=?",
                                   (job_id, request_id)).fetchone()
            if duplicate is not None:
                if duplicate["body"] != body:
                    raise VoiceJobConflict("control identifier has different body")
                return self._control_record(current, duplicate)
            current = self._fenced(db, owner, job_id, run_id, expected_revision)
            if current.state not in {"running", "waiting"}:
                raise VoiceJobConflict("voice job is not controllable")
            count, inflight = db.execute("SELECT COUNT(*), COALESCE(SUM(state='admitted'),0) "
                                        "FROM voice_job_controls WHERE job_id=?", (job_id,)).fetchone()
            # The reservation is established at original admission and must not
            # grow merely because a reopened ledger has different defaults.
            control_limit = db.execute("SELECT control_limit FROM voice_jobs WHERE job_id=?", (job_id,)).fetchone()[0]
            if count >= min(control_limit, self.maximum_controls):
                raise VoiceJobCapacity("voice job control capacity exhausted")
            if inflight:
                raise VoiceJobConflict("voice job already has an in-flight control")
            fields: dict[str, Any] = {}
            if action in {"approval", "clarification"}:
                pending = current.pending
                if (pending is None or pending.kind != action or pending.pending_id != pending_id
                        or pending.revision != pending_revision):
                    raise VoiceJobConflict("stale or mismatched pending decision")
                fields.update(state="running", pending_json=None)
            elif action == "cancel":
                # This is a *request*, not proof of cancellation. It can race a
                # successful native completion, which is still reported honestly.
                fields.update(state="cancel_requested", pending_json=None)
            elif action == "steer" and current.pending is not None:
                raise VoiceJobConflict("answer the pending request before steering")
            updated = self._update(db, current, **fields)
            db.execute("INSERT INTO voice_job_controls (job_id,request_id,body,state,dispatch_revision) "
                       "VALUES (?,?,?,'admitted',?)", (job_id, request_id, body, updated.revision))
            row = db.execute("SELECT * FROM voice_job_controls WHERE job_id=? AND request_id=?",
                             (job_id, request_id)).fetchone()
            return self._control_record(updated, row, is_new=True)

    def get_control(self, owner: VoiceJobOwner, job_id: str, request_id: str) -> VoiceJobControl:
        _identifier(request_id, "request_id")
        with self._transaction() as db:
            current = self._get(db, owner, job_id)
            row = db.execute("SELECT * FROM voice_job_controls WHERE job_id=? AND request_id=?",
                             (job_id, request_id)).fetchone()
            if row is None:
                raise VoiceJobNotFound("voice job control not found")
            return self._control_record(current, row)

    def finish_control(self, control: VoiceJobControl, *, accepted: bool) -> VoiceJobControl:
        """Record only this attempt's receipt; never overwrite newer job state."""
        if type(control) is not VoiceJobControl or type(accepted) is not bool:
            raise VoiceJobError("invalid voice control receipt")
        job = control.job
        with self._transaction() as db:
            current = self._get(db, job.owner, job.job_id)
            row = db.execute("SELECT * FROM voice_job_controls WHERE job_id=? AND request_id=?",
                             (job.job_id, control.request_id)).fetchone()
            if (row is None or current.run_id != job.run_id or row["dispatch_revision"] != job.revision
                    or json.loads(row["body"])["run_id"] != job.run_id):
                raise VoiceJobConflict("control receipt does not match dispatch")
            if row["state"] != "admitted":
                raise VoiceJobConflict("voice control receipt is already sealed")
            state = "accepted" if accepted else "uncertain"
            db.execute("UPDATE voice_job_controls SET state=? WHERE job_id=? AND request_id=?",
                       (state, job.job_id, control.request_id))
            if (not accepted and current.revision == job.revision and current.run_id == job.run_id
                    and not current.terminal):
                current = self._update(db, current, state="uncertain", pending_json=None)
            row = db.execute("SELECT * FROM voice_job_controls WHERE job_id=? AND request_id=?",
                             (job.job_id, control.request_id)).fetchone()
            return self._control_record(current, row)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                if self._db is not None:
                    self._db.close()
                    self._db = None
            finally:
                if self._fd is not None:
                    os.close(self._fd)
                    self._fd = None

    def __enter__(self) -> VoiceJobLedger:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


class VoiceJobOrchestrator:
    """Own callback tasks independently of the voice connection/request task.

    submit(job) must route job.text / job.message_id through the ordinary adapter
    MessageEvent/handle_message path, using job.session_id and owner.agent_id.
    control(envelope) must use that same exact job chat and translate only the
    whitelisted actions. Its return acknowledges dispatch, not execution success.

    authorize(owner), when supplied, is a synchronous freshness check on every
    ingress and immediately before/after a callback. Without it the embedding
    adapter MUST perform that check itself. It must never rebind an old owner to
    the currently selected account, device, host epoch or profile.

    Use one orchestrator per ledger/event loop. No constructor, reconnect, or
    list operation dispatches saved jobs. There is no provider/audio dependency.
    """

    def __init__(self, ledger: VoiceJobLedger, *,
                 submit: Callable[[VoiceJobRecord], Awaitable[VoiceJobSubmission | None]],
                 control: Callable[[VoiceJobControl], Awaitable[None]],
                 authorize: Callable[[VoiceJobOwner], bool] | None = None) -> None:
        if not isinstance(ledger, VoiceJobLedger) or not callable(submit) or not callable(control):
            raise VoiceJobError("a ledger and submit/control callbacks are required")
        if authorize is not None and not callable(authorize):
            raise VoiceJobError("authorize must be callable")
        self.ledger = ledger
        self._submit = submit
        self._control = control
        self._authorize = authorize
        self._accepting = True
        self._loop: asyncio.AbstractEventLoop | None = None
        self._tasks: dict[tuple[str, str, str], asyncio.Task[None]] = {}

    def _check_owner(self, owner: VoiceJobOwner) -> None:
        self.ledger._owner(owner)
        if self._authorize is not None and self._authorize(owner) is not True:
            raise VoiceJobNotFound("voice job owner is no longer authorized")

    def _check_ingress(self, owner: VoiceJobOwner) -> None:
        if not self._accepting:
            raise VoiceJobClosed("voice job orchestrator is retired")
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif self._loop is not loop:
            raise VoiceJobConflict("voice job orchestrator belongs to a different event loop")
        self._check_owner(owner)

    def _spawn(self, key: tuple[str, str, str], coroutine: Coroutine[Any, Any, None]) -> None:
        # Creating tasks is confined to async entrypoints on this instance's loop.
        task = asyncio.create_task(coroutine)
        self._tasks[key] = task

        def done(completed: asyncio.Task[None]) -> None:
            if self._tasks.get(key) is completed:
                self._tasks.pop(key, None)
            # Retrieve failures without logging callback text, which may contain
            # prompts or secrets. Durable job/receipt state is the recovery path.
            if not completed.cancelled():
                completed.exception()
        task.add_done_callback(done)

    def _dispatch_current(self, job: VoiceJobRecord) -> None:
        self._check_owner(job.owner)
        current = self.ledger.get(job.owner, job.job_id)
        if (current.run_id != job.run_id or current.revision != job.revision
                or current.session_id != job.session_id or current.message_id != job.message_id):
            raise VoiceJobConflict("voice callback dispatch fence is stale")

    def _mark_uncertain(self, job: VoiceJobRecord) -> None:
        try:
            self.ledger.uncertain(job.owner, job.job_id, run_id=job.run_id, expected_revision=job.revision)
        except (VoiceJobConflict, VoiceJobClosed):
            # A newer revision or independently observed terminal result wins.
            pass

    async def delegate(self, owner: VoiceJobOwner, *, voice_id: str,
                       delegation_id: str, text: str) -> VoiceJobRecord:
        self._check_ingress(owner)
        admitted = self.ledger.admit(owner, voice_id, delegation_id, text)
        if not admitted.is_new:
            return admitted
        # No await between durable admission/claim and independent task creation.
        claimed = self.ledger.start(owner, admitted.job_id, run_id=admitted.run_id,
                                    expected_revision=admitted.revision)
        self._spawn((claimed.job_id, "submit", ""), self._dispatch_submit(claimed))
        return replace(claimed, is_new=True)

    async def _dispatch_submit(self, job: VoiceJobRecord) -> None:
        try:
            self._dispatch_current(job)
            receipt = await self._submit(job)
            self._check_owner(job.owner)
            if receipt is not None and type(receipt) is not VoiceJobSubmission:
                raise VoiceJobError("submit callback must return VoiceJobSubmission or None")
            current = self.ledger.get(job.owner, job.job_id)
            if current.run_id == job.run_id and current.revision == job.revision:
                self.ledger.running(job.owner, job.job_id, run_id=job.run_id,
                    expected_revision=job.revision,
                    stored_session_id=receipt.stored_session_id if receipt is not None else None)
            # Observer callbacks may have already advanced or finished this job.
            # A late dispatch receipt must not overwrite their newer revision.
        except asyncio.CancelledError:
            self._mark_uncertain(job)
            raise
        except Exception:
            self._mark_uncertain(job)

    async def control(self, owner: VoiceJobOwner, job_id: str, *, run_id: str,
                      expected_revision: int, request_id: str, action: str,
                      text: str | None = None, pending_id: str | None = None,
                      pending_revision: int | None = None, decision: Any = None) -> VoiceJobControl:
        self._check_ingress(owner)
        envelope = self.ledger.admit_control(owner, job_id, run_id=run_id,
            expected_revision=expected_revision, request_id=request_id, action=action,
            text=text, pending_id=pending_id, pending_revision=pending_revision, decision=decision)
        key = (job_id, "control", request_id)
        if envelope.is_new:
            self._spawn(key, self._dispatch_control(envelope))
        task = self._tasks.get(key)
        if task is not None:
            # Caller/voice disconnect does not cancel an already admitted action.
            await asyncio.shield(task)
        self._check_owner(owner)
        return self.ledger.get_control(owner, job_id, request_id)

    async def _dispatch_control(self, envelope: VoiceJobControl) -> None:
        accepted = False
        try:
            self._dispatch_current(envelope.job)
            result = await self._control(envelope)
            if result is not None:
                raise VoiceJobError("control callback must acknowledge with None or raise")
            self._check_owner(envelope.job.owner)
            accepted = True
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        finally:
            try:
                self.ledger.finish_control(envelope, accepted=accepted)
            except (VoiceJobConflict, VoiceJobClosed):
                pass

    def get(self, owner: VoiceJobOwner, job_id: str) -> VoiceJobRecord:
        self._check_owner(owner)
        return self.ledger.get(owner, job_id)

    def list(self, owner: VoiceJobOwner, *, voice_id: str | None = None,
             limit: int = 100, offset: int = 0) -> tuple[VoiceJobRecord, ...]:
        self._check_owner(owner)
        return self.ledger.list(owner, voice_id=voice_id, limit=limit, offset=offset)

    def complete(self, owner: VoiceJobOwner, job_id: str, *, run_id: str,
                 expected_revision: int, state: str = "completed", summary: str | None = None) -> VoiceJobRecord:
        self._check_owner(owner)
        return self.ledger.complete(owner, job_id, run_id=run_id,
            expected_revision=expected_revision, state=state, summary=summary)

    def set_pending(self, owner: VoiceJobOwner, job_id: str, *, run_id: str,
                    expected_revision: int, pending_id: str, kind: str, prompt: str) -> VoiceJobRecord:
        self._check_owner(owner)
        return self.ledger.set_pending(owner, job_id, run_id=run_id, expected_revision=expected_revision,
                                       pending_id=pending_id, kind=kind, prompt=prompt)

    def voice_event(self, owner: VoiceJobOwner, *, voice_id: str, event: str) -> None:
        """Audio presentation events deliberately have no job lifecycle effect."""
        self._check_owner(owner)
        _identifier(voice_id, "voice_id")
        if event not in {"detach", "mute", "audio_cleared", "interrupted", "reconnected"}:
            raise VoiceJobError("invalid voice presentation event")

    def detach(self, owner: VoiceJobOwner, *, voice_id: str) -> None:
        self.voice_event(owner, voice_id=voice_id, event="detach")

    async def wait_idle(self) -> None:
        """Wait for callback receipts, NOT for background Hermes job completion.

        Cancelling this wait leaves the independent callback tasks alive.
        """
        while self._tasks:
            await asyncio.shield(asyncio.gather(*tuple(self._tasks.values()), return_exceptions=True))

    async def aclose(self) -> None:
        """Retire admission and drain dispatch callbacks; never send /stop.

        The caller owns ledger.close() after this returns. Closing a *voice call*
        must use detach(), not this adapter-lifetime drain.
        """
        self._accepting = False
        await self.wait_idle()
