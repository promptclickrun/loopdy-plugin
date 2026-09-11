"""Durable, bounded admission journal for authenticated direct commands."""

from __future__ import annotations

import asyncio
import errno
import hashlib
import ipaddress
import json
import math
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
import weakref
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal
from urllib.parse import quote, urlsplit

from .direct_connection import DirectPeer


_COMMAND_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_DEVICE_ID = re.compile(r"^[A-Za-z0-9_-]{1,96}$")
_FINGERPRINT = re.compile(r"^[A-Za-z0-9_-]{43}$")
_MAX_BODY_BYTES = 512 * 1024
_MAX_JSON_DEPTH = 20
_REQUEST_PAST_SECONDS = 24 * 60 * 60
_REQUEST_FUTURE_SECONDS = 60
_RECORD_TTL_SECONDS = _REQUEST_PAST_SECONDS + _REQUEST_FUTURE_SECONDS
_METADATA_OVERHEAD_BYTES = 256
_SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


@dataclass(frozen=True)
class DirectCommandAdmission:
    """Immutable admission snapshot; ``result`` returns a fresh decoded value."""

    account_origin: str
    host_device_id: str
    host_epoch: int
    peer_device_id: str
    peer_epoch: int
    command_id: str
    issued_at: int
    payload_digest: str
    state: Literal["admitted", "completed", "uncertain"]
    is_new: bool
    _process_owner: str = field(repr=False)
    _capability: str = field(repr=False)
    _result_json: bytes | None = field(default=None, repr=False)

    @property
    def result(self) -> dict[str, Any] | None:
        if self._result_json is None:
            return None
        decoded = json.loads(self._result_json)
        if type(decoded) is not dict:
            raise ValueError("stored direct command result is invalid")
        return decoded


def _canonical_origin(value: Any, field_name: str) -> str:
    try:
        encoded_length = len(value.encode("utf-8")) if isinstance(value, str) else 0
    except UnicodeEncodeError as error:
        raise ValueError(f"{field_name} is invalid") from error
    if (
        not isinstance(value, str)
        or not value
        or encoded_length > 512
        or any(character.isspace() or ord(character) < 0x20 for character in value)
        or "\\" in value
        or "?" in value
        or "#" in value
    ):
        raise ValueError(f"{field_name} is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (UnicodeError, ValueError) as error:
        raise ValueError(f"{field_name} is invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != ""
        or parsed.query
        or parsed.fragment
        or "%" in parsed.netloc
        or parsed.netloc.endswith(":")
    ):
        raise ValueError(f"{field_name} is invalid")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError(f"{field_name} is invalid") from error
    if not host or port == 0:
        raise ValueError(f"{field_name} is invalid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if (
            len(host) > 253
            or host.endswith(".")
            or any(
                not label
                or len(label) > 63
                or re.fullmatch(
                    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label
                )
                is None
                for label in labels
            )
        ):
            raise ValueError(f"{field_name} is invalid")
    rendered_host = f"[{host}]" if ":" in host else host
    canonical = f"https://{rendered_host}"
    if port not in {None, 443}:
        canonical += f":{port}"
    if value != canonical:
        raise ValueError(f"{field_name} is not canonical")
    return canonical


def _validate_peer(peer: Any) -> DirectPeer:
    if type(peer) is not DirectPeer:
        raise ValueError("direct peer principal is invalid")
    _canonical_origin(peer.account_origin, "account_origin")
    _canonical_origin(peer.direct_origin, "direct_origin")
    if (
        not isinstance(peer.host_device_id, str)
        or _DEVICE_ID.fullmatch(peer.host_device_id) is None
    ):
        raise ValueError("host_device_id is invalid")
    if (
        not isinstance(peer.peer_device_id, str)
        or _DEVICE_ID.fullmatch(peer.peer_device_id) is None
    ):
        raise ValueError("peer_device_id is invalid")
    if type(peer.host_epoch) is not int or peer.host_epoch <= 0:
        raise ValueError("host_epoch is invalid")
    if type(peer.peer_epoch) is not int or peer.peer_epoch <= 0:
        raise ValueError("peer_epoch is invalid")
    if (
        not isinstance(peer.host_key_fingerprint, str)
        or _FINGERPRINT.fullmatch(peer.host_key_fingerprint) is None
    ):
        raise ValueError("host_key_fingerprint is invalid")
    if (
        not isinstance(peer.peer_key_fingerprint, str)
        or _FINGERPRINT.fullmatch(peer.peer_key_fingerprint) is None
    ):
        raise ValueError("peer_key_fingerprint is invalid")
    return peer


def _validate_json(value: Any, depth: int = 1) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("JSON body exceeds maximum depth")
    if value is None or type(value) in {bool, int}:
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("JSON body contains a non-finite number")
        return
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("JSON body contains invalid Unicode") from error
        return
    if type(value) is list:
        for item in value:
            _validate_json(item, depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("JSON object keys must be strings")
            try:
                key.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ValueError("JSON body contains invalid Unicode") from error
            _validate_json(item, depth + 1)
        return
    raise ValueError("JSON body contains an unsupported value")


def _canonical_object(value: Any, label: str) -> bytes:
    if type(value) is not dict:
        raise ValueError(f"{label} must be an object")
    _validate_json(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        raise ValueError(f"{label} is not canonical JSON") from error
    if len(encoded) > _MAX_BODY_BYTES:
        raise ValueError(f"{label} exceeds maximum size")
    return encoded


class DirectCommandJournal:
    """Persist admission before delivery; callers revalidate peer auth per use."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        clock: Callable[[], float] = time.time,
        maximum_entries: int = 512,
        maximum_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        if not callable(clock):
            raise ValueError("clock must be callable")
        if type(maximum_entries) is not int or maximum_entries <= 0:
            raise ValueError("maximum_entries must be a positive integer")
        if type(maximum_bytes) is not int or maximum_bytes <= 0:
            raise ValueError("maximum_bytes must be a positive integer")
        self.path = Path(os.path.abspath(os.fspath(path)))
        self.clock = clock
        self.maximum_entries = maximum_entries
        self.maximum_bytes = maximum_bytes
        self._process_owner = uuid.uuid4().hex
        self._lock = threading.RLock()
        self._closed = False
        self._capabilities: weakref.WeakValueDictionary[
            str, DirectCommandAdmission
        ] = weakref.WeakValueDictionary()
        self._initialize()

    async def admit(
        self,
        peer: DirectPeer,
        command_id: str,
        issued_at: int,
        payload: dict[str, Any],
    ) -> DirectCommandAdmission:
        self._require_open()
        principal = _validate_peer(peer)
        if not isinstance(command_id, str) or _COMMAND_ID.fullmatch(command_id) is None:
            raise ValueError("command_id is invalid")
        payload_json = _canonical_object(payload, "payload")
        digest = hashlib.sha256(payload_json).hexdigest()
        return await asyncio.to_thread(
            self._admit_sync, principal, command_id, issued_at, digest
        )

    async def complete(
        self, admission: DirectCommandAdmission, result: dict[str, Any]
    ) -> DirectCommandAdmission:
        self._require_open()
        result_json = _canonical_object(result, "result")
        return await asyncio.to_thread(self._complete_sync, admission, result_json)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._capabilities.clear()

    def _initialize(self) -> None:
        parent_descriptor = self._open_parent(create=True)
        try:
            self._guard_sidecars_in_parent(parent_descriptor)
            try:
                database_descriptor = os.open(
                    self.path.name,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent_descriptor,
                )
            except FileExistsError:
                database_descriptor = self._open_database_file(parent_descriptor)
            try:
                database_stat = os.fstat(database_descriptor)
                if not stat.S_ISREG(database_stat.st_mode):
                    raise ValueError("direct command journal path must be a regular file")
                os.fchmod(database_descriptor, 0o600)
                identity = (database_stat.st_dev, database_stat.st_ino)
            finally:
                os.close(database_descriptor)
        finally:
            os.close(parent_descriptor)
        connection = self._sqlite_connection(identity)
        try:
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS direct_commands (
                    account_origin TEXT NOT NULL,
                    host_device_id TEXT NOT NULL,
                    host_epoch INTEGER NOT NULL,
                    peer_device_id TEXT NOT NULL,
                    peer_epoch INTEGER NOT NULL,
                    command_id TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    payload_digest TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('admitted', 'completed', 'uncertain')),
                    process_owner TEXT NOT NULL,
                    result_json BLOB,
                    expires_at INTEGER NOT NULL,
                    reserved_bytes INTEGER NOT NULL,
                    PRIMARY KEY (
                        account_origin, host_device_id, host_epoch,
                        peer_device_id, peer_epoch, command_id
                    )
                ) WITHOUT ROWID
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS direct_commands_expiry_idx "
                "ON direct_commands(expires_at)"
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
            self._restrict_files()

    @staticmethod
    def _directory_flags() -> int:
        return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    def _open_parent(self, *, create: bool) -> int:
        descriptor = os.open(self.path.anchor, self._directory_flags())
        try:
            for component in self.path.parent.parts[1:]:
                try:
                    child = os.open(
                        component, self._directory_flags(), dir_fd=descriptor
                    )
                except FileNotFoundError:
                    if not create:
                        raise
                    created = False
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=descriptor)
                        created = True
                    except FileExistsError:
                        pass
                    try:
                        child = os.open(
                            component, self._directory_flags(), dir_fd=descriptor
                        )
                    except OSError as error:
                        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                            raise ValueError(
                                "direct command journal parent contains a symlink or non-directory"
                            ) from error
                        raise
                    if created:
                        os.fchmod(child, 0o700)
                except OSError as error:
                    if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                        raise ValueError(
                            "direct command journal parent contains a symlink or non-directory"
                        ) from error
                    raise
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _open_database_file(self, parent_descriptor: int) -> int:
        try:
            descriptor = os.open(
                self.path.name, os.O_RDWR | os.O_NOFOLLOW, dir_fd=parent_descriptor
            )
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ValueError(
                    "direct command journal path must not be a symlink"
                ) from error
            raise
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise ValueError("direct command journal path must be a regular file")
        return descriptor

    def _database_identity(self) -> tuple[int, int]:
        parent_descriptor = self._open_parent(create=False)
        try:
            database_descriptor = self._open_database_file(parent_descriptor)
            try:
                database_stat = os.fstat(database_descriptor)
                return database_stat.st_dev, database_stat.st_ino
            finally:
                os.close(database_descriptor)
        finally:
            os.close(parent_descriptor)

    def _guard_sidecar_targets(self) -> None:
        parent_descriptor = self._open_parent(create=False)
        try:
            self._guard_sidecars_in_parent(parent_descriptor)
        finally:
            os.close(parent_descriptor)

    def _guard_sidecars_in_parent(self, parent_descriptor: int) -> None:
        for suffix in _SQLITE_SIDECAR_SUFFIXES:
            name = f"{self.path.name}{suffix}"
            try:
                descriptor = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_descriptor
                )
            except FileNotFoundError:
                continue
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError(
                        "direct command journal sidecar must not be a symlink"
                    ) from error
                raise
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise ValueError("direct command journal sidecar must be regular")
            finally:
                os.close(descriptor)

    def _sqlite_connection(self, expected_identity: tuple[int, int]) -> sqlite3.Connection:
        self._guard_sidecar_targets()
        uri = f"file:{quote(str(self.path), safe='/')}?mode=rw"
        connection = sqlite3.connect(
            uri, timeout=5, isolation_level=None, uri=True
        )
        try:
            if self._database_identity() != expected_identity:
                raise ValueError("direct command journal path changed while opening")
            return connection
        except BaseException:
            connection.close()
            raise

    def _connect(self) -> sqlite3.Connection:
        identity = self._database_identity()
        connection = self._sqlite_connection(identity)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA synchronous=NORMAL")
        return connection

    def _admit_sync(
        self,
        peer: DirectPeer,
        command_id: str,
        issued_at: int,
        digest: str,
    ) -> DirectCommandAdmission:
        with self._lock:
            self._require_open()
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                now = self._now()
                if type(issued_at) is not int:
                    raise ValueError("issued_at must be an integer Unix timestamp")
                if issued_at > now + _REQUEST_FUTURE_SECONDS:
                    raise ValueError("issued_at is too far in the future")
                if issued_at < now - _REQUEST_PAST_SECONDS:
                    raise ValueError("issued_at is expired")
                connection.execute(
                    "DELETE FROM direct_commands WHERE expires_at <= ?", (now,)
                )
                key = self._key(peer, command_id)
                row = connection.execute(
                    "SELECT * FROM direct_commands WHERE "
                    "account_origin=? AND host_device_id=? AND host_epoch=? AND "
                    "peer_device_id=? AND peer_epoch=? AND command_id=?",
                    key,
                ).fetchone()
                if row is not None:
                    if row["payload_digest"] != digest or row["issued_at"] != issued_at:
                        raise ValueError("command_id conflicts with an existing command")
                    state = str(row["state"])
                    if state == "admitted" and row["process_owner"] != self._process_owner:
                        state = "uncertain"
                    connection.commit()
                    result_json = (
                        bytes(row["result_json"]) if row["result_json"] is not None else None
                    )
                    return self._admission(
                        peer=peer,
                        command_id=command_id,
                        issued_at=issued_at,
                        digest=digest,
                        state=state,  # type: ignore[arg-type]
                        is_new=False,
                        result_json=result_json,
                        completable=state == "admitted"
                        and row["process_owner"] == self._process_owner,
                    )

                metadata_bytes = self._metadata_bytes(peer, command_id)
                reserved_bytes = metadata_bytes + _MAX_BODY_BYTES
                count, used_bytes = connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM(reserved_bytes), 0) FROM direct_commands"
                ).fetchone()
                if count >= self.maximum_entries:
                    raise ValueError("direct command entry capacity is exhausted")
                if used_bytes + reserved_bytes > self.maximum_bytes:
                    raise ValueError("direct command byte capacity is exhausted")
                connection.execute(
                    "INSERT INTO direct_commands ("
                    "account_origin, host_device_id, host_epoch, peer_device_id, peer_epoch, "
                    "command_id, issued_at, payload_digest, state, process_owner, result_json, "
                    "expires_at, reserved_bytes) VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, 'admitted', ?, NULL, ?, ?)",
                    (
                        *key,
                        issued_at,
                        digest,
                        self._process_owner,
                        issued_at + _RECORD_TTL_SECONDS,
                        reserved_bytes,
                    ),
                )
                connection.commit()
                return self._admission(
                    peer=peer,
                    command_id=command_id,
                    issued_at=issued_at,
                    digest=digest,
                    state="admitted",
                    is_new=True,
                    result_json=None,
                    completable=True,
                )
            except BaseException:
                connection.rollback()
                raise
            finally:
                connection.close()
                self._restrict_files()

    def _complete_sync(
        self, admission: DirectCommandAdmission, result_json: bytes
    ) -> DirectCommandAdmission:
        with self._lock:
            self._require_open()
            if type(admission) is not DirectCommandAdmission:
                raise ValueError("direct command admission is invalid")
            known = self._capabilities.get(admission._capability)
            if known is not admission or admission._process_owner != self._process_owner:
                raise ValueError("direct command admission is not owned by this journal")
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                key = (
                    admission.account_origin,
                    admission.host_device_id,
                    admission.host_epoch,
                    admission.peer_device_id,
                    admission.peer_epoch,
                    admission.command_id,
                )
                row = connection.execute(
                    "SELECT issued_at, payload_digest, state, process_owner, reserved_bytes "
                    "FROM direct_commands WHERE account_origin=? AND host_device_id=? AND "
                    "host_epoch=? AND peer_device_id=? AND peer_epoch=? AND command_id=?",
                    key,
                ).fetchone()
                if (
                    row is None
                    or row["issued_at"] != admission.issued_at
                    or row["payload_digest"] != admission.payload_digest
                    or row["state"] != "admitted"
                    or row["process_owner"] != self._process_owner
                ):
                    raise ValueError("direct command admission is stale or does not match")
                metadata_bytes = int(row["reserved_bytes"]) - _MAX_BODY_BYTES
                new_reserved_bytes = metadata_bytes + len(result_json)
                updated = connection.execute(
                    "UPDATE direct_commands SET state='completed', result_json=?, reserved_bytes=? "
                    "WHERE account_origin=? AND host_device_id=? AND host_epoch=? AND "
                    "peer_device_id=? AND peer_epoch=? AND command_id=? AND issued_at=? AND "
                    "payload_digest=? AND state='admitted' AND process_owner=?",
                    (
                        result_json,
                        new_reserved_bytes,
                        *key,
                        admission.issued_at,
                        admission.payload_digest,
                        self._process_owner,
                    ),
                )
                if updated.rowcount != 1:
                    raise ValueError("direct command completion lost ownership")
                connection.commit()
                self._forget_key(key)
                return DirectCommandAdmission(
                    account_origin=admission.account_origin,
                    host_device_id=admission.host_device_id,
                    host_epoch=admission.host_epoch,
                    peer_device_id=admission.peer_device_id,
                    peer_epoch=admission.peer_epoch,
                    command_id=admission.command_id,
                    issued_at=admission.issued_at,
                    payload_digest=admission.payload_digest,
                    state="completed",
                    is_new=admission.is_new,
                    _process_owner=self._process_owner,
                    _capability=uuid.uuid4().hex,
                    _result_json=result_json,
                )
            except BaseException:
                connection.rollback()
                raise
            finally:
                connection.close()
                self._restrict_files()

    def _admission(
        self,
        *,
        peer: DirectPeer,
        command_id: str,
        issued_at: int,
        digest: str,
        state: Literal["admitted", "completed", "uncertain"],
        is_new: bool,
        result_json: bytes | None,
        completable: bool,
    ) -> DirectCommandAdmission:
        capability = uuid.uuid4().hex
        admission = DirectCommandAdmission(
            account_origin=peer.account_origin,
            host_device_id=peer.host_device_id,
            host_epoch=peer.host_epoch,
            peer_device_id=peer.peer_device_id,
            peer_epoch=peer.peer_epoch,
            command_id=command_id,
            issued_at=issued_at,
            payload_digest=digest,
            state=state,
            is_new=is_new,
            _process_owner=self._process_owner,
            _capability=capability,
            _result_json=result_json,
        )
        if completable:
            self._capabilities[capability] = admission
        return admission

    def _forget_key(self, key: tuple[Any, ...]) -> None:
        stale = [
            capability
            for capability, admission in self._capabilities.items()
            if (
                admission.account_origin,
                admission.host_device_id,
                admission.host_epoch,
                admission.peer_device_id,
                admission.peer_epoch,
                admission.command_id,
            )
            == key
        ]
        for capability in stale:
            self._capabilities.pop(capability, None)

    @staticmethod
    def _key(peer: DirectPeer, command_id: str) -> tuple[Any, ...]:
        return (
            peer.account_origin,
            peer.host_device_id,
            peer.host_epoch,
            peer.peer_device_id,
            peer.peer_epoch,
            command_id,
        )

    @staticmethod
    def _metadata_bytes(peer: DirectPeer, command_id: str) -> int:
        return _METADATA_OVERHEAD_BYTES + sum(
            len(value.encode("utf-8"))
            for value in (
                peer.account_origin,
                peer.host_device_id,
                peer.peer_device_id,
                command_id,
            )
        )

    def _now(self) -> int:
        try:
            current = float(self.clock())
        except (TypeError, ValueError, OverflowError) as error:
            raise ValueError("clock returned an invalid time") from error
        if not math.isfinite(current):
            raise ValueError("clock returned an invalid time")
        return int(current)

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("direct command journal is closed")

    def _restrict_files(self) -> None:
        parent_descriptor = self._open_parent(create=False)
        try:
            for name in (
                self.path.name,
                *(f"{self.path.name}{suffix}" for suffix in _SQLITE_SIDECAR_SUFFIXES),
            ):
                try:
                    descriptor = os.open(
                        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_descriptor
                    )
                except FileNotFoundError:
                    continue
                except OSError as error:
                    if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                        raise ValueError(
                            "direct command journal file must not be a symlink"
                        ) from error
                    raise
                try:
                    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                        raise ValueError(
                            "direct command journal file must be regular"
                        )
                    os.fchmod(descriptor, 0o600)
                finally:
                    os.close(descriptor)
        finally:
            os.close(parent_descriptor)


__all__ = ["DirectCommandAdmission", "DirectCommandJournal"]
