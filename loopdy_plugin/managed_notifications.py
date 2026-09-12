"""Notification-only native enrollment and durable, recipient-scoped delivery.

This module owns no Hermes runtime internals. Stock registered observers provide
lifecycle facts; a plugin-owned worker drains frozen requests over HTTPS. Chat,
Link pairing, the legacy provider and LOOPDY_HOME_TARGET are not prerequisites.
"""
from __future__ import annotations

try:
    import fcntl
except ImportError:  # Unsupported private-store locking must not break legacy APIs.
    fcntl = None
import hashlib
import json
import logging
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
from collections import OrderedDict
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .relay_crypto import (
    b64url_decode, b64url_encode, canonical_json_bytes, encrypt_alert, key_id,
    public_key_bytes, public_key_from_x963, sign_p1363,
)
from .session_state import open_profile_store

ORIGIN = "https://link.loopdy.app"
ROOT = "/v1/notifications/host-grants"
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_EVENT_TYPES = {"session.completed", "session.failed", "approval.required"}
_APPROVAL_EVENT = "approval.required"
_APPROVAL_GRACE_SECONDS = 3
_APPROVAL_TTL_SECONDS = 60
_APPROVAL_LIMIT = 4096
_APPROVAL_HOOKS = ("pre_approval_request", "post_approval_response")
_ACTIONS = {
    "thinking": "Your agent is working", "waiting": "Your agent needs attention",
    "using_tool": "Your agent is working", "delegating": "Agents are working",
    "responding": "Your agent is responding", "completed": "Your agent finished",
    "failed": "Your agent could not finish",
}
logger = logging.getLogger("hermes.plugins.loopdy.notifications")


class ManagedNotificationError(ValueError):
    def __init__(self, code: str, status: int = 409):
        super().__init__(code)
        self.code, self.status = code, status


def _identifier(value: Any, pattern: re.Pattern = _ID) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ManagedNotificationError("notification_coordinate_invalid", 400)
    return value


def session_reference(profile: str, session_id: str) -> str:
    return b64url_encode(hashlib.sha256(f"{profile}\0{session_id}".encode()).digest())


def host_request_transcript(method: str, path: str, grant_id: str, timestamp: int, nonce: str, raw: bytes) -> bytes:
    return "\n".join(("loopdy-notification-host-v1", method, path, grant_id, str(timestamp), nonce, hashlib.sha256(raw).hexdigest())).encode()


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ManagedNotificationError("notification_redirect_rejected", 502)


def _https_request(method: str, path: str, raw: bytes, headers: dict[str, str]) -> dict[str, Any]:
    if not path.startswith(ROOT + "/") or "?" in path or "#" in path:
        raise ManagedNotificationError("notification_path_invalid", 400)
    request = Request(ORIGIN + path, data=raw if raw else None, headers=headers, method=method)
    try:
        with build_opener(_NoRedirect()).open(request, timeout=12) as response:
            content = response.read(65537)
            if len(content) > 65536:
                raise ManagedNotificationError("notification_response_too_large", 502)
            value = json.loads(content)
            if not isinstance(value, dict) or value.get("version") != 1:
                raise ManagedNotificationError("notification_response_invalid", 502)
            return value
    except HTTPError as error:
        # Do not copy server bodies, tokens, grant contents or headers into logs.
        raise ManagedNotificationError("notification_remote_rejected", error.code) from None
    except (OSError, json.JSONDecodeError) as error:
        raise ManagedNotificationError("notification_service_unavailable", 503) from error


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ManagedNotificationError("notification_private_storage_required", 503)


def _private_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ManagedNotificationError("notification_private_storage_required", 503)


class ManagedNotifications:
    """One process-owned observer/worker; SQLite serializes other API processes."""
    def __init__(self, directory: Path, *, transport: Callable = _https_request,
                 clock: Callable = time.time, session_opener: Callable = open_profile_store):
        if fcntl is None:
            raise ManagedNotificationError("notification_platform_unavailable", 503)
        self._fcntl = fcntl
        _private_directory(directory)
        self.directory, self.transport, self.clock = directory, transport, clock
        self.session_opener = session_opener
        self.preference_policy: Callable | None = None
        self._lock = threading.RLock()
        self._wake, self._stop = threading.Event(), threading.Event()
        self._worker: threading.Thread | None = None
        self._worker_lock = None
        self._loaded_profiles: set[str] = set()
        self._approval_profiles: set[str] = set()
        # An observation belongs to this producer lifetime, never a recovered prompt.
        self._approval_owner = str(uuid.uuid4())
        self._work: OrderedDict[tuple[str, str, str], dict[str, Any]] = OrderedDict()
        self._child_owners: dict[tuple[str, str, str], str] = {}
        self._key = self._identity()
        self.public_key = b64url_encode(public_key_bytes(self._key.public_key()))
        self.key_id = key_id(public_key_bytes(self._key.public_key()))
        self.db_path = directory / "journal.sqlite3"
        descriptor = os.open(self.db_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        _private_file(self.db_path)
        with self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS grants(grant_id TEXT PRIMARY KEY, public_json TEXT NOT NULL, state TEXT NOT NULL, expires INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS subscriptions(grant_id TEXT NOT NULL REFERENCES grants(grant_id) ON DELETE CASCADE, profile TEXT NOT NULL, session_id TEXT NOT NULL, session_ref TEXT NOT NULL, PRIMARY KEY(grant_id,profile,session_id));
                CREATE TABLE IF NOT EXISTS events(event_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(grant_id) ON DELETE CASCADE, detail_json TEXT NOT NULL, occurred_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS pending(intent_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(grant_id) ON DELETE CASCADE, path TEXT NOT NULL, raw BLOB NOT NULL, expires INTEGER NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL, session_ref TEXT NOT NULL, activity_id TEXT);
                CREATE INDEX IF NOT EXISTS pending_due ON pending(state,next_attempt);
                CREATE TABLE IF NOT EXISTS approval_attention(event_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(grant_id) ON DELETE CASCADE, profile TEXT NOT NULL, session_id TEXT NOT NULL, turn_id TEXT NOT NULL, tool_call_id TEXT NOT NULL, owner TEXT NOT NULL, state TEXT NOT NULL, expires INTEGER NOT NULL, reason TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS approval_scope ON approval_attention(grant_id,profile,session_id,turn_id);
                CREATE TABLE IF NOT EXISTS activities(activity_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(grant_id) ON DELETE CASCADE, profile TEXT NOT NULL, session_id TEXT NOT NULL, session_ref TEXT NOT NULL, lease_expires INTEGER NOT NULL, work_turn TEXT, state TEXT NOT NULL, last_timestamp INTEGER NOT NULL DEFAULT 0, last_signature TEXT, last_queued_at INTEGER NOT NULL DEFAULT 0);
            """)

    @contextmanager
    def _db(self):
        connection = sqlite3.connect(self.db_path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _identity(self):
        # A separate sidecar lock avoids locking SQLite's own inode. Never place
        # private key material inside the replaceable plugin install directory.
        lock_path = self.directory / "identity.lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a+b") as lock:
            _private_file(lock_path)
            self._fcntl.flock(lock, self._fcntl.LOCK_EX)
            path = self.directory / "host-key.pem"
            if not path.exists():
                key = ec.generate_private_key(ec.SECP256R1())
                encoded = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                temp = self.directory / f".host-key-{uuid.uuid4()}.tmp"
                try:
                    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, "wb") as output:
                        output.write(encoded); output.flush(); os.fsync(output.fileno())
                    os.replace(temp, path)
                finally:
                    temp.unlink(missing_ok=True)
            _private_file(path)
            if path.stat().st_size > 4096:
                raise ManagedNotificationError("notification_identity_invalid", 503)
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
                raise ManagedNotificationError("notification_identity_invalid", 503)
            return key

    def capabilities(self) -> dict[str, Any]:
        with self._lock:
            loaded = bool(self._loaded_profiles)
            approval_loaded = bool(self._approval_profiles)
        return {"version": 1, "hostKeyId": self.key_id, "hostPublicKey": self.public_key,
                "managedEnrollmentSupported": True, "supportedEventTypes": sorted(_EVENT_TYPES),
                "richLiveActivitySupported": True, "producerCapabilities": {
                    "sessionCompletion": loaded, "sessionFailure": loaded, "richLiveActivity": loaded,
                    "nativeApproval": approval_loaded, "nativeClarification": False}}

    def _request(self, method: str, grant_id: str, suffix: str = "", raw: bytes = b"",
                 *, before_transport: Callable | None = None):
        _identifier(grant_id, _UUID)
        path = ROOT + "/" + grant_id + suffix
        timestamp, nonce = int(self.clock()), b64url_encode(os.urandom(32))
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": "Loopdy-Managed-Notifications/1", "x-loopdy-host-key-id": self.key_id,
                   "x-loopdy-timestamp": str(timestamp), "x-loopdy-nonce": nonce,
                   "x-loopdy-signature": b64url_encode(sign_p1363(self._key, host_request_transcript(method, path, grant_id, timestamp, nonce, raw)))}
        if before_transport is not None and not before_transport():
            raise ManagedNotificationError("notification_attention_retired", 410)
        return self.transport(method, path, raw, headers)

    def _validate_grant(self, value: Any, grant_id: str) -> dict[str, Any]:
        if not isinstance(value, dict) or value.get("grantId") != grant_id or value.get("hostKeyId") != self.key_id or value.get("hostPublicKey") != self.public_key or value.get("state") != "active":
            raise ManagedNotificationError("notification_grant_identity_mismatch", 403)
        for field in ("revision", "recipientRevision", "authorizationEpoch", "createdAt", "expiresAt"):
            if type(value.get(field)) is not int or value[field] < 1:
                raise ManagedNotificationError("notification_grant_invalid", 502)
        if not value["createdAt"] < value["expiresAt"] <= value["createdAt"] + 2592000 or value["expiresAt"] <= int(self.clock()):
            raise ManagedNotificationError("notification_grant_expired", 403)
        _identifier(value.get("profile"), _PROFILE)
        _identifier(value.get("deviceId")); _identifier(value.get("tenantId"))
        recipient = b64url_decode(value.get("recipientPublicKey"), expected_length=65)
        public_key_from_x963(recipient)
        event_types = value.get("eventTypes")
        if (key_id(recipient) != value.get("recipientKeyId") or not isinstance(event_types, list)
                or not event_types or any(not isinstance(event_type, str) for event_type in event_types)
                or len(set(event_types)) != len(event_types) or not set(event_types) <= _EVENT_TYPES):
            raise ManagedNotificationError("notification_grant_invalid", 502)
        # Public metadata only; whitelist prevents accidental future secrets at rest.
        fields = ("grantId", "hostKeyId", "hostPublicKey", "deviceId", "recipientPublicKey", "recipientKeyId", "recipientRevision", "authorizationEpoch", "profile", "eventTypes", "createdAt", "expiresAt", "revision", "tenantId", "state")
        return {field: value[field] for field in fields}

    def enroll(self, grant_id: str, idempotency_key: str):
        _identifier(grant_id, _UUID); _identifier(idempotency_key, _UUID)
        value = self._request("POST", grant_id, "/claim", canonical_json_bytes({"version": 1, "idempotencyKey": idempotency_key}))
        grant = self._validate_grant(value.get("grant"), grant_id)
        with self._db() as db:
            if db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] >= 256 and not db.execute("SELECT 1 FROM grants WHERE grant_id=?", (grant_id,)).fetchone():
                raise ManagedNotificationError("notification_enrollment_limit")
            previous = db.execute("SELECT * FROM grants WHERE grant_id=?", (grant_id,)).fetchone()
            encoded = canonical_json_bytes(grant).decode()
            if previous and (previous["public_json"] != encoded or previous["state"] != "active"):
                raise ManagedNotificationError("notification_enrollment_conflict")
            db.execute("INSERT OR IGNORE INTO grants VALUES(?,?,'active',?)", (grant_id, encoded, grant["expiresAt"]))
        return {"version": 1, "grant": grant}

    def _grant(self, grant_id: str) -> dict[str, Any]:
        _identifier(grant_id, _UUID)
        with self._db() as db:
            row = db.execute("SELECT * FROM grants WHERE grant_id=? AND state='active' AND expires>?", (grant_id, int(self.clock()))).fetchone()
        if not row:
            raise ManagedNotificationError("notification_enrollment_inactive", 404)
        return json.loads(row["public_json"])

    def enrollment(self, grant_id: str):
        local = self._grant(grant_id)
        try:
            remote = self._validate_grant(self._request("GET", grant_id).get("grant"), grant_id)
        except ManagedNotificationError as error:
            if error.status in (403, 404): self.remove(grant_id)
            raise
        if remote != local:
            self.remove(grant_id)
            raise ManagedNotificationError("notification_enrollment_changed", 403)
        return {"version": 1, "grant": remote}

    def remove(self, grant_id: str):
        _identifier(grant_id, _UUID)
        with self._db() as db:
            db.execute("UPDATE grants SET state='removed' WHERE grant_id=?", (grant_id,))
            db.execute("UPDATE approval_attention SET state='retired',reason='removed' WHERE grant_id=?", (grant_id,))
            db.execute("DELETE FROM subscriptions WHERE grant_id=?", (grant_id,))
            db.execute("DELETE FROM pending WHERE grant_id=?", (grant_id,))
            db.execute("DELETE FROM activities WHERE grant_id=?", (grant_id,))
        return {"version": 1, "state": "removed", "grantId": grant_id}

    def _session(self, profile: str, session_id: str):
        _identifier(profile, _PROFILE); _identifier(session_id)
        def read(db):
            row = db.get_session(session_id)
            if not isinstance(row, dict) or row.get("id") != session_id:
                raise ManagedNotificationError("notification_session_unknown", 404)
            # Public store profile metadata, never current selected UI state.
            owner = row.get("profile_name")
            if owner != profile or row.get("deleted_at") or row.get("archived_at"):
                raise ManagedNotificationError("notification_session_forbidden", 403)
            return row
        try:
            return self.session_opener(profile, read, read_only=True)
        except (LookupError, OSError, sqlite3.Error) as error:
            raise ManagedNotificationError("notification_session_unavailable", 503) from error

    def subscribe(self, grant_id: str, profile: str, session_id: str, enabled: bool):
        grant = self.enrollment(grant_id)["grant"]
        if profile != grant["profile"] or type(enabled) is not bool:
            raise ManagedNotificationError("notification_scope_forbidden", 403)
        self._session(profile, session_id)
        reference = session_reference(profile, session_id)
        with self._db() as db:
            if enabled:
                count = db.execute("SELECT COUNT(*) FROM subscriptions WHERE grant_id=?", (grant_id,)).fetchone()[0]
                if count >= 128 and not db.execute("SELECT 1 FROM subscriptions WHERE grant_id=? AND profile=? AND session_id=?", (grant_id, profile, session_id)).fetchone():
                    raise ManagedNotificationError("notification_session_limit")
                db.execute("INSERT OR IGNORE INTO subscriptions VALUES(?,?,?,?)", (grant_id, profile, session_id, reference))
            else:
                db.execute("UPDATE approval_attention SET state='retired',reason='unsubscribed' WHERE grant_id=? AND profile=? AND session_id=?", (grant_id, profile, session_id))
                db.execute("DELETE FROM subscriptions WHERE grant_id=? AND profile=? AND session_id=?", (grant_id, profile, session_id))
                db.execute("DELETE FROM pending WHERE grant_id=? AND session_ref=?", (grant_id, reference))
                db.execute("DELETE FROM activities WHERE grant_id=? AND session_ref=?", (grant_id, reference))
        return {"version": 1, "grantId": grant_id, "profile": profile, "sessionId": session_id, "sessionReference": reference, "enabled": enabled}

    def work_snapshot(self, grant_id: str, profile: str, session_id: str):
        """Read only this process's public-hook observations, never DB starts.

        A current session observation is not correlation with a mobile frame.
        Retained older turns remain addressable by explicit activity registration.
        """
        grant = self.enrollment(grant_id)["grant"]
        if profile != grant["profile"]:
            raise ManagedNotificationError("notification_scope_forbidden", 403)
        self._session(profile, session_id)
        with self._lock, self._db() as db:
            self._require_subscription(db, grant_id, profile, session_id)
            work = next((value for key, value in reversed(self._work.items())
                         if key[:2] == (profile, session_id)), None)
            snapshot = None
            if work is not None:
                phase, count, terminal = self._work_projection(work)
                snapshot = {"profile": profile, "sessionId": session_id,
                            "turnId": work["turn"], "phase": phase,
                            "activeSubagentCount": count, "terminal": terminal,
                            "outcome": work["outcome"], "observedAt": work["observed_at"]}
            return {"version": 1, "grantId": grant_id, "work": snapshot}

    def _require_subscription(self, db, grant_id: str, profile: str, session_id: str):
        # Recheck local authority after cloud/SessionDB awaits, in the transaction
        # used by the read/write. A concurrent removal cannot resurrect authority.
        if not db.execute("SELECT 1 FROM subscriptions s JOIN grants g USING(grant_id) "
                          "WHERE s.grant_id=? AND s.profile=? AND s.session_id=? "
                          "AND g.state='active' AND g.expires>?",
                          (grant_id, profile, session_id, int(self.clock()))).fetchone():
            raise ManagedNotificationError("notification_session_not_subscribed")

    @staticmethod
    def _work_projection(work):
        count = sum(state == "active" for state in work["children"].values())
        outcome = work["outcome"]
        phase = "delegating" if count else ("completed" if outcome == "cancelled" else (outcome if outcome in ("completed", "failed") else work["phase"]))
        return phase, min(count, 99), outcome is not None and count == 0

    def event(self, grant_id: str, event_id: str):
        self.enrollment(grant_id)
        if not re.fullmatch(re.escape(grant_id) + r":[0-9a-f]{64}", event_id):
            raise ManagedNotificationError("notification_event_unknown", 404)
        with self._db() as db:
            row = db.execute("SELECT detail_json FROM events WHERE event_id=? AND grant_id=?", (event_id, grant_id)).fetchone()
        if not row:
            raise ManagedNotificationError("notification_event_unknown", 404)
        event = json.loads(row["detail_json"])
        self._session(event["profile"], event["sessionId"])
        return {"version": 1, "event": event}

    def subscribe_activity(self, grant_id: str, activity_id: str, profile: str, session_id: str, reference: str, lease_expires: int, turn_id: str | None = None):
        _identifier(activity_id)
        if turn_id is not None: _identifier(turn_id)
        grant = self.enrollment(grant_id)["grant"]
        self._session(profile, session_id)
        if profile != grant["profile"] or reference != session_reference(profile, session_id):
            raise ManagedNotificationError("notification_scope_forbidden", 403)
        receipt = self._request("GET", grant_id, "/live-activities/" + activity_id).get("activity")
        if not isinstance(receipt, dict) or receipt.get("grantId") != grant_id or receipt.get("activityId") != activity_id or receipt.get("sessionReference") != reference or receipt.get("status") != "active" or receipt.get("leaseExpires") != lease_expires or type(lease_expires) is not int or lease_expires <= int(self.clock()):
            raise ManagedNotificationError("notification_activity_unconfirmed")
        with self._lock:
            with self._db() as db:
                self._require_subscription(db, grant_id, profile, session_id)
                prior = db.execute("SELECT * FROM activities WHERE activity_id=?", (activity_id,)).fetchone()
                if prior and (prior["grant_id"] != grant_id or prior["session_ref"] != reference
                              or prior["profile"] != profile or prior["session_id"] != session_id
                              or prior["state"] not in ("active", "terminal_pending", "terminal_accepted")
                              or (turn_id is not None and prior["work_turn"] not in (None, turn_id))):
                    raise ManagedNotificationError("notification_activity_conflict")
                if not prior and db.execute("SELECT COUNT(*) FROM activities WHERE lease_expires>?", (int(self.clock()),)).fetchone()[0] >= 128:
                    raise ManagedNotificationError("notification_activity_limit")
                # Explicit delayed registration must select that retained observed
                # turn, never today's current turn. A retry preserves its owner.
                turn = prior["work_turn"] if prior and prior["work_turn"] is not None else turn_id
                if turn is not None:
                    work = self._work.get((profile, session_id, turn))
                    if work is None:
                        raise ManagedNotificationError("notification_work_unobserved")
                else:
                    work = next((value for key, value in reversed(self._work.items())
                                 if key[:2] == (profile, session_id) and not value["terminal"]
                                 and value["outcome"] is None), None)
                    turn = work["turn"] if work else None
                db.execute("INSERT INTO activities(activity_id,grant_id,profile,session_id,session_ref,lease_expires,work_turn,state) VALUES(?,?,?,?,?,?,?,'active') ON CONFLICT(activity_id) DO UPDATE SET lease_expires=excluded.lease_expires,work_turn=COALESCE(activities.work_turn,excluded.work_turn)", (activity_id, grant_id, profile, session_id, reference, lease_expires, turn))
            # Commit the owner first, then enqueue under the same observation lock.
            # No later hook is needed (including a turn ending before token arrival).
            # Terminal pending/accepted retries keep their original frozen request.
            if work is not None:
                phase, count, terminal = self._work_projection(work)
                self._queue_activity(profile, session_id, work["turn"], phase, count, terminal, stopped=work["outcome"] == "cancelled" and terminal)
        return {"version": 1, "activityId": activity_id, "grantId": grant_id, "sessionReference": reference, "state": "subscribed"}

    def remove_activity(self, grant_id: str, activity_id: str):
        self._grant(grant_id); _identifier(activity_id)
        with self._db() as db:
            db.execute("DELETE FROM activities WHERE activity_id=? AND grant_id=?", (activity_id, grant_id))
            db.execute("DELETE FROM pending WHERE activity_id=? AND grant_id=?", (activity_id, grant_id))
        return {"version": 1, "activityId": activity_id, "grantId": grant_id, "state": "removed"}

    def owns_alert(self, event: Any, device_id: str) -> bool:
        # Native observer attention never steals the legacy approval transport.
        if getattr(event, "type", None) not in {"session.completed", "session.failed"}: return False
        with self._db() as db:
            rows = db.execute("SELECT g.public_json FROM grants g JOIN subscriptions s USING(grant_id) WHERE g.state='active' AND g.expires>? AND s.profile=? AND s.session_id=?", (int(self.clock()), event.profile, event.session_id)).fetchall()
        return any((grant := json.loads(row["public_json"]))["deviceId"] == device_id
                   and event.type in grant["eventTypes"] for row in rows)

    @staticmethod
    def _approval_event_id(grant_id: str, profile: str, session_id: str, turn_id: str, tool_call_id: str):
        # Tool-scoped attention, NOT the identity of a native approval request.
        digest = hashlib.sha256(canonical_json_bytes(
            [profile, session_id, turn_id, tool_call_id, _APPROVAL_EVENT])).hexdigest()
        return grant_id + ":" + digest

    def _retire_approval_scope(self, profile: str, session_id: str, turn_id: str,
                               tool_call_id: str, reason: str):
        """Empty tool is an exact turn-end tombstone; never an invented turn."""
        now = int(self.clock())
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT g.* FROM grants g JOIN subscriptions s USING(grant_id) WHERE g.state='active' AND g.expires>? AND s.profile=? AND s.session_id=?", (now, profile, session_id)).fetchall()
            for row in rows:
                grant = json.loads(row["public_json"])
                if _APPROVAL_EVENT not in grant["eventTypes"]: continue
                scope = (grant["grantId"], profile, session_id, turn_id)
                where = "grant_id=? AND profile=? AND session_id=? AND turn_id=?"
                if tool_call_id:
                    where += " AND tool_call_id=?"
                    scope += (tool_call_id,)
                db.execute(f"UPDATE approval_attention SET state='retired',reason=? WHERE {where}", (reason, *scope))
                db.execute(f"UPDATE pending SET state='retired' WHERE state IN ('pending','sending') AND intent_id IN (SELECT event_id FROM approval_attention WHERE {where})", scope)
                # Also fence response-before-pre and delayed pre after turn end.
                event_id = self._approval_event_id(grant["grantId"], profile, session_id, turn_id, tool_call_id)
                db.execute("INSERT OR IGNORE INTO approval_attention SELECT ?,?,?,?,?,?,?,'retired',?,? WHERE (SELECT COUNT(*) FROM approval_attention WHERE grant_id=?)<?",
                           (event_id, grant["grantId"], profile, session_id, turn_id, tool_call_id,
                            self._approval_owner, now, reason, grant["grantId"], _APPROVAL_LIMIT))
        self._wake.set()

    def _observe_approval(self, hook: str, *, profile: str, **payload: Any):
        # The native gateway observer's session_id is the stored observability
        # identity. session_key is routing identity and must NEVER substitute.
        if payload.get("surface") != "gateway" or payload.get("coalesced", False) is not False:
            return
        if payload.get("parent_session_id") or payload.get("platform") == "subagent": return
        profile = _identifier(profile, _PROFILE)
        if "profile_name" in payload and payload["profile_name"] != profile: return
        session_id = _identifier(payload.get("session_id"))
        turn_id = _identifier(payload.get("turn_id"))
        tool_call_id = _identifier(payload.get("tool_call_id"))
        if hook == "post_approval_response":
            # Every gateway disposition retires; never persist command/choice text.
            self._retire_approval_scope(profile, session_id, turn_id, tool_call_id, "response")
            return
        self._session(profile, session_id)
        self._queue_event(profile, session_id, turn_id, _APPROVAL_EVENT, tool_call_id=tool_call_id)

    def _queue_event(self, profile: str, session_id: str, turn_id: str, event_type: str,
                     *, tool_call_id: str | None = None):
        approval = event_type == _APPROVAL_EVENT
        tool_call_id = _identifier(tool_call_id) if approval else ""
        now = int(self.clock())
        with self._db() as db:
            # Serialize lifecycle tombstones with the event and frozen intent.
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT g.* FROM grants g JOIN subscriptions s USING(grant_id) WHERE g.state='active' AND g.expires>? AND s.profile=? AND s.session_id=?", (now, profile, session_id)).fetchall()
            for row in rows:
                grant = json.loads(row["public_json"])
                if event_type not in grant["eventTypes"]: continue
                digest = hashlib.sha256(canonical_json_bytes([profile, session_id, turn_id, event_type])).hexdigest()
                event_id = self._approval_event_id(grant["grantId"], profile, session_id, turn_id, tool_call_id) if approval else grant["grantId"] + ":" + digest
                if db.execute("SELECT 1 FROM events WHERE event_id=?", (event_id,)).fetchone(): continue
                if approval:
                    turn_end = self._approval_event_id(grant["grantId"], profile, session_id, turn_id, "")
                    if db.execute("SELECT 1 FROM approval_attention WHERE event_id IN (?,?)", (event_id, turn_end)).fetchone(): continue
                    if db.execute("SELECT COUNT(*) FROM approval_attention WHERE grant_id=?", (grant["grantId"],)).fetchone()[0] >= _APPROVAL_LIMIT: continue
                if db.execute("SELECT COUNT(*) FROM events WHERE grant_id=?", (grant["grantId"],)).fetchone()[0] >= 4096: continue
                if db.execute("SELECT COUNT(*) FROM pending WHERE grant_id=? AND state IN ('pending','sending')", (grant["grantId"],)).fetchone()[0] >= 256: continue
                from .events import LoopdyEvent
                policy_event = LoopdyEvent(event_id=event_id, type=event_type, profile=profile, session_id=session_id)
                policy = self.preference_policy(policy_event, grant["deviceId"]) if self.preference_policy else {}
                detail = {"eventId": event_id, "eventType": event_type, "profile": profile, "sessionId": session_id, "turnId": turn_id, "occurredAt": now}
                expires = min(now + (_APPROVAL_TTL_SECONDS if approval else 900), grant["expiresAt"])
                if approval:
                    db.execute("INSERT INTO approval_attention VALUES(?,?,?,?,?,?,?,?,?,?)",
                               (event_id, grant["grantId"], profile, session_id, turn_id, tool_call_id,
                                self._approval_owner, "retired" if policy.get("suppression") else "pending",
                                expires, "suppressed" if policy.get("suppression") else "observed"))
                if policy.get("suppression"):
                    # Suppression is durable; a retry or quiet-hours boundary cannot replay it.
                    db.execute("INSERT INTO events VALUES(?,?,?,?)", (event_id, grant["grantId"], canonical_json_bytes(detail).decode(), now))
                    continue
                body = "Your agent requested approval" if approval else ("Your agent finished" if event_type == "session.completed" else "Your agent could not finish")
                envelope = encrypt_alert(tenant_id=grant["tenantId"], device_id=grant["deviceId"],
                    delivery_id="ng-" + str(uuid.uuid5(uuid.NAMESPACE_URL, event_id)), event_id=event_id,
                    event_type=event_type, title="Loopdy", body=body,
                    recipient_public_key=b64url_decode(grant["recipientPublicKey"], expected_length=65), sender_private_key=self._key,
                    issued=now, expires=expires, ephemeral_private_key=ec.generate_private_key(ec.SECP256R1()), salt=os.urandom(32), nonce=os.urandom(12))
                reference = session_reference(profile, session_id)
                raw = canonical_json_bytes({"version": 1, "eventId": event_id, "eventType": event_type, "sessionReference": reference, "envelope": envelope, "sound": policy.get("sound") is not False})
                db.execute("INSERT INTO events VALUES(?,?,?,?)", (event_id, grant["grantId"], canonical_json_bytes(detail).decode(), now))
                due = now + _APPROVAL_GRACE_SECONDS if approval else now
                db.execute("INSERT INTO pending(intent_id,grant_id,path,raw,expires,state,next_attempt,session_ref) VALUES(?,?,?,?,?,'pending',?,?)", (event_id, grant["grantId"], "/events", raw, expires, due, reference))
        self._wake.set()

    def observe(self, hook: str, *, profile: str, **payload: Any):
        """Synchronous stock hook: persist only; never perform network I/O here."""
        try:
            self._observe(hook, profile=profile, **payload)
        except (ValueError, OSError, sqlite3.Error):
            logger.warning("Managed notification lifecycle observation unavailable")

    def _observe(self, hook: str, *, profile: str, **payload: Any):
        if self._stop.is_set(): return
        if hook in _APPROVAL_HOOKS:
            self._observe_approval(hook, profile=profile, **payload)
            return
        if hook not in ("pre_llm_call", "post_llm_call", "pre_tool_call", "post_tool_call",
                        "on_session_end", "subagent_start", "subagent_stop"):
            return
        profile = _identifier(payload.get("profile_name") or profile, _PROFILE)
        child_hook = hook in ("subagent_start", "subagent_stop")
        session_id = payload.get("parent_session_id") if child_hook else payload.get("session_id")
        if not isinstance(session_id, str) or not _ID.fullmatch(session_id): return
        if not child_hook and (payload.get("parent_session_id") or payload.get("platform") == "subagent"): return
        with self._db() as db:
            if not db.execute("SELECT 1 FROM subscriptions s JOIN grants g USING(grant_id) WHERE s.profile=? AND s.session_id=? AND g.state='active' AND g.expires>?", (profile, session_id, int(self.clock()))).fetchone(): return
        turn = payload.get("turn_id")
        if not child_hook and isinstance(turn, str) and _ID.fullmatch(turn):
            if hook == "on_session_end":
                self._retire_approval_scope(profile, session_id, turn, "", "turn_end")
            elif hook == "post_tool_call":
                tool = payload.get("tool_call_id")
                if isinstance(tool, str) and _ID.fullmatch(tool):
                    self._retire_approval_scope(profile, session_id, turn, tool, "tool_end")
        if (hook == "on_session_end" and isinstance(turn, str) and _ID.fullmatch(turn)
                and payload.get("interrupted") is not True):
            if payload.get("failed") is True:
                self._queue_event(profile, session_id, turn, "session.failed")
            elif payload.get("completed") is True:
                self._queue_event(profile, session_id, turn, "session.completed")
        with self._lock:
            if child_hook:
                child = payload.get("child_session_id") or payload.get("child_subagent_id")
                turn = self._child_owners.get((profile, session_id, child)) if isinstance(child, str) else None
                if turn is None and hook == "subagent_start": turn = payload.get("parent_turn_id")
            if not isinstance(turn, str) or not _ID.fullmatch(turn): return
            coordinate = (profile, session_id, turn)
            work = self._work.get(coordinate)
            if hook == "pre_llm_call" and isinstance(turn, str) and _ID.fullmatch(turn):
                if work is None or work["turn"] != turn:
                    if len(self._work) >= 128:
                        # Never discard a live cohort or an activity's retained
                        # canonical owner merely because newer work appeared.
                        with self._db() as db:
                            bound = {(row["profile"], row["session_id"], row["work_turn"])
                                     for row in db.execute("SELECT profile,session_id,work_turn FROM activities WHERE lease_expires>?", (int(self.clock()),))}
                        evicted = next((key for key, value in self._work.items()
                                        if value["terminal"] and key not in bound), None)
                        if evicted is None: return
                        self._work.pop(evicted)
                        for child_key in tuple(self._child_owners):
                            if child_key[:2] == evicted[:2] and self._child_owners[child_key] == evicted[2]: self._child_owners.pop(child_key, None)
                    work = {"turn": turn, "phase": "thinking", "outcome": None, "children": {}, "terminal": False,
                            "observed_at": int(self.clock())}
                    self._work[coordinate] = work
                elif work["terminal"]: return
            if work is None or work["terminal"]: return
            if child_hook:
                child = payload.get("child_session_id") or payload.get("child_subagent_id")
                parent_turn = payload.get("parent_turn_id")
                if not isinstance(child, str) or not _ID.fullmatch(child): return
                owner_key = (profile, session_id, child)
                if hook == "subagent_start":
                    if not isinstance(parent_turn, str) or parent_turn != work["turn"]: return
                    if len(work["children"]) >= 128 and child not in work["children"]: return
                    self._child_owners.setdefault(owner_key, parent_turn)
                    if self._child_owners[owner_key] != work["turn"]: return
                    # A repeated start after stop cannot resurrect this child.
                    work["children"].setdefault(child, "active")
                else:
                    if self._child_owners.get(owner_key) != work["turn"] or work["children"].get(child) != "active": return
                    work["children"][child] = "ended"
            elif turn != work["turn"] or work["terminal"] or work["outcome"] is not None: return
            elif hook == "on_session_end":
                if payload.get("interrupted") is True:
                    work["outcome"] = "cancelled"
                elif payload.get("failed") is True:
                    work["outcome"] = "failed"
                    # Significant alert already persisted independently of activity state.
                elif payload.get("completed") is True:
                    work["outcome"] = "completed"
                    # Significant alert already persisted independently of activity state.
                else: return
            elif hook == "post_llm_call":
                work["phase"] = "responding"
            elif hook in ("pre_tool_call", "post_tool_call"):
                work["phase"] = "using_tool"
            work["observed_at"] = int(self.clock())
            phase, active_count, terminal = self._work_projection(work)
            work["terminal"] = terminal
            # Rich-v1 uses completed as the terminal transport state. Stopped
            # remains explicit fixed copy; cancellation never queues an alert.
            self._queue_activity(profile, session_id, work["turn"], phase, active_count, terminal,
                                 allow_bind=hook == "pre_llm_call", stopped=work["outcome"] == "cancelled" and terminal)

    def _queue_activity(self, profile: str, session_id: str, turn: str, phase: str, count: int, terminal: bool, *, allow_bind: bool = False, stopped: bool = False):
        now = int(self.clock())
        with self._db() as db:
            rows = db.execute("SELECT a.*,g.expires AS grant_expires FROM activities a JOIN grants g USING(grant_id) WHERE a.profile=? AND a.session_id=? AND a.state='active' AND a.lease_expires>? AND g.state='active' AND g.expires>?", (profile, session_id, now, now)).fetchall()
            for row in rows:
                if row["work_turn"] not in (None, turn) or (row["work_turn"] is None and not allow_bind): continue
                action = "Stopped" if stopped and terminal and phase == "completed" else _ACTIONS[phase]
                signature = json.dumps([turn, phase, count, action])
                if row["last_signature"] == signature: continue
                # Queue latest significant state, with relay's existing 30s budget.
                pending = db.execute("SELECT raw,next_attempt FROM pending WHERE activity_id=? AND state='pending' ORDER BY next_attempt LIMIT 1", (row["activity_id"],)).fetchone()
                timestamp = max(now, json.loads(bytes(pending["raw"]))["timestamp"]) if pending else max(now, row["last_timestamp"] + 1)
                expires = min(timestamp + 120, row["grant_expires"], row["lease_expires"])
                if expires <= timestamp: continue
                update_id = b64url_encode(hashlib.sha256(canonical_json_bytes([row["grant_id"], row["activity_id"], turn, signature, timestamp])).digest())
                update = {"version": 1, "updateId": update_id, "sessionReference": row["session_ref"], "phase": phase,
                          "currentAction": action, "progress": 100 if terminal else 0, "completedSteps": 0,
                          "activeSubagentCount": count, "latestTool": None, "timestamp": timestamp, "expires": expires}
                due = now if terminal or phase == "waiting" else max(now, pending["next_attempt"] if pending else row["last_queued_at"] + 30)
                # Only nonterminal updates may be superseded; terminal is durable.
                db.execute("DELETE FROM pending WHERE activity_id=? AND state='pending'", (row["activity_id"],))
                db.execute("INSERT INTO pending(intent_id,grant_id,path,raw,expires,state,next_attempt,session_ref,activity_id) VALUES(?,?,?,?,?,'pending',?,?,?)", (update_id, row["grant_id"], "/live-activities/" + row["activity_id"] + "/updates", canonical_json_bytes(update), expires, due, row["session_ref"], row["activity_id"]))
                db.execute("UPDATE activities SET work_turn=?,state=?,last_timestamp=?,last_signature=?,last_queued_at=? WHERE activity_id=?", (turn, "terminal_pending" if terminal else "active", timestamp, signature, due, row["activity_id"]))
        self._wake.set()

    def producer_loaded(self, profile: str, *, start_worker: bool = True, approval_hooks_loaded: bool = False):
        with self._lock:
            self._loaded_profiles.add(profile)
            if approval_hooks_loaded:
                self._approval_profiles.add(profile)
            if start_worker and self._worker is None:
                lock_path = self.directory / "worker.lock"
                fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                lock = os.fdopen(fd, "a+b")
                try: self._fcntl.flock(lock, self._fcntl.LOCK_EX | self._fcntl.LOCK_NB)
                except BlockingIOError:
                    lock.close(); return
                self._worker_lock = lock
                self._worker = threading.Thread(target=self._run, name="loopdy-managed-notifications", daemon=True)
                self._worker.start()

    def close(self):
        self._stop.set(); self._wake.set()
        if self._worker is not None: self._worker.join(timeout=15)
        with self._lock:
            self._loaded_profiles.clear()
            self._approval_profiles.clear()
            if self._worker_lock is not None and (self._worker is None or not self._worker.is_alive()):
                self._worker_lock.close(); self._worker_lock = None

    def _run(self):
        while not self._stop.is_set():
            try: self.drain_pending()
            except (ValueError, OSError, sqlite3.Error): logger.warning("Managed notification journal unavailable")
            self._wake.wait(5); self._wake.clear()

    def _approval_transport_ready(self, row) -> bool:
        """Last local fence after signing, immediately before the HTTPS call.

        Do not hold a lock across network I/O: observers must not delay the
        native decision. A decision after this fence can still race admission;
        an accepted push is not recallable and only states a past-tense fact.
        """
        if self._stop.is_set(): return False
        with self._db() as db:
            attention = db.execute("SELECT * FROM approval_attention WHERE event_id=? AND grant_id=?",
                                   (row["intent_id"], row["grant_id"])).fetchone()
        if not attention or attention["owner"] != self._approval_owner or attention["state"] != "pending": return False
        try:
            self._session(attention["profile"], attention["session_id"])
        except (ValueError, OSError, sqlite3.Error):
            return False
        now = int(self.clock())
        with self._db() as db:
            current = db.execute("SELECT g.public_json,p.raw,p.session_ref FROM pending p "
                "JOIN approval_attention a ON a.event_id=p.intent_id AND a.grant_id=p.grant_id "
                "JOIN grants g ON g.grant_id=a.grant_id "
                "JOIN subscriptions s ON s.grant_id=a.grant_id AND s.profile=a.profile AND s.session_id=a.session_id "
                "WHERE p.intent_id=? AND p.state='sending' AND p.expires>? AND a.state='pending' AND a.owner=? AND a.expires>? "
                "AND g.state='active' AND g.expires>?",
                (row["intent_id"], now, self._approval_owner, now, now)).fetchone()
        if not current or self._stop.is_set(): return False
        grant = json.loads(current["public_json"])
        return (grant["profile"] == attention["profile"] and _APPROVAL_EVENT in grant["eventTypes"]
                and bytes(current["raw"]) == bytes(row["raw"])
                and current["session_ref"] == session_reference(attention["profile"], attention["session_id"]))

    def drain_pending(self):
        """Bounded durable retry, exposed for main-owned no-send composition tests."""
        now = int(self.clock())
        with self._db() as db:
            # Never replay a previous producer's assertion of human waiting.
            # API-only construction is read-only here: retirement happens only in
            # the process-owned drain (not when another API reader opens the DB).
            db.execute("UPDATE approval_attention SET state='retired',reason=CASE WHEN owner!=? THEN 'recovery' ELSE 'timeout' END WHERE state='pending' AND (owner!=? OR expires<=?)", (self._approval_owner, self._approval_owner, now))
            db.execute("UPDATE pending SET state='retired' WHERE state IN ('pending','sending') AND intent_id IN (SELECT event_id FROM approval_attention WHERE state='retired')")
            db.execute("UPDATE pending SET state='pending' WHERE state='sending' AND next_attempt<=?", (now,))
            db.execute("UPDATE pending SET state='expired' WHERE state='pending' AND expires<=?", (now,))
            db.execute("DELETE FROM pending WHERE expires<?", (now - 86400,))
            db.execute("DELETE FROM events WHERE occurred_at<?", (now - 2592000,))
            db.execute("DELETE FROM grants WHERE expires<?", (now - 86400,))
            db.execute("DELETE FROM activities WHERE lease_expires<?", (now - 86400,))
            rows = db.execute("SELECT p.* FROM pending p JOIN grants g USING(grant_id) WHERE p.state='pending' AND p.next_attempt<=? AND p.expires>? AND g.state='active' AND g.expires>? ORDER BY p.next_attempt,p.intent_id LIMIT 32", (now, now, now)).fetchall()
        for row in rows:
            if self._stop.is_set(): return
            now = int(self.clock())
            with self._db() as db:
                claimed = db.execute("UPDATE pending SET state='sending',next_attempt=? WHERE intent_id=? AND state='pending' AND expires>? AND EXISTS(SELECT 1 FROM grants WHERE grants.grant_id=pending.grant_id AND grants.state='active' AND grants.expires>?)", (now + 30, row["intent_id"], now, now)).rowcount
            if claimed != 1: continue
            try:
                approval = row["path"] == "/events" and json.loads(bytes(row["raw"])).get("eventType") == _APPROVAL_EVENT
                result = self._request("POST", row["grant_id"], row["path"], bytes(row["raw"]),
                                       before_transport=(lambda: self._approval_transport_ready(row)) if approval else None)
                if result.get("status") not in ("accepted", "duplicate") or not isinstance(result.get("deliveryId"), str):
                    raise ManagedNotificationError("notification_delivery_unconfirmed", 503)
            except ManagedNotificationError as error:
                if error.status in (403, 404):
                    self.remove(row["grant_id"])
                else:
                    with self._db() as db:
                        state = "failed" if error.status in (400, 401, 410, 422) else "pending"
                        # A post-hook/removal racing an in-flight failed request
                        # must not resurrect the retired intent.
                        db.execute("UPDATE pending SET state=?,attempts=attempts+1,next_attempt=? WHERE intent_id=? AND state='sending'", (state, now + min(60, 2 ** min(row["attempts"] + 1, 6)), row["intent_id"]))
                        if state == "failed":
                            db.execute("UPDATE approval_attention SET state='retired',reason='send_failed' WHERE event_id=? AND state='pending'", (row["intent_id"],))
                continue
            with self._db() as db:
                db.execute("UPDATE pending SET state='accepted' WHERE intent_id=? AND state='sending'", (row["intent_id"],))
                if row["activity_id"] and json.loads(bytes(row["raw"])).get("phase") in ("completed", "failed"):
                    db.execute("UPDATE activities SET state='terminal_accepted' WHERE activity_id=? AND state='terminal_pending'", (row["activity_id"],))


_instances: dict[str, ManagedNotifications] = {}
_instances_lock = threading.Lock()


def get_managed_notifications() -> ManagedNotifications:
    from hermes_constants import get_hermes_home
    directory = get_hermes_home() / "plugin-data" / "loopdy" / "managed-notifications"
    with _instances_lock:
        key = str(directory)
        if key not in _instances:
            _instances[key] = ManagedNotifications(directory)
        return _instances[key]
