"""SQLite-backed Loopdy device, event, and approval state."""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .events import LoopdyEvent
from .loopdy_cards import canonical_json as canonical_card_json
from .loopdy_cards import validate_card_input


_PROTOCOL_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,179}$")
_MAX_SAFE_REVISION = 9_007_199_254_740_991
_MAX_TIMESTAMP = 9_999_999_999
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_MAX_RELAY_AUTOMATIC_ATTEMPTS = 5
_CLAIM_LEASE_SECONDS = 30
_LEGACY_RELAY_PROVIDER_CONFLICT = "Device is already registered with another provider"
_GATEWAY_LIFECYCLE_PREFIXES = (
    "♻️ Gateway online",
    "♻ Gateway online",
    "♻️ Gateway restarted",
    "♻ Gateway restarted",
    "⚠️ Gateway restarting",
    "⚠ Gateway restarting",
    "⚠️ Gateway shutting down",
    "⚠ Gateway shutting down",
)


class CardTemplateConflict(ValueError):
    """A template changed under the caller's expected version/content."""


class CardTemplateLimit(ValueError):
    """A bounded template catalog cannot represent all stored rows."""


class LoopdyStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._init_lock = threading.Lock()
        self._initialized = False
        self._ensure_schema()

    def record_turn_duration(
        self, session_id: str, turn_id: str, final_timestamp: float, duration_ms: int
    ) -> None:
        """Immutable completion keyed by the host turn, not message text or arrival time."""
        with self._connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO turn_durations "
                "(session_id, turn_id, final_timestamp, duration_ms) VALUES (?, ?, ?, ?)",
                (session_id, turn_id, final_timestamp, duration_ms),
            )

    def delete_turn_durations(self, session_id: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM turn_durations WHERE session_id = ?", (session_id,))

    def turn_durations(self, session_id: str) -> dict[float, int]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT final_timestamp, MIN(duration_ms) AS duration_ms "
                "FROM turn_durations WHERE session_id = ? GROUP BY final_timestamp "
                "HAVING COUNT(*) = 1", (session_id,),
            ).fetchall()
        return {row["final_timestamp"]: row["duration_ms"] for row in rows}

    def upsert_device(
        self,
        *,
        device_id: str,
        endpoint_id: str,
        provider: str = "managed",
        token_environment: str = "production",
        label: str = "",
        groups: Iterable[str] = (),
        preferences: Mapping[str, Any] | None = None,
    ) -> None:
        now = int(time.time())
        normalized_groups = sorted({str(value).strip() for value in groups if str(value).strip()})
        normalized_provider = _device_provider(provider)
        normalized_environment = _text(token_environment, 32) or "production"
        normalized_preferences = None if preferences is None else dict(preferences)
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT provider FROM devices WHERE device_id=?",
                (_identifier(device_id, "device_id"),),
            ).fetchone()
            if existing is not None and existing["provider"] == "relay" and normalized_provider != "relay":
                self._cancel_relay_device_work(connection, str(device_id), int(time.time()))
            connection.execute(
                """
                INSERT INTO devices (
                    device_id, endpoint_id, provider, token_environment, label,
                    groups_json, preferences_json, created_at, updated_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(device_id) DO UPDATE SET
                    endpoint_id=excluded.endpoint_id,
                    provider=excluded.provider,
                    token_environment=excluded.token_environment,
                    label=excluded.label,
                    groups_json=excluded.groups_json,
                    preferences_json=CASE WHEN ? IS NULL THEN devices.preferences_json ELSE excluded.preferences_json END,
                    updated_at=excluded.updated_at,
                    revoked_at=NULL
                """,
                (
                    _identifier(device_id, "device_id"),
                    _required_text(endpoint_id, "endpoint_id", 512),
                    normalized_provider,
                    normalized_environment,
                    _text(label, 120),
                    _json(normalized_groups),
                    _json(normalized_preferences if normalized_preferences is not None else {}),
                    now,
                    now,
                    _json(normalized_preferences) if normalized_preferences is not None else None,
                ),
            )
    def register_relay_device(
        self,
        *,
        device_id: str,
        recipient_public_key: str,
        recipient_key_id: str,
        revision: int,
        lease_expires: int,
        normalized_body: Mapping[str, Any],
        token_environment: str = "production",
        label: str = "",
        groups: Iterable[str] = (),
        preferences: Mapping[str, Any] | None = None,
        now: int | None = None,
        expected_relay_generation: int | None = None,
        terminal_claim_token: str = "",
        terminal_request_digest: str = "",
    ) -> dict[str, Any]:
        current_time = int(time.time()) if now is None else _positive_integer(now, "now")
        normalized_revision = _positive_revision(revision)
        normalized_lease = _positive_integer(lease_expires, "lease_expires")
        if normalized_lease <= current_time or normalized_lease - current_time > 2_592_000:
            raise ValueError("Relay registration lease must be positive and at most 30 days")
        device = _protocol_identifier(device_id, "device_id")
        public_key = _required_text(recipient_public_key, "recipient_public_key", 100)
        recipient_id = _required_text(recipient_key_id, "recipient_key_id", 64)
        digest = _normalized_body_digest(normalized_body)
        normalized_groups = sorted({str(value).strip() for value in groups if str(value).strip()})
        normalized_preferences = None if preferences is None else dict(preferences)
        environment = str(token_environment or "").strip().lower()
        if environment not in {"production", "sandbox"}:
            raise ValueError("Relay token environment must be production or sandbox")
        has_terminal_claim = bool(terminal_claim_token or terminal_request_digest)
        if has_terminal_claim and not (terminal_claim_token and terminal_request_digest):
            raise ValueError("Terminal relay registration claim is incomplete")
        claim_token = (
            _required_text(terminal_claim_token, "terminal_claim_token", 180)
            if has_terminal_claim else ""
        )
        claim_digest = (
            _required_text(terminal_request_digest, "terminal_request_digest", 64)
            if has_terminal_claim else ""
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            relay_generation = self._metadata_integer(connection, "relay_config_generation", 0)
            self._assert_relay_generation(connection, expected_relay_generation, relay_generation)
            if has_terminal_claim:
                claimed = connection.execute(
                    "SELECT 1 FROM pending_relay_operations WHERE operation='register_device' "
                    "AND device_id=? AND terminal=1 AND response_json<>'' AND last_error=? "
                    "AND claim_token=? AND request_digest=? AND relay_generation=? "
                    "AND claim_expires>? LIMIT 1",
                    (
                        device,
                        _LEGACY_RELAY_PROVIDER_CONFLICT,
                        claim_token,
                        claim_digest,
                        relay_generation,
                        current_time,
                    ),
                ).fetchone()
                if claimed is None:
                    raise ValueError("Terminal relay registration claim is no longer active")

            def consume_terminal_claim() -> None:
                if not has_terminal_claim:
                    return
                cursor = connection.execute(
                    "DELETE FROM pending_relay_operations WHERE operation='register_device' "
                    "AND device_id=? AND terminal=1 AND response_json<>'' AND last_error=? "
                    "AND claim_token=? AND request_digest=? AND relay_generation=? "
                    "AND claim_expires>?",
                    (
                        device,
                        _LEGACY_RELAY_PROVIDER_CONFLICT,
                        claim_token,
                        claim_digest,
                        relay_generation,
                        current_time,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ValueError("Terminal relay registration claim is no longer active")

            existing = connection.execute(
                "SELECT provider, revision, normalized_body_digest, revoked_at, relay_generation "
                "FROM devices WHERE device_id=?",
                (device,),
            ).fetchone()
            if existing is not None:
                previous_revision = int(existing["revision"])
                if existing["revoked_at"] is not None and normalized_revision <= previous_revision:
                    raise ValueError("A tombstoned relay device requires a higher revision")
                if normalized_revision < previous_revision:
                    raise ValueError("Relay device revision cannot decrease")
                if normalized_revision == previous_revision:
                    if hmac.compare_digest(str(existing["normalized_body_digest"]), digest):
                        if int(existing["relay_generation"]) != relay_generation:
                            connection.execute(
                                "UPDATE devices SET relay_generation=?, updated_at=? WHERE device_id=?",
                                (relay_generation, current_time, device),
                            )
                            consume_terminal_claim()
                            return {"changed": True, "revision": normalized_revision}
                        consume_terminal_claim()
                        return {"changed": False, "revision": normalized_revision}
                    raise ValueError("Relay registration idempotency conflict")
                if existing["provider"] != "relay":
                    connection.execute(
                        "UPDATE event_deliveries SET status='failed', failure='relay_target_changed', "
                        "relay_request_body_json='', claim_token='', claim_expires=0, next_attempt_at=0 "
                        "WHERE provider IN ('managed', 'direct') AND device_id=? AND status='queued'",
                        (device,),
                    )
                    connection.execute(
                        "DELETE FROM provider_receipts WHERE provider IN ('managed', 'direct') "
                        "AND device_id=? AND status='pending'",
                        (device,),
                    )
                connection.execute(
                    "UPDATE event_deliveries SET status='failed', failure='relay_target_changed', "
                    "relay_request_body_json='' WHERE provider='relay' AND status='queued' "
                    "AND device_id=?",
                    (device,),
                )
                # A new non-revoking device registration supersedes every
                # in-flight Live Activity registration addressed to that
                # device.  The journal key is the activity ID, so resolve
                # ownership from the frozen request body before allowing the
                # registration revision to commit.
                connection.execute(
                    "UPDATE pending_relay_operations SET terminal=1, "
                    "last_error='relay_target_changed', claim_token='', "
                    "claim_expires=0, next_attempt_at=0, updated_at=?, "
                    "row_version=row_version+1 WHERE terminal=0 "
                    "AND operation='register_live_activity' AND json_valid(body_json) "
                    "AND json_extract(body_json, '$.device_id')=?",
                    (current_time, device),
                )
                connection.execute(
                    "DELETE FROM pending_relay_live_activity_updates "
                    "WHERE activity_id IN (SELECT activity_id FROM relay_live_activities WHERE device_id=?)",
                    (device,),
                )
            connection.execute(
                """
                INSERT INTO devices (
                    device_id, endpoint_id, provider, token_environment, label,
                    groups_json, preferences_json, created_at, updated_at, revoked_at,
                    recipient_public_key, recipient_key_id, revision, lease_expires,
                    normalized_body_digest, sender_key_revision,
                    acknowledged_sender_key_ids_json, sender_ack_body_digest, relay_generation
                ) VALUES (?, ?, 'relay', ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, 0, '[]', '', ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    endpoint_id=excluded.endpoint_id,
                    provider='relay',
                    token_environment=excluded.token_environment,
                    label=excluded.label,
                    groups_json=excluded.groups_json,
                    preferences_json=CASE WHEN ? IS NULL THEN devices.preferences_json ELSE excluded.preferences_json END,
                    updated_at=excluded.updated_at,
                    revoked_at=NULL,
                    recipient_public_key=excluded.recipient_public_key,
                    recipient_key_id=excluded.recipient_key_id,
                    revision=excluded.revision,
                    lease_expires=excluded.lease_expires,
                    normalized_body_digest=excluded.normalized_body_digest,
                    sender_key_revision=CASE
                        WHEN devices.recipient_key_id=excluded.recipient_key_id
                         AND devices.recipient_public_key=excluded.recipient_public_key
                        THEN devices.sender_key_revision ELSE 0 END,
                    acknowledged_sender_key_ids_json=CASE
                        WHEN devices.recipient_key_id=excluded.recipient_key_id
                         AND devices.recipient_public_key=excluded.recipient_public_key
                        THEN devices.acknowledged_sender_key_ids_json ELSE '[]' END,
                    sender_ack_body_digest=CASE
                        WHEN devices.recipient_key_id=excluded.recipient_key_id
                         AND devices.recipient_public_key=excluded.recipient_public_key
                        THEN devices.sender_ack_body_digest ELSE '' END,
                    relay_generation=excluded.relay_generation
                """,
                (
                    device,
                    recipient_id,
                    environment,
                    _text(label, 120),
                    _json(normalized_groups),
                    _json(normalized_preferences if normalized_preferences is not None else {}),
                    current_time,
                    current_time,
                    public_key,
                    recipient_id,
                    normalized_revision,
                    normalized_lease,
                    digest,
                    relay_generation,
                    _json(normalized_preferences) if normalized_preferences is not None else None,
                ),
            )
            consume_terminal_claim()
        return {"changed": True, "revision": normalized_revision}

    def acknowledge_relay_sender_keys(
        self,
        *,
        device_id: str,
        revision: int,
        sender_key_revision: int,
        acknowledged_sender_key_ids: Iterable[str],
        normalized_body: Mapping[str, Any],
        now: int | None = None,
        expected_relay_generation: int | None = None,
    ) -> dict[str, Any]:
        current_time = int(time.time()) if now is None else _positive_integer(now, "now")
        device = _protocol_identifier(device_id, "device_id")
        normalized_revision = _positive_revision(revision)
        normalized_sender_revision = _positive_revision(sender_key_revision)
        key_ids = list(acknowledged_sender_key_ids)
        if not 1 <= len(key_ids) <= 2 or len(set(key_ids)) != len(key_ids):
            raise ValueError("Relay sender-key acknowledgement must contain one or two unique keys")
        if any(type(value) is not str for value in key_ids):
            raise ValueError("Relay sender-key acknowledgement must contain string key IDs")
        key_ids = sorted(_required_text(value, "sender_key_id", 64) for value in key_ids)
        digest = _normalized_body_digest(normalized_body)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            relay_generation = self._metadata_integer(connection, "relay_config_generation", 0)
            self._assert_relay_generation(connection, expected_relay_generation, relay_generation)
            existing = connection.execute(
                "SELECT provider, revision, sender_ack_body_digest, revoked_at "
                "FROM devices WHERE device_id=?",
                (device,),
            ).fetchone()
            if existing is None or existing["provider"] != "relay" or existing["revoked_at"] is not None:
                raise ValueError("Unknown or revoked relay device")
            previous_revision = int(existing["revision"])
            if normalized_revision < previous_revision:
                raise ValueError("Relay device revision cannot decrease")
            if normalized_revision == previous_revision:
                if hmac.compare_digest(str(existing["sender_ack_body_digest"]), digest):
                    return {"changed": False, "revision": normalized_revision}
                raise ValueError("Relay sender-key acknowledgement idempotency conflict")
            connection.execute(
                "UPDATE devices SET revision=?, sender_key_revision=?, "
                "acknowledged_sender_key_ids_json=?, sender_ack_body_digest=?, updated_at=? "
                "WHERE device_id=? AND provider='relay' AND revoked_at IS NULL",
                (
                    normalized_revision,
                    normalized_sender_revision,
                    _json(key_ids),
                    digest,
                    current_time,
                    device,
                ),
            )
        return {"changed": True, "revision": normalized_revision}

    def revoke_relay_device(
        self,
        *,
        device_id: str,
        revision: int,
        normalized_body: Mapping[str, Any],
        now: int | None = None,
        expected_relay_generation: int | None = None,
    ) -> dict[str, Any]:
        current_time = int(time.time()) if now is None else _positive_integer(now, "now")
        device = _protocol_identifier(device_id, "device_id")
        normalized_revision = _positive_revision(revision)
        digest = _normalized_body_digest(normalized_body)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            relay_generation = self._metadata_integer(connection, "relay_config_generation", 0)
            self._assert_relay_generation(connection, expected_relay_generation, relay_generation)
            existing = connection.execute(
                "SELECT provider, revision, normalized_body_digest, revoked_at "
                "FROM devices WHERE device_id=?",
                (device,),
            ).fetchone()
            if existing is None or existing["provider"] != "relay":
                raise ValueError("Unknown relay device")
            previous_revision = int(existing["revision"])
            if normalized_revision < previous_revision:
                raise ValueError("Relay device revision cannot decrease")
            if normalized_revision == previous_revision:
                if existing["revoked_at"] is not None and hmac.compare_digest(
                    str(existing["normalized_body_digest"]), digest
                ):
                    return {"changed": False, "revision": normalized_revision}
                raise ValueError("Relay revocation idempotency conflict")
            connection.execute(
                "UPDATE devices SET revision=?, normalized_body_digest=?, revoked_at=?, updated_at=? "
                "WHERE device_id=? AND provider='relay'",
                (normalized_revision, digest, current_time, current_time, device),
            )
            self._cancel_relay_device_work(connection, device, current_time)
        return {"changed": True, "revision": normalized_revision}

    def update_preferences(self, device_id: str, preferences: Mapping[str, Any]) -> bool:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT preferences_json FROM devices "
                "WHERE device_id=? AND revoked_at IS NULL",
                (_identifier(device_id, "device_id"),),
            ).fetchone()
            if row is None:
                return False
            current = _load_json(row["preferences_json"], {})
            merged = dict(current) if isinstance(current, dict) else {}
            merged.update(dict(preferences))
            cursor = connection.execute(
                "UPDATE devices SET preferences_json=?, updated_at=? "
                "WHERE device_id=? AND revoked_at IS NULL",
                (_json(merged), int(time.time()), _identifier(device_id, "device_id")),
            )
            return cursor.rowcount == 1

    def revoke_device(self, device_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE devices SET revoked_at=?, updated_at=? "
                "WHERE device_id=? AND revoked_at IS NULL",
                (
                    int(time.time()),
                    int(time.time()),
                    _identifier(device_id, "device_id"),
                ),
            )
            return cursor.rowcount == 1

    def list_devices(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT device_id, endpoint_id, provider, token_environment, label, "
                "groups_json, preferences_json, revoked_at, recipient_public_key, "
                "recipient_key_id, revision, lease_expires, sender_key_revision, "
                "acknowledged_sender_key_ids_json, relay_generation "
                "FROM devices ORDER BY device_id"
            ).fetchall()
        relay_enabled = self.relay_config_enabled()
        devices = [_device_row(row) for row in rows]
        if not relay_enabled:
            for device in devices:
                if device["provider"] == "relay":
                    device["revoked"] = True
        return devices

    def resolve_devices(
        self,
        target: str,
        provider: str | None = None,
        *,
        now: int | None = None,
    ) -> list[dict[str, Any]]:
        normalized_provider = None if provider is None else _device_provider(provider)
        current_time = int(time.time()) if now is None else _positive_integer(now, "now")
        relay_generation = self.relay_config_generation()
        relay_enabled = self.relay_config_enabled()
        value = str(target or "").strip()
        if value == "all":
            device_id = ""
            group = ""
        elif value.startswith("device:"):
            device_id = _identifier(value.split(":", 1)[1], "device_id")
            group = ""
        elif value.startswith("group:"):
            device_id = ""
            group = _identifier(value.split(":", 1)[1], "group_id")
        else:
            raise ValueError("Loopdy target must be all, device:<id>, or group:<id>")
        devices = [
            item
            for item in self.list_devices()
            if not item["revoked"]
            and (normalized_provider is None or item["provider"] == normalized_provider)
            and (
                item["provider"] != "relay"
                or (
                    relay_enabled
                    and int(item.get("relay_generation") or 0) == relay_generation
                    and int(item.get("lease_expires") or 0) > current_time
                    and bool(item.get("acknowledged_sender_key_ids"))
                )
            )
        ]
        if device_id:
            return [item for item in devices if item["device_id"] == device_id]
        if group:
            return [item for item in devices if group in item["groups"]]
        return devices

    def install_card_template(
        self,
        *,
        profile: str,
        template: Mapping[str, Any],
    ) -> dict[str, Any]:
        owner = _identifier(profile, "profile")
        normalized = _card_template(template)
        now = int(time.time())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT version, sha256, template_json FROM card_templates "
                "WHERE profile=? AND template_id=?",
                (owner, normalized["id"]),
            ).fetchone()
            if existing is not None:
                current_version = int(existing["version"])
                if normalized["version"] < current_version:
                    raise CardTemplateConflict("Card template version cannot decrease")
                if normalized["version"] == current_version:
                    if (
                        hmac.compare_digest(str(existing["sha256"]), normalized["sha256"])
                        and hmac.compare_digest(
                            str(existing["template_json"]),
                            canonical_card_json(normalized),
                        )
                    ):
                        return {"changed": False, "template": normalized}
                    raise CardTemplateConflict("Card template version conflict")
            connection.execute(
                """
                INSERT INTO card_templates (
                    profile, template_id, version, name, summary, sha256,
                    template_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(profile, template_id) DO UPDATE SET
                    version=excluded.version,
                    name=excluded.name,
                    summary=excluded.summary,
                    sha256=excluded.sha256,
                    template_json=excluded.template_json,
                    updated_at=excluded.updated_at
                """,
                (
                    owner,
                    normalized["id"],
                    normalized["version"],
                    normalized["name"],
                    normalized["summary"],
                    normalized["sha256"],
                    canonical_card_json(normalized),
                    now,
                    now,
                ),
            )
        return {"changed": True, "template": normalized}

    def list_card_templates(self, *, profile: str, limit: int | None = None) -> list[dict[str, Any]]:
        owner = _identifier(profile, "profile")
        if limit is not None and (type(limit) is not int or not 1 <= limit <= 500):
            raise ValueError("Card template catalog limit is invalid")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT template_json FROM card_templates WHERE profile=? "
                "ORDER BY name COLLATE NOCASE, template_id" + (" LIMIT ?" if limit is not None else ""),
                (owner, limit + 1) if limit is not None else (owner,),
            ).fetchall()
        if limit is not None and len(rows) > limit:
            raise CardTemplateLimit("Card template catalog exceeds the row limit")
        return [json.loads(str(row["template_json"])) for row in rows]

    def get_card_template(
        self,
        *,
        profile: str,
        template_id: str,
    ) -> dict[str, Any] | None:
        owner = _identifier(profile, "profile")
        identifier = _card_template_id(template_id)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT template_json FROM card_templates WHERE profile=? AND template_id=?",
                (owner, identifier),
            ).fetchone()
        return None if row is None else json.loads(str(row["template_json"]))

    def remove_card_template(
        self,
        *,
        profile: str,
        template_id: str,
        version: int,
        sha256: str,
    ) -> dict[str, Any]:
        owner = _identifier(profile, "profile")
        identifier = _card_template_id(template_id)
        expected_version = _positive_revision(version)
        expected_hash = _card_template_hash(sha256)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT version, sha256 FROM card_templates WHERE profile=? AND template_id=?",
                (owner, identifier),
            ).fetchone()
            if row is None:
                return {"changed": False, "templateId": identifier}
            if int(row["version"]) != expected_version or not hmac.compare_digest(
                str(row["sha256"]), expected_hash
            ):
                raise CardTemplateConflict("Card template removal conflict")
            connection.execute(
                "DELETE FROM card_templates WHERE profile=? AND template_id=?",
                (owner, identifier),
            )
        return {"changed": True, "templateId": identifier}

    def record_marketplace_skill_install(
        self,
        *,
        profile: str,
        item_id: str,
        version: int,
        sha256: str,
        skill_name: str,
        content_sha256: str | None,
        files: Mapping[str, str],
        request_id: str,
        verification_mode: str = "legacy_exact",
    ) -> dict[str, Any]:
        owner = _identifier(profile, "profile")
        item = _protocol_identifier(item_id, "item_id")
        release_version = _positive_revision(version)
        release_hash = _content_hash(sha256)
        mode = _marketplace_verification_mode(verification_mode)
        installed_hash = None if content_sha256 is None else _content_hash(content_sha256)
        skill = _required_text(skill_name, "skill_name", 64)
        request = _protocol_identifier(request_id, "request_id")
        normalized_files = {
            _required_text(path, "skill_file_path", 512): _content_hash(digest)
            for path, digest in sorted(files.items())
        }
        if mode == "hermes_hub" and (installed_hash is not None or normalized_files):
            raise ValueError("Hermes Hub receipts must not claim installed content digests")
        if mode == "legacy_exact" and installed_hash is None:
            raise ValueError("Legacy exact receipts require an installed content digest")
        files_json = _json(normalized_files)
        now = int(time.time())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            conflicting = connection.execute(
                "SELECT item_id FROM marketplace_skill_installs "
                "WHERE profile=? AND skill_name=? AND item_id<>?",
                (owner, skill, item),
            ).fetchone()
            if conflicting is not None:
                raise ValueError("Marketplace skill name belongs to another item")
            connection.execute(
                """
                INSERT INTO marketplace_skill_installs (
                    profile, item_id, version, sha256, skill_name,
                    content_sha256, installed_content_sha256, verification_mode,
                    files_json, request_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(profile, item_id) DO UPDATE SET
                    version=excluded.version,
                    sha256=excluded.sha256,
                    skill_name=excluded.skill_name,
                    content_sha256=excluded.content_sha256,
                    installed_content_sha256=excluded.installed_content_sha256,
                    verification_mode=excluded.verification_mode,
                    files_json=excluded.files_json,
                    request_id=excluded.request_id,
                    updated_at=excluded.updated_at
                """,
                (
                    owner,
                    item,
                    release_version,
                    release_hash,
                    skill,
                    installed_hash or "",
                    installed_hash,
                    mode,
                    files_json,
                    request,
                    now,
                    now,
                ),
            )
        result = self.get_marketplace_skill_install(profile=owner, item_id=item)
        if result is None:
            raise RuntimeError("Marketplace skill receipt was not persisted")
        return result

    def get_marketplace_skill_install(
        self,
        *,
        profile: str,
        item_id: str,
    ) -> dict[str, Any] | None:
        owner = _identifier(profile, "profile")
        item = _protocol_identifier(item_id, "item_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM marketplace_skill_installs WHERE profile=? AND item_id=?",
                (owner, item),
            ).fetchone()
        if row is None:
            return None
        mode = _marketplace_verification_mode(
            str(row["verification_mode"] or "legacy_exact")
        )
        installed_hash = row["installed_content_sha256"]
        if installed_hash is None and mode == "legacy_exact":
            legacy_hash = str(row["content_sha256"] or "")
            installed_hash = legacy_hash if legacy_hash else None
        result: dict[str, Any] = {
            "agentId": str(row["profile"]),
            "itemId": str(row["item_id"]),
            "version": int(row["version"]),
            "sha256": str(row["sha256"]),
            "skillName": str(row["skill_name"]),
            "requestId": str(row["request_id"]),
            "verificationMode": mode,
        }
        if installed_hash is not None:
            result["contentSha256"] = _content_hash(installed_hash)
            result["files"] = _load_json(str(row["files_json"]), {})
        return result

    def provider_mode(self) -> str:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='provider_mode'"
            ).fetchone()
        return _provider_mode(row["value"] if row is not None else "relay")

    def set_provider_mode(self, mode: str) -> None:
        normalized = _provider_mode(mode)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES ('provider_mode', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (normalized,),
            )

    def save_apns_config(self, config: Mapping[str, Any]) -> None:
        allowed = {"team_id", "key_id", "topic", "environment", "key_path"}
        value = {key: str(config.get(key) or "").strip() for key in sorted(allowed)}
        if any(not value[key] for key in allowed):
            raise ValueError("APNs configuration is incomplete")
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES ('apns_config', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (_json(value),),
            )

    def load_apns_config(self) -> dict[str, str] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='apns_config'"
            ).fetchone()
        if row is None:
            return None
        value = _load_json(row["value"], None)
        if not isinstance(value, dict):
            return None
        return {str(key): str(item) for key, item in value.items()}

    def clear_apns_config(self) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM metadata WHERE key='apns_config'")

    def save_relay_config(self, config: Mapping[str, Any]) -> None:
        allowed = {
            "base_url",
            "tenant_id",
            "credential_key_id",
            "hmac_secret_reference",
            "signing_key_secret_reference",
        }
        if set(config) != allowed:
            raise ValueError("Relay configuration must contain only approved references")
        value = {key: str(config[key]).strip() for key in sorted(allowed)}
        if any(not item for item in value.values()):
            raise ValueError("Relay configuration is incomplete")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            generation = self._metadata_integer(connection, "relay_config_generation", 0) + 1
            connection.execute(
                "UPDATE event_deliveries SET status='failed', failure='relay_target_changed', "
                "relay_request_body_json='', claim_token='', claim_expires=0, next_attempt_at=0 "
                "WHERE provider='relay' AND status='queued'"
            )
            connection.execute("DELETE FROM pending_relay_live_activity_updates")
            connection.execute("DELETE FROM pending_relay_operations")
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES ('relay_config_v1', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (_json(value),),
            )
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES ('relay_config_generation', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(generation),),
            )
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES ('relay_config_state', 'enabled') "
                "ON CONFLICT(key) DO UPDATE SET value='enabled'"
            )

    def load_relay_config(self) -> dict[str, str] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='relay_config_v1'"
            ).fetchone()
        value = None if row is None else _load_json(row["value"], None)
        if not isinstance(value, dict):
            return None
        return {str(key): str(item) for key, item in value.items()}

    def clear_relay_config(self) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM metadata WHERE key='relay_config_v1'")
            connection.execute(
                "UPDATE event_deliveries SET status='failed', failure='relay_target_changed', "
                "relay_request_body_json='', claim_token='', claim_expires=0, next_attempt_at=0 "
                "WHERE provider='relay' AND status='queued'"
            )
            connection.execute("DELETE FROM pending_relay_live_activity_updates")
            connection.execute("DELETE FROM pending_relay_operations")
            generation = self._metadata_integer(connection, "relay_config_generation", 0) + 1
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES ('relay_config_generation', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(generation),),
            )
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES ('relay_config_state', 'disabled') "
                "ON CONFLICT(key) DO UPDATE SET value='disabled'"
            )

    def relay_config_generation(self) -> int:
        with self._connect() as connection:
            return self._metadata_integer(connection, "relay_config_generation", 0)

    def relay_config_enabled(self) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='relay_config_state'"
            ).fetchone()
        return row is None or str(row["value"]) == "enabled"

    def has_pending_live_activity_updates(self) -> bool:
        with self._connect() as connection:
            return connection.execute(
                "SELECT 1 FROM pending_live_activity_updates WHERE terminal=0 LIMIT 1"
            ).fetchone() is not None

    def has_pending_relay_live_activity_updates(self) -> bool:
        with self._connect() as connection:
            return connection.execute(
                "SELECT 1 FROM pending_relay_live_activity_updates WHERE terminal=0 LIMIT 1"
            ).fetchone() is not None

    def has_pending_relay_operations(self) -> bool:
        with self._connect() as connection:
            return connection.execute(
                "SELECT 1 FROM pending_relay_operations WHERE terminal=0 LIMIT 1"
            ).fetchone() is not None

    def _cancel_relay_device_work(
        self,
        connection: sqlite3.Connection,
        device_id: str,
        now: int,
    ) -> None:
        identifier = _identifier(device_id, "device_id")
        connection.execute(
            "UPDATE event_deliveries SET status='failed', failure='relay_target_changed', "
            "relay_request_body_json='', claim_token='', claim_expires=0, next_attempt_at=0 "
            "WHERE provider='relay' AND device_id=? AND status='queued'",
            (identifier,),
        )
        connection.execute(
            "DELETE FROM pending_relay_live_activity_updates WHERE device_id=?",
            (identifier,),
        )
        connection.execute(
            "UPDATE pending_relay_operations SET terminal=1, last_error='relay_target_changed', "
            "claim_token='', claim_expires=0, next_attempt_at=0, updated_at=?, row_version=row_version+1 "
            "WHERE terminal=0 AND operation NOT IN ('revoke_device', 'device_revoke') "
            "AND (device_id=? OR (json_valid(body_json) AND "
            "json_extract(body_json, '$.device_id')=?) OR "
            "(operation='revoke_live_activity' AND device_id IN ("
            "SELECT activity_id FROM relay_live_activities WHERE device_id=?)))",
            (now, identifier, identifier, identifier),
        )
        connection.execute(
            "UPDATE relay_live_activities SET ended_at=COALESCE(ended_at, ?), "
            "revoked_at=COALESCE(revoked_at, ?), updated_at=? WHERE device_id=? "
            "AND ended_at IS NULL AND revoked_at IS NULL",
            (now, now, now, identifier),
        )

    def revoke_relay_tenant(
        self,
        *,
        clear_config: bool = False,
        expected_relay_generation: int | None = None,
    ) -> None:
        """Locally tombstone relay state after a verified tenant operation."""
        now = int(time.time())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current_generation = self._metadata_integer(connection, "relay_config_generation", 0)
            self._assert_relay_generation(connection, expected_relay_generation, current_generation)
            generation = current_generation + 1
            if clear_config:
                connection.execute("DELETE FROM event_deliveries WHERE provider='relay'")
                connection.execute("DELETE FROM provider_receipts WHERE provider='relay'")
                connection.execute("DELETE FROM pending_relay_live_activity_updates")
                connection.execute("DELETE FROM pending_relay_operations")
                connection.execute("DELETE FROM relay_live_activities")
                connection.execute("DELETE FROM devices WHERE provider='relay'")
                connection.execute("DELETE FROM metadata WHERE key='relay_config_v1'")
            else:
                connection.execute(
                    "UPDATE event_deliveries SET status='failed', failure='relay_target_changed', "
                    "relay_request_body_json='' WHERE provider='relay' AND status='queued'"
                )
                connection.execute(
                    "UPDATE devices SET revoked_at=COALESCE(revoked_at, ?), "
                    "acknowledged_sender_key_ids_json='[]', sender_ack_body_digest='', "
                    "updated_at=?, relay_generation=? WHERE provider='relay'",
                    (now, now, generation),
                )
                connection.execute(
                    "UPDATE relay_live_activities SET ended_at=COALESCE(ended_at, ?), "
                    "revoked_at=COALESCE(revoked_at, ?), updated_at=?",
                    (now, now, now),
                )
                connection.execute("DELETE FROM pending_relay_live_activity_updates")
                connection.execute("DELETE FROM pending_relay_operations")
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES ('relay_config_generation', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(generation),),
            )
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES ('relay_config_state', 'disabled') "
                "ON CONFLICT(key) DO UPDATE SET value='disabled'"
            )

    def get_device(self, device_id: str) -> dict[str, Any] | None:
        identifier = _identifier(device_id, "device_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT device_id, endpoint_id, provider, token_environment, label, "
                "groups_json, preferences_json, revoked_at, recipient_public_key, "
                "recipient_key_id, revision, lease_expires, sender_key_revision, "
                "acknowledged_sender_key_ids_json, relay_generation FROM devices WHERE device_id=?",
                (identifier,),
            ).fetchone()
        if row is None:
            return None
        result = _device_row(row)
        if result["provider"] == "relay" and not self.relay_config_enabled():
            result["revoked"] = True
        return result

    def register_relay_live_activity(
        self,
        *,
        activity_id: str,
        device_id: str,
        session_ref: str,
        revision: int,
        timestamp: int,
        lease_expires: int,
        normalized_body: Mapping[str, Any],
        expected_relay_generation: int | None = None,
    ) -> dict[str, Any]:
        activity = _protocol_identifier(activity_id, "activity_id")
        device = _protocol_identifier(device_id, "device_id")
        normalized_revision = _positive_revision(revision)
        watermark = _positive_integer(timestamp, "timestamp")
        normalized_expires = _positive_integer(lease_expires, "lease_expires")
        if watermark <= 0 or normalized_expires <= watermark or normalized_expires - watermark > 28_800:
            raise ValueError("Relay Live Activity registration lease exceeds eight hours")
        digest = _normalized_body_digest(normalized_body)
        now = int(time.time())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            relay_generation = self._metadata_integer(connection, "relay_config_generation", 0)
            self._assert_relay_generation(connection, expected_relay_generation, relay_generation)
            existing = connection.execute(
                "SELECT revision, source_timestamp, normalized_body_digest, revoked_at "
                "FROM relay_live_activities WHERE activity_id=?",
                (activity,),
            ).fetchone()
            if existing is not None:
                previous_revision = int(existing["revision"])
                if existing["revoked_at"] is not None and normalized_revision <= previous_revision:
                    raise ValueError("A revoked Live Activity requires a higher revision")
                if normalized_revision < previous_revision:
                    raise ValueError("Relay Live Activity revision cannot decrease")
                if normalized_revision == previous_revision:
                    if hmac.compare_digest(str(existing["normalized_body_digest"]), digest):
                        return {"changed": False, "revision": normalized_revision}
                    raise ValueError("Relay Live Activity idempotency conflict")
                if watermark <= int(existing["source_timestamp"]):
                    raise ValueError("Relay Live Activity timestamp must increase")
                connection.execute(
                    "DELETE FROM pending_relay_live_activity_updates WHERE activity_id=?",
                    (activity,),
                )
            connection.execute(
                """
                INSERT INTO relay_live_activities (
                    activity_id, device_id, session_ref, revision, source_timestamp,
                    lease_expires, normalized_body_digest, created_at, updated_at,
                    last_push_timestamp, ended_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                ON CONFLICT(activity_id) DO UPDATE SET
                    device_id=excluded.device_id,
                    session_ref=excluded.session_ref,
                    revision=excluded.revision,
                    source_timestamp=excluded.source_timestamp,
                    lease_expires=excluded.lease_expires,
                    normalized_body_digest=excluded.normalized_body_digest,
                    updated_at=excluded.updated_at,
                    ended_at=NULL,
                    revoked_at=NULL
                """,
                (
                    activity,
                    device,
                    _required_text(session_ref, "session_ref", 100),
                    normalized_revision,
                    watermark,
                    normalized_expires,
                    digest,
                    now,
                    now,
                    watermark,
                ),
            )
        return {"changed": True, "revision": normalized_revision}

    def revoke_relay_live_activity(
        self,
        *,
        activity_id: str,
        revision: int,
        timestamp: int,
        normalized_body: Mapping[str, Any],
        expected_relay_generation: int | None = None,
    ) -> dict[str, Any]:
        activity = _protocol_identifier(activity_id, "activity_id")
        normalized_revision = _positive_revision(revision)
        watermark = _positive_integer(timestamp, "timestamp")
        digest = _normalized_body_digest(normalized_body)
        now = int(time.time())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            relay_generation = self._metadata_integer(connection, "relay_config_generation", 0)
            self._assert_relay_generation(connection, expected_relay_generation, relay_generation)
            existing = connection.execute(
                "SELECT revision, source_timestamp, normalized_body_digest, revoked_at "
                "FROM relay_live_activities WHERE activity_id=?",
                (activity,),
            ).fetchone()
            if existing is None:
                raise ValueError("Unknown relay Live Activity")
            previous_revision = int(existing["revision"])
            if normalized_revision < previous_revision:
                raise ValueError("Relay Live Activity revision cannot decrease")
            if normalized_revision == previous_revision:
                if existing["revoked_at"] is not None and hmac.compare_digest(
                    str(existing["normalized_body_digest"]), digest
                ):
                    return {"changed": False, "revision": normalized_revision}
                raise ValueError("Relay Live Activity revocation idempotency conflict")
            if watermark <= int(existing["source_timestamp"]):
                raise ValueError("Relay Live Activity timestamp must increase")
            connection.execute(
                "UPDATE relay_live_activities SET revision=?, source_timestamp=?, "
                "normalized_body_digest=?, ended_at=?, revoked_at=?, updated_at=? "
                "WHERE activity_id=?",
                (normalized_revision, watermark, digest, now, now, now, activity),
            )
            connection.execute(
                "DELETE FROM pending_relay_live_activity_updates WHERE activity_id=?",
                (activity,),
            )
        return {"changed": True, "revision": normalized_revision}

    def active_relay_live_activities(
        self,
        session_ref: str,
        *,
        now: int | None = None,
    ) -> list[dict[str, Any]]:
        reference = _required_text(session_ref, "session_ref", 100)
        current_time = int(time.time()) if now is None else _positive_integer(now, "now")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT activity.* FROM relay_live_activities AS activity "
                "JOIN devices AS device ON device.device_id=activity.device_id "
                "WHERE activity.session_ref=? AND activity.ended_at IS NULL "
                "AND activity.revoked_at IS NULL AND activity.lease_expires>? "
                "AND device.provider='relay' AND device.revoked_at IS NULL "
                "AND ?=1 AND device.relay_generation=? "
                "AND device.lease_expires>? "
                "AND device.acknowledged_sender_key_ids_json<>'[]' "
                "ORDER BY activity.updated_at DESC, activity.activity_id",
                (reference, current_time, 1 if self.relay_config_enabled() else 0,
                 self.relay_config_generation(), current_time),
            ).fetchall()
        return [dict(row) for row in rows]

    def active_relay_live_activity(
        self,
        activity_id: str,
        *,
        expected_session_ref: str = "",
        expected_device_id: str = "",
        expected_revision: int = 0,
        expected_lease_expires: int = 0,
        now: int | None = None,
    ) -> dict[str, Any] | None:
        activity = _protocol_identifier(activity_id, "activity_id")
        current_time = int(time.time()) if now is None else _positive_integer(now, "now")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT activity.* FROM relay_live_activities AS activity "
                "JOIN devices AS device ON device.device_id=activity.device_id "
                "WHERE activity.activity_id=? AND activity.ended_at IS NULL "
                "AND activity.revoked_at IS NULL AND activity.lease_expires>? "
                "AND device.provider='relay' AND device.revoked_at IS NULL "
                "AND ?=1 AND device.relay_generation=? "
                "AND device.lease_expires>? "
                "AND device.acknowledged_sender_key_ids_json<>'[]' "
                "AND (?='' OR activity.session_ref=?) "
                "AND (?='' OR activity.device_id=?) "
                "AND (?=0 OR activity.revision=?) "
                "AND (?=0 OR activity.lease_expires=?)",
                (
                    activity,
                    current_time,
                    1 if self.relay_config_enabled() else 0,
                    self.relay_config_generation(),
                    current_time,
                    expected_session_ref,
                    expected_session_ref,
                    expected_device_id,
                    expected_device_id,
                    expected_revision,
                    expected_revision,
                    expected_lease_expires,
                    expected_lease_expires,
                ),
            ).fetchone()
        return None if row is None else dict(row)

    def allocate_relay_live_activity_timestamp(
        self,
        activity_id: str,
        current_time: int,
        *,
        expected_session_ref: str,
        expected_device_id: str,
        expected_revision: int,
        expected_lease_expires: int,
    ) -> int:
        activity = _protocol_identifier(activity_id, "activity_id")
        current = _positive_integer(current_time, "current_time")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT activity.source_timestamp, activity.last_push_timestamp "
                "FROM relay_live_activities AS activity "
                "JOIN devices AS device ON device.device_id=activity.device_id "
                "WHERE activity.activity_id=? AND activity.ended_at IS NULL "
                "AND activity.revoked_at IS NULL AND activity.lease_expires>? "
                "AND device.provider='relay' AND device.revoked_at IS NULL "
                "AND ?=1 AND device.relay_generation=? "
                "AND device.lease_expires>? "
                "AND device.acknowledged_sender_key_ids_json<>'[]' "
                "AND activity.session_ref=? AND activity.device_id=? "
                "AND activity.revision=? AND activity.lease_expires=?",
                (
                    activity,
                    current,
                    1 if self.relay_config_enabled() else 0,
                    self.relay_config_generation(),
                    current,
                    expected_session_ref,
                    expected_device_id,
                    _positive_revision(expected_revision),
                    _positive_integer(expected_lease_expires, "expected_lease_expires"),
                ),
            ).fetchone()
            if row is None:
                raise ValueError("Unknown, expired, or ended relay Live Activity")
            timestamp = max(
                current,
                int(row["source_timestamp"]) + 1,
                int(row["last_push_timestamp"]) + 1,
            )
            connection.execute(
                "UPDATE relay_live_activities SET last_push_timestamp=?, updated_at=? "
                "WHERE activity_id=? AND ended_at IS NULL AND revoked_at IS NULL "
                "AND session_ref=? AND device_id=? AND revision=? AND lease_expires=?",
                (
                    timestamp,
                    int(time.time()),
                    activity,
                    expected_session_ref,
                    expected_device_id,
                    expected_revision,
                    expected_lease_expires,
                ),
            )
        return timestamp

    def end_relay_live_activity(
        self,
        activity_id: str,
        *,
        expected_session_ref: str = "",
        expected_device_id: str = "",
        expected_revision: int = 0,
        expected_delivery_id: str = "",
        expected_idempotency_key: str = "",
    ) -> bool:
        activity = _protocol_identifier(activity_id, "activity_id")
        now = int(time.time())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if expected_delivery_id or expected_idempotency_key:
                pending = connection.execute(
                    "SELECT 1 FROM pending_relay_live_activity_updates "
                    "WHERE activity_id=? "
                    "AND (?='' OR delivery_id=?) "
                    "AND (?='' OR idempotency_key=?) "
                    "AND (?='' OR device_id=?) "
                    "AND (?='' OR session_ref=?) "
                    "AND (?=0 OR revision=?) "
                    "LIMIT 1",
                    (
                        activity,
                        expected_delivery_id,
                        expected_delivery_id,
                        expected_idempotency_key,
                        expected_idempotency_key,
                        expected_device_id,
                        expected_device_id,
                        expected_session_ref,
                        expected_session_ref,
                        expected_revision,
                        expected_revision,
                    ),
                ).fetchone()
                if pending is None:
                    return False
            cursor = connection.execute(
                "UPDATE relay_live_activities SET ended_at=?, updated_at=? "
                "WHERE activity_id=? AND ended_at IS NULL "
                "AND (?='' OR session_ref=?) AND (?='' OR device_id=?) "
                "AND (?=0 OR revision=?)",
                (
                    now,
                    now,
                    activity,
                    expected_session_ref,
                    expected_session_ref,
                    expected_device_id,
                    expected_device_id,
                    expected_revision,
                    expected_revision,
                ),
            )
            if cursor.rowcount:
                connection.execute(
                    "DELETE FROM pending_relay_live_activity_updates WHERE activity_id=? "
                    "AND (?='' OR device_id=?) AND (?='' OR session_ref=?) "
                    "AND (?=0 OR revision=?) "
                    "AND (?='' OR delivery_id=?) "
                    "AND (?='' OR idempotency_key=?)",
                    (
                        activity,
                        expected_device_id,
                        expected_device_id,
                        expected_session_ref,
                        expected_session_ref,
                        expected_revision,
                        expected_revision,
                        expected_delivery_id,
                        expected_delivery_id,
                        expected_idempotency_key,
                        expected_idempotency_key,
                    ),
                )
            return cursor.rowcount == 1

    def upsert_live_activity(
        self,
        *,
        session_id: str,
        live_session_id: str,
        profile: str,
        activity_id: str,
        push_token: str,
        token_environment: str,
    ) -> None:
        environment = str(token_environment or "production").strip().lower()
        if environment not in {"production", "sandbox"}:
            raise ValueError("Live Activity environment must be production or sandbox")
        now = int(time.time())
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO live_activities (
                    activity_id, session_id, live_session_id, profile, push_token,
                    token_environment, created_at, updated_at, ended_at,
                    owner_generation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 1)
                ON CONFLICT(activity_id) DO UPDATE SET
                    session_id=excluded.session_id,
                    live_session_id=excluded.live_session_id,
                    profile=excluded.profile,
                    push_token=excluded.push_token,
                    token_environment=excluded.token_environment,
                    updated_at=excluded.updated_at,
                    owner_generation=live_activities.owner_generation + 1,
                    ended_at=NULL
                """,
                (
                    _identifier(activity_id, "activity_id"),
                    _identifier(session_id, "session_id"),
                    _identifier(live_session_id or session_id, "live_session_id"),
                    _required_text(profile or "default", "profile", 80),
                    _required_text(push_token, "push_token", 512),
                    environment,
                    now,
                    now,
                ),
            )
            connection.execute(
                "DELETE FROM pending_live_activity_updates WHERE activity_id=?",
                (_identifier(activity_id, "activity_id"),),
            )

    def active_live_activities(self, session_id: str, profile: str = "") -> list[dict[str, Any]]:
        identifier = _identifier(session_id, "session_id")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM live_activities WHERE ended_at IS NULL "
                "AND (session_id=? OR live_session_id=?) "
                "AND (?='' OR profile=?) ORDER BY updated_at DESC",
                (identifier, identifier, str(profile or ""), str(profile or "")),
            ).fetchall()
        return [dict(row) for row in rows]

    def active_live_activity(
        self,
        activity_id: str,
        *,
        expected_session_id: str = "",
        expected_live_session_id: str = "",
        expected_profile: str = "",
        expected_push_token: str = "",
    ) -> dict[str, Any] | None:
        identifier = _identifier(activity_id, "activity_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM live_activities WHERE activity_id=? AND ended_at IS NULL "
                "AND (?='' OR session_id=?) AND (?='' OR live_session_id=?) "
                "AND (?='' OR profile=?) AND (?='' OR push_token=?)",
                (
                    identifier,
                    expected_session_id,
                    expected_session_id,
                    expected_live_session_id,
                    expected_live_session_id,
                    expected_profile,
                    expected_profile,
                    expected_push_token,
                    expected_push_token,
                ),
            ).fetchone()
        return None if row is None else dict(row)

    @contextmanager
    def live_activity_send_lock(self, activity_id: str):
        identifier = _identifier(activity_id, "activity_id")
        lock_directory = self.path.parent / f".{self.path.name}.live-activity-locks"
        lock_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_name = hashlib.sha256(identifier.encode("utf-8")).hexdigest()
        descriptor = os.open(lock_directory / lock_name, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            _lock_file_descriptor(descriptor)
            yield
        finally:
            _unlock_file_descriptor(descriptor)
            os.close(descriptor)

    def allocate_live_activity_timestamp(
        self,
        activity_id: str,
        current_time: int,
        *,
        expected_session_id: str = "",
        expected_live_session_id: str = "",
        expected_profile: str = "",
        expected_push_token: str = "",
        expected_owner_generation: int = 0,
    ) -> int:
        identifier = _identifier(activity_id, "activity_id")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT last_push_timestamp FROM live_activities "
                "WHERE activity_id=? AND ended_at IS NULL "
                "AND (?='' OR session_id=?) AND (?='' OR live_session_id=?) "
                "AND (?='' OR profile=?) AND (?='' OR push_token=?) "
                "AND (?=0 OR owner_generation=?)",
                (
                    identifier,
                    expected_session_id,
                    expected_session_id,
                    expected_live_session_id,
                    expected_live_session_id,
                    expected_profile,
                    expected_profile,
                    expected_push_token,
                    expected_push_token,
                    max(0, int(expected_owner_generation)),
                    max(0, int(expected_owner_generation)),
                ),
            ).fetchone()
            if row is None:
                raise ValueError("Unknown or ended Live Activity")
            timestamp = max(int(current_time), int(row["last_push_timestamp"]) + 1)
            connection.execute(
                "UPDATE live_activities SET last_push_timestamp=?, updated_at=? "
                "WHERE activity_id=? AND ended_at IS NULL "
                "AND (?='' OR session_id=?) AND (?='' OR live_session_id=?) "
                "AND (?='' OR profile=?) AND (?='' OR push_token=?) "
                "AND (?=0 OR owner_generation=?)",
                (
                    timestamp,
                    int(time.time()),
                    identifier,
                    expected_session_id,
                    expected_session_id,
                    expected_live_session_id,
                    expected_live_session_id,
                    expected_profile,
                    expected_profile,
                    expected_push_token,
                    expected_push_token,
                    max(0, int(expected_owner_generation)),
                    max(0, int(expected_owner_generation)),
                ),
            )
            return timestamp

    def end_live_activity(
        self,
        activity_id: str,
        *,
        expected_session_id: str = "",
        expected_live_session_id: str = "",
        expected_profile: str = "",
        expected_push_token: str = "",
        expected_owner_generation: int = 0,
        expected_request_id: str = "",
    ) -> bool:
        identifier = _identifier(activity_id, "activity_id")
        owner_generation = max(0, int(expected_owner_generation))
        request_id = str(expected_request_id or "")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if request_id:
                pending = connection.execute(
                    "SELECT 1 FROM pending_live_activity_updates "
                    "WHERE activity_id=? AND request_id=? "
                    "AND (?=0 OR owner_generation=?) LIMIT 1",
                    (identifier, _required_text(request_id, "expected_request_id", 512),
                     owner_generation, owner_generation),
                ).fetchone()
                if pending is None:
                    return False
            ended = connection.execute(
                "UPDATE live_activities SET ended_at=?, updated_at=? WHERE activity_id=? "
                "AND (?='' OR session_id=?) AND (?='' OR live_session_id=?) "
                "AND (?='' OR profile=?) AND (?='' OR push_token=?) "
                "AND (?=0 OR owner_generation=?)",
                (
                    int(time.time()),
                    int(time.time()),
                    identifier,
                    expected_session_id,
                    expected_session_id,
                    expected_live_session_id,
                    expected_live_session_id,
                    expected_profile,
                    expected_profile,
                    expected_push_token,
                    expected_push_token,
                    owner_generation,
                    owner_generation,
                ),
            )
            if ended.rowcount:
                connection.execute(
                    "DELETE FROM pending_live_activity_updates WHERE activity_id=? "
                    "AND (?='' OR owner_session_id=?) "
                    "AND (?='' OR owner_live_session_id=?) "
                    "AND (?='' OR owner_profile=?) "
                    "AND (?='' OR owner_push_token=?) "
                    "AND (?=0 OR owner_generation=?) "
                    "AND (?='' OR request_id=?)",
                    (
                        identifier,
                        expected_session_id, expected_session_id,
                        expected_live_session_id, expected_live_session_id,
                        expected_profile, expected_profile,
                        expected_push_token, expected_push_token,
                        owner_generation, owner_generation,
                        request_id, request_id,
                    ),
                )
            return ended.rowcount == 1

    def defer_live_activity_update(
        self,
        *,
        activity_id: str,
        status: str,
        detail: str,
        tool_name: str,
        active_session_count: int,
        delay_seconds: int,
        failure: str,
        expected_session_id: str = "",
        expected_live_session_id: str = "",
        expected_profile: str = "",
        expected_push_token: str = "",
        expected_owner_generation: int = 0,
        expected_request_id: str = "",
    ) -> bool:
        now = int(time.time())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            owner = connection.execute(
                "SELECT session_id, live_session_id, profile, push_token, owner_generation "
                "FROM live_activities WHERE activity_id=? AND ended_at IS NULL",
                (_identifier(activity_id, "activity_id"),),
            ).fetchone()
            if owner is None:
                raise ValueError("Unknown or ended Live Activity")
            owner_values = {
                "session_id": str(owner["session_id"]),
                "live_session_id": str(owner["live_session_id"]),
                "profile": str(owner["profile"]),
                "push_token": str(owner["push_token"]),
                "owner_generation": int(owner["owner_generation"] or 0),
            }
            expected_owner = max(0, int(expected_owner_generation))
            if (
                (expected_session_id and str(expected_session_id) != owner_values["session_id"])
                or (expected_live_session_id and str(expected_live_session_id) != owner_values["live_session_id"])
                or (expected_profile and str(expected_profile) != owner_values["profile"])
                or (expected_push_token and str(expected_push_token) != owner_values["push_token"])
                or (expected_owner and expected_owner != owner_values["owner_generation"])
            ):
                return False
            normalized_status = _required_text(status, "status", 40)
            existing = connection.execute(
                "SELECT status, terminal, attempts, owner_session_id, owner_live_session_id, "
                "owner_profile, owner_push_token, owner_generation, request_id "
                "FROM pending_live_activity_updates "
                "WHERE activity_id=?",
                (_identifier(activity_id, "activity_id"),),
            ).fetchone()
            if expected_request_id and (
                existing is None
                or str(existing["request_id"] or "") != str(expected_request_id)
                or int(existing["owner_generation"] or 0) != owner_values["owner_generation"]
            ):
                return False
            reset_attempts = False
            if existing is not None:
                previous_status = str(existing["status"])
                previous_terminal = bool(int(existing["terminal"] or 0)) or previous_status in {
                    "completed", "failed"
                }
                routine = {"thinking", "running"}
                if previous_terminal:
                    if previous_status in {"completed", "failed"} or normalized_status not in {
                        "waiting", "completed", "failed"
                    }:
                        # A non-exhausted terminal update may be retried with
                        # the same phase; a different terminal remains
                        # authoritative.  Exhausted terminal rows are never
                        # automatically retried.
                        if not (
                            previous_status == normalized_status
                            and not bool(int(existing["terminal"] or 0))
                        ):
                            return
                    else:
                        reset_attempts = True
                elif previous_status == "waiting" and normalized_status in routine:
                    return
                elif previous_status in routine and normalized_status in {
                    "waiting", "completed", "failed"
                }:
                    reset_attempts = True
                owner_changed = any(
                    str(existing[key] or "") != owner_values[value]
                    for key, value in (
                        ("owner_session_id", "session_id"),
                        ("owner_live_session_id", "live_session_id"),
                        ("owner_profile", "profile"),
                        ("owner_push_token", "push_token"),
                    )
                )
                reset_attempts = reset_attempts or owner_changed
            else:
                reset_attempts = True
            attempts = 1 if reset_attempts else int(existing["attempts"]) + 1
            terminal = int(attempts >= _MAX_RELAY_AUTOMATIC_ATTEMPTS)
            request_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO pending_live_activity_updates (
                    activity_id, status, detail, tool_name, active_session_count,
                    attempts, next_attempt_at, last_error, updated_at, terminal,
                    owner_session_id, owner_live_session_id, owner_profile,
                    owner_push_token, owner_generation, request_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(activity_id) DO UPDATE SET
                    status=excluded.status,
                    detail=excluded.detail,
                    tool_name=excluded.tool_name,
                    active_session_count=excluded.active_session_count,
                    attempts=excluded.attempts,
                    next_attempt_at=excluded.next_attempt_at,
                    last_error=excluded.last_error,
                    updated_at=excluded.updated_at,
                    terminal=excluded.terminal,
                    owner_session_id=excluded.owner_session_id,
                    owner_live_session_id=excluded.owner_live_session_id,
                    owner_profile=excluded.owner_profile,
                    owner_push_token=excluded.owner_push_token,
                    owner_generation=excluded.owner_generation,
                    request_id=excluded.request_id
                """,
                (
                    _identifier(activity_id, "activity_id"),
                    normalized_status,
                    _text(detail, 180),
                    _text(tool_name, 80),
                    max(0, int(active_session_count)),
                    attempts,
                    now + max(0, int(delay_seconds)),
                    _text(failure, 500),
                    now,
                    terminal,
                    owner_values["session_id"],
                    owner_values["live_session_id"],
                    owner_values["profile"],
                    owner_values["push_token"],
                    owner_values["owner_generation"],
                    request_id,
                ),
            )
            return True

    def due_live_activity_updates(self, *, limit: int = 100) -> list[dict[str, Any]]:
        bounded = min(1000, max(1, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT pending.*, activity.push_token, activity.token_environment
                FROM pending_live_activity_updates AS pending
                JOIN live_activities AS activity USING (activity_id)
                WHERE pending.terminal=0 AND pending.next_attempt_at <= ? AND activity.ended_at IS NULL
                ORDER BY pending.next_attempt_at, pending.updated_at
                LIMIT ?
                """,
                (int(time.time()), bounded),
            ).fetchall()
        return [dict(row) for row in rows]

    def clear_pending_live_activity_update(
        self,
        activity_id: str,
        *,
        expected_session_id: str = "",
        expected_live_session_id: str = "",
        expected_profile: str = "",
        expected_push_token: str = "",
        expected_owner_generation: int = 0,
        expected_request_id: str = "",
    ) -> bool:
        clauses = ["activity_id=?"]
        values: list[Any] = [_identifier(activity_id, "activity_id")]
        for column, value, label in (
            ("owner_session_id", expected_session_id, "expected_session_id"),
            ("owner_live_session_id", expected_live_session_id, "expected_live_session_id"),
            ("owner_profile", expected_profile, "expected_profile"),
            ("owner_push_token", expected_push_token, "expected_push_token"),
            ("owner_generation", expected_owner_generation, "expected_owner_generation"),
            ("request_id", expected_request_id, "expected_request_id"),
        ):
            if value:
                clauses.append(f"{column}=?")
                values.append(_required_text(value, label, 512))
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM pending_live_activity_updates WHERE " + " AND ".join(clauses),
                tuple(values),
            )
            return cursor.rowcount == 1

    def pending_live_activity_update(self, activity_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM pending_live_activity_updates WHERE activity_id=?",
                (_identifier(activity_id, "activity_id"),),
            ).fetchone()
        return dict(row) if row is not None else None

    def pending_live_activity_updates(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM pending_live_activity_updates ORDER BY updated_at"
            ).fetchall()
        return [dict(row) for row in rows]

    def defer_relay_live_activity_update(
        self,
        *,
        activity_id: str,
        status: str,
        detail: str,
        tool_name: str,
        active_session_count: int,
        delay_seconds: int,
        failure: str,
        timestamp: int = 0,
        delivery_id: str = "",
        idempotency_key: str = "",
        request_body: Mapping[str, Any] | None = None,
        expected_device_id: str = "",
        expected_session_ref: str = "",
        expected_revision: int = 0,
        expected_lease_expires: int = 0,
        expected_relay_generation: int | None = None,
        expected_delivery_id: str = "",
        expected_idempotency_key: str = "",
    ) -> None:
        now = int(time.time())
        normalized_body = "" if request_body is None else _json(request_body)
        expected_device = (
            "" if not expected_device_id else _identifier(expected_device_id, "expected_device_id")
        )
        expected_session = (
            "" if not expected_session_ref else _required_text(expected_session_ref, "expected_session_ref", 100)
        )
        expected_owner_revision = 0 if not expected_revision else _positive_revision(expected_revision)
        expected_lease = (
            0
            if not expected_lease_expires
            else _positive_integer(expected_lease_expires, "expected_lease_expires")
        )
        expected_generation = (
            None if expected_relay_generation is None else max(0, int(expected_relay_generation))
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            owner = connection.execute(
                "SELECT device_id, session_ref, revision, lease_expires "
                "FROM relay_live_activities WHERE activity_id=?",
                (_identifier(activity_id, "activity_id"),),
            ).fetchone()
            if owner is None:
                raise ValueError("Unknown relay Live Activity owner")
            device = str(owner["device_id"])
            session = str(owner["session_ref"])
            owner_revision = int(owner["revision"])
            lease_expires = int(owner["lease_expires"])
            device_row = connection.execute(
                "SELECT provider, revoked_at, relay_generation FROM devices WHERE device_id=?",
                (device,),
            ).fetchone()
            if (
                device_row is None
                or device_row["provider"] != "relay"
                or device_row["revoked_at"] is not None
            ):
                raise ValueError("Relay Live Activity device is not active")
            generation = int(device_row["relay_generation"])
            if (
                (expected_device and expected_device != device)
                or (expected_session and expected_session != session)
                or (expected_owner_revision and expected_owner_revision != owner_revision)
                or (expected_lease and expected_lease != lease_expires)
                or (expected_generation is not None and expected_generation != generation)
            ):
                raise ValueError("Relay Live Activity pending update owner changed")
            normalized_status = _required_text(status, "status", 40)
            existing = connection.execute(
                "SELECT status, terminal, attempts, delivery_id, idempotency_key "
                "FROM pending_relay_live_activity_updates "
                "WHERE activity_id=?",
                (_identifier(activity_id, "activity_id"),),
            ).fetchone()
            if expected_delivery_id or expected_idempotency_key:
                if existing is None or (
                    expected_delivery_id
                    and str(existing["delivery_id"] or "") != _text(expected_delivery_id, 180)
                ) or (
                    expected_idempotency_key
                    and str(existing["idempotency_key"] or "")
                    != _text(expected_idempotency_key, 180)
                ):
                    raise ValueError("Relay Live Activity pending update request changed")
            if existing is not None:
                previous_status = str(existing["status"])
                previous_terminal = bool(int(existing["terminal"] or 0)) or previous_status in {
                    "completed", "failed"
                }
                routine = {"thinking", "running"}
                if previous_terminal:
                    # A settled terminal is authoritative.  An exhausted
                    # routine row is recoverable, however, so waiting or a
                    # terminal update can replace it and reset its retry cap.
                    if previous_status in {"completed", "failed"}:
                        if not (
                            previous_status == normalized_status
                            and not bool(int(existing["terminal"] or 0))
                        ):
                            return
                    elif normalized_status not in {"waiting", "completed", "failed"}:
                        return
                    else:
                        connection.execute(
                            "UPDATE pending_relay_live_activity_updates SET attempts=0, terminal=0 "
                            "WHERE activity_id=?",
                            (_identifier(activity_id, "activity_id"),),
                        )
                elif previous_status == "waiting" and normalized_status in routine:
                    # Waiting is more actionable than routine progress and
                    # must not be hidden by a later routine coalescing write.
                    return
            connection.execute(
                """
                INSERT INTO pending_relay_live_activity_updates (
                    activity_id, status, detail, tool_name, active_session_count,
                    attempts, next_attempt_at, last_error, updated_at,
                    timestamp, delivery_id, idempotency_key, request_body_json,
                    device_id, session_ref, revision, lease_expires, relay_generation
                ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(activity_id) DO UPDATE SET
                    status=excluded.status,
                    detail=excluded.detail,
                    tool_name=excluded.tool_name,
                    active_session_count=excluded.active_session_count,
                    attempts=pending_relay_live_activity_updates.attempts + 1,
                    next_attempt_at=excluded.next_attempt_at,
                    last_error=excluded.last_error,
                    terminal=CASE WHEN pending_relay_live_activity_updates.attempts + 1 >= 5 THEN 1 ELSE 0 END,
                    updated_at=excluded.updated_at,
                    timestamp=CASE
                        WHEN pending_relay_live_activity_updates.device_id != excluded.device_id
                          OR pending_relay_live_activity_updates.session_ref != excluded.session_ref
                          OR pending_relay_live_activity_updates.revision != excluded.revision
                          OR pending_relay_live_activity_updates.lease_expires != excluded.lease_expires
                          OR pending_relay_live_activity_updates.relay_generation != excluded.relay_generation
                        THEN excluded.timestamp
                        WHEN excluded.timestamp=0 THEN pending_relay_live_activity_updates.timestamp
                        ELSE excluded.timestamp
                    END,
                    delivery_id=CASE
                        WHEN pending_relay_live_activity_updates.device_id != excluded.device_id
                          OR pending_relay_live_activity_updates.session_ref != excluded.session_ref
                          OR pending_relay_live_activity_updates.revision != excluded.revision
                          OR pending_relay_live_activity_updates.lease_expires != excluded.lease_expires
                          OR pending_relay_live_activity_updates.relay_generation != excluded.relay_generation
                        THEN excluded.delivery_id
                        WHEN excluded.delivery_id='' THEN pending_relay_live_activity_updates.delivery_id
                        ELSE excluded.delivery_id
                    END,
                    idempotency_key=CASE
                        WHEN pending_relay_live_activity_updates.device_id != excluded.device_id
                          OR pending_relay_live_activity_updates.session_ref != excluded.session_ref
                          OR pending_relay_live_activity_updates.revision != excluded.revision
                          OR pending_relay_live_activity_updates.lease_expires != excluded.lease_expires
                          OR pending_relay_live_activity_updates.relay_generation != excluded.relay_generation
                        THEN excluded.idempotency_key
                        WHEN excluded.idempotency_key='' THEN pending_relay_live_activity_updates.idempotency_key
                        ELSE excluded.idempotency_key
                    END,
                    request_body_json=CASE
                        WHEN pending_relay_live_activity_updates.device_id != excluded.device_id
                          OR pending_relay_live_activity_updates.session_ref != excluded.session_ref
                          OR pending_relay_live_activity_updates.revision != excluded.revision
                          OR pending_relay_live_activity_updates.lease_expires != excluded.lease_expires
                          OR pending_relay_live_activity_updates.relay_generation != excluded.relay_generation
                        THEN excluded.request_body_json
                        WHEN excluded.request_body_json='' THEN pending_relay_live_activity_updates.request_body_json
                        ELSE excluded.request_body_json
                    END,
                    device_id=excluded.device_id,
                    session_ref=excluded.session_ref,
                    revision=excluded.revision,
                    lease_expires=excluded.lease_expires,
                    relay_generation=excluded.relay_generation
                """,
                (
                    _identifier(activity_id, "activity_id"),
                    normalized_status,
                    _text(detail, 180),
                    _text(tool_name, 80),
                    max(0, int(active_session_count)),
                    now + max(0, int(delay_seconds)),
                    _text(failure, 500),
                    now,
                    max(0, int(timestamp)),
                    _text(delivery_id, 180),
                    _text(idempotency_key, 180),
                    normalized_body,
                    device,
                    session,
                    owner_revision,
                    lease_expires,
                    generation,
                ),
            )

    def due_relay_live_activity_updates(self, *, limit: int = 100) -> list[dict[str, Any]]:
        bounded = min(1000, max(1, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT pending.*, activity.device_id, activity.session_ref,
                       activity.revision, activity.lease_expires
                FROM pending_relay_live_activity_updates AS pending
                JOIN relay_live_activities AS activity USING (activity_id)
                WHERE pending.terminal=0 AND pending.next_attempt_at <= ? AND activity.ended_at IS NULL
                  AND activity.revoked_at IS NULL
                ORDER BY pending.next_attempt_at, pending.updated_at
                LIMIT ?
                """,
                (int(time.time()), bounded),
            ).fetchall()
        return [dict(row) for row in rows]

    def pending_relay_live_activity_update(self, activity_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM pending_relay_live_activity_updates WHERE activity_id=?",
                (_identifier(activity_id, "activity_id"),),
            ).fetchone()
        return dict(row) if row is not None else None

    def pending_relay_live_activity_updates(self, *, limit: int = 100) -> list[dict[str, Any]]:
        bounded = min(1000, max(1, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM pending_relay_live_activity_updates WHERE terminal=0 "
                "ORDER BY updated_at LIMIT ?",
                (bounded,),
            ).fetchall()
        return [dict(row) for row in rows]

    def clear_pending_relay_live_activity_update(
        self,
        activity_id: str,
        *,
        expected_device_id: str = "",
        expected_session_ref: str = "",
        expected_revision: int = 0,
        expected_lease_expires: int = 0,
        expected_relay_generation: int | None = None,
        expected_delivery_id: str = "",
        expected_idempotency_key: str = "",
    ) -> bool:
        clauses = ["activity_id=?"]
        values: list[Any] = [_identifier(activity_id, "activity_id")]
        if expected_device_id:
            clauses.append("device_id=?")
            values.append(_identifier(expected_device_id, "expected_device_id"))
        if expected_session_ref:
            clauses.append("session_ref=?")
            values.append(_required_text(expected_session_ref, "expected_session_ref", 100))
        if expected_revision:
            clauses.append("revision=?")
            values.append(_positive_revision(expected_revision))
        if expected_lease_expires:
            clauses.append("lease_expires=?")
            values.append(_positive_integer(expected_lease_expires, "expected_lease_expires"))
        if expected_relay_generation is not None:
            clauses.append("relay_generation=?")
            values.append(max(0, int(expected_relay_generation)))
        if expected_delivery_id:
            clauses.append("delivery_id=?")
            values.append(_text(expected_delivery_id, 180))
        if expected_idempotency_key:
            clauses.append("idempotency_key=?")
            values.append(_text(expected_idempotency_key, 180))
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM pending_relay_live_activity_updates WHERE " + " AND ".join(clauses),
                tuple(values),
            )
            return cursor.rowcount == 1

    def save_pending_relay_operation(
        self,
        *,
        operation: str,
        device_id: str,
        revision: int,
        idempotency_key: str,
        body: Mapping[str, Any],
        relay_generation: int = 0,
    ) -> None:
        normalized_operation = _relay_operation_name(operation)
        normalized_device = _identifier(device_id, "device_id")
        normalized_revision = _positive_revision(revision)
        normalized_key = _required_text(idempotency_key, "idempotency_key", 180)
        if _UUID.fullmatch(normalized_key) is None:
            raise ValueError("idempotency_key must be a lowercase UUID")
        body_json = _json(body)
        request_digest = hashlib.sha256(body_json.encode("utf-8")).hexdigest()
        now = int(time.time())
        with self._connect() as connection:
            # Admission is a compare-and-insert transaction.  Without an
            # immediate write lock, two processes can both observe no row and
            # race into the primary-key insert.
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT body_json, request_digest, revision, idempotency_key, relay_generation "
                "FROM pending_relay_operations WHERE operation=? AND device_id=?",
                (normalized_operation, normalized_device),
            ).fetchone()
            if existing is not None:
                existing_digest = str(existing["request_digest"] or "")
                if not existing_digest:
                    existing_digest = hashlib.sha256(str(existing["body_json"]).encode("utf-8")).hexdigest()
                if (
                    not hmac.compare_digest(existing_digest, request_digest)
                    or int(existing["revision"]) != normalized_revision
                    or str(existing["idempotency_key"]) != normalized_key
                    or int(existing["relay_generation"]) != max(0, int(relay_generation))
                ):
                    raise ValueError("Relay operation request conflict")
                return
            connection.execute(
                """
                INSERT INTO pending_relay_operations (
                    operation, device_id, revision, idempotency_key, body_json,
                    response_json, relay_generation, request_digest, attempts, updated_at,
                    next_attempt_at, claim_token, claim_expires, terminal, last_error, row_version
                ) VALUES (?, ?, ?, ?, ?, '', ?, ?, 0, ?, ?, '', 0, 0, '', 1)
                """,
                (
                    normalized_operation,
                    normalized_device,
                    normalized_revision,
                    normalized_key,
                    body_json,
                    max(0, int(relay_generation)),
                    request_digest,
                    now,
                    now,
                ),
            )

    def claim_pending_relay_operations(
        self, *, limit: int = 100, lease_seconds: int = _CLAIM_LEASE_SECONDS,
        ignore_due: bool = False,
    ) -> list[dict[str, Any]]:
        bounded = min(100, max(1, int(limit)))
        now = int(time.time())
        lease = max(5, int(lease_seconds))
        claimed: list[dict[str, Any]] = []
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM pending_relay_operations WHERE terminal=0 "
                "AND (?=1 OR next_attempt_at<=?) "
                "AND (claim_token='' OR claim_expires<=?) "
                "ORDER BY next_attempt_at, updated_at LIMIT ?",
                (1 if ignore_due else 0, now, now, bounded),
            ).fetchall()
            for row in rows:
                token = str(uuid.uuid4())
                cursor = connection.execute(
                    "UPDATE pending_relay_operations SET claim_token=?, claim_expires=?, "
                    "attempts=attempts+1, updated_at=?, row_version=row_version+1 "
                    "WHERE operation=? AND device_id=? AND row_version=? AND terminal=0 "
                    "AND (?=1 OR next_attempt_at<=?) AND (claim_token='' OR claim_expires<=?)",
                    (token, now + lease, now, row["operation"], row["device_id"], row["row_version"],
                     1 if ignore_due else 0, now, now),
                )
                if cursor.rowcount:
                    claimed_row = dict(row)
                    claimed_row.update(
                        claim_token=token,
                        claim_expires=now + lease,
                        attempts=int(row["attempts"]) + 1,
                        updated_at=now,
                        row_version=int(row["row_version"]) + 1,
                    )
                    claimed.append(claimed_row)
        return claimed

    def claim_pending_relay_operation(
        self,
        operation: str,
        device_id: str,
        *,
        lease_seconds: int = _CLAIM_LEASE_SECONDS,
        ignore_due: bool = False,
    ) -> dict[str, Any] | None:
        """Claim exactly one synchronous operation without leasing siblings."""
        normalized_device = _identifier(device_id, "device_id")
        normalized_operation = _relay_operation_name(operation)
        now = int(time.time())
        lease = max(5, int(lease_seconds))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM pending_relay_operations WHERE operation IN (?, ?) AND device_id=? "
                "AND terminal=0 AND (?=1 OR next_attempt_at<=?) "
                "AND (claim_token='' OR claim_expires<=?) "
                "ORDER BY CASE operation WHEN 'revoke_device' THEN 0 ELSE 1 END LIMIT 1",
                (normalized_operation, "device_revoke", normalized_device,
                 1 if ignore_due else 0, now, now),
            ).fetchone()
            if row is None:
                return None
            token = str(uuid.uuid4())
            cursor = connection.execute(
                "UPDATE pending_relay_operations SET claim_token=?, claim_expires=?, "
                "attempts=attempts+1, updated_at=?, row_version=row_version+1 "
                "WHERE operation=? AND device_id=? AND row_version=? AND terminal=0 "
                "AND (?=1 OR next_attempt_at<=?) AND (claim_token='' OR claim_expires<=?)",
                (token, now + lease, now, row["operation"], row["device_id"], row["row_version"],
                 1 if ignore_due else 0, now, now),
            )
            if cursor.rowcount != 1:
                return None
            result = dict(row)
            result.update(
                claim_token=token,
                claim_expires=now + lease,
                attempts=int(row["attempts"]) + 1,
                updated_at=now,
                row_version=int(row["row_version"]) + 1,
            )
            return result

    def record_relay_operation_response(
        self,
        *,
        operation: str,
        device_id: str,
        response: Mapping[str, Any],
        claim_token: str = "",
        request_digest: str = "",
        relay_generation: int | None = None,
        keep_claim: bool = False,
    ) -> bool:
        normalized_operation = _relay_operation_name(operation)
        normalized_device = _identifier(device_id, "device_id")
        conditions = ["operation IN (?, ?)", "device_id=?", "terminal=0"]
        values: list[Any] = [normalized_operation, "device_revoke", normalized_device]
        if claim_token:
            conditions.append("claim_token=?")
            values.append(_required_text(claim_token, "claim_token", 180))
        if request_digest:
            conditions.append("request_digest=?")
            values.append(_required_text(request_digest, "request_digest", 64))
        if relay_generation is not None:
            conditions.append("relay_generation=?")
            values.append(max(0, int(relay_generation)))
        with self._connect() as connection:
            claim_update = "" if keep_claim else "claim_token='', claim_expires=0,"
            cursor = connection.execute(
                "UPDATE pending_relay_operations SET response_json=?, updated_at=?, "
                + claim_update + " next_attempt_at=0, row_version=row_version+1 "
                "WHERE " + " AND ".join(conditions),
                (_json(response), int(time.time()), *values),
            )
            return cursor.rowcount == 1

    def defer_relay_operation(
        self,
        *,
        operation: str,
        device_id: str,
        claim_token: str,
        request_digest: str,
        delay_seconds: int,
        failure: str,
        terminal: bool = False,
    ) -> bool:
        conditions = ["operation IN (?, ?)", "device_id=?", "claim_token=?", "request_digest=?", "terminal=0"]
        values: list[Any] = [
            _relay_operation_name(operation),
            "device_revoke",
            _identifier(device_id, "device_id"),
            _required_text(claim_token, "claim_token", 180),
            _required_text(request_digest, "request_digest", 64),
        ]
        now = int(time.time())
        with self._connect() as connection:
            row = connection.execute(
                "SELECT attempts FROM pending_relay_operations WHERE " + " AND ".join(conditions),
                tuple(values),
            ).fetchone()
            if row is None:
                return False
            exhausted = terminal or int(row["attempts"]) >= _MAX_RELAY_AUTOMATIC_ATTEMPTS
            cursor = connection.execute(
                "UPDATE pending_relay_operations SET next_attempt_at=?, last_error=?, terminal=?, "
                "claim_token='', claim_expires=0, updated_at=?, row_version=row_version+1 WHERE "
                + " AND ".join(conditions),
                (0 if exhausted else now + max(1, int(delay_seconds)), _text(failure, 500), int(exhausted), now, *values),
            )
            return cursor.rowcount == 1

    def relay_operation_claim_active(
        self,
        operation: str,
        device_id: str,
        *,
        claim_token: str,
        request_digest: str,
        relay_generation: int,
    ) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM pending_relay_operations WHERE operation IN (?, ?) "
                "AND device_id=? AND terminal=0 AND claim_token=? AND request_digest=? "
                "AND relay_generation=? LIMIT 1",
                (
                    _relay_operation_name(operation), "device_revoke",
                    _identifier(device_id, "device_id"),
                    _required_text(claim_token, "claim_token", 180),
                    _required_text(request_digest, "request_digest", 64),
                    max(0, int(relay_generation)),
                ),
            ).fetchone()
        return row is not None

    def quarantine_relay_operation(
        self,
        operation: str,
        device_id: str,
        *,
        error: str,
        claim_token: str = "",
        request_digest: str = "",
        relay_generation: int | None = None,
    ) -> bool:
        clauses = ["operation IN (?, ?)", "device_id=?", "terminal=0"]
        values: list[Any] = [_relay_operation_name(operation), "device_revoke", _identifier(device_id, "device_id")]
        if claim_token:
            clauses.append("claim_token=?")
            values.append(_required_text(claim_token, "claim_token", 180))
        if request_digest:
            clauses.append("request_digest=?")
            values.append(_required_text(request_digest, "request_digest", 64))
        if relay_generation is not None:
            clauses.append("relay_generation=?")
            values.append(max(0, int(relay_generation)))
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE pending_relay_operations SET terminal=1, last_error=?, "
                "claim_token='', claim_expires=0, next_attempt_at=0, updated_at=?, row_version=row_version+1 "
                "WHERE " + " AND ".join(clauses),
                (_text(error, 500), int(time.time()), *values),
            )
            return cursor.rowcount == 1

    def reset_relay_operation(
        self, operation: str, device_id: str, *, request_digest: str
    ) -> bool:
        now = int(time.time())
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE pending_relay_operations SET terminal=0, last_error='', response_json='', "
                "attempts=0, next_attempt_at=?, claim_token='', claim_expires=0, updated_at=?, "
                "row_version=row_version+1 WHERE operation IN (?, ?) AND device_id=? "
                "AND request_digest=? AND terminal=1 AND (claim_token='' OR claim_expires<=?)",
                (now, now, _relay_operation_name(operation), "device_revoke",
                 _identifier(device_id, "device_id"), _required_text(request_digest, "request_digest", 64), now),
            )
            return cursor.rowcount == 1

    def claim_terminal_provider_conflict_registrations(self, *, limit: int = 10) -> list[dict[str, Any]]:
        bounded = min(10, max(1, int(limit)))
        now = int(time.time())
        claimed: list[dict[str, Any]] = []
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            generation = self._metadata_integer(connection, "relay_config_generation", 0)
            rows = connection.execute(
                "SELECT * FROM pending_relay_operations WHERE operation='register_device' "
                "AND terminal=1 AND response_json<>'' AND last_error=? AND relay_generation=? "
                "AND (claim_token='' OR claim_expires<=?) ORDER BY updated_at LIMIT ?",
                (_LEGACY_RELAY_PROVIDER_CONFLICT, generation, now, bounded),
            ).fetchall()
            for row in rows:
                token = str(uuid.uuid4())
                cursor = connection.execute(
                    "UPDATE pending_relay_operations SET claim_token=?, claim_expires=?, updated_at=?, "
                    "row_version=row_version+1 WHERE operation='register_device' AND device_id=? "
                    "AND row_version=? AND terminal=1 AND response_json<>'' AND last_error=? "
                    "AND relay_generation=? AND (claim_token='' OR claim_expires<=?)",
                    (
                        token, now + _CLAIM_LEASE_SECONDS, now, row["device_id"], row["row_version"],
                        _LEGACY_RELAY_PROVIDER_CONFLICT, generation, now,
                    ),
                )
                if cursor.rowcount == 1:
                    claimed_row = dict(row)
                    claimed_row.update(
                        claim_token=token,
                        claim_expires=now + _CLAIM_LEASE_SECONDS,
                        updated_at=now,
                        row_version=int(row["row_version"]) + 1,
                    )
                    claimed.append(claimed_row)
        return claimed

    def release_terminal_provider_conflict_registration(
        self, *, device_id: str, claim_token: str, request_digest: str, relay_generation: int
    ) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE pending_relay_operations SET claim_token='', claim_expires=0, updated_at=?, "
                "row_version=row_version+1 WHERE operation='register_device' AND device_id=? "
                "AND terminal=1 AND response_json<>'' AND last_error=? AND claim_token=? "
                "AND request_digest=? AND relay_generation=?",
                (
                    int(time.time()), _identifier(device_id, "device_id"),
                    _LEGACY_RELAY_PROVIDER_CONFLICT, _required_text(claim_token, "claim_token", 180),
                    _required_text(request_digest, "request_digest", 64), max(0, int(relay_generation)),
                ),
            )
            return cursor.rowcount == 1

    def pending_relay_operation(self, operation: str, device_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM pending_relay_operations WHERE operation IN (?, ?) AND device_id=? "
                "ORDER BY CASE operation WHEN 'revoke_device' THEN 0 ELSE 1 END LIMIT 1",
                (_relay_operation_name(operation), "device_revoke", _identifier(device_id, "device_id")),
            ).fetchone()
        return None if row is None else dict(row)

    def pending_relay_operations(self, *, limit: int = 100) -> list[dict[str, Any]]:
        bounded = min(1000, max(1, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM pending_relay_operations WHERE terminal=0 ORDER BY updated_at LIMIT ?",
                (bounded,),
            ).fetchall()
        return [dict(row) for row in rows]

    def clear_pending_relay_operation(
        self,
        operation: str,
        device_id: str,
        *,
        claim_token: str = "",
        request_digest: str = "",
        relay_generation: int | None = None,
    ) -> bool:
        clauses = ["operation IN (?, ?)", "device_id=?"]
        values: list[Any] = [_relay_operation_name(operation), "device_revoke", _identifier(device_id, "device_id")]
        if claim_token:
            clauses.append("claim_token=?")
            values.append(_required_text(claim_token, "claim_token", 180))
        if request_digest:
            clauses.append("request_digest=?")
            values.append(_required_text(request_digest, "request_digest", 64))
        if relay_generation is not None:
            clauses.append("relay_generation=?")
            values.append(max(0, int(relay_generation)))
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM pending_relay_operations WHERE " + " AND ".join(clauses),
                tuple(values),
            )
            return cursor.rowcount == 1

    def admit_relay_delivery(
        self,
        *,
        event_id: str,
        device_id: str,
        delivery_id: str,
        status: str = "queued",
        failure: str = "",
        target_revision: int,
        target_generation: int,
        target_key_id: str = "",
        target_sender_key_id: str = "",
        relay_request_body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Insert a relay delivery once and return its authoritative row.

        Admission is deliberately separate from the general delivery ledger
        upsert: concurrent processes may have already prepared different
        ciphertext, but only the first transaction may establish the frozen
        request and coordinates.  A later caller must claim and use this row
        rather than overwrite it or reset another caller's lease.
        """
        normalized_body = "" if relay_request_body is None else _json(relay_request_body)
        normalized_event = _identifier(event_id, "event_id")
        normalized_device = _identifier(device_id, "device_id")
        normalized_status = _delivery_status(status)
        now = int(time.time())
        normalized_revision = max(0, int(target_revision))
        normalized_generation = max(0, int(target_generation))
        normalized_delivery = _text(delivery_id, 180)
        normalized_key = _text(target_key_id, 64)
        normalized_sender = _text(target_sender_key_id, 64)
        normalized_failure = _text(failure, 500)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO event_deliveries (
                    event_id, device_id, provider, status, attempts, delivery_id,
                    failure, created_at, updated_at, target_revision, target_key_id,
                    target_generation, target_sender_key_id, relay_request_body_json
                ) VALUES (?, ?, 'relay', ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id, device_id) DO NOTHING
                """,
                (
                    normalized_event,
                    normalized_device,
                    normalized_status,
                    normalized_delivery,
                    normalized_failure,
                    now,
                    now,
                    normalized_revision,
                    normalized_key,
                    normalized_generation,
                    normalized_sender,
                    normalized_body,
                ),
            )
            row = connection.execute(
                "SELECT * FROM event_deliveries WHERE event_id=? AND device_id=?",
                (normalized_event, normalized_device),
            ).fetchone()
            if row is not None and str(row["status"]) == "queued":
                ownership_changed = (
                    int(row["target_revision"] or 0) != normalized_revision
                    or int(row["target_generation"] or 0) != normalized_generation
                )
                claim_free = not str(row["claim_token"] or "") or int(row["claim_expires"] or 0) <= now
                if ownership_changed and claim_free:
                    connection.execute(
                        "UPDATE event_deliveries SET delivery_id=?, failure=?, updated_at=?, "
                        "target_revision=?, target_key_id=?, target_generation=?, "
                        "target_sender_key_id=?, relay_request_body_json=?, claim_token='', claim_expires=0 "
                        "WHERE event_id=? AND device_id=? AND status='queued' "
                        "AND (claim_token='' OR claim_expires<=?)",
                        (
                            normalized_delivery,
                            normalized_failure,
                            now,
                            normalized_revision,
                            normalized_key,
                            normalized_generation,
                            normalized_sender,
                            normalized_body,
                            normalized_event,
                            normalized_device,
                            now,
                        ),
                    )
                    row = connection.execute(
                        "SELECT * FROM event_deliveries WHERE event_id=? AND device_id=?",
                        (normalized_event, normalized_device),
                    ).fetchone()
        if row is None:
            raise ValueError("Relay delivery admission failed")
        return dict(row)

    def record_device_delivery(
        self,
        *,
        event_id: str,
        device_id: str,
        provider: str,
        status: str,
        delivery_id: str = "",
        failure: str = "",
        target_revision: int = 0,
        target_generation: int = 0,
        target_key_id: str = "",
        target_sender_key_id: str = "",
        relay_request_body: Mapping[str, Any] | None = None,
    ) -> None:
        now = int(time.time())
        normalized_relay_body = "" if relay_request_body is None else _json(relay_request_body)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO event_deliveries (
                    event_id, device_id, provider, status, attempts, delivery_id,
                    failure, created_at, updated_at, target_revision, target_key_id,
                    target_generation, target_sender_key_id, relay_request_body_json
                ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id, device_id) DO UPDATE SET
                    provider=excluded.provider,
                    status=excluded.status,
                    attempts=event_deliveries.attempts + 1,
                    delivery_id=excluded.delivery_id,
                    failure=excluded.failure,
                    updated_at=excluded.updated_at,
                    target_generation=CASE
                        WHEN event_deliveries.target_generation != excluded.target_generation
                        THEN excluded.target_generation
                        WHEN event_deliveries.target_generation=0 THEN excluded.target_generation
                        ELSE event_deliveries.target_generation
                    END,
                    target_revision=CASE
                        WHEN event_deliveries.target_generation != excluded.target_generation
                          OR event_deliveries.target_revision != excluded.target_revision
                        THEN excluded.target_revision
                        WHEN event_deliveries.target_revision=0 THEN excluded.target_revision
                        ELSE event_deliveries.target_revision
                    END,
                    target_key_id=CASE
                        WHEN event_deliveries.target_generation != excluded.target_generation
                          OR event_deliveries.target_revision != excluded.target_revision
                        THEN excluded.target_key_id
                        WHEN event_deliveries.target_key_id='' THEN excluded.target_key_id
                        ELSE event_deliveries.target_key_id
                    END,
                    target_sender_key_id=CASE
                        WHEN event_deliveries.target_generation != excluded.target_generation
                          OR event_deliveries.target_revision != excluded.target_revision
                        THEN excluded.target_sender_key_id
                        WHEN event_deliveries.target_sender_key_id='' THEN excluded.target_sender_key_id
                        ELSE event_deliveries.target_sender_key_id
                    END,
                    relay_request_body_json=CASE
                        WHEN event_deliveries.target_generation != excluded.target_generation
                          OR event_deliveries.target_revision != excluded.target_revision
                        THEN excluded.relay_request_body_json
                        WHEN excluded.relay_request_body_json='' THEN event_deliveries.relay_request_body_json
                        ELSE excluded.relay_request_body_json
                    END,
                    next_attempt_at=0,
                    claim_token='',
                    claim_expires=0
                """,
                (
                    _identifier(event_id, "event_id"),
                    _identifier(device_id, "device_id"),
                    _device_provider(provider),
                    _delivery_status(status),
                    _text(delivery_id, 180),
                    _text(failure, 500),
                    now,
                    now,
                    max(0, int(target_revision)),
                    _text(target_key_id, 64),
                    max(0, int(target_generation)),
                    _text(target_sender_key_id, 64),
                    normalized_relay_body,
                ),
            )

    def claim_relay_delivery(
        self,
        *,
        event_id: str,
        device_id: str,
        lease_seconds: int = _CLAIM_LEASE_SECONDS,
        ignore_due: bool = False,
    ) -> dict[str, Any] | None:
        now = int(time.time())
        token = str(uuid.uuid4())
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE event_deliveries SET claim_token=?, claim_expires=?, attempts=attempts+1, "
                "updated_at=? WHERE event_id=? AND device_id=? AND provider='relay' AND status='queued' "
                "AND (?=1 OR next_attempt_at<=?) AND (claim_token='' OR claim_expires<=?)",
                (
                    token, now + max(5, int(lease_seconds)), now,
                    _identifier(event_id, "event_id"), _identifier(device_id, "device_id"),
                    1 if ignore_due else 0, now, now,
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = connection.execute(
                "SELECT * FROM event_deliveries WHERE event_id=? AND device_id=?",
                (_identifier(event_id, "event_id"), _identifier(device_id, "device_id")),
            ).fetchone()
        return None if row is None else dict(row)

    def finalize_relay_delivery(
        self,
        *,
        event_id: str,
        device_id: str,
        claim_token: str,
        status: str,
        delivery_id: str = "",
        failure: str = "",
        next_attempt_at: int = 0,
        expected_target_revision: int | None = None,
        expected_target_generation: int | None = None,
    ) -> bool:
        normalized_status = _delivery_status(status)
        if normalized_status not in {"queued", "sent", "failed"}:
            raise ValueError("Invalid relay delivery final status")
        now = int(time.time())
        with self._connect() as connection:
            clauses = [
                "event_id=?", "device_id=?", "provider='relay'", "status='queued'", "claim_token=?"
            ]
            where_values: list[Any] = [
                _identifier(event_id, "event_id"), _identifier(device_id, "device_id"),
                _required_text(claim_token, "claim_token", 180),
            ]
            if expected_target_revision is not None:
                clauses.append("target_revision=?")
                where_values.append(max(0, int(expected_target_revision)))
            if expected_target_generation is not None:
                clauses.append("target_generation=?")
                where_values.append(max(0, int(expected_target_generation)))
            current = connection.execute(
                "SELECT attempts FROM event_deliveries WHERE " + " AND ".join(clauses),
                tuple(where_values),
            ).fetchone()
            if current is None:
                return False
            if normalized_status == "queued" and int(current["attempts"]) >= _MAX_RELAY_AUTOMATIC_ATTEMPTS:
                normalized_status = "failed"
                failure = failure or "relay_retry_exhausted"
            terminal = normalized_status != "queued"
            cursor = connection.execute(
                "UPDATE event_deliveries SET status=?, "
                "delivery_id=CASE WHEN ?='' THEN delivery_id ELSE ? END, failure=?, updated_at=?, "
                "next_attempt_at=?, claim_token='', claim_expires=0, "
                "relay_request_body_json=CASE WHEN ? THEN '' ELSE relay_request_body_json END "
                "WHERE " + " AND ".join(clauses),
                (
                    normalized_status, _text(delivery_id, 180), _text(delivery_id, 180),
                    _text(failure, 500), now,
                    0 if terminal else max(now + 1, int(next_attempt_at)), terminal,
                    *where_values,
                ),
            )
            return cursor.rowcount == 1

    def list_event_deliveries(self, event_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM event_deliveries WHERE event_id=? ORDER BY device_id",
                (_identifier(event_id, "event_id"),),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_provider_receipt(
        self,
        *,
        receipt_id: str,
        event_id: str,
        device_id: str,
        provider: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO provider_receipts (
                    receipt_id, event_id, device_id, provider, status,
                    created_at, checked_at, error
                ) VALUES (?, ?, ?, ?, 'pending', ?, NULL, '')
                """,
                (
                    _identifier(receipt_id, "receipt_id"),
                    _identifier(event_id, "event_id"),
                    _identifier(device_id, "device_id"),
                    _device_provider(provider),
                    int(time.time()),
                ),
            )

    def pending_provider_receipts(
        self,
        provider: str,
        *,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        bounded = min(1000, max(1, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM provider_receipts "
                "WHERE provider=? AND status='pending' ORDER BY created_at LIMIT ?",
                (_device_provider(provider), bounded),
            ).fetchall()
        return [dict(row) for row in rows]

    def complete_provider_receipt(
        self,
        receipt_id: str,
        *,
        status: str,
        error: str = "",
    ) -> bool:
        normalized = str(status or "").strip().lower()
        if normalized not in {"delivered", "failed"}:
            raise ValueError("Provider receipt status must be delivered or failed")
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE provider_receipts SET status=?, checked_at=?, error=? "
                "WHERE receipt_id=? AND status='pending'",
                (
                    normalized,
                    int(time.time()),
                    _text(error, 500),
                    _identifier(receipt_id, "receipt_id"),
                ),
            )
            return cursor.rowcount == 1

    def create_approval(
        self,
        *,
        approval_id: str,
        request_digest: str,
        allowed_choices: Iterable[str],
        event_id: str,
        expires_at: int,
    ) -> None:
        choices = [str(choice) for choice in allowed_choices]
        if (
            not choices
            or len(choices) > 4
            or len(set(choices)) != len(choices)
            or not set(choices).issubset({"once", "session", "always", "deny"})
        ):
            raise ValueError("Loopdy approval choices are invalid")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO approvals (
                    approval_id, request_digest, allowed_choices_json, event_id,
                    status, choice, expires_at, created_at, responded_at
                ) VALUES (?, ?, ?, ?, 'pending', NULL, ?, ?, NULL)
                ON CONFLICT(approval_id) DO NOTHING
                """,
                (
                    _identifier(approval_id, "approval_id"),
                    _identifier(request_digest, "request_digest"),
                    _json(choices),
                    _identifier(event_id, "event_id"),
                    int(expires_at),
                    int(time.time()),
                ),
            )

    def respond_approval(self, approval_id: str, choice: str) -> bool:
        normalized = str(choice or "").strip().lower()
        if normalized not in {"once", "session", "always", "deny"}:
            raise ValueError("Loopdy approval response is invalid")
        now = int(time.time())
        with self._connect() as connection:
            row = connection.execute(
                "SELECT allowed_choices_json FROM approvals "
                "WHERE approval_id=? AND status='pending' AND expires_at>?",
                (str(approval_id), now),
            ).fetchone()
            if row is None:
                return False
            allowed = _load_json(row["allowed_choices_json"], [])
            if normalized not in allowed:
                raise ValueError("Approval choice was not offered by Hermes")
            cursor = connection.execute(
                "UPDATE approvals SET status='responded', choice=?, responded_at=? "
                "WHERE approval_id=? AND status='pending' AND expires_at>?",
                (normalized, now, str(approval_id), now),
            )
            return cursor.rowcount == 1

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        now = int(time.time())
        with self._connect() as connection:
            connection.execute(
                "UPDATE approvals SET status='expired' "
                "WHERE approval_id=? AND status='pending' AND expires_at<=?",
                (str(approval_id), now),
            )
            row = connection.execute(
                "SELECT * FROM approvals WHERE approval_id=?", (str(approval_id),)
            ).fetchone()
        if row is None:
            return None
        return {
            "approval_id": row["approval_id"],
            "request_digest": row["request_digest"],
            "allowed_choices": _load_json(row["allowed_choices_json"], []),
            "event_id": row["event_id"],
            "status": row["status"],
            "choice": row["choice"],
            "expires_at": row["expires_at"],
        }

    def create_form_request(
        self,
        *,
        request_id: str,
        profile: str,
        session_id: str,
        form_schema: Mapping[str, Any],
        content_hash: str,
        created_at: int,
        expires_at: int,
    ) -> None:
        request = _form_request_id(request_id)
        owner_profile = _required_text(profile, "profile", 80)
        owner_session = _required_text(session_id, "session_id", 180)
        schema_json = _json(dict(form_schema))
        if len(schema_json.encode("utf-8")) > 32_768:
            raise ValueError("Form schema exceeds the byte limit")
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO generative_ui_forms (
                    request_id, profile, session_id, form_schema_json, content_hash,
                    state, idempotency_key, request_digest, values_json,
                    response_json, created_at, expires_at, submitted_at, consumed_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', NULL, NULL, NULL, NULL, ?, ?, NULL, NULL)
                ON CONFLICT(request_id) DO NOTHING
                """,
                (
                    request,
                    owner_profile,
                    owner_session,
                    schema_json,
                    _content_hash(content_hash),
                    int(created_at),
                    int(expires_at),
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("Form request ID collision")

    def get_form_request(self, request_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM generative_ui_forms WHERE request_id=?",
                (_form_request_id(request_id),),
            ).fetchone()
        return _form_row(row) if row is not None else None

    def submit_form_request(
        self,
        *,
        request_id: str,
        profile: str,
        session_id: str,
        idempotency_key: str,
        values: Mapping[str, Any],
        now: int | None = None,
    ) -> dict[str, Any]:
        request = _form_request_id(request_id)
        key = _idempotency_key(idempotency_key)
        owner_profile = _required_text(profile, "profile", 80)
        owner_session = _required_text(session_id, "session_id", 180)
        values_json = _json(dict(values))
        if len(values_json.encode("utf-8")) > 8_192:
            return _form_response(request, key, "error", "payload_too_large")
        digest = hashlib.sha256(
            _json(
                {
                    "kind": "submit_form",
                    "owner": {"profile": owner_profile, "session_id": owner_session},
                    "request_id": request,
                    "values": dict(values),
                }
            ).encode("utf-8")
        ).hexdigest()
        current = int(time.time()) if now is None else int(now)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM generative_ui_forms WHERE request_id=?", (request,)
            ).fetchone()
            if row is None:
                return _form_response(request, key, "error", "request_not_found")
            if not _same_owner(row, owner_profile, owner_session):
                return _form_response(request, key, "error", "owner_mismatch")
            if row["state"] == "pending" and int(row["expires_at"]) <= current:
                connection.execute(
                    "UPDATE generative_ui_forms SET state='expired' WHERE request_id=? AND state='pending'",
                    (request,),
                )
                return _form_response(request, key, "error", "request_expired")
            stored_key = str(row["idempotency_key"] or "")
            stored_digest = str(row["request_digest"] or "")
            if stored_key and hmac.compare_digest(stored_key, key):
                if hmac.compare_digest(stored_digest, digest):
                    replay = _load_json(row["response_json"], None)
                    return replay if isinstance(replay, dict) else _form_response(request, key, "success", "accepted")
                return _form_response(request, key, "error", "idempotency_conflict")
            if row["state"] == "submitted":
                return _form_response(request, key, "error", "already_submitted")
            if row["state"] == "consumed":
                return _form_response(request, key, "error", "already_consumed")
            if row["state"] == "expired":
                return _form_response(request, key, "error", "request_expired")
            response = _form_response(request, key, "success", "accepted")
            cursor = connection.execute(
                """
                UPDATE generative_ui_forms
                SET state='submitted', idempotency_key=?, request_digest=?, values_json=?,
                    response_json=?, submitted_at=?
                WHERE request_id=? AND state='pending' AND expires_at>?
                """,
                (key, digest, values_json, _json(response), current, request, current),
            )
            if cursor.rowcount != 1:
                return _form_response(request, key, "error", "already_submitted")
            return response

    def consume_form_response(
        self,
        *,
        request_id: str,
        profile: str,
        session_id: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        request = _form_request_id(request_id)
        owner_profile = _required_text(profile, "profile", 80)
        owner_session = _required_text(session_id, "session_id", 180)
        current = int(time.time()) if now is None else int(now)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM generative_ui_forms WHERE request_id=?", (request,)
            ).fetchone()
            if row is None:
                return _form_response(request, "", "error", "request_not_found")
            if not _same_owner(row, owner_profile, owner_session):
                return _form_response(request, "", "error", "owner_mismatch")
            if row["state"] == "pending" and int(row["expires_at"]) <= current:
                connection.execute(
                    "UPDATE generative_ui_forms SET state='expired' WHERE request_id=? AND state='pending'",
                    (request,),
                )
                return _form_response(request, "", "error", "request_expired")
            if row["state"] == "pending":
                return _form_response(request, "", "pending", "accepted")
            if row["state"] == "expired":
                return _form_response(request, "", "error", "request_expired")
            if row["state"] == "consumed":
                return _form_response(request, str(row["idempotency_key"] or ""), "error", "already_consumed")
            values = _load_json(row["values_json"], None)
            if not isinstance(values, dict):
                return _form_response(request, str(row["idempotency_key"] or ""), "error", "internal_error")
            cursor = connection.execute(
                """
                UPDATE generative_ui_forms
                SET state='consumed', values_json=NULL, consumed_at=?
                WHERE request_id=? AND state='submitted'
                """,
                (current, request),
            )
            if cursor.rowcount != 1:
                return _form_response(request, str(row["idempotency_key"] or ""), "error", "already_consumed")
            return {
                **_form_response(request, str(row["idempotency_key"] or ""), "success", "accepted"),
                "values": values,
            }

    def form_request_status(
        self,
        request_id: str,
        *,
        profile: str,
        session_id: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        request = _form_request_id(request_id)
        current = int(time.time()) if now is None else int(now)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM generative_ui_forms WHERE request_id=?", (request,)
            ).fetchone()
            if row is None:
                return _form_response(request, "", "error", "request_not_found")
            if not _same_owner(row, str(profile), str(session_id)):
                return _form_response(request, "", "error", "owner_mismatch")
            if row["state"] == "pending" and int(row["expires_at"]) <= current:
                connection.execute(
                    "UPDATE generative_ui_forms SET state='expired' WHERE request_id=? AND state='pending'",
                    (request,),
                )
                return _form_response(request, "", "error", "request_expired")
            code = {
                "pending": "accepted",
                "submitted": "accepted",
                "consumed": "already_consumed",
                "expired": "request_expired",
            }[row["state"]]
            state = "pending" if row["state"] == "pending" else ("success" if row["state"] == "submitted" else "error")
            return _form_response(request, str(row["idempotency_key"] or ""), state, code)

    def record_event(self, event: LoopdyEvent, *, target: str = "all") -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO events (
                    event_id, type, status, target, profile, session_id, job_id, task_id,
                    approval_id, delegation_id, detail_json, push_json, created_at
                ) VALUES (?, ?, 'queued', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.type,
                    target,
                    event.profile,
                    event.session_id,
                    event.job_id,
                    event.task_id,
                    event.approval_id,
                    event.delegation_id,
                    _json(dict(event.detail)),
                    _json(event.push_payload),
                    int(time.time()),
                ),
            )
            return cursor.rowcount == 1

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM events WHERE event_id=?", (str(event_id),)
            ).fetchone()
        return _event_row(row) if row is not None else None

    def mark_event_delivered(self, event_id: str, delivery_id: str = "") -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE events SET status='sent', delivered_at=?, delivery_id=?, failure=NULL "
                "WHERE event_id=?",
                (int(time.time()), _text(delivery_id, 180), str(event_id)),
            )
            return cursor.rowcount == 1

    def mark_event_prompted(self, event_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE events SET status='prompted', failure=NULL "
                "WHERE event_id=? AND status='queued'",
                (str(event_id),),
            )
            return cursor.rowcount == 1

    def mark_event_pending(self, event_id: str, delivery_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE events SET status='pending', delivery_id=?, failure=NULL "
                "WHERE event_id=?",
                (_text(delivery_id, 180), str(event_id)),
            )
            return cursor.rowcount == 1

    def mark_event_failed(self, event_id: str, failure: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE events SET status='failed', failure=? WHERE event_id=?",
                (_text(failure, 500), str(event_id)),
            )
            return cursor.rowcount == 1

    def list_events(self, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        bounded = min(200, max(1, int(limit)))
        bounded_offset = max(0, int(offset))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM events WHERE dismissed_at IS NULL "
                "ORDER BY (pinned_at IS NOT NULL) DESC, pinned_at DESC, "
                "created_at DESC, rowid DESC LIMIT ? OFFSET ?",
                (bounded, bounded_offset),
            ).fetchall()
        return [_event_row(row) for row in rows]

    def set_event_state(
        self,
        event_id: str,
        *,
        is_read: bool,
        is_pinned: bool,
        changed_at: int | None = None,
    ) -> bool:
        changed = int(time.time()) if changed_at is None else int(changed_at)
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE events SET "
                "read_at=CASE WHEN ? THEN COALESCE(read_at, ?) ELSE NULL END, "
                "pinned_at=CASE WHEN ? THEN COALESCE(pinned_at, ?) ELSE NULL END "
                "WHERE event_id=? AND dismissed_at IS NULL",
                (bool(is_read), changed, bool(is_pinned), changed, str(event_id)),
            )
            return cursor.rowcount == 1

    def dismiss_event(self, event_id: str, *, dismissed_at: int | None = None) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE events SET dismissed_at=COALESCE(dismissed_at, ?) WHERE event_id=?",
                (
                    int(time.time()) if dismissed_at is None else int(dismissed_at),
                    str(event_id),
                ),
            )
            return cursor.rowcount == 1

    def dismiss_events(
        self,
        *,
        event_ids: Iterable[str] = (),
        event_types: Iterable[str] = (),
        created_before: int | None = None,
        dismissed_at: int | None = None,
    ) -> int:
        ids = tuple(dict.fromkeys(_text(value, 220) for value in event_ids if _text(value, 220)))
        types = tuple(dict.fromkeys(_text(value, 80) for value in event_types if _text(value, 80)))
        if bool(ids) == bool(types):
            raise ValueError("Choose event_ids or event_types")
        values: list[Any] = [
            int(time.time()) if dismissed_at is None else int(dismissed_at)
        ]
        if ids:
            selector = "event_id IN ({})".format(",".join("?" for _ in ids))
            values.extend(ids)
        else:
            selector = "type IN ({})".format(",".join("?" for _ in types))
            values.extend(types)
        cutoff = ""
        if created_before is not None:
            cutoff = " AND created_at<=?"
            values.append(int(created_before))
        with self._connect() as connection:
            cursor = connection.execute(
                f"UPDATE events SET dismissed_at=? WHERE dismissed_at IS NULL "
                f"AND {selector}{cutoff}",
                tuple(values),
            )
            return cursor.rowcount

    def dismiss_attention_request(
        self,
        request_id: str,
        *,
        session_id: str = "",
        dismissed_at: int | None = None,
    ) -> int:
        request = _text(request_id, 180)
        session = _text(session_id, 180)
        if not request:
            return 0
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event_id, detail_json FROM events WHERE type='attention.required' "
                "AND dismissed_at IS NULL AND (?='' OR session_id=?)",
                (session, session),
            ).fetchall()
            event_ids = [
                str(row["event_id"])
                for row in rows
                if _text(_load_json(row["detail_json"], {}).get("request_id"), 180)
                == request
            ]
            return self._dismiss_event_ids(
                connection,
                event_ids,
                dismissed_at=dismissed_at,
            )

    def dismiss_attention_for_session(
        self,
        session_id: str,
        *,
        dismissed_at: int | None = None,
    ) -> int:
        session = _text(session_id, 180)
        if not session:
            return 0
        dismissed = int(time.time()) if dismissed_at is None else int(dismissed_at)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event_id, detail_json FROM events "
                "WHERE type='attention.required' AND dismissed_at IS NULL "
                "AND session_id=?",
                (session,),
            ).fetchall()
            event_ids = []
            for row in rows:
                detail = _load_json(row["detail_json"], {})
                expiry = _text(detail.get("expires_at"), 64)
                is_expired_clarify = (
                    _text(detail.get("kind"), 80) == "clarify"
                    and expiry.isdigit()
                    and int(expiry) <= dismissed
                )
                if not is_expired_clarify:
                    event_ids.append(str(row["event_id"]))
            return self._dismiss_event_ids(
                connection,
                event_ids,
                dismissed_at=dismissed,
            )

    def dismiss_expired_attention(
        self,
        created_before: int,
        *,
        dismissed_at: int | None = None,
    ) -> int:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event_id, detail_json FROM events "
                "WHERE type='attention.required' AND dismissed_at IS NULL "
                "AND created_at<=?",
                (int(created_before),),
            ).fetchall()
            event_ids = [
                str(row["event_id"])
                for row in rows
                if _text(_load_json(row["detail_json"], {}).get("kind"), 80)
                != "clarify"
            ]
            return self._dismiss_event_ids(
                connection,
                event_ids,
                dismissed_at=dismissed_at,
            )

    def dismiss_inactive_approval_events(
        self,
        *,
        now: int | None = None,
        dismissed_at: int | None = None,
    ) -> int:
        current = int(time.time()) if now is None else int(now)
        dismissed = current if dismissed_at is None else int(dismissed_at)
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE events SET dismissed_at=? WHERE type='approval.required' "
                "AND dismissed_at IS NULL AND approval_id<>'' AND EXISTS ("
                "SELECT 1 FROM approvals WHERE approvals.approval_id=events.approval_id "
                "AND (approvals.status<>'pending' OR approvals.expires_at<=?))",
                (dismissed, current),
            )
            return cursor.rowcount

    def dismiss_gateway_lifecycle_events(
        self,
        *,
        dismissed_at: int | None = None,
    ) -> int:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event_id, detail_json FROM events WHERE type='channel.message' "
                "AND dismissed_at IS NULL"
            ).fetchall()
            event_ids = []
            for row in rows:
                detail = _load_json(row["detail_json"], {})
                message = str(detail.get("message") or "").strip()
                if any(message.startswith(prefix) for prefix in _GATEWAY_LIFECYCLE_PREFIXES):
                    event_ids.append(str(row["event_id"]))
            return self._dismiss_event_ids(
                connection,
                event_ids,
                dismissed_at=dismissed_at,
            )

    @staticmethod
    def _dismiss_event_ids(
        connection: sqlite3.Connection,
        event_ids: Iterable[str],
        *,
        dismissed_at: int | None = None,
    ) -> int:
        ids = tuple(dict.fromkeys(str(event_id) for event_id in event_ids if event_id))
        if not ids:
            return 0
        cursor = connection.execute(
            "UPDATE events SET dismissed_at=? WHERE dismissed_at IS NULL AND event_id IN ({})".format(
                ",".join("?" for _ in ids)
            ),
            (
                int(time.time()) if dismissed_at is None else int(dismissed_at),
                *ids,
            ),
        )
        return cursor.rowcount

    def queued_relay_events(self, *, limit: int = 100) -> list[dict[str, Any]]:
        bounded = min(1000, max(1, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT events.* FROM events WHERE EXISTS ("
                "SELECT 1 FROM event_deliveries WHERE event_deliveries.event_id=events.event_id "
                "AND provider='relay' AND status='queued' AND next_attempt_at<=? "
                "AND (claim_token='' OR claim_expires<=?)) "
                "ORDER BY events.created_at, events.rowid LIMIT ?",
                (int(time.time()), int(time.time()), bounded),
            ).fetchall()
        return [_event_row(row) for row in rows]

    def _ensure_schema(self) -> None:
        if self._initialized:
            return
        with self._init_lock:
            if self._initialized:
                return
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with self._connect(initialize=False) as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS turn_durations (
                        session_id TEXT NOT NULL,
                        turn_id TEXT NOT NULL,
                        final_timestamp REAL NOT NULL,
                        duration_ms INTEGER NOT NULL CHECK(duration_ms >= 0),
                        PRIMARY KEY (session_id, turn_id)
                    );
                    CREATE TABLE IF NOT EXISTS metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS devices (
                        device_id TEXT PRIMARY KEY,
                        endpoint_id TEXT NOT NULL UNIQUE,
                        provider TEXT NOT NULL DEFAULT 'managed',
                        token_environment TEXT NOT NULL DEFAULT 'production',
                        label TEXT NOT NULL,
                        groups_json TEXT NOT NULL,
                        preferences_json TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        revoked_at INTEGER,
                        recipient_public_key TEXT NOT NULL DEFAULT '',
                        recipient_key_id TEXT NOT NULL DEFAULT '',
                        revision INTEGER NOT NULL DEFAULT 0,
                        lease_expires INTEGER NOT NULL DEFAULT 0,
                        normalized_body_digest TEXT NOT NULL DEFAULT '',
                        sender_key_revision INTEGER NOT NULL DEFAULT 0,
                        acknowledged_sender_key_ids_json TEXT NOT NULL DEFAULT '[]',
                        sender_ack_body_digest TEXT NOT NULL DEFAULT '',
                        relay_generation INTEGER NOT NULL DEFAULT 0
                    );
                    CREATE TABLE IF NOT EXISTS events (
                        event_id TEXT PRIMARY KEY,
                        type TEXT NOT NULL,
                        status TEXT NOT NULL,
                        target TEXT NOT NULL,
                        profile TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        job_id TEXT NOT NULL,
                        task_id TEXT NOT NULL,
                        approval_id TEXT NOT NULL,
                        delegation_id TEXT NOT NULL,
                        detail_json TEXT NOT NULL,
                        push_json TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        delivered_at INTEGER,
                        delivery_id TEXT,
                        failure TEXT,
                        dismissed_at INTEGER,
                        read_at INTEGER,
                        pinned_at INTEGER
                    );
                    CREATE TABLE IF NOT EXISTS approvals (
                        approval_id TEXT PRIMARY KEY,
                        request_digest TEXT NOT NULL,
                        allowed_choices_json TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        choice TEXT,
                        expires_at INTEGER NOT NULL,
                        created_at INTEGER NOT NULL,
                        responded_at INTEGER
                    );
                    CREATE TABLE IF NOT EXISTS event_deliveries (
                        event_id TEXT NOT NULL,
                        device_id TEXT NOT NULL,
                        provider TEXT NOT NULL,
                        status TEXT NOT NULL,
                        attempts INTEGER NOT NULL,
                        delivery_id TEXT NOT NULL,
                        failure TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        target_revision INTEGER NOT NULL DEFAULT 0,
                        target_generation INTEGER NOT NULL DEFAULT 0,
                        target_key_id TEXT NOT NULL DEFAULT '',
                        target_sender_key_id TEXT NOT NULL DEFAULT '',
                        relay_request_body_json TEXT NOT NULL DEFAULT '',
                        next_attempt_at INTEGER NOT NULL DEFAULT 0,
                        claim_token TEXT NOT NULL DEFAULT '',
                        claim_expires INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (event_id, device_id)
                    );
                    CREATE TABLE IF NOT EXISTS provider_receipts (
                        receipt_id TEXT PRIMARY KEY,
                        event_id TEXT NOT NULL,
                        device_id TEXT NOT NULL,
                        provider TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        checked_at INTEGER,
                        error TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS live_activities (
                        activity_id TEXT PRIMARY KEY,
                        session_id TEXT NOT NULL,
                        live_session_id TEXT NOT NULL,
                        profile TEXT NOT NULL,
                        push_token TEXT NOT NULL,
                        token_environment TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        last_push_timestamp INTEGER NOT NULL DEFAULT 0,
                        owner_generation INTEGER NOT NULL DEFAULT 0,
                        ended_at INTEGER
                    );
                    CREATE INDEX IF NOT EXISTS live_activities_session_idx
                    ON live_activities(live_session_id, session_id, ended_at);
                    CREATE TABLE IF NOT EXISTS pending_live_activity_updates (
                        activity_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL,
                        detail TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        active_session_count INTEGER NOT NULL,
                        attempts INTEGER NOT NULL,
                        next_attempt_at INTEGER NOT NULL,
                        last_error TEXT NOT NULL,
                        updated_at INTEGER NOT NULL,
                        terminal INTEGER NOT NULL DEFAULT 0,
                        owner_session_id TEXT NOT NULL DEFAULT '',
                        owner_live_session_id TEXT NOT NULL DEFAULT '',
                        owner_profile TEXT NOT NULL DEFAULT '',
                        owner_push_token TEXT NOT NULL DEFAULT '',
                        owner_generation INTEGER NOT NULL DEFAULT 0,
                        request_id TEXT NOT NULL DEFAULT ''
                    );
                    CREATE INDEX IF NOT EXISTS pending_live_activity_updates_due_idx
                    ON pending_live_activity_updates(next_attempt_at);
                    CREATE TABLE IF NOT EXISTS pending_relay_live_activity_updates (
                        activity_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL,
                        detail TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        active_session_count INTEGER NOT NULL,
                        attempts INTEGER NOT NULL,
                        next_attempt_at INTEGER NOT NULL,
                        last_error TEXT NOT NULL,
                        updated_at INTEGER NOT NULL,
                        timestamp INTEGER NOT NULL DEFAULT 0,
                        delivery_id TEXT NOT NULL DEFAULT '',
                        idempotency_key TEXT NOT NULL DEFAULT '',
                        request_body_json TEXT NOT NULL DEFAULT '',
                        device_id TEXT NOT NULL DEFAULT '',
                        session_ref TEXT NOT NULL DEFAULT '',
                        revision INTEGER NOT NULL DEFAULT 0,
                        lease_expires INTEGER NOT NULL DEFAULT 0,
                        relay_generation INTEGER NOT NULL DEFAULT 0,
                        terminal INTEGER NOT NULL DEFAULT 0
                    );
                    CREATE INDEX IF NOT EXISTS pending_relay_live_activity_updates_due_idx
                    ON pending_relay_live_activity_updates(next_attempt_at);
                    CREATE TABLE IF NOT EXISTS pending_relay_operations (
                        operation TEXT NOT NULL,
                        device_id TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        idempotency_key TEXT NOT NULL,
                        body_json TEXT NOT NULL,
                        response_json TEXT NOT NULL DEFAULT '',
                        relay_generation INTEGER NOT NULL DEFAULT 0,
                        request_digest TEXT NOT NULL DEFAULT '',
                        attempts INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        next_attempt_at INTEGER NOT NULL DEFAULT 0,
                        claim_token TEXT NOT NULL DEFAULT '',
                        claim_expires INTEGER NOT NULL DEFAULT 0,
                        terminal INTEGER NOT NULL DEFAULT 0,
                        last_error TEXT NOT NULL DEFAULT '',
                        row_version INTEGER NOT NULL DEFAULT 1,
                        PRIMARY KEY (operation, device_id)
                    );
                    CREATE TABLE IF NOT EXISTS relay_live_activities (
                        activity_id TEXT PRIMARY KEY,
                        device_id TEXT NOT NULL,
                        session_ref TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        source_timestamp INTEGER NOT NULL,
                        lease_expires INTEGER NOT NULL,
                        normalized_body_digest TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        last_push_timestamp INTEGER NOT NULL DEFAULT 0,
                        ended_at INTEGER,
                        revoked_at INTEGER
                    );
                    CREATE TABLE IF NOT EXISTS generative_ui_forms (
                        request_id TEXT PRIMARY KEY,
                        profile TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        form_schema_json TEXT NOT NULL,
                        content_hash TEXT NOT NULL,
                        state TEXT NOT NULL,
                        idempotency_key TEXT,
                        request_digest TEXT,
                        values_json TEXT,
                        response_json TEXT,
                        created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        submitted_at INTEGER,
                        consumed_at INTEGER
                    );
                    CREATE INDEX IF NOT EXISTS generative_ui_forms_owner_idx
                    ON generative_ui_forms(profile, session_id, state, expires_at);
                    CREATE TABLE IF NOT EXISTS card_templates (
                        profile TEXT NOT NULL,
                        template_id TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        name TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        sha256 TEXT NOT NULL,
                        template_json TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        PRIMARY KEY (profile, template_id)
                    );
                    CREATE INDEX IF NOT EXISTS card_templates_profile_name_idx
                    ON card_templates(profile, name, template_id);
                    CREATE TABLE IF NOT EXISTS marketplace_skill_installs (
                        profile TEXT NOT NULL,
                        item_id TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        sha256 TEXT NOT NULL,
                        skill_name TEXT NOT NULL,
                        content_sha256 TEXT NOT NULL,
                        installed_content_sha256 TEXT,
                        verification_mode TEXT NOT NULL DEFAULT 'legacy_exact',
                        files_json TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        PRIMARY KEY (profile, item_id),
                        UNIQUE (profile, skill_name)
                    );
                    """
                )
                marketplace_columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(marketplace_skill_installs)"
                    ).fetchall()
                }
                if "installed_content_sha256" not in marketplace_columns:
                    connection.execute(
                        "ALTER TABLE marketplace_skill_installs "
                        "ADD COLUMN installed_content_sha256 TEXT"
                    )
                if "verification_mode" not in marketplace_columns:
                    connection.execute(
                        "ALTER TABLE marketplace_skill_installs ADD COLUMN verification_mode "
                        "TEXT NOT NULL DEFAULT 'legacy_exact'"
                    )
                event_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(events)").fetchall()
                }
                if "task_id" not in event_columns:
                    connection.execute(
                        "ALTER TABLE events ADD COLUMN task_id TEXT NOT NULL DEFAULT ''"
                    )
                if "dismissed_at" not in event_columns:
                    connection.execute(
                        "ALTER TABLE events ADD COLUMN dismissed_at INTEGER"
                    )
                if "read_at" not in event_columns:
                    connection.execute("ALTER TABLE events ADD COLUMN read_at INTEGER")
                if "pinned_at" not in event_columns:
                    connection.execute("ALTER TABLE events ADD COLUMN pinned_at INTEGER")
                device_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(devices)").fetchall()
                }
                migrated_legacy_devices = "provider" not in device_columns
                if "provider" not in device_columns:
                    connection.execute(
                        "ALTER TABLE devices ADD COLUMN provider TEXT NOT NULL "
                        "DEFAULT 'legacy_relay'"
                    )
                if "token_environment" not in device_columns:
                    connection.execute(
                        "ALTER TABLE devices ADD COLUMN token_environment TEXT NOT NULL DEFAULT ''"
                    )
                for column, declaration in (
                    ("recipient_public_key", "TEXT NOT NULL DEFAULT ''"),
                    ("recipient_key_id", "TEXT NOT NULL DEFAULT ''"),
                    ("revision", "INTEGER NOT NULL DEFAULT 0"),
                    ("lease_expires", "INTEGER NOT NULL DEFAULT 0"),
                    ("normalized_body_digest", "TEXT NOT NULL DEFAULT ''"),
                    ("sender_key_revision", "INTEGER NOT NULL DEFAULT 0"),
                    ("acknowledged_sender_key_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
                    ("sender_ack_body_digest", "TEXT NOT NULL DEFAULT ''"),
                    ("relay_generation", "INTEGER NOT NULL DEFAULT 0"),
                ):
                    if column not in device_columns:
                        connection.execute(
                            f"ALTER TABLE devices ADD COLUMN {column} {declaration}"
                        )
                if migrated_legacy_devices:
                    now = int(time.time())
                    connection.execute(
                        "UPDATE devices SET revoked_at=COALESCE(revoked_at, ?), updated_at=? "
                        "WHERE provider='legacy_relay'",
                        (now, now),
                    )
                live_activity_columns = {
                    row[1]
                    for row in connection.execute("PRAGMA table_info(live_activities)").fetchall()
                }
                if "last_push_timestamp" not in live_activity_columns:
                    connection.execute(
                        "ALTER TABLE live_activities ADD COLUMN "
                        "last_push_timestamp INTEGER NOT NULL DEFAULT 0"
                    )
                if "owner_generation" not in live_activity_columns:
                    connection.execute(
                        "ALTER TABLE live_activities ADD COLUMN "
                        "owner_generation INTEGER NOT NULL DEFAULT 0"
                    )
                relay_activity_columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(relay_live_activities)"
                    ).fetchall()
                }
                for column, declaration in (
                    ("last_push_timestamp", "INTEGER NOT NULL DEFAULT 0"),
                    ("ended_at", "INTEGER"),
                ):
                    if column not in relay_activity_columns:
                        connection.execute(
                            f"ALTER TABLE relay_live_activities ADD COLUMN {column} {declaration}"
                        )
                delivery_columns = {
                    row[1]
                    for row in connection.execute("PRAGMA table_info(event_deliveries)").fetchall()
                }
                for column, declaration in (
                    ("target_revision", "INTEGER NOT NULL DEFAULT 0"),
                    ("target_generation", "INTEGER NOT NULL DEFAULT 0"),
                    ("target_key_id", "TEXT NOT NULL DEFAULT ''"),
                    ("target_sender_key_id", "TEXT NOT NULL DEFAULT ''"),
                    ("relay_request_body_json", "TEXT NOT NULL DEFAULT ''"),
                    ("next_attempt_at", "INTEGER NOT NULL DEFAULT 0"),
                    ("claim_token", "TEXT NOT NULL DEFAULT ''"),
                    ("claim_expires", "INTEGER NOT NULL DEFAULT 0"),
                ):
                    if column not in delivery_columns:
                        connection.execute(
                            f"ALTER TABLE event_deliveries ADD COLUMN {column} {declaration}"
                        )
                connection.execute(
                    "DELETE FROM metadata WHERE key IN "
                    "('relay_url', 'credential', 'installation_id')"
                )
                relay_pending_columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(pending_relay_live_activity_updates)"
                    ).fetchall()
                }
                for column, declaration in (
                    ("timestamp", "INTEGER NOT NULL DEFAULT 0"),
                    ("delivery_id", "TEXT NOT NULL DEFAULT ''"),
                    ("idempotency_key", "TEXT NOT NULL DEFAULT ''"),
                    ("request_body_json", "TEXT NOT NULL DEFAULT ''"),
                    ("device_id", "TEXT NOT NULL DEFAULT ''"),
                    ("session_ref", "TEXT NOT NULL DEFAULT ''"),
                    ("revision", "INTEGER NOT NULL DEFAULT 0"),
                    ("lease_expires", "INTEGER NOT NULL DEFAULT 0"),
                    ("relay_generation", "INTEGER NOT NULL DEFAULT 0"),
                    ("terminal", "INTEGER NOT NULL DEFAULT 0"),
                ):
                    if column not in relay_pending_columns:
                        connection.execute(
                            f"ALTER TABLE pending_relay_live_activity_updates ADD COLUMN {column} {declaration}"
                        )
                direct_pending_columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(pending_live_activity_updates)"
                    ).fetchall()
                }
                for column, declaration in (
                    ("terminal", "INTEGER NOT NULL DEFAULT 0"),
                    ("owner_session_id", "TEXT NOT NULL DEFAULT ''"),
                    ("owner_live_session_id", "TEXT NOT NULL DEFAULT ''"),
                    ("owner_profile", "TEXT NOT NULL DEFAULT ''"),
                    ("owner_push_token", "TEXT NOT NULL DEFAULT ''"),
                    ("owner_generation", "INTEGER NOT NULL DEFAULT 0"),
                    ("request_id", "TEXT NOT NULL DEFAULT ''"),
                ):
                    if column not in direct_pending_columns:
                        connection.execute(
                            f"ALTER TABLE pending_live_activity_updates ADD COLUMN {column} {declaration}"
                        )
                # Existing direct rows predate owner/request CAS.  Rebind
                # only rows whose activity is still active; re-registration
                # already removes its old pending row before creating a new
                # owner, so this cannot revive stale work.
                connection.execute(
                    "UPDATE pending_live_activity_updates SET "
                    "owner_session_id=(SELECT session_id FROM live_activities WHERE live_activities.activity_id=pending_live_activity_updates.activity_id), "
                    "owner_live_session_id=(SELECT live_session_id FROM live_activities WHERE live_activities.activity_id=pending_live_activity_updates.activity_id), "
                    "owner_profile=(SELECT profile FROM live_activities WHERE live_activities.activity_id=pending_live_activity_updates.activity_id), "
                    "owner_push_token=(SELECT push_token FROM live_activities WHERE live_activities.activity_id=pending_live_activity_updates.activity_id) "
                    "WHERE owner_session_id='' AND EXISTS (SELECT 1 FROM live_activities "
                    "WHERE live_activities.activity_id=pending_live_activity_updates.activity_id "
                    "AND live_activities.ended_at IS NULL)"
                )
                connection.execute(
                    "UPDATE live_activities SET owner_generation=1 WHERE owner_generation=0"
                )
                connection.execute(
                    "UPDATE pending_live_activity_updates SET owner_generation=("
                    "SELECT owner_generation FROM live_activities "
                    "WHERE live_activities.activity_id=pending_live_activity_updates.activity_id"
                    ") WHERE owner_generation=0 AND EXISTS (SELECT 1 FROM live_activities "
                    "WHERE live_activities.activity_id=pending_live_activity_updates.activity_id)"
                )
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES ('schema_version', '8') "
                    "ON CONFLICT(key) DO UPDATE SET value='8'"
                )
                operation_columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(pending_relay_operations)"
                    ).fetchall()
                }
                for column, declaration in (
                    ("response_json", "TEXT NOT NULL DEFAULT ''"),
                    ("relay_generation", "INTEGER NOT NULL DEFAULT 0"),
                    ("request_digest", "TEXT NOT NULL DEFAULT ''"),
                    ("next_attempt_at", "INTEGER NOT NULL DEFAULT 0"),
                    ("claim_token", "TEXT NOT NULL DEFAULT ''"),
                    ("claim_expires", "INTEGER NOT NULL DEFAULT 0"),
                    ("terminal", "INTEGER NOT NULL DEFAULT 0"),
                    ("last_error", "TEXT NOT NULL DEFAULT ''"),
                    ("row_version", "INTEGER NOT NULL DEFAULT 1"),
                ):
                    if column not in operation_columns:
                        connection.execute(
                            f"ALTER TABLE pending_relay_operations ADD COLUMN {column} {declaration}"
                        )
                # Backfill the immutable request digest for valid legacy rows;
                # malformed rows remain quarantinable by the recovery owner.
                for legacy in connection.execute(
                    "SELECT operation, device_id, body_json FROM pending_relay_operations "
                    "WHERE request_digest=''"
                ).fetchall():
                    try:
                        parsed = json.loads(str(legacy["body_json"]))
                        digest = hashlib.sha256(_json(parsed).encode("utf-8")).hexdigest()
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                    connection.execute(
                        "UPDATE pending_relay_operations SET request_digest=? "
                        "WHERE operation=? AND device_id=? AND request_digest=''",
                        (digest, legacy["operation"], legacy["device_id"]),
                    )
                connection.execute(
                    "INSERT OR IGNORE INTO metadata(key, value) VALUES ('provider_mode', ?)",
                    ("managed" if migrated_legacy_devices else "relay",),
                )
                # v2.1 used both spellings for the device revoke route.  Keep
                # one durable key so aliases cannot create two operations.
                connection.execute(
                    "UPDATE pending_relay_operations SET operation='revoke_device' "
                    "WHERE operation='device_revoke' AND NOT EXISTS ("
                    "SELECT 1 FROM pending_relay_operations newer "
                    "WHERE newer.operation='revoke_device' "
                    "AND newer.device_id=pending_relay_operations.device_id)"
                )
                connection.execute(
                    "INSERT OR IGNORE INTO metadata(key, value) "
                    "VALUES ('relay_config_generation', '0')"
                )
                connection.execute(
                    "INSERT OR IGNORE INTO metadata(key, value) "
                    "VALUES ('relay_config_state', 'enabled')"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS pending_relay_operations_due_idx "
                    "ON pending_relay_operations(terminal, next_attempt_at, claim_expires)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS event_deliveries_relay_due_idx "
                    "ON event_deliveries(provider, status, next_attempt_at, claim_expires)"
                )
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
            self._initialized = True

    @contextmanager
    def _connect(self, *, initialize: bool = True):
        if initialize:
            self._ensure_schema()
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _metadata_integer(connection: sqlite3.Connection, key: str, default: int) -> int:
        row = connection.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        if row is None:
            return default
        try:
            value = int(row["value"])
        except (TypeError, ValueError):
            return default
        return max(0, value)

    @staticmethod
    def _assert_relay_generation(
        connection: sqlite3.Connection,
        expected: int | None,
        current: int,
    ) -> None:
        if expected is not None and int(expected) != current:
            raise ValueError("Relay configuration generation changed")


def _lock_file_descriptor(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                return
            except OSError as error:
                if error.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                    raise
                time.sleep(0.05)

    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_EX)


def _unlock_file_descriptor(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_UN)


def _event_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "event_id": row["event_id"],
        "type": row["type"],
        "status": row["status"],
        "target": row["target"],
        "profile": row["profile"],
        "session_id": row["session_id"] or None,
        "job_id": row["job_id"] or None,
        "task_id": row["task_id"] or None,
        "approval_id": row["approval_id"] or None,
        "delegation_id": row["delegation_id"] or None,
        "detail": _load_json(row["detail_json"], {}),
        "push": _load_json(row["push_json"], {}),
        "created_at": row["created_at"],
        "delivered_at": row["delivered_at"],
        "delivery_id": row["delivery_id"] or None,
        "failure": row["failure"],
        "dismissed_at": row["dismissed_at"],
        "is_read": row["read_at"] is not None,
        "is_pinned": row["pinned_at"] is not None,
    }


def _device_row(row: sqlite3.Row) -> dict[str, Any]:
    result = {
        "device_id": row["device_id"],
        "endpoint_id": row["endpoint_id"],
        "provider": row["provider"],
        "token_environment": row["token_environment"],
        "label": row["label"],
        "groups": _load_json(row["groups_json"], []),
        "preferences": _load_json(row["preferences_json"], {}),
        "revoked": row["revoked_at"] is not None,
    }
    if row["provider"] == "relay":
        result.update(
            {
                "recipient_public_key": row["recipient_public_key"],
                "recipient_key_id": row["recipient_key_id"],
                "revision": row["revision"],
                "lease_expires": row["lease_expires"],
                "sender_key_revision": row["sender_key_revision"],
                "relay_generation": row["relay_generation"],
                "acknowledged_sender_key_ids": _load_json(
                    row["acknowledged_sender_key_ids_json"], []
                ),
            }
        )
    return result


def _form_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "request_id": row["request_id"],
        "profile": row["profile"],
        "session_id": row["session_id"],
        "form_schema": _load_json(row["form_schema_json"], {}),
        "content_hash": row["content_hash"],
        "state": row["state"],
        "idempotency_key": row["idempotency_key"],
        "request_digest": row["request_digest"],
        "values": _load_json(row["values_json"], None),
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "submitted_at": row["submitted_at"],
        "consumed_at": row["consumed_at"],
    }


def _same_owner(row: sqlite3.Row, profile: str, session_id: str) -> bool:
    return hmac.compare_digest(str(row["profile"]), str(profile)) and hmac.compare_digest(
        str(row["session_id"]), str(session_id)
    )


def _form_request_id(value: Any) -> str:
    normalized = str(value or "").strip()
    if len(normalized) != 32 or any(character not in "0123456789abcdef" for character in normalized):
        raise ValueError("request_id must be 32 lowercase hexadecimal characters")
    return normalized


def _content_hash(value: Any) -> str:
    normalized = str(value or "").strip()
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        raise ValueError("content_hash must be 64 lowercase hexadecimal characters")
    return normalized


def _marketplace_verification_mode(value: Any) -> str:
    normalized = str(value or "").strip()
    if normalized not in {"legacy_exact", "hermes_hub"}:
        raise ValueError("Marketplace verification mode is invalid")
    return normalized


def _idempotency_key(value: Any) -> str:
    normalized = str(value or "").strip()
    try:
        parsed = uuid.UUID(normalized)
    except (ValueError, AttributeError) as error:
        raise ValueError("idempotency_key must be a lowercase UUID") from error
    if str(parsed) != normalized:
        raise ValueError("idempotency_key must be a lowercase UUID")
    return normalized


_FORM_MESSAGES = {
    "accepted": "Form response accepted.",
    "request_not_found": "Form request was not found.",
    "request_expired": "Form request has expired.",
    "owner_mismatch": "Form request belongs to another session.",
    "invalid_value": "One or more form values are invalid.",
    "already_submitted": "Form response was already submitted.",
    "already_consumed": "Form response was already consumed.",
    "idempotency_conflict": "Idempotency key was reused with different values.",
    "payload_too_large": "Form response exceeds the byte limit.",
    "internal_error": "Form response could not be processed.",
}


def _form_response(request_id: str, idempotency_key: str, state: str, code: str) -> dict[str, Any]:
    return {
        "schema": "loopdy.generative_ui.action_response",
        "version": 2,
        "request_id": request_id,
        "idempotency_key": idempotency_key,
        "state": state,
        "code": code,
        "message": _FORM_MESSAGES[code],
    }


def form_action_response(request_id: str, idempotency_key: str, state: str, code: str) -> dict[str, Any]:
    """Build a fixed public envelope without reflecting malformed identifiers."""
    try:
        safe_request_id = _form_request_id(request_id)
    except ValueError:
        safe_request_id = "0" * 32
    return _form_response(safe_request_id, str(idempotency_key or ""), state, code)


def _card_template(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("Card template must be an object")
    expected = {
        "id",
        "version",
        "name",
        "summary",
        "author",
        "license",
        "minimum_card_version",
        "parameters_schema",
        "document",
        "sha256",
    }
    if set(value) != expected:
        raise ValueError("Card template schema is invalid")
    normalized = json.loads(canonical_card_json(dict(value)))
    normalized["id"] = _card_template_id(normalized["id"])
    normalized["version"] = _positive_revision(normalized["version"])
    normalized["name"] = _required_text(normalized["name"], "name", 120)
    normalized["summary"] = _required_text(normalized["summary"], "summary", 1_000)
    normalized["author"] = _required_text(normalized["author"], "author", 120)
    normalized["license"] = _required_text(normalized["license"], "license", 120)
    if normalized["minimum_card_version"] != 1:
        raise ValueError("Card template minimum card version is unsupported")
    _card_template_parameters_schema(normalized["parameters_schema"])
    validate_card_input(normalized["document"], now=datetime.now(timezone.utc))
    supplied_hash = _card_template_hash(normalized["sha256"])
    expected_hash = hashlib.sha256(
        canonical_card_json(normalized["document"]).encode("utf-8")
    ).hexdigest()
    if not hmac.compare_digest(supplied_hash, expected_hash):
        raise ValueError("Card template hash does not match its bundle")
    normalized["sha256"] = expected_hash
    return normalized


def _card_template_id(value: Any) -> str:
    if type(value) is not str or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", value) is None:
        raise ValueError("Card template id is invalid")
    return value


def _card_template_hash(value: Any) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("Card template hash is invalid")
    return value


def _card_template_parameters_schema(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "type", "properties", "required", "additionalProperties"
    }:
        raise ValueError("Card template parameters schema is invalid")
    if value["type"] != "object" or value["additionalProperties"] is not False:
        raise ValueError("Card template parameters schema must be a strict object")
    properties = value["properties"]
    required = value["required"]
    if not isinstance(properties, dict):
        raise ValueError("Card template parameter properties are invalid")
    if (
        not isinstance(required, list)
        or len(required) != len(set(required))
        or any(type(item) is not str or item not in properties for item in required)
    ):
        raise ValueError("Card template required parameters are invalid")
    for name, schema in properties.items():
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", name) is None:
            raise ValueError("Card template parameter name is invalid")
        if (
            not isinstance(schema, dict)
            or set(schema) - {"type", "title", "description", "default", "enum"}
            or schema.get("type") not in {"string", "integer", "number", "boolean"}
        ):
            raise ValueError("Card template parameter schema is invalid")
        if "title" in schema:
            _required_text(schema["title"], "parameter title", 120)
        if "description" in schema:
            _required_text(schema["description"], "parameter description", 500)
        if "enum" in schema:
            enum = schema["enum"]
            if not isinstance(enum, list) or not enum:
                raise ValueError("Card template parameter enum is invalid")
            if len({canonical_card_json(item) for item in enum}) != len(enum):
                raise ValueError("Card template parameter enum is invalid")
            for item in enum:
                _card_template_parameter_value(item, schema["type"])
        if "default" in schema:
            _card_template_parameter_value(schema["default"], schema["type"])
            if "enum" in schema and schema["default"] not in schema["enum"]:
                raise ValueError("Card template parameter default is invalid")


def _card_template_parameter_value(value: Any, kind: str) -> None:
    valid = (
        (kind == "string" and isinstance(value, str))
        or (kind == "integer" and type(value) is int)
        or (kind == "number" and type(value) in {int, float})
        or (kind == "boolean" and type(value) is bool)
    )
    if not valid:
        raise ValueError("Card template parameter value is invalid")


def _identifier(value: str, name: str) -> str:
    return _required_text(value, name, 180)


def _required_text(value: str, name: str, maximum: int) -> str:
    normalized = str(value or "").strip()
    if not normalized or len(normalized) > maximum:
        raise ValueError(f"{name} must be between 1 and {maximum} characters")
    return normalized


def _provider_mode(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in {"managed", "direct", "relay"}:
        raise ValueError("Loopdy provider mode must be managed, direct, or relay")
    return normalized


def _device_provider(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in {"managed", "direct", "relay", "legacy_relay"}:
        raise ValueError("Loopdy device provider must be managed, direct, or relay")
    return normalized


def _delivery_status(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in {"queued", "sent", "failed", "suppressed"}:
        raise ValueError("Invalid device delivery status")
    return normalized


def _text(value: Any, maximum: int) -> str:
    return " ".join(str(value or "").split())[:maximum]


def _json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("Value is not canonical JSON") from error


def _relay_operation_name(value: Any) -> str:
    normalized = _required_text(value, "operation", 80)
    return "revoke_device" if normalized == "device_revoke" else normalized


def _normalized_body_digest(value: Mapping[str, Any]) -> str:
    try:
        encoded = json.dumps(
            dict(value),
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("Relay body is not canonical JSON") from error
    return hashlib.sha256(encoded).hexdigest()


def _positive_revision(value: Any) -> int:
    if (
        type(value) is not int
        or value <= 0
        or value > _MAX_SAFE_REVISION
    ):
        raise ValueError("Relay revision must be a positive integer")
    return value


def _positive_integer(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0 or value > _MAX_TIMESTAMP:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _protocol_identifier(value: Any, name: str) -> str:
    if type(value) is not str or _PROTOCOL_IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} must be a printable ASCII protocol identifier")
    return value


def _load_json(value: str, default: Any) -> Any:
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default
