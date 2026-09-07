"""Strict, surface-neutral Loopdy Link wire contracts."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import uuid
from dataclasses import dataclass
from typing import Any

from .events import EVENT_TYPES
from .wiki_contract import (
    WIKI_OPERATIONS,
    available_wiki_operations,
    bounded_result as bound_wiki_result,
    validate_payload as validate_wiki_payload,
)
from .generative_ui import canonical_json, validate_rendered_envelope


_OPAQUE = re.compile(r"^[A-Za-z0-9_-]+$")
_MIME_TYPE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")
# Device-to-host uploads retain the established per-file and aggregate limits.
MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024
MAX_MESSAGE_ATTACHMENT_BYTES = 24 * 1024 * 1024
MAX_ATTACHMENT_CHUNK_BYTES = 64 * 1024
MAX_ATTACHMENT_CHUNKS = 128
# Authenticated host-to-device agent artifacts use the host cache's larger,
# separately bounded allowance without widening user-upload parsing.
MAX_AGENT_ATTACHMENT_BYTES = 25 * 1024 * 1024
MAX_AGENT_ATTACHMENT_CHUNKS = (
    MAX_AGENT_ATTACHMENT_BYTES + MAX_ATTACHMENT_CHUNK_BYTES - 1
) // MAX_ATTACHMENT_CHUNK_BYTES
MAX_AVATAR_WORKSPACE_PLAINTEXT_BYTES = 2_800_000
MAX_ENCRYPTED_FRAME_CHARACTERS = 4_000_000
PLUGIN_VERSION = "2.8.0"
AVAILABLE_WIKI_OPERATIONS = available_wiki_operations()
WORKSPACE_OPERATIONS = frozenset(
    {
        *AVAILABLE_WIKI_OPERATIONS,
        "agents.list",
        "host_runtime.status",
        "plugin_update.start",
        "plugin_update.status",
        "agents.create",
        "agents.update",
        "agents.avatar.get",
        "agents.avatar.set",
        "sessions.list",
        "sessions.history",
        "sessions.update",
        "sessions.delete",
        "attachments.resolve",
        "attachments.fetch",
        "generated_media.resolve",
        "scheduled_tasks.list",
        "scheduled_tasks.delivery_targets",
        "scheduled_tasks.create",
        "scheduled_tasks.update",
        "scheduled_tasks.delete",
        "scheduled_tasks.pause",
        "scheduled_tasks.resume",
        "scheduled_tasks.run",
        "agent_defaults.get",
        "agent_defaults.set",
        "skills_tools.list",
        "skills_tools.get",
        "skills_tools.create",
        "skills_tools.update",
        "skills_tools.import",
        "cards.templates.list",
        "cards.templates.install",
        "cards.templates.remove",
        "marketplace.skills.install",
        "marketplace.skills.status",
        "projects.list",
        "projects.set_active",
        "projects.create",
        "projects.archive",
        "projects.list_directory",
        "projects.git.capabilities",
        "projects.git.status",
        "projects.git.diff",
        "projects.git.prepare",
        "projects.git.execute",
        "dashboard.load",
        "dashboard.set_event_state",
        "dashboard.dismiss_event",
        "dashboard.dismiss_events",
        "approvals.load",
        "approvals.respond",
        "clarifications.respond",
    }
)


@dataclass(frozen=True)
class EncryptedFrame:
    frame_id: str
    sender_device_id: str
    sender_epoch: int
    sequence: int
    ack: int
    ciphertext: str

    def wire_value(self) -> dict[str, Any]:
        return {
            "version": 1,
            "type": "frame",
            "id": self.frame_id,
            "senderDeviceId": self.sender_device_id,
            "senderEpoch": self.sender_epoch,
            "sequence": self.sequence,
            "ack": self.ack,
            "ciphertext": self.ciphertext,
        }


@dataclass(frozen=True)
class AttachmentReference:
    attachment_id: str
    file_name: str
    mime_type: str
    total_bytes: int
    sha256: str


@dataclass(frozen=True)
class AttachmentChunk:
    upload_id: str
    session_id: str
    agent_id: str
    reference: AttachmentReference
    index: int
    count: int
    data: bytes
    sent_at: int


@dataclass(frozen=True)
class UserMessage:
    message_id: str
    session_id: str
    agent_id: str
    actor_id: str
    actor_name: str
    device_name: str
    text: str
    sent_at: int
    attachments: tuple[AttachmentReference, ...] = ()
    behavior: str | None = None


@dataclass(frozen=True)
class VoiceSpeakRequest:
    request_id: str
    session_id: str
    agent_id: str
    text: str
    speed: float
    sent_at: int

    def wire_value(self) -> dict[str, Any]:
        return {
            "version": 1,
            "type": "voice.speak.request",
            "requestId": self.request_id,
            "sessionId": self.session_id,
            "agentId": self.agent_id,
            "text": self.text,
            "speed": self.speed,
            "sentAt": self.sent_at,
        }


@dataclass(frozen=True)
class PickerOpen:
    request_id: str
    session_id: str
    agent_id: str
    kind: str
    sent_at: int

    def wire_value(self) -> dict[str, Any]:
        return {
            "version": 1,
            "type": "picker.open",
            "requestId": self.request_id,
            "sessionId": self.session_id,
            "agentId": self.agent_id,
            "kind": self.kind,
            "sentAt": self.sent_at,
        }


@dataclass(frozen=True)
class PickerSelection:
    picker_id: str
    session_id: str
    kind: str
    sent_at: int
    provider: str | None = None
    model: str | None = None
    value: str | None = None

    def wire_value(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "version": 1,
            "type": "picker.select",
            "pickerId": self.picker_id,
            "sessionId": self.session_id,
            "kind": self.kind,
            "sentAt": self.sent_at,
        }
        if self.kind == "model":
            result["provider"] = self.provider
            result["model"] = self.model
        else:
            result["value"] = self.value
        return result


@dataclass(frozen=True)
class SessionForkRequest:
    request_id: str
    source_session_id: str
    fork_session_id: str
    agent_id: str
    actor_id: str
    actor_name: str
    device_name: str
    user_turn: int
    checkpoint_role: str
    checkpoint_digest: str
    title: str
    sent_at: int

    def wire_value(self) -> dict[str, Any]:
        return {
            "version": 1,
            "type": "session.fork.request",
            "requestId": self.request_id,
            "sourceSessionId": self.source_session_id,
            "forkSessionId": self.fork_session_id,
            "agentId": self.agent_id,
            "actorId": self.actor_id,
            "actorName": self.actor_name,
            "deviceName": self.device_name,
            "userTurn": self.user_turn,
            "checkpointRole": self.checkpoint_role,
            "checkpointDigest": self.checkpoint_digest,
            "title": self.title,
            "sentAt": self.sent_at,
        }


@dataclass(frozen=True)
class CommandCatalogRequest:
    request_id: str
    session_id: str
    agent_id: str
    sent_at: int

    def wire_value(self) -> dict[str, Any]:
        return {
            "version": 1,
            "type": "commands.catalog.request",
            "requestId": self.request_id,
            "sessionId": self.session_id,
            "agentId": self.agent_id,
            "sentAt": self.sent_at,
        }


@dataclass(frozen=True)
class PersonalityRequest:
    request_id: str
    action: str
    expected_revision: int | None
    name: str | None
    definition: dict[str, str] | None
    sent_at: int


@dataclass(frozen=True)
class GenerativeUIFormSubmission:
    request_id: str
    session_id: str
    profile: str
    idempotency_key: str
    values: dict[str, Any]
    submitted_at: int

    def wire_value(self) -> dict[str, Any]:
        return {
            "version": 1,
            "type": "generative.ui.form.submit",
            "requestId": self.request_id,
            "sessionId": self.session_id,
            "profile": self.profile,
            "idempotencyKey": self.idempotency_key,
            "values": dict(self.values),
            "submittedAt": self.submitted_at,
        }


@dataclass(frozen=True)
class WorkspaceRequest:
    request_id: str
    operation: str
    payload: dict[str, Any]
    sent_at: int

    def wire_value(self) -> dict[str, Any]:
        return {
            "version": 1,
            "type": "workspace.request",
            "requestId": self.request_id,
            "operation": self.operation,
            "payload": dict(self.payload),
            "sentAt": self.sent_at,
        }


class ExpiredHostRelayEnrollment(ValueError):
    """A valid host-relay enrollment whose lease cannot be replayed."""


@dataclass(frozen=True)
class RelayReady:
    device_id: str
    enrollment_revision: int
    acknowledgement_revision: int
    lease_expires: int
    recipient_public_key: str
    recipient_key_id: str
    sender_key_revision: int
    acknowledged_sender_key_ids: tuple[str, ...]
    environment: str
    topic: str
    device_name: str
    sent_at: int
    scope: str = "link_wake"

    def wire_value(self) -> dict[str, Any]:
        value = {
            "version": 1,
            "type": "relay.ready",
            "deviceId": self.device_id,
            "enrollmentRevision": self.enrollment_revision,
            "acknowledgementRevision": self.acknowledgement_revision,
            "leaseExpires": self.lease_expires,
            "recipientPublicKey": self.recipient_public_key,
            "recipientKeyId": self.recipient_key_id,
            "senderKeyRevision": self.sender_key_revision,
            "acknowledgedSenderKeyIds": list(self.acknowledged_sender_key_ids),
            "environment": self.environment,
            "topic": self.topic,
            "deviceName": self.device_name,
            "sentAt": self.sent_at,
        }
        if self.scope != "link_wake":
            value["scope"] = self.scope
        return value


def parse_encrypted_frame(encoded: str) -> EncryptedFrame:
    if not isinstance(encoded, str) or len(encoded) > MAX_ENCRYPTED_FRAME_CHARACTERS:
        raise ValueError("Loopdy Link frame is invalid")
    try:
        value = json.loads(encoded)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Loopdy Link frame is invalid") from exc
    if not isinstance(value, dict) or value.get("version") != 1 or value.get("type") != "frame":
        raise ValueError("Loopdy Link frame is invalid")
    return EncryptedFrame(
        frame_id=_opaque(value.get("id"), "id", 16, 128),
        sender_device_id=_opaque(
            value.get("senderDeviceId"), "senderDeviceId", 1, 96
        ),
        sender_epoch=_positive(value.get("senderEpoch"), "senderEpoch"),
        sequence=_positive(value.get("sequence"), "sequence"),
        ack=_nonnegative(value.get("ack"), "ack"),
        ciphertext=_opaque(
            value.get("ciphertext"),
            "ciphertext",
            16,
            MAX_ENCRYPTED_FRAME_CHARACTERS,
        ),
    )


def parse_workspace_request(value: dict[str, Any]) -> WorkspaceRequest:
    expected = {"version", "type", "requestId", "operation", "payload", "sentAt"}
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("version") != 1
        or value.get("type") != "workspace.request"
    ):
        raise ValueError("Loopdy Link workspace request is invalid")
    operation = value.get("operation")
    if not isinstance(operation, str) or operation not in WORKSPACE_OPERATIONS:
        raise ValueError("Loopdy Link workspace operation is invalid")
    if operation in AVAILABLE_WIKI_OPERATIONS:
        if type(value.get("version")) is not int:
            raise ValueError("Wiki request is invalid")
        payload = validate_wiki_payload(operation, value.get("payload"))
    elif operation.startswith("projects.git."):
        payload = _project_git_workspace_payload(operation, value.get("payload"))
    elif operation in {"agents.create", "agents.update", "agents.avatar.set"}:
        payload = _workspace_json_allowing_avatar_blobs(value.get("payload"))
    elif operation == "skills_tools.import":
        payload = _workspace_json_allowing_skill_archive(value.get("payload"))
    else:
        payload = _workspace_json(value.get("payload"), depth=0)
    if not isinstance(payload, dict):
        raise ValueError("Loopdy Link workspace payload is invalid")
    return WorkspaceRequest(
        request_id=_opaque(value.get("requestId"), "requestId", 16, 128),
        operation=operation,
        payload=payload,
        sent_at=_positive(value.get("sentAt"), "sentAt"),
    )


def parse_user_message(value: dict[str, Any]) -> UserMessage:
    if not isinstance(value, dict) or value.get("version") != 1 or value.get("type") != "user.message":
        raise ValueError("Loopdy Link user message is invalid")
    raw_attachments = value.get("attachments", [])
    if not isinstance(raw_attachments, list) or len(raw_attachments) > 10:
        raise ValueError("Loopdy Link user message attachments are invalid")
    attachments = tuple(_attachment_reference(item) for item in raw_attachments)
    if sum(item.total_bytes for item in attachments) > MAX_MESSAGE_ATTACHMENT_BYTES:
        raise ValueError("Loopdy Link user message attachments are invalid")
    behavior = value.get("behavior")
    if behavior is not None and (
        not isinstance(behavior, str)
        or isinstance(behavior, bool)
        or behavior not in {"steer", "queue", "interrupt"}
    ):
        raise ValueError("Loopdy Link user message behavior is invalid")
    return UserMessage(
        message_id=_opaque(value.get("messageId"), "messageId", 16, 128),
        session_id=_session_coordinate(value.get("sessionId")),
        agent_id=_opaque(value.get("agentId"), "agentId", 1, 96),
        actor_id=_opaque(value.get("actorId"), "actorId", 1, 96),
        actor_name=_label(value.get("actorName"), "actorName", 80),
        device_name=_label(value.get("deviceName"), "deviceName", 96),
        text=_text(value.get("text"), "text", 100_000),
        sent_at=_positive(value.get("sentAt"), "sentAt"),
        attachments=attachments,
        behavior=behavior,
    )


def parse_attachment_chunk(value: dict[str, Any]) -> AttachmentChunk:
    expected = {
        "version",
        "type",
        "uploadId",
        "sessionId",
        "agentId",
        "attachmentId",
        "fileName",
        "mimeType",
        "totalBytes",
        "sha256",
        "index",
        "count",
        "data",
        "sentAt",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("version") != 1
        or value.get("type") != "attachment.chunk"
    ):
        raise ValueError("Loopdy Link attachment chunk is invalid")
    reference = _attachment_reference(value)
    index = _nonnegative(value.get("index"), "index")
    count = _positive(value.get("count"), "count")
    if count > MAX_ATTACHMENT_CHUNKS or index >= count:
        raise ValueError("Loopdy Link attachment chunk coordinate is invalid")
    data = _decode_b64url(_opaque(value.get("data"), "data", 1, 180_000))
    if not data or len(data) > MAX_ATTACHMENT_CHUNK_BYTES:
        raise ValueError("Loopdy Link attachment chunk data is invalid")
    if index < count - 1 and len(data) != MAX_ATTACHMENT_CHUNK_BYTES:
        raise ValueError("Loopdy Link attachment chunk size is invalid")
    return AttachmentChunk(
        upload_id=_opaque(value.get("uploadId"), "uploadId", 16, 128),
        session_id=_session_coordinate(value.get("sessionId")),
        agent_id=_opaque(value.get("agentId"), "agentId", 1, 96),
        reference=reference,
        index=index,
        count=count,
        data=data,
        sent_at=_positive(value.get("sentAt"), "sentAt"),
    )


def _attachment_reference(value: Any) -> AttachmentReference:
    if not isinstance(value, dict):
        raise ValueError("Loopdy Link attachment reference is invalid")
    file_name = value.get("fileName")
    if (
        not isinstance(file_name, str)
        or not file_name
        or len(file_name) > 180
        or file_name != file_name.strip()
        or file_name in {".", ".."}
        or "/" in file_name
        or "\\" in file_name
        or not file_name.isprintable()
    ):
        raise ValueError("Loopdy Link attachment file name is invalid")
    mime_type = value.get("mimeType")
    if not isinstance(mime_type, str) or not _MIME_TYPE.fullmatch(mime_type):
        raise ValueError("Loopdy Link attachment MIME type is invalid")
    total_bytes = _positive(value.get("totalBytes"), "totalBytes")
    if total_bytes > MAX_ATTACHMENT_BYTES:
        raise ValueError("Loopdy Link attachment size is invalid")
    return AttachmentReference(
        attachment_id=_opaque(value.get("attachmentId"), "attachmentId", 16, 128),
        file_name=file_name,
        mime_type=mime_type,
        total_bytes=total_bytes,
        sha256=_b64url(value.get("sha256"), "sha256", 32),
    )


def parse_voice_speak_request(value: dict[str, Any]) -> VoiceSpeakRequest:
    expected = {
        "version",
        "type",
        "requestId",
        "sessionId",
        "agentId",
        "text",
        "speed",
        "sentAt",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("version") != 1
        or value.get("type") != "voice.speak.request"
    ):
        raise ValueError("Loopdy Link voice request is invalid")
    speed = value.get("speed")
    if (
        not isinstance(speed, (int, float))
        or isinstance(speed, bool)
        or not math.isfinite(float(speed))
        or not 0.25 <= float(speed) <= 4.0
    ):
        raise ValueError("Loopdy Link voice speed is invalid")
    return VoiceSpeakRequest(
        request_id=_opaque(value.get("requestId"), "requestId", 16, 128),
        session_id=_session_coordinate(value.get("sessionId")),
        agent_id=_opaque(value.get("agentId"), "agentId", 1, 96),
        text=_text(value.get("text"), "text", 20_000),
        speed=float(speed),
        sent_at=_positive(value.get("sentAt"), "sentAt"),
    )


def parse_personality_request(value: dict[str, Any]) -> PersonalityRequest:
    if not isinstance(value, dict) or value.get("version") != 1:
        raise ValueError("Loopdy Link personality request is invalid")
    request_type = value.get("type")
    if request_type == "personalities.catalog.request":
        if set(value) != {"version", "type", "requestId", "sentAt"}:
            raise ValueError("Loopdy Link personality request is invalid")
        return PersonalityRequest(
            request_id=_opaque(value.get("requestId"), "requestId", 16, 128),
            action="catalog",
            expected_revision=None,
            name=None,
            definition=None,
            sent_at=_positive(value.get("sentAt"), "sentAt"),
        )
    if request_type != "personalities.mutate":
        raise ValueError("Loopdy Link personality request is invalid")
    action = value.get("action")
    if action not in {"save", "delete", "activate"}:
        raise ValueError("Loopdy Link personality action is invalid")
    required = {"version", "type", "requestId", "action", "expectedRevision", "sentAt"}
    optional = {"name", "definition"}
    if not required.issubset(value) or not set(value).issubset(required | optional):
        raise ValueError("Loopdy Link personality request is invalid")
    expected_revision = _nonnegative(value.get("expectedRevision"), "expectedRevision")
    name: str | None = None
    definition: dict[str, str] | None = None
    if "name" in value:
        name = _personality_name(value.get("name"), allows_neutral=action == "activate")
    if action == "save":
        if name is None or "definition" not in value:
            raise ValueError("Loopdy Link personality save is invalid")
        definition = _personality_definition(value.get("definition"))
        if definition["name"] != name:
            raise ValueError("Loopdy Link personality save coordinates do not match")
    elif action == "delete":
        if name is None or "definition" in value:
            raise ValueError("Loopdy Link personality delete is invalid")
    elif "definition" in value:
        raise ValueError("Loopdy Link personality activation is invalid")
    return PersonalityRequest(
        request_id=_opaque(value.get("requestId"), "requestId", 16, 128),
        action=action,
        expected_revision=expected_revision,
        name=name,
        definition=definition,
        sent_at=_positive(value.get("sentAt"), "sentAt"),
    )


def parse_generative_ui_form_submission(
    value: dict[str, Any],
) -> GenerativeUIFormSubmission:
    expected = {
        "version", "type", "requestId", "sessionId", "profile",
        "idempotencyKey", "values", "submittedAt",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("version") != 1
        or value.get("type") != "generative.ui.form.submit"
    ):
        raise ValueError("Loopdy Link form submission is invalid")
    request_id = str(value.get("requestId") or "")
    if not re.fullmatch(r"[0-9a-f]{32}", request_id):
        raise ValueError("Loopdy Link form requestId is invalid")
    idempotency_key = str(value.get("idempotencyKey") or "")
    try:
        parsed_key = uuid.UUID(idempotency_key)
    except (ValueError, AttributeError) as exc:
        raise ValueError("Loopdy Link form idempotencyKey is invalid") from exc
    if str(parsed_key) != idempotency_key:
        raise ValueError("Loopdy Link form idempotencyKey is invalid")
    values = _form_submission_values(value.get("values"))
    return GenerativeUIFormSubmission(
        request_id=request_id,
        session_id=_session_coordinate(value.get("sessionId")),
        profile=_opaque(value.get("profile"), "profile", 1, 80),
        idempotency_key=idempotency_key,
        values=values,
        submitted_at=_positive(value.get("submittedAt"), "submittedAt"),
    )


def personality_catalog_payload(
    *,
    request_id: str,
    catalog: dict[str, Any],
    sent_at: int,
) -> dict[str, Any]:
    personalities = catalog.get("personalities") if isinstance(catalog, dict) else None
    if not isinstance(personalities, list) or len(personalities) > 100:
        raise ValueError("Loopdy Link personality catalog is invalid")
    validated = []
    names = set()
    for raw in personalities:
        definition = _personality_definition(raw, response=True)
        if definition["name"] in names:
            raise ValueError("Loopdy Link personality catalog contains duplicates")
        names.add(definition["name"])
        validated.append(definition)
    active_name = _personality_name(catalog.get("activeName", ""), allows_neutral=True)
    if active_name and active_name not in names:
        raise ValueError("Loopdy Link active personality is unavailable")
    return {
        "version": 1,
        "type": "personalities.catalog",
        "requestId": _opaque(request_id, "requestId", 16, 128),
        "revision": _nonnegative(catalog.get("revision"), "revision"),
        "activeName": active_name or "",
        "personalities": validated,
        "sentAt": _positive(sent_at, "sentAt"),
    }


def parse_picker_open(value: dict[str, Any]) -> PickerOpen:
    expected = {
        "version",
        "type",
        "requestId",
        "sessionId",
        "agentId",
        "kind",
        "sentAt",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("version") != 1
        or value.get("type") != "picker.open"
        or value.get("kind") not in {"model", "reasoning"}
    ):
        raise ValueError("Loopdy Link picker request is invalid")
    return PickerOpen(
        request_id=_opaque(value.get("requestId"), "requestId", 16, 128),
        session_id=_session_coordinate(value.get("sessionId")),
        agent_id=_opaque(value.get("agentId"), "agentId", 1, 96),
        kind=str(value["kind"]),
        sent_at=_positive(value.get("sentAt"), "sentAt"),
    )


def parse_picker_selection(value: dict[str, Any]) -> PickerSelection:
    if not isinstance(value, dict):
        raise ValueError("Loopdy Link picker selection is invalid")
    kind = value.get("kind")
    common = {
        "version",
        "type",
        "pickerId",
        "sessionId",
        "kind",
        "sentAt",
    }
    expected = common | ({"provider", "model"} if kind == "model" else {"value"})
    if (
        set(value) != expected
        or value.get("version") != 1
        or value.get("type") != "picker.select"
        or kind not in {"model", "reasoning"}
    ):
        raise ValueError("Loopdy Link picker selection is invalid")
    provider = model = selected_value = None
    if kind == "model":
        provider = _picker_identifier(value.get("provider"), "provider", 1, 128)
        model = _model_picker_identifier(value.get("model"), "model", 1, 256)
    else:
        selected_value = _picker_identifier(value.get("value"), "value", 1, 64)
    return PickerSelection(
        picker_id=_opaque(value.get("pickerId"), "pickerId", 16, 128),
        session_id=_session_coordinate(value.get("sessionId")),
        kind=str(kind),
        provider=provider,
        model=model,
        value=selected_value,
        sent_at=_positive(value.get("sentAt"), "sentAt"),
    )


def parse_session_fork_request(value: dict[str, Any]) -> SessionForkRequest:
    expected = {
        "version",
        "type",
        "requestId",
        "sourceSessionId",
        "forkSessionId",
        "agentId",
        "actorId",
        "actorName",
        "deviceName",
        "userTurn",
        "checkpointRole",
        "checkpointDigest",
        "title",
        "sentAt",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("version") != 1
        or value.get("type") != "session.fork.request"
        or value.get("checkpointRole") not in {"user", "assistant"}
    ):
        raise ValueError("Loopdy Link session fork is invalid")
    user_turn = _positive(value.get("userTurn"), "userTurn")
    if user_turn > 1_000_000:
        raise ValueError("Loopdy Link session fork turn is invalid")
    return SessionForkRequest(
        request_id=_opaque(value.get("requestId"), "requestId", 16, 128),
        source_session_id=_session_coordinate(
            value.get("sourceSessionId"), "sourceSessionId"
        ),
        fork_session_id=_session_coordinate(
            value.get("forkSessionId"), "forkSessionId"
        ),
        agent_id=_opaque(value.get("agentId"), "agentId", 1, 96),
        actor_id=_opaque(value.get("actorId"), "actorId", 1, 96),
        actor_name=_label(value.get("actorName"), "actorName", 80),
        device_name=_label(value.get("deviceName"), "deviceName", 96),
        user_turn=user_turn,
        checkpoint_role=str(value["checkpointRole"]),
        checkpoint_digest=_b64url(
            value.get("checkpointDigest"), "checkpointDigest", 32
        ),
        title=_activity_label(value.get("title"), "title", 240),
        sent_at=_positive(value.get("sentAt"), "sentAt"),
    )


def parse_command_catalog_request(value: dict[str, Any]) -> CommandCatalogRequest:
    expected = {
        "version",
        "type",
        "requestId",
        "sessionId",
        "agentId",
        "sentAt",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("version") != 1
        or value.get("type") != "commands.catalog.request"
    ):
        raise ValueError("Loopdy Link command catalog request is invalid")
    return CommandCatalogRequest(
        request_id=_opaque(value.get("requestId"), "requestId", 16, 128),
        session_id=_session_coordinate(value.get("sessionId")),
        agent_id=_opaque(value.get("agentId"), "agentId", 1, 96),
        sent_at=_positive(value.get("sentAt"), "sentAt"),
    )


def command_catalog_payload(
    *,
    request: CommandCatalogRequest,
    commands: list[dict[str, Any]],
    sent_at: int,
) -> dict[str, Any]:
    if not isinstance(commands, list) or len(commands) > 1_000:
        raise ValueError("Loopdy Link command catalog is invalid")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for command in commands:
        if not isinstance(command, dict):
            raise ValueError("Loopdy Link command is invalid")
        expected = {
            "name",
            "description",
            "category",
            "argsHint",
            "aliases",
            "argumentMode",
            "source",
            "requiresArguments",
        }
        if set(command) != expected:
            raise ValueError("Loopdy Link command is invalid")
        name = _command_name(command.get("name"), "name")
        if name in seen:
            raise ValueError("Loopdy Link command names must be unique")
        seen.add(name)
        aliases = command.get("aliases")
        if not isinstance(aliases, list) or len(aliases) > 32:
            raise ValueError("Loopdy Link command aliases are invalid")
        alias_rows = [_command_name(alias, "alias") for alias in aliases]
        if len(set(alias_rows)) != len(alias_rows):
            raise ValueError("Loopdy Link command aliases must be unique")
        argument_mode = command.get("argumentMode")
        source = command.get("source")
        requires_arguments = command.get("requiresArguments")
        if argument_mode not in {"none", "text", "options", "mixed"}:
            raise ValueError("Loopdy Link command argument mode is invalid")
        if source not in {"core", "plugin", "skill", "user"}:
            raise ValueError("Loopdy Link command source is invalid")
        if not isinstance(requires_arguments, bool):
            raise ValueError("Loopdy Link command requirement is invalid")
        rows.append(
            {
                "name": name,
                "description": _activity_label(
                    command.get("description"), "description", 240
                ),
                "category": _activity_label(
                    command.get("category"), "category", 80
                ),
                "argsHint": _command_args_hint(command.get("argsHint")),
                "aliases": alias_rows,
                "argumentMode": argument_mode,
                "source": source,
                "requiresArguments": requires_arguments,
            }
        )
    payload = {
        "version": 1,
        "type": "commands.catalog",
        "requestId": request.request_id,
        "sessionId": request.session_id,
        "agentId": request.agent_id,
        "commands": rows,
        "sentAt": _positive(sent_at, "sentAt"),
    }
    if len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > 240_000:
        raise ValueError("Loopdy Link command catalog is too large")
    return payload


def verified_fork_prefix(
    history: list[dict[str, Any]], request: SessionForkRequest
) -> list[dict[str, Any]]:
    if not isinstance(history, list) or not history or len(history) > 1_000_000:
        raise ValueError("Loopdy Link session history is invalid")
    user_turn = 0
    user_index: int | None = None
    for index, message in enumerate(history):
        if not isinstance(message, dict):
            raise ValueError("Loopdy Link session history is invalid")
        if message.get("role") == "user":
            user_turn += 1
            if user_turn == request.user_turn:
                user_index = index
                break
    if user_index is None:
        raise ValueError("Loopdy Link fork checkpoint is stale")

    checkpoint_index = user_index
    if request.checkpoint_role == "assistant":
        checkpoint_index = -1
        for index in range(user_index + 1, len(history)):
            message = history[index]
            if message.get("role") == "user":
                break
            if message.get("role") == "assistant" and isinstance(
                message.get("content"), str
            ):
                checkpoint_index = index
        if checkpoint_index < 0:
            raise ValueError("Loopdy Link fork checkpoint is stale")

    content = history[checkpoint_index].get("content")
    if not isinstance(content, str):
        raise ValueError("Loopdy Link fork checkpoint is stale")
    actual = base64.urlsafe_b64encode(
        hashlib.sha256(content.encode("utf-8")).digest()
    ).decode("ascii").rstrip("=")
    if not hmac.compare_digest(actual, request.checkpoint_digest):
        raise ValueError("Loopdy Link fork checkpoint changed")
    return list(history[: checkpoint_index + 1])


def session_fork_result(
    *,
    request: SessionForkRequest,
    status: str,
    title: str,
    message: str,
    sent_at: int,
) -> dict[str, Any]:
    if status not in {"completed", "failed", "conflict"}:
        raise ValueError("Loopdy Link session fork result is invalid")
    return {
        "version": 1,
        "type": "session.fork.result",
        "requestId": request.request_id,
        "sourceSessionId": request.source_session_id,
        "forkSessionId": request.fork_session_id,
        "status": status,
        "title": _activity_label(title, "title", 240),
        "message": _activity_label(message, "message", 2_000),
        "sentAt": _positive(sent_at, "sentAt"),
    }


def voice_audio_chunks(
    *,
    request: VoiceSpeakRequest,
    audio: bytes,
    mime_type: str,
    provider: str,
    sent_at: int,
) -> list[dict[str, Any]]:
    if not isinstance(audio, bytes) or not audio or len(audio) > 8 * 1024 * 1024:
        raise ValueError("Loopdy Link voice audio size is invalid")
    if mime_type not in {"audio/mpeg", "audio/ogg", "audio/wav", "audio/flac"}:
        raise ValueError("Loopdy Link voice MIME type is invalid")
    provider_name = _label(provider, "provider", 80)
    timestamp = _positive(sent_at, "sentAt")
    chunk_size = 90 * 1024
    count = (len(audio) + chunk_size - 1) // chunk_size
    if not 1 <= count <= 92:
        raise ValueError("Loopdy Link voice chunk count is invalid")
    digest = base64.urlsafe_b64encode(hashlib.sha256(audio).digest()).decode("ascii").rstrip("=")
    chunks: list[dict[str, Any]] = []
    for index in range(count):
        piece = audio[index * chunk_size : (index + 1) * chunk_size]
        chunks.append(
            {
                "version": 1,
                "type": "voice.speak.chunk",
                "requestId": request.request_id,
                "sessionId": request.session_id,
                "agentId": request.agent_id,
                "index": index,
                "count": count,
                "mimeType": mime_type,
                "provider": provider_name,
                "totalBytes": len(audio),
                "sha256": digest,
                "audio": base64.urlsafe_b64encode(piece).decode("ascii").rstrip("="),
                "sentAt": timestamp,
            }
        )
    return chunks


def voice_speak_error(
    *, request: VoiceSpeakRequest, code: str, message: str, sent_at: int
) -> dict[str, Any]:
    if code not in {"unavailable", "synthesis_failed", "audio_too_large"}:
        raise ValueError("Loopdy Link voice error code is invalid")
    return {
        "version": 1,
        "type": "voice.speak.error",
        "requestId": request.request_id,
        "sessionId": request.session_id,
        "agentId": request.agent_id,
        "code": code,
        "message": _label(message, "message", 160),
        "sentAt": _positive(sent_at, "sentAt"),
    }


def model_picker_payload(
    *,
    picker_id: str,
    session_id: str,
    current_model: str,
    current_provider: str,
    providers: list[dict[str, Any]],
    sent_at: int,
) -> dict[str, Any]:
    if not isinstance(providers, list) or not 1 <= len(providers) <= 32:
        raise ValueError("Loopdy Link model provider count is invalid")
    rows: list[dict[str, Any]] = []
    total_models = 0
    for provider in providers:
        if not isinstance(provider, dict):
            raise ValueError("Loopdy Link model provider is invalid")
        models = provider.get("models")
        if not isinstance(models, list) or not 1 <= len(models) <= 50:
            raise ValueError("Loopdy Link model count is invalid")
        model_ids = [
            _model_picker_identifier(model, "model", 1, 256)
            for model in models
        ]
        if len(set(model_ids)) != len(model_ids):
            raise ValueError("Loopdy Link model identifiers must be unique")
        total_models += len(model_ids)
        if total_models > 800:
            raise ValueError("Loopdy Link total model count is invalid")
        rows.append(
            {
                "id": _picker_identifier(provider.get("slug"), "provider", 1, 128),
                "name": _activity_label(
                    str(provider.get("name") or provider.get("slug") or ""),
                    "providerName",
                    80,
                ),
                "isCurrent": provider.get("is_current") is True,
                "isCustom": provider.get("is_user_defined") is True,
                "models": model_ids,
            }
        )
    value: dict[str, Any] = {
        "version": 1,
        "type": "picker.model",
        "pickerId": _opaque(picker_id, "pickerId", 16, 128),
        "sessionId": _session_coordinate(session_id),
        "currentModel": _model_picker_identifier(
            current_model or "unknown", "currentModel", 1, 256
        ),
        "currentProvider": _picker_identifier(
            current_provider or "unknown", "currentProvider", 1, 128
        ),
        "providers": rows,
        "sentAt": _positive(sent_at, "sentAt"),
    }
    if len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > 180_000:
        raise ValueError("Loopdy Link model picker is too large")
    return value


def choice_picker_payload(
    *,
    picker_id: str,
    session_id: str,
    title: str,
    choices: list[dict[str, Any]],
    sent_at: int,
) -> dict[str, Any]:
    if not isinstance(choices, list) or not 1 <= len(choices) <= 16:
        raise ValueError("Loopdy Link choice count is invalid")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for choice in choices:
        if not isinstance(choice, dict):
            raise ValueError("Loopdy Link choice is invalid")
        value = _picker_identifier(choice.get("value"), "choiceValue", 1, 64)
        if value in seen:
            raise ValueError("Loopdy Link choice values must be unique")
        seen.add(value)
        rows.append(
            {
                "value": value,
                "label": _activity_label(
                    str(choice.get("label") or value), "choiceLabel", 96
                ),
                "isCurrent": choice.get("is_current") is True,
            }
        )
    return {
        "version": 1,
        "type": "picker.choice",
        "pickerId": _opaque(picker_id, "pickerId", 16, 128),
        "sessionId": _session_coordinate(session_id),
        "kind": "reasoning",
        "title": _picker_title(title, "title", 240),
        "choices": rows,
        "sentAt": _positive(sent_at, "sentAt"),
    }


def picker_result(
    *,
    picker_id: str,
    session_id: str,
    kind: str,
    status: str,
    message: str,
    sent_at: int,
) -> dict[str, Any]:
    if kind not in {"model", "reasoning"} or status not in {
        "completed",
        "failed",
        "expired",
    }:
        raise ValueError("Loopdy Link picker result is invalid")
    return {
        "version": 1,
        "type": "picker.result",
        "pickerId": _opaque(picker_id, "pickerId", 16, 128),
        "sessionId": _session_coordinate(session_id),
        "kind": kind,
        "status": status,
        "message": _picker_result_message(message, "message", 2_000),
        "sentAt": _positive(sent_at, "sentAt"),
    }


def parse_relay_ready(value: dict[str, Any]) -> RelayReady:
    expected = {
        "version",
        "type",
        "deviceId",
        "enrollmentRevision",
        "acknowledgementRevision",
        "leaseExpires",
        "recipientPublicKey",
        "recipientKeyId",
        "senderKeyRevision",
        "acknowledgedSenderKeyIds",
        "environment",
        "topic",
        "deviceName",
        "sentAt",
    }
    if not isinstance(value, dict) or frozenset(value) not in {
        frozenset(expected),
        frozenset(expected | {"scope"}),
    }:
        raise ValueError("Loopdy Link relay readiness is invalid")
    if value.get("version") != 1 or value.get("type") != "relay.ready":
        raise ValueError("Loopdy Link relay readiness is invalid")
    scope = value.get("scope", "link_wake")
    if scope not in {"link_wake", "host_relay"}:
        raise ValueError("Loopdy Link relay readiness scope is invalid")
    enrollment = _positive(value.get("enrollmentRevision"), "enrollmentRevision")
    acknowledgement = _positive(
        value.get("acknowledgementRevision"), "acknowledgementRevision"
    )
    sent_at = _positive(value.get("sentAt"), "sentAt")
    lease_expires = _positive(value.get("leaseExpires"), "leaseExpires")
    if acknowledgement != enrollment + 1 or not sent_at < lease_expires <= sent_at + 2_592_000:
        raise ValueError("Loopdy Link relay readiness revisions are invalid")
    raw_ids = value.get("acknowledgedSenderKeyIds")
    if not isinstance(raw_ids, list):
        raise ValueError("Loopdy Link relay sender keys must be an array")
    if not 1 <= len(raw_ids) <= 2:
        raise ValueError("Loopdy Link relay sender-key acknowledgement count is invalid")
    if len(set(raw_ids)) != len(raw_ids):
        raise ValueError("Loopdy Link relay sender keys must be unique")
    sender_ids = tuple(_b64url(item, "senderKeyId", 32) for item in raw_ids)
    recipient_public_key = _b64url(
        value.get("recipientPublicKey"), "recipientPublicKey", 65
    )
    if _decode_b64url(recipient_public_key)[0] != 4:
        raise ValueError("Loopdy Link relay recipient key is invalid")
    environment = value.get("environment")
    topic = value.get("topic")
    if environment not in {"production", "sandbox"}:
        raise ValueError("Loopdy Link relay environment is invalid")
    if (
        not isinstance(topic, str)
        or len(topic) > 255
        or re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", topic) is None
    ):
        raise ValueError("Loopdy Link relay topic is invalid")
    return RelayReady(
        device_id=_opaque(value.get("deviceId"), "deviceId", 1, 96),
        enrollment_revision=enrollment,
        acknowledgement_revision=acknowledgement,
        lease_expires=lease_expires,
        recipient_public_key=recipient_public_key,
        recipient_key_id=_b64url(value.get("recipientKeyId"), "recipientKeyId", 32),
        sender_key_revision=_positive(value.get("senderKeyRevision"), "senderKeyRevision"),
        acknowledged_sender_key_ids=sender_ids,
        environment=environment,
        topic=topic,
        device_name=_label(value.get("deviceName"), "deviceName", 96),
        sent_at=sent_at,
        scope=scope,
    )


def assistant_message(
    *,
    message_id: str,
    session_id: str,
    text: str,
    sent_at: int,
    agent_name: str,
    agent_id: str,
    delivery: str = "final",
    draft_id: int | None = None,
) -> dict[str, Any]:
    if delivery not in {"draft", "final"}:
        raise ValueError("Loopdy Link assistant delivery is invalid")
    value: dict[str, Any] = {
        "version": 1,
        "type": "assistant.message",
        "messageId": _opaque(message_id, "messageId", 16, 128),
        "sessionId": _session_coordinate(session_id),
        "agentId": _opaque(agent_id, "agentId", 1, 96),
        "agentName": _label(agent_name, "agentName", 80),
        "text": _text(text, "text", 100_000),
        "sentAt": _positive(sent_at, "sentAt"),
        "delivery": delivery,
    }
    if draft_id is not None:
        value["draftId"] = _positive(draft_id, "draftId")
    return value


def notification_event(
    *,
    event_id: str,
    event_type: str,
    agent_id: str,
    agent_name: str,
    session_id: str,
    title: str,
    body: str,
    sent_at: int,
    card: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if event_type not in EVENT_TYPES:
        raise ValueError("Loopdy Link notification event type is invalid")
    value: dict[str, Any] = {
        "version": 1,
        "type": "notification.event",
        "eventId": _picker_identifier(event_id, "eventId", 1, 220),
        "eventType": event_type,
        "agentId": _opaque(agent_id, "agentId", 1, 96),
        "agentName": _label(agent_name, "agentName", 80),
        "title": _activity_label(title, "title", 100),
        "body": _activity_label(body, "body", 800),
        "sentAt": _positive(sent_at, "sentAt"),
    }
    if session_id:
        value["sessionId"] = _session_coordinate(session_id)
    if card is not None:
        value["card"] = validate_rendered_envelope(card)
    return value


def activity_event(
    *,
    event_id: str,
    session_id: str,
    turn_id: str,
    kind: str,
    lifecycle: str,
    title: str,
    summary: str | None,
    detail: str | None,
    occurred_at: int,
    arguments: str | None = None,
    result: str | None = None,
    duration_ms: int | None = None,
    tool_call_id: str | None = None,
    tool_name: str | None = None,
    subagent_id: str | None = None,
    bot_run_id: str | None = None,
    member_id: str | None = None,
    from_member_id: str | None = None,
) -> dict[str, Any]:
    if kind not in {"reasoning", "tool", "subagent", "bot_handoff"}:
        raise ValueError("Loopdy Link activity kind is invalid")
    if lifecycle not in {"running", "succeeded", "failed", "cancelled"}:
        raise ValueError("Loopdy Link activity lifecycle is invalid")
    if kind == "reasoning":
        valid_identity = all(
            value is None
            for value in (tool_call_id, subagent_id, bot_run_id, member_id, from_member_id)
        )
    elif kind == "tool":
        valid_identity = (
            tool_call_id is not None
            and all(value is None for value in (subagent_id, bot_run_id, member_id, from_member_id))
        )
    elif kind == "subagent":
        valid_identity = (
            subagent_id is not None
            and all(value is None for value in (tool_call_id, bot_run_id, member_id, from_member_id))
        )
    else:
        valid_identity = (
            bot_run_id is not None
            and member_id is not None
            and tool_call_id is None
            and subagent_id is None
        )
    if not valid_identity:
        raise ValueError("Loopdy Link activity identity is invalid")
    if kind not in {"tool", "bot_handoff"} and (arguments is not None or result is not None):
        raise ValueError("Loopdy Link activity detail is invalid")
    if kind != "tool" and tool_name is not None:
        raise ValueError("Loopdy Link tool detail is invalid")
    value: dict[str, Any] = {
        "version": 1,
        "type": "activity.event",
        "eventId": _opaque(event_id, "eventId", 16, 128),
        "sessionId": _session_coordinate(session_id),
        "turnId": _opaque(turn_id, "turnId", 8, 180),
        "kind": kind,
        "lifecycle": lifecycle,
        "title": _activity_label(title, "title", 80),
        "occurredAt": _positive(occurred_at, "occurredAt"),
    }
    optional_labels = (("summary", summary, 500), ("detail", detail, 1_000))
    for key, candidate, maximum in optional_labels:
        if candidate is not None:
            value[key] = _activity_label(candidate, key, maximum)
    for key, candidate in (("arguments", arguments), ("result", result)):
        if candidate is not None:
            if kind == "bot_handoff" and len(candidate.encode("utf-8")) > 64_000:
                raise ValueError(f"Loopdy Link {key} is invalid")
            value[key] = _activity_detail(candidate, key, 65_536)
    if duration_ms is not None:
        duration = _nonnegative(duration_ms, "durationMs")
        if duration > 86_400_000:
            raise ValueError("Loopdy Link durationMs is invalid")
        value["durationMs"] = duration
    for key, candidate, maximum in (
        ("toolCallId", tool_call_id, 180),
        ("toolName", tool_name, 80),
        ("subagentId", subagent_id, 180),
        ("botRunId", bot_run_id, 180),
        ("memberId", member_id, 96),
        ("fromMemberId", from_member_id, 96),
    ):
        if candidate is not None:
            value[key] = _opaque(candidate, key, 1, maximum)
    return value


def session_context(
    *,
    session_id: str,
    model: str,
    context_used: int,
    context_max: int,
    context_percent: int,
    compressions: int,
    is_compacting: bool,
    updated_at: int,
    title: str | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    cached_tokens: int | None = None,
    total_tokens: int | None = None,
) -> dict[str, Any]:
    """Build the encrypted current-context projection for one Link chat."""

    used = _nonnegative(context_used, "contextUsed")
    maximum = _positive(context_max, "contextMax")
    percent = _nonnegative(context_percent, "contextPercent")
    if percent > 100:
        raise ValueError("Loopdy Link contextPercent is invalid")
    if type(is_compacting) is not bool:
        raise ValueError("Loopdy Link isCompacting is invalid")
    value = {
        "version": 1,
        "type": "session.context",
        "sessionId": _session_coordinate(session_id),
        "model": _activity_label(model, "model", 160),
        "contextUsed": used,
        "contextMax": maximum,
        "contextPercent": percent,
        "compressions": _nonnegative(compressions, "compressions"),
        "isCompacting": is_compacting,
        "updatedAt": _positive(updated_at, "updatedAt"),
    }
    if title is not None:
        value["title"] = _activity_label(title, "title", 240)
    # Token accounting is additive: a Hermes runtime that cannot report a
    # metric omits its key rather than publishing a misleading zero.
    for key, candidate in (
        ("inputTokens", input_tokens),
        ("outputTokens", output_tokens),
        ("cachedTokens", cached_tokens),
        ("totalTokens", total_tokens),
    ):
        if candidate is not None:
            value[key] = _nonnegative(candidate, key)
    return value


def session_todos(
    *,
    session_id: str,
    revision: int,
    todos: list[dict[str, Any]],
    updated_at: int,
) -> dict[str, Any]:
    """Build Hermes' revisioned full todo snapshot for one encrypted chat."""

    if not isinstance(todos, list) or len(todos) > 256:
        raise ValueError("Loopdy Link todos are invalid")
    projected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in todos:
        if not isinstance(raw, dict) or set(raw) not in (
            {"id", "content", "status"},
            {"id", "content", "status", "parent"},
        ):
            raise ValueError("Loopdy Link todo is invalid")
        item_id = _activity_label(raw.get("id"), "todo id", 128)
        if item_id in seen:
            raise ValueError("Loopdy Link todo id is invalid")
        seen.add(item_id)
        status = raw.get("status")
        if status not in {"pending", "in_progress", "completed", "cancelled"}:
            raise ValueError("Loopdy Link todo status is invalid")
        item: dict[str, Any] = {
            "id": item_id,
            "content": _activity_detail(raw.get("content"), "todo content", 4_000),
            "status": status,
        }
        if "parent" in raw:
            parent = _activity_label(raw.get("parent"), "todo parent", 128)
            if parent == item_id:
                raise ValueError("Loopdy Link todo parent is invalid")
            item["parent"] = parent
        projected.append(item)
    return {
        "version": 1,
        "type": "session.todos",
        "sessionId": _session_coordinate(session_id),
        "revision": _nonnegative(revision, "revision"),
        "todos": projected,
        "updatedAt": _positive(updated_at, "updatedAt"),
    }


def session_subagents(
    *,
    session_id: str,
    subagents: list[dict[str, Any]],
    updated_at: int,
) -> dict[str, Any]:
    """Build the active delegated-child roster for one encrypted chat."""

    if not isinstance(subagents, list) or len(subagents) > 256:
        raise ValueError("Loopdy Link subagent roster is invalid")
    projected: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_sessions: set[str] = set()
    for raw in subagents:
        if not isinstance(raw, dict) or set(raw) not in (
            {"id", "sessionId", "role", "goal", "startedAt"},
            {"id", "sessionId", "parentId", "role", "goal", "startedAt"},
        ):
            raise ValueError("Loopdy Link subagent is invalid")
        subagent_id = _opaque(raw.get("id"), "subagent id", 1, 180)
        child_session_id = _session_coordinate(
            raw.get("sessionId"), field="subagent sessionId"
        )
        if subagent_id in seen_ids or child_session_id in seen_sessions:
            raise ValueError("Loopdy Link subagent identity is invalid")
        seen_ids.add(subagent_id)
        seen_sessions.add(child_session_id)
        item: dict[str, Any] = {
            "id": subagent_id,
            "sessionId": child_session_id,
            "role": _activity_label(raw.get("role"), "subagent role", 80),
            "goal": _activity_label(raw.get("goal"), "subagent goal", 2_000),
            "startedAt": _positive(raw.get("startedAt"), "subagent startedAt"),
        }
        if "parentId" in raw:
            parent_id = _opaque(raw.get("parentId"), "subagent parentId", 1, 180)
            if parent_id == subagent_id:
                raise ValueError("Loopdy Link subagent parentId is invalid")
            item["parentId"] = parent_id
        projected.append(item)
    return {
        "version": 1,
        "type": "session.subagents",
        "sessionId": _session_coordinate(session_id),
        "subagents": projected,
        "updatedAt": _positive(updated_at, "updatedAt"),
    }


def generative_ui_event(
    *,
    event_id: str,
    session_id: str,
    turn_id: str,
    tool_call_id: str,
    agent_id: str,
    agent_name: str,
    card: dict[str, Any],
    occurred_at: int,
) -> dict[str, Any]:
    return {
        "version": 1,
        "type": "generative.ui",
        "eventId": _opaque(event_id, "eventId", 16, 128),
        "sessionId": _session_coordinate(session_id),
        "turnId": _opaque(turn_id, "turnId", 8, 180),
        "toolCallId": _opaque(tool_call_id, "toolCallId", 1, 180),
        "agentId": _opaque(agent_id, "agentId", 1, 96),
        "agentName": _label(agent_name, "agentName", 80),
        "card": validate_rendered_envelope(card),
        "occurredAt": _positive(occurred_at, "occurredAt"),
    }


def generative_ui_form_result(
    *,
    request: GenerativeUIFormSubmission,
    state: str,
    code: str,
    message: str,
    sent_at: int,
) -> dict[str, Any]:
    if state not in {"success", "error"}:
        raise ValueError("Loopdy Link form result state is invalid")
    allowed_codes = {
        "accepted", "request_not_found", "request_expired", "owner_mismatch",
        "invalid_value", "already_submitted", "already_consumed",
        "idempotency_conflict", "payload_too_large", "internal_error",
    }
    if code not in allowed_codes:
        raise ValueError("Loopdy Link form result code is invalid")
    return {
        "version": 1,
        "type": "generative.ui.form.result",
        "requestId": request.request_id,
        "sessionId": request.session_id,
        "idempotencyKey": request.idempotency_key,
        "state": state,
        "code": code,
        "message": _activity_label(message, "message", 160),
        "sentAt": _positive(sent_at, "sentAt"),
    }


def workspace_capabilities() -> dict[str, Any]:
    wiki_operations = available_wiki_operations()
    features = [
        "workspace-rejected-v1", "backpressure-v1", "plugin-update-v1",
        "host-runtime-diagnostics-v1",
    ]
    if wiki_operations:
        features.append("wiki.v1")
    return {
        "protocolVersion": 1,
        "pluginVersion": PLUGIN_VERSION,
        "features": features,
        "operations": sorted(WORKSPACE_OPERATIONS - WIKI_OPERATIONS | wiki_operations),
    }


def workspace_rejection(value: Any, *, sent_at: int) -> dict[str, Any] | None:
    """Correlate a rejected request without constructing a supported request.

    Called only after authenticated decryption and failed request validation.
    Never echo operation names, invalid payloads, or exception details.
    """
    if not isinstance(value, dict) or value.get("type") != "workspace.request":
        return None
    try:
        request_id = _opaque(value.get("requestId"), "requestId", 16, 128)
    except ValueError:
        return None
    operation = value.get("operation")
    unsupported = (
        type(value.get("version")) is int and value.get("version") == 1
        and isinstance(operation, str)
        and re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", operation) is not None
        and operation not in WORKSPACE_OPERATIONS
    )
    return {
        "version": 1,
        "type": "workspace.rejected",
        "requestId": request_id,
        "code": "unsupported_operation" if unsupported else "invalid_request",
        "message": (
            "This host does not support that operation."
            if unsupported else "This workspace request is invalid."
        ),
        "sentAt": _positive(sent_at, "sentAt"),
    }


def parse_backpressure(value: Any) -> tuple[str, int, int]:
    expected = {"version", "type", "id", "sequence", "retryAfterMs", "reason"}
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or type(value.get("version")) is not int
        or value.get("version") != 1
        or value.get("type") != "backpressure"
        or value.get("reason") != "storage_limit"
    ):
        raise ValueError("Loopdy Link backpressure is invalid")
    frame_id = _opaque(value.get("id"), "id", 16, 128)
    sequence = _positive(value.get("sequence"), "sequence")
    delay = _positive(value.get("retryAfterMs"), "retryAfterMs")
    if not 100 <= delay <= 30_000:
        raise ValueError("Loopdy Link backpressure delay is invalid")
    return frame_id, sequence, delay


def workspace_result(
    *,
    request: WorkspaceRequest,
    status: str,
    payload: dict[str, Any],
    sent_at: int,
    code: str | None = None,
    message: str | None = None,
) -> dict[str, Any]:
    if status not in {"completed", "failed", "conflict"}:
        raise ValueError("Loopdy Link workspace result status is invalid")
    if request.operation in AVAILABLE_WIKI_OPERATIONS:
        payload = bound_wiki_result(payload)
    projected = (
        _workspace_json_allowing_dashboard_cards(payload)
        if request.operation == "dashboard.load" and status == "completed"
        else _workspace_json_allowing_avatar_blobs(payload)
        if request.operation in {
            "agents.create",
            "agents.update",
            "agents.avatar.get",
        }
        else _workspace_json(
            payload,
            depth=0,
            allowed_sensitive_keys=(
                frozenset({"statusToken", "confirmationToken"})
                if request.operation.startswith("projects.git.")
                else frozenset()
            ),
        )
    )
    if not isinstance(projected, dict):
        raise ValueError("Loopdy Link workspace result payload is invalid")
    result: dict[str, Any] = {
        "version": 1,
        "type": "workspace.result",
        "requestId": request.request_id,
        "operation": request.operation,
        "status": status,
        "payload": projected,
        "sentAt": _positive(sent_at, "sentAt"),
    }
    if (code is None) != (message is None):
        raise ValueError("Loopdy Link workspace error fields are invalid")
    if code is not None and message is not None:
        if not re.fullmatch(r"[A-Za-z0-9_]{1,80}", code):
            raise ValueError("Loopdy Link workspace error code is invalid")
        result["code"] = code
        result["message"] = _activity_label(message, "message", 2_000)
    return result


def _project_git_workspace_payload(operation: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Loopdy Link Project Git payload is invalid")
    base_keys = {"agentId", "sessionId", "workspaceId"}
    suffix = operation.removeprefix("projects.git.")
    expected = {
        "capabilities": base_keys,
        "status": base_keys,
        "diff": base_keys | {"path", "side", "statusToken", "offset", "limit"},
        "prepare": base_keys | {"operation", "statusToken", "input"},
        "execute": base_keys
        | {
            "operation",
            "statusToken",
            "input",
            "confirmationToken",
            "idempotencyKey",
        },
    }.get(suffix)
    if expected is None or set(value) != expected:
        raise ValueError("Loopdy Link Project Git payload is invalid")
    projected: dict[str, Any] = {
        "agentId": _opaque(value.get("agentId"), "agentId", 1, 64),
        "sessionId": _session_coordinate(value.get("sessionId")),
        "workspaceId": _opaque(value.get("workspaceId"), "workspaceId", 1, 160),
    }
    if suffix == "diff":
        projected.update(
            {
                "path": _project_git_path(value.get("path")),
                "side": _project_git_choice(value.get("side"), {"staged", "worktree"}),
                "statusToken": _project_git_status_token(value.get("statusToken")),
                "offset": _bounded_integer(value.get("offset"), 0, 100_000),
                "limit": _bounded_integer(value.get("limit"), 1, 500),
            }
        )
    elif suffix in {"prepare", "execute"}:
        git_operation = _project_git_choice(
            value.get("operation"), {"stage", "commit", "fetch", "pull", "push"}
        )
        projected.update(
            {
                "operation": git_operation,
                "statusToken": _project_git_status_token(value.get("statusToken")),
                "input": _project_git_input(git_operation, value.get("input")),
            }
        )
        if suffix == "execute":
            projected["confirmationToken"] = _opaque(
                value.get("confirmationToken"), "confirmationToken", 16, 200
            )
            key = value.get("idempotencyKey")
            if not isinstance(key, str) or not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                key,
            ):
                raise ValueError("Loopdy Link Project Git idempotency key is invalid")
            projected["idempotencyKey"] = key
    return projected


def _project_git_input(operation: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Loopdy Link Project Git input is invalid")
    expected = {
        "stage": {"mode", "paths"},
        "commit": {"message"},
        "fetch": {"remote"},
        "pull": {"remote", "branch"},
        "push": {"remote", "branch"},
    }[operation]
    if set(value) != expected:
        raise ValueError("Loopdy Link Project Git input is invalid")
    if operation == "stage":
        raw_paths = value.get("paths")
        if not isinstance(raw_paths, list) or not 1 <= len(raw_paths) <= 500:
            raise ValueError("Loopdy Link Project Git paths are invalid")
        paths = [_project_git_path(path) for path in raw_paths]
        if len(set(paths)) != len(paths):
            raise ValueError("Loopdy Link Project Git paths are invalid")
        return {
            "mode": _project_git_choice(value.get("mode"), {"stage", "unstage"}),
            "paths": paths,
        }
    if operation == "commit":
        message = value.get("message")
        if (
            not isinstance(message, str)
            or not message.strip()
            or len(message.encode("utf-8")) > 10_000
            or any(ord(character) < 32 and character not in "\n\t" for character in message)
        ):
            raise ValueError("Loopdy Link Project Git commit message is invalid")
        return {"message": message}
    remote = _project_git_ref_name(value.get("remote"), "remote")
    result = {"remote": remote}
    if operation in {"pull", "push"}:
        result["branch"] = _project_git_ref_name(value.get("branch"), "branch")
    return result


def _project_git_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 4_096
        or value.startswith(("/", "\\", "-"))
        or "\\" in value
        or ":" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or any(ord(character) < 32 for character in value)
        or "://" in value
    ):
        raise ValueError("Loopdy Link Project Git path is invalid")
    return value


def _project_git_ref_name(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 180
        or value.startswith(("-", "/"))
        or value.endswith(("/", "."))
        or ".." in value
        or ":" in value
        or "\\" in value
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        raise ValueError(f"Loopdy Link Project Git {label} is invalid")
    return value


def _project_git_choice(value: Any, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError("Loopdy Link Project Git choice is invalid")
    return value


def _project_git_status_token(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("Loopdy Link Project Git status token is invalid")
    return value


def _bounded_integer(value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError("Loopdy Link Project Git page is invalid")
    return value


def _workspace_json(
    value: Any,
    *,
    depth: int,
    allowed_sensitive_keys: frozenset[str] = frozenset(),
) -> Any:
    if depth > 8:
        raise ValueError("Loopdy Link workspace payload is invalid")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Loopdy Link workspace payload is invalid")
        return value
    if isinstance(value, str):
        if len(value.encode("utf-8")) > 256_000 or any(
            ord(character) < 32 and character not in "\n\r\t"
            for character in value
        ):
            raise ValueError("Loopdy Link workspace payload is invalid")
        return value
    if isinstance(value, list):
        if len(value) > 500:
            raise ValueError("Loopdy Link workspace payload is invalid")
        projected = [
            _workspace_json(
                item,
                depth=depth + 1,
                allowed_sensitive_keys=allowed_sensitive_keys,
            )
            for item in value
        ]
    elif isinstance(value, dict):
        if len(value) > 200:
            raise ValueError("Loopdy Link workspace payload is invalid")
        projected = {}
        for key, item in value.items():
            if (
                not isinstance(key, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key)
            ):
                raise ValueError("Loopdy Link workspace payload key is invalid")
            canonical = "".join(character for character in key.lower() if character.isalnum())
            if (
                canonical.startswith("gateway")
                or (canonical.endswith("token") and key not in allowed_sensitive_keys)
                or any(
                    forbidden in canonical
                    for forbidden in (
                        "authorization",
                        "cookie",
                        "credential",
                        "password",
                        "secret",
                    )
                )
            ):
                raise ValueError("Loopdy Link workspace payload key is invalid")
            projected[key] = _workspace_json(
                item,
                depth=depth + 1,
                allowed_sensitive_keys=allowed_sensitive_keys,
            )
    else:
        raise ValueError("Loopdy Link workspace payload is invalid")
    if depth == 0 and len(
        json.dumps(
            projected,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ) > 196_608:
        raise ValueError("Loopdy Link workspace payload is invalid")
    return projected


def _workspace_json_allowing_dashboard_cards(value: Any) -> Any:
    """Validate optional card documents separately from their Inbox wrappers.

    Only this response-owned path gets a separate bounded depth budget. All
    card keys still pass secret screening, and the aggregate byte cap remains
    unchanged. A bad optional card cannot make ordinary events unavailable.
    """
    if not isinstance(value, dict) or not isinstance(value.get("events"), list):
        return _workspace_json(value, depth=0)
    events = value["events"]
    if len(events) > 500:
        raise ValueError("Loopdy Link workspace payload is invalid")
    stripped_events = []
    cards = []
    for index, event in enumerate(events):
        if not isinstance(event, dict) or not isinstance(event.get("detail"), dict):
            stripped_events.append(event)
            continue
        detail = dict(event["detail"])
        card = detail.pop("generative_ui", None)
        stripped_events.append({**event, "detail": detail})
        if card is not None:
            try:
                screened = _workspace_json(card, depth=0)
                cards.append((index, validate_rendered_envelope(screened)))
            except (TypeError, ValueError):
                continue
    projected = _workspace_json({**value, "events": stripped_events}, depth=0)
    for index, card in cards:
        detail = projected["events"][index]["detail"]
        detail["generative_ui"] = card
        if len(json.dumps(projected, ensure_ascii=False, separators=(",", ":"),
                          sort_keys=True).encode("utf-8")) > 196_608:
            del detail["generative_ui"]
    return projected


def _workspace_json_allowing_skill_archive(value: Any) -> Any:
    if not isinstance(value, dict):
        raise ValueError("Loopdy Link workspace payload is invalid")
    encoded = value.get("dataBase64")
    if not isinstance(encoded, str) or not 1 <= len(encoded) <= 2_100_000:
        raise ValueError("Loopdy Link skill archive is invalid")
    try:
        base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Loopdy Link skill archive is invalid") from exc
    placeholder = dict(value)
    placeholder["dataBase64"] = "AA=="
    _workspace_json(placeholder, depth=0)
    return value


def _workspace_json_allowing_avatar_blobs(value: Any) -> Any:
    projected = _workspace_json(_workspace_avatar_placeholder_value(value), depth=0)
    _validate_workspace_avatar_blobs(value)
    return value if projected != value else projected


def _workspace_avatar_placeholder_value(value: Any) -> Any:
    if isinstance(value, dict):
        projected = {}
        for key, item in value.items():
            if key == "avatar" and item is not None:
                _avatar_payload(item)
                projected[key] = {
                    "mimeType": "image/png",
                    "byteCount": 1,
                    "sha256": "validated-avatar-sha256",
                    "data": "data:image/png;base64,AA==",
                }
            else:
                projected[key] = _workspace_avatar_placeholder_value(item)
        return projected
    if isinstance(value, list):
        return [_workspace_avatar_placeholder_value(item) for item in value]
    return value


def _validate_workspace_avatar_blobs(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "avatar" and item is not None:
                _avatar_payload(item)
            else:
                _validate_workspace_avatar_blobs(item)
    elif isinstance(value, list):
        for item in value:
            _validate_workspace_avatar_blobs(item)


def _avatar_payload(value: Any) -> dict[str, Any]:
    avatar = value
    if not isinstance(avatar, dict) or set(avatar) != {"mimeType", "byteCount", "sha256", "data"}:
        raise ValueError("Loopdy Link workspace payload is invalid")
    if avatar.get("mimeType") not in {"image/png", "image/jpeg", "image/webp"}:
        raise ValueError("Loopdy Link workspace payload is invalid")
    byte_count = avatar.get("byteCount")
    if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count <= 0:
        raise ValueError("Loopdy Link workspace payload is invalid")
    sha256 = avatar.get("sha256")
    if not isinstance(sha256, str) or not 16 <= len(sha256) <= 128:
        raise ValueError("Loopdy Link workspace payload is invalid")
    data = avatar.get("data")
    if not isinstance(data, str) or len(data) > MAX_AVATAR_WORKSPACE_PLAINTEXT_BYTES:
        raise ValueError("Loopdy Link workspace payload is invalid")
    prefix = f"data:{avatar['mimeType']};base64,"
    if not data.startswith(prefix):
        raise ValueError("Loopdy Link workspace payload is invalid")
    try:
        blob = base64.b64decode(data.removeprefix(prefix), validate=True)
    except ValueError as exc:
        raise ValueError("Loopdy Link workspace payload is invalid") from exc
    if len(blob) != byte_count:
        raise ValueError("Loopdy Link workspace payload is invalid")
    return avatar


def _opaque(value: Any, field: str, minimum: int, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or len(value) < minimum
        or len(value) > maximum
        or not _OPAQUE.fullmatch(value)
    ):
        raise ValueError(f"Loopdy Link {field} is invalid")
    return value


def _session_coordinate(value: Any, field: str = "sessionId") -> str:
    """Validate the canonical Hermes session coordinate used across Link."""
    return _opaque(value, field, 1, 180)


def _label(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Loopdy Link {field} is invalid")
    normalized = " ".join(value.split())
    allowed_punctuation = set(" .,'’()&+-_")
    if (
        not normalized
        or normalized != value.strip()
        or len(normalized) > maximum
        or any(not (character.isalnum() or character in allowed_punctuation) for character in normalized)
    ):
        raise ValueError(f"Loopdy Link {field} is invalid")
    return normalized


def _activity_label(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Loopdy Link {field} is invalid")
    normalized = " ".join(value.split())
    if (
        not normalized
        or normalized != value.strip()
        or len(normalized) > maximum
        or not normalized.isprintable()
    ):
        raise ValueError(f"Loopdy Link {field} is invalid")
    return normalized


def _activity_detail(value: Any, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(not character.isprintable() and character not in "\n\t" for character in value)
    ):
        raise ValueError(f"Loopdy Link {field} is invalid")
    return value


def _picker_title(value: Any, field: str, maximum: int) -> str:
    """Project Hermes' Markdown command title into native picker text.

    Hermes' interactive reasoning title is formatted for text surfaces (for
    example ``**Effort:** `medium` `` and line breaks). Loopdy renders this
    title as native UI, so remove those lightweight delimiters, normalize
    whitespace, and retain the same printable-label validation.
    """
    if not isinstance(value, str):
        raise ValueError(f"Loopdy Link {field} is invalid")
    plain = re.sub(r"[*_`~]", "", value)
    return _activity_label(" ".join(plain.split()), field, maximum)


def _picker_result_message(value: Any, field: str, maximum: int) -> str:
    """Project Hermes' text response into the native picker's single-line status."""
    if not isinstance(value, str):
        raise ValueError(f"Loopdy Link {field} is invalid")
    return _activity_label(" ".join(value.split()), field, maximum)


def _picker_identifier(value: Any, field: str, minimum: int, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or value != value.strip()
        or any(character.isspace() or not character.isprintable() for character in value)
    ):
        raise ValueError(f"Loopdy Link {field} is invalid")
    return value


def _model_picker_identifier(value: Any, field: str, minimum: int, maximum: int) -> str:
    """Validate an opaque model name, including named presets with spaces."""
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or value != value.strip()
        or not value.isprintable()
    ):
        raise ValueError(f"Loopdy Link {field} is invalid")
    return value


def _text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValueError(f"Loopdy Link {field} is invalid")
    return value


def _form_submission_values(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or len(value) > 12:
        raise ValueError("Loopdy Link form values are invalid")
    if len(canonical_json(value).encode("utf-8")) > 8_192:
        raise ValueError("Loopdy Link form values are invalid")
    for key, candidate in value.items():
        if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", key):
            raise ValueError("Loopdy Link form value key is invalid")
        values = candidate if isinstance(candidate, list) else [candidate]
        if len(values) > 10:
            raise ValueError("Loopdy Link form values are invalid")
        for item in values:
            if item is None or isinstance(item, (dict, list)):
                raise ValueError("Loopdy Link form values are invalid")
            if isinstance(item, str) and (len(item) > 2_000 or "\x00" in item):
                raise ValueError("Loopdy Link form values are invalid")
            if isinstance(item, (int, float)) and not isinstance(item, bool):
                if not math.isfinite(float(item)) or abs(float(item)) > 1_000_000_000_000:
                    raise ValueError("Loopdy Link form values are invalid")
            elif not isinstance(item, (str, bool)):
                raise ValueError("Loopdy Link form values are invalid")
    return dict(value)


def _positive(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"Loopdy Link {field} is invalid")
    return value


def _nonnegative(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"Loopdy Link {field} is invalid")
    return value


def _decode_b64url(value: str) -> bytes:
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, UnicodeEncodeError) as error:
        raise ValueError("Loopdy Link base64url is invalid") from error
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ValueError("Loopdy Link base64url is invalid")
    return decoded


def _b64url(value: Any, field: str, expected_length: int) -> str:
    encoded = _opaque(value, field, 1, 2_048)
    if len(_decode_b64url(encoded)) != expected_length:
        raise ValueError(f"Loopdy Link {field} is invalid")
    return encoded


def _command_name(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 96
        or value.startswith("/")
        or any(
            not (character.islower() or character.isdigit() or character in "_-")
            for character in value
        )
    ):
        raise ValueError(f"Loopdy Link command {field} is invalid")
    return value


def _command_args_hint(value: Any) -> str:
    if value == "":
        return ""
    return _activity_label(value, "argsHint", 240)


def _personality_name(value: Any, *, allows_neutral: bool) -> str:
    if not isinstance(value, str):
        raise ValueError("Loopdy Link personality name is invalid")
    name = value.strip().lower()
    if allows_neutral and name in {"", "none", "default", "neutral"}:
        return ""
    if (
        not 1 <= len(name) <= 64
        or name in {"none", "default", "neutral"}
        or any(
            not (character.islower() or character.isdigit() or character in "_-")
            for character in name
        )
    ):
        raise ValueError("Loopdy Link personality name is invalid")
    return name


def _personality_definition(value: Any, *, response: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Loopdy Link personality definition is invalid")
    required = {"name", "description", "systemPrompt", "tone", "style"}
    optional = {"originalName"}
    if response:
        required |= {"builtIn", "customized"}
        optional = set()
    if not required.issubset(value) or not set(value).issubset(required | optional):
        raise ValueError("Loopdy Link personality definition is invalid")
    description = _personality_line(value.get("description"), "description", 240)
    tone = _personality_line(value.get("tone"), "tone", 240)
    style = _personality_line(value.get("style"), "style", 240)
    prompt = value.get("systemPrompt")
    if (
        not isinstance(prompt, str)
        or not prompt.strip()
        or len(prompt) > 20_000
        or "\x00" in prompt
    ):
        raise ValueError("Loopdy Link personality systemPrompt is invalid")
    result: dict[str, Any] = {
        "name": _personality_name(value.get("name"), allows_neutral=False),
        "description": description,
        "systemPrompt": prompt.strip(),
        "tone": tone,
        "style": style,
    }
    if response:
        if not isinstance(value.get("builtIn"), bool) or not isinstance(
            value.get("customized"), bool
        ):
            raise ValueError("Loopdy Link personality source is invalid")
        result["builtIn"] = value["builtIn"]
        result["customized"] = value["customized"]
    elif "originalName" in value:
        result["originalName"] = _personality_name(
            value.get("originalName"), allows_neutral=False
        )
    return result


def _personality_line(value: Any, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or value != value.strip()
        or (value and not value.isprintable())
    ):
        raise ValueError(f"Loopdy Link personality {field} is invalid")
    return value


__all__ = [
    "AttachmentChunk",
    "AttachmentReference",
    "CommandCatalogRequest",
    "EncryptedFrame",
    "GenerativeUIFormSubmission",
    "PickerOpen",
    "PickerSelection",
    "PersonalityRequest",
    "RelayReady",
    "SessionForkRequest",
    "UserMessage",
    "VoiceSpeakRequest",
    "WorkspaceRequest",
    "AVAILABLE_WIKI_OPERATIONS",
    "WORKSPACE_OPERATIONS",
    "activity_event",
    "assistant_message",
    "choice_picker_payload",
    "command_catalog_payload",
    "generative_ui_event",
    "generative_ui_form_result",
    "model_picker_payload",
    "notification_event",
    "parse_encrypted_frame",
    "parse_generative_ui_form_submission",
    "parse_attachment_chunk",
    "parse_picker_open",
    "parse_picker_selection",
    "parse_personality_request",
    "parse_command_catalog_request",
    "parse_relay_ready",
    "parse_session_fork_request",
    "parse_user_message",
    "parse_voice_speak_request",
    "parse_workspace_request",
    "picker_result",
    "personality_catalog_payload",
    "session_context",
    "session_subagents",
    "session_todos",
    "session_fork_result",
    "verified_fork_prefix",
    "voice_audio_chunks",
    "voice_speak_error",
    "workspace_result",
    "workspace_capabilities",
    "workspace_rejection",
    "parse_backpressure",
]
