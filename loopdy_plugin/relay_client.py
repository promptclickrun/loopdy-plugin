"""Authenticated HTTPS client for the managed Loopdy relay."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import time
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .provider import DeliveryError, DeliveryReceipt, LiveActivityState, PushMessage
from .relay_crypto import (
    alert_aad,
    alert_signature_input,
    b64url_decode,
    b64url_encode,
    canonical_json_bytes,
    encrypt_alert,
    key_id,
    public_key_from_x963,
    public_key_bytes,
    request_signing_input,
    verify_p1363,
)


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_TOPIC = re.compile(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
_LIVE_ACTIVITY_TOPIC_SUFFIX = ".push-type.liveactivity"


def _base_topic(value: Any) -> bool:
    return (
        type(value) is str
        and _TOPIC.fullmatch(value) is not None
        and not value.endswith(_LIVE_ACTIVITY_TOPIC_SUFFIX)
    )
_MAX_SAFE_REVISION = 9_007_199_254_740_991
_MAX_TIMESTAMP = 9_999_999_999
_RELAY_PATHS = {
    "device_register": "/v1/devices/register",
    "sender_ack": "/v1/devices/ack-sender-keys",
    "device_revoke": "/v1/devices/revoke",
    "tenant_revoke": "/v1/tenants/revoke",
    "tenant_delete": "/v1/tenants/delete",
    "delivery": "/v1/deliveries",
    "live_register": "/v1/live-activities/register",
    "live_revoke": "/v1/live-activities/revoke",
    "health": "/health",
}


def _identifier(value: Any, name: str, maximum: int = 180) -> str:
    if type(value) is not str:
        raise ValueError(f"{name} must be a printable ASCII protocol identifier")
    normalized = value
    if (
        len(normalized) > maximum
        or not normalized.isascii()
        or _IDENTIFIER.fullmatch(normalized) is None
    ):
        raise ValueError(f"{name} must be a printable ASCII protocol identifier")
    return normalized


def _revision(value: Any, name: str = "revision") -> int:
    if type(value) is not int or value <= 0 or value > _MAX_SAFE_REVISION:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _positive_integer(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0 or value > _MAX_TIMESTAMP:
        raise ValueError(f"{name} must be a positive integer")
    return value


def validate_registration_response(
    response: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    tenant_id: str,
    sender_keyring: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a registration response against local request and sender pins."""
    keys = {
        "version",
        "status",
        "tenant_id",
        "device_id",
        "recipient_key_id",
        "revision",
        "lease_expires",
        "sender_key_revision",
        "current_sender_key",
        "previous_sender_key",
    }
    if (
        set(response) != keys
        or type(response.get("version")) is not int
        or response.get("version") != 1
        or response.get("status") not in {"accepted", "duplicate"}
    ):
        raise ValueError("Relay registration response is invalid")
    if (
        response.get("tenant_id") != tenant_id
        or response.get("device_id") != request.get("device_id")
        or response.get("recipient_key_id") != request.get("recipient_key_id")
        or _revision(response.get("revision")) != _revision(request.get("revision"))
        or _positive_integer(response.get("lease_expires"), "lease_expires")
        != _positive_integer(request.get("lease_expires"), "lease_expires")
    ):
        raise ValueError("Relay registration response does not match the request")
    if (
        _revision(response.get("sender_key_revision"), "sender key revision")
        != sender_keyring.get("revision")
        or response.get("current_sender_key") != sender_keyring.get("current")
        or response.get("previous_sender_key") != sender_keyring.get("previous")
    ):
        raise ValueError("Relay registration response sender pins do not match this plugin")
    return dict(response)


def _idempotency_key(value: Any) -> str:
    if type(value) is not str:
        raise ValueError("idempotency_key must be a lowercase UUID")
    normalized = value
    if _UUID.fullmatch(normalized) is None:
        raise ValueError("idempotency_key must be a lowercase UUID")
    return normalized


def _display_text(value: Any, name: str, maximum_bytes: int) -> str:
    if type(value) is not str or unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{name} must use Unicode NFC")
    if len(value.encode("utf-8")) > maximum_bytes:
        raise ValueError(f"{name} exceeds {maximum_bytes} UTF-8 bytes")
    return value


def _strict_keys(value: Mapping[str, Any], allowed: set[str], required: set[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("Relay request must be an object")
    body = dict(value)
    extras = set(body) - allowed
    missing = required - set(body)
    if extras or missing:
        raise ValueError("Relay request contains unknown or missing fields")
    return body


def normalize_relay_operation(
    operation: str,
    value: Mapping[str, Any],
    *,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Validate and normalize a revisioned relay operation without I/O.

    The service journals exactly this route contract before it touches a
    provider.  Keyring-dependent sender acknowledgement checks remain in the
    client immediately before network I/O.
    """
    normalized_operation = "revoke_device" if operation == "device_revoke" else operation
    routes: dict[str, set[str]] = {
        "register_device": {
            "version", "device_id", "revision", "issued", "lease_expires", "provider",
            "recipient_public_key", "recipient_key_id", "push_token", "environment", "topic",
            "label", "groups", "idempotency_key",
        },
        "acknowledge_sender_keys": {
            "version", "device_id", "revision", "sender_key_revision",
            "acknowledged_sender_key_ids", "idempotency_key",
        },
        "revoke_device": {"version", "device_id", "revision", "idempotency_key"},
        "register_live_activity": {
            "version", "activity_id", "device_id", "session_ref", "push_token", "environment",
            "topic", "revision", "timestamp", "lease_expires", "idempotency_key",
        },
        "revoke_live_activity": {"version", "activity_id", "revision", "timestamp", "idempotency_key"},
        "revoke_tenant": {"version", "tenant_id", "revision", "idempotency_key"},
        "delete_tenant": {"version", "tenant_id", "revision", "confirmation", "idempotency_key"},
    }
    allowed = routes.get(normalized_operation)
    if allowed is None:
        raise ValueError("Unknown relay operation")
    normalized = _strict_keys(value, allowed, allowed)
    if type(normalized["version"]) is not int or normalized["version"] != 1:
        raise ValueError("Relay protocol version must be 1")
    _revision(normalized["revision"])
    _idempotency_key(normalized["idempotency_key"])

    if normalized_operation in {"register_device", "acknowledge_sender_keys", "revoke_device"}:
        _identifier(normalized["device_id"], "device_id")
    if normalized_operation == "register_device":
        if normalized["provider"] != "relay":
            raise ValueError("Relay registration provider must be relay")
        issued = _positive_integer(normalized["issued"], "issued")
        lease = _positive_integer(normalized["lease_expires"], "lease_expires")
        if lease <= issued or lease - issued > 2_592_000:
            raise ValueError("Relay registration lease exceeds 30 days")
        public_key = b64url_decode(normalized["recipient_public_key"], expected_length=65)
        if key_id(public_key) != normalized["recipient_key_id"]:
            raise ValueError("Relay registration recipient key does not match")
        b64url_decode(normalized["recipient_key_id"], expected_length=32)
        if re.fullmatch(r"(?:[0-9a-f]{2}){1,256}", str(normalized["push_token"])) is None:
            raise ValueError("Relay APNs token is invalid")
        if normalized["environment"] not in {"production", "sandbox"}:
            raise ValueError("Relay APNs environment is invalid")
        if not _base_topic(normalized["topic"]):
            raise ValueError("Relay registration bundle topic is invalid")
        _display_text(normalized["label"], "label", 120)
        if type(normalized["groups"]) is not list or len(normalized["groups"]) > 50:
            raise ValueError("Relay registration groups are invalid")
        for group in normalized["groups"]:
            _identifier(group, "group", 80)
    elif normalized_operation == "acknowledge_sender_keys":
        _revision(normalized["sender_key_revision"], "sender_key_revision")
        keys = normalized["acknowledged_sender_key_ids"]
        if type(keys) is not list or not 1 <= len(keys) <= 2 or len(set(keys)) != len(keys):
            raise ValueError("Relay sender-key acknowledgement is invalid")
        for key in keys:
            b64url_decode(key, expected_length=32)
    elif normalized_operation == "register_live_activity":
        _identifier(normalized["activity_id"], "activity_id")
        _identifier(normalized["device_id"], "device_id")
        if len(b64url_decode(normalized["session_ref"])) > 64:
            raise ValueError("Live Activity session reference exceeds 64 bytes")
        if re.fullmatch(r"(?:[0-9a-f]{2}){1,256}", str(normalized["push_token"])) is None:
            raise ValueError("Live Activity token is invalid")
        if normalized["environment"] not in {"production", "sandbox"}:
            raise ValueError("Live Activity environment is invalid")
        if not _base_topic(normalized["topic"]):
            raise ValueError("Live Activity bundle topic is invalid")
        timestamp = _positive_integer(normalized["timestamp"], "timestamp")
        lease = _positive_integer(normalized["lease_expires"], "lease_expires")
        if lease <= timestamp or lease - timestamp > 28_800:
            raise ValueError("Live Activity registration lease exceeds eight hours")
    elif normalized_operation == "revoke_live_activity":
        _identifier(normalized["activity_id"], "activity_id")
        _positive_integer(normalized["timestamp"], "timestamp")
    elif normalized_operation in {"revoke_tenant", "delete_tenant"}:
        _identifier(normalized["tenant_id"], "tenant_id")
        if normalized_operation == "delete_tenant" and normalized["confirmation"] != "delete":
            raise ValueError("Tenant deletion requires exact confirmation")
        if tenant_id is not None and normalized["tenant_id"] != tenant_id:
            raise ValueError("Relay operation tenant does not match configuration")
    return normalized


@dataclass(frozen=True)
class RelayConfig:
    base_url: str
    tenant_id: str
    credential_key_id: str
    hmac_secret_reference: str
    signing_key_secret_reference: str

    def __post_init__(self) -> None:
        parsed = urlsplit(str(self.base_url or ""))
        if (
            len(self.base_url) > 300
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("Relay base URL must be a bounded HTTPS origin")
        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        object.__setattr__(
            self,
            "credential_key_id",
            _identifier(self.credential_key_id, "credential_key_id"),
        )
        _validate_secret_reference(self.hmac_secret_reference)
        _validate_secret_reference(self.signing_key_secret_reference)

    def stored_values(self) -> dict[str, str]:
        return {
            "base_url": self.base_url,
            "tenant_id": self.tenant_id,
            "credential_key_id": self.credential_key_id,
            "hmac_secret_reference": self.hmac_secret_reference,
            "signing_key_secret_reference": self.signing_key_secret_reference,
        }


@dataclass(frozen=True)
class RelayHttpResponse:
    status_code: int
    body: bytes


class RelayOutcomeUnknown(RuntimeError):
    pass


class _HttpxTransport:
    def __init__(self) -> None:
        self._client = httpx.Client(timeout=8, follow_redirects=False)

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
        follow_redirects: bool,
    ) -> RelayHttpResponse:
        try:
            response = self._client.request(
                method,
                url,
                headers=dict(headers),
                content=body,
                timeout=timeout,
                follow_redirects=follow_redirects,
            )
        except (httpx.TransportError, OSError) as error:
            raise RelayOutcomeUnknown("relay_transport_outcome_unknown") from error
        return RelayHttpResponse(int(response.status_code), bytes(response.content))

    def close(self) -> None:
        self._client.close()


def _validate_secret_reference(reference: Any) -> str:
    normalized = str(reference or "")
    if normalized.startswith("env:"):
        name = normalized[4:]
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", name):
            raise ValueError("Environment secret reference is invalid")
        return normalized
    if normalized.startswith("file:"):
        path = Path(normalized[5:])
        if not path.is_absolute() or "\x00" in str(path):
            raise ValueError("File secret reference must be absolute")
        return normalized
    raise ValueError("Secret references must use env:NAME or file:/absolute/path")


def resolve_secret_reference(
    reference: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> bytes:
    normalized = _validate_secret_reference(reference)
    if normalized.startswith("env:"):
        value = (environ if environ is not None else os.environ).get(normalized[4:], "")
        if not value:
            raise ValueError("Referenced environment secret is unavailable")
        return value.encode("utf-8")
    path = Path(normalized[5:]).resolve()
    try:
        metadata = path.stat()
    except OSError as error:
        raise ValueError("Referenced secret file is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("Referenced secret file must be a regular file")
    if os.name == "posix":
        if metadata.st_uid != os.geteuid():
            raise ValueError("Referenced secret file must be owned by the current user")
        if stat.S_IMODE(metadata.st_mode) & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError("Referenced secret file permissions must be owner-only")
    try:
        value = path.read_bytes()
    except OSError as error:
        raise ValueError("Referenced secret file is unavailable") from error
    if not value or len(value) > 65_536:
        raise ValueError("Referenced secret file has an invalid size")
    return value


def local_sender_key_set(
    signing_key_secret_reference: str,
    *,
    secret_resolver: Callable[[str], bytes] = resolve_secret_reference,
    now: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """Load only the local public sender-key pins for offline validation."""
    return _load_signing_keyring(
        secret_resolver(signing_key_secret_reference), now=int(now())
    ).public_value()


@dataclass(frozen=True)
class _SigningKey:
    private_key: ec.EllipticCurvePrivateKey
    state: str
    not_before: int
    not_after: int

    @property
    def public_key(self) -> bytes:
        return public_key_bytes(self.private_key.public_key())

    @property
    def key_id(self) -> str:
        return key_id(self.public_key)

    def public_value(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "public_key": b64url_encode(self.public_key),
            "state": self.state,
            "not_before": self.not_before,
            "not_after": self.not_after,
        }


@dataclass(frozen=True)
class _SigningKeyring:
    revision: int
    current: _SigningKey
    previous: _SigningKey | None

    def public_value(self) -> dict[str, Any]:
        return {
            "version": 1,
            "revision": self.revision,
            "current": self.current.public_value(),
            "previous": None if self.previous is None else self.previous.public_value(),
        }

    def acknowledged_key(self, key_ids: list[str], *, now: int) -> _SigningKey:
        acknowledged = set(key_ids)
        for candidate in (self.current, self.previous):
            if (
                candidate is not None
                and candidate.key_id in acknowledged
                and candidate.not_before <= now <= candidate.not_after
            ):
                return candidate
        raise ValueError("Device has not acknowledged an active relay sender key")


def _load_private_key(value: bytes) -> ec.EllipticCurvePrivateKey:
    try:
        key = serialization.load_pem_private_key(value, password=None)
    except (TypeError, ValueError) as error:
        raise ValueError("Relay signing key reference must contain an unencrypted P-256 key") from error
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("Relay signing key reference must contain an unencrypted P-256 key")
    return key


def _load_signing_keyring(value: bytes, *, now: int) -> _SigningKeyring:
    if not value.lstrip().startswith(b"{"):
        raise ValueError("Relay signing secret must be a versioned keyring")
    try:
        parsed = json.loads(value)
        if set(parsed) != {"version", "revision", "current", "previous"}:
            raise ValueError
        if type(parsed["version"]) is not int or parsed["version"] != 1:
            raise ValueError
        revision = _revision(parsed["revision"], "sender key revision")
        current = _keyring_item(parsed["current"], "current")
        previous = None if parsed["previous"] is None else _keyring_item(parsed["previous"], "previous")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("Relay signing keyring secret is invalid") from error
    if previous is not None:
        if previous.key_id == current.key_id or previous.not_after - current.not_before > 604_800:
            raise ValueError("Relay signing key overlap is invalid")
    return _SigningKeyring(revision=revision, current=current, previous=previous)


def _keyring_item(value: Any, state: str) -> _SigningKey:
    if not isinstance(value, dict) or set(value) != {"pem", "not_before", "not_after"}:
        raise ValueError("Relay signing keyring entry is invalid")
    if type(value["pem"]) is not str:
        raise ValueError("Relay signing keyring entry is invalid")
    key = _SigningKey(
        _load_private_key(value["pem"].encode("utf-8")),
        state,
        _positive_integer(value["not_before"], "not_before"),
        _positive_integer(value["not_after"], "not_after"),
    )
    if key.not_before <= 0 or key.not_after <= key.not_before or key.not_after - key.not_before > 2_678_400:
        raise ValueError("Relay signing key validity is invalid")
    return key


class RelayClient:
    def __init__(
        self,
        config: RelayConfig,
        *,
        transport: Any | None = None,
        secret_resolver: Callable[[str], bytes] = resolve_secret_reference,
        now: Callable[[], float] = time.time,
        random_bytes: Callable[[int], bytes] = os.urandom,
        timeout: float = 8,
    ) -> None:
        self.config = config
        self._transport = transport or _HttpxTransport()
        self._secret_resolver = secret_resolver
        self._now = now
        self._random_bytes = random_bytes
        self._timeout = min(10.0, max(1.0, float(timeout)))

    def sender_key_set(self) -> dict[str, Any]:
        return local_sender_key_set(
            self.config.signing_key_secret_reference,
            secret_resolver=self._secret_resolver,
            now=self._now,
        )

    def validate_local_credentials(self) -> None:
        self._hmac_key()
        keyring = self._keyring()
        now = int(self._now())
        if not keyring.current.not_before <= now <= keyring.current.not_after:
            raise ValueError("Relay current signing key is outside its validity window")

    def select_sender_key_id(self, acknowledged_sender_key_ids: list[str]) -> str:
        return self._keyring().acknowledged_key(
            acknowledged_sender_key_ids,
            now=int(self._now()),
        ).key_id

    def deliver_alert(
        self,
        *,
        device: Mapping[str, Any],
        message: PushMessage,
        delivery_id: str,
        idempotency_key: str,
        ephemeral_private_key: ec.EllipticCurvePrivateKey | None = None,
        salt: bytes | None = None,
        nonce: bytes | None = None,
        request_body: Mapping[str, Any] | None = None,
    ) -> DeliveryReceipt:
        if request_body is None:
            body = self.prepare_alert(
                device=device,
                message=message,
                delivery_id=delivery_id,
                idempotency_key=idempotency_key,
                ephemeral_private_key=ephemeral_private_key,
                salt=salt,
                nonce=nonce,
            )
        else:
            if not request_body:
                raise ValueError("Frozen alert request is invalid")
            body = request_body
            body = _strict_keys(body, {"device_id", "envelope", "idempotency_key", "sound"}, {"device_id", "envelope", "idempotency_key"})
            if (
                _identifier(body["device_id"], "device_id") != _identifier(device.get("device_id"), "device_id")
                or _idempotency_key(body["idempotency_key"]) != _idempotency_key(idempotency_key)
            ):
                raise ValueError("Frozen alert request does not match current coordinates")
            if "sound" in body and type(body["sound"]) is not bool:
                raise ValueError("Frozen alert request is invalid")
            self._validate_frozen_alert_body(body, device=device, delivery_id=delivery_id)
        response = self._request("POST", _RELAY_PATHS["delivery"], body, attempts=2)
        accepted = self._accepted_response(
            response,
            expected_id=_identifier(delivery_id, "delivery_id"),
            expected_revision=_revision(device.get("revision"), "target revision"),
            allowed_statuses={"accepted", "duplicate"},
        )
        return DeliveryReceipt(delivery_id=accepted["id"])

    def _validate_frozen_alert_body(
        self,
        body: Mapping[str, Any],
        *,
        device: Mapping[str, Any],
        delivery_id: str,
    ) -> None:
        envelope = body.get("envelope")
        expected_fields = {
            "v", "kind", "delivery_id", "event_ref", "recipient_key_id", "sender_key_id",
            "issued", "expires", "ephemeral_public_key", "salt", "nonce", "ciphertext",
            "tag", "signature",
        }
        if not isinstance(envelope, Mapping) or set(envelope) != expected_fields:
            raise ValueError("Frozen alert envelope is invalid")
        if envelope.get("v") != 1 or envelope.get("kind") != "alert":
            raise ValueError("Frozen alert envelope is invalid")
        if _identifier(envelope.get("delivery_id"), "delivery_id") != _identifier(delivery_id, "delivery_id"):
            raise ValueError("Frozen alert envelope does not match delivery coordinates")
        recipient = b64url_decode(device.get("recipient_public_key"), expected_length=65)
        recipient_key_id = b64url_decode(envelope.get("recipient_key_id"), expected_length=32)
        if key_id(recipient) != b64url_encode(recipient_key_id):
            raise ValueError("Frozen alert envelope recipient key does not match device")
        event_ref = b64url_decode(envelope.get("event_ref"), expected_length=32)
        sender_key_id = b64url_decode(envelope.get("sender_key_id"), expected_length=32)
        ephemeral = b64url_decode(envelope.get("ephemeral_public_key"), expected_length=65)
        public_key_from_x963(ephemeral)
        salt = b64url_decode(envelope.get("salt"), expected_length=32)
        nonce = b64url_decode(envelope.get("nonce"), expected_length=12)
        ciphertext = b64url_decode(envelope.get("ciphertext"))
        if not 1 <= len(ciphertext) <= 1_200:
            raise ValueError("Frozen alert ciphertext is invalid")
        tag = b64url_decode(envelope.get("tag"), expected_length=16)
        signature = b64url_decode(envelope.get("signature"), expected_length=64)
        issued = _positive_integer(envelope.get("issued"), "issued")
        expires = _positive_integer(envelope.get("expires"), "expires")
        if expires <= issued or expires - issued > 900:
            raise ValueError("Frozen alert expiry is invalid")
        recipient_id = b64url_encode(recipient_key_id)
        sender_id = b64url_encode(sender_key_id)
        aad = alert_aad(
            tenant_id=self.config.tenant_id,
            device_id=_identifier(device.get("device_id"), "device_id"),
            delivery_id=_identifier(delivery_id, "delivery_id"),
            event_ref=b64url_encode(event_ref),
            recipient_key_id=recipient_id,
            sender_key_id=sender_id,
            issued=issued,
            expires=expires,
        )
        signed = alert_signature_input(
            aad=aad,
            ephemeral_public_key=ephemeral,
            salt=salt,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )
        keyring = self._keyring()
        candidates = [keyring.current, keyring.previous]
        for candidate in candidates:
            if candidate is not None and candidate.key_id == sender_id:
                try:
                    verify_p1363(candidate.private_key.public_key(), signature, signed)
                except Exception as error:
                    raise ValueError("Frozen alert envelope signature is invalid") from error
                return
        raise ValueError("Frozen alert envelope sender key is not configured")

    def prepare_alert(
        self,
        *,
        device: Mapping[str, Any],
        message: PushMessage,
        delivery_id: str,
        idempotency_key: str,
        ephemeral_private_key: ec.EllipticCurvePrivateKey | None = None,
        salt: bytes | None = None,
        nonce: bytes | None = None,
    ) -> dict[str, Any]:
        now = int(self._now())
        keyring = self._keyring()
        acknowledged = [str(value) for value in device.get("acknowledged_sender_key_ids") or []]
        signing_key = keyring.acknowledged_key(acknowledged, now=now)
        recipient = b64url_decode(device.get("recipient_public_key"), expected_length=65)
        recipient_id = str(device.get("recipient_key_id") or "")
        if key_id(recipient) != recipient_id:
            raise ValueError("Relay device recipient key ID does not match its public key")
        encrypted = encrypt_alert(
            tenant_id=self.config.tenant_id,
            device_id=_identifier(device.get("device_id"), "device_id"),
            delivery_id=_identifier(delivery_id, "delivery_id"),
            event_id=message.event_id,
            event_type=message.event_type,
            title=message.title,
            body=message.body,
            recipient_public_key=recipient,
            sender_private_key=signing_key.private_key,
            issued=now,
            expires=now + 900,
            ephemeral_private_key=ephemeral_private_key or ec.generate_private_key(ec.SECP256R1()),
            salt=bytes(salt) if salt is not None else self._fresh_random(32),
            nonce=bytes(nonce) if nonce is not None else self._fresh_random(12),
        )
        body = {
            "device_id": _identifier(device.get("device_id"), "device_id"),
            "envelope": encrypted,
            "idempotency_key": _idempotency_key(idempotency_key),
        }
        if not message.sound:
            body["sound"] = False
        return body

    def send_live_activity(
        self,
        *,
        device_id: str,
        state: LiveActivityState,
        delivery_id: str,
        target_revision: int,
        idempotency_key: str,
        request_body: Mapping[str, Any] | None = None,
    ) -> DeliveryReceipt:
        if request_body is None:
            body = {
                "device_id": _identifier(device_id, "device_id"),
                "delivery_id": _identifier(delivery_id, "delivery_id"),
                "state": state.as_payload(),
                "idempotency_key": _idempotency_key(idempotency_key),
            }
        else:
            body = _strict_keys(
                request_body,
                {"device_id", "delivery_id", "state", "idempotency_key"},
                {"device_id", "delivery_id", "state", "idempotency_key"},
            )
            if (
                _identifier(body["device_id"], "device_id") != _identifier(device_id, "device_id")
                or _identifier(body["delivery_id"], "delivery_id") != _identifier(delivery_id, "delivery_id")
                or body["state"] != state.as_payload()
                or _idempotency_key(body["idempotency_key"]) != _idempotency_key(idempotency_key)
            ):
                raise ValueError("Frozen Live Activity request does not match current coordinates")
        response = self._request("POST", _RELAY_PATHS["delivery"], body, attempts=2)
        accepted = self._accepted_response(
            response,
            expected_id=_identifier(delivery_id, "delivery_id"),
            expected_revision=_revision(target_revision, "target revision"),
            allowed_statuses={"accepted", "duplicate"},
        )
        return DeliveryReceipt(delivery_id=accepted["id"])

    def register_device(self, body: Mapping[str, Any]) -> dict[str, Any]:
        normalized = self._device_registration(body)
        response = self._request("POST", _RELAY_PATHS["device_register"], normalized, attempts=2)
        return self._registration_response(response, normalized)

    def revoke_device(self, body: Mapping[str, Any]) -> dict[str, Any]:
        return self._post_revisioned("device_revoke", body, {"version", "device_id", "revision", "idempotency_key"})

    def acknowledge_sender_keys(self, body: Mapping[str, Any]) -> dict[str, Any]:
        normalized = normalize_relay_operation(
            "acknowledge_sender_keys", body, tenant_id=self.config.tenant_id
        )
        keyring = self._keyring()
        if _revision(normalized["sender_key_revision"], "sender_key_revision") != keyring.revision:
            raise ValueError("Relay sender-key acknowledgement revision is stale")
        if type(normalized["acknowledged_sender_key_ids"]) is not list:
            raise ValueError("Relay sender-key acknowledgement is invalid")
        acknowledged = normalized["acknowledged_sender_key_ids"]
        if not 1 <= len(acknowledged) <= 2 or len(set(acknowledged)) != len(acknowledged):
            raise ValueError("Relay sender-key acknowledgement is invalid")
        for value in acknowledged:
            if type(value) is not str:
                raise ValueError("Relay sender-key acknowledgement is invalid")
            b64url_decode(value, expected_length=32)
        keyring.acknowledged_key(acknowledged, now=int(self._now()))
        return self._accepted_response(
            self._request("POST", _RELAY_PATHS["sender_ack"], normalized, attempts=2),
            expected_id=_identifier(normalized["device_id"], "device_id"),
            expected_revision=_revision(normalized["revision"]),
            allowed_statuses={"accepted", "duplicate"},
        )

    def revoke_tenant(self, body: Mapping[str, Any]) -> dict[str, Any]:
        return self._post_revisioned("tenant_revoke", body, set())

    def delete_tenant(self, body: Mapping[str, Any]) -> dict[str, Any]:
        return self._post_revisioned("tenant_delete", body, set())

    def register_live_activity(self, body: Mapping[str, Any]) -> dict[str, Any]:
        normalized = normalize_relay_operation(
            "register_live_activity", body, tenant_id=self.config.tenant_id
        )
        return self._accepted_response(
            self._request("POST", _RELAY_PATHS["live_register"], normalized, attempts=2),
            expected_id=_identifier(normalized["activity_id"], "activity_id"),
            expected_revision=_revision(normalized["revision"]),
            allowed_statuses={"accepted", "duplicate"},
        )

    def revoke_live_activity(self, body: Mapping[str, Any]) -> dict[str, Any]:
        normalized = normalize_relay_operation(
            "revoke_live_activity", body, tenant_id=self.config.tenant_id
        )
        return self._accepted_response(
            self._request("POST", _RELAY_PATHS["live_revoke"], normalized, attempts=2),
            expected_id=_identifier(normalized["activity_id"], "activity_id"),
            expected_revision=_revision(normalized["revision"]),
            allowed_statuses={"revoked", "duplicate"},
        )

    def health(self) -> dict[str, Any]:
        response = self._request("GET", _RELAY_PATHS["health"], None, attempts=1)
        if (
            set(response) != {"version", "status"}
            or type(response.get("version")) is not int
            or response.get("version") != 1
            or response.get("status") != "ok"
        ):
            raise ValueError("Relay health response is invalid")
        return response

    def close(self) -> None:
        close = getattr(self._transport, "close", None)
        if callable(close):
            close()

    def _keyring(self) -> _SigningKeyring:
        return _load_signing_keyring(
            self._secret_resolver(self.config.signing_key_secret_reference),
            now=int(self._now()),
        )

    def _device_registration(self, body: Mapping[str, Any]) -> dict[str, Any]:
        return normalize_relay_operation(
            "register_device", body, tenant_id=self.config.tenant_id
        )

    def _validate_common(self, body: Mapping[str, Any]) -> None:
        if type(body.get("version")) is not int or body.get("version") != 1:
            raise ValueError("Relay protocol version must be 1")
        _revision(body.get("revision"))
        _idempotency_key(body.get("idempotency_key"))

    def _post_revisioned(
        self,
        path_name: str,
        body: Mapping[str, Any],
        keys: set[str],
    ) -> dict[str, Any]:
        operation = {
            "device_revoke": "revoke_device",
            "tenant_revoke": "revoke_tenant",
            "tenant_delete": "delete_tenant",
        }[path_name]
        normalized = normalize_relay_operation(
            operation, body, tenant_id=self.config.tenant_id
        )
        expected_id = normalized.get("device_id", normalized.get("tenant_id"))
        return self._accepted_response(
            self._request("POST", _RELAY_PATHS[path_name], normalized, attempts=2),
            expected_id=_identifier(expected_id, "id"),
            expected_revision=_revision(normalized["revision"]),
            allowed_statuses=(
                {"revoked", "duplicate"}
                if path_name in {"device_revoke", "tenant_revoke"}
                else {"deleted", "duplicate"}
            ),
        )

    def _request(
        self,
        method: str,
        path: str,
        value: Mapping[str, Any] | None,
        *,
        attempts: int,
    ) -> dict[str, Any]:
        body = b"" if value is None else canonical_json_bytes(value)
        if len(body) > 4_096:
            raise ValueError("Relay request exceeds 4096 bytes")
        hmac_key = self._hmac_key()
        last_error: RelayOutcomeUnknown | None = None
        last_transport_error: httpx.TransportError | None = None
        for _attempt in range(attempts):
            timestamp = int(self._now())
            request_nonce = b64url_encode(self._fresh_random(16))
            signing_input = request_signing_input(
                method=method,
                path=path,
                tenant_id=self.config.tenant_id,
                credential_key_id=self.config.credential_key_id,
                timestamp=timestamp,
                nonce=request_nonce,
                body=body,
            )
            headers = {
                "content-type": "application/json",
                "x-loopdy-tenant-id": self.config.tenant_id,
                "x-loopdy-credential-key-id": self.config.credential_key_id,
                "x-loopdy-timestamp": str(timestamp),
                "x-loopdy-nonce": request_nonce,
                "x-loopdy-signature": b64url_encode(
                    hmac.new(hmac_key, signing_input, hashlib.sha256).digest()
                ),
            }
            try:
                response = self._transport.request(
                    method=method,
                    url=f"{self.config.base_url}{path}",
                    headers=headers,
                    body=body,
                    timeout=self._timeout,
                    follow_redirects=False,
                )
            except RelayOutcomeUnknown as error:
                last_error = error
                continue
            except httpx.TransportError as error:
                last_error = RelayOutcomeUnknown("relay_transport_outcome_unknown")
                last_transport_error = error
                continue
            response_body = bytes(response.body)
            if len(response_body) > 65_536:
                raise ValueError("Relay response exceeds the size limit")
            response_status = int(response.status_code)
            if (
                (response_status == 429 or 500 <= response_status < 600)
                and _attempt + 1 < attempts
            ):
                continue
            if response_status not in {200, 201, 202}:
                raise DeliveryError(
                    "relay_unavailable" if response_status >= 500 else "relay_rejected",
                    status=response_status,
                )
            try:
                parsed = json.loads(response_body)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError("Relay response is invalid") from error
            if not isinstance(parsed, dict):
                raise ValueError("Relay response is invalid")
            return parsed
        if last_error is not None:
            if last_transport_error is not None:
                raise last_error from last_transport_error
            raise last_error
        raise RelayOutcomeUnknown("relay_transport_outcome_unknown")

    def _hmac_key(self) -> bytes:
        hmac_key = bytes(self._secret_resolver(self.config.hmac_secret_reference))
        if len(hmac_key) < 32 or len(hmac_key) > 4_096:
            raise ValueError("Relay HMAC secret must be between 32 and 4096 bytes")
        return hmac_key

    def _accepted_response(
        self,
        response: Mapping[str, Any],
        *,
        expected_id: str,
        expected_revision: int,
        allowed_statuses: set[str],
    ) -> dict[str, Any]:
        if set(response) != {"version", "status", "id", "revision"}:
            raise ValueError("Relay response contains unknown or missing fields")
        if type(response.get("version")) is not int or response.get("version") != 1 or response.get("status") not in {
            "accepted", "duplicate", "revoked", "deleted"
        }:
            raise ValueError("Relay response is invalid")
        accepted = {
            "version": 1,
            "status": str(response["status"]),
            "id": _identifier(response["id"], "id"),
            "revision": _revision(response["revision"]),
        }
        if (
            accepted["id"] != expected_id
            or accepted["revision"] != expected_revision
        ):
            raise ValueError("Relay response does not match the request coordinates")
        if accepted["status"] not in allowed_statuses:
            raise ValueError("Relay response status is invalid for this operation")
        return accepted

    def _registration_response(
        self,
        response: Mapping[str, Any],
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        return validate_registration_response(
            response,
            request,
            tenant_id=self.config.tenant_id,
            sender_keyring=self._keyring().public_value(),
        )

    def _fresh_random(self, count: int) -> bytes:
        value = bytes(self._random_bytes(count))
        if len(value) != count:
            raise ValueError("Random source returned an invalid byte count")
        return value


class RelayPushProvider:
    """Device-aware relay provider; intentionally not an APNs-token PushProvider."""

    name = "relay"

    def __init__(self, client: RelayClient):
        self.client = client

    def send_device(
        self,
        device: Mapping[str, Any],
        message: PushMessage,
        *,
        delivery_id: str,
        idempotency_key: str,
        request_body: Mapping[str, Any] | None = None,
    ) -> DeliveryReceipt:
        return self.client.deliver_alert(
            device=device,
            message=message,
            delivery_id=delivery_id,
            idempotency_key=idempotency_key,
            request_body=request_body,
        )

    def prepare_device(
        self,
        device: Mapping[str, Any],
        message: PushMessage,
        *,
        delivery_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self.client.prepare_alert(
            device=device,
            message=message,
            delivery_id=delivery_id,
            idempotency_key=idempotency_key,
        )

    def select_sender_key_id(self, acknowledged_sender_key_ids: list[str]) -> str:
        return self.client.select_sender_key_id(acknowledged_sender_key_ids)

    def send_live_activity(
        self,
        *,
        device_id: str,
        state: LiveActivityState,
        delivery_id: str,
        target_revision: int,
        idempotency_key: str,
        request_body: Mapping[str, Any] | None = None,
    ) -> DeliveryReceipt:
        return self.client.send_live_activity(
            device_id=device_id,
            state=state,
            delivery_id=delivery_id,
            target_revision=target_revision,
            idempotency_key=idempotency_key,
            request_body=request_body,
        )

    def close(self) -> None:
        close = getattr(self.client, "close", None)
        if callable(close):
            close()


def delivery_coordinates(event_id: str, device_id: str, revision: int) -> tuple[str, str]:
    normalized_event_id = _identifier(event_id, "event_id", maximum=512)
    normalized_device_id = _identifier(device_id, "device_id")
    normalized_revision = _revision(revision)
    source = f"loopdy:{normalized_event_id}:{normalized_device_id}:{normalized_revision}"
    return (
        hashlib.sha256(source.encode("utf-8")).hexdigest()[:48],
        str(uuid.uuid5(uuid.NAMESPACE_URL, source)),
    )


def live_activity_delivery_coordinates(
    state: LiveActivityState,
    device_id: str,
    revision: int,
) -> tuple[str, str]:
    source = f"live-activity:{state.activity_id}:{state.timestamp}:{state.phase}"
    return delivery_coordinates(source, device_id, revision)


__all__ = [
    "RelayClient",
    "RelayConfig",
    "RelayHttpResponse",
    "RelayOutcomeUnknown",
    "RelayPushProvider",
    "delivery_coordinates",
    "live_activity_delivery_coordinates",
    "normalize_relay_operation",
    "resolve_secret_reference",
]
