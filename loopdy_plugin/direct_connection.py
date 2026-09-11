"""Direct Loopdy-to-Hermes identity and admission authority.

One authority instance and its lock belong to one immutable runtime owner. The
caller must not create competing instances for the same owner context. Link
enrollment and lifecycle refresh methods are internal trust-boundary methods:
their callers must authenticate the paired Link frame or REST response first.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .link_crypto import decode_base64url, encode_base64url, raw_p256_to_der, sign_p256_raw


_ENROLLMENT_DOMAIN = b"loopdy-direct-enrollment-v1\n"
_ENROLLMENT_RESULT_DOMAIN = b"loopdy-direct-enrollment-result-v1\n"
_SESSION_DOMAIN = b"loopdy-direct-session-v1\n"
_OPAQUE = re.compile(r"^[A-Za-z0-9_-]+$")
_ENROLLMENT_FIELDS = frozenset(
    {"version", "exchangeId", "phoneNonce", "phonePublicKey", "phoneProof"}
)
_STORED_BINDING_FIELDS = frozenset(
    {"deviceId", "epoch", "publicKey", "fingerprint", "exchangeId", "phoneNonce",
     "requestHash", "outcome"}
)
_ENROLLMENT_RESULT_FIELDS = frozenset(
    {"version", "exchangeId", "phoneNonce", "accountOrigin", "directOrigin",
     "hostDeviceId", "hostEpoch", "hostPublicKey", "hostKeyFingerprint",
     "phoneDeviceId", "phoneEpoch", "phonePublicKey", "phoneKeyFingerprint",
     "hostProof"}
)
_ENROLLMENT_RESULT_BODY_FIELDS = _ENROLLMENT_RESULT_FIELDS - {"hostProof"}
_DEVICE_FIELDS = frozenset(
    {
        "deviceId", "encryptedName", "role", "kind", "lifecycle", "revision",
        "authorizationEpoch", "connection", "pushState", "pushRevision", "createdAt",
        "revokedAt", "lastSeenBucket",
    }
)
_DEVICE_KINDS = frozenset({"phone", "tablet", "computer", "hermes_host"})
_PUSH_STATES = frozenset(
    {"permission_required", "registering", "ready", "denied", "retrying",
     "unavailable", "revoked"}
)


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def canonical_enrollment_transcript(
    *, account_origin: str, direct_origin: str, host_device_id: str,
    host_epoch: int, phone_device_id: str, phone_epoch: int, exchange_id: str,
    phone_nonce: str, phone_public_key: str,
) -> bytes:
    """Build the enrollment proof transcript shared with the mobile client."""
    return _ENROLLMENT_DOMAIN + _canonical_json(
        {
            "version": 1,
            "accountOrigin": account_origin,
            "directOrigin": direct_origin,
            "hostDeviceId": host_device_id,
            "hostEpoch": host_epoch,
            "phoneDeviceId": phone_device_id,
            "phoneEpoch": phone_epoch,
            "exchangeId": exchange_id,
            "phoneNonce": phone_nonce,
            "phonePublicKey": phone_public_key,
        }
    )


def canonical_enrollment_result_transcript(result: Mapping[str, Any]) -> bytes:
    """Build the host enrollment-result proof transcript."""
    if not isinstance(result, Mapping) or set(result) != _ENROLLMENT_RESULT_BODY_FIELDS:
        raise ValueError("enrollment result fields are invalid")
    return _ENROLLMENT_RESULT_DOMAIN + _canonical_json(result)


def canonical_session_transcript(
    *, account_origin: str, direct_origin: str, host_device_id: str,
    host_epoch: int, peer_device_id: str, peer_epoch: int, connection_id: str,
    nonce: str, client_nonce: str,
) -> bytes:
    """Build the direct-session challenge transcript shared with the peer."""
    return _SESSION_DOMAIN + _canonical_json(
        {
            "version": 1,
            "accountOrigin": account_origin,
            "directOrigin": direct_origin,
            "hostDeviceId": host_device_id,
            "hostEpoch": host_epoch,
            "peerDeviceId": peer_device_id,
            "peerEpoch": peer_epoch,
            "connectionID": connection_id,
            "nonce": nonce,
            "clientNonce": client_nonce,
        }
    )


@dataclass(frozen=True)
class DirectPeer:
    """Authenticated peer identity, still subject to per-use validation."""
    account_origin: str
    direct_origin: str
    host_device_id: str
    host_epoch: int
    host_key_fingerprint: str
    peer_device_id: str
    peer_epoch: int
    peer_key_fingerprint: str


@dataclass(frozen=True)
class _Challenge:
    peer_device_id: str
    peer_epoch: int
    connection_id: str
    client_nonce: str
    expires_at: float


@dataclass(frozen=True)
class _Owner:
    account_origin: str
    direct_origin: str
    host_device_id: str
    host_epoch: int


def _opaque(value: Any, field: str, *, maximum: int = 96) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum
            or _OPAQUE.fullmatch(value) is None):
        raise ValueError(f"{field} is invalid")
    return value


def _positive_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _nonnegative_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a nonnegative integer")
    return value


def _origin(value: Any, field: str) -> str:
    if (not isinstance(value, str) or not value
            or any(character.isspace() or ord(character) < 0x20 for character in value)
            or "\\" in value or "?" in value or "#" in value):
        raise ValueError(f"{field} must be an HTTPS origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{field} must be an HTTPS origin") from exc
    if (parsed.scheme.lower() != "https" or not parsed.netloc or parsed.hostname is None
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            or "%" in parsed.netloc or parsed.netloc.endswith(":")):
        raise ValueError(f"{field} must be an HTTPS origin")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"{field} must be an HTTPS origin") from exc
    if not host or port == 0:
        raise ValueError(f"{field} must be an HTTPS origin")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if (len(host) > 253 or host.endswith(".")
                or any(not label or len(label) > 63
                       or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label) is None
                       for label in labels)):
            raise ValueError(f"{field} must be an HTTPS origin")
    if ":" in host:
        host = f"[{host}]"
    suffix = "" if port in {None, 443} else f":{port}"
    return f"https://{host}{suffix}"


def _public_spki(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _fingerprint(public_spki: bytes) -> str:
    return encode_base64url(hashlib.sha256(public_spki).digest())


def _decode_canonical(value: Any, *, length: int, field: str) -> bytes:
    try:
        decoded = decode_base64url(value, minimum=length, maximum=length)
    except ValueError as exc:
        raise ValueError(f"{field} is invalid") from exc
    if encode_base64url(decoded) != value:
        raise ValueError(f"{field} is invalid")
    return decoded


def _load_public_key(encoded: Any) -> tuple[ec.EllipticCurvePublicKey, bytes]:
    der = _decode_canonical(encoded, length=91, field="phonePublicKey")
    try:
        key = serialization.load_der_public_key(der)
    except (TypeError, ValueError) as exc:
        raise ValueError("phonePublicKey is invalid") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("phonePublicKey is invalid")
    canonical = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if canonical != der:
        raise ValueError("phonePublicKey is not canonical DER SPKI")
    return key, der


def _clone(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value, separators=(",", ":"), sort_keys=True))


class DirectConnectionAuthority:
    """Own enrollment and challenge state for one immutable host identity."""
    _STATE_PREFIX = "direct.connection.enrollments.v1"
    _ENROLLMENT_TTL = 300.0
    _ENROLLMENT_LIMIT = 256
    _LIFECYCLE_TTL = 300.0
    _CHALLENGE_TTL = 30.0
    _CHALLENGE_LIMIT = 64

    def __init__(
        self, *, account_origin: str, direct_origin: str, host_device_id: str,
        host_epoch: int, host_private_key: ec.EllipticCurvePrivateKey, state: Any,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self._owner_context = _Owner(
            _origin(account_origin, "account_origin"), _origin(direct_origin, "direct_origin"),
            _opaque(host_device_id, "host_device_id"), _positive_integer(host_epoch, "host_epoch"),
        )
        if (not isinstance(host_private_key, ec.EllipticCurvePrivateKey)
                or not isinstance(host_private_key.curve, ec.SECP256R1)):
            raise ValueError("host_private_key must be a P-256 private key")
        if not callable(monotonic):
            raise ValueError("monotonic must be callable")
        self._host_private_key = host_private_key
        self._host_public_der = _public_spki(host_private_key)
        self._host_public_key = encode_base64url(self._host_public_der)
        self._host_fingerprint = _fingerprint(self._host_public_der)
        self._state = state
        self._monotonic = monotonic
        self._lock = threading.RLock()
        self._owner = {
            "accountOrigin": self.account_origin,
            "directOrigin": self.direct_origin,
            "hostDeviceId": self.host_device_id,
            "hostEpoch": self.host_epoch,
            "hostPublicKey": self._host_public_key,
        }
        owner_scope = _fingerprint(_canonical_json(self._owner))
        self._state_key = f"{self._STATE_PREFIX}.{owner_scope}"
        self._bindings = self._load_bindings()
        self._denied_through = self._load_lifecycle_fences()
        self._fences_dirty = False
        self._enrollment_nonces: dict[str, float] = {}
        self._challenges: dict[str, _Challenge] = {}
        self._lifecycle_devices: dict[str, dict[str, Any]] = {}
        self._lifecycle_refreshed_at: float | None = None

    @property
    def account_origin(self) -> str:
        return self._owner_context.account_origin

    @property
    def direct_origin(self) -> str:
        return self._owner_context.direct_origin

    @property
    def host_device_id(self) -> str:
        return self._owner_context.host_device_id

    @property
    def host_epoch(self) -> int:
        return self._owner_context.host_epoch

    def _load_lifecycle_fences(self) -> dict[str, int]:
        stored = self._state.get(self._state_key + ".lifecycle", None)
        if stored is None:
            return {}
        if (not isinstance(stored, dict) or set(stored) != {"version", "owner", "deniedThrough"}
                or type(stored["version"]) is not int or stored["version"] != 1
                or stored["owner"] != self._owner or not isinstance(stored["deniedThrough"], dict)
                or len(stored["deniedThrough"]) > 257):
            raise ValueError("persisted direct lifecycle fences are invalid")
        return {_opaque(key, "deviceId"): _nonnegative_integer(value, "deniedThrough")
                for key, value in stored["deniedThrough"].items()}

    def _load_bindings(self) -> dict[str, dict[str, Any]]:
        stored = self._state.get(self._state_key, {})
        if (not isinstance(stored, dict) or type(stored.get("version")) is not int
                or stored.get("version") != 1
                or stored.get("owner") != self._owner
                or not isinstance(stored.get("bindings"), dict)):
            return {}
        valid: dict[str, dict[str, Any]] = {}
        for device_id, binding in stored["bindings"].items():
            if self._valid_stored_binding(device_id, binding):
                valid[device_id] = _clone(binding)
        return valid

    def _valid_stored_binding(self, device_id: Any, binding: Any) -> bool:
        if not isinstance(binding, dict) or set(binding) != _STORED_BINDING_FIELDS:
            return False
        try:
            _opaque(device_id, "deviceId")
            epoch = _positive_integer(binding.get("epoch"), "epoch")
            exchange_id = _opaque(binding.get("exchangeId"), "exchangeId")
            phone_nonce = _opaque(binding.get("phoneNonce"), "phoneNonce", maximum=128)
            _, public_der = _load_public_key(binding.get("publicKey"))
            fingerprint = _decode_canonical(
                binding.get("fingerprint"), length=32, field="fingerprint"
            )
            request_hash = _decode_canonical(
                binding.get("requestHash"), length=32, field="requestHash"
            )
            outcome = binding.get("outcome")
            if not isinstance(outcome, dict) or set(outcome) != _ENROLLMENT_RESULT_FIELDS:
                return False
            if (
                binding.get("deviceId") != device_id
                or fingerprint != hashlib.sha256(public_der).digest()
                or type(outcome.get("version")) is not int
                or outcome.get("version") != 1
                or outcome.get("exchangeId") != exchange_id
                or outcome.get("phoneNonce") != phone_nonce
                or outcome.get("accountOrigin") != self.account_origin
                or outcome.get("directOrigin") != self.direct_origin
                or outcome.get("hostDeviceId") != self.host_device_id
                or outcome.get("hostEpoch") != self.host_epoch
                or outcome.get("hostPublicKey") != self._host_public_key
                or outcome.get("hostKeyFingerprint") != self._host_fingerprint
                or outcome.get("phoneDeviceId") != device_id
                or outcome.get("phoneEpoch") != epoch
                or outcome.get("phonePublicKey") != binding.get("publicKey")
                or outcome.get("phoneKeyFingerprint") != binding.get("fingerprint")
            ):
                return False
            transcript = canonical_enrollment_transcript(
                account_origin=self.account_origin,
                direct_origin=self.direct_origin,
                host_device_id=self.host_device_id,
                host_epoch=self.host_epoch,
                phone_device_id=device_id,
                phone_epoch=epoch,
                exchange_id=exchange_id,
                phone_nonce=phone_nonce,
                phone_public_key=binding["publicKey"],
            )
            if request_hash != hashlib.sha256(transcript).digest():
                return False
            outcome_body = dict(outcome)
            host_proof = _decode_canonical(
                outcome_body.pop("hostProof"), length=64, field="hostProof"
            )
            self._host_private_key.public_key().verify(
                raw_p256_to_der(host_proof),
                canonical_enrollment_result_transcript(outcome_body),
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, ValueError):
            return False
        return True

    def _enroll_from_link(
        self, payload: Mapping[str, Any], *, trusted_sender_device_id: str,
        trusted_sender_epoch: int,
    ) -> dict[str, Any]:
        """Enroll a peer after the caller validates its authenticated Link frame."""
        with self._lock:
            if not isinstance(payload, Mapping) or set(payload) != _ENROLLMENT_FIELDS:
                raise ValueError("direct enrollment payload fields are invalid")
            if type(payload.get("version")) is not int or payload.get("version") != 1:
                raise ValueError("direct enrollment version is invalid")
            phone_device_id = _opaque(trusted_sender_device_id, "trusted_sender_device_id")
            phone_epoch = _positive_integer(trusted_sender_epoch, "trusted_sender_epoch")
            if phone_epoch <= self._denied_through.get(phone_device_id, 0):
                raise ValueError("phone enrollment epoch has been invalidated")
            if phone_device_id not in self._bindings and len(self._bindings) >= 256:
                raise ValueError("direct enrollment capacity is exhausted")
            exchange_id = _opaque(payload.get("exchangeId"), "exchangeId")
            phone_nonce = _opaque(payload.get("phoneNonce"), "phoneNonce", maximum=128)
            public_key, public_der = _load_public_key(payload.get("phonePublicKey"))
            phone_public_key = encode_base64url(public_der)
            signature = _decode_canonical(payload.get("phoneProof"), length=64, field="phoneProof")
            transcript = canonical_enrollment_transcript(
                account_origin=self.account_origin, direct_origin=self.direct_origin,
                host_device_id=self.host_device_id, host_epoch=self.host_epoch,
                phone_device_id=phone_device_id, phone_epoch=phone_epoch,
                exchange_id=exchange_id, phone_nonce=phone_nonce,
                phone_public_key=phone_public_key,
            )
            try:
                public_key.verify(raw_p256_to_der(signature), transcript, ec.ECDSA(hashes.SHA256()))
            except (InvalidSignature, ValueError) as exc:
                raise ValueError("phoneProof is invalid") from exc

            request_hash = encode_base64url(hashlib.sha256(transcript).digest())
            existing = self._bindings.get(phone_device_id)
            if existing is not None:
                existing_epoch = existing["epoch"]
                if phone_epoch < existing_epoch:
                    raise ValueError("phone enrollment epoch is stale")
                if phone_epoch == existing_epoch:
                    if existing["publicKey"] != phone_public_key:
                        raise ValueError("phone key cannot change at the same epoch")
                    if existing["requestHash"] != request_hash:
                        raise ValueError("phone is already enrolled for this epoch")
                    return _clone(existing["outcome"])

            now = float(self._monotonic())
            self._prune_enrollment_nonces(now)
            if phone_nonce in self._enrollment_nonces:
                raise ValueError("phoneNonce has already been used")
            if len(self._enrollment_nonces) >= self._ENROLLMENT_LIMIT:
                raise ValueError("direct enrollment nonce capacity is exhausted")
            self._enrollment_nonces[phone_nonce] = now + self._ENROLLMENT_TTL
            try:
                phone_fingerprint = _fingerprint(public_der)
                result = self._enrollment_result(
                    exchange_id=exchange_id, phone_nonce=phone_nonce,
                    phone_device_id=phone_device_id, phone_epoch=phone_epoch,
                    phone_public_key=phone_public_key, phone_fingerprint=phone_fingerprint,
                )
                binding = {
                    "deviceId": phone_device_id, "epoch": phone_epoch,
                    "publicKey": phone_public_key, "fingerprint": phone_fingerprint,
                    "exchangeId": exchange_id, "phoneNonce": phone_nonce,
                    "requestHash": request_hash, "outcome": result,
                }
                candidate = dict(self._bindings)
                candidate[phone_device_id] = binding
                self._state.set(
                    self._state_key,
                    {"version": 1, "owner": dict(self._owner), "bindings": candidate},
                )
            except Exception:
                self._enrollment_nonces.pop(phone_nonce, None)
                raise
            self._bindings = candidate
            return _clone(result)

    def _enrollment_result(
        self, *, exchange_id: str, phone_nonce: str, phone_device_id: str,
        phone_epoch: int, phone_public_key: str, phone_fingerprint: str,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "version": 1, "exchangeId": exchange_id, "phoneNonce": phone_nonce,
            "accountOrigin": self.account_origin, "directOrigin": self.direct_origin,
            "hostDeviceId": self.host_device_id, "hostEpoch": self.host_epoch,
            "hostPublicKey": self._host_public_key,
            "hostKeyFingerprint": self._host_fingerprint,
            "phoneDeviceId": phone_device_id, "phoneEpoch": phone_epoch,
            "phonePublicKey": phone_public_key,
            "phoneKeyFingerprint": phone_fingerprint,
        }
        proof = sign_p256_raw(
            self._host_private_key, canonical_enrollment_result_transcript(result)
        )
        result["hostProof"] = encode_base64url(proof)
        return result

    def _prune_enrollment_nonces(self, now: float) -> None:
        self._enrollment_nonces = {
            nonce: expiry for nonce, expiry in self._enrollment_nonces.items() if expiry >= now
        }

    def _refresh_lifecycle_catalog(self, catalog: Mapping[str, Any]) -> None:
        """Install a caller-authenticated `/v1/devices` response snapshot."""
        devices = self._parse_catalog(catalog)
        now = float(self._monotonic())
        with self._lock:
            known = {key: ("mobile", binding["epoch"]) for key, binding in self._bindings.items()}
            known[self.host_device_id] = ("host", self.host_epoch)
            floors = dict(self._denied_through)
            for device_id, (role, expected_epoch) in known.items():
                device = devices.get(device_id)
                if device is None:
                    floor = expected_epoch
                elif (device["lifecycle"] != "active" or device["revokedAt"] is not None
                      or device["role"] != role):
                    floor = max(expected_epoch, device["authorizationEpoch"])
                else:
                    floor = (device["authorizationEpoch"] - 1
                             if device["authorizationEpoch"] > expected_epoch
                             else floors.get(device_id, 0))
                if floor > floors.get(device_id, 0):
                    floors[device_id] = floor
            if floors != self._denied_through:
                # Publish denial in memory before persistence. Failure retires
                # freshness immediately; it can never retain old authorization.
                self._denied_through = floors
                self._fences_dirty = True
            if self._fences_dirty:
                self._lifecycle_refreshed_at = None
                self._state.set(self._state_key + ".lifecycle", {
                    "version": 1, "owner": dict(self._owner), "deniedThrough": floors,
                })
                self._fences_dirty = False
            if any(device["lifecycle"] == "active" and device["revokedAt"] is None
                   and device["role"] == known[device_id][0]
                   and device["authorizationEpoch"] <= floors.get(device_id, 0)
                   for device_id, device in devices.items() if device_id in known):
                self._lifecycle_refreshed_at = None
                raise ValueError("lifecycle catalog rolls back a known invalidation")
            self._lifecycle_devices = devices
            self._lifecycle_refreshed_at = now

    @classmethod
    def _parse_catalog(cls, catalog: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        if (not isinstance(catalog, Mapping) or set(catalog) != {"version", "devices"}
                or type(catalog.get("version")) is not int or catalog.get("version") != 1
                or not isinstance(catalog.get("devices"), list)
                or len(catalog["devices"]) > 128):
            raise ValueError("lifecycle catalog is invalid")
        parsed: dict[str, dict[str, Any]] = {}
        for value in catalog["devices"]:
            if not isinstance(value, Mapping) or set(value) != _DEVICE_FIELDS:
                raise ValueError("lifecycle device fields are invalid")
            device_id = _opaque(value.get("deviceId"), "deviceId")
            if device_id in parsed:
                raise ValueError("lifecycle catalog contains duplicate devices")
            if not isinstance(value.get("encryptedName"), str) or not value["encryptedName"]:
                raise ValueError("encryptedName is invalid")
            role, kind = value.get("role"), value.get("kind")
            lifecycle, connection = value.get("lifecycle"), value.get("connection")
            push_state = value.get("pushState")
            if not isinstance(role, str) or role not in {"mobile", "host"}:
                raise ValueError("device role is invalid")
            if (not isinstance(kind, str) or kind not in _DEVICE_KINDS
                    or (role == "host" and kind != "hermes_host")):
                raise ValueError("device kind is invalid")
            if not isinstance(lifecycle, str) or lifecycle not in {"active", "revoked"}:
                raise ValueError("device lifecycle is invalid")
            if (not isinstance(connection, str)
                    or connection not in {"online", "recent", "offline"}):
                raise ValueError("device connection is invalid")
            if (push_state is not None
                    and (not isinstance(push_state, str) or push_state not in _PUSH_STATES)):
                raise ValueError("device pushState is invalid")
            _positive_integer(value.get("revision"), "revision")
            _positive_integer(value.get("authorizationEpoch"), "authorizationEpoch")
            _nonnegative_integer(value.get("pushRevision"), "pushRevision")
            _positive_integer(value.get("createdAt"), "createdAt")
            if value.get("revokedAt") is not None:
                _positive_integer(value.get("revokedAt"), "revokedAt")
            if value.get("lastSeenBucket") is not None:
                _positive_integer(value.get("lastSeenBucket"), "lastSeenBucket")
            parsed[device_id] = dict(value)
        return parsed

    def issue_challenge(
        self, *, peer_device_id: str, peer_epoch: int, connection_id: str, client_nonce: str,
    ) -> dict[str, Any]:
        peer_id = _opaque(peer_device_id, "peer_device_id")
        epoch = _positive_integer(peer_epoch, "peer_epoch")
        connection = _opaque(connection_id, "connection_id", maximum=128)
        _decode_canonical(client_nonce, length=32, field="clientNonce")
        with self._lock:
            self._require_current_peer(peer_id, epoch)
            now = float(self._monotonic())
            self._prune_challenges(now)
            if len(self._challenges) >= self._CHALLENGE_LIMIT:
                raise ValueError("direct challenge capacity is exhausted")
            while True:
                nonce = encode_base64url(os.urandom(32))
                if nonce not in self._challenges:
                    break
            transcript = canonical_session_transcript(
                account_origin=self.account_origin, direct_origin=self.direct_origin,
                host_device_id=self.host_device_id, host_epoch=self.host_epoch,
                peer_device_id=peer_id, peer_epoch=epoch, connection_id=connection,
                nonce=nonce, client_nonce=client_nonce,
            )
            self._challenges[nonce] = _Challenge(
                peer_device_id=peer_id, peer_epoch=epoch, connection_id=connection,
                client_nonce=client_nonce,
                expires_at=now + self._CHALLENGE_TTL,
            )
            result = json.loads(transcript[len(_SESSION_DOMAIN):])
            result["hostProof"] = encode_base64url(sign_p256_raw(self._host_private_key, transcript))
            return result

    def _prune_challenges(self, now: float) -> None:
        self._challenges = {
            nonce: challenge for nonce, challenge in self._challenges.items()
            if challenge.expires_at >= now
        }

    def verify_challenge_response(
        self, *, peer_device_id: str, peer_epoch: int, connection_id: str,
        nonce: str, peer_proof: str,
    ) -> DirectPeer:
        peer_id = _opaque(peer_device_id, "peer_device_id")
        epoch = _positive_integer(peer_epoch, "peer_epoch")
        connection = _opaque(connection_id, "connection_id", maximum=128)
        challenge_nonce = _opaque(nonce, "nonce", maximum=64)
        with self._lock:
            challenge = self._challenges.pop(challenge_nonce, None)
            if challenge is None:
                raise ValueError("direct challenge is unknown or already used")
            signature = _decode_canonical(peer_proof, length=64, field="peerProof")
            now = float(self._monotonic())
            if challenge.expires_at < now:
                raise ValueError("direct challenge has expired")
            if (challenge.peer_device_id != peer_id or challenge.peer_epoch != epoch
                    or challenge.connection_id != connection):
                raise ValueError("direct challenge response context does not match")
            binding = self._require_current_peer(peer_id, epoch)
            public_key, _ = _load_public_key(binding["publicKey"])
            transcript = canonical_session_transcript(
                account_origin=self.account_origin, direct_origin=self.direct_origin,
                host_device_id=self.host_device_id, host_epoch=self.host_epoch,
                peer_device_id=peer_id, peer_epoch=epoch, connection_id=connection,
                nonce=challenge_nonce, client_nonce=challenge.client_nonce,
            )
            try:
                public_key.verify(raw_p256_to_der(signature), transcript, ec.ECDSA(hashes.SHA256()))
            except (InvalidSignature, ValueError) as exc:
                raise ValueError("peerProof is invalid") from exc
            return DirectPeer(
                account_origin=self.account_origin, direct_origin=self.direct_origin,
                host_device_id=self.host_device_id, host_epoch=self.host_epoch,
                host_key_fingerprint=self._host_fingerprint, peer_device_id=peer_id,
                peer_epoch=epoch, peer_key_fingerprint=binding["fingerprint"],
            )

    def validate_peer(self, peer: DirectPeer) -> DirectPeer:
        if not isinstance(peer, DirectPeer):
            raise ValueError("direct peer principal is invalid")
        with self._lock:
            if (peer.account_origin != self.account_origin
                    or peer.direct_origin != self.direct_origin
                    or peer.host_device_id != self.host_device_id
                    or peer.host_epoch != self.host_epoch
                    or peer.host_key_fingerprint != self._host_fingerprint):
                raise ValueError("direct peer belongs to another owner")
            binding = self._require_current_peer(peer.peer_device_id, peer.peer_epoch)
            if binding["fingerprint"] != peer.peer_key_fingerprint:
                raise ValueError("direct peer enrollment has been replaced")
            return peer

    def _require_current_peer(self, peer_device_id: str, peer_epoch: int) -> dict[str, Any]:
        now = float(self._monotonic())
        refreshed_at = self._lifecycle_refreshed_at
        if refreshed_at is None or now - refreshed_at > self._LIFECYCLE_TTL:
            raise ValueError("lifecycle authorization is stale")
        if (self.host_epoch <= self._denied_through.get(self.host_device_id, 0)
                or peer_epoch <= self._denied_through.get(peer_device_id, 0)):
            raise ValueError("lifecycle authorization epoch was invalidated")
        host = self._lifecycle_devices.get(self.host_device_id)
        if not self._active_at_epoch(host, role="host", epoch=self.host_epoch):
            raise ValueError("host lifecycle authorization is invalid")
        peer = self._lifecycle_devices.get(peer_device_id)
        if not self._active_at_epoch(peer, role="mobile", epoch=peer_epoch):
            raise ValueError("peer lifecycle authorization is invalid")
        binding = self._bindings.get(peer_device_id)
        if binding is None or binding.get("epoch") != peer_epoch:
            raise ValueError("peer enrollment is unknown or stale")
        return binding

    @staticmethod
    def _active_at_epoch(device: Mapping[str, Any] | None, *, role: str, epoch: int) -> bool:
        return bool(
            device and device.get("role") == role and device.get("lifecycle") == "active"
            and device.get("authorizationEpoch") == epoch and device.get("revokedAt") is None
        )


__all__ = [
    "DirectConnectionAuthority", "DirectPeer", "canonical_enrollment_result_transcript",
    "canonical_enrollment_transcript", "canonical_session_transcript",
]
