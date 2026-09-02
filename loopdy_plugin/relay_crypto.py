"""Strict, versioned cryptography for ordinary Loopdy relay alerts."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
import unicodedata
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_TIMESTAMP = 9_999_999_999


def _positive_integer(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0 or value > _MAX_TIMESTAMP:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _identifier(value: Any, name: str, maximum: int = 180) -> str:
    if type(value) is not str:
        raise ValueError(f"{name} must be a printable ASCII protocol identifier")
    normalized = value
    if (
        not normalized
        or len(normalized) > maximum
        or not normalized.isascii()
        or _IDENTIFIER.fullmatch(normalized) is None
    ):
        raise ValueError(f"{name} must be a printable ASCII protocol identifier")
    return normalized


def _nfc(value: Any, name: str, maximum_bytes: int) -> str:
    if type(value) is not str:
        raise ValueError(f"{name} must use Unicode NFC")
    normalized = value
    if unicodedata.normalize("NFC", normalized) != normalized:
        raise ValueError(f"{name} must use Unicode NFC")
    if len(normalized.encode("utf-8")) > maximum_bytes:
        raise ValueError(f"{name} exceeds {maximum_bytes} UTF-8 bytes")
    return normalized


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(value)).rstrip(b"=").decode("ascii")


def b64url_decode(value: Any, *, expected_length: int | None = None) -> bytes:
    if type(value) is not str:
        raise ValueError("Expected canonical unpadded base64url")
    normalized = value
    if not normalized or _B64URL.fullmatch(normalized) is None or len(normalized) % 4 == 1:
        raise ValueError("Expected canonical unpadded base64url")
    try:
        decoded = base64.b64decode(
            normalized + "=" * (-len(normalized) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError) as error:
        raise ValueError("Expected canonical unpadded base64url") from error
    if b64url_encode(decoded) != normalized:
        raise ValueError("Expected canonical unpadded base64url")
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError(f"Expected {expected_length} decoded bytes")
    return decoded


def public_key_bytes(key: ec.EllipticCurvePublicKey) -> bytes:
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("Relay keys must use P-256")
    return key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def public_key_from_x963(value: bytes) -> ec.EllipticCurvePublicKey:
    encoded = bytes(value)
    if len(encoded) != 65 or encoded[0] != 4:
        raise ValueError("P-256 public key must be a 65-byte uncompressed X9.63 point")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), encoded)
    except ValueError as error:
        raise ValueError("P-256 public key is not on the curve") from error


def key_id(public_key: bytes) -> str:
    public_key_from_x963(public_key)
    return b64url_encode(hashlib.sha256(public_key).digest())


def event_reference(event_id: Any) -> str:
    normalized = _identifier(event_id, "event_id", 180)
    return b64url_encode(hashlib.sha256(normalized.encode("ascii")).digest())


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("Value is not canonical JSON") from error


def alert_aad(
    *,
    tenant_id: Any,
    device_id: Any,
    delivery_id: Any,
    event_ref: Any,
    recipient_key_id: Any,
    sender_key_id: Any,
    issued: int,
    expires: int,
) -> bytes:
    tenant = _identifier(tenant_id, "tenant_id")
    device = _identifier(device_id, "device_id")
    delivery = _identifier(delivery_id, "delivery_id")
    event = event_ref
    recipient = recipient_key_id
    sender = sender_key_id
    b64url_decode(event, expected_length=32)
    b64url_decode(recipient, expected_length=32)
    b64url_decode(sender, expected_length=32)
    issued_value = _positive_integer(issued, "issued")
    expires_value = _positive_integer(expires, "expires")
    if issued_value <= 0 or expires_value <= issued_value or expires_value - issued_value > 900:
        raise ValueError("Alert expiry must be within 900 seconds")
    return "\n".join(
        (
            "loopdy-relay-alert-aad-v1",
            tenant,
            device,
            delivery,
            event,
            "alert",
            recipient,
            sender,
            str(issued_value),
            str(expires_value),
        )
    ).encode("utf-8")


def alert_plaintext(*, event_id: Any, event_type: Any, title: Any, body: Any) -> bytes:
    fields = (
        _identifier(event_id, "event_id", 180).encode("ascii"),
        _identifier(event_type, "event_type", 64).encode("ascii"),
        _nfc(title, "title", 120).encode("utf-8"),
        _nfc(body, "body", 800).encode("utf-8"),
    )
    encoded = b"LP1" + b"".join(struct.pack(">H", len(field)) + field for field in fields)
    if len(encoded) > 1_200:
        raise ValueError("LP1 plaintext exceeds 1200 bytes")
    return encoded


def alert_signature_input(
    *,
    aad: bytes,
    ephemeral_public_key: bytes,
    salt: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> bytes:
    public_key_from_x963(ephemeral_public_key)
    if len(salt) != 32 or len(nonce) != 12 or len(tag) != 16:
        raise ValueError("Invalid alert salt, nonce, or tag length")
    if len(ciphertext) > 1_200:
        raise ValueError("Ciphertext exceeds 1200 bytes")
    return b"".join(
        (
            b"loopdy-relay-envelope-signature-v1\0",
            hashlib.sha256(aad).digest(),
            ephemeral_public_key,
            salt,
            nonce,
            struct.pack(">I", len(ciphertext)),
            ciphertext,
            tag,
        )
    )


def p1363_to_der(signature: bytes) -> bytes:
    encoded = bytes(signature)
    if len(encoded) != 64:
        raise InvalidSignature("P1363 signature must be 64 bytes")
    return encode_dss_signature(
        int.from_bytes(encoded[:32], "big"),
        int.from_bytes(encoded[32:], "big"),
    )


def sign_p1363(private_key: ec.EllipticCurvePrivateKey, value: bytes) -> bytes:
    if not isinstance(private_key.curve, ec.SECP256R1):
        raise ValueError("Relay signing key must use P-256")
    der = private_key.sign(bytes(value), ec.ECDSA(hashes.SHA256()))
    first, second = decode_dss_signature(der)
    return first.to_bytes(32, "big") + second.to_bytes(32, "big")


def verify_p1363(
    public_key: ec.EllipticCurvePublicKey,
    signature: bytes,
    value: bytes,
) -> None:
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise InvalidSignature("Relay signing key must use P-256")
    public_key.verify(p1363_to_der(signature), bytes(value), ec.ECDSA(hashes.SHA256()))


def request_signing_input(
    *,
    method: Any,
    path: Any,
    tenant_id: Any,
    credential_key_id: Any,
    timestamp: int,
    nonce: Any,
    body: bytes,
) -> bytes:
    if type(method) is not str or type(path) is not str:
        raise ValueError("Request method and path must be strings")
    normalized_method = method.upper()
    normalized_path = path
    if not normalized_method.isascii() or not normalized_method.isalpha():
        raise ValueError("Request method must be uppercase ASCII")
    if (
        not normalized_path.startswith("/")
        or "?" in normalized_path
        or "#" in normalized_path
        or "\r" in normalized_path
        or "\n" in normalized_path
        or not normalized_path.isascii()
    ):
        raise ValueError("Request path must be exact, ASCII, and query-free")
    tenant = _identifier(tenant_id, "tenant_id")
    credential = _identifier(credential_key_id, "credential_key_id")
    if type(nonce) is not str:
        raise ValueError("Request nonce must be canonical base64url")
    nonce_value = nonce
    b64url_decode(nonce_value)
    timestamp_value = _positive_integer(timestamp, "timestamp")
    digest = hashlib.sha256(bytes(body)).hexdigest()
    return "\n".join(
        (
            "loopdy-relay-request-v1",
            normalized_method,
            normalized_path,
            tenant,
            credential,
            str(timestamp_value),
            nonce_value,
            digest,
        )
    ).encode("utf-8")


def validate_request_timestamp(value: int, *, now: int) -> int:
    timestamp = _positive_integer(value, "timestamp")
    current = _positive_integer(now, "now")
    if abs(current - timestamp) > 300:
        raise ValueError("Relay request timestamp is outside the five minute window")
    return timestamp


def encrypt_alert(
    *,
    tenant_id: str,
    device_id: str,
    delivery_id: str,
    event_id: str,
    event_type: str,
    title: str,
    body: str,
    recipient_public_key: bytes,
    sender_private_key: ec.EllipticCurvePrivateKey,
    issued: int,
    expires: int,
    ephemeral_private_key: ec.EllipticCurvePrivateKey,
    salt: bytes,
    nonce: bytes,
) -> dict[str, Any]:
    recipient = public_key_from_x963(recipient_public_key)
    if not isinstance(ephemeral_private_key.curve, ec.SECP256R1):
        raise ValueError("Ephemeral key must use P-256")
    ephemeral_public = public_key_bytes(ephemeral_private_key.public_key())
    sender_public = public_key_bytes(sender_private_key.public_key())
    recipient_id = key_id(recipient_public_key)
    sender_id = key_id(sender_public)
    event_ref = event_reference(event_id)
    aad = alert_aad(
        tenant_id=tenant_id,
        device_id=device_id,
        delivery_id=delivery_id,
        event_ref=event_ref,
        recipient_key_id=recipient_id,
        sender_key_id=sender_id,
        issued=issued,
        expires=expires,
    )
    plaintext = alert_plaintext(
        event_id=event_id,
        event_type=event_type,
        title=title,
        body=body,
    )
    if len(salt) != 32 or len(nonce) != 12:
        raise ValueError("Alert salt and nonce must be 32 and 12 bytes")
    shared = ephemeral_private_key.exchange(ec.ECDH(), recipient)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt),
        info=b"loopdy-relay-alert-key-v1\0" + hashlib.sha256(aad).digest(),
    ).derive(shared)
    combined = AESGCM(derived).encrypt(bytes(nonce), plaintext, aad)
    ciphertext, tag = combined[:-16], combined[-16:]
    signed = alert_signature_input(
        aad=aad,
        ephemeral_public_key=ephemeral_public,
        salt=bytes(salt),
        nonce=bytes(nonce),
        ciphertext=ciphertext,
        tag=tag,
    )
    envelope: dict[str, Any] = {
        "v": 1,
        "kind": "alert",
        "delivery_id": _identifier(delivery_id, "delivery_id"),
        "event_ref": event_ref,
        "recipient_key_id": recipient_id,
        "sender_key_id": sender_id,
        "issued": _positive_integer(issued, "issued"),
        "expires": _positive_integer(expires, "expires"),
        "ephemeral_public_key": b64url_encode(ephemeral_public),
        "salt": b64url_encode(salt),
        "nonce": b64url_encode(nonce),
        "ciphertext": b64url_encode(ciphertext),
        "tag": b64url_encode(tag),
        "signature": b64url_encode(sign_p1363(sender_private_key, signed)),
    }
    if len(canonical_json_bytes(envelope)) > 4_096:
        raise ValueError("Encrypted alert exceeds the APNs payload limit")
    return envelope


__all__ = [
    "alert_aad",
    "alert_plaintext",
    "alert_signature_input",
    "b64url_decode",
    "b64url_encode",
    "canonical_json_bytes",
    "encrypt_alert",
    "event_reference",
    "key_id",
    "p1363_to_der",
    "public_key_bytes",
    "public_key_from_x963",
    "request_signing_input",
    "sign_p1363",
    "validate_request_timestamp",
    "verify_p1363",
]
