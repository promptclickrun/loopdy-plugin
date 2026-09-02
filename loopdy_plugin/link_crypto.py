"""End-to-end cryptography for Loopdy Link.

Private keys and the account key stay on paired devices. The relay sees only
public keys, hashes, and authenticated ciphertext.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


_GENERIC_PLAINTEXT_MAX_BYTES = 196_608
_AVATAR_PLAINTEXT_MAX_BYTES = 2_800_000
_ENCRYPTED_ENVELOPE_MAX_BYTES = 3_000_000


def _plaintext_limit(value: Any) -> int:
    if not isinstance(value, dict):
        return _GENERIC_PLAINTEXT_MAX_BYTES
    message_type = value.get("type")
    operation = value.get("operation")
    if (
        message_type == "workspace.request"
        and operation == "agents.avatar.set"
    ) or (
        message_type == "workspace.result"
        and operation == "agents.avatar.get"
    ):
        return _AVATAR_PLAINTEXT_MAX_BYTES
    return _GENERIC_PLAINTEXT_MAX_BYTES


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_base64url(value: str, *, minimum: int = 0, maximum: int = 262_144) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum * 2:
        raise ValueError("invalid base64url value")
    if any(not (character.isalnum() or character in "_-") for character in value):
        raise ValueError("invalid base64url value")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ValueError("invalid base64url value") from exc
    if len(decoded) < minimum or len(decoded) > maximum:
        raise ValueError("invalid base64url value")
    return decoded


def sign_p256_raw(private_key: ec.EllipticCurvePrivateKey, value: bytes) -> bytes:
    der = private_key.sign(value, ec.ECDSA(hashes.SHA256()))
    r_value, s_value = decode_dss_signature(der)
    return r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")


def raw_p256_to_der(value: bytes) -> bytes:
    if len(value) != 64:
        raise ValueError("P-256 signature must be 64 bytes")
    return encode_dss_signature(
        int.from_bytes(value[:32], "big"),
        int.from_bytes(value[32:], "big"),
    )


class AccountCipher:
    """AES-256-GCM envelope used inside account-scoped relay frames."""

    _AAD = b"loopdy-link-frame-v1"

    def __init__(self, account_key: bytes):
        if len(account_key) != 32:
            raise ValueError("Loopdy Link account key must be 32 bytes")
        self._cipher = AESGCM(bytes(account_key))

    def seal(self, value: dict[str, Any]) -> str:
        try:
            plaintext = json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("Loopdy Link payload is not JSON serializable") from exc
        if len(plaintext) > _plaintext_limit(value):
            raise ValueError("Loopdy Link payload is too large")
        nonce = os.urandom(12)
        return encode_base64url(
            nonce + self._cipher.encrypt(nonce, plaintext, self._AAD)
        )

    def open(self, encoded: str) -> dict[str, Any]:
        raw = decode_base64url(
            encoded,
            minimum=29,
            maximum=_ENCRYPTED_ENVELOPE_MAX_BYTES,
        )
        nonce, ciphertext = raw[:12], raw[12:]
        try:
            plaintext = self._cipher.decrypt(nonce, ciphertext, self._AAD)
            value = json.loads(plaintext)
        except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Loopdy Link ciphertext is invalid") from exc
        if not isinstance(value, dict):
            raise ValueError("Loopdy Link plaintext must be an object")
        if len(plaintext) > _plaintext_limit(value):
            raise ValueError("Loopdy Link payload is too large")
        return value


@dataclass(frozen=True)
class HostGrant:
    account_key: bytes


def decrypt_host_grant(
    envelope: str,
    *,
    flow_id: str,
    device_id: str,
    agreement_private_key: x25519.X25519PrivateKey,
) -> HostGrant:
    """Open the one-time grant encrypted by the approving mobile device."""

    raw = decode_base64url(envelope, minimum=61, maximum=65_536)
    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(raw[:32])
    nonce, ciphertext = raw[32:44], raw[44:]
    shared = agreement_private_key.exchange(ephemeral_public)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=flow_id.encode("ascii"),
        info=b"loopdy-link-host-grant-v1",
    ).derive(shared)
    try:
        plaintext = AESGCM(key).decrypt(
            nonce,
            ciphertext,
            flow_id.encode("ascii"),
        )
        value = json.loads(plaintext)
    except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Loopdy Link host grant is invalid") from exc
    if (
        not isinstance(value, dict)
        or value.get("version") != 1
        or value.get("deviceId") != device_id
        or not isinstance(value.get("accountKey"), str)
    ):
        raise ValueError("Loopdy Link host grant is invalid")
    account_key = decode_base64url(value["accountKey"], minimum=32, maximum=32)
    return HostGrant(account_key=account_key)


__all__ = [
    "AccountCipher",
    "HostGrant",
    "decode_base64url",
    "decrypt_host_grant",
    "encode_base64url",
    "raw_p256_to_der",
    "sign_p256_raw",
]
