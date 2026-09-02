"""Interactive, proof-of-possession pairing for a Loopdy Link Hermes host."""

from __future__ import annotations

import hashlib
import base64
import os
import time
from typing import Any, Callable
from urllib.parse import urlencode, urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

from .link_crypto import (
    decrypt_host_grant,
    encode_base64url,
    sign_p256_raw,
)


LINK_SECRET_ENV_KEYS = (
    "LOOPDY_LINK_SIGNING_PRIVATE_KEY",
    "LOOPDY_LINK_AGREEMENT_PRIVATE_KEY",
    "LOOPDY_LINK_ACCOUNT_KEY",
)
LINK_ENV_KEYS = (
    "LOOPDY_LINK_BASE_URL",
    "LOOPDY_LINK_DEVICE_ID",
    "LOOPDY_LINK_AUTHORIZATION_EPOCH",
    *LINK_SECRET_ENV_KEYS,
)


def canonical_pairing_proof(
    *,
    action: str,
    flow_id: str,
    device_id: str,
    signing_public_key_spki: str,
    agreement_public_key: str,
    timestamp: int,
    nonce: str,
    secret_hash: str,
) -> str:
    return "\n".join(
        (
            "loopdy-link-pair-v1",
            action,
            flow_id,
            device_id,
            signing_public_key_spki,
            agreement_public_key,
            str(timestamp),
            nonce,
            secret_hash,
        )
    )


def host_key_commitment(
    *,
    flow_id: str,
    device_id: str,
    signing_public_key_spki: str,
    agreement_public_key: str,
) -> str:
    canonical = "\n".join(
        (
            "loopdy-link-host-key-v1",
            flow_id,
            device_id,
            signing_public_key_spki,
            agreement_public_key,
        )
    )
    return encode_base64url(hashlib.sha256(canonical.encode("utf-8")).digest())


def key_fingerprint(commitment: str) -> str:
    padding = "=" * (-len(commitment) % 4)
    try:
        digest = base64.urlsafe_b64decode(commitment + padding)
    except Exception as exc:
        raise ValueError("Loopdy Link host key commitment is invalid") from exc
    if len(digest) != 32:
        raise ValueError("Loopdy Link host key commitment is invalid")
    return digest[:8].hex().upper()


def _formatted_fingerprint(fingerprint: str) -> str:
    return "-".join(fingerprint[index : index + 4] for index in range(0, 16, 4))


def pair_host(
    base_url: str,
    *,
    save_secret: Callable[[str, str], None],
    announce: Callable[[dict[str, Any]], None],
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    origin = _validated_origin(base_url)
    signing_private = ec.generate_private_key(ec.SECP256R1())
    agreement_private = x25519.X25519PrivateKey.generate()
    device_id = "host_" + encode_base64url(os.urandom(24))
    signing_public = encode_base64url(
        signing_private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    agreement_public = encode_base64url(
        agreement_private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )
    claim_secret = encode_base64url(os.urandom(32))
    claim_secret_hash = encode_base64url(hashlib.sha256(claim_secret.encode("ascii")).digest())
    timestamp = int(time.time())
    nonce = encode_base64url(os.urandom(24))
    create_proof = canonical_pairing_proof(
        action="create",
        flow_id="-",
        device_id=device_id,
        signing_public_key_spki=signing_public,
        agreement_public_key=agreement_public,
        timestamp=timestamp,
        nonce=nonce,
        secret_hash=claim_secret_hash,
    )
    response = _post(
        f"{origin}/v1/pairing/challenges",
        {
            "deviceId": device_id,
            "signingPublicKeySPKI": signing_public,
            "agreementPublicKey": agreement_public,
            "claimSecretHash": claim_secret_hash,
            "timestamp": timestamp,
            "nonce": nonce,
            "proof": encode_base64url(
                sign_p256_raw(signing_private, create_proof.encode("utf-8"))
            ),
        },
    )
    if response.status_code != 201:
        raise ValueError(_public_error(response, "Loopdy Link pairing could not start"))
    challenge = _object_response(response)
    flow_id = _required_text(challenge, "flowId")
    code = _required_text(challenge, "code")
    expires_at = int(challenge.get("expiresAt") or 0)
    commitment = host_key_commitment(
        flow_id=flow_id,
        device_id=device_id,
        signing_public_key_spki=signing_public,
        agreement_public_key=agreement_public,
    )
    pairing_url = "loopdy://link/pair?" + urlencode(
        {"flow": flow_id, "code": code, "kc": commitment}
    )
    announce(
        {
            "state": "waiting_for_approval",
            "code": code,
            "verification_code": _formatted_fingerprint(key_fingerprint(commitment)),
            "pairing_url": pairing_url,
            "expires_at": expires_at,
        }
    )

    deadline = min(expires_at, timestamp + max(30, min(timeout_seconds, 600)))
    while int(time.time()) <= deadline:
        claim_timestamp = int(time.time())
        claim_nonce = encode_base64url(os.urandom(24))
        claim_proof = canonical_pairing_proof(
            action="claim",
            flow_id=flow_id,
            device_id=device_id,
            signing_public_key_spki=signing_public,
            agreement_public_key=agreement_public,
            timestamp=claim_timestamp,
            nonce=claim_nonce,
            secret_hash=claim_secret_hash,
        )
        claimed = _post(
            f"{origin}/v1/pairing/challenges/{flow_id}/claim",
            {
                "claimSecret": claim_secret,
                "timestamp": claim_timestamp,
                "nonce": claim_nonce,
                "proof": encode_base64url(
                    sign_p256_raw(signing_private, claim_proof.encode("utf-8"))
                ),
            },
        )
        if claimed.status_code == 425:
            time.sleep(2)
            continue
        if claimed.status_code != 200:
            raise ValueError(_public_error(claimed, "Loopdy Link pairing failed"))
        grant_value = _object_response(claimed)
        if grant_value.get("deviceId") != device_id:
            raise ValueError("Loopdy Link pairing returned the wrong host")
        grant = decrypt_host_grant(
            _required_text(grant_value, "grantEnvelope"),
            flow_id=flow_id,
            device_id=device_id,
            agreement_private_key=agreement_private,
        )
        epoch = int(grant_value.get("authorizationEpoch") or 0)
        if epoch < 1:
            raise ValueError("Loopdy Link pairing returned an invalid authorization epoch")
        values = {
            "LOOPDY_LINK_BASE_URL": origin,
            "LOOPDY_LINK_DEVICE_ID": device_id,
            "LOOPDY_LINK_AUTHORIZATION_EPOCH": str(epoch),
            "LOOPDY_LINK_SIGNING_PRIVATE_KEY": encode_base64url(
                signing_private.private_bytes(
                    serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            ),
            "LOOPDY_LINK_AGREEMENT_PRIVATE_KEY": encode_base64url(
                agreement_private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            ),
            "LOOPDY_LINK_ACCOUNT_KEY": encode_base64url(grant.account_key),
        }
        for key, value in values.items():
            save_secret(key, value)
        return {
            "state": "paired",
            "device_id": device_id,
            "base_url": origin,
            "authorization_epoch": epoch,
        }
    raise TimeoutError("Loopdy Link pairing approval expired")


def _post(url: str, body: dict[str, Any]) -> httpx.Response:
    return httpx.post(
        url,
        json=body,
        timeout=15.0,
        follow_redirects=False,
        headers={"accept": "application/json"},
    )


def _validated_origin(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Loopdy Link base URL must be an HTTPS origin")
    return f"https://{parsed.netloc}"


def _object_response(response: Any) -> dict[str, Any]:
    value = response.json()
    if not isinstance(value, dict) or value.get("version") != 1:
        raise ValueError("Loopdy Link returned an invalid response")
    return value


def _required_text(value: dict[str, Any], key: str) -> str:
    field = value.get(key)
    if not isinstance(field, str) or not field:
        raise ValueError("Loopdy Link returned an invalid response")
    return field


def _public_error(response: Any, fallback: str) -> str:
    try:
        value = response.json()
        message = value.get("message") if isinstance(value, dict) else None
        if isinstance(message, str) and message:
            return message[:240]
    except Exception:
        pass
    return fallback


__all__ = [
    "LINK_ENV_KEYS",
    "LINK_SECRET_ENV_KEYS",
    "canonical_pairing_proof",
    "host_key_commitment",
    "key_fingerprint",
    "pair_host",
]
