from __future__ import annotations

import hashlib
import hmac
import json
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from loopdy_plugin.relay_crypto import (
    alert_aad,
    alert_plaintext,
    alert_signature_input,
    b64url_decode,
    b64url_encode,
    canonical_json_bytes,
    encrypt_alert,
    event_reference,
    key_id,
    p1363_to_der,
    request_signing_input,
    sign_p1363,
    validate_request_timestamp,
    verify_p1363,
)


FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "contracts"
    / "relay-v1-vector.json"
)
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
SESSION_COORDINATE_FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "contracts"
    / "relay-session-coordinate-v1.json"
)
SESSION_COORDINATE_FIXTURE = json.loads(
    SESSION_COORDINATE_FIXTURE_PATH.read_text(encoding="utf-8")
)


def private_key(scalar_hex: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int(scalar_hex, 16), ec.SECP256R1())


class RelayCryptoTests(unittest.TestCase):
    def test_live_activity_session_reference_matches_shared_cross_runtime_fixture(self) -> None:
        from loopdy_plugin.service import _session_reference

        self.assertEqual(SESSION_COORDINATE_FIXTURE["version"], 1)
        self.assertEqual(
            _session_reference(SESSION_COORDINATE_FIXTURE["hermes_session_id"]),
            SESSION_COORDINATE_FIXTURE["session_ref"],
        )
        self.assertNotEqual(
            _session_reference(SESSION_COORDINATE_FIXTURE["live_session_id"]),
            SESSION_COORDINATE_FIXTURE["session_ref"],
        )
        self.assertNotEqual(
            _session_reference(SESSION_COORDINATE_FIXTURE["activity_id"]),
            SESSION_COORDINATE_FIXTURE["session_ref"],
        )

    def test_shared_fixture_recomputes_all_vector_bytes(self) -> None:
        recipient_private = private_key(FIXTURE["recipient"]["private_scalar_hex"])
        ephemeral_private = private_key(FIXTURE["ephemeral"]["private_scalar_hex"])
        sender_private = private_key(FIXTURE["sender"]["private_scalar_hex"])

        recipient_public = b64url_decode(FIXTURE["recipient"]["public_key_b64url"])
        ephemeral_public = b64url_decode(FIXTURE["ephemeral"]["public_key_b64url"])
        sender_public = b64url_decode(FIXTURE["sender"]["public_key_b64url"])
        self.assertEqual(recipient_public.hex(), FIXTURE["recipient"]["public_key_hex"])
        self.assertEqual(ephemeral_public.hex(), FIXTURE["ephemeral"]["public_key_hex"])
        self.assertEqual(sender_public.hex(), FIXTURE["sender"]["public_key_hex"])
        self.assertEqual(key_id(recipient_public), FIXTURE["recipient"]["key_id"])
        self.assertEqual(key_id(sender_public), FIXTURE["sender"]["key_id"])
        self.assertEqual(event_reference(FIXTURE["event_id"]), FIXTURE["event_ref"])

        aad = alert_aad(
            tenant_id=FIXTURE["tenant_id"],
            device_id=FIXTURE["device_id"],
            delivery_id=FIXTURE["delivery_id"],
            event_ref=FIXTURE["event_ref"],
            recipient_key_id=FIXTURE["recipient"]["key_id"],
            sender_key_id=FIXTURE["sender"]["key_id"],
            issued=FIXTURE["issued"],
            expires=FIXTURE["expires"],
        )
        self.assertEqual(aad.decode("utf-8"), FIXTURE["aad"])
        self.assertEqual(hashlib.sha256(aad).hexdigest(), FIXTURE["aad_sha256_hex"])
        plaintext = alert_plaintext(
            event_id=FIXTURE["event_id"],
            event_type=FIXTURE["event_type"],
            title=FIXTURE["title"],
            body=FIXTURE["body"],
        )
        self.assertEqual(plaintext.hex(), FIXTURE["plaintext_hex"])

        shared = recipient_private.exchange(ec.ECDH(), ephemeral_private.public_key())
        self.assertEqual(shared.hex(), FIXTURE["shared_secret_hex"])
        info = b"loopdy-relay-alert-key-v1\0" + hashlib.sha256(aad).digest()
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=bytes.fromhex(FIXTURE["salt_hex"]),
            info=info,
        ).derive(shared)
        self.assertEqual(derived.hex(), FIXTURE["derived_key_hex"])
        combined = AESGCM(derived).encrypt(
            bytes.fromhex(FIXTURE["nonce_hex"]), plaintext, aad
        )
        self.assertEqual(combined[:-16].hex(), FIXTURE["ciphertext_hex"])
        self.assertEqual(combined[-16:].hex(), FIXTURE["tag_hex"])

        signed = alert_signature_input(
            aad=aad,
            ephemeral_public_key=ephemeral_public,
            salt=bytes.fromhex(FIXTURE["salt_hex"]),
            nonce=bytes.fromhex(FIXTURE["nonce_hex"]),
            ciphertext=combined[:-16],
            tag=combined[-16:],
        )
        self.assertEqual(len(signed), 311)
        self.assertEqual(
            hashlib.sha256(signed).hexdigest(), FIXTURE["signature_input_sha256_hex"]
        )
        fixed_signature = b64url_decode(FIXTURE["signature_b64url"])
        verify_p1363(sender_private.public_key(), fixed_signature, signed)
        sender_private.public_key().verify(
            p1363_to_der(fixed_signature), signed, ec.ECDSA(hashes.SHA256())
        )
        order = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        r = int.from_bytes(fixed_signature[:32], "big")
        s = int.from_bytes(fixed_signature[32:], "big")
        high_s = max(s, order - s)
        high_signature = r.to_bytes(32, "big") + high_s.to_bytes(32, "big")
        verify_p1363(sender_private.public_key(), high_signature, signed)

        randomized = sign_p1363(sender_private, signed)
        self.assertEqual(len(randomized), 64)
        verify_p1363(sender_private.public_key(), randomized, signed)

    def test_encrypt_alert_matches_vector_with_injected_ephemeral_salt_and_nonce(self) -> None:
        encrypted = encrypt_alert(
            tenant_id=FIXTURE["tenant_id"],
            device_id=FIXTURE["device_id"],
            delivery_id=FIXTURE["delivery_id"],
            event_id=FIXTURE["event_id"],
            event_type=FIXTURE["event_type"],
            title=FIXTURE["title"],
            body=FIXTURE["body"],
            recipient_public_key=b64url_decode(FIXTURE["recipient"]["public_key_b64url"]),
            sender_private_key=private_key(FIXTURE["sender"]["private_scalar_hex"]),
            issued=FIXTURE["issued"],
            expires=FIXTURE["expires"],
            ephemeral_private_key=private_key(FIXTURE["ephemeral"]["private_scalar_hex"]),
            salt=bytes.fromhex(FIXTURE["salt_hex"]),
            nonce=bytes.fromhex(FIXTURE["nonce_hex"]),
        )
        expected = json.loads(FIXTURE["canonical_delivery_body"])["envelope"]
        self.assertEqual({**encrypted, "signature": expected["signature"]}, expected)
        verify_p1363(
            private_key(FIXTURE["sender"]["private_scalar_hex"]).public_key(),
            b64url_decode(encrypted["signature"]),
            alert_signature_input(
                aad=FIXTURE["aad"].encode(),
                ephemeral_public_key=b64url_decode(encrypted["ephemeral_public_key"]),
                salt=b64url_decode(encrypted["salt"]),
                nonce=b64url_decode(encrypted["nonce"]),
                ciphertext=b64url_decode(encrypted["ciphertext"]),
                tag=b64url_decode(encrypted["tag"]),
            ),
        )

    def test_canonical_body_and_request_hmac_match_vector(self) -> None:
        self.assertEqual(canonical_json_bytes({"label": "Café"}), b'{"label":"Caf\xc3\xa9"}')
        body = canonical_json_bytes(json.loads(FIXTURE["canonical_delivery_body"]))
        self.assertEqual(body.decode(), FIXTURE["canonical_delivery_body"])
        self.assertEqual(hashlib.sha256(body).hexdigest(), FIXTURE["body_sha256_hex"])
        signed = request_signing_input(
            method="post",
            path="/v1/deliveries",
            tenant_id=FIXTURE["tenant_id"],
            credential_key_id=FIXTURE["credential_key_id"],
            timestamp=FIXTURE["issued"],
            nonce=FIXTURE["request_nonce_b64url"],
            body=body,
        )
        self.assertEqual(signed.decode(), FIXTURE["request_signing_input"])
        digest = hmac.new(
            bytes.fromhex(FIXTURE["hmac_key_hex"]), signed, hashlib.sha256
        ).digest()
        self.assertEqual(digest.hex(), FIXTURE["request_hmac_hex"])
        self.assertEqual(b64url_encode(digest), FIXTURE["request_hmac_b64url"])

    def test_rejects_noncanonical_base64_identifiers_bounds_and_bad_signatures(self) -> None:
        for invalid in ("", "AA==", "A+", "A/", "AB", "A\n"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                b64url_decode(invalid)
        for invalid in (True, 123, b"AA"):
            with self.subTest(invalid_type=type(invalid).__name__), self.assertRaises(ValueError):
                b64url_decode(invalid)
        with self.assertRaisesRegex(ValueError, "ASCII"):
            event_reference(True)
        with self.assertRaisesRegex(ValueError, "NFC"):
            alert_plaintext(
                event_id="event_01",
                event_type="approval.required",
                title=True,
                body="Body",
            )
        with self.assertRaisesRegex(ValueError, "ASCII"):
            event_reference("approval.required:événement")
        with self.assertRaisesRegex(ValueError, "title"):
            alert_plaintext(
                event_id="event_01",
                event_type="approval.required",
                title="x" * 121,
                body="Body",
            )
        with self.assertRaisesRegex(ValueError, "900"):
            alert_aad(
                tenant_id=FIXTURE["tenant_id"],
                device_id=FIXTURE["device_id"],
                delivery_id=FIXTURE["delivery_id"],
                event_ref=FIXTURE["event_ref"],
                recipient_key_id=FIXTURE["recipient"]["key_id"],
                sender_key_id=FIXTURE["sender"]["key_id"],
                issued=FIXTURE["issued"],
                expires=FIXTURE["issued"] + 901,
            )
        with self.assertRaises(InvalidSignature):
            verify_p1363(
                private_key(FIXTURE["sender"]["private_scalar_hex"]).public_key(),
                b"\0" * 64,
                b"wrong",
            )

    def test_request_timestamp_window_is_inclusive(self) -> None:
        self.assertEqual(validate_request_timestamp(1_000, now=1_300), 1_000)
        self.assertEqual(validate_request_timestamp(1_000, now=700), 1_000)
        for now in (699, 1_301):
            with self.assertRaisesRegex(ValueError, "timestamp"):
                validate_request_timestamp(1_000, now=now)
        for value in (True, 1.5):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "integer"):
                validate_request_timestamp(value, now=1_000)


if __name__ == "__main__":
    unittest.main()
