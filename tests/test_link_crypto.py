from __future__ import annotations

import base64
import json
import os
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class LinkCryptoTests(unittest.TestCase):
    def test_account_cipher_round_trips_and_rejects_tampering(self) -> None:
        from loopdy_plugin.link_crypto import AccountCipher

        cipher = AccountCipher(os.urandom(32))
        encoded = cipher.seal({"version": 1, "type": "user.message", "text": "hello"})

        self.assertEqual(cipher.open(encoded)["text"], "hello")
        raw = bytearray(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        raw[-1] ^= 1
        with self.assertRaises(ValueError):
            cipher.open(_b64(bytes(raw)))

    def test_account_cipher_only_allows_large_native_avatar_operations(self) -> None:
        from loopdy_plugin.link_crypto import AccountCipher
        from loopdy_plugin.link_contracts import EncryptedFrame, parse_encrypted_frame

        cipher = AccountCipher(os.urandom(32))
        data = "data:image/png;base64," + base64.b64encode(
            b"\x89PNG\r\n\x1a\n" + (b"a" * 200_000)
        ).decode("ascii")
        avatar_set = {
            "version": 1,
            "type": "workspace.request",
            "requestId": "workspace_avatar_set_0001",
            "operation": "agents.avatar.set",
            "payload": {
                "agentId": "default",
                "avatar": {
                    "mimeType": "image/png",
                    "byteCount": 200_008,
                    "sha256": "sha256-agent-avatar-large-0001",
                    "data": data,
                },
            },
            "sentAt": 1_788_000_063,
        }

        encoded = cipher.seal(avatar_set)
        frame = EncryptedFrame(
            frame_id="frame_avatar_transport_0001",
            sender_device_id="device_avatar_transport_0001",
            sender_epoch=1,
            sequence=1,
            ack=0,
            ciphertext=encoded,
        )

        self.assertEqual(cipher.open(encoded), avatar_set)
        parsed = parse_encrypted_frame(json.dumps(frame.wire_value(), separators=(",", ":")))
        self.assertEqual(parsed.ciphertext, encoded)
        with self.assertRaises(ValueError):
            cipher.seal({"version": 1, "type": "user.message", "text": data})

    def test_host_grant_uses_x25519_hkdf_and_binds_the_flow(self) -> None:
        from loopdy_plugin.link_crypto import decrypt_host_grant

        host_private = x25519.X25519PrivateKey.generate()
        ephemeral = x25519.X25519PrivateKey.generate()
        flow_id = _b64(os.urandom(24))
        shared = ephemeral.exchange(host_private.public_key())
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=flow_id.encode("ascii"),
            info=b"loopdy-link-host-grant-v1",
        ).derive(shared)
        nonce = os.urandom(12)
        account_key = os.urandom(32)
        plaintext = json.dumps(
            {
                "version": 1,
                "deviceId": "host-fixture",
                "accountKey": _b64(account_key),
            },
            separators=(",", ":"),
        ).encode()
        ephemeral_public = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        envelope = _b64(
            ephemeral_public
            + nonce
            + AESGCM(key).encrypt(nonce, plaintext, flow_id.encode("ascii"))
        )

        grant = decrypt_host_grant(
            envelope,
            flow_id=flow_id,
            device_id="host-fixture",
            agreement_private_key=host_private,
        )
        self.assertEqual(grant.account_key, account_key)
        with self.assertRaises(ValueError):
            decrypt_host_grant(
                envelope,
                flow_id=_b64(os.urandom(24)),
                device_id="host-fixture",
                agreement_private_key=host_private,
            )

    def test_device_signatures_are_raw_p256_and_verify_with_the_public_key(self) -> None:
        from loopdy_plugin.link_crypto import sign_p256_raw

        private_key = ec.generate_private_key(ec.SECP256R1())
        signature = sign_p256_raw(private_key, b"canonical request")

        self.assertEqual(len(signature), 64)
        private_key.public_key().verify(
            __import__("loopdy_plugin.link_crypto", fromlist=["raw_p256_to_der"]).raw_p256_to_der(
                signature
            ),
            b"canonical request",
            ec.ECDSA(hashes.SHA256()),
        )


if __name__ == "__main__":
    unittest.main()
