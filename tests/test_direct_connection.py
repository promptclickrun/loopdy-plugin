from __future__ import annotations

import json
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from loopdy_plugin.link_crypto import (
    decode_base64url,
    encode_base64url,
    raw_p256_to_der,
    sign_p256_raw,
)


class _State:
    def __init__(self) -> None:
        self.values: dict[str, object] = {}

    def get(self, key: str, default=None):
        return self.values.get(key, default)

    def set(self, key: str, value: object) -> None:
        self.values[key] = value


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _FailingState(_State):
    def __init__(self) -> None:
        super().__init__()
        self.fail = True

    def set(self, key: str, value: object) -> None:
        if self.fail:
            raise OSError("fixture persistence failure")
        super().set(key, value)


def _spki(private_key: ec.EllipticCurvePrivateKey) -> str:
    return encode_base64url(
        private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _device(
    device_id: str,
    *,
    role: str,
    epoch: int,
    lifecycle: str = "active",
    revoked_at: int | None = None,
) -> dict[str, object]:
    return {
        "deviceId": device_id,
        "encryptedName": "encrypted-name",
        "role": role,
        "kind": "hermes_host" if role == "host" else "phone",
        "lifecycle": lifecycle,
        "revision": 1,
        "authorizationEpoch": epoch,
        "connection": "online",
        "pushState": None if role == "host" else "ready",
        "pushRevision": 0 if role == "host" else 1,
        "createdAt": 1,
        "revokedAt": revoked_at,
        "lastSeenBucket": 1,
    }


def _catalog(*devices: dict[str, object]) -> dict[str, object]:
    return {"version": 1, "devices": list(devices)}


class DirectConnectionTests(unittest.TestCase):
    def _authority(self, state: _State | None = None, clock: _Clock | None = None):
        from loopdy_plugin.direct_connection import DirectConnectionAuthority

        self.host_key = ec.generate_private_key(ec.SECP256R1())
        self.phone_key = ec.generate_private_key(ec.SECP256R1())
        self.state = state or _State()
        self.clock = clock or _Clock()
        return DirectConnectionAuthority(
            account_origin="https://account.example",
            direct_origin="https://direct.example:8443/",
            host_device_id="host_1",
            host_epoch=7,
            host_private_key=self.host_key,
            state=self.state,
            monotonic=self.clock,
        )

    def _enrollment_payload(
        self,
        *,
        phone_key=None,
        payload_overrides=None,
        transcript_overrides=None,
    ):
        from loopdy_plugin.direct_connection import canonical_enrollment_transcript

        key = phone_key or self.phone_key
        payload = {
            "version": 1,
            "exchangeId": "exchange_1",
            "phoneNonce": "phone_nonce_1",
            "phonePublicKey": _spki(key),
        }
        payload.update(payload_overrides or {})
        transcript_values = {
            "account_origin": "https://account.example",
            "direct_origin": "https://direct.example:8443",
            "host_device_id": "host_1",
            "host_epoch": 7,
            "phone_device_id": "phone_1",
            "phone_epoch": 11,
            "exchange_id": payload["exchangeId"],
            "phone_nonce": payload["phoneNonce"],
            "phone_public_key": payload["phonePublicKey"],
        }
        transcript_values.update(transcript_overrides or {})
        transcript = canonical_enrollment_transcript(**transcript_values)
        payload["phoneProof"] = encode_base64url(sign_p256_raw(key, transcript))
        return payload

    def _enrollment(self, authority, **overrides):
        payload = self._enrollment_payload(payload_overrides=overrides)
        return authority._enroll_from_link(
            payload,
            trusted_sender_device_id="phone_1",
            trusted_sender_epoch=11,
        )

    def _enroll_identity(
        self,
        authority,
        *,
        key,
        device_id: str,
        epoch: int,
        exchange_id: str,
        phone_nonce: str,
    ):
        from loopdy_plugin.direct_connection import canonical_enrollment_transcript

        public_key = _spki(key)
        transcript = canonical_enrollment_transcript(
            account_origin="https://account.example",
            direct_origin="https://direct.example:8443",
            host_device_id="host_1",
            host_epoch=7,
            phone_device_id=device_id,
            phone_epoch=epoch,
            exchange_id=exchange_id,
            phone_nonce=phone_nonce,
            phone_public_key=public_key,
        )
        return authority._enroll_from_link(
            {
                "version": 1,
                "exchangeId": exchange_id,
                "phoneNonce": phone_nonce,
                "phonePublicKey": public_key,
                "phoneProof": encode_base64url(sign_p256_raw(key, transcript)),
            },
            trusted_sender_device_id=device_id,
            trusted_sender_epoch=epoch,
        )

    def test_canonical_transcript_is_domain_separated_compact_sorted_json(self) -> None:
        from loopdy_plugin.direct_connection import canonical_enrollment_transcript

        actual = canonical_enrollment_transcript(
            account_origin="https://account.example",
            direct_origin="https://direct.example",
            host_device_id="host_1",
            host_epoch=7,
            phone_device_id="phone_1",
            phone_epoch=11,
            exchange_id="exchange_1",
            phone_nonce="nonce_1",
            phone_public_key="public_key_1",
        )

        expected_json = (
            b'{"accountOrigin":"https://account.example","directOrigin":"https://direct.example",'
            b'"exchangeId":"exchange_1","hostDeviceId":"host_1","hostEpoch":7,'
            b'"phoneDeviceId":"phone_1","phoneEpoch":11,"phoneNonce":"nonce_1",'
            b'"phonePublicKey":"public_key_1","version":1}'
        )
        self.assertEqual(actual, b"loopdy-direct-enrollment-v1\n" + expected_json)

    def test_enrollment_result_transcript_has_deterministic_wire_fixture(self) -> None:
        from loopdy_plugin.direct_connection import canonical_enrollment_result_transcript

        result = {
            "version": 1,
            "exchangeId": "exchange_1",
            "phoneNonce": "nonce_1",
            "accountOrigin": "https://account.example",
            "directOrigin": "https://direct.example",
            "hostDeviceId": "host_1",
            "hostEpoch": 7,
            "hostPublicKey": "host_public_key",
            "hostKeyFingerprint": "host_fingerprint",
            "phoneDeviceId": "phone_1",
            "phoneEpoch": 11,
            "phonePublicKey": "phone_public_key",
            "phoneKeyFingerprint": "phone_fingerprint",
        }
        expected_json = (
            b'{"accountOrigin":"https://account.example","directOrigin":"https://direct.example",'
            b'"exchangeId":"exchange_1","hostDeviceId":"host_1","hostEpoch":7,'
            b'"hostKeyFingerprint":"host_fingerprint","hostPublicKey":"host_public_key",'
            b'"phoneDeviceId":"phone_1","phoneEpoch":11,'
            b'"phoneKeyFingerprint":"phone_fingerprint","phoneNonce":"nonce_1",'
            b'"phonePublicKey":"phone_public_key","version":1}'
        )
        self.assertEqual(
            canonical_enrollment_result_transcript(result),
            b"loopdy-direct-enrollment-result-v1\n" + expected_json,
        )

    def test_real_p256_enrollment_and_reconnect_interoperate(self) -> None:
        from loopdy_plugin.direct_connection import canonical_session_transcript

        authority = self._authority()
        enrollment = self._enrollment(authority)
        repeated = self._enrollment(authority)
        self.assertEqual(repeated, enrollment)
        self.assertEqual(enrollment["hostPublicKey"], _spki(self.host_key))
        self.assertEqual(enrollment["phonePublicKey"], _spki(self.phone_key))
        enrollment_body = dict(enrollment)
        host_proof = decode_base64url(enrollment_body.pop("hostProof"))
        self.host_key.public_key().verify(
            raw_p256_to_der(host_proof),
            b"loopdy-direct-enrollment-result-v1\n"
            + json.dumps(
                enrollment_body,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode(),
            ec.ECDSA(hashes.SHA256()),
        )

        authority._refresh_lifecycle_catalog(
            _catalog(
                _device("host_1", role="host", epoch=7),
                _device("phone_1", role="mobile", epoch=11),
            )
        )
        challenge = authority.issue_challenge(
            peer_device_id="phone_1",
            peer_epoch=11,
            connection_id="connection_1",
        )
        transcript = canonical_session_transcript(
            account_origin="https://account.example",
            direct_origin="https://direct.example:8443",
            host_device_id="host_1",
            host_epoch=7,
            peer_device_id="phone_1",
            peer_epoch=11,
            connection_id="connection_1",
            nonce=challenge["nonce"],
        )
        self.host_key.public_key().verify(
            raw_p256_to_der(decode_base64url(challenge["hostProof"])),
            transcript,
            ec.ECDSA(hashes.SHA256()),
        )
        peer = authority.verify_challenge_response(
            peer_device_id="phone_1",
            peer_epoch=11,
            connection_id="connection_1",
            nonce=challenge["nonce"],
            peer_proof=encode_base64url(sign_p256_raw(self.phone_key, transcript)),
        )
        self.assertEqual(peer.peer_device_id, "phone_1")
        self.assertIs(authority.validate_peer(peer), peer)
        with self.assertRaises(ValueError):
            authority.verify_challenge_response(
                peer_device_id="phone_1",
                peer_epoch=11,
                connection_id="connection_1",
                nonce=challenge["nonce"],
                peer_proof=encode_base64url(sign_p256_raw(self.phone_key, transcript)),
            )

        reconnect = authority.issue_challenge(
            peer_device_id="phone_1",
            peer_epoch=11,
            connection_id="connection_2",
        )
        self.assertNotEqual(reconnect["nonce"], challenge["nonce"])

    def test_constructor_rejects_non_origins_invalid_ids_epochs_and_non_p256_key(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec
        from loopdy_plugin.direct_connection import DirectConnectionAuthority

        good = {
            "account_origin": "https://account.example",
            "direct_origin": "https://direct.example",
            "host_device_id": "host_1",
            "host_epoch": 1,
            "host_private_key": ec.generate_private_key(ec.SECP256R1()),
            "state": _State(),
        }
        for field, value in (
            ("account_origin", "http://account.example"),
            ("account_origin", "https://user@account.example"),
            ("account_origin", "https://.example"),
            ("account_origin", "https://-bad.example"),
            ("account_origin", "https://bad..example"),
            ("account_origin", "https://account.example?#"),
            ("account_origin", "https://account.example:"),
            ("account_origin", "https://account.example:0"),
            ("direct_origin", "https://direct.example/path"),
            ("direct_origin", "https://direct.example?query=yes"),
            ("host_device_id", "bad/id"),
            ("host_epoch", True),
            ("host_epoch", 0),
            ("host_private_key", ec.generate_private_key(ec.SECP384R1())),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                DirectConnectionAuthority(**{**good, field: value})

    def test_enrollment_rejects_unknown_hostile_and_malformed_inputs(self) -> None:
        authority = self._authority()
        cases = []
        cases.append({**self._enrollment_payload(), "unknown": "field"})
        for field, value in (
            ("version", True),
            ("version", 1.0),
            ("exchangeId", "bad/id"),
            ("phoneNonce", "bad nonce"),
            ("phonePublicKey", "AA"),
            ("phoneProof", "AA"),
        ):
            payload = self._enrollment_payload()
            payload[field] = value
            cases.append(payload)
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                authority._enroll_from_link(
                    payload,
                    trusted_sender_device_id="phone_1",
                    trusted_sender_epoch=11,
                )

        substitutions = (
            {"account_origin": "https://other-account.example"},
            {"direct_origin": "https://other-direct.example"},
            {"host_device_id": "other_host"},
            {"host_epoch": 8},
            {"phone_device_id": "other_phone"},
            {"phone_epoch": 12},
        )
        for substitution in substitutions:
            with self.subTest(substitution=substitution), self.assertRaises(ValueError):
                authority._enroll_from_link(
                    self._enrollment_payload(transcript_overrides=substitution),
                    trusted_sender_device_id="phone_1",
                    trusted_sender_epoch=11,
                )

        wrong_key = ec.generate_private_key(ec.SECP256R1())
        payload = self._enrollment_payload()
        payload["phoneProof"] = encode_base64url(
            sign_p256_raw(wrong_key, b"wrong-key-proof")
        )
        with self.assertRaises(ValueError):
            authority._enroll_from_link(
                payload,
                trusted_sender_device_id="phone_1",
                trusted_sender_epoch=11,
            )

    def test_same_epoch_key_rotation_is_rejected_and_higher_epoch_replaces(self) -> None:
        authority = self._authority()
        self._enrollment(authority)
        replacement = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(ValueError):
            self._enroll_identity(
                authority,
                key=replacement,
                device_id="phone_1",
                epoch=11,
                exchange_id="exchange_2",
                phone_nonce="phone_nonce_2",
            )

        result = self._enroll_identity(
            authority,
            key=replacement,
            device_id="phone_1",
            epoch=12,
            exchange_id="exchange_3",
            phone_nonce="phone_nonce_3",
        )
        self.assertEqual(result["phoneEpoch"], 12)
        self.assertEqual(result["phonePublicKey"], _spki(replacement))
        authority._refresh_lifecycle_catalog(
            _catalog(
                _device("host_1", role="host", epoch=7),
                _device("phone_1", role="mobile", epoch=12),
            )
        )
        with self.assertRaises(ValueError):
            authority.issue_challenge(
                peer_device_id="phone_1", peer_epoch=11, connection_id="old_epoch"
            )

    def test_phone_nonce_is_one_time_bounded_to_authority_lifetime(self) -> None:
        authority = self._authority()
        self._enrollment(authority)
        with self.assertRaises(ValueError):
            self._enroll_identity(
                authority,
                key=self.phone_key,
                device_id="phone_2",
                epoch=11,
                exchange_id="exchange_2",
                phone_nonce="phone_nonce_1",
            )
        self.clock.advance(301)
        result = self._enroll_identity(
            authority,
            key=self.phone_key,
            device_id="phone_2",
            epoch=11,
            exchange_id="exchange_2",
            phone_nonce="phone_nonce_1",
        )
        self.assertEqual(result["phoneDeviceId"], "phone_2")

    def test_bindings_are_owner_scoped_and_restart_requires_fresh_lifecycle(self) -> None:
        from loopdy_plugin.direct_connection import DirectConnectionAuthority

        authority = self._authority()
        self._enrollment(authority)
        shared_state = self.state
        host_key = self.host_key
        phone_key = self.phone_key
        clock = self.clock
        restarted = DirectConnectionAuthority(
            account_origin="https://account.example",
            direct_origin="https://direct.example:8443",
            host_device_id="host_1",
            host_epoch=7,
            host_private_key=host_key,
            state=shared_state,
            monotonic=clock,
        )
        with self.assertRaises(ValueError):
            restarted.issue_challenge(
                peer_device_id="phone_1", peer_epoch=11, connection_id="restart"
            )
        restarted._refresh_lifecycle_catalog(
            _catalog(
                _device("host_1", role="host", epoch=7),
                _device("phone_1", role="mobile", epoch=11),
            )
        )
        self.assertIn(
            "nonce",
            restarted.issue_challenge(
                peer_device_id="phone_1", peer_epoch=11, connection_id="restart"
            ),
        )

        other_owner = DirectConnectionAuthority(
            account_origin="https://account.example",
            direct_origin="https://other-direct.example",
            host_device_id="host_1",
            host_epoch=7,
            host_private_key=host_key,
            state=shared_state,
            monotonic=clock,
        )
        other_owner._refresh_lifecycle_catalog(
            _catalog(
                _device("host_1", role="host", epoch=7),
                _device("phone_1", role="mobile", epoch=11),
            )
        )
        with self.assertRaises(ValueError):
            other_owner.issue_challenge(
                peer_device_id="phone_1", peer_epoch=11, connection_id="other_owner"
            )
        self.phone_key = phone_key

    def test_tampered_persisted_binding_is_not_loaded(self) -> None:
        from loopdy_plugin.direct_connection import DirectConnectionAuthority

        authority = self._authority()
        self._enrollment(authority)
        state_key = next(iter(self.state.values))
        stored = self.state.values[state_key]
        stored["bindings"]["phone_1"]["outcome"]["phoneEpoch"] = 99
        restarted = DirectConnectionAuthority(
            account_origin="https://account.example",
            direct_origin="https://direct.example:8443",
            host_device_id="host_1",
            host_epoch=7,
            host_private_key=self.host_key,
            state=self.state,
            monotonic=self.clock,
        )
        restarted._refresh_lifecycle_catalog(
            _catalog(
                _device("host_1", role="host", epoch=7),
                _device("phone_1", role="mobile", epoch=11),
            )
        )
        with self.assertRaises(ValueError):
            restarted.issue_challenge(
                peer_device_id="phone_1", peer_epoch=11, connection_id="tampered"
            )

    def test_noninteger_persisted_schema_version_is_not_loaded(self) -> None:
        from loopdy_plugin.direct_connection import DirectConnectionAuthority

        authority = self._authority()
        self._enrollment(authority)
        state_key = next(iter(self.state.values))
        self.state.values[state_key]["version"] = True
        restarted = DirectConnectionAuthority(
            account_origin="https://account.example",
            direct_origin="https://direct.example:8443",
            host_device_id="host_1",
            host_epoch=7,
            host_private_key=self.host_key,
            state=self.state,
            monotonic=self.clock,
        )
        restarted._refresh_lifecycle_catalog(
            _catalog(
                _device("host_1", role="host", epoch=7),
                _device("phone_1", role="mobile", epoch=11),
            )
        )
        with self.assertRaises(ValueError):
            restarted.issue_challenge(
                peer_device_id="phone_1", peer_epoch=11, connection_id="bad_schema"
            )

    def test_persistence_contains_only_public_owner_and_enrollment_material(self) -> None:
        authority = self._authority()
        self._enrollment(authority)
        serialized = json.dumps(self.state.values, sort_keys=True)
        private_pkcs8 = encode_base64url(
            self.host_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.assertNotIn(private_pkcs8, serialized)
        self.assertNotIn("phoneProof", serialized)
        self.assertIn("hostPublicKey", serialized)

    def test_lifecycle_staleness_missing_devices_revocation_and_failed_refresh_deny(self) -> None:
        authority = self._authority()
        self._enrollment(authority)
        active = _catalog(
            _device("host_1", role="host", epoch=7),
            _device("phone_1", role="mobile", epoch=11),
        )
        authority._refresh_lifecycle_catalog(active)
        self.clock.advance(299)
        invalid = _catalog(*active["devices"])
        invalid["extra"] = True
        with self.assertRaises(ValueError):
            authority._refresh_lifecycle_catalog(invalid)
        with self.assertRaises(ValueError):
            authority._refresh_lifecycle_catalog({"version": 1.0, "devices": []})
        malformed_device = _device("host_1", role="host", epoch=7)
        malformed_device["role"] = []
        with self.assertRaises(ValueError):
            authority._refresh_lifecycle_catalog(_catalog(malformed_device))
        self.clock.advance(2)
        with self.assertRaises(ValueError):
            authority.issue_challenge(
                peer_device_id="phone_1", peer_epoch=11, connection_id="stale"
            )

        for catalog in (
            _catalog(_device("host_1", role="host", epoch=7)),
            _catalog(
                _device("host_1", role="host", epoch=7),
                _device(
                    "phone_1",
                    role="mobile",
                    epoch=12,
                    lifecycle="revoked",
                    revoked_at=2,
                ),
            ),
            _catalog(
                _device("host_1", role="mobile", epoch=7),
                _device("phone_1", role="mobile", epoch=11),
            ),
        ):
            authority._refresh_lifecycle_catalog(catalog)
            with self.assertRaises(ValueError):
                authority.issue_challenge(
                    peer_device_id="phone_1", peer_epoch=11, connection_id="denied"
                )

    def test_challenge_is_single_use_connection_bound_and_expiring(self) -> None:
        from loopdy_plugin.direct_connection import canonical_session_transcript

        authority = self._authority()
        self._enrollment(authority)
        authority._refresh_lifecycle_catalog(
            _catalog(
                _device("host_1", role="host", epoch=7),
                _device("phone_1", role="mobile", epoch=11),
            )
        )
        challenge = authority.issue_challenge(
            peer_device_id="phone_1", peer_epoch=11, connection_id="connection_1"
        )
        transcript = canonical_session_transcript(
            account_origin="https://account.example",
            direct_origin="https://direct.example:8443",
            host_device_id="host_1",
            host_epoch=7,
            peer_device_id="phone_1",
            peer_epoch=11,
            connection_id="connection_1",
            nonce=challenge["nonce"],
        )
        proof = encode_base64url(sign_p256_raw(self.phone_key, transcript))
        with self.assertRaises(ValueError):
            authority.verify_challenge_response(
                peer_device_id="phone_1",
                peer_epoch=11,
                connection_id="connection_2",
                nonce=challenge["nonce"],
                peer_proof=proof,
            )
        with self.assertRaises(ValueError):
            authority.verify_challenge_response(
                peer_device_id="phone_1",
                peer_epoch=11,
                connection_id="connection_1",
                nonce=challenge["nonce"],
                peer_proof=proof,
            )

        challenge = authority.issue_challenge(
            peer_device_id="phone_1", peer_epoch=11, connection_id="connection_3"
        )
        self.clock.advance(31)
        with self.assertRaises(ValueError):
            authority.verify_challenge_response(
                peer_device_id="phone_1",
                peer_epoch=11,
                connection_id="connection_3",
                nonce=challenge["nonce"],
                peer_proof=encode_base64url(b"x" * 64),
            )

    def test_invalid_proof_consumes_challenge_and_validate_peer_checks_owner(self) -> None:
        from loopdy_plugin.direct_connection import (
            DirectConnectionAuthority,
            canonical_session_transcript,
        )

        authority = self._authority()
        self._enrollment(authority)
        catalog = _catalog(
            _device("host_1", role="host", epoch=7),
            _device("phone_1", role="mobile", epoch=11),
        )
        authority._refresh_lifecycle_catalog(catalog)
        challenge = authority.issue_challenge(
            peer_device_id="phone_1", peer_epoch=11, connection_id="connection_1"
        )
        with self.assertRaises(ValueError):
            authority.verify_challenge_response(
                peer_device_id="phone_1",
                peer_epoch=11,
                connection_id="connection_1",
                nonce=challenge["nonce"],
                peer_proof="AA",
            )
        transcript = canonical_session_transcript(
            account_origin="https://account.example",
            direct_origin="https://direct.example:8443",
            host_device_id="host_1",
            host_epoch=7,
            peer_device_id="phone_1",
            peer_epoch=11,
            connection_id="connection_1",
            nonce=challenge["nonce"],
        )
        with self.assertRaises(ValueError):
            authority.verify_challenge_response(
                peer_device_id="phone_1",
                peer_epoch=11,
                connection_id="connection_1",
                nonce=challenge["nonce"],
                peer_proof=encode_base64url(sign_p256_raw(self.phone_key, transcript)),
            )

        valid = authority.issue_challenge(
            peer_device_id="phone_1", peer_epoch=11, connection_id="connection_2"
        )
        valid_transcript = canonical_session_transcript(
            account_origin="https://account.example",
            direct_origin="https://direct.example:8443",
            host_device_id="host_1",
            host_epoch=7,
            peer_device_id="phone_1",
            peer_epoch=11,
            connection_id="connection_2",
            nonce=valid["nonce"],
        )
        peer = authority.verify_challenge_response(
            peer_device_id="phone_1",
            peer_epoch=11,
            connection_id="connection_2",
            nonce=valid["nonce"],
            peer_proof=encode_base64url(sign_p256_raw(self.phone_key, valid_transcript)),
        )
        other = DirectConnectionAuthority(
            account_origin="https://account.example",
            direct_origin="https://other.example",
            host_device_id="host_1",
            host_epoch=7,
            host_private_key=self.host_key,
            state=_State(),
            monotonic=self.clock,
        )
        with self.assertRaises(ValueError):
            other.validate_peer(peer)
        authority._refresh_lifecycle_catalog(
            _catalog(_device("host_1", role="host", epoch=7))
        )
        with self.assertRaises(ValueError):
            authority.validate_peer(peer)

    def test_bounded_nonce_and_challenge_caches_reject_capacity(self) -> None:
        authority = self._authority()
        for index in range(256):
            self._enroll_identity(
                authority,
                key=self.phone_key,
                device_id=f"phone_{index}",
                epoch=11,
                exchange_id=f"exchange_{index}",
                phone_nonce=f"nonce_{index}",
            )
        with self.assertRaises(ValueError):
            self._enroll_identity(
                authority,
                key=self.phone_key,
                device_id="phone_overflow",
                epoch=11,
                exchange_id="exchange_overflow",
                phone_nonce="nonce_overflow",
            )

        clock = _Clock()
        authority = self._authority(clock=clock)
        self._enrollment(authority)
        authority._refresh_lifecycle_catalog(
            _catalog(
                _device("host_1", role="host", epoch=7),
                _device("phone_1", role="mobile", epoch=11),
            )
        )
        for index in range(64):
            authority.issue_challenge(
                peer_device_id="phone_1",
                peer_epoch=11,
                connection_id=f"connection_{index}",
            )
        with self.assertRaises(ValueError):
            authority.issue_challenge(
                peer_device_id="phone_1", peer_epoch=11, connection_id="overflow"
            )
        clock.advance(31)
        self.assertIn(
            "nonce",
            authority.issue_challenge(
                peer_device_id="phone_1", peer_epoch=11, connection_id="after_expiry"
            ),
        )

    def test_state_failure_does_not_publish_or_consume_enrollment(self) -> None:
        state = _FailingState()
        authority = self._authority(state=state)
        payload = self._enrollment_payload()
        with self.assertRaises(OSError):
            authority._enroll_from_link(
                payload,
                trusted_sender_device_id="phone_1",
                trusted_sender_epoch=11,
            )
        authority._refresh_lifecycle_catalog(
            _catalog(
                _device("host_1", role="host", epoch=7),
                _device("phone_1", role="mobile", epoch=11),
            )
        )
        with self.assertRaises(ValueError):
            authority.issue_challenge(
                peer_device_id="phone_1", peer_epoch=11, connection_id="not_published"
            )
        state.fail = False
        result = authority._enroll_from_link(
            payload,
            trusted_sender_device_id="phone_1",
            trusted_sender_epoch=11,
        )
        self.assertEqual(result["exchangeId"], "exchange_1")


if __name__ == "__main__":
    unittest.main()
