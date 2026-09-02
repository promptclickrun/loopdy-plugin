from __future__ import annotations

import json
import base64
import hashlib
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch


class _Response:
    def __init__(self, status_code: int, body: dict):
        self.status_code = status_code
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


class LinkPairingTests(unittest.TestCase):
    def test_host_key_commitment_has_a_stable_canonical_fingerprint(self) -> None:
        from loopdy_plugin.link_pairing import host_key_commitment, key_fingerprint

        canonical = "\n".join(
            (
                "loopdy-link-host-key-v1",
                "pairing-flow-coordinate-0001",
                "host-fixture",
                "signing-key-fixture",
                "agreement-key-fixture",
            )
        ).encode("utf-8")
        expected = base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).decode().rstrip("=")

        commitment = host_key_commitment(
            flow_id="pairing-flow-coordinate-0001",
            device_id="host-fixture",
            signing_public_key_spki="signing-key-fixture",
            agreement_public_key="agreement-key-fixture",
        )

        self.assertEqual(commitment, expected)
        self.assertEqual(
            key_fingerprint(commitment),
            hashlib.sha256(canonical).hexdigest()[:16].upper(),
        )

    def test_pairing_persists_only_final_runtime_credentials_via_hermes_writer(self) -> None:
        from loopdy_plugin.link_pairing import pair_host

        saved = {}
        announced = []
        posted = []
        expected_device_id = "host_" + base64.urlsafe_b64encode(b"h" * 24).decode().rstrip("=")
        responses = [
            _Response(
                201,
                {
                    "version": 1,
                    "flowId": "pairing-flow-coordinate-0001",
                    "code": "ABCD23",
                    "expiresAt": 1788000600,
                    "pairingURL": "loopdy://link/pair?flow=attacker&code=ZZZZZZ",
                },
            ),
            _Response(425, {"version": 1, "error": "pairing_pending"}),
            _Response(
                200,
                {
                    "version": 1,
                    "state": "claimed",
                    "deviceId": expected_device_id,
                    "authorizationEpoch": 1,
                    "grantEnvelope": "opaque-grant-envelope-fixture",
                    "socketPath": "/v1/socket",
                },
            ),
        ]

        def post(url, body):
            posted.append((url, body))
            return responses.pop(0)

        with (
            patch("loopdy_plugin.link_pairing._post", side_effect=post),
            patch(
                "loopdy_plugin.link_pairing.decrypt_host_grant",
                return_value=type("Grant", (), {"account_key": b"a" * 32})(),
            ),
            patch("loopdy_plugin.link_pairing.time.time", return_value=1788000000),
            patch("loopdy_plugin.link_pairing.time.sleep"),
            patch("loopdy_plugin.link_pairing.os.urandom", side_effect=lambda size: b"h" * size),
        ):
            result = pair_host(
                "https://link.loopdy.example",
                save_secret=lambda key, value: saved.__setitem__(key, value),
                announce=announced.append,
            )

        self.assertEqual(result["state"], "paired")
        waiting = announced[0]
        query = parse_qs(urlsplit(waiting["pairing_url"]).query)
        self.assertEqual(query["flow"], ["pairing-flow-coordinate-0001"])
        self.assertEqual(query["code"], ["ABCD23"])
        self.assertEqual(len(query["kc"][0]), 43)
        self.assertEqual(len(waiting["verification_code"].replace("-", "")), 16)
        self.assertNotIn("attacker", waiting["pairing_url"])
        create_body = posted[0][1]
        from loopdy_plugin.link_pairing import host_key_commitment, key_fingerprint
        expected_commitment = host_key_commitment(
            flow_id="pairing-flow-coordinate-0001",
            device_id=create_body["deviceId"],
            signing_public_key_spki=create_body["signingPublicKeySPKI"],
            agreement_public_key=create_body["agreementPublicKey"],
        )
        self.assertEqual(query["kc"], [expected_commitment])
        self.assertEqual(
            waiting["verification_code"].replace("-", ""),
            key_fingerprint(expected_commitment),
        )
        self.assertEqual(
            set(saved),
            {
                "LOOPDY_LINK_BASE_URL",
                "LOOPDY_LINK_DEVICE_ID",
                "LOOPDY_LINK_AUTHORIZATION_EPOCH",
                "LOOPDY_LINK_SIGNING_PRIVATE_KEY",
                "LOOPDY_LINK_AGREEMENT_PRIVATE_KEY",
                "LOOPDY_LINK_ACCOUNT_KEY",
            },
        )
        serialized = json.dumps(result)
        for secret_key in (
            "LOOPDY_LINK_SIGNING_PRIVATE_KEY",
            "LOOPDY_LINK_AGREEMENT_PRIVATE_KEY",
            "LOOPDY_LINK_ACCOUNT_KEY",
        ):
            self.assertNotIn(saved[secret_key], serialized)


if __name__ == "__main__":
    unittest.main()
