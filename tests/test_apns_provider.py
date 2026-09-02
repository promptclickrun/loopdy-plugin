from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from loopdy_plugin.provider import DeliveryError, PushMessage
from loopdy_plugin.providers.apns import ApnsPushProvider, load_apns_config


class _Response:
    def __init__(self, status_code: int, *, body: dict | None = None, headers: dict | None = None):
        self.status_code = status_code
        self._body = body or {}
        self.headers = headers or {}
        self.content = json.dumps(self._body).encode("utf-8")

    def json(self) -> dict:
        return self._body


class _Client:
    def __init__(self, responses: list[_Response]):
        self.responses = list(responses)
        self.requests: list[dict] = []

    def post(self, url: str, *, headers: dict, json: dict):
        self.requests.append({"url": url, "headers": headers, "json": json})
        return self.responses.pop(0)


def _message() -> PushMessage:
    return PushMessage(
        event_id="event-1",
        event_type="approval.required",
        title="Needs your approval",
        body="Open loopdy to review the request.",
        data={"loopdy": {"event_id": "event-1", "approval_id": "approval-1"}},
        sound=True,
    )


class ApnsPushProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.key_path = Path(self.temporary.name) / "AuthKey_FIXTURE01.p8"
        self.key_path.write_bytes(
            self.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        self.values = {
            "team_id": "TEAMFIX001",
            "key_id": "KEYFIX0001",
            "topic": "app.loopdy.personal",
            "environment": "production",
            "key_path": str(self.key_path),
        }

    def test_direct_provider_signs_and_sends_to_the_selected_topic(self) -> None:
        client = _Client([_Response(200, headers={"apns-id": "apns-id-1"})])
        config = load_apns_config(self.values, {})
        provider = ApnsPushProvider(config, client=client, now=lambda: 1_700_000_000)

        receipt = provider.send("a" * 64, _message(), environment="production")

        request = client.requests[0]
        self.assertEqual(
            request["url"],
            f"https://api.push.apple.com/3/device/{'a' * 64}",
        )
        self.assertEqual(request["headers"]["apns-topic"], "app.loopdy.personal")
        self.assertEqual(request["headers"]["apns-push-type"], "alert")
        self.assertEqual(request["headers"]["apns-priority"], "10")
        self.assertEqual(request["headers"]["apns-expiration"], "0")
        self.assertEqual(request["headers"]["apns-collapse-id"], "event-1")
        encoded = request["headers"]["authorization"].removeprefix("bearer ")
        claims = jwt.decode(
            encoded,
            self.key.public_key(),
            algorithms=["ES256"],
            audience=None,
            options={"verify_aud": False},
        )
        self.assertEqual(claims, {"iss": "TEAMFIX001", "iat": 1_700_000_000})
        self.assertEqual(jwt.get_unverified_header(encoded)["kid"], "KEYFIX0001")
        self.assertEqual(request["json"]["aps"]["category"], "LOOPDY_APPROVAL")
        self.assertEqual(receipt.delivery_id, "apns-id-1")

    def test_attention_uses_the_compatible_review_category(self) -> None:
        client = _Client([_Response(200, headers={"apns-id": "attention-id"})])
        provider = ApnsPushProvider(
            load_apns_config(self.values, {}),
            client=client,
            now=lambda: 1_700_000_000,
        )

        provider.send(
            "f" * 64,
            PushMessage(
                event_id="attention-event",
                event_type="attention.required",
                title="Atlas has a question",
                body="Choose an answer in Loopdy.",
                data={"loopdy": {"event_id": "attention-event"}},
                sound=True,
            ),
        )

        self.assertEqual(client.requests[0]["json"]["aps"]["category"], "LOOPDY_APPROVAL")

    def test_sandbox_endpoint_and_jwt_refresh(self) -> None:
        times = iter([1_700_000_000, 1_700_002_901])
        client = _Client(
            [
                _Response(200, headers={"apns-id": "first"}),
                _Response(200, headers={"apns-id": "second"}),
            ]
        )
        config = load_apns_config({**self.values, "environment": "sandbox"}, {})
        provider = ApnsPushProvider(config, client=client, now=lambda: next(times))

        provider.send("b" * 64, _message(), environment="sandbox")
        provider.send("b" * 64, _message(), environment="sandbox")

        self.assertTrue(client.requests[0]["url"].startswith("https://api.sandbox.push.apple.com/"))
        self.assertNotEqual(
            client.requests[0]["headers"]["authorization"],
            client.requests[1]["headers"]["authorization"],
        )

    def test_channel_messages_set_an_unread_app_badge(self) -> None:
        client = _Client([_Response(200, headers={"apns-id": "message-id"})])
        provider = ApnsPushProvider(
            load_apns_config(self.values, {}),
            client=client,
            now=lambda: 1_700_000_000,
        )
        provider.send(
            "e" * 64,
            PushMessage(
                event_id="message-event",
                event_type="channel.message",
                title="Atlas messaged you",
                body="Open Loopdy to read it.",
                data={"loopdy": {"event_id": "message-event"}},
                sound=True,
            ),
        )

        self.assertEqual(client.requests[0]["json"]["aps"]["badge"], 1)

    def test_live_activity_updates_use_apple_liveactivity_headers_and_payload(self) -> None:
        client = _Client(
            [
                _Response(200, headers={"apns-id": "activity-update"}),
                _Response(200, headers={"apns-id": "activity-complete"}),
                _Response(200, headers={"apns-id": "activity-failed"}),
            ]
        )
        provider = ApnsPushProvider(
            load_apns_config(self.values, {}),
            client=client,
            now=lambda: 1_700_000_000,
        )

        receipt = provider.send_live_activity(
            "f" * 64,
            activity_id="activity-1",
            session_ref="Q0RFRkdISUpLTE1OT1A",
            phase="running",
            progress=42,
            timestamp=1_700_000_000,
            active_session_count=2,
            expires=1_700_000_120,
        )

        request = client.requests[0]
        self.assertEqual(
            request["headers"]["apns-topic"],
            "app.loopdy.personal.push-type.liveactivity",
        )
        self.assertEqual(request["headers"]["apns-push-type"], "liveactivity")
        self.assertEqual(request["headers"]["apns-priority"], "5")
        self.assertEqual(request["headers"]["apns-expiration"], "1700000120")
        self.assertEqual(
            request["headers"]["apns-collapse-id"],
            hashlib.sha256(b"activity-1").hexdigest(),
        )
        self.assertEqual(request["json"]["aps"]["event"], "update")
        self.assertEqual(request["json"]["aps"]["timestamp"], 1_700_000_000)
        self.assertEqual(
            request["json"]["aps"]["content-state"],
            {
                "phase": "running",
                "progress": 42,
                "activeSessionCount": 2,
                "sessionRef": "Q0RFRkdISUpLTE1OT1A",
            },
        )
        self.assertEqual(request["json"]["aps"]["stale-date"], 1_700_000_120)
        self.assertNotIn("detail", json.dumps(request["json"]))
        self.assertNotIn("tool", json.dumps(request["json"]))
        self.assertEqual(receipt.delivery_id, "activity-update")

        for field, value in (("activity_id", True), ("session_ref", True)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                provider.send_live_activity(
                    "f" * 64,
                    activity_id="activity-1" if field != "activity_id" else value,
                    session_ref="Q0RFRkdISUpLTE1OT1A" if field != "session_ref" else value,
                    phase="running",
                    progress=42,
                    timestamp=1_700_000_000,
                    active_session_count=2,
                    expires=1_700_000_120,
                )

        provider.send_live_activity(
            "f" * 64,
            activity_id="activity-1",
            session_ref="Q0RFRkdISUpLTE1OT1A",
            phase="completed",
            progress=100,
            timestamp=1_700_000_001,
            expires=1_700_000_121,
        )
        self.assertEqual(client.requests[1]["json"]["aps"]["event"], "end")
        self.assertEqual(client.requests[1]["headers"]["apns-priority"], "10")
        self.assertEqual(client.requests[1]["headers"]["apns-expiration"], "1700000121")
        self.assertEqual(client.requests[1]["json"]["aps"]["timestamp"], 1_700_000_001)
        self.assertEqual(client.requests[1]["json"]["aps"]["dismissal-date"], 1_700_000_001)

        provider.send_live_activity(
            "f" * 64,
            activity_id="activity-1",
            session_ref="Q0RFRkdISUpLTE1OT1A",
            phase="failed",
            progress=100,
            timestamp=1_700_000_002,
            expires=1_700_000_122,
        )
        self.assertEqual(client.requests[2]["json"]["aps"]["event"], "end")
        self.assertEqual(client.requests[2]["headers"]["apns-priority"], "10")
        self.assertEqual(client.requests[2]["json"]["aps"]["timestamp"], 1_700_000_002)
        self.assertEqual(client.requests[2]["json"]["aps"]["dismissal-date"], 1_700_000_002)

    def test_classifies_invalid_tokens_and_temporary_failures(self) -> None:
        config = load_apns_config(self.values, {})
        invalid = ApnsPushProvider(
            config,
            client=_Client([_Response(410, body={"reason": "Unregistered"})]),
        )
        with self.assertRaises(DeliveryError) as invalid_context:
            invalid.send("c" * 64, _message())
        self.assertTrue(invalid_context.exception.invalid_token)
        self.assertFalse(invalid_context.exception.retryable)

        for status in (429, 500, 503):
            with self.subTest(status=status):
                temporary = ApnsPushProvider(
                    config,
                    client=_Client([_Response(status, body={"reason": "ServiceUnavailable"})]),
                )
                with self.assertRaises(DeliveryError) as temporary_context:
                    temporary.send("d" * 64, _message())
                self.assertTrue(temporary_context.exception.retryable)

    def test_classifies_remote_protocol_transport_failure_as_retryable(self) -> None:
        class FailingClient:
            def post(self, *_args, **_kwargs):
                raise httpx.RemoteProtocolError("connection ended before headers")

        provider = ApnsPushProvider(
            load_apns_config(self.values, {}),
            client=FailingClient(),
            now=lambda: 1_700_000_000,
        )

        with self.assertRaises(DeliveryError) as context:
            provider.send("a" * 64, _message())

        self.assertEqual(context.exception.code, "transport_error")
        self.assertTrue(context.exception.retryable)

    def test_rejects_bad_tokens_and_oversized_payloads_before_network_io(self) -> None:
        client = _Client([])
        provider = ApnsPushProvider(load_apns_config(self.values, {}), client=client)
        with self.assertRaisesRegex(ValueError, "topic"):
            load_apns_config(
                {**self.values, "topic": "app.loopdy.personal.push-type.liveactivity"}, {}
            )
        with self.assertRaisesRegex(ValueError, "APNs device token"):
            provider.send("not-a-token", _message())
        oversized = PushMessage(
            event_id="event-large",
            event_type="channel.message",
            title="Message",
            body="x" * 5_000,
            data={"loopdy": {"event_id": "event-large"}},
            sound=False,
        )
        with self.assertRaisesRegex(ValueError, "4 KB"):
            provider.send("e" * 64, oversized)
        self.assertEqual(client.requests, [])

    def test_config_requires_a_private_owner_readable_key_file(self) -> None:
        loaded = load_apns_config(
            {},
            {
                "LOOPDY_APNS_TEAM_ID": "TEAMFIX001",
                "LOOPDY_APNS_KEY_ID": "KEYFIX0001",
                "LOOPDY_APNS_TOPIC": "app.loopdy.personal",
                "LOOPDY_APNS_ENVIRONMENT": "production",
                "LOOPDY_APNS_KEY_PATH": str(self.key_path),
            },
        )
        self.assertEqual(loaded.key_path, self.key_path.resolve())

        if os.name == "posix":
            self.key_path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
            with self.assertRaisesRegex(ValueError, "owner-only"):
                load_apns_config(self.values, {})

        for changes in (
            {"team_id": "bad"},
            {"key_id": ""},
            {"topic": "not a topic"},
            {"environment": "preview"},
            {"key_path": str(Path(self.temporary.name) / "missing.p8")},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    load_apns_config({**self.values, **changes}, {})

        malformed_path = Path(self.temporary.name) / "AuthKey_MALFORMED.p8"
        malformed_path.write_text("not an EC signing key", encoding="utf-8")
        malformed_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        with self.assertRaisesRegex(ValueError, "signing key"):
            load_apns_config({**self.values, "key_path": str(malformed_path)}, {})


if __name__ == "__main__":
    unittest.main()
