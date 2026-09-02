from __future__ import annotations

import io
import json
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from loopdy_plugin.provider import DeliveryError, PushMessage
from loopdy_plugin.providers.expo import ExpoPushProvider


class _Response:
    def __init__(self, body: dict, *, status: int = 200, headers: dict | None = None):
        self.body = json.dumps(body).encode("utf-8")
        self.status = status
        self.headers = headers or {}

    def read(self, amount: int) -> bytes:
        return self.body[:amount]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


class _Server:
    def __init__(self, responses: list[_Response | Exception]):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, *, timeout: int):
        self.requests.append((request, timeout))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    @property
    def json_body(self) -> dict:
        return json.loads(self.requests[-1][0].data)


class _RedirectHandler(BaseHTTPRequestHandler):
    accepted = 0

    def do_POST(self):
        self.send_response(302)
        self.send_header("Location", "/accepted")
        self.end_headers()

    def do_GET(self):
        type(self).accepted += 1
        body = json.dumps({"data": {"status": "ok", "id": "redirected-ticket"}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


def _message() -> PushMessage:
    return PushMessage(
        event_id="event-1",
        event_type="channel.message",
        title="Hermes just messaged you!",
        body="Deployment complete",
        data={"loopdy": {"event_id": "event-1", "type": "channel.message"}},
        sound=True,
    )


class ExpoPushProviderTests(unittest.TestCase):
    def test_sends_a_complete_push_envelope(self) -> None:
        server = _Server([_Response({"data": {"status": "ok", "id": "ticket-1"}})])
        provider = ExpoPushProvider(open_request=server.open)

        receipt = provider.send("ExponentPushToken[fixture-device]", _message())

        request, timeout = server.requests[0]
        self.assertEqual(request.full_url, "https://exp.host/--/api/v2/push/send")
        self.assertEqual(timeout, 8)
        self.assertEqual(receipt.delivery_id, "ticket-1")
        self.assertEqual(receipt.pending_receipt_id, "ticket-1")
        self.assertEqual(server.json_body["to"], "ExponentPushToken[fixture-device]")
        self.assertEqual(server.json_body["title"], "Hermes just messaged you!")
        self.assertEqual(server.json_body["body"], "Deployment complete")
        self.assertEqual(server.json_body["sound"], "default")
        self.assertEqual(server.json_body["priority"], "high")
        self.assertEqual(server.json_body["badge"], 1)
        self.assertEqual(server.json_body["data"]["loopdy"]["event_id"], "event-1")

    def test_interaction_events_set_the_compatible_review_notification_category(self) -> None:
        server = _Server(
            [
                _Response({"data": {"status": "ok", "id": "ticket-2"}}),
                _Response({"data": {"status": "ok", "id": "ticket-3"}}),
            ]
        )
        provider = ExpoPushProvider(open_request=server.open)
        approval = PushMessage(
            event_id="approval-event",
            event_type="approval.required",
            title="Needs your approval",
            body="Review the request",
            data={"loopdy": {"event_id": "approval-event"}},
            sound=False,
        )

        provider.send("ExpoPushToken[fixture-approval]", approval)

        self.assertEqual(server.json_body["categoryId"], "LOOPDY_APPROVAL")
        self.assertNotIn("sound", server.json_body)
        self.assertEqual(server.json_body["priority"], "normal")

        attention = PushMessage(
            event_id="attention-event",
            event_type="attention.required",
            title="Atlas has a question",
            body="Choose an answer in Loopdy.",
            data={"loopdy": {"event_id": "attention-event"}},
            sound=False,
        )
        provider.send("ExpoPushToken[fixture-attention]", attention)
        self.assertEqual(server.json_body["categoryId"], "LOOPDY_APPROVAL")

    def test_rejects_invalid_tokens_before_network_io(self) -> None:
        server = _Server([])
        provider = ExpoPushProvider(open_request=server.open)

        with self.assertRaisesRegex(ValueError, "Expo push token"):
            provider.send("native-apns-token", _message())

        self.assertEqual(server.requests, [])

    def test_classifies_ticket_and_http_failures(self) -> None:
        invalid_server = _Server(
            [
                _Response(
                    {
                        "data": {
                            "status": "error",
                            "message": "Device is not registered",
                            "details": {"error": "DeviceNotRegistered"},
                        }
                    }
                )
            ]
        )
        with self.assertRaises(DeliveryError) as invalid_context:
            ExpoPushProvider(open_request=invalid_server.open).send(
                "ExponentPushToken[fixture-device]",
                _message(),
            )
        self.assertTrue(invalid_context.exception.invalid_token)
        self.assertFalse(invalid_context.exception.retryable)

        http_error = urllib.error.HTTPError(
            "https://exp.host/--/api/v2/push/send",
            503,
            "Unavailable",
            {},
            io.BytesIO(b'{"errors":[{"code":"SERVICE_UNAVAILABLE"}]}'),
        )
        with self.assertRaises(DeliveryError) as temporary_context:
            ExpoPushProvider(open_request=_Server([http_error]).open).send(
                "ExponentPushToken[fixture-device]",
                _message(),
            )
        self.assertEqual(temporary_context.exception.status, 503)
        self.assertTrue(temporary_context.exception.retryable)

        rate_server = _Server(
            [
                _Response(
                    {
                        "data": {
                            "status": "error",
                            "message": "Slow down",
                            "details": {"error": "MessageRateExceeded"},
                        }
                    }
                )
            ]
        )
        with self.assertRaises(DeliveryError) as rate_context:
            ExpoPushProvider(open_request=rate_server.open).send(
                "ExponentPushToken[fixture-device]",
                _message(),
            )
        self.assertTrue(rate_context.exception.retryable)

    def test_refuses_redirects_without_contacting_the_redirect_target(self) -> None:
        _RedirectHandler.accepted = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        url = f"http://127.0.0.1:{server.server_port}/redirect"
        try:
            with patch("loopdy_plugin.providers.expo._SEND_URL", url):
                with self.assertRaises(DeliveryError) as context:
                    ExpoPushProvider().send(
                        "ExponentPushToken[fixture-device]",
                        _message(),
                    )
            self.assertEqual(context.exception.status, 302)
            self.assertEqual(_RedirectHandler.accepted, 0)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

    def test_rejects_oversized_provider_responses(self) -> None:
        response = _Response({"data": {"status": "ok", "id": "ticket-1"}})
        response.body = b"x" * 65_537

        with self.assertRaises(DeliveryError) as context:
            ExpoPushProvider(open_request=_Server([response]).open).send(
                "ExponentPushToken[fixture-device]",
                _message(),
            )

        self.assertEqual(context.exception.code, "oversized_response")
        self.assertFalse(context.exception.retryable)

    def test_normalizes_delivery_receipts(self) -> None:
        server = _Server(
            [
                _Response(
                    {
                        "data": {
                            "ticket-ok": {"status": "ok"},
                            "ticket-gone": {
                                "status": "error",
                                "message": "Device is not registered",
                                "details": {"error": "DeviceNotRegistered"},
                            },
                        }
                    }
                )
            ]
        )

        receipts = ExpoPushProvider(open_request=server.open).receipts(
            ["ticket-ok", "ticket-gone"]
        )

        self.assertEqual(
            server.json_body,
            {"ids": ["ticket-ok", "ticket-gone"]},
        )
        self.assertEqual(receipts["ticket-ok"].status, "delivered")
        self.assertEqual(receipts["ticket-gone"].status, "failed")
        self.assertTrue(receipts["ticket-gone"].invalid_token)


if __name__ == "__main__":
    unittest.main()
