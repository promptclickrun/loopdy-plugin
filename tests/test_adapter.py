from __future__ import annotations

import asyncio
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from unittest.mock import AsyncMock

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import ProcessingOutcome, SendResult
from gateway.platform_registry import PlatformEntry, platform_registry
from gateway.run import GatewayRunner
from gateway.session import SessionContext, SessionSource
from gateway.stream_consumer import GatewayStreamConsumer, StreamConsumerConfig
from loopdy_plugin.adapter import LoopdyAdapter, standalone_send
from loopdy_plugin.attachments import AttachmentStore
from loopdy_plugin.workspace_control import HermesWorkspaceBackend, WorkspaceController


class _EventStore:
    def __init__(self):
        self.events = []
        self.delivered = []
        self.failed = []
        self.records = {}

    def record_event(self, event, *, target):
        if event.event_id in self.records:
            return False
        self.events.append((event, target))
        self.records[event.event_id] = {
            "event_id": event.event_id,
            "status": "queued",
        }
        return True

    def get_event(self, event_id):
        return self.records.get(event_id)

    def mark_event_delivered(self, event_id, delivery_id=""):
        self.delivered.append((event_id, delivery_id))
        self.records[event_id]["status"] = "sent"
        return True

    def mark_event_prompted(self, event_id):
        self.records[event_id]["status"] = "prompted"
        return True

    def mark_event_pending(self, event_id, delivery_id):
        self.records[event_id]["status"] = "pending"
        self.records[event_id]["delivery_id"] = delivery_id
        return True

    def mark_event_failed(self, event_id, failure):
        self.failed.append((event_id, failure))
        self.records[event_id]["status"] = "failed"
        return True


class _Service:
    def __init__(self):
        self.deliveries = []
        self.link_relay_registrations = []
        self.store = _EventStore()

    def health(self):
        return {
            "configured": True,
            "ready": True,
            "detail": "Managed provider ready",
            "compatible_devices": 1,
        }

    def deliver(self, event, *, target):
        self.deliveries.append((event, target))
        return {"success": True, "message_id": "delivery-123"}

    def enqueue(self, event, *, target):
        self.deliveries.append((event, target))
        return True

    def adopt_link_relay_device(self, registration, *, sender_device_id):
        self.link_relay_registrations.append((registration, sender_device_id))
        return {"ready": True}


class _LinkClient:
    def __init__(self):
        self.connected = True
        self.callback = None
        self.status_callback = None
        self.payloads = []
        self.live_activity_payloads = []
        self.released_attachment_paths = []
        self.stopped = False

    def start(self, callback, *, status_callback=None):
        self.callback = callback
        self.status_callback = status_callback

    async def stop(self):
        self.stopped = True

    async def send_payload(self, payload):
        self.payloads.append(payload)
        return "frame-fixture-0001"

    async def send_live_activity_update(self, payload):
        self.live_activity_payloads.append(payload)
        return payload["updateId"]

    def release_attachment_paths(self, paths):
        normalized = tuple(paths)
        self.released_attachment_paths.append(normalized)
        for path in normalized:
            Path(path).unlink(missing_ok=True)

    def status(self):
        return {"configured": True, "state": "connected"}


class _UnreadyLinkClient(_LinkClient):
    def __init__(self):
        super().__init__()
        self.connected = False

    async def wait_until_connected(self, *, timeout):
        del timeout
        return False


class _SupersededLinkClient(_UnreadyLinkClient):
    def status(self):
        return {
            "configured": True,
            "state": "superseded",
            "detail": "connection replaced by newer runtime",
        }


class _ReconnectableControlLink(_LinkClient):
    def __init__(self):
        super().__init__()
        self.connected = False
        self.send_attempts = 0

    async def wait_until_connected(self, *, timeout):
        del timeout
        self.connected = True
        return True

    async def send_payload(self, payload):
        self.send_attempts += 1
        if self.send_attempts == 1:
            raise ConnectionError("Link socket reconnected while sending control response")
        return await super().send_payload(payload)


class _NotificationFailingOnceLink(_LinkClient):
    def __init__(self):
        super().__init__()
        self.notification_failures_remaining = 1

    async def send_payload(self, payload):
        if (
            payload.get("type") == "notification.event"
            and self.notification_failures_remaining > 0
        ):
            self.notification_failures_remaining -= 1
            raise RuntimeError("notification delivery failed")
        return await super().send_payload(payload)


class _NotificationAcknowledgementTimeoutLink(_LinkClient):
    def __init__(self):
        super().__init__()
        self.pending_payload = None

    async def send_payload(self, payload):
        self.payloads.append(payload)
        if payload.get("type") == "notification.event":
            self.pending_payload = payload
            raise TimeoutError("relay acknowledgement timed out")
        return "frame-fixture-prompt-0001"

    def pending_payload_frame_id(self, payload):
        if payload == self.pending_payload:
            return "frame-fixture-notification-0001"
        return None


class _AssistantFailingLink(_LinkClient):
    async def send_payload(self, payload):
        if payload.get("type") == "assistant.message":
            raise RuntimeError("assistant delivery failed")
        return await super().send_payload(payload)


class _BlockingNotificationLink(_LinkClient):
    def __init__(self):
        super().__init__()
        self.notification_started = asyncio.Event()
        self.release_notification = asyncio.Event()

    async def send_payload(self, payload):
        self.payloads.append(payload)
        if payload.get("type") == "notification.event":
            self.notification_started.set()
            await self.release_notification.wait()
        return "frame-fixture-0001"


class _ActivityBroker:
    def __init__(self):
        self.sender = None
        self.live_activity_sender = None
        self.completions = []
        self.bindings = []
        self.session_store = None

    def bind_link_session(self, session_id, link_session_id):
        self.bindings.append((session_id, link_session_id))

    def attach_session_store(self, session_store):
        self.session_store = session_store

    async def attach(self, sender, *, live_activity_sender=None):
        self.sender = sender
        self.live_activity_sender = live_activity_sender

    async def detach(self):
        self.sender = None
        self.live_activity_sender = None

    async def complete(self, session_id, *, agent_name, succeeded=True):
        self.completions.append((session_id, agent_name, succeeded))
        return True


class AdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        runtime_config_patcher = patch(
            "loopdy_plugin.adapter.load_runtime_config",
            return_value=None,
        )
        runtime_config_patcher.start()
        self.addCleanup(runtime_config_patcher.stop)
        platform_registry.register(
            PlatformEntry(
                name="loopdy",
                label="Loopdy",
                adapter_factory=lambda config: None,
                check_fn=lambda: True,
            )
        )

    def test_outbound_channel_ledgers_content_and_pushes_only_a_wakeup(self) -> None:
        service = _Service()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True, extra={"home_target": "all"}),
            service=service,
        )

        self.assertTrue(asyncio.run(adapter.connect()))
        result = asyncio.run(
            adapter.send(
                "device:phone-123",
                "private channel content",
                metadata={"profile": "dora", "agent_name": "Dora"},
            )
        )

        self.assertTrue(result.success)
        self.assertEqual(result.message_id, "delivery-123")
        event, target = service.deliveries[0]
        self.assertEqual(target, "device:phone-123")
        self.assertEqual(event.detail["message"], "private channel content")
        self.assertEqual(event.type, "channel.message")
        self.assertEqual(event.profile, "dora")
        self.assertEqual(event.detail["agent_name"], "Dora")
        self.assertFalse(event.session_id)
        self.assertNotIn("private channel content", str(event.push_payload))

    def test_clarify_prompt_queues_request_bound_home_attention_after_send(self) -> None:
        service = _Service()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True, extra={"home_target": "device:home"}),
            service=service,
        )
        adapter.send = AsyncMock(
            return_value=SendResult(success=True, message_id="prompt-message-1")
        )
        pending = SimpleNamespace(clarify_id="clarify-actual-1", multi_select=True)

        with (
            patch("tools.clarify_gateway.get_pending_for_session", return_value=pending),
            patch("tools.clarify_gateway.get_clarify_timeout", return_value=90),
            patch("loopdy_plugin.adapter.time.time", return_value=1_788_200_000),
        ):
            result = asyncio.run(
                adapter.send_clarify(
                    chat_id="chat-1",
                    question="Which checks should run?",
                    choices=["Unit", "UI", "Smoke"],
                    clarify_id="clarify-actual-1",
                    session_key="session-key-1",
                )
            )

        self.assertTrue(result.success)
        adapter.send.assert_awaited_once()
        event, target = service.deliveries[0]
        self.assertEqual(target, "device:home")
        self.assertEqual(event.type, "attention.required")
        self.assertEqual(event.session_id, "chat-1")
        self.assertEqual(event.detail["kind"], "clarify")
        self.assertEqual(event.detail["request_id"], "clarify-actual-1")
        self.assertEqual(event.detail["session_key"], "session-key-1")
        self.assertEqual(event.detail["question"], "Which checks should run?")
        self.assertEqual(event.detail["expires_at"], "1788200090")
        self.assertEqual(
            event.detail["interaction"],
            {
                "schemaVersion": 1,
                "type": "clarify",
                "requestId": "clarify-actual-1",
                "expiresAt": 1_788_200_090,
                "allowsCustomResponse": True,
                "questions": [
                    {
                        "id": "q0",
                        "question": "Which checks should run?",
                        "choices": ["Unit", "UI", "Smoke"],
                        "multiSelect": True,
                        "allowsCustomResponse": True,
                    }
                ],
            },
        )

    def test_failed_clarify_prompt_does_not_create_actionable_attention(self) -> None:
        service = _Service()
        adapter = LoopdyAdapter(PlatformConfig(enabled=True), service=service)
        adapter.send = AsyncMock(return_value=SendResult(success=False, error="offline"))

        result = asyncio.run(
            adapter.send_clarify(
                chat_id="chat-1",
                question="Choose one",
                choices=["A", "B"],
                clarify_id="clarify-actual-1",
                session_key="session-key-1",
            )
        )

        self.assertFalse(result.success)
        self.assertEqual(service.deliveries, [])

    def test_failed_connected_link_clarify_prompt_does_not_persist_attention(self) -> None:
        service = _Service()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True, extra={"home_target": "all"}),
            service=service,
            link_client=_AssistantFailingLink(),
        )

        with (
            patch("tools.clarify_gateway.get_pending_for_session", return_value=None),
            patch("tools.clarify_gateway.get_clarify_timeout", return_value=90),
        ):
            result = asyncio.run(
                adapter.send_clarify(
                    chat_id="opaque-link-chat-prompt-failure",
                    question="Choose one",
                    choices=["A", "B"],
                    clarify_id="clarify-link-prompt-failure",
                    session_key="loopdy:gordie:opaque-link-chat-prompt-failure",
                )
            )

        self.assertFalse(result.success)
        self.assertEqual(service.store.events, [])
        self.assertEqual(service.store.records, {})

    def test_connected_link_clarify_persists_and_emits_one_typed_notification(self) -> None:
        service = _Service()
        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True, extra={"home_target": "all"}),
            service=service,
            link_client=link,
        )
        pending = SimpleNamespace(clarify_id="clarify-link-1", multi_select=False)

        async def scenario():
            self.assertTrue(await adapter.connect())
            return await adapter.send_clarify(
                chat_id="opaque-link-chat-7fb2",
                question="Which environment should I deploy?",
                choices=["Staging", "Production"],
                clarify_id="clarify-link-1",
                session_key="loopdy:gordie:opaque-link-chat-7fb2",
                metadata={"profile": "weather", "agent_name": "Dora"},
            )

        with (
            patch("tools.clarify_gateway.get_pending_for_session", return_value=pending),
            patch("tools.clarify_gateway.get_clarify_timeout", return_value=90),
            patch("loopdy_plugin.adapter.time.time", return_value=1_788_200_000),
        ):
            result = asyncio.run(scenario())

        self.assertTrue(result.success)
        self.assertEqual(service.deliveries, [])
        self.assertEqual(len(service.store.events), 1)
        event, target = service.store.events[0]
        self.assertEqual(target, "all")
        self.assertEqual(
            event.event_id,
            "attention.required:886804c86d92f4233a1f1acc4a07f5a7",
        )
        self.assertEqual(event.type, "attention.required")
        self.assertEqual(event.session_id, "opaque-link-chat-7fb2")
        self.assertEqual(
            event.detail["session_key"],
            "loopdy:gordie:opaque-link-chat-7fb2",
        )
        notifications = [
            payload
            for payload in link.payloads
            if payload.get("type") == "notification.event"
        ]
        self.assertEqual(notifications, [{
            "version": 1,
            "type": "notification.event",
            "eventId": "attention.required:886804c86d92f4233a1f1acc4a07f5a7",
            "eventType": "attention.required",
            "agentId": "weather",
            "agentName": "Dora",
            "sessionId": "opaque-link-chat-7fb2",
            "title": "Dora has a question",
            "body": "Which environment should I deploy?",
            "sentAt": 1_788_200_000,
        }])
        self.assertEqual(
            service.store.delivered,
            [(event.event_id, "frame-fixture-0001")],
        )
        self.assertEqual(service.store.failed, [])

    def test_connected_link_clarify_failure_is_durable_and_replay_is_idempotent(
        self,
    ) -> None:
        service = _Service()
        link = _NotificationFailingOnceLink()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True, extra={"home_target": "all"}),
            service=service,
            link_client=link,
        )
        pending = SimpleNamespace(clarify_id="clarify-link-replay", multi_select=False)

        async def send_clarify():
            return await adapter.send_clarify(
                chat_id="opaque-link-chat-replay",
                question="Which environment should I deploy?",
                choices=["Staging", "Production"],
                clarify_id="clarify-link-replay",
                session_key="loopdy:gordie:opaque-link-chat-replay",
                metadata={"profile": "weather", "agent_name": "Dora"},
            )

        async def scenario():
            self.assertTrue(await adapter.connect())
            failed = await send_clarify()
            replayed = await send_clarify()
            duplicate = await send_clarify()
            return failed, replayed, duplicate

        with (
            patch("tools.clarify_gateway.get_pending_for_session", return_value=pending),
            patch("tools.clarify_gateway.get_clarify_timeout", return_value=90),
            patch("loopdy_plugin.adapter.time.time", return_value=1_788_200_000),
        ):
            failed, replayed, duplicate = asyncio.run(scenario())

        self.assertFalse(failed.success)
        self.assertEqual(
            failed.error,
            "Loopdy Link notification failed (RuntimeError)",
        )
        self.assertTrue(replayed.success)
        self.assertTrue(duplicate.success)
        self.assertEqual(len(service.store.events), 1)
        event, _ = service.store.events[0]
        self.assertEqual(service.store.failed, [(event.event_id, "RuntimeError")])
        self.assertEqual(
            service.store.delivered,
            [(event.event_id, "frame-fixture-0001")],
        )
        notifications = [
            payload
            for payload in link.payloads
            if payload.get("type") == "notification.event"
        ]
        self.assertEqual(len(notifications), 1)
        assistant_messages = [
            payload
            for payload in link.payloads
            if payload.get("type") == "assistant.message"
        ]
        self.assertEqual(len(assistant_messages), 1)

    def test_connected_link_clarify_acknowledgement_timeout_keeps_one_pending_frame(
        self,
    ) -> None:
        service = _Service()
        link = _NotificationAcknowledgementTimeoutLink()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True, extra={"home_target": "all"}),
            service=service,
            link_client=link,
        )
        pending = SimpleNamespace(clarify_id="clarify-link-timeout", multi_select=False)

        async def send_clarify():
            return await adapter.send_clarify(
                chat_id="opaque-link-chat-timeout",
                question="Which environment should I deploy?",
                choices=["Staging", "Production"],
                clarify_id="clarify-link-timeout",
                session_key="loopdy:gordie:opaque-link-chat-timeout",
                metadata={"profile": "weather", "agent_name": "Dora"},
            )

        async def scenario():
            self.assertTrue(await adapter.connect())
            first = await send_clarify()
            replay = await send_clarify()
            return first, replay

        with (
            patch("tools.clarify_gateway.get_pending_for_session", return_value=pending),
            patch("tools.clarify_gateway.get_clarify_timeout", return_value=90),
            patch("loopdy_plugin.adapter.time.time", return_value=1_788_200_000),
        ):
            first, replay = asyncio.run(scenario())

        self.assertTrue(first.success)
        self.assertTrue(replay.success)
        self.assertEqual(
            [payload["type"] for payload in link.payloads],
            ["assistant.message", "notification.event"],
        )
        self.assertEqual(len(service.store.events), 1)
        event, _ = service.store.events[0]
        self.assertEqual(service.store.records[event.event_id]["status"], "pending")
        self.assertEqual(
            service.store.records[event.event_id]["delivery_id"],
            "frame-fixture-notification-0001",
        )
        self.assertEqual(service.store.delivered, [])
        self.assertEqual(service.store.failed, [])

    def test_concurrent_connected_link_clarify_replay_serializes_the_whole_operation(
        self,
    ) -> None:
        service = _Service()
        link = _BlockingNotificationLink()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True, extra={"home_target": "all"}),
            service=service,
            link_client=link,
        )
        pending = SimpleNamespace(clarify_id="clarify-link-concurrent", multi_select=False)

        async def send_clarify():
            return await adapter.send_clarify(
                chat_id="opaque-link-chat-concurrent",
                question="Which environment should I deploy?",
                choices=["Staging", "Production"],
                clarify_id="clarify-link-concurrent",
                session_key="loopdy:gordie:opaque-link-chat-concurrent",
                metadata={"profile": "weather", "agent_name": "Dora"},
            )

        async def scenario():
            self.assertTrue(await adapter.connect())
            first = asyncio.create_task(send_clarify())
            await link.notification_started.wait()
            replay = asyncio.create_task(send_clarify())
            await asyncio.sleep(0)
            link.release_notification.set()
            return await asyncio.gather(first, replay)

        with (
            patch("tools.clarify_gateway.get_pending_for_session", return_value=pending),
            patch("tools.clarify_gateway.get_clarify_timeout", return_value=90),
            patch("loopdy_plugin.adapter.time.time", return_value=1_788_200_000),
        ):
            results = asyncio.run(scenario())

        self.assertTrue(all(result.success for result in results))
        self.assertEqual(
            [payload["type"] for payload in link.payloads],
            ["assistant.message", "notification.event"],
        )
        self.assertEqual(len(service.store.events), 1)
        self.assertEqual(len(service.store.delivered), 1)

    def test_connect_does_not_report_loopdy_ready_before_link_socket_ready(self) -> None:
        link = _UnreadyLinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )

        self.assertFalse(asyncio.run(adapter.connect()))
        self.assertFalse(adapter.is_connected)
        self.assertTrue(adapter.has_fatal_error)
        self.assertEqual(adapter.fatal_error_code, "loopdy_link_not_ready")
        self.assertTrue(adapter.fatal_error_retryable)

    def test_superseded_link_owner_is_not_reported_as_retryable(self) -> None:
        link = _SupersededLinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )

        self.assertFalse(asyncio.run(adapter.connect()))
        self.assertFalse(adapter.is_connected)
        self.assertTrue(adapter.has_fatal_error)
        self.assertEqual(adapter.fatal_error_code, "loopdy_link_superseded")
        self.assertFalse(adapter.fatal_error_retryable)

    def test_proactive_link_channel_queues_encrypted_notification_and_host_inbox_event(self) -> None:
        service = _Service()
        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True, extra={"home_target": "all"}),
            service=service,
            link_client=link,
        )

        async def scenario():
            self.assertTrue(await adapter.connect())
            return await adapter.send(
                "all",
                "The forecast is ready.",
                metadata={
                    "profile": "weather",
                    "agent_name": "Dora",
                    "session_id": "session-coordinate-0001",
                },
            )

        with patch("loopdy_plugin.adapter.time.time", return_value=1_788_000_011):
            result = asyncio.run(scenario())

        self.assertTrue(result.success)
        self.assertEqual(service.deliveries, [])
        self.assertEqual(len(service.store.events), 1)
        event, target = service.store.events[0]
        self.assertEqual(target, "all")
        self.assertEqual(event.detail["message"], "The forecast is ready.")
        self.assertEqual(link.payloads[-1], {
            "version": 1,
            "type": "notification.event",
            "eventId": event.event_id,
            "eventType": "channel.message",
            "agentId": "weather",
            "agentName": "Dora",
            "sessionId": "session-coordinate-0001",
            "title": "Dora just messaged you!",
            "body": "Message: The forecast is ready.",
            "sentAt": 1_788_000_011,
        })
        self.assertEqual(
            service.store.delivered,
            [(event.event_id, "frame-fixture-0001")],
        )
        self.assertEqual(service.store.failed, [])

    def test_proactive_link_channel_persists_and_delivers_a_validated_generative_ui_card(self) -> None:
        service = _Service()
        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True, extra={"home_target": "all"}),
            service=service,
            link_client=link,
        )
        card = {
            "schema": "loopdy.generative_ui",
            "version": 1,
            "component": "summary",
            "title": "Morning briefing",
            "body": "Three priorities are ready.",
        }

        async def scenario():
            self.assertTrue(await adapter.connect())
            return await adapter.send(
                "home",
                json.dumps(card),
                metadata={"profile": "default", "agent_name": "Gordie"},
            )

        result = asyncio.run(scenario())

        self.assertTrue(result.success)
        event, target = service.store.events[0]
        self.assertEqual(target, "home")
        self.assertEqual(event.detail["message"], "Morning briefing")
        self.assertEqual(event.detail["generative_ui"], card)
        self.assertEqual(link.payloads[-1]["card"], card)

    def test_cron_wrapped_renderer_envelope_persists_and_delivers_the_card(self) -> None:
        service = _Service()
        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True, extra={"home_target": "all"}),
            service=service,
            link_client=link,
        )
        card = {
            "schema": "loopdy.generative_ui",
            "version": 1,
            "component": "summary",
            "title": "Morning briefing",
            "body": "Three priorities are ready.",
        }
        wrapped = (
            "Cronjob Response: Morning briefing\n"
            "(job_id: morning-briefing)\n"
            "-------------\n\n"
            f"{json.dumps(card)}\n\n"
            "To stop or manage this job, send me a new message "
            '(e.g. "stop reminder Morning briefing").'
        )

        async def scenario():
            self.assertTrue(await adapter.connect())
            return await adapter.send(
                "home",
                wrapped,
                metadata={
                    "job_id": "morning-briefing",
                    "profile": "default",
                    "agent_name": "Gordie",
                },
            )

        result = asyncio.run(scenario())

        self.assertTrue(result.success)
        event, target = service.store.events[0]
        self.assertEqual(target, "home")
        self.assertEqual(event.job_id, "morning-briefing")
        self.assertEqual(event.detail["message"], "Morning briefing")
        self.assertEqual(event.detail["generative_ui"], card)
        self.assertEqual(link.payloads[-1]["card"], card)

    def test_invalid_cron_card_safely_falls_back_to_text(self) -> None:
        service = _Service()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True, extra={"home_target": "all"}),
            service=service,
        )
        wrapped = (
            "Cronjob Response: Morning briefing\n"
            "(job_id: morning-briefing)\n"
            "-------------\n\n"
            '{"schema":"loopdy.generative_ui","version":1,"component":"summary"}\n\n'
            "To stop or manage this job, send me a new message."
        )

        self.assertTrue(asyncio.run(adapter.connect()))
        result = asyncio.run(
            adapter.send(
                "device:phone-123",
                wrapped,
                metadata={"job_id": "morning-briefing"},
            )
        )

        self.assertTrue(result.success)
        event, _ = service.deliveries[0]
        self.assertEqual(event.job_id, "morning-briefing")
        self.assertNotIn("generative_ui", event.detail)
        self.assertIn("Cronjob Response: Morning briefing", event.detail["message"])

    def test_standalone_sender_uses_the_registered_adapter_contract_and_closes_it(self) -> None:
        service = _Service()
        adapter = AsyncMock()
        adapter.connect.return_value = True
        adapter.send.return_value = SendResult(
            success=True,
            message_id="event-fixture-0001",
        )

        async def scenario():
            return await standalone_send(
                PlatformConfig(enabled=True, extra={"home_target": "all"}),
                "all",
                "The forecast is ready.",
                thread_id="session-coordinate-0001",
                service=service,
                link_state={"durable": True},
                adapter_factory=lambda *_args, **_kwargs: adapter,
            )

        result = asyncio.run(scenario())

        self.assertEqual(result, {
            "success": True,
            "message_id": "event-fixture-0001",
        })
        adapter.send.assert_awaited_once_with(
            "all",
            "The forecast is ready.",
            metadata={"thread_id": "session-coordinate-0001"},
        )
        adapter.disconnect.assert_awaited_once()

    def test_loopdy_platform_suppresses_gateway_lifecycle_notifications(self) -> None:
        config = PlatformConfig(enabled=True, gateway_restart_notification=True)

        adapter = LoopdyAdapter(config, service=_Service())

        self.assertFalse(config.gateway_restart_notification)
        self.assertFalse(adapter.config.gateway_restart_notification)

    def test_connects_a_configured_provider_before_the_first_device_registers(self) -> None:
        service = _Service()
        service.health = lambda: {
            "configured": True,
            "ready": False,
            "detail": "No managed Loopdy devices are registered",
            "compatible_devices": 0,
        }
        adapter = LoopdyAdapter(PlatformConfig(enabled=True), service=service)

        self.assertTrue(asyncio.run(adapter.connect()))

    def test_link_activity_sender_is_attached_and_only_the_final_message_completes_it(self) -> None:
        link = _LinkClient()
        broker = _ActivityBroker()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=link,
            activity_broker=broker,
        )

        async def scenario() -> None:
            self.assertTrue(await adapter.connect())
            await adapter.send(
                "session-coordinate-0001",
                "Draft",
                metadata={"_interim_send": True, "agent_name": "Gordie"},
            )
            await adapter.send(
                "session-coordinate-0001",
                "Final",
                metadata={"agent_name": "Gordie"},
            )

        asyncio.run(scenario())

        self.assertIsNotNone(broker.live_activity_sender)
        self.assertEqual(
            broker.completions,
            [("session-coordinate-0001", "Gordie", True)],
        )

    def test_partial_link_configuration_never_crashes_plugin_startup(self) -> None:
        service = _Service()
        with patch(
            "loopdy_plugin.adapter.load_runtime_config",
            side_effect=ValueError("Loopdy Link configuration is incomplete"),
        ):
            adapter = LoopdyAdapter(PlatformConfig(enabled=True), service=service)

        self.assertIsNone(adapter.link_client)
        self.assertTrue(asyncio.run(adapter.connect()))

    def test_connect_rejects_an_unconfigured_provider(self) -> None:
        service = _Service()
        service.health = lambda: {
            "configured": False,
            "ready": False,
            "detail": "Provider configuration is invalid",
            "compatible_devices": 0,
        }
        adapter = LoopdyAdapter(PlatformConfig(enabled=True), service=service)

        self.assertFalse(asyncio.run(adapter.connect()))

    def test_channel_message_resolves_the_active_profile_display_name(self) -> None:
        service = _Service()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=service
        )  # type: ignore[arg-type]
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "profile.yaml").write_text(
                "ui_meta:\n  displayName: Atlas\n",
                encoding="utf-8",
            )
            with patch("loopdy_plugin.adapter.get_hermes_home", return_value=home):
                result = asyncio.run(adapter.send("all", "Household update"))

        self.assertTrue(result.success)
        event, _ = service.deliveries[0]
        self.assertEqual(event.profile, "default")
        self.assertEqual(event.detail["agent_name"], "Atlas")

    def test_non_channel_event_resolves_the_configured_profile_display_name(
        self,
    ) -> None:
        service = _Service()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=service
        )  # type: ignore[arg-type]
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "profile.yaml").write_text(
                "ui_meta:\n  displayName: Atlas\n",
                encoding="utf-8",
            )
            with patch("loopdy_plugin.adapter.get_hermes_home", return_value=home):
                result = asyncio.run(
                    adapter.send(
                        "all",
                        "Completed",
                        metadata={
                            "event_type": "session.completed",
                            "profile": "default",
                        },
                    )
                )

        self.assertTrue(result.success)
        event, _ = service.deliveries[0]
        self.assertEqual(event.profile, "default")
        self.assertEqual(event.detail["agent_name"], "Atlas")

    def test_verified_link_turn_enters_the_official_inbound_message_path(self) -> None:
        from loopdy_plugin.link_client import InboundLinkTurn
        from loopdy_plugin.link_contracts import UserMessage

        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )
        adapter.handle_message = AsyncMock()
        with tempfile.TemporaryDirectory() as directory:
            media_path = Path(directory) / "forecast.png"
            media_path.write_bytes(b"PNG!")
            turn = InboundLinkTurn(
                message=UserMessage(
                    message_id="message-coordinate-0001",
                    session_id="session-coordinate-0001",
                    agent_id="finance",
                    actor_id="actor-coordinate-1",
                    actor_name="Alex",
                    device_name="Kitchen iPad",
                    text="Hello Hermes",
                    attachments=(),
                    sent_at=1788000000,
                ),
                sender_id="link_verified_sender_coordinate",
                sender_device_id="mobile-private-coordinate",
                attachment_paths=(str(media_path),),
                attachment_types=("image/png",),
            )

            asyncio.run(adapter.receive_link_turn(turn))

            event = adapter.handle_message.await_args.args[0]
            self.assertEqual(event.text, "Hello Hermes")
            self.assertEqual(event.source.user_id, "link_verified_sender_coordinate")
            self.assertEqual(event.source.chat_id, "session-coordinate-0001")
            self.assertEqual(event.source.platform.value, "loopdy")
            self.assertEqual(event.source.profile, "finance")
            self.assertEqual(event.media_urls, [str(media_path)])
            self.assertEqual(event.media_types, ["image/png"])
            self.assertTrue(media_path.exists())
            self.assertTrue(event.metadata["loopdy_link_verified"])
        self.assertNotIn("mobile-private-coordinate", repr(event.metadata))

    def test_verified_link_media_is_released_only_after_hermes_processing_completes(self) -> None:
        from loopdy_plugin.link_client import InboundLinkTurn
        from loopdy_plugin.link_contracts import UserMessage

        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )
        adapter.handle_message = AsyncMock()
        with tempfile.TemporaryDirectory() as directory:
            media_path = Path(directory) / "forecast.png"
            media_path.write_bytes(b"PNG!")
            turn = InboundLinkTurn(
                message=UserMessage(
                    message_id="message-media-lifecycle-0001",
                    session_id="session-media-lifecycle-0001",
                    agent_id="finance",
                    actor_id="actor-coordinate-1",
                    actor_name="Alex",
                    device_name="Kitchen iPad",
                    text="Read this image",
                    attachments=(),
                    sent_at=1788000000,
                ),
                sender_id="link_verified_sender_coordinate",
                sender_device_id="mobile-private-coordinate",
                attachment_paths=(str(media_path),),
                attachment_types=("image/png",),
            )

            asyncio.run(adapter.receive_link_turn(turn))
            self.assertTrue(media_path.exists())

            event = adapter.handle_message.await_args.args[0]
            asyncio.run(adapter.on_processing_complete(event, ProcessingOutcome.SUCCESS))

            self.assertFalse(media_path.exists())
            self.assertEqual(
                link.released_attachment_paths,
                [(str(media_path),)],
            )

    def test_verified_link_turn_maps_explicit_behaviors_to_official_gateway_controls(self) -> None:
        from loopdy_plugin.link_client import InboundLinkTurn
        from loopdy_plugin.link_contracts import UserMessage

        async def scenario(behavior: str):
            adapter = LoopdyAdapter(
                PlatformConfig(enabled=True),
                service=_Service(),
                link_client=_LinkClient(),
            )
            adapter.handle_message = AsyncMock()
            turn = InboundLinkTurn(
                message=UserMessage(
                    message_id=f"message-{behavior}-coordinate-0001",
                    session_id=f"session-{behavior}-coordinate-0001",
                    agent_id="finance",
                    actor_id="actor-coordinate-1",
                    actor_name="Alex",
                    device_name="Kitchen iPad",
                    text="Change course",
                    sent_at=1788000000,
                    behavior=behavior,
                ),
                sender_id="link_verified_sender_coordinate",
                sender_device_id="mobile-private-coordinate",
                attachment_paths=(),
                attachment_types=(),
            )
            await adapter.receive_link_turn(turn)
            return adapter

        steered = asyncio.run(scenario("steer"))
        queued = asyncio.run(scenario("queue"))

        self.assertEqual(
            steered.handle_message.await_args.args[0].text,
            "/steer Change course",
        )
        self.assertEqual(
            queued.handle_message.await_args.args[0].text,
            "/queue Change course",
        )

    def test_verified_link_steer_with_media_uses_the_official_queue_fallback(self) -> None:
        from loopdy_plugin.link_client import InboundLinkTurn
        from loopdy_plugin.link_contracts import UserMessage

        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=_LinkClient(),
        )
        adapter.handle_message = AsyncMock()
        turn = InboundLinkTurn(
            message=UserMessage(
                message_id="message-media-steer-coordinate-0001",
                session_id="session-media-steer-coordinate-0001",
                agent_id="finance",
                actor_id="actor-coordinate-1",
                actor_name="Alex",
                device_name="Kitchen iPad",
                text="Use this image next",
                sent_at=1788000000,
                behavior="steer",
            ),
            sender_id="link_verified_sender_coordinate",
            sender_device_id="mobile-private-coordinate",
            attachment_paths=("/private/fixture/image.png",),
            attachment_types=("image/png",),
        )

        asyncio.run(adapter.receive_link_turn(turn))

        event = adapter.handle_message.await_args.args[0]
        self.assertEqual(event.text, "/queue Use this image next")
        self.assertEqual(event.media_urls, ["/private/fixture/image.png"])
        self.assertEqual(event.media_types, ["image/png"])

    def test_pending_hermes_intercept_keeps_original_link_text_unprefixed(self) -> None:
        from loopdy_plugin.link_client import InboundLinkTurn
        from loopdy_plugin.link_contracts import UserMessage

        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=_LinkClient(),
        )
        adapter.handle_message = AsyncMock()
        adapter._has_pending_link_intercept = lambda _source: True
        turn = InboundLinkTurn(
            message=UserMessage(
                message_id="message-clarify-coordinate-0001",
                session_id="session-clarify-coordinate-0001",
                agent_id="finance",
                actor_id="actor-coordinate-1",
                actor_name="Alex",
                device_name="Kitchen iPad",
                text="Yes",
                sent_at=1788000000,
                behavior="steer",
            ),
            sender_id="link_verified_sender_coordinate",
            sender_device_id="mobile-private-coordinate",
            attachment_paths=(),
            attachment_types=(),
        )

        asyncio.run(adapter.receive_link_turn(turn))

        self.assertEqual(adapter.handle_message.await_count, 1)
        self.assertEqual(adapter.handle_message.await_args.args[0].text, "Yes")

    def test_interrupt_behavior_orders_silent_stop_before_the_original_event(self) -> None:
        from gateway.platforms.base import EphemeralReply
        from gateway.session import build_session_key
        from loopdy_plugin.link_client import InboundLinkTurn
        from loopdy_plugin.link_contracts import UserMessage

        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=_LinkClient(),
        )
        observed = []

        async def handle(event):
            observed.append(
                (event.text, adapter._unwrap_ephemeral(EphemeralReply("Stopped")))
            )

        adapter.handle_message = handle
        turn = InboundLinkTurn(
            message=UserMessage(
                message_id="message-interrupt-coordinate-0001",
                session_id="session-interrupt-coordinate-0001",
                agent_id="finance",
                actor_id="actor-coordinate-1",
                actor_name="Alex",
                device_name="Kitchen iPad",
                text="Do this instead",
                sent_at=1788000000,
                behavior="interrupt",
            ),
            sender_id="link_verified_sender_coordinate",
            sender_device_id="mobile-private-coordinate",
            attachment_paths=(),
            attachment_types=(),
        )
        source = adapter.build_source(
            chat_id=turn.message.session_id,
            chat_name="Loopdy chat",
            chat_type="dm",
            user_id=turn.sender_id,
            user_name=turn.message.actor_name,
            message_id=turn.message.message_id,
        )
        source.profile = turn.message.agent_id
        session_key = build_session_key(
            source,
            group_sessions_per_user=adapter.config.extra.get(
                "group_sessions_per_user", True
            ),
            thread_sessions_per_user=adapter.config.extra.get(
                "thread_sessions_per_user", False
            ),
            profile=adapter._session_key_profile(source),
        )
        adapter._active_sessions[session_key] = asyncio.Event()

        asyncio.run(adapter.receive_link_turn(turn))

        self.assertEqual([text for text, _ in observed], ["/stop", "Do this instead"])
        self.assertEqual(observed[0][1], (None, 0))
        self.assertEqual(observed[1][1], ("Stopped", 0))

    def test_link_reply_uses_the_verified_profile_bound_to_its_session(self) -> None:
        from loopdy_plugin.link_client import InboundLinkTurn
        from loopdy_plugin.link_contracts import UserMessage

        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )
        adapter.handle_message = AsyncMock()
        turn = InboundLinkTurn(
            message=UserMessage(
                message_id="message-coordinate-0002",
                session_id="session-coordinate-0002",
                agent_id="finance",
                actor_id="actor-coordinate-1",
                actor_name="Alex",
                device_name="Kitchen iPad",
                text="Give the finance agent a turn",
                attachments=(),
                sent_at=1788000000,
            ),
            sender_id="link_verified_sender_coordinate",
            sender_device_id="mobile-private-coordinate",
            attachment_paths=(),
            attachment_types=(),
        )

        async def scenario() -> SendResult:
            await adapter.receive_link_turn(turn)
            return await adapter.send(
                "session-coordinate-0002",
                "Finance agent reply",
            )

        with patch("loopdy_plugin.adapter._active_profile_id", return_value="default"), \
             patch(
                 "loopdy_plugin.adapter.profile_display_name",
                 side_effect=lambda profile: {
                     "default": "Default",
                     "finance": "Finance",
                 }[profile],
             ):
            result = asyncio.run(scenario())

        self.assertTrue(result.success)
        self.assertEqual(link.payloads[-1]["agentId"], "finance")
        self.assertEqual(link.payloads[-1]["agentName"], "Finance")

    def test_official_session_store_is_shared_with_the_link_activity_broker(
        self,
    ) -> None:
        broker = _ActivityBroker()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=_LinkClient(),
            activity_broker=broker,
        )
        session_store = type(
            "SessionStore",
            (),
            {},
        )()

        adapter.set_session_store(session_store)

        self.assertIs(broker.session_store, session_store)

    def test_link_wake_readiness_never_becomes_a_host_relay_registration_or_hermes_turn(self) -> None:
        from loopdy_plugin.link_client import InboundLinkRelayReady
        from loopdy_plugin.link_contracts import RelayReady

        service = _Service()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=service, link_client=_LinkClient()
        )
        adapter.handle_message = AsyncMock()
        registration = RelayReady(
            device_id="mobile-private-coordinate",
            enrollment_revision=4,
            acknowledgement_revision=5,
            lease_expires=1789000000,
            recipient_public_key="B" + "A" * 86,
            recipient_key_id="A" * 43,
            sender_key_revision=2,
            acknowledged_sender_key_ids=("A" * 43,),
            environment="production",
            topic=".".join(("app", "loopdy", "mobile")),
            device_name="Alex's iPhone",
            sent_at=1788000000,
            scope="link_wake",
        )

        asyncio.run(
            adapter.receive_link_payload(
                InboundLinkRelayReady(
                    registration=registration,
                    sender_device_id="mobile-private-coordinate",
                )
            )
        )

        self.assertEqual(service.link_relay_registrations, [])
        adapter.handle_message.assert_not_awaited()

    def test_link_chat_reply_and_native_draft_use_encrypted_realtime_transport(self) -> None:
        link = _LinkClient()
        service = _Service()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=service, link_client=link
        )

        self.assertTrue(asyncio.run(adapter.connect()))
        self.assertTrue(adapter.authorization_is_upstream)
        self.assertTrue(adapter.supports_draft_streaming(chat_type="dm"))
        draft = asyncio.run(
            adapter.send_draft(
                "session-coordinate-0001", 42, "Working on it", {"agent_name": "Atlas"}
            )
        )
        final = asyncio.run(
            adapter.send(
                "session-coordinate-0001",
                "Finished",
                metadata={"agent_name": "Atlas"},
            )
        )

        self.assertTrue(draft.success)
        self.assertTrue(final.success)
        self.assertEqual([value["delivery"] for value in link.payloads], ["draft", "final"])
        self.assertEqual([value["agentId"] for value in link.payloads], ["default", "default"])
        self.assertEqual(service.deliveries, [])
        asyncio.run(adapter.disconnect())
        self.assertTrue(link.stopped)

    def test_interim_assistant_send_stays_draft_until_the_turn_final(self) -> None:
        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )

        interim = asyncio.run(
            adapter.send(
                "session-coordinate-0001",
                "I’ll check the weather.",
                metadata={"_interim_send": True, "agent_name": "Gordie"},
            )
        )
        final = asyncio.run(
            adapter.send(
                "session-coordinate-0001",
                "It is 72 degrees and sunny.",
                metadata={"agent_name": "Gordie"},
            )
        )

        self.assertTrue(interim.success)
        self.assertTrue(final.success)
        self.assertEqual(
            [value["delivery"] for value in link.payloads],
            ["draft", "final"],
        )
        self.assertEqual(
            [value["agentName"] for value in link.payloads],
            ["Gordie", "Gordie"],
        )
        self.assertGreater(link.payloads[0]["draftId"], 0)
        self.assertNotIn("draftId", link.payloads[1])

    def test_hermes_stream_consumer_emits_a_terminal_link_message(self) -> None:
        """The Hermes draft contract must end with a real final Link frame.

        ``send_draft`` is intentionally preview-only.  When Hermes receives
        the completed turn, its stream consumer must take the regular
        ``send`` path so Loopdy Link receives ``delivery=final`` and the
        client can stop its working state.
        """
        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )
        config = StreamConsumerConfig(
            transport="auto",
            chat_type="dm",
            edit_interval=0.01,
            buffer_threshold=1,
            cursor="",
        )
        consumer = GatewayStreamConsumer(
            adapter,
            "session-coordinate-0001",
            config,
        )

        async def scenario() -> None:
            self.assertTrue(await adapter.connect())
            task = asyncio.create_task(consumer.run())
            consumer.on_delta("The weather is sunny.")
            await asyncio.sleep(0.06)
            consumer.finish("The weather is sunny.")
            await task

        asyncio.run(scenario())

        self.assertEqual(
            [value["delivery"] for value in link.payloads],
            ["draft", "final"],
        )
        self.assertEqual(link.payloads[-1]["text"], "The weather is sunny.")

    def test_native_draft_revisions_and_final_reuse_one_link_message_identity(self) -> None:
        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )
        metadata = {
            "agent_name": "Gordie",
            "reply_to_message_id": "user_turn_fixture_0001",
        }

        first = asyncio.run(
            adapter.send_draft(
                "session-coordinate-0001", 42, "Tomorrow in Kansas City:", metadata
            )
        )
        second = asyncio.run(
            adapter.send_draft(
                "session-coordinate-0001",
                42,
                "Tomorrow in Kansas City:\n\n- Sunny\n- High: 100°F",
                metadata,
            )
        )
        final = asyncio.run(
            adapter.send(
                "session-coordinate-0001",
                "Tomorrow in Kansas City:\n\n- Sunny\n- High: 100°F\n- Low: 79°F",
                metadata=metadata,
            )
        )

        self.assertTrue(first.success)
        self.assertTrue(second.success)
        self.assertTrue(final.success)
        self.assertEqual(
            [payload["delivery"] for payload in link.payloads],
            ["draft", "draft", "final"],
        )
        self.assertEqual(len({payload["messageId"] for payload in link.payloads}), 1)

    def test_native_draft_revision_ids_still_reuse_one_turn_message_identity(self) -> None:
        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )
        metadata = {
            "agent_name": "Gordie",
            "reply_to_message_id": "user_turn_fixture_revision_0001",
        }

        first = asyncio.run(
            adapter.send_draft(
                "session-coordinate-0001", 41, "Tomorrow in Kansas City:", metadata
            )
        )
        second = asyncio.run(
            adapter.send_draft(
                "session-coordinate-0001",
                42,
                "Tomorrow in Kansas City:\n\n- Sunny\n- High: 100°F",
                metadata,
            )
        )
        final = asyncio.run(
            adapter.send(
                "session-coordinate-0001",
                "Tomorrow in Kansas City:\n\n- Sunny\n- High: 100°F\n- Low: 79°F",
                metadata=metadata,
            )
        )

        self.assertTrue(first.success)
        self.assertTrue(second.success)
        self.assertTrue(final.success)
        self.assertEqual(
            [payload["delivery"] for payload in link.payloads],
            ["draft", "draft", "final"],
        )
        self.assertEqual(len({payload["messageId"] for payload in link.payloads}), 1)

    def test_clarify_prompt_identity_wins_over_active_draft_and_survives_replay(
        self,
    ) -> None:
        service = _Service()
        first_link = _NotificationFailingOnceLink()
        first_adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=service, link_client=first_link
        )
        metadata = {
            "agent_name": "Gordie",
            "reply_to_message_id": "user_turn_clarify_identity_0001",
        }
        pending = SimpleNamespace(
            clarify_id="clarify-deterministic-identity",
            multi_select=False,
        )

        async def scenario():
            draft = await first_adapter.send_draft(
                "session-clarify-identity-0001",
                42,
                "I need one detail before continuing.",
                metadata,
            )
            failed = await first_adapter.send_clarify(
                chat_id="session-clarify-identity-0001",
                question="Which environment should I use?",
                choices=["Staging", "Production"],
                clarify_id="clarify-deterministic-identity",
                session_key="loopdy:gordie:session-clarify-identity-0001",
                metadata=metadata,
            )

            # Recreate the adapter around the same durable event store, as a
            # host process would after crashing between prompt and notification
            # delivery.
            replay_link = _LinkClient()
            replay_adapter = LoopdyAdapter(
                PlatformConfig(enabled=True), service=service, link_client=replay_link
            )
            replayed = await replay_adapter.send_clarify(
                chat_id="session-clarify-identity-0001",
                question="Which environment should I use?",
                choices=["Staging", "Production"],
                clarify_id="clarify-deterministic-identity",
                session_key="loopdy:gordie:session-clarify-identity-0001",
                metadata=metadata,
            )
            return draft, failed, replayed, replay_link

        with (
            patch("tools.clarify_gateway.get_pending_for_session", return_value=pending),
            patch("tools.clarify_gateway.get_clarify_timeout", return_value=90),
            patch("loopdy_plugin.adapter.time.time", return_value=1_788_200_000),
        ):
            draft, failed, replayed, replay_link = asyncio.run(scenario())

        self.assertTrue(draft.success)
        self.assertFalse(failed.success)
        self.assertTrue(replayed.success)
        first_draft, clarify_prompt = [
            payload
            for payload in first_link.payloads
            if payload.get("type") == "assistant.message"
        ]
        self.assertNotEqual(first_draft["messageId"], clarify_prompt["messageId"])
        self.assertEqual(clarify_prompt["messageId"], replayed.message_id)
        self.assertTrue(clarify_prompt["messageId"].startswith("message_"))
        self.assertEqual(
            [
                payload
                for payload in replay_link.payloads
                if payload.get("type") == "assistant.message"
            ],
            [],
        )

    def test_link_reply_resolves_name_from_the_target_profile(self) -> None:
        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )

        with patch("loopdy_plugin.adapter._active_profile_id", return_value="default"), \
             patch(
                 "loopdy_plugin.adapter.profile_display_name",
                 side_effect=lambda profile: {
                     "default": "Default",
                     "research": "Research",
                 }[profile],
             ):
            result = asyncio.run(
                adapter.send(
                    "session-coordinate-0001",
                    "Research update",
                    metadata={"profile": "research"},
                )
            )

        self.assertTrue(result.success)
        self.assertEqual(link.payloads[-1]["agentId"], "research")
        self.assertEqual(link.payloads[-1]["agentName"], "Research")

    def test_verified_voice_request_uses_hermes_tts_and_returns_encrypted_audio_chunks(self) -> None:
        from loopdy_plugin.adapter import SynthesizedVoiceAudio
        from loopdy_plugin.link_client import InboundLinkVoiceSpeak
        from loopdy_plugin.link_contracts import VoiceSpeakRequest

        link = _LinkClient()
        synthesized = []

        def synthesize(request):
            synthesized.append(request)
            return SynthesizedVoiceAudio(
                audio=b"a" * 100_000,
                mime_type="audio/mpeg",
                provider="ElevenLabs",
            )

        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=link,
            voice_synthesizer=synthesize,
        )
        inbound = InboundLinkVoiceSpeak(
            request=VoiceSpeakRequest(
                request_id="voice_request_fixture_0001",
                session_id="session-coordinate-0001",
                agent_id="finance",
                text="Read this aloud.",
                speed=1.15,
                sent_at=1_788_000_000,
            ),
            sender_device_id="mobile-private-coordinate",
        )

        async def run():
            await adapter.receive_link_payload(inbound)
            await asyncio.gather(*tuple(adapter._voice_tasks))

        asyncio.run(run())

        self.assertEqual(synthesized, [inbound.request])
        self.assertEqual([item["type"] for item in link.payloads], [
            "voice.speak.chunk",
            "voice.speak.chunk",
        ])
        self.assertEqual([item["index"] for item in link.payloads], [0, 1])
        self.assertTrue(all(item["provider"] == "ElevenLabs" for item in link.payloads))

    def test_official_model_picker_round_trip_is_exactly_session_and_sender_bound(self) -> None:
        from loopdy_plugin.link_client import (
            InboundLinkPickerOpen,
            InboundLinkPickerSelection,
        )
        from loopdy_plugin.link_contracts import PickerOpen, PickerSelection

        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )
        callback = AsyncMock(return_value="Model changed for this session.")
        picker_results = []

        async def handler(event):
            picker_results.append(await adapter.send_model_picker(
                chat_id="session-coordinate-0001",
                providers=[
                    {
                        "slug": "openai-codex",
                        "name": "OpenAI Codex",
                        "models": ["gpt-5.6", "gpt-5.5"],
                        "api_key": "must-never-cross-link",
                    }
                ],
                current_model="gpt-5.5",
                current_provider="openai-codex",
                session_key="loopdy:session-coordinate-0001",
                on_model_selected=callback,
            ))

        adapter._message_handler = AsyncMock(side_effect=handler)
        opened = InboundLinkPickerOpen(
            request=PickerOpen(
                request_id="picker_request_fixture_0001",
                session_id="session-coordinate-0001",
                agent_id="finance",
                kind="model",
                sent_at=1_788_000_030,
            ),
            sender_device_id="mobile-private-coordinate",
        )

        async def run() -> None:
            await adapter.receive_link_payload(opened)
            event = adapter._message_handler.await_args.args[0]
            self.assertEqual(event.text, "/model")
            self.assertEqual(event.source.profile, "finance")
            self.assertTrue(event.metadata["loopdy_link_control"])
            self.assertTrue(picker_results[0].success)
            await adapter.receive_link_payload(
                InboundLinkPickerSelection(
                    selection=PickerSelection(
                        picker_id="picker_request_fixture_0001",
                        session_id="session-coordinate-0001",
                        kind="model",
                        provider="openai-codex",
                        model="gpt-5.6",
                        sent_at=1_788_000_031,
                    ),
                    sender_device_id="mobile-private-coordinate",
                )
            )

        asyncio.run(run())

        callback.assert_awaited_once_with(
            "session-coordinate-0001", "gpt-5.6", "openai-codex"
        )
        self.assertEqual([item["type"] for item in link.payloads], [
            "picker.model",
            "picker.result",
        ])
        self.assertNotIn("must-never-cross-link", repr(link.payloads))
        self.assertEqual(link.payloads[1]["status"], "completed")

    def test_picker_control_dispatch_does_not_deliver_text_fallback_into_chat(self) -> None:
        """A picker request is control-plane traffic, never a chat turn."""
        from loopdy_plugin.link_client import InboundLinkPickerOpen
        from loopdy_plugin.link_contracts import PickerOpen

        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )
        adapter.handle_message = AsyncMock()
        handler = AsyncMock(return_value="**OpenAI** `--provider openai`: gpt-5.6")
        adapter._message_handler = handler
        opened = InboundLinkPickerOpen(
            request=PickerOpen(
                request_id="picker_request_fixture_control_0001",
                session_id="session-coordinate-control-0001",
                agent_id="finance",
                kind="model",
                sent_at=1_788_000_040,
            ),
            sender_device_id="mobile-private-coordinate",
        )

        asyncio.run(adapter.receive_link_payload(opened))

        handler.assert_awaited_once()
        control_event = handler.await_args.args[0]
        self.assertEqual(control_event.text, "/model")
        self.assertTrue(control_event.metadata["loopdy_link_control"])
        adapter.handle_message.assert_not_awaited()
        self.assertEqual(len(link.payloads), 1)
        self.assertEqual(link.payloads[0]["type"], "picker.result")
        self.assertEqual(link.payloads[0]["pickerId"], opened.request.request_id)
        self.assertEqual(link.payloads[0]["status"], "failed")
        self.assertIn("without opening", link.payloads[0]["message"].lower())

    def test_picker_open_without_handler_returns_correlated_failure(self) -> None:
        """A missing Hermes handler must not leave the mobile picker pending."""
        from loopdy_plugin.link_client import InboundLinkPickerOpen
        from loopdy_plugin.link_contracts import PickerOpen

        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )
        adapter._message_handler = None
        opened = InboundLinkPickerOpen(
            request=PickerOpen(
                request_id="picker_request_fixture_missing_0001",
                session_id="session-coordinate-missing-0001",
                agent_id="finance",
                kind="model",
                sent_at=1_788_000_041,
            ),
            sender_device_id="mobile-private-coordinate",
        )

        asyncio.run(adapter.receive_link_payload(opened))

        self.assertEqual(len(link.payloads), 1)
        failure = link.payloads[0]
        self.assertEqual(
            {
                "type": failure["type"],
                "pickerId": failure["pickerId"],
                "sessionId": failure["sessionId"],
                "kind": failure["kind"],
                "status": failure["status"],
            },
            {
                "type": "picker.result",
                "pickerId": opened.request.request_id,
                "sessionId": opened.request.session_id,
                "kind": opened.request.kind,
                "status": "failed",
            },
        )
        self.assertIn("handler", failure["message"].lower())

    def test_picker_open_handler_failure_returns_correlated_failure(self) -> None:
        """A Hermes picker dispatch exception must be reported to the requester."""
        from loopdy_plugin.link_client import InboundLinkPickerOpen
        from loopdy_plugin.link_contracts import PickerOpen

        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )

        async def failing_handler(_event):
            raise RuntimeError("picker backend unavailable")

        adapter._message_handler = failing_handler
        opened = InboundLinkPickerOpen(
            request=PickerOpen(
                request_id="picker_request_fixture_failure_0001",
                session_id="session-coordinate-failure-0001",
                agent_id="finance",
                kind="reasoning",
                sent_at=1_788_000_042,
            ),
            sender_device_id="mobile-private-coordinate",
        )

        asyncio.run(adapter.receive_link_payload(opened))

        self.assertEqual(len(link.payloads), 1)
        failure = link.payloads[0]
        self.assertEqual(failure["type"], "picker.result")
        self.assertEqual(failure["pickerId"], opened.request.request_id)
        self.assertEqual(failure["sessionId"], opened.request.session_id)
        self.assertEqual(failure["kind"], opened.request.kind)
        self.assertEqual(failure["status"], "failed")
        self.assertIn("could not open", failure["message"].lower())

    def test_overlapping_picker_requests_keep_request_ownership_and_reject_late_callback(self) -> None:
        from loopdy_plugin.link_client import InboundLinkPickerOpen
        from loopdy_plugin.link_contracts import PickerOpen

        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )
        callbacks = []

        async def handler(event):
            callbacks.append(event)
            if event.message_id.endswith("0002"):
                result = await adapter.send_model_picker(
                    chat_id="shared-session-coordinate",
                    providers=[{"slug": "openai", "name": "OpenAI", "models": ["gpt-5.6"]}],
                    current_model="gpt-5.6",
                    current_provider="openai",
                    session_key="loopdy:shared-session",
                    on_model_selected=AsyncMock(),
                )
                self.assertTrue(result.success)

        adapter._message_handler = handler
        first = InboundLinkPickerOpen(
            request=PickerOpen(
                request_id="picker_request_overlap_0001",
                session_id="shared-session-coordinate",
                agent_id="finance",
                kind="model",
                sent_at=1_788_000_043,
            ),
            sender_device_id="mobile-private-coordinate",
        )
        second = InboundLinkPickerOpen(
            request=PickerOpen(
                request_id="picker_request_overlap_0002",
                session_id="shared-session-coordinate",
                agent_id="finance",
                kind="model",
                sent_at=1_788_000_044,
            ),
            sender_device_id="mobile-private-coordinate",
        )

        async def run() -> None:
            await adapter.receive_link_payload(first)
            await adapter.receive_link_payload(second)
            late = await adapter.send_model_picker(
                chat_id="shared-session-coordinate",
                providers=[{"slug": "openai", "name": "OpenAI", "models": ["gpt-5.5"]}],
                current_model="gpt-5.5",
                current_provider="openai",
                session_key="loopdy:shared-session",
                on_model_selected=AsyncMock(),
            )
            self.assertFalse(late.success)

        asyncio.run(run())

        self.assertEqual(
            [(item["type"], item["pickerId"]) for item in link.payloads],
            [
                ("picker.result", first.request.request_id),
                ("picker.model", second.request.request_id),
            ],
        )

    def test_reasoning_picker_rejects_replay_from_another_device_and_accepts_allowed_choice(self) -> None:
        from loopdy_plugin.link_client import (
            InboundLinkPickerOpen,
            InboundLinkPickerSelection,
        )
        from loopdy_plugin.link_contracts import PickerOpen, PickerSelection

        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )
        callback = AsyncMock(return_value="Reasoning effort set to high.")
        picker_results = []

        async def handler(event):
            picker_results.append(await adapter.send_choice_picker(
                chat_id="session-coordinate-0001",
                title="Reasoning effort · Medium",
                choices=[
                    {"value": "low", "label": "Low", "is_current": False},
                    {"value": "high", "label": "High", "is_current": False},
                ],
                session_key="loopdy:session-coordinate-0001",
                on_choice_selected=callback,
            ))

        adapter._message_handler = AsyncMock(side_effect=handler)
        open_message = InboundLinkPickerOpen(
            request=PickerOpen(
                request_id="picker_request_fixture_0002",
                session_id="session-coordinate-0001",
                agent_id="finance",
                kind="reasoning",
                sent_at=1_788_000_032,
            ),
            sender_device_id="mobile-private-coordinate",
        )
        selection = PickerSelection(
            picker_id="picker_request_fixture_0002",
            session_id="session-coordinate-0001",
            kind="reasoning",
            value="high",
            sent_at=1_788_000_033,
        )

        async def run() -> None:
            await adapter.receive_link_payload(open_message)
            self.assertTrue(picker_results[0].success)
            await adapter.receive_link_payload(
                InboundLinkPickerSelection(
                    selection=selection,
                    sender_device_id="different-paired-device",
                )
            )
            callback.assert_not_awaited()
            await adapter.receive_link_payload(
                InboundLinkPickerSelection(
                    selection=selection,
                    sender_device_id="mobile-private-coordinate",
                )
            )

        asyncio.run(run())

        callback.assert_awaited_once_with("session-coordinate-0001", "high")
        self.assertEqual([item["status"] for item in link.payloads if item["type"] == "picker.result"], [
            "failed",
            "completed",
        ])

    def test_verified_session_fork_returns_only_the_bound_result_to_the_requesting_device(self) -> None:
        import base64
        import hashlib

        from loopdy_plugin.link_client import InboundLinkSessionFork
        from loopdy_plugin.link_contracts import SessionForkRequest, session_fork_result

        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )
        request = SessionForkRequest(
            request_id="fork_request_fixture_0001",
            source_session_id="source_session_fixture_0001",
            fork_session_id="fork_session_fixture_000001",
            agent_id="finance",
            actor_id="family-member-1",
            actor_name="Alex",
            device_name="Kitchen iPad",
            user_turn=2,
            checkpoint_role="assistant",
            checkpoint_digest=base64.urlsafe_b64encode(
                hashlib.sha256(b"Second answer").digest()
            ).decode("ascii").rstrip("="),
            title="Budget review · Fork",
            sent_at=1_788_000_040,
        )
        expected = session_fork_result(
            request=request,
            status="completed",
            title=request.title,
            message="Fork ready.",
            sent_at=1_788_000_041,
        )
        adapter._fork_link_session = AsyncMock(return_value=expected)

        asyncio.run(
            adapter.receive_link_payload(
                InboundLinkSessionFork(
                    request=request,
                    sender_id="link_verified_sender_coordinate",
                    sender_device_id="mobile-private-coordinate",
                )
            )
        )

        adapter._fork_link_session.assert_awaited_once()
        self.assertEqual(link.payloads, [expected])
        self.assertNotIn("Second answer", repr(link.payloads))

    def test_slash_catalog_uses_official_registry_metadata_and_returns_to_requester(self) -> None:
        from loopdy_plugin.link_client import InboundLinkCommandCatalog
        from loopdy_plugin.link_contracts import CommandCatalogRequest

        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )
        request = CommandCatalogRequest(
            request_id="commands_request_fixture_0001",
            session_id="session_fixture_0001",
            agent_id="gordie",
            sent_at=1_788_000_060,
        )
        adapter._build_link_command_catalog = AsyncMock(
            return_value=[
                {
                    "name": "help",
                    "description": "Show available commands",
                    "category": "Help",
                    "argsHint": "[query]",
                    "aliases": ["commands"],
                    "argumentMode": "text",
                    "source": "core",
                    "requiresArguments": False,
                }
            ]
        )

        asyncio.run(
            adapter.receive_link_payload(
                InboundLinkCommandCatalog(
                    request=request,
                    sender_device_id="mobile-private-coordinate",
                )
            )
        )

        adapter._build_link_command_catalog.assert_awaited_once_with(request)
        self.assertEqual(link.payloads[0]["type"], "commands.catalog")
        self.assertEqual(link.payloads[0]["commands"][0]["name"], "help")

    def test_slash_catalog_retries_after_link_reconnect(self) -> None:
        from loopdy_plugin.link_client import InboundLinkCommandCatalog
        from loopdy_plugin.link_contracts import CommandCatalogRequest

        link = _ReconnectableControlLink()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True), service=_Service(), link_client=link
        )
        request = CommandCatalogRequest(
            request_id="commands_request_reconnect_0001",
            session_id="session_fixture_reconnect_0001",
            agent_id="gordie",
            sent_at=1_788_000_061,
        )
        adapter._build_link_command_catalog = AsyncMock(
            return_value=[
                {
                    "name": "help",
                    "description": "Show help",
                    "category": "Help",
                    "argsHint": "",
                    "aliases": [],
                    "argumentMode": "none",
                    "source": "core",
                    "requiresArguments": False,
                }
            ]
        )

        asyncio.run(
            adapter.receive_link_payload(
                InboundLinkCommandCatalog(
                    request=request,
                    sender_device_id="mobile-private-coordinate",
                )
            )
        )

        self.assertEqual(link.send_attempts, 2)
        self.assertEqual(link.payloads[0]["type"], "commands.catalog")

    def test_personality_management_returns_the_hermes_owned_revisioned_catalog(self) -> None:
        from loopdy_plugin.link_client import InboundLinkPersonalityRequest
        from loopdy_plugin.link_contracts import PersonalityRequest

        class _Personalities:
            def mutate(self, request):
                self.request = request
                return {
                    "revision": 7,
                    "activeName": "helpful",
                    "personalities": [
                        {
                            "name": "helpful",
                            "description": "Friendly and useful",
                            "systemPrompt": "Be helpful.",
                            "tone": "",
                            "style": "",
                            "builtIn": True,
                            "customized": False,
                        }
                    ],
                }

        link = _LinkClient()
        personalities = _Personalities()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=link,
            personality_manager=personalities,
        )
        request = PersonalityRequest(
            request_id="personality-request-0001",
            action="catalog",
            expected_revision=None,
            name=None,
            definition=None,
            sent_at=1_788_000_070,
        )

        asyncio.run(
            adapter.receive_link_payload(
                InboundLinkPersonalityRequest(
                    request=request,
                    sender_device_id="mobile-private-coordinate",
                )
            )
        )

        self.assertIs(personalities.request, request)
        self.assertEqual(link.payloads[0]["type"], "personalities.catalog")
        self.assertEqual(link.payloads[0]["revision"], 7)

    def test_workspace_metadata_is_not_sent_to_an_unnegotiated_legacy_client(self) -> None:
        from loopdy_plugin.link_client import InboundLinkWorkspaceRequest
        from loopdy_plugin.link_contracts import WorkspaceRequest

        controller = SimpleNamespace(execute=AsyncMock(return_value={"agents": []}))
        link = _LinkClient()
        adapter = LoopdyAdapter(PlatformConfig(enabled=True), service=_Service(),
                                link_client=link, workspace_controller=controller)
        request = WorkspaceRequest("workspace-legacy-metadata-0001", "agents.list", {}, 1_788_000_000)
        asyncio.run(adapter.receive_link_payload(InboundLinkWorkspaceRequest(
            request=request, sender_device_id="mobile-legacy-fixture",
        )))
        self.assertNotIn("capabilities", link.payloads[-1])
        self.assertNotIn("context", link.payloads[-1])

    def test_safe_probe_negotiates_metadata_per_device_and_history_reports_current_context(self) -> None:
        from loopdy_plugin.link_client import InboundLinkWorkspaceRequest
        from loopdy_plugin.link_contracts import WorkspaceRequest

        class Controller:
            def __init__(self):
                self.requests = []

            async def execute(self, request):
                self.requests.append(request)
                if request.operation == "agents.list":
                    return {"agents": []}
                return {"storedId": "canonical-session-fixture", "agentId": "default", "messages": []}

        link = _LinkClient()
        controller = Controller()
        adapter = LoopdyAdapter(PlatformConfig(enabled=True), service=_Service(),
                                link_client=link, workspace_controller=controller)
        provider = lambda _: {
            "model": "fixture-model", "contextUsed": 17, "contextMax": 100,
            "contextPercent": 17, "compressions": 0, "isCompacting": False,
        }
        with patch.object(adapter, "_context_window_snapshot", side_effect=provider) as context:
            async def scenario():
                probe = WorkspaceRequest("workspace-metadata-probe-0001", "agents.list",
                                         {"linkProtocol": 1}, 1_788_000_000)
                await adapter.receive_link_payload(InboundLinkWorkspaceRequest(
                    request=probe, sender_device_id="mobile-metadata-fixture",
                ))
                self.assertEqual(controller.requests[-1].payload, {})
                self.assertIn("capabilities", link.payloads[-1])
                history = WorkspaceRequest("workspace-metadata-history-0001", "sessions.history",
                                           {"storedId": "visible-session-fixture", "agentId": "default"},
                                           1_788_000_001)
                await adapter.receive_link_payload(InboundLinkWorkspaceRequest(
                    request=history, sender_device_id="mobile-metadata-fixture",
                ))
                envelope = link.payloads[-1]["context"]
                self.assertEqual(envelope["sessionId"], "visible-session-fixture")
                self.assertTrue(envelope["available"])
                self.assertEqual(envelope["snapshot"]["contextUsed"], 17)
                context.assert_called_with("canonical-session-fixture")
                await adapter.receive_link_payload(InboundLinkWorkspaceRequest(
                    request=history, sender_device_id="another-legacy-fixture",
                ))
                self.assertNotIn("capabilities", link.payloads[-1])
                self.assertNotIn("context", link.payloads[-1])
            asyncio.run(scenario())

    def test_workspace_request_uses_the_explicit_controller_and_returns_a_bound_result(self) -> None:
        from loopdy_plugin.link_client import InboundLinkWorkspaceRequest
        from loopdy_plugin.link_contracts import WorkspaceRequest

        class _WorkspaceController:
            async def execute(self, request):
                self.request = request
                return {
                    "agents": [
                        {
                            "id": "gordie",
                            "name": "Gordie",
                            "isDefault": True,
                        }
                    ]
                }

        link = _LinkClient()
        controller = _WorkspaceController()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=link,
            workspace_controller=controller,
        )
        request = WorkspaceRequest(
            request_id="workspace-request-0001",
            operation="agents.list",
            payload={},
            sent_at=1_788_000_080,
        )

        asyncio.run(
            adapter.receive_link_payload(
                InboundLinkWorkspaceRequest(
                    request=request,
                    sender_device_id="mobile-private-coordinate",
                )
            )
        )

        self.assertIs(controller.request, request)
        self.assertEqual(link.payloads[0]["type"], "workspace.result")
        self.assertEqual(link.payloads[0]["requestId"], request.request_id)
        self.assertEqual(link.payloads[0]["operation"], request.operation)
        self.assertEqual(link.payloads[0]["status"], "completed")
        self.assertEqual(link.payloads[0]["payload"]["agents"][0]["name"], "Gordie")

    def test_workspace_request_binds_the_authenticated_link_sender_during_execution(self) -> None:
        from loopdy_plugin.link_client import InboundLinkWorkspaceRequest
        from loopdy_plugin.link_contracts import WorkspaceRequest

        class _WorkspaceController:
            async def execute(self, request):
                self.request = request
                self.connection_id = adapter._link_workspace_connection_id()
                return {"accepted": True}

        link = _LinkClient()
        controller = _WorkspaceController()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=link,
            workspace_controller=controller,
        )
        request = WorkspaceRequest(
            request_id="workspace-request-connection-0001",
            operation="projects.git.capabilities",
            payload={
                "agentId": "default",
                "sessionId": "session_fixture_0001",
                "workspaceId": "project-loopdy",
            },
            sent_at=1_788_000_081,
        )

        asyncio.run(
            adapter.receive_link_payload(
                InboundLinkWorkspaceRequest(
                    request=request,
                    sender_device_id="mobile-private-coordinate",
                )
            )
        )

        self.assertEqual(controller.connection_id, "mobile-private-coordinate")
        with self.assertRaises(RuntimeError):
            adapter._link_workspace_connection_id()

    def test_project_git_control_error_returns_only_the_bounded_wire_error(self) -> None:
        from loopdy_plugin.link_client import InboundLinkWorkspaceRequest
        from loopdy_plugin.link_contracts import WorkspaceRequest
        from loopdy_plugin.workspace_control import WorkspaceControlError

        class _WorkspaceController:
            async def execute(self, request):
                raise WorkspaceControlError(
                    "Project changes changed. Refresh and try again.",
                    code="status_changed",
                    status="conflict",
                )

        link = _LinkClient()
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=link,
            workspace_controller=_WorkspaceController(),
        )
        request = WorkspaceRequest(
            request_id="workspace-request-error-0001",
            operation="projects.git.status",
            payload={
                "agentId": "default",
                "sessionId": "session_fixture_0001",
                "workspaceId": "project-loopdy",
            },
            sent_at=1_788_000_082,
        )

        asyncio.run(
            adapter.receive_link_payload(
                InboundLinkWorkspaceRequest(
                    request=request,
                    sender_device_id="mobile-private-coordinate",
                )
            )
        )

        self.assertEqual(link.payloads[0]["status"], "conflict")
        self.assertEqual(link.payloads[0]["code"], "status_changed")
        self.assertEqual(link.payloads[0]["payload"], {})
        self.assertNotIn("private", repr(link.payloads[0]).lower())

    def test_project_git_session_workspace_comes_from_the_official_session_row(self) -> None:
        class SessionDB:
            def get_session(self, session_id):
                self.session_id = session_id
                return {"id": session_id, "cwd": "/fixture/loopdy"}

        class SessionStore:
            def __init__(self):
                self._db = SessionDB()

            def lookup_by_session_key(self, session_key):
                self.session_key = session_key
                return SimpleNamespace(
                    session_id="stored-session-0001",
                    platform=Platform("loopdy"),
                    origin=SimpleNamespace(
                        platform=Platform("loopdy"),
                        chat_id="session_fixture_0001",
                        profile="default",
                    ),
                )

        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=_LinkClient(),
        )
        store = SessionStore()
        adapter.set_session_store(store)

        cwd = asyncio.run(
            adapter._get_link_session_workspace("default", "session_fixture_0001")
        )

        self.assertEqual(cwd, "/fixture/loopdy")
        self.assertEqual(store._db.session_id, "stored-session-0001")
        with self.assertRaises(RuntimeError):
            asyncio.run(
                adapter._get_link_session_workspace(
                    "research", "session_fixture_0001"
                )
            )

    def test_workspace_catalog_loads_before_the_link_session_exists(self) -> None:
        class SessionStore:
            _db = SimpleNamespace()

            @staticmethod
            def lookup_by_session_key(_session_key):
                return None

        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=_LinkClient(),
        )
        adapter.set_session_store(SessionStore())
        backend = adapter.workspace_controller.backend

        async def projects_catalog(agent_id):
            self.assertEqual(agent_id, "default")
            return {
                "active_id": "project-loopdy",
                "projects": [{
                    "id": "project-loopdy",
                    "name": "Loopdy",
                    "description": "Loopdy workspace",
                    "archived": False,
                    "primary_path": "/fixture/loopdy",
                    "folders": [{
                        "path": "/fixture/loopdy",
                        "is_primary": True,
                    }],
                }],
            }

        backend._projects_catalog = projects_catalog

        catalog = asyncio.run(backend.projects_list({
            "agentId": "default",
            "sessionId": "session_not_created_0001",
        }))

        self.assertEqual(catalog, {
            "activeWorkspaceId": "project-loopdy",
            "sessionWorkspaceId": None,
            "workspaces": [{
                "id": "project-loopdy",
                "name": "Loopdy",
                "description": "Loopdy workspace",
                "folderCount": 1,
                "isActive": True,
            }],
        })

    def test_production_adapter_installs_the_hermes_workspace_controller(self) -> None:
        from loopdy_plugin.link_contracts import WORKSPACE_OPERATIONS

        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=_LinkClient(),
        )

        self.assertEqual(adapter.workspace_controller.operations, WORKSPACE_OPERATIONS)

    def test_chat_workspace_selection_persists_and_seeds_exact_hermes_session_cwd(self) -> None:
        class _SessionDB:
            def __init__(self):
                self.moves = []

            def update_session_cwd(
                self,
                session_id,
                cwd,
                git_branch=None,
                git_repo_root=None,
                replace_git_meta=False,
            ):
                self.moves.append((
                    session_id,
                    cwd,
                    git_branch,
                    git_repo_root,
                    replace_git_meta,
                ))
                return 1

        class _SessionStore:
            def __init__(self):
                self._db = _SessionDB()
                self.sources = []

            def lookup_by_session_key(self, session_key):
                self.session_key = session_key
                return SimpleNamespace(
                    session_key="agent:main:loopdy:dm:loopdy-chat-0001",
                    session_id="canonical-session-0001",
                )

        evicted = []
        runner = SimpleNamespace(
            _profile_name_for_source=lambda _source: None,
            _evict_cached_agent=evicted.append,
        )
        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=_LinkClient(),
        )
        store = _SessionStore()
        adapter.set_session_store(store)
        adapter.gateway_runner = runner

        with (
            patch("hermes_cli.profiles.profile_exists", return_value=True),
            patch("hermes_cli.profiles.get_profile_dir", return_value=Path("/profiles/default")),
            patch("tools.terminal_tool.register_task_env_overrides") as register,
        ):
            asyncio.run(adapter._set_link_session_workspace(
                "default",
                "loopdy-chat-0001",
                "/srv/workspaces/loopdy",
            ))

        self.assertEqual(
            store.session_key,
            "agent:main:loopdy:dm:loopdy-chat-0001",
        )
        self.assertEqual(store._db.moves, [(
            "canonical-session-0001",
            "/srv/workspaces/loopdy",
            None,
            None,
            True,
        )])
        self.assertEqual(register.call_args_list, [
            unittest.mock.call(
                "agent:main:loopdy:dm:loopdy-chat-0001",
                {"cwd": "/srv/workspaces/loopdy", "cwd_source": "project"},
            ),
            unittest.mock.call(
                "canonical-session-0001",
                {"cwd": "/srv/workspaces/loopdy", "cwd_source": "project"},
            ),
        ])
        self.assertEqual(evicted, [
            "agent:main:loopdy:dm:loopdy-chat-0001",
        ])

    def test_new_chat_workspace_seeds_creation_without_persisting_an_empty_session(self) -> None:
        class _SessionStore:
            _db = SimpleNamespace()

            @staticmethod
            def lookup_by_session_key(_session_key):
                return None

        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=_LinkClient(),
        )
        adapter.set_session_store(_SessionStore())

        with (
            patch("hermes_cli.profiles.profile_exists", return_value=True),
            patch("hermes_cli.profiles.get_profile_dir", return_value=Path("/profiles/default")),
            patch("tools.terminal_tool.register_task_env_overrides") as register,
        ):
            asyncio.run(adapter._set_link_session_workspace(
                "default",
                "loopdy-chat-0001",
                "/srv/workspaces/loopdy",
            ))

        register.assert_called_once_with(
            "agent:main:loopdy:dm:loopdy-chat-0001",
            {"cwd": "/srv/workspaces/loopdy", "cwd_source": "project"},
        )
        self.assertEqual(
            asyncio.run(adapter._get_link_session_workspace(
                "default",
                "loopdy-chat-0001",
            )),
            "/srv/workspaces/loopdy",
        )

    def test_first_turn_persists_pending_workspace_once_without_reseeding_later_turns(self) -> None:
        class _SessionDB:
            def __init__(self):
                self.moves = []

            def update_session_cwd(
                self,
                session_id,
                cwd,
                git_branch=None,
                git_repo_root=None,
                replace_git_meta=False,
            ):
                self.moves.append((
                    session_id,
                    cwd,
                    git_branch,
                    git_repo_root,
                    replace_git_meta,
                ))
                return 1

        class _SessionStore:
            def __init__(self):
                self._db = _SessionDB()
                self.created = []

            @staticmethod
            def lookup_by_session_key(_session_key):
                return None

            def get_or_create_session(self, source):
                self.created.append(source)
                return SimpleNamespace(
                    session_key="agent:main:loopdy:dm:loopdy-chat-0001",
                    session_id="canonical-session-0001",
                )

        adapter = LoopdyAdapter(
            PlatformConfig(enabled=True),
            service=_Service(),
            link_client=_LinkClient(),
        )
        store = _SessionStore()
        adapter.set_session_store(store)
        source = adapter.build_source(
            chat_id="loopdy-chat-0001",
            chat_name="Loopdy chat",
            chat_type="dm",
        )
        source.profile = "default"

        with (
            patch("hermes_cli.profiles.profile_exists", return_value=True),
            patch("hermes_cli.profiles.get_profile_dir", return_value=Path("/profiles/default")),
            patch("tools.terminal_tool.register_task_env_overrides") as register,
        ):
            asyncio.run(adapter._set_link_session_workspace(
                "default",
                "loopdy-chat-0001",
                "/srv/workspaces/loopdy",
            ))
            asyncio.run(adapter._materialize_pending_link_session_workspace(
                "default",
                "loopdy-chat-0001",
                source,
            ))
            asyncio.run(adapter._materialize_pending_link_session_workspace(
                "default",
                "loopdy-chat-0001",
                source,
            ))

        self.assertEqual(len(store.created), 1)
        self.assertEqual(store._db.moves, [(
            "canonical-session-0001",
            "/srv/workspaces/loopdy",
            None,
            None,
            True,
        )])
        self.assertEqual(register.call_args_list, [
            unittest.mock.call(
                "agent:main:loopdy:dm:loopdy-chat-0001",
                {"cwd": "/srv/workspaces/loopdy", "cwd_source": "project"},
            ),
            unittest.mock.call(
                "agent:main:loopdy:dm:loopdy-chat-0001",
                {"cwd": "/srv/workspaces/loopdy", "cwd_source": "project"},
            ),
            unittest.mock.call(
                "canonical-session-0001",
                {"cwd": "/srv/workspaces/loopdy", "cwd_source": "project"},
            ),
        ])
        self.assertNotIn(
            ("default", "loopdy-chat-0001"),
            adapter._link_session_workspaces,
        )

    def test_gateway_runtime_cwd_bridge_uses_persisted_workspace_in_real_prompt(self) -> None:
        from agent.prompt_builder import build_environment_hints
        from agent.runtime_cwd import resolve_agent_cwd
        from tools.terminal_tool import clear_task_env_overrides, terminal_tool

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "selected-workspace"
            configured_home = root / "configured-home"
            selected.mkdir()
            configured_home.mkdir()
            subprocess.run(
                ["git", "init", "-q", str(selected)],
                check=True,
            )
            session_key = "agent:main:loopdy:dm:loopdy-chat-persisted"
            session_id = "canonical-session-persisted"

            class _SessionDB:
                @staticmethod
                def get_session(requested_session_id):
                    self.assertEqual(requested_session_id, session_id)
                    return {"id": session_id, "cwd": str(selected)}

            store = SimpleNamespace(_db=_SessionDB())
            adapter = LoopdyAdapter(
                PlatformConfig(enabled=True),
                service=_Service(),
                link_client=_LinkClient(),
            )
            runner = SimpleNamespace(
                adapters={Platform("loopdy"): adapter},
                session_store=store,
                _profile_name_for_source=lambda _source: None,
            )
            runner._set_session_env = GatewayRunner._set_session_env.__get__(
                runner,
                GatewayRunner,
            )
            runner._clear_session_env = GatewayRunner._clear_session_env.__get__(
                runner,
                GatewayRunner,
            )
            adapter.gateway_runner = runner
            adapter.set_session_store(store)
            context = SessionContext(
                source=SessionSource(
                    platform=Platform("loopdy"),
                    chat_id="loopdy-chat-persisted",
                    profile="default",
                ),
                connected_platforms=[Platform("loopdy")],
                home_channels={},
                session_key=session_key,
                session_id=session_id,
            )

            clear_task_env_overrides(session_key)
            clear_task_env_overrides(session_id)
            with patch.dict(os.environ, {"TERMINAL_CWD": str(configured_home)}):
                tokens = runner._set_session_env(context)
                try:
                    self.assertEqual(resolve_agent_cwd(), selected)
                    prompt = build_environment_hints()
                    terminal = json.loads(terminal_tool(
                        "pwd; git rev-parse --show-toplevel",
                        task_id=session_key,
                        timeout=30,
                    ))
                finally:
                    runner._clear_session_env(tokens)
                self.assertEqual(resolve_agent_cwd(), configured_home)

            self.assertIn(f"Current working directory: {selected}", prompt)
            self.assertNotIn(
                f"Current working directory: {configured_home}",
                prompt,
            )
            self.assertEqual(terminal["exit_code"], 0)
            self.assertEqual(
                [Path(value).resolve() for value in terminal["output"].strip().splitlines()],
                [selected.resolve(), selected.resolve()],
            )

    def test_pending_first_turn_workspace_reaches_real_runtime_prompt(self) -> None:
        from agent.prompt_builder import build_environment_hints
        from agent.runtime_cwd import resolve_agent_cwd
        from tools.terminal_tool import clear_task_env_overrides

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "pending-workspace"
            configured_home = root / "configured-home"
            profile_home = root / "profile-home"
            selected.mkdir()
            configured_home.mkdir()
            profile_home.mkdir()
            session_key = "agent:main:loopdy:dm:loopdy-chat-pending"
            session_id = "canonical-session-pending"

            class _SessionDB:
                def __init__(self):
                    self.rows = {}

                def update_session_cwd(
                    self,
                    requested_session_id,
                    cwd,
                    git_branch=None,
                    git_repo_root=None,
                    replace_git_meta=False,
                ):
                    self.rows[requested_session_id] = {
                        "id": requested_session_id,
                        "cwd": cwd,
                    }
                    return 1

                def get_session(self, requested_session_id):
                    return self.rows.get(requested_session_id)

            class _SessionStore:
                def __init__(self):
                    self._db = _SessionDB()
                    self.entry = None

                def lookup_by_session_key(self, requested_session_key):
                    if requested_session_key != session_key:
                        raise AssertionError(requested_session_key)
                    return self.entry

                def get_or_create_session(self, source):
                    self.entry = SimpleNamespace(
                        session_key=session_key,
                        session_id=session_id,
                    )
                    return self.entry

            store = _SessionStore()
            adapter = LoopdyAdapter(
                PlatformConfig(enabled=True),
                service=_Service(),
                link_client=_LinkClient(),
            )
            runner = SimpleNamespace(
                adapters={Platform("loopdy"): adapter},
                session_store=store,
                _evict_cached_agent=lambda _session_key: None,
                _profile_name_for_source=lambda _source: None,
            )
            runner._set_session_env = GatewayRunner._set_session_env.__get__(
                runner,
                GatewayRunner,
            )
            runner._clear_session_env = GatewayRunner._clear_session_env.__get__(
                runner,
                GatewayRunner,
            )
            adapter.gateway_runner = runner
            adapter.set_session_store(store)
            source = adapter.build_source(
                chat_id="loopdy-chat-pending",
                chat_name="Loopdy chat",
                chat_type="dm",
            )
            source.profile = "default"

            clear_task_env_overrides(session_key)
            clear_task_env_overrides(session_id)
            try:
                with (
                    patch("hermes_cli.profiles.profile_exists", return_value=True),
                    patch(
                        "hermes_cli.profiles.get_profile_dir",
                        return_value=profile_home,
                    ),
                ):
                    asyncio.run(
                        adapter._set_link_session_workspace(
                            "default",
                            "loopdy-chat-pending",
                            str(selected),
                        )
                    )
                    asyncio.run(
                        adapter._materialize_pending_link_session_workspace(
                            "default",
                            "loopdy-chat-pending",
                            source,
                        )
                    )

                context = SessionContext(
                    source=source,
                    connected_platforms=[Platform("loopdy")],
                    home_channels={},
                    session_key=session_key,
                    session_id=session_id,
                )
                with patch.dict(
                    os.environ,
                    {"TERMINAL_CWD": str(configured_home)},
                ):
                    tokens = runner._set_session_env(context)
                    try:
                        self.assertEqual(resolve_agent_cwd(), selected)
                        prompt = build_environment_hints()
                    finally:
                        runner._clear_session_env(tokens)
            finally:
                clear_task_env_overrides(session_key)
                clear_task_env_overrides(session_id)

            self.assertIn(f"Current working directory: {selected}", prompt)
            self.assertNotIn(
                f"Current working directory: {configured_home}",
                prompt,
            )

    def test_gateway_runtime_cwd_bridge_keeps_concurrent_loopdy_sessions_isolated(self) -> None:
        from agent.prompt_builder import build_environment_hints
        from tools.terminal_tool import (
            clear_task_env_overrides,
            register_task_env_overrides,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspaces = [root / "workspace-a", root / "workspace-b"]
            for workspace in workspaces:
                workspace.mkdir()
            session_keys = [
                "agent:main:loopdy:dm:loopdy-chat-a",
                "agent:main:loopdy:dm:loopdy-chat-b",
            ]

            adapter = LoopdyAdapter(
                PlatformConfig(enabled=True),
                service=_Service(),
                link_client=_LinkClient(),
            )
            store = SimpleNamespace(_db=SimpleNamespace())
            runner = SimpleNamespace(
                adapters={Platform("loopdy"): adapter},
                session_store=store,
                _profile_name_for_source=lambda _source: None,
            )
            runner._set_session_env = GatewayRunner._set_session_env.__get__(
                runner,
                GatewayRunner,
            )
            runner._clear_session_env = GatewayRunner._clear_session_env.__get__(
                runner,
                GatewayRunner,
            )
            adapter.gateway_runner = runner
            adapter.set_session_store(store)

            contexts = []
            for index, (session_key, workspace) in enumerate(
                zip(session_keys, workspaces)
            ):
                register_task_env_overrides(
                    session_key,
                    {"cwd": str(workspace), "cwd_source": "project"},
                )
                contexts.append(
                    SessionContext(
                        source=SessionSource(
                            platform=Platform("loopdy"),
                            chat_id=f"loopdy-chat-{index}",
                            profile="default",
                        ),
                        connected_platforms=[Platform("loopdy")],
                        home_channels={},
                        session_key=session_key,
                        session_id=f"canonical-session-{index}",
                    )
                )

            async def render(context):
                tokens = runner._set_session_env(context)
                try:
                    await asyncio.sleep(0)
                    return build_environment_hints()
                finally:
                    runner._clear_session_env(tokens)

            async def render_all():
                return await asyncio.gather(
                    *(render(context) for context in contexts)
                )

            try:
                prompts = asyncio.run(render_all())
            finally:
                for session_key in session_keys:
                    clear_task_env_overrides(session_key)

            for index, prompt in enumerate(prompts):
                self.assertIn(
                    f"Current working directory: {workspaces[index]}",
                    prompt,
                )
                self.assertNotIn(
                    f"Current working directory: {workspaces[1 - index]}",
                    prompt,
                )

    def test_native_link_media_callbacks_emit_resolvable_media_directives(self) -> None:
        link = _LinkClient()
        with tempfile.TemporaryDirectory() as directory:
            attachment_store = AttachmentStore(Path(directory) / "attachments.sqlite3")
            workspace_controller = WorkspaceController(
                backend=HermesWorkspaceBackend(
                    service=_Service(),
                    attachment_store=attachment_store,
                )
            )
            adapter = LoopdyAdapter(
                PlatformConfig(enabled=True),
                service=_Service(),
                link_client=link,
                workspace_controller=workspace_controller,
            )
            adapter._remember_verified_link_profile(
                "session_fixture_0001",
                "default",
            )
            image = Path(directory) / "render.png"
            image.write_bytes(b"\x89PNG\r\n\x1a\nfixture")
            result = asyncio.run(adapter.send_image_file(
                chat_id="session_fixture_0001",
                image_path=str(image),
                caption="Rendered image attached.",
            ))
            expected_path = image.resolve()
            image.unlink()

            self.assertTrue(result.success)
            self.assertEqual(len(link.payloads), 1)
            self.assertEqual(link.payloads[0]["type"], "assistant.message")
            self.assertEqual(
                link.payloads[0]["text"],
                f"Rendered image attached.\nMEDIA:{expected_path}",
            )
            resolved = attachment_store.resolve(
                profile="default",
                session_id="session_fixture_0001",
                items=[{
                    "id": link.payloads[0]["messageId"],
                    "text": link.payloads[0]["text"],
                }],
            )
            self.assertEqual(resolved[0]["attachments"][0]["name"], "render.png")

    def test_native_link_remote_images_are_cached_before_delivery(self) -> None:
        link = _LinkClient()
        with tempfile.TemporaryDirectory() as directory:
            attachment_store = AttachmentStore(Path(directory) / "attachments.sqlite3")
            workspace_controller = WorkspaceController(
                backend=HermesWorkspaceBackend(
                    service=_Service(),
                    attachment_store=attachment_store,
                )
            )
            adapter = LoopdyAdapter(
                PlatformConfig(enabled=True),
                service=_Service(),
                link_client=link,
                workspace_controller=workspace_controller,
            )
            adapter._remember_verified_link_profile(
                "session_fixture_0001",
                "default",
            )
            image = Path(directory) / "generated.png"
            image.write_bytes(b"\x89PNG\r\n\x1a\nfixture")

            with patch(
                "gateway.platforms.base.cache_image_from_url",
                new=AsyncMock(return_value=str(image)),
            ) as cache:
                result = asyncio.run(adapter.send_image(
                    chat_id="session_fixture_0001",
                    image_url="https://images.example.invalid/generated.png",
                    caption="Generated image attached.",
                ))

            self.assertTrue(result.success)
            cache.assert_awaited_once_with(
                "https://images.example.invalid/generated.png"
            )
            self.assertEqual(
                link.payloads[0]["text"],
                f"Generated image attached.\nMEDIA:{image.resolve()}",
            )

    def test_verified_link_form_submission_uses_the_host_owned_schema(self) -> None:
        import json
        from datetime import datetime, timezone

        from loopdy_plugin.generative_ui import render_v2_envelope
        from loopdy_plugin.link_client import InboundLinkGenerativeUIFormSubmission
        from loopdy_plugin.link_contracts import GenerativeUIFormSubmission
        from loopdy_plugin.store import LoopdyStore

        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "forms.sqlite3")
            payload = json.loads(
                (Path(__file__).resolve().parents[1] / "fixtures" / "generative_ui_v2" / "valid-form.json")
                .read_text(encoding="utf-8")
            )
            now = datetime.now(timezone.utc)
            card = render_v2_envelope(
                "loopdy_render_form",
                payload,
                now=now,
                profile="personal",
                session_id="session-coordinate-0001",
                request_id_factory=lambda: "a" * 32,
            )
            store.create_form_request(
                request_id="a" * 32,
                profile="personal",
                session_id="session-coordinate-0001",
                form_schema=card["data"],
                content_hash=card["content_hash"],
                created_at=int(now.timestamp()),
                expires_at=int(now.timestamp()) + 300,
            )
            service = _Service()
            service.store = store
            link = _LinkClient()
            adapter = LoopdyAdapter(
                PlatformConfig(enabled=True), service=service, link_client=link
            )
            request = GenerativeUIFormSubmission(
                request_id="a" * 32,
                session_id="session-coordinate-0001",
                profile="personal",
                idempotency_key="123e4567-e89b-42d3-a456-426614174000",
                values={"departure_day": "friday", "bags": 2},
                submitted_at=int(now.timestamp()) + 10,
            )

            asyncio.run(
                adapter.receive_link_payload(
                    InboundLinkGenerativeUIFormSubmission(
                        request=request,
                        sender_device_id="mobile-private-coordinate",
                    )
                )
            )

            self.assertEqual(link.payloads[0]["type"], "generative.ui.form.result")
            self.assertEqual(link.payloads[0]["state"], "success")
            self.assertEqual(link.payloads[0]["code"], "accepted")
            stored = store.get_form_request("a" * 32)
            self.assertEqual(stored["state"], "submitted")


if __name__ == "__main__":
    unittest.main()
