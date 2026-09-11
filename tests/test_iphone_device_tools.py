from __future__ import annotations

import asyncio
import json
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock


class DeviceToolContractTests(unittest.TestCase):
    def test_device_tool_round_trip_preserves_composite_hermes_turn_ids(self):
        from loopdy_plugin.link_contracts import device_tool_request, device_tool_result

        for turn_id in (
            "session-1:session:loopdy_link:phone-1:9e4a120b",
            "session-1:" + "t" * 493 + ":12345678",  # Native 512-byte boundary.
        ):
            with self.subTest(turn_id=turn_id):
                request = device_tool_request(
                    request_id="request-device-tool-turn", device_id="phone-1",
                    host_id="host-1", authorization_epoch=7, session_id="session-1",
                    agent_id="default", turn_id=turn_id, operation="health.read",
                    arguments={
                        "start": "2026-09-09T17:39:16.650462-05:00",
                        "end": "2026-09-10T17:39:16.650462-05:00",
                        "timeZone": "America/Chicago", "limit": 20,
                        "types": ["step_count", "heart_rate", "sleep_analysis"],
                    }, sent_at=100, expires_at=130,
                )
                response = device_tool_result(
                    request=request, status="completed", payload={"items": []}, sent_at=101,
                )
                self.assertEqual(request["turnId"], turn_id)
                self.assertEqual(response["turnId"], turn_id)

    def test_device_tool_turn_ids_remain_bounded_and_reject_invalid_coordinates(self):
        from loopdy_plugin.link_contracts import (
            device_tool_request, device_tool_result, parse_device_tool_request,
            parse_device_tool_result,
        )

        request = device_tool_request(
            request_id="request-device-tool-turn", device_id="phone-1",
            host_id="host-1", authorization_epoch=7, session_id="session-1",
            agent_id="default", turn_id="turn-1", operation="reminders.list",
            arguments={}, sent_at=100, expires_at=130,
        )
        response = device_tool_result(
            request=request, status="completed", payload={"items": []}, sent_at=101,
        )
        for turn_id in (None, True, 123, "", "t" * 513, "turn\n1", "turn\x001",
                        "turn\x7f1", "turn 1", "turn/1", "turn\u202e1"):
            with self.subTest(turn_id=turn_id):
                with self.assertRaises(ValueError):
                    parse_device_tool_request({**request, "turnId": turn_id})
                with self.assertRaises(ValueError):
                    parse_device_tool_result({**response, "turnId": turn_id})

    def test_device_tool_request_and_result_are_strict_and_correlated(self):
        from loopdy_plugin.link_contracts import (
            device_tool_request,
            device_tool_result,
            parse_device_tool_request,
            parse_device_tool_result,
        )

        request = device_tool_request(
            request_id="request-device-tool-0001",
            device_id="phone-1",
            host_id="host-1",
            authorization_epoch=3,
            session_id="session-1",
            agent_id="default",
            turn_id="turn-1",
            operation="calendar.create",
            arguments={
                "title": "Dentist",
                "start": "2026-09-11T15:00:00Z",
                "end": "2026-09-11T16:00:00Z",
                "timeZone": "America/Chicago",
                "span": "thisEvent",
            },
            sent_at=100,
            expires_at=130,
        )
        parsed = parse_device_tool_request(request)
        self.assertEqual(parsed["requestId"], "request-device-tool-0001")
        self.assertEqual(parsed["operation"], "calendar.create")
        self.assertEqual(parsed["expiresAt"], 130)

        result = device_tool_result(
            request=parsed,
            status="completed",
            payload={"id": "event-1", "revision": "rev-1"},
            sent_at=101,
        )
        parsed_result = parse_device_tool_result(result, sender_device_id="phone-1")
        self.assertEqual(parsed_result["hostId"], "host-1")
        self.assertEqual(parsed_result["payload"]["id"], "event-1")

        with self.assertRaises(ValueError):
            parse_device_tool_request({**request, "unexpected": True})

        recurring = device_tool_request(
            request_id="request-device-tool-0002",
            device_id="phone-1",
            host_id="host-1",
            authorization_epoch=3,
            session_id="session-1",
            agent_id="default",
            turn_id="turn-1",
            operation="calendar.update",
            arguments={
                "id": "event-1",
                "expectedRevision": "rev-1",
                "occurrenceStart": "2026-09-11T15:00:00Z",
                "span": "thisEvent",
            },
            sent_at=100,
            expires_at=130,
        )
        self.assertEqual(recurring["arguments"]["occurrenceStart"], "2026-09-11T15:00:00Z")
        reminders = device_tool_request(
            request_id="request-device-tool-0003",
            device_id="phone-1",
            host_id="host-1",
            authorization_epoch=3,
            session_id="session-1",
            agent_id="default",
            turn_id="turn-1",
            operation="reminders.list",
            arguments={"completed": False, "includeUndated": True},
            sent_at=100,
            expires_at=130,
        )
        self.assertTrue(reminders["arguments"]["includeUndated"])

    def test_device_tool_status_is_strict_and_bounded(self):
        from loopdy_plugin.link_contracts import device_tool_status, parse_device_tool_status

        status = device_tool_status(
            device_id="phone-1",
            host_id="host-1",
            authorization_epoch=3,
            enabled=["health", "calendar"],
            available=True,
            sent_at=100,
        )
        parsed = parse_device_tool_status(status, sender_device_id="phone-1")
        self.assertEqual(parsed["enabled"], ["health", "calendar"])
        with self.assertRaises(ValueError):
            parse_device_tool_status(
                {**status, "enabled": ["health"] * 33}, sender_device_id="phone-1"
            )

    def test_list_arguments_validate_health_catalog_ids_limits_and_ranges(self):
        from loopdy_plugin.link_contracts import device_tool_request

        base = {
            "start": "2026-09-01T00:00:00Z",
            "end": "2026-09-02T00:00:00Z",
            "timeZone": "America/Chicago",
            "limit": 200,
        }

        def request(operation, arguments):
            return device_tool_request(
                request_id=f"request-{operation.replace('.', '-')}-0001",
                device_id="phone-1",
                host_id="host-1",
                authorization_epoch=3,
                session_id="session-1",
                agent_id="default",
                turn_id="turn-1",
                operation=operation,
                arguments=arguments,
                sent_at=100,
                expires_at=130,
            )

        request("health.read", {**base, "types": ["step_count", "sleep_analysis"]})
        request("calendar.list", {**base, "calendarIDs": ["calendar-1"]})
        request("reminders.list", {"listIDs": ["list-1"], "limit": 1})

        with self.assertRaises(ValueError):
            request("health.read", {**base, "types": ["not-a-health-type"]})
        with self.assertRaises(ValueError):
            request("health.read", {**base, "limit": 201})
        with self.assertRaises(ValueError):
            request("calendar.list", {**base, "calendarIDs": []})
        with self.assertRaises(ValueError):
            request("calendar.list", {**base, "calendarIDs": ["calendar-1"] * 51})
        with self.assertRaises(ValueError):
            request("reminders.list", {"listIDs": ["list-1"], "limit": 0})

    def test_list_arguments_require_ordered_bounded_native_date_ranges(self):
        from loopdy_plugin.link_contracts import device_tool_request

        def request(operation, arguments):
            return device_tool_request(
                request_id=f"request-{operation.replace('.', '-')}-0002",
                device_id="phone-1",
                host_id="host-1",
                authorization_epoch=3,
                session_id="session-1",
                agent_id="default",
                turn_id="turn-1",
                operation=operation,
                arguments=arguments,
                sent_at=100,
                expires_at=130,
            )

        valid = {
            "start": "2026-09-01T00:00:00Z",
            "end": "2026-10-02T00:00:00Z",
            "timeZone": "America/Chicago",
        }
        request("health.read", valid)
        request("calendar.list", valid)
        request("reminders.list", {})

        for operation in ("health.read", "calendar.list"):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                request(operation, {**valid, "end": "2026-09-01T00:00:00Z"})
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                request(operation, {**valid, "end": "2026-10-03T00:00:00Z"})
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                request(operation, {"start": valid["start"], "timeZone": valid["timeZone"]})

        with self.assertRaises(ValueError):
            request("reminders.list", {"start": valid["start"], "timeZone": valid["timeZone"]})
        with self.assertRaises(ValueError):
            request("reminders.list", {**valid, "end": "2026-10-03T00:00:00Z"})

    def test_result_builder_rejects_timestamp_before_originating_request(self):
        from loopdy_plugin.link_contracts import device_tool_request, device_tool_result

        request = device_tool_request(
            request_id="request-device-tool-0004",
            device_id="phone-1",
            host_id="host-1",
            authorization_epoch=3,
            session_id="session-1",
            agent_id="default",
            turn_id="turn-1",
            operation="health.read",
            arguments={
                "start": "2026-09-01T00:00:00Z",
                "end": "2026-09-02T00:00:00Z",
                "timeZone": "UTC",
            },
            sent_at=100,
            expires_at=130,
        )
        with self.assertRaises(ValueError):
            device_tool_result(request=request, status="completed", payload={}, sent_at=99)
        self.assertEqual(
            device_tool_result(request=request, status="completed", payload={}, sent_at=100)["sentAt"],
            100,
        )

    def test_calendar_create_rejects_reversed_date_range(self):
        from loopdy_plugin.link_contracts import device_tool_request

        with self.assertRaises(ValueError):
            device_tool_request(
                request_id="request-device-tool-0005",
                device_id="phone-1",
                host_id="host-1",
                authorization_epoch=3,
                session_id="session-1",
                agent_id="default",
                turn_id="turn-1",
                operation="calendar.create",
                arguments={
                    "title": "Invalid",
                    "start": "2026-09-02T16:00:00Z",
                    "end": "2026-09-02T15:00:00Z",
                    "timeZone": "UTC",
                },
                sent_at=100,
                expires_at=130,
            )


class DeviceToolHandlerTests(unittest.TestCase):
    def test_registered_health_tool_uses_gateway_loop_for_real_link_delivery(self):
        from pathlib import Path
        from loopdy_plugin.device_tools import DeviceToolBridge, register
        from loopdy_plugin.link_client import LoopdyLinkClient
        from loopdy_plugin.link_contracts import device_tool_result, device_tool_status

        async def run(root):
            gateway_loop = asyncio.get_running_loop()
            client = LoopdyLinkClient(SimpleNamespace(
                device_id="host-1", authorization_epoch=3, account_key=b"k" * 32,
            ), attachment_root=Path(root))
            client._connected.set()
            client.peer_capabilities = frozenset({"directed-frames-v1"})
            bridge = DeviceToolBridge(clock=lambda: 100)
            bridge.bind_link_client(client)
            bridge.accept_status(device_tool_status(
                device_id="phone-1", host_id="host-1", authorization_epoch=7,
                enabled=["health"], available=True, sent_at=100,
            ), sender_device_id="phone-1", sender_epoch=7, target_device_id="host-1")
            registry = SimpleNamespace(tools={})
            registry.register_tool = lambda *, name, handler, **kwargs: registry.tools.update({name: handler})
            register(registry, bridge=bridge)
            sent = []
            errors = []
            original_send = client.send_payload

            async def observed_send(*args, **kwargs):
                try:
                    return await original_send(*args, **kwargs)
                except Exception as exc:
                    errors.append(f"{type(exc).__name__}: {exc}")
                    raise

            client.send_payload = observed_send

            class Socket:
                async def send(_self, encoded):
                    self.assertIs(asyncio.get_running_loop(), gateway_loop)
                    frame = json.loads(encoded)
                    request = client.cipher.open(frame["ciphertext"])
                    sent.append((frame, request))
                    self.assertIs(bridge._pending[request["requestId"]].future.get_loop(), gateway_loop)
                    client._accept_outbound({"id": frame["id"], "sequence": frame["sequence"]})
                    result = device_tool_result(
                        request=request, status="completed", payload={"items": []}, sent_at=101,
                    )
                    self.assertTrue(bridge.accept_result(result, sender_device_id="phone-1",
                        sender_epoch=7, target_device_id="host-1"))

            client._socket = Socket()
            # Real chat sends contend on this gateway-owned asyncio lock. Bind
            # it with an actual waiting acquisition, then leave one send ahead
            # of the phone tool. A tool-worker loop cannot acquire this lock.
            await client._send_lock.acquire()
            waiter = asyncio.create_task(client._send_lock.acquire())
            await asyncio.sleep(0)
            client._send_lock.release()
            await waiter
            release = gateway_loop.call_later(0.1, client._send_lock.release)
            try:
                # Hermes' async tool registry uses a separate worker loop.
                result = await asyncio.wait_for(asyncio.to_thread(lambda: json.loads(asyncio.run(
                    registry.tools["iphone_health"]({
                        "start": "2026-09-09T20:54:46.165731-05:00",
                        "end": "2026-09-10T20:54:46.165731-05:00",
                        "timeZone": "America/Chicago", "limit": 20,
                        "types": ["step_count", "heart_rate", "sleep_analysis"],
                    }, tool_execution_context=self._execution_context(), session_id="session-1",
                    turn_id="session-1:session:loopdy_link:phone-1:9e4a120b", tool_call_id="call-1")
                ))), timeout=3)
                self.assertEqual(result["status"], "completed", {"result": result, "transport_errors": errors})
                self.assertEqual(result["payload"], {"items": []})
                self.assertEqual(len(sent), 1)
                self.assertEqual(sent[0][0]["targetDeviceId"], "phone-1")
                self.assertEqual(sent[0][1]["operation"], "health.read")
                self.assertFalse(client._accepted)
                self.assertFalse(bridge._pending)
                self.assertFalse(bridge._outcomes)
            finally:
                release.cancel()
                if client._send_lock.locked():
                    client._send_lock.release()

        with tempfile.TemporaryDirectory() as root:
            asyncio.run(run(root), debug=True)

    def test_cross_loop_health_call_honors_disable_and_disconnect_while_waiting(self):
        from loopdy_plugin.device_tools import DeviceToolBridge, register
        from loopdy_plugin.link_contracts import device_tool_status

        async def run(disconnect):
            sent = asyncio.Event()

            class Client:
                connected = True
                peer_capabilities = {"directed-frames-v1"}
                config = SimpleNamespace(device_id="host-1")

                async def send_payload(self, request, **kwargs):
                    sent.set()

            bridge = DeviceToolBridge(Client(), clock=lambda: 100)
            status = device_tool_status(device_id="phone-1", host_id="host-1",
                authorization_epoch=7, enabled=["health"], available=True, sent_at=100)
            bridge.accept_status(status, sender_device_id="phone-1", sender_epoch=7, target_device_id="host-1")
            registry = SimpleNamespace(tools={})
            registry.register_tool = lambda *, name, handler, **kwargs: registry.tools.update({name: handler})
            register(registry, bridge=bridge)
            task = asyncio.create_task(asyncio.to_thread(lambda: json.loads(asyncio.run(
                registry.tools["iphone_health"]({
                    "start": "2026-09-09T00:00:00Z", "end": "2026-09-10T00:00:00Z", "timeZone": "UTC",
                }, tool_execution_context=self._execution_context(), session_id="session-1",
                turn_id="session-1:loopdy:turn", tool_call_id="call-1")
            ))))
            await asyncio.wait_for(sent.wait(), timeout=2)
            if disconnect:
                bridge.bind_link_client(None)
            else:
                self.assertTrue(bridge.accept_status({**status, "enabled": []},
                    sender_device_id="phone-1", sender_epoch=7, target_device_id="host-1"))
            result = await asyncio.wait_for(task, timeout=2)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["code"], "owner_changed" if disconnect else "authorization_required")
            self.assertEqual(result["payload"], {})
            self.assertFalse(bridge._pending)
            self.assertFalse(bridge._outcomes)

        for disconnect in (False, True):
            with self.subTest(disconnect=disconnect):
                asyncio.run(run(disconnect), debug=True)

    def test_closed_gateway_loop_fails_without_sending_on_tool_worker(self):
        from loopdy_plugin.device_tools import DeviceToolBridge

        client = SimpleNamespace(connected=True, send_payload=AsyncMock())

        async def bind():
            return DeviceToolBridge(client)

        bridge = asyncio.run(bind())
        result = asyncio.run(bridge.execute())
        self.assertEqual(result["code"], "unavailable")
        client.send_payload.assert_not_awaited()

    def test_registered_phone_tools_complete_with_canonical_hermes_turn_coordinates(self):
        from loopdy_plugin.device_tools import DeviceToolBridge, register
        from loopdy_plugin.link_contracts import device_tool_result, device_tool_status

        turn_id = "session-1:session:loopdy_link:phone-1:9e4a120b"
        queries = (
            ("iphone_health", "health.read", {
                "start": "2026-09-10T00:00:00-05:00",
                "end": "2026-09-10T17:39:16-05:00",
                "timeZone": "America/Chicago", "limit": 10, "types": ["step_count"],
            }),
            ("iphone_calendar", "calendar.list", {
                "operation": "list", "start": "2026-09-10T00:00:00-05:00",
                "end": "2026-09-10T17:39:16-05:00", "timeZone": "America/Chicago",
            }),
            ("iphone_reminders", "reminders.list", {"operation": "list"}),
        )
        for name, operation, arguments in queries:
            with self.subTest(tool=name):
                sent = []
                accepted = []
                bridge = None

                class Client:
                    connected = True
                    peer_capabilities = {"directed-frames-v1"}
                    config = SimpleNamespace(device_id="host-1")

                    async def send_payload(self, request, **kwargs):
                        sent.append((request, kwargs))
                        result = device_tool_result(
                            request=request, status="completed", payload={"items": []}, sent_at=101,
                        )
                        for candidate in ({**result, "turnId": turn_id + "-other"}, result):
                            accepted.append(bridge.accept_result(
                                candidate, sender_device_id="phone-1", sender_epoch=7,
                                target_device_id="host-1",
                            ))

                bridge = DeviceToolBridge(Client(), clock=lambda: 100)
                bridge.accept_status(device_tool_status(
                    device_id="phone-1", host_id="host-1", authorization_epoch=7,
                    enabled=["health", "calendar", "reminders"], available=True, sent_at=100,
                ), sender_device_id="phone-1", sender_epoch=7, target_device_id="host-1")
                registry = SimpleNamespace(tools={})
                registry.register_tool = lambda *, name, handler, **kwargs: registry.tools.update({name: handler})
                register(registry, bridge=bridge)
                result = json.loads(asyncio.run(registry.tools[name](
                    arguments, tool_execution_context=self._execution_context(),
                    session_id="session-1", turn_id=turn_id, tool_call_id="call-1",
                )))
                self.assertEqual(result["status"], "completed", result)
                self.assertEqual(result["payload"], {"items": []})
                self.assertEqual(result["turnId"], turn_id)
                self.assertEqual(accepted, [False, True])
                self.assertEqual(len(sent), 1)
                self.assertEqual(sent[0][0]["turnId"], turn_id)
                self.assertEqual(sent[0][0]["operation"], operation)
                self.assertEqual(sent[0][1]["target_device_id"], "phone-1")

    @staticmethod
    def _execution_context(*, source="loopdy_link", owner_id="phone-1", scope_id="finance", epoch=7, attributes=None):
        # Bridge inputs are structural; do not require an optional host module
        # just to exercise plugin-owned authorization and transport behavior.
        return SimpleNamespace(
            source=source,
            owner_id=owner_id,
            scope_id=scope_id,
            authorization_epoch=epoch,
            attributes={"host_id": "host-1"} if attributes is None else attributes,
        )

    def test_bridge_is_default_off_until_matching_phone_status(self):
        from loopdy_plugin.device_tools import DeviceToolBridge

        bridge = DeviceToolBridge()
        execution = self._execution_context()
        result = asyncio.run(bridge.execute(
            context=execution,
            device_id="phone-1", host_id="host-1", authorization_epoch=7,
            session_id="session-1", agent_id="finance", turn_id="turn-1",
            tool_call_id="call-1", operation="calendar.list", arguments={
                "start": "2026-09-10T00:00:00Z", "end": "2026-09-11T00:00:00Z", "timeZone": "UTC",
            },
        ))
        self.assertEqual(result["code"], "unavailable")

    def test_handlers_fail_closed_without_verified_context(self):
        from loopdy_plugin.device_tools import register

        context = SimpleNamespace(tools={}, schemas={})
        context.register_tool = lambda *, name, handler, schema, **kwargs: context.tools.update({name: handler}) or context.schemas.update({name: schema})
        register(context, bridge=None)
        with self.assertRaises(ValueError):
            asyncio.run(context.tools["iphone_health"]({
                    "start": "2026-09-10T00:00:00Z",
                    "end": "2026-09-11T00:00:00Z",
                    "timeZone": "UTC",
                }))

    def test_handler_uses_context_owner_and_official_coordinates(self):
        from loopdy_plugin.device_tools import DeviceToolBridge, register

        bridge = DeviceToolBridge()
        bridge.execute = AsyncMock(return_value={"status": "completed", "payload": {"items": []}})
        context = SimpleNamespace(tools={}, schemas={})
        context.register_tool = lambda *, name, handler, schema, **kwargs: context.tools.update({name: handler}) or context.schemas.update({name: schema})
        register(context, bridge=bridge)
        execution = self._execution_context()
        result = asyncio.run(
            context.tools["iphone_calendar"](
                {
                    "operation": "list",
                    "start": "2026-09-10T00:00:00Z",
                    "end": "2026-09-11T00:00:00Z",
                    "timeZone": "UTC",
                    "limit": 20,
                },
                tool_execution_context=execution,
                session_id="session-1",
                turn_id="turn-1",
                tool_call_id="call-1",
            )
        )
        self.assertEqual(json.loads(result)["status"], "completed")
        bridge.execute.assert_awaited_once()
        request = bridge.execute.await_args.kwargs
        self.assertEqual(request["device_id"], "phone-1")
        self.assertEqual(request["host_id"], "host-1")
        self.assertEqual(request["authorization_epoch"], 7)
        self.assertEqual(request["session_id"], "session-1")
        self.assertEqual(request["turn_id"], "turn-1")
        self.assertEqual(request["tool_call_id"], "call-1")
        self.assertEqual(request["operation"], "calendar.list")

    def test_context_attributes_are_exactly_authenticated_host_coordinate(self):
        from loopdy_plugin.device_tools import DeviceToolBridge, DeviceToolError

        context = self._execution_context(attributes={"host_id": "host-1", "untrusted": "value"})
        with self.assertRaises(DeviceToolError):
            DeviceToolBridge._assert_context(
                context,
                device_id="phone-1",
                host_id="host-1",
                authorization_epoch=7,
                session_id="session-1",
                agent_id="finance",
                turn_id="turn-1",
            )

    def test_handler_requires_ordinary_session_turn_and_tool_call_coordinates(self):
        from loopdy_plugin.device_tools import DeviceToolBridge, register

        bridge = DeviceToolBridge()
        bridge.execute = AsyncMock(return_value={"status": "completed", "payload": {}})
        context = SimpleNamespace(tools={}, schemas={})
        context.register_tool = lambda *, name, handler, schema, **kwargs: context.tools.update({name: handler}) or context.schemas.update({name: schema})
        register(context, bridge=bridge)
        execution = self._execution_context()
        payload = {
            "operation": "list",
            "start": "2026-09-10T00:00:00Z",
            "end": "2026-09-11T00:00:00Z",
            "timeZone": "UTC",
        }
        with self.assertRaises(ValueError):
            asyncio.run(context.tools["iphone_calendar"](
                payload,
                tool_execution_context=execution,
                task_id="must-not-be-used-as-turn-id",
                tool_call_id="call-1",
            ))
        with self.assertRaises(ValueError):
            asyncio.run(context.tools["iphone_calendar"](
                payload,
                tool_execution_context=execution,
                session_id="session-1",
                turn_id="turn-1",
            ))

    def test_context_requires_canonical_source_nonempty_ids_and_positive_integer_epoch(self):
        from loopdy_plugin.device_tools import DeviceToolBridge, DeviceToolError

        coordinates = dict(
            device_id="phone-1",
            host_id="host-1",
            authorization_epoch=7,
            session_id="session-1",
            agent_id="finance",
            turn_id="turn-1",
        )
        for kwargs in (
            {"source": "proxy"},
            {"owner_id": ""},
            {"scope_id": ""},
            {"epoch": 0},
            {"epoch": "7"},
        ):
            context = SimpleNamespace(
                source=kwargs.get("source", "loopdy_link"),
                owner_id=kwargs.get("owner_id", "phone-1"),
                scope_id=kwargs.get("scope_id", "finance"),
                authorization_epoch=kwargs.get("epoch", 7),
                attributes={"host_id": "host-1"},
            )
            with self.subTest(kwargs=kwargs), self.assertRaises(DeviceToolError):
                DeviceToolBridge._assert_context(context, **coordinates)

    def test_status_epoch_must_match_the_verified_sender_frame_epoch(self):
        from loopdy_plugin.device_tools import DeviceToolBridge
        from loopdy_plugin.link_contracts import device_tool_status

        bridge = DeviceToolBridge(
            link_client=SimpleNamespace(
                config=SimpleNamespace(device_id="host-1", authorization_epoch=8),
            ),
            clock=lambda: 100,
        )
        stale = device_tool_status(
            device_id="phone-1",
            host_id="host-1",
            authorization_epoch=7,
            enabled=["calendar"],
            available=True,
            sent_at=100,
        )
        self.assertTrue(
            bridge.accept_status(
                stale,
                sender_device_id="phone-1",
                sender_epoch=7,
                target_device_id="host-1",
            )
        )
        self.assertFalse(
            bridge.accept_status(
                stale,
                sender_device_id="phone-1",
                sender_epoch=8,
                target_device_id="host-1",
            )
        )

    def test_same_second_status_transition_is_not_dropped(self):
        from loopdy_plugin.device_tools import DeviceToolBridge
        from loopdy_plugin.link_contracts import device_tool_status

        bridge = DeviceToolBridge(
            link_client=SimpleNamespace(config=SimpleNamespace(device_id="host-1")),
            clock=lambda: 100,
        )
        disabled = device_tool_status(
            device_id="phone-1", host_id="host-1", authorization_epoch=7,
            enabled=[], available=False, sent_at=100,
        )
        enabled = device_tool_status(
            device_id="phone-1", host_id="host-1", authorization_epoch=7,
            enabled=["calendar"], available=True, sent_at=100,
        )
        self.assertTrue(bridge.accept_status(
            disabled, sender_device_id="phone-1", sender_epoch=7, target_device_id="host-1",
        ))
        self.assertTrue(bridge.accept_status(
            enabled, sender_device_id="phone-1", sender_epoch=7, target_device_id="host-1",
        ))
        self.assertFalse(bridge.accept_status(
            enabled, sender_device_id="phone-1", sender_epoch=7, target_device_id="host-1",
        ))

    def test_same_second_disable_cancels_pending_request(self):
        from loopdy_plugin.device_tools import DeviceToolBridge
        from loopdy_plugin.link_contracts import device_tool_status

        class Client:
            connected = True
            peer_capabilities = {"directed-frames-v1"}
            config = SimpleNamespace(device_id="host-1")

            async def send_payload(self, _request, **_kwargs):
                await asyncio.sleep(0)

        bridge = DeviceToolBridge(Client(), clock=lambda: 100)
        enabled = device_tool_status(
            device_id="phone-1", host_id="host-1", authorization_epoch=7,
            enabled=["calendar"], available=True, sent_at=100,
        )
        disabled = device_tool_status(
            device_id="phone-1", host_id="host-1", authorization_epoch=7,
            enabled=[], available=False, sent_at=100,
        )
        self.assertTrue(bridge.accept_status(
            enabled, sender_device_id="phone-1", sender_epoch=7, target_device_id="host-1",
        ))
        context = SimpleNamespace(
            source="loopdy_link", owner_id="phone-1", scope_id="default",
            authorization_epoch=7, attributes={"host_id": "host-1"},
        )

        async def run():
            task = asyncio.create_task(bridge.execute(
                context=context, device_id="phone-1", host_id="host-1", authorization_epoch=7,
                session_id="session-1", agent_id="default", turn_id="turn-1", tool_call_id="call-disable",
                operation="calendar.create", arguments={
                    "title": "Dentist", "start": "2026-09-11T15:00:00Z",
                    "end": "2026-09-11T16:00:00Z", "timeZone": "UTC",
                },
            ))
            while not bridge._pending:
                await asyncio.sleep(0)
            self.assertTrue(bridge.accept_status(
                disabled, sender_device_id="phone-1", sender_epoch=7, target_device_id="host-1",
            ))
            return await task

        result = asyncio.run(run())
        self.assertEqual(result["code"], "authorization_required")


class DirectedLinkTests(unittest.TestCase):
    def test_encrypted_frame_preserves_optional_directed_target(self):
        from loopdy_plugin.link_contracts import EncryptedFrame, parse_encrypted_frame

        frame = EncryptedFrame(
            frame_id="frame-directed-0001",
            sender_device_id="host-1",
            sender_epoch=3,
            sequence=1,
            ack=0,
            ciphertext="ciphertext-000000",
            target_device_id="phone-1",
        )
        parsed = parse_encrypted_frame(json.dumps(frame.wire_value()))
        self.assertEqual(parsed.target_device_id, "phone-1")

    def test_targeted_payload_requires_negotiated_directed_frames(self):
        from loopdy_plugin.link_client import LoopdyLinkClient

        client = object.__new__(LoopdyLinkClient)
        client._connected = asyncio.Event()
        client._connected.set()
        client._authentication_failed = False
        client._send_lock = asyncio.Lock()
        client._transport_lock = AsyncMock()
        client._transport_lock.__aenter__ = AsyncMock(return_value=client._transport_lock)
        client._transport_lock.__aexit__ = AsyncMock(return_value=None)
        client._transport_get = lambda name, default=None: default
        client._transport_set = lambda name, value: None
        client._wait_for_prior_pending = AsyncMock()
        client._send_wire = AsyncMock()
        client._delivery_timeout = 1
        client.config = SimpleNamespace(device_id="host-1", authorization_epoch=3)
        client.cipher = SimpleNamespace(seal=lambda payload: "ciphertext-000000")
        client._accepted = {}
        client._backpressured_frame_id = None
        client._mark_failed_outbound_and_reconnect = AsyncMock()
        client.peer_capabilities = frozenset()
        with self.assertRaises(ConnectionError):
            asyncio.run(client.send_payload({"type": "device.tool.request"}, target_device_id="phone-1"))

    def test_status_uses_frame_coordinates_and_replacement_invalidates_cache(self):
        from loopdy_plugin.device_tools import DeviceToolBridge
        from loopdy_plugin.link_contracts import device_tool_status

        client = SimpleNamespace(
            config=SimpleNamespace(device_id="host-1"),
            connected=True,
            peer_capabilities={"directed-frames-v1"},
        )
        bridge = DeviceToolBridge(client, clock=lambda: 100)
        status = device_tool_status(
            device_id="phone-1", host_id="host-1", authorization_epoch=7,
            enabled=["calendar"], available=True, sent_at=100,
        )
        self.assertTrue(bridge.accept_status(
            status, sender_device_id="phone-1", sender_epoch=7, target_device_id="host-1",
        ))
        self.assertFalse(bridge.accept_status(
            status, sender_device_id="phone-1", sender_epoch=8, target_device_id="host-1",
        ))
        self.assertFalse(bridge.accept_status(
            status, sender_device_id="phone-1", sender_epoch=7, target_device_id="other-host",
        ))
        bridge.bind_link_client(SimpleNamespace(config=SimpleNamespace(device_id="host-2")))
        self.assertFalse(bridge._status)

    def test_call_identity_deduplicates_and_changed_arguments_conflict(self):
        from loopdy_plugin.device_tools import DeviceToolBridge
        from loopdy_plugin.link_contracts import device_tool_result, device_tool_status

        sent = []
        bridge = None

        class Client:
            connected = True
            peer_capabilities = {"directed-frames-v1"}
            config = SimpleNamespace(device_id="host-1")

            async def send_payload(self, request, **_kwargs):
                sent.append(request)
                result = device_tool_result(
                    request=request, status="completed", payload={"id": "event-1"}, sent_at=101,
                )
                bridge.accept_result(
                    result,
                    sender_device_id="phone-1",
                    sender_epoch=7,
                    target_device_id="host-1",
                )

        bridge = DeviceToolBridge(Client(), clock=lambda: 100)
        status = device_tool_status(
            device_id="phone-1", host_id="host-1", authorization_epoch=7,
            enabled=["calendar"], available=True, sent_at=100,
        )
        self.assertTrue(bridge.accept_status(
            status, sender_device_id="phone-1", sender_epoch=7, target_device_id="host-1",
        ))
        context = SimpleNamespace(
            source="loopdy_link", owner_id="phone-1", scope_id="default",
            authorization_epoch=7, attributes={"host_id": "host-1"},
        )

        async def run():
            first = await bridge.execute(
                context=context, device_id="phone-1", host_id="host-1", authorization_epoch=7,
                session_id="session-1", agent_id="default", turn_id="turn-1", tool_call_id="call-1",
                operation="calendar.create", arguments={
                    "title": "Dentist", "start": "2026-09-11T15:00:00Z",
                    "end": "2026-09-11T16:00:00Z", "timeZone": "UTC",
                },
            )
            replay = await bridge.execute(
                context=context, device_id="phone-1", host_id="host-1", authorization_epoch=7,
                session_id="session-1", agent_id="default", turn_id="turn-1", tool_call_id="call-1",
                operation="calendar.create", arguments={
                    "title": "Dentist", "start": "2026-09-11T15:00:00Z",
                    "end": "2026-09-11T16:00:00Z", "timeZone": "UTC",
                },
            )
            conflict = await bridge.execute(
                context=context, device_id="phone-1", host_id="host-1", authorization_epoch=7,
                session_id="session-1", agent_id="default", turn_id="turn-1", tool_call_id="call-1",
                operation="calendar.create", arguments={
                    "title": "Different", "start": "2026-09-11T15:00:00Z",
                    "end": "2026-09-11T16:00:00Z", "timeZone": "UTC",
                },
            )
            return first, replay, conflict

        first, replay, conflict = asyncio.run(run())
        self.assertEqual(first["status"], "completed")
        self.assertEqual(replay, first)
        self.assertEqual(conflict["code"], "request_conflict")
        self.assertEqual(len(sent), 1)

    def test_mutation_outcomes_and_request_identity_are_bound_to_host(self):
        from loopdy_plugin.device_tools import DeviceToolBridge
        from loopdy_plugin.link_contracts import device_tool_result, device_tool_status

        bridge = None
        sent = []

        class Client:
            connected = True
            peer_capabilities = {"directed-frames-v1"}

            def __init__(self, host_id, result_id):
                self.config = SimpleNamespace(device_id=host_id)
                self.result_id = result_id

            async def send_payload(self, request, **_kwargs):
                sent.append(request)
                bridge.accept_result(
                    device_tool_result(
                        request=request,
                        status="completed",
                        payload={"id": self.result_id},
                        sent_at=101,
                    ),
                    sender_device_id="phone-1",
                    sender_epoch=7,
                    target_device_id=self.config.device_id,
                )

        client_one = Client("host-1", "event-host-1")
        bridge = DeviceToolBridge(client_one, clock=lambda: 100)
        for host_id in ("host-1",):
            status = device_tool_status(
                device_id="phone-1",
                host_id=host_id,
                authorization_epoch=7,
                enabled=["calendar"],
                available=True,
                sent_at=100,
            )
            self.assertTrue(
                bridge.accept_status(
                    status,
                    sender_device_id="phone-1",
                    sender_epoch=7,
                    target_device_id=host_id,
                )
            )
        context_one = SimpleNamespace(
            source="loopdy_link",
            owner_id="phone-1",
            scope_id="default",
            authorization_epoch=7,
            attributes={"host_id": "host-1"},
        )
        arguments = {
            "title": "Dentist",
            "start": "2026-09-11T15:00:00Z",
            "end": "2026-09-11T16:00:00Z",
            "timeZone": "UTC",
        }
        first = asyncio.run(
            bridge.execute(
                context=context_one,
                device_id="phone-1",
                host_id="host-1",
                authorization_epoch=7,
                session_id="session-1",
                agent_id="default",
                turn_id="turn-1",
                tool_call_id="call-1",
                operation="calendar.create",
                arguments=arguments,
            )
        )
        self.assertEqual(first["payload"]["id"], "event-host-1")

        client_two = Client("host-2", "event-host-2")
        bridge.bind_link_client(client_two)
        status = device_tool_status(
            device_id="phone-1",
            host_id="host-2",
            authorization_epoch=7,
            enabled=["calendar"],
            available=True,
            sent_at=100,
        )
        self.assertTrue(
            bridge.accept_status(
                status,
                sender_device_id="phone-1",
                sender_epoch=7,
                target_device_id="host-2",
            )
        )
        context_two = SimpleNamespace(
            source="loopdy_link",
            owner_id="phone-1",
            scope_id="default",
            authorization_epoch=7,
            attributes={"host_id": "host-2"},
        )
        second = asyncio.run(
            bridge.execute(
                context=context_two,
                device_id="phone-1",
                host_id="host-2",
                authorization_epoch=7,
                session_id="session-1",
                agent_id="default",
                turn_id="turn-1",
                tool_call_id="call-1",
                operation="calendar.create",
                arguments=arguments,
            )
        )
        self.assertEqual(second["payload"]["id"], "event-host-2")
        self.assertEqual(len(sent), 2)
        self.assertNotEqual(sent[0]["requestId"], sent[1]["requestId"])

    def test_completed_read_payload_is_not_retained(self):
        from loopdy_plugin.device_tools import DeviceToolBridge
        from loopdy_plugin.link_contracts import device_tool_result, device_tool_status

        bridge = None

        class Client:
            connected = True
            peer_capabilities = {"directed-frames-v1"}
            config = SimpleNamespace(device_id="host-1")

            async def send_payload(self, request, **_kwargs):
                bridge.accept_result(
                    device_tool_result(
                        request=request,
                        status="completed",
                        payload={"sensitive": "private-health-value"},
                        sent_at=101,
                    ),
                    sender_device_id="phone-1",
                    sender_epoch=7,
                    target_device_id="host-1",
                )

        bridge = DeviceToolBridge(Client(), clock=lambda: 100)
        status = device_tool_status(
            device_id="phone-1", host_id="host-1", authorization_epoch=7,
            enabled=["health"], available=True, sent_at=100,
        )
        self.assertTrue(bridge.accept_status(
            status, sender_device_id="phone-1", sender_epoch=7, target_device_id="host-1",
        ))
        context = SimpleNamespace(
            source="loopdy_link", owner_id="phone-1", scope_id="default",
            authorization_epoch=7, attributes={"host_id": "host-1"},
        )
        result = asyncio.run(bridge.execute(
            context=context, device_id="phone-1", host_id="host-1", authorization_epoch=7,
            session_id="session-1", agent_id="default", turn_id="turn-1", tool_call_id="call-read",
            operation="health.read", arguments={
                "start": "2026-09-10T00:00:00Z", "end": "2026-09-11T00:00:00Z", "timeZone": "UTC",
            },
        ))
        self.assertEqual(result["payload"]["sensitive"], "private-health-value")
        self.assertFalse(bridge._outcomes)

    def test_accept_result_rejects_timestamp_before_originating_request(self):
        from loopdy_plugin.device_tools import DeviceToolBridge, _Pending
        from loopdy_plugin.link_contracts import device_tool_request, device_tool_result

        client = SimpleNamespace(config=SimpleNamespace(device_id="host-1"))
        bridge = DeviceToolBridge(client, clock=lambda: 100)
        request = device_tool_request(
            request_id="request-device-tool-0006",
            device_id="phone-1",
            host_id="host-1",
            authorization_epoch=3,
            session_id="session-1",
            agent_id="default",
            turn_id="turn-1",
            operation="health.read",
            arguments={
                "start": "2026-09-01T00:00:00Z",
                "end": "2026-09-02T00:00:00Z",
                "timeZone": "UTC",
            },
            sent_at=100,
            expires_at=130,
        )
        result = device_tool_result(
            request=request, status="completed", payload={}, sent_at=100,
        )
        result["sentAt"] = 99

        async def run():
            future = asyncio.get_running_loop().create_future()
            bridge._pending[request["requestId"]] = _Pending(
                request=request,
                context_key=(),
                fingerprint="fingerprint",
                future=future,
            )
            accepted = bridge.accept_result(
                result,
                sender_device_id="phone-1",
                sender_epoch=3,
                target_device_id="host-1",
            )
            return accepted, future.done()

        self.assertEqual(asyncio.run(run()), (False, False))
