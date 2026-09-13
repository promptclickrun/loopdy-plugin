"""Focused tests for the native iPhone device-tool channel."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import sys
import threading
import unittest
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from starlette.datastructures import Headers, QueryParams

from loopdy_plugin.link_contracts import device_tool_result
from loopdy_plugin.native_context import NativeContext
from loopdy_plugin.native_device_tools import (
    NativeDeviceToolError,
    NativeDeviceToolHub,
    _Scope,
    _Connect,
    _live_profile_matches,
    available,
    register_middleware,
)


@dataclass(frozen=True)
class Owner:
    provider: str = "test"
    user_id: str = "user-1"
    serving_profile_id: str = "default"
    runtime_id: str = "runtime-1"


class Clock:
    def __init__(self, value: float = 1_700_000_000) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def channel_fields(*, channel_id: str | None = None, device_id: str | None = None,
                   session_id: str = "stored-session") -> dict:
    return {
        "channelId": channel_id or str(uuid.uuid4()),
        "deviceId": device_id or str(uuid.uuid4()),
        "hostId": "local-host",
        "authorizationEpoch": 1,
        "agentId": "default",
        "sessionId": session_id,
        "enabled": ["calendar", "reminders", "health"],
    }


class NativeDeviceToolHubTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.owner = Owner()
        self.hub = NativeDeviceToolHub(
            clock=self.clock,
            profile_session_validator=lambda profile, session: profile == "default" and session in {
                "stored-session", "runtime-session"
            },
        )

    async def test_connect_poll_result_and_close_are_owner_bound(self) -> None:
        fields = channel_fields()
        self.assertEqual(
            self.hub.connect(self.owner, fields),
            {"channelId": fields["channelId"], "connected": True},
        )
        task = asyncio.create_task(self.hub.execute(
            profile="default", session_id="stored-session", turn_id="turn-1",
            tool_call_id="call-1", operation="calendar.list", arguments={
                "start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z", "timeZone": "UTC",
            },
        ))
        await asyncio.sleep(0)
        feed = self.hub.poll(self.owner, fields, after=0)
        self.assertEqual(feed["next"], 1)
        request = feed["requests"][0]["request"]
        self.assertEqual(request["operation"], "calendar.list")
        self.assertEqual(request["sessionId"], "stored-session")
        self.assertEqual(request["turnId"], "turn-1")
        result = device_tool_result(
            request=request, status="completed", payload={"items": []},
            sent_at=self.clock.value,
        )
        self.assertEqual(self.hub.accept_result(self.owner, fields, result), {"accepted": True})
        self.assertEqual((await task)["payload"], {"items": []})
        with self.assertRaises(NativeDeviceToolError) as replay:
            self.hub.accept_result(self.owner, fields, result)
        self.assertEqual(replay.exception.code, "result_replay")
        self.assertEqual(self.hub.close(self.owner, fields), {"closed": True})

    async def test_forged_coordinates_do_not_complete_pending_request(self) -> None:
        fields = channel_fields()
        self.hub.connect(self.owner, fields)
        task = asyncio.create_task(self.hub.execute(
            profile="default", session_id="stored-session", turn_id="turn-2",
            tool_call_id="call-2", operation="reminders.list", arguments={},
        ))
        await asyncio.sleep(0)
        request = self.hub.poll(self.owner, fields, after=0)["requests"][0]["request"]
        forged = device_tool_result(
            request=request, status="completed", payload={"items": []}, sent_at=self.clock.value,
        )
        forged["turnId"] = "other-turn"
        with self.assertRaises(NativeDeviceToolError) as error:
            self.hub.accept_result(self.owner, fields, forged)
        self.assertEqual(error.exception.code, "result_coordinates_mismatch")
        self.assertFalse(task.done())
        self.hub.close(self.owner, fields)
        self.assertEqual((await task)["code"], "phone_unavailable")

    async def test_disabled_scope_and_expiry_are_truthful(self) -> None:
        fields = channel_fields()
        fields["enabled"] = ["calendar"]
        self.hub.connect(self.owner, fields)
        denied = await self.hub.execute(
            profile="default", session_id="stored-session", turn_id="turn-3",
            tool_call_id="call-3", operation="health.read", arguments={"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z", "timeZone": "UTC"},
        )
        self.assertEqual(denied["code"], "authorization_required")
        self.clock.advance(31)
        expired = await self.hub.execute(
            profile="default", session_id="stored-session", turn_id="turn-4",
            tool_call_id="call-4", operation="calendar.list", arguments={
                "start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z", "timeZone": "UTC",
            },
        )
        self.assertEqual(expired["code"], "phone_unavailable")

    async def test_connect_allows_zero_optional_grants(self) -> None:
        fields = channel_fields()
        fields["enabled"] = []
        self.assertEqual(_Connect(**fields).enabled, [])
        self.assertEqual(
            self.hub.connect(self.owner, fields),
            {"channelId": fields["channelId"], "connected": True},
        )
        denied = await self.hub.execute(
            profile="default", session_id="stored-session", turn_id="turn-no-grants",
            tool_call_id="call-no-grants", operation="calendar.list", arguments={
                "start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z", "timeZone": "UTC",
            },
        )
        self.assertEqual(denied["code"], "authorization_required")

    async def test_duplicate_call_identity_coalesces_and_conflicting_args_do_not_queue(self) -> None:
        fields = channel_fields()
        self.hub.connect(self.owner, fields)
        arguments = {
            "start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z", "timeZone": "UTC",
        }
        first = asyncio.create_task(self.hub.execute(
            profile="default", session_id="stored-session", turn_id="turn-5",
            tool_call_id="call-5", operation="calendar.list", arguments=arguments,
        ))
        await asyncio.sleep(0)
        conflicting = await self.hub.execute(
            profile="default", session_id="stored-session", turn_id="turn-5",
            tool_call_id="call-5", operation="calendar.list", arguments={**arguments, "limit": 2},
        )
        self.assertEqual(conflicting["code"], "request_conflict")
        self.assertEqual(self.hub.poll(self.owner, fields, after=0)["next"], 1)
        request = self.hub.poll(self.owner, fields, after=0)["requests"][0]["request"]
        self.hub.accept_result(self.owner, fields, device_tool_result(
            request=request, status="completed", payload={"items": []}, sent_at=self.clock.value,
        ))
        self.assertEqual((await first)["status"], "completed")

    async def test_completed_request_tombstones_retain_the_newest_call(self) -> None:
        fields = channel_fields()
        self.hub.connect(self.owner, fields)
        request_ids: list[str] = []
        for index in range(300):
            task = asyncio.create_task(self.hub.execute(
                profile="default", session_id="stored-session", turn_id=f"turn-{index}",
                tool_call_id=f"call-{index}", operation="reminders.list", arguments={},
            ))
            await asyncio.sleep(0)
            request = next(iter(self.hub.channels[fields["channelId"]].pending.values())).request
            request_ids.append(request["requestId"])
            self.hub.accept_result(self.owner, fields, device_tool_result(
                request=request, status="completed", payload={"items": []}, sent_at=self.clock.value,
            ))
            self.assertEqual((await task)["status"], "completed")
        self.assertTrue(set(request_ids[-256:]).issubset(
            self.hub.channels[fields["channelId"]].completed
        ))

    def test_multiple_phones_for_one_session_are_ambiguous(self) -> None:
        first = channel_fields()
        second = channel_fields()
        second["sessionId"] = first["sessionId"]
        self.hub.connect(self.owner, first)
        with self.assertRaises(NativeDeviceToolError) as error:
            self.hub.connect(self.owner, second)
        self.assertEqual(error.exception.code, "channel_ambiguous")

    def test_channel_owner_is_fenced_for_poll_result_and_close(self) -> None:
        fields = channel_fields()
        self.hub.connect(self.owner, fields)
        other = Owner(user_id="other-user")
        for operation in (
            lambda: self.hub.poll(other, {"channelId": fields["channelId"], "after": 0}),
            lambda: self.hub.close(other, {"channelId": fields["channelId"]}),
        ):
            with self.subTest(operation=operation):
                with self.assertRaises(NativeDeviceToolError) as error:
                    operation()
                self.assertEqual(error.exception.code, "channel_owner_changed")

    async def test_close_from_thread_without_running_loop_releases_waiter(self) -> None:
        fields = channel_fields()
        self.hub.connect(self.owner, fields)
        task = asyncio.create_task(self.hub.execute(
            profile="default", session_id="stored-session", turn_id="turn-thread",
            tool_call_id="call-thread", operation="reminders.list", arguments={},
        ))
        await asyncio.sleep(0)

        closer = threading.Thread(target=lambda: self.hub.close(self.owner, fields))
        closer.start()
        closer.join()
        self.assertFalse(task.cancelled())
        self.assertEqual((await task)["code"], "phone_unavailable")

    def test_expired_channels_are_purged_before_capacity_and_without_mutating_iteration(self) -> None:
        clock = Clock()
        hub = NativeDeviceToolHub(clock=clock, profile_session_validator=lambda _profile, _session: True)
        for index in range(64):
            hub.connect(self.owner, channel_fields(session_id=f"session-{index}"))
        self.assertEqual(len(hub.channels), 64)
        clock.advance(31)
        replacement = channel_fields(session_id="replacement-session")
        self.assertEqual(hub.connect(self.owner, replacement), {
            "channelId": replacement["channelId"], "connected": True,
        })
        self.assertEqual(len(hub.channels), 1)

    def test_live_profile_matching_requires_the_requested_profile(self) -> None:
        with patch("hermes_constants.get_process_hermes_home", return_value=Path("/profiles/default")), \
             patch("hermes_constants.profile_name_for_home", side_effect=lambda home: {
                 Path("/profiles/default"): "default",
                 Path("/profiles/other"): "other",
             }[home]):
            self.assertTrue(_live_profile_matches({}, "default"))
            self.assertFalse(_live_profile_matches({"profile_home": "/profiles/other"}, "default"))

    def test_runtime_and_stored_ids_use_hermes_live_session_map(self) -> None:
        from loopdy_plugin import native_device_tools

        with patch.object(native_device_tools, "_live_sessions_snapshot", return_value={
            "runtime-session": {"session_key": "stored-session"},
        }):
            self.assertTrue(native_device_tools._same_live_session("runtime-session", "stored-session"))
            self.assertFalse(native_device_tools._same_live_session("runtime-session", "other-session"))

    def test_connect_scope_identifiers_are_full_matches(self) -> None:
        valid = channel_fields()
        _Scope(channelId=valid["channelId"])
        for suffix in ("x", "\n"):
            with self.assertRaises(ValueError):
                _Scope(channelId=valid["channelId"] + suffix)


class MiddlewareTests(unittest.IsolatedAsyncioTestCase):
    def test_registration_requires_official_middleware_and_tracks_lifecycle(self) -> None:
        callbacks = []
        unload = []

        class Context:
            profile_name = "default"

            def register_middleware(self, kind, callback):
                callbacks.append((kind, callback))

            def on_unload(self, callback):
                unload.append(callback)

        self.assertTrue(register_middleware(Context(), hub=NativeDeviceToolHub(
            profile_session_validator=lambda profile, session: True,
        )))
        self.assertTrue(available())
        unload[0]()
        self.assertFalse(available())
        self.assertEqual(callbacks[0][0], "tool_execution")

    def test_registration_unload_retires_native_channels(self) -> None:
        callbacks = []
        unload = []

        class Context:
            profile_name = "default"

            def register_middleware(self, kind, callback):
                callbacks.append((kind, callback))

            def on_unload(self, callback):
                unload.append(callback)

        hub = NativeDeviceToolHub(profile_session_validator=lambda _profile, _session: True)
        fields = channel_fields()
        owner = Owner()
        hub.connect(owner, fields)
        self.assertTrue(register_middleware(Context(), hub=hub))
        unload[0]()
        self.assertFalse(available())
        with self.assertRaises(NativeDeviceToolError) as error:
            hub.poll(owner, {"channelId": fields["channelId"], "after": 0})
        self.assertEqual(error.exception.code, "phone_unavailable")

    async def test_middleware_uses_official_ids_and_does_not_accept_model_identity(self) -> None:
        clock = Clock()
        hub = NativeDeviceToolHub(
            clock=clock, profile_session_validator=lambda profile, session: True,
        )
        owner = Owner()
        fields = channel_fields()
        hub.connect(owner, fields)
        callbacks: list = []

        class Context:
            profile_name = "default"

            def register_middleware(self, kind, callback):
                callbacks.append((kind, callback))

        self.assertTrue(register_middleware(Context(), hub=hub))
        self.assertEqual(callbacks[0][0], "tool_execution")
        callback = callbacks[0][1]
        with patch.dict(sys.modules, {
            "model_tools": SimpleNamespace(_run_async=lambda coroutine: asyncio.run(coroutine)),
        }):
            task = asyncio.create_task(asyncio.to_thread(callback,
                tool_name="iphone_calendar",
                args={"operation": "list", "sessionId": "forged", "deviceId": "forged",
                      "start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z", "timeZone": "UTC"},
                original_args={},
                session_id="stored-session",
                turn_id="official-turn",
                tool_call_id="official-call",
                next_call=lambda: self.fail("native channel must terminate the chain"),
            ))
            await asyncio.sleep(0)
            request = hub.poll(owner, fields, after=0)["requests"][0]["request"]
            self.assertEqual(request["sessionId"], "stored-session")
            self.assertEqual(request["turnId"], "official-turn")
            self.assertEqual(request["operation"], "calendar.list")
            result = device_tool_result(request=request, status="completed", payload={"items": []}, sent_at=clock.value)
            hub.accept_result(owner, fields, result)
            self.assertEqual(json.loads(await task)["payload"], {"items": []})

    async def test_middleware_falls_through_to_legacy_link_only_without_native_lease(self) -> None:
        callbacks: list = []

        class Context:
            profile_name = "default"

            def register_middleware(self, kind, callback):
                callbacks.append((kind, callback))

        hub = NativeDeviceToolHub(profile_session_validator=lambda _profile, _session: True)
        self.assertTrue(register_middleware(Context(), hub=hub, fallback_to_link=True))
        captured: list = []

        def downstream(payload=None):
            effective = {"operation": "list"} if payload is None else payload
            captured.append(effective)
            return {"legacy": effective}
        result = callbacks[0][1](
            tool_name="iphone_calendar",
            args={"operation": "list"},
            original_args={"operation": "list"},
            session_id="no-native-lease",
            turn_id="turn-legacy",
            tool_call_id="call-legacy",
            next_call=downstream,
        )
        self.assertEqual(result, {"legacy": {"operation": "list"}})
        self.assertEqual(captured, [{"operation": "list"}])

    async def test_coalesced_waiter_cancellation_does_not_cancel_shared_request(self) -> None:
        clock = Clock()
        hub = NativeDeviceToolHub(
            clock=clock,
            profile_session_validator=lambda profile, session: profile == "default" and session == "stored-session",
        )
        owner = Owner()
        fields = channel_fields()
        hub.connect(owner, fields)
        kwargs = dict(
            profile="default", session_id="stored-session", turn_id="turn-shared",
            tool_call_id="call-shared", operation="calendar.list", arguments={
                "start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z", "timeZone": "UTC",
            },
        )
        first = asyncio.create_task(hub.execute(**kwargs))
        await asyncio.sleep(0)
        second = asyncio.create_task(hub.execute(**kwargs))
        await asyncio.sleep(0)
        second.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await second
        request = hub.poll(owner, fields, after=0)["requests"][0]["request"]
        hub.accept_result(owner, fields, device_tool_result(
            request=request, status="completed", payload={"items": []}, sent_at=clock.value,
        ))
        self.assertEqual((await first)["status"], "completed")

    async def test_duplicate_call_coalesces_across_two_worker_event_loops(self) -> None:
        clock = Clock()
        hub = NativeDeviceToolHub(
            clock=clock,
            profile_session_validator=lambda profile, session: profile == "default" and session == "stored-session",
        )
        owner = Owner()
        fields = channel_fields()
        hub.connect(owner, fields)
        kwargs = dict(
            profile="default", session_id="stored-session", turn_id="turn-cross-loop",
            tool_call_id="call-cross-loop", operation="calendar.list", arguments={
                "start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z", "timeZone": "UTC",
            },
        )

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(lambda: asyncio.run(hub.execute(**kwargs)))
            deadline = asyncio.get_running_loop().time() + 1.0
            while not hub.channels[fields["channelId"]].pending and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.005)
            self.assertTrue(hub.channels[fields["channelId"]].pending)
            second = pool.submit(lambda: asyncio.run(hub.execute(**kwargs)))
            while (
                next(iter(hub.channels[fields["channelId"]].pending.values())).waiters < 2
                and asyncio.get_running_loop().time() < deadline
            ):
                await asyncio.sleep(0.005)
            try:
                self.assertEqual(next(iter(hub.channels[fields["channelId"]].pending.values())).waiters, 2)
                request = next(iter(hub.channels[fields["channelId"]].pending.values())).request
                hub.accept_result(owner, fields, device_tool_result(
                    request=request, status="completed", payload={"items": []}, sent_at=clock.value,
                ))
                self.assertEqual(first.result(timeout=2)["status"], "completed")
                self.assertEqual(second.result(timeout=2)["status"], "completed")
            finally:
                if not first.done() or not second.done():
                    hub.close(owner, fields)

    def test_official_execution_middleware_consumes_native_async_work_before_returning(self) -> None:
        from hermes_cli import middleware

        callbacks: list = []

        class Context:
            profile_name = "default"

            def register_middleware(self, kind, callback):
                callbacks.append((kind, callback))

        class Hub:
            def native_channel_count(self, profile, session_id):
                return 1

            async def execute(self, **kwargs):
                return {
                    "version": 1,
                    "type": "device.tool.result",
                    "status": "completed",
                    "payload": {"items": []},
                }

        self.assertTrue(register_middleware(Context(), hub=Hub()))
        callback = callbacks[-1][1]
        manager = SimpleNamespace(_middleware={"tool_execution": [callback]})
        with patch.dict(sys.modules, {
            "model_tools": SimpleNamespace(_run_async=lambda coroutine: asyncio.run(coroutine)),
        }), patch("hermes_cli.plugins.get_plugin_manager", return_value=manager):
            value = middleware.run_tool_execution_middleware(
                "iphone_calendar", {"operation": "list"}, lambda _args: "downstream",
                session_id="stored-session", turn_id="turn-official", tool_call_id="call-official",
            )
        self.assertIsInstance(value, str)
        self.assertEqual(json.loads(value)["status"], "completed")

    def test_official_execution_middleware_forwards_unrelated_tools_once(self) -> None:
        from hermes_cli import middleware

        callbacks: list = []

        class Context:
            profile_name = "default"

            def register_middleware(self, kind, callback):
                callbacks.append((kind, callback))

        self.assertTrue(register_middleware(Context(), hub=SimpleNamespace()))
        callback = callbacks[-1][1]
        manager = SimpleNamespace(_middleware={"tool_execution": [callback]})
        calls: list = []

        def downstream(payload):
            calls.append(payload)
            return {"downstream": payload}

        with patch("hermes_cli.plugins.get_plugin_manager", return_value=manager):
            value = middleware.run_tool_execution_middleware(
                "weather", {"location": "Chicago"}, downstream,
                session_id="stored-session", turn_id="turn-unrelated", tool_call_id="call-unrelated",
            )
        self.assertEqual(value, {"downstream": {"location": "Chicago"}})
        self.assertEqual(calls, [{"location": "Chicago"}])

        calls.clear()

        def failing_downstream(payload):
            calls.append(payload)
            raise RuntimeError("downstream failure")

        with patch("hermes_cli.plugins.get_plugin_manager", return_value=manager):
            with self.assertRaisesRegex(RuntimeError, "downstream failure"):
                middleware.run_tool_execution_middleware(
                    "weather", {"location": "Chicago"}, failing_downstream,
                    session_id="stored-session", turn_id="turn-error", tool_call_id="call-error",
                )
        self.assertEqual(calls, [{"location": "Chicago"}])

    def test_native_execution_bridge_failure_does_not_fall_through(self) -> None:
        callbacks: list = []

        class Context:
            profile_name = "default"

            def register_middleware(self, kind, callback):
                callbacks.append((kind, callback))

        class Hub:
            def native_channel_count(self, profile, session_id):
                return 1

            async def execute(self, **kwargs):
                return {"status": "completed"}

        self.assertTrue(register_middleware(Context(), hub=Hub()))

        def broken_run_async(coroutine):
            coroutine.close()
            raise RuntimeError("bridge stopped")

        with patch.dict(sys.modules, {
            "model_tools": SimpleNamespace(_run_async=broken_run_async),
        }):
            value = callbacks[0][1](
                tool_name="iphone_calendar", args={"operation": "list"},
                session_id="stored-session", turn_id="turn-bridge", tool_call_id="call-bridge",
                next_call=lambda _args=None: self.fail("active native lease must not fall through"),
            )
        self.assertEqual(json.loads(value)["code"], "phone_unavailable")


class LoaderNamespaceTests(unittest.TestCase):
    def test_dashboard_module_resolves_loader_scoped_registration_by_profile(self) -> None:
        """The dashboard API and Hermes loader import the package under different names."""
        from loopdy_plugin import native_device_tools as dashboard_module

        scoped_name = "hermes_plugins.loopdy.loopdy_plugin.native_device_tools"
        scoped_module = SimpleNamespace(
            __name__=scoped_name,
            __file__=dashboard_module.__file__,
            _registered=True,
            _registered_profile="default",
        )
        with patch.dict(sys.modules, {scoped_name: scoped_module}):
            self.assertIs(
                dashboard_module._implementation_for_profile("default"),
                scoped_module,
            )
            self.assertTrue(dashboard_module.available("default"))

    def test_dashboard_module_does_not_cross_profile_registration(self) -> None:
        from loopdy_plugin import native_device_tools as dashboard_module

        scoped_name = "hermes_plugins.loopdy.loopdy_plugin.native_device_tools"
        scoped_module = SimpleNamespace(
            __name__=scoped_name,
            __file__=dashboard_module.__file__,
            _registered=True,
            _registered_profile="research",
        )
        with patch.dict(sys.modules, {scoped_name: scoped_module}):
            self.assertIsNone(dashboard_module._implementation_for_profile("default"))
            self.assertFalse(dashboard_module.available("default"))

    def test_dashboard_module_rejects_ambiguous_registered_generations(self) -> None:
        from loopdy_plugin import native_device_tools as dashboard_module

        modules = {
            f"hermes_plugins.loopdy.generation_{index}.native_device_tools": SimpleNamespace(
                __file__=dashboard_module.__file__,
                _registered=True,
                _registered_profile="default",
            )
            for index in (1, 2)
        }
        with patch.dict(sys.modules, modules):
            self.assertIsNone(dashboard_module._implementation_for_profile("default"))
            self.assertFalse(dashboard_module.available("default"))

    def test_dashboard_device_route_calls_loader_owned_module(self) -> None:
        from loopdy_plugin import native_api, native_device_tools

        scoped_name = "hermes_plugins.loopdy.loopdy_plugin.native_device_tools"
        marker = object()
        captured: dict[str, object] = {}

        class ScopedModule:
            __name__ = scoped_name
            __file__ = native_device_tools.__file__
            _registered = True
            _registered_profile = "default"

            @staticmethod
            async def request(operation, request, **kwargs):
                captured.update(kwargs)
                return marker

        owner = SimpleNamespace(serving_profile_id="default")
        with patch.dict(sys.modules, {scoped_name: ScopedModule}), \
             patch.object(native_api, "native_context", return_value=owner):
            value = asyncio.run(native_api.device_tools("poll", object()))
        self.assertIs(value, marker)
        self.assertIs(captured["owner"], owner)
        self.assertIs(captured["auth_module"], native_api)

    def test_scoped_request_reuses_bare_auth_context_for_real_channel_lifecycle(self) -> None:
        """The mounted dashboard route and Hermes middleware have distinct module IDs."""
        import importlib
        import importlib.util
        import types

        from loopdy_plugin import native_api, native_context

        root = Path(__file__).resolve().parents[1] / "loopdy_plugin"
        namespace = f"hermes_plugins.loopdy_test_{uuid.uuid4().hex}"
        package = namespace + ".loopdy_plugin"
        module_name = package + ".native_device_tools"
        created_namespace = False
        if "hermes_plugins" not in sys.modules:
            parent_module = types.ModuleType("hermes_plugins")
            parent_module.__path__ = []
            parent_module.__package__ = "hermes_plugins"
            sys.modules["hermes_plugins"] = parent_module
            created_namespace = True
        scoped_parent = types.ModuleType(namespace)
        scoped_parent.__path__ = []
        scoped_parent.__package__ = namespace
        scoped_package = types.ModuleType(package)
        scoped_package.__path__ = [str(root)]
        scoped_package.__package__ = package
        sys.modules[namespace] = scoped_parent
        sys.modules[package] = scoped_package
        try:
            spec = importlib.util.spec_from_file_location(
                module_name, root / "native_device_tools.py")
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            scoped_module = importlib.util.module_from_spec(spec)
            scoped_module.__package__ = package
            sys.modules[module_name] = scoped_module
            spec.loader.exec_module(scoped_module)
            scoped_context = importlib.import_module(package + ".native_context")
            self.assertNotEqual(native_context.RUNTIME_ID, scoped_context.RUNTIME_ID)

            owner = NativeContext(
                None, None, None, "default", (scoped_module.CAPABILITY,),
                native_context.RUNTIME_ID,
            )

            class Request:
                def __init__(self, payload: dict, etag: str) -> None:
                    self.query_params = QueryParams()
                    self.headers = Headers({
                        "content-type": "application/json",
                        "if-match": etag,
                        "x-loopdy-request-id": str(uuid.uuid4()),
                    })
                    self.payload = payload

                async def stream(self):
                    yield json.dumps(self.payload, separators=(",", ":")).encode("utf-8")

            fields = channel_fields(session_id="stored-session")
            scoped_module._HUB = scoped_module.NativeDeviceToolHub(
                profile_session_validator=lambda _profile, _session: True,
            )
            with patch.object(scoped_module, "available", return_value=True), \
                 patch.object(native_api, "native_context", return_value=owner):
                connected = asyncio.run(scoped_module.request(
                    "connect", Request(fields, owner.etag), owner=owner, auth_module=native_api))
                self.assertEqual(json.loads(connected.body), {
                    "channelId": fields["channelId"], "connected": True,
                })

                polled = asyncio.run(scoped_module.request(
                    "poll", Request({"channelId": fields["channelId"], "after": 0}, owner.etag),
                    owner=owner, auth_module=native_api))
                self.assertEqual(json.loads(polled.body), {
                    "channelId": fields["channelId"], "next": 0, "requests": [],
                })

                stale_owner = NativeContext(
                    None, None, None, "default", (scoped_module.CAPABILITY,),
                    scoped_context.RUNTIME_ID,
                )
                with self.assertRaises(native_api.NativeAPIError) as error:
                    asyncio.run(scoped_module.request(
                        "poll", Request({"channelId": fields["channelId"], "after": 0}, stale_owner.etag),
                        owner=owner, auth_module=native_api))
                self.assertEqual(error.exception.code, "context_changed")
        finally:
            for name in tuple(sys.modules):
                if name == namespace or name.startswith(namespace + "."):
                    sys.modules.pop(name, None)
            if created_namespace:
                sys.modules.pop("hermes_plugins", None)


if __name__ == "__main__":
    unittest.main()
