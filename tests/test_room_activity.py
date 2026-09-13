from __future__ import annotations

import copy
import asyncio
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from loopdy_plugin import native_context, room_activity, room_activity_api
from loopdy_plugin.native_context import NativeAPIError
from loopdy_plugin.room_activity import RoomActivityHub, RoomScope, register_room_activity
import test_native_api as native_fixtures
from test_native_api import ROOT, PREFIX


SCOPE = RoomScope("room-fixture", "gateway-fixture", 1, (("alice", "default"), ("bob", "research")))


def event(**updates):
    value = {
        "room_id": SCOPE.room_id, "member_id": "alice", "thread_id": "thread-1",
        "turn_id": "turn-1", "task_id": "dtask:1", "execution_generation": 1,
        "kind": "tool.started", "seq": 1, "telemetry_schema_version": "hermes.observer.v1",
        "payload": {"tool_id": "call:1", "name": "terminal", "args": {"command": "ls"}},
    }
    value.update(updates)
    return value


class RoomActivityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = native_fixtures.NativeAPITests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.client = self.fixture.client
        self.client.app.include_router(room_activity_api.router, prefix="/api/plugins/loopdy/native")
        self.hub = room_activity.activity_hub()
        self.callbacks = {}
        self.stop = register_room_activity(SimpleNamespace(register_hook=lambda name, callback: self.callbacks.update({name: callback})))
        self.addCleanup(self.stop)
        scope_patch = patch.object(room_activity_api, "read_room_scope", return_value=SCOPE)
        self.read_scope = scope_patch.start()
        self.addCleanup(scope_patch.stop)

    def call(self, operation, body, headers=None):
        return self.client.post(PREFIX + "/groups/activity/" + operation, json=body,
                                headers=self.fixture.headers() if headers is None else headers)

    def open(self):
        result = self.call("open", {"roomId": SCOPE.room_id})
        self.assertEqual(result.status_code, 200, result.text)
        self.stream = result.json()["streamId"]
        return result.json()

    def poll(self, after=0, **updates):
        body = {"roomId": SCOPE.room_id, "streamId": self.stream, "after": after, "limit": 8}
        return self.call("poll", {**body, **updates})

    def emit(self, **updates):
        self.callbacks[room_activity.HOOK](**event(**updates))

    def test_exact_page_and_tool_detail_preserve_native_coordinates_without_success_claim(self):
        page = self.open()
        self.assertEqual(set(page), {"schemaVersion", "runtimeId", "roomId", "streamId", "sourceState",
            "upstreamLoss", "openedAt", "expiresAt", "cursor", "highWater", "hasMore", "resetRequired",
            "resetReason", "droppedTotal", "projectionDrops", "events"})
        self.assertEqual((page["sourceState"], page["upstreamLoss"], page["events"]),
                         ("registered_unobserved", "unobservable", []))
        original = event()
        before = copy.deepcopy(original)
        self.callbacks[room_activity.HOOK](**original)
        self.emit(kind="tool.completed", seq=20, payload={"tool_id": "call:1", "name": "terminal",
                                                         "duration_s": 1.125, "result": {"error": "command failed"}})
        response = self.poll()
        self.assertEqual(response.status_code, 200, response.text)
        page = response.json()
        self.assertEqual((page["highWater"], page["cursor"], page["droppedTotal"]), (2, 2, 0))
        self.assertEqual(page["upstreamLoss"], "unobservable")
        started, finished = page["events"]
        self.assertEqual(started["tool"], {"id": "call:1", "name": "terminal", "durationMs": None})
        self.assertEqual(started["result"], {"state": "unavailable", "text": None})
        self.assertEqual(started["arguments"]["text"], '{"command":"ls"}')
        self.assertEqual(finished["tool"]["durationMs"], 1125)
        self.assertEqual(finished["sourceSequence"], 20)
        self.assertEqual(finished["executionGeneration"], 1)
        self.assertNotIn("success", finished)
        self.assertNotIn("profile", finished)
        self.assertEqual(original, before)
        self.assertEqual(self.poll(2).json()["events"], [])

    def test_credential_oversize_and_binary_details_are_explicitly_omitted(self):
        self.open()
        self.emit(payload={"tool_id": "call-1", "name": "terminal",
                           "args": {"authorization": "short-secret"}, "result": "x" * 8193})
        details = self.poll().json()["events"][0]
        self.assertEqual(details["arguments"], {"state": "omitted_sensitive", "text": None})
        self.assertEqual(details["result"], {"state": "omitted_size", "text": None})
        self.emit(seq=2, payload={"tool_id": "call-2", "name": "terminal",
                                 "args": "sk-" + "a" * 30, "result": b"binary"})
        row = self.poll(1).json()["events"][0]
        self.assertEqual(row["arguments"]["state"], "omitted_sensitive")
        self.assertEqual(row["result"]["state"], "unavailable")
        self.assertNotIn("short-secret", self.poll().text)
        self.emit(seq=3, payload={"tool_id": "call-3", "name": "terminal",
                                 "args": "\\\"" * 4096, "result": "\\\"" * 4096})
        escaped = self.poll(2).json()
        self.assertFalse(escaped["resetRequired"])
        self.assertIn("omitted_size", {escaped["events"][0][key]["state"] for key in ("arguments", "result")})
        self.emit(seq=4, payload={"tool_id": "call-4", "name": "terminal",
                                 "args": {"token": "opaque-value"}, "result": '{"auth":"opaque-value"}'})
        credentials = self.poll(3).json()["events"][0]
        self.assertEqual(credentials["arguments"]["state"], "omitted_sensitive")
        self.assertEqual(credentials["result"]["state"], "omitted_sensitive")

    def test_non_tool_sources_ignored_missing_coordinates_trigger_projection_reset(self):
        self.open()
        for kind in ("message.delta", "reasoning.delta", "request.opened", "tool.output_risk"):
            self.emit(kind=kind)
        self.assertEqual(self.poll().json()["sourceState"], "registered_unobserved")
        self.emit(task_id=None)
        result = self.poll().json()
        self.assertEqual(result["sourceState"], "unsupported_payload")
        self.assertEqual(result["resetReason"], "projection_loss")
        self.assertTrue(result["resetRequired"])
        self.assertEqual(result["events"], [])
        self.assertEqual(result["projectionDrops"], 1)

    def test_count_and_byte_overflow_are_bounded_and_require_reset_only_for_lost_cursor(self):
        self.open()
        for index in range(129):
            self.emit(seq=index + 1)
        page = self.poll().json()
        self.assertEqual(page["resetReason"], "buffer_loss")
        self.assertEqual((page["cursor"], page["highWater"], page["droppedTotal"]), (129, 129, 1))
        self.assertEqual(page["events"], [])
        self.assertFalse(self.poll(1).json()["resetRequired"])
        self.assertTrue(self.poll(1).json()["hasMore"])
        self.assertEqual(self.poll(130).status_code, 422)
        for index in range(129, 170):
            self.emit(seq=index + 1, payload={"tool_id": "call-big", "name": "terminal",
                                            "args": "a" * 8192, "result": "b" * 8192})
        feed = self.hub._feeds[self.stream]
        self.assertLessEqual(feed.size, room_activity.MAX_FEED_BYTES)
        self.assertTrue(all(len(digest) == 32 for digest in feed.seen))
        self.assertLessEqual(len(self.poll(169).content), 196608)

    def test_same_source_delivery_dedupes_without_equating_session_gaps_to_loss(self):
        self.open()
        self.emit()
        self.emit()
        self.emit(seq=300)
        result = self.poll().json()
        self.assertEqual(result["highWater"], 2)
        self.assertFalse(result["resetRequired"])
        self.assertEqual(result["droppedTotal"], 0)

    def test_wrong_principal_room_headers_and_unload_fence_delivery(self):
        self.open()
        self.emit()
        body = {"roomId": SCOPE.room_id, "streamId": self.stream, "after": 0, "limit": 8}
        self.assertEqual(self.call("poll", body, self.fixture.headers("fixture-bob")).status_code, 404)
        self.assertEqual(self.poll(roomId="different").status_code, 404)
        self.assertEqual(self.poll(limit=True).status_code, 422)
        self.assertEqual(self.call("open", {"roomId": SCOPE.room_id, "deviceId": "forged"}).status_code, 422)
        stale = self.fixture.headers()
        self.stop()
        self.emit()
        self.assertEqual(self.call("poll", body, stale).status_code, 412)
        self.assertEqual(self.poll().status_code, 410)
        self.assertNotIn(room_activity.CAPABILITY, self.fixture.context().json()["features"])

    def test_authority_change_and_post_await_runtime_change_fail_closed(self):
        self.open()
        self.read_scope.return_value = replace(SCOPE, epoch=2)
        self.assertEqual(self.poll().status_code, 410)
        self.read_scope.return_value = SCOPE
        self.open()
        before = native_context.RUNTIME_ID
        self.addCleanup(setattr, native_context, "RUNTIME_ID", before)
        async def changed(_room):
            native_context.RUNTIME_ID = "changed-runtime"
            return SCOPE
        self.read_scope.side_effect = changed
        self.assertEqual(self.poll().status_code, 412)

    def test_unload_during_room_await_discards_the_pending_projection(self):
        self.open()
        self.emit()
        async def unload_during_read(_room):
            await asyncio.sleep(0)
            self.stop()
            return SCOPE
        self.read_scope.side_effect = unload_during_read
        self.assertEqual(self.poll().status_code, 412)
        self.assertFalse(self.hub.available)
        self.assertEqual(self.hub._feeds, {})

    def test_supported_registration_without_observations_and_old_hook_set(self):
        self.assertIn(room_activity.CAPABILITY, self.fixture.context().json()["features"])
        self.stop()
        with patch("hermes_cli.plugins.VALID_HOOKS", set()):
            called = []
            stop = register_room_activity(SimpleNamespace(register_hook=lambda *args: called.append(args)))
            stop()
        self.assertEqual(called, [])
        self.assertEqual(self.call("open", {"roomId": SCOPE.room_id}).status_code, 503)

    def test_lease_capacity_close_and_late_registration_callback(self):
        self.open()
        owner = native_context.NativeContext("native-fixture", "alice", "Alice", "default",
                 ("native-context-v1", "serving-profile-v1", "native-card-templates-v1", room_activity.CAPABILITY),
                 native_context.RUNTIME_ID)
        clock = [10.0]
        hub = RoomActivityHub(clock=lambda: clock[0], wall_clock=lambda: 1000.0)
        lease = hub.attach()
        streams = [hub.open(owner, SCOPE)["streamId"] for _ in range(16)]
        with self.assertRaises(NativeAPIError) as full:
            hub.open(owner, SCOPE)
        self.assertEqual(full.exception.status, 429)
        hub.close(streams[0], owner, SCOPE.room_id)
        with self.assertRaises(NativeAPIError):
            hub.check(streams[0], owner, SCOPE.room_id)
        clock[0] += 61
        with self.assertRaises(NativeAPIError) as expired:
            hub.poll(streams[1], owner, SCOPE, 0, 8)
        self.assertEqual(expired.exception.status, 410)
        hub.detach(lease)
        current = hub.attach()
        stream = hub.open(owner, SCOPE)["streamId"]
        hub.observe(lease, event())
        self.assertEqual(hub.poll(stream, owner, SCOPE, 0, 8)["highWater"], 0)
        hub.observe(current, event())
        self.assertEqual(hub.poll(stream, owner, SCOPE, 0, 8)["highWater"], 1)


class StockRoomActivityTests(unittest.TestCase):
    def test_stock_http_auth_native_room_and_actual_public_emitter(self):
        script = r'''
import os, sys, time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from fastapi.testclient import TestClient
from hermes_cli.web_server import app
from hermes_cli.dashboard_auth.registry import register_provider
from test_native_api import FixtureProvider, PREFIX
from loopdy_plugin.room_activity import HOOK, register_room_activity
from tui_gateway.server import handle_request
from tui_gateway.methods_groups import start_hosted_room_service, stop_hosted_room_service
from tui_gateway.hosted_room_member_activity import emit_room_member_activity
provider = FixtureProvider()
register_provider(provider)
callbacks = {}
stop = register_room_activity(SimpleNamespace(register_hook=lambda name, callback: callbacks.update({name:callback})))
app.state.auth_required = True
start_hosted_room_service()
created = handle_request({"jsonrpc":"2.0","id":"fixture-create","method":"groups.create","params":{
 "room_id":"room-fixture","name":"Fixture","members":[
 {"member_id":"alice","profile":"default","handle":"alice"},
 {"member_id":"bob","profile":"research","handle":"bob"}]}})
assert "result" in created, created
client = TestClient(app, base_url="http://localhost")
headers = {"Authorization":"Bearer fixture-alice"}
context = client.get(PREFIX + "/context", headers=headers)
assert context.status_code == 200, context.text
headers.update({"If-Match":context.headers["etag"],"X-Loopdy-Request-ID":"123e4567-e89b-42d3-a456-426614174000"})
base = PREFIX + "/groups/activity/"
assert client.post(base + "open",json={"roomId":"room-fixture"}).status_code == 401
opened = client.post(base + "open",headers=headers,json={"roomId":"room-fixture"})
assert opened.status_code == 200, (opened.status_code,opened.text)
stream = opened.json()["streamId"]
with patch("hermes_cli.plugins.iter_hook_callbacks", side_effect=lambda name: (callbacks[HOOK],) if name==HOOK else ()):
 assert emit_room_member_activity({"room_id":"room-fixture","member_id":"alice","thread_id":"thread-1",
  "turn_id":"turn-1","task_id":"dtask:1","execution_generation":1},kind="tool.started",
  payload={"tool_id":"call-1","name":"terminal","args":{"command":"ls"}},seq=10)
 deadline = time.monotonic()+2
 while True:
  page = client.post(base+"poll",headers=headers,json={"roomId":"room-fixture","streamId":stream,"after":0,"limit":8})
  assert page.status_code==200, (page.status_code,page.text)
  if page.json()["events"] or time.monotonic()>deadline:
   break
  time.sleep(.01)
 assert page.json()["events"][0]["tool"]["id"]=="call-1"
 assert page.json()["upstreamLoss"]=="unobservable"
provider.tokens.pop("fixture-alice")
assert client.post(base+"poll",headers=headers,json={"roomId":"room-fixture","streamId":stream,"after":0,"limit":8}).status_code==401
provider.tokens["fixture-alice"]=provider.alice
(Path(os.environ["HERMES_HOME"])/"config.yaml").write_text("plugins:\n  enabled: []\n  disabled: [loopdy]\n")
assert client.post(base+"poll",headers=headers,json={"roomId":"room-fixture","streamId":stream,"after":0,"limit":8}).status_code==404
stop()
stop_hosted_room_service(timeout=1.0)
print("stock auth, actual native room, public emitter, scoped HTTP tool observation passed", file=sys.__stdout__, flush=True)
'''
        with tempfile.TemporaryDirectory(prefix="loopdy-room-http-", dir=Path(tempfile.gettempdir()).resolve()) as directory:
            home = Path(directory) / "hermes-home"
            (home / "plugins").mkdir(parents=True)
            (home / "profiles/research").mkdir(parents=True)
            (home / "plugins/loopdy").symlink_to(ROOT, target_is_directory=True)
            (home / "config.yaml").write_text("plugins:\n  enabled: [loopdy]\n")
            env = {key: os.environ[key] for key in ("PATH", "PYTHONPATH") if key in os.environ}
            env.update(HOME=directory, HERMES_HOME=str(home), TMPDIR=directory, PYTHONDONTWRITEBYTECODE="1")
            result = subprocess.run([sys.executable, "-B", "-c", script], env=env, cwd=directory,
                                    capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("public emitter", result.stdout)
