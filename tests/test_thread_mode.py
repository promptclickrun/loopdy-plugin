"""Thread-mode plugin contract tests: tools, hooks, REST, injection.

Uses unittest discovery (``python -m unittest discover -s tests``), matching
the repo's CI. The Hermes ``agent.subagent_lifecycle`` module is faked in
sys.modules; the dashboard REST tests reuse the real Hermes auth middleware
with a fixture provider, mirroring tests/test_native_api.py.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Hermes lifecycle types (real code, verified at ~/workspace/hermes-agent).
# The handlers lazy-import these inside the turn; the tests import the same
# module so construction matches the real dataclass shapes.
# ---------------------------------------------------------------------------
from agent.subagent_lifecycle import (  # noqa: E402
    SubagentHandle,
    SubagentLaunchRequest,
    SubagentLifecycleError,
    SubagentResult,
    SubagentState,
    SubagentStatus,
)

from loopdy_plugin import thread_mode  # noqa: E402


def _handle(subagent_id="sub-1", parent="coord-1", correlation="worker-a"):
    return SubagentHandle(1, subagent_id, parent, correlation, time.time(),
                          None, None, "leaf", 1, "capability")


class FakeState:
    def __init__(self):
        self._data = {}

    def get(self, key, default=None):
        return self._data.get(key, default)

    def set(self, key, value):
        self._data[key] = value


class FakeLifecycle:
    def __init__(self):
        self.launched = []
        self.launch_behavior = None
        self.statuses = {}
        self.results = {}

    def launch(self, request):
        self.launched.append(request)
        if self.launch_behavior is not None:
            return self.launch_behavior(request)
        return _handle(correlation=request.correlation_id)

    def status(self, handle):
        return self.statuses.get(handle.subagent_id,
                                 SubagentStatus(handle, SubagentState.RUNNING, time.time()))

    def result(self, handle):
        return self.results.get(handle.subagent_id,
                                SubagentResult(handle, SubagentState.RUNNING, False))


class FakeCtx:
    profile_name = "default"

    def __init__(self):
        self.tools = {}
        self.schemas = {}
        self.toolsets = {}
        self.hooks = {}
        self.state = FakeState()
        self.subagent_lifecycle = FakeLifecycle()

    def register_tool(self, *, name, handler, schema, toolset=None, **_kwargs):
        self.tools[name] = handler
        self.schemas[name] = schema
        self.toolsets[name] = toolset

    def register_hook(self, name, callback):
        self.hooks.setdefault(name, []).append(callback)


COORD = "coord-session-1"


def _spawn_payload(*specs):
    return {"threads": [{"name": name, "brief": brief, **extra}
                        for name, brief, extra in specs]}


class ThreadToolRegistrationTests(unittest.TestCase):
    def test_four_tools_registered_in_loopdy_toolset(self):
        ctx = FakeCtx()
        thread_mode.register(ctx)
        for name in ("thread_spawn", "thread_status", "thread_collect", "thread_note"):
            self.assertIn(name, ctx.tools)
            self.assertEqual(ctx.toolsets[name], "loopdy")
            schema = ctx.schemas[name]
            self.assertEqual(schema["name"], name)
            self.assertIn("parameters", schema)

    def test_additive_hooks_registered(self):
        ctx = FakeCtx()
        thread_mode.register(ctx)
        for hook in ("pre_llm_call", "subagent_start", "subagent_stop"):
            self.assertIn(hook, ctx.hooks)
            self.assertEqual(len(ctx.hooks[hook]), 1)

    def test_plugin_yaml_provides_thread_tools(self):
        import yaml
        manifest = yaml.safe_load((ROOT / "plugin.yaml").read_text(encoding="utf-8"))
        provides = manifest["provides_tools"]
        for name in ("thread_spawn", "thread_status", "thread_collect", "thread_note"):
            self.assertIn(name, provides)
        for hook in ("pre_llm_call", "subagent_start", "subagent_stop"):
            self.assertIn(hook, manifest["provides_hooks"])

    def test_dashboard_mounts_threads_router(self):
        source = (ROOT / "dashboard" / "plugin_api.py").read_text(encoding="utf-8")
        self.assertIn("native_threads_router", source)
        self.assertIn("include_router(native_threads_router)", source)


class ThreadNameValidationTests(unittest.TestCase):
    def setUp(self):
        self.ctx = FakeCtx()
        thread_mode.register(self.ctx)
        self.spawn = self.ctx.tools["thread_spawn"]

    def _spawn(self, *specs):
        return json.loads(self.spawn(_spawn_payload(*specs), session_id=COORD))

    def test_rejects_bad_names_per_thread_and_continues(self):
        result = self._spawn(
            ("Bad Name", "brief", {}),
            ("-leading", "brief", {}),
            ("ok-name_1", "brief", {}),
            ("x" * 65, "brief", {}),
            ("", "brief", {}),
        )
        by_name = {item["name"]: item for item in result["threads"]}
        self.assertFalse(by_name["Bad Name"]["ok"])
        self.assertFalse(by_name["-leading"]["ok"])
        self.assertFalse(by_name["x" * 65]["ok"])
        self.assertFalse(by_name[None]["ok"] if None in by_name else by_name[""]["ok"])
        self.assertTrue(by_name["ok-name_1"]["ok"])
        for item in result["threads"]:
            if not item["ok"]:
                self.assertIn("error", item)
                self.assertIn("^[a-z0-9][a-z0-9_-]{0,63}$", item["error"])

    def test_rejects_duplicate_name_per_coordinator(self):
        self._spawn(("dup", "first", {}))
        result = self._spawn(("dup", "second", {}))
        self.assertFalse(result["threads"][0]["ok"])
        self.assertIn("already exists", result["threads"][0]["error"])

    def test_rejects_empty_brief(self):
        result = self._spawn(("nobrieef", "   ", {}))
        self.assertFalse(result["threads"][0]["ok"])
        self.assertIn("brief", result["threads"][0]["error"])

    def test_rejects_empty_thread_list(self):
        result = json.loads(self.spawn({"threads": []}, session_id=COORD))
        self.assertFalse(result["ok"])


class ThreadSpawnLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.ctx = FakeCtx()
        thread_mode.register(self.ctx)
        self.spawn = self.ctx.tools["thread_spawn"]

    def test_spawning_record_persisted_before_launch(self):
        seen = {}

        def launch(request):
            record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
            seen["status_at_launch"] = record["threads"]["early"]["status"]
            seen["request"] = request
            return _handle(correlation=request.correlation_id)

        self.ctx.subagent_lifecycle.launch_behavior = launch
        result = json.loads(self.spawn(_spawn_payload(("early", "do things", {})),
                                         session_id=COORD))
        self.assertEqual(seen["status_at_launch"], "spawning")
        self.assertTrue(result["threads"][0]["ok"])
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        self.assertEqual(record["threads"]["early"]["status"], "running")
        self.assertEqual(record["threads"]["early"]["subagent_id"], "sub-1")
        self.assertIn("handle", record["threads"]["early"])

    def test_launch_request_carries_discipline_goal_role_metadata(self):
        self.spawn(_spawn_payload(("worker-a", "scope the brief", {"context": "extra ctx"})),
                   session_id=COORD)
        request = self.ctx.subagent_lifecycle.launched[0]
        self.assertEqual(request.goal, "scope the brief")
        self.assertEqual(request.role, "leaf")
        self.assertEqual(request.correlation_id, "worker-a")
        self.assertEqual(request.metadata, {"threadmode": COORD, "thread": "worker-a"})
        self.assertIn("worker-a", request.context)
        self.assertIn("scope the brief", request.context)
        self.assertIn("extra ctx", request.context)
        self.assertIn("## Result", request.context)
        self.assertIn("MEMORY.md", request.context)

    def test_no_live_turn_returns_clean_error_without_traceback(self):
        def launch(_request):
            raise SubagentLifecycleError("No active Hermes parent session is available.")

        self.ctx.subagent_lifecycle.launch_behavior = launch
        result = json.loads(self.spawn(_spawn_payload(("ghost", "brief", {})),
                                       session_id=COORD))
        item = result["threads"][0]
        self.assertFalse(item["ok"])
        self.assertEqual(item["error"], thread_mode.NO_LIVE_TURN_ERROR)
        self.assertIn("Loopdy thread view", item["error"])
        self.assertNotIn("Traceback", json.dumps(result))
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        self.assertEqual(record["threads"]["ghost"]["status"], "failed")

    def test_duplicate_correlation_id_is_clear_error(self):
        def launch(_request):
            raise SubagentLifecycleError("Duplicate correlation_id for this parent session.")

        self.ctx.subagent_lifecycle.launch_behavior = launch
        result = json.loads(self.spawn(_spawn_payload(("twice", "brief", {})),
                                       session_id=COORD))
        self.assertFalse(result["threads"][0]["ok"])
        self.assertIn("already launching", result["threads"][0]["error"])

    def test_unexpected_launch_error_never_leaks_traceback(self):
        def launch(_request):
            raise RuntimeError("boom\nTraceback (most recent call last): ...")

        self.ctx.subagent_lifecycle.launch_behavior = launch
        result = json.loads(self.spawn(_spawn_payload(("oops", "brief", {})),
                                       session_id=COORD))
        self.assertFalse(result["threads"][0]["ok"])
        self.assertNotIn("Traceback", result["threads"][0]["error"])


class ThreadStatusTests(unittest.TestCase):
    def setUp(self):
        self.ctx = FakeCtx()
        thread_mode.register(self.ctx)
        self.spawn = self.ctx.tools["thread_spawn"]
        self.status = self.ctx.tools["thread_status"]
        self.spawn(_spawn_payload(("worker-a", "brief a", {}), ("worker-b", "brief b", {})),
                   session_id=COORD)

    def test_refreshes_subagent_status_and_persists(self):
        self.ctx.subagent_lifecycle.statuses["sub-1"] = SubagentStatus(
            _handle("sub-1"), SubagentState.SUCCEEDED, time.time())
        result = json.loads(self.status({}, session_id=COORD))
        by_name = {item["name"]: item for item in result["threads"]}
        self.assertEqual(by_name["worker-a"]["status"], "succeeded")
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        self.assertEqual(record["threads"]["worker-a"]["status"], "succeeded")

    def test_session_kind_reports_stored_status(self):
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        entry = thread_mode._new_thread_record("sess-w", "brief", "session")
        entry["status"] = "running"
        entry["worker_session_id"] = "worker-session-9"
        record["threads"]["sess-w"] = entry
        self.ctx.state.set(thread_mode.coordinator_key(COORD), record)
        result = json.loads(self.status({}, session_id=COORD))
        by_name = {item["name"]: item for item in result["threads"]}
        self.assertEqual(by_name["sess-w"]["status"], "running")
        self.assertEqual(by_name["sess-w"]["kind"], "session")
        self.assertEqual(by_name["sess-w"]["ids"]["worker_session_id"], "worker-session-9")
        self.assertNotIn("handle", json.dumps(by_name["sess-w"]))

    def test_unknown_coordinator_returns_empty_roster(self):
        result = json.loads(self.status({}, session_id="nope"))
        self.assertEqual(result["threads"], [])


class ThreadCollectTests(unittest.TestCase):
    def setUp(self):
        self.ctx = FakeCtx()
        thread_mode.register(self.ctx)
        self.spawn = self.ctx.tools["thread_spawn"]
        self.collect = self.ctx.tools["thread_collect"]
        self.spawn(_spawn_payload(("worker-a", "brief", {})), session_id=COORD)

    def test_not_ready_reports_status(self):
        result = json.loads(self.collect({"thread_name": "worker-a"}, session_id=COORD))
        self.assertFalse(result["collected"])
        self.assertEqual(result["status"], "running")

    def test_ready_parses_result_section(self):
        self.ctx.subagent_lifecycle.results["sub-1"] = SubagentResult(
            _handle("sub-1"), SubagentState.SUCCEEDED, True,
            summary="Some chatter\n\n## Result\n\nThe deliverable.\n\n## Notes\nscratch")
        result = json.loads(self.collect({"thread_name": "worker-a"}, session_id=COORD))
        self.assertTrue(result["collected"])
        self.assertEqual(result["result"], "The deliverable.")
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        self.assertEqual(record["threads"]["worker-a"]["result"], "The deliverable.")

    def test_ready_without_result_heading_falls_back_to_full_text(self):
        self.ctx.subagent_lifecycle.results["sub-1"] = SubagentResult(
            _handle("sub-1"), SubagentState.SUCCEEDED, True, summary="just prose")
        result = json.loads(self.collect({"thread_name": "worker-a"}, session_id=COORD))
        self.assertTrue(result["collected"])
        self.assertEqual(result["result"], "just prose")

    def test_session_kind_without_readable_session_returns_hint(self):
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        entry = thread_mode._new_thread_record("sess-w", "brief", "session")
        entry["worker_session_id"] = "missing-session"
        record["threads"]["sess-w"] = entry
        self.ctx.state.set(thread_mode.coordinator_key(COORD), record)
        with patch("hermes_state.SessionDB", side_effect=RuntimeError("no db")):
            result = json.loads(self.collect({"thread_name": "sess-w"}, session_id=COORD))
        self.assertFalse(result["collected"])
        self.assertEqual(result["worker_session_id"], "missing-session")
        self.assertIn("hint", result)

    def test_unknown_thread(self):
        result = json.loads(self.collect({"thread_name": "nope"}, session_id=COORD))
        self.assertFalse(result["collected"])
        self.assertIn("error", result)


class ParseResultSectionTests(unittest.TestCase):
    def test_first_result_section_only(self):
        text = "# Title\n\n## Result\n\nLine one.\nLine two.\n\n## Result\n\nSecond.\n"
        self.assertEqual(thread_mode.parse_result_section(text), "Line one.\nLine two.")

    def test_stops_before_next_h2(self):
        text = "## Result\n\ndone\n\n## Appendix\n\nnope"
        self.assertEqual(thread_mode.parse_result_section(text), "done")

    def test_missing_heading_returns_full_text(self):
        self.assertEqual(thread_mode.parse_result_section("hello"), "hello")

    def test_non_string_returns_empty(self):
        self.assertEqual(thread_mode.parse_result_section(None), "")


class ThreadNoteTests(unittest.TestCase):
    def setUp(self):
        self.ctx = FakeCtx()
        thread_mode.register(self.ctx)
        self.note = self.ctx.tools["thread_note"]
        self.spawn = self.ctx.tools["thread_spawn"]
        self.spawn(_spawn_payload(("worker-a", "brief", {})), session_id=COORD)

    def test_thread_and_coordinator_notes(self):
        first = json.loads(self.note({"thread_name": "worker-a", "note": "hello"}, session_id=COORD))
        self.assertTrue(first["ok"])
        self.assertEqual(first["note_count"], 1)
        second = json.loads(self.note({"note": "coordinator scratch"}, session_id=COORD))
        self.assertTrue(second["ok"])
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        self.assertEqual(record["threads"]["worker-a"]["notes"], ["hello"])
        self.assertEqual(record["notes"], ["coordinator scratch"])

    def test_notes_capped_at_fifty(self):
        for index in range(60):
            self.note({"thread_name": "worker-a", "note": f"n{index}"}, session_id=COORD)
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        notes = record["threads"]["worker-a"]["notes"]
        self.assertEqual(len(notes), 50)
        self.assertEqual(notes[0], "n10")
        self.assertEqual(notes[-1], "n59")

    def test_note_truncated_to_2000_chars(self):
        self.note({"thread_name": "worker-a", "note": "x" * 3000}, session_id=COORD)
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        self.assertEqual(len(record["threads"]["worker-a"]["notes"][0]), 2000)

    def test_unknown_thread_is_error(self):
        result = json.loads(self.note({"thread_name": "nope", "note": "x"}, session_id=COORD))
        self.assertFalse(result["ok"])

    def test_empty_note_is_error(self):
        result = json.loads(self.note({"thread_name": "worker-a", "note": "  "}, session_id=COORD))
        self.assertFalse(result["ok"])


class PreLlmCallInjectionTests(unittest.TestCase):
    def setUp(self):
        self.ctx = FakeCtx()
        thread_mode.register(self.ctx)
        self.spawn = self.ctx.tools["thread_spawn"]
        self.note = self.ctx.tools["thread_note"]

    def _inject(self, **payload):
        callbacks = self.ctx.hooks["pre_llm_call"]
        self.assertEqual(len(callbacks), 1)
        return callbacks[0](**payload)

    def test_coordinator_turn_injects_roster_and_memory_discipline(self):
        self.spawn(_spawn_payload(("worker-a", "brief a", {}), ("worker-b", "brief b", {})),
                   session_id=COORD)
        result = self._inject(session_id=COORD, parent_session_id="")
        self.assertIsNotNone(result)
        context = result["context"]
        self.assertIn("## Thread mode — coordinator", context)
        self.assertIn("worker-a", context)
        self.assertIn("worker-b", context)
        self.assertIn("thread_spawn", context)
        self.assertIn("thread_status", context)
        self.assertIn("thread_collect", context)
        self.assertIn("never ask a worker to assemble", context)
        self.assertIn("ONLY you write durable profile memory", context)

    def test_non_thread_session_injects_nothing(self):
        self.assertIsNone(self._inject(session_id="plain", parent_session_id=""))

    def test_disabled_flag_injects_nothing(self):
        self.spawn(_spawn_payload(("worker-a", "brief", {})), session_id=COORD)
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        record["enabled"] = False
        self.ctx.state.set(thread_mode.coordinator_key(COORD), record)
        self.assertIsNone(self._inject(session_id=COORD, parent_session_id=""))

    def test_subagent_worker_turn_injects_assignment(self):
        self.spawn(_spawn_payload(("worker-a", "do the thing", {})), session_id=COORD)
        self.note({"thread_name": "worker-a", "note": "remember x"}, session_id=COORD)
        # subagent_start records the child session id
        self.ctx.hooks["subagent_start"][0](
            parent_session_id=COORD, child_subagent_id="sub-1", child_session_id="child-9")
        result = self._inject(session_id="child-9", parent_session_id=COORD)
        self.assertIsNotNone(result)
        context = result["context"]
        self.assertIn("## Your thread assignment", context)
        self.assertIn("worker-a", context)
        self.assertIn("do the thing", context)
        self.assertIn("remember x", context)
        self.assertIn("## Result", context)
        self.assertIn("MEMORY.md", context)
        self.assertIn("Do not wait on them", context)

    def test_session_kind_worker_resolves_via_index(self):
        record = thread_mode._ensure_coordinator(self.ctx.state, COORD)
        entry = thread_mode._new_thread_record("sess-w", "session brief", "session")
        entry["worker_session_id"] = "worker-sess-1"
        entry["status"] = "running"
        record["threads"]["sess-w"] = entry
        self.ctx.state.set(thread_mode.coordinator_key(COORD), record)
        self.ctx.state.set(thread_mode.worker_key("worker-sess-1"),
                           {"coordinator_session_id": COORD, "thread": "sess-w"})
        result = self._inject(session_id="worker-sess-1", parent_session_id="")
        self.assertIsNotNone(result)
        self.assertIn("## Your thread assignment", result["context"])
        self.assertIn("sess-w", result["context"])

    def test_worker_turn_without_match_injects_nothing(self):
        result = self._inject(session_id="stray", parent_session_id=COORD)
        self.assertIsNone(result)

    def test_injection_fails_silent(self):
        class BrokenState:
            def get(self, *_args, **_kwargs):
                raise RuntimeError("broken")

            def set(self, *_args, **_kwargs):
                raise RuntimeError("broken")

        broken = FakeCtx()
        broken.state = BrokenState()
        thread_mode.register(broken)
        callback = broken.hooks["pre_llm_call"][0]
        self.assertIsNone(callback(session_id=COORD, parent_session_id=""))


class SubagentHookTests(unittest.TestCase):
    def setUp(self):
        self.ctx = FakeCtx()
        thread_mode.register(self.ctx)
        self.spawn = self.ctx.tools["thread_spawn"]
        self.spawn(_spawn_payload(("worker-a", "brief", {})), session_id=COORD)

    def _hooks(self, name):
        callbacks = self.ctx.hooks[name]
        self.assertEqual(len(callbacks), 1)
        return callbacks[0]

    def test_subagent_start_records_child_session_and_index(self):
        self._hooks("subagent_start")(
            parent_session_id=COORD, child_subagent_id="sub-1", child_session_id="child-9")
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        entry = record["threads"]["worker-a"]
        self.assertEqual(entry["subagent_session_id"], "child-9")
        self.assertEqual(entry["status"], "running")
        index = self.ctx.state.get(thread_mode.worker_key("child-9"))
        self.assertEqual(index, {"coordinator_session_id": COORD, "thread": "worker-a"})

    def test_subagent_start_ignores_unknown_child(self):
        self._hooks("subagent_start")(
            parent_session_id=COORD, child_subagent_id="nope", child_session_id="child-x")
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        self.assertIsNone(record["threads"]["worker-a"]["subagent_session_id"])
        self.assertIsNone(self.ctx.state.get(thread_mode.worker_key("child-x")))

    def test_subagent_stop_maps_terminal_status(self):
        start = self._hooks("subagent_start")
        stop = self._hooks("subagent_stop")
        start(parent_session_id=COORD, child_subagent_id="sub-1", child_session_id="child-9")
        stop(parent_session_id=COORD, child_session_id="child-9", child_status="completed")
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        self.assertEqual(record["threads"]["worker-a"]["status"], "succeeded")

    def test_subagent_stop_maps_failed_and_interrupted(self):
        start = self._hooks("subagent_start")
        stop = self._hooks("subagent_stop")
        start(parent_session_id=COORD, child_subagent_id="sub-1", child_session_id="child-9")
        stop(parent_session_id=COORD, child_session_id="child-9", child_status="failed")
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        self.assertEqual(record["threads"]["worker-a"]["status"], "failed")
        stop(parent_session_id=COORD, child_session_id="child-9", child_status="interrupted")
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        self.assertEqual(record["threads"]["worker-a"]["status"], "interrupted")

    def test_subagent_stop_unknown_status_leaves_record(self):
        start = self._hooks("subagent_start")
        stop = self._hooks("subagent_stop")
        start(parent_session_id=COORD, child_subagent_id="sub-1", child_session_id="child-9")
        stop(parent_session_id=COORD, child_session_id="child-9", child_status="weird")
        record = self.ctx.state.get(thread_mode.coordinator_key(COORD))
        self.assertEqual(record["threads"]["worker-a"]["status"], "running")

    def test_hooks_fail_silent(self):
        broken = FakeCtx()

        class BrokenState(FakeState):
            def get(self, *_args, **_kwargs):
                raise RuntimeError("broken")

        broken.state = BrokenState()
        thread_mode.register(broken)
        broken.hooks["subagent_start"][0](parent_session_id=COORD)
        broken.hooks["subagent_stop"][0](parent_session_id=COORD)


class WorkerDisciplineTests(unittest.TestCase):
    def test_discipline_contains_all_required_elements(self):
        text = thread_mode.worker_discipline("worker-a", "the brief", "extra")
        self.assertIn("worker-a", text)
        self.assertIn("the brief", text)
        self.assertIn("extra", text)
        self.assertIn("Do ONLY", text)
        self.assertIn("## Result", text)
        self.assertIn("MEMORY.md", text)
        self.assertIn("thread_note", text)
        self.assertIn("Do not wait on them", text)


# ---------------------------------------------------------------------------
# REST tests (real Hermes auth middleware, fake plugin state)
# ---------------------------------------------------------------------------

class NativeThreadsRestTests(unittest.TestCase):
    PREFIX = "/api/plugins/loopdy/native/threads"

    @classmethod
    def setUpClass(cls):
        from hermes_cli.dashboard_auth.base import DashboardAuthProvider, Session
        from hermes_cli.dashboard_auth.middleware import gated_auth_middleware
        from hermes_cli.dashboard_auth.registry import register_provider, unregister_global_provider
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from loopdy_plugin import native_threads, native_api

        class FixtureProvider(DashboardAuthProvider):
            name = "thread-mode-fixture"
            display_name = "Thread mode fixture"

            def __init__(self):
                self.alice = Session("alice", "not-returned@example.invalid", "Alice",
                                     "fixture-org", self.name, int(time.time()) + 3600,
                                     "fixture-access-secret", "fixture-refresh-secret")
                self.tokens = {"fixture-alice": self.alice}

            def start_login(self, **kwargs):
                raise NotImplementedError

            def complete_login(self, **kwargs):
                raise NotImplementedError

            def verify_session(self, *, access_token):
                return self.tokens.get(access_token)

            def refresh_session(self, **kwargs):
                raise NotImplementedError

            def revoke_session(self, **kwargs):
                raise NotImplementedError

        cls._provider = FixtureProvider()
        register_provider(cls._provider)
        app = FastAPI()
        app.state.auth_required = True
        app.middleware("http")(gated_auth_middleware)
        app.include_router(native_api.router, prefix="/api/plugins/loopdy")
        app.include_router(native_threads.router, prefix="/api/plugins/loopdy")
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        from hermes_cli.dashboard_auth.registry import unregister_global_provider
        unregister_global_provider(cls._provider.name, cls._provider)
        cls.client.close()

    def setUp(self):
        from loopdy_plugin import native_threads
        self.state = FakeState()
        native_threads.register_state_resolver("default", self.state)
        self.addCleanup(native_threads.register_state_resolver, "default", None)
        temporary = tempfile.TemporaryDirectory(prefix="thread-mode-rest-")
        self.addCleanup(temporary.cleanup)
        self._env = patch.dict(os.environ, {"HERMES_HOME": temporary.name, "HOME": temporary.name})
        self._env.start()
        self.addCleanup(self._env.stop)

    def _headers(self, token="fixture-alice"):
        from loopdy_plugin import native_threads  # noqa: F401
        context = self.client.get(
            "/api/plugins/loopdy/native/context",
            headers={"Authorization": "Bearer " + token})
        self.assertEqual(context.status_code, 200, context.text)
        self.assertEqual(context.json()["servingProfileId"], "default")
        return {"Authorization": "Bearer " + token,
                "If-Match": context.headers["etag"],
                "X-Loopdy-Request-ID": str(uuid.uuid4())}

    def test_flag_creates_and_updates_record(self):
        response = self.client.post(self.PREFIX + "/flag", headers=self._headers(),
                                    json={"session_id": "sess-1", "enabled": True})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {"enabled": True, "ok": True, "session_id": "sess-1"})
        record = self.state.get(thread_mode.coordinator_key("sess-1"))
        self.assertTrue(record["enabled"])
        response = self.client.post(self.PREFIX + "/flag", headers=self._headers(),
                                    json={"session_id": "sess-1", "enabled": False})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(self.state.get(thread_mode.coordinator_key("sess-1"))["enabled"])

    def test_register_adds_session_thread_and_index(self):
        self.client.post(self.PREFIX + "/flag", headers=self._headers(),
                         json={"session_id": "sess-1", "enabled": True})
        response = self.client.post(
            self.PREFIX + "/register", headers=self._headers(),
            json={"coordinator_session_id": "sess-1", "name": "research",
                  "worker_session_id": "worker-1", "brief": "look things up"})
        self.assertEqual(response.status_code, 200, response.text)
        thread = response.json()["thread"]
        self.assertEqual(thread["name"], "research")
        self.assertEqual(thread["kind"], "session")
        self.assertEqual(thread["status"], "running")
        self.assertEqual(thread["ids"]["worker_session_id"], "worker-1")
        self.assertNotIn("handle", json.dumps(thread))
        index = self.state.get(thread_mode.worker_key("worker-1"))
        self.assertEqual(index, {"coordinator_session_id": "sess-1", "thread": "research"})

    def test_register_duplicate_name_is_409(self):
        self.client.post(self.PREFIX + "/flag", headers=self._headers(),
                         json={"session_id": "sess-1", "enabled": True})
        body = {"coordinator_session_id": "sess-1", "name": "research",
                "worker_session_id": "worker-1", "brief": "brief"}
        self.assertEqual(self.client.post(self.PREFIX + "/register", headers=self._headers(),
                                          json=body).status_code, 200)
        duplicate = self.client.post(self.PREFIX + "/register", headers=self._headers(),
                                     json={**body, "worker_session_id": "worker-2"})
        self.assertEqual(duplicate.status_code, 409, duplicate.text)

    def test_register_rejects_bad_name(self):
        response = self.client.post(
            self.PREFIX + "/register", headers=self._headers(),
            json={"coordinator_session_id": "sess-1", "name": "Bad Name",
                  "worker_session_id": "worker-1", "brief": "brief"})
        self.assertEqual(response.status_code, 422, response.text)

    def test_roster_returns_record_without_handle(self):
        self.client.post(self.PREFIX + "/flag", headers=self._headers(),
                         json={"session_id": "sess-1", "enabled": True})
        self.client.post(self.PREFIX + "/register", headers=self._headers(),
                         json={"coordinator_session_id": "sess-1", "name": "research",
                               "worker_session_id": "worker-1", "brief": "look things up"})
        response = self.client.get(self.PREFIX + "/roster",
                                   params={"coordinator_session_id": "sess-1"},
                                   headers=self._headers())
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["coordinator_session_id"], "sess-1")
        self.assertTrue(body["enabled"])
        self.assertEqual(len(body["threads"]), 1)
        thread = body["threads"][0]
        for field in ("name", "kind", "status", "brief", "ids", "notes", "result", "updated_at"):
            self.assertIn(field, thread)

    def test_roster_unknown_session_is_404(self):
        response = self.client.get(self.PREFIX + "/roster",
                                   params={"coordinator_session_id": "missing"},
                                   headers=self._headers())
        self.assertEqual(response.status_code, 404, response.text)

    def test_requires_auth(self):
        self.assertEqual(self.client.post(self.PREFIX + "/flag",
                                          json={"session_id": "s", "enabled": True}).status_code, 401)


if __name__ == "__main__":
    unittest.main()
