import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from loopdy_plugin.activity_bridge import LinkActivityBroker, publish_hook_activity
from loopdy_plugin.store import LoopdyStore


class TurnDurationTests(unittest.TestCase):
    def test_socket_detach_does_not_erase_inflight_duration(self):
        import asyncio
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            broker = LinkActivityBroker()
            broker.attach_duration_store(store)
            broker.bind_link_session("stored-session", "visible-session")
            payload = {"session_id": "stored-session", "turn_id": "turn-0001", "platform": "loopdy"}
            with patch("loopdy_plugin.activity_bridge.time.monotonic", return_value=10):
                publish_hook_activity("pre_llm_call", broker=broker, profile="default", payload=payload)
            asyncio.run(broker.detach())
            with patch("loopdy_plugin.activity_bridge.time.monotonic", return_value=30):
                publish_hook_activity("post_llm_call", broker=broker, profile="default", payload={
                    **payload, "conversation_history": [{"role": "assistant", "timestamp": 120.25}]
                })
            self.assertEqual(store.turn_durations("stored-session"), {120.25: 20000})

    def test_failed_or_interrupted_completion_after_detach_consumes_timing(self):
        import asyncio
        from loopdy_plugin.activity_bridge import finish_failed_turn_activity

        for terminal_flag in ("failed", "interrupted"):
            with self.subTest(terminal_flag=terminal_flag), tempfile.TemporaryDirectory() as directory:
                store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
                broker = LinkActivityBroker()
                broker.attach_duration_store(store)
                broker.bind_link_session("stored-session", "visible-session")
                payload = {"session_id": "stored-session", "turn_id": "turn-0001", "platform": "loopdy"}
                with patch("loopdy_plugin.activity_bridge.time.monotonic", return_value=10):
                    publish_hook_activity("pre_llm_call", broker=broker, profile="default", payload=payload)
                asyncio.run(broker.detach())
                events = []
                broker.publish = lambda event: events.append(event) or True
                with patch("loopdy_plugin.activity_bridge.time.monotonic", return_value=20):
                    finish_failed_turn_activity(broker=broker, payload={**payload, terminal_flag: True})
                self.assertEqual(events, [])
                self.assertEqual(store.turn_durations("stored-session"), {})
                self.assertNotIn(("stored-session", "turn-0001"), broker._turn_started)
                broker.bind_link_session("stored-session", "visible-session")
                with patch("loopdy_plugin.activity_bridge.time.monotonic", return_value=90000):
                    publish_hook_activity("pre_llm_call", broker=broker, profile="default", payload=payload)
                    finish_failed_turn_activity(broker=broker, payload={**payload, terminal_flag: True})
                self.assertFalse(broker.is_active("stored-session", "turn-0001"))
                self.assertFalse(broker.start_turn_timing("stored-session", "turn-0001"))
                self.assertEqual(events, [])
                self.assertEqual(store.turn_durations("stored-session"), {})

    def test_canonical_fractional_timestamp_join_survives_history_pagination(self):
        import asyncio
        from types import SimpleNamespace
        from hermes_state import SessionDB
        from loopdy_plugin.workspace_control import HermesWorkspaceBackend

        with tempfile.TemporaryDirectory() as directory:
            db = SessionDB(Path(directory) / "state.db")
            db.create_session("stored-session", "loopdy")
            try:
                db.append_message("stored-session", "user", "Work", timestamp=100.125)
                db.append_message("stored-session", "assistant", "Done", timestamp=120.25)
                db.append_message("stored-session", "user", "Next", timestamp=90000.125)
                db.append_message("stored-session", "assistant", "Done again", timestamp=90002.25)
                canonical = db.get_messages("stored-session", limit=2, offset=2, latest=True)
                self.assertEqual(canonical[-1]["timestamp"], 120.25)
                store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
                store.record_turn_duration("stored-session", "turn-0001", 120.25, 20125)
                class Backend(HermesWorkspaceBackend):
                    async def _session_messages(self, *args, **kwargs):
                        return {"session_id": "stored-session", "messages": db.get_messages(
                            "stored-session", limit=2, offset=kwargs.get("offset", 0), latest=True,
                            include_compacted=kwargs.get("include_compacted", True)
                        )}
                    async def _session_runtime(self, stored_id, agent_id):
                        return None
                backend = Backend(service=SimpleNamespace(store=store))
                with patch("hermes_cli.web_routers.sessions._open_session_db_for_profile",
                           side_effect=lambda *args, **kwargs: SessionDB(Path(directory) / "state.db", read_only=True)):
                    current = asyncio.run(backend.sessions_history({"storedId": "stored-session", "agentId": "default"}))
                    self.assertNotIn("turn_duration_ms", current["messages"][-1])
                    older = asyncio.run(backend.sessions_history({"storedId": "stored-session", "agentId": "default", "offset": 2}))
                    self.assertEqual(older["messages"][-1]["turn_duration_ms"], 20125)
                    self.assertEqual(older["messages"][-1]["timestamp"], 120.25)
            finally:
                db.close()

    def test_cross_page_timestamp_ambiguity_stays_unknown(self):
        import asyncio
        from types import SimpleNamespace
        from hermes_state import SessionDB
        from loopdy_plugin.workspace_control import HermesWorkspaceBackend

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            db = SessionDB(path)
            try:
                db.create_session("stored-session", "loopdy")
                db.append_message("stored-session", "assistant", "Measured answer", timestamp=120.25)
                filler_count = 500
                for index in range(filler_count):
                    db.append_message("stored-session", "user", f"Intervening row {index}", timestamp=200 + index)
                db.append_message("stored-session", "assistant", "Untimed other answer", timestamp=120.25)
                store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
                store.record_turn_duration("stored-session", "turn-0001", 120.25, 20125)

                class Backend(HermesWorkspaceBackend):
                    async def _session_messages(self, stored_id, agent_id, **kwargs):
                        return {"session_id": stored_id, "messages": db.get_messages(
                            stored_id, limit=1, offset=kwargs.get("offset", 0),
                            latest=True, include_compacted=True,
                        )}
                    async def _session_runtime(self, stored_id, agent_id):
                        return None

                backend = Backend(service=SimpleNamespace(store=store))
                with patch("hermes_cli.web_routers.sessions._open_session_db_for_profile",
                           side_effect=lambda *args, **kwargs: SessionDB(path, read_only=True)):
                    for offset in (0, filler_count + 1):
                        with self.subTest(offset=offset):
                            result = asyncio.run(backend.sessions_history({
                                "storedId": "stored-session", "agentId": "default", "offset": offset,
                            }))
                            self.assertEqual(len(result["messages"]), 1)
                            self.assertNotIn("turn_duration_ms", result["messages"][0])
            finally:
                db.close()

    def test_missing_start_and_overlong_turn_stay_unknown(self):
        broker = LinkActivityBroker()
        self.assertEqual(broker.finish_turn_timing("session", "unknown-turn", {}), (True, None))
        with patch("loopdy_plugin.activity_bridge.time.monotonic", return_value=0):
            broker.start_turn_timing("session", "long-turn")
        with patch("loopdy_plugin.activity_bridge.time.monotonic", return_value=86_401):
            self.assertEqual(broker.finish_turn_timing("session", "long-turn", {}), (True, None))

    def test_history_store_failure_does_not_hide_messages(self):
        import asyncio
        import sqlite3
        from types import SimpleNamespace
        from loopdy_plugin.workspace_control import HermesWorkspaceBackend
        class Backend(HermesWorkspaceBackend):
            async def _session_messages(self, *args, **kwargs):
                return {"messages": [{"id": 1, "role": "assistant", "content": "Done"}]}
            async def _session_runtime(self, stored_id, agent_id):
                return None
        def unavailable(_):
            raise sqlite3.OperationalError("locked")
        backend = Backend(service=SimpleNamespace(store=SimpleNamespace(turn_durations=unavailable)))
        result = asyncio.run(backend.sessions_history({"storedId": "stored-session", "agentId": "default"}))
        self.assertEqual(result["messages"][0]["content"], "Done")

    def test_history_exports_only_exact_unique_final_timestamp(self):
        import asyncio
        from types import SimpleNamespace
        from loopdy_plugin.workspace_control import HermesWorkspaceBackend

        class Backend(HermesWorkspaceBackend):
            async def _session_messages(self, *args, **kwargs):
                return {"messages": self.rows}
            async def _session_runtime(self, stored_id, agent_id):
                return None

        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.record_turn_duration("stored-session", "turn-0001", 120.25, 0)
            backend = Backend(service=SimpleNamespace(store=store))
            backend.rows = [{"id": 1, "role": "assistant", "content": "Done", "timestamp": 120.25}]
            canonical_db = SimpleNamespace(get_messages=lambda *args, **kwargs: backend.rows, close=lambda: None)
            with patch("hermes_cli.web_routers.sessions._open_session_db_for_profile", return_value=canonical_db):
                result = asyncio.run(backend.sessions_history({"storedId": "stored-session", "agentId": "default"}))
                self.assertEqual(result["messages"][0].get("turn_duration_ms"), 0)
                backend.rows.append({**backend.rows[0], "id": 2})
                result = asyncio.run(backend.sessions_history({"storedId": "stored-session", "agentId": "default"}))
                self.assertTrue(all("turn_duration_ms" not in row for row in result["messages"]))
            # An older/incompatible canonical API must not fall back to page-local matching.
            for error in (ImportError("unavailable"), TypeError("unsupported API"), OSError("unreadable")):
                with self.subTest(error=type(error).__name__), patch(
                    "hermes_cli.web_routers.sessions._open_session_db_for_profile", side_effect=error,
                ):
                    backend.rows = backend.rows[:1]
                    result = asyncio.run(backend.sessions_history({"storedId": "stored-session", "agentId": "default"}))
                    self.assertEqual(result["messages"][0]["content"], "Done")
                    self.assertNotIn("turn_duration_ms", result["messages"][0])

    def test_terminal_duration_survives_store_reopen_and_duplicate_hooks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "loopdy.sqlite3"
            broker = LinkActivityBroker()
            broker.attach_duration_store(LoopdyStore(path))
            broker.bind_link_session("stored-session", "visible-session")
            events = []
            broker.publish = lambda payload: events.append(payload) or True
            payload = {"session_id": "stored-session", "turn_id": "turn-0001", "platform": "loopdy"}
            with patch("loopdy_plugin.activity_bridge.time.monotonic", return_value=10):
                publish_hook_activity("pre_llm_call", broker=broker, profile="default", payload=payload, occurred_at=100)
            with patch("loopdy_plugin.activity_bridge.time.monotonic", return_value=15):
                publish_hook_activity("pre_llm_call", broker=broker, profile="default", payload=payload, occurred_at=105)
            final = {**payload, "conversation_history": [{"role": "assistant", "content": "Done", "timestamp": 120.25}]}
            with patch("loopdy_plugin.activity_bridge.time.monotonic", return_value=30.125):
                publish_hook_activity("post_llm_call", broker=broker, profile="default", payload=final, occurred_at=120)
            with patch("loopdy_plugin.activity_bridge.time.monotonic", return_value=90000):
                publish_hook_activity("post_llm_call", broker=broker, profile="default", payload=final, occurred_at=90100)
                publish_hook_activity("pre_llm_call", broker=broker, profile="default", payload=payload, occurred_at=90100)
            terminal = [event for event in events if event.get("lifecycle") == "succeeded"]
            self.assertEqual([event.get("durationMs") for event in terminal], [20125])
            self.assertEqual(LoopdyStore(path).turn_durations("stored-session"), {120.25: 20125})
            self.assertEqual(LoopdyStore(path).turn_durations("another-session"), {})
            self.assertFalse(broker.is_active("stored-session", "turn-0001"))
