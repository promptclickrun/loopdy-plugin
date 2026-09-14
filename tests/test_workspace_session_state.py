from __future__ import annotations

import asyncio
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from hermes_state import SessionDB
from loopdy_plugin.link_contracts import WorkspaceRequest, workspace_capabilities
from loopdy_plugin.workspace_control import HermesWorkspaceBackend, WorkspaceController, WorkspaceControlError


class WorkspaceSessionStateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db = SessionDB(Path(self.directory.name) / "state.db")
        self.db.create_session("stored-one", source="loopdy", profile_name="default")
        self.ids = [self.db.append_message("stored-one", "user", f"Message {i}") for i in range(40)]
        self.backend = HermesWorkspaceBackend(service=SimpleNamespace())
        self.backend._session_runtime = AsyncMock(return_value={"model": "test-model"})
        self.backend._session_catalog = AsyncMock(return_value={"sessions": [{"id": "stored-one", "chat_id": "visible-one"}]})
        self.backend._session_messages = AsyncMock(side_effect=AssertionError("Legacy transcript read"))
        self.opener = patch("loopdy_plugin.session_state.open_profile_store", side_effect=self.open_db)
        self.opener_threads = []
        self.opener.start()

    def open_db(self, profile, callback, *, read_only):
        self.opener_threads.append(threading.get_ident())
        self.assertEqual(profile, "default")
        self.assertTrue(read_only)
        return callback(self.db)

    def tearDown(self):
        self.opener.stop()
        self.db.close()
        self.directory.cleanup()

    async def request(self, operation, **payload):
        request = WorkspaceRequest(request_id="state-request-0001", operation=operation,
                                   payload={"agentId": "default", "storedId": "stored-one", **payload}, sent_at=1)
        return await WorkspaceController(backend=self.backend).execute(request)

    async def test_state_operation_returns_recent_canonical_page_and_continuation(self):
        recent = await self.request("sessions.state")
        self.assertEqual([m["row_id"] for m in recent["messages"]], self.ids[-24:])
        self.assertEqual(recent["runtime"], {"model": "test-model"})
        earlier = await self.request("sessions.state", cursor=recent["nextCursor"])
        self.assertEqual([m["row_id"] for m in earlier["messages"]], self.ids[:-24])
        self.backend._session_messages.assert_not_called()
        self.backend._session_catalog.assert_not_called()
        self.assertIn("sessions.state", workspace_capabilities()["operations"])
        self.assertIn("sessions.content", workspace_capabilities()["operations"])
        self.assertIn("session-state-v1", workspace_capabilities()["features"])

    async def test_initial_visible_alias_uses_only_the_exact_profile_catalog(self):
        page = await self.request("sessions.state", storedId="visible-one")
        self.assertEqual(page["storedId"], "stored-one")
        self.backend._session_catalog.assert_awaited_once_with("default")
        self.assertEqual(page["sessionId"], "visible-one")

    async def test_cursor_scope_failure_cannot_be_reinterpreted_as_an_alias(self):
        page = await self.request("sessions.state")
        with self.assertRaises(WorkspaceControlError) as failure:
            await self.request("sessions.state", storedId="visible-one", cursor=page["nextCursor"])
        self.assertEqual(failure.exception.code, "session_state_invalid")
        self.backend._session_catalog.assert_not_called()

    async def test_rewind_returns_explicit_reset_without_legacy_fallback(self):
        page = await self.request("sessions.state")
        self.db.rewind_to_message("stored-one", self.ids[5])
        with self.assertRaises(WorkspaceControlError) as failure:
            await self.request("sessions.state", cursor=page["nextCursor"])
        self.assertEqual(failure.exception.code, "session_state_reset")
        self.backend._session_messages.assert_not_called()

    async def test_full_content_is_retrieved_by_canonical_reference_off_loop(self):
        content = "result 👩🏽\u200d💻\n" * 10_000
        self.db.append_message("stored-one", "tool", content, tool_call_id="call-one")
        page = await self.request("sessions.state")
        reference = page["messages"][-1]["contentReference"]
        import json
        chunks, offset = [], 0
        while True:
            part = await self.request("sessions.content", reference=reference, offset=offset)
            chunks.append(part["text"])
            if "nextOffset" not in part:
                break
            offset = part["nextOffset"]
        self.assertEqual(json.loads("".join(chunks))["content"], content)
        self.assertTrue(self.opener_threads)
        self.assertTrue(all(thread != threading.get_ident() for thread in self.opener_threads))

    async def test_no_unknown_fields_or_bool_offsets_are_accepted(self):
        for operation, fields in [("sessions.state", {"url": "https://example.com"}),
                                  ("sessions.content", {"reference": {}, "offset": True})]:
            with self.subTest(operation=operation), self.assertRaises(WorkspaceControlError):
                await self.request(operation, **fields)

    async def test_top_level_scope_errors_have_the_state_error_code(self):
        for operation in ("sessions.state", "sessions.content"):
            for fields in ({"storedId": None}, {"agentId": 4}):
                with self.subTest(operation=operation, fields=fields), self.assertRaises(WorkspaceControlError) as failure:
                    options = {"reference": {}} if operation == "sessions.content" else {}
                    await self.request(operation, **options, **fields)
                self.assertEqual(failure.exception.code, "session_state_invalid")

    async def test_state_index_failure_is_explicit_and_never_loads_legacy_history(self):
        with patch("loopdy_plugin.session_state.display_index_ready", return_value=False):
            with self.assertRaises(WorkspaceControlError) as failure:
                await self.request("sessions.state")
        self.assertEqual(failure.exception.code, "session_state_unavailable")
        self.backend._session_messages.assert_not_called()
