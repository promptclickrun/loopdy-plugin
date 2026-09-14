from __future__ import annotations

import json
import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hermes_state import SessionDB


class SessionStateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db = SessionDB(Path(self.directory.name) / "state.db")
        self.db.create_session("session-one", source="loopdy", profile_name="default")

    def tearDown(self):
        self.db.close()
        self.directory.cleanup()

    def reader(self, **kwargs):
        from loopdy_plugin.session_state import SessionStateReader
        return SessionStateReader(**kwargs)

    def append(self, count):
        start = self.db.get_session("session-one")["message_count"]
        return [self.db.append_message("session-one", "user", "Repeated text", timestamp=100 - start - index)
                for index in range(count)]

    def test_reader_does_not_call_private_hermes_helpers(self):
        self.append(8)
        backing = self.db
        class PublicSessionStore:
            def __getattr__(self, name):
                if name.startswith("_"):
                    raise AssertionError("private Hermes access: " + name)
                return getattr(backing, name)
        reader = self.reader(maximum_rows=4)
        page = reader.read(PublicSessionStore(), agent_id="default", stored_id="session-one")
        self.append(2)
        earlier = reader.read(PublicSessionStore(), agent_id="default", stored_id="session-one", cursor=page["nextCursor"])
        self.assertEqual(len(earlier["messages"]), 4)

    def test_replaced_display_generation_requires_a_fresh_snapshot(self):
        from loopdy_plugin.session_state import SessionStateResetRequired
        self.append(8)
        reader = self.reader(maximum_rows=4)
        page = reader.read(self.db, agent_id="default", stored_id="session-one")
        # Hermes intentionally uses the new row as an older display generation.
        self.db.append_message("session-one", "user", "Repeated text", timestamp=100)
        with self.assertRaises(SessionStateResetRequired):
            reader.read(self.db, agent_id="default", stored_id="session-one", cursor=page["nextCursor"])

    def test_recent_and_earlier_pages_use_canonical_rows_not_text_or_timestamps(self):
        ids = self.append(12)
        reader = self.reader(maximum_rows=4)
        with patch.object(self.db, "get_messages", wraps=self.db.get_messages) as reads:
            recent = reader.read(self.db, agent_id="default", stored_id="session-one")
            earlier = reader.read(self.db, agent_id="default", stored_id="session-one", cursor=recent["nextCursor"])
        self.assertEqual([row["row_id"] for row in recent["messages"]], ids[-4:])
        self.assertEqual([row["row_id"] for row in earlier["messages"]], ids[-8:-4])
        self.assertTrue(all(call.kwargs.get("limit", 0) <= 5 for call in reads.call_args_list))

    def test_append_rebases_earlier_cursor_without_duplicate_or_skipped_rows(self):
        ids = self.append(8)
        reader = self.reader(maximum_rows=4)
        page = reader.read(self.db, agent_id="default", stored_id="session-one")
        self.append(3)
        earlier = reader.read(self.db, agent_id="default", stored_id="session-one", cursor=page["nextCursor"])
        self.assertEqual([row["row_id"] for row in earlier["messages"]], ids[:4])
        self.assertNotIn("nextCursor", earlier)

    def test_duplicate_new_display_generations_count_once_when_rebasing(self):
        ids = self.append(8)
        reader = self.reader(maximum_rows=4)
        page = reader.read(self.db, agent_id="default", stored_id="session-one")
        for _ in range(2):
            self.db.append_message("session-one", "assistant", "New duplicated generation", timestamp=200)
        earlier = reader.read(self.db, agent_id="default", stored_id="session-one", cursor=page["nextCursor"])
        self.assertEqual([row["row_id"] for row in earlier["messages"]], ids[:4])

    def test_rewind_invalidates_cursor_instead_of_showing_removed_rows(self):
        from loopdy_plugin.session_state import SessionStateResetRequired
        ids = self.append(8)
        reader = self.reader(maximum_rows=4)
        page = reader.read(self.db, agent_id="default", stored_id="session-one")
        self.db.rewind_to_message("session-one", ids[3])
        with self.assertRaises(SessionStateResetRequired):
            reader.read(self.db, agent_id="default", stored_id="session-one", cursor=page["nextCursor"])

    def test_compaction_invalidates_cursor_and_keeps_hermes_display_history(self):
        from loopdy_plugin.session_state import SessionStateResetRequired
        self.append(8)
        reader = self.reader(maximum_rows=4)
        page = reader.read(self.db, agent_id="default", stored_id="session-one")
        self.db.archive_and_compact("session-one", [{"role": "user", "content": "Compacted context"}])
        with self.assertRaises(SessionStateResetRequired):
            reader.read(self.db, agent_id="default", stored_id="session-one", cursor=page["nextCursor"])
        snapshot = reader.read(self.db, agent_id="default", stored_id="session-one")
        canonical = self.db.get_messages("session-one", latest=True, limit=4, include_compacted=True)
        self.assertEqual([row["row_id"] for row in snapshot["messages"]], [row["id"] for row in canonical])

    def test_large_result_has_bounded_preview_and_lossless_explicit_content_read(self):
        content = "👩🏽\u200d💻 original result\n" * 12_000
        row_id = self.db.append_message("session-one", "tool", content, tool_name="fixture", tool_call_id="call-one")
        reader = self.reader(maximum_bytes=8_192, maximum_row_bytes=2_048)
        page = reader.read(self.db, agent_id="default", stored_id="session-one")
        encoded = json.dumps(page, ensure_ascii=False, separators=(",", ":")).encode()
        self.assertLessEqual(len(encoded), 8_192)
        self.assertEqual(page["messages"][0]["row_id"], row_id)
        reference = page["messages"][0]["contentReference"]
        offset, chunks = 0, []
        while True:
            part = reader.content(self.db, agent_id="default", stored_id="session-one", reference=reference, offset=offset)
            self.assertLessEqual(len(part["text"].encode()), 65_536)
            chunks.append(part["text"])
            if "nextOffset" not in part:
                break
            offset = part["nextOffset"]
        restored = json.loads("".join(chunks))
        self.assertEqual(restored["content"], content)
        self.assertEqual(restored["tool_call_id"], "call-one")

    def test_cursor_and_content_reference_cannot_cross_profile_or_session(self):
        self.append(8)
        reader = self.reader(maximum_rows=4)
        page = reader.read(self.db, agent_id="default", stored_id="session-one")
        with self.assertRaises(ValueError):
            reader.read(self.db, agent_id="another", stored_id="session-one", cursor=page["nextCursor"])
        with self.assertRaises(ValueError):
            reader.read(self.db, agent_id="default", stored_id="session-two", cursor=page["nextCursor"])

    def test_large_content_reference_rejects_wrong_scope_and_rewound_result(self):
        from loopdy_plugin.session_state import SessionStateResetRequired
        user = self.db.append_message("session-one", "user", "Question")
        self.db.append_message("session-one", "tool", "Large result " * 10_000)
        reader = self.reader()
        reference = reader.read(self.db, agent_id="default", stored_id="session-one")["messages"][-1]["contentReference"]
        for agent_id, stored_id in [("other", "session-one"), ("default", "other-session")]:
            with self.assertRaises(ValueError):
                reader.content(self.db, agent_id=agent_id, stored_id=stored_id, reference=reference)
        self.db.rewind_to_message("session-one", user)
        with self.assertRaises(SessionStateResetRequired):
            reader.content(self.db, agent_id="default", stored_id="session-one", reference=reference)

    def test_content_reference_is_invalidated_when_resume_tip_moves(self):
        from loopdy_plugin.session_state import SessionStateResetRequired
        self.db.append_message("session-one", "tool", "Large result " * 10_000)
        reader = self.reader()
        reference = reader.read(self.db, agent_id="default", stored_id="session-one")["messages"][-1]["contentReference"]
        self.db.create_session("new-tip", source="loopdy", parent_session_id="session-one")
        self.db.append_message("new-tip", "assistant", "New answer")
        with self.assertRaises(SessionStateResetRequired):
            reader.content(self.db, agent_id="default", stored_id="session-one", reference=reference)

    def test_missing_profile_does_not_fall_back_to_default(self):
        reader = self.reader()
        with patch("loopdy_plugin.session_state.open_profile_store", side_effect=LookupError("Profile unavailable")) as opener:
            with self.assertRaises(LookupError):
                asyncio.run(reader.read_profile(agent_id="missing", stored_id="session-one"))
        self.assertEqual(opener.call_count, 1)
        self.assertEqual(opener.call_args.args[0], "missing")
        self.assertTrue(opener.call_args.kwargs["read_only"])

    def test_resume_alias_returns_the_canonical_descendant_and_rejects_old_cursor(self):
        from loopdy_plugin.session_state import SessionStateResetRequired
        self.append(8)
        reader = self.reader(maximum_rows=4)
        page = reader.read(self.db, agent_id="default", stored_id="session-one")
        self.db.create_session("session-continuation", source="loopdy", parent_session_id="session-one")
        row_id = self.db.append_message("session-continuation", "assistant", "Continued answer")
        current = reader.read(self.db, agent_id="default", stored_id="session-one")
        self.assertEqual(current["storedId"], "session-continuation")
        self.assertEqual([row["row_id"] for row in current["messages"]], [row_id])
        with self.assertRaises(SessionStateResetRequired):
            reader.read(self.db, agent_id="default", stored_id="session-one", cursor=page["nextCursor"])

    def test_profile_reader_uses_the_hermes_opener_on_a_background_thread(self):
        import threading
        reader = self.reader()
        self.append(2)
        main_thread = threading.get_ident()
        threads = []

        def open_profile(profile, callback, *, read_only):
            self.assertEqual(profile, "default")
            self.assertTrue(read_only)
            threads.append(threading.get_ident())
            return callback(self.db)

        with patch("loopdy_plugin.session_state.open_profile_store", side_effect=open_profile):
            result = asyncio.run(reader.read_profile(agent_id="default", stored_id="session-one"))
        self.assertEqual(len(result["messages"]), 2)
        self.assertNotEqual(threads, [main_thread])

    def test_resume_tip_change_during_snapshot_does_not_publish_the_old_tip(self):
        self.append(8)
        reader = self.reader(maximum_rows=4)
        original = self.db.get_messages
        moved = False

        def get_messages(*args, **kwargs):
            nonlocal moved
            rows = original(*args, **kwargs)
            if not moved:
                moved = True
                self.db.create_session("new-tip", source="loopdy", parent_session_id="session-one")
                self.db.append_message("new-tip", "assistant", "Current answer")
            return rows

        with patch.object(self.db, "get_messages", side_effect=get_messages):
            page = reader.read(self.db, agent_id="default", stored_id="session-one")
        self.assertEqual(page["storedId"], "new-tip")
        self.assertEqual(page["messages"][0]["content"], "Current answer")

    def test_legacy_unindexed_history_does_not_trigger_a_full_transcript_read(self):
        from loopdy_plugin.session_state import SessionStateUnavailable
        reader = self.reader()
        with patch("loopdy_plugin.session_state.display_index_ready", return_value=False), patch.object(self.db, "get_messages") as read:
            with self.assertRaises(SessionStateUnavailable):
                reader.read(self.db, agent_id="default", stored_id="session-one")
        read.assert_not_called()

    def test_response_and_preview_limits_include_json_escaping(self):
        for _ in range(20):
            self.db.append_message("session-one", "tool", "\x01" * 10_000, tool_name="n" * 180, tool_call_id="c" * 180)
        reader = self.reader(maximum_bytes=4_096, maximum_row_bytes=1_024)
        cursor = None
        read_ids = []
        while True:
            page = reader.read(self.db, agent_id="default", stored_id="session-one", cursor=cursor)
            self.assertLessEqual(len(json.dumps(page, ensure_ascii=False, separators=(",", ":")).encode()), 4_096)
            self.assertTrue(page["messages"])
            for row in page["messages"]:
                self.assertLessEqual(len(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode()), 1_024)
                read_ids.append(row["row_id"])
            cursor = page.get("nextCursor")
            if cursor is None:
                break
        self.assertEqual(len(set(read_ids)), 20)

    def test_mutation_during_read_is_reconciled_before_returning(self):
        ids = self.append(8)
        reader = self.reader(maximum_rows=4)
        original = self.db.get_messages
        mutated = False

        def get_messages(*args, **kwargs):
            nonlocal mutated
            rows = original(*args, **kwargs)
            if not mutated:
                mutated = True
                self.db.rewind_to_message("session-one", ids[3])
            return rows

        with patch.object(self.db, "get_messages", side_effect=get_messages):
            page = reader.read(self.db, agent_id="default", stored_id="session-one")
        self.assertTrue(all(row["row_id"] < ids[3] for row in page["messages"]))


if __name__ == "__main__":
    unittest.main()
