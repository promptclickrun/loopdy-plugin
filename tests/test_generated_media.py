from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from loopdy_plugin import generated_media as media
from loopdy_plugin.attachments import AttachmentStore


class GeneratedMediaTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.home = patch.object(media, "get_hermes_home", return_value=self.root)
        self.home.start()
        self.policy = patch.dict("os.environ", {
            "HERMES_MEDIA_DELIVERY_STRICT": "1",
            "HERMES_MEDIA_ALLOW_DIRS": str(self.root),
            "HERMES_MEDIA_TRUST_RECENT_FILES": "0",
        })
        self.policy.start()
        self.store = AttachmentStore(self.root / "attachments.sqlite3")

    def tearDown(self):
        self.policy.stop()
        self.home.stop()
        self.directory.cleanup()

    def rows(self, calls):
        return [{"id": 41, "role": "user", "content": "generate"},
                {"id": 42, "role": "assistant", "tool_calls": [
                    {"id": name, "function": {"name": tool, "arguments": "{}"}}
                    for name, tool, _ in calls]},
                *[{"id": 50 + i, "role": "tool", "tool_call_id": name, "content": text}
                  for i, (name, _, text) in enumerate(reversed(calls))]]

    def resolve(self, rows, call="call_a", turn="history-turn-41", profile="default"):
        return media.resolve_generated_media(profile=profile, stored_id="session_a", turn_id=turn,
                                              tool_call_id=call, rows=rows, attachment_store=self.store)

    def test_exact_names_and_deferred_names_only(self):
        self.assertEqual(media.effective_generation_kind("image_generate", {}), "image")
        self.assertEqual(media.effective_generation_kind("video_generate", {}), "video")
        self.assertEqual(media.effective_generation_kind("tool_call", '{"name":"image_generate"}'), "image")
        self.assertIsNone(media.effective_generation_kind("terminal", {"command": "image_generate"}))
        self.assertIsNone(media.effective_generation_kind("image_generate_lookalike", {}))

    def test_reversed_concurrent_results_stay_with_their_calls(self):
        first = self.root / "first.png"
        second = self.root / "second.png"
        first.write_bytes(b"\x89PNG\r\n\x1a\nfirst-test-fixture")
        second.write_bytes(b"\x89PNG\r\n\x1a\nsecond-test-fixture")
        rows = self.rows([("call_a", "image_generate", f"MEDIA:{first}"),
                          ("call_b", "image_generate", f"MEDIA:{second}")])
        a = self.resolve(rows)
        b = self.resolve(rows, call="call_b")
        self.assertEqual(a["state"], "ready")
        self.assertEqual(b["state"], "ready")
        self.assertEqual(a["attachments"][0]["fileName"], "first.png")
        self.assertEqual(b["attachments"][0]["fileName"], "second.png")
        self.assertNotEqual(a["attachments"][0]["id"], b["attachments"][0]["id"])
        self.assertNotIn(str(self.root), json.dumps(a))

    def test_real_provider_json_local_image_and_video_fields_resolve(self):
        for tool, key, name in [("image_generate", "image", "provider.png"),
                                ("video_generate", "video", "provider.mp4")]:
            with self.subTest(tool=tool):
                artifact = self.root / name
                artifact.write_bytes(b"local-provider-result-fixture")
                result_json = json.dumps({"success": True, key: str(artifact), "provider": "fixture"})
                rows = self.rows([("call_a", tool, result_json)])
                result = self.resolve(rows)
                self.assertEqual(result["state"], "ready")
                self.assertEqual(result["attachments"][0]["fileName"], name)

    def test_live_hook_coordinate_resolves_when_link_and_stored_sessions_differ(self):
        from loopdy_plugin.activity_bridge import LinkActivityBroker, publish_hook_activity

        class Broker(LinkActivityBroker):
            def __init__(self):
                super().__init__()
                self.payloads = []

            def publish(self, payload):
                self.payloads.append(payload)
                return True

        broker = Broker()
        internal_turn = "session_a:turn:live"
        broker.activate("session_a", internal_turn, link_session_id="link_session_a")
        image = self.root / "live.png"
        image.write_bytes(b"\\x89PNG\\r\\n\\x1a\\nfixture")
        result = json.dumps({"success": True, "image": str(image)})
        publish_hook_activity("post_tool_call", broker=broker, profile="default", payload={
            "session_id": "session_a", "turn_id": internal_turn, "tool_name": "image_generate",
            "tool_call_id": "call_a", "args": {}, "status": "ok", "result": result,
        }, occurred_at=1_788_000_031)
        emitted = broker.payloads[-1]
        rows = self.rows([("call_a", "image_generate", result)])
        self.assertEqual(self.resolve(rows, turn=emitted["turnId"])["state"], "ready")

    def test_workspace_resolves_exact_recent_call_in_long_history(self):
        import asyncio
        from loopdy_plugin.workspace_control import HermesWorkspaceBackend

        image = self.root / "long-history.png"
        image.write_bytes(b"fixture")
        recent = self.rows([("call_a", "image_generate", json.dumps({"success": True, "image": str(image)}))])
        for index, row in enumerate(recent):
            row["id"] = 601 + index
        rows = [{"id": index + 1, "role": "assistant", "content": "Earlier text"} for index in range(600)] + recent

        class Backend(HermesWorkspaceBackend):
            async def _session_messages(inner, stored_id, agent_id, **kwargs):
                self.assertEqual((stored_id, agent_id), ("session_a", "default"))
                return {"session_id": stored_id, "messages": rows}

        backend = Backend(service=None, attachment_store=self.store)
        result = asyncio.run(backend.generated_media_resolve({
            "agentId": "default", "storedId": "session_a", "turnId": "history-turn-601", "toolCallId": "call_a",
        }))
        self.assertEqual(result["state"], "ready")

    def test_live_resolution_survives_history_projection_after_source_removal(self):
        image = self.root / "live-to-history.png"
        image.write_bytes(b"fixture")
        rows = self.rows([("call_a", "image_generate", json.dumps({"success": True, "image": str(image)}))])
        media.record_generated_media_call(profile="default", stored_id="session_a", turn_id="native-turn",
                                          tool_call_id="call_a", tool_name="image_generate", arguments={},
                                          link_session_id="link-session")
        live_turn = media._external_turn_id("link-session", "native-turn")
        first = self.resolve(rows, turn=live_turn)
        self.assertEqual(first["state"], "ready")
        image.unlink()
        restored = self.resolve(rows)
        self.assertEqual(restored["state"], "ready")
        self.assertEqual(restored["attachments"], first["attachments"])

    def test_wrong_turn_does_not_resolve_any_artifact(self):
        image = self.root / "private.png"
        image.write_bytes(b"\x89PNG\r\n\x1a\nfixture")
        rows = self.rows([("call_a", "image_generate", f"MEDIA:{image}")])
        self.assertEqual(self.resolve(rows, turn="history-turn-999")["state"], "unavailable")

    def test_reopening_uses_cached_bytes_after_source_is_removed(self):
        image = self.root / "result.png"
        image.write_bytes(b"\x89PNG\r\n\x1a\nfixture")
        rows = self.rows([("call_a", "image_generate", f"MEDIA:{image}")])
        first = self.resolve(rows)
        self.assertEqual(first["state"], "ready")
        image.unlink()
        self.store = AttachmentStore(self.root / "attachments.sqlite3")
        self.assertEqual(self.resolve(rows), first)

    def test_duplicate_call_identity_fails_closed(self):
        rows = self.rows([("call_a", "image_generate", "MEDIA:/missing.png"),
                          ("call_a", "image_generate", "MEDIA:/other.png")])
        with self.assertRaises(ValueError):
            self.resolve(rows)

    def test_file_policy_remains_authoritative(self):
        rows = self.rows([("call_a", "image_generate", "MEDIA:/etc/passwd")])
        self.assertEqual(self.resolve(rows)["attachments"], [])

    def test_oversized_video_is_explicit_and_not_returned(self):
        video = self.root / "large.mp4"
        video.write_bytes(b"\0" * (media.MAX_NATIVE_ARTIFACT_BYTES + 1))
        rows = self.rows([("call_a", "video_generate", f"MEDIA:{video}")])
        result = self.resolve(rows)
        self.assertEqual(result["state"], "oversized")
        self.assertEqual(result["attachments"], [])
        self.assertEqual(result["omittedCount"], 1)

    def test_ledger_is_profile_session_and_call_scoped(self):
        image = self.root / "result.png"
        image.write_bytes(b"\x89PNG\r\n\x1a\nfixture")
        rows = self.rows([("call_a", "image_generate", f"MEDIA:{image}")])
        media.record_generated_media_call(profile="default", stored_id="session_a", turn_id="live_turn",
                                          tool_call_id="call_a", tool_name="image_generate", arguments={})
        live = media._external_turn_id("session_a", "live_turn")
        self.assertEqual(self.resolve(rows, turn=live)["state"], "ready")
        self.assertEqual(self.resolve(rows, turn=live, profile="other")["state"], "unavailable")


if __name__ == "__main__":
    unittest.main()
