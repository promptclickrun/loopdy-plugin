from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from loopdy_plugin.agent_board import (
    ActivityRecorder, BoardError, BoardStore, MAX_ITEMS_PER_KIND, handle_tool, tool_category,
)

PNG = b"\x89PNG\r\n\x1a\n" + b"x" * 32


class AgentBoardStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = BoardStore(self.root / "board")

    def test_posts_copy_images_and_reject_non_images(self):
        image = self.root / "porch.png"
        image.write_bytes(PNG)
        item = self.store.publish("feed", title="Porch", body="Bag delivered.", images=[str(image)])
        image.unlink()  # a cleaned cache must not break the post
        mime, data = self.store.image(item["id"], 0)
        self.assertEqual((mime, data), ("image/png", PNG))
        secret = self.root / "notes.txt"
        secret.write_text("private")
        with self.assertRaises(BoardError):
            self.store.publish("feed", title="Leak", images=[str(secret)])
        with self.assertRaises(BoardError):
            self.store.publish("feed", title="Relative", images=["porch.png"])
        with self.assertRaises(BoardError):
            self.store.publish("feed", title="", body="No title")
        with self.assertRaises(BoardError):
            self.store.publish("feed", title="Bad link", links=["javascript:alert(1)"])

    def test_goals_update_in_place_and_ideas_reuse_ids(self):
        self.store.publish("goal", title="Package watch", section="tracking", note="Ordered", item_id="pkg")
        self.store.update_goal("pkg", note="Out for delivery")
        again = self.store.publish("goal", title="Package watch", section="tracking", note="Delivered",
                                   item_id="pkg", status="done")
        goals = self.store.items(("goal",))
        self.assertEqual(len(goals), 1)
        self.assertEqual((goals[0]["note"], goals[0]["status"]), ("Delivered", "done"))
        self.assertEqual(again["createdAt"], goals[0]["createdAt"])
        with self.assertRaises(BoardError):
            self.store.publish("goal", title="Nope", section="wishlist")
        with self.assertRaises(BoardError):
            self.store.publish("idea", title="Clash", item_id="pkg")
        self.store.publish("idea", title="Audit Google access", section="Security", item_id="audit")
        self.store.publish("idea", title="Audit Google access now", section="Security", item_id="audit")
        self.assertEqual([idea["title"] for idea in self.store.items(("idea",))], ["Audit Google access now"])

    def test_dismissed_items_hide_and_republishing_restores(self):
        item = self.store.publish("idea", title="Sleep check-in", item_id="sleep")
        self.store.set_flags(item["id"], dismissed=True, liked=True)
        self.assertEqual(self.store.items(("idea",)), [])
        self.assertTrue(self.store.items(("idea",), include_dismissed=True)[0]["liked"])
        self.store.publish("idea", title="Sleep check-in", item_id="sleep")
        self.assertEqual(len(self.store.items(("idea",))), 1)

    def test_each_kind_is_capped(self):
        for index in range(MAX_ITEMS_PER_KIND + 3):
            self.store.publish("feed", title=f"Post {index}", now=1_000 + index)
        feed = self.store.items(("feed",), limit=200)
        self.assertEqual(feed[0]["title"], f"Post {MAX_ITEMS_PER_KIND + 2}")
        with self.store._db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM items").fetchone()[0], MAX_ITEMS_PER_KIND)

    def test_tool_reports_errors_to_the_agent_instead_of_raising(self):
        self.assertEqual(json.loads(handle_tool({"action": "post", "title": ""}, self.store)),
                         {"error": "title is required."})
        created = json.loads(handle_tool({"action": "idea", "title": "Track sleep", "icon": "🌙",
                                          "section": "Health"}, self.store))
        self.assertEqual((created["kind"], created["shownIn"]), ("idea", "Ideas"))
        listed = json.loads(handle_tool({"action": "list", "kind": "idea"}, self.store))
        self.assertEqual(listed["items"][0]["title"], "Track sleep")
        self.assertEqual(json.loads(handle_tool({"action": "remove", "id": created["id"]}, self.store)),
                         {"removed": True})
        self.assertIn("error", json.loads(handle_tool({"action": "launch"}, self.store)))


class ActivityRecorderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = BoardStore(Path(self.temporary.name))
        self.recorder = ActivityRecorder(lambda: self.store)

    def turn(self, tools, response="Done. The bag is by the chair.", **end):
        base = {"session_id": "s1", "turn_id": "t1"}
        self.recorder.observe("pre_llm_call", user_message="Did the dog food arrive? Check the porch.", **base)
        for tool in tools:
            self.recorder.observe("post_tool_call", tool_name=tool, **base)
        self.recorder.observe("post_llm_call", assistant_response=response, **base)
        self.recorder.observe("on_session_end", completed=True, **base, **end)

    def test_turns_that_used_tools_become_activity(self):
        self.turn(["vision_analyze", "vision_analyze", "memory"])
        row = self.store.activity()[0]
        self.assertEqual(row["request"], "Did the dog food arrive?")
        self.assertEqual(row["summary"], "Done.")
        self.assertEqual((row["category"], row["tools"], row["outcome"]), ("seeing", ["vision_analyze", "memory"], "done"))

    def test_plain_chat_and_subagents_are_not_activity(self):
        self.turn([])
        self.recorder.observe("pre_llm_call", session_id="child", turn_id="c", platform="subagent", user_message="x")
        self.assertEqual(self.store.activity(), [])

    def test_failed_and_stopped_turns_keep_their_outcome(self):
        self.turn(["terminal"], interrupted=True)
        self.assertEqual(self.store.activity()[0]["outcome"], "stopped")
        self.assertEqual(self.store.activity()[0]["category"], "coding")

    def test_approval_decisions_are_logged(self):
        self.recorder.observe("post_approval_response", session_id="s1", description="Delete a folder",
                              command="rm -rf build", choice="once")
        self.assertEqual(self.store.approvals()[0]["choice"], "once")

    def test_tool_categories(self):
        self.assertEqual(tool_category("image_generate"), "images")
        self.assertEqual(tool_category("browser_navigate"), "web")
        self.assertEqual(tool_category("execute_code"), "coding")
        self.assertEqual(tool_category("cronjob"), "scheduling")
        self.assertEqual(tool_category("mcp_linear_create_issue"), "tools")
