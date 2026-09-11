import unittest
from loopdy_plugin.session_stream import SessionStreamHub


class SessionPresentationTests(unittest.TestCase):
    def test_snapshot_covers_only_published_versions_and_preserves_complete_draft(self):
        from loopdy_plugin.session_presentation import SessionPresentationStore
        store = SessionPresentationStore(SessionStreamHub())
        def draft(text):
            return {"version": 1, "type": "assistant.message", "sessionId": "session-one", "agentId": "default",
                    "messageId": "draft-one", "delivery": "draft", "text": text}
        store.publish(agent_id="default", payload=draft("partial"))
        cursor = store.publish(agent_id="default", payload=draft("complete current partial"))
        snapshot = store.snapshot(agent_id="default", session_id="session-one")
        self.assertEqual(snapshot["coverageCursor"], cursor)
        self.assertEqual(snapshot["events"], [draft("complete current partial")])
        snapshot["events"][0]["text"] = "must not mutate cache"
        self.assertEqual(store.snapshot(agent_id="default", session_id="session-one")["events"][0]["text"], "complete current partial")
        self.assertEqual(store.snapshot(agent_id="other", session_id="session-one")["events"], [])
        store.close()
        self.assertEqual(store.snapshot(agent_id="default", session_id="session-one")["events"], [])

    def test_oversized_new_state_cannot_leave_a_false_complete_old_snapshot(self):
        from loopdy_plugin.session_presentation import SessionPresentationStore
        store=SessionPresentationStore(SessionStreamHub(), maximum_bytes=256)
        base={"type":"assistant.message","sessionId":"chat","messageId":"draft","text":"old"}
        store.publish(agent_id="default",payload=base)
        with self.assertRaises(ValueError):
            store.publish(agent_id="default",payload={**base,"text":"x"*300})
        self.assertFalse(store.snapshot(agent_id="default",session_id="chat")["complete"])

    def test_later_updates_preserve_original_event_position(self):
        from loopdy_plugin.session_presentation import SessionPresentationStore
        store = SessionPresentationStore(SessionStreamHub())
        for event_id, text in (("first", "running"), ("second", "running"), ("first", "completed")):
            store.publish(agent_id="default", payload={"type": "activity.event", "sessionId": "chat", "eventId": event_id, "text": text})
        events = store.snapshot(agent_id="default", session_id="chat")["events"]
        self.assertEqual([event["eventId"] for event in events], ["first", "second"])
        self.assertEqual(events[0]["text"], "completed")

    def test_bounded_snapshot_marks_eviction_incomplete(self):
        from loopdy_plugin.session_presentation import SessionPresentationStore
        store = SessionPresentationStore(SessionStreamHub(), maximum_events=2)
        for index in range(4):
            store.publish(agent_id="default", payload={"type": "activity.event", "sessionId": "chat", "eventId": str(index)})
        snapshot = store.snapshot(agent_id="default", session_id="chat")
        self.assertLessEqual(len(snapshot["events"]), 2)
        self.assertFalse(snapshot["complete"])
