from __future__ import annotations

import unittest
from urllib.parse import quote

from loopdy_plugin.events import build_event


class EventBuilderTests(unittest.TestCase):
    def test_push_payload_is_an_opaque_wakeup_signal(self) -> None:
        event = build_event(
            "approval.required",
            correlation=("approval", "request-123"),
            profile="default",
            session_id="session-456",
            approval_id="approval-789",
            detail={"command": "cat /private/file", "description": "Read private file"},
        )

        self.assertEqual(
            event.push_payload,
            {
                "schema_version": 1,
                "event_id": event.event_id,
                "type": "approval.required",
                "deep_link": f"loopdy:///dashboard?eventId={quote(event.event_id, safe='')}",
            },
        )
        self.assertNotIn("command", str(event.push_payload))
        self.assertNotIn("private", str(event.push_payload))

        task = build_event(
            "task.updated",
            correlation=("task", "task-123", "completed"),
            task_id="task-123",
        )
        self.assertEqual(
            task.deep_link,
            f"loopdy:///dashboard?eventId={quote(task.event_id, safe='')}",
        )

        message = build_event(
            "channel.message",
            correlation=("message", "message-123"),
            detail={"message": "Proactive hello"},
        )
        self.assertEqual(message.type, "channel.message")
        self.assertNotIn("Proactive hello", str(message.push_payload))

        completion = build_event(
            "job.completed",
            correlation=("job", "job-123", "turn-456"),
            profile="default",
            session_id="cron_job-123_20260815_120000",
            job_id="job-123",
            task_id="job-123",
            detail={
                "job_title": "Private morning weather",
                "summary": "Private persisted result",
                "status": "completed",
            },
        )
        self.assertEqual(
            completion.push_payload,
            {
                "schema_version": 1,
                "event_id": completion.event_id,
                "type": "job.completed",
                "deep_link": completion.deep_link,
            },
        )
        self.assertNotIn("Private morning weather", repr(completion.push_payload))
        self.assertNotIn("Private persisted result", repr(completion.push_payload))


if __name__ == "__main__":
    unittest.main()
