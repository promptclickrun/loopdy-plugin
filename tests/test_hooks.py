from __future__ import annotations

import unittest

from loopdy_plugin.hooks import normalize_hook
from loopdy_plugin.presentation import shape_notification


class HookNormalizationTests(unittest.TestCase):
    def test_neutral_session_end_is_not_misclassified_as_failure(self) -> None:
        cases = (
            {
                "platform": "cron",
                "session_id": "cron_job-123_20260815_120000",
                "completed": False,
                "failed": False,
            },
            {
                "platform": "webui",
                "session_id": "session-max-iterations",
                "completed": False,
            },
        )
        for payload in cases:
            with self.subTest(payload=payload):
                self.assertIsNone(
                    normalize_hook(
                        "on_session_end",
                        profile="default",
                        turn_id="turn-max-iterations",
                        assistant_response="A final response was still produced.",
                        **payload,
                    )
                )

    def test_successful_turn_is_not_a_completed_session(self) -> None:
        self.assertIsNone(
            normalize_hook(
                "post_llm_call",
                profile="default",
                platform="webui",
                session_id="session-still-open",
                turn_id="turn-1",
            )
        )

        self.assertIsNone(
            normalize_hook(
                "on_session_end",
                profile="default",
                platform="webui",
                session_id="session-still-open",
                session_title="Release readiness",
                turn_id="turn-2",
                completed=True,
                failed=False,
                assistant_response="private response",
            )
        )

    def test_normalizes_only_shipped_lifecycle_signals(self) -> None:
        attention = normalize_hook(
            "pre_tool_call",
            profile="default",
            tool_name="clarify",
            args={"question": "Which environment?"},
            session_id="session-1",
            turn_id="turn-1",
            tool_call_id="tool-1",
        )
        self.assertIsNone(attention)

        completed = normalize_hook(
            "on_session_end",
            profile="default",
            platform="cron",
            session_id="cron_job-123_20260815_120000",
            task_id="01234567-89ab-4cde-8fab-0123456789ab",
            turn_id="turn-2",
            completed=True,
            failed=False,
            task_name="Private morning weather",
            assistant_response="private response",
        )
        self.assertEqual(completed.type, "job.completed")
        self.assertEqual(completed.job_id, "job-123")
        self.assertEqual(completed.task_id, "job-123")
        self.assertEqual(completed.detail, {"status": "completed"})
        self.assertNotIn("private response", str(completed.detail))
        notification = shape_notification(completed)
        self.assertEqual(notification.title, "Completion alert")
        self.assertEqual(
            notification.body,
            "Scheduled task complete: Open Loopdy to view the scheduled task result.",
        )
        self.assertEqual(notification.data, {"loopdy": completed.push_payload})
        self.assertNotIn("Private morning weather", repr(notification))
        self.assertNotIn("private response", repr(notification))
        self.assertLessEqual(len(str(notification.data).encode("utf-8")), 1_024)

        compressed = normalize_hook(
            "on_session_end",
            profile="default",
            platform="cron",
            session_id="compression-tip-0001",
            task_id="fedcba98-7654-4cba-8765-fedcba987654",
            turn_id="turn-3",
            completed=True,
            failed=False,
        )
        self.assertEqual(compressed.type, "job.completed")
        self.assertEqual(compressed.job_id, "")
        self.assertEqual(compressed.task_id, "")
        self.assertEqual(compressed.detail, {"status": "completed"})

        task = normalize_hook(
            "kanban_task_completed",
            profile="default",
            profile_name="work",
            task_id="task-123",
            board="shipping",
            summary="private task summary",
        )
        self.assertEqual(task.type, "task.updated")
        self.assertEqual(task.profile, "work")
        self.assertEqual(task.task_id, "task-123")
        self.assertIn("loopdy:///dashboard?eventId=", task.deep_link)
        self.assertNotIn("private task summary", str(task.push_payload))

        self.assertIsNone(
            normalize_hook(
                "pre_tool_call",
                profile="default",
                tool_name="terminal",
                args={"command": "echo ignored"},
            )
        )

    def test_delegation_hooks_keep_started_updated_and_completed_distinct(self) -> None:
        started = normalize_hook(
            "subagent_start",
            profile="default",
            parent_session_id="parent-1",
            child_subagent_id="child-1",
        )
        updated = normalize_hook(
            "subagent_stop",
            profile="default",
            parent_session_id="parent-1",
            child_subagent_id="child-1",
            child_status="failed",
        )
        completed = normalize_hook(
            "subagent_stop",
            profile="default",
            parent_session_id="parent-1",
            child_subagent_id="child-2",
            child_status="completed",
        )

        self.assertEqual(started.type, "delegation.started")
        self.assertEqual(started.detail, {"status": "running"})
        self.assertEqual(updated.type, "delegation.updated")
        self.assertEqual(updated.detail, {"status": "failed"})
        self.assertEqual(completed.type, "delegation.completed")
        self.assertEqual(completed.detail, {"status": "completed"})
        self.assertIsNone(
            normalize_hook(
                "on_session_end",
                profile="default",
                session_id="session-legacy-exit",
                reason="cli_exit",
            )
        )


if __name__ == "__main__":
    unittest.main()
