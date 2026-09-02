from __future__ import annotations

import unittest

from loopdy_plugin.events import build_event
from loopdy_plugin.presentation import shape_notification


class NotificationPresentationTests(unittest.TestCase):
    def test_delegation_lifecycle_copy_prefers_friendly_agent_metadata(self):
        expected = {
            "delegation.started": "Atlas started a delegation",
            "delegation.updated": "Atlas delegation updated",
            "delegation.completed": "Atlas completed a delegation",
        }
        for event_type, title in expected.items():
            with self.subTest(event_type=event_type):
                event = build_event(
                    event_type,
                    correlation=(event_type,),
                    profile="default",
                    detail={"agent_name": "Atlas", "status": "running"},
                )
                message = shape_notification(event)
                self.assertEqual(message.title, title)
                self.assertNotIn("Atlas", str(message.data))
                self.assertNotIn("default", str(message.data))

    def test_non_channel_notification_prefers_agent_display_metadata_without_payload_leak(
        self,
    ):
        event = build_event(
            "session.completed",
            correlation=("friendly-session",),
            profile="default",
            session_id="stored-1",
            detail={"agent_name": "Atlas", "summary": "Finished"},
        )

        message = shape_notification(event)

        self.assertEqual(message.title, "Atlas finished")
        self.assertEqual(message.body, "Session complete: Finished")
        self.assertNotIn("Atlas", str(message.data))
        self.assertNotIn("default", str(message.data))

    def test_session_notifications_identify_session_agent_and_event(self):
        completed = build_event(
            "session.completed",
            correlation=("identified-session",),
            profile="default",
            session_id="stored-1",
            detail={
                "agent_name": "Atlas",
                "session_title": "Release readiness",
                "summary": "The release candidate is ready.",
            },
        )
        clarification = build_event(
            "attention.required",
            correlation=("identified-clarification",),
            profile="default",
            session_id="stored-1",
            detail={
                "agent_name": "Atlas",
                "session_title": "Release readiness",
                "question": "Which environment should I use?",
            },
        )

        completed_message = shape_notification(completed)
        clarification_message = shape_notification(clarification)

        self.assertEqual(completed_message.title, "Release readiness · Atlas")
        self.assertEqual(
            completed_message.body,
            "Session complete: The release candidate is ready.",
        )
        self.assertEqual(clarification_message.title, "Release readiness · Atlas")
        self.assertEqual(clarification_message.body, "Which environment should I use?")
        self.assertNotIn("Release readiness", str(completed_message.data))

    def test_proactive_agent_title_is_bounded_with_required_suffix(self):
        event = build_event(
            "channel.message",
            correlation=("message", "bounded"),
            detail={"agent_name": "A" * 500, "message": "Hello"},
        )
        message = shape_notification(event)
        self.assertLessEqual(len(message.title), 100)
        self.assertTrue(message.title.endswith(" just messaged you!"))
    def test_automatic_channel_message_uses_the_host_message(self) -> None:
        event = build_event(
            "channel.message",
            correlation=("message-1",),
            profile="personal",
            detail={
                "agent_name": "Hermes",
                "title": "Deployment",
                "message": "  The deployment   completed successfully.  ",
            },
        )

        message = shape_notification(
            event,
            {"detail_mode": "automatic", "priority_sound": True},
        )

        self.assertEqual(message.title, "Hermes just messaged you!")
        self.assertEqual(message.body, "Message: The deployment completed successfully.")
        self.assertTrue(message.sound)
        self.assertEqual(message.data["loopdy"]["event_id"], event.event_id)
        self.assertNotIn("deployment", str(message.data).lower())

    def test_channel_message_uses_the_sending_agent_name(self) -> None:
        event = build_event(
            "channel.message",
            profile="dora",
            detail={"agent_name": "Dora", "message": "The brief is ready"},
        )

        message = shape_notification(event)

        self.assertEqual(message.title, "Dora just messaged you!")
        self.assertNotEqual(message.title, "Hermes just messaged you!")

    def test_minimal_and_disabled_previews_hide_event_content(self) -> None:
        event = build_event(
            "job.completed",
            job_id="job-1",
            detail={
                "agent_name": "Private agent name",
                "session_title": "Private acquisition target",
                "summary": "Private customer report is ready",
            },
        )

        minimal = shape_notification(event, {"detail_mode": "minimal"})
        hidden = shape_notification(
            event,
            {"detail_mode": "detailed", "lock_screen_previews": False},
        )

        self.assertEqual(minimal.body, "Open Loopdy to view the scheduled task result.")
        self.assertEqual(hidden.body, minimal.body)
        self.assertEqual(minimal.title, "Completion alert")
        self.assertEqual(hidden.title, minimal.title)
        self.assertNotIn("private", hidden.title.lower())
        self.assertNotIn("customer", str(hidden.data).lower())

    def test_detailed_content_is_normalized_and_bounded(self) -> None:
        event = build_event(
            "session.completed",
            session_id="session-1",
            detail={"summary": "  complete   result " + ("x" * 2_000)},
        )

        message = shape_notification(event, {"detail_mode": "detailed"})

        self.assertTrue(message.body.startswith("Session complete: complete result "))
        self.assertLessEqual(len(message.body), 800)

    def test_approval_never_includes_tool_arguments(self) -> None:
        event = build_event(
            "approval.required",
            approval_id="approval-1",
            detail={
                "command": "cat /private/key",
                "arguments": {"path": "/private/key"},
                "summary": "Review the requested action",
            },
        )

        message = shape_notification(event, {"detail_mode": "detailed"})

        self.assertEqual(message.title, "Needs your approval")
        self.assertEqual(message.body, "Review the requested action")
        self.assertEqual(message.data["loopdy"]["approval_id"], "approval-1")
        self.assertNotIn("command", str(message.data))
        self.assertNotIn("private", str(message.data))

    def test_attention_copy_names_the_profile_and_prefers_safe_human_detail(self) -> None:
        approval = build_event(
            "approval.required",
            approval_id="approval-2",
            detail={
                "agent_name": "Builder",
                "command": "pnpm test --filter /private/customer-suite",
                "arguments": {"token": "fixture-secret", "prompt": "private prompt"},
                "pattern_key": "pnpm-test",
                "description": "Approve running the test suite?",
            },
        )
        clarification = build_event(
            "attention.required",
            session_id="session-2",
            detail={"agent_name": "Builder", "question": "Which release channel?"},
        )
        completion = build_event(
            "session.completed",
            session_id="session-3",
            detail={"agent_name": "Builder", "summary": "The checks passed."},
        )

        approval_message = shape_notification(approval, {"detail_mode": "detailed"})
        clarification_message = shape_notification(clarification, {"detail_mode": "detailed"})
        completion_message = shape_notification(completion, {"detail_mode": "detailed"})

        self.assertEqual(approval_message.title, "Builder needs approval")
        self.assertEqual(approval_message.body, "Approve running the test suite?")
        self.assertEqual(clarification_message.title, "Builder has a question")
        self.assertEqual(clarification_message.body, "Which release channel?")
        self.assertEqual(completion_message.title, "Builder finished")
        self.assertEqual(completion_message.body, "Session complete: The checks passed.")

    def test_safe_command_only_approval_uses_specific_copy(self) -> None:
        event = build_event(
            "approval.required",
            approval_id="approval-safe-4",
            detail={"agent_name": "Builder", "command": "  pnpm   test  "},
        )

        message = shape_notification(event, {"detail_mode": "detailed"})

        self.assertEqual(message.title, "Builder needs approval")
        self.assertEqual(message.body, "pnpm test")
        self.assertNotIn("command", str(message.data))

    def test_safe_command_only_approval_is_bounded(self) -> None:
        event = build_event(
            "approval.required",
            approval_id="approval-bounded-command",
            detail={"command": "verify" + ("x" * 600)},
        )

        message = shape_notification(event, {"detail_mode": "detailed"})

        self.assertTrue(message.body.startswith("verify"))
        self.assertEqual(len(message.body.encode("utf-8")), 400)

    def test_approval_command_fallback_never_exposes_arguments_paths_or_secrets(self) -> None:
        event = build_event(
            "approval.required",
            approval_id="approval-3",
            detail={
                "agent_name": "Builder",
                "command": "cat /private/customer/token.txt --header fixture-secret",
                "arguments": {"path": "/private/customer/token.txt"},
                "prompt": "private prompt",
                "pattern_keys": ["cat", "token"],
            },
        )

        message = shape_notification(event, {"detail_mode": "detailed"})

        self.assertEqual(message.title, "Builder needs approval")
        self.assertEqual(message.body, "Review the requested command in Loopdy.")
        rendered = f"{message.title} {message.body} {message.data}".lower()
        for private_value in ("/private", "customer", "fixture-secret", "private prompt", "pattern"):
            self.assertNotIn(private_value, rendered)

    def test_unsafe_human_description_falls_back_without_raw_metadata(self) -> None:
        for index, description in enumerate(
            (
                "Review (/private/customer/key.txt)",
                "Use prompt: private instructions",
                "Run with --token fixture-secret",
                "Read ../customer/config",
            )
        ):
            with self.subTest(description=description):
                event = build_event(
                    "approval.required",
                    approval_id=f"approval-unsafe-{index}",
                    detail={"command": "private command", "description": description},
                )

                message = shape_notification(event, {"detail_mode": "detailed"})

                self.assertEqual(message.body, "Review the requested command in Loopdy.")

    def test_attention_detail_fields_redact_private_paths_and_secrets(self) -> None:
        unsafe_details = {
            "question": "Which file should I use? /private/customer/token.txt",
            "summary": "Use --token fixture-secret to continue",
            "message": "Open https://private.example.test/action",
        }

        for field, value in unsafe_details.items():
            with self.subTest(field=field):
                event = build_event(
                    "attention.required",
                    detail={"agent_name": "Builder", field: value},
                )

                message = shape_notification(event, {"detail_mode": "detailed"})

                self.assertEqual(message.body, "Open Loopdy to continue.")
                rendered = f"{message.title} {message.body} {message.data}".lower()
                self.assertNotIn("private", rendered)
                self.assertNotIn("token", rendered)
                self.assertNotIn("fixture-secret", rendered)

    def test_common_credentials_and_private_paths_never_leave_approval_copy(self) -> None:
        jwt_fixture = ".".join(
            (
                "eyJ" + "hbGciOiJIUzI1NiJ9",
                "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0",
                "signature_fixture_value_123456",
            )
        )
        unsafe_descriptions = (
            "Approve using " + "sk-" + "proj-fixturecredential0123456789?",
            "Approve credential " + "AKIA" + "IOSFODNN7EXAMPLE?",
            "Use " + "github_" + "pat_11AA22BB33CC44DD55EE66FF77GG88HH99II00JJ",
            "Post with " + "xox" + "b-123456789012-123456789012-abcdefghijklmnopqrstuvwx",
            "Authorize " + jwt_fixture,
            "Charge using " + "sk_" + "live_51FixtureCredential0123456789",
            "opaque_value=AbCdEf0123456789AbCdEf0123456789",
            "Open src/customer/config.json?",
            "Open /Users/example/private/config.json?",
            "Fetch https://private.example.test/action",
            "Run deploy --token fixture-value",
            "Approve arguments: fixture-value",
        )
        for index, description in enumerate(unsafe_descriptions):
            with self.subTest(description=description):
                event = build_event(
                    "approval.required",
                    approval_id=f"approval-sensitive-{index}",
                    detail={"command": "review command", "description": description},
                )

                message = shape_notification(event, {"detail_mode": "detailed"})

                self.assertEqual(message.body, "Review the requested command in Loopdy.")

        safe = build_event(
            "approval.required",
            approval_id="approval-safe-natural",
            detail={
                "command": "review command",
                "description": "Approve deploying the reviewed build?",
            },
        )
        self.assertEqual(
            shape_notification(safe, {"detail_mode": "detailed"}).body,
            "Approve deploying the reviewed build?",
        )


if __name__ == "__main__":
    unittest.main()
