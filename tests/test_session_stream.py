import asyncio
import threading
import unittest
from unittest.mock import patch


class SessionStreamTests(unittest.IsolatedAsyncioTestCase):
    async def test_stalled_subscriber_resets_without_disrupting_healthy_subscriber(self) -> None:
        from loopdy_plugin.session_stream import SessionStreamHub, StreamResetRequired

        hub = SessionStreamHub(maximum_events=2, maximum_bytes=4_096)
        stalled = hub.subscribe(agent_id="default", session_id="link-session")
        healthy = hub.subscribe(agent_id="default", session_id="link-session")

        hub.publish(
            agent_id="default",
            session_id="link-session",
            payload={"type": "assistant.message", "text": "one"},
        )
        first = await healthy.receive()
        hub.publish(
            agent_id="default",
            session_id="link-session",
            payload={"type": "assistant.message", "text": "two"},
        )
        hub.publish(
            agent_id="default",
            session_id="link-session",
            payload={"type": "assistant.message", "text": "three"},
        )

        with self.assertRaises(StreamResetRequired):
            await stalled.receive()
        second = await healthy.receive()
        third = await healthy.receive()

        self.assertEqual(first["payload"]["text"], "one")
        self.assertEqual(second["payload"]["text"], "two")
        self.assertEqual(third["payload"]["text"], "three")

    async def test_wire_events_have_one_process_epoch_monotonic_cursor_and_independent_payloads(self) -> None:
        from loopdy_plugin.session_stream import SessionStreamHub

        hub = SessionStreamHub(maximum_events=4, maximum_bytes=4_096)
        first = hub.subscribe(agent_id="default", session_id="link-session")
        second = hub.subscribe(agent_id="default", session_id="link-session")
        initial_cursor = first.cursor
        payload = {
            "type": "assistant.message",
            "agentId": "default",
            "sessionId": "link-session",
            "parts": [{"text": "original"}],
        }

        published_cursor = hub.publish(
            agent_id="default", session_id="link-session", payload=payload
        )
        payload["parts"][0]["text"] = "changed after publish"
        first_event = await first.receive()
        first_event["payload"]["parts"][0]["text"] = "changed by first receiver"
        second_event = await second.receive()

        self.assertEqual(initial_cursor, 0)
        self.assertEqual(published_cursor, 1)
        self.assertEqual(first_event["processEpoch"], hub.process_epoch)
        self.assertEqual(first_event["cursor"], 1)
        self.assertEqual(first.cursor, 1)
        self.assertEqual(second_event["payload"]["parts"][0]["text"], "original")

    async def test_events_published_during_snapshot_loading_remain_buffered(self) -> None:
        from loopdy_plugin.session_stream import SessionStreamHub

        hub = SessionStreamHub(maximum_events=4, maximum_bytes=4_096)
        subscription = hub.subscribe(agent_id="default", session_id="link-session")
        snapshot_fence = subscription.cursor

        hub.publish(
            agent_id="default",
            session_id="link-session",
            payload={"type": "session.context", "sessionId": "link-session"},
        )
        await asyncio.sleep(0)  # stand in for the authoritative snapshot read
        event = await subscription.receive()

        self.assertEqual(snapshot_fence, 0)
        self.assertEqual(event["cursor"], 1)
        self.assertGreater(event["cursor"], snapshot_fence)

    async def test_thread_publications_preserve_cursor_order_with_one_coalesced_wake(self) -> None:
        from loopdy_plugin.session_stream import SessionStreamHub

        hub = SessionStreamHub(maximum_events=128, maximum_bytes=64_000)
        subscription = hub.subscribe(agent_id="default", session_id="link-session")
        waiting = asyncio.create_task(subscription.receive())
        await asyncio.sleep(0)
        loop = asyncio.get_running_loop()
        original_wake = loop.call_soon_threadsafe
        wake_calls = 0
        published: list[tuple[int, int]] = []
        published_lock = threading.Lock()

        def counted_wake(callback, *args, **kwargs):
            nonlocal wake_calls
            wake_calls += 1
            return original_wake(callback, *args, **kwargs)

        def publish_range(values: range) -> None:
            for value in values:
                cursor = hub.publish(
                    agent_id="default",
                    session_id="link-session",
                    payload={"type": "activity.event", "value": value},
                )
                with published_lock:
                    published.append((cursor, value))

        threads = [
            threading.Thread(target=publish_range, args=(range(start, start + 20),))
            for start in (0, 20, 40, 60)
        ]
        with patch.object(loop, "call_soon_threadsafe", side_effect=counted_wake):
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=1)

        first_event = await asyncio.wait_for(waiting, timeout=1)
        received = [(first_event["cursor"], first_event["payload"]["value"])]
        for _ in range(79):
            event = await subscription.receive()
            received.append((event["cursor"], event["payload"]["value"]))

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(wake_calls, 1)
        self.assertEqual(received, sorted(published))

    async def test_profile_and_session_scopes_are_isolated(self) -> None:
        from loopdy_plugin.session_stream import SessionStreamHub

        hub = SessionStreamHub(maximum_events=4, maximum_bytes=4_096)
        selected = hub.subscribe(agent_id="default", session_id="selected")
        other_profile = hub.subscribe(agent_id="research", session_id="selected")
        other_session = hub.subscribe(agent_id="default", session_id="other")

        hub.publish(
            agent_id="default",
            session_id="selected",
            payload={"type": "session.todos", "sessionId": "selected"},
        )
        selected_event = await selected.receive()
        profile_wait = asyncio.create_task(other_profile.receive())
        session_wait = asyncio.create_task(other_session.receive())
        await asyncio.sleep(0)

        self.assertEqual(selected_event["payload"]["type"], "session.todos")
        self.assertFalse(profile_wait.done())
        self.assertFalse(session_wait.done())
        profile_wait.cancel()
        session_wait.cancel()
        await asyncio.gather(profile_wait, session_wait, return_exceptions=True)

    async def test_byte_overflow_clears_and_unregisters_only_that_subscription(self) -> None:
        from loopdy_plugin.session_stream import SessionStreamHub, StreamResetRequired

        hub = SessionStreamHub(maximum_events=8, maximum_bytes=64)
        subscription = hub.subscribe(agent_id="default", session_id="selected")
        payload = {"type": "session.context", "value": "1234567890"}

        hub.publish(agent_id="default", session_id="selected", payload=payload)
        overflow_cursor = hub.publish(
            agent_id="default", session_id="selected", payload=payload
        )

        self.assertEqual(hub.subscription_count, 0)
        with self.assertRaises(StreamResetRequired) as caught:
            await subscription.receive()
        self.assertEqual(caught.exception.process_epoch, hub.process_epoch)
        self.assertEqual(caught.exception.cursor, overflow_cursor)

    async def test_oversized_payload_is_rejected_without_poisoning_subscription(self) -> None:
        from loopdy_plugin.session_stream import SessionStreamHub

        hub = SessionStreamHub(maximum_events=4, maximum_bytes=80)
        subscription = hub.subscribe(agent_id="default", session_id="selected")

        with self.assertRaisesRegex(ValueError, "exceeds maximum_bytes"):
            hub.publish(
                agent_id="default",
                session_id="selected",
                # The character count fits; its UTF-8 representation does not.
                payload={"type": "assistant.message", "text": "🙂" * 20},
            )
        hub.publish(
            agent_id="default",
            session_id="selected",
            payload={"type": "session.context"},
        )

        self.assertEqual((await subscription.receive())["payload"]["type"], "session.context")

    async def test_publish_validates_presentation_type_scope_and_json(self) -> None:
        from loopdy_plugin.session_stream import (
            PRESENTATION_EVENT_TYPES,
            SessionStreamHub,
        )

        hub = SessionStreamHub(maximum_events=16, maximum_bytes=8_192)
        subscription = hub.subscribe(agent_id="default", session_id="selected")
        for event_type in PRESENTATION_EVENT_TYPES:
            hub.publish(
                agent_id="default",
                session_id="selected",
                payload={"type": event_type},
            )
        for event_type in (
            "user.message",
            "workspace.request",
            "notification.event",
            "generative.ui.form.result",
            "device.tool.request",
        ):
            with self.subTest(event_type=event_type):
                with self.assertRaisesRegex(ValueError, "not transient presentation"):
                    hub.publish(
                        agent_id="default",
                        session_id="selected",
                        payload={"type": event_type},
                    )
        for mismatched in (
            {"type": "assistant.message", "agentId": "other"},
            {"type": "assistant.message", "sessionId": "other"},
        ):
            with self.assertRaisesRegex(ValueError, "does not match"):
                hub.publish(
                    agent_id="default", session_id="selected", payload=mismatched
                )
        with self.assertRaisesRegex(ValueError, "JSON object"):
            hub.publish(  # type: ignore[arg-type]
                agent_id="default", session_id="selected", payload=[]
            )
        with self.assertRaisesRegex(ValueError, "valid JSON"):
            hub.publish(
                agent_id="default",
                session_id="selected",
                payload={"type": "assistant.message", "value": object()},
            )
        with self.assertRaisesRegex(ValueError, "not transient presentation"):
            hub.publish(
                agent_id="default",
                session_id="selected",
                payload={"type": ["assistant.message"]},
            )

        accepted = [(await subscription.receive())["payload"]["type"] for _ in range(6)]
        self.assertEqual(set(accepted), set(PRESENTATION_EVENT_TYPES))

    async def test_publish_without_subscribers_retains_no_backlog(self) -> None:
        from loopdy_plugin.session_stream import SessionStreamHub

        hub = SessionStreamHub(maximum_events=4, maximum_bytes=4_096)
        old_cursor = hub.publish(
            agent_id="default",
            session_id="selected",
            payload={"type": "assistant.message", "text": "before subscribe"},
        )
        subscription = hub.subscribe(agent_id="default", session_id="selected")
        waiting = asyncio.create_task(subscription.receive())
        await asyncio.sleep(0)

        self.assertEqual(subscription.cursor, old_cursor)
        self.assertFalse(waiting.done())
        hub.publish(
            agent_id="default",
            session_id="selected",
            payload={"type": "assistant.message", "text": "after subscribe"},
        )
        event = await asyncio.wait_for(waiting, timeout=1)
        self.assertEqual(event["payload"]["text"], "after subscribe")

    async def test_cancelled_receive_is_reusable_and_close_wakes_and_unregisters(self) -> None:
        from loopdy_plugin.session_stream import SessionStreamHub, StreamClosed

        hub = SessionStreamHub(maximum_events=4, maximum_bytes=4_096)
        subscription = hub.subscribe(agent_id="default", session_id="selected")
        cancelled = asyncio.create_task(subscription.receive())
        await asyncio.sleep(0)
        cancelled.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await cancelled

        hub.publish(
            agent_id="default",
            session_id="selected",
            payload={"type": "assistant.message", "text": "still usable"},
        )
        self.assertEqual(
            (await subscription.receive())["payload"]["text"], "still usable"
        )

        waiting = asyncio.create_task(subscription.receive())
        await asyncio.sleep(0)
        subscription.close()
        with self.assertRaises(StreamClosed):
            await asyncio.wait_for(waiting, timeout=1)
        self.assertEqual(hub.subscription_count, 0)

    async def test_global_subscription_limit_is_released_by_close(self) -> None:
        from loopdy_plugin.session_stream import SessionStreamHub

        hub = SessionStreamHub(
            maximum_events=4, maximum_bytes=4_096, maximum_subscriptions=1
        )
        first = hub.subscribe(agent_id="default", session_id="selected")
        with self.assertRaisesRegex(RuntimeError, "subscription limit"):
            hub.subscribe(agent_id="default", session_id="selected")

        first.close()
        replacement = hub.subscribe(agent_id="default", session_id="selected")
        self.assertEqual(hub.subscription_count, 1)
        replacement.close()

    def test_constructor_and_scope_inputs_are_bounded(self) -> None:
        from loopdy_plugin.session_stream import SessionStreamHub

        for kwargs in (
            {"maximum_events": 0, "maximum_bytes": 1},
            {"maximum_events": 1, "maximum_bytes": 0},
            {"maximum_events": 1, "maximum_bytes": 1, "maximum_subscriptions": 0},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    SessionStreamHub(**kwargs)
        hub = SessionStreamHub()
        for agent_id, session_id in (("", "selected"), ("default", "bad/session")):
            with self.subTest(agent_id=agent_id, session_id=session_id):
                with self.assertRaises(ValueError):
                    hub.subscribe(agent_id=agent_id, session_id=session_id)


if __name__ == "__main__":
    unittest.main()
