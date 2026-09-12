from __future__ import annotations

import importlib.util
import argparse
import contextlib
import io
import json
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


class _Context:
    profile_name = "personal"

    def __init__(self):
        self.platform = None
        self.approval = None
        self.hooks = {}
        self.cli = None
        self.unload = None
        self.tools = {}
        self.skills = {}
        self.state = type(
            "State",
            (),
            {
                "values": {},
                "get": lambda self, key, default=None: self.values.get(key, default),
                "set": lambda self, key, value: self.values.__setitem__(key, value),
            },
        )()

    def register_tool(self, **kwargs):
        self.tools[kwargs["name"]] = kwargs

    def register_platform(self, **kwargs):
        self.platform = kwargs

    def register_skill(self, name, path, **kwargs):
        self.skills[name] = {"path": Path(path), **kwargs}

    def register_approval_transport(self, name, present_fn):
        self.approval = (name, present_fn)

    def register_hook(self, name, callback):
        self.hooks[name] = callback

    def register_cli_command(self, **kwargs):
        self.cli = kwargs

    def on_unload(self, callback):
        self.unload = callback


class _Service:
    def __init__(self):
        self.events = []
        self.dismissed_requests = []
        self.dismissed_sessions = []
        service = self

        class Store:
            def __init__(self):
                self.records = {}

            def record_event(self, event, *, target="all"):
                if event.event_id in self.records:
                    return False
                self.records[event.event_id] = {
                    "event_id": event.event_id, "type": event.type,
                    "profile": event.profile, "session_id": event.session_id,
                    "detail": dict(event.detail),
                }
                return True

            def get_event(self, event_id):
                return self.records.get(event_id)

            def dismiss_attention_request(
                self, request_id, *, session_id="", dismissed_at=None
            ):
                service.dismissed_requests.append((request_id, session_id))
                return 1

            def dismiss_attention_for_session(self, session_id, *, dismissed_at=None):
                service.dismissed_sessions.append(session_id)
                return 1

        self.store = Store()

    def enqueue(self, event, *, target):
        self.store.record_event(event, target=target)
        self.events.append((event, target))
        return True

    def close(self):
        pass

    def enqueue_live_activity_update(self, **update):
        self.events.append(("live-activity", update))
        return True


class _ActivityBroker:
    def __init__(self):
        self.active = {}
        self.bindings = {}
        self.payloads = []

    def bind_link_session(self, session_id, link_session_id):
        self.bindings[session_id] = link_session_id

    def bound_link_session(self, session_id):
        return self.bindings.get(session_id)

    def activate(self, session_id, turn_id, *, link_session_id):
        self.active[(session_id, turn_id)] = link_session_id

    def is_active(self, session_id, turn_id):
        return (session_id, turn_id) in self.active

    def resolved_session_id(self, session_id, turn_id):
        return self.active.get((session_id, turn_id))

    def publish(self, payload):
        self.payloads.append(payload)
        return True

    def deactivate(self, session_id, turn_id):
        self.active.pop((session_id, turn_id), None)


class RegistrationTests(unittest.TestCase):
    def test_registered_todo_hook_projects_current_and_legacy_tool_snapshots(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker
        from loopdy_plugin.registration import register

        class CapturingBroker(LinkActivityBroker):
            def __init__(self):
                super().__init__()
                self.payloads = []

            def publish(self, payload):
                self.payloads.append(payload)
                return True

        for tool_name in ("todo_list", "todo"):
            with self.subTest(tool_name=tool_name):
                broker = CapturingBroker()
                context = _Context()
                register(context, service=_Service(), activity_broker=broker)
                broker.bind_link_session("stored-todo-session", "visible-todo-session")
                for revision, status in enumerate(("pending", "in_progress", "completed"), 1):
                    snapshot = {
                        "todos": [{"id": "task-1", "content": "Verify task rail", "status": status}],
                        "revision": revision,
                    }
                    payload = {
                        "session_id": "stored-todo-session",
                        "turn_id": "stored-todo-session:turn:todo01",
                        "tool_call_id": f"todo-call-{revision}",
                        # Hermes unwraps deferred tool_call before invoking hooks.
                        "tool_name": tool_name,
                        "args": {"todos": snapshot["todos"], "merge": True},
                        "status": "ok",
                        "result": json.dumps(snapshot) if revision % 2 else snapshot,
                    }
                    context.hooks["post_tool_call"](**payload)
                    context.hooks["post_tool_call"](**payload)
                events = [item for item in broker.payloads if item["type"] == "session.todos"]
                self.assertEqual([event["revision"] for event in events], [1, 2, 3])
                self.assertEqual(
                    [event["todos"][0]["status"] for event in events],
                    ["pending", "in_progress", "completed"],
                )
                self.assertTrue(all(event["sessionId"] == "visible-todo-session" for event in events))

    def test_registered_todo_hook_rejects_failed_unbound_and_unrelated_results(self) -> None:
        from loopdy_plugin.activity_bridge import LinkActivityBroker
        from loopdy_plugin.registration import register

        class CapturingBroker(LinkActivityBroker):
            def __init__(self):
                super().__init__()
                self.payloads = []

            def publish(self, payload):
                self.payloads.append(payload)
                return True

        broker = CapturingBroker()
        context = _Context()
        register(context, service=_Service(), activity_broker=broker)
        broker.bind_link_session("stored-todo-session", "visible-todo-session")
        snapshot = {"todos": [{"id": "task-1", "content": "Keep private", "status": "pending"}], "revision": 1}
        base = {
            "session_id": "stored-todo-session",
            "turn_id": "stored-todo-session:turn:todo01",
            "tool_call_id": "todo-call-1",
            "tool_name": "todo_list",
            "status": "ok",
            "result": snapshot,
        }
        for change in (
            {"status": "failed"},
            {"status": "cancelled"},
            {"session_id": "unbound-session"},
            {"tool_name": "terminal"},
            {"tool_name": "tool_call", "args": {"name": "unrelated_tool"}},
            {"result": "not json"},
            {"result": {"todos": snapshot["todos"], "revision": True}},
            {"result": {"todos": [{"id": "task-1", "status": "invalid"}], "revision": 1}},
        ):
            with self.subTest(change=change):
                context.hooks["post_tool_call"](**(base | change))
        self.assertFalse(any(item["type"] == "session.todos" for item in broker.payloads))

    def test_registered_api_hook_projects_usage_without_notification(self):
        from loopdy_plugin.registration import register
        from loopdy_plugin.activity_bridge import LinkActivityBroker

        context, service, broker = _Context(), _Service(), LinkActivityBroker()
        register(context, service=service, activity_broker=broker)
        broker.bind_link_session("hermes-usage", "link-usage")
        context.hooks["post_api_request"](
            session_id="hermes-usage", model="model-usage", api_request_id="request-usage",
            usage={"prompt_tokens":100,"output_tokens":5,"cache_read_tokens":75,"total_tokens":105},
        )
        self.assertEqual(broker.usage_snapshot("hermes-usage", "model-usage")["cachedTokens"], 75)
        self.assertEqual(service.events, [])
        context.hooks["on_session_reset"](session_id="hermes-usage")
        self.assertIsNone(broker.usage_snapshot("hermes-usage", "model-usage"))

    def test_loopdy_native_presentation_context_matches_static_card_contract(self) -> None:
        from loopdy_plugin.registration import register

        service = _Service()
        context = _Context()
        register(context, service=service)

        result = context.hooks["pre_llm_call"](
            platform="loopdy",
            session_id="static-card-contract",
            sender_id="sender",
        )

        self.assertIsNotNone(result)
        prompt = result["context"]
        self.assertIn("embedded values and an empty data_sources array", prompt)
        self.assertIn("Live Loopdy Card data refresh is unavailable", prompt)
        self.assertNotIn("public-GET live-data", prompt)

    def test_link_chat_hooks_publish_safe_exact_activity_lifecycle(self) -> None:
        from loopdy_plugin.registration import register

        service = _Service()
        context = _Context()
        broker = _ActivityBroker()
        register(context, service=service, activity_broker=broker)
        coordinates = {
            "session_id": "session_coordinate_0001",
            "task_id": "session_coordinate_0001",
            "turn_id": (
                "session_coordinate_0001:session_coordinate_0001:abc12345"
            ),
        }
        broker.bind_link_session(
            coordinates["session_id"], "link_chat_coordinate_0001"
        )

        context.hooks["pre_llm_call"](
            **coordinates,
            platform="loopdy",
            model="claude-sonnet",
            user_message="private user request",
        )
        context.hooks["pre_tool_call"](
            **coordinates,
            tool_name="web_search",
            tool_call_id="call_weather_fixture_01",
            args={"query": "private search", "api_token": "do-not-leak"},
        )
        context.hooks["post_tool_call"](
            **coordinates,
            tool_name="web_search",
            tool_call_id="call_weather_fixture_01",
            args={"query": "private search", "api_token": "do-not-leak"},
            result="private tool output",
            status="ok",
            duration_ms=420,
        )
        context.hooks["subagent_start"](
            parent_session_id=coordinates["session_id"],
            parent_turn_id=coordinates["turn_id"],
            child_session_id="child_session_coordinate_01",
            child_subagent_id="child_subagent_coordinate_1",
            child_role="researcher",
            child_goal="Compare provider documentation",
        )
        context.hooks["subagent_stop"](
            parent_session_id=coordinates["session_id"],
            parent_turn_id=coordinates["turn_id"],
            child_session_id="child_session_coordinate_01",
            child_role="researcher",
            child_summary="Provider comparison completed",
            child_status="completed",
            duration_ms=840,
        )
        context.hooks["post_llm_call"](
            **coordinates,
            platform="loopdy",
            assistant_response="private final response",
        )

        self.assertEqual(
            [(item["kind"], item["lifecycle"]) for item in broker.payloads],
            [
                ("reasoning", "running"),
                ("tool", "running"),
                ("tool", "succeeded"),
                ("subagent", "running"),
                ("subagent", "succeeded"),
                ("reasoning", "succeeded"),
            ],
        )
        self.assertEqual(
            {item["sessionId"] for item in broker.payloads},
            {"link_chat_coordinate_0001"},
        )
        self.assertEqual(len({item["turnId"] for item in broker.payloads}), 1)
        self.assertTrue(broker.payloads[0]["turnId"].startswith("turn_"))
        self.assertNotIn(":", broker.payloads[0]["turnId"])
        tool_events = [item for item in broker.payloads if item["kind"] == "tool"]
        self.assertEqual(
            {item["eventId"] for item in tool_events},
            {tool_events[0]["eventId"]},
        )
        self.assertEqual(
            {item["toolCallId"] for item in tool_events},
            {"call_weather_fixture_01"},
        )
        self.assertEqual(
            {item["toolName"] for item in tool_events},
            {"web_search"},
        )
        self.assertEqual(
            tool_events[0]["arguments"],
            '{"api_token":"do-not-leak","query":"private search"}',
        )
        self.assertEqual(tool_events[1]["arguments"], tool_events[0]["arguments"])
        self.assertEqual(tool_events[1]["result"], "private tool output")
        self.assertNotIn("private final response", repr(broker.payloads))
        self.assertFalse(broker.active)

    def test_successful_renderer_tool_publishes_native_card_for_active_link_turn(self) -> None:
        from loopdy_plugin.registration import register

        broker = _ActivityBroker()
        context = _Context()
        register(context, service=_Service(), activity_broker=broker)
        coordinates = {
            "session_id": "session_coordinate_0003",
            "task_id": "session_coordinate_0003",
            "turn_id": (
                "session_coordinate_0003:session_coordinate_0003:def67890"
            ),
        }
        broker.bind_link_session(
            coordinates["session_id"], "link_chat_coordinate_0003"
        )
        context.hooks["pre_llm_call"](
            **coordinates,
            platform="loopdy",
            profile_name="personal",
        )
        context.hooks["post_tool_call"](
            **coordinates,
            profile_name="personal",
            tool_name="loopdy_render_summary",
            tool_call_id="call_render_fixture_0001",
            status="ok",
            result=json.dumps(
                {
                    "schema": "loopdy.generative_ui",
                    "version": 1,
                    "component": "summary",
                    "title": "Weather ready",
                    "body": "Clear skies through this afternoon.",
                }
            ),
        )

        cards = [item for item in broker.payloads if item["type"] == "generative.ui"]
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0]["sessionId"], "link_chat_coordinate_0003")
        self.assertTrue(cards[0]["turnId"].startswith("turn_"))
        self.assertNotIn(":", cards[0]["turnId"])
        self.assertEqual(cards[0]["toolCallId"], "call_render_fixture_0001")
        self.assertEqual(cards[0]["card"]["component"], "summary")

    def test_successful_loopdy_card_renderer_publishes_native_card_live(self) -> None:
        from loopdy_plugin.loopdy_cards import render_card
        from loopdy_plugin.registration import register

        broker = _ActivityBroker()
        context = _Context()
        register(context, service=_Service(), activity_broker=broker)
        session_id = "session_coordinate_card_0001"
        turn_id = "session_coordinate_card_0001:session_coordinate_card_0001:abc12345"
        broker.bind_link_session(session_id, "link_chat_coordinate_card_0001")
        context.hooks["pre_llm_call"](
            session_id=session_id,
            turn_id=turn_id,
            platform="loopdy",
            profile_name="personal",
        )
        source = json.loads(
            (PLUGIN_ROOT / "fixtures/loopdy_card_v1/static-metrics.json").read_text(
                encoding="utf-8"
            )
        )
        rendered = render_card(
            source,
            now=datetime(2026, 9, 3, tzinfo=timezone.utc),
        )

        context.hooks["post_tool_call"](
            session_id=session_id,
            turn_id=turn_id,
            profile_name="personal",
            tool_name="loopdy_render_card",
            tool_call_id="call_render_card_fixture_0001",
            status="ok",
            result=json.dumps(rendered),
        )

        cards = [item for item in broker.payloads if item["type"] == "generative.ui"]
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0]["sessionId"], "link_chat_coordinate_card_0001")
        self.assertEqual(cards[0]["card"]["schema"], "loopdy.card")
        self.assertEqual(cards[0]["card"]["content_hash"], rendered["content_hash"])

    def test_failed_or_unbound_renderer_tool_never_publishes_native_card(self) -> None:
        from loopdy_plugin.registration import register

        broker = _ActivityBroker()
        context = _Context()
        register(context, service=_Service(), activity_broker=broker)
        payload = {
            "session_id": "session_coordinate_0004",
            "turn_id": "turn_coordinate_0004",
            "profile_name": "personal",
            "tool_name": "loopdy_render_summary",
            "tool_call_id": "call_render_fixture_0002",
            "result": json.dumps(
                {
                    "schema": "loopdy.generative_ui",
                    "version": 1,
                    "component": "summary",
                    "title": "Private",
                    "body": "Do not deliver this result.",
                }
            ),
        }
        context.hooks["post_tool_call"](**payload, status="ok")
        context.hooks["pre_llm_call"](
            session_id=payload["session_id"],
            turn_id=payload["turn_id"],
            platform="loopdy",
        )
        context.hooks["post_tool_call"](**payload, status="failed")

        self.assertFalse(any(item["type"] == "generative.ui" for item in broker.payloads))

    def test_non_link_session_never_publishes_link_activity(self) -> None:
        from loopdy_plugin.registration import register

        broker = _ActivityBroker()
        context = _Context()
        register(context, service=_Service(), activity_broker=broker)

        context.hooks["pre_llm_call"](
            session_id="session_coordinate_0002",
            turn_id="turn_coordinate_0002",
            platform="imsg",
        )
        context.hooks["pre_tool_call"](
            session_id="session_coordinate_0002",
            turn_id="turn_coordinate_0002",
            tool_name="terminal",
            tool_call_id="call_terminal_fixture_01",
            args={"command": "echo private"},
        )

        self.assertEqual(broker.payloads, [])

    def test_clarify_tool_cleanup_does_not_allow_session_end_to_clear_newer_attention(self) -> None:
        from loopdy_plugin.registration import register

        service = _Service()
        context = _Context()
        register(context, service=service)

        context.hooks["post_tool_call"](
            tool_name="clarify",
            tool_call_id="request-1",
            session_id="session-1",
        )
        context.hooks["on_session_end"](
            session_id="session-2",
            completed=True,
            failed=False,
            interrupted=False,
        )

        self.assertEqual(service.dismissed_requests, [])
        self.assertEqual(service.dismissed_sessions, ["session-1"])

    def test_post_llm_preserves_pending_attention_for_a_newer_turn(self) -> None:
        from loopdy_plugin.registration import register

        service = _Service()
        context = _Context()
        register(context, service=service)

        context.hooks["post_llm_call"](session_id="session-1")

        self.assertEqual(service.dismissed_sessions, [])

    def test_interrupted_session_ends_live_activity_as_failed(self) -> None:
        from loopdy_plugin.registration import _live_activity_from_hook

        service = _Service()
        _live_activity_from_hook(
            "on_session_end",
            service=service,
            profile="default",
            payload={"session_id": "session-1", "interrupted": True},
        )
        _, update = service.events[0]
        self.assertEqual(update["phase"], "failed")
        self.assertEqual(update["active_session_count"], 0)
        self.assertNotIn("detail", update)

    def test_successful_turn_completes_live_activity_from_post_llm_only(self) -> None:
        from loopdy_plugin.registration import register

        service = _Service()
        context = _Context()
        register(context, service=service)

        context.hooks["post_llm_call"](
            profile_name="personal",
            session_id="session-1",
            turn_id="turn-1",
            assistant_response="Finished",
        )
        context.hooks["on_session_end"](
            profile_name="personal",
            session_id="session-1",
            turn_id="turn-1",
            completed=True,
            failed=False,
            interrupted=False,
        )

        live_updates = [value for kind, value in service.events if kind == "live-activity"]
        self.assertEqual(len(live_updates), 1)
        self.assertEqual(live_updates[0]["phase"], "completed")
        self.assertEqual(live_updates[0]["active_session_count"], 0)

    def test_provider_and_apns_commands_store_only_host_configuration(self) -> None:
        from loopdy_plugin.registration import handle_cli, setup_cli

        class Store:
            def __init__(self):
                self.mode = "managed"
                self.config = None

            def provider_mode(self):
                return self.mode

            def set_provider_mode(self, mode):
                self.mode = mode

            def save_apns_config(self, config):
                self.config = dict(config)

            def load_apns_config(self):
                return self.config

            def clear_apns_config(self):
                self.config = None

            def list_devices(self):
                return [
                    {
                        "device_id": "phone-1",
                        "endpoint_id": "ExponentPushToken[fixture-phone-1]",
                        "provider": "managed",
                        "token_environment": "production",
                        "label": "iPhone",
                        "groups": [],
                        "preferences": {},
                        "revoked": False,
                    }
                ]

        class Service:
            store = Store()

            def health(self):
                return {"mode": self.store.mode, "ready": True, "configured": True}

            def set_provider_mode(self, mode):
                self.store.set_provider_mode(mode)
                return self.health()

        service = Service()
        parser = argparse.ArgumentParser()
        setup_cli(parser)
        with tempfile.TemporaryDirectory() as temporary:
            key_path = Path(temporary) / "AuthKey_FIXTURE01.p8"
            key_path.write_bytes(
                ec.generate_private_key(ec.SECP256R1()).private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            args = parser.parse_args(
                [
                    "configure-apns",
                    "--team-id",
                    "TEAMFIX001",
                    "--key-id",
                    "KEYFIX0001",
                    "--topic",
                    "app.loopdy.personal",
                    "--environment",
                    "production",
                    "--key-path",
                    str(key_path),
                ]
            )
            with contextlib.redirect_stdout(io.StringIO()):
                handle_cli(args, service=service, profile="default")

            self.assertEqual(
                set(service.store.config),
                {"team_id", "key_id", "topic", "environment", "key_path"},
            )
            self.assertEqual(service.store.config["key_path"], str(key_path.resolve()))
            self.assertEqual(service.store.mode, "direct")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                handle_cli(
                    parser.parse_args(["status"]),
                    service=service,
                    profile="default",
                )
            status = json.loads(output.getvalue())
            self.assertEqual(status["provider"], "direct")
            self.assertEqual(status["apns"]["key_file"], "AuthKey_FIXTURE01.p8")
            self.assertNotIn(str(key_path), output.getvalue())
            self.assertNotIn("PRIVATE KEY", output.getvalue())
            self.assertNotIn("ExponentPushToken", output.getvalue())
            self.assertEqual(status["devices"][0]["token_fingerprint"], "4242918ebfa3")

            with contextlib.redirect_stdout(io.StringIO()):
                handle_cli(
                    parser.parse_args(["provider", "managed"]),
                    service=service,
                    profile="default",
                )
            self.assertEqual(service.store.mode, "managed")

            with contextlib.redirect_stdout(io.StringIO()):
                handle_cli(
                    parser.parse_args(["remove-apns", "--yes"]),
                    service=service,
                    profile="default",
                )
            self.assertIsNone(service.store.config)

    def test_loopdy_link_pairing_commands_are_registered(self) -> None:
        from loopdy_plugin.registration import setup_cli

        parser = argparse.ArgumentParser()
        setup_cli(parser)
        pair = parser.parse_args(
            ["link", "pair", "--base-url", "https://link.loopdy.example"]
        )
        unpair = parser.parse_args(["link", "unpair", "--yes"])
        status = parser.parse_args(["link", "status"])
        self.assertEqual(pair.loopdy_link_action, "pair")
        self.assertEqual(unpair.loopdy_link_action, "unpair")
        self.assertEqual(status.loopdy_link_action, "status")

    def test_successful_loopdy_link_pairing_requests_gateway_activation(self) -> None:
        from loopdy_plugin.registration import _handle_link_cli

        paired = {
            "state": "paired",
            "device_id": "host-device-current",
            "base_url": "https://link.loopdy.example",
            "authorization_epoch": 1,
        }
        output = io.StringIO()

        with (
            patch("loopdy_plugin.registration.pair_host", return_value=paired),
            patch(
                "loopdy_plugin.registration._request_gateway_activation",
                return_value=True,
            ) as activate,
            contextlib.redirect_stdout(output),
        ):
            _handle_link_cli(
                SimpleNamespace(
                    loopdy_link_action="pair",
                    timeout=600,
                    base_url="https://link.loopdy.example",
                ),
                identity_state=_Context().state,
            )

        activate.assert_called_once_with()
        result = json.loads(output.getvalue())
        self.assertEqual(result["state"], "paired")
        self.assertEqual(result["gateway_activation"], "requested")

    def test_loopdy_link_status_reads_the_matching_persisted_gateway_state(self) -> None:
        from loopdy_plugin.registration import _handle_link_cli

        config = SimpleNamespace(
            base_url="https://link.loopdy.example",
            device_id="host-device-fixture",
            authorization_epoch=3,
        )
        state = _Context().state
        state.set(
            "link.runtime_status",
            {
                "state": "connected",
                "observed_at": 1_788_000_123,
                "last_connected_at": 1_788_000_123,
                "base_url": config.base_url,
                "device_id": config.device_id,
                "authorization_epoch": config.authorization_epoch,
                "reconnect_attempt": 0,
                "detail": "",
            },
        )
        output = io.StringIO()

        with (
            patch("loopdy_plugin.registration.load_runtime_config", return_value=config),
            contextlib.redirect_stdout(output),
        ):
            _handle_link_cli(
                SimpleNamespace(loopdy_link_action="status"),
                identity_state=state,
            )

        status = json.loads(output.getvalue())
        self.assertEqual(status["state"], "connected")
        self.assertEqual(status["observed_at"], 1_788_000_123)
        self.assertEqual(status["last_connected_at"], 1_788_000_123)
        self.assertNotIn("detail", status)

    def test_loopdy_link_status_does_not_trust_a_different_pairing(self) -> None:
        from loopdy_plugin.registration import _handle_link_cli

        config = SimpleNamespace(
            base_url="https://link.loopdy.example",
            device_id="host-device-current",
            authorization_epoch=4,
        )
        state = _Context().state
        state.set(
            "link.runtime_status",
            {
                "state": "connected",
                "observed_at": 1_788_000_123,
                "last_connected_at": 1_788_000_123,
                "base_url": config.base_url,
                "device_id": "host-device-previous",
                "authorization_epoch": 3,
                "reconnect_attempt": 0,
                "detail": "",
            },
        )
        output = io.StringIO()

        with (
            patch("loopdy_plugin.registration.load_runtime_config", return_value=config),
            contextlib.redirect_stdout(output),
        ):
            _handle_link_cli(
                SimpleNamespace(loopdy_link_action="status"),
                identity_state=state,
            )

        status = json.loads(output.getvalue())
        self.assertEqual(status["state"], "restart_required_or_connecting")
        self.assertNotIn("observed_at", status)

    def test_loopdy_link_status_surfaces_unready_enrollment(self) -> None:
        from loopdy_plugin.registration import _handle_link_cli

        config = SimpleNamespace(
            base_url="https://link.loopdy.example",
            device_id="host-device-current",
            authorization_epoch=4,
        )
        state = _Context().state
        state.set(
            "link.runtime_status",
            {
                "state": "unready",
                "observed_at": 1_788_000_123,
                "last_connected_at": 1_788_000_100,
                "base_url": config.base_url,
                "device_id": config.device_id,
                "authorization_epoch": config.authorization_epoch,
                "reconnect_attempt": 1,
                "detail": "ValueError: sender-key acknowledgement is invalid",
            },
        )
        output = io.StringIO()

        with (
            patch("loopdy_plugin.registration.load_runtime_config", return_value=config),
            contextlib.redirect_stdout(output),
        ):
            _handle_link_cli(
                SimpleNamespace(loopdy_link_action="status"),
                identity_state=state,
            )

        status = json.loads(output.getvalue())
        self.assertEqual(status["state"], "unready")
        self.assertEqual(status["detail"], "ValueError: sender-key acknowledgement is invalid")

    def test_pre_llm_hook_injects_only_registered_loopdy_identity_context(self) -> None:
        from loopdy_plugin.link_identity import LinkIdentityRegistry
        from loopdy_plugin.registration import register

        context = _Context()
        service = _Service()
        registry = LinkIdentityRegistry(context.state, account_key=b"k" * 32)
        sender = registry.remember(
            sender_device_id="mobile-device-1",
            actor_id="actor-1",
            actor_name="Alex",
            device_name="Kitchen iPad",
        )
        register(context, service=service)

        result = context.hooks["pre_llm_call"](
            platform="loopdy", sender_id=sender, session_id="session-1"
        )
        cron = context.hooks["pre_llm_call"](
            platform="cron", sender_id=sender, session_id="session-2"
        )

        self.assertIn("Alex", result["context"])
        self.assertIn("loopdy_render_weather_forecast", result["context"])
        self.assertIn("structured presentation", result["context"])
        self.assertIn("tool_search", result["context"])
        self.assertIn("Do not stop at prose", result["context"])
        self.assertIsNone(cron)

    def test_native_surfaces_and_nonblocking_hooks_are_registered(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "loopdy_entry_for_test",
            PLUGIN_ROOT / "__init__.py",
            submodule_search_locations=[str(PLUGIN_ROOT)],
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        import sys

        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        service = _Service()
        context = _Context()

        module.register(context, service=service)

        self.assertEqual(context.platform["name"], "loopdy")
        self.assertIn("hermes loopdy link pair", context.platform["install_hint"])
        self.assertEqual(context.platform["cron_deliver_env_var"], "LOOPDY_HOME_TARGET")
        from loopdy_plugin.loopdy_cards import MAX_DOCUMENT_BYTES
        self.assertGreater(context.platform["max_message_length"], MAX_DOCUMENT_BYTES)
        self.assertNotIn("platform_hint", context.platform or {})
        self.assertEqual(
            context.platform["parse_target_ref_fn"]("device:phone"),
            ("device:phone", None),
        )
        self.assertEqual(context.approval[0], "loopdy")
        self.assertEqual(context.cli["name"], "loopdy")
        from hermes_cli.plugins import VALID_HOOKS
        self.assertEqual(
            set(context.hooks),
            {
                "pre_approval_request",
                "pre_tool_call",
                "post_tool_call",
                "pre_llm_call",
                "post_llm_call",
                "post_api_request",
                "on_session_reset",
                "on_session_end",
                "subagent_start",
                "subagent_stop",
                "kanban_task_claimed",
                "kanban_task_completed",
                "kanban_task_blocked",
            } | ({"on_room_member_activity"} if "on_room_member_activity" in VALID_HOOKS else set()),
        )
        self.assertEqual(set(context.skills), {"loopdy-marketplace-publish"})
        self.assertTrue(context.skills["loopdy-marketplace-publish"]["path"].is_file())

        self.assertIsNone(
            context.hooks["pre_llm_call"](
                is_first_turn=True,
                user_message="Show this as a native card",
            )
        )
        self.assertIsNone(
            context.hooks["pre_llm_call"](
                is_first_turn=False,
                user_message="Continue",
            )
        )

        manifest = (PLUGIN_ROOT / "plugin.yaml").read_text()
        self.assertIn("  - pre_llm_call\n", manifest)
        self.assertIn("platforms:\n  - linux\n  - macos\n  - windows\n", manifest)
        self.assertNotIn("Hermes" + "Link", manifest)

    def test_clarify_pre_tool_hook_only_updates_live_activity(
        self,
    ) -> None:
        from loopdy_plugin.registration import register

        service = _Service()
        context = _Context()
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "profiles" / "personal").mkdir(parents=True)
            (home / "profiles" / "personal" / "profile.yaml").write_text(
                "ui_meta:\n  displayName: Atlas\n",
                encoding="utf-8",
            )
            with patch("loopdy_plugin.adapter.get_hermes_home", return_value=home):
                register(context, service=service)
                context.hooks["pre_tool_call"](
                    profile_name="personal",
                    session_id="stored-1",
                    turn_id="turn-1",
                    tool_name="clarify",
                    tool_call_id="clarify-1",
                    args={"question": "Choose one"},
                )

        kind, update = service.events[0]
        self.assertEqual(kind, "live-activity")
        self.assertEqual(update["profile"], "personal")
        self.assertEqual(update["phase"], "waiting")

    def test_clarify_pre_tool_hook_does_not_duplicate_adapter_notification(
        self,
    ) -> None:
        from loopdy_plugin.registration import register

        service = _Service()
        context = _Context()
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "profiles" / "personal").mkdir(parents=True)
            (home / "profiles" / "personal" / "profile.yaml").write_text(
                "ui_meta:\n  displayName: Atlas\n",
                encoding="utf-8",
            )
            with (
                patch("loopdy_plugin.adapter.get_hermes_home", return_value=home),
                patch.dict("os.environ", {"LOOPDY_HOME_TARGET": "device:home"}),
            ):
                register(context, service=service)
                context.hooks["pre_tool_call"](
                    profile_name="personal",
                    session_id="stored-1",
                    turn_id="turn-1",
                    tool_name="clarify",
                    tool_call_id="clarify-1",
                    args={"question": "Choose one"},
                )

        self.assertEqual([record[0] for record in service.events], ["live-activity"])
        _, update = service.events[0]
        self.assertEqual(update["profile"], "personal")
        self.assertEqual(update["session_id"], "stored-1")
        self.assertEqual(update["phase"], "waiting")
        self.assertNotIn("detail", update)
        self.assertNotIn("tool_name", update)

    def test_relay_cli_persists_only_public_configuration_and_secret_references(self) -> None:
        from loopdy_plugin.registration import handle_cli, setup_cli

        class Store:
            def __init__(self):
                self.mode = "managed"
                self.relay_config = None

            def provider_mode(self):
                return self.mode

            def set_provider_mode(self, mode):
                self.mode = mode

            def save_relay_config(self, config):
                self.relay_config = dict(config)

            def load_relay_config(self):
                return self.relay_config

            def clear_relay_config(self):
                self.relay_config = None

            def load_apns_config(self):
                return None

            def list_devices(self):
                return []

        class Service:
            store = Store()

            def health(self):
                return {
                    "mode": self.store.mode,
                    "ready": self.store.relay_config is not None,
                    "configured": self.store.relay_config is not None,
                }

            def set_provider_mode(self, mode):
                if mode == "relay" and self.store.relay_config is None:
                    raise ValueError("Configure relay before selecting the relay provider")
                self.store.set_provider_mode(mode)
                return self.health()

            def configure_relay(self, config):
                self.store.save_relay_config(config.stored_values())
                self.store.set_provider_mode("relay")
                return self.health()

            def remove_relay_configuration(self):
                self.store.clear_relay_config()
                if self.store.provider_mode() == "relay":
                    self.store.set_provider_mode("managed")
                return self.health()

        service = Service()
        parser = argparse.ArgumentParser()
        setup_cli(parser)
        args = parser.parse_args(
            [
                "configure-relay",
                "--base-url",
                "https://relay.example.invalid",
                "--tenant-id",
                "TENANT_EXAMPLE",
                "--credential-key-id",
                "credential_fixture_01",
                "--hmac-secret-ref",
                "env:LOOPDY_RELAY_HMAC",
                "--signing-key-secret-ref",
                "file:/private/loopdy-signing-key.pem",
            ]
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            handle_cli(args, service=service, profile="default")
        self.assertEqual(
            set(service.store.relay_config),
            {
                "base_url",
                "tenant_id",
                "credential_key_id",
                "hmac_secret_reference",
                "signing_key_secret_reference",
            },
        )
        self.assertEqual(service.store.mode, "relay")
        rendered = output.getvalue()
        self.assertNotIn("LOOPDY_RELAY_HMAC", rendered)
        self.assertNotIn("loopdy-signing-key.pem", rendered)
        self.assertNotIn("PRIVATE KEY", rendered)

        status_output = io.StringIO()
        with contextlib.redirect_stdout(status_output):
            handle_cli(parser.parse_args(["status"]), service=service, profile="default")
        status = json.loads(status_output.getvalue())
        self.assertEqual(status["relay"]["base_url"], "https://relay.example.invalid")
        self.assertTrue(status["relay"]["hmac_secret_reference_configured"])
        self.assertTrue(status["relay"]["signing_key_secret_reference_configured"])
        self.assertNotIn("hmac_secret_reference", status["relay"])
        self.assertNotIn("signing_key_secret_reference", status["relay"])

        with contextlib.redirect_stdout(io.StringIO()):
            handle_cli(
                parser.parse_args(["remove-relay", "--yes"]),
                service=service,
                profile="default",
            )
        self.assertIsNone(service.store.relay_config)
        self.assertEqual(service.store.mode, "managed")

    def test_relay_cli_has_no_secret_value_arguments_or_public_enrollment_command(self) -> None:
        from loopdy_plugin.registration import setup_cli

        parser = argparse.ArgumentParser()
        setup_cli(parser)
        help_text = parser.format_help()
        self.assertNotIn("enroll", help_text.lower())
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "configure-relay",
                    "--hmac-secret",
                    "fake-secret-value",
                    "--signing-private-key",
                    "fake-private-value",
                ]
            )

    def test_terminal_relay_recovery_cli_requires_confirmation_and_reports_counts_only(
        self,
    ) -> None:
        from loopdy_plugin.registration import handle_cli, setup_cli

        class Service:
            calls = 0

            def recover_terminal_relay_registrations(self):
                self.calls += 1
                return {
                    "claimed": 1,
                    "applied": 1,
                    "skipped": 0,
                    "remote_calls": 0,
                }

        service = Service()
        parser = argparse.ArgumentParser()
        setup_cli(parser)
        with contextlib.redirect_stderr(io.StringIO()):
            try:
                args = parser.parse_args(
                    ["recover-terminal-relay-registration", "--yes"]
                )
            except SystemExit as exc:
                self.fail(f"terminal relay recovery command was not registered: {exc}")

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            handle_cli(args, service=service, profile="default")
        self.assertEqual(
            json.loads(output.getvalue()),
            {"claimed": 1, "applied": 1, "skipped": 0, "remote_calls": 0},
        )
        self.assertEqual(service.calls, 1)
        self.assertNotIn("device", output.getvalue().lower())
        self.assertNotIn("token", output.getvalue().lower())

        with self.assertRaisesRegex(ValueError, "Pass --yes"):
            handle_cli(
                argparse.Namespace(
                    loopdy_action="recover-terminal-relay-registration", yes=False
                ),
                service=service,
                profile="default",
            )
        self.assertEqual(service.calls, 1)

    def test_public_delegation_hooks_keep_distinct_lifecycle_and_friendly_metadata(
        self,
    ) -> None:
        from loopdy_plugin.registration import register

        service = _Service()
        context = _Context()
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "profiles" / "personal").mkdir(parents=True)
            (home / "profiles" / "personal" / "profile.yaml").write_text(
                "ui_meta:\n  displayName: Atlas\n",
                encoding="utf-8",
            )
            with patch("loopdy_plugin.adapter.get_hermes_home", return_value=home):
                register(context, service=service)
                context.hooks["subagent_start"](
                    profile_name="personal",
                    parent_session_id="stored-parent",
                    child_session_id="stored-child",
                )
                context.hooks["subagent_stop"](
                    profile_name="personal",
                    parent_session_id="stored-parent",
                    child_session_id="stored-child",
                    child_status="running",
                )
                context.hooks["subagent_stop"](
                    profile_name="personal",
                    parent_session_id="stored-parent",
                    child_session_id="stored-child",
                    child_status="completed",
                )

        events = [event for event, _target in service.events]
        self.assertEqual(
            [event.type for event in events],
            ["delegation.started", "delegation.updated", "delegation.completed"],
        )
        self.assertTrue(all(event.profile == "personal" for event in events))
        self.assertTrue(all(event.session_id == "stored-parent" for event in events))
        self.assertTrue(all(event.detail["agent_name"] == "Atlas" for event in events))
        self.assertTrue(all("agent_name" not in event.push_payload for event in events))


if __name__ == "__main__":
    unittest.main()
