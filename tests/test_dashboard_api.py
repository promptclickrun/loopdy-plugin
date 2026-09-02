from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from loopdy_plugin.events import build_event
from loopdy_plugin.store import LoopdyStore
from loopdy_plugin.targets import validate_target


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


class _Service:
    def __init__(self, store):
        self.store = store
        self.test_targets = []
        self.reconciled = 0
        self.live_activity_ready = False
        self.relay_operations = []

    def health(self):
        mode = self.store.provider_mode()
        devices = self.store.resolve_devices("all", mode)
        return {
            "mode": mode,
            "configured": mode == "managed",
            "ready": mode == "managed" and bool(devices),
            "detail": "Managed provider ready" if devices else "No managed devices",
            "compatible_devices": len(devices),
        }

    def reconcile_receipts(self):
        self.reconciled += 1
        return {"checked": 0, "delivered": 0, "failed": 0}

    def set_provider_mode(self, mode):
        if mode == "direct":
            raise ValueError("Configure APNs before selecting the direct provider")
        self.store.set_provider_mode(mode)
        return self.health()

    def register_device(self, **device):
        self.store.upsert_device(**device)
        return {
            "registered": True,
            "device_id": device["device_id"],
            "provider": device["provider"],
        }

    def register_live_activity(self, **activity):
        if not self.live_activity_ready:
            raise ValueError("Configure direct APNs before registering Live Activities")
        self.store.upsert_live_activity(**activity)
        return {"registered": True, "activity_id": activity["activity_id"]}

    def update_device_preferences(self, device_id, preferences):
        if not self.store.update_preferences(device_id, preferences):
            raise ValueError("Unknown device")
        return {"updated": True, "device_id": device_id}

    def revoke_device(self, device_id):
        if not self.store.revoke_device(device_id):
            raise ValueError("Unknown device")
        return {"revoked": True, "device_id": device_id}

    def test_notification(self, target, *, profile="default"):
        verdict = validate_target(target)
        if verdict is not True:
            raise ValueError(str(verdict))
        self.test_targets.append((target, profile))
        return {"success": True, "event_id": "attention.required:fixture", "message_id": "delivery-1"}

    def relay_operation(self, operation, body):
        self.relay_operations.append((operation, dict(body)))
        return {
            "version": 1,
            "status": "accepted",
            "id": str(body.get("device_id") or body.get("activity_id") or body.get("tenant_id")),
            "revision": int(body["revision"]),
        }


class DashboardApiTests(unittest.TestCase):
    def test_events_preserve_durable_completion_when_enrichment_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            previous_home = os.environ.get("HERMES_HOME")
            os.environ["HERMES_HOME"] = directory
            try:
                module_name = "loopdy_dashboard_api_completion_fallback_test"
                spec = importlib.util.spec_from_file_location(
                    module_name,
                    PLUGIN_ROOT / "dashboard" / "plugin_api.py",
                )
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                assert spec.loader is not None
                spec.loader.exec_module(module)
            finally:
                if previous_home is None:
                    os.environ.pop("HERMES_HOME", None)
                else:
                    os.environ["HERMES_HOME"] = previous_home

            store = LoopdyStore(Path(directory) / "api.sqlite3")
            transient = build_event(
                "job.failed",
                correlation=("job", "transient-job", "turn-1"),
                profile="offline",
                session_id="cron_transient-job_20260815_120000",
                job_id="transient-job",
                task_id="transient-job",
                detail={
                    "agent_name": "Atlas",
                    "reason": "Stored timeout",
                    "status": "failed",
                },
            )
            deleted = build_event(
                "job.completed",
                correlation=("job", "deleted-job", "turn-2"),
                profile="default",
                session_id="cron_deleted-job_20260815_120100",
                job_id="deleted-job",
                task_id="deleted-job",
                detail={"agent_name": "Nova", "status": "completed"},
            )
            store.record_event(transient)
            store.record_event(deleted)
            module._service = _Service(store)
            app = FastAPI()
            app.include_router(module.router)
            client = TestClient(app)

            async def cron_list(_backend, agent_id):
                if agent_id == "offline":
                    raise RuntimeError("catalog temporarily unavailable")
                self.assertEqual(agent_id, "default")
                return []

            async def session_messages(*_args, **_kwargs):
                raise AssertionError("history must not load without a catalog match")

            with (
                patch.object(module.HermesWorkspaceBackend, "_cron_list", cron_list),
                patch.object(
                    module.HermesWorkspaceBackend,
                    "_session_messages",
                    session_messages,
                ),
            ):
                listed_response = client.get("/events")
                exact_responses = {
                    event.event_id: client.get(f"/events/{event.event_id}")
                    for event in (transient, deleted)
                }

            self.assertEqual(listed_response.status_code, 200)
            listed = {
                event["event_id"]: event
                for event in listed_response.json()["events"]
            }
            self.assertEqual(set(listed), {transient.event_id, deleted.event_id})
            self.assertEqual(
                listed[transient.event_id]["detail"],
                {
                    "agent_name": "Atlas",
                    "reason": "Stored timeout",
                    "status": "failed",
                },
            )
            self.assertEqual(
                listed[deleted.event_id]["detail"],
                {"agent_name": "Nova", "status": "completed"},
            )
            for event_id, response in exact_responses.items():
                with self.subTest(event_id=event_id):
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json(), listed[event_id])

    def test_events_adds_profile_scoped_completion_metadata_without_changing_push(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            previous_home = os.environ.get("HERMES_HOME")
            os.environ["HERMES_HOME"] = directory
            try:
                module_name = "loopdy_dashboard_api_v2_events_test"
                spec = importlib.util.spec_from_file_location(
                    module_name,
                    PLUGIN_ROOT / "dashboard" / "plugin_api.py",
                )
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                assert spec.loader is not None
                spec.loader.exec_module(module)
            finally:
                if previous_home is None:
                    os.environ.pop("HERMES_HOME", None)
                else:
                    os.environ["HERMES_HOME"] = previous_home

            store = LoopdyStore(Path(directory) / "api.sqlite3")
            completion = build_event(
                "job.completed",
                correlation=("job", "job-123", "turn-456"),
                profile="default",
                session_id="cron_job-123_20260815_120000",
                job_id="job-123",
                detail={"agent_name": "Gordie"},
            )
            store.record_event(completion)
            stored_push = store.get_event(completion.event_id)["push"]
            module._service = _Service(store)
            app = FastAPI()
            app.include_router(module.router)
            client = TestClient(app)

            async def cron_list(_backend, agent_id):
                self.assertEqual(agent_id, "default")
                return [{
                    "id": "job-123",
                    "profile": "default",
                    "name": "Morning weather",
                    "prompt": "private task prompt",
                }]

            async def session_messages(
                _backend, stored_id, agent_id, *, include_compacted=False
            ):
                self.assertEqual(
                    (stored_id, agent_id, include_compacted),
                    ("cron_job-123_20260815_120000", "default", True),
                )
                return {"messages": [{
                    "role": "assistant",
                    "content": "Bring an umbrella after 4 PM.",
                    "reasoning_content": "private reasoning",
                }]}

            with (
                patch.object(module.HermesWorkspaceBackend, "_cron_list", cron_list),
                patch.object(
                    module.HermesWorkspaceBackend,
                    "_session_messages",
                    session_messages,
                ),
            ):
                response = client.get("/events")
                exact_response = client.get(f"/events/{completion.event_id}")

            self.assertEqual(response.status_code, 200)
            event = response.json()["events"][0]
            self.assertEqual(event["task_id"], "job-123")
            self.assertEqual(event["detail"], {
                "agent_name": "Gordie",
                "title": "Morning weather",
                "status": "completed",
                "summary": "Bring an umbrella after 4 PM.",
            })
            self.assertEqual(exact_response.status_code, 200)
            self.assertEqual(exact_response.json(), event)
            self.assertEqual(store.get_event(completion.event_id)["push"], stored_push)
            self.assertNotIn("Morning weather", repr(stored_push))
            self.assertNotIn("Bring an umbrella", repr(stored_push))

    def test_authenticated_local_provider_contract_is_bounded_and_request_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            previous_home = os.environ.get("HERMES_HOME")
            os.environ["HERMES_HOME"] = directory
            try:
                module_name = "loopdy_dashboard_api_for_test"
                spec = importlib.util.spec_from_file_location(
                    module_name,
                    PLUGIN_ROOT / "dashboard" / "plugin_api.py",
                )
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                assert spec.loader is not None
                spec.loader.exec_module(module)
            finally:
                if previous_home is None:
                    os.environ.pop("HERMES_HOME", None)
                else:
                    os.environ["HERMES_HOME"] = previous_home

            store = LoopdyStore(Path(directory) / "api.sqlite3")
            module._service = _Service(store)
            app = FastAPI()
            app.include_router(module.router)
            client = TestClient(app)

            capabilities = client.get("/capabilities")
            self.assertEqual(capabilities.status_code, 200)
            value = capabilities.json()
            self.assertEqual(value["plugin_version"], "2.2.11")
            self.assertEqual(value["default_provider"], "relay")
            self.assertEqual(value["detail_modes"], ["automatic", "minimal", "detailed"])
            self.assertTrue(value["capabilities"]["native_channel"])
            self.assertTrue(value["capabilities"]["proactive_delivery"])
            self.assertEqual(value["providers"], ["relay", "direct"])
            self.assertTrue(value["capabilities"]["encrypted_relay"])
            self.assertIn("channel.message", value["event_types"])
            self.assertIn("delegation.started", value["event_types"])
            self.assertIn("delegation.completed", value["event_types"])
            self.assertEqual(value["preferences_schema_version"], 2)
            self.assertEqual(client.post("/pairing/start", json={}).status_code, 404)
            self.assertEqual(client.post("/relay/enroll", json={}).status_code, 404)

            provider = client.get("/provider")
            self.assertEqual(provider.status_code, 200)
            self.assertEqual(provider.json()["mode"], "relay")
            self.assertEqual(module._service.reconciled, 1)
            self.assertEqual(client.put("/provider", json={"mode": "managed"}).status_code, 200)
            direct = client.put("/provider", json={"mode": "direct"})
            self.assertEqual(direct.status_code, 400)
            self.assertNotIn("path", direct.text.lower())
            self.assertEqual(
                client.put("/provider", json={"mode": "managed", "credential": "no"}).status_code,
                422,
            )

            push_token = "ExponentPushToken[fixture-phone-123]"
            device = {
                "device_id": "phone-123",
                "provider": "managed",
                "push_token": push_token,
                "token_environment": "production",
                "label": "Phone",
                "groups": ["personal"],
            }
            registered = client.post("/devices", json=device)
            self.assertEqual(registered.status_code, 201)
            self.assertNotIn(push_token, registered.text)
            listed = client.get("/devices")
            self.assertEqual(listed.status_code, 200)
            self.assertNotIn(push_token, listed.text)
            listed_device = listed.json()["devices"][0]
            self.assertNotIn("endpoint_id", listed_device)
            self.assertNotIn("push_token", listed_device)
            self.assertEqual(len(listed_device["token_fingerprint"]), 12)

            relay_common = {
                "version": 1,
                "idempotency_key": "11111111-1111-4111-8111-111111111111",
            }
            relay_device = {
                **relay_common,
                "device_id": "relay_phone_01",
                "revision": 1,
                "issued": 1_735_689_600,
                "lease_expires": 1_738_281_600,
                "provider": "relay",
                "recipient_public_key": "BHzyexiNA09-ilI4AwS1GsPAiWnid_IbNaYLSPxHZpl4B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E",
                "recipient_key_id": "qfMA61lg6JEzr3NiARoeJvDi6i423EAqBK9sGSuJGow",
                "push_token": "b" * 64,
                "environment": "production",
                "topic": "com.example.loopdy",
                "label": "Phone",
                "groups": [],
            }
            relay_registered = client.post("/relay/devices/register", json=relay_device)
            self.assertEqual(relay_registered.status_code, 201)
            self.assertNotIn("push_token", relay_registered.text)
            self.assertNotIn("recipient_public_key", relay_registered.text)
            uppercase_token = "AB" * 32
            uppercase_registered = client.post(
                "/relay/devices/register",
                json={**relay_device, "push_token": uppercase_token},
            )
            self.assertEqual(uppercase_registered.status_code, 201)
            self.assertEqual(
                module._service.relay_operations[-1][1]["push_token"],
                uppercase_token.lower(),
            )
            rejected_topic = client.post(
                "/relay/devices/register",
                json={
                    **relay_device,
                    "topic": "com.example.loopdy.push-type.liveactivity",
                },
            )
            self.assertEqual(rejected_topic.status_code, 400)
            self.assertNotIn("push-type.liveactivity", rejected_topic.text)
            invalid_token_only = "not-an-apns-token"
            invalid_token_response = client.post(
                "/relay/devices/register",
                json={**relay_device, "push_token": invalid_token_only},
            )
            self.assertEqual(invalid_token_response.status_code, 400)
            self.assertEqual(
                invalid_token_response.json()["detail"],
                "Invalid relay request (push_token:string_pattern_mismatch)",
            )
            self.assertNotIn(invalid_token_only, invalid_token_response.text)
            rejected_token = "A" * 65
            rejected_key = "!" * 87
            rejected = client.post(
                "/relay/devices/register",
                json={
                    **relay_device,
                    "push_token": rejected_token,
                    "recipient_public_key": rejected_key,
                },
            )
            self.assertEqual(rejected.status_code, 400)
            self.assertNotIn(rejected_token, rejected.text)
            self.assertNotIn(rejected_key, rejected.text)
            for invalid_revision in (True, 1.5, 9_007_199_254_740_992):
                with self.subTest(invalid_revision=invalid_revision):
                    invalid = client.post(
                        "/relay/devices/register",
                        json={**relay_device, "revision": invalid_revision},
                    )
                    self.assertEqual(invalid.status_code, 400)
                    self.assertRegex(
                        invalid.json()["detail"],
                        r"^Invalid relay request \(revision:[a-z0-9_]+\)$",
                    )
            self.assertEqual(
                client.post(
                    "/relay/devices/ack-sender-keys",
                    json={
                        **relay_common,
                        "device_id": "relay_phone_01",
                        "revision": 2,
                        "sender_key_revision": 1,
                        "acknowledged_sender_key_ids": [
                            "YX4396SNMKY95u_qpE-qSDLgbBfQAOVJnTxYdswiUIA"
                        ],
                    },
                ).status_code,
                200,
            )
            self.assertEqual(
                client.post(
                    "/relay/devices/revoke",
                    json={
                        **relay_common,
                        "device_id": "relay_phone_01",
                        "revision": 3,
                    },
                ).status_code,
                200,
            )
            live_activity = {
                **relay_common,
                "activity_id": "activity_fixture_01",
                "device_id": "relay_phone_01",
                "session_ref": "Q0RFRkdISUpLTE1OT1A",
                "push_token": "c" * 64,
                "environment": "production",
                "topic": "com.example.loopdy",
                "revision": 1,
                "timestamp": 1_735_689_842,
                "lease_expires": 1_735_718_642,
            }
            self.assertEqual(
                client.post("/relay/live-activities/register", json=live_activity).status_code,
                201,
            )
            self.assertEqual(
                client.post(
                    "/relay/live-activities/revoke",
                    json={
                        **relay_common,
                        "activity_id": "activity_fixture_01",
                        "revision": 2,
                        "timestamp": 1_735_689_843,
                    },
                ).status_code,
                200,
            )
            self.assertEqual(
                client.post(
                    "/relay/tenant/revoke",
                    json={
                        **relay_common,
                        "tenant_id": "TENANT_EXAMPLE",
                        "revision": 3,
                    },
                ).status_code,
                200,
            )
            self.assertEqual(
                client.post(
                    "/relay/tenant/delete",
                    json={
                        **relay_common,
                        "tenant_id": "TENANT_EXAMPLE",
                        "revision": 4,
                        "confirmation": "delete",
                    },
                ).status_code,
                200,
            )
            self.assertEqual(
                [operation for operation, _body in module._service.relay_operations],
                [
                    "register_device",
                    "register_device",
                    "acknowledge_sender_keys",
                    "revoke_device",
                    "register_live_activity",
                    "revoke_live_activity",
                    "revoke_tenant",
                    "delete_tenant",
                ],
            )

            activity_token = "a" * 64
            live_activity_body = {
                "session_id": "stored-session",
                "live_session_id": "live-session",
                "profile": "default",
                "activity_id": "activity-1",
                "push_token": activity_token,
                "environment": "production",
            }
            unavailable_activity = client.post("/live-activities", json=live_activity_body)
            self.assertEqual(unavailable_activity.status_code, 400)
            self.assertEqual(store.active_live_activities("live-session", "default"), [])

            module._service.live_activity_ready = True
            live_activity = client.post(
                "/live-activities",
                json=live_activity_body,
            )
            self.assertEqual(live_activity.status_code, 201)
            self.assertNotIn(activity_token, live_activity.text)
            self.assertEqual(
                store.active_live_activities("live-session", "default")[0]["activity_id"],
                "activity-1",
            )

            invalid_token = "not-an-expo-token"
            invalid = client.post("/devices", json={**device, "device_id": "bad-token", "push_token": invalid_token})
            self.assertEqual(invalid.status_code, 400)
            self.assertNotIn(invalid_token, invalid.text)
            self.assertEqual(
                client.post("/devices", json={**device, "endpoint_id": "forbidden"}).status_code,
                422,
            )

            preferences = {
                "detail_mode": "detailed",
                "lock_screen_previews": False,
                "enabled_types": ["approval.required", "session.failed"],
                "notifications_enabled": True,
                "priority_sound": False,
                "quiet_hours": {"start": "22:00", "end": "07:00"},
                "timezone": "America/Chicago",
            }
            self.assertEqual(
                client.put("/devices/phone-123/preferences", json=preferences).status_code,
                200,
            )
            self.assertEqual(
                client.put(
                    "/devices/phone-123/preferences",
                    json={"priority_sound": True},
                ).status_code,
                200,
            )
            stored_preferences = store.list_devices()[0]["preferences"]
            self.assertEqual(
                stored_preferences["enabled_types"],
                ["approval.required", "session.failed"],
            )
            self.assertTrue(stored_preferences["priority_sound"])
            self.assertEqual(
                client.post("/test", json={"target": "device:phone-123"}).status_code,
                200,
            )
            self.assertEqual(module._service.test_targets, [("device:phone-123", "default")])
            self.assertEqual(client.post("/test", json={"target": "bad/target"}).status_code, 400)

            event = build_event(
                "approval.required",
                correlation=("approval", "approval-123", "digest-456"),
                approval_id="approval-123",
                detail={"summary": "Review the requested action"},
            )
            store.record_event(event)
            store.create_approval(
                approval_id="approval-123",
                request_digest="digest-456",
                allowed_choices=["once", "deny"],
                event_id=event.event_id,
                expires_at=9_999_999_999,
            )
            first_event_page = client.get("/events?limit=1&offset=0")
            self.assertEqual(first_event_page.status_code, 200)
            self.assertEqual(first_event_page.json()["events"][0]["event_id"], event.event_id)
            self.assertEqual(first_event_page.json()["next_offset"], 1)
            second_event_page = client.get("/events?limit=1&offset=1")
            self.assertEqual(second_event_page.status_code, 200)
            self.assertEqual(second_event_page.json(), {"events": [], "next_offset": None})
            self.assertEqual(client.get(f"/events/{event.event_id}").status_code, 200)
            updated_state = client.patch(
                f"/events/{event.event_id}",
                json={"is_read": True, "is_pinned": True},
            )
            self.assertEqual(updated_state.status_code, 200)
            self.assertEqual(updated_state.json(), {
                "event_id": event.event_id,
                "is_read": True,
                "is_pinned": True,
            })
            stored_state = client.get(f"/events/{event.event_id}").json()
            self.assertTrue(stored_state["is_read"])
            self.assertTrue(stored_state["is_pinned"])
            self.assertEqual(
                client.patch(
                    f"/events/{event.event_id}",
                    json={"is_read": 1, "is_pinned": False},
                ).status_code,
                422,
            )
            self.assertEqual(client.delete(f"/events/{event.event_id}").status_code, 200)
            self.assertEqual(client.get("/events").json()["events"], [])
            self.assertEqual(client.delete(f"/events/{event.event_id}").status_code, 200)

            update_one = build_event(
                "channel.message",
                correlation=("channel", "update-one"),
                detail={"message": "First update"},
            )
            update_two = build_event(
                "channel.message",
                correlation=("channel", "update-two"),
                detail={"message": "Second update"},
            )
            store.record_event(update_one)
            store.record_event(update_two)
            cleared = client.post(
                "/events/dismiss",
                json={
                    "event_types": ["channel.message"],
                    "created_before": 9_999_999_999,
                },
            )
            self.assertEqual(cleared.status_code, 200)
            self.assertEqual(cleared.json()["dismissed"], 2)
            self.assertEqual(client.get("/events").json()["events"], [])
            self.assertEqual(
                client.post(
                    "/events/dismiss",
                    json={"event_types": ["not.an.event"], "created_before": 1},
                ).status_code,
                422,
            )
            approval = client.get("/approvals/approval-123")
            self.assertEqual(approval.status_code, 200)
            self.assertEqual(approval.json()["request_digest"], "digest-456")
            self.assertEqual(
                client.post(
                    "/approvals/approval-123/respond",
                    json={"choice": "once", "request_digest": "wrong"},
                ).status_code,
                409,
            )
            accepted = client.post(
                "/approvals/approval-123/respond",
                json={"choice": "once", "request_digest": "digest-456"},
            )
            self.assertEqual(accepted.status_code, 200)
            self.assertEqual(accepted.json()["choice"], "once")


if __name__ == "__main__":
    unittest.main()
