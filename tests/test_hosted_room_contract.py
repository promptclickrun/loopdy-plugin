from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

from loopdy_plugin.link_contracts import (
    MAX_ENCRYPTED_FRAME_CHARACTERS, WorkspaceRequest, parse_workspace_request,
    workspace_capabilities, workspace_result,
)
from loopdy_plugin.link_crypto import AccountCipher
from loopdy_plugin.groups_contracts import (
    GROUPS_RESULT_ENVELOPE_BYTES, GROUPS_RESULT_PAYLOAD_BYTES, GROUPS_RESULTS_CAPABILITY,
)


class HostedRoomContractTests(unittest.TestCase):
    def request(self, operation="groups.log"):
        return WorkspaceRequest(
            request_id="groups_fixture_request_0001", operation=operation,
            payload={"room_id": "room-fixture", "since_seq": 0, "limit": 2},
            sent_at=1788000200,
        )

    def page(self):
        return {
            "events": [{
                "room_id": "room-fixture", "seq": 1, "event_id": "user:fixture",
                "kind": "message.user", "actor": {"kind": "user", "id": "desktop"},
                "authority_epoch": 1, "payload": {"text": "Synthetic", "thread_id": "thread"},
                "created_at": 1788000200.5, "idempotent": False,
            }],
            "cursor": 1, "latest_seq": 1, "has_more": False,
            "authority": {"gateway_id": "gateway-fixture", "epoch": 1},
        }

    def encode(self, page, operation="groups.log"):
        return workspace_result(
            request=self.request(operation), status="completed", payload=page, sent_at=1788000201
        )

    def test_exact_groups_log_round_trips_through_result_and_cipher(self):
        page = self.page()
        original = copy.deepcopy(page)
        result = self.encode(page)
        cipher = AccountCipher(b"x" * 32)
        self.assertEqual(cipher.open(cipher.seal(result)), result)
        self.assertEqual(result["payload"], original)
        self.assertEqual(page, original)

    def test_gateway_allowance_never_applies_to_other_operation_or_path(self):
        for operation in ("agents.list", "groups.state", "groups.capabilities"):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                self.encode(self.page(), operation)
        for key in ("gateway_id", "gateway_token", "password", "secret", "authorization"):
            page = self.page()
            page["events"][0]["payload"][key] = "not-permitted"
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.encode(page)

    def test_groups_log_rejects_wrong_room_cursor_actor_and_authority(self):
        mutations = [
            lambda page: page["events"][0].update(room_id="other"),
            lambda page: page["events"][0].update(seq=2),
            lambda page: page.update(cursor=2, latest_seq=2),
            lambda page: page.update(has_more=True),
            lambda page: page["authority"].update(epoch=True),
            lambda page: page["authority"].update(gateway_token="not-permitted"),
            lambda page: page["events"][0].update(authority_epoch=2),
            lambda page: page["events"][0]["actor"].update(kind="member"),
            lambda page: page["events"][0].update(created_at=float("nan")),
        ]
        for mutate in mutations:
            page = self.page()
            mutate(page)
            with self.subTest(page=page), self.assertRaises(ValueError):
                self.encode(page)

    def test_legacy_large_page_fails_without_truncation(self):
        page = self.page()
        page["events"][0]["payload"]["text"] = "x" * 200_000
        original = copy.deepcopy(page)
        with self.assertRaises(ValueError):
            self.encode(page)
        self.assertEqual(page, original)

    def test_negotiated_large_page_preserves_every_event_through_encryption(self):
        page = self.page()
        page["events"] = [
            {**copy.deepcopy(page["events"][0]), "seq": index + 1, "event_id": f"user:fixture-{index}",
             "payload": {"text": "\\\"" * 32_000, "thread_id": "thread"}}
            for index in range(4)
        ]
        page.update(cursor=4, latest_seq=4)
        request = replace(self.request(), payload={**self.request().payload, "limit": 4}, groups_result_version=1)
        result = workspace_result(request=request, status="completed", payload=page, sent_at=1788000201)
        self.assertEqual(result["groupsResultVersion"], 1)
        cipher = AccountCipher(b"x" * 32)
        encrypted = cipher.seal(result)
        self.assertLess(len(encrypted), MAX_ENCRYPTED_FRAME_CHARACTERS)
        self.assertEqual(cipher.open(encrypted)["payload"], page)
        with self.assertRaises(ValueError):
            workspace_result(request=replace(request, groups_result_version=None),
                             status="completed", payload=page, sent_at=1788000201)

    def test_negotiation_is_explicit_operation_scoped_and_not_forwarded_as_params(self):
        self.assertIn(GROUPS_RESULTS_CAPABILITY, workspace_capabilities()["features"])
        legacy = self.request().wire_value()
        self.assertNotIn("groupsResultVersion", legacy)
        self.assertEqual(parse_workspace_request(legacy).wire_value(), legacy)
        marked = {**legacy, "groupsResultVersion": 1}
        parsed = parse_workspace_request(marked)
        self.assertEqual(parsed.groups_result_version, 1)
        self.assertEqual(parsed.payload, legacy["payload"])
        self.assertEqual(parsed.wire_value(), marked)
        for version in (True, 0, 2, "1", None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                parse_workspace_request({**legacy, "groupsResultVersion": version})
        with self.assertRaises(ValueError):
            parse_workspace_request({**marked, "operation": "agents.list"})
        for operation in ("agents.list", "groups.peer.invite"):
            with self.assertRaises(ValueError):
                AccountCipher(b"x" * 32).seal({
                    "type": "workspace.result", "operation": operation, "groupsResultVersion": 1
                })

    def test_groups_payload_and_full_envelope_bounds_are_independent(self):
        request = replace(self.request("groups.state"), groups_result_version=1)
        payload = {"items": ["x" * 200_000] * 11}
        self.assertGreater(len(json.dumps(payload).encode()), GROUPS_RESULT_PAYLOAD_BYTES)
        with self.assertRaises(ValueError):
            workspace_result(request=request, status="completed", payload=payload, sent_at=1788000201)
        oversized = {
            "type": "workspace.result", "operation": "groups.state", "groupsResultVersion": 1,
            "payload": "x" * GROUPS_RESULT_ENVELOPE_BYTES,
        }
        with self.assertRaises(ValueError):
            AccountCipher(b"x" * 32).seal(oversized)

    def test_portable_groups_result_vector(self):
        vector = json.loads((Path(__file__).parent / "fixtures" / "groups-result-v1.json").read_text())
        request = parse_workspace_request(vector["request"])
        result = workspace_result(
            request=request, status="completed", payload=vector["result"]["payload"],
            sent_at=vector["result"]["sentAt"],
        )
        self.assertEqual(result, vector["result"])
        self.assertEqual(vector["payloadBytes"], GROUPS_RESULT_PAYLOAD_BYTES)
        self.assertEqual(vector["envelopeBytes"], GROUPS_RESULT_ENVELOPE_BYTES)
