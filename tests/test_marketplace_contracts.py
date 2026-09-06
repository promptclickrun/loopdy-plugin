from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric import ec

from loopdy_plugin.link_contracts import parse_workspace_request, workspace_result
from loopdy_plugin.loopdy_cards import canonical_json
from loopdy_plugin.store import LoopdyStore
from loopdy_plugin.workspace_control import HermesWorkspaceBackend, WorkspaceController


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
CARD_FIXTURE = PLUGIN_ROOT / "fixtures" / "loopdy_card_v1" / "static-metrics.json"


def _template() -> dict:
    document = json.loads(CARD_FIXTURE.read_text(encoding="utf-8"))
    return {
        "id": "marketplace-health",
        "version": 1,
        "name": "Marketplace health",
        "summary": "Show bounded marketplace health metrics.",
        "author": "Loopdy",
        "license": "MIT",
        "minimum_card_version": 1,
        "parameters_schema": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        "document": document,
        "sha256": hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest(),
    }


class MarketplaceCardWorkspaceContractTests(unittest.TestCase):
    def test_parser_dispatcher_and_store_are_profile_scoped_without_registration_side_effects(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            controller = WorkspaceController(
                backend=HermesWorkspaceBackend(service=SimpleNamespace(store=store))
            )
            wire = {
                "version": 1,
                "type": "workspace.request",
                "requestId": "marketplace-card-request-0001",
                "operation": "cards.templates.install",
                "payload": {"agentId": "personal", "template": _template()},
                "sentAt": 1_788_000_001,
            }

            try:
                request = parse_workspace_request(wire)
            except ValueError as error:
                self.fail(f"static card workspace parser rejected its declared operation: {error}")
            installed = asyncio.run(controller.execute(request))
            result = workspace_result(
                request=request,
                status="completed",
                payload=installed,
                sent_at=1_788_000_002,
            )

            self.assertEqual(result["requestId"], wire["requestId"])
            self.assertEqual(result["operation"], "cards.templates.install")
            self.assertTrue(result["payload"]["changed"])
            self.assertEqual(
                store.get_card_template(
                    profile="personal", template_id="marketplace-health"
                ),
                _template(),
            )
            self.assertIsNone(
                store.get_card_template(
                    profile="research", template_id="marketplace-health"
                )
            )


class _MarketplaceSkillInstaller:
    def __init__(self) -> None:
        self.installs: list[dict] = []

    async def install(self, payload: dict) -> dict:
        self.installs.append(payload)
        return {**payload, "installed": True, "changed": True}

    async def status(self, payload: dict) -> dict:
        return {**payload, "installed": bool(self.installs), "version": 1}


class MarketplaceSkillWorkspaceContractTests(unittest.TestCase):
    def test_parser_and_dispatcher_use_the_dedicated_skill_install_service(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            installer = _MarketplaceSkillInstaller()
            backend = HermesWorkspaceBackend(service=SimpleNamespace(store=store))
            backend.marketplace_skill_installer = installer
            controller = WorkspaceController(backend=backend)
            payload = {
                "agentId": "research",
                "itemId": "itm_01K4CV8BDQ8JH3V4X2Y6Z7W9AA",
                "version": 1,
                "sha256": "a" * 64,
                "approvalId": "apr_01K4CX5S4D8N2M6Q9V3Z7RTKPA",
                "requestId": "req_01K4CX5S4D8N2M6Q9V3Z7RTKPA",
            }
            wire = {
                "version": 1,
                "type": "workspace.request",
                "requestId": "marketplace-skill-request-0001",
                "operation": "marketplace.skills.install",
                "payload": payload,
                "sentAt": 1_788_000_001,
            }

            try:
                request = parse_workspace_request(wire)
            except ValueError as error:
                self.fail(
                    "static marketplace skill parser rejected its declared operation: "
                    f"{error}"
                )
            installed = asyncio.run(controller.execute(request))

            self.assertTrue(installed["installed"])
            self.assertEqual(installer.installs, [payload])

            status_wire = {
                **wire,
                "requestId": "marketplace-skill-request-0002",
                "operation": "marketplace.skills.status",
                "payload": {"agentId": "research", "itemId": payload["itemId"]},
            }
            status = asyncio.run(
                controller.execute(parse_workspace_request(status_wire))
            )
            self.assertTrue(status["installed"])

    def test_capabilities_are_opt_in_and_legacy_ready_envelope_stays_exact(self) -> None:
        from loopdy_plugin.link_client import LinkRuntimeConfig, LoopdyLinkClient
        from loopdy_plugin.marketplace import (
            CARD_TEMPLATE_CAPABILITY,
            MARKETPLACE_SKILL_CAPABILITY,
            build_marketplace_gateway_client,
        )

        class State:
            def __init__(self) -> None:
                self.values = {}

            def get(self, key, default=None):
                return self.values.get(key, default)

            def set(self, key, value):
                self.values[key] = value

        config = LinkRuntimeConfig(
            base_url="https://link.example.test",
            device_id="host-device-fixture",
            authorization_epoch=3,
            signing_private_key=ec.generate_private_key(ec.SECP256R1()),
            account_key=b"k" * 32,
        )
        self.assertIsNone(build_marketplace_gateway_client(config, values={}))
        legacy = LoopdyLinkClient(config, state=State())
        capable = LoopdyLinkClient(
            config,
            state=State(),
            capabilities=(CARD_TEMPLATE_CAPABILITY, MARKETPLACE_SKILL_CAPABILITY),
        )

        self.assertEqual(legacy.capabilities, ("socket-ready-v1", "backpressure-v1"))
        self.assertEqual(
            capable.capabilities,
            (
                "socket-ready-v1",
                "backpressure-v1",
                "cards-templates-v1",
                "marketplace-skills-hub-v1",
            ),
        )
        ready = {
            "version": 1,
            "type": "socket.ready",
            "deviceId": config.device_id,
            "authorizationEpoch": config.authorization_epoch,
            "lastInboundSequence": 0,
            "lastInboundFrameId": None,
            "lastAcknowledgedSequence": 0,
        }
        self.assertTrue(
            asyncio.run(
                legacy.handle_wire_message(json.dumps(ready), lambda _message: None)
            )
        )


if __name__ == "__main__":
    unittest.main()
