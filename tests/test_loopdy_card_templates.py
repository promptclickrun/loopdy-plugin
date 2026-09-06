from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from loopdy_plugin.link_contracts import parse_workspace_request, workspace_result
from loopdy_plugin.loopdy_cards import canonical_json, validate_card_result
from loopdy_plugin.registration import register as register_plugin
from loopdy_plugin.store import LoopdyStore
from loopdy_plugin.tools import register as register_tools
from loopdy_plugin.workspace_control import HermesWorkspaceBackend, WorkspaceController


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
CARD_FIXTURE = PLUGIN_ROOT / "fixtures" / "loopdy_card_v1" / "static-metrics.json"
NOW = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)


def _template(*, template_id: str = "build-health", version: int = 1, name: str = "Build health") -> dict:
    value = {
        "id": template_id,
        "version": version,
        "name": name,
        "summary": "Show bounded build health metrics.",
        "author": "Loopdy",
        "license": "MIT",
        "minimum_card_version": 1,
        "parameters_schema": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        "document": json.loads(CARD_FIXTURE.read_text(encoding="utf-8")),
    }
    value["sha256"] = hashlib.sha256(
        canonical_json(value["document"]).encode("utf-8")
    ).hexdigest()
    return value


def _template_projection(template: dict) -> dict:
    return {
        key: template[key]
        for key in (
            "id", "version", "name", "summary", "author", "license",
            "minimum_card_version", "sha256",
        )
    }


class _PluginContext:
    profile_name = "personal"
    state = None

    def __init__(self) -> None:
        self.tools: dict[str, Callable[..., str]] = {}
        self.schemas: dict[str, dict[str, Any]] = {}

    def register_tool(self, *, name, handler, schema, **_kwargs) -> None:
        self.tools[name] = handler
        self.schemas[name] = schema

    def register_platform(self, **_kwargs) -> None: pass
    def register_approval_transport(self, *_args) -> None: pass
    def register_hook(self, *_args) -> None: pass
    def register_cli_command(self, **_kwargs) -> None: pass
    def register_skill(self, *_args, **_kwargs) -> None: pass
    def on_unload(self, *_args) -> None: pass


class _Service:
    def __init__(self, store: LoopdyStore) -> None:
        self.store = store

    def enqueue(self, *_args, **_kwargs) -> None:
        raise AssertionError("card templates must not use notification relay delivery")


class LoopdyCardTemplateStoreTests(unittest.TestCase):
    def test_install_lists_only_the_owning_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")

            result = store.install_card_template(profile="personal", template=_template())

            self.assertEqual(result, {"changed": True, "template": _template()})
            self.assertEqual(store.list_card_templates(profile="personal"), [_template()])
            self.assertEqual(store.list_card_templates(profile="research"), [])

    def test_install_rejects_schema_card_and_hash_mismatches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            missing = _template()
            del missing["license"]
            with self.assertRaisesRegex(ValueError, "schema"):
                store.install_card_template(profile="personal", template=missing)

            invalid_card = _template()
            invalid_card["document"]["schema"] = "not.loopdy.card"
            invalid_card["sha256"] = hashlib.sha256(
                canonical_json(invalid_card["document"]).encode("utf-8")
            ).hexdigest()
            with self.assertRaisesRegex(ValueError, "Loopdy Card schema"):
                store.install_card_template(profile="personal", template=invalid_card)

            bad_hash = _template()
            bad_hash["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "hash"):
                store.install_card_template(profile="personal", template=bad_hash)

    def test_install_is_idempotent_and_rejects_version_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            template = _template()
            store.install_card_template(profile="personal", template=template)

            self.assertEqual(
                store.install_card_template(profile="personal", template=template)["changed"],
                False,
            )
            conflicting = _template(name="Different build card")
            with self.assertRaisesRegex(ValueError, "version conflict"):
                store.install_card_template(profile="personal", template=conflicting)
            upgrade = _template(version=2, name="Build health 2")
            self.assertTrue(store.install_card_template(profile="personal", template=upgrade)["changed"])
            with self.assertRaisesRegex(ValueError, "cannot decrease"):
                store.install_card_template(profile="personal", template=template)

    def test_remove_requires_current_coordinates_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            template = _template()
            store.install_card_template(profile="personal", template=template)

            with self.assertRaisesRegex(ValueError, "removal conflict"):
                store.remove_card_template(
                    profile="personal",
                    template_id=template["id"],
                    version=template["version"],
                    sha256="0" * 64,
                )
            self.assertTrue(store.remove_card_template(
                profile="personal",
                template_id=template["id"],
                version=template["version"],
                sha256=template["sha256"],
            )["changed"])
            self.assertFalse(store.remove_card_template(
                profile="personal",
                template_id=template["id"],
                version=template["version"],
                sha256=template["sha256"],
            )["changed"])

    def test_reconnect_reads_the_same_profile_scoped_sqlite_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "loopdy.sqlite3"
            LoopdyStore(path).install_card_template(profile="personal", template=_template())

            reconnected = LoopdyStore(path)

            self.assertEqual(reconnected.get_card_template(
                profile="personal", template_id="build-health"
            ), _template())
            self.assertIsNone(reconnected.get_card_template(
                profile="research", template_id="build-health"
            ))


class LoopdyCardTemplateWorkspaceTests(unittest.TestCase):
    def test_exact_operations_use_request_bound_encrypted_workspace_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            service = _Service(store)
            register_plugin(_PluginContext(), service=service)
            controller = WorkspaceController(backend=HermesWorkspaceBackend(service=service))
            operations = {
                "cards.templates.list",
                "cards.templates.install",
                "cards.templates.remove",
            }
            self.assertTrue(operations.issubset(controller.operations))

            install_wire = {
                "version": 1,
                "type": "workspace.request",
                "requestId": "card-template-request-0001",
                "operation": "cards.templates.install",
                "payload": {"agentId": "personal", "template": _template()},
                "sentAt": 1_788_000_001,
            }
            request = parse_workspace_request(install_wire)
            installed = asyncio.run(controller.execute(request))
            result = workspace_result(
                request=request,
                status="completed",
                payload=installed,
                sent_at=1_788_000_002,
            )

            self.assertEqual(result["requestId"], install_wire["requestId"])
            self.assertEqual(result["operation"], install_wire["operation"])
            self.assertEqual(result["payload"]["agentId"], "personal")
            self.assertTrue(result["payload"]["changed"])
            self.assertEqual(result["payload"]["template"], _template_projection(_template()))

            def execute(operation: str, request_id: str, payload: dict) -> dict:
                request = parse_workspace_request({
                    "version": 1,
                    "type": "workspace.request",
                    "requestId": request_id,
                    "operation": operation,
                    "payload": payload,
                    "sentAt": 1_788_000_003,
                })
                return asyncio.run(controller.execute(request))

            listed = execute(
                "cards.templates.list",
                "card-template-request-0002",
                {"agentId": "personal"},
            )
            self.assertEqual(listed, {
                "agentId": "personal",
                "templates": [_template_projection(_template())],
            })
            self.assertEqual(execute(
                "cards.templates.list",
                "card-template-request-0003",
                {"agentId": "research"},
            ), {"agentId": "research", "templates": []})
            with self.assertRaisesRegex(ValueError, "ownership"):
                execute(
                    "cards.templates.list",
                    "card-template-request-0004",
                    {"agentId": "../personal"},
                )
            removed = execute(
                "cards.templates.remove",
                "card-template-request-0005",
                {
                    "agentId": "personal",
                    "templateId": _template()["id"],
                    "version": _template()["version"],
                    "sha256": _template()["sha256"],
                },
            )
            self.assertEqual(removed, {
                "agentId": "personal",
                "changed": True,
                "templateId": "build-health",
            })


class LoopdyCardTemplateToolTests(unittest.TestCase):
    def test_profile_scoped_search_get_and_render_register_as_generic_tools(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            store.install_card_template(profile="personal", template=_template())
            context = _PluginContext()

            register_tools(context, store=store, profile="personal", now=lambda: NOW)

            names = {
                "loopdy_search_card_templates",
                "loopdy_get_card_template",
                "loopdy_render_card_template",
            }
            self.assertTrue(names.issubset(context.tools))
            search = json.loads(context.tools["loopdy_search_card_templates"]({"query": "health"}))
            self.assertEqual([item["id"] for item in search["templates"]], ["build-health"])
            fetched = json.loads(context.tools["loopdy_get_card_template"]({
                "template_id": "build-health"
            }))
            self.assertEqual(fetched["template"], _template())
            rendered = json.loads(context.tools["loopdy_render_card_template"]({
                "template_id": "build-health",
                "parameters": {},
            }))
            self.assertEqual(validate_card_result(rendered, now=NOW), rendered)

            isolated = _PluginContext()
            isolated.profile_name = "research"
            register_plugin(isolated, service=_Service(store))
            self.assertEqual(
                json.loads(isolated.tools["loopdy_search_card_templates"]({"query": ""})),
                {"templates": []},
            )
            with self.assertRaisesRegex(ValueError, "not found"):
                isolated.tools["loopdy_get_card_template"]({"template_id": "build-health"})

    def test_render_template_validates_and_substitutes_declared_parameters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = LoopdyStore(Path(directory) / "loopdy.sqlite3")
            template = _template(template_id="status-card")
            template["parameters_schema"] = {
                "type": "object",
                "properties": {"Status-Label": {"type": "string", "enum": ["Ready", "Blocked"]}},
                "required": ["Status-Label"],
                "additionalProperties": False,
            }
            template["document"]["title"] = "{{Status-Label}}"
            template["document"]["spoken_summary"] = "Build is {{Status-Label}}"
            template["document"]["elements"]["status"]["props"]["value"]["literal"] = "{{Status-Label}}"
            template["sha256"] = hashlib.sha256(
                canonical_json(template["document"]).encode("utf-8")
            ).hexdigest()
            store.install_card_template(profile="personal", template=template)
            context = _PluginContext()
            register_tools(context, store=store, profile="personal", now=lambda: NOW)

            rendered = json.loads(context.tools["loopdy_render_card_template"]({
                "template_id": "status-card",
                "parameters": {"Status-Label": "Ready"},
            }))

            self.assertEqual(rendered["title"], "Ready")
            self.assertEqual(rendered["spoken_summary"], "Build is Ready")
            self.assertEqual(
                rendered["elements"]["status"]["props"]["value"]["literal"],
                "Ready",
            )
            self.assertEqual(validate_card_result(rendered, now=NOW), rendered)
            with self.assertRaisesRegex(ValueError, "invalid"):
                context.tools["loopdy_render_card_template"]({
                    "template_id": "status-card",
                    "parameters": {"Status-Label": "Unknown"},
                })

            unsafe = _template(template_id="unsafe-pointer")
            unsafe["parameters_schema"] = {
                "type": "object",
                "properties": {"Field": {"type": "string", "enum": ["passed"]}},
                "required": ["Field"],
                "additionalProperties": False,
            }
            expires = datetime.now(timezone.utc) + timedelta(days=1)
            unsafe["document"]["data_sources"] = [{
                "id": "feed",
                "request": {"method": "GET", "url": "https://example.com/status.json"},
                "response": {"format": "json", "root": ""},
                "refresh": {
                    "minimum_interval_seconds": 60,
                    "stale_after_seconds": 60,
                    "expires_at": expires.isoformat().replace("+00:00", "Z"),
                },
            }]
            unsafe["document"]["elements"]["passed"]["props"]["value"] = {
                "source": "feed",
                "pointer": "/{{Field}}",
            }
            unsafe["sha256"] = hashlib.sha256(
                canonical_json(unsafe["document"]).encode("utf-8")
            ).hexdigest()
            with self.assertRaisesRegex(ValueError, "Live Loopdy Card data sources"):
                store.install_card_template(profile="personal", template=unsafe)


if __name__ == "__main__":
    unittest.main()
