"""Native routes with real Hermes auth middleware and temporary local state."""
from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient

from hermes_cli.dashboard_auth.base import DashboardAuthProvider, Session, TokenPrincipal
from hermes_cli.dashboard_auth.middleware import gated_auth_middleware
from hermes_cli.dashboard_auth.registry import register_provider, unregister_global_provider
from loopdy_plugin import native_api, native_context
from loopdy_plugin import room_activity
from loopdy_plugin.store import LoopdyStore
from test_loopdy_card_templates import _template


ROOT = Path(__file__).resolve().parents[1]
PREFIX = "/api/plugins/loopdy/native"


class FixtureProvider(DashboardAuthProvider):
    name = "native-fixture"
    display_name = "Synthetic native fixture"

    def __init__(self):
        self.alice = Session("alice", "not-returned@example.invalid", "Alice", "fixture-org",
                             self.name, int(time.time()) + 3600, "fixture-access-secret",
                             "fixture-refresh-secret")
        self.tokens = {"fixture-alice": self.alice,
                       "fixture-bob": replace(self.alice, user_id="bob", display_name="Bob")}

    def start_login(self, **kwargs):
        raise NotImplementedError

    def complete_login(self, **kwargs):
        raise NotImplementedError

    def verify_session(self, *, access_token):
        return self.tokens.get(access_token)

    def refresh_session(self, **kwargs):
        raise NotImplementedError

    def revoke_session(self, **kwargs):
        raise NotImplementedError


class NativeAPITests(unittest.TestCase):
    def setUp(self):
        hub_patch = patch.object(room_activity, "_HUB", room_activity.RoomActivityHub())
        hub_patch.start()
        self.addCleanup(hub_patch.stop)
        temporary = tempfile.TemporaryDirectory(prefix="loopdy-native-api-", dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        (self.home / "profiles/research").mkdir(parents=True)
        self.environment = patch.dict(os.environ, {"HERMES_HOME": str(self.home), "HOME": str(self.home)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.store = LoopdyStore(self.home / "fixture.sqlite3")
        self.service_patch = patch("loopdy_plugin.adapter.get_service", return_value=SimpleNamespace(store=self.store))
        self.service_patch.start()
        self.addCleanup(self.service_patch.stop)
        self.provider = FixtureProvider()
        register_provider(self.provider)
        self.addCleanup(unregister_global_provider, self.provider.name, self.provider)
        app = FastAPI()
        app.state.auth_required = True
        app.middleware("http")(gated_auth_middleware)
        app.include_router(native_api.router, prefix="/api/plugins/loopdy")
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def context(self, token="fixture-alice"):
        return self.client.get(PREFIX + "/context", headers={"Authorization": "Bearer " + token})

    def headers(self, token="fixture-alice"):
        context = self.context(token)
        self.assertEqual(context.status_code, 200, context.text)
        return {"Authorization": "Bearer " + token, "If-Match": context.headers["etag"],
                "X-Loopdy-Request-ID": str(uuid.uuid4())}

    def post(self, operation, payload, headers=None):
        return self.client.post(PREFIX + "/cards/templates/" + operation,
                                headers=self.headers() if headers is None else headers, json=payload)

    def test_context_exact_safe_identity_cookie_and_no_unimplemented_features(self):
        result = self.context()
        value = result.json()
        self.assertEqual(set(value), {"schemaVersion", "pluginVersion", "runtimeId",
                                     "servingProfileId", "principal", "features"})
        self.assertEqual(value["principal"], {"provider": "native-fixture", "userId": "alice", "displayName": "Alice"})
        from loopdy_plugin.wiki_contract import available_wiki_operations
        expected = ["native-context-v1", "serving-profile-v1", "native-card-templates-v1"]
        if available_wiki_operations():
            expected.extend(("native-wiki-v1", "native-wiki-disconnect-v1"))
        from loopdy_plugin.native_project_git import supported
        if supported():
            expected.append("native-project-git-read-v1")
        self.assertEqual(value["features"], expected)
        self.assertEqual(value["servingProfileId"], "default")
        self.assertEqual(result.headers["cache-control"], "no-store")
        self.assertRegex(result.headers["etag"], r'^"sha256:[0-9a-f]{64}"$')
        self.assertEqual(result.headers["etag"], self.context().headers["etag"])
        for secret in ("fixture-access-secret", "fixture-refresh-secret", "not-returned@", "fixture-org", str(self.home)):
            self.assertNotIn(secret, result.text)
        self.client.cookies.set("hermes_session_at", "fixture-alice")
        cookie = self.client.get(PREFIX + "/context")
        self.assertEqual(cookie.status_code, 200, cookie.text)
        self.assertEqual(cookie.json(), value)
        for path in ("/wiki/roots", "/groups/send", "/phone-tools/poll"):
            self.assertEqual(self.client.post(PREFIX + path).status_code, 404)

    def test_requires_real_unexpired_session_and_rechecks_revocation(self):
        self.assertEqual(self.client.get(PREFIX + "/context").status_code, 401)
        self.assertEqual(self.context("invalid").status_code, 401)
        for invalid in (
            TokenPrincipal("service", "fixture", ()),
            SimpleNamespace(provider="native-fixture", user_id="pretend"),
            replace(self.provider.alice, expires_at=0),
            replace(self.provider.alice, expires_at=True),
            replace(self.provider.alice, user_id="a" * 513),
            replace(self.provider.alice, user_id="bad\nidentity"),
            replace(self.provider.alice, display_name="\ud800"),
        ):
            with self.subTest(identity_type=type(invalid).__name__):
                self.provider.tokens["invalid-object"] = invalid
                self.assertEqual(self.context("invalid-object").status_code, 401)
        headers = self.headers()
        self.provider.tokens.pop("fixture-alice")
        self.assertEqual(self.post("list", {"agentId": "default"}, headers).status_code, 401)

    def test_loopback_no_auth_gate_does_not_invent_person(self):
        self.client.app.state.auth_required = False
        result = self.client.get(PREFIX + "/context", headers={
            "Authorization": "Bearer fixture-alice",
            "X-Hermes-Session-Token": "legacy", "X-Actor-ID": "alice",
        })
        self.assertEqual(result.status_code, 401)
        self.assertEqual(result.json()["error"]["code"], "native_identity_required")

    def test_process_profile_ignores_request_override_and_null_is_unproven(self):
        from hermes_constants import set_hermes_home_override, reset_hermes_home_override
        first = self.context()
        token = set_hermes_home_override(self.home / "profiles/research")
        try:
            self.assertEqual(self.context().json()["servingProfileId"], "default")
            self.assertEqual(self.context().headers["etag"], first.headers["etag"])
        finally:
            reset_hermes_home_override(token)
        with patch("hermes_constants.profile_name_for_home", return_value=None):
            context = self.context()
            self.assertIsNone(context.json()["servingProfileId"])
            self.assertNotIn("serving-profile-v1", context.json()["features"])
            self.assertNotEqual(first.headers["etag"], context.headers["etag"])
        with patch("hermes_constants.profile_name_for_home", return_value="../private"):
            self.assertEqual(self.context().status_code, 503)

    def test_context_takes_no_body_or_selected_profile_query(self):
        for path in ("/context?profile=research", "/context?actor=alice"):
            self.assertEqual(self.client.get(PREFIX + path, headers=self.headers()).status_code, 422)
        self.assertEqual(self.client.request("GET", PREFIX + "/context", headers=self.headers(),
                                            content=b"x" * 200_000).status_code, 422)

    def test_template_headers_are_required_exact_and_echoed(self):
        headers = self.headers()
        response = self.post("list", {"agentId": "default"}, headers)
        self.assertEqual(response.json(), {"agentId": "default", "templates": []})
        self.assertEqual(response.headers["etag"], headers["If-Match"])
        self.assertEqual(response.headers["x-loopdy-request-id"], headers["X-Loopdy-Request-ID"])
        for changes, status in (({"If-Match": None}, 428), ({"If-Match": '"stale"'}, 412),
                                ({"X-Loopdy-Request-ID": None}, 422),
                                ({"X-Loopdy-Request-ID": "arbitrary"}, 422),
                                ({"Authorization": "Bearer fixture-bob"}, 412)):
            altered = {key: value for key, value in {**headers, **changes}.items() if value is not None}
            rejected = self.post("list", {"agentId": "default"}, altered)
            self.assertEqual(rejected.status_code, status)
            if status != 422:
                self.assertEqual(rejected.headers["x-loopdy-request-id"], headers["X-Loopdy-Request-ID"])
            self.assertNotIn("etag", rejected.headers)
        with patch.object(native_context, "RUNTIME_ID", uuid.uuid4().hex):
            self.assertEqual(self.post("list", {"agentId": "default"}, headers).status_code, 412)
        duplicate = list(headers.items()) + [("If-Match", headers["If-Match"])]
        self.assertEqual(self.post("list", {"agentId": "default"}, duplicate).status_code, 412)

    def test_templates_reuse_store_profiles_conflicts_and_repeat_outcomes(self):
        template = _template()
        body = {"agentId": "research", "template": template}
        installed = self.post("install", body)
        self.assertEqual(installed.status_code, 200, installed.text)
        self.assertTrue(installed.json()["changed"])
        self.assertEqual(self.store.get_card_template(profile="research", template_id=template["id"]), template)
        self.assertFalse(self.post("install", body).json()["changed"])
        self.assertEqual(self.post("list", {"agentId": "default"}).json()["templates"], [])
        listed = self.post("list", {"agentId": "research"}).json()["templates"]
        self.assertEqual(listed, [installed.json()["template"]])
        self.assertNotIn("document", listed[0])
        changed = {**template, "name": "Different immutable version"}
        self.assertEqual(self.post("install", {**body, "template": changed}).status_code, 409)
        remove = {"agentId": "research", "templateId": template["id"], "version": 2, "sha256": template["sha256"]}
        self.assertEqual(self.post("remove", remove).status_code, 409)
        remove["version"] = 1
        self.assertTrue(self.post("remove", remove).json()["changed"])
        self.assertFalse(self.post("remove", remove).json()["changed"])

    def test_unknown_profiles_and_fake_authority_or_bad_bundle_rejected(self):
        self.assertEqual(self.post("list", {"agentId": "missing"}).status_code, 404)
        for key in ("actor", "deviceId", "hostId", "authorizationEpoch", "profile", "command"):
            self.assertEqual(self.post("list", {"agentId": "default", key: "pretend"}).status_code, 422)
        for field, value in (("version", True), ("minimum_card_version", True),
                             ("sha256", "0" * 64), ("name", "x" * 121)):
            template = {**_template(), field: value}
            self.assertEqual(self.post("install", {"agentId": "default", "template": template}).status_code, 422)
        template = _template()
        template["document"]["data_sources"] = [{"url": "https://example.invalid/executable"}]
        self.assertEqual(self.post("install", {"agentId": "default", "template": template}).status_code, 422)
        self.assertEqual(self.store.list_card_templates(profile="default"), [])

    def test_malformed_nested_duplicate_and_oversize_bodies_are_bounded(self):
        path = PREFIX + "/cards/templates/list"
        for content, expected in (
            ('{"agentId":"default","agentId":"research"}', 422),
            ('{"agentId":NaN}', 422),
            ('{"agentId":"default","x":' + "[" * 40 + "0" + "]" * 40 + "}", 422),
            ("x" * (native_api.MAX_BODY_BYTES + 1), 413),
        ):
            response = self.client.post(path, headers={**self.headers(), "Content-Type": "application/json"},
                                        content=content)
            self.assertEqual(response.status_code, expected, response.text)
            self.assertLess(len(response.content), 512)
        self.assertEqual(self.client.post(path, headers=self.headers(), content="not-json").status_code, 422)

    def test_context_change_after_worker_prevents_stale_result_and_reconciles_mutation(self):
        original = native_api._templates
        def changes_identity(*args):
            result = original(*args)
            # Simulate an authority/runtime change while the event loop awaits I/O.
            native_context.RUNTIME_ID = "changed-runtime"
            return result
        before = native_context.RUNTIME_ID
        self.addCleanup(setattr, native_context, "RUNTIME_ID", before)
        with patch.object(native_api, "_templates", side_effect=changes_identity):
            response = self.post("install", {"agentId": "default", "template": _template()})
        self.assertEqual(response.status_code, 412)
        # A stale receipt is not proof that the underlying transaction rolled back.
        self.assertEqual(len(self.post("list", {"agentId": "default"}).json()["templates"]), 1)

    def test_catalog_rows_and_bytes_fail_without_truncation(self):
        template = _template()
        template["summary"] = "x" * 1000
        self.store.install_card_template(profile="default", template=template)
        with self.store._connect() as connection:
            encoded = connection.execute("SELECT template_json FROM card_templates").fetchone()[0]
            connection.executemany(
                "INSERT INTO card_templates(profile,template_id,version,name,summary,sha256,template_json,created_at,updated_at) "
                "VALUES('default',?,1,?,?,?,?,0,0)",
                [(f"fixture-{index}", template["name"], template["summary"], template["sha256"], encoded)
                 for index in range(499)],
            )
        response = self.post("list", {"agentId": "default"})
        self.assertEqual(response.status_code, 413)
        self.assertNotIn("templates", response.json())
        self.store.install_card_template(profile="default", template=_template(template_id="over-limit"))
        self.assertEqual(self.post("list", {"agentId": "default"}).json()["error"]["code"], "catalog_too_large")
        self.assertEqual(len(self.store.list_card_templates(profile="default")), 501)


class NativeStockServeTests(unittest.TestCase):
    def test_actual_stock_discovery_bearer_cookie_legacy_and_runtime_disable(self):
        script = r'''
import os, sys
from pathlib import Path
from fastapi.testclient import TestClient
from hermes_cli.web_server import app
from hermes_cli.dashboard_auth.registry import register_provider
from test_native_api import FixtureProvider, PREFIX, _template
from loopdy_plugin import native_api
home = Path(os.environ["HERMES_HOME"])
candidate = Path(os.environ["CANDIDATE_ROOT"])
assert Path(sys.modules["hermes_cli.web_server"].__file__).resolve().parent.parent == Path(os.environ["EXPECTED_HERMES_SOURCE"])
assert Path(native_api.__file__).resolve() == candidate / "loopdy_plugin/native_api.py"
assert Path(sys.modules["hermes_dashboard_plugin_loopdy"].__file__).resolve() == candidate / "dashboard/plugin_api.py"
provider = FixtureProvider()
register_provider(provider)
app.state.auth_required = True
client = TestClient(app, base_url="http://localhost")
assert client.get(PREFIX + "/context").status_code == 401
assert client.get(PREFIX + "/context", headers={"Authorization":"Bearer bogus"}).status_code == 401
headers = {"Authorization":"Bearer fixture-alice"}
context = client.get(PREFIX + "/context", headers=headers)
assert context.status_code == 200, (context.status_code, context.text)
assert context.json()["principal"]["userId"] == client.get("/api/auth/me", headers=headers).json()["user_id"]
headers.update({"If-Match":context.headers["etag"],"X-Loopdy-Request-ID":"123e4567-e89b-42d3-a456-426614174000"})
installed = client.post(PREFIX + "/cards/templates/install", headers=headers, json={"agentId":"default","template":_template()})
assert installed.status_code == 200 and installed.json()["changed"], (installed.status_code, installed.text)
assert installed.headers["etag"] == headers["If-Match"]
client.cookies.set("hermes_session_at", "fixture-alice")
assert client.get(PREFIX + "/context").status_code == 200
client.cookies.clear()
provider.tokens.pop("fixture-alice")
assert client.post(PREFIX + "/cards/templates/list", headers=headers, json={"agentId":"default"}).status_code == 401
provider.tokens["fixture-alice"] = provider.alice
(home / "config.yaml").write_text("plugins:\n  enabled: []\n  disabled: [loopdy]\n")
assert client.get(PREFIX + "/context", headers=headers).status_code == 404
(home / "config.yaml").write_text("plugins:\n  enabled: [loopdy]\n")
app.state.auth_required = False
legacy = {"X-Hermes-Session-Token":os.environ["HERMES_DASHBOARD_SESSION_TOKEN"]}
assert client.get("/api/plugins/loopdy/capabilities", headers=legacy).status_code == 200
assert client.get(PREFIX + "/context", headers=legacy).status_code == 401
print("native stock mount, verified bearer/cookie, revocation, disabled gate, legacy isolation passed")
'''
        with tempfile.TemporaryDirectory(prefix="loopdy-native-stock-", dir=Path(tempfile.gettempdir()).resolve()) as directory:
            home = Path(directory) / "hermes-home"
            (home / "plugins").mkdir(parents=True)
            (home / "plugins/loopdy").symlink_to(ROOT, target_is_directory=True)
            (home / "config.yaml").write_text("plugins:\n  enabled: [loopdy]\n")
            env = {key: os.environ[key] for key in ("PATH", "PYTHONPATH") if key in os.environ}
            env.update(HOME=directory, HERMES_HOME=str(home), TMPDIR=directory,
                       PYTHONDONTWRITEBYTECODE="1", CANDIDATE_ROOT=str(ROOT),
                       EXPECTED_HERMES_SOURCE=str(Path(sys.modules["hermes_cli"].__file__).resolve().parent.parent),
                       HERMES_DASHBOARD_SESSION_TOKEN=uuid.uuid4().hex)
            result = subprocess.run([sys.executable, "-B", "-c", script], env=env,
                                    cwd=directory, capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("native stock mount", result.stdout)


if __name__ == "__main__":
    unittest.main()
