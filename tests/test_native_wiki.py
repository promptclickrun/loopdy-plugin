from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from loopdy_plugin import native_context, native_wiki_api
from loopdy_plugin.wiki_contract import available_wiki_operations
from loopdy_plugin.wiki_schema import migrate_owner_schema
from loopdy_plugin.wiki_service import WikiService, WikiServiceError
from loopdy_plugin.wiki_uploads import WikiUploads
import test_native_api as native_fixtures
from wiki_schema_fixtures import restore_legacy_schema


@unittest.skipUnless(available_wiki_operations(), "Requires secure traversal")
class NativeWikiTests(unittest.TestCase):
    def setUp(self):
        self.fixture = native_fixtures.NativeAPITests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.client = self.fixture.client
        self.client.app.include_router(native_wiki_api.router, prefix="/api/plugins/loopdy")
        self.home = self.fixture.home
        self.root = self.home / "notes"
        self.root.mkdir()
        (self.root / "index.md").write_bytes(b"# Original\n")
        self.state = self.home / "plugin-data/loopdy/wiki"

    def call(self, suffix, fields=None, *, token="fixture-alice", headers=None):
        return self.client.post(native_fixtures.PREFIX + "/wiki/" + suffix,
            headers=self.fixture.headers(token) if headers is None else headers,
            json={"agentId": "default", **(fields or {})})

    def connect(self):
        response = self.call("connect", {"folderPath": str(self.root)})
        self.assertEqual(response.status_code, 200, response.text)
        self.wiki_id = response.json()["wikiId"]
        return response.json()

    def read(self, **updates):
        return self.call("read", {"wikiId": self.wiki_id, "path": "index.md", "offset": 0, "limit": 65536, **updates})

    def begin(self, content=b"# Changed\n", operation="native-save"):
        read = self.read().json()
        body = {"wikiId": self.wiki_id, "path": "index.md", "baseRevision": read["revision"],
                "operationId": operation, "totalBytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        response = self.call("save/begin", body)
        self.assertEqual(response.status_code, 200, response.text)
        return body

    def test_native_login_alone_connects_and_same_principal_devices_resume_exact_upload(self):
        self.assertEqual(self.call("roots").json(), {"roots": []})
        root = self.connect()
        self.assertTrue(root["writable"])
        self.assertEqual(self.call("connect", {"folderPath": str(self.root)}).json(), root)
        self.assertEqual(self.call("resolve", {"folderPath": str(self.root)}).json(), root)
        content = b"# Shared principal\n" * 5000
        self.begin(content)
        first = self.call("save/chunk", {"operationId": "native-save", "offset": 0,
                         "data": base64.b64encode(content[:65536]).decode()})
        self.assertEqual(first.json()["nextOffset"], 65536)
        self.fixture.provider.tokens["another-device"] = replace(self.fixture.provider.alice,
                                                                  access_token="different-device-token")
        self.assertEqual(self.call("roots", token="another-device").json(), {"roots": [root]})
        status = self.call("save/status", {"operationId": "native-save"}, token="another-device")
        self.assertEqual(status.json()["nextOffset"], 65536)
        second = self.call("save/chunk", {"operationId": "native-save", "offset": 65536,
                          "data": base64.b64encode(content[65536:]).decode()}, token="another-device")
        self.assertEqual(second.json()["nextOffset"], len(content))
        committed = self.call("save/commit", {"operationId": "native-save"}, token="another-device")
        self.assertEqual(committed.json()["status"], "committed", committed.text)
        self.assertEqual((self.root / "index.md").read_bytes(), content)
        self.assertEqual(self.call("save/status", {"operationId": "native-save"}).json(), committed.json())
        self.assertEqual(self.call("save/commit", {"operationId": "native-save"}).json(), committed.json())
        with sqlite3.connect(self.state / "wiki.sqlite3") as connection:
            for table in ("wiki_uploads", "wiki_operations"):
                row = connection.execute(f"SELECT owner_kind,principal_id,device_id FROM {table}").fetchone()
                self.assertEqual(row[0], "native_principal")
                self.assertEqual(len(row[1]), 64)
                self.assertIsNone(row[2])
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)

    def test_wrong_principal_profile_device_fields_and_stale_context_fail(self):
        self.connect()
        self.begin()
        self.assertEqual(self.call("roots", token="fixture-bob").json(), {"roots": []})
        for token, fields in (("fixture-bob", {}), ("fixture-alice", {"agentId": "research"})):
            denied = self.call("save/status", {"operationId": "native-save", **fields}, token=token)
            self.assertEqual(denied.status_code, 404)
        self.assertEqual(self.call("connect", {"folderPath": str(self.root)}, token="fixture-bob").status_code, 404)
        for name in ("deviceId", "principalId", "owner_kind", "account_authorized", "authorizationEpoch"):
            self.assertEqual(self.call("roots", {name: "forged"}).status_code, 422)
        self.assertEqual(self.call("roots", {"agentId": "missing"}).status_code, 404)
        self.assertEqual(self.call("roots", headers={"Authorization": "Bearer fixture-alice"}).status_code, 428)
        headers = self.fixture.headers()
        self.fixture.provider.tokens.pop("fixture-alice")
        self.assertEqual(self.call("save/commit", {"operationId": "native-save"}, headers=headers).status_code, 401)
        self.assertEqual((self.root / "index.md").read_bytes(), b"# Original\n")

    def test_existing_link_root_is_not_adopted_and_legacy_device_revocation_stays_independent(self):
        link = WikiService(self.state, authority_id="link-authority")
        link.grant("link-notes", root=self.root, label="Notes", profile_id="default", device_ids=("phone-a",), writable=True)
        before = link.list_grants()
        conflict = self.call("connect", {"folderPath": str(self.root)})
        self.assertEqual(conflict.status_code, 409, conflict.text)
        self.assertEqual(conflict.json()["error"]["code"], "WIKI_AUTHORITY_CONFLICT")
        self.assertEqual(link.list_grants(), before)
        with self.assertRaises(WikiServiceError):
            link.read_file("link-notes", profile_id="default", device_id="phone-b", path="index.md")
        link.revoke("link-notes")
        with self.assertRaises(WikiServiceError):
            link.read_file("link-notes", profile_id="default", device_id="phone-a", path="index.md")
        self.connect()
        self.assertEqual(self.read().json()["text"], "# Original\n")
        self.assertEqual(link.roots(profile_id="default", device_id="phone-a"), {"roots": []})

    def test_bound_reads_search_creation_images_and_stale_revision(self):
        root = self.connect()
        listing = self.call("list", {"wikiId": self.wiki_id, "path": "", "offset": 0, "limit": 100, "query": ""})
        self.assertEqual(listing.json()["entries"][0]["name"], "index.md")
        found = self.call("search", {"wikiId": self.wiki_id, "query": "Original", "mode": "content", "offset": 0, "limit": 100})
        self.assertEqual(found.json()["matches"][0]["path"], "index.md")
        revision = self.read().json()["revision"]
        (self.root / "index.md").write_text("# Changed outside\n")
        self.assertEqual(self.read(revision=revision).status_code, 409)
        (self.root / "image.png").write_bytes(b"\x89PNG\r\n\x1a\nfixture")
        image = self.call("image", {"wikiId": self.wiki_id, "path": "image.png", "offset": 0, "limit": 65536})
        self.assertEqual(image.json()["availability"], "binary")
        self.assertIsNone(image.json()["text"])
        new = {"wikiId": self.wiki_id, "path": "new.md", "operationId": "create-page",
               "baseRevision": "wiki-new-v1:" + root["generation"], "totalBytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
        self.assertEqual(self.call("save/begin", new).status_code, 200)
        self.assertEqual(self.call("save/commit", {"operationId": "create-page"}).json()["status"], "committed")
        self.assertEqual((self.root / "new.md").read_bytes(), b"")
        for path in ("../index.md", "/etc/passwd", ".env"):
            self.assertGreaterEqual(self.read(path=path).status_code, 400)
        (self.root / "alias.md").symlink_to(self.root / "index.md")
        self.assertGreaterEqual(self.read(path="alias.md").status_code, 400)

    def test_partial_digest_conflict_and_uncertain_commit_are_not_blindly_repeated(self):
        self.connect()
        begin = self.begin()
        self.assertEqual(self.call("save/commit", {"operationId": "native-save"}).json()["error"]["code"], "UPLOAD_INCOMPLETE")
        conflict = self.call("save/begin", {**begin, "sha256": "0" * 64})
        self.assertEqual(conflict.json()["error"]["code"], "OPERATION_CONFLICT")
        self.call("save/chunk", {"operationId": "native-save", "offset": 0,
                               "data": base64.b64encode(b"# Changed\n").decode()})
        with patch.object(WikiService, "_save_file_locked", side_effect=OSError("synthetic interruption")):
            self.assertEqual(self.call("save/commit", {"operationId": "native-save"}).status_code, 503)
        status = self.call("save/status", {"operationId": "native-save"}).json()
        self.assertEqual(status["status"], "indeterminate")
        self.assertEqual(self.call("save/commit", {"operationId": "native-save"}).json(), status)
        self.assertEqual((self.root / "index.md").read_bytes(), b"# Original\n")

    def test_context_change_after_worker_rejects_receipt_without_claiming_rollback(self):
        original = native_wiki_api._execute
        runtime = native_context.RUNTIME_ID
        self.addCleanup(setattr, native_context, "RUNTIME_ID", runtime)
        def changed(*args):
            value = original(*args)
            native_context.RUNTIME_ID = "changed-runtime"
            return value
        with patch.object(native_wiki_api, "_execute", side_effect=changed):
            self.assertEqual(self.call("connect", {"folderPath": str(self.root)}).status_code, 412)
        self.assertEqual(len(self.call("roots").json()["roots"]), 1)

    def test_generated_mirror_and_export_native_roots_never_gain_write_access(self):
        self.connect()
        for source in ("generated", "mirror", "export"):
            with sqlite3.connect(self.state / "wiki.sqlite3") as connection:
                connection.execute("UPDATE wiki_grants SET source_kind=? WHERE wiki_id=?", (source, self.wiki_id))
            connected = self.call("connect", {"folderPath": str(self.root)}).json()
            self.assertFalse(connected["writable"])
            read = self.read().json()
            begin = self.call("save/begin", {"wikiId": self.wiki_id, "path": "index.md",
                "baseRevision": read["revision"], "operationId": "readonly-" + source, "totalBytes": 0,
                "sha256": hashlib.sha256(b"").hexdigest()})
            self.assertEqual(begin.status_code, 403)
            self.assertEqual(begin.json()["error"]["code"], "READ_ONLY")

    def test_atomic_legacy_migration_rolls_back_and_preserves_recovery_digest(self):
        link = WikiService(self.state, authority_id="link-authority")
        link.grant("old", root=self.root, label="Old", profile_id="default", device_ids=("phone",), writable=True)
        read = link.read_file("old", profile_id="default", device_id="phone", path="index.md")
        saved = link.save_file("old", profile_id="default", device_id="phone", path="index.md",
                              base_revision=read["revision"], content=b"# Legacy\n", operation_id="legacy-save")
        current = link.read_file("old", profile_id="default", device_id="phone", path="index.md")
        pending_content = b"# Pending legacy upload\n"
        uploads = WikiUploads(link)
        uploads.begin({"agentId": "default", "wikiId": "old", "path": "index.md",
            "baseRevision": current["revision"], "operationId": "legacy-upload",
            "totalBytes": len(pending_content), "sha256": hashlib.sha256(pending_content).hexdigest()}, device_id="phone")
        uploads.chunk({"agentId": "default", "operationId": "legacy-upload", "offset": 0,
                       "data": base64.b64encode(pending_content[:5]).decode()}, device_id="phone")
        before = link.list_grants()
        with link._locked() as connection:
            restore_legacy_schema(connection)
            class Fault:
                @property
                def in_transaction(self):
                    return connection.in_transaction
                def execute(self, sql, *args):
                    if sql.startswith("ALTER TABLE wiki_operations_owner_v2"):
                        raise sqlite3.OperationalError("injected migration failure")
                    return connection.execute(sql, *args)
                def commit(self):
                    connection.commit()
                def rollback(self):
                    connection.rollback()
            with self.assertRaises(sqlite3.OperationalError):
                migrate_owner_schema(Fault())
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertNotIn("owner_kind", [row[1] for row in connection.execute("PRAGMA table_info(wiki_grants)")])
            self.assertEqual(connection.execute("SELECT name FROM sqlite_master WHERE name LIKE '%owner_v2'").fetchall(), [])
        reopened = WikiService(self.state, authority_id="link-authority")
        self.assertEqual(reopened.list_grants(), before)
        self.assertEqual(reopened.save_status("legacy-save", profile_id="default", device_id="phone"), saved)
        with reopened._locked() as connection:
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(tuple(connection.execute("SELECT owner_kind,principal_id,device_id FROM wiki_operations").fetchone()),
                             ("link_device", None, "phone"))
        resumed = WikiUploads(reopened)
        self.assertEqual(resumed.status({"agentId": "default", "operationId": "legacy-upload"}, device_id="phone")["nextOffset"], 5)
        with self.assertRaises(WikiServiceError):
            resumed.status({"agentId": "default", "operationId": "legacy-upload"}, device_id="wrong-device")
        resumed.chunk({"agentId": "default", "operationId": "legacy-upload", "offset": 5,
                       "data": base64.b64encode(pending_content[5:]).decode()}, device_id="phone")
        self.assertEqual(resumed.commit({"agentId": "default", "operationId": "legacy-upload"}, device_id="phone")["status"], "committed")
        self.assertEqual((self.root / "index.md").read_bytes(), pending_content)

    def test_same_shared_lock_serializes_native_connects_and_legacy_reads(self):
        first = WikiService(self.state, authority_id="native-a", principal_id="principal-a")
        second = WikiService(self.state, authority_id="native-b", principal_id="principal-b")
        barrier = threading.Barrier(2)
        outcomes = []
        def connect(service):
            barrier.wait()
            try:
                outcomes.append(service.connect(str(self.root), profile_id="default", device_id=None))
            except WikiServiceError as error:
                outcomes.append(error.code)
        threads = [threading.Thread(target=connect, args=(service,)) for service in (first, second)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sum(isinstance(item, dict) for item in outcomes), 1)
        self.assertIn("WIKI_NOT_ALLOWED", outcomes)
        legacy = WikiService(self.state, authority_id="link-c")
        entered, finished = threading.Event(), threading.Event()
        def read():
            entered.set()
            legacy.roots(profile_id="default", device_id="phone")
            finished.set()
        with first._locked():
            thread = threading.Thread(target=read)
            thread.start()
            self.assertTrue(entered.wait(1))
            self.assertFalse(finished.wait(.1))
        thread.join(5)
        self.assertTrue(finished.is_set())

    def test_disconnect_is_principal_scoped_idempotent_and_reconnect_cannot_adopt_upload(self):
        old = self.connect()
        begin = self.begin()
        self.assertEqual(self.call("disconnect", {"wikiId": self.wiki_id}, token="fixture-bob").status_code, 404)
        self.assertEqual(self.call("disconnect", {"wikiId": self.wiki_id, "agentId": "research"}).status_code, 404)
        self.fixture.provider.tokens["other-device"] = self.fixture.provider.alice
        result = self.call("disconnect", {"wikiId": self.wiki_id}, token="other-device")
        self.assertEqual(result.json(), {"wikiId": self.wiki_id, "disconnected": True})
        self.assertEqual(self.call("disconnect", {"wikiId": self.wiki_id}).json(), result.json())
        self.assertEqual(self.call("disconnect", {"wikiId": "unknown"}).status_code, 404)
        self.assertEqual(self.call("roots").json(), {"roots": []})
        self.assertEqual((self.root / "index.md").read_bytes(), b"# Original\n")
        self.assertEqual(self.call("save/commit", {"operationId": "native-save"}).status_code, 404)
        fresh = self.connect()
        self.assertNotEqual(fresh["wikiId"], old["wikiId"])
        self.assertNotEqual(fresh["generation"], old["generation"])
        retry = self.call("save/begin", {**begin, "wikiId": fresh["wikiId"],
                         "baseRevision": self.read().json()["revision"]})
        self.assertEqual(retry.status_code, 404)
        self.assertEqual(self.call("disconnect", {"wikiId": old["wikiId"]}).json(), result.json())
        self.assertEqual(self.call("roots").json()["roots"], [fresh])
        with sqlite3.connect(self.state / "wiki.sqlite3") as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM wiki_uploads").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM wiki_native_disconnects").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_commit_finishes_before_concurrent_disconnect_without_journal_cascade(self):
        self.connect()
        self.begin()
        self.call("save/chunk", {"operationId": "native-save", "offset": 0,
                               "data": base64.b64encode(b"# Changed\n").decode()})
        entered, release, disconnected = threading.Event(), threading.Event(), threading.Event()
        results = {}
        original = WikiService._replace
        def paused(service, *args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise AssertionError("test writer release timed out")
            return original(service, *args, **kwargs)
        def commit():
            results["commit"] = self.call("save/commit", {"operationId": "native-save"})
        def disconnect():
            results["disconnect"] = self.call("disconnect", {"wikiId": self.wiki_id})
            disconnected.set()
        with patch.object(WikiService, "_replace", paused):
            writer = threading.Thread(target=commit)
            writer.start()
            self.assertTrue(entered.wait(3))
            revoker = threading.Thread(target=disconnect)
            revoker.start()
            self.assertFalse(disconnected.wait(.1))
            release.set()
            writer.join(5)
            revoker.join(5)
            self.assertFalse(writer.is_alive())
            self.assertFalse(revoker.is_alive())
        self.assertEqual(results["commit"].json()["status"], "committed")
        self.assertEqual(results["disconnect"].json()["disconnected"], True)
        self.assertEqual((self.root / "index.md").read_bytes(), b"# Changed\n")
        with sqlite3.connect(self.state / "wiki.sqlite3") as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM wiki_operations").fetchone()[0], 1)
            self.assertGreater(connection.execute("SELECT COUNT(*) FROM wiki_events").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM wiki_uploads").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM wiki_grants").fetchone()[0], 0)

    def test_disconnect_does_not_require_source_folder_and_quota_fails_before_removal(self):
        self.connect()
        with patch("loopdy_plugin.wiki_service._MAX_NATIVE_DISCONNECTS", 0):
            denied = self.call("disconnect", {"wikiId": self.wiki_id})
            self.assertEqual(denied.status_code, 413)
        self.assertEqual(len(self.call("roots").json()["roots"]), 1)
        (self.root / "index.md").unlink()
        self.root.rmdir()
        result = self.call("disconnect", {"wikiId": self.wiki_id})
        self.assertEqual(result.status_code, 200, result.text)


class NativeWikiStockTests(unittest.TestCase):
    @unittest.skipUnless(available_wiki_operations(), "Requires secure traversal")
    def test_stock_authenticated_wiki_connect_save_status_without_pairing(self):
        script = r'''
import base64, hashlib, os, sys
from pathlib import Path
from fastapi.testclient import TestClient
from hermes_cli.web_server import app
from hermes_cli.dashboard_auth.registry import register_provider
from test_native_api import FixtureProvider, PREFIX
register_provider(FixtureProvider())
app.state.auth_required=True
client=TestClient(app,base_url="http://localhost")
root=Path(os.environ["HOME"])/"notes"
root.mkdir()
(root/"index.md").write_text("# Original\n")
headers={"Authorization":"Bearer fixture-alice"}
context=client.get(PREFIX+"/context",headers=headers)
assert "native-wiki-v1" in context.json()["features"]
headers.update({"If-Match":context.headers["etag"],"X-Loopdy-Request-ID":"123e4567-e89b-42d3-a456-426614174000"})
def call(path,fields):
 r=client.post(PREFIX+"/wiki/"+path,headers=headers,json={"agentId":"default",**fields})
 assert r.status_code==200,(r.status_code,r.text)
 return r.json()
assert client.post(PREFIX+"/wiki/roots",json={"agentId":"default"}).status_code==401
connected=call("connect",{"folderPath":str(root)})
read=call("read",{"wikiId":connected["wikiId"],"path":"index.md","offset":0,"limit":65536})
content=b"# Native\n"
call("save/begin",{"wikiId":connected["wikiId"],"path":"index.md","baseRevision":read["revision"],
 "operationId":"stock-save","totalBytes":len(content),"sha256":hashlib.sha256(content).hexdigest()})
call("save/chunk",{"operationId":"stock-save","offset":0,"data":base64.b64encode(content).decode()})
assert call("save/commit",{"operationId":"stock-save"})["status"]=="committed"
assert call("save/status",{"operationId":"stock-save"})["status"]=="committed"
assert (root/"index.md").read_bytes()==content
assert not (Path(os.environ["HERMES_HOME"])/"plugin-data/loopdy/native-devices").exists()
(Path(os.environ["HERMES_HOME"])/"config.yaml").write_text("plugins:\n  enabled: []\n  disabled: [loopdy]\n")
assert client.post(PREFIX+"/wiki/roots",headers=headers,json={"agentId":"default"}).status_code==404
print("stock principal-only Wiki connect/save/status passed",file=sys.__stdout__,flush=True)
'''
        with tempfile.TemporaryDirectory(prefix="loopdy-wiki-http-", dir=Path(tempfile.gettempdir()).resolve()) as directory:
            home = Path(directory) / "hermes-home"
            (home / "plugins").mkdir(parents=True)
            (home / "plugins/loopdy").symlink_to(native_fixtures.ROOT, target_is_directory=True)
            (home / "config.yaml").write_text("plugins:\n  enabled: [loopdy]\n")
            env = {key: os.environ[key] for key in ("PATH", "PYTHONPATH") if key in os.environ}
            env.update(HOME=directory, HERMES_HOME=str(home), TMPDIR=directory, PYTHONDONTWRITEBYTECODE="1")
            result = subprocess.run([sys.executable, "-B", "-c", script], env=env, cwd=directory,
                                    capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("principal-only", result.stdout)
