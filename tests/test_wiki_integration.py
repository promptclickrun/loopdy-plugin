"""Candidate-only Wiki acceptance through real crypto, dispatch and disk.

The runner supplies a credential-free HERMES_HOME before importing this module.
Only network acknowledgements and unrelated provider delivery are test doubles.
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from gateway.config import PlatformConfig
from loopdy_plugin.adapter import LoopdyAdapter
from loopdy_plugin.link_client import LoopdyLinkClient
from loopdy_plugin.link_crypto import AccountCipher
from loopdy_plugin.link_contracts import parse_workspace_request, workspace_result
from loopdy_plugin.wiki_service import WikiServiceError
from loopdy_plugin.wiki_contract import available_wiki_operations
from loopdy_plugin.wiki_transport import WikiTransport, WikiRequestContext, authority_id, production_factory
from loopdy_plugin.workspace_control import WorkspaceController
from loopdy_plugin.workspace_files import WorkspaceFilesError
from test_adapter import _Service
import test_link_client as link_fixtures
from test_link_client import _State


@unittest.skipUnless(available_wiki_operations(), "Requires secure descriptor-relative traversal")
class WikiIntegrationTests(unittest.TestCase):
    def setUp(self):
        from gateway.platform_registry import PlatformEntry, platform_registry
        platform_registry.register(PlatformEntry(name='loopdy', label='Loopdy',
            adapter_factory=lambda config: LoopdyAdapter(config), check_fn=lambda: True))
        self.temp = tempfile.TemporaryDirectory(prefix='wiki-acceptance-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'notes'
        self.root.mkdir()
        self.path = self.root / 'index.md'
        self.path.write_bytes(b'\xef\xbb\xbf# Original\r\n')
        _, config = link_fixtures.LinkClientTests()._configuration()
        self.config = replace(config, account_key=os.urandom(32))
        self.transport = WikiTransport(state_dir=self.base / 'state', config_getter=lambda: self.config)
        self.service = self.transport.host_service()
        self.service.grant('notes', root=self.root, label='Notes', profile_id='default',
                           device_ids=('mobile-device-1',), writable=True)
        self.context = WikiRequestContext(self.config.device_id, 'mobile-device-1',
                                          authority_id(self.config), 1)

    def execute(self, operation, **payload):
        return self.transport.execute(operation, {'agentId': 'default', **payload}, context=self.context)

    def upload(self, content, operation_id=None):
        operation_id = operation_id or 'save-' + uuid.uuid4().hex
        original = self.execute('wiki.read', wikiId='notes', path='index.md', offset=0, limit=65536)
        begin = dict(wikiId='notes', path='index.md', baseRevision=original['revision'],
                     operationId=operation_id, totalBytes=len(content), sha256=hashlib.sha256(content).hexdigest())
        self.execute('wiki.save.begin', **begin)
        for offset in range(0, len(content), 65536):
            self.execute('wiki.save.chunk', operationId=operation_id, offset=offset,
                         data=base64.b64encode(content[offset:offset + 65536]).decode('ascii'))
        return operation_id, begin

    def test_cold_host_connect_is_read_only_and_discovers_nested_markdown(self):
        home = self.base / "fresh-hermes"
        home.mkdir(mode=0o700)
        transport = production_factory(host_home=home, config_getter=lambda: self.config)
        self.assertFalse((home / "plugin-data").exists())
        notes = self.base / "new-notes"
        (notes / "nested" / "deeper").mkdir(parents=True)
        (notes / "nested" / "deeper" / "plan.md").write_text("# Nested plan\nunique body content\n")
        binary = notes / "nested" / "deeper" / "paper.pdf"
        binary.write_bytes(b"%PDF-fixture\x00")
        def call(op, **fields):
            return transport.execute(op, {"agentId": "default", **fields}, context=self.context)
        with self.assertRaises(WikiServiceError) as denied:
            call("wiki.resolve", folderPath=str(notes))
        self.assertEqual(denied.exception.code, "WIKI_NOT_ALLOWED")
        root = call("wiki.connect", folderPath=str(notes))
        self.assertFalse(root["writable"])
        self.assertEqual(root["folderPath"], str(notes))
        self.assertEqual(call("wiki.connect", folderPath=str(notes)), root)
        self.assertEqual(call("wiki.resolve", folderPath=str(notes)), root)
        self.assertEqual(call("wiki.roots")["roots"], [root])
        for mode, query in (("name", "plan"), ("content", "unique")):
            page = call("wiki.search", wikiId=root["wikiId"], query=query, mode=mode, offset=0, limit=100)
            self.assertEqual([hit["path"] for hit in page["matches"]], ["nested/deeper/plan.md"])
        read = call("wiki.read", wikiId=root["wikiId"], path="nested/deeper/plan.md", offset=0, limit=65536)
        self.assertEqual(read["text"], "# Nested plan\nunique body content\n")
        with self.assertRaises(WikiServiceError) as denied:
            call("wiki.save.begin", wikiId=root["wikiId"], path="nested/deeper/plan.md",
                 baseRevision=read["revision"], operationId="read-only-connect", totalBytes=0,
                 sha256=hashlib.sha256(b"").hexdigest())
        self.assertEqual(denied.exception.code, "READ_ONLY")
        listing = call("wiki.list", wikiId=root["wikiId"], path="nested/deeper", offset=0, limit=100, query="")
        pdf = next(entry for entry in listing["entries"] if entry["name"] == "paper.pdf")
        self.assertEqual(pdf["kind"], "file")
        self.assertEqual(pdf["size"], len(b"%PDF-fixture\x00"))
        binary.write_bytes(b"%PDF-changed-fixture\x00")
        with self.assertRaises(WikiServiceError) as changed:
            call("wiki.list", wikiId=root["wikiId"], path="nested/deeper", offset=0, limit=100,
                 query="", revision=listing["revision"])
        self.assertEqual(changed.exception.code, "REVISION_STALE")
        self.assertEqual((home / "plugin-data").stat().st_mode & 0o777, 0o700)

    def test_connect_reuses_host_grant_inside_protected_home(self):
        home = self.base / "host-home"
        notes = home / "Alfie Brain Wiki"
        notes.mkdir(parents=True)
        (notes / "index.md").write_text("# Hosted wiki\n")
        transport = production_factory(host_home=home, config_getter=lambda: self.config)
        service = transport.host_service()
        granted = service.grant("hosted-wiki", root=notes, label="Hosted Wiki", profile_id="default",
                                device_ids=(self.context.device_id,), writable=False)
        before = service.list_grants()
        def call(op, **fields):
            return transport.execute(op, {"agentId": "default", **fields}, context=self.context)
        connected = call("wiki.connect", folderPath=str(notes))
        self.assertEqual(connected, granted)
        self.assertEqual(call("wiki.resolve", folderPath=str(notes)), granted)
        self.assertEqual(service.list_grants(), before)
        read = call("wiki.read", wikiId=granted["wikiId"], path="index.md", offset=0, limit=65536)
        self.assertEqual(read["text"], "# Hosted wiki\n")
        with self.assertRaises(WikiServiceError) as denied:
            call("wiki.save.begin", wikiId=granted["wikiId"], path="index.md",
                 baseRevision=read["revision"], operationId="hosted-read-only", totalBytes=0,
                 sha256=hashlib.sha256(b"").hexdigest())
        self.assertEqual(denied.exception.code, "READ_ONLY")

    def test_account_grant_accepts_new_devices_after_reopen(self):
        home = self.base / "account-host"
        notes = home / "notes"
        notes.mkdir(parents=True)
        (notes / "index.md").write_text("# Account wiki\n")
        transport = production_factory(host_home=home, config_getter=lambda: self.config)
        service = transport.host_service()
        granted = service.grant("account-wiki", root=notes, label="Account Wiki", profile_id="default",
                                access_scope="account", writable=False)
        before = service.list_grants()
        self.assertEqual(before["grants"][0]["accessScope"], "account")
        self.assertEqual(before["grants"][0]["deviceIds"], [])
        for device in ("new-phone", "new-tablet"):
            reopened = production_factory(host_home=home, config_getter=lambda: self.config)
            context = replace(self.context, device_id=device)
            def call(op, **fields):
                return reopened.execute(op, {"agentId": "default", **fields}, context=context)
            self.assertEqual(call("wiki.connect", folderPath=str(notes)), granted)
            self.assertEqual(call("wiki.resolve", folderPath=str(notes)), granted)
            self.assertEqual(call("wiki.roots"), {"roots": [granted]})
            read = call("wiki.read", wikiId="account-wiki", path="index.md", offset=0, limit=65536)
            self.assertEqual(read["text"], "# Account wiki\n")
            self.assertEqual(len(call("wiki.list", wikiId="account-wiki", path="", offset=0,
                                      limit=100, query="")["entries"]), 1)
            self.assertEqual(len(call("wiki.search", wikiId="account-wiki", query="Account",
                                      mode="content", offset=0, limit=100)["matches"]), 1)
            with self.assertRaises(WikiServiceError) as denied:
                call("wiki.save.begin", wikiId="account-wiki", path="index.md", baseRevision=read["revision"],
                     operationId="account-read-only", totalBytes=0, sha256=hashlib.sha256(b"").hexdigest())
            self.assertEqual(denied.exception.code, "READ_ONLY")
            self.assertEqual(reopened.host_service().list_grants(), before)

    def test_account_grant_rejects_foreign_account_profile_and_stale_context(self):
        self.service.grant('notes', root=self.root, label='Notes', profile_id='default', access_scope='account')
        before = self.service.list_grants()
        for context in (None, replace(self.context, target_host_id='wrong-host'),
                        replace(self.context, authority_id='foreign-account'), replace(self.context, sender_epoch=0)):
            with self.subTest(context=context), self.assertRaises(WikiServiceError):
                self.transport.execute('wiki.roots', {'agentId': 'default'}, context=context)
        with self.assertRaises(WikiServiceError):
            self.transport.execute('wiki.read', dict(agentId='another-profile', wikiId='notes',
                path='index.md', offset=0, limit=64), context=self.context)
        original_config = self.config
        for changed in (replace(original_config, account_key=os.urandom(32)),
                        replace(original_config, authorization_epoch=original_config.authorization_epoch + 1),
                        replace(original_config, device_id='replacement-host')):
            self.config = changed
            current_context = replace(self.context, target_host_id=changed.device_id, authority_id=authority_id(changed))
            self.assertEqual(self.transport.execute('wiki.roots', {'agentId': 'default'}, context=current_context), {'roots': []})
            for operation, fields in (
                ('wiki.connect', {'folderPath': str(self.root)}),
                ('wiki.resolve', {'folderPath': str(self.root)}),
                ('wiki.read', dict(wikiId='notes', path='index.md', offset=0, limit=64)),
            ):
                with self.subTest(operation=operation), self.assertRaises(WikiServiceError):
                    self.transport.execute(operation, {'agentId': 'default', **fields}, context=current_context)
        self.config = original_config
        self.assertEqual(self.transport.host_service().list_grants(), before)
        self.transport.host_service().revoke('notes')
        with self.assertRaises(WikiServiceError):
            self.execute('wiki.read', wikiId='notes', path='index.md', offset=0, limit=64)

    def test_credential_named_host_home_remains_ungrantable(self):
        user_home = self.base / "user-home"
        user_home.mkdir()
        home = user_home / ".hermes"
        notes = home / "notes"
        notes.mkdir(parents=True)
        transport = production_factory(host_home=home, config_getter=lambda: self.config)
        service = transport.host_service()
        with patch.object(Path, "home", return_value=user_home):
            with self.assertRaises(WorkspaceFilesError) as denied:
                service.grant("hosted-wiki", root=notes, label="Hosted Wiki", profile_id="default",
                              device_ids=(self.context.device_id,), writable=False)
            self.assertEqual(denied.exception.code, "INVALID_GRANT")
            with self.assertRaises(WikiServiceError) as denied:
                transport.execute("wiki.connect", {"agentId": "default", "folderPath": str(notes)}, context=self.context)
            self.assertEqual(denied.exception.code, "WIKI_NOT_ALLOWED")
        self.assertEqual(service.list_grants(), {"grants": []})

    def test_protected_host_grant_cannot_expand_access(self):
        home = self.base / "host-home"
        notes = home / "notes"
        (notes / "child").mkdir(parents=True)
        sibling = home / "unapproved"
        sibling.mkdir()
        linked = home / "linked"
        linked.symlink_to(notes, target_is_directory=True)
        transport = production_factory(host_home=home, config_getter=lambda: self.config)
        service = transport.host_service()
        service.grant("hosted-wiki", root=notes, label="Hosted Wiki", profile_id="default",
                      device_ids=(self.context.device_id,), writable=False)
        before = service.list_grants()
        for folder, profile, context in (
            (notes, "other", self.context),
            (notes, "default", replace(self.context, device_id="another-device")),
            (notes / "child", "default", self.context),
            (sibling, "default", self.context),
            (home, "default", self.context),
            (service._state_dir, "default", self.context),
            (linked, "default", self.context),
        ):
            with self.subTest(folder=folder, profile=profile, device=context.device_id):
                with self.assertRaises(WikiServiceError) as denied:
                    transport.execute("wiki.connect", {"agentId": profile, "folderPath": str(folder)}, context=context)
                self.assertEqual(denied.exception.code, "WIKI_NOT_ALLOWED")
        self.assertEqual(service.list_grants(), before)
        service.revoke("hosted-wiki")
        with self.assertRaises(WikiServiceError) as denied:
            transport.execute("wiki.connect", {"agentId": "default", "folderPath": str(notes)}, context=self.context)
        self.assertEqual(denied.exception.code, "WIKI_NOT_ALLOWED")
        self.assertEqual(service.list_grants(), {"grants": []})

    def test_protected_host_grant_checks_ambiguity_overlap_and_root_identity(self):
        home = self.base / "host-home"
        notes = home / "notes"
        child = notes / "child"
        child.mkdir(parents=True)
        transport = production_factory(host_home=home, config_getter=lambda: self.config)
        service = transport.host_service()
        service.grant("hosted-wiki", root=notes, label="Hosted Wiki", profile_id="default",
                      device_ids=(self.context.device_id,), writable=False)
        service.grant("duplicate", root=notes, label="Duplicate", profile_id="default",
                      device_ids=(self.context.device_id,), writable=False)
        with self.assertRaises(WikiServiceError) as ambiguous:
            transport.execute("wiki.connect", {"agentId": "default", "folderPath": str(notes)}, context=self.context)
        self.assertEqual(ambiguous.exception.code, "WIKI_AMBIGUOUS")
        service.revoke("duplicate")
        service.grant("foreign-child", root=child, label="Foreign child", profile_id="other",
                      device_ids=(self.context.device_id,), writable=False)
        with self.assertRaises(WikiServiceError) as overlap:
            transport.execute("wiki.connect", {"agentId": "default", "folderPath": str(notes)}, context=self.context)
        self.assertEqual(overlap.exception.code, "WIKI_NOT_ALLOWED")
        service.revoke("foreign-child")
        before = service.list_grants()
        notes.rename(home / "moved-notes")
        notes.mkdir()
        for folder in (notes, home / "moved-notes"):
            with self.subTest(folder=folder), self.assertRaises(WikiServiceError) as stale:
                transport.execute("wiki.connect", {"agentId": "default", "folderPath": str(folder)}, context=self.context)
            self.assertEqual(stale.exception.code, "WIKI_NOT_ALLOWED")
        self.assertEqual(service.list_grants(), before)

    def test_connect_cannot_adopt_or_overwrite_existing_authority(self):
        before = self.execute("wiki.roots")
        self.assertEqual(self.execute("wiki.connect", folderPath=str(self.root)), before["roots"][0])
        for profile, context in (("other", self.context),
                                 ("default", replace(self.context, device_id="another-device"))):
            for folder in (self.root, self.base):
                with self.assertRaises(WikiServiceError):
                    self.transport.execute("wiki.connect", {"agentId": profile, "folderPath": str(folder)}, context=context)
        self.assertEqual(self.execute("wiki.roots"), before)
        self.config = replace(self.config, account_key=os.urandom(32))
        with self.assertRaises(WikiServiceError):
            self.execute("wiki.connect", folderPath=str(self.root))
        self.context = replace(self.context, authority_id=authority_id(self.config))
        with self.assertRaises(WikiServiceError):
            self.execute("wiki.connect", folderPath=str(self.root))
        self.assertEqual(self.execute("wiki.roots"), {"roots": []})

    def test_connect_rejects_renamed_grant_inode_and_descendants(self):
        # Portable real-filesystem alias: lexical path changes but the pinned
        # grant identity and its descendants must remain protected.
        moved = self.base / "moved-notes"
        self.root.rename(moved)
        (moved / "child").mkdir()
        foreign = replace(self.context, device_id="another-device")
        for candidate in (moved, moved / "child"):
            with self.assertRaises(WikiServiceError) as denied:
                self.transport.execute("wiki.connect", {"agentId": "default", "folderPath": str(candidate)}, context=foreign)
            self.assertEqual(denied.exception.code, "WIKI_NOT_ALLOWED")
        with self.service._locked() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM wiki_grants").fetchone()[0], 1)

    def test_connect_casefold_overlap_is_conservative_on_all_filesystems(self):
        alternate = self.base / "NOTES"
        alternate.mkdir(exist_ok=True)
        (alternate / "child").mkdir(exist_ok=True)
        foreign = replace(self.context, device_id="another-device")
        for candidate in (alternate, alternate / "child"):
            with self.assertRaises(WikiServiceError) as denied:
                self.transport.execute("wiki.connect", {"agentId": "default", "folderPath": str(candidate)}, context=foreign)
            self.assertEqual(denied.exception.code, "WIKI_NOT_ALLOWED")

    def test_case_insensitive_volume_aliases_cannot_cross_grants_or_host_home(self):
        alternate = self.base / "NOTES"
        if not alternate.exists() or not alternate.samefile(self.root):
            self.skipTest("Requires a case-insensitive filesystem (default macOS volume)")
        child = self.root / "child"
        child.mkdir()
        foreign = replace(self.context, device_id="another-device")
        for candidate in (alternate, alternate / "child"):
            with self.assertRaises(WikiServiceError) as denied:
                self.transport.execute("wiki.connect", {"agentId": "default", "folderPath": str(candidate)}, context=foreign)
            self.assertEqual(denied.exception.code, "WIKI_NOT_ALLOWED")
        self.service.revoke("notes")
        self.service.grant("child-grant", root=child, label="Child", profile_id="default",
                           device_ids=(self.context.device_id,))
        with self.assertRaises(WikiServiceError) as denied:
            self.transport.execute("wiki.connect", {"agentId": "default", "folderPath": str(alternate)}, context=foreign)
        self.assertEqual(denied.exception.code, "WIKI_NOT_ALLOWED")
        home = self.base / "CustomControlHome"
        (home / "secrets").mkdir(parents=True)
        transport = production_factory(host_home=home, config_getter=lambda: self.config)
        for candidate in (self.base / "CUSTOMCONTROLHOME", self.base / "CUSTOMCONTROLHOME" / "secrets"):
            with self.assertRaises(WikiServiceError) as denied:
                transport.execute("wiki.connect", {"agentId": "default", "folderPath": str(candidate)}, context=self.context)
            self.assertEqual(denied.exception.code, "WIKI_NOT_ALLOWED")

    def test_connect_rejects_unsafe_roots_paths_and_cold_state_symlinks(self):
        linked = self.base / "linked"
        linked.symlink_to(self.root, target_is_directory=True)
        for folder in ("/", "/etc", str(Path.home()), str(linked), str(self.root) + "/../notes",
                       str(self.base / "state"), str(self.root) + "/"):
            with self.assertRaises(WikiServiceError):
                self.execute("wiki.connect", folderPath=folder)
        home = self.base / "hermes-home"
        home.mkdir()
        (home / "secrets").mkdir()
        transport = production_factory(host_home=home, config_getter=lambda: self.config)
        with self.assertRaises(WikiServiceError):
            transport.execute("wiki.connect", {"agentId": "default", "folderPath": str(home / "secrets")}, context=self.context)
        unsafe_home = self.base / "unsafe-home"
        unsafe_home.mkdir()
        (unsafe_home / "plugin-data").symlink_to(self.root, target_is_directory=True)
        transport = production_factory(host_home=unsafe_home, config_getter=lambda: self.config)
        with self.assertRaises(WikiServiceError) as denied:
            transport.execute("wiki.roots", {"agentId": "default"}, context=self.context)
        self.assertEqual(denied.exception.code, "STATE_UNAVAILABLE")
        self.assertFalse((self.root / "loopdy").exists())

    def test_connect_contract_rejects_caller_authority_and_write_policy(self):
        for fields in ({"deviceId": "another-device"}, {"writable": True}, {"authorityId": "other"},
                       {"accessScope": "account"}, {"accountId": "caller-claimed-account"}):
            with self.assertRaises(ValueError):
                parse_workspace_request(dict(version=1, type="workspace.request", requestId="wiki-connect-invalid-0001",
                    operation="wiki.connect", payload={"agentId": "default", "folderPath": str(self.root), **fields}, sentAt=1))

    def test_distinct_device_authorization_epochs_work_through_encrypted_adapter(self):
        async def scenario(reuse_host_grant, account_scope=False):
            context = replace(self.context, device_id="new-account-phone") if account_scope else self.context
            home = self.base / ("account-encrypted-host" if account_scope else "encrypted-host" if reuse_host_grant else "fresh-host")
            home.mkdir()
            transport = production_factory(host_home=home, config_getter=lambda: self.config)
            connected = (home if reuse_host_grant else self.base) / "encrypted-notes"
            connected.mkdir()
            if reuse_host_grant:
                transport.host_service().grant("hosted-wiki", root=connected, label="Hosted Wiki",
                    profile_id="default", device_ids=() if account_scope else (self.context.device_id,),
                    access_scope="account" if account_scope else "device", writable=False)
            client = LoopdyLinkClient(self.config, state=_State())
            sent = []
            class Socket:
                async def send(_, value):
                    message = json.loads(value)
                    sent.append(message)
                    if message['type'] == 'frame':
                        await client.handle_wire_message(json.dumps({
                            'version': 1, 'type': 'accepted', 'id': message['id'],
                            'sequence': message['sequence'],
                        }), lambda _: None)
            client._socket = Socket()
            client._connected.set()
            adapter = LoopdyAdapter(PlatformConfig(enabled=True), service=_Service(), link_client=client,
                wiki_transport=transport,
                workspace_controller=WorkspaceController(backend=SimpleNamespace(), wiki_transport=transport))
            request = {'version': 1, 'type': 'workspace.request', 'requestId': 'wiki-encrypted-connect-0001',
                       'operation': 'wiki.connect', 'payload': {'agentId': 'default', 'folderPath': str(connected)}, 'sentAt': 1,
                       'targetHostId': self.config.device_id}
            if account_scope:
                before = transport.host_service().list_grants()
                foreign_cipher = AccountCipher(os.urandom(32))
                with self.assertRaisesRegex(ValueError, "ciphertext is invalid"):
                    await client.handle_wire_message(json.dumps({
                        'version': 1, 'type': 'frame', 'id': 'wiki-foreign-frame-0001',
                        'senderDeviceId': context.device_id, 'senderEpoch': context.sender_epoch,
                        'sequence': 1, 'ack': 0, 'ciphertext': foreign_cipher.seal(request),
                    }), adapter.receive_link_payload)
                self.assertEqual(sent, [])
                self.assertEqual(transport.host_service().list_grants(), before)
            self.assertNotEqual(self.context.sender_epoch, self.config.authorization_epoch)
            await asyncio.wait_for(client.handle_wire_message(json.dumps({
                'version': 1, 'type': 'frame', 'id': 'wiki-mobile-frame-0001',
                'senderDeviceId': context.device_id, 'senderEpoch': context.sender_epoch,
                'sequence': 1, 'ack': 0, 'ciphertext': client.cipher.seal(request),
            }), adapter.receive_link_payload), 5)
            results = [client.cipher.open(frame['ciphertext']) for frame in sent if frame['type'] == 'frame']
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]['status'], 'completed', results[0])
            self.assertFalse(results[0]['payload']['writable'])
            resolved = transport.execute('wiki.resolve', {'agentId': 'default', 'folderPath': str(connected)},
                                         context=context)
            self.assertEqual(results[0]['payload'], resolved)
            self.assertNotIn('capabilities', results[0])
            self.assertEqual(results[0]["payload"]["folderPath"], str(connected))
        for reuse_host_grant, account_scope in ((False, False), (True, False), (True, True)):
            with self.subTest(reuse_host_grant=reuse_host_grant, account_scope=account_scope):
                asyncio.run(scenario(reuse_host_grant, account_scope))

    def test_exact_large_upload_replay_empty_save_and_serialization(self):
        content = b'\xef\xbb\xbf# Updated\r\n' + ('e\u0301 / \U0001f431\r\n' * 10000).encode('utf-8')
        operation_id, begin = self.upload(content)
        result = self.execute('wiki.save.commit', operationId=operation_id)
        self.assertEqual(result['status'], 'committed')
        self.assertEqual(self.path.read_bytes(), content)
        self.assertEqual(self.execute('wiki.save.commit', operationId=operation_id), result)
        self.execute('wiki.save.begin', **begin)
        self.assertEqual(self.execute('wiki.save.status', operationId=operation_id), result)
        recovered = bytearray()
        offset, revision = 0, None
        while True:
            payload = dict(agentId='default', wikiId='notes', path='index.md', offset=offset, limit=65536)
            if revision:
                payload['revision'] = revision
            request = parse_workspace_request(dict(version=1, type='workspace.request',
                requestId='wiki-read-roundtrip-0001', operation='wiki.read', payload=payload, sentAt=1))
            page = self.transport.execute(request.operation, request.payload, context=self.context)
            envelope = workspace_result(request=request, status='completed', payload=page, sent_at=1)
            self.assertLess(len(json.dumps(envelope, ensure_ascii=True).encode()), 196608)
            revision = revision or page['revision']
            self.assertEqual(page['revision'], revision)
            recovered.extend(base64.b64decode(page['data'], validate=True))
            if page['nextOffset'] is None:
                break
            self.assertGreater(page['nextOffset'], offset)
            offset = page['nextOffset']
        self.assertEqual(bytes(recovered), content)
        empty_id, _ = self.upload(b'')
        self.assertEqual(self.execute('wiki.save.commit', operationId=empty_id)['status'], 'committed')
        self.assertEqual(self.path.read_bytes(), b'')

    def test_context_device_profile_and_regrant_denials(self):
        for context in (None, replace(self.context, target_host_id='wrong-host'),
                        replace(self.context, authority_id='stale-authority'),
                        replace(self.context, sender_epoch=0)):
            with self.subTest(context=context), self.assertRaises(WikiServiceError):
                self.transport.execute('wiki.roots', {'agentId': 'default'}, context=context)
        foreign = replace(self.context, device_id='other-mobile')
        self.assertEqual(self.transport.execute('wiki.roots', {'agentId': 'default'}, context=foreign), {'roots': []})
        with self.assertRaises(WikiServiceError):
            self.transport.execute('wiki.read', dict(agentId='other-profile', wikiId='notes',
                path='index.md', offset=0, limit=64), context=self.context)
        operation_id, _ = self.upload(b'# Pending\n')
        self.service.revoke('notes')
        self.service.grant('notes', root=self.root, label='Notes', profile_id='default',
                           device_ids=('mobile-device-1',), writable=True)
        with self.assertRaises(WikiServiceError):
            self.execute('wiki.save.commit', operationId=operation_id)
        self.assertEqual(self.path.read_bytes(), b'\xef\xbb\xbf# Original\r\n')

    def test_external_conflict_and_submitted_crash_never_retry_replace(self):
        operation_id, _ = self.upload(b'# My draft\n')
        self.path.write_bytes(b'# External\n')
        result = self.execute('wiki.save.commit', operationId=operation_id)
        self.assertEqual(result['status'], 'conflict')
        self.assertEqual(self.path.read_bytes(), b'# External\n')
        crash_id, _ = self.upload(b'# Crash draft\n')
        with patch.object(self.service, '_save_file_locked', side_effect=RuntimeError('fixture crash')):
            with self.assertRaises(RuntimeError):
                self.execute('wiki.save.commit', operationId=crash_id)
        reopened = WikiTransport(state_dir=self.base / 'state', config_getter=lambda: self.config)
        for operation in ('wiki.save.status', 'wiki.save.commit'):
            outcome = reopened.execute(operation, {'agentId': 'default', 'operationId': crash_id}, context=self.context)
            self.assertEqual(outcome['status'], 'indeterminate')
        self.assertEqual(self.path.read_bytes(), b'# External\n')

    def test_upload_reuse_malformed_chunks_and_pairing_change_fail_closed(self):
        operation_id, begin = self.upload(b'# Ready\n')
        with self.assertRaises(WikiServiceError):
            self.execute('wiki.save.begin', **dict(begin, totalBytes=begin['totalBytes'] + 1))
        for data in ('YQ', 'YR==', 'YQ==\n', ''):
            with self.subTest(data=data), self.assertRaises(WikiServiceError):
                self.execute('wiki.save.chunk', operationId=operation_id, offset=0, data=data)
        with self.assertRaises(WikiServiceError):
            self.execute('wiki.save.chunk', operationId=operation_id, offset=0, data='YQ==')
        self.config = replace(self.config, authorization_epoch=self.config.authorization_epoch + 1)
        with self.assertRaises(WikiServiceError):
            self.execute('wiki.save.commit', operationId=operation_id)
        self.assertEqual(self.path.read_bytes(), b'\xef\xbb\xbf# Original\r\n')

    def test_search_image_and_optional_initialization_are_scoped(self):
        untouched = self.base / 'not-created'
        optional = WikiTransport(state_dir=untouched, config_getter=lambda: None)
        self.assertFalse(untouched.exists())
        self.assertIsNone(optional._service)
        (self.root / 'nested').mkdir()
        (self.root / 'nested' / 'topic.md').write_text('# Find the search sentinel\n')
        (self.root / 'escape.md').symlink_to(self.base / 'outside.md')
        (self.base / 'outside.md').write_text('# Outside private sentinel\n')
        search = self.execute('wiki.search', wikiId='notes', query='search sentinel', mode='content', offset=0, limit=20)
        self.assertEqual([row['path'] for row in search['matches']], ['nested/topic.md'])
        self.assertNotIn('Outside private', json.dumps(search))
        png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aWQ0AAAAASUVORK5CYII=')
        (self.root / 'pixel.png').write_bytes(png)
        image = self.execute('wiki.image', wikiId='notes', path='pixel.png', offset=0, limit=65536)
        self.assertEqual(base64.b64decode(image['data']), png)
        self.assertIsNone(image['text'])
        (self.root / 'fake.png').write_text('<script>not an image</script>')
        with self.assertRaises(WikiServiceError):
            self.execute('wiki.image', wikiId='notes', path='fake.png', offset=0, limit=65536)
        with self.assertRaises(WikiServiceError):
            self.execute('wiki.read', wikiId='notes', path='escape.md', offset=0, limit=65536)


if __name__ == '__main__':
    unittest.main()
