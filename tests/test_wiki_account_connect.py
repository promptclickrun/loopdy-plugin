"""Explicit Save authorizes the paired account, not a mobile installation."""
import base64
from dataclasses import replace
import hashlib
import unittest

import test_wiki_integration as fixtures
from loopdy_plugin.wiki_transport import production_factory
from loopdy_plugin.wiki_service import WikiServiceError
from loopdy_plugin.wiki_contract import available_wiki_operations


@unittest.skipUnless(available_wiki_operations(), "Requires secure descriptor-relative traversal")
class AccountConnectTests(unittest.TestCase):
    setUp = fixtures.WikiIntegrationTests.setUp

    def test_legacy_schema_migration_preserves_policy_and_generation(self):
        before = self.service.list_grants()
        with self.service._locked() as connection:
            from wiki_schema_fixtures import restore_legacy_schema
            restore_legacy_schema(connection, omit_access_scope=True)
        reopened = fixtures.WikiTransport(state_dir=self.base / 'state', config_getter=lambda: self.config)
        self.assertEqual(reopened.host_service().list_grants(), before)
        self.assertEqual(before['grants'][0]['accessScope'], 'device')

    def test_generated_source_connect_is_account_scoped_but_read_only(self):
        self.service.grant('notes', root=self.root, label='Notes', profile_id='default',
                           device_ids=('old-device',), writable=True, source_kind='generated')
        root = self.transport.execute('wiki.connect', {'agentId': 'default', 'folderPath': str(self.root)}, context=self.context)
        self.assertFalse(root['writable'])
        self.assertEqual(self.service.list_grants()['grants'][0]['accessScope'], 'account')
        other = replace(self.context, device_id='replacement-phone')
        read = self.transport.execute('wiki.read', {'agentId': 'default', 'wikiId': 'notes',
            'path': 'index.md', 'offset': 0, 'limit': 64}, context=other)
        with self.assertRaises(WikiServiceError) as denied:
            self.transport.execute('wiki.save.begin', {'agentId': 'default', 'wikiId': 'notes',
                'path': 'index.md', 'operationId': 'generated-save', 'baseRevision': read['revision'],
                'totalBytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}, context=other)
        self.assertEqual(denied.exception.code, 'READ_ONLY')

    def test_explicit_selection_converts_only_exact_legacy_grant(self):
        before = self.service.list_grants()
        original = self.service.read_file('notes', profile_id='default', device_id=self.context.device_id,
                                          path='index.md', offset=0, limit=64)
        # Reads keep the existing device policy and generation untouched.
        self.assertEqual(self.service.list_grants(), before)
        self.context = replace(self.context, device_id='new-account-device')
        with self.assertRaises(WikiServiceError):
            self.transport.execute('wiki.resolve', {'agentId': 'default', 'folderPath': str(self.root)}, context=self.context)
        unrelated = self.base / 'unrelated'
        unrelated.mkdir()
        self.service.grant('unrelated', root=unrelated, label='Unrelated', profile_id='default',
                           device_ids=('old-device',), writable=False)
        untouched = self.service.list_grants()['grants'][1]
        root = self.transport.execute('wiki.connect', {'agentId': 'default', 'folderPath': str(self.root)}, context=self.context)
        self.assertTrue(root['writable'])
        self.assertNotEqual(root['generation'], before['grants'][0]['generation'])
        self.assertEqual(self.service.list_grants()['grants'][1], untouched)
        self.assertEqual(self.service.list_grants()['grants'][0]['accessScope'], 'account')
        with self.assertRaises(WikiServiceError):
            self.transport.execute('wiki.read', {'agentId': 'default', 'wikiId': 'notes', 'path': 'index.md',
                'offset': 0, 'limit': 64, 'revision': original['revision']}, context=self.context)

    def test_encrypted_connect_read_save_restart_new_device_and_wrong_account(self):
        async def scenario():
            home = self.base / 'encrypted-home'
            notes = home / 'Alfie Brain Wiki'
            notes.mkdir(parents=True)
            (notes / 'index.md').write_bytes(b'# Original\n')
            transport = production_factory(host_home=home, config_getter=lambda: self.config)
            client = fixtures.LoopdyLinkClient(self.config, state=fixtures._State())
            sent = []
            class Socket:
                async def send(_, value):
                    message = fixtures.json.loads(value)
                    sent.append(message)
                    if message['type'] == 'frame':
                        await client.handle_wire_message(fixtures.json.dumps({
                            'version': 1, 'type': 'accepted', 'id': message['id'],
                            'sequence': message['sequence']}), lambda _: None)
            client._socket = Socket()
            client._connected.set()
            def adapter_for(current):
                return fixtures.LoopdyAdapter(fixtures.PlatformConfig(enabled=True),
                    service=fixtures._Service(), link_client=client, wiki_transport=current,
                    workspace_controller=fixtures.WorkspaceController(
                        backend=fixtures.SimpleNamespace(), wiki_transport=current))
            adapter = adapter_for(transport)
            sequence = 0
            sender = 'first-phone'
            async def call(op, *, profile='default', cipher=None, **fields):
                nonlocal sequence
                sequence += 1
                request = dict(version=1, type='workspace.request',
                    requestId=f'account-wiki-request-{sequence:04}', operation=op,
                    payload={'agentId': profile, **fields}, sentAt=1,
                    targetHostId=self.config.device_id)
                sent.clear()
                await fixtures.asyncio.wait_for(client.handle_wire_message(fixtures.json.dumps({
                    'version': 1, 'type': 'frame', 'id': f'account-frame-{sequence:04}',
                    'senderDeviceId': sender, 'senderEpoch': 1, 'sequence': sequence,
                    'ack': 0, 'ciphertext': (cipher or client.cipher).seal(request)}),
                    adapter.receive_link_payload), 5)
                responses = [client.cipher.open(frame['ciphertext']) for frame in sent if frame['type'] == 'frame']
                self.assertEqual(len(responses), 1)
                return responses[0]
            root_result = await call('wiki.connect', folderPath=str(notes))
            self.assertEqual(root_result['status'], 'completed', root_result)
            root = root_result['payload']
            self.assertTrue(root['writable'])
            before = transport.host_service().list_grants()
            # Rebuild services/adapter with the persisted journal; sign-in creates a new sender.
            transport = production_factory(host_home=home, config_getter=lambda: self.config)
            adapter = adapter_for(transport)
            sender = 'replacement-phone'
            self.assertEqual((await call('wiki.connect', folderPath=str(notes)))['payload'], root)
            read = (await call('wiki.read', wikiId=root['wikiId'], path='index.md', offset=0, limit=64))['payload']
            content = b'# Account edit\n'
            result = await call('wiki.save.begin', wikiId=root['wikiId'], path='index.md',
                operationId='encrypted-account-save', baseRevision=read['revision'],
                totalBytes=len(content), sha256=hashlib.sha256(content).hexdigest())
            self.assertEqual(result['status'], 'completed', result)
            await call('wiki.save.chunk', operationId='encrypted-account-save', offset=0,
                       data=base64.b64encode(content).decode())
            saved = await call('wiki.save.commit', operationId='encrypted-account-save')
            self.assertEqual(saved['payload']['status'], 'committed', saved)
            self.assertEqual((notes / 'index.md').read_bytes(), content)
            self.assertEqual((await call('wiki.save.commit', operationId='encrypted-account-save'))['payload'], saved['payload'])
            self.assertEqual((await call('wiki.read', profile='other', wikiId=root['wikiId'],
                                       path='index.md', offset=0, limit=64))['status'], 'failed')
            foreign = fixtures.LoopdyLinkClient(replace(self.config, account_key=fixtures.os.urandom(32)), state=fixtures._State())
            with self.assertRaises(ValueError):
                await call('wiki.connect', folderPath=str(notes), cipher=foreign.cipher)
            self.assertEqual(transport.host_service().list_grants(), before)
        fixtures.asyncio.run(scenario())

    def test_host_control_subtrees_and_ancestors_are_not_connectable(self):
        home = self.base / 'host-home'
        home.mkdir()
        transport = production_factory(host_home=home, config_getter=lambda: self.config)
        for name in ('plugin-data/other', 'config', 'profiles/other/notes', 'plugins/custom',
                     'sessions', 'logs', 'memories', 'skills', 'cache', '.env.d', '.config'):
            candidate = home / name
            candidate.mkdir(parents=True)
            with self.subTest(name=name), self.assertRaises(WikiServiceError):
                transport.execute('wiki.connect', {'agentId': 'default', 'folderPath': str(candidate)}, context=self.context)
        for candidate in (home, self.base):
            with self.assertRaises(WikiServiceError):
                transport.execute('wiki.connect', {'agentId': 'default', 'folderPath': str(candidate)}, context=self.context)
        self.assertEqual(transport.host_service().list_grants(), {'grants': []})

    def test_connect_under_host_home_is_durable_account_read_write(self):
        home = self.base / 'host-home'
        notes = home / 'Alfie Brain Wiki'
        notes.mkdir(parents=True)
        (notes / 'index.md').write_text('# Original\n')
        transport = production_factory(host_home=home, config_getter=lambda: self.config)
        def call(op, **fields):
            return transport.execute(op, {'agentId': 'default', **fields}, context=self.context)
        with self.assertRaises(WikiServiceError):
            call('wiki.resolve', folderPath=str(notes))
        root = call('wiki.connect', folderPath=str(notes))
        self.assertTrue(root['writable'])
        self.assertEqual(call('wiki.connect', folderPath=str(notes)), root)
        transport = production_factory(host_home=home, config_getter=lambda: self.config)
        self.context = replace(self.context, device_id='new-installation', sender_epoch=3)
        self.assertEqual(call('wiki.resolve', folderPath=str(notes)), root)
        self.assertEqual(call('wiki.roots')['roots'], [root])
        read = call('wiki.read', wikiId=root['wikiId'], path='index.md', offset=0, limit=64)
        content = b'# Updated\n'
        call('wiki.save.begin', wikiId=root['wikiId'], path='index.md', baseRevision=read['revision'],
             operationId='account-save', totalBytes=len(content), sha256=hashlib.sha256(content).hexdigest())
        call('wiki.save.chunk', operationId='account-save', offset=0, data=base64.b64encode(content).decode())
        result = call('wiki.save.commit', operationId='account-save')
        self.assertEqual(result['status'], 'committed')
        self.assertEqual(call('wiki.save.commit', operationId='account-save'), result)
        self.assertEqual((notes / 'index.md').read_bytes(), content)
