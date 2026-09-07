"""Host-local account grants are explicit and never widen legacy policies."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from loopdy_plugin.wiki_cli import setup_wiki_cli, handle_wiki_cli
from loopdy_plugin.wiki_contract import available_wiki_operations
from loopdy_plugin.wiki_service import WikiService, WikiServiceError
from loopdy_plugin.wiki_transport import WikiTransport


@unittest.skipUnless(available_wiki_operations(), 'Requires secure traversal')
class WikiAccountCLITests(unittest.TestCase):
    def test_explicit_account_cli_replaces_device_policy_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / 'notes'
            root.mkdir()
            config = SimpleNamespace(device_id='host-fixture', authorization_epoch=1,
                                     base_url='https://link.example.test', account_key=b't' * 32)
            transport = WikiTransport(state_dir=base / 'state', config_getter=lambda: config)
            service = transport.host_service()
            original = service.grant('notes', root=root, label='Notes', profile_id='default', device_ids=('old-phone',))
            parser = argparse.ArgumentParser()
            setup_wiki_cli(parser.add_subparsers(dest='action', required=True))
            common = ['wiki', 'grant', 'notes', '--root', str(root), '--label', 'Notes',
                      '--profile-id', 'default', '--access', 'read-only', '--source-kind', 'files', '--yes']
            args = parser.parse_args(common + ['--account'])
            with redirect_stdout(StringIO()):
                handle_wiki_cli(args, transport=transport)
            granted = service.list_grants()['grants'][0]
            self.assertEqual(granted['accessScope'], 'account')
            self.assertEqual(granted['deviceIds'], [])
            self.assertFalse(granted['writable'])
            self.assertNotEqual(granted['generation'], original['generation'])
            with redirect_stdout(StringIO()):
                handle_wiki_cli(args, transport=transport)
            self.assertEqual(service.list_grants()['grants'][0], granted)
            for flags in ([], ['--account', '--device', 'phone']):
                with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
                    parser.parse_args(common + flags)
            device_args = parser.parse_args(common + ['--device', 'phone'])
            with redirect_stdout(StringIO()):
                handle_wiki_cli(device_args, transport=transport)
            policy = service.list_grants()['grants'][0]
            self.assertEqual(policy['accessScope'], 'device')
            self.assertEqual(policy['deviceIds'], ['phone'])
            self.assertNotEqual(policy['generation'], granted['generation'])


    def test_legacy_store_migrates_without_widening_or_rotating_grants(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / 'notes'
            root.mkdir()
            service = WikiService(base / 'state', authority_id='trusted-account')
            granted = service.grant('notes', root=root, label='Notes', profile_id='default', device_ids=('phone',))
            with service._locked() as connection:
                connection.execute('ALTER TABLE wiki_grants DROP COLUMN access_scope')
                connection.commit()
            reopened = WikiService(base / 'state', authority_id='trusted-account')
            policy = reopened.list_grants()['grants'][0]
            self.assertEqual(policy['generation'], granted['generation'])
            self.assertEqual(policy['accessScope'], 'device')
            self.assertEqual(policy['deviceIds'], ['phone'])
            self.assertEqual(reopened.roots(profile_id='default', device_id='other'), {'roots': []})
            for scope, devices in (('device', ()), ('unknown', ()), ('account', ('phone',))):
                with self.subTest(scope=scope, devices=devices), self.assertRaises(WikiServiceError):
                    reopened.grant('notes', root=root, label='Notes', profile_id='default',
                                   access_scope=scope, device_ids=devices)
            self.assertEqual(reopened.list_grants()['grants'][0], policy)


if __name__ == '__main__':
    unittest.main()
