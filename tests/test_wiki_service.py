from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

from loopdy_plugin.wiki_contract import available_wiki_operations


@unittest.skipUnless(available_wiki_operations(), "Requires secure descriptor-relative traversal")
class WikiServiceTests(unittest.TestCase):
    def test_granted_existing_file_save_is_exact_and_idempotent(self):
        self.assertIsNotNone(importlib.util.find_spec('loopdy_plugin.wiki_service'), 'Wiki must have a real, separately authorized file service')
        from loopdy_plugin.wiki_service import WikiService
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / 'notes'
            root.mkdir()
            path = root / 'index.md'
            path.write_bytes(b'# Start\n')
            service = WikiService(base / 'state', authority_id='paired-host-generation-a')
            service.grant('notes', root=root, label='Notes', profile_id='default', device_ids=('device-a',), writable=True)
            original = service.read_file('notes', profile_id='default', device_id='device-a', path='index.md')
            self.assertEqual(original['text'], '# Start\n')
            args = dict(profile_id='default', device_id='device-a', path='index.md', base_revision=original['revision'], content=b'# Updated\n', operation_id='save-fixture-0001')
            result = service.save_file('notes', **args)
            self.assertEqual(result['status'], 'committed')
            self.assertEqual(path.read_bytes(), b'# Updated\n')
            reopened = WikiService(base / 'state', authority_id='paired-host-generation-a')
            self.assertEqual(reopened.save_file('notes', **args), result)
            self.assertEqual(reopened.save_status('save-fixture-0001', profile_id='default', device_id='device-a')['status'], 'committed')


    def test_stale_source_and_generated_grants_never_overwrite(self):
        from loopdy_plugin.wiki_service import WikiService, WikiServiceError
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / 'notes'
            root.mkdir()
            path = root / 'index.md'
            path.write_bytes(b'# Original\r\n')
            service = WikiService(base / 'state', authority_id='authority-a')
            service.grant('notes', root=root, label='Notes', profile_id='default', device_ids=('device-a',), writable=True)
            original = service.read_file('notes', profile_id='default', device_id='device-a', path='index.md')
            with self.assertRaises(WikiServiceError):
                service.read_file('notes', profile_id='default', device_id='device-b', path='index.md')
            with self.assertRaises(WikiServiceError):
                service.read_file('notes', profile_id='other', device_id='device-a', path='index.md')
            path.write_bytes(b'# External change\r\n')
            result = service.save_file('notes', profile_id='default', device_id='device-a', path='index.md', base_revision=original['revision'], content=b'# My draft\r\n', operation_id='conflict-fixture-0001')
            self.assertEqual(result['status'], 'conflict')
            self.assertEqual(path.read_bytes(), b'# External change\r\n')
            with self.assertRaises(WikiServiceError) as private_status:
                service.save_status('conflict-fixture-0001', profile_id='default', device_id='device-b')
            self.assertEqual(private_status.exception.code, 'OPERATION_NOT_FOUND')
            regenerated = service.grant('notes', root=root, label='Notes', profile_id='default', device_ids=('device-a',), writable=True, source_kind='generated')
            self.assertFalse(regenerated['writable'])
            with self.assertRaises(WikiServiceError) as denied:
                service.save_file('notes', profile_id='default', device_id='device-a', path='index.md', base_revision=original['revision'], content=b'# My draft\r\n', operation_id='generated-fixture-0001')
            self.assertEqual(denied.exception.code, 'READ_ONLY')
            self.assertEqual(path.read_bytes(), b'# External change\r\n')

    def test_regrant_and_new_authority_invalidate_old_revisions(self):
        from loopdy_plugin.wiki_service import WikiService, WikiServiceError
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / 'notes'
            root.mkdir()
            path = root / 'index.md'
            path.write_bytes(b'# Original\n')
            service = WikiService(base / 'state', authority_id='authority-a')
            service.grant('notes', root=root, label='Notes', profile_id='default', device_ids=('device-a',), writable=True)
            original = service.read_file('notes', profile_id='default', device_id='device-a', path='index.md')
            service.revoke('notes')
            service.grant('notes', root=root, label='Notes', profile_id='default', device_ids=('device-a',), writable=True)
            with self.assertRaises(WikiServiceError) as stale:
                service.save_file('notes', profile_id='default', device_id='device-a', path='index.md', base_revision=original['revision'], content=b'edit', operation_id='regrant-fixture-0001')
            self.assertEqual(stale.exception.code, 'REVISION_STALE')
            other = WikiService(base / 'state', authority_id='authority-b')
            self.assertEqual(other.roots(profile_id='default', device_id='device-a'), {'roots': []})
            self.assertEqual(path.read_bytes(), b'# Original\n')

    @unittest.skipUnless(__import__('sys').platform == 'darwin', 'macOS ACL fixture')
    def test_acl_file_is_not_silently_replaced_with_weaker_permissions(self):
        import os
        import pwd
        import subprocess
        from loopdy_plugin.wiki_service import WikiService, WikiServiceError
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / 'notes'
            root.mkdir()
            path = root / 'index.md'
            path.write_bytes(b'# Private ACL note\n')
            os.chmod(path, 0o644)
            owner = pwd.getpwuid(os.geteuid()).pw_name
            subprocess.run(['chmod', '+a', 'group:everyone deny read', str(path)], check=True, capture_output=True)
            subprocess.run(['chmod', '+a#', '0', f'user:{owner} allow read,write,readattr,writeattr,readextattr,writeextattr,readsecurity,writesecurity', str(path)], check=True, capture_output=True)
            self.assertEqual(path.read_bytes(), b'# Private ACL note\n')
            original_inode = path.stat().st_ino
            service = WikiService(base / 'state', authority_id='paired-host-generation-a')
            service.grant('notes', root=root, label='Notes', profile_id='default', device_ids=('device-a',), writable=True)
            original = service.read_file('notes', profile_id='default', device_id='device-a', path='index.md')
            with self.assertRaises(WikiServiceError) as rejected:
                service.save_file('notes', profile_id='default', device_id='device-a', path='index.md', base_revision=original['revision'], content=b'# Edited\n', operation_id='save-acl-fixture-0001')
            self.assertEqual(rejected.exception.code, 'READ_ONLY')
            self.assertEqual(path.stat().st_ino, original_inode)
            self.assertEqual(path.read_bytes(), b'# Private ACL note\n')


if __name__ == '__main__':
    unittest.main()
