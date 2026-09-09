from __future__ import annotations

import importlib.util
import tempfile
import unittest
from functools import partial
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


    def test_directory_pages_only_include_client_navigable_entries(self):
        from loopdy_plugin.wiki_service import WikiService, WikiServiceError
        from loopdy_plugin.workspace_files import WorkspaceFilesService
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / 'notes'
            root.mkdir()
            service = WikiService(base / 'state', authority_id='authority-a')
            service.grant('notes', root=root, label='Notes', profile_id='default', device_ids=('device-a',))
            listing = partial(service.list_directory, 'notes', profile_id='default', device_id='device-a')
            for parent in ('', 'nested'):
                with self.subTest(parent=parent):
                    folder = root / parent
                    folder.mkdir(exist_ok=True)
                    for name in ('.obsidian', '.migration-evidence', 'draft:archive', 'articles'):
                        (folder / name).mkdir()
                    hidden = ('.gitignore', '.notes.md', 'draft:notes.md')
                    visible = ('alpha.md', 'release.v1.md', 'zulu.md')
                    for name in hidden + visible:
                        (folder / name).write_text('# Fixture\n')
                    # Keep existing secret/link exclusions alongside the compatibility filter.
                    (folder / '.env').write_text('fixture')
                    (folder / 'link.md').symlink_to(folder / 'alpha.md')
                    first = listing(path=parent, limit=2)
                    self.assertEqual([e['name'] for e in first['entries']], ['articles', 'alpha.md'])
                    self.assertEqual(first['total'], 4)
                    self.assertEqual(first['nextOffset'], 2)
                    second = listing(path=parent, offset=2, limit=2, revision=first['revision'])
                    self.assertEqual([e['name'] for e in second['entries']], ['release.v1.md', 'zulu.md'])
                    self.assertEqual(second['total'], first['total'])
                    self.assertEqual(second['revision'], first['revision'])
                    self.assertIsNone(second['nextOffset'])
                    for entry in first['entries'] + second['entries']:
                        self.assertEqual(entry['path'], f"{parent}/{entry['name']}" if parent else entry['name'])
                        self.assertNotIn(':', entry['path'])
                        self.assertFalse(any(part.startswith('.') for part in entry['path'].split('/')))
                    # Excluded file metadata must not enter the whole-listing digest.
                    # Editing contents does not mutate the parent directory identity.
                    for name in hidden:
                        (folder / name).write_text('# Changed excluded content\n')
                    unchanged = listing(path=parent, offset=2, limit=2, revision=first['revision'])
                    self.assertEqual(unchanged, second)
                    filtered = listing(path=parent, query='notes')
                    self.assertEqual(filtered['entries'], [])
                    self.assertEqual(filtered['total'], 0)
                    self.assertIsNone(filtered['nextOffset'])
                    # A visible off-page edit still invalidates the shared revision.
                    (folder / 'zulu.md').write_text('# Changed visible content\n')
                    with self.assertRaises(WikiServiceError) as stale:
                        listing(path=parent, limit=2, revision=first['revision'])
                    self.assertEqual(stale.exception.code, 'REVISION_STALE')
                    self.assertTrue(all((folder / name).exists() for name in hidden))
            # Generic Files retains its existing hidden/colon entry policy.
            files = WorkspaceFilesService(base / 'files-state')
            files.grant('notes', root=root, label='Notes')
            names = {entry['name'] for entry in files.list_directory('notes')['entries']}
            self.assertTrue({'.obsidian', '.migration-evidence', '.gitignore', 'draft:notes.md'} <= names)
            self.assertNotIn('.env', names)
            self.assertNotIn('link.md', names)

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
