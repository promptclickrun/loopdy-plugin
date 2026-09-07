"""Create-only Wiki uploads against disposable roots, never a live grant."""
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

import os
from unittest.mock import patch

from loopdy_plugin.wiki_service import WikiService, WikiServiceError
from loopdy_plugin.workspace_files import WorkspaceFilesError
from loopdy_plugin.wiki_uploads import WikiUploads


class WikiCreationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'notes'
        (self.root / 'nested').mkdir(parents=True)
        self.service = WikiService(self.base / 'state', authority_id='creation-fixture')
        self.grant = self.service.grant('notes', root=self.root, label='Notes',
            profile_id='default', device_ids=('device-a',), writable=True)
        self.uploads = WikiUploads(self.service)

    def begin(self, content=b'\xef\xbb\xbf# New\r\n', path='nested/new.md', operation='create-1'):
        payload = dict(agentId='default', wikiId='notes', path=path,
            baseRevision='wiki-new-v1:' + self.grant['generation'], operationId=operation,
            totalBytes=len(content), sha256=hashlib.sha256(content).hexdigest())
        self.uploads.begin(payload, device_id='device-a')
        if content:
            self.uploads.chunk(dict(agentId='default', operationId=operation, offset=0,
                data=base64.b64encode(content).decode('ascii')), device_id='device-a')
        return dict(agentId='default', operationId=operation)

    def test_roots_explicitly_advertise_create_only_support(self):
        self.assertIs(self.grant.get('supportsCreation'), True)
        roots = self.service.roots(profile_id='default', device_id='device-a')['roots']
        self.assertIs(roots[0].get('supportsCreation'), True)

    def test_create_nested_file_is_exact_verified_and_idempotent_after_restart(self):
        payload = self.begin()
        outcome = self.uploads.commit(payload, device_id='device-a')
        self.assertEqual(outcome['status'], 'committed')
        self.assertEqual((self.root / 'nested/new.md').read_bytes(), b'\xef\xbb\xbf# New\r\n')
        read = self.service.read_file('notes', profile_id='default', device_id='device-a', path='nested/new.md')
        self.assertEqual(read['revision'], outcome['revision'])
        restarted = WikiUploads(WikiService(self.base / 'state', authority_id='creation-fixture'))
        self.assertEqual(restarted.status(payload, device_id='device-a'), outcome)
        self.assertEqual(restarted.commit(payload, device_id='device-a'), outcome)

    def test_creation_never_overwrites_existing_or_racing_file(self):
        for phase in ('before-begin', 'before-commit', 'last-instant'):
            with self.subTest(phase=phase):
                path = self.root / 'nested' / (phase + '.md')
                if phase == 'before-begin':
                    path.write_bytes(b'External')
                payload = self.begin(path='nested/' + path.name, operation=phase)
                if phase == 'before-commit':
                    path.write_bytes(b'External')
                link = os.link
                def race(*args, **kwargs):
                    path.write_bytes(b'External')
                    return link(*args, **kwargs)
                with patch('loopdy_plugin.wiki_service.os.link', side_effect=race if phase == 'last-instant' else link):
                    result = self.uploads.commit(payload, device_id='device-a')
                self.assertEqual(result['status'], 'conflict')
                self.assertEqual(path.read_bytes(), b'External')
                self.assertEqual(self.uploads.status(payload, device_id='device-a')['status'], 'conflict')

    def test_read_only_and_obsolete_grants_cannot_create(self):
        payload = self.begin()
        self.service.grant('notes', root=self.root, label='Notes', profile_id='default',
            device_ids=('device-a',), writable=False)
        with self.assertRaises(WikiServiceError) as denied:
            self.uploads.commit(payload, device_id='device-a')
        self.assertEqual(denied.exception.code, 'READ_ONLY')
        with self.assertRaises(WikiServiceError) as denied:
            self.begin(operation='read-only')
        self.assertEqual(denied.exception.code, 'READ_ONLY')
        self.service.grant('notes', root=self.root, label='Notes', profile_id='default',
            device_ids=('device-a',), writable=True)
        with self.assertRaises(WikiServiceError) as denied:
            self.begin(operation='stale')
        self.assertEqual(denied.exception.code, 'REVISION_STALE')
        self.assertFalse((self.root / 'nested/new.md').exists())

    def test_absent_file_is_not_authority_to_create_parents_or_follow_links(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (self.root / 'link').symlink_to(outside, target_is_directory=True)
        (self.root / 'nested/linked.md').symlink_to(outside / 'absent.md')
        for path in ('missing/new.md', 'link/new.md', 'nested/linked.md', '../outside/new.md', '.env.secret.md'):
            with self.subTest(path=path), self.assertRaises((WorkspaceFilesError, ValueError, OSError)):
                self.begin(path=path)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((self.root / 'missing').exists())

    def test_empty_creation_and_owner_scoped_recovery(self):
        payload = self.begin(content=b'')
        with self.assertRaises(WikiServiceError):
            self.uploads.commit(payload, device_id='device-b')
        result = self.uploads.commit(payload, device_id='device-a')
        self.assertEqual(result['status'], 'committed')
        self.assertEqual((self.root / 'nested/new.md').read_bytes(), b'')

    def test_interrupted_creation_never_repeats_publication(self):
        payload = self.begin()
        link = os.link
        def crash(*args, **kwargs):
            link(*args, **kwargs)
            raise KeyboardInterrupt('crash after publication')
        with patch('loopdy_plugin.wiki_service.os.link', side_effect=crash):
            with self.assertRaises(KeyboardInterrupt):
                self.uploads.commit(payload, device_id='device-a')
        path = self.root / 'nested/new.md'
        path.write_bytes(b'Later editor')
        restarted = WikiUploads(WikiService(self.base / 'state', authority_id='creation-fixture'))
        self.assertEqual(restarted.status(payload, device_id='device-a')['status'], 'indeterminate')
        self.assertEqual(restarted.commit(payload, device_id='device-a')['status'], 'indeterminate')
        self.assertEqual(path.read_bytes(), b'Later editor')
