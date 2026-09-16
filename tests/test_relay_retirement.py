"""Retired Cloudflare state is migration input, never a delivery contract."""
import argparse
import contextlib
import io
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock

from loopdy_plugin.events import build_event
from loopdy_plugin.registration import setup_cli
from loopdy_plugin.service import LoopdyService
from loopdy_plugin.store import LoopdyStore


class RelayRetirementTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'loopdy.sqlite3'
        self.store = LoopdyStore(self.path)

    def service(self):
        relay = Mock()
        service = LoopdyService(self.store, providers={'relay': relay})
        self.addCleanup(service.close)
        return service, relay

    def seed_legacy_rows(self):
        # Write the on-disk legacy representation, not retired public APIs.
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO metadata(key,value) VALUES('relay_config_v1','{}')")
            db.execute("INSERT INTO devices(device_id,endpoint_id,provider,label,groups_json,preferences_json,created_at,updated_at) VALUES('legacy','obsolete','relay','','[]','{}',1,1)")
            db.execute("INSERT INTO relay_live_activities(activity_id,device_id,session_ref,revision,source_timestamp,lease_expires,normalized_body_digest,created_at,updated_at) VALUES('activity','legacy','session',1,1,9999999999,'',1,1)")
            db.execute("INSERT INTO pending_relay_operations(operation,device_id,revision,idempotency_key,body_json,attempts,updated_at) VALUES('register_device','legacy',1,'old-request','{malformed',0,1)")
            db.execute("INSERT INTO pending_relay_live_activity_updates(activity_id,status,detail,tool_name,active_session_count,attempts,next_attempt_at,last_error,updated_at) VALUES('activity','running','','',1,0,1,'',1)")
            db.execute("INSERT INTO provider_receipts VALUES('old-receipt','old-event','legacy','relay','pending',1,NULL,'')")

    def assert_retired(self):
        self.assertIsNone(self.store.load_relay_config())
        self.assertNotEqual(self.store.provider_mode(), 'relay')
        with sqlite3.connect(self.path) as db:
            for table in ('relay_live_activities', 'pending_relay_operations', 'pending_relay_live_activity_updates'):
                self.assertEqual(db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0], 0, table)
            for table in ('devices', 'event_deliveries', 'provider_receipts'):
                self.assertEqual(db.execute(f"SELECT COUNT(*) FROM {table} WHERE provider='relay'").fetchone()[0], 0, table)

    def test_startup_purges_legacy_state_without_network_or_unrelated_data_loss(self):
        self.store.upsert_device(device_id='managed', endpoint_id='managed-endpoint')
        event = build_event('session.completed', correlation=('retirement',))
        self.store.record_event(event)
        self.seed_legacy_rows()
        service, relay = self.service()
        self.assert_retired()
        self.assertIsNotNone(self.store.get_device('managed'))
        self.assertIsNotNone(self.store.get_event(event.event_id))
        self.assertEqual(relay.mock_calls, [])
        self.assertNotIn('relay', service._providers)
        self.assertFalse(self.store.retire_legacy_relay())

    def test_removal_also_cleans_state_reintroduced_after_startup(self):
        service, relay = self.service()
        self.seed_legacy_rows()
        service.remove_relay_configuration()
        self.assert_retired()
        self.assertEqual(relay.mock_calls, [])

    def test_orphaned_relay_receipts_alone_are_retired(self):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO provider_receipts VALUES('orphan','event','device','relay','pending',1,NULL,'')")
        self.assertTrue(self.store.retire_legacy_relay())
        self.assert_retired()

    def test_all_service_relay_entry_points_reject_without_mutation_or_send(self):
        service, relay = self.service()
        before = self.path.read_bytes()
        calls = [lambda: service.configure_relay(None),
                 lambda: service.adopt_link_relay_device(None, sender_device_id='legacy'),
                 lambda: service.register_device(device_id='legacy', endpoint_id='obsolete', provider='relay')]
        calls += [lambda operation=operation: service.relay_operation(operation, {}) for operation in
                  ('register_device', 'acknowledge_sender_keys', 'revoke_device', 'register_live_activity', 'revoke_live_activity', 'revoke_tenant', 'delete_tenant')]
        for call in calls:
            with self.assertRaisesRegex(ValueError, 'retired|managed or direct'):
                call()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(relay.mock_calls, [])
        self.assert_retired()

    def test_retired_cli_commands_are_absent(self):
        parser = argparse.ArgumentParser()
        setup_cli(parser)
        for command in ('configure-relay', 'remove-relay', 'recover-terminal-relay-registration'):
            with self.subTest(command=command), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parser.parse_args([command])
        for value in ('relay', 'legacy_relay'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parser.parse_args(['provider', value])
