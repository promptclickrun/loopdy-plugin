from __future__ import annotations
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid
from cryptography.hazmat.primitives.asymmetric import ec
from loopdy_plugin.managed_notifications import ManagedNotifications, ManagedNotificationError, host_request_transcript
from loopdy_plugin.relay_crypto import b64url_encode, b64url_decode, key_id, public_key_bytes, public_key_from_x963, verify_p1363


class ManagedNotificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = 1_800_000_000
        self.calls = []
        self.fail_send = False
        self.grant_id = str(uuid.uuid4())
        self.service = ManagedNotifications(Path(self.temp.name)/"managed", transport=self.transport,
            clock=lambda: self.now, session_opener=lambda profile, read, read_only: read(self))
        recipient = public_key_bytes(ec.generate_private_key(ec.SECP256R1()).public_key())
        self.grant = dict(grantId=self.grant_id,hostKeyId=self.service.key_id,hostPublicKey=self.service.public_key,
            deviceId="mobile-a",recipientPublicKey=b64url_encode(recipient),recipientKeyId=key_id(recipient),
            recipientRevision=1,authorizationEpoch=1,profile="default",eventTypes=["session.completed","session.failed"],
            createdAt=self.now-10,expiresAt=self.now+3600,revision=1,tenantId="fixture-tenant",state="active")
        self.service.enroll(self.grant_id,str(uuid.uuid4()))
        self.service.subscribe(self.grant_id,"default","native-session",True)
        self.calls.clear()

    def tearDown(self):
        self.service.close()
        self.temp.cleanup()

    def get_session(self, sid):
        return {"id":sid,"profile_name":"default"}

    def transport(self, method, path, raw, headers):
        self.calls.append((method,path,raw,headers))
        public = public_key_from_x963(b64url_decode(self.service.public_key))
        signed = host_request_transcript(method,path,self.grant_id,int(headers["x-loopdy-timestamp"]),headers["x-loopdy-nonce"],raw)
        verify_p1363(public,b64url_decode(headers["x-loopdy-signature"]),signed)
        if path.endswith("/events"):
            if self.fail_send: raise ManagedNotificationError("synthetic_unavailable",503)
            return {"version":1,"status":"accepted","deliveryId":json.loads(raw)["envelope"]["delivery_id"]}
        return {"version":1,"grant":self.grant}

    def test_capability_distinguishes_supported_events_from_lazy_producer_load(self):
        caps=self.service.capabilities()
        self.assertEqual(set(caps["supportedEventTypes"]),{"session.completed","session.failed","approval.required"})
        self.assertFalse(caps["producerCapabilities"]["nativeApproval"])
        self.assertFalse(caps["producerCapabilities"]["sessionCompletion"])
        self.service.producer_loaded("default",start_worker=False)
        self.assertTrue(self.service.capabilities()["producerCapabilities"]["sessionCompletion"])
        self.assertFalse(self.service.capabilities()["producerCapabilities"]["nativeApproval"])
        self.service.producer_loaded("default",start_worker=False,approval_hooks_loaded=True)
        self.assertTrue(self.service.capabilities()["producerCapabilities"]["nativeApproval"])
        self.service.close()
        self.assertFalse(self.service.capabilities()["producerCapabilities"]["nativeApproval"])

    def test_cancelled_work_queues_neutral_terminal_without_alert(self):
        self.service.observe("pre_llm_call",profile="default",session_id="native-session",turn_id="turn-a",platform="desktop")
        with sqlite3.connect(self.service.db_path) as db:
            db.execute("INSERT INTO activities(activity_id,grant_id,profile,session_id,session_ref,lease_expires,work_turn,state) VALUES(?,?,?,?,?,?,?,'active')",
                ("activity-a",self.grant_id,"default","native-session","x"*43,self.now+600,"turn-a"))
        self.service.observe("on_session_end",profile="default",session_id="native-session",turn_id="turn-a",interrupted=True,platform="desktop")
        with sqlite3.connect(self.service.db_path) as db:
            row=db.execute("SELECT raw FROM pending WHERE activity_id='activity-a'").fetchone()
            self.assertIsNotNone(row)
            value=json.loads(row[0]);self.assertEqual(value["phase"],"completed");self.assertEqual(value["currentAction"],"Stopped")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0],0)

    def test_late_activity_registration_keeps_original_turn_and_frozen_terminal(self):
        from loopdy_plugin.managed_notifications import session_reference
        reference = session_reference("default", "native-session")
        original_transport = self.service.transport
        def transport(method, path, raw, headers):
            if method == "GET" and "/live-activities/" in path:
                return {"version": 1, "activity": {"grantId": self.grant_id,
                    "activityId": "late-activity", "sessionReference": reference,
                    "status": "active", "leaseExpires": self.now + 600}}
            return original_transport(method, path, raw, headers)
        self.service.transport = transport
        self.service.observe("pre_llm_call", profile="default", session_id="native-session", turn_id="original")
        self.service.observe("on_session_end", profile="default", session_id="native-session", turn_id="original", completed=True)
        self.service.observe("pre_llm_call", profile="default", session_id="native-session", turn_id="newer")
        args=(self.grant_id,"late-activity","default","native-session",reference,self.now+600,"original")
        self.service.subscribe_activity(*args)
        with sqlite3.connect(self.service.db_path) as db:
            first=db.execute("SELECT raw FROM pending WHERE activity_id='late-activity'").fetchone()[0]
            self.assertEqual(json.loads(first)["phase"],"completed")
            self.assertEqual(db.execute("SELECT work_turn FROM activities").fetchone()[0],"original")
        self.service.subscribe_activity(*args)
        with sqlite3.connect(self.service.db_path) as db:
            self.assertEqual(db.execute("SELECT raw FROM pending WHERE activity_id='late-activity'").fetchone()[0],first)
        self.assertEqual(self.service.work_snapshot(self.grant_id,"default","native-session")["work"]["turnId"],"newer")
        with self.assertRaises(ManagedNotificationError):
            self.service.subscribe_activity(*args[:-1],"invented")

    def test_cancelled_parent_waits_for_owned_child_before_neutral_terminal(self):
        self.service.observe("pre_llm_call",profile="default",session_id="native-session",turn_id="parent")
        self.service.observe("subagent_start",profile="default",parent_session_id="native-session",parent_turn_id="parent",child_session_id="child")
        self.service.observe("on_session_end",profile="default",session_id="native-session",turn_id="parent",interrupted=True)
        snapshot=self.service.work_snapshot(self.grant_id,"default","native-session")["work"]
        self.assertEqual(snapshot["phase"],"delegating")
        self.assertFalse(snapshot["terminal"])
        self.service.observe("subagent_stop",profile="default",parent_session_id="native-session",parent_turn_id="later-parent",child_session_id="child")
        snapshot=self.service.work_snapshot(self.grant_id,"default","native-session")["work"]
        self.assertEqual(snapshot["phase"],"completed")
        self.assertEqual(snapshot["outcome"],"cancelled")
        self.assertTrue(snapshot["terminal"])

    def test_fresh_process_does_not_restore_live_work_from_subscription(self):
        self.service.observe("pre_llm_call",profile="default",session_id="native-session",turn_id="old")
        reopened=ManagedNotifications(Path(self.temp.name)/"managed",transport=self.transport,clock=lambda:self.now,
            session_opener=lambda profile,read,read_only:read(self))
        try:
            self.assertIsNone(reopened.work_snapshot(self.grant_id,"default","native-session")["work"])
        finally:
            reopened.close()

    def test_current_work_snapshot_is_scoped_and_canonical(self):
        self.service.observe("pre_llm_call",profile="default",session_id="native-session",turn_id="canonical-turn",platform="desktop")
        snapshot = self.service.work_snapshot(self.grant_id,"default","native-session")
        self.assertEqual(snapshot["work"]["turnId"],"canonical-turn")
        self.assertEqual(snapshot["work"]["sessionId"],"native-session")
        self.assertEqual(snapshot["work"]["phase"],"thinking")
        self.assertNotIn("private",repr(snapshot).lower())
        with self.assertRaises(ManagedNotificationError):
            self.service.work_snapshot(self.grant_id,"default","unsubscribed")

    def test_one_native_terminal_event_persists_and_retries_identical_ciphertext(self):
        payload=dict(profile="default",session_id="native-session",turn_id="turn-a",completed=True,platform="desktop")
        self.service.observe("on_session_end",**payload)
        self.service.observe("on_session_end",**payload)
        with sqlite3.connect(self.service.db_path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0],1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending").fetchone()[0],1)
        self.fail_send=True
        self.service.drain_pending()
        first=self.calls[-1]
        self.now+=5
        self.fail_send=False
        self.service.drain_pending()
        second=self.calls[-1]
        self.assertEqual(first[2],second[2])
        self.assertNotEqual(first[3]["x-loopdy-nonce"],second[3]["x-loopdy-nonce"])
        self.assertTrue(json.loads(second[2])["eventId"].startswith(self.grant_id+":"))
        with sqlite3.connect(self.service.db_path) as db:
            self.assertEqual(db.execute("SELECT state FROM pending").fetchone()[0],"accepted")

    def test_unsubscribed_other_profile_children_and_cancellation_do_not_alert(self):
        for change in [dict(session_id="other-session"),dict(profile="other"),dict(platform="subagent"),dict(interrupted=True)]:
            payload=dict(profile="default",session_id="native-session",turn_id="turn-a",completed=True,platform="desktop")|change
            self.service.observe("on_session_end",**payload)
        self.service.drain_pending()
        self.assertEqual(self.calls,[])

    def test_local_revocation_cancels_pending_and_retains_identity_after_reopen(self):
        self.service.observe("on_session_end",profile="default",session_id="native-session",turn_id="turn-a",failed=True,platform="desktop")
        self.service.remove(self.grant_id)
        self.service.drain_pending()
        self.assertEqual(self.calls,[])
        self.service.close()
        reopened=ManagedNotifications(Path(self.temp.name)/"managed",transport=self.transport,clock=lambda:self.now)
        try:
            self.assertEqual(reopened.public_key,self.service.public_key)
            with self.assertRaises(ManagedNotificationError): reopened.enrollment(self.grant_id)
        finally: reopened.close()

    def test_policy_suppression_is_durable_not_delayed_until_quiet_hours_end(self):
        self.service.preference_policy=lambda event,device:{"suppression":"quiet_hours","sound":False}
        payload=dict(profile="default",session_id="native-session",turn_id="turn-a",completed=True,platform="desktop")
        self.service.observe("on_session_end",**payload)
        self.service.preference_policy=None
        self.service.observe("on_session_end",**payload)
        self.service.drain_pending()
        self.assertEqual(self.calls,[])
        with sqlite3.connect(self.service.db_path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0],1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending").fetchone()[0],0)

if __name__ == "__main__": unittest.main()
