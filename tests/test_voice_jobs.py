"""Durable concurrent voice-job ownership, no live agent invocations."""
import tempfile
import unittest
from pathlib import Path


class VoiceJobTests(unittest.IsolatedAsyncioTestCase):
    async def test_reverse_completion_owner_fences_and_restart_do_not_repeat_work(self):
        from loopdy_plugin.voice_jobs import VoiceJobLedger, VoiceJobOwner, VoiceJobConflict, VoiceJobNotFound
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as root:
            owner=VoiceJobOwner("https://account.example","host",1,"phone",1,"default")
            ledger=VoiceJobLedger(Path(root)/"jobs.sqlite3")
            first=ledger.admit(owner,"voice","delegation_one","First task")
            second=ledger.admit(owner,"voice","delegation_two","Second task")
            with self.assertRaises(VoiceJobConflict):
                VoiceJobLedger(Path(root)/"jobs.sqlite3")
            running=[]
            for job in (first,second):
                job=ledger.start(owner,job.job_id,run_id=job.run_id,expected_revision=job.revision)
                running.append(ledger.running(owner,job.job_id,run_id=job.run_id,expected_revision=job.revision))
            for job in reversed(running):
                done=ledger.complete(owner,job.job_id,run_id=job.run_id,expected_revision=job.revision,summary=job.text)
                self.assertEqual(done.state,"completed")
            with self.assertRaises(VoiceJobNotFound):
                ledger.get(replace(owner,device_id="other"),first.job_id)
            with self.assertRaises(VoiceJobConflict):
                ledger.complete(owner,running[0].job_id,run_id=running[0].run_id,expected_revision=running[0].revision,summary="stale")
            third=ledger.admit(owner,"voice","delegation_three","Third task")
            ledger.close()
            reopened=VoiceJobLedger(Path(root)/"jobs.sqlite3")
            self.assertEqual(reopened.get(owner,third.job_id).state,"uncertain")
            self.assertFalse(reopened.admit(owner,"voice","delegation_three","Third task").is_new)
            self.assertEqual(reopened.get(owner,first.job_id).summary,"First task")
            reopened.close()

    async def test_duplicate_delegation_does_not_create_or_submit_another_job(self):
        from loopdy_plugin.voice_jobs import VoiceJobLedger, VoiceJobOwner
        with tempfile.TemporaryDirectory() as root:
            owner = VoiceJobOwner(account_origin="https://account.example", host_id="host_fixture",
                                 host_epoch=1, device_id="phone_fixture", device_epoch=1, agent_id="default")
            ledger = VoiceJobLedger(Path(root) / "jobs.sqlite3")
            first = ledger.admit(owner, voice_id="voice_fixture", delegation_id="delegation_a", text="Read project status")
            second = ledger.admit(owner, voice_id="voice_fixture", delegation_id="delegation_b", text="Read project tests")
            duplicate = ledger.admit(owner, voice_id="voice_fixture", delegation_id="delegation_a", text="Read project status")
            self.assertNotEqual(first.job_id, second.job_id)
            self.assertNotEqual(first.session_id, second.session_id)
            self.assertEqual(first.job_id, duplicate.job_id)
            self.assertTrue(first.is_new)
            self.assertFalse(duplicate.is_new)
            ledger.close()
            reopened = VoiceJobLedger(Path(root) / "jobs.sqlite3")
            replay = reopened.admit(owner, voice_id="voice_fixture", delegation_id="delegation_a", text="Read project status")
            self.assertFalse(replay.is_new)
            self.assertEqual(replay.job_id, first.job_id)
            reopened.close()
