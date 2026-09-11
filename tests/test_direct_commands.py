from __future__ import annotations

import asyncio
import dataclasses
import math
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from loopdy_plugin.direct_connection import DirectPeer


class _Clock:
    def __init__(self, now: float = 2_000_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _peer(**changes: object) -> DirectPeer:
    values: dict[str, object] = {
        "account_origin": "https://account.example",
        "direct_origin": "https://direct.example:8443",
        "host_device_id": "host_device_1",
        "host_epoch": 7,
        "host_key_fingerprint": "h" * 43,
        "peer_device_id": "phone_device_1",
        "peer_epoch": 11,
        "peer_key_fingerprint": "p" * 43,
    }
    values.update(changes)
    return DirectPeer(**values)  # type: ignore[arg-type]


class DirectCommandJournalTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "private" / "direct-commands.sqlite3"
        self.clock = _Clock()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _journal(self, path: Path | None = None, **limits: int):
        from loopdy_plugin.direct_commands import DirectCommandJournal

        return DirectCommandJournal(path or self.path, clock=self.clock, **limits)

    async def test_concurrent_journals_admit_one_execution(self) -> None:
        first = self._journal()
        second = self._journal()
        issued_at = int(self.clock())

        admissions = await asyncio.gather(
            first.admit(_peer(), "command.concurrent.1", issued_at, {"value": 1}),
            second.admit(_peer(), "command.concurrent.1", issued_at, {"value": 1}),
        )

        self.assertEqual(sum(admission.is_new for admission in admissions), 1)
        self.assertEqual(
            {admission.state for admission in admissions}, {"admitted", "uncertain"}
        )
        winner, owner = (
            (admissions[0], first) if admissions[0].is_new else (admissions[1], second)
        )
        completed = await owner.complete(winner, {"executed": True})
        self.assertEqual(completed.state, "completed")
        replay = await second.admit(
            _peer(), "command.concurrent.1", issued_at, {"value": 1}
        )
        self.assertEqual(replay.result, {"executed": True})
        first.close()
        second.close()

    async def test_same_key_requires_exact_payload_digest_and_issued_at(self) -> None:
        journal = self._journal()
        issued_at = int(self.clock())
        first = await journal.admit(
            _peer(), "command.conflict.1", issued_at, {"nested": {"a": 1, "b": 2}}
        )
        duplicate = await journal.admit(
            _peer(), "command.conflict.1", issued_at, {"nested": {"b": 2, "a": 1}}
        )

        self.assertTrue(first.is_new)
        self.assertFalse(duplicate.is_new)
        self.assertEqual(duplicate.state, "admitted")
        with self.assertRaises(ValueError):
            await journal.admit(
                _peer(), "command.conflict.1", issued_at, {"nested": {"a": 2}}
            )
        with self.assertRaises(ValueError):
            await journal.admit(
                _peer(), "command.conflict.1", issued_at - 1, {"nested": {"a": 1, "b": 2}}
            )
        journal.close()

    async def test_owner_scope_and_epochs_are_independent_keys(self) -> None:
        journal = self._journal()
        issued_at = int(self.clock())
        peers = (
            _peer(),
            _peer(account_origin="https://other-account.example"),
            _peer(host_device_id="host_device_2"),
            _peer(host_epoch=8),
            _peer(peer_device_id="phone_device_2"),
            _peer(peer_epoch=12),
        )

        admissions = [
            await journal.admit(peer, "command.scoped.001", issued_at, {"value": 1})
            for peer in peers
        ]

        self.assertTrue(all(admission.is_new for admission in admissions))
        journal.close()

    async def test_route_and_key_rotation_do_not_change_replay_key(self) -> None:
        journal = self._journal()
        issued_at = int(self.clock())
        original = await journal.admit(
            _peer(), "command.route-key.1", issued_at, {"value": "same"}
        )
        rotated = await journal.admit(
            _peer(
                direct_origin="https://new-direct.example",
                host_key_fingerprint="n" * 43,
                peer_key_fingerprint="q" * 43,
            ),
            "command.route-key.1",
            issued_at,
            {"value": "same"},
        )

        self.assertTrue(original.is_new)
        self.assertFalse(rotated.is_new)
        journal.close()

    async def test_reopen_marks_unfinished_uncertain_and_preserves_completed_result(self) -> None:
        first = self._journal()
        issued_at = int(self.clock())
        unfinished = await first.admit(
            _peer(), "command.restart.01", issued_at, {"operation": "one"}
        )
        completed_source = await first.admit(
            _peer(), "command.restart.02", issued_at, {"operation": "two"}
        )
        completed = await first.complete(
            completed_source, {"ok": True, "nested": {"count": 2}}
        )
        self.assertEqual(completed.state, "completed")
        first.close()

        reopened = self._journal()
        uncertain = await reopened.admit(
            _peer(), "command.restart.01", issued_at, {"operation": "one"}
        )
        replayed = await reopened.admit(
            _peer(), "command.restart.02", issued_at, {"operation": "two"}
        )

        self.assertFalse(uncertain.is_new)
        self.assertEqual(uncertain.state, "uncertain")
        self.assertFalse(replayed.is_new)
        self.assertEqual(replayed.state, "completed")
        self.assertEqual(replayed.result, {"ok": True, "nested": {"count": 2}})
        snapshot = replayed.result
        assert snapshot is not None
        snapshot["nested"]["count"] = 99
        self.assertEqual(replayed.result, {"ok": True, "nested": {"count": 2}})
        with self.assertRaises(dataclasses.FrozenInstanceError):
            unfinished.state = "completed"  # type: ignore[misc]
        reopened.close()

    async def test_completion_requires_exact_live_admission_capability(self) -> None:
        journal = self._journal()
        other = self._journal()
        issued_at = int(self.clock())
        admission = await journal.admit(
            _peer(), "command.capability.1", issued_at, {"operation": "mutate"}
        )

        with self.assertRaises(ValueError):
            await other.complete(admission, {"ok": True})
        forged = dataclasses.replace(admission, command_id="command.capability.2")
        with self.assertRaises(ValueError):
            await journal.complete(forged, {"ok": True})
        completed = await journal.complete(admission, {"ok": True})
        self.assertEqual(completed.result, {"ok": True})
        with self.assertRaises(ValueError):
            await journal.complete(admission, {"ok": False})
        journal.close()
        other.close()

    async def test_expired_request_cannot_be_readmitted_after_record_pruning(self) -> None:
        journal = self._journal()
        issued_at = int(self.clock())
        await journal.admit(_peer(), "command.expired.001", issued_at, {"value": 1})
        self.clock.advance(24 * 60 * 60 + 61)

        with self.assertRaises(ValueError):
            await journal.admit(_peer(), "command.expired.001", issued_at, {"value": 1})

        fresh = await journal.admit(
            _peer(), "command.fresh.0001", int(self.clock()), {"value": 2}
        )
        self.assertTrue(fresh.is_new)
        journal.close()

    async def test_rejects_clock_skew_invalid_command_peer_and_noncanonical_bodies(self) -> None:
        journal = self._journal()
        now = int(self.clock())
        payload_cases = (
            None,
            {"value": float("nan")},
            {"value": float("inf")},
            {"value": b"bytes"},
            {"value": (1, 2)},
            {1: "non-string key"},
            {"value": "x" * (512 * 1024)},
        )
        nested: dict[str, object] = {"leaf": True}
        for _ in range(20):
            nested = {"nested": nested}
        payload_cases += (nested,)

        for index, payload in enumerate(payload_cases):
            with self.subTest(payload=index), self.assertRaises(ValueError):
                await journal.admit(
                    _peer(), f"command.invalid.{index:02d}", now, payload  # type: ignore[arg-type]
                )
        for command_id in ("short", "contains spaces 1", "a" * 129):
            with self.subTest(command_id=command_id), self.assertRaises(ValueError):
                await journal.admit(_peer(), command_id, now, {"value": 1})
        for issued_at in (True, now + 61, now - 24 * 60 * 60 - 1):
            with self.subTest(issued_at=issued_at), self.assertRaises(ValueError):
                await journal.admit(
                    _peer(), "command.clock-skew", issued_at, {"value": 1}  # type: ignore[arg-type]
                )
        for peer in (
            object(),
            _peer(account_origin="https://account.example/invalid"),
            _peer(host_epoch=True),
            _peer(peer_device_id="bad/device"),
            _peer(peer_key_fingerprint="short"),
        ):
            with self.subTest(peer=peer), self.assertRaises(ValueError):
                await journal.admit(
                    peer, "command.invalid-peer", now, {"value": 1}  # type: ignore[arg-type]
                )
        journal.close()

    async def test_entry_and_byte_capacity_reject_without_evicting_live_records(self) -> None:
        issued_at = int(self.clock())
        entry_limited = self._journal(maximum_entries=1)
        first = await entry_limited.admit(
            _peer(), "command.capacity.01", issued_at, {"value": 1}
        )
        with self.assertRaises(ValueError):
            await entry_limited.admit(
                _peer(), "command.capacity.02", issued_at, {"value": 2}
            )
        replay = await entry_limited.admit(
            _peer(), "command.capacity.01", issued_at, {"value": 1}
        )
        self.assertTrue(first.is_new)
        self.assertFalse(replay.is_new)
        entry_limited.close()

        byte_path = Path(self.temporary.name) / "bytes" / "journal.sqlite3"
        byte_limited = self._journal(byte_path, maximum_entries=10, maximum_bytes=525_000)
        await byte_limited.admit(
            _peer(), "command.byte-cap.01", issued_at, {"value": 1}
        )
        with self.assertRaises(ValueError):
            await byte_limited.admit(
                _peer(), "command.byte-cap.02", issued_at, {"value": 2}
            )
        byte_limited.close()

    async def test_failed_sqlite_insert_never_claims_new_admission(self) -> None:
        journal = self._journal()
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "CREATE TRIGGER reject_direct_command_insert "
                "BEFORE INSERT ON direct_commands BEGIN "
                "SELECT RAISE(ABORT, 'fixture persistence failure'); END"
            )

        with self.assertRaises(sqlite3.IntegrityError):
            await journal.admit(
                _peer(), "command.persist-fail", int(self.clock()), {"value": 1}
            )
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM direct_commands").fetchone()[0], 0)
            connection.execute("DROP TRIGGER reject_direct_command_insert")

        admitted = await journal.admit(
            _peer(), "command.persist-fail", int(self.clock()), {"value": 1}
        )
        self.assertTrue(admitted.is_new)
        journal.close()

    async def test_cancelled_wait_after_commit_cannot_readmit(self) -> None:
        journal = self._journal()
        original = journal._admit_sync
        committed = threading.Event()
        release = threading.Event()
        finished = threading.Event()

        def committed_then_wait(*args: object):
            try:
                admission = original(*args)
                committed.set()
                release.wait(5)
                return admission
            finally:
                finished.set()

        journal._admit_sync = committed_then_wait  # type: ignore[method-assign]
        issued_at = int(self.clock())
        task = asyncio.create_task(
            journal.admit(_peer(), "command.cancelled.1", issued_at, {"value": 1})
        )
        self.assertTrue(await asyncio.to_thread(committed.wait, 5))
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        journal._admit_sync = original  # type: ignore[method-assign]
        release.set()
        self.assertTrue(await asyncio.to_thread(finished.wait, 5))

        replay = await journal.admit(
            _peer(), "command.cancelled.1", issued_at, {"value": 1}
        )
        self.assertFalse(replay.is_new)
        self.assertEqual(replay.state, "admitted")
        journal.close()

    async def test_oversized_result_leaves_record_unfinished_and_retryable_only_for_completion(self) -> None:
        journal = self._journal()
        issued_at = int(self.clock())
        admission = await journal.admit(
            _peer(), "command.result-size.1", issued_at, {"value": 1}
        )

        with self.assertRaises(ValueError):
            await journal.complete(admission, {"value": "x" * (512 * 1024)})
        replay = await journal.admit(
            _peer(), "command.result-size.1", issued_at, {"value": 1}
        )
        self.assertEqual(replay.state, "admitted")
        completed = await journal.complete(admission, {"unavailable": True})
        self.assertEqual(completed.result, {"unavailable": True})
        journal.close()

    async def test_payload_is_not_stored_and_private_files_are_restricted(self) -> None:
        journal = self._journal()
        await journal.admit(
            _peer(),
            "command.no-body.001",
            int(self.clock()),
            {"syntheticSecret": "fixture-value-that-must-not-persist"},
        )
        with sqlite3.connect(self.path) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(direct_commands)")}
            row_text = repr(connection.execute("SELECT * FROM direct_commands").fetchone())

        self.assertNotIn("payload", columns)
        self.assertNotIn("fixture-value-that-must-not-persist", row_text)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.path.parent).st_mode & 0o777, 0o700)
        journal.close()
        with self.assertRaises(RuntimeError):
            await journal.admit(
                _peer(), "command.closed.0001", int(self.clock()), {"value": 1}
            )


if __name__ == "__main__":
    unittest.main()
