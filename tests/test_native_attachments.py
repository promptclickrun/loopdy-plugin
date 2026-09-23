"""Native agent-attachment provenance and transport."""
from __future__ import annotations

import base64
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from loopdy_plugin import native_attachments as na
from loopdy_plugin.attachments import AttachmentStore


def _db(path: Path, rows: list[tuple[str, str, str]], parents: dict[str, str | None]) -> None:
    with sqlite3.connect(path) as c:
        c.execute("CREATE TABLE sessions (id TEXT PRIMARY KEY, parent_session_id TEXT)")
        c.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT)")
        c.executemany("INSERT INTO sessions VALUES (?, ?)", parents.items())
        c.executemany("INSERT INTO messages (session_id, role, content) VALUES (?, ?, ?)", rows)


class NativeAttachmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.pdf = root / "Report.pdf"
        self.pdf.write_bytes(b"%PDF-1.4\n" + b"x" * 5000)
        self.secret = root / "other.pdf"
        self.secret.write_bytes(b"%PDF-1.4 other")
        self.db = root / "state.db"
        _db(self.db, [
            ("parent", "assistant", f"Here you go.\nMEDIA://{self.pdf}"),
            ("child", "user", f"MEDIA:{self.secret}"),
        ], {"parent": None, "child": "parent"})
        na._store = AttachmentStore(root / "a.sqlite3")
        self.addCleanup(setattr, na, "_store", None)
        self.addCleanup(self.tmp.cleanup)
        p = patch.object(na, "_state_db", return_value=self.db)
        p.start()
        self.addCleanup(p.stop)

    def test_resolves_emitted_path_through_compaction_lineage_including_double_slash(self):
        body = na._Resolve(agentId="default", storedId="child",
                           items=[na._Item(itemId="m1", text=f"Here you go.\nMEDIA://{self.pdf}")])
        [item] = na.resolve(body)["items"]
        self.assertEqual(item["text"], "Here you go.")
        [attachment] = item["attachments"]
        self.assertEqual((attachment["fileName"], attachment["mimeType"]), ("Report.pdf", "application/pdf"))
        self.assertNotIn(self.tmp.name, repr(item))

        na.MAX_CHUNK_BYTES, saved = 2048, na.MAX_CHUNK_BYTES
        self.addCleanup(setattr, na, "MAX_CHUNK_BYTES", saved)
        data, offset = b"", 0
        while offset is not None:
            chunk = na.fetch(na._Fetch(agentId="default", attachmentId=attachment["id"], offset=offset))
            data += base64.b64decode(chunk["data"])
            offset = chunk["nextOffset"]
        self.assertEqual(data, self.pdf.read_bytes())

    def test_refuses_paths_no_assistant_emitted_even_when_the_client_names_them(self):
        body = na._Resolve(agentId="default", storedId="child", items=[
            na._Item(itemId="m1", text=f"MEDIA:{self.secret}"),
            na._Item(itemId="m2", text=f"MEDIA:{self.pdf}\nMEDIA:{self.secret}"),
        ])
        first, second = na.resolve(body)["items"]
        self.assertEqual(first["attachments"], [])
        self.assertEqual([a["fileName"] for a in second["attachments"]], ["Report.pdf"])

    def test_unknown_session_and_other_profile_fail_closed(self):
        body = na._Resolve(agentId="default", storedId="nope",
                           items=[na._Item(itemId="m1", text=f"MEDIA:{self.pdf}")])
        self.assertEqual(na.resolve(body)["items"][0]["attachments"], [])
        [item] = na.resolve(na._Resolve(agentId="default", storedId="parent",
                                        items=[na._Item(itemId="m1", text=f"MEDIA:{self.pdf}")]))["items"]
        with self.assertRaises(na.NativeAPIError):
            na.fetch(na._Fetch(agentId="other", attachmentId=item["attachments"][0]["id"], offset=0))


if __name__ == "__main__":
    unittest.main()
