from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from loopdy_plugin.attachments import AttachmentStore
from loopdy_plugin.link_contracts import MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_CHUNKS
from loopdy_plugin.workspace_control import HermesWorkspaceBackend, WorkspaceControlError


class AgentMediaTransferTests(unittest.TestCase):
    def test_large_agent_video_resolves_and_reassembles_without_expanding_upload_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reproduction = os.environ.get("LOOPDY_MEDIA_REPRO_PATH")
            content = Path(reproduction).read_bytes() if reproduction else (bytes(range(256)) * 51_321)[:13_138_172]
            self.assertEqual(len(content), 13_138_172)
            source = root / "render.mp4"
            source.write_bytes(content)
            backend = HermesWorkspaceBackend(service=object(), attachment_store=AttachmentStore(root / "media.sqlite3"))

            async def transfer():
                resolved = await backend.attachments_resolve({
                    "agentId": "default", "storedId": "media-session",
                    "items": [{"itemId": "media-message", "text": f"Video\nMEDIA:{source}"}],
                })
                self.assertEqual(len(resolved["items"][0]["attachments"]), 1,
                                 "A valid agent video above 8 MiB must not be silently omitted")
                attachment = resolved["items"][0]["attachments"][0]
                self.assertEqual(attachment["byteCount"], len(content))
                offset, chunks = 0, []
                while offset < len(content):
                    response = await backend.attachments_fetch({
                        "agentId": "default", "attachmentId": attachment["id"], "offset": offset,
                    })
                    self.assertEqual(response["offset"], offset)
                    chunk = base64.b64decode(response["data"], validate=True)
                    self.assertGreater(len(chunk), 0)
                    self.assertLessEqual(len(chunk), 65_536)
                    chunks.append(chunk)
                    offset += len(chunk)
                    self.assertEqual(response["nextOffset"], offset if offset < len(content) else None)
                    self.assertLessEqual(len(chunks), 400)
                self.assertEqual(hashlib.sha256(b"".join(chunks)).digest(), hashlib.sha256(content).digest())
                self.assertEqual(len(chunks), 201)
                with self.assertRaises(WorkspaceControlError):
                    await backend.attachments_fetch({"agentId": "another-profile", "attachmentId": attachment["id"], "offset": 0})
                with self.assertRaises(WorkspaceControlError):
                    await backend.attachments_fetch({"agentId": "default", "attachmentId": attachment["id"], "offset": len(content)})

            asyncio.run(transfer())
            # Agent download expansion must not enlarge phone upload authority.
            self.assertEqual(MAX_ATTACHMENT_BYTES, 8 * 1024 * 1024)
            self.assertEqual(MAX_ATTACHMENT_CHUNKS, 128)

    def test_maximum_agent_file_is_available_and_over_limit_is_not_registered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            maximum = 25 * 1024 * 1024
            source = root / "boundary.mp4"
            source.write_bytes(b"v" * maximum)
            backend = HermesWorkspaceBackend(service=object(), attachment_store=AttachmentStore(root / "media.sqlite3"))
            resolved = asyncio.run(backend.attachments_resolve({
                "agentId": "default", "storedId": "boundary-session",
                "items": [{"itemId": "boundary-message", "text": f"MEDIA:{source}"}],
            }))
            self.assertEqual(len(resolved["items"][0]["attachments"]), 1)
            attachment = resolved["items"][0]["attachments"][0]
            final = asyncio.run(backend.attachments_fetch({
                "agentId": "default", "attachmentId": attachment["id"], "offset": maximum - 65_536,
            }))
            self.assertEqual(len(base64.b64decode(final["data"])), 65_536)
            self.assertIsNone(final["nextOffset"])
            source.write_bytes(b"v" * (maximum + 1))
            oversized = asyncio.run(backend.attachments_resolve({
                "agentId": "default", "storedId": "oversize-session",
                "items": [{"itemId": "oversize-message", "text": f"MEDIA:{source}"}],
            }))
            self.assertEqual(oversized["items"][0]["attachments"], [])


if __name__ == "__main__":
    unittest.main()
