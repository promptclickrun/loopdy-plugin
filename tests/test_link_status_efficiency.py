from __future__ import annotations

import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
from loopdy_plugin.link_client import LinkRuntimeConfig, LoopdyLinkClient


class CountingState:
    def __init__(self, directory: Path):
        self.data_dir = directory
        self.values = {}
        self.writes = Counter()

    def get(self, key, default=None):
        return self.values.get(key, default)

    def set(self, key, value):
        self.values[key] = value
        self.writes[key] += 1


class LinkStatusEfficiencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_repeated_receipts_preserve_status_without_rewriting_each_frame(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = CountingState(root)
            client = LoopdyLinkClient(
                LinkRuntimeConfig("https://link.example.invalid", "host-status-fixture", 1,
                                  ec.generate_private_key(ec.SECP256R1()), b"k" * 32),
                state=state, attachment_root=root / "attachments",
            )
            with patch("loopdy_plugin.link_client.time.time", return_value=100):
                client._record_runtime_status("connected")
                for index in range(100):
                    await client.handle_wire_message(json.dumps({
                        "version": 1, "type": "receipt.accepted", "frameId": f"fixture-frame-{index:04d}",
                    }), lambda _: None)
            self.assertEqual(state.writes["link.runtime_status"], 1)
            self.assertEqual(state.values["link.runtime_status"]["state"], "connected")
            with patch("loopdy_plugin.link_client.time.time", return_value=131):
                client._record_runtime_status("connected")
            self.assertEqual(state.writes["link.runtime_status"], 2)
            self.assertEqual(state.values["link.runtime_status"]["last_connected_at"], 100)
            with patch("loopdy_plugin.link_client.time.time", return_value=132):
                client._record_runtime_status("disconnected", "network unavailable")
            self.assertEqual(state.writes["link.runtime_status"], 3)
            self.assertEqual(state.values["link.runtime_status"]["detail"], "network unavailable")
            await client.stop()
