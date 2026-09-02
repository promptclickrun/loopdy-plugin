from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from loopdy_plugin import attachments as attachment_module
from loopdy_plugin.attachments import AttachmentStore


class AttachmentStoreTests(unittest.TestCase):
    def test_resolve_extracts_media_image_and_pdf_without_exposing_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "chart.png"
            document = root / "brief.pdf"
            image.write_bytes(b"\x89PNG\r\n\x1a\nfixture")
            document.write_bytes(b"%PDF-1.7\nfixture")
            store = AttachmentStore(root / "loopdy.sqlite3")

            with patch.dict(
                "os.environ",
                {
                    "HERMES_MEDIA_DELIVERY_STRICT": "0",
                    "HERMES_MEDIA_ALLOW_DIRS": "",
                    "HERMES_MEDIA_TRUST_RECENT_FILES": "1",
                },
            ):
                result = store.resolve(
                    profile="default",
                    session_id="session-1",
                    items=[
                        {
                            "id": "row-9",
                            "text": (
                                f"Here are the files.\nMEDIA:{image}\n"
                                f"MEDIA:{document}"
                            ),
                        }
                    ],
                )

            self.assertEqual(result[0]["id"], "row-9")
            self.assertEqual(result[0]["text"], "Here are the files.")
            self.assertEqual(
                [attachment["kind"] for attachment in result[0]["attachments"]],
                ["image", "file"],
            )
            self.assertEqual(
                [attachment["name"] for attachment in result[0]["attachments"]],
                ["chart.png", "brief.pdf"],
            )
            self.assertEqual(
                [attachment["mime_type"] for attachment in result[0]["attachments"]],
                ["image/png", "application/pdf"],
            )
            for attachment in result[0]["attachments"]:
                self.assertRegex(attachment["id"], r"^[0-9a-f]{32}$")
                self.assertGreater(attachment["size"], 0)

            public_json = json.dumps(result)
            self.assertNotIn(str(root), public_json)
            self.assertNotIn("MEDIA:", public_json)

    def test_resolve_deduplicates_references_and_rehydrates_cached_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "chart.png"
            image.write_bytes(b"\x89PNG\r\n\x1a\nfixture")
            text = f"Chart ready.\nMEDIA:{image}\nMEDIA:{image}"
            store = AttachmentStore(root / "loopdy.sqlite3")

            first = store.resolve(
                profile="default",
                session_id="session-1",
                items=[{"id": "row-1", "text": text}],
            )
            image.unlink()
            reopened = AttachmentStore(root / "loopdy.sqlite3").resolve(
                profile="default",
                session_id="session-1",
                items=[{"id": "row-1", "text": text}],
            )

            self.assertEqual(len(first[0]["attachments"]), 1)
            self.assertEqual(reopened, first)
            cached = store.read(
                profile="default",
                attachment_id=first[0]["attachments"][0]["id"],
            )
            self.assertEqual(cached["content"], b"\x89PNG\r\n\x1a\nfixture")
            self.assertIsNone(
                store.read(
                    profile="other",
                    attachment_id=first[0]["attachments"][0]["id"],
                )
            )

    def test_resolve_fails_closed_for_missing_denied_and_oversized_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oversized = root / "large.pdf"
            oversized.write_bytes(b"0123456789")
            store = AttachmentStore(root / "loopdy.sqlite3")
            missing = root / "missing.pdf"
            system_password_file = Path("/etc") / "passwd"

            with (
                patch.object(attachment_module, "MAX_ARTIFACT_BYTES", 8),
                patch.object(
                    attachment_module.BasePlatformAdapter,
                    "filter_media_delivery_paths",
                    return_value=[(str(oversized), False)],
                ),
            ):
                result = store.resolve(
                    profile="default",
                    session_id="session-1",
                    items=[
                        {
                            "id": "row-2",
                            "text": (
                                f"Unavailable.\nMEDIA:{missing}\n"
                                f"MEDIA:{system_password_file}\n"
                                f"MEDIA:{oversized}"
                            ),
                        }
                    ],
                )

            self.assertEqual(result[0]["text"], "Unavailable.")
            self.assertEqual(result[0]["attachments"], [])
            self.assertNotIn(str(root), json.dumps(result))
            self.assertNotIn(str(system_password_file), json.dumps(result))

    def test_resolve_honors_strict_recency_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stale = root / "stale.pdf"
            stale.write_bytes(b"%PDF-1.7\nfixture")
            os.utime(stale, (1, 1))
            store = AttachmentStore(root / "loopdy.sqlite3")

            with patch.dict(
                "os.environ",
                {
                    "HERMES_MEDIA_DELIVERY_STRICT": "1",
                    "HERMES_MEDIA_ALLOW_DIRS": "",
                    "HERMES_MEDIA_TRUST_RECENT_FILES": "1",
                    "HERMES_MEDIA_TRUST_RECENT_SECONDS": "1",
                },
            ):
                result = store.resolve(
                    profile="default",
                    session_id="session-1",
                    items=[{"id": "row-3", "text": f"Old file.\nMEDIA:{stale}"}],
                )

            self.assertEqual(result, [{"id": "row-3", "text": "Old file.", "attachments": []}])

    def test_cache_evicts_oldest_profile_bytes_and_invalidates_message_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_file = root / "first.pdf"
            second_file = root / "second.pdf"
            first_file.write_bytes(b"12345678")
            second_file.write_bytes(b"abcdefgh")
            store = AttachmentStore(root / "loopdy.sqlite3")
            environment = {
                "HERMES_MEDIA_DELIVERY_STRICT": "0",
                "HERMES_MEDIA_ALLOW_DIRS": "",
                "HERMES_MEDIA_TRUST_RECENT_FILES": "1",
            }

            with (
                patch.dict("os.environ", environment),
                patch.object(attachment_module, "MAX_CACHE_BYTES_PER_PROFILE", 12),
                patch.object(attachment_module, "MAX_CACHE_ITEMS_PER_PROFILE", 10),
            ):
                first = store.resolve(
                    profile="default",
                    session_id="session-1",
                    items=[{"id": "row-first", "text": f"First.\nMEDIA:{first_file}"}],
                )
                second = store.resolve(
                    profile="default",
                    session_id="session-1",
                    items=[{"id": "row-second", "text": f"Second.\nMEDIA:{second_file}"}],
                )
                first_id = first[0]["attachments"][0]["id"]
                second_id = second[0]["attachments"][0]["id"]
                self.assertIsNone(store.read(profile="default", attachment_id=first_id))
                cached_second = store.read(profile="default", attachment_id=second_id)
                self.assertIsNotNone(cached_second)
                assert cached_second is not None
                self.assertEqual(cached_second["content"], b"abcdefgh")

                restored = store.resolve(
                    profile="default",
                    session_id="session-1",
                    items=[{"id": "row-first", "text": f"First.\nMEDIA:{first_file}"}],
                )
                self.assertNotEqual(restored[0]["attachments"][0]["id"], first_id)
                self.assertEqual(restored[0]["text"], "First.")

    def test_resolve_keeps_normal_text_unchanged_and_rejects_oversized_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = AttachmentStore(Path(directory) / "loopdy.sqlite3")
            self.assertEqual(
                store.resolve(
                    profile="default",
                    session_id="session-1",
                    items=[{"id": "row-4", "text": "Normal assistant text."}],
                ),
                [{"id": "row-4", "text": "Normal assistant text.", "attachments": []}],
            )
            with self.assertRaisesRegex(ValueError, "bytes"):
                store.resolve(
                    profile="default",
                    session_id="session-1",
                    items=[{"id": "row-5", "text": "x" * (attachment_module.MAX_TEXT_BYTES + 1)}],
                )


if __name__ == "__main__":
    unittest.main()
