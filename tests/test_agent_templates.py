"""Credential-free template persistence checks against public profile helpers."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

# Isolate before importing host/plugin modules, and restore the environment
# when this test module finishes rather than contaminating later test modules.
def setUpModule():
    global _HOME, _previous_home, templates
    _previous_home = os.environ.get("HERMES_HOME")
    _HOME = tempfile.TemporaryDirectory(prefix="loopdy-template-test-")
    os.environ["HERMES_HOME"] = _HOME.name
    from loopdy_plugin import agent_templates
    templates = agent_templates


def tearDownModule():
    if _previous_home is None:
        os.environ.pop("HERMES_HOME", None)
    else:
        os.environ["HERMES_HOME"] = _previous_home
    _HOME.cleanup()


class AgentTemplateTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(_HOME.name)
        self.workspace = self.home / ("workspace-" + uuid.uuid4().hex)
        self.workspace.mkdir()
        self.config = self.home / "config.yaml"
        self.config.write_text(json.dumps({"terminal": {"cwd": str(self.workspace)}, "model": "fixture-model"}))
        self.soul = self.home / "SOUL.md"
        self.soul.write_text("Help with the selected task.\n", encoding="utf-8")
        self.template_id = str(uuid.uuid4())

    def document(self):
        return templates._derive("default", self.template_id)

    def test_derive_save_read_preserves_source(self):
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in [self.config, self.soul]}
        document = self.document()
        self.assertFalse((self.workspace / ".loopdy").exists())
        document["title"] = "Independent template"
        document["soul"] = "A separate purpose.\n"
        saved = templates._save("default", document, None)
        read = templates._read("default", self.template_id)
        self.assertEqual(saved, read)
        self.assertEqual(read["template"]["soul"], "A separate purpose.\n")
        self.assertEqual(len(templates._catalog("default")["templates"]), 1)
        self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in before})

    def test_create_only_and_stale_update_conflict(self):
        document = self.document()
        saved = templates._save("default", document, None)
        with self.assertRaises(templates.AgentTemplateError):
            templates._save("default", document, None)
        document["title"] = "Changed"
        with self.assertRaises(templates.AgentTemplateError):
            templates._save("default", document, "sha256:" + "0" * 64)
        updated = templates._save("default", document, saved["revision"])
        self.assertEqual(updated["template"]["title"], "Changed")

    def test_source_provenance_is_immutable(self):
        document = self.document()
        saved = templates._save("default", document, None)
        document["source"]["derivedAt"] += 1
        with self.assertRaises(templates.AgentTemplateError):
            templates._save("default", document, saved["revision"])
        self.assertEqual(templates._read("default", self.template_id), saved)

    def test_symlinked_template_directory_is_refused(self):
        outside = self.home / ("outside-" + uuid.uuid4().hex)
        outside.mkdir()
        (self.workspace / ".loopdy").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(templates.AgentTemplateError):
            templates._save("default", self.document(), None)
        self.assertEqual(list(outside.iterdir()), [])

    def test_sensitive_config_keys_remain_excluded(self):
        for name in (
            "api_key", "APIKEY", "access_token", "secret", "password", "credential",
            "authorization", "cookie", "header", "headers", "env", "certificate",
            "private_key", "environment",
        ):
            with self.subTest(name=name):
                self.assertIsNotNone(templates._SECRET_KEY.search(name))
        for name in ("model", "temperature", "cwd", "max_iterations", "tools"):
            with self.subTest(name=name):
                self.assertIsNone(templates._SECRET_KEY.search(name))

    def test_editable_content_still_rejects_credentials(self):
        document = self.document()
        document["soul"] = "api_key=" + uuid.uuid4().hex
        with self.assertRaises(templates.AgentTemplateError) as caught:
            templates._save("default", document, None)
        self.assertEqual(caught.exception.code, "secret_scan_blocked")
        self.assertFalse((self.workspace / ".loopdy").exists())

    def test_zero_progress_write_fails_without_leaving_temporary_file(self):
        document = self.document()
        with patch.object(templates.os, "write", return_value=0):
            with self.assertRaises(OSError):
                templates._save("default", document, None)
        folder = self.workspace / ".loopdy" / "agent-templates" / "default"
        self.assertEqual(list(folder.glob(".tmp-*")), [])

    def test_write_failure_cleans_temporary_file(self):
        document = self.document()
        real_write = os.write
        def partial_then_fail(fd, content):
            real_write(fd, content[:8])
            raise OSError("fixture write failure")
        with patch.object(templates.os, "write", side_effect=partial_then_fail):
            with self.assertRaises(OSError):
                templates._save("default", document, None)
        folder = self.workspace / ".loopdy" / "agent-templates" / "default"
        self.assertEqual(list(folder.glob(".tmp-*")), [])
        self.assertFalse((folder / (self.template_id + ".json")).exists())


if __name__ == "__main__":
    unittest.main()
