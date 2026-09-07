"""Read-only discovery never imports a gateway or treats disk metadata as activation."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("companion_discovery", Path(__file__).parents[1] / "scripts" / "companion_discovery.py")
discovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(discovery)


class CompanionDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "profile"

    def test_missing_home_does_not_get_created(self):
        result = discovery.inspect_profile(str(self.home))
        self.assertEqual(result["installation"], "absent")
        self.assertIsNone(result["activeRevision"])
        self.assertFalse(self.home.exists())
        self.assertNotIn("runtimeID", result)

    def test_metadata_is_only_evidence_not_gateway_activation(self):
        self.make_install()
        before = {str(p): p.read_bytes() for p in self.home.rglob("*") if p.is_file()}
        result = discovery.inspect_profile(str(self.home))
        self.assertEqual(result["installation"], "metadataPresent")
        self.assertEqual(result["recordedRevision"], "a" * 40)
        self.assertEqual(result["sourceKind"], "canonical")
        self.assertIsNone(result["activeRevision"])
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.home.rglob("*") if p.is_file()})
        self.assertNotIn("secret", json.dumps(result))

    def test_unknown_and_symlinked_installations_require_repair(self):
        self.make_install(source="https://example.invalid/plugin")
        self.assertEqual(discovery.inspect_profile(str(self.home))["installation"], "unrecognized")
        path = self.home / "plugins" / ".install-metadata.json"
        path.unlink()
        path.symlink_to(self.root / "missing")
        self.assertEqual(discovery.inspect_profile(str(self.home))["installation"], "unrecognized")
        with self.assertRaises(ValueError):
            discovery.inspect_profile("relative/home")

    def test_initial_plan_is_pinned_and_revalidated_before_use(self):
        result = discovery.inspect_profile(str(self.home))
        plan = discovery.prepare_initial_install(str(self.home), "b" * 40, result["fingerprint"])
        self.assertEqual(plan["arguments"], ["plugins", "install", "https://github.com/promptclickrun/loopdy-plugin", "--ref", "b" * 40, "--no-enable"])
        self.assertEqual(plan["activationOwner"], "hermes")
        self.assertFalse(self.home.exists())
        self.make_install()
        with self.assertRaisesRegex(ValueError, "changed"):
            discovery.prepare_initial_install(str(self.home), "b" * 40, result["fingerprint"])
        with self.assertRaisesRegex(ValueError, "existing"):
            discovery.prepare_initial_install(str(self.home), "b" * 40, discovery.inspect_profile(str(self.home))["fingerprint"])
        with self.assertRaises(ValueError):
            discovery.prepare_initial_install(str(self.home), "main", result["fingerprint"])

    def test_malformed_oversized_or_unmarked_plugin_is_not_absent(self):
        self.make_install()
        path = self.home / "plugins" / ".install-metadata.json"
        for content in ["{", "x" * 65537, '{"loopdy":{},"loopdy":{}}']:
            path.write_text(content)
            self.assertEqual(discovery.inspect_profile(str(self.home))["installation"], "unrecognized")
        path.unlink()
        self.assertEqual(discovery.inspect_profile(str(self.home))["installation"], "unrecognized")

    def test_null_registration_requires_repair_and_deep_metadata_is_bounded(self):
        plugins = self.home / "plugins"
        plugins.mkdir(parents=True)
        metadata = plugins / ".install-metadata.json"
        for value in ['{"loopdy":null}', '[' * 30000 + '0' + ']' * 30000]:
            metadata.write_text(value)
            result = discovery.inspect_profile(str(self.home))
            self.assertEqual(result["installation"], "unrecognized")
            with self.assertRaisesRegex(ValueError, "existing"):
                discovery.prepare_initial_install(str(self.home), "b" * 40, result["fingerprint"])

    def make_install(self, source="https://github.com/promptclickrun/loopdy-plugin"):
        plugin = self.home / "plugins" / "loopdy"
        plugin.mkdir(parents=True)
        (plugin / "plugin.yaml").write_text("name: loopdy\nversion: 2.8.0\n")
        (self.home / "config.yaml").write_text("secret: do-not-read\n")
        (self.home / "plugins" / ".install-metadata.json").write_text(json.dumps({"loopdy": {"revision": "a" * 40, "source": source}}))
