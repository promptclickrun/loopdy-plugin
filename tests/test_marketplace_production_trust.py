from __future__ import annotations
import base64
import unittest
from loopdy_plugin.marketplace import load_marketplace_trust_keys, MarketplaceInstallError

class MarketplaceProductionTrustTests(unittest.TestCase):
    def test_absent_override_uses_bundled_release_key(self):
        expected = base64.b64decode('GnPP7wB2Le94RCGEzcDCa+SNzc/6i2Ftgox92cHhzGQ=')
        self.assertEqual(load_marketplace_trust_keys({}), {'loopdy-release-2026-09': expected})

    def test_bundled_key_verifies_release_custody_challenge(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        public = load_marketplace_trust_keys({})['loopdy-release-2026-09']
        signature = base64.b64decode('3ocUA305XJRebCc+voxWrqsF6FNXobTgm5UCowL1FcFQi/WKgkMZzFDYRtVq1gQg/KaieMLnAWQvthGR7yeoAw==')
        Ed25519PublicKey.from_public_bytes(public).verify(signature, b'loopdy-marketplace-trust-proof-v1')

    def test_explicit_empty_override_disables_trust(self):
        self.assertEqual(load_marketplace_trust_keys({'LOOPDY_MARKETPLACE_TRUSTED_ED25519_KEYS': ''}), {})

    def test_malformed_override_does_not_fall_back(self):
        with self.assertRaises(MarketplaceInstallError):
            load_marketplace_trust_keys({'LOOPDY_MARKETPLACE_TRUSTED_ED25519_KEYS': '{bad'})

    def test_valid_override_replaces_instead_of_extending_trust(self):
        import json
        key = base64.b64encode(bytes([1]) * 32).decode()
        self.assertEqual(load_marketplace_trust_keys({'LOOPDY_MARKETPLACE_TRUSTED_ED25519_KEYS': json.dumps({'custom-key': key})}), {'custom-key': bytes([1]) * 32})
