"""Runtime configuration/lifecycle test seeds owned by the integration agent."""
import unittest


class DirectRuntimeTests(unittest.TestCase):
    def test_unconfigured_runtime_is_disabled_without_opening_a_port(self):
        from loopdy_plugin.direct_runtime import DirectSettings
        settings = DirectSettings.from_mapping({})
        self.assertFalse(settings.enabled)

    def test_direct_configuration_requires_explicit_https_origin_and_fixed_port(self):
        from loopdy_plugin.direct_runtime import DirectSettings
        settings = DirectSettings.from_mapping({"enabled": True, "origin": "https://fixture.tail.example", "port": 8789})
        self.assertTrue(settings.enabled)
        self.assertEqual(settings.origin, "https://fixture.tail.example")
        self.assertEqual(settings.port, 8789)
        for values in ({"enabled": True}, {"enabled": True, "origin": "http://fixture", "port": 8789},
                       {"enabled": True, "origin": "https://user:password@fixture", "port": 8789},
                       {"enabled": True, "origin": "https://fixture", "port": 0}):
            with self.assertRaises(ValueError):
                DirectSettings.from_mapping(values)
