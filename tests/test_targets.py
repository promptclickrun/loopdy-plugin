from __future__ import annotations

import unittest

from loopdy_plugin.targets import parse_target, validate_target


class TargetTests(unittest.TestCase):
    def test_accepts_only_explicit_loopdy_targets(self) -> None:
        self.assertEqual(parse_target("all"), ("all", None))
        self.assertEqual(parse_target("device:phone_123"), ("device:phone_123", None))
        self.assertEqual(parse_target("group:on-call"), ("group:on-call", None))
        self.assertIsNone(parse_target("phone_123"))
        self.assertIsNone(parse_target("device:../../secrets"))
        self.assertIs(validate_target("device:phone_123"), True)
        self.assertIsInstance(validate_target("unknown"), str)


if __name__ == "__main__":
    unittest.main()
