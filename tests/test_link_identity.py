from __future__ import annotations

import os
import unittest


class _State:
    def __init__(self):
        self.values = {}

    def get(self, key, default=None):
        return self.values.get(key, default)

    def set(self, key, value):
        self.values[key] = value


class LinkIdentityTests(unittest.TestCase):
    def test_verified_device_actor_context_is_bounded_and_interactive_only(self) -> None:
        from loopdy_plugin.link_identity import LinkIdentityRegistry

        registry = LinkIdentityRegistry(_State(), account_key=os.urandom(32))
        coordinate = registry.remember(
            sender_device_id="mobile-device-secret-coordinate",
            actor_id="actor-secret-coordinate",
            actor_name="Alex",
            device_name="Kitchen iPad",
        )

        context = registry.pre_llm_context(platform="loopdy", sender_id=coordinate)
        self.assertIn("Alex", context["context"])
        self.assertIn("Kitchen iPad", context["context"])
        self.assertIn("identity data only", context["context"])
        self.assertNotIn("mobile-device-secret-coordinate", context["context"])
        self.assertNotIn("actor-secret-coordinate", context["context"])
        self.assertIsNone(registry.pre_llm_context(platform="cron", sender_id=coordinate))
        self.assertIsNone(registry.pre_llm_context(platform="loopdy", sender_id="unknown"))


if __name__ == "__main__":
    unittest.main()
