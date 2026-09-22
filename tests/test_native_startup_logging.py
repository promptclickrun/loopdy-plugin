"""Deterministic startup/context parity; no host configuration or service I/O."""
from __future__ import annotations

from contextlib import ExitStack
import sys
from types import ModuleType, SimpleNamespace
from typing import Any
import unittest
from unittest.mock import Mock, patch

from fastapi import Request

from loopdy_plugin import native_context, registration


LOG = "hermes.plugins.loopdy"
SUMMARY = "Loopdy native features advertised at startup: "
PROCESS_FEATURES = (
    "native-context-v1", "serving-profile-v1", "native-card-templates-v1",
    "native-voice-v1", "native-device-tools-v1", "native-room-activity-v1",
    "native-project-git-read-v1", "native-agent-templates-v1",
    "native-workspace-files-v1",
)
WIKI_FEATURES = ("native-wiki-v1", "native-wiki-disconnect-v1")


class Session(SimpleNamespace):
    pass


def module(name, **attributes) -> Any:
    value = ModuleType(name)
    value.__dict__.update(attributes)
    return value


class NativeStartupLoggingTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.constants = module(
            "hermes_constants",
            get_process_hermes_home=Mock(return_value="synthetic-home"),
            profile_name_for_home=Mock(return_value="research"),
            set_hermes_home_override=Mock(), reset_hermes_home_override=Mock(),
        )
        self.profiles = module("hermes_cli.profiles", profile_exists=Mock(return_value=True))
        self.hub = SimpleNamespace(available=True)
        self.device = module("loopdy_plugin.native_device_tools", CAPABILITY=PROCESS_FEATURES[4],
                             available=Mock(return_value=True), register_middleware=Mock(return_value=True))
        self.room = module("loopdy_plugin.room_activity", CAPABILITY=PROCESS_FEATURES[5],
                           activity_hub=Mock(return_value=self.hub), register_room_activity=Mock())
        self.git = module("loopdy_plugin.native_project_git", CAPABILITY=PROCESS_FEATURES[6],
                          supported=Mock(return_value=True))
        self.templates = module("loopdy_plugin.agent_templates", CAPABILITY=PROCESS_FEATURES[7],
                                available=Mock(return_value=True))
        self.files = module("loopdy_plugin.workspace_artifacts", CAPABILITY=PROCESS_FEATURES[8],
                            available=Mock(return_value=True))
        self.wiki = module("loopdy_plugin.wiki_contract", available_wiki_operations=Mock(return_value=True))
        modules = [self.constants, self.profiles, self.device, self.room, self.git,
                   self.templates, self.files, self.wiki,
                   module("hermes_cli.dashboard_auth.base", Session=Session)]
        self.stack.enter_context(patch.dict(sys.modules, {value.__name__: value for value in modules}))
        self.stack.enter_context(patch.object(native_context, "_startup_advertisement_logged", False))
        self.stack.enter_context(patch.object(native_context.time, "time", return_value=1000))

    def request(self, *, principal=False):
        session = Session(provider="fixture", user_id="alice", display_name="Alice", expires_at=2000)
        return Request({
            "type": "http", "path": "/api/plugins/loopdy/native/context", "headers": [],
            "state": {"session": session if principal else None, "token_authenticated": False},
            "app": SimpleNamespace(state=SimpleNamespace(auth_required=principal)),
        })

    def logged_features(self, records):
        summaries = [record.getMessage()[len(SUMMARY):] for record in records
                     if record.getMessage().startswith(SUMMARY)]
        self.assertEqual(len(summaries), 1)
        return tuple(summaries[0].split(", "))

    def assert_warning(self, records, feature):
        self.assertTrue(any(record.levelname == "WARNING" and feature in record.getMessage()
                            and "NOT advertised" in record.getMessage() for record in records), feature)

    def test_complete_process_inventory_matches_context_in_order(self):
        with self.assertLogs(LOG, level="INFO") as logs:
            native_context.log_native_feature_startup("research")
        context = native_context.native_context(self.request())
        self.assertEqual(self.logged_features(logs.records), PROCESS_FEATURES)
        self.assertEqual(context.features, PROCESS_FEATURES)
        self.assertEqual(context.serving_profile_id, "research")
        self.device.available.assert_called_with("research")
        self.wiki.available_wiki_operations.assert_not_called()

    def test_unavailable_capabilities_are_omitted_and_each_is_warned(self):
        self.profiles.profile_exists = None
        self.device.available.return_value = False
        self.hub.available = False
        self.git.supported.return_value = False
        self.templates.available.return_value = False
        self.files.available.return_value = False
        with self.assertLogs(LOG, level="INFO") as logs:
            native_context.log_native_feature_startup("research")
        expected = PROCESS_FEATURES[:2]
        self.assertEqual(self.logged_features(logs.records), expected)
        self.assertEqual(native_context.native_context(self.request()).features, expected)
        for feature in PROCESS_FEATURES[2:]:
            self.assert_warning(logs.records, feature)

    def test_optional_import_failures_match_context_and_warn(self):
        missing = {
            "hermes_cli.profiles": ("native-card-templates-v1", "native-voice-v1"),
            "loopdy_plugin.native_device_tools": ("native-device-tools-v1",),
            "loopdy_plugin.agent_templates": ("native-agent-templates-v1",),
            "loopdy_plugin.workspace_artifacts": ("native-workspace-files-v1",),
        }
        for name, omitted in missing.items():
            with self.subTest(module=name), patch.dict(sys.modules, {name: None}), \
                    patch.object(native_context, "_startup_advertisement_logged", False):
                with self.assertLogs(LOG, level="INFO") as logs:
                    native_context.log_native_feature_startup("research")
                expected = tuple(feature for feature in PROCESS_FEATURES if feature not in omitted)
                self.assertEqual(self.logged_features(logs.records), expected)
                self.assertEqual(native_context.native_context(self.request()).features, expected)
                for feature in omitted:
                    self.assert_warning(logs.records, feature)

    def test_missing_profile_resolver_does_not_claim_serving_profile(self):
        del self.constants.profile_name_for_home
        with self.assertLogs(LOG, level="INFO") as logs:
            native_context.log_native_feature_startup("research")
        context = native_context.native_context(self.request())
        expected = tuple(feature for feature in PROCESS_FEATURES
                         if feature not in ("serving-profile-v1", "native-device-tools-v1"))
        self.assertEqual(self.logged_features(logs.records), expected)
        self.assertEqual(context.features, expected)
        self.assertIsNone(context.serving_profile_id)
        self.assert_warning(logs.records, "serving-profile-v1")
        self.device.available.assert_not_called()

    def test_unresolved_profile_does_not_use_registration_profile(self):
        self.constants.profile_name_for_home.return_value = None
        with self.assertLogs(LOG, level="INFO") as logs:
            native_context.log_native_feature_startup("research")
        context = native_context.native_context(self.request())
        self.assertEqual(self.logged_features(logs.records), context.features)
        self.assertNotIn("serving-profile-v1", context.features)
        self.assertNotIn("native-device-tools-v1", context.features)
        self.assert_warning(logs.records, "serving-profile-v1")
        self.device.available.assert_not_called()

    def test_registration_profile_mismatch_uses_verified_process_profile(self):
        self.device.available.side_effect = lambda profile: profile == "personal"
        with self.assertLogs(LOG, level="INFO") as logs:
            native_context.log_native_feature_startup("personal")
        context = native_context.native_context(self.request())
        self.assertEqual(self.logged_features(logs.records), context.features)
        self.assertNotIn("native-device-tools-v1", context.features)
        self.assertEqual(context.serving_profile_id, "research")
        self.assertTrue(all(call.args == ("research",) for call in self.device.available.call_args_list))
        self.assert_warning(logs.records, "native-device-tools-v1")
        self.assertIn("Restart `hermes serve`", " ".join(logs.output))

    def test_invalid_serving_profile_keeps_api_error_and_no_success_inventory(self):
        for profile in ("Bad Profile", "", 7):
            with self.subTest(profile=profile), patch.object(
                    native_context, "_startup_advertisement_logged", False):
                self.constants.profile_name_for_home.return_value = profile
                with self.assertLogs(LOG, level="WARNING") as logs:
                    native_context.log_native_feature_startup("research")
                self.assertFalse(any(record.getMessage().startswith(SUMMARY) for record in logs.records))
                self.assertIn("native_context_unavailable", " ".join(logs.output))
                with self.assertRaises(native_context.NativeAPIError) as error:
                    native_context.native_context(self.request())
                self.assertEqual((error.exception.status, error.exception.code),
                                 (503, "native_context_unavailable"))

    def test_wiki_is_named_as_request_dependent_and_preserves_api_order(self):
        with self.assertLogs(LOG, level="INFO") as logs:
            native_context.log_native_feature_startup("research")
        self.assertEqual(self.logged_features(logs.records), PROCESS_FEATURES)
        self.wiki.available_wiki_operations.assert_not_called()
        notes = " ".join(record.getMessage() for record in logs.records
                         if "request-dependent" in record.getMessage())
        for feature in WIKI_FEATURES:
            self.assertIn(feature, notes)
        self.assertEqual(native_context.native_context(self.request(principal=True)).features,
                         PROCESS_FEATURES[:6] + WIKI_FEATURES + PROCESS_FEATURES[6:])
        self.wiki.available_wiki_operations.return_value = False
        self.assertEqual(native_context.native_context(self.request(principal=True)).features, PROCESS_FEATURES)
        self.profiles.profile_exists = None
        self.wiki.available_wiki_operations.reset_mock()
        native_context.native_context(self.request(principal=True))
        self.wiki.available_wiki_operations.assert_not_called()

    def test_startup_is_logged_once_without_reprobing_and_api_stays_live(self):
        with self.assertLogs(LOG, level="INFO") as logs:
            native_context.log_native_feature_startup("research")
            self.files.available.return_value = False
            native_context.log_native_feature_startup("personal")
        self.assertEqual(self.logged_features(logs.records), PROCESS_FEATURES)
        self.files.available.assert_called_once_with()
        self.assertNotIn("native-workspace-files-v1", native_context.native_context(self.request()).features)

    def test_failed_probe_logs_once_without_leaking_details_or_changing_api_error(self):
        self.constants.profile_name_for_home.side_effect = RuntimeError("private-fixture-detail")
        with self.assertLogs(LOG, level="INFO") as logs:
            native_context.log_native_feature_startup("research")
            native_context.log_native_feature_startup("research")
        self.constants.profile_name_for_home.assert_called_once_with("synthetic-home")
        warnings = [record for record in logs.records if record.levelname == "WARNING"]
        self.assertEqual(len(warnings), 1)
        self.assertIn("RuntimeError", warnings[0].getMessage())
        self.assertNotIn("private-fixture-detail", " ".join(logs.output))
        self.assertFalse(any(record.getMessage().startswith(SUMMARY) for record in logs.records))
        with self.assertRaisesRegex(RuntimeError, "private-fixture-detail"):
            native_context.native_context(self.request())

    def test_identity_gate_still_precedes_capability_probes(self):
        request = self.request(principal=True)
        for session, code in ((None, "native_identity_required"),
                              (Session(provider="fixture", user_id="alice", display_name="Alice",
                                       expires_at=0), "native_identity_invalid")):
            with self.subTest(code=code):
                request.state.session = session
                with self.assertRaises(native_context.NativeAPIError) as error:
                    native_context.native_context(request)
                self.assertEqual((error.exception.status, error.exception.code), (401, code))
        self.constants.get_process_hermes_home.assert_not_called()
        self.device.available.assert_not_called()

    def test_registration_logs_after_room_registration_without_promising_device_advertisement(self):
        self.hub.available = False
        self.device.available.return_value = False  # callback accepted, no lifecycle ownership

        def register_room(ctx):
            self.hub.available = True
            return Mock()

        self.room.register_room_activity.side_effect = register_room
        managed = Mock()
        self.stack.enter_context(patch.dict(sys.modules, {
            "loopdy_plugin.managed_notifications": module(
                "loopdy_plugin.managed_notifications", get_managed_notifications=lambda: managed),
            "hermes_cli.plugins": module("hermes_cli.plugins", VALID_HOOKS=set()),
            "loopdy_plugin.direct_runtime": module("loopdy_plugin.direct_runtime", DirectSettings=Mock()),
        }))
        for name in ("production_manager", "DeviceToolBridge", "register_tools", "register_device_tools",
                     "register_marketplace_publish_skill", "LoopdyApprovalTransport", "profile_display_name",
                     "_home_target"):
            self.stack.enter_context(patch.object(registration, name))
        self.stack.enter_context(patch.object(registration, "_device_tools_supported", return_value=False))
        ctx = Mock(profile_name="research", state=None)
        with self.assertLogs(LOG, level="INFO") as logs:
            registration.register(ctx, service=SimpleNamespace(store=object()), activity_broker=Mock(),
                                  attachment_store=object(), marketplace_gateway_client=object())
        self.room.register_room_activity.assert_called_once_with(ctx)
        self.device.register_middleware.assert_called_once_with(ctx)
        self.assertEqual(self.logged_features(logs.records),
                         tuple(feature for feature in PROCESS_FEATURES if feature != "native-device-tools-v1"))
        self.assertNotIn("will be advertised", " ".join(logs.output))
        self.assert_warning(logs.records, "native-device-tools-v1")


if __name__ == "__main__":
    unittest.main()
