from __future__ import annotations

import asyncio
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from loopdy_plugin.workspace_control import WorkspaceConflictError, WorkspaceControlError


class _VoiceBackend:
    def __init__(self, configs: dict[str, dict], key_status: dict[str, dict]) -> None:
        self.configs = copy.deepcopy(configs)
        self.key_status = copy.deepcopy(key_status)
        self.saved: list[tuple[str, dict]] = []

    async def _profile_config(self, agent_id: str) -> dict:
        return copy.deepcopy(self.configs[agent_id])

    async def _voice_settings_key_status(self, agent_id: str) -> dict:
        return copy.deepcopy(self.key_status[agent_id])

    async def _save_profile_config(self, agent_id: str, config: dict) -> None:
        self.saved.append((agent_id, copy.deepcopy(config)))
        self.configs[agent_id] = _merge(self.configs[agent_id], config)


def _merge(existing: dict, incoming: dict) -> dict:
    merged = copy.deepcopy(existing)
    for key, value in incoming.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _backend() -> _VoiceBackend:
    return _VoiceBackend(
        {
            "default": {
                "tts": {
                    "provider": "edge",
                    "edge": {"voice": "en-US-AriaNeural"},
                    "openai": {"voice": "alloy"},
                    "elevenlabs": {"voice_id": "pNInz6obpgDQGcFmaJgB"},
                }
            },
            "research": {
                "tts": {
                    "provider": "openai",
                    "openai": {"voice": "ash"},
                    "elevenlabs": {"voice_id": "research-voice"},
                }
            },
        },
        {
            "default": {
                "openai": False,
                "elevenlabs": False,
                "revision": {"mtimeNs": 1, "size": 2},
            },
            "research": {
                "openai": True,
                "elevenlabs": True,
                "revision": {"mtimeNs": 3, "size": 4},
            },
        },
    )


def _voice_functions():
    try:
        from loopdy_plugin.voice_settings import get_voice_settings, set_voice_settings
    except ModuleNotFoundError as exc:
        raise AssertionError("voice_settings bridge is not implemented") from exc
    return get_voice_settings, set_voice_settings


class VoiceSettingsTests(unittest.TestCase):
    def test_get_returns_current_edge_and_direct_choices_without_secret_material(self) -> None:
        get_voice_settings, _ = _voice_functions()

        result = asyncio.run(get_voice_settings(_backend(), {"agentId": "default"}))

        self.assertEqual(result["agentId"], "default")
        self.assertEqual(result["providerId"], "edge")
        self.assertEqual(
            [(row["providerId"], row["voiceId"]) for row in result["providers"]],
            [
                ("edge", "en-US-AriaNeural"),
                ("openai", "alloy"),
                ("elevenlabs", "pNInz6obpgDQGcFmaJgB"),
            ],
        )
        self.assertNotIn("API_KEY", json.dumps(result))
        self.assertNotIn("secret", json.dumps(result).lower())

    def test_get_preserves_managed_nous_selection_and_effective_openai_voice(self) -> None:
        get_voice_settings, _ = _voice_functions()

        backend = _backend()
        backend.configs["default"]["tts"] = {"provider": "nous", "openai": {}}
        result = asyncio.run(get_voice_settings(backend, {"agentId": "default"}))

        self.assertEqual(result["providerId"], "nous")
        self.assertEqual(result["providers"][0]["providerId"], "nous")
        self.assertEqual(result["providers"][0]["voiceId"], "alloy")
        self.assertEqual(result["providers"][0]["title"], "Nous Subscription")

    def test_set_openai_uses_official_selection_and_credential_writers(self) -> None:
        get_voice_settings, set_voice_settings = _voice_functions()

        backend = _backend()
        before = asyncio.run(get_voice_settings(backend, {"agentId": "default"}))
        persisted: dict[str, str] = {}

        @contextmanager
        def profile_scope(_profile: str):
            yield

        def save_credential(env_var: str, value: str) -> dict:
            persisted[env_var] = value
            return {"ok": True, "key": env_var}

        with (
            patch("loopdy_plugin.voice_settings.apply_provider_selection") as select,
            patch("loopdy_plugin.voice_settings.save_provider_env_credential", side_effect=save_credential) as save_key,
            patch("hermes_cli.web_server_profiles._profile_scope", profile_scope),
            patch("hermes_cli.config.load_env", side_effect=lambda: dict(persisted)),
        ):
            select.side_effect = lambda _name, _row, config: config.setdefault("tts", {}).update({"provider": "openai"})
            result = asyncio.run(set_voice_settings(backend, {
                "agentId": "default",
                "expectedRevision": before["revision"],
                "providerId": "openai",
                "voiceId": "ash",
                "apiKey": "replacement-secret",
                "confirmed": True,
            }))

        select.assert_called_once()
        self.assertEqual(select.call_args.args[:2], ("tts", "OpenAI TTS"))
        save_key.assert_called_once_with("VOICE_TOOLS_OPENAI_KEY", "replacement-secret")
        self.assertEqual(result["providerId"], "openai")
        self.assertEqual(result["providers"][0]["providerId"], "openai")
        self.assertNotIn("replacement-secret", json.dumps(result))
        self.assertEqual(backend.configs["default"]["tts"]["openai"]["voice"], "ash")
        self.assertEqual(backend.configs["default"]["tts"]["openai"]["api_key"], "")

    def test_credential_writer_noop_is_rejected_without_config_write(self) -> None:
        get_voice_settings, set_voice_settings = _voice_functions()
        backend = _backend()
        before = asyncio.run(get_voice_settings(backend, {"agentId": "default"}))

        @contextmanager
        def profile_scope(_profile: str):
            yield

        with (
            patch("loopdy_plugin.voice_settings.apply_provider_selection") as select,
            patch("loopdy_plugin.voice_settings.save_provider_env_credential", return_value={"ok": True}),
            patch("hermes_cli.web_server_profiles._profile_scope", profile_scope),
            patch("hermes_cli.config.load_env", return_value={}),
        ):
            select.side_effect = lambda _name, _row, config: config.setdefault("tts", {}).update({"provider": "openai"})
            with self.assertRaises(WorkspaceControlError) as raised:
                asyncio.run(set_voice_settings(backend, {
                    "agentId": "default",
                    "expectedRevision": before["revision"],
                    "providerId": "openai",
                    "voiceId": "ash",
                    "apiKey": "must-not-leak",
                    "confirmed": True,
                }))

        self.assertNotIn("must-not-leak", str(raised.exception))
        self.assertEqual(backend.saved, [])

    def test_selection_writer_runs_in_selected_profile_and_worker(self) -> None:
        get_voice_settings, set_voice_settings = _voice_functions()
        backend = _backend()
        before = asyncio.run(get_voice_settings(backend, {"agentId": "research"}))
        marker = __import__("contextvars").ContextVar("voice_scope_marker", default=False)
        observations: list[tuple[bool, str]] = []

        @contextmanager
        def scoped(profile: str):
            token = marker.set(profile == "research")
            try:
                yield
            finally:
                marker.reset(token)

        def select(_name: str, _row: str, config: dict) -> None:
            observations.append((marker.get(), __import__("threading").current_thread().name))
            config.setdefault("tts", {}).update({"provider": "openai"})

        with patch("hermes_cli.web_server_profiles._config_profile_scope", scoped), patch(
            "loopdy_plugin.voice_settings.apply_provider_selection", side_effect=select
        ):
            asyncio.run(set_voice_settings(backend, {
                "agentId": "research",
                "expectedRevision": before["revision"],
                "providerId": "openai",
                "voiceId": "sage",
                "confirmed": True,
            }))

        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0][0], True)
        self.assertNotEqual(observations[0][1], "MainThread")

    def test_omitted_or_blank_key_preserves_existing_credential(self) -> None:
        get_voice_settings, set_voice_settings = _voice_functions()

        backend = _backend()
        backend.configs["default"]["tts"]["openai"]["api_key"] = "inline-secret"
        before = asyncio.run(get_voice_settings(backend, {"agentId": "default"}))
        with patch("loopdy_plugin.voice_settings.apply_provider_selection") as select, patch(
            "loopdy_plugin.voice_settings.save_provider_env_credential"
        ) as save_key:
            select.side_effect = lambda _name, _row, config: config.setdefault("tts", {}).update({"provider": "openai"})
            result = asyncio.run(set_voice_settings(backend, {
                "agentId": "default",
                "expectedRevision": before["revision"],
                "providerId": "openai",
                "voiceId": "coral",
                "apiKey": "",
                "confirmed": True,
            }))

        save_key.assert_not_called()
        self.assertEqual(result["providers"][0]["voiceId"], "coral")
        self.assertEqual(backend.configs["default"]["tts"]["openai"]["api_key"], "inline-secret")

    def test_stale_revision_is_rejected_before_any_write(self) -> None:
        _, set_voice_settings = _voice_functions()

        backend = _backend()
        with self.assertRaises(WorkspaceConflictError):
            asyncio.run(set_voice_settings(backend, {
                "agentId": "default",
                "expectedRevision": "0" * 64,
                "providerId": "openai",
                "voiceId": "alloy",
                "confirmed": True,
            }))
        self.assertEqual(backend.saved, [])

    def test_key_rotation_changes_revision_even_when_presence_stays_true(self) -> None:
        get_voice_settings, _ = _voice_functions()

        backend = _backend()
        backend.key_status["default"]["openai"] = True
        first = asyncio.run(get_voice_settings(backend, {"agentId": "default"}))
        backend.key_status["default"]["revision"] = {"mtimeNs": 9, "size": 2}
        second = asyncio.run(get_voice_settings(backend, {"agentId": "default"}))
        self.assertNotEqual(first["revision"], second["revision"])

    def test_inline_config_rotation_changes_revision_even_when_key_presence_stays_true(self) -> None:
        get_voice_settings, _ = _voice_functions()

        backend = _backend()
        backend.key_status["default"]["openai"] = True
        backend.key_status["default"]["configRevision"] = {"mtimeNs": 11, "size": 22}
        first = asyncio.run(get_voice_settings(backend, {"agentId": "default"}))
        backend.key_status["default"]["configRevision"] = {"mtimeNs": 12, "size": 22}
        second = asyncio.run(get_voice_settings(backend, {"agentId": "default"}))
        self.assertNotEqual(first["revision"], second["revision"])

    def test_unchanged_save_is_a_noop(self) -> None:
        from loopdy_plugin.voice_settings import get_voice_settings, set_voice_settings

        backend = _backend()
        backend.configs["default"]["tts"]["provider"] = "openai"
        before = asyncio.run(get_voice_settings(backend, {"agentId": "default"}))
        with patch("loopdy_plugin.voice_settings.apply_provider_selection") as select, patch(
            "loopdy_plugin.voice_settings.save_provider_env_credential"
        ) as save_key:
            result = asyncio.run(set_voice_settings(backend, {
                "agentId": "default",
                "expectedRevision": before["revision"],
                "providerId": "openai",
                "voiceId": "alloy",
                "confirmed": True,
            }))

        self.assertEqual(result, before)
        select.assert_not_called()
        save_key.assert_not_called()
        self.assertEqual(backend.saved, [])

    def test_profile_selection_and_writes_are_isolated(self) -> None:
        get_voice_settings, set_voice_settings = _voice_functions()

        backend = _backend()
        research = asyncio.run(get_voice_settings(backend, {"agentId": "research"}))
        with patch("hermes_cli.web_server_profiles._config_profile_scope"), patch(
            "loopdy_plugin.voice_settings.apply_provider_selection"
        ) as select:
            select.side_effect = lambda _name, _row, config: config.setdefault("tts", {}).update({"provider": "elevenlabs"})
            asyncio.run(set_voice_settings(backend, {
                "agentId": "research",
                "expectedRevision": research["revision"],
                "providerId": "elevenlabs",
                "voiceId": "new-research-voice",
                "confirmed": True,
            }))
        self.assertEqual(backend.configs["research"]["tts"]["elevenlabs"]["voice_id"], "new-research-voice")
        self.assertEqual(backend.configs["default"]["tts"]["provider"], "edge")
        self.assertEqual(backend.saved[-1][0], "research")

    def test_malformed_and_unsupported_updates_are_rejected(self) -> None:
        _, set_voice_settings = _voice_functions()

        backend = _backend()
        cases = [
            {"agentId": "default", "expectedRevision": "0" * 64, "providerId": "openai", "voiceId": "alloy"},
            {"agentId": "default", "expectedRevision": "0" * 64, "providerId": "edge", "voiceId": "x", "confirmed": True},
            {"agentId": "default", "expectedRevision": "0" * 64, "providerId": "openai", "voiceId": "", "confirmed": True},
        ]
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(WorkspaceControlError):
                asyncio.run(set_voice_settings(backend, payload))

    def test_saved_choice_is_consumed_by_hermes_config_and_selection_readers(self) -> None:
        import hermes_constants

        source_root = Path(__file__).resolve().parents[1]
        hermes_root = Path(hermes_constants.__file__).resolve().parent
        script = textwrap.dedent(
            """
            import asyncio
            import json
            import os
            from contextlib import contextmanager
            from pathlib import Path
            from types import SimpleNamespace
            from unittest.mock import patch

            from hermes_cli import credential_lifecycle
            from hermes_cli.config import get_config_path, get_env_path, load_config, save_config
            from hermes_cli.web_server_profiles import (
                _config_profile_scope,
                _hermes_home_scope,
                _resolve_profile_dir,
            )
            from loopdy_plugin.voice_settings import get_voice_settings, set_voice_settings
            from loopdy_plugin.workspace_control import HermesWorkspaceBackend
            import hermes_cli.tools_config as tools_config
            from tools import tts_tool
            from tools.tool_backend_helpers import read_selection

            home = Path(os.environ["HERMES_HOME"]).resolve()
            research_home = home / "profiles" / "research"
            research_home.mkdir(parents=True)
            with _hermes_home_scope(home):
                save_config({"tts": {"provider": "edge", "edge": {"voice": "old-default"}}}, strip_defaults=False)
            with _hermes_home_scope(research_home):
                save_config({"tts": {"provider": "edge", "edge": {"voice": "old-research"}}}, strip_defaults=False)
            (home / ".env").write_text("# default profile\\n", encoding="utf-8")
            (research_home / ".env").write_text("VOICE_TOOLS_OPENAI_KEY=research-existing\\n", encoding="utf-8")

            class RealBackend(HermesWorkspaceBackend):
                pass

            backend = RealBackend(service=object())

            async def config_request(method, params, *, unavailable_message, request_id=None):
                assert method == "config.get"
                with _config_profile_scope(params["profile"]):
                    return {"config": load_config()}

            backend._hermes_request = config_request
            paths: list[Path] = []
            original_config_path = get_config_path
            original_env_path = get_env_path
            original_resolve_profile = _resolve_profile_dir

            def inside(path: Path) -> Path:
                resolved = Path(path).resolve()
                assert resolved == home or home in resolved.parents
                paths.append(resolved)
                return resolved

            def checked_config_path():
                return inside(original_config_path())

            def checked_env_path():
                return inside(original_env_path())

            def checked_profile_dir(profile):
                return inside(original_resolve_profile(profile))

            with patch("hermes_cli.config.get_config_path", side_effect=checked_config_path), \\
                 patch("hermes_cli.config.get_env_path", side_effect=checked_env_path), \\
                 patch("hermes_cli.web_server_profiles._resolve_profile_dir", side_effect=checked_profile_dir), \\
                 patch.object(tools_config, "get_nous_subscription_features", return_value=SimpleNamespace(account_info=None, nous_auth_present=False)), \\
                 patch.object(credential_lifecycle, "_providers_for_env_var", return_value=[]):
                default_before = asyncio.run(backend.voice_settings_get({"agentId": "default"}))
                default_result = asyncio.run(backend.voice_settings_set({
                    "agentId": "default",
                    "expectedRevision": default_before["revision"],
                    "providerId": "openai",
                    "voiceId": "nova",
                    "apiKey": "default-secret",
                    "confirmed": True,
                }))
                research_before = asyncio.run(backend.voice_settings_get({"agentId": "research"}))
                research_config_before = load_config()
                with _config_profile_scope("research"):
                    research_config_before = load_config()
                research_env_before = (research_home / ".env").read_text(encoding="utf-8")
                research_result = asyncio.run(backend.voice_settings_set({
                    "agentId": "research",
                    "expectedRevision": research_before["revision"],
                    "providerId": "elevenlabs",
                    "voiceId": "research-voice",
                    "apiKey": "research-secret",
                    "confirmed": True,
                }))

            assert default_result["providerId"] == "openai"
            assert default_result["providers"][0]["apiKeyConfigured"] is True
            assert research_result["providerId"] == "elevenlabs"
            assert research_result["providers"][0]["apiKeyConfigured"] is True
            assert "default-secret" not in json.dumps(default_result)
            assert "research-secret" not in json.dumps(research_result)
            with _config_profile_scope("default"):
                default_config = load_config()
                assert read_selection("tts") == "openai"
                assert tts_tool._load_tts_config()["openai"]["voice"] == "nova"
            with _config_profile_scope("research"):
                saved_research_config = load_config()
                assert read_selection("tts") == "elevenlabs"
                assert tts_tool._load_tts_config()["elevenlabs"]["voice_id"] == "research-voice"
            assert default_config["tts"]["provider"] == "openai"
            assert default_config["tts"]["openai"]["voice"] == "nova"
            assert saved_research_config["tts"]["provider"] == "elevenlabs"
            assert saved_research_config["tts"]["elevenlabs"]["voice_id"] == "research-voice"
            assert (home / ".env").read_text(encoding="utf-8").find("VOICE_TOOLS_OPENAI_KEY=default-secret") >= 0
            assert (research_home / ".env").read_text(encoding="utf-8").find("VOICE_TOOLS_OPENAI_KEY=research-existing") >= 0
            assert (research_home / ".env").read_text(encoding="utf-8").find("ELEVENLABS_API_KEY=research-secret") >= 0
            assert research_config_before["tts"]["edge"]["voice"] == "old-research"
            assert research_env_before == "VOICE_TOOLS_OPENAI_KEY=research-existing\\n"
            assert paths and all(path == home or home in path.parents for path in paths)
            print("ok")
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            env = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(home),
                "HERMES_HOME": str(home),
                "PYTHONPATH": os.pathsep.join((str(hermes_root), str(source_root))),
                "PYTHONUNBUFFERED": "1",
            }
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=source_root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout.strip(), "ok")


if __name__ == "__main__":
    unittest.main()
