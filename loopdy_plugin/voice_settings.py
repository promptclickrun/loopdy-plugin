"""Profile-scoped Hermes TTS settings exposed through the bounded workspace bridge."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
from typing import Any

from .workspace_control import WorkspaceConflictError, WorkspaceControlError


_AGENT_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_REVISION = re.compile(r"^[0-9a-f]{64}$")
_SELECTION_ROWS = {"openai": "OpenAI TTS", "elevenlabs": "ElevenLabs"}
_TITLES = {
    "edge": "Microsoft Edge TTS",
    "nous": "Nous Subscription",
    "openai": "OpenAI TTS",
    "elevenlabs": "ElevenLabs",
}
_DEFAULT_VOICES = {
    "edge": "en-US-AriaNeural",
    "openai": "alloy",
    # Hermes stores the managed Nous subscription as provider="nous", but its
    # speech path uses the same OpenAI voice section and default.
    "nous": "alloy",
    "elevenlabs": "pNInz6obpgDQGcFmaJgB",
}


def apply_provider_selection(toolset: str, provider_name: str, config: dict) -> None:
    """Late-bind Hermes' canonical provider selector so tests can pin the seam."""
    from hermes_cli.tools_config_providers import apply_provider_selection as writer

    writer(toolset, provider_name, config)


def save_provider_env_credential(env_var: str, value: str) -> dict[str, Any]:
    """Late-bind Hermes' credential lifecycle writer so the key never enters this module's state."""
    from hermes_cli.credential_lifecycle import save_provider_env_credential as writer

    return writer(env_var, value)


def _agent_id(value: Any) -> str:
    if not isinstance(value, str) or not _AGENT_ID.fullmatch(value):
        raise WorkspaceControlError("Voice settings agent is invalid", code="voice_settings_invalid")
    return value


def _text(value: Any, *, name: str, maximum: int, required: bool = True) -> str:
    if not isinstance(value, str):
        raise WorkspaceControlError("Voice settings request is invalid", code="voice_settings_invalid")
    value = value.strip()
    if required and not value:
        raise WorkspaceControlError(f"Voice settings {name} is required", code="voice_settings_invalid")
    if len(value) > maximum or any(ord(character) < 32 for character in value):
        raise WorkspaceControlError("Voice settings request is invalid", code="voice_settings_invalid")
    return value


def _payload(payload: Any, *, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(payload, dict) or not set(payload).issubset(allowed):
        raise WorkspaceControlError("Voice settings request is invalid", code="voice_settings_invalid")
    return payload


async def profile_key_status(agent_id: str) -> dict[str, Any]:
    """Return only configured flags and non-secret profile file revisions."""
    def read() -> dict[str, Any]:
        from hermes_cli.config import get_config_path, get_env_path, load_env
        from hermes_cli.web_server_profiles import _config_profile_scope

        def stat_revision(path) -> dict[str, int]:
            try:
                stat = path.stat()
                return {"mtimeNs": int(stat.st_mtime_ns), "size": int(stat.st_size)}
            except OSError:
                return {"mtimeNs": 0, "size": 0}

        with _config_profile_scope(agent_id):
            env = load_env()
            env_revision = stat_revision(get_env_path())
            config_revision = stat_revision(get_config_path())
        return {
            "openai": bool(env.get("VOICE_TOOLS_OPENAI_KEY") or env.get("OPENAI_API_KEY")),
            "elevenlabs": bool(env.get("ELEVENLABS_API_KEY")),
            "revision": env_revision,
            "configRevision": config_revision,
        }

    return await asyncio.to_thread(read)


def _section(value: Any, name: str) -> dict[str, Any]:
    section = value.get(name) if isinstance(value, dict) else None
    return section if isinstance(section, dict) else {}


def _provider_id(config: dict[str, Any]) -> str:
    tts = _section(config, "tts")
    provider = str(tts.get("provider") or "edge").strip().lower()
    return provider if _AGENT_ID.fullmatch(provider) else "edge"


def _voice_id(tts: dict[str, Any], provider: str) -> str:
    if provider == "edge":
        value = _section(tts, "edge").get("voice")
    elif provider in {"openai", "nous"}:
        value = _section(tts, "openai").get("voice")
    elif provider == "elevenlabs":
        value = _section(tts, "elevenlabs").get("voice_id")
    else:
        section = _section(tts, provider)
        value = section.get("voice_id") or section.get("voice")
    voice = str(value or _DEFAULT_VOICES.get(provider, "")).strip()
    return voice[:160] if voice and not any(ord(character) < 32 for character in voice) else ""


def _key_configured(tts: dict[str, Any], provider: str, key_status: dict[str, Any]) -> bool:
    if provider == "openai":
        return bool(_section(tts, "openai").get("api_key") or key_status.get("openai"))
    if provider == "elevenlabs":
        return bool(key_status.get("elevenlabs"))
    return False


def _revision(
    agent_id: str,
    provider: str,
    providers: list[dict[str, Any]],
    env_revision: dict[str, Any],
    config_revision: dict[str, Any],
) -> str:
    value = {
        "agentId": agent_id,
        "providerId": provider,
        "providers": [
            {
                "providerId": item["providerId"],
                "voiceId": item["voiceId"],
                "apiKeyConfigured": item["apiKeyConfigured"],
            }
            for item in providers
        ],
        "envRevision": {
            "mtimeNs": int(env_revision.get("mtimeNs", 0)),
            "size": int(env_revision.get("size", 0)),
        },
        "configRevision": {
            "mtimeNs": int(config_revision.get("mtimeNs", 0)),
            "size": int(config_revision.get("size", 0)),
        },
    }
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


async def _projection(backend: Any, agent_id: str) -> dict[str, Any]:
    try:
        config = await backend._profile_config(agent_id)
        key_status = await backend._voice_settings_key_status(agent_id)
        tts = _section(config, "tts")
        current_provider = _provider_id(config)
        provider_ids = [current_provider, "openai", "elevenlabs"]
        providers: list[dict[str, Any]] = []
        for provider in provider_ids:
            if provider in {item["providerId"] for item in providers}:
                continue
            providers.append({
                "providerId": provider,
                "title": _TITLES.get(provider, provider),
                "voiceId": _voice_id(tts, provider),
                "apiKeyConfigured": _key_configured(tts, provider, key_status),
            })
        return {
            "agentId": agent_id,
            "revision": _revision(
                agent_id,
                current_provider,
                providers,
                key_status.get("revision", {}),
                key_status.get("configRevision", {}),
            ),
            "providerId": current_provider,
            "providers": providers,
        }
    except WorkspaceControlError:
        raise
    except Exception as exc:
        raise WorkspaceControlError("Voice settings are unavailable", code="voice_settings_unavailable") from exc


async def get_voice_settings(backend: Any, payload: dict[str, Any]) -> dict[str, Any]:
    values = _payload(payload, allowed={"agentId"})
    if set(values) != {"agentId"}:
        raise WorkspaceControlError("Voice settings request is invalid", code="voice_settings_invalid")
    return await _projection(backend, _agent_id(values["agentId"]))


async def _save_credential(agent_id: str, env_var: str, value: str) -> None:
    def write() -> None:
        from hermes_cli.config import load_env
        from hermes_cli.web_server_profiles import _profile_scope

        with _profile_scope(agent_id):
            save_provider_env_credential(env_var, value)
            persisted = load_env()
            if not isinstance(persisted, dict) or persisted.get(env_var) != value:
                raise WorkspaceControlError(
                    "Hermes did not persist the voice credential",
                    code="voice_settings_unconfirmed",
                )

    await asyncio.to_thread(write)


async def _voice_update_config(
    agent_id: str,
    provider: str,
    voice_id: str,
    replacement_key: str | None,
) -> dict[str, Any]:
    def update() -> dict[str, Any]:
        from hermes_cli.web_server_profiles import _config_profile_scope

        with _config_profile_scope(agent_id):
            selection = {"tts": {}}
            try:
                apply_provider_selection("tts", _SELECTION_ROWS[provider], selection)
            except Exception as exc:
                raise WorkspaceControlError(
                    "Voice provider selection is unavailable", code="voice_settings_unavailable"
                ) from exc
            tts = selection.setdefault("tts", {})
            if provider == "openai":
                tts.setdefault("openai", {})["voice"] = voice_id
                if replacement_key:
                    # Inline config wins over the dedicated voice key in Hermes' resolver.
                    tts["openai"]["api_key"] = ""
            else:
                tts.setdefault("elevenlabs", {})["voice_id"] = voice_id
            return selection

    return await asyncio.to_thread(update)


def _lock_for(backend: Any, agent_id: str) -> asyncio.Lock:
    locks = getattr(backend, "_voice_settings_update_locks", None)
    if locks is None:
        locks = {}
        setattr(backend, "_voice_settings_update_locks", locks)
    return locks.setdefault(agent_id, asyncio.Lock())


async def set_voice_settings(backend: Any, payload: dict[str, Any]) -> dict[str, Any]:
    values = _payload(
        payload,
        allowed={"agentId", "expectedRevision", "providerId", "voiceId", "apiKey", "confirmed"},
    )
    required = {"agentId", "expectedRevision", "providerId", "voiceId", "confirmed"}
    if set(values) - {"apiKey"} != required or values.get("confirmed") is not True:
        raise WorkspaceControlError("Confirm this voice settings change before applying it", code="voice_settings_invalid")
    agent_id = _agent_id(values["agentId"])
    expected = _text(values["expectedRevision"], name="revision", maximum=64).lower()
    if not _REVISION.fullmatch(expected):
        raise WorkspaceControlError("Voice settings revision is invalid", code="voice_settings_invalid")
    provider = _text(values["providerId"], name="provider", maximum=64).lower()
    if provider not in _SELECTION_ROWS:
        raise WorkspaceControlError("This voice provider cannot be configured here", code="voice_settings_unsupported")
    voice_id = _text(values["voiceId"], name="voice", maximum=160)
    replacement = values.get("apiKey")
    if replacement is not None and not isinstance(replacement, str):
        raise WorkspaceControlError("Voice settings request is invalid", code="voice_settings_invalid")
    replacement = replacement.strip() if isinstance(replacement, str) else ""
    if len(replacement) > 4096 or any(ord(character) < 32 for character in replacement):
        raise WorkspaceControlError("Voice settings request is invalid", code="voice_settings_invalid")

    async with _lock_for(backend, agent_id):
        current = await _projection(backend, agent_id)
        if not hmac.compare_digest(expected, current["revision"]):
            raise WorkspaceConflictError("Voice settings changed. Refresh and confirm again.")
        selected = next(item for item in current["providers"] if item["providerId"] == provider)
        if current["providerId"] == provider and selected["voiceId"] == voice_id and not replacement:
            return current
        if replacement:
            env_var = "VOICE_TOOLS_OPENAI_KEY" if provider == "openai" else "ELEVENLABS_API_KEY"
            try:
                await _save_credential(agent_id, env_var, replacement)
            except WorkspaceControlError:
                raise
            except Exception as exc:
                raise WorkspaceControlError("Hermes could not save the voice credential", code="voice_settings_unavailable") from exc
        try:
            config = await _voice_update_config(agent_id, provider, voice_id, replacement or None)
            await backend._save_profile_config(agent_id, config)
        except WorkspaceControlError:
            raise
        except Exception as exc:
            raise WorkspaceControlError("Hermes could not save voice settings", code="voice_settings_unavailable") from exc

        verified = await _projection(backend, agent_id)
        saved = next(item for item in verified["providers"] if item["providerId"] == provider)
        if verified["providerId"] != provider or saved["voiceId"] != voice_id:
            raise WorkspaceControlError(
                "Voice settings readback did not match the requested change",
                code="voice_settings_unconfirmed",
            )
        return verified


__all__ = ["get_voice_settings", "set_voice_settings", "profile_key_status"]
