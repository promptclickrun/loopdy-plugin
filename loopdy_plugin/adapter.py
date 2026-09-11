"""Loopdy Hermes platform adapter for Link chat and notification delivery."""

from __future__ import annotations

import asyncio
import contextvars
import inspect
import json
import logging
import os
import tempfile
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import (
    BasePlatformAdapter,
    EphemeralReply,
    MessageEvent,
    ProcessingOutcome,
    SendResult,
)
from gateway.session import SessionSource, build_session_key
from hermes_constants import get_hermes_home

from .events import EVENT_TYPES, LoopdyEvent, build_event
from .link_client import (
    InboundLinkCommandCatalog,
    InboundLinkDeviceToolResult,
    InboundLinkDeviceToolStatus,
    InboundLinkGenerativeUIFormSubmission,
    InboundLinkPersonalityRequest,
    InboundLinkPickerOpen,
    InboundLinkPickerSelection,
    InboundLinkRelayReady,
    InboundLinkSessionFork,
    InboundLinkTurn,
    InboundLinkVoiceSpeak,
    InboundLinkWorkspaceRequest,
    LoopdyLinkClient,
    load_runtime_config,
)
from .link_contracts import (
    CommandCatalogRequest,
    PickerOpen,
    PickerSelection,
    SessionForkRequest,
    VoiceSpeakRequest,
    WorkspaceRequest,
    _session_coordinate,
    assistant_message,
    choice_picker_payload,
    command_catalog_payload,
    generative_ui_form_result,
    model_picker_payload,
    notification_event,
    picker_result,
    personality_catalog_payload,
    session_context,
    session_fork_result,
    verified_fork_prefix,
    voice_audio_chunks,
    voice_speak_error,
    workspace_capabilities,
    workspace_result,
    DEVICE_TOOL_CAPABILITY,
    DIRECTED_FRAMES_CAPABILITY,
)
from .device_tools import DeviceToolBridge
from .generative_ui import (
    GenerativeUIError,
    parse_v2_json,
    validate_rendered_envelope,
    validate_submission_values,
)
from .link_crypto import encode_base64url
from .personality_catalog import PersonalityCatalogManager
from .plugin_update import PluginUpdateManager
from .presentation import shape_notification
from .service import LoopdyService
from .store import LoopdyStore, form_action_response
from .targets import parse_target, validate_target
from .workspace_control import (
    HermesWorkspaceBackend,
    WorkspaceControlError,
    WorkspaceController,
)


_services: dict[str, LoopdyService] = {}
_services_lock = threading.Lock()
logger = logging.getLogger(__name__)
_MAX_LINK_SESSION_PROFILE_BINDINGS = 4096
_MAX_LINK_DRAFT_IDENTITIES = 512
_MAX_LINK_METADATA_DEVICES = 256
_LINK_DRAFT_MINIMUM_INTERVAL_SECONDS = 0.25
_RUNTIME_CWD_BRIDGE_MARKER = "_loopdy_runtime_cwd_bridge_installed"
_suppress_link_control_ephemeral: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "suppress_link_control_ephemeral",
    default=False,
)
_link_workspace_connection: contextvars.ContextVar[str] = contextvars.ContextVar(
    "link_workspace_connection",
    default="",
)
_picker_request_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "loopdy_picker_request_id",
    default="",
)


@dataclass(frozen=True)
class SynthesizedVoiceAudio:
    audio: bytes
    mime_type: str
    provider: str


@dataclass(frozen=True)
class _PendingPickerRequest:
    request: PickerOpen
    sender_device_id: str
    expires_at: float


@dataclass(frozen=True)
class _ActivePicker:
    picker_id: str
    session_id: str
    kind: str
    sender_device_id: str
    callback: Any
    allowed_models: frozenset[tuple[str, str]]
    allowed_values: frozenset[str]
    expires_at: float


class VoiceSynthesisError(RuntimeError):
    pass


def tool_execution_context_type() -> Any:
    """Require both halves of the optional host context contract."""
    if "tool_execution_context" not in inspect.signature(MessageEvent).parameters:
        return None
    try:
        from tool_execution_context import ToolExecutionContext
    except (ImportError, AttributeError):
        return None
    return ToolExecutionContext if callable(ToolExecutionContext) else None


def _verified_tool_execution_context(link_client: Any, turn: InboundLinkTurn) -> Any:
    """Map only verified Link frame coordinates into Hermes' generic context."""
    context_type = tool_execution_context_type()
    if turn.sender_epoch is None or context_type is None:
        return None
    config = getattr(link_client, "config", None)
    host_id = turn.target_host_id or getattr(config, "device_id", "")
    if not host_id or host_id != getattr(config, "device_id", host_id):
        return None
    return context_type(
        source="loopdy_link",
        owner_id=turn.sender_device_id,
        scope_id=turn.message.agent_id,
        authorization_epoch=turn.sender_epoch,
        attributes={
            "host_id": host_id,
        },
    )


def synthesize_voice_audio(request: VoiceSpeakRequest) -> SynthesizedVoiceAudio:
    """Run Hermes' configured TTS provider inside the requested profile scope."""
    from gateway.run import _profile_runtime_scope
    from hermes_cli.profiles import get_profile_dir, profile_exists
    from tools.tts_tool import text_to_speech_tool

    if not profile_exists(request.agent_id):
        raise VoiceSynthesisError("The selected agent is unavailable")
    profile_home = get_profile_dir(request.agent_id)
    with tempfile.TemporaryDirectory(prefix="loopdy-voice-") as directory:
        root = Path(directory).resolve()
        output_path = root / "speech.mp3"
        with _profile_runtime_scope(profile_home):
            raw_result = text_to_speech_tool(
                request.text,
                output_path=str(output_path),
                speed=request.speed,
            )
        try:
            result = json.loads(raw_result) if isinstance(raw_result, str) else raw_result
        except (TypeError, json.JSONDecodeError) as exc:
            raise VoiceSynthesisError("Hermes TTS returned an invalid result") from exc
        if not isinstance(result, dict) or result.get("success") is not True:
            raise VoiceSynthesisError("Hermes TTS could not synthesize this response")
        file_value = result.get("file_path")
        if not isinstance(file_value, str) or not file_value:
            raise VoiceSynthesisError("Hermes TTS did not return audio")
        audio_path = Path(file_value).expanduser().resolve()
        if not audio_path.is_relative_to(root) or not audio_path.is_file():
            raise VoiceSynthesisError("Hermes TTS returned an invalid audio file")
        size = audio_path.stat().st_size
        if not 0 < size <= 8 * 1024 * 1024:
            raise VoiceSynthesisError("Hermes TTS audio exceeds the Loopdy limit")
        audio = audio_path.read_bytes()
        extension = audio_path.suffix.lower()
        mime_type = {
            ".mp3": "audio/mpeg",
            ".ogg": "audio/ogg",
            ".opus": "audio/ogg",
            ".wav": "audio/wav",
            ".flac": "audio/flac",
        }.get(extension, "audio/mpeg")
        provider = " ".join(str(result.get("provider") or "Hermes TTS").split())
        if not provider or len(provider) > 80 or any(ord(character) < 32 for character in provider):
            provider = "Hermes TTS"
        return SynthesizedVoiceAudio(
            audio=audio,
            mime_type=mime_type,
            provider=provider,
        )


def data_path() -> Path:
    return get_hermes_home() / "plugin-data" / "loopdy" / "loopdy.sqlite3"


def get_service() -> LoopdyService:
    key = str(data_path().resolve())
    with _services_lock:
        service = _services.get(key)
        if service is None:
            service = LoopdyService(LoopdyStore(Path(key)))
            _services[key] = service
        return service


def release_service(service: LoopdyService) -> None:
    service.close()
    with _services_lock:
        for key, cached in list(_services.items()):
            if cached is service:
                del _services[key]


def _loopdy_runtime_cwd(runner: Any, context: Any) -> str | None:
    """Resolve one Loopdy turn's live Hermes cwd without global process state."""
    source = getattr(context, "source", None)
    if getattr(getattr(source, "platform", None), "value", None) != "loopdy":
        return None

    session_key = str(getattr(context, "session_key", "") or "").strip()
    session_id = str(getattr(context, "session_id", "") or "").strip()

    from tools.terminal_tool import get_session_cwd

    for coordinate in (session_key, session_id):
        if not coordinate:
            continue
        cwd = get_session_cwd(coordinate)
        if isinstance(cwd, str) and cwd.strip():
            return cwd.strip()

    if not session_id:
        return None
    session_store = getattr(runner, "session_store", None)
    if session_store is None:
        return None
    db_for_session_id = getattr(session_store, "_db_for_session_id", None)
    session_db = (
        db_for_session_id(session_id)
        if callable(db_for_session_id)
        else getattr(session_store, "_db", None)
    )
    get_session = getattr(session_db, "get_session", None)
    row = get_session(session_id) if callable(get_session) else None
    cwd = row.get("cwd") if isinstance(row, dict) else None
    if isinstance(cwd, str) and cwd.strip():
        return cwd.strip()
    return None


def _install_runtime_cwd_bridge(runner: Any) -> None:
    """Restore Loopdy's task-local cwd after Hermes binds session variables."""
    if runner is None or getattr(runner, _RUNTIME_CWD_BRIDGE_MARKER, False):
        return
    original = getattr(runner, "_set_session_env", None)
    if not callable(original):
        return

    def set_session_env_with_loopdy_cwd(context: Any) -> list:
        tokens = original(context)
        try:
            cwd = _loopdy_runtime_cwd(runner, context)
            if cwd:
                from agent.runtime_cwd import set_session_cwd
                from tools.terminal_tool import register_task_env_overrides

                set_session_cwd(cwd)
                override = {"cwd": cwd, "cwd_source": "project"}
                for coordinate in (
                    str(getattr(context, "session_key", "") or "").strip(),
                    str(getattr(context, "session_id", "") or "").strip(),
                ):
                    if coordinate:
                        register_task_env_overrides(coordinate, override)
        except Exception:
            logger.warning(
                "Loopdy could not restore Hermes runtime cwd for session %s",
                str(getattr(context, "session_id", "") or "")[:80],
                exc_info=True,
            )
        return tokens

    runner._set_session_env = set_session_env_with_loopdy_cwd
    setattr(runner, _RUNTIME_CWD_BRIDGE_MARKER, True)


class LoopdyAdapter(BasePlatformAdapter):
    """Turns Hermes outbound messages into opaque Loopdy wakeup events."""

    supports_async_delivery = True
    interactive_resume = False
    # Own message sizing: card envelopes must reach validation intact, while
    # ordinary Inbox text is split below rather than cut by Hermes cron delivery.
    splits_long_messages = True

    def __init__(
        self,
        config: PlatformConfig,
        *,
        service: LoopdyService | None = None,
        link_client: LoopdyLinkClient | Any | None = None,
        link_state: Any | None = None,
        activity_broker: Any | None = None,
        personality_manager: PersonalityCatalogManager | Any | None = None,
        workspace_controller: Any | None = None,
        plugin_update_manager: PluginUpdateManager | None = None,
        device_tool_bridge: DeviceToolBridge | None = None,
        wiki_transport: Any | None = None,
        voice_synthesizer: Callable[[VoiceSpeakRequest], SynthesizedVoiceAudio] = synthesize_voice_audio,
    ):
        # Restart and shutdown pings are operator lifecycle signals, not user
        # inbox content. Loopdy presents connection health in its device UI.
        config.gateway_restart_notification = False
        super().__init__(config=config, platform=Platform("loopdy"))
        self.service = service or get_service()
        self.home_target = str((config.extra or {}).get("home_target") or "all").strip()
        self.link_client = link_client
        self._wiki_uses_runtime_config = link_client is None
        from .wiki_transport import production_factory
        self.wiki_transport = wiki_transport or production_factory(
            host_home=get_hermes_home(), config_getter=self._wiki_current_config,
        )
        self.activity_broker = activity_broker
        self.device_tool_bridge = device_tool_bridge or DeviceToolBridge()
        self.personality_manager = personality_manager or PersonalityCatalogManager(
            config_path=get_hermes_home() / "config.yaml"
        )
        self.workspace_controller = workspace_controller or WorkspaceController(
            wiki_transport=self.wiki_transport,
            backend=HermesWorkspaceBackend(
                service=self.service,
                session_workspace_setter=self._set_link_session_workspace,
                session_workspace_getter=self._get_link_session_workspace,
                session_active_getter=self._is_link_session_active,
                session_subagents_getter=(
                    getattr(self.activity_broker, "subagent_snapshot", None)
                ),
                session_goal_getter=self.goal_snapshot_for_session,
                session_runtime_getter=self.runtime_snapshot_for_session,
                connection_id_getter=self._link_workspace_connection_id,
                plugin_update_manager=plugin_update_manager,
                workspace_git_state_path=(
                    get_hermes_home()
                    / "plugin-data"
                    / "loopdy"
                    / "workspace-git-link.sqlite3"
                ),
            )
        )
        self.voice_synthesizer = voice_synthesizer
        self._voice_tasks: set[asyncio.Task[None]] = set()
        self._pending_picker_requests: dict[str, _PendingPickerRequest] = {}
        self._active_pickers: dict[str, _ActivePicker] = {}
        self._link_metadata_devices: OrderedDict[str, None] = OrderedDict()
        self._link_session_profiles: OrderedDict[str, str] = OrderedDict()
        self._link_session_workspaces: OrderedDict[tuple[str, str], str] = OrderedDict()
        self._link_draft_messages: OrderedDict[tuple[str, int], str] = OrderedDict()
        self._link_active_drafts: OrderedDict[
            tuple[str, str], tuple[tuple[str, int], str]
        ] = OrderedDict()
        self._link_draft_sent_at: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._link_delivery_lock = asyncio.Lock()
        self.link_configuration_error = ""
        self.marketplace_configuration_error = ""
        marketplace_client = None
        if self.link_client is None:
            try:
                runtime_config = load_runtime_config()
            except (TypeError, ValueError) as exc:
                runtime_config = None
                self.link_configuration_error = str(exc)[:160]
            if runtime_config is not None:
                from .marketplace import (
                    CARD_TEMPLATE_CAPABILITY,
                    MARKETPLACE_SKILL_CAPABILITY,
                    build_marketplace_gateway_client,
                )

                capabilities = [
                    CARD_TEMPLATE_CAPABILITY,
                    DEVICE_TOOL_CAPABILITY,
                    DIRECTED_FRAMES_CAPABILITY,
                ]
                try:
                    marketplace_client = build_marketplace_gateway_client(runtime_config)
                except Exception as exc:
                    self.marketplace_configuration_error = str(exc)[:160]
                if marketplace_client is not None:
                    capabilities.append(MARKETPLACE_SKILL_CAPABILITY)
                self.link_client = LoopdyLinkClient(
                    runtime_config,
                    state=link_state,
                    attachment_root=(
                        get_hermes_home()
                        / "plugin-data"
                        / "loopdy"
                        / "link-inbound"
                    ),
                    capabilities=capabilities,
                )
                self.device_tool_bridge.bind_link_client(self.link_client)
        elif getattr(self.link_client, "config", None) is not None:
            self.device_tool_bridge.bind_link_client(self.link_client)
            from .marketplace import build_marketplace_gateway_client

            try:
                marketplace_client = build_marketplace_gateway_client(
                    self.link_client.config
                )
            except Exception as exc:
                self.marketplace_configuration_error = str(exc)[:160]
        if marketplace_client is not None:
            from .marketplace import MarketplaceSkillInstaller

            backend = getattr(self.workspace_controller, "backend", None)
            if (
                isinstance(backend, HermesWorkspaceBackend)
                and backend.marketplace_skill_installer is None
            ):
                backend.marketplace_skill_installer = MarketplaceSkillInstaller(
                    store=self.service.store,
                    release_client=marketplace_client,
                )

    def _wiki_current_config(self):
        from .wiki_transport import authority_id
        client = self.link_client
        if client is None or getattr(client, "_authentication_failed", False):
            return None
        stopping = getattr(client, "_stopping", None)
        if stopping is not None and stopping.is_set():
            return None
        config = client.config
        if self._wiki_uses_runtime_config:
            current = load_runtime_config()
            if current is None or authority_id(current) != authority_id(config):
                return None
        return config

    @property
    def authorization_is_upstream(self) -> bool:
        # User/device authorization is completed by the signed Link socket;
        # message identity is then authenticated again by the account AEAD.
        return self.link_client is not None

    def set_session_store(self, session_store: Any) -> None:
        super().set_session_store(session_store)
        _install_runtime_cwd_bridge(getattr(self, "gateway_runner", None))
        attach = getattr(self.activity_broker, "attach_session_store", None)
        if callable(attach):
            attach(session_store)
        attach_context = getattr(self.activity_broker, "attach_context_provider", None)
        if callable(attach_context):
            attach_context(self._context_window_snapshot)
        attach_goal = getattr(self.activity_broker, "attach_goal_provider", None)
        if callable(attach_goal):
            attach_goal(self._goal_state_snapshot)

    def _goal_state_snapshot(self, session_id: str) -> dict[str, Any] | None:
        """Read Hermes' documented goal:<session_id> metadata, without mutation.

        load_goal() intentionally collapses storage failures into None. That
        convenience API is unsuitable for reconciliation: only a successful
        absent-row read is authoritative absence. Read the same public
        SessionDB metadata through the owning gateway profile instead.
        """
        store = getattr(self, "_session_store", None)
        lookup = getattr(store, "lookup_by_session_id", None)
        db_for_session = getattr(store, "_db_for_session_id", None)
        if not callable(lookup) or not callable(db_for_session):
            return None
        entry = lookup(session_id)
        origin = getattr(entry, "origin", None)
        if (
            getattr(entry, "session_id", None) != session_id
            or getattr(getattr(entry, "platform", None), "value", None) != "loopdy"
            or getattr(getattr(origin, "platform", None), "value", None) != "loopdy"
        ):
            return None
        route = getattr(origin, "chat_id", None)
        if not isinstance(route, str) or not _is_link_chat_id(route):
            return None
        db = db_for_session(session_id)
        get_meta = getattr(db, "get_meta", None)
        if not callable(get_meta):
            return None
        raw = get_meta(f"goal:{session_id}")
        if raw is None:
            status, summary = "none", None
        else:
            # Reject malformed/unknown state rather than erasing a valid rail.
            # Hermes' raw status is done (not a tool/turn's completed flag).
            if not isinstance(raw, (str, bytes, bytearray)):
                return None
            state = json.loads(raw)
            if not isinstance(state, dict):
                return None
            status = state.get("status")
            if not isinstance(status, str) or status not in {"active", "paused", "done", "cleared"}:
                return None
            summary = state.get("goal") if status in {"active", "paused"} else None
            if status in {"active", "paused"} and (
                not isinstance(summary, str) or not summary.strip()
            ):
                return None
        # Compression/reset may replace the route while the DB read is in
        # flight. Do not stamp the former owner's state as a fresh snapshot.
        current = lookup(session_id)
        if (
            getattr(current, "session_id", None) != session_id
            or getattr(getattr(current, "origin", None), "chat_id", None) != route
        ):
            return None
        return {
            "sessionId": route, "storedSessionId": session_id,
            "status": status, "summary": summary,
        }

    async def runtime_snapshot_for_session(self, agent_id: str, stored_id: str) -> dict[str, str] | None:
        """Read an exact current session override through the public session store."""
        store = getattr(self, "_session_store", None)
        if store is None:
            return None

        def read():
            entry = store.lookup_by_session_id(stored_id)
            if entry is None or (getattr(entry.origin, "profile", None) or "default") != agent_id:
                return None
            key = entry.session_key
            override = store.get_model_override(key)
            if store.peek_session_id(key) != stored_id or not override:
                return None
            return {key: override[key] for key in ("model", "provider") if override.get(key)}

        return await asyncio.to_thread(read)

    async def goal_snapshot_for_session(
        self, agent_id: str, session_id: str, stored_id: str
    ) -> dict[str, Any] | None:
        """Catalog/history readback seam for an already authorized session row.

        The workspace owner calls this with the resolved profile, visible
        route and exact stored id. Mismatched/retired rows are unavailable,
        never aliased onto the current conversation's goal.
        """
        store = getattr(self, "_session_store", None)
        lookup = getattr(store, "lookup_by_session_key", None)
        snapshot = getattr(self.activity_broker, "goal_snapshot", None)
        bind = getattr(self.activity_broker, "bind_link_session", None)
        if not callable(lookup) or not callable(snapshot) or not callable(bind):
            return None
        source = self.build_source(chat_id=session_id, chat_type="dm")
        source.profile = agent_id
        try:
            entry = await asyncio.to_thread(lookup, self._link_session_key(source))
            if getattr(entry, "session_id", None) != stored_id:
                return None
            bind(stored_id, session_id)
            result = await asyncio.to_thread(snapshot, stored_id)
            return result if isinstance(result, dict) else None
        except Exception as exc:
            logger.warning("Loopdy goal readback failed (%s)", type(exc).__name__)
            return None

    async def _refresh_goal_for_source(self, source: SessionSource) -> None:
        store = getattr(self, "_session_store", None)
        lookup = getattr(store, "lookup_by_session_key", None)
        publish = getattr(self.activity_broker, "publish_goal_snapshot", None)
        bind = getattr(self.activity_broker, "bind_link_session", None)
        if not callable(lookup) or not callable(publish) or not callable(bind):
            return
        try:
            entry = await asyncio.to_thread(lookup, self._link_session_key(source))
            session_id = getattr(entry, "session_id", None)
            if session_id:
                bind(session_id, source.chat_id)
                await asyncio.to_thread(publish, session_id, force=True)
        except Exception as exc:
            logger.warning("Loopdy goal refresh failed (%s)", type(exc).__name__)

    def _context_window_snapshot(self, session_id: str) -> dict[str, Any] | None:
        """Read the live/cached gateway state used by Hermes /status and /context."""

        resolver = getattr(
            getattr(self, "_session_store", None),
            "lookup_by_session_id",
            None,
        )
        if not callable(resolver):
            return None
        entry = resolver(session_id)
        session_key = str(getattr(entry, "session_key", "") or "").strip()
        runner = getattr(self, "gateway_runner", None)
        if not session_key or runner is None:
            return None
        agent = (getattr(runner, "_running_agents", None) or {}).get(session_key)
        compressor = getattr(agent, "context_compressor", None)
        if compressor is None:
            cache = getattr(runner, "_agent_cache", None)
            cache_lock = getattr(runner, "_agent_cache_lock", None)
            try:
                if cache_lock is not None:
                    with cache_lock:
                        cached = cache.get(session_key) if cache is not None else None
                else:
                    cached = cache.get(session_key) if cache is not None else None
                if cached:
                    agent = cached[0]
                    compressor = getattr(agent, "context_compressor", None)
            except Exception:
                agent = None
                compressor = None
        if agent is None or compressor is None:
            return None

        def nonnegative_int(value: Any) -> int:
            try:
                return max(0, int(value))
            except (TypeError, ValueError):
                return 0

        used = nonnegative_int(getattr(compressor, "last_prompt_tokens", 0))
        if not used:
            used = nonnegative_int(getattr(entry, "last_prompt_tokens", 0))
        maximum = nonnegative_int(getattr(compressor, "context_length", 0))
        model = str(getattr(agent, "model", "") or "").strip()
        if not model or not maximum:
            return None

        title = ""
        session_db = getattr(runner, "_session_db", None)
        session_db = getattr(session_db, "_db", session_db)
        title_reader = getattr(session_db, "get_session_title", None)
        if callable(title_reader):
            try:
                title = str(title_reader(session_id) or "").strip()[:240]
            except Exception:
                title = ""

        snapshot = {
            "model": model,
            "contextUsed": used,
            "contextMax": maximum,
            "contextPercent": min(100, round((used / maximum) * 100)),
            "compressions": nonnegative_int(
                getattr(compressor, "compression_count", 0)
            ),
            "isCompacting": (
                getattr(agent, "_active_compression_lock_holder", None) is not None
            ),
        }
        if title:
            snapshot["title"] = title

        # Per-request usage belongs to the activity broker's public-hook state.
        # Keep it separate from Hermes runner internals so reconnect snapshots
        # can reuse the same verified session/model projection.
        usage_reader = getattr(self.activity_broker, "usage_snapshot", None)
        try:
            usage = usage_reader(session_id, model) if callable(usage_reader) else None
        except Exception as exc:
            logger.warning("Loopdy usage snapshot failed (%s)", type(exc).__name__)
            usage = None
        if isinstance(usage, dict):
            for key in (
                "inputTokens", "outputTokens", "cachedTokens", "totalTokens"
            ):
                value = usage.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    snapshot[key] = value
            prompt_tokens = snapshot.get("inputTokens")
            if prompt_tokens is not None:
                snapshot["contextUsed"] = prompt_tokens
                snapshot["contextPercent"] = min(
                    100, round((prompt_tokens / maximum) * 100)
                )

        return snapshot

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        _install_runtime_cwd_bridge(getattr(self, "gateway_runner", None))
        plugin_update_manager = getattr(
            getattr(self.workspace_controller, "backend", None),
            "plugin_update_manager",
            None,
        )
        if plugin_update_manager is not None:
            # Adapter connection is a real gateway lifecycle. Plugin Doctor
            # and CLI discovery register the plugin but never reach here.
            try:
                plugin_update_manager.record_runtime_loaded()
            except Exception:
                # Update status can fail closed without disabling ordinary Link.
                pass
        health = self.service.health()
        if self.link_client is not None:
            self.device_tool_bridge.bind_link_client(self.link_client)
            self.link_client.start(
                self.receive_link_payload,
                status_callback=self._on_link_status,
            )
            if self.activity_broker is not None:
                await self.activity_broker.attach(
                    self.link_client.send_payload,
                    live_activity_sender=self.link_client.send_live_activity_update,
                )
            if not await self._wait_for_link_connection():
                detail = "Loopdy Link did not complete the socket-ready handshake."
                link_state = "disconnected"
                status = getattr(self.link_client, "status", None)
                if callable(status):
                    try:
                        snapshot = status()
                        detail = str(snapshot.get("detail") or detail)[:160]
                        link_state = str(snapshot.get("state") or link_state)
                    except Exception:
                        pass
                superseded = link_state == "superseded"
                self._set_fatal_error(
                    (
                        "loopdy_link_superseded"
                        if superseded
                        else "loopdy_link_not_ready"
                    ),
                    detail,
                    retryable=not superseded,
                )
                return False
        if not health.get("configured") and self.link_client is None:
            self._set_fatal_error(
                (
                    "loopdy_link_configuration_invalid"
                    if self.link_configuration_error
                    else "loopdy_provider_not_ready"
                ),
                self.link_configuration_error
                or str(health.get("detail") or "Configure Loopdy notifications first."),
                retryable=False,
            )
            return False
        self._mark_connected()
        return True

    async def _wait_for_link_connection(self) -> bool:
        client = self.link_client
        if client is None:
            return False
        wait = getattr(client, "wait_until_connected", None)
        if callable(wait):
            try:
                return bool(await wait(timeout=20.0))
            except asyncio.CancelledError:
                raise
            except Exception:
                return False
        return bool(getattr(client, "connected", False))

    def _on_link_status(self, state: str, detail: str = "") -> None:
        if state == "connected":
            self._mark_connected()
        elif state == "unready":
            self._set_fatal_error(
                "loopdy_link_enrollment_unready",
                detail or "Loopdy Link enrollment is not ready.",
                retryable=True,
            )
        elif state == "superseded":
            self._set_fatal_error(
                "loopdy_link_superseded",
                detail or "A newer Hermes runtime owns this Loopdy Link device.",
                retryable=False,
            )
        elif state in {"disconnected", "reconnecting"}:
            self._mark_disconnected()

    async def _send_link_payload(self, payload: dict[str, Any], *,
                                 owner_check: Callable[[], None] | None = None) -> str:
        """Send control traffic after a verified reconnect, with one retry."""
        client = self.link_client
        if client is None:
            raise ConnectionError("Loopdy Link is not configured")
        wait = getattr(client, "wait_until_connected", None)
        last_error: BaseException | None = None
        for attempt in range(2):
            if callable(wait):
                ready = await wait(timeout=20.0)
                if not ready:
                    last_error = ConnectionError("Loopdy Link is not connected")
                    continue
            elif not bool(getattr(client, "connected", False)):
                last_error = ConnectionError("Loopdy Link is not connected")
                continue
            try:
                if owner_check is not None:
                    owner_check()
                    return await client.send_payload(payload, owner_check=owner_check)
                return await client.send_payload(payload)
            except Exception as exc:
                if owner_check is not None:
                    owner_check()
                pending_frame = getattr(client, "pending_payload_frame_id", None)
                if callable(pending_frame):
                    frame_id = pending_frame(payload)
                    if frame_id:
                        return str(frame_id)
                # Retry only failures that prove no matching durable frame owns
                # the payload. Other errors may be ambiguous and must surface.
                if isinstance(exc, ConnectionError):
                    last_error = exc
                    continue
                raise
        if last_error is not None:
            raise last_error
        raise ConnectionError("Loopdy Link control delivery failed")

    async def _deliver_link_notification(
        self,
        event: LoopdyEvent,
        *,
        target: str,
    ) -> SendResult:
        async with self._link_delivery_lock:
            return await self._deliver_link_notification_locked(event, target=target)

    async def _deliver_link_notification_locked(
        self,
        event: LoopdyEvent,
        *,
        target: str,
    ) -> SendResult:
        await asyncio.to_thread(
            self.service.store.record_event,
            event,
            target=target,
        )
        existing = await asyncio.to_thread(
            self.service.store.get_event,
            event.event_id,
        )
        if existing is not None and existing.get("status") == "sent":
            return SendResult(success=True, message_id=event.event_id)
        sent_at = int((existing or {}).get("created_at") or time.time())
        push = shape_notification(event)
        payload = notification_event(
            event_id=event.event_id,
            event_type=event.type,
            agent_id=event.profile,
            agent_name=str(event.detail.get("agent_name") or event.profile),
            session_id=event.session_id,
            title=push.title,
            body=push.body,
            card=(
                event.detail.get("generative_ui")
                if isinstance(event.detail.get("generative_ui"), dict)
                else None
            ),
            sent_at=sent_at,
        )
        if existing is not None and existing.get("status") == "pending":
            client = self.link_client
            pending_frame = getattr(client, "pending_payload_frame_id", None)
            frame_id = pending_frame(payload) if callable(pending_frame) else None
            if frame_id:
                await asyncio.to_thread(
                    self.service.store.mark_event_pending,
                    event.event_id,
                    frame_id,
                )
            else:
                await asyncio.to_thread(
                    self.service.store.mark_event_delivered,
                    event.event_id,
                    str(existing.get("delivery_id") or ""),
                )
            return SendResult(success=True, message_id=event.event_id)
        try:
            frame_id = await self._send_link_payload(payload)
            client = self.link_client
            pending_frame = getattr(client, "pending_payload_frame_id", None)
            is_pending = callable(pending_frame) and pending_frame(payload) == frame_id
            marker = (
                self.service.store.mark_event_pending
                if is_pending
                else self.service.store.mark_event_delivered
            )
            await asyncio.to_thread(marker, event.event_id, frame_id)
            return SendResult(success=True, message_id=event.event_id)
        except Exception as exc:
            await asyncio.to_thread(
                self.service.store.mark_event_failed,
                event.event_id,
                type(exc).__name__,
            )
            return SendResult(
                success=False,
                error=f"Loopdy Link notification failed ({type(exc).__name__})",
            )

    async def disconnect(self) -> None:
        self.device_tool_bridge.bind_link_client(None)
        if self.activity_broker is not None:
            await self.activity_broker.detach()
        active_voice_tasks = tuple(self._voice_tasks)
        for task in active_voice_tasks:
            task.cancel()
        if active_voice_tasks:
            await asyncio.gather(*active_voice_tasks, return_exceptions=True)
        if self.link_client is not None:
            await self.link_client.stop()
        self._pending_picker_requests.clear()
        self._active_pickers.clear()
        self._link_metadata_devices.clear()
        self._link_session_workspaces.clear()
        self._link_draft_messages.clear()
        self._link_active_drafts.clear()
        self._link_draft_sent_at.clear()
        self._mark_disconnected()

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        if self.link_client is not None and _is_link_chat_id(chat_id):
            values = metadata or {}
            is_interim = values.get("_interim_send") is True
            try:
                agent_id = self._link_response_profile(chat_id, values)
                agent_name = (
                    _text(values.get("agent_name") or values.get("sender_name"), 80)
                    or profile_display_name(agent_id)
                )
                active_draft = None if is_interim else self._active_link_draft(
                    chat_id, values
                )
                requested_message_id = _text(values.get("_loopdy_message_id"), 180)
                message_id = (
                    requested_message_id
                    or (active_draft[1] if active_draft else self._new_message_id())
                )
                await self._send_link_payload(
                    assistant_message(
                        message_id=message_id,
                        session_id=chat_id,
                        text=content,
                        sent_at=int(time.time()),
                        agent_name=agent_name,
                        agent_id=agent_id,
                        delivery=(
                            "draft" if is_interim else "final"
                        ),
                        draft_id=(
                            int.from_bytes(os.urandom(6), "big") or 1
                            if is_interim
                            else None
                        ),
                    )
                )
                if active_draft is not None:
                    self._finish_link_draft(chat_id, values, active_draft[0])
                if not is_interim and self.activity_broker is not None:
                    try:
                        await self.activity_broker.complete(
                            chat_id,
                            agent_name=agent_name,
                            succeeded=True,
                        )
                    except Exception:
                        pass
                return SendResult(success=True, message_id=message_id)
            except Exception as exc:
                return SendResult(
                    success=False,
                    error=f"Loopdy Link delivery failed ({type(exc).__name__})",
                )
        target = str(chat_id or self.home_target or "all").strip()
        event = _channel_event(content, metadata=metadata, target=target)
        # A validated card is atomic even when its JSON exceeds the text limit.
        if "generative_ui" not in event.detail and len(content) > 50_000:
            result = SendResult(success=True)
            for offset in range(0, len(content), 50_000):
                result = await self.send(
                    chat_id, content[offset:offset + 50_000],
                    reply_to=reply_to, metadata=metadata,
                )
                if not result.success:
                    return result
            return result
        if self.link_client is not None and target in {"all", "home"}:
            return await self._deliver_link_notification(event, target=target)
        result = await asyncio.to_thread(self.service.deliver, event, target=target)
        if result.get("success"):
            message_id = str(result.get("message_id") or event.event_id)
            return SendResult(success=True, message_id=message_id)
        return SendResult(
            success=False,
            error=str(result.get("error") or "Loopdy delivery failed"),
        )

    async def _send_link_attachment(
        self,
        *,
        chat_id: str,
        path: str,
        caption: str | None,
        reply_to: str | None,
        metadata: Dict[str, Any] | None,
    ) -> SendResult:
        if self.link_client is None or not _is_link_chat_id(chat_id):
            return SendResult(success=False, error="Loopdy Link is not connected")
        safe_path = self.validate_media_delivery_path(path)
        if safe_path is None:
            return SendResult(success=False, error="Loopdy attachment path is unavailable")
        content = f"{caption}\nMEDIA:{safe_path}" if caption else f"MEDIA:{safe_path}"
        values = dict(metadata or {})
        try:
            agent_id = self._link_response_profile(chat_id, values)
            message_id = self._new_message_id()
            backend = getattr(self.workspace_controller, "backend", None)
            attachment_store = getattr(backend, "attachment_store", None)
            resolve = getattr(attachment_store, "resolve", None)
            if not callable(resolve):
                return SendResult(
                    success=False,
                    error="Loopdy attachment storage is unavailable",
                )
            resolved = await asyncio.to_thread(
                resolve,
                profile=agent_id,
                session_id=chat_id,
                items=[{"id": message_id, "text": content}],
            )
            if (
                not isinstance(resolved, list)
                or len(resolved) != 1
                or not resolved[0].get("attachments")
            ):
                return SendResult(
                    success=False,
                    error="Loopdy attachment could not be cached",
                )
            values["_loopdy_message_id"] = message_id
        except Exception as exc:
            return SendResult(
                success=False,
                error=f"Loopdy attachment caching failed ({type(exc).__name__})",
            )
        return await self.send(
            chat_id=chat_id,
            content=content,
            reply_to=reply_to,
            metadata=values,
        )

    async def send_image_file(
        self,
        chat_id: str,
        image_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        del kwargs
        if self.link_client is None or not _is_link_chat_id(chat_id):
            return await super().send_image_file(
                chat_id=chat_id,
                image_path=image_path,
                caption=caption,
                reply_to=reply_to,
                metadata=metadata,
            )
        return await self._send_link_attachment(
            chat_id=chat_id,
            path=image_path,
            caption=caption,
            reply_to=reply_to,
            metadata=metadata,
        )

    async def send_image(
        self,
        chat_id: str,
        image_url: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        if self.link_client is None or not _is_link_chat_id(chat_id):
            return await super().send_image(
                chat_id=chat_id,
                image_url=image_url,
                caption=caption,
                reply_to=reply_to,
                metadata=metadata,
            )
        try:
            from gateway.platforms.base import cache_image_from_url
            import httpx
        except ImportError as exc:
            return SendResult(
                success=False,
                error=f"Loopdy remote image support is unavailable ({type(exc).__name__})",
            )
        try:
            image_path = await cache_image_from_url(image_url)
        except (OSError, ValueError, httpx.HTTPError) as exc:
            return SendResult(
                success=False,
                error=f"Loopdy remote image download failed ({type(exc).__name__})",
            )
        return await self._send_link_attachment(
            chat_id=chat_id,
            path=image_path,
            caption=caption,
            reply_to=reply_to,
            metadata=metadata,
        )

    async def send_document(
        self,
        chat_id: str,
        file_path: str,
        caption: Optional[str] = None,
        file_name: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        del kwargs
        if self.link_client is None or not _is_link_chat_id(chat_id):
            return await super().send_document(
                chat_id=chat_id,
                file_path=file_path,
                caption=caption,
                reply_to=reply_to,
                metadata=metadata,
            )
        return await self._send_link_attachment(
            chat_id=chat_id,
            path=file_path,
            caption=caption,
            reply_to=reply_to,
            metadata=metadata,
        )

    async def send_video(
        self,
        chat_id: str,
        video_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        del kwargs
        if self.link_client is None or not _is_link_chat_id(chat_id):
            return await super().send_video(
                chat_id=chat_id,
                video_path=video_path,
                caption=caption,
                reply_to=reply_to,
                metadata=metadata,
            )
        return await self._send_link_attachment(
            chat_id=chat_id,
            path=video_path,
            caption=caption,
            reply_to=reply_to,
            metadata=metadata,
        )

    async def send_voice(
        self,
        chat_id: str,
        audio_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        del kwargs
        if self.link_client is None or not _is_link_chat_id(chat_id):
            return await super().send_voice(
                chat_id=chat_id,
                audio_path=audio_path,
                caption=caption,
                reply_to=reply_to,
                metadata=metadata,
            )
        return await self._send_link_attachment(
            chat_id=chat_id,
            path=audio_path,
            caption=caption,
            reply_to=reply_to,
            metadata=metadata,
        )

    async def send_clarify(
        self,
        chat_id: str,
        question: str,
        choices: Optional[list],
        clarify_id: str,
        session_key: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Render Hermes' prompt, then enqueue one request-bound Home card."""
        from tools.clarify_gateway import (
            get_clarify_timeout,
            get_pending_for_session,
        )

        canonical_id = _text(clarify_id, 180)
        canonical_session = _text(session_key, 180)
        canonical_chat = _text(chat_id, 180)
        canonical_question = _text(question, 2_000)
        normalized_choices = [
            value
            for value in (_text(choice, 500) for choice in list(choices or ())[:4])
            if value
        ]
        pending = get_pending_for_session(
            canonical_session,
            include_choice_prompts=True,
        )
        multi_select = bool(
            pending is not None
            and str(getattr(pending, "clarify_id", "")) == canonical_id
            and getattr(pending, "multi_select", False)
        )
        try:
            timeout = int(get_clarify_timeout())
        except (TypeError, ValueError):
            timeout = 3_600
        expires_at = int(time.time()) + timeout if timeout > 0 else None
        interaction = {
            "schemaVersion": 1,
            "type": "clarify",
            "requestId": canonical_id,
            "expiresAt": expires_at,
            "allowsCustomResponse": True,
            "questions": [
                {
                    "id": "q0",
                    "question": canonical_question,
                    "choices": normalized_choices,
                    "multiSelect": multi_select,
                    "allowsCustomResponse": True,
                }
            ],
        }
        values = metadata or {}
        profile = (
            _text(values.get("profile") or values.get("profile_name"), 80)
            or _active_profile_id()
        )
        agent_name = (
            _text(values.get("agent_name") or values.get("sender_name"), 80)
            or profile_display_name(profile)
        )
        detail = {
            "kind": "clarify",
            "request_id": canonical_id,
            "session_key": canonical_session,
            "question": canonical_question,
            "interaction": interaction,
            **({"expires_at": str(expires_at)} if expires_at is not None else {}),
            **({"agent_name": agent_name} if agent_name else {}),
        }
        event = build_event(
            "attention.required",
            correlation=("clarify", canonical_id, canonical_session),
            profile=profile,
            session_id=canonical_chat,
            detail=detail,
        )
        target = self.home_target or "all"
        if self.link_client is not None:
            async with self._link_delivery_lock:
                existing = await asyncio.to_thread(
                    self.service.store.get_event,
                    event.event_id,
                )
                status = str((existing or {}).get("status") or "")
                prompt_message_id = "message_" + event.event_id.rsplit(":", 1)[-1]
                if status == "sent":
                    return SendResult(success=True, message_id=prompt_message_id)
                if existing is None:
                    prompt_metadata = dict(metadata or {})
                    prompt_metadata["_loopdy_message_id"] = prompt_message_id
                    result = await super().send_clarify(
                        chat_id=chat_id,
                        question=question,
                        choices=choices,
                        clarify_id=clarify_id,
                        session_key=session_key,
                        metadata=prompt_metadata,
                    )
                    if not result.success:
                        return result
                    await asyncio.to_thread(
                        self.service.store.record_event,
                        event,
                        target=target,
                    )
                    await asyncio.to_thread(
                        self.service.store.mark_event_prompted,
                        event.event_id,
                    )
                else:
                    result = SendResult(success=True, message_id=prompt_message_id)
                    if status == "queued":
                        await asyncio.to_thread(
                            self.service.store.mark_event_prompted,
                            event.event_id,
                        )
                delivery = await self._deliver_link_notification_locked(
                    event,
                    target=target,
                )
                return result if delivery.success else delivery

        result = await super().send_clarify(
            chat_id=chat_id,
            question=question,
            choices=choices,
            clarify_id=clarify_id,
            session_key=session_key,
            metadata=metadata,
        )
        if not result.success:
            return result
        self.service.enqueue(event, target=target)
        return result

    async def get_chat_info(self, chat_id: str) -> dict[str, str]:
        return {
            "name": "Loopdy chat" if _is_link_chat_id(chat_id) else str(chat_id),
            "type": "dm" if _is_link_chat_id(chat_id) else "notification",
        }

    def supports_draft_streaming(
        self,
        chat_type: str | None = None,
        metadata: Dict[str, Any] | None = None,
        chat_id: str | None = None,
    ) -> bool:
        return self.link_client is not None and (
            chat_id is None or _is_link_chat_id(chat_id)
        )

    async def send_draft(
        self,
        chat_id: str,
        draft_id: int,
        content: str,
        metadata: Dict[str, Any] | None = None,
    ) -> SendResult:
        if self.link_client is None or not _is_link_chat_id(chat_id):
            return SendResult(success=False, error="Loopdy Link is not connected")
        values = metadata or {}
        try:
            draft_key = (str(chat_id), int(draft_id))
            turn_key = self._link_draft_turn_key(chat_id, values)
            previous = self._link_active_drafts.pop(turn_key, None)
            message_id = (
                previous[1]
                if previous is not None
                else self._link_draft_messages.get(draft_key)
            )
            if message_id is None:
                message_id = self._new_message_id()
            self._link_draft_messages[draft_key] = message_id
            self._link_draft_messages.move_to_end(draft_key)
            self._link_active_drafts[turn_key] = (draft_key, message_id)
            if previous is not None and previous[0] != draft_key:
                self._link_draft_messages.pop(previous[0], None)
            self._trim_link_draft_identities()
            now = time.monotonic()
            last_sent_at = self._link_draft_sent_at.get(turn_key)
            if (
                last_sent_at is not None
                and now - last_sent_at < _LINK_DRAFT_MINIMUM_INTERVAL_SECONDS
            ):
                # The final response carries the complete text. Intermediate
                # token snapshots are presentation hints, so bound Link/APNs
                # backlog without weakening durable final/tool history.
                return SendResult(success=True)
            agent_id = self._link_response_profile(chat_id, values)
            await self._send_link_payload(
                assistant_message(
                    message_id=message_id,
                    session_id=chat_id,
                    text=content,
                    sent_at=int(time.time()),
                    agent_name=(
                        _text(values.get("agent_name") or values.get("sender_name"), 80)
                        or profile_display_name(agent_id)
                    ),
                    agent_id=agent_id,
                    delivery="draft",
                    draft_id=draft_id,
                )
            )
            self._link_draft_sent_at[turn_key] = now
            self._link_draft_sent_at.move_to_end(turn_key)
            return SendResult(success=True)
        except Exception as exc:
            return SendResult(
                success=False,
                error=f"Loopdy Link draft failed ({type(exc).__name__})",
            )

    @staticmethod
    def _new_message_id() -> str:
        return "message_" + encode_base64url(os.urandom(18))

    @staticmethod
    def _link_draft_turn_key(
        chat_id: str, metadata: Dict[str, Any]
    ) -> tuple[str, str]:
        reply_to = _text(metadata.get("reply_to_message_id"), 180)
        return (str(chat_id), reply_to)

    def _active_link_draft(
        self, chat_id: str, metadata: Dict[str, Any]
    ) -> tuple[tuple[str, int], str] | None:
        key = self._link_draft_turn_key(chat_id, metadata)
        active = self._link_active_drafts.get(key)
        if active is not None:
            self._link_active_drafts.move_to_end(key)
        return active

    def _finish_link_draft(
        self,
        chat_id: str,
        metadata: Dict[str, Any],
        draft_key: tuple[str, int],
    ) -> None:
        turn_key = self._link_draft_turn_key(chat_id, metadata)
        self._link_active_drafts.pop(turn_key, None)
        self._link_draft_sent_at.pop(turn_key, None)
        self._link_draft_messages.pop(draft_key, None)

    def _trim_link_draft_identities(self) -> None:
        while len(self._link_draft_messages) > _MAX_LINK_DRAFT_IDENTITIES:
            stale_key, _ = self._link_draft_messages.popitem(last=False)
            for turn_key, active in tuple(self._link_active_drafts.items()):
                if active[0] == stale_key:
                    self._link_active_drafts.pop(turn_key, None)
                    self._link_draft_sent_at.pop(turn_key, None)
        while len(self._link_active_drafts) > _MAX_LINK_DRAFT_IDENTITIES:
            turn_key, active = self._link_active_drafts.popitem(last=False)
            self._link_draft_sent_at.pop(turn_key, None)
            self._link_draft_messages.pop(active[0], None)

    async def send_model_picker(
        self,
        chat_id: str,
        providers: list,
        current_model: str,
        current_provider: str,
        session_key: str,
        on_model_selected,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        del session_key, metadata
        if self.link_client is None:
            return SendResult(success=False, error="Loopdy Link is not connected")
        pending = self._take_pending_picker(
            request_id=_picker_request_id.get(),
            session_id=str(chat_id),
            kind="model",
        )
        if pending is None:
            return SendResult(success=False, error="No active Loopdy model request")
        try:
            payload = model_picker_payload(
                picker_id=pending.request.request_id,
                session_id=pending.request.session_id,
                current_model=current_model,
                current_provider=current_provider,
                providers=providers,
                sent_at=int(time.time()),
            )
            allowed = frozenset(
                (row["id"], model)
                for row in payload["providers"]
                for model in row["models"]
            )
            self._remember_picker(
                _ActivePicker(
                    picker_id=pending.request.request_id,
                    session_id=pending.request.session_id,
                    kind="model",
                    sender_device_id=pending.sender_device_id,
                    callback=on_model_selected,
                    allowed_models=allowed,
                    allowed_values=frozenset(),
                    expires_at=time.monotonic() + 600,
                )
            )
            await self._send_link_payload(payload)
            return SendResult(success=True, message_id=pending.request.request_id)
        except Exception as exc:
            self._active_pickers.pop(pending.request.request_id, None)
            await self._send_picker_open_failure(
                pending.request,
                "Hermes could not open this model picker. Try again.",
            )
            return SendResult(
                success=False,
                error=f"Loopdy model picker failed ({type(exc).__name__})",
            )

    async def send_choice_picker(
        self,
        chat_id: str,
        title: str,
        choices: list,
        session_key: str,
        on_choice_selected,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        del session_key, metadata
        if self.link_client is None:
            return SendResult(success=False, error="Loopdy Link is not connected")
        pending = self._take_pending_picker(
            request_id=_picker_request_id.get(),
            session_id=str(chat_id),
            kind="reasoning",
        )
        if pending is None:
            return SendResult(success=False, error="No active Loopdy reasoning request")
        try:
            payload = choice_picker_payload(
                picker_id=pending.request.request_id,
                session_id=pending.request.session_id,
                title=title,
                choices=choices,
                sent_at=int(time.time()),
            )
            self._remember_picker(
                _ActivePicker(
                    picker_id=pending.request.request_id,
                    session_id=pending.request.session_id,
                    kind="reasoning",
                    sender_device_id=pending.sender_device_id,
                    callback=on_choice_selected,
                    allowed_models=frozenset(),
                    allowed_values=frozenset(row["value"] for row in payload["choices"]),
                    expires_at=time.monotonic() + 600,
                )
            )
            await self._send_link_payload(payload)
            return SendResult(success=True, message_id=pending.request.request_id)
        except Exception as exc:
            self._active_pickers.pop(pending.request.request_id, None)
            await self._send_picker_open_failure(
                pending.request,
                "Hermes could not open this reasoning picker. Try again.",
            )
            return SendResult(
                success=False,
                error=f"Loopdy reasoning picker failed ({type(exc).__name__})",
            )

    async def receive_link_turn(self, turn: InboundLinkTurn) -> None:
        self._remember_verified_link_profile(
            turn.message.session_id,
            turn.message.agent_id,
        )
        source = self.build_source(
            chat_id=turn.message.session_id,
            chat_name="Loopdy chat",
            chat_type="dm",
            user_id=turn.sender_id,
            user_name=turn.message.actor_name,
            message_id=turn.message.message_id,
        )
        source.profile = turn.message.agent_id
        execution_context = _verified_tool_execution_context(self.link_client, turn)
        event = MessageEvent(
            text=turn.message.text,
            source=source,
            message_id=turn.message.message_id,
            media_urls=list(turn.attachment_paths),
            media_types=list(turn.attachment_types),
            metadata={
                "loopdy_link_verified": True,
                **(
                    {"loopdy_link_behavior": turn.message.behavior}
                    if turn.message.behavior is not None
                    else {}
                ),
            },
            **(
                {"tool_execution_context": execution_context}
                if execution_context is not None else {}
            ),
        )
        await self._materialize_pending_link_session_workspace(
            turn.message.agent_id,
            turn.message.session_id,
            source,
        )
        behavior = turn.message.behavior
        if (
            behavior is None
            or self._has_pending_link_intercept(source)
            or self._has_registered_command(event.text)
        ):
            await self.handle_message(event)
            # Safe/bypass slash commands need not enter background processing,
            # so they do not necessarily reach on_processing_complete.
            await self._refresh_goal_for_source(source)
            return

        if behavior == "steer" and (event.media_urls or event.media_types):
            # Hermes' official /steer control carries text only. Preserve Link
            # attachments by using Hermes' official FIFO /queue fallback.
            behavior = "queue"

        if behavior == "steer":
            event.text = f"/steer {event.text}"
            await self.handle_message(event)
            return

        if behavior == "queue":
            event.text = f"/queue {event.text}"
            await self.handle_message(event)
            return

        session_key = self._link_session_key(source)
        if session_key in self._active_sessions:
            self._heal_stale_session_lock(session_key)
        if session_key not in self._active_sessions:
            # An idle session has nothing to interrupt. Submit the original
            # event normally so first-turn semantics and attachments stay
            # byte-for-byte equivalent to an ordinary Link send.
            await self.handle_message(event)
            return

        stop_event = MessageEvent(
            text="/stop",
            source=source,
            metadata={
                "loopdy_link_verified": True,
                "loopdy_link_behavior": "interrupt",
                "loopdy_link_control": True,
            },
        )
        token = _suppress_link_control_ephemeral.set(True)
        try:
            # BasePlatformAdapter's interrupt_then_dispatch path does not
            # return until Hermes has handled /stop, cancelled the old owner,
            # released its command guard, and drained any pending handoff.
            await self.handle_message(stop_event)
        finally:
            _suppress_link_control_ephemeral.reset(token)
        await self.handle_message(event)

    async def on_processing_complete(
        self,
        event: MessageEvent,
        outcome: ProcessingOutcome,
    ) -> None:
        try:
            await super().on_processing_complete(event, outcome)
        finally:
            # BasePlatformAdapter.handle_message() returns after scheduling
            # Hermes' background work. Link media must therefore outlive the
            # inbound callback and remain readable until this authoritative
            # processing-complete lifecycle hook runs.
            if (event.metadata or {}).get("loopdy_link_verified"):
                release = getattr(self.link_client, "release_attachment_paths", None)
                if callable(release) and event.media_urls:
                    release(tuple(event.media_urls))
            # Runs after the goal judge. The text/outcome are never verdicts.
            # Release attachments first even if this readback is cancelled.
            if event.source is not None:
                await self._refresh_goal_for_source(event.source)

    def _link_session_key(self, source: SessionSource) -> str:
        return build_session_key(
            source,
            group_sessions_per_user=self.config.extra.get(
                "group_sessions_per_user", True
            ),
            thread_sessions_per_user=self.config.extra.get(
                "thread_sessions_per_user", False
            ),
            profile=self._session_key_profile(source),
        )

    def _is_link_session_active(
        self,
        agent_id: str,
        session_id: str,
        _stored_id: str,
    ) -> bool:
        """Reconcile persisted catalog activity with the live Hermes owner."""
        source = self.build_source(
            chat_id=session_id,
            chat_name="Loopdy chat",
            chat_type="dm",
            user_id="loopdy-session-state",
            user_name="Loopdy",
            message_id="loopdy-session-state-refresh",
        )
        source.profile = agent_id
        session_key = self._link_session_key(source)
        if session_key in self._active_sessions:
            self._heal_stale_session_lock(session_key)
        return session_key in self._active_sessions

    def _has_pending_link_intercept(self, source: SessionSource) -> bool:
        """Keep Hermes approval/clarification replies on the normal text path."""
        session_key = self._link_session_key(source)
        try:
            from tools.approval import has_blocking_approval

            if has_blocking_approval(session_key):
                return True
        except Exception:
            # Fail safe: a behavior prefix would prevent Hermes' normal
            # plaintext approval routing from seeing the reply.
            return True
        try:
            from tools.clarify_gateway import get_pending_for_session

            return (
                get_pending_for_session(
                    session_key,
                    include_choice_prompts=True,
                )
                is not None
            )
        except Exception:
            # Fail safe for the same reason: never hide a possible clarify
            # response behind /steer or /queue when inspection is unavailable.
            return True

    @staticmethod
    def _has_registered_command(text: str) -> bool:
        """Let Hermes own every registered command's active-turn behavior."""
        token = text.split(None, 1)[0] if text else ""
        if not token.startswith("/"):
            return False
        try:
            from hermes_cli.commands import should_bypass_active_session

            return should_bypass_active_session(token[1:].lower())
        except Exception:
            return False

    def _unwrap_ephemeral(self, response: Any) -> tuple[Optional[str], int]:
        if _suppress_link_control_ephemeral.get() and isinstance(
            response, EphemeralReply
        ):
            return None, 0
        return super()._unwrap_ephemeral(response)

    def _remember_verified_link_profile(self, session_id: str, profile: str) -> None:
        resolved_profile = _profile_coordinate(profile)
        if not _is_link_chat_id(session_id) or not resolved_profile:
            raise ValueError("Loopdy Link session profile is invalid")
        existing = self._link_session_profiles.get(session_id)
        if existing is not None and existing != resolved_profile:
            raise ValueError("Loopdy Link session cannot change agents")
        self._link_session_profiles.pop(session_id, None)
        self._link_session_profiles[session_id] = resolved_profile
        while len(self._link_session_profiles) > _MAX_LINK_SESSION_PROFILE_BINDINGS:
            self._link_session_profiles.popitem(last=False)

    async def _set_link_session_workspace(
        self,
        agent_id: str,
        session_id: str,
        cwd: str,
    ) -> None:
        """Bind one verified Link chat to a Hermes-owned project directory."""
        self._remember_verified_link_profile(session_id, agent_id)
        session_store = getattr(self, "_session_store", None)
        if session_store is None:
            raise RuntimeError("Hermes session storage is unavailable")

        from hermes_cli.profiles import get_profile_dir, profile_exists
        from hermes_constants import (
            reset_hermes_home_override,
            set_hermes_home_override,
        )
        from tools.terminal_tool import register_task_env_overrides

        if not profile_exists(agent_id):
            raise ValueError("The selected agent is unavailable")
        source = self.build_source(
            chat_id=session_id,
            chat_name="Loopdy chat",
            chat_type="dm",
        )
        source.profile = agent_id

        token = set_hermes_home_override(get_profile_dir(agent_id))
        try:
            session_key = self._link_session_key(source)
            lookup = getattr(session_store, "lookup_by_session_key", None)
            entry = await asyncio.to_thread(lookup, session_key) if callable(lookup) else None
            workspace_override = {"cwd": cwd, "cwd_source": "project"}
            if entry is None:
                # Match session.create {cwd}: seed the live routing coordinate
                # without materializing an empty persisted conversation.
                register_task_env_overrides(session_key, workspace_override)
            else:
                session_db = getattr(session_store, "_db", None)
                if session_db is None:
                    raise RuntimeError("Hermes session database is unavailable")
                generation = await asyncio.to_thread(
                    session_db.update_session_cwd,
                    entry.session_id,
                    cwd,
                    replace_git_meta=True,
                )
                if (
                    isinstance(generation, bool)
                    or not isinstance(generation, int)
                    or generation < 1
                ):
                    raise RuntimeError("Hermes did not persist the session workspace")
                register_task_env_overrides(session_key, workspace_override)
                register_task_env_overrides(entry.session_id, workspace_override)
        finally:
            reset_hermes_home_override(token)

        workspace_key = (agent_id, session_id)
        if entry is None:
            self._link_session_workspaces.pop(workspace_key, None)
            self._link_session_workspaces[workspace_key] = cwd
            while len(self._link_session_workspaces) > _MAX_LINK_SESSION_PROFILE_BINDINGS:
                self._link_session_workspaces.popitem(last=False)
        else:
            self._link_session_workspaces.pop(workspace_key, None)
            runner = getattr(self, "gateway_runner", None)
            evict = getattr(runner, "_evict_cached_agent", None)
            if callable(evict):
                evict(entry.session_key)

    async def _materialize_pending_link_session_workspace(
        self,
        agent_id: str,
        session_id: str,
        source: SessionSource,
    ) -> None:
        workspace_key = (agent_id, session_id)
        cwd = self._link_session_workspaces.get(workspace_key)
        if cwd is None:
            return

        session_store = getattr(self, "_session_store", None)
        create = getattr(session_store, "get_or_create_session", None)
        session_db = getattr(session_store, "_db", None)
        if not callable(create) or session_db is None:
            raise RuntimeError("Hermes session storage is unavailable")

        from hermes_cli.profiles import get_profile_dir, profile_exists
        from hermes_constants import (
            reset_hermes_home_override,
            set_hermes_home_override,
        )
        from tools.terminal_tool import register_task_env_overrides

        if not profile_exists(agent_id):
            raise ValueError("The selected agent is unavailable")
        token = set_hermes_home_override(get_profile_dir(agent_id))
        try:
            entry = await asyncio.to_thread(create, source)
            generation = await asyncio.to_thread(
                session_db.update_session_cwd,
                entry.session_id,
                cwd,
                replace_git_meta=True,
            )
            if (
                isinstance(generation, bool)
                or not isinstance(generation, int)
                or generation < 1
            ):
                raise RuntimeError("Hermes did not persist the session workspace")
            workspace_override = {"cwd": cwd, "cwd_source": "project"}
            register_task_env_overrides(entry.session_key, workspace_override)
            register_task_env_overrides(entry.session_id, workspace_override)
        finally:
            reset_hermes_home_override(token)

        if self._link_session_workspaces.get(workspace_key) == cwd:
            self._link_session_workspaces.pop(workspace_key, None)
        runner = getattr(self, "gateway_runner", None)
        evict = getattr(runner, "_evict_cached_agent", None)
        if callable(evict):
            evict(entry.session_key)

    def _link_workspace_connection_id(self) -> str:
        """Return the authenticated Link sender for the current request only."""

        connection_id = _link_workspace_connection.get()
        if not connection_id:
            raise RuntimeError("Loopdy Link connection identity is unavailable")
        return connection_id

    async def _get_link_session_workspace(
        self,
        agent_id: str,
        session_id: str,
    ) -> str | None:
        """Read the exact Hermes session cwd without creating another session."""

        session_store = getattr(self, "_session_store", None)
        if session_store is None:
            raise RuntimeError("Hermes session storage is unavailable")
        source = self.build_source(
            chat_id=session_id,
            chat_name="Loopdy chat",
            chat_type="dm",
        )
        source.profile = agent_id
        session_key = self._link_session_key(source)

        def load() -> str:
            from hermes_cli.profiles import get_profile_dir, profile_exists
            from hermes_constants import (
                reset_hermes_home_override,
                set_hermes_home_override,
            )

            if not profile_exists(agent_id):
                raise RuntimeError("The selected agent is unavailable")
            token = set_hermes_home_override(get_profile_dir(agent_id))
            try:
                lookup = getattr(session_store, "lookup_by_session_key", None)
                entry = lookup(session_key) if callable(lookup) else None
                if entry is None:
                    return self._link_session_workspaces.get((agent_id, session_id))
                origin = getattr(entry, "origin", None)
                if (
                    getattr(getattr(entry, "platform", None), "value", None)
                    != "loopdy"
                    or getattr(getattr(origin, "platform", None), "value", None)
                    != "loopdy"
                    or getattr(origin, "chat_id", None) != session_id
                    or getattr(origin, "profile", None) != agent_id
                ):
                    raise RuntimeError("Hermes session ownership is unavailable")
                session_db = getattr(session_store, "_db", None)
                getter = getattr(session_db, "get_session", None)
                row = getter(entry.session_id) if callable(getter) else None
                cwd = row.get("cwd") if isinstance(row, dict) else None
                if not isinstance(cwd, str) or not cwd.strip():
                    pending = self._link_session_workspaces.get((agent_id, session_id))
                    if pending is not None:
                        return pending
                    raise RuntimeError("Hermes session workspace is unavailable")
                return cwd
            finally:
                reset_hermes_home_override(token)

        return await asyncio.to_thread(load)

    def _link_response_profile(
        self,
        session_id: str,
        metadata: Dict[str, Any],
    ) -> str:
        explicit = _profile_coordinate(
            metadata.get("profile") or metadata.get("profile_name")
        )
        verified = self._link_session_profiles.get(session_id, "")
        if explicit and verified and explicit != verified:
            raise ValueError("Loopdy Link response agent does not match its session")
        return explicit or verified or _active_profile_id()

    async def _workspace_history_context(
        self, request: WorkspaceRequest, result: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Read current context only after profile-scoped history succeeded.

        The controller resolves visible aliases through its authorized catalog;
        only its returned storedId is a provider coordinate. The wire snapshot
        retains the requested coordinate, not that internal alias resolution.
        """
        try:
            requested = _session_coordinate(request.payload.get("storedId"))
        except ValueError:
            return None
        envelope = {"sessionId": requested, "available": False, "snapshot": None}
        agent_id = request.payload.get("agentId")
        if not isinstance(agent_id, str) or not agent_id or result.get("agentId") != agent_id:
            return envelope
        try:
            stored_id = _session_coordinate(result.get("storedId"))
            # A known live binding must agree with the successful controller.
            for coordinate in (requested, stored_id):
                bound = self._link_session_profiles.get(coordinate)
                if bound is not None and bound != agent_id:
                    return envelope
            current = await asyncio.to_thread(self._context_window_snapshot, stored_id)
            if not isinstance(current, dict):
                return envelope
            snapshot = session_context(
                session_id=requested,
                model=current["model"],
                context_used=current["contextUsed"],
                context_max=current["contextMax"],
                context_percent=current["contextPercent"],
                compressions=current["compressions"],
                is_compacting=current["isCompacting"],
                updated_at=current.get("updatedAt", int(time.time())),
                title=current.get("title"),
                input_tokens=current.get("inputTokens"),
                output_tokens=current.get("outputTokens"),
                cached_tokens=current.get("cachedTokens"),
                total_tokens=current.get("totalTokens"),
            )
        except Exception:
            # Provider absence/failure is not a failed history load. Never log
            # payloads or exception text from this optional private boundary.
            return envelope
        return {"sessionId": requested, "available": True, "snapshot": snapshot}

    async def receive_link_payload(
        self,
        payload: (
            InboundLinkTurn
            | InboundLinkRelayReady
            | InboundLinkVoiceSpeak
            | InboundLinkPickerOpen
            | InboundLinkPickerSelection
            | InboundLinkSessionFork
            | InboundLinkCommandCatalog
            | InboundLinkPersonalityRequest
            | InboundLinkGenerativeUIFormSubmission
            | InboundLinkWorkspaceRequest
            | InboundLinkDeviceToolResult
            | InboundLinkDeviceToolStatus
        ),
    ) -> None:
        if isinstance(payload, InboundLinkWorkspaceRequest):
            request = payload.request
            # Opt in only via the existing read-only operation; the v1 envelope
            # and controller operation permissions are unchanged.
            if (request.operation == "agents.list"
                    and type(request.payload.get("linkProtocol")) is int
                    and request.payload["linkProtocol"] == 1):
                request = replace(request, payload={
                    key: value for key, value in request.payload.items()
                    if key != "linkProtocol"
                })
                self._link_metadata_devices[payload.sender_device_id] = None
            negotiated = payload.sender_device_id in self._link_metadata_devices
            if negotiated:
                self._link_metadata_devices.move_to_end(payload.sender_device_id)
            while len(self._link_metadata_devices) > _MAX_LINK_METADATA_DEVICES:
                self._link_metadata_devices.popitem(last=False)
            connection_token = _link_workspace_connection.set(
                payload.sender_device_id
            )
            try:
                if self.workspace_controller is None:
                    raise RuntimeError("Workspace controls are unavailable")
                if request.operation.startswith("wiki."):
                    from .wiki_transport import WikiRequestContext
                    wiki_context = WikiRequestContext(
                        target_host_id=payload.target_host_id,
                        device_id=payload.sender_device_id,
                        authority_id=payload.authority_id,
                        sender_epoch=payload.sender_epoch,
                    )
                    result_payload = await self.workspace_controller.execute(request, wiki_context=wiki_context)
                else:
                    result_payload = await self.workspace_controller.execute(request)
                result = workspace_result(
                    request=payload.request,
                    status="completed",
                    payload=result_payload,
                    sent_at=int(time.time()),
                )
            except WorkspaceControlError as exc:
                result = workspace_result(
                    request=payload.request,
                    status=exc.status,
                    payload={},
                    code=exc.code,
                    message=str(exc),
                    sent_at=int(time.time()),
                )
            except ValueError:
                result = workspace_result(
                    request=payload.request,
                    status="conflict",
                    payload={},
                    code="workspace_conflict",
                    message="The workspace changed. Refresh and try again.",
                    sent_at=int(time.time()),
                )
            except Exception:
                result = workspace_result(
                    request=payload.request,
                    status="failed",
                    payload={},
                    code="workspace_unavailable",
                    message="Hermes could not complete this workspace request.",
                    sent_at=int(time.time()),
                )
            finally:
                _link_workspace_connection.reset(connection_token)
            if negotiated:
                result["capabilities"] = workspace_capabilities()
                if result["status"] == "completed" and request.operation == "sessions.history":
                    context = await self._workspace_history_context(request, result["payload"])
                    if context is not None:
                        result["context"] = context
            if self.link_client is not None:
                if request.operation.startswith("wiki."):
                    from .wiki_service import WikiServiceError
                    from .wiki_transport import authority_id
                    response_client = self.link_client
                    def check_response_owner():
                        if (self.link_client is not response_client
                                or authority_id(self._wiki_current_config()) != payload.authority_id):
                            raise WikiServiceError("WIKI_OWNER_CHANGED", "Wiki response owner changed")
                    await self._send_link_payload(result, owner_check=check_response_owner)
                else:
                    await self._send_link_payload(result)
                manager = getattr(getattr(self.workspace_controller, "backend", None), "plugin_update_manager", None)
                if (manager is not None and result["status"] == "completed"
                        and request.operation != "host_runtime.status"):
                    try:
                        await asyncio.to_thread(manager.record_link_response, payload.sender_device_id)
                    except Exception:
                        # Optional update bookkeeping cannot break workspace delivery.
                        pass
            return
        if isinstance(payload, InboundLinkDeviceToolStatus):
            bridge = self.device_tool_bridge
            if bridge is not None:
                bridge.accept_status(
                    payload.status,
                    sender_device_id=payload.sender_device_id,
                    sender_epoch=payload.sender_epoch,
                    target_device_id=payload.target_device_id,
                )
            return
        if isinstance(payload, InboundLinkDeviceToolResult):
            bridge = self.device_tool_bridge
            if bridge is not None:
                bridge.accept_result(
                    payload.result,
                    sender_device_id=payload.sender_device_id,
                    sender_epoch=payload.sender_epoch,
                    target_device_id=payload.target_device_id,
                )
            return
        if isinstance(payload, InboundLinkGenerativeUIFormSubmission):
            response = await asyncio.to_thread(
                self._submit_generative_ui_form,
                payload.request,
            )
            if self.link_client is not None:
                await self._send_link_payload(
                    generative_ui_form_result(
                        request=payload.request,
                        state=response["state"],
                        code=response["code"],
                        message=response["message"],
                        sent_at=int(time.time()),
                    )
                )
            return
        if isinstance(payload, InboundLinkPersonalityRequest):
            catalog = await asyncio.to_thread(
                self.personality_manager.mutate,
                payload.request,
            )
            if self.link_client is not None:
                await self._send_link_payload(
                    personality_catalog_payload(
                        request_id=payload.request.request_id,
                        catalog=catalog,
                        sent_at=int(time.time()),
                    )
                )
            return
        if isinstance(payload, InboundLinkCommandCatalog):
            commands = await self._build_link_command_catalog(payload.request)
            if self.link_client is not None:
                await self._send_link_payload(
                    command_catalog_payload(
                        request=payload.request,
                        commands=commands,
                        sent_at=int(time.time()),
                    )
                )
            return
        if isinstance(payload, InboundLinkSessionFork):
            try:
                result = await self._fork_link_session(payload)
            except ValueError as exc:
                result = session_fork_result(
                    request=payload.request,
                    status="conflict",
                    title=payload.request.title,
                    message=str(exc)[:2_000] or "The checkpoint changed. Try again.",
                    sent_at=int(time.time()),
                )
            except Exception:
                result = session_fork_result(
                    request=payload.request,
                    status="failed",
                    title=payload.request.title,
                    message="Hermes could not create this fork. Try again.",
                    sent_at=int(time.time()),
                )
            if self.link_client is not None:
                await self._send_link_payload(result)
            return
        if isinstance(payload, InboundLinkPickerOpen):
            await self._receive_picker_open(payload)
            return
        if isinstance(payload, InboundLinkPickerSelection):
            await self._receive_picker_selection(payload)
            return
        if isinstance(payload, InboundLinkVoiceSpeak):
            task = asyncio.create_task(
                self._serve_voice_request(payload.request),
                name=f"loopdy-voice-{payload.request.request_id}",
            )
            self._voice_tasks.add(task)
            task.add_done_callback(self._voice_tasks.discard)
            return
        if isinstance(payload, InboundLinkRelayReady):
            # Link APNs is an account-scoped wake channel owned by the Link
            # service.  It must never be mistaken for this host's optional
            # notification-relay tenant.  Only an explicitly host-scoped
            # registration may enter the local relay delivery ledger.
            if payload.registration.scope == "host_relay":
                await asyncio.to_thread(
                    self.service.adopt_link_relay_device,
                    payload.registration,
                    sender_device_id=payload.sender_device_id,
                )
            return
        await self.receive_link_turn(payload)

    def _submit_generative_ui_form(self, request: Any) -> dict[str, Any]:
        """Validate a Link form only against the host-owned rendered schema."""
        try:
            stored = self.service.store.get_form_request(request.request_id)
            if stored is None:
                return form_action_response(
                    request.request_id,
                    request.idempotency_key,
                    "error",
                    "request_not_found",
                )
            if (
                stored.get("profile") != request.profile
                or stored.get("session_id") != request.session_id
            ):
                return form_action_response(
                    request.request_id,
                    request.idempotency_key,
                    "error",
                    "owner_mismatch",
                )
            values = validate_submission_values(
                stored.get("form_schema", {}),
                request.values,
            )
            return self.service.store.submit_form_request(
                request_id=request.request_id,
                profile=request.profile,
                session_id=request.session_id,
                idempotency_key=request.idempotency_key,
                values=values,
                now=int(time.time()),
            )
        except GenerativeUIError:
            return form_action_response(
                request.request_id,
                request.idempotency_key,
                "error",
                "invalid_value",
            )
        except Exception:
            return form_action_response(
                request.request_id,
                request.idempotency_key,
                "error",
                "internal_error",
            )

    async def _build_link_command_catalog(
        self, request: CommandCatalogRequest
    ) -> list[dict[str, Any]]:
        from gateway.run import _profile_runtime_scope
        from hermes_cli.profiles import get_profile_dir, profile_exists

        if not profile_exists(request.agent_id):
            raise ValueError("The selected agent is unavailable")

        def load() -> list[dict[str, Any]]:
            from agent.skill_commands import get_skill_commands
            from agent.skill_utils import get_disabled_skill_names
            from cli import load_cli_config
            from hermes_cli.plugins import get_plugin_commands

            from .command_catalog import build_command_catalog

            skills = get_skill_commands()
            disabled = get_disabled_skill_names(platform="loopdy")
            filtered_skills = {
                key: value
                for key, value in skills.items()
                if not isinstance(value, dict)
                or value.get("name") not in disabled
            }
            config = load_cli_config()
            quick_commands = (
                config.get("quick_commands", {})
                if isinstance(config, dict)
                else {}
            )
            return build_command_catalog(
                plugin_commands=get_plugin_commands(),
                skill_commands=filtered_skills,
                quick_commands=quick_commands,
            )

        with _profile_runtime_scope(get_profile_dir(request.agent_id)):
            return await asyncio.to_thread(load)

    async def _fork_link_session(
        self, inbound: InboundLinkSessionFork
    ) -> dict[str, Any]:
        request = inbound.request
        from gateway.run import _profile_runtime_scope
        from hermes_cli.profiles import get_profile_dir, profile_exists

        if not profile_exists(request.agent_id):
            raise ValueError("The selected agent is unavailable")
        with _profile_runtime_scope(get_profile_dir(request.agent_id)):
            source = self.build_source(
                chat_id=request.source_session_id,
                chat_name="Loopdy chat",
                chat_type="dm",
                user_id=inbound.sender_id,
                user_name=request.actor_name,
                message_id=request.request_id,
            )
            source.profile = request.agent_id
            source_entry = await self.async_session_store.get_or_create_session(
                source, touch_activity=False
            )
            history = await self.async_session_store.load_transcript(
                source_entry.session_id
            )
            prefix = verified_fork_prefix(history, request)

            target = self.build_source(
                chat_id=request.fork_session_id,
                chat_name="Loopdy chat",
                chat_type="dm",
                user_id=inbound.sender_id,
                user_name=request.actor_name,
                message_id=request.request_id,
            )
            target.profile = request.agent_id
            target_entry = await self.async_session_store.get_or_create_session(
                target, touch_activity=False
            )
            if target_entry.session_id == source_entry.session_id:
                raise ValueError("The fork coordinate already exists")
            existing = await self.async_session_store.load_transcript(
                target_entry.session_id
            )
            if existing:
                raise ValueError("The fork coordinate already exists")
            written = await self.async_session_store.rewrite_transcript(
                target_entry.session_id,
                prefix,
                reject_active_turn_lease=True,
            )
            if written is False:
                raise RuntimeError("Hermes did not persist the fork")

            db = getattr(self, "_session_db", None)
            if db is not None:
                source_row = await asyncio.to_thread(
                    db.get_session, source_entry.session_id
                )
                await asyncio.to_thread(
                    db.create_session,
                    target_entry.session_id,
                    "loopdy",
                    model=(source_row or {}).get("model"),
                    system_prompt=(source_row or {}).get("system_prompt"),
                    parent_session_id=source_entry.session_id,
                )
                await asyncio.to_thread(
                    db.set_session_title, target_entry.session_id, request.title
                )
        return session_fork_result(
            request=request,
            status="completed",
            title=request.title,
            message="Fork ready.",
            sent_at=int(time.time()),
        )

    async def _receive_picker_open(self, inbound: InboundLinkPickerOpen) -> None:
        self._clean_picker_state()
        request = inbound.request
        self._pending_picker_requests[request.request_id] = _PendingPickerRequest(
            request=request,
            sender_device_id=inbound.sender_device_id,
            expires_at=time.monotonic() + 60,
        )
        source = self.build_source(
            chat_id=request.session_id,
            chat_name="Loopdy chat",
            chat_type="dm",
            user_id="loopdy_link_control",
            user_name="Loopdy user",
            message_id=request.request_id,
        )
        source.profile = request.agent_id
        # Picker opens are control-plane requests from an already verified
        # Link device.  Dispatch them through Hermes' installed message
        # handler so the canonical slash-command implementation builds the
        # native picker, but do not send the handler's return value through
        # BasePlatformAdapter.handle_message().  The latter treats every
        # non-empty return as a user-visible chat response; when the picker
        # cannot be built it would leak Hermes' textual provider listing into
        # the session and occupy the current turn.
        event = MessageEvent(
            text="/model" if request.kind == "model" else "/reasoning",
            source=source,
            message_id=request.request_id,
            metadata={
                "loopdy_link_verified": True,
                "loopdy_link_control": True,
            },
        )
        handler = getattr(self, "_message_handler", None)
        if not callable(handler):
            self._pending_picker_requests.pop(request.request_id, None)
            await self._send_picker_open_failure(
                request,
                "Hermes could not open this picker because its message handler is unavailable.",
            )
            return
        try:
            token = _picker_request_id.set(request.request_id)
            try:
                result = handler(event)
                if inspect.isawaitable(result):
                    await result
            finally:
                _picker_request_id.reset(token)
        except Exception:
            # The native picker is best effort.  Its control response must
            # never become a normal assistant message or interrupt a chat.
            self._pending_picker_requests.pop(request.request_id, None)
            await self._send_picker_open_failure(
                request,
                "Hermes could not open this picker. Try again.",
            )
            return
        if self._pending_picker_requests.pop(request.request_id, None) is not None:
            await self._send_picker_open_failure(
                request,
                "Hermes completed this request without opening a native picker. Try again.",
            )

    async def _send_picker_open_failure(
        self, request: PickerOpen, message: str
    ) -> None:
        """Complete a failed picker-open request on the same control channel."""
        if self.link_client is None:
            return
        try:
            await self._send_link_payload(
                picker_result(
                    picker_id=request.request_id,
                    session_id=request.session_id,
                    kind=request.kind,
                    status="failed",
                    message=message,
                    sent_at=int(time.time()),
                )
            )
        except Exception:
            return

    async def _receive_picker_selection(
        self, inbound: InboundLinkPickerSelection
    ) -> None:
        self._clean_picker_state()
        selection = inbound.selection
        state = self._active_pickers.get(selection.picker_id)
        valid = bool(
            state is not None
            and state.session_id == selection.session_id
            and state.kind == selection.kind
            and state.sender_device_id == inbound.sender_device_id
            and (
                (selection.provider, selection.model) in state.allowed_models
                if selection.kind == "model"
                else selection.value in state.allowed_values
            )
        )
        if not valid or state is None:
            await self._send_picker_result(
                selection=selection,
                status="failed",
                message="This control is no longer available. Open it again to continue.",
            )
            return
        self._active_pickers.pop(selection.picker_id, None)
        try:
            if selection.kind == "model":
                result = state.callback(
                    selection.session_id, selection.model, selection.provider
                )
            else:
                result = state.callback(selection.session_id, selection.value)
            if inspect.isawaitable(result):
                result = await result
            message = str(result or "Updated for this session.")
            status = "completed"
        except Exception:
            message = "Hermes could not update this session. Open the control and try again."
            status = "failed"
        await self._send_picker_result(
            selection=selection,
            status=status,
            message=message,
        )

    async def _send_picker_result(
        self,
        *,
        selection: PickerSelection,
        status: str,
        message: str,
    ) -> None:
        if self.link_client is None:
            return
        try:
            await self._send_link_payload(
                picker_result(
                    picker_id=selection.picker_id,
                    session_id=selection.session_id,
                    kind=selection.kind,
                    status=status,
                    message=message[:2_000] or "The control could not be updated.",
                    sent_at=int(time.time()),
                )
            )
        except Exception:
            return

    def _take_pending_picker(
        self, request_id: str, session_id: str, kind: str
    ) -> _PendingPickerRequest | None:
        self._clean_picker_state()
        if not request_id:
            return None
        pending = self._pending_picker_requests.get(request_id)
        if pending is None:
            return None
        if pending.request.session_id != session_id or pending.request.kind != kind:
            return None
        return self._pending_picker_requests.pop(request_id, None)

    def _remember_picker(self, state: _ActivePicker) -> None:
        self._clean_picker_state()
        if len(self._active_pickers) >= 64:
            oldest = min(self._active_pickers.values(), key=lambda item: item.expires_at)
            self._active_pickers.pop(oldest.picker_id, None)
        self._active_pickers[state.picker_id] = state

    def _clean_picker_state(self) -> None:
        now = time.monotonic()
        self._pending_picker_requests = {
            key: value
            for key, value in self._pending_picker_requests.items()
            if value.expires_at > now
        }
        self._active_pickers = {
            key: value
            for key, value in self._active_pickers.items()
            if value.expires_at > now
        }

    async def _serve_voice_request(self, request: VoiceSpeakRequest) -> None:
        if self.link_client is None:
            return
        try:
            result = await asyncio.to_thread(self.voice_synthesizer, request)
            payloads = voice_audio_chunks(
                request=request,
                audio=result.audio,
                mime_type=result.mime_type,
                provider=result.provider,
                sent_at=int(time.time()),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            code = "synthesis_failed"
            message = "The selected agent could not create speech right now."
            try:
                await self._send_link_payload(
                    voice_speak_error(
                        request=request,
                        code=code,
                        message=message,
                        sent_at=int(time.time()),
                    )
                )
            except Exception:
                pass
            return
        for payload in payloads:
            try:
                await self._send_link_payload(payload)
            except asyncio.CancelledError:
                raise
            except Exception:
                return


async def standalone_send(
    pconfig: PlatformConfig,
    chat_id: str,
    message: str,
    *,
    thread_id: str | None = None,
    media_files: list[str] | None = None,
    force_document: bool = False,
    service: LoopdyService | Any | None = None,
    link_state: Any | None = None,
    adapter_factory: Callable[..., LoopdyAdapter | Any] = LoopdyAdapter,
) -> dict[str, Any]:
    if media_files:
        return {"error": "Loopdy proactive notifications do not accept attachments"}
    del force_document
    target = str(
        chat_id
        or (getattr(pconfig, "extra", {}) or {}).get("home_target")
        or os.getenv("LOOPDY_HOME_TARGET", "all")
    ).strip()
    adapter = adapter_factory(
        pconfig,
        service=service or get_service(),
        link_state=link_state,
    )
    try:
        if not await adapter.connect():
            return {"error": "Loopdy Link is unavailable"}
        result = await adapter.send(
            target,
            message,
            metadata={"thread_id": thread_id} if thread_id else None,
        )
        if result.success:
            return {
                "success": True,
                "message_id": str(result.message_id or ""),
            }
        return {"error": str(result.error or "Loopdy delivery failed")}
    finally:
        await adapter.disconnect()


def check_requirements() -> bool:
    return True


def validate_config(_config: PlatformConfig) -> bool:
    try:
        link_ready = load_runtime_config() is not None
    except ValueError:
        link_ready = False
    return bool(link_ready or get_service().health().get("configured"))


def is_connected(config: PlatformConfig) -> bool:
    return bool(config.enabled and validate_config(config))


def env_enablement() -> dict[str, Any] | None:
    service = get_service()
    try:
        link_ready = load_runtime_config() is not None
    except ValueError:
        link_ready = False
    if not service.health().get("configured") and not link_ready:
        return None
    target = os.getenv("LOOPDY_HOME_TARGET", "all").strip() or "all"
    if validate_target(target) is not True:
        return None
    return {
        "home_target": target,
        "home_channel": {"chat_id": target, "name": "Loopdy"},
    }


def _is_link_chat_id(value: str) -> bool:
    chat_id = str(value or "")
    return (
        16 <= len(chat_id) <= 128
        and all(character.isalnum() or character in "_-" for character in chat_id)
        and chat_id not in {"all", "home"}
    )


def _channel_event(
    content: str, *, metadata: Optional[Dict[str, Any]], target: str = "all"
) -> Any:
    values = metadata or {}
    requested_type = str(values.get("event_type") or "")
    job_id = _text(values.get("job_id"), 180)
    kind = requested_type if requested_type in EVENT_TYPES else "channel.message"
    profile = (
        _text(values.get("profile") or values.get("profile_name"), 80)
        or _active_profile_id()
    )
    agent_name = _text(values.get("agent_name") or values.get("sender_name"), 80)
    if not agent_name:
        agent_name = profile_display_name(profile)
    message = _text(content, 50_000)
    detail: dict[str, Any] = {
        "message": message,
        **({"agent_name": agent_name} if agent_name else {}),
    }
    correlation: tuple[str, ...] = ()
    card_content = _channel_card_content(content, job_id=job_id)
    if card_content is not None:
        try:
            card = validate_rendered_envelope(parse_v2_json(card_content))
            detail["message"] = _text(card.get("title"), 120) or "Agent update"
            detail["generative_ui"] = card
            # Standalone cron fallback drops job metadata. Use the complete
            # validated card instance, including creation time, so both paths
            # retain one Inbox identity without hiding later identical updates.
            correlation = (
                "card-instance-v1", profile, target,
                json.dumps(card, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
            )
        except (GenerativeUIError, TypeError, ValueError):
            pass
    return build_event(
        kind,
        correlation=correlation,
        profile=profile,
        session_id=_text(values.get("session_id"), 180),
        job_id=job_id,
        detail=detail,
    )


def _channel_card_content(content: Any, *, job_id: str) -> str | None:
    """Return only a complete renderer envelope from an official send boundary.

    Hermes platform adapters receive final text, not tool-result metadata. Cron
    normally wraps that final text with its stable response header/footer and
    supplies the matching ``job_id`` in adapter metadata. Unwrap only that
    authenticated-by-correlation shape; renderer validation remains the final
    authority and every other value falls back to ordinary text.
    """
    if not isinstance(content, str):
        return None
    stripped = content.strip()
    if stripped.startswith("{"):
        return stripped
    if not job_id or not content.startswith("Cronjob Response: "):
        return None
    boundary = f"\n(job_id: {job_id})\n-------------\n\n"
    prefix, found, remainder = content.partition(boundary)
    if not found or not prefix.startswith("Cronjob Response: "):
        return None
    payload, footer, _ = remainder.partition(
        "\n\nTo stop or manage this job, send me a new message "
    )
    if not footer:
        return None
    candidate = payload.strip()
    return candidate if candidate.startswith("{") else None


def _active_profile_id() -> str:
    home = get_hermes_home()
    return home.name if home.parent.name == "profiles" else "default"


def profile_display_name(profile: str) -> str:
    home = get_hermes_home()
    if home.parent.name == "profiles" and home.name != profile:
        root = home.parent.parent
        home = root if profile == "default" else root / "profiles" / profile
    elif home.parent.name != "profiles" and profile != "default":
        home = home / "profiles" / profile
    try:
        import yaml

        value = (
            yaml.safe_load((home / "profile.yaml").read_text(encoding="utf-8"))
            or {}
        )
        ui_meta = value.get("ui_meta") if isinstance(value, dict) else {}
        display_name = (
            ui_meta.get("displayName")
            if isinstance(ui_meta, dict)
            else None
        ) or (value.get("display_name") if isinstance(value, dict) else None)
        resolved = _text(display_name, 80)
        if resolved:
            return resolved
    except Exception:
        pass
    return " ".join(
        part.capitalize()
        for part in profile.replace("-", "_").split("_")
        if part
    )


def _text(value: Any, maximum: int) -> str:
    return " ".join(value.split())[:maximum] if isinstance(value, str) else ""


def _profile_coordinate(value: Any) -> str:
    profile = str(value or "").strip()
    if not 1 <= len(profile) <= 96 or any(
        not (character.isalnum() or character in "_-") for character in profile
    ):
        return ""
    return profile


__all__ = [
    "LoopdyAdapter",
    "profile_display_name",
    "check_requirements",
    "env_enablement",
    "get_service",
    "is_connected",
    "parse_target",
    "release_service",
    "standalone_send",
    "validate_config",
    "validate_target",
]
