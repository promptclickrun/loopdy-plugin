"""Safe native HTTP identity; never a phone or model-turn authority."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import logging
import re
import time
import unicodedata
import uuid

from fastapi import Request

from .link_contracts import PLUGIN_VERSION


logger = logging.getLogger("hermes.plugins.loopdy")
RUNTIME_ID = uuid.uuid4().hex
PROFILE_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_startup_advertisement_logged = False


class NativeAPIError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message
        super().__init__(message)


def _identity_text(value: object, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Invalid identity")
    if len(value.encode("utf-8")) > maximum or any(
        unicodedata.category(character).startswith("C") for character in value
    ):
        raise ValueError("Invalid identity")
    return value


@dataclass(frozen=True)
class NativeContext:
    provider: str | None
    user_id: str | None
    display_name: str | None
    serving_profile_id: str | None
    features: tuple[str, ...]
    runtime_id: str

    def payload(self) -> dict:
        return {
            "schemaVersion": 1,
            "pluginVersion": PLUGIN_VERSION,
            "runtimeId": self.runtime_id,
            "servingProfileId": self.serving_profile_id,
            "principal": {
                "provider": self.provider,
                "userId": self.user_id,
                "displayName": self.display_name,
            } if self.provider is not None else None,
            "features": list(self.features),
        }

    @property
    def etag(self) -> str:
        encoded = json.dumps(self.payload(), ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
        return '"sha256:' + hashlib.sha256(encoded).hexdigest() + '"'


def log_native_feature_startup(profile: str | None = None) -> None:
    """Log the context API's process inventory once, after all registration.

    Wiki features require a request principal and are explicitly excluded.
    The registration profile is diagnostic only: the API's verified process
    profile, not a caller-supplied fallback, determines device availability.
    """
    global _startup_advertisement_logged
    if _startup_advertisement_logged:
        return
    _startup_advertisement_logged = True
    logger.info(
        "Loopdy request-dependent features excluded from the startup inventory: "
        "native-wiki-v1, native-wiki-disconnect-v1 (require a verified request "
        "principal, profile helpers, and available wiki operations).")
    skipped: list[tuple[str, str]] = []
    try:
        serving_profile, advertised = _native_features(None, skipped=skipped)
    except NativeAPIError as exc:
        logger.warning(
            "Loopdy native startup inventory unavailable: %s; "
            "the context API cannot advertise features.", exc.code)
        return
    except Exception as exc:
        # Diagnostics must not turn a failing capability probe into a plugin
        # registration failure. The request path retains its original errors.
        logger.warning(
            "Loopdy native startup inventory unavailable: capability probe "
            "failed (%s); no advertisement claimed.", type(exc).__name__)
        return
    if profile is not None and profile != serving_profile:
        logger.warning(
            "Loopdy registration profile %r differs from verified serving "
            "profile %r; startup inventory uses the serving profile.",
            profile, serving_profile)
    for feature, reason in skipped:
        logger.warning("Loopdy native feature %r NOT advertised: %s", feature, reason)
    logger.info(
        "Loopdy native features advertised at startup: %s",
        ", ".join(advertised))


def native_context(request: Request) -> NativeContext:
    try:
        from hermes_cli.dashboard_auth.base import Session
    except ImportError:
        raise NativeAPIError(401, "native_identity_required",
                             "A verified native interactive session is required.") from None
    session = getattr(request.state, "session", None)
    # Hermes authenticates EVERY mounted /api/plugins/* request before invoking
    # this router, either by dashboard session token or its provider middleware.
    # A dashboard-wide grant has no person identity; do not fabricate a Session.
    dashboard_mode = (getattr(request.app.state, "auth_required", None) is False
                      and not getattr(request.state, "token_authenticated", False)
                      and request.url.path.startswith("/api/plugins/loopdy/native/"))
    if dashboard_mode and session is None:
        provider = user_id = display_name = None
    else:
        if not isinstance(session, Session):
            raise NativeAPIError(401, "native_identity_required",
                                 "A verified Hermes session is required.")
        try:
            provider = _identity_text(session.provider, 128)
            user_id = _identity_text(session.user_id, 512)
            display_name = None if session.display_name in ("", None) else _identity_text(session.display_name, 200)
            if type(session.expires_at) is not int or session.expires_at <= time.time():
                raise ValueError("Expired identity")
        except (ValueError, UnicodeError):
            raise NativeAPIError(401, "native_identity_invalid",
                                 "The Hermes identity is invalid or expired.") from None

    profile, features = _native_features(provider)
    return NativeContext(provider, user_id, display_name, profile, features, RUNTIME_ID)


def _native_features(
    provider: str | None, *, skipped: list[tuple[str, str]] | None = None,
) -> tuple[str | None, tuple[str, ...]]:
    """Single source for API predicates/order and optional startup diagnostics."""
    def skip(feature: str, reason: str) -> None:
        if skipped is not None:
            skipped.append((feature, reason))

    profile = None
    features = ["native-context-v1"]
    try:
        from hermes_constants import get_process_hermes_home, profile_name_for_home
    except ImportError:
        # Older hosts cannot prove process profile; never infer "default".
        skip("serving-profile-v1", "process profile helpers are unimportable.")
    else:
        profile = profile_name_for_home(get_process_hermes_home())
        if profile is not None:
            if not isinstance(profile, str) or PROFILE_ID.fullmatch(profile) is None:
                raise NativeAPIError(503, "native_context_unavailable",
                                     "The serving profile could not be verified.")
            features.append("serving-profile-v1")
        else:
            skip("serving-profile-v1", "the process home has no verified serving profile.")
    try:
        from hermes_cli.profiles import profile_exists
        from hermes_constants import (
            get_process_hermes_home, set_hermes_home_override, reset_hermes_home_override,
        )
    except ImportError:
        # The routes fail closed when their public profile helpers are absent.
        skip("native-card-templates-v1", "public profile helpers are unimportable.")
        skip("native-voice-v1", "public profile helpers are unimportable.")
    else:
        if all(callable(function) for function in (
            profile_exists, get_process_hermes_home,
            set_hermes_home_override, reset_hermes_home_override,
        )):
            features.extend(("native-card-templates-v1", "native-voice-v1"))
        else:
            skip("native-card-templates-v1", "one or more public profile helpers are not callable.")
            skip("native-voice-v1", "one or more public profile helpers are not callable.")
    try:
        from .native_device_tools import (
            CAPABILITY as device_tools_capability,
            available as device_tools_available,
        )
        if profile is not None and device_tools_available(profile):
            features.append(device_tools_capability)
        else:
            skip(device_tools_capability,
                 "no unique lifecycle-owned middleware registration matches the "
                 "verified serving profile (missing profile/registration, "
                 "namespace/profile mismatch, or stale generations). "
                 "Restart `hermes serve` and check the middleware registration warnings.")
    except ImportError:
        skip("native-device-tools-v1", "native device-tool support is unimportable.")
    from .room_activity import CAPABILITY, activity_hub
    if activity_hub().available:
        features.append(CAPABILITY)
    else:
        skip(CAPABILITY, "the room activity hub is unavailable after registration.")
    from .wiki_contract import available_wiki_operations
    if provider is not None and "native-card-templates-v1" in features and available_wiki_operations():
        features.extend(("native-wiki-v1", "native-wiki-disconnect-v1"))
    from .native_project_git import CAPABILITY as project_git_capability, supported as project_git_supported
    if project_git_supported():
        features.append(project_git_capability)
    else:
        skip(project_git_capability, "the host does not support native project Git reads.")
    try:
        from .agent_templates import CAPABILITY as agent_templates_capability
        from .agent_templates import available as agent_templates_available
        if agent_templates_available():
            features.append(agent_templates_capability)
        else:
            skip(agent_templates_capability, "agent template availability checks failed.")
    except ImportError:
        skip("native-agent-templates-v1", "agent template support is unimportable.")
    try:
        from .workspace_artifacts import CAPABILITY as workspace_files_capability
        from .workspace_artifacts import available as workspace_files_available
        if workspace_files_available():
            features.append(workspace_files_capability)
        else:
            skip(workspace_files_capability, "workspace file availability checks failed.")
    except ImportError:
        skip("native-workspace-files-v1", "workspace file support is unimportable.")
    return profile, tuple(features)
