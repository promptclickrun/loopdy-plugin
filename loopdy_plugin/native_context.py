"""Safe native HTTP identity; never a phone or model-turn authority."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import time
import unicodedata
import uuid

from fastapi import Request

from .link_contracts import PLUGIN_VERSION


RUNTIME_ID = uuid.uuid4().hex
PROFILE_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")


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
    provider: str
    user_id: str
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
            },
            "features": list(self.features),
        }

    @property
    def etag(self) -> str:
        encoded = json.dumps(self.payload(), ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
        return '"sha256:' + hashlib.sha256(encoded).hexdigest() + '"'


def native_context(request: Request) -> NativeContext:
    try:
        from hermes_cli.dashboard_auth.base import Session
    except ImportError:
        raise NativeAPIError(401, "native_identity_required",
                             "A verified native interactive session is required.") from None
    session = getattr(request.state, "session", None)
    if not isinstance(session, Session):
        raise NativeAPIError(401, "native_identity_required",
                             "A verified native interactive session is required.")
    try:
        provider = _identity_text(session.provider, 128)
        user_id = _identity_text(session.user_id, 512)
        display_name = None if session.display_name in ("", None) else _identity_text(session.display_name, 200)
        if type(session.expires_at) is not int or session.expires_at <= time.time():
            raise ValueError("Expired identity")
    except (ValueError, UnicodeError):
        raise NativeAPIError(401, "native_identity_invalid",
                             "The native interactive identity is invalid or expired.") from None

    profile = None
    features = ["native-context-v1"]
    try:
        from hermes_constants import get_process_hermes_home, profile_name_for_home
    except ImportError:
        pass  # Older hosts cannot prove process profile; never infer "default".
    else:
        profile = profile_name_for_home(get_process_hermes_home())
        if profile is not None:
            if not isinstance(profile, str) or PROFILE_ID.fullmatch(profile) is None:
                raise NativeAPIError(503, "native_context_unavailable",
                                     "The serving profile could not be verified.")
            features.append("serving-profile-v1")
    try:
        from hermes_cli.profiles import profile_exists
        from hermes_constants import (
            get_process_hermes_home, set_hermes_home_override, reset_hermes_home_override,
        )
    except ImportError:
        pass  # The routes fail closed when their public profile helpers are absent.
    else:
        if all(callable(function) for function in (
            profile_exists, get_process_hermes_home,
            set_hermes_home_override, reset_hermes_home_override,
        )):
            features.append("native-card-templates-v1")
    from .room_activity import CAPABILITY, activity_hub
    if activity_hub().available:
        features.append(CAPABILITY)
    from .wiki_contract import available_wiki_operations
    if "native-card-templates-v1" in features and available_wiki_operations():
        features.extend(("native-wiki-v1", "native-wiki-disconnect-v1"))
    from .native_project_git import CAPABILITY as project_git_capability, supported as project_git_supported
    if project_git_supported():
        features.append(project_git_capability)
    return NativeContext(provider, user_id, display_name, profile, tuple(features), RUNTIME_ID)
