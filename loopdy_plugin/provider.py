"""Provider-neutral contracts for Loopdy push delivery."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Protocol

from .relay_crypto import b64url_decode


ProviderMode = Literal["managed", "direct", "relay"]
_PROTOCOL_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,179}$")
_MAX_TIMESTAMP = 9_999_999_999


class DeliveryError(RuntimeError):
    """A bounded provider failure safe to classify without exposing response data."""

    def __init__(
        self,
        code: str,
        *,
        status: int = 0,
        invalid_token: bool = False,
        retryable: bool | None = None,
    ):
        normalized = str(code or "provider_error").strip()[:80] or "provider_error"
        super().__init__(normalized)
        self.code = normalized
        self.status = int(status)
        self.invalid_token = bool(invalid_token)
        self._retryable = retryable

    @property
    def retryable(self) -> bool:
        if self._retryable is not None:
            return self._retryable
        return self.status == 0 or self.status == 429 or 500 <= self.status <= 599


@dataclass(frozen=True)
class PushMessage:
    event_id: str
    event_type: str
    title: str
    body: str
    data: Mapping[str, Any]
    sound: bool


@dataclass(frozen=True)
class DeliveryReceipt:
    delivery_id: str
    pending_receipt_id: str = ""


@dataclass(frozen=True)
class ProviderStatus:
    mode: ProviderMode
    configured: bool
    ready: bool
    detail: str


@dataclass(frozen=True)
class ProviderReceipt:
    status: Literal["delivered", "failed"]
    error_code: str = ""
    invalid_token: bool = False
    retryable: bool = False


@dataclass(frozen=True)
class LiveActivityState:
    version: Literal[1]
    kind: Literal["live_activity"]
    activity_id: str
    session_ref: str
    phase: Literal["thinking", "waiting", "running", "completed", "failed"]
    progress: int
    active_session_count: int
    timestamp: int
    expires: int

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1 or self.kind != "live_activity":
            raise ValueError("Live Activity state must use relay schema version 1")
        if type(self.activity_id) is not str or _PROTOCOL_IDENTIFIER.fullmatch(self.activity_id) is None:
            raise ValueError("Live Activity activity_id is invalid")
        if len(b64url_decode(self.session_ref)) > 64:
            raise ValueError("Live Activity session_ref exceeds 64 bytes")
        if self.phase not in {"thinking", "waiting", "running", "completed", "failed"}:
            raise ValueError("Live Activity phase is invalid")
        if type(self.progress) is not int or not 0 <= self.progress <= 100:
            raise ValueError("Live Activity progress must be between 0 and 100")
        if type(self.active_session_count) is not int or not 0 <= self.active_session_count <= 999:
            raise ValueError("Live Activity active session count must be between 0 and 999")
        if (
            type(self.timestamp) is not int
            or type(self.expires) is not int
            or self.timestamp <= 0
            or self.timestamp > _MAX_TIMESTAMP
            or self.expires <= self.timestamp
            or self.expires > _MAX_TIMESTAMP
            or self.expires - self.timestamp > 120
        ):
            raise ValueError("Live Activity expiry must be within 120 seconds")

    def as_payload(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "kind": self.kind,
            "activity_id": self.activity_id,
            "session_ref": self.session_ref,
            "phase": self.phase,
            "progress": self.progress,
            "active_session_count": self.active_session_count,
            "timestamp": self.timestamp,
            "expires": self.expires,
        }


class PushProvider(Protocol):
    name: str

    def send(
        self,
        token: str,
        message: PushMessage,
        *,
        environment: str = "",
    ) -> DeliveryReceipt: ...


__all__ = [
    "DeliveryError",
    "DeliveryReceipt",
    "LiveActivityState",
    "ProviderMode",
    "ProviderReceipt",
    "ProviderStatus",
    "PushMessage",
    "PushProvider",
]
