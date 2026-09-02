"""Direct HTTP/2 delivery to Apple Push Notification service."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..provider import DeliveryError, DeliveryReceipt, LiveActivityState, PushMessage


_IDENTIFIER = re.compile(r"^[A-Za-z0-9]{10}$")
_TOPIC = re.compile(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
_LIVE_ACTIVITY_TOPIC_SUFFIX = ".push-type.liveactivity"
_DEVICE_TOKEN = re.compile(r"^[0-9a-fA-F]{64,200}$")
_HOSTS = {
    "production": "https://api.push.apple.com",
    "sandbox": "https://api.sandbox.push.apple.com",
}


@dataclass(frozen=True)
class ApnsConfig:
    team_id: str
    key_id: str
    topic: str
    environment: str
    key_path: Path

    def stored_values(self) -> dict[str, str]:
        return {
            "team_id": self.team_id,
            "key_id": self.key_id,
            "topic": self.topic,
            "environment": self.environment,
            "key_path": str(self.key_path),
        }


def load_apns_config(
    values: Mapping[str, Any] | None,
    environ: Mapping[str, str] | None = None,
) -> ApnsConfig:
    source = dict(values or {})
    environment_values = environ if environ is not None else os.environ

    def value(name: str) -> str:
        env_name = f"LOOPDY_APNS_{name.upper()}"
        return str(source.get(name) or environment_values.get(env_name) or "").strip()

    team_id = value("team_id")
    key_id = value("key_id")
    topic = value("topic")
    environment = value("environment").lower()
    raw_path = value("key_path")
    if not _IDENTIFIER.fullmatch(team_id):
        raise ValueError("APNs team ID must contain exactly 10 letters or digits")
    if not _IDENTIFIER.fullmatch(key_id):
        raise ValueError("APNs key ID must contain exactly 10 letters or digits")
    if (
        len(topic) > 255
        or not _TOPIC.fullmatch(topic)
        or topic.endswith(_LIVE_ACTIVITY_TOPIC_SUFFIX)
    ):
        raise ValueError("APNs topic must be a valid bundle identifier")
    if environment not in _HOSTS:
        raise ValueError("APNs environment must be production or sandbox")
    if not raw_path:
        raise ValueError("APNs key path is required")
    key_path = Path(raw_path).expanduser().resolve()
    try:
        key_stat = key_path.stat()
    except OSError as error:
        raise ValueError("APNs key path must reference a readable file") from error
    if not stat.S_ISREG(key_stat.st_mode) or not os.access(key_path, os.R_OK):
        raise ValueError("APNs key path must reference a readable file")
    if os.name == "posix":
        if key_stat.st_uid != os.geteuid():
            raise ValueError("APNs key file must be owned by the current user")
        mode = stat.S_IMODE(key_stat.st_mode)
        if not mode & stat.S_IRUSR or mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError("APNs key file permissions must be owner-only and owner-readable")
    try:
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (OSError, TypeError, ValueError) as error:
        raise ValueError("APNs key file must contain an unencrypted P-256 signing key") from error
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve,
        ec.SECP256R1,
    ):
        raise ValueError("APNs key file must contain an unencrypted P-256 signing key")
    return ApnsConfig(
        team_id=team_id,
        key_id=key_id,
        topic=topic,
        environment=environment,
        key_path=key_path,
    )


class ApnsPushProvider:
    name = "direct"

    def __init__(
        self,
        config: ApnsConfig,
        *,
        client: Any | None = None,
        now: Callable[[], float] = time.time,
    ):
        self.config = config
        self._client = client or httpx.Client(
            http2=True,
            timeout=8,
            follow_redirects=False,
        )
        self._now = now
        self._cached_jwt = ""
        self._jwt_created_at = 0

    def send(
        self,
        token: str,
        message: PushMessage,
        *,
        environment: str = "",
    ) -> DeliveryReceipt:
        normalized_token = str(token or "").strip()
        if not _DEVICE_TOKEN.fullmatch(normalized_token):
            raise ValueError("A valid APNs device token is required")
        selected_environment = str(environment or self.config.environment).strip().lower()
        host = _HOSTS.get(selected_environment)
        if host is None:
            raise ValueError("APNs environment must be production or sandbox")
        payload = _payload(message)
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > 4096:
            raise ValueError("APNs notification payload exceeds 4 KB")
        headers = {
            "authorization": f"bearer {self._provider_token()}",
            "apns-topic": self.config.topic,
            "apns-push-type": "alert",
            "apns-priority": "10" if message.sound else "5",
            "apns-expiration": "0",
            "apns-collapse-id": message.event_id[:64],
        }
        try:
            response = self._client.post(
                f"{host}/3/device/{normalized_token}",
                headers=headers,
                json=payload,
            )
        except (httpx.TransportError, OSError) as error:
            raise DeliveryError("transport_error", retryable=True) from error
        if len(getattr(response, "content", b"")) > 65_536:
            raise DeliveryError("oversized_response", retryable=False)
        status = int(response.status_code)
        if status != 200:
            reason = _response_reason(response)
            invalid = status == 410 or reason in {
                "BadDeviceToken",
                "DeviceTokenNotForTopic",
                "Unregistered",
            }
            raise DeliveryError(
                reason,
                status=status,
                invalid_token=invalid,
                retryable=False if invalid else None,
            )
        delivery_id = str(response.headers.get("apns-id") or "").strip()[:180]
        if not delivery_id:
            raise DeliveryError("missing_apns_id", retryable=True)
        return DeliveryReceipt(delivery_id=delivery_id)

    def send_live_activity(
        self,
        token: str,
        *,
        activity_id: str,
        session_ref: str,
        phase: str,
        progress: int,
        timestamp: int,
        active_session_count: int = 0,
        expires: int,
        environment: str = "",
    ) -> DeliveryReceipt:
        normalized_token = str(token or "").strip()
        if not _DEVICE_TOKEN.fullmatch(normalized_token):
            raise ValueError("A valid Live Activity push token is required")
        selected_environment = str(environment or self.config.environment).strip().lower()
        host = _HOSTS.get(selected_environment)
        if host is None:
            raise ValueError("APNs environment must be production or sandbox")
        state = LiveActivityState(
            version=1,
            kind="live_activity",
            activity_id=activity_id,
            session_ref=session_ref,
            phase=phase,
            progress=progress,
            active_session_count=active_session_count,
            timestamp=timestamp,
            expires=expires,
        )
        terminal = state.phase in {"completed", "failed"}
        aps: dict[str, Any] = {
            "timestamp": state.timestamp,
            "event": "end" if terminal else "update",
            "content-state": {
                "phase": state.phase,
                "progress": state.progress,
                "activeSessionCount": state.active_session_count,
                "sessionRef": state.session_ref,
            },
            "stale-date": state.expires,
        }
        if terminal:
            aps["dismissal-date"] = state.timestamp
        payload = {"aps": aps}
        if len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > 4096:
            raise ValueError("APNs Live Activity payload exceeds 4 KB")
        headers = {
            "authorization": f"bearer {self._provider_token()}",
            "apns-topic": f"{self.config.topic}.push-type.liveactivity",
            "apns-push-type": "liveactivity",
            "apns-priority": "10" if state.phase in {"waiting", "completed", "failed"} else "5",
            "apns-expiration": str(state.expires),
            "apns-collapse-id": hashlib.sha256(state.activity_id.encode("ascii")).hexdigest(),
        }
        try:
            response = self._client.post(
                f"{host}/3/device/{normalized_token}",
                headers=headers,
                json=payload,
            )
        except (httpx.TransportError, OSError) as error:
            raise DeliveryError("transport_error", retryable=True) from error
        if len(getattr(response, "content", b"")) > 65_536:
            raise DeliveryError("oversized_response", retryable=False)
        status_code = int(response.status_code)
        if status_code != 200:
            reason = _response_reason(response)
            invalid = status_code == 410 or reason in {
                "BadDeviceToken",
                "DeviceTokenNotForTopic",
                "Unregistered",
            }
            raise DeliveryError(
                reason,
                status=status_code,
                invalid_token=invalid,
                retryable=False if invalid else None,
            )
        delivery_id = str(response.headers.get("apns-id") or "").strip()[:180]
        if not delivery_id:
            raise DeliveryError("missing_apns_id", retryable=True)
        return DeliveryReceipt(delivery_id=delivery_id)

    def close(self) -> None:
        close = getattr(self._client, "close", None)
        if callable(close):
            close()

    def _provider_token(self) -> str:
        now = int(self._now())
        if self._cached_jwt and now - self._jwt_created_at < 2_700:
            return self._cached_jwt
        try:
            key = self.config.key_path.read_bytes()
            encoded = jwt.encode(
                {"iss": self.config.team_id, "iat": now},
                key,
                algorithm="ES256",
                headers={"kid": self.config.key_id},
            )
        except (OSError, ValueError, jwt.PyJWTError) as error:
            raise DeliveryError("invalid_apns_signing_key", retryable=False) from error
        self._cached_jwt = str(encoded)
        self._jwt_created_at = now
        return self._cached_jwt


def _payload(message: PushMessage) -> dict[str, Any]:
    aps: dict[str, Any] = {
        "alert": {"title": message.title, "body": message.body},
    }
    if message.sound:
        aps["sound"] = "default"
    if message.event_type == "channel.message":
        aps["badge"] = 1
    if message.event_type in {"attention.required", "approval.required"}:
        # Direct delivery keeps the established category for installed-client compatibility.
        # Current Loopdy builds register this alias with the authenticated Review action.
        aps["category"] = "LOOPDY_APPROVAL"
    return {"aps": aps, **dict(message.data)}


def _response_reason(response: Any) -> str:
    try:
        value = response.json()
    except Exception:
        value = {}
    reason = value.get("reason") if isinstance(value, dict) else None
    normalized = str(reason or "request_rejected").strip()
    return normalized[:80] or "request_rejected"


__all__ = ["ApnsConfig", "ApnsPushProvider", "load_apns_config"]
